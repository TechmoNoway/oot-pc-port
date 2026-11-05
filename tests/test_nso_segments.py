"""Synthetic segment streams, module headers, and preparation failures."""

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from input_formats import InputError, inspect_nso, inspect_path
from nso_segments import MAX_DECODED_MODULE, decode_lz4, decode_nso, decode_zbic, default_zbic_decoder, normalize_nso
from prepare_exefs import prepare
from test_input_inspection import make_nup


def literal_block(data):
    if len(data) < 15:
        return bytes([len(data) << 4]) + data
    remaining, extensions = len(data) - 15, bytearray()
    while remaining >= 255:
        extensions.append(255)
        remaining -= 255
    return b"\xf0" + extensions + bytes([remaining]) + data


def raw_zbic(data):
    # Single-segment frame with a one-byte content size and a final raw block.
    assert len(data) < 256
    return b"ZBIC\x20" + bytes([len(data)]) + ((len(data) << 3) | 1).to_bytes(3, "little") + data


def module_fixture(compression="none", required_hashes=True):
    plain = [b"synthetic text", b"synthetic constants", b"synthetic writable data"]
    header = bytearray(256)
    header[:4] = b"NSO0"
    flags = 0x38 if required_hashes else 0
    if compression != "none":
        flags |= 7
    if compression == "zbic":
        flags |= 128
    struct.pack_into("<I", header, 12, flags)
    struct.pack_into("<I", header, 60, 4096)
    body = bytearray()
    for index, content in enumerate(plain):
        stored = literal_block(content) if compression == "lz4" else raw_zbic(content) if compression == "zbic" else content
        struct.pack_into("<III", header, 16 + index * 16, 256 + len(body), index * 4096, len(content))
        struct.pack_into("<I", header, 96 + index * 4, len(stored))
        header[160 + index * 32:192 + index * 32] = hashlib.sha256(content).digest()
        body += stored
    return bytes(header + body), plain


class Lz4Tests(unittest.TestCase):
    def test_literals_and_extended_lengths(self):
        for length in (0, 1, 14, 15, 270, 1024):
            with self.subTest(length=length):
                plain = bytes(index % 251 for index in range(length))
                self.assertEqual(decode_lz4(literal_block(plain), length), plain)

    def test_overlapping_match(self):
        block = b"\x18a\x01\x00\x50bcdef"
        self.assertEqual(decode_lz4(block, 18), b"a" * 13 + b"bcdef")

    def test_multi_byte_overlap(self):
        block = b"\x36abc\x03\x00\x50vwxyz"
        self.assertEqual(decode_lz4(block, 18), b"abcabcabcabca" + b"vwxyz")

    def test_extended_match(self):
        block = b"\x1fa\x01\x00\xff\x00\x50bcdef"
        self.assertEqual(decode_lz4(block, 280), b"a" * 275 + b"bcdef")

    def test_invalid_offsets(self):
        for block in (b"\x10a\x00\x00\x00", b"\x10a\x02\x00\x00"):
            with self.assertRaisesRegex(InputError, "offset"):
                decode_lz4(block, 5)

    def test_truncated_sequences(self):
        for block in (b"\xf0", b"\x40ab", b"\x10a\x01", b"\x1fa\x01\x00\xff"):
            with self.subTest(block=block), self.assertRaises(InputError):
                decode_lz4(block, 1024)

    def test_output_size_mismatch(self):
        for expected in (1, 100):
            with self.assertRaises(InputError):
                decode_lz4(literal_block(b"hello"), expected)

    def test_match_output_limit(self):
        with self.assertRaisesRegex(InputError, "exceed"):
            decode_lz4(b"\x1fa\x01\x00\xff\x00\x50bcdef", 32)

    def test_missing_final_sequence(self):
        with self.assertRaisesRegex(InputError, "final literal"):
            decode_lz4(b"\x10a\x01\x00", 5)

    def test_memory_limit(self):
        with self.assertRaises(InputError):
            decode_lz4(b"\x00", MAX_DECODED_MODULE + 1)


class ModuleTests(unittest.TestCase):
    def test_raw_and_lz4_hash_verification(self):
        for compression in ("none", "lz4"):
            with self.subTest(compression=compression):
                raw, expected = module_fixture(compression)
                decoded, report = decode_nso(raw)
                self.assertEqual(decoded, expected)
                self.assertTrue(report["segment_hashes_checked"])
                self.assertEqual(report["verified_segment_hash_count"], 3)

    def test_hash_mismatch(self):
        raw, _ = module_fixture("lz4")
        changed = bytearray(raw)
        changed[160] ^= 1
        with self.assertRaisesRegex(InputError, "text SHA-256 mismatch"):
            decode_nso(changed)

    def test_unrequired_hashes_are_not_claimed_verified(self):
        raw, _ = module_fixture(required_hashes=False)
        _, report = decode_nso(raw)
        self.assertFalse(report["segment_hashes_checked"])
        self.assertEqual(report["verified_segment_hash_count"], 0)
        self.assertTrue(all(item["hash_verified"] is None for item in report["segments"]))

    def test_normalized_nso_round_trip(self):
        raw, expected = module_fixture("lz4")
        decoded, original = decode_nso(raw)
        plain = normalize_nso(raw, decoded)
        repeated, report = decode_nso(plain)
        self.assertEqual(repeated, expected)
        self.assertEqual(report["flags"], 0x38)
        self.assertEqual(report["bss_size"], original["bss_size"])
        self.assertTrue(all(item["compression"] == "none" for item in report["segments"]))

    def test_normalized_module_name_preserved(self):
        raw, _ = module_fixture()
        changed = bytearray(raw)
        struct.pack_into("<I", changed, 28, len(changed))
        struct.pack_into("<I", changed, 44, 5)
        changed += b"demo\0"
        decoded, _ = decode_nso(changed)
        plain = normalize_nso(changed, decoded)
        self.assertEqual(plain[256:261], b"demo\0")
        self.assertEqual(decode_nso(plain)[0], decoded)

    def test_inspector_verification_flag(self):
        raw, _ = module_fixture("lz4")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "main"
            path.write_bytes(raw)
            self.assertFalse(inspect_path(path)["segment_hashes_checked"])
            self.assertTrue(inspect_path(path, verify_segments=True)["segment_hashes_checked"])

    def test_declared_module_size_limit(self):
        raw, _ = module_fixture("lz4")
        changed = bytearray(raw)
        struct.pack_into("<I", changed, 24, MAX_DECODED_MODULE + 1)
        struct.pack_into("<I", changed, 36, MAX_DECODED_MODULE + 4096)
        struct.pack_into("<I", changed, 52, MAX_DECODED_MODULE + 8192)
        with self.assertRaisesRegex(InputError, "size limit"):
            decode_nso(changed)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "build").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / "build")
        self.root = Path(self.temporary.name)
        self.source = self.root / "input.nup"
        raw, _ = module_fixture("lz4")
        self.source.write_bytes(make_nup(files=[("main", raw)]))
        self.target = self.root / "prepared"

    def tearDown(self):
        self.temporary.cleanup()

    def test_prepare_verified_plain_exefs(self):
        manifest = prepare(self.source, self.target)
        entry = manifest["files"][0]
        plain = (self.target / "main").read_bytes()
        self.assertTrue(inspect_path(self.target, verify_segments=True)["files"][0]["segment_hashes_checked"])
        self.assertEqual(entry["sha256"], hashlib.sha256(plain).hexdigest())
        self.assertEqual(entry["segments"][0]["file_offset"], inspect_nso(plain)["segments"][0]["file_offset"])
        self.assertEqual(entry["segments"][0]["source_compression"], "lz4")
        self.assertEqual(json.loads((self.target / "manifest.json").read_text()), manifest)
        self.assertFalse(manifest["relocations_applied"])

    def test_no_partial_output_on_hash_failure(self):
        raw, _ = module_fixture("lz4")
        changed = bytearray(raw)
        changed[160] ^= 1
        self.source.write_bytes(make_nup(files=[("main", bytes(changed))]))
        with self.assertRaises(InputError):
            prepare(self.source, self.target)
        self.assertFalse(self.target.exists())
        self.assertFalse(list(self.root.glob(".prepare-*")))

    def test_existing_output_is_preserved(self):
        self.target.mkdir()
        sentinel = self.target / "keep.txt"
        sentinel.write_text("keep")
        with self.assertRaisesRegex(InputError, "already exists"):
            prepare(self.source, self.target)
        self.assertEqual(sentinel.read_text(), "keep")

    def test_output_must_stay_in_build(self):
        with self.assertRaisesRegex(InputError, "subdirectory"):
            prepare(self.source, ROOT / "prepared")


class ZbicTests(unittest.TestCase):
    def test_missing_decoder_has_instructions(self):
        with self.assertRaisesRegex(InputError, "decoder missing"):
            decode_zbic(raw_zbic(b"sample"), 6, ROOT / "build" / "missing-zbic.exe")

    def test_bad_magic(self):
        with self.assertRaisesRegex(InputError, "signature"):
            decode_zbic(b"not zbic", 8)

    def test_timeout_is_reported(self):
        decoder = default_zbic_decoder()
        with patch.object(Path, "is_file", return_value=True), patch("nso_segments.subprocess.run", side_effect=subprocess.TimeoutExpired("fixture", 60)):
            with self.assertRaisesRegex(InputError, "could not run"):
                decode_zbic(raw_zbic(b"sample"), 6, decoder)

    def test_helper_wrong_output_size(self):
        result = subprocess.CompletedProcess([], 0, b"short", b"")
        with patch.object(Path, "is_file", return_value=True), patch("nso_segments.subprocess.run", return_value=result):
            with self.assertRaisesRegex(InputError, "size mismatch"):
                decode_zbic(raw_zbic(b"sample"), 6)

    @unittest.skipUnless(default_zbic_decoder().is_file(), "local ZBIC helper not built")
    def test_helper_rejects_excessive_allocation(self):
        result = subprocess.run([str(default_zbic_decoder()), str(MAX_DECODED_MODULE + 1)], input=b"", capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"Invalid decoded size", result.stderr)

    @unittest.skipUnless(default_zbic_decoder().is_file(), "local ZBIC helper not built")
    def test_synthetic_zbic_frame(self):
        self.assertEqual(decode_zbic(raw_zbic(b"synthetic frame"), 15), b"synthetic frame")

    @unittest.skipUnless(default_zbic_decoder().is_file(), "local ZBIC helper not built")
    def test_zbic_nso_hashes_and_round_trip(self):
        raw, expected = module_fixture("zbic")
        decoded, report = decode_nso(raw)
        self.assertEqual(decoded, expected)
        self.assertEqual(report["verified_segment_hash_count"], 3)
        self.assertEqual(decode_nso(normalize_nso(raw, decoded))[0], expected)

    @unittest.skipUnless(default_zbic_decoder().is_file(), "local ZBIC helper not built")
    def test_wrong_size_and_corrupt_frame(self):
        for data, size in ((raw_zbic(b"test"), 3), (raw_zbic(b"test"), 5), (b"ZBICbad frame", 4)):
            with self.subTest(size=size), self.assertRaises(InputError):
                decode_zbic(data, size)


if __name__ == "__main__":
    unittest.main()
