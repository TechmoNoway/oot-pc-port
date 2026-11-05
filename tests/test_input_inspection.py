"""Synthetic input fixtures only; no game bytes are used in these tests."""

import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from input_formats import InputError, NupCatalog, decode_zstd, inspect_nso, inspect_npdm, inspect_path

try:
    from compression import zstd as standard_zstd
except ImportError:
    standard_zstd = None
try:
    import zstandard
except ImportError:
    zstandard = None
ZSTD_PROGRAM = shutil.which("zstd")
if ZSTD_PROGRAM is None and Path("C:/msys64/usr/bin/zstd.exe").is_file():
    ZSTD_PROGRAM = "C:/msys64/usr/bin/zstd.exe"
CAN_COMPRESS = bool(standard_zstd or zstandard or ZSTD_PROGRAM)


def compress_zstd(data):
    if standard_zstd is not None:
        return standard_zstd.compress(data)
    if zstandard is not None:
        return zstandard.ZstdCompressor().compress(data)
    return subprocess.check_output([ZSTD_PROGRAM, "-q", "-c"], input=data)


def make_nso():
    data = bytearray(304)
    data[:4] = b"NSO0"
    for index in range(3):
        struct.pack_into("<III", data, 16 + index * 16, 256 + index * 16, index * 4096, 16)
        struct.pack_into("<I", data, 96 + index * 4, 16)
    struct.pack_into("<I", data, 60, 4096)
    data[64:96] = bytes(range(32))
    return data


def make_npdm():
    data = bytearray(192)
    data[:4] = b"META"
    data[12], data[14], data[15] = 7, 44, 2
    struct.pack_into("<I", data, 28, 1048576)
    struct.pack_into("<IIII", data, 112, 128, 64, 0, 0)
    data[128:132] = b"ACI0"
    struct.pack_into("<Q", data, 144, 0x123456789ABCDEF0)
    return data


def make_nup(files=None, *, compressed=False, package_count=1, cycle=False, unsafe=False):
    files = files or [("main", bytes(make_nso())), ("main.npdm", bytes(make_npdm()))]
    strings = bytearray(b"exefs")
    names = []
    for name, _ in files:
        encoded = ("../main" if unsafe else name).encode()
        names.append((len(strings), len(encoded)))
        strings += encoded
    directory_count = 2
    children = [1] + [directory_count + index for index in range(len(files))]
    if cycle:
        children[1] = 1
    pool_offset = 48 + 64 * package_count + 24 * directory_count + 80 * len(files) + 4 * len(children)
    toc_size = pool_offset + len(strings)
    blob_offset = (128 + toc_size + 15) & ~15
    payloads, records = bytearray(), bytearray()
    for index, (_, original) in enumerate(files):
        padding = (-len(payloads)) % 16
        payloads += bytes(padding)
        stored = compress_zstd(original) if compressed else original
        records += struct.pack("<IIQQQ32sBBH12s", *names[index], len(original),
                               blob_offset + len(payloads), len(stored), hashlib.sha256(original).digest(),
                               int(compressed), 0, 0, bytes(12))
        payloads += stored
    toc = bytearray(struct.pack("<IIQQQQQ", 0x01434F54, package_count, directory_count,
                                len(files), pool_offset, len(strings), 0))
    for _ in range(package_count):
        package = struct.pack("<QIIIIBBHIQI", 0x123456789ABCDEF0, 0, 1, 0xFFFFFFFF, 1, 1, 1, 0, 0, 0, 0)
        toc += package + bytes(64 - len(package))
    toc += struct.pack("<IIIIQ", 0, 0, 0, 1, 0)
    toc += struct.pack("<IIIIQ", 0, 5, 1, len(files), 0)
    toc += records + struct.pack(f"<{len(children)}I", *children) + strings
    header = bytearray(128)
    header[:4] = b"NUP\x01"
    struct.pack_into("<HHQQ32sQQII", header, 4, 128, 1, 128, len(toc), hashlib.sha256(toc).digest(),
                     blob_offset, blob_offset + len(payloads), package_count, 0)
    return header + toc + bytes(blob_offset - 128 - len(toc)) + payloads


class NsoTests(unittest.TestCase):
    def test_plain_header_and_bss(self):
        result = inspect_nso(make_nso())
        self.assertEqual(result["image_size"], 12304)
        self.assertEqual(result["segments"][0]["compression"], "none")
        self.assertFalse(result["segment_hashes_checked"])

    def test_zbic_is_reported_without_decoding(self):
        data = make_nso()
        struct.pack_into("<I", data, 12, 0xFF)
        result = inspect_nso(data)
        self.assertTrue(all(item["compression"] == "zbic" for item in result["segments"]))

    def test_lz4_is_reported(self):
        data = make_nso()
        struct.pack_into("<I", data, 12, 1)
        self.assertEqual(inspect_nso(data)["segments"][0]["compression"], "lz4")

    def test_truncated_header(self):
        with self.assertRaises(InputError):
            inspect_nso(make_nso()[:255])

    def test_extent_out_of_bounds(self):
        data = make_nso()
        struct.pack_into("<I", data, 16, 0xFFFFFFFF)
        with self.assertRaisesRegex(InputError, "exceeds"):
            inspect_nso(data)

    def test_overlapping_segments(self):
        data = make_nso()
        struct.pack_into("<I", data, 36, 0)
        with self.assertRaisesRegex(InputError, "Overlapping"):
            inspect_nso(data)

    def test_segment_inside_header(self):
        data = make_nso()
        struct.pack_into("<I", data, 16, 32)
        with self.assertRaisesRegex(InputError, "header"):
            inspect_nso(data)


class NpdmTests(unittest.TestCase):
    def test_thread_and_program_id(self):
        result = inspect_npdm(make_npdm())
        self.assertTrue(result["is_64_bit"])
        self.assertEqual(result["program_id"], "123456789abcdef0")
        self.assertEqual(result["main_thread_core"], 2)

    def test_truncated_aci(self):
        with self.assertRaises(InputError):
            inspect_npdm(make_npdm()[:160])

    def test_invalid_aci_magic(self):
        data = make_npdm()
        data[128:132] = b"bad!"
        with self.assertRaises(InputError):
            inspect_npdm(data)


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "fixture.nup"

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, data):
        self.path.write_bytes(data)
        return self.path

    def test_raw_exefs_hashes(self):
        result = inspect_path(self.write(make_nup()))
        self.assertTrue(result["catalog_sha256_verified"])
        self.assertEqual(len(result["files"]), 2)
        self.assertTrue(all(item["container_sha256_verified"] for item in result["files"]))

    @unittest.skipUnless(CAN_COMPRESS, "zstd backend unavailable")
    def test_compressed_exefs(self):
        result = inspect_path(self.write(make_nup(compressed=True)))
        self.assertEqual(result["files"][0]["container_compression"], "zstd")
        self.assertTrue(result["files"][0]["container_sha256_verified"])

    def test_truncated_container(self):
        with self.assertRaisesRegex(InputError, "size"):
            inspect_path(self.write(make_nup()[:-1]))

    def test_changed_catalog(self):
        data = make_nup()
        data[150] ^= 1
        with self.assertRaisesRegex(InputError, "catalog SHA-256"):
            inspect_path(self.write(data))

    def test_changed_payload(self):
        data = make_nup()
        data[-1] ^= 1
        with self.assertRaisesRegex(InputError, "ExeFS SHA-256"):
            inspect_path(self.write(data))

    def test_directory_cycle(self):
        with self.assertRaisesRegex(InputError, "repeated"):
            inspect_path(self.write(make_nup(cycle=True)))

    def test_path_traversal(self):
        with self.assertRaisesRegex(InputError, "Unsafe"):
            inspect_path(self.write(make_nup(unsafe=True)))

    def test_multiple_packages_require_selection(self):
        self.write(make_nup(package_count=2))
        with self.assertRaisesRegex(InputError, "Multiple"):
            inspect_path(self.path)
        self.assertEqual(inspect_path(self.path, 1)["selected_package"], 1)

    def test_invalid_package_index(self):
        with self.assertRaisesRegex(InputError, "package index"):
            inspect_path(self.write(make_nup()), -1)

    def test_duplicate_exefs_path(self):
        with self.assertRaisesRegex(InputError, "Duplicate"):
            inspect_path(self.write(make_nup(files=[("main", bytes(make_nso()))] * 2)))

    def test_module_with_invalid_magic(self):
        with self.assertRaisesRegex(InputError, "NSO signature"):
            inspect_path(self.write(make_nup(files=[("main", b"not an NSO")])))

    def test_directory_lists_additional_subsdk(self):
        (self.path.parent / "main").write_bytes(make_nso())
        (self.path.parent / "subsdk3").write_bytes(make_nso())
        result = inspect_path(self.path.parent)
        self.assertEqual([item["name"] for item in result["files"]], ["main", "subsdk3"])

    @unittest.skipUnless(CAN_COMPRESS, "zstd backend unavailable")
    def test_compressed_output_size_limit(self):
        data = compress_zstd(b"x" * 4096)
        with self.assertRaises(InputError):
            decode_zstd(data, 16)

    @unittest.skipUnless(CAN_COMPRESS, "zstd backend unavailable")
    def test_invalid_compressed_data(self):
        with self.assertRaises(InputError):
            decode_zstd(b"not a zstd frame", 16)

    def test_excessive_catalog_limit(self):
        data = make_nup()
        struct.pack_into("<Q", data, 16, NupCatalog.MAX_TOC_BYTES + 1)
        with self.assertRaisesRegex(InputError, "size limit"):
            inspect_path(self.write(data))

    def test_cli_outputs_json(self):
        self.write(make_nup())
        result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/inspect_input.py"), str(self.path)],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["inspection"]["format"], "nup")

    def test_cli_failure_has_no_traceback(self):
        self.write(b"bad input")
        result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/inspect_input.py"), str(self.path)],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Input inspection failed", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_directory_requires_main(self):
        with self.assertRaisesRegex(InputError, "no main"):
            inspect_path(self.path.parent)

    def test_cli_rejects_report_outside_build(self):
        self.write(make_nup())
        destination = self.path.parent / "report.json"
        result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/inspect_input.py"), str(self.path),
                                 "--report", str(destination)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Report destination", result.stderr)
        self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
