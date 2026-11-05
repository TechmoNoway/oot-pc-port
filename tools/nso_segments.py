"""Bounded NSO segment decoding and verification before module loading."""

import hashlib
import os
from pathlib import Path
import struct
import subprocess

from input_formats import InputError, inspect_nso, require

MAX_DECODED_MODULE = 256 * 1024 * 1024


def decode_lz4(payload: bytes, expected_size: int) -> bytes:
    """Decode an independent LZ4 block, including overlapping match copies."""
    require(0 <= expected_size <= MAX_DECODED_MODULE, "LZ4 output exceeds the module size limit")
    if not payload and expected_size == 0:
        return b""
    position, output = 0, bytearray()

    def length(value):
        nonlocal position
        if value == 15:
            while True:
                require(position < len(payload), "Truncated LZ4 length")
                extra = payload[position]
                position += 1
                value += extra
                require(value <= expected_size, "LZ4 length exceeds declared output size")
                if extra != 255:
                    break
        return value

    while position < len(payload):
        token = payload[position]
        position += 1
        literals = length(token >> 4)
        require(literals <= len(payload) - position, "Truncated LZ4 literals")
        require(literals <= expected_size - len(output), "LZ4 literals exceed declared output size")
        output += payload[position:position + literals]
        position += literals
        if position == len(payload):
            require(len(output) == expected_size, "LZ4 decoded size mismatch")
            return bytes(output)
        require(position + 2 <= len(payload), "Truncated LZ4 match offset")
        distance = payload[position] | (payload[position + 1] << 8)
        position += 2
        require(0 < distance <= len(output), "Invalid LZ4 match offset")
        count = length(token & 15) + 4
        require(count <= expected_size - len(output), "LZ4 match exceeds declared output size")
        # A repeated suffix also covers matches that refer to bytes being produced.
        pattern = output[-distance:]
        output += (pattern * ((count + distance - 1) // distance))[:count]
    raise InputError("LZ4 block has no final literal sequence")


def default_zbic_decoder() -> Path:
    configured = os.environ.get("OOT_ZBIC_DECODER")
    if configured:
        return Path(configured)
    name = "zbic-decode.exe" if os.name == "nt" else "zbic-decode"
    return Path(__file__).resolve().parent.parent / "build" / "tools" / name


def decode_zbic(payload: bytes, expected_size: int, decoder: Path | None = None) -> bytes:
    require(0 <= expected_size <= MAX_DECODED_MODULE, "ZBIC output exceeds the module size limit")
    require(len(payload) <= MAX_DECODED_MODULE, "ZBIC input exceeds the module size limit")
    if not payload and expected_size == 0:
        return b""
    require(payload[:4] == b"ZBIC", "Invalid ZBIC frame signature")
    executable = default_zbic_decoder() if decoder is None else decoder
    require(executable.is_file(), "ZBIC decoder missing; run python tools/build_zbic.py --fetch first")
    try:
        result = subprocess.run([str(executable.resolve()), str(expected_size)], input=payload,
                                capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as error:
        raise InputError(f"ZBIC decoder could not run: {error}") from error
    require(result.returncode == 0, "ZBIC decoding failed: " + result.stderr[:1024].decode("utf-8", errors="replace").strip())
    require(len(result.stdout) == expected_size, "ZBIC decoded size mismatch")
    return result.stdout


def decode_nso(data: bytes, decoder: Path | None = None) -> tuple[list[bytes], dict]:
    report = inspect_nso(data)
    total = sum(segment["memory_size"] for segment in report["segments"])
    require(total <= MAX_DECODED_MODULE, "Decoded NSO segments exceed the module size limit")
    decoded = []
    verified = 0
    for index, segment in enumerate(report["segments"]):
        begin, stored = segment["file_offset"], segment["stored_size"]
        payload = data[begin:begin + stored]
        compression = segment["compression"]
        if compression == "lz4":
            plain = decode_lz4(payload, segment["memory_size"])
        elif compression == "zbic":
            plain = decode_zbic(payload, segment["memory_size"], decoder)
        else:
            plain = payload
        require(len(plain) == segment["memory_size"], f"NSO {segment['name']} decoded size mismatch")
        digest = hashlib.sha256(plain).digest()
        segment["sha256"] = digest.hex()
        segment["hash_verified"] = None
        if segment["hash_required"]:
            expected = data[160 + index * 32:192 + index * 32]
            require(digest == expected, f"NSO {segment['name']} SHA-256 mismatch")
            segment["hash_verified"] = True
            verified += 1
        decoded.append(plain)
    report["segments_decoded"] = True
    report["segment_hashes_checked"] = verified == 3
    report["verified_segment_hash_count"] = verified
    report["required_segment_hashes_verified"] = True
    return decoded, report


def normalize_nso(data: bytes, decoded: list[bytes]) -> bytes:
    """Store already-decoded segments in an NSO, preserving memory offsets and BSS."""
    require(len(decoded) == 3, "An NSO must have three decoded segments")
    header = bytearray(data[:256])
    require(len(header) == 256, "Truncated NSO header")
    output = bytearray(header)
    name_offset, name_size = struct.unpack_from("<I", header, 28)[0], struct.unpack_from("<I", header, 44)[0]
    if name_size:
        require(name_size <= 1024 * 1024 and 256 <= name_offset <= len(data) and name_size <= len(data) - name_offset,
                "Invalid NSO module name range")
        struct.pack_into("<I", output, 28, 256)
        output += data[name_offset:name_offset + name_size]
    for index, plain in enumerate(decoded):
        require(len(plain) == struct.unpack_from("<I", header, 24 + index * 16)[0], "Decoded NSO segment size mismatch")
        output += bytes((-len(output)) % 16)
        require(len(output) + len(plain) <= MAX_DECODED_MODULE, "Plain NSO exceeds the module size limit")
        struct.pack_into("<I", output, 16 + index * 16, len(output))
        struct.pack_into("<I", output, 96 + index * 4, len(plain))
        output += plain
    flags = struct.unpack_from("<I", header, 12)[0]
    struct.pack_into("<I", output, 12, flags & ~0x87)
    return bytes(output)
