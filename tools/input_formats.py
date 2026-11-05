"""Read input metadata without loading or executing guest code."""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

EXEFS_NAMES = ("rtld", "main", *(f"subsdk{index}" for index in range(10)), "sdk", "main.npdm")


class InputError(ValueError):
    """Invalid, truncated, or unsupported input."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InputError(message)


def in_bounds(offset: int, length: int, total: int) -> bool:
    return 0 <= offset <= total and 0 <= length <= total - offset


def inspect_nso(data: bytes) -> dict:
    require(len(data) >= 256 and data[:4] == b"NSO0", "Invalid or truncated NSO header")
    version, _, flags = struct.unpack_from("<III", data, 4)
    require(version == 0, f"Unsupported NSO version {version}")
    require(flags & ~0xFF == 0, f"Unsupported NSO flags {flags:#x}")
    segments = []
    for index, name in enumerate(("text", "rodata", "data")):
        file_offset, memory_offset, size = struct.unpack_from("<III", data, 16 + index * 16)
        compressed = bool(flags & (1 << index))
        stored = struct.unpack_from("<I", data, 96 + index * 4)[0] if compressed else size
        require(in_bounds(file_offset, stored, len(data)), f"NSO {name} exceeds the file")
        require(not stored or file_offset >= 256, f"NSO {name} overlaps the header")
        require(not size or stored > 0, f"NSO {name} has no stored data")
        segments.append({
            "name": name, "file_offset": file_offset, "memory_offset": memory_offset,
            "memory_size": size, "stored_size": stored,
            "compression": ("zbic" if flags & 128 else "lz4") if compressed else "none",
            "hash_required": bool(flags & (1 << (index + 3))),
        })
    for left_index, left in enumerate(segments):
        for right in segments[left_index + 1:]:
            for start, size in (("file_offset", "stored_size"), ("memory_offset", "memory_size")):
                if left[size] and right[size]:
                    require(left[start] + left[size] <= right[start] or
                            right[start] + right[size] <= left[start], "Overlapping NSO segments")
    bss = struct.unpack_from("<I", data, 60)[0]
    image_size = max(section["memory_offset"] + section["memory_size"] for section in segments)
    image_size = max(image_size, segments[2]["memory_offset"] + segments[2]["memory_size"] + bss)
    return {
        "format": "nso", "build_id": data[64:96].hex(), "flags": flags,
        "segments": segments, "bss_size": bss, "image_size": image_size,
        "segment_hashes_checked": False,
    }


def inspect_npdm(data: bytes) -> dict:
    require(len(data) >= 128 and data[:4] == b"META", "Invalid or truncated NPDM header")
    aci_offset, aci_size, acid_offset, acid_size = struct.unpack_from("<IIII", data, 112)
    for name, offset, size in (("ACI", aci_offset, aci_size), ("ACID", acid_offset, acid_size)):
        require(in_bounds(offset, size, len(data)), f"NPDM {name} exceeds the file")
        require(not size or offset >= 128, f"NPDM {name} overlaps the header")
    program_id = None
    if aci_size:
        require(aci_size >= 64 and data[aci_offset:aci_offset + 4] == b"ACI0", "Invalid NPDM ACI")
        program_id = f"{struct.unpack_from('<Q', data, aci_offset + 16)[0]:016x}"
    return {
        "format": "npdm", "program_id": program_id, "is_64_bit": bool(data[12] & 1),
        "address_space_type": (data[12] >> 1) & 7,
        "main_thread_priority": data[14], "main_thread_core": data[15],
        "main_thread_stack_size": struct.unpack_from("<I", data, 28)[0],
        "signatures_checked": False,
    }


def decode_zstd(payload: bytes, expected_size: int) -> bytes:
    """Bound decoded output; use an available library or the local zstd program."""
    try:
        from compression.zstd import ZstdError, ZstdFile
    except ImportError:
        ZstdFile = None
    if ZstdFile is not None:
        try:
            with ZstdFile(io.BytesIO(payload), "rb") as stream:
                output = stream.read(expected_size + 1)
        except ZstdError as error:
            raise InputError(f"zstd decoding failed: {error}") from error
    else:
        try:
            import zstandard
        except ImportError:
            zstandard = None
        if zstandard is not None:
            try:
                with zstandard.ZstdDecompressor(max_window_size=128 * 1024).stream_reader(io.BytesIO(payload)) as stream:
                    output = stream.read(expected_size + 1)
            except zstandard.ZstdError as error:
                raise InputError(f"zstd decoding failed: {error}") from error
        else:
            program = shutil.which("zstd")
            fallback = Path("C:/msys64/usr/bin/zstd.exe")
            if program is None and fallback.is_file():
                program = str(fallback)
            require(program is not None, "zstd decoding requires Python 3.14, zstandard, or a zstd program")
            with tempfile.TemporaryDirectory(prefix="oot-input-") as temporary:
                compressed = Path(temporary) / "input.zst"
                compressed.write_bytes(payload)
                with tempfile.TemporaryFile() as errors:
                    process = subprocess.Popen(
                        [program, "-d", "-c", "-q", "-M128MB", str(compressed)],
                        stdout=subprocess.PIPE, stderr=errors,
                    )
                    try:
                        output = process.stdout.read(expected_size + 1)
                        if len(output) > expected_size:
                            process.kill()
                        result = process.wait(timeout=30)
                        require(result == 0, "zstd decoding failed")
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.wait()
                        process.stdout.close()
    require(len(output) == expected_size, "zstd decoded size differs from the container record")
    return output


class NupCatalog:
    """A bounded metadata reader. Payload access is limited to selected ExeFS files."""

    MAX_TOC_BYTES = 128 * 1024 * 1024
    MAX_MODULE_BYTES = 256 * 1024 * 1024

    def __init__(self, path: Path):
        self.path = path
        with path.open("rb") as stream:
            self.file_size = stream.seek(0, 2)
            stream.seek(0)
            header = stream.read(128)
            require(len(header) == 128 and header[:4] == b"NUP\x01", "Invalid NUP header")
            header_size, version, offset, size, digest, blob, total, count, flags = struct.unpack_from(
                "<HHQQ32sQQII", header, 4)
            require(header_size == 128 and version == 1 and flags == 0, "Unsupported NUP header layout")
            require(total == self.file_size, "NUP file size does not match its header")
            require(48 <= size <= self.MAX_TOC_BYTES, "NUP catalog exceeds the inspection size limit")
            require(offset >= header_size and in_bounds(offset, size, total), "NUP catalog exceeds the file")
            require(offset + size <= blob <= total and blob % 16 == 0, "Invalid NUP payload boundary")
            stream.seek(offset)
            self.toc = stream.read(size)
            require(hashlib.sha256(self.toc).digest() == digest, "NUP catalog SHA-256 mismatch")
        self.blob_offset = blob
        magic, packages, directories, files, strings, string_bytes, reserved = struct.unpack_from("<IIQQQQQ", self.toc)
        require(magic == 0x01434F54 and packages == count and count > 0 and reserved == 0, "Invalid NUP catalog header")
        self.directory_count = directories
        self.file_count = files
        self.directory_offset = 48 + packages * 64
        self.file_offset = self.directory_offset + directories * 24
        self.child_offset = self.file_offset + files * 80
        require(self.child_offset <= strings and (strings - self.child_offset) % 4 == 0,
                "Invalid NUP catalog table sizes")
        require(in_bounds(strings, string_bytes, len(self.toc)), "NUP string table exceeds catalog")
        self.string_offset, self.string_size = strings, string_bytes
        self.child_count = (strings - self.child_offset) // 4
        self.packages = []
        for index in range(packages):
            title, root, exefs, romfs, version, kind, flags, _, _, meta, meta_size = struct.unpack_from(
                "<QIIIIBBHIQI", self.toc, 48 + index * 64)
            require(kind <= 2 and flags & ~1 == 0, "Unsupported NUP package record")
            require(root < directories and all(item == 0xFFFFFFFF or item < directories for item in (exefs, romfs)),
                    "NUP package directory index is out of bounds")
            require(meta_size <= 1024 * 1024 and in_bounds(meta, meta_size, self.file_size),
                    "Invalid NUP package metadata range")
            package = {
                "index": index, "title_id": f"{title:016x}", "kind": ("base", "update", "addon")[kind],
                "version": version, "standalone": bool(flags & 1), "exefs_directory": exefs,
                "romfs_directory": romfs,
            }
            with self.path.open("rb") as stream:
                stream.seek(meta)
                metadata = stream.read(meta_size)
            position = 0
            while position < len(metadata):
                require(position + 8 <= len(metadata), "Truncated NUP metadata record")
                tag, _, length = struct.unpack_from("<HHI", metadata, position)
                position += 8
                require(in_bounds(position, length, len(metadata)), "NUP metadata record exceeds its block")
                if tag in (4, 5):
                    package["display_version" if tag == 4 else "title"] = metadata[position:position + length].decode("utf-8")
                position += length
            self.packages.append(package)

    def name(self, offset: int, size: int) -> str:
        require(in_bounds(offset, size, self.string_size), "NUP name exceeds string table")
        value = self.toc[self.string_offset + offset:self.string_offset + offset + size].decode("utf-8")
        require(value not in (".", "..") and not any(char in value for char in "\\/:\0"), "Unsafe NUP entry name")
        return value

    def files_in(self, directory: int):
        if directory == 0xFFFFFFFF:
            return
        pending = [(directory, ())]
        visited = set()
        while pending:
            index, path = pending.pop()
            require(index < self.directory_count and index not in visited, "Invalid or repeated NUP directory reference")
            visited.add(index)
            _, _, first, count, _ = struct.unpack_from("<IIIIQ", self.toc, self.directory_offset + index * 24)
            require(in_bounds(first, count, self.child_count), "NUP directory children exceed the catalog")
            for slot in range(first, first + count):
                child = struct.unpack_from("<I", self.toc, self.child_offset + slot * 4)[0]
                if child < self.directory_count:
                    offset, size = struct.unpack_from("<II", self.toc, self.directory_offset + child * 24)
                    name = self.name(offset, size)
                    require(bool(name), "Empty NUP directory name")
                    pending.append((child, path + (name,)))
                else:
                    file_index = child - self.directory_count
                    require(file_index < self.file_count, "NUP file index exceeds the catalog")
                    values = struct.unpack_from("<IIQQQ32sBBH12s", self.toc, self.file_offset + file_index * 80)
                    offset, length, size, payload, stored, digest, codec, flags, _, _ = values
                    name = self.name(offset, length)
                    require(bool(name) and codec in (0, 1) and flags == 0, "Invalid NUP file record")
                    require(in_bounds(payload, stored, self.file_size), "NUP file extent exceeds the container")
                    require(not size or (stored > 0 and payload >= self.blob_offset and payload % 16 == 0),
                            "Invalid NUP file extent")
                    require(codec != 0 or stored == size, "Raw NUP file size mismatch")
                    yield path + (name,), (size, payload, stored, digest, codec)

    def read_exefs(self, package_index: int):
        require(0 <= package_index < len(self.packages), "NUP package index is out of bounds")
        package = self.packages[package_index]
        seen = set()
        with self.path.open("rb") as stream:
            for path, record in self.files_in(package["exefs_directory"]):
                name = "/".join(path)
                require(name not in seen, "Duplicate NUP ExeFS path")
                seen.add(name)
                size, offset, stored, expected, codec = record
                require(max(size, stored) <= self.MAX_MODULE_BYTES, "ExeFS module exceeds inspection size limit")
                stream.seek(offset)
                payload = stream.read(stored)
                require(len(payload) == stored, "Truncated NUP file payload")
                data = payload if codec == 0 else decode_zstd(payload, size)
                digest = hashlib.sha256(data).digest()
                require(digest == expected, f"NUP ExeFS SHA-256 mismatch: {name}")
                yield name, data, {"container_sha256_verified": True,
                                   "container_compression": "none" if codec == 0 else "zstd"}
        require(bool(seen), "The selected NUP package has no ExeFS files")

    def exefs_report(self, package_index: int, verify_segments=False, decoder=None) -> list[dict]:
        reports = []
        for name, data, container in self.read_exefs(package_index):
            report = describe_file(name, data, verify_segments, decoder)
            report.update(container)
            reports.append(report)
        return reports


def describe_file(name: str, data: bytes, verify_segments=False, decoder=None) -> dict:
    module = Path(name).name
    if module in ("main", "rtld", "sdk") or (module.startswith("subsdk") and module[6:].isdigit()):
        require(data[:4] == b"NSO0", f"Invalid NSO signature: {name}")
    if module == "main.npdm":
        require(data[:4] == b"META", f"Invalid NPDM signature: {name}")
    report = {"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if data[:4] == b"NSO0":
        if verify_segments:
            from nso_segments import decode_nso
            _, verified = decode_nso(data, decoder)
            report.update(verified)
        else:
            report.update(inspect_nso(data))
    elif data[:4] == b"META":
        report.update(inspect_npdm(data))
    else:
        report["format"] = "unknown"
    return report


def inspect_path(path: Path, package_index: int | None = None, verify_segments=False, decoder=None) -> dict:
    if path.is_dir():
        require(package_index is None, "--package applies only to NUP input")
        files = []
        for name in EXEFS_NAMES:
            candidate = path / name
            if candidate.is_file():
                require(candidate.stat().st_size <= NupCatalog.MAX_MODULE_BYTES, "ExeFS module exceeds inspection size limit")
                files.append(describe_file(name, candidate.read_bytes(), verify_segments, decoder))
        require(any(item["name"] == "main" for item in files), "ExeFS directory has no main module")
        return {"format": "exefs", "files": files}
    with path.open("rb") as stream:
        magic = stream.read(4)
    if magic == b"NUP\x01":
        catalog = NupCatalog(path)
        require(package_index is not None or len(catalog.packages) == 1,
                "Multiple NUP packages found; choose one with --package INDEX")
        selected = 0 if package_index is None else package_index
        return {
            "format": "nup", "bytes": catalog.file_size, "catalog_sha256_verified": True,
            "catalog_file_count": catalog.file_count, "packages": catalog.packages,
            "selected_package": selected, "files": catalog.exefs_report(selected, verify_segments, decoder),
            "romfs_payloads_checked": False,
        }
    require(package_index is None, "--package applies only to NUP input")
    require(magic in (b"NSO0", b"META"), "Input is not a recognized NUP, NSO, or NPDM file")
    require(path.stat().st_size <= NupCatalog.MAX_MODULE_BYTES, "Input exceeds inspection size limit")
    return describe_file(path.name, path.read_bytes(), verify_segments, decoder)
