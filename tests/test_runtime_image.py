"""Verified synthetic linked images, native map permissions, and package rejection."""

from ctypes import POINTER, byref, c_char_p, c_int, c_size_t, c_uint64, c_void_p, create_string_buffer, string_at
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from input_formats import InputError
from lifter_validation import compile_library
from lifter_validation_types import BASE, Memory, Program, State
from module_linker import Linker, Module
from pair_validation import pair
from prepare_exefs import prepare
from prepare_runtime import HEADER, REGION, STACK_BASE, STACK_SIZE, make_package, write_package
from test_module_linker import fixture, symbol

HOST = Path(os.environ.get("OOT_NATIVE_HOST", str(ROOT / "build/cmake/Release/oot-pc-port.exe")))


def linked_fixture(bss_relocation=True):
    relocations = [(0x2000, 1027, 0, 0x40)]
    if bss_relocation:
        relocations.append((0x2200, 1027, 0, 0x44))
    module = Module("main", fixture(rela=relocations))
    linker = Linker([module])
    assert linker.apply()["link_complete"]
    return linker


def reseal(data):
    data[64:96] = hashlib.sha256(data[HEADER.size:]).digest()
    return bytes(data)


class PackageTests(unittest.TestCase):
    def test_layout_permissions_digest_and_relocated_bss(self):
        linker = linked_fixture()
        original = bytes(linker.modules[0].image)
        data, report = make_package(linker)
        header = HEADER.unpack_from(data)
        self.assertEqual((header[0], header[1], header[2], header[3]), (b"OOTMEM1\0", 1, 5, STACK_BASE + STACK_SIZE))
        self.assertEqual(header[-1], hashlib.sha256(data[HEADER.size:]).digest())
        self.assertEqual(header[-3], len(data))
        self.assertEqual([r["permissions"] for r in report["regions"]], ["r", "r", "rw", "rw", "rw"])
        bss = REGION.unpack_from(data, HEADER.size + 3 * REGION.size)
        self.assertEqual(bss[3], bss[1])
        self.assertEqual(struct.unpack_from("<Q", data, bss[2])[0], linker.modules[0].base + 0x44)
        self.assertEqual(bytes(linker.modules[0].image), original)
        self.assertFalse(report["guest_code_executed"])

    def test_zero_bss_omits_payload_but_retains_backing(self):
        data, report = make_package(linked_fixture(False))
        bss = REGION.unpack_from(data, HEADER.size + 3 * REGION.size)
        self.assertEqual((bss[1], bss[3]), (4096, 0))
        self.assertEqual(report["regions"][-1]["payload_bytes"], 0)

    def test_incomplete_link_is_rejected(self):
        linker = Linker([Module("main", fixture(symbols=[symbol("missing", section=0)], rela=[(0x2000, 1025, 1, 0)]))])
        linker.apply()
        with self.assertRaisesRegex(InputError, "complete offline link"):
            make_package(linker)

    def test_stack_bounds_alignment_guards_and_overlap(self):
        linker = linked_fixture()
        for base, size in ((STACK_BASE + 1, 4096), (STACK_BASE, 1), (0, 4096),
                           (1 << 39, 4096), (STACK_BASE, 128 * 1024 * 1024),
                           (linker.modules[0].base + 0x4000, 4096)):
            with self.subTest(base=base, size=size), self.assertRaises(InputError):
                make_package(linker, base, size)

    def test_write_requires_fresh_build_output(self):
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            output = Path(temporary) / "image.ootmem"
            write_package(linked_fixture(), output)
            before = output.read_bytes()
            with self.assertRaises(InputError):
                write_package(linked_fixture(), output)
            self.assertEqual(output.read_bytes(), before)
        with self.assertRaises(InputError):
            write_package(linked_fixture(), ROOT / "never-write.ootmem")

    def test_prepared_input_cli_preserves_sources(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            folder = Path(temporary)
            source, prepared, output, report = folder / "main", folder / "prepared", folder / "test.ootmem", folder / "test.json"
            source.write_bytes(fixture(rela=[(0x2000, 1027, 0, 0x40)]))
            prepare(source, prepared)
            before = {p.name: p.read_bytes() for p in prepared.iterdir()}
            result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/prepare_runtime.py"), str(prepared),
                                     "--output", str(output), "--report", str(report)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)["guest_code_executed"])
            self.assertTrue(json.loads(report.read_text())["offline_link"]["link_complete"])
            self.assertEqual({p.name: p.read_bytes() for p in prepared.iterdir()}, before)


@unittest.skipUnless(os.name == "nt" and HOST.is_file(), "build the native Windows host for runtime bridge tests")
class NativeRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Independently generated stack program only, not an extracted function.
        words = [pair(2, False, 29, 30, 31, 3, -2), 0x910003FD, 0xD280001E, pair(2, True, 29, 30, 31, 1, 2)]
        cls.library, cls.build = compile_library([Program("bridge_stack", words, [])], os.environ.get("OOT_LIFTER_COMPILER", "cmake"))
        lib = cls.library
        lib.oot_runtime_open.argtypes = [c_char_p, c_char_p, c_size_t]
        lib.oot_runtime_open.restype = c_void_p
        lib.oot_runtime_close.argtypes = [c_void_p]
        lib.oot_runtime_close.restype = None
        lib.oot_runtime_memory.argtypes = [c_void_p]
        lib.oot_runtime_memory.restype = POINTER(Memory)
        lib.oot_runtime_stack_pointer.argtypes = [c_void_p]
        lib.oot_runtime_stack_pointer.restype = c_uint64
        lib.oot_runtime_backing_bytes.argtypes = [c_void_p]
        lib.oot_runtime_backing_bytes.restype = c_uint64
        lib.oot_memory_load.argtypes = [POINTER(Memory), c_uint64, c_int, POINTER(c_uint64)]
        lib.oot_memory_store.argtypes = [POINTER(Memory), c_uint64, c_int, c_uint64]
        lib.oot_lift_bridge_stack.argtypes = [POINTER(State), POINTER(Memory), c_uint64, POINTER(c_uint64)]
        lib.oot_lift_bridge_stack.restype = c_int

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / "build")
        self.path = Path(self.temporary.name) / "image.ootmem"

    def tearDown(self):
        self.temporary.cleanup()

    def open_blob(self, data):
        self.path.write_bytes(data)
        error = create_string_buffer(192)
        handle = self.library.oot_runtime_open(os.fsencode(self.path), error, len(error))
        return handle, error.value.decode()

    def test_native_bytes_relocations_bss_permissions_and_guard_pages(self):
        linker = linked_fixture()
        data, report = make_package(linker)
        handle, error = self.open_blob(data)
        self.assertTrue(handle, error)
        try:
            memory = self.library.oot_runtime_memory(handle)
            self.assertEqual(memory.contents.count, len(report["regions"]))
            self.assertEqual(self.library.oot_runtime_backing_bytes(handle), report["backing_bytes"])
            module = linker.modules[0]
            for index, record in enumerate(report["regions"]):
                region = memory.contents.regions[index]
                expected = (b"\0" * region.size if record["kind"] == "stack" else
                            bytes(module.image[region.base - module.base:region.base - module.base + region.size]))
                self.assertEqual(string_at(region.data, region.size), expected)
            value = c_uint64()
            self.assertEqual(self.library.oot_memory_load(memory, module.base + 0x2000, 8, byref(value)), 1)
            self.assertEqual(value.value, module.base + 0x40)
            self.assertEqual(self.library.oot_memory_load(memory, module.base + 0x2200, 8, byref(value)), 1)
            self.assertEqual(value.value, module.base + 0x44)
            for address in (module.base, module.base + 0x1000):
                self.assertEqual(self.library.oot_memory_store(memory, address, 8, 0), 0)
                self.assertEqual(memory.contents.fault.reason, 2)
            for address in (module.base + 0x100, STACK_BASE - 1, STACK_BASE + STACK_SIZE):
                self.assertEqual(self.library.oot_memory_load(memory, address, 1, byref(value)), 0)
                self.assertEqual(memory.contents.fault.reason, 1)
            self.assertEqual(self.library.oot_memory_store(memory, module.base + 0x2008, 8, 0x1234), 1)
            self.assertEqual(self.library.oot_memory_load(memory, module.base + 0x2008, 8, byref(value)), 1)
            self.assertEqual(value.value, 0x1234)
        finally:
            self.library.oot_runtime_close(handle)

    def test_generated_pair_stack_program_uses_loaded_native_stack(self):
        handle, error = self.open_blob(make_package(linked_fixture())[0])
        self.assertTrue(handle, error)
        try:
            memory, state, retired = self.library.oot_runtime_memory(handle), State(), c_uint64()
            state.pc, state.sp, state.nzcv = BASE, self.library.oot_runtime_stack_pointer(handle), 0xA0000000
            state.x[29], state.x[30] = 0x1122334455667788, 0xFFEEDDCCBBAA9988
            self.assertEqual(self.library.oot_lift_bridge_stack(byref(state), memory, 16, byref(retired)), 0)
            self.assertEqual((retired.value, state.pc, state.sp, state.nzcv), (4, BASE + 16, STACK_BASE + STACK_SIZE, 0xA0000000))
            self.assertEqual((state.x[29], state.x[30]), (0x1122334455667788, 0xFFEEDDCCBBAA9988))
            value = c_uint64()
            self.assertEqual(self.library.oot_memory_load(memory, state.sp - 16, 8, byref(value)), 1)
            self.assertEqual(value.value, state.x[29])
        finally:
            self.library.oot_runtime_close(handle)

    def test_native_zero_bss_and_zero_stack(self):
        handle, error = self.open_blob(make_package(linked_fixture(False))[0])
        self.assertTrue(handle, error)
        try:
            memory = self.library.oot_runtime_memory(handle).contents
            for index in (3, 4):
                region = memory.regions[index]
                self.assertEqual(string_at(region.data, region.size), b"\0" * region.size)
        finally:
            self.library.oot_runtime_close(handle)

    def test_native_rejects_corrupt_metadata_ranges_payload_and_checksum(self):
        original = make_package(linked_fixture())[0]
        first_base = REGION.unpack_from(original, HEADER.size)[0]
        changes = [(0, b"BROKEN!!"), (8, struct.pack("<I", 2)), (12, struct.pack("<I", 65)),
                   (16, struct.pack("<Q", STACK_BASE)), (24, struct.pack("<Q", 1)),
                   (32, struct.pack("<Q", 97)), (40, struct.pack("<Q", 1)), (56, struct.pack("<Q", 1)),
                   (HEADER.size + 32, struct.pack("<I", 3)), (HEADER.size + 36, struct.pack("<I", 6)),
                   (HEADER.size + 16, struct.pack("<Q", 0)),
                   (HEADER.size, struct.pack("<Q", 1 << 39)),
                   (HEADER.size + 8, struct.pack("<Q", 513 * 1024 * 1024)),
                   (HEADER.size + 24, struct.pack("<Q", 1)),
                   (HEADER.size + REGION.size, struct.pack("<Q", first_base)),
                   (HEADER.size + 4 * REGION.size + 40, b"wrong\0")]
        for offset, replacement in changes:
            with self.subTest(offset=offset):
                changed = bytearray(original)
                changed[offset:offset + len(replacement)] = replacement
                handle, error = self.open_blob(reseal(changed))
                if handle:
                    self.library.oot_runtime_close(handle)
                self.assertFalse(handle, f"accepted malformed field at {offset}")
                self.assertTrue(error)
        changed = bytearray(original)
        changed[-1] ^= 1
        handle, error = self.open_blob(changed)
        self.assertFalse(handle)
        self.assertIn("SHA-256", error)
        for data in (b"", original[:80], original[:-1], original + b"extra"):
            handle, error = self.open_blob(data)
            self.assertFalse(handle)

    def test_mapping_cli_reports_no_guest_execution_and_preserves_package(self):
        data = make_package(linked_fixture())[0]
        self.path.write_bytes(data)
        result = subprocess.run([str(HOST), "--map-images", str(self.path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["regions"], 5)
        self.assertFalse(report["guest_code_executed"])
        self.assertFalse(report["native_guest_addresses_reserved"])
        self.assertEqual(self.path.read_bytes(), data)
        self.path.write_bytes(b"bad")
        self.assertNotEqual(subprocess.run([str(HOST), "--map-images", str(self.path)], capture_output=True).returncode, 0)

    def test_null_accessors(self):
        self.assertFalse(self.library.oot_runtime_memory(None))
        self.assertEqual(self.library.oot_runtime_stack_pointer(None), 0)
        self.library.oot_runtime_close(None)


if __name__ == "__main__":
    unittest.main()
