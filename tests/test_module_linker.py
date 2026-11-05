"""Synthetic MOD0, ELF symbol, RELA, and RELR fixtures."""

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from input_formats import InputError
from link_exefs import export_images, load_prepared
from module_linker import Linker, Module, U64
from prepare_exefs import prepare


def symbol(name, *, binding=1, kind=2, visibility=0, section=1, value=0x40, size=4):
    return name, binding, kind, visibility, section, value, size


def fixture(symbols=(), rela=(), relr=(), values=None, needed=(), init_array=False, gnu=False, plt=()):
    strings = bytearray(b"\0")
    encoded_symbols = bytearray(24)
    for name, binding, kind, visibility, section, value, size in symbols:
        offset = len(strings)
        strings += name.encode() + b"\0"
        encoded_symbols += struct.pack("<IBBHQQ", offset, (binding << 4) | kind, visibility, section, value, size)
    needed_offsets = []
    for name in needed:
        needed_offsets.append(len(strings))
        strings += name.encode() + b"\0"
    text, rodata, data = bytearray(256), bytearray(4096), bytearray(512)
    struct.pack_into("<I", text, 4, 0x80)
    text[0x80:0x84] = b"MOD0"
    struct.pack_into("<6i", text, 0x84, *[address - 0x80 for address in (0x1000, 0x2200, 0x2300, 0x1100, 0x1110, 0x2208)])
    rodata[0x200:0x200 + len(strings)] = strings
    rodata[0x400:0x400 + len(encoded_symbols)] = encoded_symbols
    dynamic = [(5, 0x1200), (10, len(strings)), (6, 0x1400), (11, 24), (12, 0x40)]
    dynamic += [(1, offset) for offset in needed_offsets]
    count = len(symbols) + 1
    if gnu:
        # Empty GNU buckets: all symbols precede the hashable-symbol range.
        struct.pack_into("<4IQI", rodata, 0xA00, 1, count, 1, 26, 0, 0)
        dynamic.append((0x6FFFFEF5, 0x1A00))
    else:
        struct.pack_into(f"<{3 + count}I", rodata, 0xA00, 1, count, *([0] * (count + 1)))
        dynamic.append((4, 0x1A00))
    if rela:
        rows = b"".join(struct.pack("<QQq", offset, (index << 32) | kind, addend) for offset, kind, index, addend in rela)
        rodata[0x600:0x600 + len(rows)] = rows
        dynamic += [(7, 0x1600), (8, len(rows)), (9, 24)]
    if relr:
        rows = struct.pack(f"<{len(relr)}Q", *relr)
        rodata[0x900:0x900 + len(rows)] = rows
        dynamic += [(36, 0x1900), (35, len(rows)), (37, 8)]
    if plt:
        rows = b"".join(struct.pack("<QQq", offset, (index << 32) | kind, addend) for offset, kind, index, addend in plt)
        rodata[0x800:0x800 + len(rows)] = rows
        dynamic += [(23, 0x1800), (2, len(rows)), (20, 7)]
    if init_array:
        dynamic += [(25, 0x20A0), (27, 8)]
    for offset, value in (values or {}).items():
        struct.pack_into("<Q", data, offset - 0x2000, value)
    table = b"".join(struct.pack("<qQ", tag, value) for tag, value in dynamic + [(0, 0)])
    rodata[:len(table)] = table
    header = bytearray(256)
    header[:4] = b"NSO0"
    struct.pack_into("<I", header, 12, 0x38)
    struct.pack_into("<I", header, 60, 4096)
    struct.pack_into("<4I", header, 144, 0x200, len(strings), 0x400, len(encoded_symbols))
    output = bytearray(header)
    for index, (address, content) in enumerate(((0, text), (0x1000, rodata), (0x2000, data))):
        struct.pack_into("<III", output, 16 + index * 16, len(output), address, len(content))
        struct.pack_into("<I", output, 96 + index * 4, len(content))
        output[160 + index * 32:192 + index * 32] = hashlib.sha256(content).digest()
        output += content
    return bytes(output)


def change_memory(raw, address, content):
    output = bytearray(raw)
    for index in range(3):
        offset, memory, size = struct.unpack_from("<III", raw, 16 + index * 16)
        if memory <= address and address + len(content) <= memory + size:
            output[offset + address - memory:offset + address - memory + len(content)] = content
            output[160 + index * 32:192 + index * 32] = hashlib.sha256(output[offset:offset + size]).digest()
            return bytes(output)
    raise AssertionError("fixture edit is out of bounds")


class MetadataTests(unittest.TestCase):
    def test_mod0_dynamic_symbols_and_needed_order(self):
        module = Module("main", fixture([symbol("export")], needed=("first", "second")))
        self.assertEqual(module.mod0["dynamic"], 0x1000)
        self.assertEqual(module.needed, ["first", "second"])
        self.assertEqual(module.symbols[1].name, "export")
        self.assertEqual(module.image[0x2200:0x3200], bytes(4096))

    def test_signed_mod0_offsets(self):
        raw = fixture()
        raw = change_memory(raw, 0x90, struct.pack("<i", 0x40 - 0x80))
        raw = change_memory(raw, 0x94, struct.pack("<i", 0x50 - 0x80))
        self.assertEqual(Module("main", raw).mod0["exception_start"], 0x40)

    def test_bad_mod0_signature(self):
        with self.assertRaisesRegex(InputError, "MOD0"):
            Module("main", change_memory(fixture(), 0x80, b"bad!"))

    def test_bad_mod0_pointer(self):
        with self.assertRaisesRegex(InputError, "not mapped"):
            Module("main", change_memory(fixture(), 4, struct.pack("<I", 0xFFFFFFF0)))

    def test_bss_disagreement(self):
        with self.assertRaisesRegex(InputError, "BSS"):
            Module("main", change_memory(fixture(), 0x88, struct.pack("<i", 0x2100 - 0x80)))

    def test_symbol_entry_size(self):
        with self.assertRaisesRegex(InputError, "symbol entry size"):
            Module("main", change_memory(fixture(), 0x1038, struct.pack("<Q", 16)))

    def test_invalid_symbol_string(self):
        raw = fixture([symbol("name")])
        with self.assertRaisesRegex(InputError, "string offset"):
            Module("main", change_memory(raw, 0x1418, struct.pack("<I", 0xFFFFFF)))

    def test_gnu_hash_fallback(self):
        raw = bytearray(fixture([symbol("name")], gnu=True))
        struct.pack_into("<I", raw, 156, 0)
        self.assertEqual(len(Module("main", raw).symbols), 2)

    def test_gnu_hash_nonempty_chain(self):
        raw = bytearray(fixture([symbol("name")], gnu=True))
        struct.pack_into("<I", raw, 156, 0)
        raw = change_memory(raw, 0x1A00, struct.pack("<4IQII", 1, 1, 1, 26, 0, 1, 1))
        self.assertEqual(len(Module("main", raw).symbols), 2)

    def test_conflicting_symbol_counts(self):
        raw = fixture([symbol("name")])
        with self.assertRaisesRegex(InputError, "conflicting"):
            Module("main", change_memory(raw, 0x1A04, struct.pack("<I", 3)))

    def test_image_budget(self):
        with self.assertRaisesRegex(InputError, "size limit"):
            Module("main", fixture(), image_budget=4096)

    def test_duplicate_dynamic_tag(self):
        with self.assertRaisesRegex(InputError, "duplicate dynamic"):
            Module("main", change_memory(fixture(), 0x1010, struct.pack("<q", 5)))


class RelocationTests(unittest.TestCase):
    def test_rela_relative_and_negative_addend(self):
        module = Module("main", fixture(rela=((0x2000, 1027, 0, 0x40), (0x2008, 257, 0, -1))))
        result = Linker([module]).apply()
        self.assertTrue(result["link_complete"])
        self.assertEqual(module.unpack("<Q", 0x2000)[0], module.base + 0x40)
        self.assertEqual(module.unpack("<Q", 0x2008)[0], U64)

    def test_relr_address_and_bitmap(self):
        values = {0x2000: 0x40, 0x2008: 0x50, 0x2018: 0x60}
        module = Module("main", fixture(relr=(0x2000, 0b1011), values=values))
        result = Linker([module]).apply()
        self.assertEqual(result["applied_relocations"], 3)
        for address, original in values.items():
            self.assertEqual(module.unpack("<Q", address)[0], module.base + original)
        self.assertEqual(module.unpack("<Q", 0x2010)[0], 0)

    def test_relr_bitmap_without_address(self):
        with self.assertRaisesRegex(InputError, "bitmap before"):
            Linker([Module("main", fixture(relr=(3,)))]).apply()

    def test_symbol_resolution_across_modules(self):
        caller = Module("main", fixture([symbol("function", section=0, value=0, size=0)],
                                         rela=((0x2000, 257, 1, 4), (0x2008, 1025, 1, 0), (0x2010, 1026, 1, 0))))
        provider = Module("sdk", fixture([symbol("function")]))
        result = Linker([caller, provider]).apply()
        self.assertTrue(result["link_complete"])
        self.assertEqual(caller.unpack("<3Q", 0x2000), (provider.base + 0x44, provider.base + 0x40, provider.base + 0x40))

    def test_plt_relocation_table(self):
        caller = Module("main", fixture([symbol("function", section=0, value=0, size=0)], plt=((0x2000, 1026, 1, 0),)))
        provider = Module("sdk", fixture([symbol("function")]))
        self.assertTrue(Linker([caller, provider]).apply()["link_complete"])
        self.assertEqual(caller.unpack("<Q", 0x2000)[0], provider.base + 0x40)

    def test_absolute_symbol(self):
        module = Module("main", fixture([symbol("absolute", section=0xFFF1, value=1234, size=0)],
                                         rela=((0x2000, 257, 1, 8),)))
        Linker([module]).apply()
        self.assertEqual(module.unpack("<Q", 0x2000)[0], 1242)

    def test_unresolved_strong_is_not_stubbed(self):
        module = Module("main", fixture([symbol("missing", section=0, value=0, size=0)],
                                         rela=((0x2000, 1026, 1, 0),), values={0x2000: 1234}))
        result = Linker([module]).apply()
        self.assertFalse(result["link_complete"])
        self.assertEqual(result["unresolved_strong_relocations"], 1)
        self.assertEqual(module.unpack("<Q", 0x2000)[0], 1234)

    def test_unresolved_weak_uses_zero_plus_addend(self):
        module = Module("main", fixture([symbol("optional", binding=2, section=0, value=0, size=0)],
                                         rela=((0x2000, 257, 1, 17),)))
        self.assertTrue(Linker([module]).apply()["link_complete"])
        self.assertEqual(module.unpack("<Q", 0x2000)[0], 17)

    def test_strong_definition_preferred_to_weak(self):
        caller = Module("main", fixture([symbol("pick", section=0, value=0, size=0)], rela=((0x2000, 257, 1, 0),)))
        weak = Module("weak", fixture([symbol("pick", binding=2)]))
        strong = Module("strong", fixture([symbol("pick")]))
        Linker([caller, weak, strong]).apply()
        self.assertEqual(caller.unpack("<Q", 0x2000)[0], strong.base + 0x40)

    def test_protected_symbol_binds_to_self(self):
        first = Module("first", fixture([symbol("protected")]))
        own = Module("own", fixture([symbol("protected", visibility=3)], rela=((0x2000, 257, 1, 0),)))
        Linker([first, own]).apply()
        self.assertEqual(own.unpack("<Q", 0x2000)[0], own.base + 0x40)

    def test_local_symbol_binds_to_self(self):
        first = Module("first", fixture([symbol("local")]))
        own = Module("own", fixture([symbol("local", binding=0)], rela=((0x2000, 257, 1, 0),)))
        Linker([first, own]).apply()
        self.assertEqual(own.unpack("<Q", 0x2000)[0], own.base + 0x40)

    def test_hidden_symbol_is_not_exported(self):
        caller = Module("main", fixture([symbol("hidden", section=0, value=0, size=0)], rela=((0x2000, 257, 1, 0),)))
        provider = Module("sdk", fixture([symbol("hidden", visibility=2)]))
        self.assertFalse(Linker([caller, provider]).apply()["link_complete"])

    def test_text_write_rejected(self):
        with self.assertRaisesRegex(InputError, "writable"):
            Linker([Module("main", fixture(rela=((0x40, 1027, 0, 0),)))]).apply()

    def test_duplicate_write_rejected(self):
        module = Module("main", fixture(rela=((0x2000, 1027, 0, 0),), relr=(0x2000,)))
        linker = Linker([module])
        with self.assertRaisesRegex(InputError, "overlapping"):
            linker.apply()
        self.assertFalse(linker.report()["relocation_pass_completed"])

    def test_unresolved_write_overlap_rejected(self):
        module = Module("main", fixture([symbol("missing", section=0, value=0, size=0)],
                                         rela=((0x2000, 257, 1, 0), (0x2000, 1027, 0, 0))))
        with self.assertRaisesRegex(InputError, "overlapping"):
            Linker([module]).apply()

    def test_relocation_into_bss(self):
        module = Module("main", fixture(rela=((0x2200, 1027, 0, 0x40),)))
        Linker([module]).apply()
        self.assertEqual(module.unpack("<Q", 0x2200, memory=True)[0], module.base + 0x40)

    def test_symbol_in_unmapped_gap(self):
        module = Module("main", fixture([symbol("gap", value=0x800)], rela=((0x2000, 257, 1, 0),)))
        with self.assertRaisesRegex(InputError, "not mapped"):
            Linker([module]).apply()

    def test_unsupported_relocation(self):
        with self.assertRaisesRegex(InputError, "unsupported relocation"):
            Linker([Module("main", fixture(rela=((0x2000, 1032, 0, 0),)))]).apply()

    def test_symbol_index_out_of_bounds(self):
        with self.assertRaisesRegex(InputError, "symbol index"):
            Linker([Module("main", fixture(rela=((0x2000, 257, 999, 0),)))]).apply()

    def test_abs32_overflow(self):
        module = Module("main", fixture([symbol("pointer")], rela=((0x2000, 258, 1, 0),)))
        with self.assertRaisesRegex(InputError, "ABS32"):
            Linker([module]).apply()

    def test_abs32_at_low_base(self):
        module = Module("main", fixture([symbol("pointer")], rela=((0x2000, 258, 1, 0),)))
        Linker([module], base=0x200000).apply()
        self.assertEqual(module.unpack("<I", 0x2000)[0], module.base + 0x40)

    def test_constructor_targets_checked_after_relocation(self):
        module = Module("main", fixture(rela=((0x20A0, 1027, 0, 0x40),), init_array=True))
        self.assertTrue(Linker([module]).apply()["link_complete"])
        invalid = Module("main", fixture(rela=((0x20A0, 1027, 0, 0x1200),), init_array=True))
        self.assertFalse(Linker([invalid]).apply()["link_complete"])

    def test_second_apply_rejected(self):
        linker = Linker([Module("main", fixture())])
        linker.apply()
        with self.assertRaisesRegex(InputError, "already"):
            linker.apply()

    def test_layout_address_limit(self):
        with self.assertRaisesRegex(InputError, "39-bit"):
            Linker([Module("main", fixture())], base=1 << 39)


class FileTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "build").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / "build")
        self.root = Path(self.temporary.name)
        source = self.root / "source"
        source.mkdir()
        (source / "main").write_bytes(fixture(rela=((0x2000, 1027, 0, 0x40),)))
        self.prepared = self.root / "prepared"
        prepare(source, self.prepared)

    def tearDown(self):
        self.temporary.cleanup()

    def test_export_and_input_preserved(self):
        before = (self.prepared / "main").read_bytes()
        linker = Linker(load_prepared(self.prepared))
        result = linker.apply()
        destination = self.root / "images"
        export_images(linker, result, destination)
        exported = (destination / "main.image.bin").read_bytes()
        self.assertEqual(hashlib.sha256(exported).hexdigest(), result["modules"][0]["image_sha256"])
        self.assertEqual(before, (self.prepared / "main").read_bytes())
        self.assertEqual(json.loads((destination / "manifest.json").read_text()), result)

    def test_tampered_prepared_file(self):
        with (self.prepared / "main").open("ab") as stream:
            stream.write(b"bad")
        with self.assertRaisesRegex(InputError, "size mismatch"):
            load_prepared(self.prepared)

    def test_prepared_file_hash_mismatch(self):
        path = self.prepared / "main"
        raw = bytearray(path.read_bytes())
        raw[-1] ^= 1
        path.write_bytes(raw)
        with self.assertRaisesRegex(InputError, "SHA-256 mismatch"):
            load_prepared(self.prepared)

    def test_incomplete_images_are_not_exported(self):
        module = Module("main", fixture([symbol("missing", section=0, value=0, size=0)], rela=((0x2000, 257, 1, 0),)))
        linker = Linker([module])
        result = linker.apply()
        with self.assertRaisesRegex(InputError, "Incomplete link"):
            export_images(linker, result, self.root / "images")
        self.assertFalse((self.root / "images").exists())

    def test_export_outside_build_rejected(self):
        linker = Linker(load_prepared(self.prepared))
        result = linker.apply()
        with self.assertRaisesRegex(InputError, "Output must"):
            export_images(linker, result, ROOT / "images")

    def test_cli_success_and_report(self):
        report_path = self.root / "report.json"
        result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/link_exefs.py"), str(self.prepared),
                                 "--report", str(report_path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(report_path.read_text())["link_complete"])
        self.assertFalse(json.loads(result.stdout)["guest_code_executed"])


if __name__ == "__main__":
    unittest.main()
