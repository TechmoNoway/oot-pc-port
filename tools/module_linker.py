"""Offline MOD0 parsing and AArch64 relocation in private, non-executable images."""

from collections import Counter
from dataclasses import dataclass
import hashlib
import struct

from input_formats import InputError, inspect_nso, require
from nso_segments import MAX_DECODED_MODULE, decode_nso

PAGE = 4096
MAX_SYMBOLS = 1_000_000
MAX_RELOCATIONS = 2_000_000
U64 = (1 << 64) - 1
RELOCATION_NAMES = {0: "NONE", 257: "ABS64", 258: "ABS32", 1025: "GLOB_DAT", 1026: "JUMP_SLOT", 1027: "RELATIVE"}


def align(value, alignment):
    return (value + alignment - 1) & -alignment


@dataclass(frozen=True)
class Symbol:
    name: str
    binding: int
    kind: int
    visibility: int
    section: int
    value: int
    size: int


class Module:
    def __init__(self, name: str, raw: bytes, image_budget=MAX_DECODED_MODULE):
        self.name = name
        self.header = inspect_nso(raw)
        require(all(segment["compression"] == "none" for segment in self.header["segments"]),
                f"{name}: use prepared, uncompressed NSO input")
        require(self.header["segments"][0]["memory_offset"] == 0, f"{name}: unsupported nonzero text memory offset")
        size = align(self.header["image_size"], PAGE)
        require(0 < size <= min(MAX_DECODED_MODULE, image_budget), f"{name}: module image exceeds size limit")
        decoded, self.header = decode_nso(raw)
        self.image = bytearray(size)
        self.base = 0
        self.source_sha256 = hashlib.sha256(raw).hexdigest()
        self.ranges = []
        for content, segment in zip(decoded, self.header["segments"]):
            offset = segment["memory_offset"]
            self.image[offset:offset + len(content)] = content
            self.ranges.append((offset, offset + len(content)))
        data = self.header["segments"][2]
        self.writable_start = data["memory_offset"]
        self.bss_start = self.writable_start + data["memory_size"]
        self.bss_end = self.bss_start + self.header["bss_size"]
        self.touched = set()
        self.counts = Counter()
        self.bindings = Counter()
        self.unresolved = Counter()
        self.weak_zero = Counter()
        self.samples = []
        self.parse_mod0()
        self.parse_dynamic()
        self.parse_symbols(raw)
        self.parse_relocations()
        self.parse_initializers()

    def check_range(self, offset, size, *, memory=False):
        valid = 0 <= offset <= len(self.image) and 0 <= size <= len(self.image) - offset
        if valid and size:
            valid = any(begin <= offset and offset + size <= end for begin, end in self.ranges)
            if memory:
                valid |= self.writable_start <= offset and offset + size <= self.bss_end
        require(valid, f"{self.name}: range {offset:#x}+{size:#x} is not mapped")

    def read(self, offset, size):
        self.check_range(offset, size)
        return bytes(self.image[offset:offset + size])

    def unpack(self, fmt, offset, *, memory=False):
        self.check_range(offset, struct.calcsize(fmt), memory=memory)
        return struct.unpack_from(fmt, self.image, offset)

    def parse_mod0(self):
        offset = self.unpack("<I", 4)[0]
        require(self.read(offset, 4) == b"MOD0", f"{self.name}: invalid MOD0 signature")
        fields = self.unpack("<6i", offset + 4)
        names = ("dynamic", "bss_start", "bss_end", "exception_start", "exception_end", "module_object")
        self.mod0 = {"offset": offset, **{key: offset + value for key, value in zip(names, fields)}}
        require(self.bss_start <= self.mod0["bss_start"] <= self.mod0["bss_end"] <= self.bss_end,
                f"{self.name}: MOD0 BSS disagrees with NSO BSS")
        begin, end = self.mod0["exception_start"], self.mod0["exception_end"]
        require(begin <= end, f"{self.name}: reversed exception range")
        self.check_range(begin, end - begin)
        self.check_range(self.mod0["module_object"], 8, memory=True)

    def parse_dynamic(self):
        self.dynamic, self.needed_offsets = {}, []
        for index in range(4096):
            tag, value = self.unpack("<qQ", self.mod0["dynamic"] + index * 16)
            if tag == 0:
                break
            if tag == 1:
                self.needed_offsets.append(value)
            else:
                require(tag not in self.dynamic, f"{self.name}: duplicate dynamic tag {tag:#x}")
                self.dynamic[tag] = value
        else:
            raise InputError(f"{self.name}: dynamic table has no terminator")
        require(not self.dynamic.get(18, 0), f"{self.name}: DT_REL is not supported")
        require(not any(tag in self.dynamic for tag in (0x6FFFFFF0, 0x6FFFFFFC, 0x6FFFFFFE)),
                f"{self.name}: symbol versioning is not supported")
        for tag in (5, 6, 10, 11):
            require(tag in self.dynamic, f"{self.name}: missing dynamic tag {tag:#x}")
        require(self.dynamic[11] == 24, f"{self.name}: unsupported symbol entry size")
        require(0 < self.dynamic[10] <= 64 * 1024 * 1024, f"{self.name}: invalid dynamic string table size")
        self.strings = self.read(self.dynamic[5], self.dynamic[10])
        require(self.strings[0] == 0, f"{self.name}: dynamic string table has no empty first entry")
        self.string_cache = {}
        self.needed = [self.string(offset) for offset in self.needed_offsets]
        self.soname = self.string(self.dynamic[14]) if 14 in self.dynamic else None
        self.symbolic = 16 in self.dynamic or bool(self.dynamic.get(30, 0) & 2)

    def string(self, offset):
        if offset in self.string_cache:
            return self.string_cache[offset]
        require(0 <= offset < len(self.strings), f"{self.name}: string offset exceeds dynamic strings")
        end = self.strings.find(b"\0", offset, min(offset + 16385, len(self.strings)))
        require(end >= 0, f"{self.name}: unterminated or excessive dynamic string")
        value = self.strings[offset:end].decode("utf-8")
        self.string_cache[offset] = value
        return value

    def gnu_symbol_count(self):
        address = self.dynamic[0x6FFFFEF5]
        buckets, first_symbol, bloom_words, _ = self.unpack("<4I", address)
        require(0 < buckets <= MAX_SYMBOLS and 0 < bloom_words <= MAX_SYMBOLS,
                f"{self.name}: invalid GNU hash table size")
        require(bloom_words & (bloom_words - 1) == 0, f"{self.name}: invalid GNU bloom size")
        start = address + 16 + bloom_words * 8
        self.check_range(address, 16 + bloom_words * 8 + buckets * 4)
        values = struct.unpack(f"<{buckets}I", self.read(start, buckets * 4))
        require(first_symbol <= MAX_SYMBOLS and all(value == 0 or first_symbol <= value < MAX_SYMBOLS for value in values),
                f"{self.name}: invalid GNU hash bucket")
        last = max(values)
        if last == 0:
            return first_symbol
        chains = start + buckets * 4
        for symbol in range(last, MAX_SYMBOLS):
            chain = self.unpack("<I", chains + (symbol - first_symbol) * 4)[0]
            if chain & 1:
                return symbol + 1
        raise InputError(f"{self.name}: GNU hash chain exceeds symbol limit")

    def parse_symbols(self, raw):
        candidates = []
        rodata = self.header["segments"][1]["memory_offset"]
        string_offset, string_size, symbol_offset, symbol_size = struct.unpack_from("<4I", raw, 144)
        if symbol_size:
            require(rodata + symbol_offset == self.dynamic[6] and symbol_size % 24 == 0,
                    f"{self.name}: NSO dynamic symbol range mismatch")
            candidates.append(symbol_size // 24)
        if string_size:
            require(rodata + string_offset == self.dynamic[5] and string_size == len(self.strings),
                    f"{self.name}: NSO dynamic string range mismatch")
        if 39 in self.dynamic:
            require(self.dynamic[39] % 24 == 0, f"{self.name}: invalid DT_SYMTABSZ")
            candidates.append(self.dynamic[39] // 24)
        if 4 in self.dynamic:
            buckets, symbols = self.unpack("<II", self.dynamic[4])
            require(buckets <= MAX_SYMBOLS and symbols <= MAX_SYMBOLS, f"{self.name}: excessive SysV hash table")
            self.check_range(self.dynamic[4], 8 + 4 * (buckets + symbols))
            candidates.append(symbols)
        gnu_count = self.gnu_symbol_count() if 0x6FFFFEF5 in self.dynamic else None
        if candidates:
            require(len(set(candidates)) == 1, f"{self.name}: conflicting dynamic symbol counts")
            count = candidates[0]
            require(gnu_count is None or gnu_count <= count, f"{self.name}: GNU hash exceeds symbol table")
        else:
            require(gnu_count is not None, f"{self.name}: no bounded dynamic symbol count")
            count = gnu_count
        require(0 < count <= MAX_SYMBOLS, f"{self.name}: invalid dynamic symbol count")
        table = self.read(self.dynamic[6], count * 24)
        self.symbols = []
        for name, info, other, section, value, size in struct.iter_unpack("<IBBHQQ", table):
            self.symbols.append(Symbol(self.string(name), info >> 4, info & 15, other & 3, section, value, size))
        require(self.symbols[0] == Symbol("", 0, 0, 0, 0, 0, 0), f"{self.name}: invalid null symbol")

    def parse_relocations(self):
        self.rela = []
        self.relr = b""
        for pointer, size_tag, entry_tag, label in ((7, 8, 9, "rela"), (23, 2, 20, "plt")):
            size = self.dynamic.get(size_tag, 0)
            if pointer in self.dynamic or size:
                require(pointer in self.dynamic and size_tag in self.dynamic, f"{self.name}: incomplete {label} tags")
                require(self.dynamic.get(entry_tag) == (24 if label == "rela" else 7),
                        f"{self.name}: unsupported {label} relocation format")
                require(size % 24 == 0 and size // 24 <= MAX_RELOCATIONS, f"{self.name}: invalid relocation table size")
                self.rela.append((label, self.read(self.dynamic[pointer], size)))
        if 36 in self.dynamic or self.dynamic.get(35, 0):
            require(all(tag in self.dynamic for tag in (35, 36, 37)) and self.dynamic[37] == 8,
                    f"{self.name}: incomplete or unsupported RELR tags")
            require(self.dynamic[35] % 8 == 0 and self.dynamic[35] // 8 <= MAX_RELOCATIONS,
                    f"{self.name}: invalid RELR table size")
            self.relr = self.read(self.dynamic[36], self.dynamic[35])

    def parse_initializers(self):
        self.initializer_tables = {}
        for pointer, size_tag, name in ((25, 27, "init"), (26, 28, "fini")):
            if pointer in self.dynamic or self.dynamic.get(size_tag, 0):
                require(pointer in self.dynamic and size_tag in self.dynamic and self.dynamic[size_tag] % 8 == 0,
                        f"{self.name}: invalid {name} array metadata")
                require(self.dynamic[size_tag] // 8 <= MAX_SYMBOLS, f"{self.name}: excessive {name} array size")
                self.check_range(self.dynamic[pointer], self.dynamic[size_tag])
                self.initializer_tables[name] = (self.dynamic[pointer], self.dynamic[size_tag] // 8)
        for tag in (12, 13):
            if self.dynamic.get(tag):
                require(self.is_code(self.dynamic[tag]), f"{self.name}: initializer function is not in text")

    def is_code(self, offset):
        text = self.header["segments"][0]
        return offset % 4 == 0 and text["memory_offset"] <= offset < text["memory_offset"] + text["memory_size"]

    def claim_relocation(self, offset, size):
        require(offset % size == 0 and self.writable_start <= offset and offset + size <= self.bss_end,
                f"{self.name}: relocation write {offset:#x} is not aligned writable data/BSS")
        slots = tuple(range(offset // 4, (offset + size) // 4))
        require(not any(slot in self.touched for slot in slots), f"{self.name}: overlapping relocation writes")
        self.touched.update(slots)
        require(len(self.touched) <= MAX_RELOCATIONS * 2, f"{self.name}: excessive expanded relocation count")

    def write_relocation(self, offset, size, value, label):
        self.claim_relocation(offset, size)
        self.image[offset:offset + size] = (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")
        self.counts[label] += 1
        if len(self.samples) < 16:
            self.samples.append({"offset": offset, "kind": label, "value": f"0x{value & U64:x}"})


class Linker:
    def __init__(self, modules, base=0x100000000, alignment=0x200000):
        require(bool(modules) and len({module.name for module in modules}) == len(modules), "Duplicate or empty module scope")
        require(PAGE <= alignment <= 0x40000000 and alignment & (alignment - 1) == 0,
                "Module alignment must be a power of two between 4 KiB and 1 GiB")
        require(base >= 0 and base % alignment == 0, "Module base must be nonnegative and aligned")
        require(sum(len(module.image) for module in modules) <= 512 * 1024 * 1024, "Module images exceed total size limit")
        self.modules = modules
        self.started = False
        self.applied = False
        cursor = base
        for module in modules:
            module.base = cursor
            cursor = align(cursor + len(module.image), alignment)
            require(cursor <= 1 << 39, "Module layout exceeds the supported 39-bit guest address space")
        self.exports = {}
        for module in modules:
            for symbol in module.symbols:
                if symbol.name and symbol.section and symbol.binding in (1, 2) and symbol.visibility in (0, 3):
                    self.exports.setdefault(symbol.name, []).append((module, symbol))

    def symbol_address(self, module, symbol):
        require(symbol.kind not in (6, 10), f"{module.name}: TLS/IFUNC symbol requires unsupported runtime behavior")
        if symbol.section == 0xFFF1:
            return symbol.value
        require(0 < symbol.section < 0xFF00, f"{module.name}: unsupported special symbol section")
        require(symbol.value <= len(module.image) and symbol.size <= len(module.image) - symbol.value,
                f"{module.name}: defined symbol exceeds its module")
        if symbol.size or symbol.value not in {end for _, end in module.ranges} | {module.bss_end}:
            module.check_range(symbol.value, symbol.size or 1, memory=True)
        return module.base + symbol.value

    def resolve(self, module, index):
        require(index < len(module.symbols), f"{module.name}: relocation symbol index exceeds table")
        if index == 0:
            return 0, "null"
        symbol = module.symbols[index]
        require(symbol.binding in (0, 1, 2), f"{module.name}: unsupported symbol binding")
        require(symbol.binding != 0 or symbol.section != 0, f"{module.name}: undefined local symbol")
        if symbol.section and (symbol.binding == 0 or symbol.visibility in (1, 2, 3) or module.symbolic):
            return self.symbol_address(module, symbol), "local"
        choices = self.exports.get(symbol.name, []) if symbol.visibility in (0, 3) else []
        # Prefer a global definition; weak definitions are a fallback in this explicit scope.
        selected = next((item for item in choices if item[1].binding == 1), choices[0] if choices else None)
        if selected:
            owner, definition = selected
            return self.symbol_address(owner, definition), owner.name
        if symbol.section:
            return self.symbol_address(module, symbol), "local"
        if symbol.binding == 2:
            module.weak_zero[symbol.name] += 1
            return 0, "weak-zero"
        module.unresolved[symbol.name] += 1
        return None, "unresolved"

    def apply(self):
        require(not self.started, "Relocation has already been attempted on these images")
        self.started = True
        for module in self.modules:
            cursor = None
            for (word,) in struct.iter_unpack("<Q", module.relr):
                if word & 1 == 0:
                    targets = (word,)
                    cursor = word + 8
                else:
                    require(cursor is not None, f"{module.name}: RELR bitmap before address")
                    targets = tuple(cursor + bit * 8 for bit in range(63) if word & (1 << (bit + 1)))
                    cursor += 63 * 8
                for offset in targets:
                    value = module.unpack("<Q", offset, memory=True)[0]
                    module.write_relocation(offset, 8, value + module.base, "RELR")
            for _, table in module.rela:
                for offset, info, addend in struct.iter_unpack("<QQq", table):
                    kind, index = info & 0xFFFFFFFF, info >> 32
                    require(kind in RELOCATION_NAMES, f"{module.name}: unsupported relocation {kind}")
                    if kind == 0:
                        module.counts["NONE"] += 1
                        continue
                    if kind == 1027:
                        require(index == 0, f"{module.name}: RELATIVE relocation has a symbol")
                        value = module.base + addend
                    else:
                        value, origin = self.resolve(module, index)
                        if value is None:
                            # Validate the destination even when the symbol is unresolved.
                            module.claim_relocation(offset, 4 if kind == 258 else 8)
                            continue
                        module.bindings[origin] += 1
                        value += addend
                    if kind == 258:
                        require(-(1 << 31) <= value < 1 << 32, f"{module.name}: ABS32 relocation overflow")
                    module.write_relocation(offset, 4 if kind == 258 else 8, value, RELOCATION_NAMES[kind])
        self.applied = True
        return self.report()

    def report(self):
        output = []
        for module in self.modules:
            arrays = {}
            for name, (offset, count) in module.initializer_tables.items():
                values = module.unpack(f"<{count}Q", offset) if count else ()
                invalid = [value for value in values if value not in (0, U64) and
                           not any(owner.is_code(value - owner.base) for owner in self.modules)]
                arrays[name] = {"count": count, "unmapped_target_count": len(invalid),
                                "sample_addresses": [f"0x{value:x}" for value in values[:8]]}
            output.append({
                "name": module.name, "base": f"0x{module.base:x}", "image_size": len(module.image),
                "build_id": module.header["build_id"], "source_sha256": module.source_sha256,
                "image_sha256": hashlib.sha256(module.image).hexdigest(), "mod0": module.mod0,
                "needed": module.needed, "soname": module.soname,
                "symbol_count": len(module.symbols), "bss_zero_initialized": True,
                "relocations": dict(module.counts), "bindings": dict(module.bindings),
                "unresolved_strong": dict(module.unresolved), "unresolved_weak_bound_to_zero": dict(module.weak_zero),
                "initializers": arrays, "sample_relocations": module.samples,
                "segments": [{"name": entry["name"], "offset": entry["memory_offset"], "size": entry["memory_size"],
                              "permissions": "rx" if entry["name"] == "text" else "r" if entry["name"] == "rodata" else "rw"}
                             for entry in module.header["segments"]],
            })
        unresolved = sum(sum(module.unresolved.values()) for module in self.modules)
        invalid_initializers = sum(array["unmapped_target_count"] for module in output for array in module["initializers"].values())
        return {"schema_version": 1, "format": "offline-linked-exefs", "guest_code_executed": False,
                "host_address_space_mapped": False, "relocation_pass_completed": self.applied,
                "link_complete": self.applied and unresolved == 0 and invalid_initializers == 0,
                "unresolved_strong_relocations": unresolved, "invalid_initializer_targets": invalid_initializers,
                "applied_relocations": sum(sum(module.counts.values()) - module.counts["NONE"] for module in self.modules),
                "symbol_resolution_policy": "explicit module order, global definitions before weak fallback",
                "modules": output}
