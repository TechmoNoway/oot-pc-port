"""Syntax decoding and control-flow classification; no instruction semantics."""

from array import array
from collections import Counter
from importlib.metadata import version
import struct

from input_formats import InputError, require

NORMAL, CALL, JUMP, CONDITIONAL, INDIRECT_CALL, INDIRECT_JUMP, RETURN, TRAP = range(8)
FAMILIES = ("unknown", "integer_immediate", "integer_register", "load_store", "simd_fp",
            "system", "supervisor_call", "pointer_authentication", "atomic_ordered", "control_flow", "other")
ATOMIC_PREFIXES = ("ldxr", "ldaxr", "ldxp", "ldaxp", "stxr", "stlxr", "stxp", "stlxp", "ldar", "ldapr",
                   "stlr", "cas", "swp", "ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax",
                   "ldumin", "stadd", "stclr", "steor", "stset", "stsmax", "stsmin", "stumax", "stumin")


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def flow_kind(word, mnemonic):
    if word & 0x7C000000 == 0x14000000:
        return CALL if word & 0x80000000 else JUMP
    if word & 0xFF000000 == 0x54000000 or word & 0x7E000000 in (0x34000000, 0x36000000):
        return CONDITIONAL
    if mnemonic in ("blr", "blraa", "blrab", "blraaz", "blrabz"):
        return INDIRECT_CALL
    if mnemonic in ("br", "braa", "brab", "braaz", "brabz"):
        return INDIRECT_JUMP
    if mnemonic in ("ret", "retaa", "retab", "eret", "eretaa", "eretab", "drps"):
        return RETURN
    if mnemonic in ("brk", "hlt", "udf", "dcps1", "dcps2", "dcps3"):
        return TRAP
    return NORMAL


def direct_target(word, pc):
    if word & 0x7C000000 == 0x14000000:
        return pc + signed(word & 0x3FFFFFF, 26) * 4
    bits = 14 if word & 0x7E000000 == 0x36000000 else 19
    return pc + signed((word >> 5) & ((1 << bits) - 1), bits) * 4


def family(word, mnemonic, flow):
    if mnemonic.startswith(("pac", "aut", "xpac")) or mnemonic in ("retaa", "retab", "braa", "brab", "blraa", "blrab", "braaz", "brabz", "blraaz", "blrabz"):
        return 7
    if mnemonic.startswith(ATOMIC_PREFIXES):
        return 8
    if mnemonic == "svc":
        return 6
    if flow != NORMAL:
        return 9
    group = (word >> 25) & 15
    if group in (8, 9):
        return 1
    if group in (5, 13):
        return 2
    if group in (4, 6, 12, 14):
        return 3
    if group in (7, 15):
        return 4
    if group in (10, 11):
        return 5
    return 10


def literal_reference(word, pc):
    if word & 0x3B000000 != 0x18000000:
        return None
    opc, vector = word >> 30, bool(word & (1 << 26))
    width = (4, 8, 16, 0)[opc] if vector else (4, 8, 4, 0)[opc]
    return (pc + signed((word >> 5) & 0x7FFFF, 19) * 4, width) if width else None


class Decoder:
    def __init__(self):
        try:
            import capstone
        except ImportError as error:
            raise InputError("ARM64 analysis requires the project environment: pip install -r tools/requirements-analysis.txt") from error
        self.engine = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        self.engine.skipdata = True
        self.engine.skipdata_setup = (".word", None, None)
        self.metadata = {"name": "capstone", "distribution_version": version("capstone"),
                         "binding_version": capstone.__version__, "detail_mode": False}

    def scan(self, module, progress=None):
        size = module.header["segments"][0]["memory_size"]
        require(size % 4 == 0, f"{module.name}: text size is not instruction aligned")
        words = size // 4
        mnemonics = [""]
        identifiers = {}
        ids = array("H", [0]) * words
        flows, families = bytearray(words), bytearray(words)
        linear = Counter()
        # Chunk boundaries are instruction-aligned. Skipdata describes undecoded words,
        # not proof that those words are data.
        chunk_bytes = 256 * 1024
        for begin in range(0, size, chunk_bytes):
            end = min(begin + chunk_bytes, size)
            expected = begin
            for pc, length, mnemonic, _ in self.engine.disasm_lite(bytes(module.image[begin:end]), begin):
                require(pc == expected and length == 4, "Decoder did not preserve ARM64 word boundaries")
                expected += 4
                if mnemonic == ".word":
                    continue
                identifier = identifiers.get(mnemonic)
                if identifier is None:
                    identifier = len(mnemonics)
                    require(identifier < 65536, "Excessive distinct instruction mnemonics")
                    identifiers[mnemonic] = identifier
                    mnemonics.append(mnemonic)
                word = struct.unpack_from("<I", module.image, pc)[0]
                flow = flow_kind(word, mnemonic)
                index = pc // 4
                ids[index], flows[index], families[index] = identifier, flow, family(word, mnemonic, flow)
                linear[identifier] += 1
            require(expected == end, "Decoder left an unreported partial text chunk")
            if progress:
                progress(end, size)
        return ids, flows, families, mnemonics, linear
