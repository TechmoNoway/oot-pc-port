"""Native validation ABI and synthetic program descriptions."""

from ctypes import POINTER, Structure, c_size_t, c_uint8, c_uint32, c_uint64
from dataclasses import dataclass
import struct

BASE = 0x1000000


class State(Structure):
    _fields_ = [("x", c_uint64 * 31), ("sp", c_uint64), ("pc", c_uint64), ("nzcv", c_uint32)]

    def values(self):
        return tuple(self.x), self.sp, self.pc, self.nzcv


class Region(Structure):
    _fields_ = [("base", c_uint64), ("size", c_uint64), ("data", POINTER(c_uint8)), ("permissions", c_uint32)]


class Fault(Structure):
    _fields_ = [("address", c_uint64), ("failing_address", c_uint64), ("size", c_uint32),
                ("access", c_uint32), ("reason", c_uint32)]

    def values(self):
        return self.address, self.failing_address, self.size, self.access, self.reason


class Memory(Structure):
    _fields_ = [("regions", POINTER(Region)), ("count", c_size_t), ("fault", Fault), ("valid", c_uint32)]


@dataclass
class Trial:
    index: int
    registers: list
    sp: int
    nzcv: int
    budget: int = 1


@dataclass(frozen=True)
class RegionSpec:
    base: int
    data: bytes
    permissions: int = 3


@dataclass
class MemoryTrial(Trial):
    regions: tuple = ()
    expected_fault: tuple | None = None  # address, failing_address, width, access, reason
    reference_fault_sizes: tuple = ()  # Paired accesses may be split by the reference backend.


@dataclass
class Program:
    name: str
    words: list
    trials: list
    base: int = BASE
    memory: bool = False

    @property
    def data(self):
        return struct.pack(f"<{len(self.words)}I", *self.words)
