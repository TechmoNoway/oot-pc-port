"""Exact startup-only thread-register instructions; legacy decoders stay closed."""
from arm64_lifter import Instruction, U64
from input_formats import require
from pauth_lifter import decode_pauth_instruction


SYSTEM_FORMS = {
    0xd53bd060: 'tpidrro_read',
    0xd53bd040: 'tpidr_read',
    0xd51bd040: 'tpidr_write',
}
DMB_OPTIONS = frozenset((1,2,3,5,6,7,9,10,11,13,14,15))


def sdk_system_kind(word):
    if type(word) is not int or not 0 <= word <= 0xffffffff:
        return None
    return SYSTEM_FORMS.get(word & 0xffffffe0)


def sdk_atomic_kind(word):
    if type(word) is not int or not 0 <= word <= 0xffffffff:
        return None
    return 'compare_exchange' if word & 0xbfa07c00 == 0x88a07c00 else None


def sdk_barrier_kind(word):
    """Named DMB options only; other immediate aliases are outside this model."""
    if type(word) is not int or not 0 <= word <= 0xffffffff:
        return None
    return 'dmb' if word & 0xfffff0ff == 0xd50330bf and (word >> 8 & 15) in DMB_OPTIONS else None


def decode_sdk_instruction(word, pc):
    """Opt-in wrapper, including the preceding exact integer/PAC semantics."""
    require(type(word) is int and 0 <= word <= 0xffffffff, 'SDK instruction must be uint32')
    require(type(pc) is int and 0 <= pc <= U64 and pc % 4 == 0, 'SDK PC must be aligned uint64')
    if sdk_barrier_kind(word) is not None:
        return Instruction(pc, word, 'sdk_barrier', operation=word >> 8 & 15)
    if sdk_atomic_kind(word) is not None:
        return Instruction(pc, word, 'sdk_atomic', width=64 if word >> 30 == 3 else 32,
                           rd=(word >> 16) & 31, rn=(word >> 5) & 31,
                           rm=word & 31, operation=(word >> 15 & 1) | (word >> 21 & 2))
    kind = sdk_system_kind(word)
    if kind is None:
        return decode_pauth_instruction(word, pc)
    operation = ('tpidrro_read', 'tpidr_read', 'tpidr_write').index(kind)
    return Instruction(pc, word, 'sdk_system', width=64, rd=word & 31,
                       operation=operation, load=operation != 2)
