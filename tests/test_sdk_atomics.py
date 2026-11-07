"""Synthetic SDK CAS32/64, complete faults, native concurrency and LSE prefixes."""

from ctypes import (POINTER, byref, c_int, c_uint8, c_uint32, c_uint64, c_void_p,
                    cast, string_at)
from importlib.metadata import version
import os
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
from arm64_lifter import U64, decode_instruction
from input_formats import InputError
from lifter_validation import compile_library
from lifter_validation_types import Memory, Region, State
from pauth_lifter import decode_pauth_instruction
from pauth_validation import Reference
from sdk_instructions import decode_sdk_instruction, sdk_atomic_kind
from startup_validation import Config, Program, TRACE, bindings, snapshot
from test_sdk_instructions import BASE, STACK, NativeSession, SdkConfig

DATA = 0x200000000


def cas(width, expected=0, desired=1, address=2, order=0):
    return (0x88a07c00 | ((width == 64) << 30) | (expected << 16) |
            (address << 5) | desired | ((order & 1) << 15) | ((order & 2) << 21))


STRESS = r'''
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "startup_dispatch.h"
typedef struct CasWorker {
    OotGuestMemory memory;
    HANDLE start;
    volatile LONG *failed;
    uint64_t address;
    unsigned size, rounds;
} CasWorker;
static DWORD WINAPI cas_worker(void *arg) {
    CasWorker *w = arg;
    ULONGLONG deadline = GetTickCount64() + 15000;
    unsigned n;
    if (WaitForSingleObject(w->start,15000) != WAIT_OBJECT_0) goto failed;
    for (n=0;n<w->rounds;++n) {
        uint64_t expected, observed;
        if (!oot_memory_load(&w->memory,w->address,w->size,&expected)) goto failed;
        for (;;) {
            if (GetTickCount64()>deadline || InterlockedCompareExchange(w->failed,0,0)) goto failed;
            if (!oot_memory_compare_exchange(&w->memory,w->address,w->size,0,expected,expected+1,&observed)) goto failed;
            if (observed==expected) break;
            expected=observed;
        }
    }
    return 0;
failed:
    InterlockedExchange(w->failed,1); return 1;
}
OOT_LIFT_EXPORT int oot_sdk_cas_stress(unsigned size,unsigned rounds) {
    uint8_t bytes[8]={0};
    OotGuestRegion regions[4];
    CasWorker workers[4]={0};
    HANDLE threads[4]={0},start;
    volatile LONG failed=0;
    uint64_t value;
    unsigned n;
    DWORD code;
    if ((size!=4 && size!=8) || !rounds || rounds>100000) return 0;
    start=CreateEventW(NULL,TRUE,FALSE,NULL);
    if (!start) return 0;
    for (n=0;n<4;++n) {
        regions[n]=(OotGuestRegion){UINT64_C(0x200000000)+n*4096,8,bytes,3};
        if (!oot_memory_init(&workers[n].memory,&regions[n],1)) { CloseHandle(start); return 0; }
        workers[n].start=start; workers[n].failed=&failed; workers[n].address=regions[n].base;
        workers[n].size=size; workers[n].rounds=rounds;
    }
    for (n=0;n<4;++n) {
        threads[n]=CreateThread(NULL,0,cas_worker,&workers[n],0,NULL);
        if (!threads[n]) { InterlockedExchange(&failed,1); break; }
    }
    SetEvent(start);
    for (n=0;n<4;++n) if (threads[n]) {
        /* A stuck worker must not retain pointers to unwound test storage. */
        if (WaitForSingleObject(threads[n],30000)!=WAIT_OBJECT_0) ExitProcess(1);
        if (!GetExitCodeThread(threads[n],&code) || code) InterlockedExchange(&failed,1);
        CloseHandle(threads[n]);
    }
    CloseHandle(start);
    return !failed && oot_memory_load(&workers[0].memory,regions[0].base,8,&value) && value==4*(uint64_t)rounds;
}
'''


class SdkAtomicDecoderTests(unittest.TestCase):
    def test_exact_width_order_and_every_register_field(self):
        for width in (32, 64):
            for order in range(4):
                for expected in range(32):
                    for desired in range(32):
                        for address in range(32):
                            word = cas(width, expected, desired, address, order)
                            i = decode_sdk_instruction(word, BASE)
                            self.assertEqual((i.form, i.width, i.rd, i.rm, i.rn, i.operation),
                                             ('sdk_atomic', width, expected, desired, address, order))
                            self.assertEqual(sdk_atomic_kind(word), 'compare_exchange')
                for legacy in (decode_instruction, decode_pauth_instruction):
                    with self.assertRaises(InputError): legacy(cas(width, order=order), BASE)
                word = cas(width, order=order)
                for bit in range(32):
                    if 0xbfa07c00 & (1 << bit):
                        self.assertIsNone(sdk_atomic_kind(word ^ (1 << bit)))
        for word in (True, -1, 1 << 32, None, 'word', 0x08a07c00, 0x48a07c00,
                     0x08207c00, 0xc8dffc20, 0xf8a00020):
            self.assertIsNone(sdk_atomic_kind(word))


class NativeSdkAtomicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib, cls.build = compile_library([], os.environ.get('OOT_LIFTER_COMPILER', 'cmake'),
                                             extra_source=STRESS, startup=True)
        bindings(cls.lib)
        signatures = {
            'oot_memory_compare_exchange': ([POINTER(Memory), c_uint64, c_uint32, c_uint32,
                                             c_uint64, c_uint64, POINTER(c_uint64)], c_int),
            'oot_memory_store': ([POINTER(Memory), c_uint64, c_uint32, c_uint64], c_int),
            'oot_memory_load': ([POINTER(Memory), c_uint64, c_uint32, POINTER(c_uint64)], c_int),
            'oot_startup_context_create_sdk': ([c_void_p, POINTER(Config), POINTER(SdkConfig), POINTER(c_uint32)], c_void_p),
            'oot_startup_context_system': ([c_void_p, c_uint32, POINTER(State)], c_int),
            'oot_startup_dispatch_create_sdk': ([c_void_p, c_void_p, c_void_p, POINTER(Program), c_uint64, POINTER(c_uint32)], c_void_p),
            'oot_sdk_cas_stress': ([c_uint32, c_uint32], c_int),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(cls.lib, name)
            function.argtypes, function.restype = arguments, result

    def memory(self, regions):
        table = (Region*len(regions))(*regions)
        memory = Memory()
        self.assertTrue(self.lib.oot_memory_init(byref(memory), table, len(table)))
        return memory, table

    def compare(self, memory, address, size, expected, desired, sp=0, observed=None):
        observed = c_uint64(0x7f123456789abcde) if observed is None else observed
        result = self.lib.oot_memory_compare_exchange(byref(memory), address, size, sp,
                                                       expected, desired, byref(observed))
        return result, observed.value

    def test_little_endian_match_miss_permissions_and_atomic_fault_outputs(self):
        original = struct.pack('<Q', 0x89abcdef01234567)
        for size in (4, 8):
            mask = (1 << (size*8))-1
            for permissions in range(4):
                for match in (False, True):
                    backing = (c_uint8*8).from_buffer_copy(original)
                    memory, keep = self.memory([Region(DATA, 8, backing, permissions)])
                    expected = int.from_bytes(original[:size], 'little') ^ (0 if match else 1)
                    desired = 0x76543210fedcba98
                    ok, observed = self.compare(memory, DATA, size, expected | (0xaabbccdd00000000 if size == 4 else 0), desired)
                    self.assertEqual(ok, permissions == 3)
                    if permissions == 3:
                        self.assertEqual(observed, int.from_bytes(original[:size], 'little'))
                        wanted = (desired & mask).to_bytes(size, 'little')+original[size:] if match else original
                        self.assertEqual(bytes(backing), wanted)
                        self.assertEqual(memory.fault.reason, 0)
                    else:
                        self.assertEqual(observed, 0x7f123456789abcde)
                        self.assertEqual(bytes(backing), original)
                        self.assertEqual(memory.fault.values(), (DATA, DATA, size, 3, 2))
            for split, second_permission in ((1, 3), (3, 3), (size-1, 1), (size-1, 2)):
                backing = (c_uint8*size)(*range(size))
                second = cast(byref(backing, split), POINTER(c_uint8))
                memory, keep = self.memory([Region(DATA, split, backing, 3),
                                            Region(DATA+split, size-split, second, second_permission)])
                before = bytes(backing)
                ok, observed = self.compare(memory, DATA, size, U64, 0)
                self.assertEqual(ok, second_permission == 3)
                self.assertEqual(bytes(backing), before)  # Comparison misses, including permission failures.
                if ok: self.assertEqual(observed, int.from_bytes(before, 'little'))
                else:
                    self.assertEqual(observed, 0x7f123456789abcde)
                    self.assertEqual(memory.fault.values(), (DATA, DATA+split, size, 3, 2))
            backing = (c_uint8*size)(*range(size))
            memory, keep = self.memory([Region(DATA, size-1, backing, 3)])
            before = bytes(backing)
            self.assertEqual(self.compare(memory, DATA, size, U64, 0), (0, 0x7f123456789abcde))
            self.assertEqual(memory.fault.values(), (DATA, DATA+size-1, size, 3, 1))
            self.assertEqual(bytes(backing), before)
            memory, keep = self.memory([Region(U64-size+1, size, backing, 3)])
            self.assertEqual(self.compare(memory, U64-size+1, size, int.from_bytes(before, 'little'), 0),
                             (1, int.from_bytes(before, 'little')))
            self.assertEqual(bytes(backing), bytes(size))

    def test_alignment_configuration_and_missing_output_preserve_all_bytes(self):
        backing = (c_uint8*32)(*range(32))
        memory, keep = self.memory([Region(DATA, 32, backing, 3)])
        before = bytes(backing)
        for size in (4, 8):
            for delta in range(1, size):
                self.assertEqual(self.compare(memory, DATA+delta, size, 0, 0), (0, 0x7f123456789abcde))
                self.assertEqual(memory.fault.values(), (DATA+delta, DATA+delta, size, 3, 5))
            self.assertEqual(self.compare(memory, DATA+size, size, 0, 0, sp=1), (0, 0x7f123456789abcde))
            self.assertEqual(memory.fault.reason, 5)
            self.assertEqual(self.compare(memory, DATA, size, 0, 0, sp=2), (0, 0x7f123456789abcde))
            self.assertEqual(memory.fault.reason, 4)
            self.assertEqual(self.lib.oot_memory_compare_exchange(byref(memory), DATA, size, 0, 0, 0, None), 0)
            self.assertEqual(memory.fault.reason, 4)
        for size in (0, 1, 2, 3, 16):
            self.assertEqual(self.compare(memory, DATA, size, 0, 0), (0, 0x7f123456789abcde))
            self.assertEqual(memory.fault.reason, 4)
        memory.valid = 0
        self.assertEqual(self.compare(memory, DATA, 8, 0, 0), (0, 0x7f123456789abcde))
        self.assertEqual(memory.fault.reason, 4)
        out = c_uint64(U64)
        self.assertFalse(self.lib.oot_memory_compare_exchange(None, DATA, 8, 0, 0, 0, byref(out)))
        self.assertEqual(out.value, U64)
        self.assertEqual(bytes(backing), before)

    def test_native_alias_views_increment_without_lost_updates(self):
        for size in (4, 8):
            self.assertEqual(self.lib.oot_sdk_cas_stress(size, 10000), 1)

    def test_lse_enabled_reference_all_register_roles_aliases_widths_and_orders(self):
        self.assertEqual(version('unicorn'), '2.1.4')
        reference = Reference()
        self.assertGreaterEqual((reference.u.cpr_read(3, 0, 0, 6, 0) >> 20) & 15, 2)
        session = NativeSession(self.lib, self.build['directory'])
        try:
            memory = self.lib.oot_startup_context_memory(session.context)
            reference.u.mem_map(session.config.tls_base, session.config.tls_size)
            roles = sorted({(n, 1, 2) for n in range(32)} |
                           {(0, n, 2) for n in range(32)} |
                           {(0, 1, n) for n in range(32)} |
                           {(0, 0, 0), (31, 31, 31), (0, 0, 2), (0, 1, 1)})
            cases = 0
            for width in (32, 64):
                size, mask = width//8, (1 << width)-1
                for order in range(4):
                    for expected_reg, desired_reg, address_reg in roles:
                        word = cas(width, expected_reg, desired_reg, address_reg, order)
                        reference.code(struct.pack('<I', word))
                        for value in (0, U64, 0x80000000ffffffff, 0x0123456789abcdef):
                            for match in (False, True):
                                state = session.initial()
                                state.sp = STACK+0x800
                                state.nzcv = ((cases*7) & 15) << 28
                                for n in range(31): state.x[n] = (value ^ (n*0x1020304050607)) & U64
                                address = state.sp if address_reg == 31 else session.config.tls_base+0x40
                                if address_reg != 31: state.x[address_reg] = address
                                expected = (0 if expected_reg == 31 else state.x[expected_reg]) & mask
                                initial = expected ^ (not match)
                                raw = initial.to_bytes(size, 'little')+bytes([0xa5]*(8-size))
                                self.assertTrue(self.lib.oot_memory_store(memory, address, 8, int.from_bytes(raw, 'little')))
                                reference.u.mem_write(address, raw)
                                wanted = reference.step(State.from_buffer_copy(state), word)
                                wanted_bytes = bytes(reference.u.mem_read(address, 8))
                                self.assertEqual(self.lib.oot_startup_context_system(session.context, word, byref(state)), 0)
                                self.assertEqual(state.values(), wanted.values(), (hex(word), hex(value), match))
                                actual = c_uint64()
                                self.assertTrue(self.lib.oot_memory_load(memory, address, 8, byref(actual)))
                                self.assertEqual(actual.value.to_bytes(8, 'little'), wanted_bytes)
                                cases += 1
            self.assertGreaterEqual(cases, 6000)
        finally: session.close()

    def test_dispatcher_complete_state_memory_prefixes_and_fault_retirement(self):
        words = [cas(32, 0, 1, 2, 3), cas(64, 3, 4, 5, 2), cas(64, 6, 7, 31, 1),
                 cas(32, 31, 8, 9), cas(64, 10, 31, 11), cas(64, 12, 12, 13),
                 cas(64, 14, 15, 14, 3), cas(64, 16, 17, 17, 2)]
        for budget in (1, 3, 100):
            session = NativeSession(self.lib, self.build['directory'], words)
            reference = Reference(); reference.code(struct.pack('<'+str(len(words))+'I', *words))
            try:
                reference.u.mem_map(session.config.tls_base, session.config.tls_size)
                memory = self.lib.oot_startup_context_memory(session.context)
                state = session.initial(); state.sp = STACK+0x800; state.nzcv = 0xa0000000
                for n in range(31): state.x[n] = U64 ^ (n*0x123456789abcdef)
                state.x[2], state.x[5], state.x[9] = [session.config.tls_base+0x40+n*16 for n in range(3)]
                state.x[11], state.x[13], state.x[14], state.x[17] = [session.config.tls_base+0x80+n*16 for n in range(4)]
                for word in words:
                    rs, rn, size = (word >> 16) & 31, (word >> 5) & 31, 8 if word >> 30 == 3 else 4
                    address = state.sp if rn == 31 else state.x[rn]
                    value = (0 if rs == 31 else state.x[rs]) & ((1 << (size*8))-1)
                    # The raw image claim includes the pristine zero stack.
                    # Exercise SP-base compare miss without changing it before begin.
                    if rn == 31: value = 0
                    self.assertTrue(self.lib.oot_memory_store(memory, address, 8, value))
                    reference.u.mem_write(address, value.to_bytes(8, 'little'))
                expected_states, expected_bytes = [State.from_buffer_copy(state)], [snapshot(self.lib, session.context)]
                initial = expected_bytes[0]
                for word in words:
                    expected_states.append(reference.step(expected_states[-1], word))
                    expected_bytes.append({base: bytes(reference.u.mem_read(base, len(data)))
                        if base in (STACK, session.config.tls_base) else data for base, data in initial.items()})
                self.assertTrue(session.create())
                self.assertEqual(self.lib.oot_startup_dispatch_begin(session.dispatcher, byref(state), byref(session.report)), 0)
                for _ in range(len(words)+1):
                    status = session.run(state, budget)
                    self.assertEqual(state.values(), expected_states[session.report.retired].values())
                    self.assertEqual(snapshot(self.lib, session.context), expected_bytes[session.report.retired])
                    if status == 2: break
                    self.assertEqual(status, 1)
                else: self.fail('CAS sequence failed to stop')
                self.assertEqual((session.report.error, session.report.retired), (8, len(words)))
            finally: session.close()
        # A selected CAS against read-only code must not retire or alter Rs.
        session = NativeSession(self.lib, self.build['directory'], [cas(64)])
        try:
            state = session.initial(); state.x[0] = 0x123456789abcdef0; state.x[2] = BASE
            before, data = state.values(), snapshot(self.lib, session.context)
            self.assertTrue(session.create())
            self.assertEqual(self.lib.oot_startup_dispatch_begin(session.dispatcher, byref(state), byref(session.report)), 0)
            self.assertEqual(session.run(state, 10), 2)
            self.assertEqual((session.report.error, session.report.retired), (11, 0))
            self.assertEqual((state.values(), snapshot(self.lib, session.context)), (before, data))
        finally: session.close()


if __name__ == '__main__':
    unittest.main()
