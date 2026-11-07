"""Synthetic SDK thread registers, explicit startup opt-in and native prefixes."""

from ctypes import (POINTER, Structure, byref, c_int, c_uint8, c_uint32,
                    c_uint64, c_void_p, create_string_buffer)
import hashlib
from importlib.metadata import version
import os
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'tools'))
from arm64_lifter import U64, decode_instruction
from input_formats import InputError
from lifter_validation import compile_library
from pauth_lifter import decode_pauth_instruction
from pauth_validation import KEYS, Reference
from prepare_runtime import pack_regions
from prepare_startup import CONTEXT
from sdk_instructions import SYSTEM_FORMS, decode_sdk_instruction, sdk_system_kind
from startup_validation import (Config, Instruction, Program, Report, Span, State,
                                TRACE, bindings, snapshot)

BASE, STACK = 0x1000000, 0x7000000000
RO, READ, WRITE = 0xd53bd060, 0xd53bd040, 0xd51bd040
STOP = 0xd4200000


class SdkConfig(Structure):
    _fields_ = [('version', c_uint32), ('flags', c_uint32), ('entropy', c_uint64*4)] + [
        (name, c_uint64) for name in ('core_mask', 'priority_mask', 'aslr_base',
            'aslr_size', 'alias_base', 'alias_size', 'program_id', 'is_application', 'total_memory',
            'main_thread_id', 'main_thread_priority', 'main_thread_core')]


class SdkGoal(Structure):
    _fields_ = [('version', c_uint32), ('stage_count', c_uint32), ('thunk', c_uint64),
                ('entry', c_uint64), ('thunk_word', c_uint32), ('stages', POINTER(c_uint64))]


def make_fixture(words):
    words = list(words)+[STOP]
    data = struct.pack('<'+str(len(words))+'I', *words)
    size = (len(data)+4095) & ~4095
    module = SimpleNamespace(name='sdk_fixture', base=BASE,
        ranges=((0, size), (size, size), (size, size)), bss_start=size,
        bss_end=size, image=data+bytes(size-len(data)))
    blob, manifest = pack_regions([module], {'synthetic_raw': True}, STACK, 4096)
    instructions = (Instruction*len(words))()
    for n, word in enumerate(words):
        pc = BASE+4*n
        instructions[n] = Instruction(pc, word, 4 if n == len(words)-1 else 5,
                                      pc if n == len(words)-1 else pc+4,
                                      pc if n == len(words)-1 else pc+4, None)
    spans = (Span*((len(data)+65535)//65536))()
    for n in range(len(spans)):
        chunk = data[n*65536:(n+1)*65536]
        spans[n] = Span(BASE+n*65536, len(chunk), (c_uint8*32).from_buffer_copy(hashlib.sha256(chunk).digest()))
    program = Program(1, 3, BASE, (c_uint8*32).from_buffer_copy(bytes.fromhex(manifest['body_sha256'])),
                      instructions, len(instructions), spans, len(spans))
    return blob, program, instructions, spans


class NativeSession:
    def __init__(self, lib, directory, words=(), sdk=True):
        self.lib, self.keep = lib, make_fixture(words)
        blob, self.program, _, _ = self.keep
        path = Path(directory)/'sdk-registers.ootmem'
        path.write_bytes(blob)
        self.context = self.keys = self.dispatcher = None
        self.error, self.report = c_uint32(), Report()
        message = create_string_buffer(192)
        self.image = lib.oot_runtime_open(os.fsencode(path), message, len(message))
        if not self.image: raise AssertionError(message.value)
        self.config = Config(**dict(CONTEXT, heap_capacity=0x200000))
        self.sdk_config = SdkConfig(version=1, flags=1, entropy=(c_uint64*4)(1, 2, 3, 4))
        if sdk:
            self.context = lib.oot_startup_context_create_sdk(self.image, byref(self.config),
                                                               byref(self.sdk_config), byref(self.error))
        else:
            self.context = lib.oot_startup_context_create(self.image, byref(self.config), byref(self.error))
        if not self.context: raise AssertionError(self.error.value)
        self.keys = lib.oot_pauth_create(1, (c_uint64*4)(*KEYS))
        if not self.keys: raise AssertionError('synthetic PAC allocation failed')

    def close(self):
        if self.dispatcher: self.lib.oot_startup_dispatch_destroy(self.dispatcher)
        if self.keys: self.lib.oot_pauth_destroy(self.keys)
        if self.context: self.lib.oot_startup_context_destroy(self.context)
        if self.image: self.lib.oot_runtime_close(self.image)
        self.dispatcher = self.keys = self.context = self.image = None

    def initial(self):
        state = State()
        assert self.lib.oot_startup_context_initial_state(self.context, BASE, byref(state))
        return state

    def create(self, sdk=True, limit=100000):
        function = self.lib.oot_startup_dispatch_create_sdk if sdk else self.lib.oot_startup_dispatch_create
        self.dispatcher = function(self.image, self.context, self.keys, byref(self.program), limit, byref(self.error))
        return self.dispatcher

    def run(self, state, budget, sink=None):
        from ctypes import cast
        return self.lib.oot_startup_dispatch_run(self.dispatcher, byref(state), budget,
            cast(sink, c_void_p) if sink else None, None, byref(self.report))


class SdkInstructionTests(unittest.TestCase):
    def test_exact_register_fields_and_legacy_decoder_rejection(self):
        for operation, base in enumerate((RO, READ, WRITE)):
            for reg in range(32):
                word = base | reg
                decoded = decode_sdk_instruction(word, BASE)
                self.assertEqual((decoded.form, decoded.width, decoded.rd, decoded.operation,
                                  decoded.load), ('sdk_system', 64, reg, operation, operation != 2))
                self.assertEqual(sdk_system_kind(word), SYSTEM_FORMS[base])
                for legacy in (decode_instruction, decode_pauth_instruction):
                    with self.assertRaises(InputError): legacy(word, BASE)
            for bit in range(5, 32):
                changed = base ^ (1 << bit)
                if changed & ~31 in SYSTEM_FORMS: continue
                self.assertIsNone(sdk_system_kind(changed))
        for word in (0xd51bd060, 0xd53be020, 0xd53b4400, 0xd53b4420, 0xd538d080):
            with self.assertRaises(InputError): decode_sdk_instruction(word, BASE)
        for word in (True, -1, 1 << 32, 'word', None):
            self.assertIsNone(sdk_system_kind(word))
            with self.assertRaises(InputError): decode_sdk_instruction(word, BASE)
        for pc in (True, -4, 2, 1 << 64):
            with self.assertRaises(InputError): decode_sdk_instruction(RO, pc)
        for word in (0xd503201f, 0xd503237f, 0x91000400):
            self.assertEqual(decode_sdk_instruction(word, BASE), decode_pauth_instruction(word, BASE))


class NativeSdkInstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib, cls.build = compile_library([], os.environ.get('OOT_LIFTER_COMPILER', 'cmake'),
            extra_source='''#include "startup_dispatch.h"
OOT_LIFT_EXPORT int oot_sdk_test_branch(OotArm64State *s, OotGuestMemory *m,
    const OotPauth *p, uint64_t budget, uint64_t *retired) {
    (void)m; (void)p;
    if (!s || !retired || budget != 1 || (s->pc != UINT64_C(0x1000000) && s->pc != UINT64_C(0x1000008)))
        return OOT_LIFT_MEMORY_FAULT;
    s->pc = UINT64_C(0x1000010); *retired = 1; return OOT_LIFT_DISPATCH;
}
''', startup=True)
        bindings(cls.lib)
        signatures = {
            'oot_startup_context_create_sdk': ([c_void_p, POINTER(Config), POINTER(SdkConfig), POINTER(c_uint32)], c_void_p),
            'oot_startup_context_sdk_enabled': ([c_void_p], c_int),
            'oot_startup_context_tpidr_el0': ([c_void_p], c_uint64),
            'oot_startup_context_system': ([c_void_p, c_uint32, POINTER(State)], c_int),
            'oot_startup_dispatch_create_sdk': ([c_void_p, c_void_p, c_void_p, POINTER(Program), c_uint64, POINTER(c_uint32)], c_void_p),
            'oot_startup_dispatch_set_sdk_goal': ([c_void_p, POINTER(SdkGoal), POINTER(c_uint32)], c_int),
            'oot_startup_dispatch_sdk_stages_completed': ([c_void_p], c_uint32),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(cls.lib, name)
            function.argtypes, function.restype = arguments, result

    def goal_session(self, bypass=False):
        from ctypes import cast
        session = self.session([0x14000004 if bypass else WRITE, READ, 0x14000002, READ])
        for index in ((0, 2) if bypass else (2,)):
            row = session.keep[2][index]
            row.kind, row.next_a, row.next_b = 1, BASE+16, BASE+16
            row.run = cast(self.lib.oot_sdk_test_branch, c_void_p).value
        return session

    def goal(self, stages=(BASE, BASE+4)):
        values = (c_uint64*len(stages))(*stages)
        return SdkGoal(1, len(stages), BASE+8, BASE+16, 0x14000002, values), values

    def test_goal_requires_ordered_retired_stages_and_exact_thunk_before_main(self):
        for budget in (1, 2, 3, 100):
            session = self.goal_session()
            try:
                self.assertTrue(session.create())
                goal, stages = self.goal()
                self.assertTrue(self.lib.oot_startup_dispatch_set_sdk_goal(session.dispatcher, byref(goal), byref(session.error)))
                stages[0], goal.entry, goal.thunk_word = BASE+12, BASE+12, 0
                state = session.initial(); state.x[0] = 0x123456789abcdef0
                self.assertEqual(self.lib.oot_startup_dispatch_begin(session.dispatcher, byref(state), byref(session.report)), 0)
                self.assertEqual(self.lib.oot_startup_dispatch_sdk_stages_completed(session.dispatcher), 0)
                events = []
                @TRACE
                def sink(row, _):
                    r = row.contents
                    events.append((r.pc, r.next_pc, r.retired, r.event, r.error))
                for _ in range(5):
                    status = session.run(state, budget, sink)
                    if status == 2: break
                    self.assertEqual(status, 1)
                    self.assertEqual(self.lib.oot_startup_dispatch_sdk_stages_completed(session.dispatcher), min(session.report.retired, 2))
                else: self.fail('SDK goal did not stop')
                self.assertEqual((session.report.error, session.report.pc, session.report.retired), (15, BASE+16, 3))
                self.assertEqual(self.lib.oot_startup_dispatch_sdk_stages_completed(session.dispatcher), 2)
                self.assertEqual((state.pc, state.x[0], state.x[30]), (BASE+16, 0x123456789abcdef0, 0))
                self.assertEqual(events, [(BASE, BASE+4, 1, 0, 0), (BASE+4, BASE+8, 2, 0, 0),
                                          (BASE+8, BASE+16, 3, 0, 0), (BASE+16, BASE+16, 3, 2, 15)])
                previous = list(events)
                self.assertEqual(session.run(state, 100, sink), 2)
                self.assertEqual(events, previous)
                self.assertFalse(self.lib.oot_startup_dispatch_set_sdk_goal(session.dispatcher, byref(goal), byref(session.error)))
                self.assertEqual(self.lib.oot_startup_dispatch_abort(session.dispatcher), 1)
                self.assertEqual(self.lib.oot_startup_dispatch_sdk_stages_completed(session.dispatcher), 0)
                state = session.initial()
                self.assertEqual(self.lib.oot_startup_dispatch_begin(session.dispatcher, byref(state), byref(session.report)), 3)
                self.assertEqual(session.report.error, 3)
            finally: session.close()
        for stages, bypass, retired, observed in (((BASE+4, BASE), False, 3, 1),
                                                   ((BASE, BASE+12), False, 3, 1),
                                                   ((BASE,), True, 1, 1)):
            session = self.goal_session(bypass)
            try:
                self.assertTrue(session.create())
                goal, keep = self.goal(stages)
                self.assertTrue(self.lib.oot_startup_dispatch_set_sdk_goal(session.dispatcher, byref(goal), byref(session.error)))
                state = session.initial()
                self.assertEqual(self.lib.oot_startup_dispatch_begin(session.dispatcher, byref(state), byref(session.report)), 0)
                self.assertEqual(session.run(state, 100), 2)
                self.assertEqual((session.report.error, session.report.retired, state.pc), (16, retired, BASE+16))
                self.assertEqual(self.lib.oot_startup_dispatch_sdk_stages_completed(session.dispatcher), observed)
            finally: session.close()

    def test_goal_metadata_is_closed_and_diagnostic_mode_does_not_claim_completion(self):
        for change in ('version', 'empty', 'count', 'null', 'unknown_stage', 'duplicate',
                       'stage_entry', 'unknown_entry', 'unknown_thunk', 'word', 'target'):
            session = self.goal_session()
            try:
                self.assertTrue(session.create())
                goal, stages = self.goal()
                if change == 'version': goal.version = 2
                elif change == 'empty': goal.stage_count = 0
                elif change == 'count': goal.stage_count = 33
                elif change == 'null': goal.stages = None
                elif change == 'unknown_stage': stages[1] = BASE+100
                elif change == 'duplicate': stages[1] = stages[0]
                elif change == 'stage_entry': stages[1] = goal.entry
                elif change == 'unknown_entry': goal.entry = BASE+100
                elif change == 'unknown_thunk': goal.thunk = BASE+100
                elif change == 'word': goal.thunk_word ^= 1
                else: goal.entry = BASE+12
                self.assertFalse(self.lib.oot_startup_dispatch_set_sdk_goal(session.dispatcher, byref(goal), byref(session.error)), change)
                self.assertEqual(session.error.value, 16)
            finally: session.close()
        session = self.goal_session()
        try:
            self.assertTrue(session.create())
            state = session.initial()
            self.assertEqual(self.lib.oot_startup_dispatch_begin(session.dispatcher, byref(state), byref(session.report)), 0)
            self.assertEqual(session.run(state, 100), 2)
            self.assertEqual((session.report.error, session.report.retired), (8, 3))
            self.assertEqual(self.lib.oot_startup_dispatch_sdk_stages_completed(session.dispatcher), 0)
        finally: session.close()

    def test_goal_markers_and_quota_require_actual_retirement(self):
        for marker, limit, error, retired, observed in ((True, 100, 8, 1, 1),
                                                       (False, 2, 12, 2, 2),
                                                       (False, 3, 15, 3, 2)):
            session = self.goal_session()
            try:
                if marker:
                    row = session.keep[2][1]
                    row.kind, row.next_a, row.next_b, row.run = 4, row.pc, row.pc, None
                self.assertTrue(session.create(limit=limit))
                goal, keep = self.goal()
                self.assertTrue(self.lib.oot_startup_dispatch_set_sdk_goal(session.dispatcher, byref(goal), byref(session.error)))
                state = session.initial()
                self.assertEqual(self.lib.oot_startup_dispatch_begin(session.dispatcher, byref(state), byref(session.report)), 0)
                self.assertEqual(session.run(state, 100), 2)
                self.assertEqual((session.report.error, session.report.retired), (error, retired))
                self.assertEqual(self.lib.oot_startup_dispatch_sdk_stages_completed(session.dispatcher), observed)
            finally: session.close()
        session = self.session(sdk=False)
        try:
            session.program.flags = 1
            self.assertTrue(session.create(False))
            goal, stages = self.goal()
            self.assertFalse(self.lib.oot_startup_dispatch_set_sdk_goal(session.dispatcher, byref(goal), byref(session.error)))
            self.assertEqual(session.error.value, 16)
        finally: session.close()

    def session(self, words=(), sdk=True):
        return NativeSession(self.lib, self.build['directory'], words, sdk)

    def test_all_fields_values_flags_full_state_against_enabled_reference(self):
        self.assertEqual(version('unicorn'), '2.1.4')
        reference = Reference()
        session = self.session()
        cases = 0
        try:
            before_memory = snapshot(self.lib, session.context)
            for base in (RO, READ, WRITE):
                for reg in range(32):
                    word = base | reg
                    reference.code(struct.pack('<I', word))
                    for value in (0, 1, U64, 0xffffffff, 1 << 32, (1 << 63)-1, 1 << 63, 0x123456789abcdef0):
                        for flags in range(16):
                            state = session.initial()
                            for n in range(31): state.x[n] = (value ^ (n*0x123456789abcdef)) & U64
                            state.nzcv = flags << 28
                            seed = session.initial(); seed.x[0] = value
                            self.assertEqual(self.lib.oot_startup_context_system(session.context, WRITE, byref(seed)), 0)
                            reference.u.reg_write(reference.r.UC_ARM64_REG_TPIDRRO_EL0, session.config.tls_base)
                            reference.u.reg_write(reference.r.UC_ARM64_REG_TPIDR_EL0, value)
                            expected = reference.step(State.from_buffer_copy(state), word)
                            self.assertEqual(self.lib.oot_startup_context_system(session.context, word, byref(state)), 0)
                            self.assertEqual(state.values(), expected.values(), (hex(word), hex(value), flags))
                            self.assertEqual(self.lib.oot_startup_context_tpidr_el0(session.context),
                                             reference.u.reg_read(reference.r.UC_ARM64_REG_TPIDR_EL0))
                            cases += 1
            self.assertEqual(cases, 12288)
            self.assertEqual(snapshot(self.lib, session.context), before_memory)
        finally: session.close()

    def test_native_dispatch_prefixes_zero_budget_copied_metadata_and_context_isolation(self):
        words = [base | reg for reg in range(32) for base in (WRITE, READ, RO)]
        reference = Reference(); reference.code(struct.pack('<'+str(len(words))+'I', *words))
        for budget in (1, 7, 96, 1000):
            session, other = self.session(words), self.session()
            try:
                self.assertTrue(session.create())
                # The constructor owns copies; caller metadata may subsequently change.
                session.keep[2][0].kind = 4
                session.keep[3][0].size = 4
                state = session.initial()
                for n in range(31): state.x[n] = U64 ^ (n*0x123456789abcdef)
                state.nzcv = 0xa0000000
                expected = [State.from_buffer_copy(state)]
                rw = [0]
                reference.u.reg_write(reference.r.UC_ARM64_REG_TPIDRRO_EL0, session.config.tls_base)
                reference.u.reg_write(reference.r.UC_ARM64_REG_TPIDR_EL0, 0)
                for word in words:
                    expected.append(reference.step(expected[-1], word))
                    rw.append(reference.u.reg_read(reference.r.UC_ARM64_REG_TPIDR_EL0))
                self.assertEqual(self.lib.oot_startup_dispatch_begin(session.dispatcher, byref(state), byref(session.report)), 0)
                memory = snapshot(self.lib, session.context)
                events = []
                @TRACE
                def sink(row, _):
                    r = row.contents
                    events.append((r.pc, r.next_pc, r.retired, r.word, r.event, r.error, r.service))
                self.assertEqual(session.run(state, 0, sink), 1)
                self.assertEqual((state.values(), session.report.retired, events), (expected[0].values(), 0, []))
                for _ in range(len(words)+1):
                    status = session.run(state, budget, sink)
                    retired = session.report.retired
                    self.assertEqual(state.values(), expected[retired].values())
                    self.assertEqual(self.lib.oot_startup_context_tpidr_el0(session.context), rw[retired])
                    self.assertEqual(self.lib.oot_startup_context_tpidr_el0(other.context), 0)
                    self.assertEqual(snapshot(self.lib, session.context), memory)
                    if status == 2: break
                    self.assertEqual(status, 1)
                else: self.fail('synthetic SDK sequence did not stop')
                self.assertEqual((session.report.error, session.report.retired), (8, len(words)))
                self.assertEqual(events[:-1], [(BASE+4*n, BASE+4*n+4, n+1, word, 0, 0, 0) for n, word in enumerate(words)])
                self.assertEqual(events[-1], (BASE+4*len(words), BASE+4*len(words), len(words), STOP, 2, 8, 0))
            finally: session.close(); other.close()

    def test_constructor_profile_metadata_and_new_limits_are_closed(self):
        for sdk_context in (False, True):
            for sdk_constructor in (False, True):
                for flags in (0, 1, 2, 3, 7):
                    session = self.session([RO], sdk_context)
                    try:
                        session.program.flags = flags
                        accepted = sdk_context and sdk_constructor and flags == 3
                        self.assertEqual(bool(session.create(sdk_constructor)), accepted)
                        if not accepted: self.assertIn(session.error.value, (1, 2))
                    finally: session.close()
        for change in ('kind', 'callback', 'next_a', 'next_b', 'fallthrough', 'word'):
            session = self.session([RO])
            try:
                instruction = session.keep[2][0]
                if change == 'kind': instruction.kind = 0
                elif change == 'callback': instruction.run = 1
                elif change in ('next_a', 'next_b'): setattr(instruction, change, BASE)
                elif change == 'fallthrough': session.program.instruction_count = 1
                else: instruction.word = 0xd51bd060
                self.assertFalse(session.create())
                self.assertEqual(session.error.value, 2)
            finally: session.close()
        for sdk, limit, expected in ((False, 100000001, False), (True, 100000001, True),
                                      (True, 1000000000, True), (True, 1000000001, False)):
            session = self.session(sdk=sdk)
            try:
                session.program.flags = 3 if sdk else 1
                self.assertEqual(bool(session.create(sdk, limit)), expected)
            finally: session.close()
        # A real table beyond the original 16K cap is accepted only by SDK mode.
        session = self.session([RO]*16384)
        try: self.assertTrue(session.create())
        finally: session.close()
        for count, span_count in ((65537, 1), (1, 1025)):
            session = self.session()
            try:
                session.program.instruction_count, session.program.span_count = count, span_count
                self.assertFalse(session.create())
                self.assertEqual(session.error.value, 1)
            finally: session.close()

    def test_unsupported_and_faulting_system_operations_preserve_state_and_context(self):
        for sdk in (False, True):
            session = self.session(sdk=sdk)
            try:
                for word in (RO, READ, WRITE, 0xd51bd060, 0xd53be020):
                    state = session.initial(); state.x[0] = U64
                    before, memory = state.values(), snapshot(self.lib, session.context)
                    if sdk and sdk_system_kind(word): continue
                    self.assertEqual(self.lib.oot_startup_context_system(session.context, word, byref(state)), 1)
                    self.assertEqual((state.values(), snapshot(self.lib, session.context)), (before, memory))
                    self.assertEqual(self.lib.oot_startup_context_tpidr_el0(session.context), 0)
                for field, value in (('pc', BASE+1), ('pc', (1 << 39)-4), ('nzcv', 1)):
                    state = session.initial(); state.x[0] = U64; setattr(state, field, value)
                    before = state.values()
                    self.assertEqual(self.lib.oot_startup_context_system(session.context, WRITE, byref(state)), 2)
                    self.assertEqual(state.values(), before)
                    self.assertEqual(self.lib.oot_startup_context_tpidr_el0(session.context), 0)
            finally: session.close()


if __name__ == '__main__':
    unittest.main()
