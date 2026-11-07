"""Synthetic raw-package and native startup evidence, never game execution."""

from copy import deepcopy
from ctypes import POINTER, byref, c_uint8, c_uint32, c_uint64, c_void_p, cast, create_string_buffer, memset, sizeof
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
from input_formats import InputError
from module_linker import Linker, Module
from test_arm64_analysis import synthetic_module, branch
from test_module_linker import symbol
from prepare_runtime import HEADER, REGION, pack_regions, make_package
from prepare_startup import emit_startup, prepare_bundle, selection
from startup_validation import (Config, Session, State, Report, TRACE, ServiceReport,
    READY, YIELDED, STOPPED, REJECTED, CONTRACT, compile_validation, copied_program,
    fixture, reference_trace, run_validation, snapshot, Instruction)


class StartupBundleTests(unittest.TestCase):
    def test_exact_linked_plt_lookahead_selects_code_without_relocating_raw_slots(self):
        words={0:branch(0,0x40),0x40:branch(0x40,0xc0,True),0x44:0xd65f03c0,
               0xc0:0xd0000010,0xc4:0xf9400211,0xc8:0x91000210,0xcc:0xd61f0220}
        raw=Linker([Module('main',synthetic_module(words,symbols=[symbol('startup_callee',section=0,value=0,size=0)],plt=((0x2000,1026,1,0),))),
                    Module('sdk',synthetic_module(symbols=[symbol('startup_callee')]))])
        before=[bytes(m.image) for m in raw.modules]
        with tempfile.TemporaryDirectory(dir=ROOT/'build',prefix='startup-plt-select-') as temporary:
            report=prepare_bundle(raw,Path(temporary)/'bundle')
            target=raw.modules[1].base+0x40
            self.assertIn(target,report['static_plt_lookahead']['entries'])
            self.assertFalse(report['static_plt_lookahead']['live_targets_proven'])
            self.assertNotIn(target,[n['address'] for n in report['entry_audit']['entry_graph']['nodes']])
            self.assertEqual([bytes(m.image) for m in raw.modules],before)
            self.assertFalse(raw.applied)

    def test_startup_page_padding_preserves_source_and_legacy_exact_regions(self):
        f = fixture('chunks'); linker = f['linker']
        before = [bytes(m.image) for m in linker.modules]
        with tempfile.TemporaryDirectory(dir=ROOT/'build', prefix='startup-pages-test-') as directory:
            output = Path(directory)/'bundle'
            report = prepare_bundle(linker, output, stack_size=4096)
            self.assertEqual([bytes(m.image) for m in linker.modules], before)
            self.assertTrue(report['package']['segment_padding_zero'])
            self.assertTrue(report['package']['writable_data_and_bss_share_pages'])
            raw = (output/'startup.ootmem').read_bytes()
            regions = report['package']['regions']
            self.assertTrue(all(r['base'] % 4096 == 0 and r['size'] % 4096 == 0 for r in regions))
            self.assertEqual(len(regions), 7)  # Three page spans per NSO and one stack.
            for module in linker.modules:
                for offset, logical_end in ((0, module.ranges[0][1]), (0x2000, module.bss_end)):
                    index = next(i for i, r in enumerate(regions) if r['base'] == module.base+offset)
                    row = REGION.unpack_from(raw, HEADER.size+index*REGION.size)
                    payload = raw[row[2]:row[2]+row[3]]
                    self.assertEqual(payload[:logical_end-offset], module.image[offset:logical_end])
                    self.assertEqual(payload[logical_end-offset:], bytes(row[1]-(logical_end-offset)))
            linked = deepcopy(linker); linked.apply()
            _, exact = make_package(linked, stack_size=4096)
            self.assertEqual(len(exact['regions']), 9)  # Legacy separates exact data and BSS.
            for module in linked.modules:
                owned = [r for r in exact['regions'] if r['owner'] == module.name]
                self.assertEqual([(r['base']-module.base, r['size'], r['kind']) for r in owned],
                                 [(0, 256, 'text'), (0x1000, 4096, 'rodata'),
                                  (0x2000, 512, 'data'), (0x2200, 4096, 'bss')])

    def test_unselected_service_word_keeps_an_explicit_stop(self):
        raw=Linker([Module('main',synthetic_module({0:branch(0,0x40),0x40:0xd4000fe1,0x44:0xd4000521}))])
        _,nodes=selection(raw)
        boundary=next(n for n in nodes if n['address']==raw.modules[0].base+0x44)
        self.assertEqual(boundary['selection_stop'],'unselected continuation')
        _,manifest=pack_regions(raw.modules,{'image_phase':'raw'})
        source,_=emit_startup(raw,nodes,manifest)
        self.assertIn('UINT32_C(0xd4000521), 4,',source)
        self.assertNotIn('UINT32_C(0xd4000521), 3,',source)

    def test_raw_payload_is_distinct_from_independent_link_audit_and_source_preserved(self):
        f = fixture()
        linker = f['linker']
        before = [bytes(m.image) for m in linker.modules]
        with tempfile.TemporaryDirectory(dir=ROOT/'build', prefix='startup-bundle-test-') as directory:
            output = Path(directory)/'bundle'
            report = prepare_bundle(linker, output, extra_entries=[linker.modules[0].base+0x40])
            self.assertEqual([bytes(m.image) for m in linker.modules], before)
            self.assertFalse(linker.started)
            self.assertFalse(linker.applied)
            self.assertFalse(report['package']['offline_link_applied_to_package'])
            self.assertTrue(report['package']['offline_link_audit_on_independent_copy'])
            self.assertTrue(report['initializer_audit']['offline_link']['link_complete'])
            self.assertEqual(report['selection']['image_phase'], 'raw-before-rtld-relocation')
            raw = (output/'startup.ootmem').read_bytes()
            self.assertEqual(hashlib.sha256(raw[HEADER.size:]).hexdigest(), report['package']['body_sha256'])
            for region in report['package']['regions']:
                if region['base'] == linker.modules[0].base+0x2000:
                    data = REGION.unpack_from(raw, HEADER.size+report['package']['regions'].index(region)*REGION.size)
                    self.assertEqual(raw[data[2]+8:data[2]+16], bytes(8))
                    break
            else: self.fail('synthetic raw data region missing')
            independent = deepcopy(linker)
            self.assertTrue(independent.apply()['link_complete'])
            self.assertNotEqual(independent.modules[0].image[0x2008:0x2010], bytes(8))
            self.assertEqual(json.loads((output/'manifest.json').read_text())['source_sha256'],
                             hashlib.sha256((output/'startup.c').read_text().encode()).hexdigest())
            with self.assertRaises(InputError): prepare_bundle(linker, output)

    def test_selection_original_words_raw_phase_and_explicit_stops(self):
        f = fixture('indirect')
        linker, nodes = f['linker'], f['nodes']
        base = linker.modules[0].base
        selected = {n['address']: n for n in nodes}
        self.assertIn(base+0x10, selected)
        self.assertEqual(selected[base+0x60]['service_immediate'], 0x7f)
        bad = deepcopy(nodes)
        bad[0]['word'] ^= 4
        with self.assertRaises(InputError): emit_startup(linker, bad, f['manifest'])
        for roots in ([base+1], [base+0x2000], [base+0x40]*2):
            with self.subTest(roots=roots), self.assertRaises(InputError):
                selection(linker, extra_entries=roots)
        linked = deepcopy(linker)
        linked.apply()
        with self.assertRaises(InputError): selection(linked)
        partial = deepcopy(linker)
        partial.started = True
        with self.assertRaises(InputError): selection(partial)


class NativeStartupDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mode = os.environ.get('OOT_LIFTER_COMPILER', 'cmake')
        cls.compiled = compile_validation(cls.mode)
        cls.lib, cls.build, cls.fixtures = cls.compiled

    def session(self, name='loop', program=None, limit=100000):
        return Session(self.lib, self.fixtures[name], self.build['directory'], program, limit)

    def test_full_native_prefixes_both_pac_keys_loops_writeback_and_independent_bytes(self):
        report = run_validation(self.mode, self.compiled)
        self.assertEqual(report['whole_call_cases'], 480)
        self.assertGreater(report['prefix_checks'], report['whole_call_cases'])

    def test_multimodule_calls_and_conditionals_cross_native_emitter_chunks(self):
        f = self.fixtures['chunks']; main, sdk = f['linker'].modules
        program = copied_program(self.lib, 'chunks')
        callbacks = {i.pc: i.run for i in program[1] if i.run}
        self.assertGreater(len(callbacks), 64)
        self.assertGreaterEqual(len(set(callbacks.values())), 2)
        self.assertNotEqual(callbacks[main.base+0x74], callbacks[sdk.base+0xa0])
        self.assertNotEqual(callbacks[sdk.base+0xac], callbacks[sdk.base+0x10])
        for call in (0, 1):
            for wide_path in (0, 1):
                for initial in (0, 0xffffffffffffffff, 0x7fffffffffffffff):
                    for budget in (1, 7, 10000):
                        session = self.session('chunks')
                        try:
                            state = session.initial()
                            state.x[0], state.x[2], state.x[3] = initial, wide_path, call
                            state.x[29], state.x[30], state.nzcv = 0x12345678, main.base+0x64, 0xa0000000
                            before = State.from_buffer_copy(state)
                            states, memories = reference_trace(f, state)
                            session.begin(state)
                            for _ in range(200):
                                status = session.run(state, budget)
                                n = session.report.retired
                                self.assertEqual(state.values(), states[n].values())
                                self.assertEqual(snapshot(self.lib, session.context), memories[n])
                                if status == STOPPED:
                                    self.assertEqual(session.report.error, 9)
                                    self.assertEqual(n, len(states)-1)
                                    break
                                self.assertEqual(status, YIELDED)
                            else: self.fail('cross-chunk synthetic startup did not stop')
                            self.assertEqual(state.x[0], (initial+23+21*3+(56+130*wide_path if call else 0)) & ((1 << 64)-1))
                            self.assertEqual((state.sp, state.x[29], state.x[30]), (before.sp, before.x[29], before.x[30]))
                        finally: session.close()

    def test_selected_indirect_calls_and_unselected_target_stop_without_lr_retirement(self):
        f = self.fixtures['indirect']
        base = f['linker'].modules[0].base
        for target in (base+0x40, base+0x70, 1 << 45):
            session = self.session('indirect')
            try:
                state = session.initial()
                state.x[0], state.x[10], state.x[30] = 19, target, base+0x64
                original_lr = state.x[30]
                session.begin(state)
                self.assertEqual(session.run(state, 1), YIELDED)
                before = state.values(), snapshot(self.lib, session.context)
                if target == base+0x40:
                    states, memories = reference_trace(f, state)
                    for n in range(1, len(states)):
                        self.assertEqual(session.run(state, 1), YIELDED)
                        self.assertEqual(state.values(), states[n].values())
                        self.assertEqual(snapshot(self.lib, session.context), memories[n])
                    self.assertEqual(state.x[0], 26)
                    self.assertEqual(session.run(state, 1), STOPPED)
                    self.assertEqual(session.report.error, 9)
                else:
                    self.assertEqual(session.run(state, 99), STOPPED)
                    self.assertEqual(session.report.error, 10)
                    self.assertEqual(session.report.retired, 1)
                    self.assertEqual(state.x[30], original_lr)
                    self.assertEqual((state.values(), snapshot(self.lib, session.context)), before)
            finally: session.close()
        program = copied_program(self.lib, 'indirect')
        program[0].entry = base+0x44
        session = self.session('indirect', program)
        try:
            state = session.initial(); state.x[30] = base+0x70
            session.begin(state); before = state.values()
            self.assertEqual(session.run(state, 1), STOPPED)
            self.assertEqual((session.report.error, session.report.retired), (10, 0))
            self.assertEqual(state.values(), before)
        finally: session.close()
        # A direct BL with an unselected target also stops before publishing LR.
        p, ins, spans = copied_program(self.lib, 'loop')
        base = self.fixtures['loop']['linker'].modules[0].base
        filtered = (Instruction*(len(ins)-1))(*[i for i in ins if i.pc != base+0xa0])
        p.instructions, p.instruction_count, p.entry = filtered, len(filtered), base+0x1c
        session = self.session('loop', (p, filtered, spans))
        try:
            state = session.initial(); state.x[30] = base+0x64
            session.begin(state); before = state.values()
            self.assertEqual(session.run(state, 1), STOPPED)
            self.assertEqual((session.report.error, session.report.retired), (10, 0))
            self.assertEqual(state.values(), before)
        finally: session.close()

    def test_real_service_integration_heap_debug_capture_and_precise_unsupported_fault_stops(self):
        f = self.fixtures['services']; base = f['linker'].modules[0].base
        session = self.session('services')
        try:
            state = session.initial(); state.x[1] = 0x200000
            state.x[2], state.x[3], state.x[4] = base+0x2040, 8, 0x1020304050607080
            expected = State.from_buffer_copy(state)
            events = []
            @TRACE
            def sink(row, _): events.append((row.contents.event, row.contents.service))
            session.begin(state)
            for step in range(6):
                if step == 0: expected.pc = base+0x10
                elif step == 1:
                    expected.pc += 4; expected.x[0] = 0; expected.x[1] = f['config']['heap_base']
                elif step == 2: expected.pc += 4
                elif step == 3: expected.pc += 4; expected.x[0] = expected.x[2]
                elif step == 4: expected.pc += 4; expected.x[1] = expected.x[3]
                elif step == 5: expected.pc += 4; expected.x[0] = 0
                self.assertEqual(session.run(state, 1, sink), YIELDED)
                self.assertEqual(state.values(), expected.values())
                self.assertEqual(session.report.retired, step+1)
            self.assertEqual(self.lib.oot_startup_context_heap_size(session.context), 0x200000)
            self.assertEqual(snapshot(self.lib, session.context)[f['config']['heap_base']][:8],
                             state.x[4].to_bytes(8, 'little'))
            before = state.values(), snapshot(self.lib, session.context)
            self.assertEqual(session.run(state, 1, sink), STOPPED)
            self.assertEqual((session.report.error, session.report.service, session.report.retired), (9, 0x77, 6))
            self.assertEqual((state.values(), snapshot(self.lib, session.context)), before)
            self.assertEqual([item for item in events if item[0] == 1], [(1, 1), (1, 0x27)])
            debug = State.from_buffer_copy(state); debug.x[0], debug.x[1] = base+0x2040, 8
            report = ServiceReport()
            self.assertEqual(self.lib.oot_startup_context_service(session.context, 0x27, byref(debug), byref(report)), 0)
            self.assertEqual(report.text_size, 8)
            # A NUL byte is legitimate captured debug data.
            from ctypes import string_at, addressof
            self.assertEqual(string_at(addressof(report)+ServiceReport.text.offset, 8), bytes(range(8)))
        finally: session.close()
        for entry, pointer, size in ((base+0x10, 0, 4096), (base+0x20, base+0x31ff, 2)):
            p = copied_program(self.lib, 'services'); p[0].entry = entry
            session = self.session('services', p)
            try:
                state = session.initial(); state.x[0], state.x[1] = pointer, size
                session.begin(state); before = state.values(), snapshot(self.lib, session.context)
                self.assertEqual(session.run(state, 99), STOPPED)
                self.assertEqual((session.report.error, session.report.retired), (14, 0))
                self.assertEqual((state.values(), snapshot(self.lib, session.context)), before)
                self.assertEqual(self.lib.oot_startup_context_heap_size(session.context), 0)
            finally: session.close()

    def test_pair_fault_and_eight_bad_callbacks_do_not_publish_bytes_or_writeback(self):
        f = self.fixtures['loop']; base = f['linker'].modules[0].base
        cases = [(0, 0xa4, 6)]+[(mode, offset, count) for mode in range(1, 9)
                                  for offset, count in ((0xa4, 6), (0xb0, 9))]
        for bad_mode, offset, count in cases:
            p = copied_program(self.lib, 'loop')
            if bad_mode:
                row = next(i for i in p[1] if i.pc == base+offset)
                row.run = cast(self.lib.oot_test_start_bad, c_void_p).value
                self.lib.oot_test_start_bad_set(bad_mode)
            session = self.session(program=p)
            try:
                state = session.initial()
                state.x[1], state.x[2], state.x[3] = base+(0x2100 if bad_mode else 0x31f8), base+0x2040, 1
                state.x[4], state.x[5], state.x[30] = 0xfedcba9876543210, 0x1122334455667788, base+0x64
                session.begin(state)
                self.assertEqual(session.run(state, count), YIELDED)
                self.assertEqual(state.pc, base+offset)
                before = state.values(), snapshot(self.lib, session.context)
                self.assertEqual(session.run(state, 100), CONTRACT if bad_mode else STOPPED)
                self.assertEqual((session.report.error, session.report.retired), (13 if bad_mode else 11, count))
                self.assertEqual((state.values(), snapshot(self.lib, session.context)), before)
                self.assertEqual(session.run(state, 100), CONTRACT if bad_mode else STOPPED)
                self.assertEqual((state.values(), snapshot(self.lib, session.context)), before)
            finally: session.close()

    def test_metadata_body_code_raw_phase_and_copied_retained_lifetimes(self):
        session = self.session()
        lib = self.lib
        try:
            for change, expected in (('version', 1), ('flags', 1), ('body', 3), ('edge', 2), ('span', 2), ('word', 2)):
                p, ins, spans = copied_program(lib, 'loop')
                if change == 'version': p.version += 1
                elif change == 'flags': p.flags = 0
                elif change == 'body': p.body_sha256[0] ^= 1
                elif change == 'edge': ins[0].next_a += 4
                elif change == 'span': spans[0].entry |= 1
                elif change == 'word': ins[0].word = 0xd503201f
                error = c_uint32()
                rejected = lib.oot_startup_dispatch_create(session.image, session.context, session.keys, byref(p), 100, byref(error))
                self.assertFalse(rejected, change)
                self.assertEqual(error.value, expected, change)
            linked = deepcopy(self.fixtures['loop']['linker']); linked.apply()
            raw, _ = pack_regions(linked.modules, linked.report(), 0x7000000000, 4096)
            path = Path(self.build['directory'])/'linked-negative.ootmem'; path.write_bytes(raw)
            message = create_string_buffer(192)
            image = lib.oot_runtime_open(os.fsencode(path), message, len(message)); self.assertTrue(image)
            error = c_uint32(); context = lib.oot_startup_context_create(image, byref(Config(**self.fixtures['loop']['config'])), byref(error))
            self.assertTrue(context)
            try:
                p = copied_program(lib, 'loop')[0]
                self.assertFalse(lib.oot_startup_dispatch_create(image, context, session.keys, byref(p), 100, byref(error)))
                self.assertEqual(error.value, 3)
            finally:
                lib.oot_startup_context_destroy(context); lib.oot_runtime_close(image)
            state = session.initial(); session.begin(state)
            memory = lib.oot_runtime_memory(session.image).contents
            text = memory.regions[0].data
            before = state.values(); text[0] ^= 1
            try:
                self.assertEqual(session.run(state, 0), STOPPED)
                self.assertEqual(session.report.error, 4)
                self.assertEqual(state.values(), before)
            finally: text[0] ^= 1
        finally: session.close()
        session = self.session()
        try:
            state = session.initial(); base = self.fixtures['loop']['linker'].modules[0].base
            state.x[1], state.x[2], state.x[3] = base+0x2100, base+0x2040, 2
            p, ins, spans = session.keep
            memset(ins, 0, sizeof(ins)); memset(spans, 0, sizeof(spans)); p.body_sha256[0] ^= 1
            lib.oot_startup_context_destroy(session.context); session.context = None
            lib.oot_pauth_destroy(session.keys); session.keys = None
            lib.oot_runtime_close(session.image); session.image = None
            session.begin(state)
            self.assertEqual(session.run(state, 1000), STOPPED)
            self.assertEqual(session.report.error, 9)
        finally: session.close()

    def test_quota_checkpoint_and_trace_reentry_preserve_retirement_boundaries(self):
        session = self.session(limit=5)
        lib = self.lib
        try:
            state = session.initial(); base = self.fixtures['loop']['linker'].modules[0].base
            state.x[1], state.x[2], state.x[3] = base+0x2100, base+0x2040, 2
            session.begin(state)
            state.x[0] ^= 1
            self.assertEqual(session.run(state, 0), REJECTED)
            self.assertEqual(session.report.error, 5)
            state.x[0] ^= 1
            events, reentry = [], []
            @TRACE
            def sink(row, _):
                events.append((row.contents.event, row.contents.retired))
                inner = Report()
                reentry.append((lib.oot_startup_dispatch_run(session.dispatcher, byref(state), 0, None, None, byref(inner)), inner.error,
                                lib.oot_startup_dispatch_abort(session.dispatcher), lib.oot_startup_dispatch_destroy(session.dispatcher)))
            self.assertEqual(session.run(state, 1000, sink), STOPPED)
            self.assertEqual((session.report.error, session.report.retired), (12, 5))
            self.assertTrue(reentry)
            self.assertTrue(all(item == (REJECTED, 6, 0, 0) for item in reentry))
            self.assertEqual(events, [(0, n) for n in range(1, 6)]+[(2, 5)])
            self.assertEqual(lib.oot_startup_dispatch_abort(session.dispatcher), 1)
        finally: session.close()

    def test_pristine_image_claim_rejects_changed_backing_metadata_and_every_replay(self):
        lib = self.lib
        for change in ('rodata_byte', 'data_byte', 'bss_byte', 'stack_byte',
                       'base', 'size', 'permission', 'null_backing'):
            session = self.session()
            try:
                memory = lib.oot_runtime_memory(session.image).contents
                data = memory.regions[2]
                if change.endswith('_byte'):
                    index = {'rodata_byte': 1, 'data_byte': 2, 'bss_byte': 3,
                             'stack_byte': memory.count-1}[change]
                    changed = memory.regions[index].data
                    old = changed[37]
                    changed[37] ^= 1
                    restore = lambda: changed.__setitem__(37, old)
                elif change == 'base':
                    old = data.base; data.base += 4096
                    restore = lambda: setattr(data, 'base', old)
                elif change == 'size':
                    old = data.size; data.size += 8
                    restore = lambda: setattr(data, 'size', old)
                elif change == 'permission':
                    old = data.permissions; data.permissions ^= 1
                    restore = lambda: setattr(data, 'permissions', old)
                else:
                    old = cast(data.data, c_void_p).value
                    data.data = POINTER(c_uint8)()
                    restore = lambda: setattr(data, 'data', cast(c_void_p(old), POINTER(c_uint8)))
                state = session.initial()
                before = state.values(), snapshot(lib, session.context)
                try:
                    self.assertEqual(lib.oot_startup_dispatch_begin(session.dispatcher, byref(state), byref(session.report)), REJECTED, change)
                    self.assertEqual(session.report.error, 3, change)
                    self.assertEqual((state.values(), snapshot(lib, session.context)), before, change)
                finally: restore()
                # Rejected preflight does not consume the claim; restored raw
                # bytes permit the first genuine begin on this same image.
                session.begin(state)
            finally: session.close()
        session = self.session()
        try:
            state = session.initial(); before = state.values(), snapshot(lib, session.context)
            session.begin(state)
            self.assertEqual(lib.oot_startup_dispatch_abort(session.dispatcher), 1)
            self.assertEqual(lib.oot_startup_dispatch_begin(session.dispatcher, byref(state), byref(session.report)), REJECTED)
            self.assertEqual(session.report.error, 3)
            self.assertEqual((state.values(), snapshot(lib, session.context)), before)
            error = c_uint32()
            second = lib.oot_startup_dispatch_create(session.image, session.context, session.keys,
                                                     byref(session.program), 100, byref(error))
            self.assertTrue(second)
            try:
                self.assertEqual(lib.oot_startup_dispatch_begin(second, byref(state), byref(session.report)), REJECTED)
                self.assertEqual(session.report.error, 3)
            finally: lib.oot_startup_dispatch_destroy(second)
            fresh_context = lib.oot_startup_context_create(session.image,
                byref(Config(**self.fixtures['loop']['config'])), byref(error))
            self.assertTrue(fresh_context)
            self.assertTrue(lib.oot_startup_dispatch_destroy(session.dispatcher)); session.dispatcher = None
            try:
                second = lib.oot_startup_dispatch_create(session.image, fresh_context, session.keys,
                    byref(session.program), 100, byref(error))
                self.assertTrue(second)
                try:
                    self.assertEqual(lib.oot_startup_dispatch_begin(second, byref(state), byref(session.report)), REJECTED)
                    self.assertEqual(session.report.error, 3)
                finally: lib.oot_startup_dispatch_destroy(second)
            finally: lib.oot_startup_context_destroy(fresh_context)
        finally: session.close()
        # Reopening the immutable package is the explicit supported reset.
        session = self.session()
        try: session.begin(session.initial())
        finally: session.close()


if __name__ == '__main__':
    unittest.main()
