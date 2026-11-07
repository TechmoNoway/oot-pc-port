"""Synthetic SDK CLI execution, private entropy input and exact goal reporting."""

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
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
from build_startup import build_native
from module_linker import Linker, Module
from prepare_startup import CONTEXT, emit_startup, prepare_bundle, selection
from test_arm64_analysis import branch, synthetic_module


class NativeSdkCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(dir=ROOT/'build', prefix='sdk-cli-test-')
        cls.folder = Path(cls.temporary.name)
        cls.addClassCleanup(cls.temporary.cleanup)
        # The artificial entropy value controls only a bit-test branch. The
        # even path retires two ordered stage entries and the original B thunk;
        # the odd path reaches an unsupported SVC without claiming completion.
        words = {0: branch(0, 0x40),
                 0x40: 0xd53bd068, 0x44: 0xd51bd048, 0x48: 0xd53bd049,
                 0x4c: 0xd2800161, 0x50: 0xd2800002, 0x54: 0xd2800003,
                 0x58: 0xd4000521,
                 0x5c: 0x36000001 | (((0xa0-0x5c)//4) << 5),
                 0x60: 0x10000381, 0x64: 0xd40003e1, 0x68: 0xd65f03c0,
                 0xa0: 0xd2803e80, 0xa4: 0x910004a5,
                 0xa8: 0xf1000400, 0xac: 0x54ffffc1,
                 0xb0: branch(0xb0, 0xb4), 0xb4: branch(0xb4, 0xc0),
                 0xc0: 0xd4200000, 0xd0: 0x003a6d73}  # ADR X1 points to "sm:\0".
        raw = Linker([Module('main', synthetic_module(words))])
        cls.words = words
        cls.base = raw.modules[0].base
        cls.bundle = cls.folder/'bundle'
        report = prepare_bundle(raw, cls.bundle)
        _, nodes = selection(raw, extra_entries=(cls.base+0x5c,), sdk=True)
        config = dict(CONTEXT, heap_capacity=0x200000)
        sdk = dict(core_mask=3, priority_mask=(1 << 64)-1,
                   aslr_base=0, aslr_size=1 << 39,
                   alias_base=0x5000000000, alias_size=0x200000,
                   program_id=0x0100000000001000, is_application=1,
                   main_thread_id=1, main_thread_priority=44, main_thread_core=0,
                   total_memory=report['package']['backing_bytes']+
                       config['tls_size']+config['heap_capacity'])
        goal = dict(mandatory_stage_entries=[cls.base+0x40, cls.base+0xa0],
                    goal_entry=dict(thunk_entry=cls.base+0xb4, entry=cls.base+0xc0,
                                    thunk_word=words[0xb4]))
        cls.source, summary = emit_startup(raw, nodes, report['package'], config,
                                           sdk_config=sdk, sdk_goal=goal)
        (cls.bundle/'startup.c').write_text(cls.source, encoding='utf-8')
        report.update(selection=summary, source_sha256=hashlib.sha256(cls.source.encode()).hexdigest())
        (cls.bundle/'manifest.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
        cls.exe, _ = build_native(cls.bundle, os.environ.get('OOT_LIFTER_COMPILER', 'cmake'))
        cls.package = cls.bundle/'startup.ootmem'
        cls.original_package = cls.package.read_bytes()
        cls.seed_words = (0x8fe1d3c5a792b460, 0x02468ace13579bdf,
                          0xfeed0123456789ab, 0xdedcba9876543210)

    def run_cli(self, name, entropy=None, mode='full', quantum=1):
        trace = self.folder/(name+'.jsonl')
        args = [str(self.exe), '--boot-images', str(self.package), '--trace', str(trace),
                '--limit', '10000', '--quantum', str(quantum), '--trace-mode', mode]
        if entropy is not None:
            args += ['--entropy-file', str(entropy)]
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
        return result, trace

    def assert_private(self, result, trace, seeds):
        visible = self.source+result.stdout+result.stderr
        if trace.exists():
            visible += trace.read_text(encoding='utf-8')
        for seed in seeds:
            self.assertNotIn(seed.hex(), visible.lower())
            for word in struct.unpack('<4Q', seed):
                self.assertNotIn(str(word), visible)
                self.assertNotIn(format(word, 'x'), visible.lower())
        self.assertEqual(self.package.read_bytes(), self.original_package)

    def test_sdk_selection_preserves_explicit_service_and_legacy_boundaries(self):
        raw = Linker([Module('main', synthetic_module(self.words))])
        _, old = selection(raw)
        old_rows = {row['address']-self.base: row for row in old}
        self.assertFalse(old_rows[0x40]['semantic_supported'])
        self.assertNotIn(0x44, old_rows)
        _, sdk = selection(raw, sdk=True)
        sdk_rows = {row['address']-self.base: row for row in sdk}
        for offset in (0x40, 0x44, 0x48):
            self.assertEqual(sdk_rows[offset]['form'], 'sdk_system')
            self.assertTrue(sdk_rows[offset]['semantic_supported'])
        self.assertEqual(sdk_rows[0x58]['service_immediate'], 0x29)
        self.assertTrue(sdk_rows[0x5c]['semantic_supported'])
        self.assertEqual(sdk_rows[0x60]['form'], 'pc_relative')
        self.assertEqual(sdk_rows[0x64]['service_immediate'], 0x1f)
        self.assertTrue(sdk_rows[0x68]['semantic_supported'])
        _, old_service = selection(raw, extra_entries=(self.base+0x4c,))
        old_service_rows = {row['address']-self.base: row for row in old_service}
        self.assertEqual(old_service_rows[0x58]['service_immediate'], 0x29)
        self.assertEqual(old_service_rows[0x5c]['selection_stop'], 'unselected continuation')
        self.assertFalse(old_service_rows[0x5c]['semantic_supported'])

    def test_entropy_file_requires_exactly_32_bytes_before_creating_trace(self):
        for size in (0, 31, 33):
            with self.subTest(size=size):
                path = self.folder/f'invalid-{size}.bin'
                path.write_bytes(bytes(size))
                result, trace = self.run_cli(f'invalid-{size}', path)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertIn('exactly 32 bytes', result.stderr)
                self.assertFalse(trace.exists())
        result, trace = self.run_cli('missing', self.folder/'missing.bin')
        self.assertEqual(result.returncode, 1)
        self.assertIn('could not be opened', result.stderr)
        self.assertFalse(trace.exists())

    def test_private_entropy_controls_original_path_and_compact_trace_preserves_goal(self):
        even = struct.pack('<4Q', *self.seed_words)
        odd = struct.pack('<4Q', self.seed_words[0]+1, *self.seed_words[1:])
        seeds = [even, odd]
        even_path, odd_path = self.folder/'even.bin', self.folder/'odd.bin'
        even_path.write_bytes(even)
        odd_path.write_bytes(odd)
        reports = {}
        for mode, quantum in (('full', 1), ('compact', 1000)):
            result, trace = self.run_cli('even-'+mode, even_path, mode, quantum)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            reports[mode] = report
            self.assertEqual((report['status'], report['error'], report['retired']), (2, 15, 1512))
            self.assertTrue(report['sdk_runtime'])
            self.assertTrue(report['sdk_initialization_completed'])
            self.assertTrue(report['game_entry_reached'])
            self.assertFalse(report['startup_completed'])
            self.assertEqual(report['sdk_stages_completed'], 2)
            self.assertEqual(int(report['pc'], 16), self.base+0xc0)
            self.assertEqual((report['trace_rows'], report['trace_steps']), (1513, 1512))
            data = trace.read_bytes().replace(b'\r\n', b'\n')
            rows = [json.loads(line) for line in data.splitlines()]
            self.assertEqual((rows[-1]['event'], rows[-1]['error']), (2, 15))
            # The first game-body instruction is observed but never retired.
            self.assertFalse(any(row['pc'] == f'0x{self.base+0xc0:x}' and
                                 row['event'] != 2 for row in rows))
            if mode == 'full':
                self.assertEqual(len(rows), 1513)
                self.assertEqual(hashlib.sha256(data).hexdigest(), report['trace_sha256'])
            else:
                self.assertLess(len(rows), 100)
            self.assert_private(result, trace, seeds)
        self.assertEqual(reports['full']['trace_sha256'], reports['compact']['trace_sha256'])
        result, trace = self.run_cli('odd', odd_path)
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual((report['status'], report['error'], report['service'], report['retired']),
                         (2, 9, 0x1f, 10))
        self.assertEqual(report['named_port'], 'sm:')
        self.assertEqual(report['sdk_stages_completed'], 1)
        self.assertFalse(report['sdk_initialization_completed'])
        self.assertFalse(report['game_entry_reached'])
        self.assert_private(result, trace, seeds)

    def test_missing_entropy_argument_uses_private_host_entropy(self):
        result, trace = self.run_cli('host-entropy')
        self.assertIn(result.returncode, (0, 3), result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report['sdk_runtime'])
        self.assertIn((report['error'], report['service'], report['retired']),
                      ((15, 0, 1512), (9, 0x1f, 10)))
        if result.returncode == 3:
            self.assertEqual(report['named_port'], 'sm:')
        self.assertEqual(report['sdk_initialization_completed'], result.returncode == 0)
        self.assertEqual(report['game_entry_reached'], result.returncode == 0)
        self.assertFalse(report['startup_completed'])
        self.assertEqual(self.package.read_bytes(), self.original_package)
        self.assertTrue(trace.is_file())


if __name__ == '__main__':
    unittest.main()
