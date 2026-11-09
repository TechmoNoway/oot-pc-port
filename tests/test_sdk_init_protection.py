"""Synthetic SDK-init RELRO effects, queried views and atomic rejection."""
from ctypes import (POINTER, byref, cast, c_int, c_uint32, c_uint64, c_void_p,
                    create_string_buffer, string_at)
import os
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
from lifter_validation import compile_library
from prepare_runtime import pack_regions
from prepare_startup import CONTEXT
from startup_validation import Config, ServiceReport, State, bindings
from test_sdk_instructions import SdkConfig, BASE, STACK

PAGE = 4096
DATA = BASE + 2 * PAGE
FLAGS = 1 | 2 | 8 | 128 | 256


class SdkInitProtectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib, cls.build = compile_library([], os.environ.get('OOT_LIFTER_COMPILER', 'cmake'),
            startup=True, extra_source='int oot_sdk_init_protection_fixture;')
        bindings(cls.lib)
        signatures = {
            'oot_startup_context_create_sdk': ([c_void_p, POINTER(Config), POINTER(SdkConfig), POINTER(c_uint32)], c_void_p),
            'oot_memory_store': ([c_void_p, c_uint64, c_uint32, c_uint64], c_int),
            'oot_memory_load': ([c_void_p, c_uint64, c_uint32, POINTER(c_uint64)], c_int)}
        for name, (args, result) in signatures.items():
            function = getattr(cls.lib, name)
            function.argtypes, function.restype = args, result

    def create(self, flags=FLAGS, data_pages=8):
        data_end = (2 + data_pages) * PAGE
        bss_end = data_end + 2 * PAGE
        content = bytearray(bss_end)
        struct.pack_into('<I', content, 0, 0xd65f03c0)
        content[2 * PAGE:data_end] = bytes((index * 17 + 9) & 255 for index in range(data_pages * PAGE))
        module = SimpleNamespace(name='synthetic_relro', base=BASE,
            ranges=((0, PAGE), (PAGE, 2 * PAGE), (2 * PAGE, data_end)),
            bss_start=data_end, bss_end=bss_end, image=content)
        blob, _ = pack_regions([module], {'synthetic_raw': True}, STACK, PAGE)
        path = Path(self.build['directory']) / 'sdk-init-protection.ootmem'
        path.write_bytes(blob)
        message = create_string_buffer(192)
        image = self.lib.oot_runtime_open(os.fsencode(path), message, len(message))
        self.assertTrue(image, message.value)
        self.addCleanup(self.lib.oot_runtime_close, image)
        cfg = Config(**dict(CONTEXT, heap_capacity=0x400000))
        sdk = SdkConfig(version=1, flags=flags, entropy=(c_uint64 * 4)(1, 2, 3, 4),
            core_mask=1, priority_mask=(1 << 64) - 1, aslr_base=0, aslr_size=1 << 39,
            alias_base=0x5000000000, alias_size=0x200000, program_id=0x1000,
            is_application=1, total_memory=1 << 32, main_thread_id=7,
            main_thread_priority=44, main_thread_core=0)
        error = c_uint32()
        context = self.lib.oot_startup_context_create_sdk(image, byref(cfg), byref(sdk), byref(error))
        self.assertTrue(context, error.value)
        self.addCleanup(self.lib.oot_startup_context_destroy, context)
        return context, cfg

    def state(self):
        state = State()
        for index in range(31):
            state.x[index] = 0x9988776600000000 + index
        state.pc, state.sp, state.nzcv = BASE, STACK + PAGE, 0x90000000
        return state

    def memory(self, context):
        return self.lib.oot_startup_context_memory(context)

    def metadata(self, context):
        memory = self.memory(context).contents
        return tuple((region.base, region.size, region.permissions, cast(region.data,c_void_p).value)
                     for region in memory.regions[:memory.count])

    def contents(self, context):
        # A split changes region keys but not the concatenated backing bytes.
        memory = self.memory(context).contents
        return b''.join(string_at(region.data, region.size) for region in memory.regions[:memory.count])

    def service(self, context, service, values, expected=0):
        state = self.state()
        for index, value in values.items():
            state.x[index] = value
        before = State.from_buffer_copy(state)
        metadata, data = self.metadata(context), self.contents(context)
        report = ServiceReport()
        result = self.lib.oot_startup_context_service(context, service, byref(state), byref(report))
        self.assertEqual(result, expected, (service, values, report.error))
        if expected:
            self.assertEqual(state.values(), before.values())
            self.assertEqual(self.metadata(context), metadata)
            self.assertEqual(self.contents(context), data)
        else:
            before.pc += 4
            before.x[0] = 0
            self.assertEqual(state.values(), before.values())
            self.assertEqual(self.contents(context), data)
        return state

    def protect(self, context, begin, size, expected=0, permission=1):
        return self.service(context, 2, {0: begin, 1: size, 2: permission}, expected)

    def lock(self, context, begin, size, expected=0, mask=16, attribute=16):
        return self.service(context, 3, {0: begin, 1: size, 2: mask, 3: attribute}, expected)

    def query(self, context, cfg, address):
        state = self.state()
        state.x[0], state.x[2] = cfg.tls_base + 0x200, address
        report = ServiceReport()
        self.assertEqual(self.lib.oot_startup_context_service(context, 6, byref(state), byref(report)), 0)
        self.assertEqual((state.x[0], state.x[1], state.pc), (0, 0, BASE + 4))
        memory = self.memory(context).contents
        region = next(region for region in memory.regions[:memory.count] if region.base == cfg.tls_base)
        record = string_at(cast(region.data,c_void_p).value + 0x200, 40)
        return struct.unpack('<QQIIIIII', record)

    def load(self, context, address, width=8):
        value = c_uint64(0xfeedface)
        self.assertTrue(self.lib.oot_memory_load(self.memory(context), address, width, byref(value)))
        return value.value

    def test_middle_range_split_query_and_cross_edge_store_failure(self):
        context, cfg = self.create()
        begin = DATA + 2 * PAGE
        original = self.load(context, begin)
        self.protect(context, begin, 2 * PAGE)
        self.assertEqual(self.query(context, cfg, begin)[:5], (begin, 2 * PAGE, 4, 0, 1))
        self.assertEqual(self.query(context, cfg, begin - 1)[:5], (DATA, 2 * PAGE, 4, 0, 3))
        self.assertEqual(self.query(context, cfg, begin + 2 * PAGE)[:5], (begin + 2 * PAGE, 4 * PAGE, 4, 0, 3))
        self.assertEqual(self.load(context, begin), original)
        memory = self.memory(context)
        for address in (begin, begin + 2 * PAGE - 8):
            self.assertFalse(self.lib.oot_memory_store(memory, address, 8, 0xabcdef))
        for address in (begin - 4, begin + 2 * PAGE - 4):
            before = self.contents(context)
            self.assertFalse(self.lib.oot_memory_store(memory, address, 8, 0x123456789abcdef0))
            self.assertEqual(self.contents(context), before)
        for address in (begin - 8, begin + 2 * PAGE):
            self.assertTrue(self.lib.oot_memory_store(memory, address, 8, 0x123456789abcdef0))
            self.assertEqual(self.load(context, address), 0x123456789abcdef0)

    def test_permission_lock_is_visible_and_cannot_be_cleared_or_reprotected(self):
        context, cfg = self.create()
        begin = DATA + PAGE
        self.protect(context, begin, 4 * PAGE)
        self.lock(context, begin + PAGE, 2 * PAGE)
        self.assertEqual(self.query(context, cfg, begin + PAGE)[:5], (begin + PAGE, 2 * PAGE, 4, 16, 1))
        self.assertEqual(self.query(context, cfg, begin)[:5], (begin, PAGE, 4, 0, 1))
        self.protect(context, begin + PAGE, PAGE, expected=2)
        self.protect(context, begin, 3 * PAGE, expected=2)
        self.protect(context, begin + PAGE, PAGE, expected=1, permission=3)
        self.lock(context, begin + PAGE, PAGE, expected=1, attribute=0)
        self.lock(context, begin, PAGE, expected=1, mask=8, attribute=8)
        self.assertEqual(self.query(context, cfg, begin + PAGE)[3:5], (16, 1))

    def test_adjacent_data_bss_and_mixed_permission_lock_preserve_each_permission(self):
        context, cfg = self.create()
        self.lock(context, DATA, PAGE)
        self.assertEqual(self.query(context, cfg, DATA)[3:5], (16, 3))
        self.assertTrue(self.lib.oot_memory_store(self.memory(context), DATA, 8, 1234))
        self.assertEqual(self.load(context, DATA), 1234)
        self.protect(context, DATA, PAGE, expected=2)
        self.protect(context, DATA + 7 * PAGE, 3 * PAGE)
        self.assertEqual(self.query(context, cfg, DATA + 7 * PAGE)[3:5], (0, 1))
        self.assertEqual(self.query(context, cfg, DATA + 8 * PAGE)[3:5], (0, 1))
        self.lock(context, DATA + 7 * PAGE, 3 * PAGE)
        self.assertEqual(self.query(context, cfg, DATA + 9 * PAGE)[3:5], (16, 1))
        # PermissionLocked freezes the current permissions; it does not remove
        # write access from the leading writable page in a mixed request.
        self.lock(context, DATA + 6 * PAGE, 3 * PAGE)
        self.assertEqual(self.query(context, cfg, DATA + 6 * PAGE)[3:5], (16, 3))
        self.assertEqual(self.query(context, cfg, DATA + 7 * PAGE)[3:5], (16, 1))
        self.assertTrue(self.lib.oot_memory_store(self.memory(context), DATA + 6 * PAGE, 8, 5678))
        self.assertFalse(self.lib.oot_memory_store(self.memory(context), DATA + 7 * PAGE, 8, 5678))
        self.protect(context, DATA + 6 * PAGE, 3 * PAGE, expected=2)

    def test_invalid_domains_and_legacy_profile_preserve_state_bytes_and_views(self):
        context, cfg = self.create()
        for begin, size in ((DATA + 1, PAGE), (DATA, 0), (DATA, PAGE - 1),
                            ((1 << 39) - PAGE, 2 * PAGE), (BASE, PAGE),
                            (BASE + PAGE, PAGE), (STACK, PAGE), (cfg.tls_base, PAGE),
                            (cfg.heap_base, PAGE), (DATA + 9 * PAGE, 2 * PAGE)):
            with self.subTest(begin=begin, size=size):
                self.protect(context, begin, size, expected=2)
        for permission in (0, 2, 3, 5, 7):
            self.protect(context, DATA, PAGE, expected=1, permission=permission)
        legacy, _ = self.create(flags=FLAGS & ~256)
        self.protect(legacy, DATA, PAGE, expected=1)
        self.lock(legacy, DATA, PAGE, expected=1)

    def test_heap_regrowth_keeps_sealed_image_views_and_query_attributes(self):
        context, cfg = self.create()
        self.protect(context, DATA + PAGE, PAGE)
        self.lock(context, DATA + PAGE, PAGE)
        for size in (0x400000, 0x200000, 0, 0x200000):
            state = self.state()
            state.x[1] = size
            report = ServiceReport()
            self.assertEqual(self.lib.oot_startup_context_service(context, 1, byref(state), byref(report)), 0)
            self.assertEqual(self.query(context, cfg, DATA + PAGE)[3:5], (16, 1))
            self.assertFalse(self.lib.oot_memory_store(self.memory(context), DATA + PAGE, 8, 99))
        self.assertTrue(self.lib.oot_memory_store(self.memory(context), cfg.heap_base, 8, 1234))

    def test_finite_split_capacity_and_forged_public_view_reject_without_commit(self):
        context, _ = self.create(data_pages=260)
        successful = 0
        for index in range(100):
            state = self.state()
            state.x[0], state.x[1], state.x[2] = DATA + (index * 2 + 1) * PAGE, PAGE, 1
            before, metadata, data = state.values(), self.metadata(context), self.contents(context)
            report = ServiceReport()
            status = self.lib.oot_startup_context_service(context, 2, byref(state), byref(report))
            if status:
                self.assertEqual(status, 2)
                self.assertEqual(state.values(), before)
                self.assertEqual(self.metadata(context), metadata)
                self.assertEqual(self.contents(context), data)
                break
            successful += 1
        self.assertGreater(successful, 0)
        self.assertLess(successful, 100)
        context, _ = self.create()
        self.protect(context, DATA + PAGE, PAGE)
        memory = self.memory(context).contents
        region = next(region for region in memory.regions[:memory.count] if region.base == DATA + PAGE)
        region.permissions = 3  # Caller-forged borrowed metadata is never authoritative.
        state = self.state()
        state.x[0], state.x[1], state.x[2] = DATA + 2 * PAGE, PAGE, 1
        before = state.values()
        report = ServiceReport()
        self.assertEqual(self.lib.oot_startup_context_service(context, 2, byref(state), byref(report)), 2)
        self.assertEqual(state.values(), before)
        self.assertFalse(self.memory(context))
        region.permissions = 1
        self.assertTrue(self.memory(context))


if __name__ == '__main__':
    unittest.main()
