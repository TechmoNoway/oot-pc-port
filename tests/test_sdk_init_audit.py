"""Synthetic SDK init registry provenance and consumer-boundary checks."""
from dataclasses import replace
import hashlib
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
from arm64_decode import Decoder
from input_formats import InputError
from module_linker import Linker, Module
from sdk_init_audit import (FUNCTIONS, MAX_FUNCTIONS, _in_family, _merge_bindings,sdk_init_tick_frequency,
                            _progress, _select_bindings)
from sdk_startup_audit import STAGE_SYMBOLS
from test_arm64_analysis import RET, branch


def synthetic_image(symbols, words=None):
    """Build independent dynamic-symbol bytes, with no original game material."""
    text, ro, data = bytearray(4096), bytearray(16384), bytearray(512)
    struct.pack_into('<I', text, 0, branch(0, 0x40))
    struct.pack_into('<I', text, 4, 0x80)
    text[0x80:0x84] = b'MOD0'
    struct.pack_into('<6i', text, 0x84,
        *[offset - 0x80 for offset in (0x2000, 0x7200, 0x8200, 0x5e00, 0x5e00, 0x7010)])
    struct.pack_into('<I', text, 0x40, RET)
    strings, records = bytearray(b'\0'), bytearray(24)
    for name, offset, size, kind, visibility in symbols:
        name_offset = len(strings)
        strings += name.encode() + b'\0'
        records += struct.pack('<IBBHQQ', name_offset, 0x10 | kind, visibility, 1, offset, size)
        if kind == 2:
            for address in range(offset, offset + size, 4):
                struct.pack_into('<I', text, address, RET)
    for address, word in (words or {}).items():
        struct.pack_into('<I', text, address, word)
    assert len(strings) < 0x1800 and len(records) < 0x1000
    ro[0x800:0x800 + len(strings)] = strings
    ro[0x2000:0x2000 + len(records)] = records
    count = len(symbols) + 1
    struct.pack_into('<' + 'I' * (3 + count), ro, 0x3000, 1, count, *([0] * (count + 1)))
    dynamic = [(5, 0x2800), (10, len(strings)), (6, 0x4000), (11, 24),
               (4, 0x5000), (12, 0x40), (0, 0)]
    table = b''.join(struct.pack('<qQ', tag, value) for tag, value in dynamic)
    ro[:len(table)] = table
    header = bytearray(256)
    header[:4] = b'NSO0'
    struct.pack_into('<I', header, 12, 0x38)
    struct.pack_into('<I', header, 60, 4096)
    struct.pack_into('<4I', header, 144, 0x800, len(strings), 0x2000, len(records))
    raw = bytearray(header)
    for index, (address, content) in enumerate(((0, text), (0x2000, ro), (0x7000, data))):
        struct.pack_into('<III', raw, 16 + index * 16, len(raw), address, len(content))
        struct.pack_into('<I', raw, 96 + index * 4, len(content))
        raw[160 + index * 32:192 + index * 32] = hashlib.sha256(content).digest()
        raw += content
    return bytes(raw)


def fixture(*, missing=None, alias=None, extra=(), changes=None, stages=False):
    symbols = [(symbol, 0x100 + index * 16, 8 if handler==224 else 4, 2, 0)
               for index, (handler, _, symbol, _, _) in enumerate(FUNCTIONS) if symbol != missing]
    changes=dict(changes or {})
    for name,offset,*_ in symbols:
        if name=='_ZN2nn2os13GetSystemTickEv':changes.setdefault(offset,0xd53be020)
    symbols += list(extra)
    if alias:
        name, target = alias
        offset = next(row[1] for row in symbols if row[0] == target)
        symbols = [(n, offset if n == name else o, s, k, v) for n, o, s, k, v in symbols]
    main_symbols = []
    main_words = None
    if stages:
        for index, (_, owner, name) in enumerate(STAGE_SYMBOLS[:8]):
            (symbols if owner == 'sdk' else main_symbols).append((name, 0x600 + index * 16, 4, 2, 0))
        symbols.append(('nntimeStartup', 0x700, 4, 2, 0))
        main_words = {0x670: branch(0x670, 0x800), 0x800: RET}
    modules = [Module('sdk', synthetic_image(symbols, changes))]
    if stages:
        modules.insert(0, Module('main', synthetic_image(main_symbols, main_words)))
    linker = Linker(modules)
    assert linker.apply()['link_complete']
    return linker, next(module for module in linker.modules if module.name == 'sdk')


class SdkInitAuditTests(unittest.TestCase):
    def setUp(self):
        self.decoder = Decoder()

    def select(self, linker, module):
        return _select_bindings(linker, module, self.decoder, [])

    def test_exact_provider_bodies_and_explicit_return_abi_without_mutation(self):
        linker, module = fixture()
        before = bytes(module.image)
        functions, census = self.select(linker, module)
        self.assertEqual(census['supported_exports'], len(FUNCTIONS))
        self.assertEqual(len(functions), len(FUNCTIONS))
        for row in functions:
            self.assertEqual(row['body_sha256'], hashlib.sha256(module.read(row['offset'], row['size'])).hexdigest())
            self.assertFalse(row['native_execution_proven'])
            self.assertFalse(row['original_body_executed'])
            self.assertEqual(row['entry_word'], 0xd53be020 if row['handler_id']==224 else RET)
        by_id = {row['handler_id']: row for row in functions}
        self.assertTrue(by_id[208]['returns_value'])  # Result, even though Ev omits return type.
        self.assertEqual((by_id[256]['returns_value'],by_id[256]['return_register']),(True,'d0'))
        self.assertFalse(by_id[128]['returns_value'])
        self.assertFalse(by_id[192]['returns_value'])
        self.assertEqual(bytes(module.image), before)

    def test_tick_rate_is_read_from_bound_original_constant_body(self):
        name='_ZN2nn2os22GetSystemTickFrequencyEv'
        linker,module=fixture(extra=[(name,0x500,12,2,0)],changes={0x500:0x529aca00,0x504:0x72a03b80})
        self.assertEqual(sdk_init_tick_frequency(linker),31250000)
        linker,module=fixture(extra=[(name,0x500,12,2,0)],changes={0x500:0x52800001,0x504:0x72a03b80})
        with self.assertRaises(InputError):sdk_init_tick_frequency(linker)

    def test_original_default_constructor_exception_requires_only_bounded_this_zero_stores(self):
        name='_ZN2nn6applet20NotificationReceiverC1Ev'
        words={0x500:0x3900e01f,0x504:0xa9007c1f,0x508:RET}
        linker,module=fixture(extra=[(name,0x500,12,2,0)],changes=words)
        rows,census=self.select(linker,module)
        self.assertEqual(census['original_zero_constructor_exports'],1)
        self.assertFalse(any(r['symbol']==name for r in rows))
        # A load, live-value store, different base, writeback, oversized offset,
        # resource call or different final return keeps the ordinary guard.
        for word in (0x3940e000,0x3900e000,0x3900e03f,0xf800841f,0x3908001f,0x94000001):
            changed=dict(words,**{});changed[0x500]=word
            linker,module=fixture(extra=[(name,0x500,12,2,0)],changes=changed)
            rows,_=self.select(linker,module)
            self.assertEqual(next(r['handler_id'] for r in rows if r['symbol']==name),31)

    def test_const_detail_applet_and_abort_consumers_guarded(self):
        names = ('_ZNK2nn2fs6Handle7InspectEv', '_ZN2nn4time6detail5QueryEv',
                 '_ZN2nn6applet12ReturnObjectEv', '_ZN2nn4diag21RegisterAbortObserverEPv')
        linker, module = fixture(extra=[(name, 0x400 + index * 16, 4, 2, 0)
                                       for index, name in enumerate(names)])
        functions, census = self.select(linker, module)
        self.assertEqual(census['guarded_exports'], len(names))
        self.assertEqual({row['symbol'] for row in functions if row['handler_id'] == 31}, set(names))
        self.assertFalse(_in_family('_ZN2nn2os10InitializeEv'))
        self.assertFalse(_in_family('_ZN2nn4diag6detail7PutImplEv'))

    def test_missing_hidden_unmapped_and_forged_original_metadata_rejected(self):
        with self.assertRaises(InputError):
            self.select(*fixture(missing=FUNCTIONS[0][2]))
        linker, module = fixture()
        index = next(i for i, symbol in enumerate(module.symbols) if symbol.name == FUNCTIONS[0][2])
        original = module.symbols[index]
        for field, value in (('kind', 1), ('visibility', 2), ('value', 0x900), ('size', 8)):
            module.symbols[index] = replace(original, **{field: value})
            with self.subTest(field=field), self.assertRaises(InputError):
                self.select(linker, module)
        module.symbols[index] = original

    def test_identical_guard_aliases_merge_but_handler_or_extent_conflicts_reject(self):
        a, b = '_ZN2nn2fs4ReadEv', '_ZN2nn2fs5WriteEv'
        linker, module = fixture(extra=[(a, 0x400, 4, 2, 0), (b, 0x400, 4, 2, 0)])
        functions, _ = self.select(linker, module)
        row = next(row for row in functions if row['handler_id'] == 31)
        self.assertEqual(row['names'], [a, b])
        with self.assertRaises(InputError):
            self.select(*fixture(alias=(FUNCTIONS[1][2], FUNCTIONS[0][2])))
        with self.assertRaises(InputError):
            self.select(*fixture(extra=[(a, 0x400, 8, 2, 0), (b, 0x404, 4, 2, 0)]))
        with self.assertRaises(InputError):
            self.select(*fixture(extra=[(a, 0x400, 8, 2, 0), (b, 0x400, 4, 2, 0)]))

    def test_guard_cannot_disappear_by_forging_its_parsed_namespace_kind_or_census(self):
        name = '_ZN2nn2fs11UnknownReadEv'
        linker, module = fixture(extra=[(name, 0x400, 4, 2, 0)])
        index = next(i for i, symbol in enumerate(module.symbols) if symbol.name == name)
        original = module.symbols[index]
        for field, value in (('name', 'outside_namespace'), ('kind', 1), ('section', 0)):
            module.symbols[index] = replace(original, **{field: value})
            with self.subTest(field=field), self.assertRaises(InputError):
                self.select(linker, module)
        module.symbols.pop(index)
        with self.assertRaises(InputError):
            self.select(linker, module)

    def test_required_stages_and_nnmain_target_remain_original(self):
        linker, module = fixture(stages=True)
        functions, _ = self.select(linker, module)
        progress = _progress(linker, functions, self.decoder)
        self.assertEqual(len(progress['required_original_stages']), 8)
        self.assertTrue(all(row['original_entry_retirement_required'] for row in progress['required_original_stages']))
        self.assertFalse(progress['initialization_completed'])
        self.assertFalse(progress['callback_tables_executed'])
        for forbidden in (progress['required_original_stages'][0]['entry'], progress['nn_main_target']):
            row = dict(functions[0], entry=forbidden, size=4)
            with self.assertRaises(InputError):
                _progress(linker, [row], self.decoder)

    def test_bad_nnmain_thunk_and_namespace_owner_rejected(self):
        linker, module = fixture(stages=True)
        main = next(owner for owner in linker.modules if owner.name == 'main')
        main.image[0x670:0x674] = struct.pack('<I', RET)
        with self.assertRaises(InputError):
            _progress(linker, [], self.decoder)
        other = Module('other', synthetic_image([('_ZN2nn2fs11UnknownReadEv', 0x100, 4, 2, 0)]))
        linker, module = fixture()
        linker.modules.append(other)
        with self.assertRaises(InputError):
            self.select(linker, module)

    def test_registry_limit_is_finite(self):
        row = dict(entry=0, size=4, body_sha256='a' * 64, handler_id=31,
                   returns_value=False, symbol='guard', symbol_metadata={})
        self.assertEqual(len(_merge_bindings([dict(row, entry=index * 4) for index in range(MAX_FUNCTIONS)])), MAX_FUNCTIONS)
        with self.assertRaises(InputError):
            _merge_bindings([dict(row, entry=index * 4) for index in range(MAX_FUNCTIONS + 1)])


if __name__ == '__main__':
    unittest.main()
