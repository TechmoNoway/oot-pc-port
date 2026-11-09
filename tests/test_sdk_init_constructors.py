"""Synthetic original-constructor selection; never invoke a guest callback."""
from copy import deepcopy
import hashlib
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
from input_formats import InputError
from module_linker import Linker, Module
from prepare_startup import compact_sdk_init_nodes, sdk_init_constructor_entries, selection
from startup_audit import MAX_INIT_ENTRIES, MAX_INIT_INSTRUCTIONS, audit_entry, audit_startup
from test_sdk_init_audit import synthetic_image


def fixture(*, values=None):
    """An original synthetic DT_INIT plus independently encoded array slots."""
    values = [0x100000100, 0x100000120, 0x100000100, 0, (1 << 64) - 1] if values is None else values
    image = bytearray(synthetic_image([('ctor_a', 0x100, 4, 2, 0), ('ctor_b', 0x120, 4, 2, 0)]))
    ro_file = struct.unpack_from('<I', image, 32)[0]
    dynamic = [(5, 0x2800), (10, len(b'\0ctor_a\0ctor_b\0')), (6, 0x4000),
               (11, 24), (4, 0x5000), (12, 0x40), (25, 0x5800), (27, len(values) * 8), (0, 0)]
    table = b''.join(struct.pack('<qQ', tag, value) for tag, value in dynamic)
    image[ro_file:ro_file + len(table)] = table
    for index, value in enumerate(values):
        struct.pack_into('<Q', image, ro_file + 0x3800 + index * 8, value)
    image[192:224] = hashlib.sha256(image[ro_file:ro_file + 16384]).digest()
    raw = Linker([Module('sdk', bytes(image))])
    linked = deepcopy(raw)
    assert linked.apply()['link_complete']
    return raw, linked, audit_startup(linked, 32)


class SdkInitConstructorTests(unittest.TestCase):
    def test_snapshot_selects_unique_dt_init_and_code_slots_preserving_raw_images(self):
        raw, linked, audit = fixture()
        before = bytes(raw.modules[0].image)
        entries, evidence = sdk_init_constructor_entries(raw, linked, audit)
        self.assertEqual(entries, [0x100000040, 0x100000100, 0x100000120])
        self.assertEqual(evidence['code_slots'], 3)
        self.assertEqual(evidence['dt_init_functions'], 1)
        self.assertFalse(evidence['runtime_authority_granted'])
        self.assertFalse(evidence['constructor_execution_proven'])
        self.assertFalse(raw.applied)
        self.assertEqual(bytes(raw.modules[0].image), before)

    def test_forged_slot_classification_pointer_extent_and_source_rejected(self):
        mutations = [lambda a: a['modules'][0]['arrays']['init']['slots'][0].update(value=0x100000120),
                     lambda a: a['modules'][0]['arrays']['init']['slots'][0].update(kind='null'),
                     lambda a: a['modules'][0]['arrays']['init'].update(count=4),
                     lambda a: a['modules'][0]['dynamic_functions']['init'].update(address=0x100000100),
                     lambda a: a['modules'][0].update(source_sha256='0' * 64)]
        for mutation in mutations:
            raw, linked, audit = fixture()
            mutation(audit)
            with self.subTest(mutation=mutation), self.assertRaises(InputError):
                sdk_init_constructor_entries(raw, linked, audit)
        raw, linked, audit = fixture()
        raw.modules[0].image[0x100] ^= 1
        with self.assertRaises(InputError):
            sdk_init_constructor_entries(raw, linked, audit)

    def test_fresh_link_and_complete_original_module_set_required(self):
        raw, linked, audit = fixture()
        raw.apply()
        with self.assertRaises(InputError):
            sdk_init_constructor_entries(raw, linked, audit)
        raw, linked, audit = fixture()
        linked.applied = False
        with self.assertRaises(InputError):
            sdk_init_constructor_entries(raw, linked, audit)
        raw, linked, audit = fixture()
        audit['modules'].append(dict(audit['modules'][0]))
        with self.assertRaises(InputError):
            sdk_init_constructor_entries(raw, linked, audit)

    def test_large_limits_are_explicit_init_only_and_remain_finite(self):
        raw, _, _ = fixture()
        for sdk in (False, True):
            with self.subTest(sdk=sdk), self.assertRaises(InputError):
                audit_entry(raw, 65537, sdk=sdk)
        report = audit_entry(raw, MAX_INIT_INSTRUCTIONS, sdk=True, sdk_init=True)
        self.assertFalse(report['guest_code_executed'])
        with self.assertRaises(InputError):
            audit_entry(raw, MAX_INIT_INSTRUCTIONS + 1, sdk=True, sdk_init=True)
        with self.assertRaises(InputError):
            audit_entry(raw, 32, sdk_init=True)
        entries = tuple(0x100000100 + index * 4 for index in range(1025))
        with self.assertRaises(InputError):
            audit_entry(raw, 32, extra_entries=entries, sdk=True)
        with self.assertRaises(InputError):
            audit_entry(raw, 32, extra_entries=(0x100000100,) * (MAX_INIT_ENTRIES + 1), sdk=True, sdk_init=True)

    def test_selected_constructor_retains_original_instruction_and_return_boundary(self):
        raw, linked, audit = fixture()
        entries, _ = sdk_init_constructor_entries(raw, linked, audit)
        report, nodes = selection(raw, 256, entries, sdk=True, sdk_init=True)
        by_pc = {row['address']: row for row in nodes}
        self.assertTrue(by_pc[0x100000100]['semantic_supported'])
        self.assertTrue(by_pc[0x100000100]['return_boundary'])
        self.assertEqual(by_pc[0x100000100]['word'], raw.modules[0].unpack('<I', 0x100)[0])
        self.assertFalse(report['entry_graph']['indirect_targets_followed'])
        self.assertFalse(report['entry_graph']['runtime_path_proven'])

    def test_compaction_preserves_exact_ordered_words_count_and_other_audit_fields(self):
        raw, linked, audit = fixture()
        entries, _ = sdk_init_constructor_entries(raw, linked, audit)
        report, _ = selection(raw, 256, entries, sdk=True, sdk_init=True)
        graph = report['entry_graph']
        rows = sorted(graph['nodes'], key=lambda row: row['address'])
        expected = hashlib.sha256(b''.join(struct.pack('<QI', row['address'], row['word']) for row in rows)).hexdigest()
        count, frontier = graph['instruction_count'], deepcopy(graph['frontier'])
        compact_sdk_init_nodes(report)
        self.assertEqual(graph['nodes'], [])
        self.assertEqual(graph['node_binding']['count'], len(rows))
        self.assertEqual(graph['node_binding']['sha256'], expected)
        self.assertEqual(graph['instruction_count'], count)
        self.assertEqual(graph['frontier'], frontier)
        self.assertFalse(report['guest_code_executed'])
        # The legacy selector itself retains complete nodes. Compaction is an
        # explicit preparation step confined to the sdk_init branch.
        legacy, _ = selection(raw, 256, sdk=True)
        self.assertTrue(legacy['entry_graph']['nodes'])
        self.assertNotIn('node_binding', legacy['entry_graph'])


if __name__ == '__main__':
    unittest.main()
