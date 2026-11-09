"""Synthetic exact-object and relocation-bound SDK libc++ selection hints."""
from copy import deepcopy
from dataclasses import replace
import hashlib
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from input_formats import InputError
from module_linker import Linker,Module
from prepare_startup import sdk_init_vtable_entries
from test_sdk_init_audit import synthetic_image

VTABLE='_ZTVNSt3__112SyntheticOneE'


def fixture(alias=False):
    symbols=[(VTABLE,0x7000,48,1,0),('method_a',0x100,4,2,0),('method_b',0x120,4,2,0),
             ('_ZTVN2nn12OtherFamilyE',0x7080,24,1,0)]
    if alias:symbols.append(('_ZTVNSt3__112SyntheticTwoE',0x7000,48,1,0))
    image=bytearray(synthetic_image(symbols))
    ro_file=struct.unpack_from('<I',image,32)[0]
    data_file=struct.unpack_from('<I',image,48)[0]
    string_size=1+sum(len(row[0].encode())+1 for row in symbols)
    dynamic=[(5,0x2800),(10,string_size),(6,0x4000),(11,24),(4,0x5000),(12,0x40),
             (36,0x5400),(35,16),(37,8),(0,0)]
    table=b''.join(struct.pack('<qQ',tag,value)for tag,value in dynamic)
    image[ro_file:ro_file+len(table)]=table
    # First slot is the vtable ABI prefix. Two code pointers and one data
    # pointer use explicit RELR; a further code-valued integer has no relocation
    # and must not be guessed into a target.
    struct.pack_into('<QQ',image,ro_file+0x3400,0x7010,1|(1<<1)|(1<<2))
    struct.pack_into('<6Q',image,data_file,0,0,0x100,0x120,0x7000,0x100000140)
    image[192:224]=hashlib.sha256(image[ro_file:ro_file+16384]).digest()
    image[224:256]=hashlib.sha256(image[data_file:data_file+512]).digest()
    raw=Linker([Module('sdk',bytes(image))]);linked=deepcopy(raw)
    assert linked.apply()['link_complete']
    return raw,linked


class SdkInitVtableTests(unittest.TestCase):
    def test_exact_sdk_object_slots_select_unique_code_without_mutation_or_authority(self):
        raw,linked=fixture();before=bytes(raw.modules[0].image);snapshot=bytes(linked.modules[0].image)
        entries,evidence=sdk_init_vtable_entries(raw,linked)
        self.assertEqual(entries,[0x100000100,0x100000120])
        self.assertEqual(len(evidence['objects']),1)
        self.assertEqual(len(evidence['slots']),2)
        self.assertEqual(evidence['unrelocated_code_values_ignored'],1)
        self.assertEqual(evidence['objects'][0]['original_segment'],'data-potential-relro')
        self.assertFalse(evidence['objects'][0]['runtime_read_only_proven'])
        self.assertFalse(evidence['runtime_authority_granted'])
        self.assertFalse(evidence['guest_code_executed'])
        self.assertEqual(bytes(raw.modules[0].image),before)
        self.assertEqual(bytes(linked.modules[0].image),snapshot)
        self.assertFalse(raw.started)

    def test_alias_objects_do_not_duplicate_target_entries(self):
        entries,evidence=sdk_init_vtable_entries(*fixture(alias=True))
        self.assertEqual(entries,[0x100000100,0x100000120])
        self.assertEqual(len(evidence['objects']),2)
        self.assertEqual(len(evidence['slots']),4)

    def test_observed_neighborhood_requires_original_recipe_and_exact_snapshot(self):
        raw,linked=fixture()
        entries,evidence=sdk_init_vtable_entries(raw,linked,[0x100000100])
        self.assertEqual(entries,[0x100000100,0x100000120])
        self.assertEqual(len(evidence['observed_neighbors']),2)
        self.assertFalse(evidence['runtime_authority_granted'])
        raw,linked=fixture();struct.pack_into('<Q',linked.modules[0].image,0x7018,0x100000140)
        with self.assertRaises(InputError):sdk_init_vtable_entries(raw,linked,[0x100000100])

    def test_parsed_symbol_namespace_kind_extent_and_census_cannot_hide_or_forge_object(self):
        for field,value in (('name','outside_namespace'),('kind',2),('size',40),('value',0x7010),('visibility',2)):
            raw,linked=fixture();module=raw.modules[0]
            index=next(i for i,s in enumerate(module.symbols)if s.name==VTABLE)
            module.symbols[index]=replace(module.symbols[index],**{field:value})
            with self.subTest(field=field),self.assertRaises(InputError):sdk_init_vtable_entries(raw,linked)
        raw,linked=fixture();raw.modules[0].symbols.pop();linked.modules[0].symbols.pop()
        with self.assertRaises(InputError):sdk_init_vtable_entries(raw,linked)

    def test_changed_linked_code_pointer_cannot_be_selected_or_silently_disappear(self):
        for value in (0x100000120,0x100000102,0,0x100007000):
            raw,linked=fixture();struct.pack_into('<Q',linked.modules[0].image,0x7010,value)
            with self.subTest(value=value),self.assertRaises(InputError):sdk_init_vtable_entries(raw,linked)
        raw,linked=fixture();linked.modules[0].image[0x7028]^=1
        with self.assertRaises(InputError):sdk_init_vtable_entries(raw,linked)

    def test_source_data_recipe_and_fresh_complete_link_are_required(self):
        raw,linked=fixture();raw.modules[0].image[0x7010]^=1
        with self.assertRaises(InputError):sdk_init_vtable_entries(raw,linked)
        raw,linked=fixture();raw.modules[0].relr=b''
        with self.assertRaises(InputError):sdk_init_vtable_entries(raw,linked)
        raw,linked=fixture();linked.modules[0].touched.remove(0x7010//4)
        with self.assertRaises(InputError):sdk_init_vtable_entries(raw,linked)
        raw,linked=fixture();raw.apply()
        with self.assertRaises(InputError):sdk_init_vtable_entries(raw,linked)
        raw,linked=fixture();linked.applied=False
        with self.assertRaises(InputError):sdk_init_vtable_entries(raw,linked)


if __name__=='__main__':unittest.main()
