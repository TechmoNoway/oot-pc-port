"""Independent artificial VI refcount/void wrapper, callee PLTs and raw census."""
from copy import deepcopy
from dataclasses import replace
import struct
import unittest
from test_arm64_analysis import branch,RET,NOP
from test_module_linker import symbol,change_memory
from test_sdk_init_audit import synthetic_image
from test_host_boot import adrp
from module_linker import Linker,Module
from input_formats import InputError
from graphics_audit import CHECK
from display_audit import extend_display_audit,INITIALIZE,LOWER,LOCK,UNLOCK,CONSTRUCTORS

def fixture(changes=None,*,counter=0x7300):
    entry=0x100;mutex=0x7180
    names=[(INITIALIZE,entry,104),(LOWER,0x200,4),(LOCK,0x204,4),
        (UNLOCK,0x208,4),(CHECK,0x20c,4),('_ZN2nn3vi23sdk10InitializeEv',0x210,4),
        ('_ZN2nn2vi18OpenDefaultDisplayEPPNS0_7DisplayE',0x214,4),
        ('_ZNK2nn2vi7Display8GetWidthEv',0x218,4)]
    for index,(first,second,size,vtable,_) in enumerate(CONSTRUCTORS):
        names.extend(((first,0x600+index*0x80,size),(second,0x600+index*0x80,size)))
    words={0:branch(0,0x40),0x40:RET};relocations=[]
    for n,index in enumerate((2,3,4,1)):
        slot=0x7000+n*8;stub=0x400+n*16
        relocations.append((slot,1026,index+1,0))
        words.update({stub:adrp(16,stub,slot),stub+4:0xf9400211|((slot-0x7000)//8<<10),
            stub+8:0x91000210|((slot-0x7000)<<10),stub+12:0xd61f0220})
    for n in (3,15,21):
        words[entry+n*4]=adrp(0,entry+n*4,mutex)
        words[entry+(n+1)*4]=0x91000000|((mutex&4095)<<10)
    words.update({entry+n*4:w for n,w in {
        0:0xd503237f,1:0xa9bf7bfd,2:0x910003fd,5:branch(entry+20,0x400,True),
        6:adrp(0,entry+24,0x5f00),7:0x913c0000,8:0x52800261,9:branch(entry+36,0x420,True),
        10:adrp(8,entry+40,counter),11:0xf9400109|(((counter&4095)//8)<<10),
        12:0x9100052a,13:0xf900010a|(((counter&4095)//8)<<10),14:0xb40000c9,
        17:0xa8c17bfd,18:0xd50323ff,19:branch(entry+76,0x410),20:branch(entry+80,0x430,True),
        23:0xa8c17bfd,24:0xd50323ff,25:branch(entry+100,0x410)}.items()})
    words.update(changes or {})
    records=[symbol(name,value=offset,size=size) for name,offset,size in names]
    for index,(_,_,_,vtable,_) in enumerate(CONSTRUCTORS):
        records.append(symbol(vtable,value=0x7100+index*0x20,size=32,kind=1))
        relocations.append((0x7040+index*8,257,len(records),0))
    for index,target_index in enumerate((10,12)):
        slot=0x7020+index*8;stub=0x440+index*16
        relocations.append((slot,1026,target_index+1,0))
        words.update({stub:adrp(16,stub,slot),stub+4:0xf9400211|((slot-0x7000)//8<<10),
            stub+8:0x91000210|((slot-0x7000)<<10),stub+12:0xd61f0220})
    words.update({0x600+n*4:w for n,w in enumerate((0xd503237f,0xa9be7bfd,0xf9000bf3,0x910003fd,
        adrp(8,0x610,0x7040),0xaa0003f3,0xaa1303e1,0xf9402108,0x91004108,0xf9000008,
        0x91122000,branch(0x62c,0x440,True),0x91126260,0x91122261,branch(0x638,0x450,True),
        0x7909a27f,0xf902667f,0xf902627f,0xf9025e7f,0xf9400bf3,0xa8c27bfd,0xd65f0fff))})
    words.update({0x680+n*4:w for n,w in enumerate((adrp(8,0x680,0x7048),0xf9402508,0x91004108,0xa9000408,RET))})
    words.update({0x700+n*4:w for n,w in enumerate((0x3900401f,adrp(8,0x704,0x7050),0xf9402908,
        0xf9000c01,0x91004108,0xa9007c08,RET))})
    words.update(changes or {})
    raw=synthetic_image([(s[0],s[5],s[6],s[2],s[3]) for s in records],words)
    table=b''.join(struct.pack('<QQq',off,(index<<32)|kind,addend) for off,kind,index,addend in relocations)
    raw=change_memory(raw,0x5800,table)
    raw=change_memory(raw,0x2000+6*16,b''.join(struct.pack('<qQ',tag,value) for tag,value in
        ((23,0x5800),(2,len(table)),(20,7),(0,0))))
    sdk=Module('sdk',raw);linker=Linker([sdk]);assert linker.apply()['link_complete']
    old=dict(format='oot-graphics-sdk-audit',graphics_runtime=True,functions=[],
        graphics_bootstrap=dict(skipped_provider_closure=True))
    return linker,sdk,old

class DisplayAuditTests(unittest.TestCase):
    def test_source_bound_void_initializer_and_all_other_exports_guarded(self):
        linker,sdk,old=fixture();before=deepcopy(old);image=bytes(sdk.image)
        report=extend_display_audit(linker,old)
        self.assertEqual(old,before);self.assertEqual(bytes(sdk.image),image)
        self.assertIs(report['display_runtime'],True)
        domain=report['display_initialization'];self.assertTrue(domain['skipped_provider_closure'])
        self.assertEqual(domain['exported_consumers'],11)
        names={name:r for r in report['functions'] for name in r['names']}
        self.assertEqual(names[INITIALIZE]['handler_id'],450)
        self.assertFalse(names[INITIALIZE]['returns_value']);self.assertIsNone(names[INITIALIZE]['return_register'])
        for name in (LOWER,'_ZN2nn3vi23sdk10InitializeEv','_ZN2nn2vi18OpenDefaultDisplayEPPNS0_7DisplayE',
            '_ZNK2nn2vi7Display8GetWidthEv'):
            self.assertEqual(names[name]['handler_id'],31)
        self.assertEqual(len(domain['callees']),5)
        self.assertEqual(len(domain['original_constructors']),3)
        for first,second,_,_,_ in CONSTRUCTORS:
            self.assertNotIn(first,names);self.assertNotIn(second,names)

    def test_counter_must_remain_full_width_writable_and_separate_from_mutex(self):
        linker,_,old=fixture(counter=0x7ff8)
        self.assertTrue(extend_display_audit(linker,old)['display_initialization']['skipped_provider_closure'])
        for counter in (0x5f00,0x7180,0x8200,0x9000):
            linker,_,old=fixture(counter=counter)
            with self.subTest(counter=counter),self.assertRaises(InputError):extend_display_audit(linker,old)

    def test_complete_stack_refcount_check_and_both_void_return_routes_are_required(self):
        for index in range(26):
            linker,_,old=fixture({0x100+index*4:NOP})
            with self.subTest(index=index),self.assertRaises(InputError):extend_display_audit(linker,old)

    def test_parsed_census_text_and_original_callee_bindings_cannot_be_forged(self):
        for change in ('name','remove','hash','got','scope','vtable'):
            linker,sdk,old=fixture()
            if change=='name':sdk.symbols[-1]=replace(sdk.symbols[-1],name='unrelated')
            if change=='remove':sdk.symbols.pop()
            if change=='hash':sdk.header['segments'][0]['hash_verified']=False
            if change=='got':struct.pack_into('<Q',sdk.image,0x7000,sdk.base+0x218)
            if change=='scope':old['graphics_runtime']=False
            if change=='vtable':struct.pack_into('<Q',sdk.image,0x7040,sdk.base+0x7140)
            with self.subTest(change=change),self.assertRaises(InputError):extend_display_audit(linker,old)

    def test_preinitialization_original_constructors_keep_their_full_roles(self):
        for begin,count in ((0x600,22),(0x680,5),(0x700,7)):
            for index in range(count):
                linker,_,old=fixture({begin+index*4:NOP})
                with self.subTest(begin=begin,index=index),self.assertRaises(InputError):extend_display_audit(linker,old)

if __name__=='__main__':unittest.main()
