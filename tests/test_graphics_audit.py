"""Artificial static GS ABI/PLT and skipped-provider census evidence."""
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
from graphics_audit import extend_graphics_audit,BOOT,PUBLIC,CHECK,REMOTE,CALLEES,ALLOCATOR,GET_ALLOCATOR

def fixture(changes=None,*,state_address=0x7100):
    boot,check,plt=0x100,0x200,0x300
    words={0:branch(0,0x40),0x40:RET,0x50:branch(0x50,plt),0x60:0x52800020,0x64:RET,0x70:RET}
    words.update({boot+4*n:NOP for n in range(56)})
    words.update({boot+4*n:w for n,w in {
        0:0xd503237f,5:adrp(21,boot+20,state_address),6:0x910002b5|((state_address&4095)<<10),7:0xaa0103f3,8:0xaa0003f4,
        9:0xb8bfc2a8,10:0x7100051f,11:0x54000000|((45-11)<<5),
        14:0xb8bfc2a8,15:0x7100051f,16:0x54000000|((42-16)<<5),22:0x52800036,
        40:0xa9000000|(1<<15)|(19<<10)|(21<<5)|20,41:0x889ffc00|(21<<5)|22,
        45:adrp(8,boot+45*4,state_address+8),46:0x91000108|(((state_address+8)&4095)<<10),47:0xa9402109,48:0xeb14013f,
        49:0xfa530100,50:0x54000001|((55-50)<<5),54:0xd65f0fff}.items()})
    symbols=[symbol(PUBLIC,value=0x50,size=4),symbol(BOOT,value=boot,size=224),
        symbol(CHECK,value=check,size=40),symbol(REMOTE,value=0x60,size=8),
        symbol('_ZN2nn3gsv11UnsupportedEv',value=0x70,size=4)]
    symbols.append(symbol(ALLOCATOR,value=0x500,size=28))
    words.update({0x500:0xaa0303e4,0x504:0xaa0203e3,0x508:0xaa0103e2,0x50c:0xaa0003e1,
        0x510:adrp(0,0x510,0x7180),0x514:0x91060000,0x518:branch(0x518,0x540),0x540:RET})
    symbols.append(symbol(GET_ALLOCATOR,value=0x600,size=40))
    for n,target in enumerate((0x680,0x684,0x688)):
        pc=0x600+n*12;delta=target-(pc+4)
        words.update({pc:NOP,pc+4:0x10000008|((delta&3)<<29)|(((delta>>2)&0x7ffff)<<5),
            pc+8:0xf9000008|(n<<5),target:RET})
    words[0x624]=RET
    relocations=[(0x7000,1026,2,0)]
    # Real relocation-backed PLTs to independent RET callees. These are not
    # original SDK bodies and are never generated into executable callbacks.
    for n,(at,name) in enumerate(CALLEES.items()):
        offset=0x400+n*4;slot=0x7008+n*8;target=0x310+n*16
        symbols.append(symbol(name,value=offset,size=4));words[offset]=RET
        relocations.append((slot,1026,len(symbols),0))
        words[boot+at*4]=branch(boot+at*4,target,True)
        words[target]=adrp(16,target,slot);words[target+4]=0xf9400211|((slot-0x7000)//8<<10)
        words[target+8]=0x91000210|((slot-0x7000)<<10);words[target+12]=0xd61f0220
    words.update({plt:adrp(16,plt,0x7000),plt+4:0xf9400211,plt+8:0x91000210,plt+12:0xd61f0220})
    check_words=[adrp(8,check,state_address),0x91000108|((state_address&4095)<<10),0xb8bfc108,0x7100051f,0x54000041,
                 RET,0xd503237f,0xa9bf7bfd,0x910003fd,branch(check+36,0x310+9*16,True)]
    words.update({check+n*4:w for n,w in enumerate(check_words)})
    words.update(changes or {})
    raw=synthetic_image([(s[0],s[5],s[6],s[2],s[3]) for s in symbols],words)
    table=b''.join(struct.pack('<QQq',off,(index<<32)|kind,addend) for off,kind,index,addend in relocations)
    raw=change_memory(raw,0x5800,table)
    raw=change_memory(raw,0x2000+6*16,b''.join(struct.pack('<qQ',tag,value) for tag,value in
        ((23,0x5800),(2,len(table)),(20,7),(0,0))))
    sdk=Module('sdk',raw)
    linker=Linker([sdk]);assert linker.apply()['link_complete']
    original=dict(format='oot-application-sdk-audit',application_runtime=True,
        functions=[],application_providers=[],application_resource_identity={'exported_am_consumer_closure':True})
    return linker,sdk,original

class GraphicsAuditTests(unittest.TestCase):
    def test_state_can_use_original_zero_initialized_bss_but_not_leave_it(self):
        linker,_,old=fixture(state_address=0x7300)
        self.assertTrue(extend_graphics_audit(linker,old)['graphics_bootstrap']['skipped_provider_closure'])
        linker,_,old=fixture(state_address=0x9000)
        with self.assertRaises(InputError):extend_graphics_audit(linker,old)
    def test_source_bound_void_handlers_and_full_skipped_provider_closure(self):
        linker,sdk,old=fixture();before=deepcopy(old);image=bytes(sdk.image)
        r=extend_graphics_audit(linker,old)
        self.assertEqual(old,before);self.assertEqual(bytes(sdk.image),image)
        names={name:row for row in r['functions'] for name in row['names']}
        self.assertEqual(names[BOOT]['handler_id'],448)
        self.assertEqual(names[PUBLIC]['handler_id'],448)
        self.assertEqual(names[CHECK]['handler_id'],449)
        self.assertTrue(all(not names[n]['returns_value'] for n in (BOOT,PUBLIC,CHECK)))
        self.assertNotIn(REMOTE,names)
        self.assertNotIn(ALLOCATOR,names)
        self.assertNotIn(GET_ALLOCATOR,names)
        self.assertEqual(names['_ZN2nn3gsv11UnsupportedEv']['handler_id'],31)
        for dependency in (
            '_ZN2nn3gsv20BootWithRemoteMemoryENS0_12MemoryRegionE',
            '_ZN2nn5nvsrv20BootWithRemoteMemoryENS_3gsv12MemoryRegionEPDoFNS_2os17RemoteMemoryUsageEvE',
            '_ZN2nn6syncpt3sdk12InitializeExEPvmNS1_14LibraryOptionsE',
            '_ZN2nn3gpu3sdk20BootWithRemoteMemoryENS_3gsv12MemoryRegionE'):
            self.assertEqual(names[dependency]['handler_id'],31)
        self.assertTrue(r['graphics_bootstrap']['skipped_provider_closure'])

    def test_argument_pair_state_branches_return_and_precondition_are_required(self):
        for at in (0x50,0x60,0x100+7*4,0x100+8*4,0x100+11*4,0x100+40*4,
                   0x100+41*4,0x100+47*4,0x100+48*4,0x100+49*4,0x100+50*4,
                   0x100+54*4,0x200+8,0x200+16,0x200+20,0x500,0x518,0x604,0x608,0x624):
            with self.subTest(at=at):
                linker,_,old=fixture({at:NOP})
                with self.assertRaises(InputError):extend_graphics_audit(linker,old)

    def test_census_and_original_text_cannot_be_forged_by_parsed_symbols(self):
        for change in ('name','remove','hash','got','call'):
            linker,sdk,old=fixture()
            if change=='name':sdk.symbols[5]=replace(sdk.symbols[5],name='unrelated')
            if change=='remove':sdk.symbols.pop()
            if change=='hash':sdk.header['segments'][0]['hash_verified']=False
            if change=='got':struct.pack_into('<Q',sdk.image,0x7000,sdk.base+0x70)
            if change=='call':struct.pack_into('<I',sdk.image,0x100+24*4,NOP)
            with self.subTest(change=change),self.assertRaises(InputError):extend_graphics_audit(linker,old)

if __name__=='__main__':unittest.main()
