"""Synthetic native SDK binding and logging-record evidence; no game execution."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from input_formats import InputError
from module_linker import Linker,Module
from native_sdk_audit import FUNCTIONS,PUT_SYMBOL,OE_INITIALIZE_SYMBOL,audit_native_sdk
from test_arm64_analysis import RET,NOP,branch,synthetic_module


def adr(pc,target,rd=0):
    delta=target-pc
    return 0x10000000|((delta&3)<<29)|(((delta>>2)&0x7ffff)<<5)|rd


def fixture(*,missing=None,hidden=None,alias=None,changes=None,after_capture=(),before_capture=(),oe_initialize=False):
    """Independent artificial exports, two self-PLTs and a record consumer."""
    offsets={name:0x100+index*0x20 for index,(_,name,_,_) in enumerate(FUNCTIONS)}
    if alias:
        name,target=alias if isinstance(alias,tuple) else (alias,'lm_set_destination')
        offsets[name]=offsets[target]
    put,observer,emit_plt,replace_plt=0x300,0x600,0x900,0x910
    words={0:branch(0,0x40),0x40:RET}
    sizes={name:4 for name in offsets};sizes['lm_initialize']=12
    for address in offsets.values():words[address]=RET
    words.update({offsets['lm_initialize']:adr(offsets['lm_initialize'],observer),
                  offsets['lm_initialize']+4:branch(offsets['lm_initialize']+4,replace_plt),
                  offsets['lm_initialize']+8:RET})
    recipe=[0x52800000|(0x101<<5)|8,
            0xf9000000|(1<<10)|(31<<5)|1,
            0x91000000|(8<<10)|(31<<5)|1,
            0xa9000000|(2<<15)|(8<<10)|(31<<5)|2,
            branch(put+16,emit_plt,True),RET]
    words.update({put+index*4:word for index,word in enumerate(recipe)})
    consumer=[*before_capture,0xaa0103f3,0xaa0003f4,*after_capture,
        0x29400000|(8<<15)|(5<<10)|(20<<5)|4,
        0x39400000|(17<<10)|(19<<5)|8,
        0x39400000|(16<<10)|(19<<5)|7,
        0x39400000|(16<<10)|(19<<5)|8,
        0x7100001f|(1<<10)|(8<<5),
        0xb9400000|(20<<5)|1,
        0xf9400000|(1<<10)|(20<<5)|21,
        0xf9400000|(2<<10)|(20<<5)|21,
        0xf9400000|(3<<10)|(20<<5)|20,
        0xa9400000|(2<<10)|(19<<5)|1]
    for index in range(0x250//4):words[observer+index*4]=consumer[index] if index<len(consumer) else NOP
    words[observer+0x24c]=RET
    symbols=[(symbol,offsets[name],sizes[name],2 if name==hidden else 0)
             for _,name,symbol,_ in FUNCTIONS if name!=missing]
    symbols.append((PUT_SYMBOL,put,len(recipe)*4,0))
    if oe_initialize:
        symbols.append((OE_INITIALIZE_SYMBOL,0x2c0,4,0));words[0x2c0]=RET
    names={name:index+1 for index,(name,*_) in enumerate(symbols)}
    for address,got in ((emit_plt,0x5000),(replace_plt,0x5008)):
        pages=(got>>12)-(address>>12);low=got&4095
        words[address]=0x90000010|((pages&3)<<29)|(((pages>>2)&0x7ffff)<<5)
        words[address+4]=0xf9400000|((low//8)<<10)|(16<<5)|17
        words[address+8]=0x91000000|(low<<10)|(16<<5)|16
        words[address+12]=0xd61f0220
    words.update(changes or {})
    text,ro,data=bytearray(4096),bytearray(8192),bytearray(512)
    for address,word in words.items():struct.pack_into('<I',text,address,word)
    struct.pack_into('<I',text,4,0x80);text[0x80:0x84]=b'MOD0'
    struct.pack_into('<6i',text,0x84,*[offset-0x80 for offset in (0x2000,0x5200,0x6200,0x3e00,0x3e00,0x5010)])
    strings=bytearray(b'\0');records=bytearray(24)
    for name,offset,size,visibility in symbols:
        index=len(strings);strings+=name.encode()+b'\0'
        records+=struct.pack('<IBBHQQ',index,0x12,visibility,1,offset,size)
    assert len(strings)<0x800 and len(records)<0x400
    ro[0x800:0x800+len(strings)]=strings;ro[0x1000:0x1000+len(records)]=records
    count=len(symbols)+1
    struct.pack_into('<'+'I'*(3+count),ro,0x1400,1,count,*([0]*(count+1)))
    relocations=b''.join(struct.pack('<QQq',got,(names[name]<<32)|1026,0)
        for got,name in ((0x5000,FUNCTIONS[2][2]),(0x5008,FUNCTIONS[6][2])))
    ro[0x1500:0x1500+len(relocations)]=relocations
    dynamic=[(5,0x2800),(10,len(strings)),(6,0x3000),(11,24),(4,0x3400),(12,0x40),
             (23,0x3500),(2,len(relocations)),(20,7),(0,0)]
    table=b''.join(struct.pack('<qQ',tag,value) for tag,value in dynamic);ro[:len(table)]=table
    header=bytearray(256);header[:4]=b'NSO0';struct.pack_into('<I',header,12,0x38)
    struct.pack_into('<I',header,60,4096)
    struct.pack_into('<4I',header,144,0x800,len(strings),0x1000,len(records))
    raw=bytearray(header)
    for index,(address,content) in enumerate(((0,text),(0x2000,ro),(0x5000,data))):
        struct.pack_into('<III',raw,16+index*16,len(raw),address,len(content))
        struct.pack_into('<I',raw,96+index*4,len(content));raw[160+index*32:192+index*32]=hashlib.sha256(content).digest();raw+=content
    linker=Linker([Module('sdk',bytes(raw))]);assert linker.apply()['link_complete']
    return linker,bytes(raw),offsets


class NativeSdkAuditTests(unittest.TestCase):
    def test_exact_exports_bodies_record_layout_and_no_mutation(self):
        linker,_,offsets=fixture();module=linker.modules[0];before=bytes(module.image)
        report=audit_native_sdk(linker)
        self.assertEqual((report['format'],len(report['functions'])),('oot-native-sdk-audit',13))
        self.assertEqual(sorted(row['handler_id'] for row in report['functions']),[1,3,5,6]+[31]*9)
        for row in report['functions']:
            self.assertEqual(row['body_sha256'],hashlib.sha256(module.read(row['offset'],row['size'])).hexdigest())
            self.assertFalse(row['original_body_executed']);self.assertFalse(row['returns_value'])
        self.assertEqual(report['logging_contract']['body']['bytes'],24)
        self.assertEqual(report['logging_contract']['metadata']['consumed_prefix_bytes'],40)
        self.assertIsNone(report['original_oe_initialize'])
        self.assertFalse(report['logging_contract']['metadata']['complete_structure_layout_proven'])
        self.assertTrue(all(report[key] is False for key in ('guest_code_executed','translation_performed',
            'native_callbacks_registered','runtime_capabilities_granted','sdk_initialization_completed','game_entry_reached')))
        self.assertEqual(bytes(module.image),before)

    def test_missing_hidden_wrong_kind_parsed_metadata_and_alias_contracts(self):
        for name in ('lm_set_destination','diag_enable_default','guard_get_log'):
            with self.subTest(name=name),self.assertRaises(InputError):audit_native_sdk(fixture(missing=name)[0])
        with self.assertRaises(InputError):audit_native_sdk(fixture(hidden='diag_emit')[0])
        with self.assertRaises(InputError):audit_native_sdk(fixture(alias='diag_enable_default')[0])
        linker,_,_=fixture();module=linker.modules[0]
        index=next(i for i,s in enumerate(module.symbols) if s.name==FUNCTIONS[1][2])
        original=module.symbols[index]
        for field,value in (('kind',1),('size',8),('visibility',2),('name','different')):
            module.symbols[index]=replace(original,**{field:value})
            with self.subTest(field=field),self.assertRaises(InputError):audit_native_sdk(linker)
        module.symbols[index]=original

    def test_changed_recipe_observer_fields_installation_and_call_target_rejected(self):
        mutations=[{0x300:0x52800008}, # Wrong head/tail flags.
                   {0x308:0x910023e0}, # Wrong record argument register.
                   {0x310:branch(0x310,0x910,True)}, # Calls replacement instead of emission.
                   {0x600+2*4:0x29400000|(9<<15)|(5<<10)|(20<<5)|4},
                   {0x600+9*4:NOP}, # Missing pointer/size pair consumption.
                   {0x104:branch(0x104,0x900)}] # Installs via wrong target.
        for changes in mutations:
            with self.subTest(changes=changes),self.assertRaises(InputError):audit_native_sdk(fixture(changes=changes)[0])

    def test_requires_complete_link_and_unchanged_text(self):
        linker,_,_=fixture();linker.applied=False
        with self.assertRaises(InputError):audit_native_sdk(linker)

    def test_input_roles_reject_clobbers_with_all_original_fields_retained(self):
        # These insertions retain every formerly required instruction word.
        for word in (0xaa1f03f3,0xaa1f03f4,0x2a1f03f3,0x2a1f03f4,
                     0xaa0103f3,0xaa0003f4):
            with self.subTest(word=word),self.assertRaises(InputError):
                audit_native_sdk(fixture(after_capture=(word,))[0])
        for word in (0xaa1f03e0,0xaa1f03e1,branch(0x600,0x900,True),
                     0xf9402003,0xf9400023): # Reads through incoming X0/X1.
            with self.subTest(prefix=word),self.assertRaises(InputError):
                audit_native_sdk(fixture(before_capture=(word,))[0])
        linker,_,_=fixture();linker.modules[0].image[0x500]^=1
        with self.assertRaises(InputError):audit_native_sdk(linker)

    def test_identical_guard_aliases_share_one_bound_descriptor(self):
        linker,_,_=fixture(alias=('guard_unregister','guard_register'))
        functions=audit_native_sdk(linker)['functions']
        self.assertEqual(len(functions),12)
        aliases=[row for row in functions if len(row['names'])==2]
        self.assertEqual(len(aliases),1)
        self.assertEqual(aliases[0]['handler_id'],31)

    def test_optional_oe_entry_is_observation_not_a_native_binding(self):
        linker,_,_=fixture(oe_initialize=True)
        report=audit_native_sdk(linker);observer=report['original_oe_initialize']
        self.assertEqual(observer['symbol'],OE_INITIALIZE_SYMBOL)
        self.assertTrue(observer['observation_only'])
        self.assertFalse(observer['native_execution'])
        self.assertTrue(observer['original_entry_retirement_required'])
        self.assertEqual(observer['body_sha256'],hashlib.sha256(struct.pack('<I',RET)).hexdigest())
        self.assertNotIn(observer['entry'],[row['entry'] for row in report['functions']])

    def test_cli_private_fresh_report_and_outside_build_rejection(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build',prefix='native-sdk-audit-') as temporary:
            folder=Path(temporary);prepared=folder/'prepared';prepared.mkdir()
            _,sdk,_=fixture();main=synthetic_module()
            records=[]
            for name,data in (('main',main),('sdk',sdk)):
                (prepared/name).write_bytes(data)
                records.append(dict(name=name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
            (prepared/'manifest.json').write_text(json.dumps(dict(schema_version=1,format='prepared-exefs',files=records)))
            destination=folder/'report.json'
            argv=[sys.executable,'-B',str(ROOT/'tools/native_sdk_audit.py'),str(prepared),'--report',str(destination)]
            first=subprocess.run(argv,capture_output=True,text=True,timeout=60)
            self.assertEqual(first.returncode,0,first.stderr)
            self.assertEqual(json.loads(first.stdout)['native_operations'],4)
            before=destination.read_bytes();second=subprocess.run(argv,capture_output=True,text=True,timeout=60)
            self.assertNotEqual(second.returncode,0);self.assertEqual(destination.read_bytes(),before)
            bad=subprocess.run(argv[:-1]+[str(ROOT/'not-private-native-audit.json')],capture_output=True,text=True,timeout=60)
            self.assertNotEqual(bad.returncode,0);self.assertFalse((ROOT/'not-private-native-audit.json').exists())


if __name__=='__main__':unittest.main()
