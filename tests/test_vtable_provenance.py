"""Artificial relocated polymorphic tables; no original game bytes or addresses."""
from copy import deepcopy
from dataclasses import replace
import hashlib,json,struct,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from input_formats import InputError
from module_linker import Linker,Module
from test_sdk_init_audit import synthetic_image
from test_module_linker import change_memory
from vtable_provenance import prove_vtables

NAME='_ZTV9Artificial'

def fixture(*,kind=257,addend=0,foreign=False,raw_edit=None):
    symbols=[(NAME,0x7080,40,1,0),('_ZTI9Artificial',0x70c0,8,1,0),
        ('artificial_method',0x180,8,2,0)]
    raw=synthetic_image(symbols,{0x180:0xd503201f,0x184:0xd65f03c0,
        0x240:0xd503201f,0x244:0xd65f03c0})
    cie=struct.pack('<I',16)+bytes(4)+b'\1zR\0\1\x7c\x1e\1\x1b\x0c\x1f\0'
    frame=0x5e80;first=frame+len(cie);second=first+20
    hdr=b'\1\x1b\3\x3b'+struct.pack('<iI4i',frame-0x5e04,2,
        0x180-0x5e00,first-0x5e00,0x240-0x5e00,second-0x5e00)
    raw=change_memory(raw,0x90,struct.pack('<i',0x5e00-0x80))
    raw=change_memory(raw,0x94,struct.pack('<i',0x5e1c-0x80))
    raw=change_memory(raw,0x5e00,hdr)
    raw=change_memory(raw,frame,cie)
    for at,pc in ((first,0x180),(second,0x240)):
        raw=change_memory(raw,at,struct.pack('<IIiI',16,at+4-frame,pc-at-8,8)+bytes(4))
    rela=b''.join(struct.pack('<QQq',offset,(index<<32)|k,a)for offset,index,k,a in
        ((0x7088,2,257,0),(0x7090,3,kind,addend)))
    raw=change_memory(raw,0x5800,rela)
    raw=change_memory(raw,0x5900,struct.pack('<QQ',0x7098,3))
    raw=change_memory(raw,0x7098,struct.pack('<QQ',0x240,0x180))
    raw=change_memory(raw,0x2060,b''.join(struct.pack('<qQ',tag,value)for tag,value in
        ((7,0x5800),(8,len(rela)),(9,24),(36,0x5900),(35,16),(37,8),(0,0))))
    if raw_edit:raw=raw_edit(raw)
    pristine=Module('sdk',raw);linked=Module('sdk',raw)
    modules=[linked]
    if foreign:
        other=Module('other',synthetic_image([('artificial_method',0x180,8,2,0)]))
        modules.insert(0,other)
    linker=Linker(modules);assert linker.apply()['link_complete']
    return pristine,linker,linked

class VtableProvenanceTests(unittest.TestCase):
    def test_complete_table_and_unique_extents_bind_rela_relr_aliases_without_authority(self):
        original,linker,sdk=fixture();before=(bytes(original.image),bytes(sdk.image),deepcopy(sdk.symbols))
        report=prove_vtables(original,linker,{NAME:3})
        self.assertFalse(report['runtime_capability']);self.assertFalse(report['guest_code_executed'])
        self.assertEqual(report['slot_count'],3);self.assertEqual(len(report['targets']),2)
        table=report['tables'][0]
        self.assertEqual(table['symbol'],NAME)
        self.assertEqual([s['relocation']['kind']for s in table['slots']],['ABS64','RELR','RELR'])
        self.assertEqual(table['linked_sha256'],hashlib.sha256(sdk.read(0x7080,40)).hexdigest())
        target=next(t for t in report['targets']if t['entry']==sdk.base+0x180)
        self.assertEqual(len(target['slots']),2);self.assertEqual(len(target['export_aliases']),1)
        private=next(t for t in report['targets']if t['entry']==sdk.base+0x240)
        self.assertEqual(private['export_aliases'],[])
        self.assertNotIn('symbol',private);self.assertNotIn('symbol_metadata',private)
        self.assertEqual(before,(bytes(original.image),bytes(sdk.image),sdk.symbols))

    def test_link_source_tables_and_parsed_metadata_must_agree(self):
        for change in ('source','unlinked','original-data','linked-text','linked-rodata','linked-slot',
                'dynamic','mod0','rela-cache','relr-cache','symbol','symbol-count','missing','slots'):
            original,linker,sdk=fixture();spec={NAME:3}
            if change=='source':sdk.source_sha256='ab'*32
            elif change=='unlinked':linker.applied=False
            elif change=='original-data':original.image[0x70a0]^=1
            elif change=='linked-text':sdk.image[0x180]^=1
            elif change=='linked-rodata':sdk.image[0x5800]^=1
            elif change=='linked-slot':sdk.image[0x7098]^=4
            elif change=='dynamic':sdk.dynamic[7]+=24
            elif change=='mod0':sdk.mod0['exception_start']+=4
            elif change=='rela-cache':sdk.rela=[]
            elif change=='relr-cache':sdk.relr=b''
            elif change=='symbol':sdk.symbols[1]=replace(sdk.symbols[1],name='forged')
            elif change=='symbol-count':sdk.symbols.pop()
            elif change=='missing':spec={'_ZTV7Missing':3}
            elif change=='slots':spec={NAME:2}
            with self.subTest(change=change),self.assertRaises(InputError):prove_vtables(original,linker,spec)

    def test_relocation_kind_addend_and_foreign_resolution_are_rejected(self):
        for args in ({'kind':1025},{'kind':1026},{'addend':4},{'foreign':True}):
            original,linker,sdk=fixture(**args)
            with self.subTest(args=args),self.assertRaises(InputError):prove_vtables(original,linker,{NAME:3})

    def test_original_table_shape_and_missing_relocation_are_rejected(self):
        for at,value in ((0x7080,8),(0x7098,0x244),(0x7098,0x7000)):
            original,linker,sdk=fixture()
            struct.pack_into('<Q',original.image,at,value)
            a,b=original.ranges[2]
            original.header['segments'][2]['sha256']=hashlib.sha256(original.read(a,b-a)).hexdigest()
            with self.subTest(at=at,value=value),self.assertRaises(InputError):prove_vtables(original,linker,{NAME:3})
        for spec in ({},{NAME:0},{NAME:True},{NAME:4097},{'invalid':3}):
            original,linker,sdk=fixture()
            with self.subTest(spec=spec),self.assertRaises(InputError):prove_vtables(original,linker,spec)

    def test_original_missing_slot_and_export_extent_conflict_cannot_be_relabelled(self):
        for offset,payload in ((0x5900,struct.pack('<QQ',0x70a0,1)),
                (0x4000+3*24+16,struct.pack('<Q',4)),
                (0x7080,struct.pack('<Q',0xfffffffffffffff8))):
            original,linker,sdk=fixture(raw_edit=lambda raw:change_memory(raw,offset,payload))
            with self.subTest(offset=offset),self.assertRaises(InputError):prove_vtables(original,linker,{NAME:3})

    def test_cli_emits_only_private_build_report_and_preserves_existing_evidence(self):
        parent=ROOT/'build/vtable-tests';parent.mkdir(parents=True,exist_ok=True)
        folder=Path(tempfile.mkdtemp(dir=parent));prepared=folder/'prepared';prepared.mkdir()
        captures=[]
        fixture(raw_edit=lambda raw:(captures.append(raw)or raw))
        files={'sdk':captures[0],'main':synthetic_image([])}
        manifest=[]
        for name,raw in files.items():
            (prepared/name).write_bytes(raw)
            manifest.append(dict(name=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
        (prepared/'manifest.json').write_text(json.dumps(dict(schema_version=1,format='prepared-exefs',files=manifest)))
        output=folder/'proof.json'
        command=[sys.executable,'-B',str(ROOT/'tools/vtable_provenance.py'),str(prepared),
            '--table',NAME+'=3','--output',str(output)]
        first=subprocess.run(command,capture_output=True,text=True,timeout=30)
        self.assertEqual(first.returncode,0,first.stdout+first.stderr)
        data=output.read_bytes();report=json.loads(data)
        self.assertFalse(report['runtime_capability']);self.assertEqual(report['slot_count'],3)
        again=subprocess.run(command,capture_output=True,text=True,timeout=30)
        self.assertNotEqual(again.returncode,0);self.assertEqual(output.read_bytes(),data)
        outside=subprocess.run(command[:-1]+[str(ROOT/'vtable-proof-must-not-exist.json')],
            capture_output=True,text=True,timeout=30)
        self.assertNotEqual(outside.returncode,0);self.assertIn('Output must be',outside.stderr)
        malformed=subprocess.run(command[:-1]+[str(folder/'bad.json'),'--table','broken'],
            capture_output=True,text=True,timeout=30)
        self.assertNotEqual(malformed.returncode,0);self.assertFalse((folder/'bad.json').exists())

if __name__=='__main__':unittest.main()
