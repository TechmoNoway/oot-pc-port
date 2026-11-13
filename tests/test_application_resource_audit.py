"""Independent synthetic wrapper/PLT/getter and consumer-census provenance."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import struct,sys,unittest
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from module_linker import Linker,Module
from arm64_decode import Decoder
from sdk_startup_audit import _stage
from test_module_linker import symbol
from test_arm64_analysis import synthetic_module,branch,RET
from input_formats import InputError
from application_audit import extend_application_resource_audit

APP='_ZN2nn6applet23GetAppletResourceUserIdEv'
AM='_ZN2nn2am23GetAppletResourceUserIdEv'
OTHER='_ZN2nn2am12GetFakeEventEv'


def fixture(changes=None,*,getter_size=12,public_size=4):
    words={0:branch(0,0x40),0x40:RET,0x50:branch(0x50,0xc0),
        0x60:0xd0000008,0x64:0xf9400900,0x68:RET,0x70:RET,
        0xc0:0xd0000010,0xc4:0xf9400211,0xc8:0x91000210,0xcc:0xd61f0220}
    words.update(changes or {})
    sdk=Module('sdk',synthetic_module(words,symbols=[symbol(APP,value=0x50,size=public_size),
        symbol(AM,value=0x60,size=getter_size),symbol(OTHER,value=0x70)],plt=((0x2000,1026,2,0),)))
    linker=Linker([sdk]);assert linker.apply()['link_complete']
    row=_stage(linker.modules,'guard_'+APP,'sdk',APP,Decoder())
    row.update(handler_id=31,names=[APP],returns_value=False,return_register=None,implementation='guard',
               signature='unsupported SDK initialization-model consumer',entry_word=row['entry_instruction']['word'])
    original=dict(format='oot-application-sdk-audit',application_runtime=True,functions=[row],application_providers=[])
    return linker,sdk,original


class ApplicationResourceAuditTests(unittest.TestCase):
    def test_full_width_getter_and_complete_consumer_closure_preserve_prior_audit(self):
        linker,sdk,old=fixture();before=deepcopy(old);image=bytes(sdk.image)
        report=extend_application_resource_audit(linker,old)
        self.assertEqual(old,before);self.assertEqual(bytes(sdk.image),image)
        functions={r['symbol']:r for r in report['functions']}
        for name in (APP,AM):
            self.assertEqual((functions[name]['handler_id'],functions[name]['returns_value'],functions[name]['return_register']),(322,True,'X0'))
        self.assertEqual(functions[OTHER]['handler_id'],31)
        self.assertEqual(len(report['application_providers']),2)
        self.assertEqual(report['application_resource_identity']['return_bytes'],8)
        self.assertTrue(report['application_resource_identity']['exported_am_consumer_closure'])

    def test_thunk_plt_getter_width_base_return_and_body_extent_must_match(self):
        for at,word in ((0x50,branch(0x50,0xc0,True)),(0xc0,RET),
                        (0x60,0xd0000009),(0x64,0xb9400900),(0x64,0xf9400920),(0x68,0xd65f0fff)):
            with self.subTest(at=at,word=word):
                linker,sdk,old=fixture({at:word})
                with self.assertRaises(InputError):extend_application_resource_audit(linker,old)
        for kwargs in (dict(getter_size=8),dict(getter_size=16),dict(public_size=8)):
            linker,sdk,old=fixture(**kwargs)
            with self.subTest(extents=kwargs),self.assertRaises(InputError):extend_application_resource_audit(linker,old)

    def test_parsed_symbol_census_names_kinds_and_bound_got_cannot_omit_consumers(self):
        for mutation in ('name','kind','remove','got','alias','guard','old_word','old_instruction','old_symbol','unverified'):
            linker,sdk,old=fixture()
            if mutation=='name':sdk.symbols[3]=replace(sdk.symbols[3],name='unrelated')
            if mutation=='kind':sdk.symbols[3]=replace(sdk.symbols[3],kind=1)
            if mutation=='remove':sdk.symbols.pop()
            if mutation=='got':struct.pack_into('<Q',sdk.image,0x2000,sdk.base+0x70)
            if mutation=='alias':old['functions'][0]['names'].append('alias')
            if mutation=='guard':old['functions'][0]['handler_id']=320
            if mutation=='old_word':old['functions'][0]['entry_word']^=1
            if mutation=='old_instruction':old['functions'][0]['entry_instruction']['word']^=1
            if mutation=='old_symbol':old['functions'][0]['symbol']='other'
            if mutation=='unverified':sdk.header['segments'][0]['hash_verified']=False
            with self.subTest(mutation=mutation),self.assertRaises(InputError):extend_application_resource_audit(linker,old)


if __name__=='__main__':unittest.main()
