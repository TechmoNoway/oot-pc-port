"""Bounded original-name reads preserve complete metadata/hash evidence."""
from dataclasses import replace
import hashlib,struct,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from sdk_startup_audit import _symbol_record
from module_linker import Module
from test_sdk_init_audit import synthetic_image
from input_formats import InputError

class SdkSymbolRecordTests(unittest.TestCase):
    def fixture(self):
        return Module('sdk',synthetic_image([('symbol_'+('x'*512),0x100,4,2,0),('unicode_ế',0x120,4,2,0)]))
    def test_complete_original_record_and_name_hashes_match_independent_table_slices(self):
        m=self.fixture();before=bytes(m.image);strings=m.read(m.dynamic[5],m.dynamic[10])
        for n,symbol in enumerate(m.symbols):
            record=m.read(m.dynamic[6]+n*24,24);name,info,other,section,value,size=struct.unpack('<IBBHQQ',record)
            end=strings.find(b'\0',name)
            expected=dict(index=n,binding=info>>4,kind=info&15,visibility=other&3,section=section,value=value,size=size,
                record_sha256=hashlib.sha256(record).hexdigest(),name_sha256=hashlib.sha256(strings[name:end+1]).hexdigest())
            self.assertEqual(_symbol_record(m,n,symbol),expected)
        self.assertEqual(bytes(m.image),before)
    def test_unmapped_truncated_unterminated_and_invalid_utf8_names_reject(self):
        for mutation in ('range','truncated','terminator','utf8','parsed'):
            m=self.fixture();symbol=m.symbols[1]
            if mutation=='range':m.dynamic[5]=len(m.image)+1
            if mutation=='truncated':m.dynamic[10]=2
            if mutation=='terminator':m.image[m.dynamic[5]+1:m.dynamic[5]+m.dynamic[10]]=b'x'*(m.dynamic[10]-1)
            if mutation=='utf8':m.image[m.dynamic[5]+1]=0xff
            if mutation=='parsed':symbol=replace(symbol,name='forged')
            with self.subTest(mutation=mutation),self.assertRaises(InputError):_symbol_record(m,1,symbol)
