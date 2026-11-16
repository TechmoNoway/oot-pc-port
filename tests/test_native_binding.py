"""Proved stage records must carry the exact source word into runtime guards."""
import hashlib,struct,unittest
from copy import deepcopy
from input_formats import InputError
from native_binding import bind_entry_word

class NativeBindingTests(unittest.TestCase):
    def stage(self):
        word=0xd503237f
        return dict(entry=0x2000,module='sdk',entry_instruction=dict(address=0x2000,module='sdk',word=word,
            sha256=hashlib.sha256(struct.pack('<I',word)).hexdigest()))
    def test_original_word_is_copied_without_mutating_the_stage(self):
        stage=self.stage();bound=bind_entry_word(stage)
        self.assertEqual(bound['entry_word'],0xd503237f);self.assertNotIn('entry_word',stage)
        self.assertEqual(bind_entry_word(bound),bound)
    def test_address_module_hash_word_and_conflicting_metadata_reject(self):
        for key,value in(('address',0x2004),('module','main'),('word',True),('word',0x100000000),('sha256','00'*32)):
            stage=self.stage();stage['entry_instruction'][key]=value
            with self.subTest(key=key),self.assertRaises(InputError):bind_entry_word(stage)
        stage=self.stage();stage['entry_word']=0
        with self.assertRaises(InputError):bind_entry_word(stage)

if __name__=='__main__':unittest.main()
