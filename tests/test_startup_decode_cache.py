"""A pure decode memo cannot retain roots, native boundaries or image bytes."""
import sys
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from input_formats import InputError
from startup_audit import StartupDecodeCache,audit_entry
from test_startup_audit import linked
from test_arm64_analysis import branch,RET

class StartupDecodeCacheTests(unittest.TestCase):
    def test_application_simd_decode_does_not_cross_profiles(self):
        from arm64_decode import Decoder
        from startup_audit import _decode_entry_word
        cache=StartupDecodeCache();syntax=Decoder()
        for word in (0x7e21d808,0x4ea21c20,0x5e180423,0x6e180420,0x6e228c20,0x6ee21c20):
            for application in (False,True,False):
                decoded=cache.decode(syntax,word,0x1000,True,True,application)
                self.assertEqual(decoded,_decode_entry_word(syntax,word,0x1000,True,True,application))
                self.assertEqual(decoded[3]=='sdk_init_vector',application)

    def test_exact_reports_original_bytes_and_fresh_native_boundaries(self):
        linker=linked({0:branch(0,0x40),0x40:0x91000400,0x44:RET,0x60:RET})
        base=linker.modules[0].base;before=bytes(linker.modules[0].image)
        cache=StartupDecodeCache()
        for options in ({},{'sdk':True},{'sdk':True,'sdk_init':True},
                        {'sdk':True,'sdk_init':True,'native_entries':[base+0x40]},
                        {'sdk':True,'sdk_init':True,'extra_entries':[base+0x60]},{}):
            self.assertEqual(audit_entry(linker,decode_cache=cache,**options),audit_entry(linker,**options))
        self.assertGreater(cache.hits,0);self.assertEqual(bytes(linker.modules[0].image),before)

    def test_word_pc_profile_key_and_capacity_fallback(self):
        cache=StartupDecodeCache(limit=1)
        for word in (RET,0xd53b4400,0xd4200000):
            linker=linked({0:branch(0,0x40),0x40:word})
            for options in ({},{'sdk':True,'sdk_init':True}):
                self.assertEqual(audit_entry(linker,decode_cache=cache,**options),audit_entry(linker,**options))
        self.assertEqual(len(cache._rows),1)
        self.assertGreater(cache.misses,1);self.assertGreater(cache.hits,0)
        for limit in (0,True,1048577):
            with self.assertRaises(InputError):StartupDecodeCache(limit)
