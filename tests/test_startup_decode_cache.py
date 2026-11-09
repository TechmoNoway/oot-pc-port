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
