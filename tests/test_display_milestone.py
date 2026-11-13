"""A display milestone retains the graphics lane and requires the actual VI frontier."""
import json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from input_formats import InputError
from run_milestone import validate_display_config

class DisplayMilestoneTests(unittest.TestCase):
    def config(self):return json.loads((ROOT/'config/milestones/display-initialization.json').read_text())
    def test_real_display_and_both_prior_profile_proofs_are_explicit(self):
        c=self.config();validate_display_config(c)
        self.assertTrue(c['graphics_experiment'] and c['application_experiment'])
        self.assertIn('test_display*.py',c['gcc_tests'])
        self.assertEqual(c['graphics_expected_guard'],'_ZN2nn3gsv14GetUserSessionEv')
        self.assertEqual(c['application_resource_owner'],1)
        # Replacing an earlier whole parent elides its original instructions.
        # Prefix/native-return proof establishes progress, not larger counters.
        self.assertLess(c['display_min_post_entry'],c['graphics_min_post_entry'])
        validate_display_config(dict(name='older-profile'))
    def test_missing_or_crossed_scope_source_and_endpoint_reject(self):
        for key,value in (('display_experiment',False),('display_experiment',1),
            ('graphics_experiment',False),('application_experiment',False),
            ('display_seed_report',''),('display_baseline',''),('display_min_post_entry',0),
            ('display_min_post_entry',True),('display_expected_guard',None)):
            c=self.config();c[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(InputError):validate_display_config(c)

if __name__=='__main__':unittest.main()
