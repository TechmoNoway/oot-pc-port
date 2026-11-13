"""Closed graphics milestone scope retains the preceding application lane."""
import json
from pathlib import Path
import sys,unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from input_formats import InputError
from run_milestone import validate_graphics_config

class GraphicsMilestoneTests(unittest.TestCase):
    def config(self):return json.loads((ROOT/'config/milestones/graphics-bootstrap.json').read_text())
    def test_config_requires_real_graphics_and_preserves_resource_profile_proof(self):
        c=self.config();validate_graphics_config(c)
        self.assertEqual(c['application_expected_guard'],
            '_ZN2nn2am21GetGraphicsSupervisorENS_2sf3OutINS1_12NativeHandleEvEE')
        self.assertEqual(c['application_resource_owner'],1)
        self.assertIn('test_graphics*.py',c['gcc_tests'])
        self.assertGreater(c['graphics_min_post_entry'],c['application_min_post_entry'])
        validate_graphics_config(dict(name='older-profile'))
    def test_missing_or_crossed_scope_provenance_and_endpoint_reject(self):
        for key,value in (('graphics_experiment',False),('graphics_experiment',1),
            ('application_experiment',False),('application_resource_progress_baseline',''),
            ('graphics_seed_report',''),('graphics_baseline',''),('graphics_min_post_entry',0),
            ('graphics_min_post_entry',True),('graphics_min_post_entry',311543),('graphics_expected_guard',None)):
            c=self.config();c[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(InputError):validate_graphics_config(c)

if __name__=='__main__':unittest.main()
