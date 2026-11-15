"""An explicit object profile retains the complete earlier display lane."""
import json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'tools'))
from run_milestone import validate_objects_config
from input_formats import InputError
ROOT=Path(__file__).resolve().parent.parent
class ObjectsMilestoneTests(unittest.TestCase):
    def config(self):return json.loads((ROOT/'config/milestones/display-objects.json').read_text())
    def test_explicit_profile_source_baseline_and_measured_event_boundary(self):
        c=self.config();validate_objects_config(c)
        self.assertTrue(c['display_experiment']);self.assertIn('test_native_*.py',c['gcc_tests'])
        validate_objects_config({'name':'older-profile'})
    def test_missing_or_crossed_profile_and_unmeasured_boundary_reject(self):
        for key,value in(('objects_experiment',False),('objects_experiment',1),('display_experiment',False),
            ('objects_baseline',''),('objects_min_post_entry',True),('objects_min_post_entry',311488),('objects_expected_guard',None)):
            c=self.config();c[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(InputError):validate_objects_config(c)
if __name__=='__main__':unittest.main()
