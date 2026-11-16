import json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(ROOT/'tools'))
from input_formats import InputError
from run_milestone import validate_events_config
class EventMilestoneTests(unittest.TestCase):
    def config(self):return json.loads((ROOT/'config/milestones/system-events.json').read_text())
    def test_preserves_object_lane_and_records_the_measured_next_boundary(self):
        c=self.config();validate_events_config(c);self.assertTrue(c['objects_experiment'])
        validate_events_config({'name':'older-profile'})
    def test_crossed_flags_baseline_and_boundary_reject(self):
        for key,value in(('events_experiment',False),('events_experiment',1),('objects_experiment',False),
            ('events_baseline',''),('events_min_post_entry',True),('events_min_post_entry',311502),('events_expected_guard',None)):
            c=self.config();c[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(InputError):validate_events_config(c)
if __name__=='__main__':unittest.main()
