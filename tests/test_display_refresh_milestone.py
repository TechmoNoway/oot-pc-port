import json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from input_formats import InputError
from run_milestone import validate_refresh_config

class RefreshMilestoneTests(unittest.TestCase):
    def config(self):return json.loads((ROOT/'config/milestones/display-refresh.json').read_text())
    def test_requires_retained_events_and_an_explicit_next_endpoint(self):
        c=self.config();validate_refresh_config(c);self.assertTrue(c['events_experiment'])
        validate_refresh_config({'name':'older-profile'})
    def test_crossed_flags_baseline_counts_and_endpoints_reject(self):
        for key,value in (('refresh_experiment',False),('refresh_experiment',1),('events_experiment',False),
            ('refresh_baseline',''),('refresh_min_post_entry',True),('refresh_min_post_entry',311509)):
            c=self.config();c[key]=value
            with self.subTest(key=key),self.assertRaises(InputError):validate_refresh_config(c)
        c=self.config()
        for k in ('refresh_expected_guard','refresh_expected_word','refresh_expected_svc'):c.pop(k,None)
        with self.assertRaises(InputError):validate_refresh_config(c)

if __name__=='__main__':unittest.main()
