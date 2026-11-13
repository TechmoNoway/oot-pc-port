"""Closed resource progress configuration without game inputs or execution."""
from pathlib import Path
import sys,unittest
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from input_formats import InputError
from run_milestone import validate_resource_progress_config


class ApplicationResourceMilestoneTests(unittest.TestCase):
    def fixture(self):
        return dict(name='application-resource-identity',application_experiment=True,
                    application_resource_progress_baseline='build/baseline.json',application_resource_owner=1)

    def test_explicit_owned_process_and_native_baseline_required(self):
        validate_resource_progress_config(self.fixture())
        for key,values in (('application_resource_progress_baseline',(None,'',42)),
                           ('application_resource_owner',(None,True,0,2,'1')),
                           ('application_experiment',(False,1,None))):
            for value in values:
                config=self.fixture();config[key]=value
                with self.subTest(key=key,value=value),self.assertRaises(InputError):validate_resource_progress_config(config)
        config=self.fixture();config.pop('application_resource_progress_baseline')
        with self.assertRaises(InputError):validate_resource_progress_config(config)

    def test_older_milestone_remains_separate_but_cannot_bypass_an_explicit_proof(self):
        config=dict(name='application-narrow-cas',application_experiment=True)
        validate_resource_progress_config(config)
        config['application_resource_progress_baseline']='build/baseline.json'
        with self.assertRaises(InputError):validate_resource_progress_config(config)


if __name__=='__main__':unittest.main()
