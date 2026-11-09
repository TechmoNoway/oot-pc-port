"""Reject incomplete synthetic initialization evidence before milestone pass."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from input_formats import InputError
from run_milestone import sdk_init_evidence,host_init_evidence


def completed():
    stats=dict.fromkeys(('platform_initialized','aoc_initialized','err_initialized','diag_initialized',
        'pctl_initialized','fs_mode','local_access_log','result_handled','clock_initialized'),1)
    stats.update(platform_initializations=1,platform_calls=1,service_calls=8,heap_size=0x200000,
        cpu_boost_mode=1,relro_readonly_bytes=0x2000,relro_locked_bytes=0x2000,permission_updates=1,permission_locks=1)
    execution=dict(status=2,error=15,pc='0x1000010',retired=100,word=0,service=0,
        startup_completed=False,relative_relocation_probes=2,relative_relocations_matching_offline_link=2,
        trace_sha256='11'*32,trace_steps=110,trace_rows=111,sdk_runtime=True,sdk_stages_completed=7,
        sdk_initialization_completed=True,game_entry_reached=True,native_sdk=True,native_calls=10,
        native_stats=dict(calls=10,logging_initializations=1),native_handler_stop=False,
        sdk_init_providers=True,init_stats=stats)
    return dict(status='diagnostic-complete',game_code_executed=True,startup_completed=False,
        switch2_startup_abi_proven=False,sdk_runtime=True,sdk_init_providers=True,
        sdk_initialization_completed=True,iterations=[dict(execution=execution,compiler='synthetic')])


class SdkInitMilestoneTests(unittest.TestCase):
    def test_host_boot_requires_original_constructor_returns_and_separate_counts(self):
        report=completed();report['host_linked']=True
        report['iterations'][0]['execution'].update(host_linked=True,host_scaffold_retired=10,original_retired=90,constructors_completed=3)
        bundle=dict(host_boot=dict(original_rtld_execution_allowed=False,module_order=[{}, {}, {}]),
            package=dict(image_phase='host-offline-linked',offline_link_applied_to_package=True))
        self.assertEqual(host_init_evidence(report,bundle,7,10)['constructors_completed'],3)
        for key,value in (('host_linked',False),('original_retired',100),('host_scaffold_retired',0),('constructors_completed',2)):
            bad=deepcopy(report);bad['iterations'][0]['execution'][key]=value
            with self.subTest(key=key),self.assertRaises(InputError):host_init_evidence(bad,bundle,7,10)
    def test_original_goal_and_owned_state_produce_complete_evidence(self):
        report=completed();evidence=sdk_init_evidence(report,7,10)
        self.assertEqual((evidence['error'],evidence['sdk_stages_completed'],evidence['native_calls']),(15,7,10))
        self.assertEqual(evidence['init_stats']['heap_size'],0x200000)
        self.assertEqual(evidence['trace_steps'],110)

    def test_stage_marker_or_native_success_cannot_replace_original_goal(self):
        for key,value in (('error',9),('sdk_stages_completed',6),('sdk_initialization_completed',False),
                ('game_entry_reached',False),('native_handler_stop',True),('sdk_init_providers',False)):
            report=completed();report['iterations'][0]['execution'][key]=value
            with self.subTest(key=key),self.assertRaises(InputError):sdk_init_evidence(report,7,10)
        report=completed();report['sdk_init_providers']=False
        with self.assertRaises(InputError):sdk_init_evidence(report,7,10)

    def test_missing_provider_lifetime_or_heap_effect_cannot_pass(self):
        original=completed()
        for key,value in [(name,0) for name in original['iterations'][0]['execution']['init_stats']]+[
                ('heap_size',0x80000000+0x200000),('heap_size',1)]:
            report=deepcopy(original);report['iterations'][0]['execution']['init_stats'][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(InputError):sdk_init_evidence(report,7,10)

    def test_original_retirement_native_counts_and_relocation_probes_are_checked(self):
        for key,value in (('native_calls',9),('trace_steps',100),('trace_rows',110),
                ('relative_relocations_matching_offline_link',1),('relative_relocation_probes',0)):
            report=completed();report['iterations'][0]['execution'][key]=value
            with self.subTest(key=key),self.assertRaises(InputError):sdk_init_evidence(report,7,10)
        for key,value in (('calls',9),('logging_initializations',0)):
            report=completed();report['iterations'][0]['execution']['native_stats'][key]=value
            with self.subTest(key=key),self.assertRaises(InputError):sdk_init_evidence(report,7,10)


if __name__=='__main__':unittest.main()
