"""Synthetic dependency frontiers, diagnostic targets, PLT snapshots and CLI bounds."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from callee_audit import audit_callees,compare_baseline
from call_validation import LrAssembler
from input_formats import InputError
from module_linker import Linker,Module
from prepare_exefs import prepare
from profile_survey import survey_modules
from test_arm64_analysis import branch,synthetic_module,RET,NOP
from test_module_linker import symbol
from test_profile_survey import programs_module


def caller(name,offset,target,twice=False):
    a=LrAssembler(name,offset,16);a.bl(target)
    if twice:a.bl(target)
    return name,offset,a.finish().data


def shared_fixture(extra=None,callee=None):
    programs=[caller('root_a',0x10,0xc0),caller('root_b',0x40,0xc0),caller('parent',0xa0,0x10,True)]
    if callee:programs.append(('callee',0xc0,callee))
    return programs_module(programs,extra or {0xc0:RET})


def plt_fixture(name='callee',relocation=True):
    root=caller('root',0x10,0xc0)
    instructions={0:branch(0,0x10),0x40:RET,0xc0:0xD0000010,0xc4:0xF9400211,0xc8:0x91000210,0xcc:0xD61F0220}
    instructions.update({root[1]+i:int.from_bytes(root[2][i:i+4],'little') for i in range(0,len(root[2]),4)})
    raw=synthetic_module(instructions,symbols=[symbol(name,section=0,value=0,size=0),symbol('root',value=0x10,size=len(root[2]))],
        plt=((0x2000,1026,1,0),) if relocation else ())
    main=Module('main',raw);sdk=Module('sdk',synthetic_module({0:branch(0,0x40),0x40:RET},symbols=[symbol(name,value=0x40,size=4)]))
    linker=Linker([main,sdk]);assert linker.apply()['link_complete']
    return raw,linker


class CalleeAuditTests(unittest.TestCase):
    def test_shared_transitive_frontier_deduplicates_roots_callers_and_bl_sites(self):
        m=shared_fixture();before=bytes(m.image);r=audit_callees([m]);t=r['totals'];row=r['targets'][0]
        self.assertEqual((t['dependency_blocked_roots'],t['unique_frontier_targets'],t['frontier_edge_count']),(3,1,2))
        self.assertEqual(t['direct_call_edges'],3) # The parent has two BL sites to the same region.
        self.assertEqual((row['caller_region_count'],row['blocked_root_references']),(2,3))
        self.assertEqual(row['kind'],'unseeded_text_target');self.assertEqual(row['probe']['status'],'register_leaf_candidate')
        self.assertFalse(row['probe']['admitted_to_registry']);self.assertEqual(t['accepted_regions'],0)
        self.assertEqual(bytes(m.image),before);self.assertFalse(r['guest_code_executed']);self.assertFalse(r['translation_performed'])
        self.assertFalse(r['native_callbacks_registered']);self.assertFalse(r['function_identity_proven'])
        baseline=survey_modules([m],lr_calls=True);compare_baseline(r,baseline)
        self.assertTrue(r['baseline_comparison']['policy_outcomes_match'])

    def test_metadata_unsupported_indirect_and_window_failures_are_not_reprobed(self):
        for code,reason in ((bytes.fromhex('010000d4'),'unsupported_encoding'),(NOP.to_bytes(4,'little'),'window_boundary'),
                            (0xD61F0000.to_bytes(4,'little'),'indirect_jump')):
            m=shared_fixture({0xc4:RET},code);r=audit_callees([m]);row=r['targets'][0]
            self.assertEqual(row['kind'],'discovery_blocked_metadata_entry');self.assertEqual(row['metadata']['failure']['reason'],reason)
            self.assertNotIn('probe',row);self.assertEqual(r['totals']['frontier_discovery_reasons'][reason],1)

    def test_probe_does_not_supply_a_callee_to_another_probe(self):
        hidden=caller('hidden',0xc0,0xe0)[2]
        extra={0xe0:RET,**{0xc0+i:int.from_bytes(hidden[i:i+4],'little') for i in range(0,len(hidden),4)}}
        m=programs_module([caller('root_a',0x10,0xc0),caller('root_b',0x40,0xe0)],extra)
        r=audit_callees([m]);by_offset={x['offset']:x for x in r['targets']}
        self.assertEqual(by_offset[0xe0]['probe']['status'],'register_leaf_candidate')
        self.assertEqual((by_offset[0xc0]['probe']['status'],by_offset[0xc0]['probe']['reason']),('policy_rejected','call_dependency'))
        self.assertEqual(r['totals']['accepted_regions'],0)

    def test_probe_obeys_next_metadata_entry_and_explicit_symbol_end(self):
        root=caller('root',0x10,0xc0)
        m=programs_module([root,('next',0xd0,RET.to_bytes(4,'little'))],{off:NOP for off in range(0xc0,0xd0,4)})
        p=audit_callees([m])['targets'][0]['probe']
        self.assertEqual(p['window_bytes'],16);self.assertIn('next_metadata_entry',p['limiting_evidence'])
        self.assertEqual(p['failure']['reason'],'window_boundary')
        # A sized symbol ends before the next metadata entry/text boundary.
        holder=RET.to_bytes(4,'little')+bytes(36)
        m=programs_module([root,('holder',0xa0,holder)],{0xc0:NOP,0xc4:NOP})
        p=audit_callees([m])['targets'][0]['probe']
        self.assertEqual(p['window_bytes'],8);self.assertIn('enclosing_symbol_end',p['limiting_evidence'])
        self.assertEqual(p['failure']['reason'],'window_boundary')

    def test_internal_label_probe_records_overlap_without_claiming_identity(self):
        holder=NOP.to_bytes(4,'little')*8+RET.to_bytes(4,'little')
        m=programs_module([caller('root',0x10,0xc0),('holder',0xa0,holder)])
        r=audit_callees([m]);p=r['targets'][0]['probe']
        self.assertTrue(p['overlaps_discovered_span']);self.assertEqual(p['status'],'register_leaf_candidate')
        self.assertFalse(p['admitted_to_registry']);self.assertFalse(r['function_identity_proven'])

    def test_policy6_probe_stays_diagnostic_and_obeys_word_limit(self):
        p=LrAssembler('hidden',0xc0,16).finish()
        extra={0xc0+i:int.from_bytes(p.data[i:i+4],'little') for i in range(0,len(p.data),4)}
        m=programs_module([caller('root',0x10,0xc0)],extra);r=audit_callees([m])
        self.assertEqual(r['targets'][0]['probe']['status'],'policy6_candidate')
        self.assertFalse(r['targets'][0]['probe']['admitted_to_registry']);self.assertEqual(r['totals']['accepted_regions'],0)
        extra={off:NOP for off in range(0xc0,0xe0,4)};extra[0xe0]=RET
        m=programs_module([caller('root',0x10,0xc0)],extra)
        probe=audit_callees([m],max_words=8)['targets'][0]['probe']
        self.assertEqual(probe['window_bytes'],32);self.assertIn('word_limit',probe['limiting_evidence'])
        self.assertEqual(probe['failure']['reason'],'window_boundary')

    def test_nontext_gaps_and_outside_addresses_remain_missing(self):
        for offset,kind in ((0x2100,'mapped_nontext_target'),(0x2200,'mapped_nontext_target'),
                            (0x300,'unmapped_module_gap'),(0x10000,'unmapped_target')):
            m=programs_module([caller('root',0x10,offset)]);r=audit_callees([m]);row=r['targets'][0]
            self.assertEqual(row['kind'],kind);self.assertNotIn('probe',row);self.assertEqual(r['totals']['accepted_regions'],0)

    def test_relocation_backed_plt_snapshot_is_not_a_dispatch_or_target_set_proof(self):
        for name in ('callee','setjmp'):
            _,linker=plt_fixture(name);before=[bytes(m.image) for m in linker.modules]
            r=audit_callees(linker.modules);row=r['targets'][0]
            self.assertEqual(row['kind'],'plt_stub');self.assertEqual(row['plt_snapshot']['symbol'],name)
            self.assertEqual(row['plt_snapshot']['resolved_target']['kind'],'verified_register_leaf')
            self.assertEqual(row['plt_snapshot']['nonlocal_return_symbol'],name=='setjmp')
            self.assertFalse(row['plt_snapshot']['runtime_target_set_proven']);self.assertNotIn('probe',row)
            self.assertEqual([bytes(m.image) for m in linker.modules],before);self.assertEqual(r['totals']['dependency_blocked_roots'],1)
            self.assertEqual(r['totals']['plt_snapshot_target_kinds'],{'verified_register_leaf':1})
            self.assertEqual(r['totals']['plt_unique_snapshot_targets'],1)
        _,linker=plt_fixture(relocation=False)
        row=audit_callees(linker.modules)['targets'][0]
        self.assertEqual(row['kind'],'unseeded_text_target');self.assertEqual(row['probe']['failure']['reason'],'indirect_jump')

    def test_known_leaf_and_framed_edges_are_counted_separately(self):
        root=caller('root',0x10,0x40);child=caller('child',0x40,0xc0)
        m=programs_module([root,child,('leaf',0xc0,RET.to_bytes(4,'little'))])
        r=audit_callees([m]);self.assertEqual(r['totals']['accepted_regions'],2)
        self.assertEqual(r['totals']['direct_edge_kinds'],{'discovered_metadata_region':1,'verified_register_leaf':1})
        self.assertEqual(r['targets'],[]);self.assertEqual(r['blocked_roots'],[])

    def test_fresh_baseline_hash_counts_limits_and_module_set_are_required(self):
        m=shared_fixture();r=audit_callees([m]);baseline=survey_modules([m],lr_calls=True)
        bad_cases=[{},dict(baseline,policies=[]),dict(baseline,modules=[None]),dict(baseline,totals=[])]
        for path,value in ((('method','max_words'),16),(('modules',0,'source_sha256'),'0'*64),
                           (('pauth_model',),None),(('decoder',),{}),
                           (('totals','profiles','lr_calls','accepted_regions'),999)):
            bad=deepcopy(baseline);node=bad
            for key in path[:-1]:node=node[key]
            node[path[-1]]=value;bad_cases.append(bad)
        bad_cases.append(dict(baseline,modules=baseline['modules']*2))
        for bad in bad_cases:
            with self.assertRaises(InputError):compare_baseline(r,bad)
        with self.assertRaises(InputError):audit_callees([m,m])
        for kw in ({'sample_limit':True},{'sample_limit':4097},{'max_words':0}):
            with self.assertRaises(InputError):audit_callees([m],**kw)

    def test_determinism_zero_samples_and_accounting(self):
        m=shared_fixture();r=audit_callees([m],sample_limit=0)
        self.assertEqual(r,audit_callees([m],sample_limit=0));self.assertEqual(r['ranked_target_samples'],[])
        self.assertTrue(r['ranked_samples_truncated']);t=r['totals']
        self.assertEqual(t['metadata_entry_candidates'],t['discovery_blocked']+t['accepted_regions']+sum(t['rejected'].values()))
        self.assertEqual(t['direct_call_edges'],sum(t['direct_edge_kinds'].values()))
        self.assertEqual(t['unique_frontier_targets'],sum(t['frontier_target_kinds'].values()))
        self.assertEqual(t['dependency_blocked_roots'],len(r['blocked_roots']))


class CalleeAuditCliTests(unittest.TestCase):
    def test_cli_verified_inputs_baseline_fresh_output_and_no_execution(self):
        raw,linker=plt_fixture();baseline=survey_modules(linker.modules,lr_calls=True)
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            folder=Path(temporary);inputs=folder/'inputs';inputs.mkdir()
            # The CLI fixture needs both source modules for a complete link.
            (inputs/'main').write_bytes(raw)
            sdk=synthetic_module({0:branch(0,0x40),0x40:RET},symbols=[symbol('callee',value=0x40,size=4)])
            (inputs/'sdk').write_bytes(sdk);prepared=folder/'prepared';prepare(inputs,prepared)
            before={p.name:p.read_bytes() for p in prepared.iterdir()}
            base=folder/'baseline.json';base.write_text(json.dumps(baseline));report=folder/'audit.json'
            args=[sys.executable,'-B',str(ROOT/'tools/survey_callees.py'),str(prepared),'--baseline',str(base),'--report',str(report)]
            result=subprocess.run(args,capture_output=True,text=True);self.assertEqual(result.returncode,0,result.stderr)
            saved=report.read_bytes();r=json.loads(saved);self.assertTrue(r['baseline_comparison']['policy_outcomes_match'])
            self.assertFalse(r['guest_code_executed']);self.assertFalse(r['native_callbacks_registered'])
            self.assertNotEqual(subprocess.run(args,capture_output=True).returncode,0);self.assertEqual(report.read_bytes(),saved)
            self.assertEqual({p.name:p.read_bytes() for p in prepared.iterdir()},before)
            # Refuse stale baselines and corrupt prepared input without partial reports.
            bad=deepcopy(baseline);bad['modules'][0]['linked_text_sha256']='0'*64;base.write_text(json.dumps(bad))
            report2=folder/'stale.json';args[-1]=str(report2)
            self.assertNotEqual(subprocess.run(args,capture_output=True).returncode,0);self.assertFalse(report2.exists())
            base.write_text(json.dumps(baseline));(prepared/'main').write_bytes(before['main'][:-1])
            self.assertNotEqual(subprocess.run(args,capture_output=True).returncode,0);self.assertFalse(report2.exists())

    def test_cli_rejects_output_outside_build_and_inside_inputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            folder=Path(temporary);source=folder/'main';source.write_bytes(synthetic_module());prepared=folder/'prepared';prepare(source,prepared)
            for target in (ROOT/'audit-forbidden.json',prepared/'audit.json'):
                args=[sys.executable,'-B',str(ROOT/'tools/survey_callees.py'),str(prepared),'--report',str(target)]
                self.assertNotEqual(subprocess.run(args,capture_output=True).returncode,0);self.assertFalse(target.exists())


if __name__=='__main__':unittest.main()
