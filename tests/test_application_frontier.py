"""Synthetic source-bound frontier proofs do not grant runtime permissions."""
from copy import deepcopy
import hashlib,json,struct,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from input_formats import InputError
from application_frontier import summarize_boundaries,verify_progress_trace,verify_full_trace


def fixture():
    site=dict(address=0x1000,word=0x7e21d808,module='main',source_sha256='22'*32,
              word_sha256=hashlib.sha256(struct.pack('<I',0x7e21d808)).hexdigest())
    modules=[dict(name='main',source_sha256='22'*32,text_sha256='33'*32,base=0x1000)]
    old=dict(entry_audit=dict(modules=modules),application_word_boundaries=[dict(site,semantic_error='old stop')])
    current=dict(entry_audit=dict(modules=deepcopy(modules)),application_simd_sites=[site])
    execution=dict(pc='0x1000',word=site['word'],retired=10,error=8)
    row=dict(pc='0x1000',next_pc='0x1004',word=site['word'],retired=11,event=0,error=0,service=0)
    return old,current,execution,row


class ApplicationFrontierTests(unittest.TestCase):
    def test_narrow_cas_progress_uses_atomic_domain_and_keeps_simd_counts_separate(self):
        old,current,e,row=fixture();word=0x08e87d2a
        site=current.pop('application_simd_sites')[0]
        site.update(word=word,word_sha256=hashlib.sha256(struct.pack('<I',word)).hexdigest())
        current['application_atomic_sites']=[site]
        old['application_word_boundaries']=[dict(site,semantic_error='old CASAB frontier')]
        e['word']=row['word']=word
        proof=self.proof([row],old,current,e)
        self.assertEqual(proof['source_site'],site)
        survey=summarize_boundaries(old)
        self.assertEqual(sum(survey['families'].values()),0)
        self.assertEqual(survey['atomic_families'],{'compare_exchange_narrow':1})
        bad=deepcopy(current);bad['application_simd_sites']=bad.pop('application_atomic_sites')
        with self.assertRaises(InputError):self.proof([row],old,bad,e)
        bad=deepcopy(current);bad['application_simd_sites']=[deepcopy(site)]
        with self.assertRaises(InputError):self.proof([row],old,bad,e)

    def test_cli_checks_native_full_trace_and_build_paths_before_writing_proof(self):
        old,current,e,crossing=fixture()
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            root=Path(tmp);before=root/'before';after=root/'after';before.mkdir();after.mkdir()
            (before/'manifest.json').write_text(json.dumps(old));(after/'manifest.json').write_text(json.dumps(current))
            rows=[dict(crossing,pc=hex(0x3000+4*i),next_pc=hex(0x3004+4*i),retired=i+1) for i in range(10)]
            rows += [crossing,dict(crossing,event=2)]
            trace=root/'trace.jsonl';trace.write_text(''.join(json.dumps(r)+'\n' for r in rows),newline='\n')
            native=dict(retired=11,native_calls=0,trace_rows=12,trace_steps=11,
                        trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest())
            baseline=root/'baseline.json';run=root/'run.json'
            baseline.write_text(json.dumps(dict(iterations=[dict(bundle=str(before),execution=e)])))
            run.write_text(json.dumps(dict(iterations=[dict(bundle=str(after),execution=native)])))
            output=root/'proof.json'
            args=[sys.executable,'-B',str(ROOT/'tools/application_frontier.py'),'progress',
                  '--baseline',str(baseline),'--run',str(run),'--trace',str(trace),'--output',str(output)]
            result=subprocess.run(args,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(output.read_text())['crossing'],crossing)
            saved=output.read_bytes()
            self.assertNotEqual(subprocess.run(args,capture_output=True).returncode,0)
            self.assertEqual(output.read_bytes(),saved)
            # A compact trace with the matching frontier row cannot satisfy the native all-row digest.
            trace.write_text(json.dumps(crossing)+'\n'+json.dumps(rows[-1])+'\n')
            args[-1]=str(root/'compact-proof.json')
            self.assertNotEqual(subprocess.run(args,capture_output=True).returncode,0)
            self.assertFalse((root/'compact-proof.json').exists())
            escaped=subprocess.run([sys.executable,'-B',str(ROOT/'tools/application_frontier.py'),'survey',
                '--manifest',str(ROOT/'CMakeLists.txt'),'--output',str(root/'escape.json')],capture_output=True)
            self.assertNotEqual(escaped.returncode,0);self.assertFalse((root/'escape.json').exists())

    def proof(self,rows=None,old=None,current=None,execution=None,raw=None):
        before,after,e,row=fixture()
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            path=Path(tmp)/'trace.jsonl'
            path.write_bytes(raw if raw is not None else ''.join(json.dumps(r)+'\n' for r in
                ([row] if rows is None else rows)).encode())
            return verify_progress_trace(path,execution or e,old or before,current or after)

    def test_exact_crossing_is_proved_with_hash_and_later_repeats(self):
        old,current,e,row=fixture();later=dict(row,retired=20)
        proof=self.proof([row,later])
        self.assertEqual(proof['crossing'],row)
        self.assertEqual(len(proof['trace_sha256']),64)
        self.assertFalse(proof['runtime_authority_granted'])

    def test_missing_duplicate_stop_and_mutated_crossings_reject(self):
        old,current,e,row=fixture()
        for rows in ([],[row,row],*[ [dict(row,**{k:v})] for k,v in
             (('pc','0x1004'),('next_pc','0x1008'),('retired',12),('word',0),
              ('event',2),('error',8),('service',1))]):
            with self.subTest(rows=rows),self.assertRaises(InputError):self.proof(rows)
        for raw in (b'{',b'{}\n',b'[]\n',json.dumps(row).encode(),b'not json\n'):
            with self.subTest(raw=raw),self.assertRaises(InputError):self.proof(raw=raw)

    def test_source_word_and_module_identity_are_not_inferred(self):
        old,current,e,row=fixture()
        for k,v in (('address',0x1004),('word',0),('module','sdk'),('source_sha256','44'*32),('word_sha256','55'*32)):
            bad=deepcopy(current);bad['application_simd_sites'][0][k]=v
            with self.subTest(k=k),self.assertRaises(InputError):self.proof(current=bad)
        for k in ('source_sha256','text_sha256','name','base'):
            bad=deepcopy(current);bad['entry_audit']['modules'][0][k]='stale'
            with self.subTest(k=k),self.assertRaises(InputError):self.proof(current=bad)
        for which in ('old','current'):
            bad=deepcopy(old if which=='old' else current);bad['entry_audit']['modules']=[]
            with self.assertRaises(InputError):self.proof(**{which:bad})

    def test_survey_redecodes_historical_errors_without_mutating_manifest(self):
        old,_,_,_=fixture()
        old['application_word_boundaries'] += [dict(word=w,address=0x2000+i*4) for i,w in enumerate(
            (0x4ea21c20,0x5e180423,0x6e180420,0x6e228c20,0x6ee21c20,0x91000400,0xffffffff))]
        before=deepcopy(old);report=summarize_boundaries(old)
        self.assertEqual(report['format'],'oot-application-frontier')
        self.assertEqual(report['total_records'],8)
        self.assertEqual(report['already_supported'],1)
        self.assertEqual(report['remaining_unsupported'],1)
        self.assertEqual(list(report['families'].values()),[1]*6)
        self.assertEqual(old,before)

    def test_cli_trace_validation_requires_full_native_digest_and_accounting(self):
        _,_,_,row=fixture();row['retired']=1
        stop=dict(row,event=2)
        raw=''.join(json.dumps(r)+'\n' for r in (row,stop)).encode()
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            path=Path(tmp)/'trace.jsonl';path.write_bytes(raw)
            report=dict(trace_mode='compact',trace_sha256=hashlib.sha256(raw).hexdigest(),
                        trace_rows=2,trace_steps=1,retired=1,native_calls=0)
            verify_full_trace(path,report)
            for k,v in (('trace_sha256','11'*32),('trace_rows',3),('trace_steps',2),('retired',0)):
                with self.subTest(k=k),self.assertRaises(InputError):verify_full_trace(path,dict(report,**{k:v}))
            path.write_bytes(raw+json.dumps(row).encode()+b'\n')
            with self.assertRaises(InputError):verify_full_trace(path,report)


if __name__=='__main__':unittest.main()
