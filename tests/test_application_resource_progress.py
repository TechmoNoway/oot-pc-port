"""Source-bound native frontier proof with an exact prior all-row prefix hash."""
from copy import deepcopy
import hashlib,json,subprocess
from pathlib import Path
import sys,tempfile,unittest
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from application_frontier import verify_resource_progress_trace,verify_full_trace
from test_application_resource_audit import fixture as audit_fixture,APP,AM
from application_audit import extend_application_resource_audit
from test_arm64_analysis import branch
from input_formats import InputError


def encoded(rows):
    return b''.join(json.dumps(r,separators=(',',':')).encode()+b'\n' for r in rows)


def fixture():
    linker,sdk,old_audit=audit_fixture({0x40:branch(0x40,0x50,True)})
    identities=[dict(name='sdk',base=sdk.base,source_sha256=sdk.source_sha256,
                     text_sha256=hashlib.sha256(sdk.read(*[sdk.ranges[0][0],sdk.ranges[0][1]-sdk.ranges[0][0]])).hexdigest())]
    old=dict(entry_audit=dict(modules=identities),native_audit=old_audit)
    current=dict(entry_audit=deepcopy(old['entry_audit']),native_audit=extend_application_resource_audit(linker,old_audit))
    public=old_audit['functions'][0];pc=f"0x{public['entry']:x}"
    step=dict(pc=f'0x{sdk.base+0x40:x}',next_pc=pc,retired=1,word=branch(0x40,0x50,True),event=0,error=0,service=0)
    stop=dict(pc=pc,next_pc=pc,retired=1,word=public['entry_word'],event=2,error=9,service=31)
    baseline=dict(error=9,native_handler_stop=True,service=31,pc=pc,retired=1,word=public['entry_word'],
                  native_calls=0,trace_sha256=hashlib.sha256(encoded([step,stop])).hexdigest())
    call=dict(stop,event=3,error=0,service=322,next_pc=f'0x{sdk.base+0x44:x}')
    terminal=dict(pc=call['next_pc'],next_pc=call['next_pc'],retired=1,word=0,event=2,error=8,service=0)
    rows=[step,call,terminal]
    execution=dict(retired=1,native_calls=1,trace_rows=3,trace_steps=2,trace_sha256=hashlib.sha256(encoded(rows)).hexdigest(),
                   application_resource=dict(logical_process_id=1,active=1,queries=1))
    return old,current,baseline,execution,rows


class ApplicationResourceProgressTests(unittest.TestCase):
    def proof(self,old,current,baseline,execution,rows):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            path=Path(tmp)/'trace.jsonl';path.write_bytes(encoded(rows))
            execution=deepcopy(execution)
            execution['trace_sha256']=hashlib.sha256(encoded(rows)).hexdigest()
            return verify_resource_progress_trace(path,baseline,old,current,execution,1)

    def test_native_crossing_retires_no_original_and_matches_exact_old_prefix(self):
        old,current,baseline,execution,rows=fixture()
        proof=self.proof(old,current,baseline,execution,rows)
        self.assertEqual(proof['crossing'],rows[1]);self.assertEqual(proof['resource_events'],1)
        self.assertEqual(proof['original_prefix_sha256'],baseline['trace_sha256'])
        self.assertEqual(proof['trace_sha256'],execution['trace_sha256'])
        self.assertFalse(proof['runtime_authority_granted'])
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            path=Path(tmp)/'trace.jsonl';path.write_bytes(encoded(rows));verify_full_trace(path,execution)

    def test_cli_requires_verified_full_trace_and_explicit_native_owner(self):
        old,current,baseline,execution,rows=fixture()
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            root=Path(tmp);trace=root/'trace.jsonl';trace.write_bytes(encoded(rows))
            for name,bundle,e in (('old',old,baseline),('new',current,execution)):
                folder=root/name;folder.mkdir();(folder/'manifest.json').write_text(json.dumps(bundle))
                (root/(name+'.json')).write_text(json.dumps(dict(iterations=[dict(bundle=str(folder),execution=e)])))
            args=[sys.executable,'-B',str(ROOT/'tools/application_frontier.py'),'progress',
                  '--baseline',str(root/'old.json'),'--run',str(root/'new.json'),'--trace',str(trace)]
            good=root/'proof.json'
            run=subprocess.run([*args,'--resource-owner','1','--output',str(good)],cwd=ROOT,capture_output=True,text=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertEqual(json.loads(good.read_text())['original_prefix_sha256'],baseline['trace_sha256'])
            for owner in (None,2):
                output=root/f'rejected-{owner}.json'
                extra=[] if owner is None else ['--resource-owner',str(owner)]
                run=subprocess.run([*args,*extra,'--output',str(output)],cwd=ROOT,capture_output=True,text=True,timeout=30)
                self.assertNotEqual(run.returncode,0);self.assertFalse(output.exists())

    def test_prefix_checkpoint_event_handler_return_and_counter_mutations_reject(self):
        for mutation in ('prefix','retired','event','handler','word','return_self','return_alignment','return_limit',
                         'queries','owner','inactive','missing','duplicate','old_digest','not_native'):
            old,current,baseline,execution,rows=fixture()
            if mutation=='prefix':rows[0]['word']^=1
            if mutation=='retired':rows[1]['retired']+=1
            if mutation=='event':rows[1]['event']=0
            if mutation=='handler':rows[1]['service']=321
            if mutation=='word':rows[1]['word']^=1
            if mutation=='return_self':rows[1]['next_pc']=rows[1]['pc']
            if mutation=='return_alignment':rows[1]['next_pc']='0x100000001'
            if mutation=='return_limit':rows[1]['next_pc']=hex(1<<39)
            if mutation=='queries':execution['application_resource']['queries']=2
            if mutation=='owner':execution['application_resource']['logical_process_id']=2
            if mutation=='inactive':execution['application_resource']['active']=0
            if mutation=='missing':rows.pop(1)
            if mutation=='duplicate':rows.insert(2,dict(rows[1]))
            if mutation=='old_digest':baseline['trace_sha256']='11'*32
            if mutation=='not_native':baseline['native_handler_stop']=False
            with self.subTest(mutation=mutation),self.assertRaises(InputError):self.proof(old,current,baseline,execution,rows)

    def test_source_body_abi_domain_and_binding_mutations_reject(self):
        for mutation in ('module','body','handler','abi','domain','names','duplicate'):
            old,current,baseline,execution,rows=fixture()
            public=next(f for f in current['native_audit']['functions'] if f['symbol']==APP)
            if mutation=='module':current['entry_audit']['modules'][0]['source_sha256']='11'*32
            if mutation=='body':public['body_sha256']='11'*32
            if mutation=='handler':public['handler_id']=321
            if mutation=='abi':public['return_register']='W0'
            if mutation=='domain':current['native_audit']['application_resource_identity']['exported_am_consumer_closure']=False
            if mutation=='names':public['names']=[AM]
            if mutation=='duplicate':current['native_audit']['functions'].append(dict(public))
            with self.subTest(mutation=mutation),self.assertRaises(InputError):self.proof(old,current,baseline,execution,rows)


if __name__=='__main__':unittest.main()
