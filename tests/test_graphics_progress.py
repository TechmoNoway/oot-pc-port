"""Synthetic full native trace proves the earlier whole-boot replacement."""
from copy import deepcopy
import hashlib,json,tempfile,unittest
from pathlib import Path
from test_graphics_audit import fixture as audit_fixture
from graphics_audit import extend_graphics_audit,BOOT
from graphics_progress import verify_graphics_progress_trace
from input_formats import InputError

def encoded(rows):return b''.join(json.dumps(row,separators=(',',':')).encode()+b'\n' for row in rows)
def fixture():
    linker,sdk,base=audit_fixture();audit=extend_graphics_audit(linker,base)
    identities=[dict(name='sdk',base=sdk.base,source_sha256=sdk.source_sha256,
        text_sha256=hashlib.sha256(sdk.read(0,sdk.ranges[0][1])).hexdigest())]
    old=dict(entry_audit=dict(modules=identities),native_audit=base)
    current=dict(entry_audit=deepcopy(old['entry_audit']),native_audit=audit)
    boot=audit['graphics_bootstrap']['boot'];pc=boot['entry'];word=boot['entry_instruction']['word']
    prefix=dict(pc=hex(sdk.base+0x40),next_pc=hex(pc),retired=1,word=0xd503201f,event=0,error=0,service=0)
    original=dict(pc=hex(pc),next_pc=hex(pc+4),retired=2,word=word,event=0,error=0,service=0)
    old_rows=[prefix,original,dict(pc=hex(pc+4),next_pc=hex(pc+4),retired=2,word=0,event=2,error=8,service=0)]
    crossing=dict(pc=hex(pc),next_pc=hex(sdk.base+0x44),retired=1,word=word,event=3,error=0,service=448)
    continued=dict(pc=crossing['next_pc'],next_pc=hex(sdk.base+0x48),retired=2,word=0xd503201f,event=0,error=0,service=0)
    rows=[prefix,crossing,continued,dict(pc=continued['next_pc'],next_pc=continued['next_pc'],retired=2,word=0,event=2,error=8,service=0)]
    baseline=dict(retired=2,native_calls=0,trace_steps=2,trace_rows=3,trace_sha256=hashlib.sha256(encoded(old_rows)).hexdigest())
    execution=dict(retired=2,native_calls=1,trace_steps=3,trace_rows=4,trace_sha256=hashlib.sha256(encoded(rows)).hexdigest(),
        application_graphics=dict(ready=True,calls=1,boots=1,checks=0))
    return old,current,baseline,execution,old_rows,rows

class GraphicsProgressTests(unittest.TestCase):
    def proof(self,old,current,baseline,execution,old_rows,rows):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);before=root/'old.jsonl';after=root/'new.jsonl'
            before.write_bytes(encoded(old_rows));after.write_bytes(encoded(rows))
            return verify_graphics_progress_trace(before,baseline,old,after,execution,current)
    def test_prefix_restores_original_step_and_requires_actual_caller_continuation(self):
        args=fixture();r=self.proof(*args)
        self.assertEqual(r['crossing']['retired'],1)
        self.assertEqual(r['original_entry_step']['retired'],2)
        self.assertEqual(r['continuation'],args[-1][2])
        self.assertFalse(r['runtime_authority_granted'])
    def test_native_hash_prefix_owner_counter_and_abi_mutations_reject(self):
        for mutation in ('prefix','retired','handler','word','return','missing','continue','ready','boots','calls','old_hash','new_hash','module','body','closure','returns'):
            old,current,baseline,e,before,rows=fixture()
            if mutation=='prefix':rows[0]['word']^=1
            if mutation=='retired':rows[1]['retired']+=1
            if mutation=='handler':rows[1]['service']=449
            if mutation=='word':rows[1]['word']^=1
            if mutation=='return':rows[1]['next_pc']=rows[1]['pc']
            if mutation=='missing':rows.pop(1)
            if mutation=='continue':rows[2]['pc']=rows[2]['next_pc']
            if mutation=='ready':e['application_graphics']['ready']=False
            if mutation=='boots':e['application_graphics']['boots']=2
            if mutation=='calls':e['application_graphics']['calls']=2
            if mutation=='module':current['entry_audit']['modules'][0]['source_sha256']='11'*32
            if mutation=='body':current['native_audit']['graphics_bootstrap']['boot']['body_sha256']='11'*32
            if mutation=='closure':current['native_audit']['graphics_bootstrap']['skipped_provider_closure']=False
            if mutation=='returns':next(f for f in current['native_audit']['functions'] if f['symbol']==BOOT)['returns_value']=True
            e['trace_sha256']=hashlib.sha256(encoded(rows)).hexdigest()
            if mutation=='old_hash':baseline['trace_sha256']='11'*32
            if mutation=='new_hash':e['trace_sha256']='11'*32
            with self.subTest(mutation=mutation),self.assertRaises(InputError):self.proof(old,current,baseline,e,before,rows)

if __name__=='__main__':unittest.main()
