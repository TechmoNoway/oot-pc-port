"""Independent native full traces for replacing the reached VI parent function."""
from copy import deepcopy
import hashlib,json,tempfile,unittest
from pathlib import Path
from test_display_audit import fixture as audit_fixture
from display_audit import extend_display_audit,INITIALIZE
from display_progress import verify_display_progress_trace
from input_formats import InputError

def encoded(rows):return b''.join(json.dumps(r,separators=(',',':')).encode()+b'\n' for r in rows)
def fixture():
    linker,sdk,base=audit_fixture();audit=extend_display_audit(linker,base)
    identities=[dict(name='sdk',base=sdk.base,source_sha256=sdk.source_sha256,
        text_sha256=hashlib.sha256(sdk.read(0,sdk.ranges[0][1])).hexdigest())]
    old=dict(entry_audit=dict(modules=identities),native_audit=base)
    current=dict(entry_audit=deepcopy(old['entry_audit']),native_audit=audit)
    source=audit['display_initialization']['initialize'];pc=source['entry'];word=source['entry_instruction']['word']
    prefix=dict(pc=hex(sdk.base+0x44),next_pc=hex(sdk.base+0x40),retired=1,word=0xd503201f,event=0,error=0,service=0)
    prior=dict(pc=hex(sdk.base+0x40),next_pc=hex(pc),retired=1,word=0xd503201f,event=3,error=0,service=448)
    original=dict(pc=hex(pc),next_pc=hex(pc+4),retired=2,word=word,event=0,error=0,service=0)
    old_rows=[prefix,prior,original,dict(pc=hex(pc+4),next_pc=hex(pc+4),retired=2,word=0,event=2,error=8,service=0)]
    crossing=dict(pc=hex(pc),next_pc=hex(sdk.base+0x48),retired=1,word=word,event=3,error=0,service=450)
    continuation=dict(pc=crossing['next_pc'],next_pc=hex(sdk.base+0x4c),retired=2,word=0xd503201f,event=0,error=0,service=0)
    rows=[prefix,prior,crossing,continuation,dict(pc=continuation['next_pc'],next_pc=continuation['next_pc'],retired=2,word=0,event=2,error=8,service=0)]
    baseline=dict(retired=2,native_calls=1,trace_steps=3,trace_rows=4,trace_sha256=hashlib.sha256(encoded(old_rows)).hexdigest())
    execution=dict(retired=2,native_calls=2,trace_steps=4,trace_rows=5,trace_sha256=hashlib.sha256(encoded(rows)).hexdigest(),
        graphics_runtime=True,application_graphics=dict(ready=True,calls=1,boots=1,checks=0),
        display_runtime=True,application_display=dict(ready=True,presentation_supported=True,calls=1,initializations=1))
    return old,current,baseline,execution,old_rows,rows

class DisplayProgressTests(unittest.TestCase):
    def proof(self,old,current,baseline,execution,before,rows):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);a=root/'old.jsonl';b=root/'new.jsonl'
            a.write_bytes(encoded(before));b.write_bytes(encoded(rows))
            return verify_display_progress_trace(a,baseline,old,b,execution,current)
    def test_restores_first_original_vi_step_and_keeps_prior_graphics_native_event(self):
        args=fixture();report=self.proof(*args)
        self.assertEqual(report['crossing']['retired'],1)
        self.assertEqual(report['original_entry_step']['retired'],2)
        self.assertEqual(report['continuation'],args[-1][3]);self.assertEqual(report['initialize_events'],1)
        self.assertFalse(report['runtime_authority_granted'])
    def test_full_hash_prefix_source_void_abi_counters_and_original_continuation_are_required(self):
        for mutation in ('prefix','retired','handler','word','return','missing','continue','ready','support','calls',
            'initializations','old_hash','new_hash','module','body','closure','returns','profile','constructors',
            'graphics_profile','graphics_ready','graphics_calls','graphics_boots','graphics_checks'):
            old,current,baseline,e,before,rows=fixture()
            if mutation=='prefix':rows[1]['word']^=1
            if mutation=='retired':rows[2]['retired']+=1
            if mutation=='handler':rows[2]['service']=451
            if mutation=='word':rows[2]['word']^=1
            if mutation=='return':rows[2]['next_pc']=rows[2]['pc']
            if mutation=='missing':rows.pop(2)
            if mutation=='continue':rows[3]['pc']=rows[3]['next_pc']
            if mutation=='ready':e['application_display']['ready']=False
            if mutation=='support':e['application_display']['presentation_supported']=False
            if mutation=='calls':e['application_display']['calls']=True
            if mutation=='initializations':e['application_display']['initializations']=2
            if mutation=='module':current['entry_audit']['modules'][0]['source_sha256']='11'*32
            if mutation=='body':current['native_audit']['display_initialization']['initialize']['body_sha256']='11'*32
            if mutation=='closure':current['native_audit']['display_initialization']['skipped_provider_closure']=False
            if mutation=='returns':next(f for f in current['native_audit']['functions'] if f['symbol']==INITIALIZE)['returns_value']=True
            if mutation=='profile':e['display_runtime']=False
            if mutation=='constructors':current['native_audit']['display_initialization']['original_constructors'][0]['original_execution_retained']=False
            if mutation=='graphics_profile':e['graphics_runtime']=False
            if mutation=='graphics_ready':e['application_graphics']['ready']=False
            if mutation=='graphics_calls':e['application_graphics']['calls']=True
            if mutation=='graphics_boots':e['application_graphics']['calls']=2;e['application_graphics']['boots']=2
            if mutation=='graphics_checks':e['application_graphics']['calls']=2;e['application_graphics']['checks']=1
            e['trace_sha256']=hashlib.sha256(encoded(rows)).hexdigest()
            if mutation=='old_hash':baseline['trace_sha256']='11'*32
            if mutation=='new_hash':e['trace_sha256']='11'*32
            with self.subTest(mutation=mutation),self.assertRaises(InputError):self.proof(old,current,baseline,e,before,rows)

if __name__=='__main__':unittest.main()
