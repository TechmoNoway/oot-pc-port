"""Independent synthetic full-trace checkpoints for the event capability gate."""
from copy import deepcopy
import hashlib,json,struct,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'tools'))
from input_formats import InputError
from system_event_audit import PUBLIC
from system_event_progress import verify_events_progress_trace

def encoded(rows):return b''.join(json.dumps(r,separators=(',',':')).encode()+b'\n'for r in rows)
def fixture():
    def row(pc,next_pc,retired,event=0,service=0,error=0,word=0xd503201f):
        return dict(pc=hex(pc),next_pc=hex(next_pc),retired=retired,word=word,event=event,error=error,service=service)
    def instruction(pc,word):return dict(address=pc,word=word,sha256=hashlib.sha256(struct.pack('<I',word)).hexdigest())
    pub=dict(symbol=PUBLIC,module='sdk',entry=0x2000,size=44,body_sha256='ab'*32,symbol_metadata={'index':3},
        entry_word=0xd503201f,entry_instruction=instruction(0x2000,0xd503201f),names=[PUBLIC])
    old=dict(entry_audit=dict(modules=[dict(name='sdk',base=0x1000,source_sha256='bc'*32,text_sha256='cd'*32)]),
        native_audit=dict(objects_runtime=True,functions=[dict(pub,handler_id=31)],display_objects={'declaration':{'flags':0}}))
    current=deepcopy(old);a=current['native_audit'];a.update(events_runtime=True)
    a['functions']=[dict(pub,handler_id=456,returns_value=True,return_register='w0')]
    branch=0x36000002|(6<<5)
    a['display_objects']['declaration']['flags']=1
    a['system_events']=dict(public=pub,consumer_closure=True,original_consumers_retained=True,census=[{}for _ in range(256)],
        early_create=dict(symbol='early_source',entry=0x1000,size=104,entry_instruction=instruction(0x1000,0xd503201f)),
        early_inprocess_branch=instruction(0x1014,branch),consumers=[{'symbol':'wait_source'}],
        retained_symbols=['early_source','wait_source'])
    prefix=[row(0x1000,0x1004,1),row(0x1014,0x102c,2,word=branch),row(0x1000,0x1004,3),
        row(0x1014,0x102c,4,word=branch),row(0x1100,0x2000,5)]
    before=prefix+[row(0x2000,0x2000,5,2,31,9)]
    rows=prefix+[row(0x2000,0x1104,5,3,456),row(0x1104,0x1108,6),row(0x3000,0x3000,6,2,31,9)]
    owner=dict(display_open=1,layer_open=1,references=1,opens=1,creates=1,closes=0,destroys=0,window_getters=0,
        waits=0,resets=0,clears=0,handle_closes=0,calls=2,event_open=0,vsync_events=0)
    baseline=dict(pc=hex(0x2000),word=0xd503201f,error=9,service=31,native_handler_stop=True,retired=5,native_calls=0,
        trace_steps=5,trace_rows=6,trace_sha256=hashlib.sha256(encoded(before)).hexdigest(),display_objects=owner)
    execution=dict(events_runtime=True,retired=6,native_calls=1,trace_steps=7,trace_rows=8,
        trace_sha256=hashlib.sha256(encoded(rows)).hexdigest(),display_objects=dict(owner,calls=3,event_open=1,vsync_events=1))
    return old,current,baseline,execution,before,rows

class EventProgressTests(unittest.TestCase):
    def proof(self,old,current,b,e,before,rows):
        with tempfile.TemporaryDirectory()as d:
            a=Path(d)/'old';c=Path(d)/'new';a.write_bytes(encoded(before));c.write_bytes(encoded(rows))
            return verify_events_progress_trace(a,b,old,c,e,current)
    def test_restored_guard_real_publication_original_early_paths_and_caller(self):
        p=self.proof(*fixture());self.assertEqual(p['publications'],1)
        self.assertEqual(len(p['early_original_creations']),2);self.assertEqual(len(p['early_inprocess_branches']),2)
        self.assertFalse(p['runtime_authority_granted'])
    def test_wrong_prefix_early_branch_owner_source_or_return_cannot_establish_progress(self):
        for mutation in('prefix','branch','missing_early','source','closure','flags','early_guard','abi','counter',
            'unpublished','continuation','retired','handler','old_hash','new_hash'):
            old,current,b,e,before,rows=fixture();a=current['native_audit']
            if mutation=='prefix':rows[4]['word']^=1
            if mutation=='branch':rows[1]['next_pc']=hex(0x1018)
            if mutation=='missing_early':rows[0]['pc']=hex(0x1004)
            if mutation=='source':a['system_events']['public']['body_sha256']='11'*32
            if mutation=='closure':a['system_events']['consumer_closure']=False
            if mutation=='flags':a['display_objects']['declaration']['flags']=0
            if mutation=='early_guard':a['functions'].append({'entry':0x1000,'handler_id':31})
            if mutation=='abi':a['functions'][0]['return_register']='X0'
            if mutation=='counter':e['display_objects']['calls']=4
            if mutation=='unpublished':e['display_objects']['event_open']=0
            if mutation=='continuation':rows[6]['pc']=rows[6]['next_pc']
            if mutation=='retired':rows[5]['retired']+=1
            if mutation=='handler':rows[5]['service']=451
            e['trace_sha256']=hashlib.sha256(encoded(rows)).hexdigest()
            if mutation=='old_hash':b['trace_sha256']='00'*32
            if mutation=='new_hash':e['trace_sha256']='00'*32
            with self.subTest(mutation=mutation),self.assertRaises(InputError):self.proof(old,current,b,e,before,rows)

if __name__=='__main__':unittest.main()
