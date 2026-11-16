"""Synthetic full traces independently exercise the public refresh checkpoint."""
from copy import deepcopy
import hashlib,json,struct,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from input_formats import InputError
from display_refresh_audit import PUBLIC
from display_refresh_progress import verify_refresh_progress_trace

def encoded(rows):return b''.join(json.dumps(r,separators=(',',':')).encode()+b'\n'for r in rows)
def fixture():
    word=0x90000008
    def row(pc,to,ret,event=0,service=0,error=0):
        return dict(pc=hex(pc),next_pc=hex(to),retired=ret,word=word,event=event,error=error,service=service)
    public=dict(module='sdk',symbol=PUBLIC,entry=0x2000,size=76,body_sha256='ab'*32,symbol_metadata={'index':3},
        entry_word=word,entry_instruction=dict(word=word,sha256=hashlib.sha256(struct.pack('<I',word)).hexdigest()),names=[PUBLIC])
    old=dict(entry_audit=dict(modules=[dict(name='sdk',base=0x1000,source_sha256='bc'*32,text_sha256='cd'*32)]),
        native_audit=dict(events_runtime=True,functions=[dict(public,handler_id=31)],display_objects={'declaration':{'flags':1}}))
    new=deepcopy(old);a=new['native_audit'];a['refresh_runtime']=True;a['display_objects']['declaration']['flags']=3
    a['functions']=[dict(public,handler_id=457,returns_value=False,return_register=None)]
    a['display_refresh']=dict(public=deepcopy(public),consumer_closure=True,consumer_census=[{}for _ in range(22)],
        enabled_bits=2,update_mask=2,request_command=0x13d)
    prefix=[row(0x1100,0x2000,1)]
    before=prefix+[row(0x2000,0x2000,1,2,31,9)]
    after=prefix+[row(0x2000,0x1104,1,3,457),row(0x1104,0x1108,2),row(0x3000,0x3000,2,2,31,9)]
    owner=dict(calls=3,display_open=1,layer_open=1,event_open=1,references=1,opens=1,creates=1,vsync_events=1,
        closes=0,destroys=0,window_getters=0,waits=0,resets=0,clears=0,handle_closes=0)
    b=dict(pc=hex(0x2000),word=word,error=9,service=31,native_handler_stop=True,retired=1,native_calls=0,
        trace_steps=1,trace_rows=2,trace_sha256=hashlib.sha256(encoded(before)).hexdigest(),display_objects=owner)
    e=dict(refresh_runtime=True,events_runtime=True,retired=2,native_calls=1,trace_steps=3,trace_rows=4,
        trace_sha256=hashlib.sha256(encoded(after)).hexdigest(),display_objects=dict(owner,calls=4),
        display_refresh=dict(capability_bits=2,update_mask=2,updates=1,ignored=0))
    return old,new,b,e,before,after

class RefreshProgressTests(unittest.TestCase):
    def proof(self,old,new,b,e,before,after):
        with tempfile.TemporaryDirectory()as d:
            a=Path(d)/'old';c=Path(d)/'new';a.write_bytes(encoded(before));c.write_bytes(encoded(after))
            return verify_refresh_progress_trace(a,b,old,c,e,new)
    def test_original_prefix_and_retired_caller_with_owned_declaration(self):
        p=self.proof(*fixture());self.assertEqual(p['updates'],1);self.assertFalse(p['physical_mode_changed'])
    def test_changed_prefix_return_body_abi_closure_or_owner_rejects(self):
        for change in ('prefix','return','body','abi','closure','flags','handler','retired','count','mask','bits','new_hash'):
            old,new,b,e,before,after=fixture();a=new['native_audit']
            if change=='prefix':after[0]['word']^=1
            if change=='return':after[2]['pc']=hex(0x1108)
            if change=='body':a['display_refresh']['public']['body_sha256']='11'*32
            if change=='abi':a['functions'][0]['returns_value']=True
            if change=='closure':a['display_refresh']['consumer_closure']=False
            if change=='flags':a['display_objects']['declaration']['flags']=1
            if change=='handler':after[1]['service']=456
            if change=='retired':after[1]['retired']+=1
            if change=='count':e['display_refresh']['updates']=0
            if change=='mask':e['display_refresh']['update_mask']=4
            if change=='bits':e['display_refresh']['capability_bits']=4
            e['trace_sha256']=hashlib.sha256(encoded(after)).hexdigest()
            if change=='new_hash':e['trace_sha256']='00'*32
            with self.subTest(change=change),self.assertRaises(InputError):self.proof(old,new,b,e,before,after)

if __name__=='__main__':unittest.main()
