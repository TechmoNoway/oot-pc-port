"""Synthetic original loader/typed-call full-prefix proof, including failures."""
import hashlib,json,struct,tempfile,unittest
from copy import deepcopy
from pathlib import Path
from input_formats import InputError
from nvn_progress import verify_nvn_progress_trace
from nvn_milestone import validate_nvn_config

def encoded(rows):return b''.join(json.dumps(r,separators=(',',':')).encode()+b'\n'for r in rows)
def fixture():
    word=0xd503201f
    def row(pc,to,ret,event=0,service=0,error=0):return dict(pc=hex(pc),next_pc=hex(to),retired=ret,word=word,event=event,error=error,service=service)
    loader=dict(entry=0x2000,size=96,body_sha256='ab'*32,entry_word=word,
        entry_instruction=dict(sha256=hashlib.sha256(struct.pack('<I',word)).hexdigest()))
    old=dict(entry_audit=dict(modules=[dict(name='sdk',base=0x1000,source_sha256='bc'*32,text_sha256='cd'*32)]),
        native_audit=dict(display_objects=dict(declaration=dict(flags=3)),functions=[dict(loader,names=['nvnBootstrapLoader'],handler_id=31)]))
    new=deepcopy(old);a=new['native_audit'];a.update(nvn_runtime=True,functions=[dict(handler_id=n,entry=0x3000+n*4,entry_word=word)for n in range(458,466)])
    a['display_objects']['declaration']['flags']=7;a['nvn']=dict(loader=loader,consumer_closure=True,procedures=[{}]*735)
    prefix=[row(0x1000,0x2000,1)];before=prefix+[row(0x2000,0x2000,1,2,31,9)]
    after=prefix+[row(0x2000,0x2004,2)];retired=2;counts={458:735,459:1,461:2,462:1,464:1}
    for handler,n in counts.items():
        for _ in range(n):
            after.append(row(0x3000+handler*4,0x2100,retired,3,handler));retired+=1;after.append(row(0x2100,0x2104,retired))
    after.append(row(0x2300,0x2300,retired,2,461,9));calls=sum(counts.values())
    b=dict(pc=hex(0x2000),word=word,error=9,service=31,native_handler_stop=True,retired=1,native_calls=0,
        trace_steps=1,trace_rows=2,trace_sha256=hashlib.sha256(encoded(before)).hexdigest())
    e=dict(retired=retired,native_calls=calls,trace_steps=retired+calls,trace_rows=retired+calls+1,trace_sha256=hashlib.sha256(encoded(after)).hexdigest(),
        nvn=dict(device_ready=True,initializations=1,finalizations=0,lookups=735,integer_queries=2,state_updates=2,state_queries=0,window_origin=1,depth_mode=1))
    return old,new,b,e,before,after

class NvnProgressTests(unittest.TestCase):
    def proof(self,old,new,b,e,before,after):
        with tempfile.TemporaryDirectory()as folder:
            a=Path(folder)/'old';c=Path(folder)/'new';a.write_bytes(encoded(before));c.write_bytes(encoded(after))
            return verify_nvn_progress_trace(a,b,old,c,e,new)
    def test_original_loader_and_each_typed_original_caller(self):
        r=self.proof(*fixture());self.assertEqual(r['original_caller_returns'],740);self.assertFalse(r['game_frame_proven'])
    def test_prefix_source_quota_return_and_owner_changes_reject(self):
        for mutation in('prefix','loader','return','word','counter','flags','closure'):
            old,new,b,e,before,after=fixture()
            if mutation=='prefix':after[0]['word']^=1
            if mutation=='loader':after[1]['event']=3
            if mutation=='return':after[3]['pc']='0x2104'
            if mutation=='word':after[2]['word']^=1
            if mutation=='counter':e['nvn']['lookups']-=1
            if mutation=='flags':new['native_audit']['display_objects']['declaration']['flags']=3
            if mutation=='closure':new['native_audit']['nvn']['consumer_closure']=False
            e['trace_sha256']=hashlib.sha256(encoded(after)).hexdigest()
            with self.subTest(mutation=mutation),self.assertRaises(InputError):self.proof(old,new,b,e,before,after)
    def test_config_requires_closed_preceding_profile_and_unknown_property(self):
        c=dict(nvn_experiment=True,refresh_experiment=True,refresh_expected_guard='nvnBootstrapLoader',nvn_seed_report='build/seed.json',
            nvn_expected_guard='nvnDeviceGetInteger',nvn_expected_query=15,nvn_min_post_entry=325815,refresh_min_post_entry=311510,
            renderer_shader_tool='build/tool.exe',renderer_shader_identity='build/identity.json')
        validate_nvn_config(c);validate_nvn_config({})
        for key,value in(('refresh_experiment',False),('nvn_expected_query',0),('nvn_expected_query',42),('nvn_expected_query',True),('nvn_seed_report','')):
            changed=dict(c);changed[key]=value
            with self.subTest(key=key),self.assertRaises(InputError):validate_nvn_config(changed)

if __name__=='__main__':unittest.main()
