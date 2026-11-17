"""Synthetic full-prefix/caller proof; no original instructions or addresses."""
from copy import deepcopy
import hashlib,json,struct,tempfile,unittest
from pathlib import Path
from input_formats import InputError
from nvn_resources_audit import OPERATIONS
from nvn_milestone import validate_nvn_config
from nvn_resources_progress import verify_nvn_resources_progress_trace
from test_nvn_progress import encoded

def fixture():
    word=0xd503201f
    def row(pc,to,ret,event=0,service=0,error=0):return dict(pc=hex(pc),next_pc=hex(to),retired=ret,word=word,event=event,error=error,service=service)
    operations={};functions=[]
    for n,(name,handler,size,returns)in enumerate(OPERATIONS):
        p=dict(entry=0x10000+n*0x1000,size=size,entry_word=word,body_sha256='ab'*32)
        operations[name]=p;functions.append(dict(p,handler_id=handler,nvn_procedures=[name],return_register=returns))
    first=functions[0];a=dict(entry_audit=dict(modules=[dict(name='sdk',base=0x1000,source_sha256='bc'*32,text_sha256='cd'*32)]),
        native_audit=dict(display_objects=dict(declaration=dict(flags=15)),functions=[dict(first,handler_id=31)]))
    original=dict(name='nvnSamplerBuilderSetDefaults',entry=0x7000,size=8,body_sha256=hashlib.sha256(struct.pack('<II',0xf9000001,0xd65f03c0)).hexdigest())
    a['native_audit']['nvn']=dict(procedures=[original])
    b=deepcopy(a);b['native_audit'].update(functions=functions,nvn_resources_runtime=True,
        nvn_resources=dict(operations=operations,consumer_closure=True,supported_pool_flags=0x22,game_draws_implemented=False,descriptor_binding_implemented=False,sampler_registration_implemented=True,retained_sampler_methods=[original]))
    b['native_audit']['display_objects']['declaration']['flags']=31
    prefix=[row(0x1000,0x1004,1),row(0x1004,0x10000,2)]
    old=prefix+[row(0x10000,0x10000,2,2,31,9)]
    new=prefix+[row(0x10000,0x1008,2,3,466),row(0x1008,0x7000,3),dict(row(0x7000,0x7004,4),word=0xf9000001),dict(row(0x7004,0x100c,5),word=0xd65f03c0),row(0x100c,0x12000,6),row(0x12000,0x1010,6,3,468),row(0x1010,0x9000,7),row(0x9000,0x9000,7,2,31,9)]
    before=dict(pc='0x10000',word=word,retired=2,service=31,error=9,native_handler_stop=True,native_calls=0,
        trace_steps=2,trace_rows=3,trace_sha256=hashlib.sha256(encoded(old)).hexdigest())
    after=dict(retired=7,native_calls=2,trace_steps=9,trace_rows=10,trace_sha256=hashlib.sha256(encoded(new)).hexdigest(),
        nvn_resources_runtime=True,game_frame_proven=False,nvn_resources=dict(pools=1,buffers=0,bytes=8192,
            initializations=1,finalizations=0,maps=1,queries=0,flushes=0,invalidations=0,descriptor_pools=0,descriptor_slots=0,descriptor_initializations=0,descriptor_finalizations=0,descriptor_queries=0,samplers=0,sampler_registrations=0))
    return a,b,before,after,old,new

class NvnResourceProgressTests(unittest.TestCase):
    def proof(self,a,b,before,after,old,new):
        with tempfile.TemporaryDirectory()as d:
            x=Path(d)/'old';y=Path(d)/'new';x.write_bytes(encoded(old));y.write_bytes(encoded(new))
            return verify_nvn_resources_progress_trace(x,before,a,y,after,b)
    def test_complete_old_guard_prefix_and_typed_original_caller_returns(self):
        r=self.proof(*fixture());self.assertEqual(r['original_caller_returns'],2);self.assertFalse(r['game_frame_proven'])
    def test_crossed_source_flags_counts_bodies_retirement_and_caller_reject(self):
        for mutation in ('source','flags','counts','body','word','prefix','caller','retirement','draws','closure','family','ordinaryword','ordinaryreturn','ordinaryhash'):
            a,b,before,after,old,new=fixture()
            if mutation=='source':b['entry_audit']['modules'][0]['source_sha256']='ff'*32
            if mutation=='flags':b['native_audit']['display_objects']['declaration']['flags']=15
            if mutation=='counts':after['nvn_resources']['maps']=0
            if mutation=='body':b['native_audit']['functions'][0]['body_sha256']='ff'*32
            if mutation=='word':new[2]['word']^=1
            if mutation=='prefix':new[0]['next_pc']='0x1008'
            if mutation=='caller':new[3]['pc']='0x1010'
            if mutation=='retirement':new[2]['retired']=3
            if mutation=='draws':b['native_audit']['nvn_resources']['game_draws_implemented']=True
            if mutation=='closure':b['native_audit']['nvn_resources']['consumer_closure']=False
            if mutation=='ordinaryword':new[4]['word']^=1
            if mutation=='ordinaryreturn':new[5]['next_pc']='0x1010'
            if mutation=='ordinaryhash':b['native_audit']['nvn_resources']['retained_sampler_methods'][0]['body_sha256']='ff'*32
            if mutation=='family':b['native_audit']['functions'].pop()
            after['trace_sha256']=hashlib.sha256(encoded(new)).hexdigest()
            with self.subTest(mutation=mutation),self.assertRaises(InputError):self.proof(a,b,before,after,old,new)

    def test_configuration_retains_layout_lane_and_resource_execution(self):
        c=json.loads((Path(__file__).resolve().parents[1]/'config/milestones/nvn-resources.json').read_text());validate_nvn_config(c)
        for key,value in [('nvn_resources_experiment',False),('nvn_layout_experiment',False),('nvn_resources_experiment',1),
            ('nvn_resources_expected_guard','unknown'),('nvn_resources_min_post_entry',326218)]:
            changed=dict(c);changed[key]=value
            with self.subTest(key=key),self.assertRaises(InputError):validate_nvn_config(changed)
