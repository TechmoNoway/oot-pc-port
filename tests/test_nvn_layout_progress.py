"""Synthetic complete old-boundary and original caller-continuation proofs."""
from copy import deepcopy
import hashlib,json,tempfile,unittest
from pathlib import Path
from input_formats import InputError
from nvn_layout_progress import verify_nvn_layout_progress_trace
from nvn_milestone import validate_nvn_config
from test_nvn_progress import encoded
from nvn_layout_audit import BUILDER_ROLES

def fixture():
    word=0xd503201f
    def row(pc,to,ret,event=0,service=0,error=0):
        return dict(pc=hex(pc),next_pc=hex(to),retired=ret,word=word,event=event,error=error,service=service)
    prefix=[row(0x1000,0x3000,1),row(0x3000,0x2000,1,3,461),row(0x2000,0x3000,2)]
    old=prefix+[row(0x3000,0x3000,2,2,461,9)]
    records=[dict(name=name,entry=0x4000+n*4,entry_word=word)for n,name in enumerate(BUILDER_ROLES)]
    new=prefix+[row(0x3000,0x2004,2,3,461),row(0x2004,0x4000,3)]
    for n,p in enumerate(records[:4]):new.append(row(p['entry'],p['entry']+4,4+n))
    new.append(row(0x6000,0x6000,7,2,31,9))
    binding=dict(entry=0x3000,size=4,entry_word=word,handler_id=461,body_sha256='ab'*32)
    a=dict(entry_audit=dict(modules=[dict(name='sdk',base=0x1000,source_sha256='bc'*32,text_sha256='cd'*32)]),
        native_audit=dict(display_objects=dict(declaration=dict(flags=7)),functions=[binding],nvn=dict(procedures=records)))
    b=deepcopy(a);b['native_audit'].update(nvn_layout_runtime=True,nvn_layout=dict(resource_apis_implemented=False,
        queries={str(q):dict(value=v)for q,v in((15,32),(16,32),(17,256),(18,256),(19,4),(20,8))},retained_builders=records))
    b['native_audit']['display_objects']['declaration']['flags']=15
    before=dict(pc=hex(0x3000),word=word,error=9,service=461,native_handler_stop=True,retired=2,native_calls=1,
        trace_steps=3,trace_rows=4,trace_sha256=hashlib.sha256(encoded(old)).hexdigest(),
        application_stop_arguments=[0x5000,15,0x6000,0,0,0,0,0],nvn=dict(device_identity=0x5000,integer_queries=1))
    after=dict(retired=7,native_calls=2,trace_steps=9,trace_rows=10,trace_sha256=hashlib.sha256(encoded(new)).hexdigest(),
        nvn_layout_runtime=True,nvn=dict(integer_queries=2))
    return a,b,before,after,old,new

class NvnLayoutProgressTests(unittest.TestCase):
    def proof(self,a,b,before,after,old,new):
        with tempfile.TemporaryDirectory()as folder:
            x=Path(folder)/'old';y=Path(folder)/'new';x.write_bytes(encoded(old));y.write_bytes(encoded(new))
            return verify_nvn_layout_progress_trace(x,before,a,y,after,b)
    def test_exact_old_property_prefix_and_original_return(self):
        r=self.proof(*fixture());self.assertEqual(r['original_caller_step']['retired'],3);self.assertFalse(r['game_frame_proven'])
    def test_crossed_owner_layout_source_prefix_and_continuation_reject(self):
        for mutation in('owner','query','layout','source','prefix','return','counter','flags','builder'):
            a,b,before,after,old,new=fixture()
            if mutation=='owner':before['application_stop_arguments'][0]+=8
            if mutation=='query':before['application_stop_arguments'][1]=16
            if mutation=='layout':b['native_audit']['nvn_layout']['queries']['15']['value']=64
            if mutation=='source':b['native_audit']['functions'][0]['body_sha256']='ff'*32
            if mutation=='prefix':new[0]['word']^=1
            if mutation=='return':new[4]['pc']='0x2008'
            if mutation=='counter':after['nvn']['integer_queries']=1
            if mutation=='flags':b['native_audit']['display_objects']['declaration']['flags']=7
            if mutation=='builder':new[5]['word']^=1
            after['trace_sha256']=hashlib.sha256(encoded(new)).hexdigest()
            with self.subTest(mutation=mutation),self.assertRaises(InputError):self.proof(a,b,before,after,old,new)
    def test_layout_config_keeps_its_old_lane_and_precise_next_boundary(self):
        root=Path(__file__).resolve().parents[1]
        c=json.loads((root/'config/milestones/nvn-textures.json').read_text());validate_nvn_config(c)
        for k,v in(('nvn_experiment',False),('nvn_expected_query',16),('nvn_layout_experiment',1),
            ('nvn_layout_expected_guard','nvnDeviceGetInteger'),('nvn_layout_min_post_entry',325815)):
            changed=dict(c);changed[k]=v
            with self.subTest(key=k),self.assertRaises(InputError):validate_nvn_config(changed)

if __name__=='__main__':unittest.main()
