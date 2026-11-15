"""Independent synthetic evidence; no original guest code or addresses."""
from copy import deepcopy
import hashlib,json,struct,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'tools'))
from display_objects_audit import FUNCTIONS
from display_objects_progress import verify_objects_progress_trace
from input_formats import InputError

def encoded(rows):return b''.join(json.dumps(r,separators=(',',':')).encode()+b'\n'for r in rows)
def fixture():
    def row(pc,retired,event=0,service=0,next_pc=None,error=0):
        return dict(pc=hex(pc),next_pc=hex(pc+4 if next_pc is None else next_pc),retired=retired,
            word=0xd503201f,event=event,error=error,service=service)
    original=[];typed=[];contracts=[]
    for n,(handler,name,size,returns)in enumerate(FUNCTIONS):
        pc=0x10000+n*0x200;instruction=dict(address=pc,word=0xd503201f,sha256=hashlib.sha256(struct.pack('<I',0xd503201f)).hexdigest())
        f=dict(symbol=name,module='sdk',entry=pc,size=size,body_sha256='ab'*32,symbol_metadata={'index':n},
            entry_instruction=instruction,entry_word=instruction['word'],names=[name])
        contracts.append(deepcopy(f));original.append(dict(f,handler_id=31,returns_value=False,return_register=None))
        typed.append(dict(f,handler_id=handler,returns_value=returns,return_register='w0'if returns else None))
    targets=[dict(entry=0x20000+n*8,size=4,body_sha256='bc'*32)for n in range(85)]
    guards=[dict(t,handler_id=31)for t in targets]
    prefix=[row(0x3000+n*4,n+1)for n in range(4)]
    steps=[dict(address=int(r['pc'],16),word=r['word'],sha256=hashlib.sha256(struct.pack('<I',r['word'])).hexdigest())for r in prefix]
    old=dict(entry_audit=dict(modules=[dict(name='sdk',base=0x1000,source_sha256='cd'*32,text_sha256='ef'*32)]),
        native_audit=dict(display_runtime=True,functions=original))
    current=deepcopy(old);current['native_audit'].update(objects_runtime=True,functions=typed+guards,
        display_objects=dict(original_construction_retained=True,skipped_history_and_driver_consumers_guarded=True,
            declaration={'flags':0},public_contracts=contracts,constructor={'required_original_steps':steps},
            vtables=dict(tables=[{}for _ in range(8)],slot_count=103,targets=targets)))
    before=prefix+[row(0x10000,4,2,31,next_pc=0x10000,error=9)]
    rows=prefix+[row(0x10000,4,3,451,next_pc=0x4000),row(0x4000,5),
        row(0x10400,5,3,453,next_pc=0x4004),row(0x4004,6),row(0x5000,6,2,31,next_pc=0x5000,error=9)]
    baseline=dict(retired=4,native_calls=0,trace_steps=4,trace_rows=5,trace_sha256=hashlib.sha256(encoded(before)).hexdigest(),
        native_handler_stop=True,error=9,service=31,pc=hex(0x10000),word=0xd503201f)
    objects=dict(display_open=1,layer_open=1,event_open=0,references=1,calls=2,opens=1,creates=1,
        closes=0,destroys=0,window_getters=0,vsync_events=0,waits=0,resets=0,clears=0,handle_closes=0)
    execution=dict(retired=6,native_calls=2,trace_steps=8,trace_rows=9,trace_sha256=hashlib.sha256(encoded(rows)).hexdigest(),
        objects_runtime=True,display_objects=objects)
    return old,current,baseline,execution,before,rows

class ObjectsProgressTests(unittest.TestCase):
    def proof(self,old,current,baseline,execution,before,rows):
        with tempfile.TemporaryDirectory()as directory:
            a=Path(directory)/'before';b=Path(directory)/'after';a.write_bytes(encoded(before));b.write_bytes(encoded(rows))
            return verify_objects_progress_trace(a,baseline,old,b,execution,current)
    def test_restores_original_guard_and_requires_actual_constructor_and_each_return(self):
        r=self.proof(*fixture());self.assertEqual(len(r['original_constructor_steps']),4)
        self.assertEqual(r['object_events'][451],1);self.assertEqual(r['object_events'][453],1)
        self.assertFalse(r['runtime_authority_granted'])
    def test_wrong_source_prefix_vptr_steps_closure_abi_owner_and_continuation_reject(self):
        for mutation in('module','prefix','ctor_word','ctor_count','closure','guard','public','returns','events',
            'profile','owner','layer','calls','return','continue','handler','retired','old_hash','new_hash'):
            old,current,b,e,before,rows=fixture();a=current['native_audit'];d=a['display_objects']
            if mutation=='module':current['entry_audit']['modules'][0]['source_sha256']='ff'*32
            if mutation=='prefix':rows[0]['word']^=1;d['constructor']['required_original_steps'][0]['word']^=1
            if mutation=='ctor_word':d['constructor']['required_original_steps'][0]['word']^=1
            if mutation=='ctor_count':d['constructor']['required_original_steps'].pop()
            if mutation=='closure':d['skipped_history_and_driver_consumers_guarded']=False
            if mutation=='guard':a['functions'][-1]['handler_id']=450
            if mutation=='public':d['public_contracts'][0]['body_sha256']='11'*32
            if mutation=='returns':a['functions'][0]['return_register']='X0'
            if mutation=='events':d['declaration']['flags']=1
            if mutation=='profile':e['objects_runtime']=False
            if mutation=='owner':e['display_objects']['references']=2
            if mutation=='layer':e['display_objects']['layer_open']=0
            if mutation=='calls':e['display_objects']['creates']=2
            if mutation=='return':rows[4]['next_pc']=rows[4]['pc']
            if mutation=='continue':rows[7]['pc']=rows[7]['next_pc']
            if mutation=='handler':rows[6]['service']=451
            if mutation=='retired':rows[4]['retired']+=1
            e['trace_sha256']=hashlib.sha256(encoded(rows)).hexdigest()
            if mutation=='old_hash':b['trace_sha256']='00'*32
            if mutation=='new_hash':e['trace_sha256']='00'*32
            with self.subTest(mutation=mutation),self.assertRaises(InputError):self.proof(old,current,b,e,before,rows)

if __name__=='__main__':unittest.main()
