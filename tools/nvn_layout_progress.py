"""Prove the old property boundary and complete original prefix survive."""
import hashlib,json
from application_frontier import module_identities,trace_rows,verify_full_trace
from input_formats import require
from nvn_layout_audit import BUILDER_ROLES

def verify_nvn_layout_progress_trace(old_trace,before,old_bundle,trace,execution,bundle):
    verify_full_trace(old_trace,before);verify_full_trace(trace,execution)
    require(module_identities(old_bundle)==module_identities(bundle),'NVN layout original module identities changed')
    a=old_bundle['native_audit'];b=bundle['native_audit'];domain=b.get('nvn_layout',{})
    require(a['display_objects']['declaration']['flags']==7 and b['display_objects']['declaration']['flags']==15 and
        b.get('nvn_layout_runtime')is True and domain.get('resource_apis_implemented')is False and
        {k:v['value']for k,v in domain.get('queries',{}).items()}=={'15':32,'16':32,'17':256,'18':256,'19':4,'20':8},
        'NVN layout opt-in/source geometry differs')
    prior=[f for f in a['functions']if f['handler_id']==461];now=[f for f in b['functions']if f['handler_id']==461]
    require(len(prior)==len(now)==1 and prior==now,'NVN layout public body/ABI binding changed')
    args=before.get('application_stop_arguments',[])
    require(before.get('native_handler_stop')is True and before.get('service')==461 and before.get('error')==9 and
        before.get('pc')==hex(prior[0]['entry'])and before.get('word')==prior[0]['entry_word']and len(args)==8 and
        args[0]==before.get('nvn',{}).get('device_identity')and args[1]&0xffffffff==15,
        'NVN layout baseline is not its exact owned-device property boundary')
    stop=dict(pc=before['pc'],next_pc=before['pc'],retired=before['retired'],word=before['word'],event=2,error=9,service=461)
    retained=domain.get('retained_builders',[])
    require(len(retained)==8 and {p['name']for p in retained}==set(BUILDER_ROLES)and
        all(p in a.get('nvn',{}).get('procedures',[])and p in b.get('nvn',{}).get('procedures',[])for p in retained)and
        not any(f['entry']==p['entry']for p in retained for f in b['functions']),
        'NVN original memory-pool builder source/retention differs')
    builder_entries={p['entry']:p for p in retained};builders={}
    digest=hashlib.sha256();crossing=None;continuation=None;calls=0;pending=False
    for line,row in trace_rows(trace):
        if pending:
            require(row['event']==0 and row['error']==row['service']==0 and row['pc']==crossing['next_pc']and
                row['retired']==crossing['retired']+1,'NVN layout did not retire the original property caller')
            continuation=row;pending=False
        if row['event']==3:calls+=1
        if int(row['pc'],16)in builder_entries:
            p=builder_entries[int(row['pc'],16)]
            require(crossing is not None and row['event']==0 and row['error']==row['service']==0 and
                row['word']==p['entry_word']and int(row['next_pc'],16)==p['entry']+4,
                'NVN memory-pool builder did not execute its exact original first instruction')
            builders.setdefault(p['name'],[]).append(row)
        if crossing is None and row['pc']==before['pc']and row['retired']==before['retired']:
            require(row['event']==3 and row['error']==0 and row['service']==461 and row['word']==before['word']and
                row['pc']!=row['next_pc']and calls==before['native_calls']+1,'NVN layout boundary did not become its exact native call')
            restored=digest.copy();restored.update(json.dumps(stop,separators=(',',':')).encode()+b'\n')
            require(restored.hexdigest()==before['trace_sha256'],'NVN layout preceding complete trace prefix changed')
            crossing=row;pending=True
        digest.update(line)
    required={name for name in BUILDER_ROLES if 'Set'in name}
    require(required<=set(builders)and crossing is not None and continuation is not None and not pending and
        execution.get('nvn_layout_runtime')is True and execution.get('nvn',{}).get('integer_queries',0)>before['nvn']['integer_queries']and
        digest.hexdigest()==execution['trace_sha256'],'NVN layout full continuation proof is incomplete')
    return dict(format='oot-nvn-layout-progress',property_call=crossing,original_caller_step=continuation,
        original_builders=builders,original_prefix_sha256=before['trace_sha256'],trace_sha256=digest.hexdigest(),game_frame_proven=False)
