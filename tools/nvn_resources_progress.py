"""Complete old pool-init prefix, typed resources and original caller returns."""
import hashlib,json,struct
from collections import Counter
from application_frontier import module_identities,trace_rows,verify_full_trace
from input_formats import require
from nvn_resources_audit import OPERATIONS

def verify_nvn_resources_progress_trace(old_trace,before,old_bundle,trace,execution,bundle):
    verify_full_trace(old_trace,before);verify_full_trace(trace,execution)
    require(module_identities(old_bundle)==module_identities(bundle),'NVN resource original sources changed')
    a=old_bundle['native_audit'];b=bundle['native_audit'];domain=b.get('nvn_resources',{})
    require(a['display_objects']['declaration']['flags']==15 and b['display_objects']['declaration']['flags']==31 and
        b.get('nvn_resources_runtime')is True and domain.get('consumer_closure')is True and
        domain.get('supported_pool_flags')==0x22 and domain.get('game_draws_implemented')is False and domain.get('descriptor_binding_implemented')is False and
        domain.get('sampler_registration_implemented')is True,
        'NVN resource opt-in/closure differs')
    bindings={f['handler_id']:f for f in b['functions']if 466<=f['handler_id']<=494}
    require(set(bindings)==set(range(466,495)),'NVN resource typed family is incomplete')
    for name,handler,size,returns in OPERATIONS:
        f=bindings[handler];p=domain.get('operations',{}).get(name,{})
        require(f.get('nvn_procedures')==[name] and f['size']==size and f.get('return_register')==returns and
            all(f[k]==p.get(k)for k in('entry','size','entry_word','body_sha256')),'NVN resource source/ABI binding differs')
    prior=[f for f in a['functions']if f.get('nvn_procedures')==['nvnMemoryPoolInitialize']]
    target=bindings[466]
    require(len(prior)==1 and prior[0]['handler_id']==31 and all(prior[0][k]==target[k]for k in('entry','size','entry_word','body_sha256')) and
        (before.get('pc'),before.get('word'),before.get('service'),before.get('error'),before.get('native_handler_stop'))==
        (hex(target['entry']),target['entry_word'],31,9,True),'NVN resource baseline is not its exact original pool guard')
    stop=dict(pc=before['pc'],next_pc=before['pc'],retired=before['retired'],word=before['word'],event=2,error=9,service=31)
    ordinary=domain.get('retained_sampler_methods',[])
    require(ordinary and all(p in a.get('nvn',{}).get('procedures',[]) and p in b.get('nvn',{}).get('procedures',[]) and
        not any(f['entry']==p['entry']for f in b['functions'])for p in ordinary),'NVN ordinary sampler source/retention differs')
    original_entries={p['entry']:p for p in ordinary};active=None;original_return=None;original_proofs={}
    counts=Counter();digest=hashlib.sha256();crossing=None;pending=None;returns=0;native=0
    for line,row in trace_rows(trace):
        if original_return is not None:
            require(row['event']==0 and row['error']==row['service']==0 and row['pc']==original_return['return_pc'] and
                row['retired']==original_return['retired']+1,'NVN ordinary sampler did not retire its original caller')
            original_return['caller_step']=row;original_proofs.setdefault(original_return['name'],[]).append(original_return);original_return=None
        pc=int(row['pc'],16)
        if active is None and pc in original_entries:
            require(crossing is not None,'NVN ordinary sampler preceded its complete old prefix')
            active=dict(record=original_entries[pc],raw=bytearray(),first=row['retired'],previous=row['retired']-1)
        if active is not None:
            p=active['record'];offset=len(active['raw'])
            require(row['event']==0 and row['error']==row['service']==0 and pc==p['entry']+offset and
                row['retired']==active['previous']+1,'NVN ordinary sampler body was replaced/skipped')
            active['raw'].extend(struct.pack('<I',row['word']));active['previous']=row['retired']
            if len(active['raw'])<p['size']:require(int(row['next_pc'],16)==pc+4,'NVN ordinary sampler body left its linear source')
            else:
                require(len(active['raw'])==p['size'] and row['word']==0xd65f03c0 and
                    hashlib.sha256(active['raw']).hexdigest()==p['body_sha256'],'NVN ordinary sampler complete body/return differs')
                to=int(row['next_pc'],16)
                require(4<=to<1<<39 and to%4==0 and not p['entry']<=to<p['entry']+p['size'],'NVN ordinary sampler return is not canonical/distinct')
                original_return=dict(name=p['name'],body_sha256=p['body_sha256'],first_retired=active['first'],retired=row['retired'],return_pc=row['next_pc']);active=None
        if pending is not None:
            require(row['event']==0 and row['error']==row['service']==0 and row['pc']==pending['next_pc'] and
                row['retired']==pending['retired']+1,'NVN resource did not retire its original caller')
            returns+=1;pending=None
        if row['event']==3:native+=1
        if row['event']==3 and row['service']in bindings:
            f=bindings[row['service']]
            require(row['pc']==hex(f['entry']) and row['word']==f['entry_word'] and row['error']==0 and
                row['pc']!=row['next_pc'] and 4<=int(row['next_pc'],16)<1<<39 and int(row['next_pc'],16)%4==0,
                'NVN resource typed entry/return differs')
            if crossing is None:
                require(row['service']==466 and row['retired']==before['retired'] and native==before['native_calls']+1,
                    'NVN resource first call changed the old retirement checkpoint')
                restored=digest.copy();restored.update(json.dumps(stop,separators=(',',':')).encode()+b'\n')
                require(restored.hexdigest()==before['trace_sha256'],'NVN resource complete preceding prefix changed')
                crossing=row
            counts[row['service']]+=1;pending=row
        digest.update(line)
    owner=execution.get('nvn_resources',{})
    require(owner.get('pools')==counts[466]-counts[467]>0 and owner.get('buffers')==counts[474]-counts[475] and
        owner.get('initializations')==counts[466]+counts[474] and owner.get('finalizations')==counts[467]+counts[475] and
        owner.get('maps')==counts[468]+counts[476] and owner.get('queries')==sum(counts[n]for n in(469,470,473,477,478,479,480)) and
        owner.get('flushes')==counts[471]+counts[481] and owner.get('invalidations')==counts[472]+counts[482] and
        0<owner.get('bytes',0)<=64*1024*1024,'NVN resource owner/call counters differ')
    require(active is None and original_return is None and 'nvnSamplerBuilderSetDefaults'in original_proofs,
        'NVN original sampler defaults/body/return evidence is incomplete')
    require(crossing is not None and pending is None and returns==sum(counts.values()) and
        execution.get('nvn_resources_runtime')is True and execution.get('game_frame_proven')is False and
        native==execution['native_calls'] and digest.hexdigest()==execution['trace_sha256'],'NVN resource full evidence is incomplete')
    return dict(format='oot-nvn-resources-progress',first_pool_call=crossing,typed_calls=dict(counts),
        original_caller_returns=returns,original_sampler_bodies=original_proofs,original_prefix_sha256=before['trace_sha256'],trace_sha256=digest.hexdigest(),game_frame_proven=False)
