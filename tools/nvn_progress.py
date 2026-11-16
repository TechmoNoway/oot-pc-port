"""Original loader prefix and typed NVN caller-continuation evidence."""
import hashlib,json
from collections import Counter
from application_frontier import module_identities,trace_rows,verify_full_trace,validate_site
from input_formats import require

def verify_nvn_progress_trace(old_trace,before,old_bundle,trace,execution,bundle):
    verify_full_trace(old_trace,before);verify_full_trace(trace,execution)
    identities=module_identities(bundle);require(module_identities(old_bundle)==identities,'NVN source identities changed')
    audit=bundle.get('native_audit',{});domain=audit.get('nvn',{});loader=domain.get('loader',{})
    require(audit.get('nvn_runtime')is True and domain.get('consumer_closure')is True and
        audit.get('display_objects',{}).get('declaration',{}).get('flags')==7 and
        old_bundle.get('native_audit',{}).get('display_objects',{}).get('declaration',{}).get('flags')==3 and
        len(domain.get('procedures',[]))==735,'NVN audit/table/opt-in closure differs')
    old=[f for f in old_bundle['native_audit']['functions']if f['entry']==loader.get('entry')]
    require(len(old)==1 and old[0]['handler_id']==31 and old[0].get('names')==['nvnBootstrapLoader']and
        all(old[0][k]==loader[k]for k in('size','body_sha256','entry_word'))and
        not any(f['entry']==loader['entry']for f in audit['functions']),'original NVN loader was replaced or differs')
    entry=loader['entry'];word=loader['entry_word']
    validate_site(dict(address=entry,word=word,module='sdk',source_sha256=identities['sdk'][1],
        word_sha256=loader['entry_instruction']['sha256']),bundle,entry,word)
    require((before.get('pc'),before.get('word'),before.get('error'),before.get('service'),before.get('native_handler_stop'))==
        (hex(entry),word,9,31,True),'NVN baseline is not the preceding original loader guard')
    stop=dict(pc=before['pc'],next_pc=before['pc'],retired=before['retired'],word=word,event=2,error=9,service=31)
    stop_bytes=json.dumps(stop,separators=(',',':')).encode()+b'\n'
    bindings={f['handler_id']:f for f in audit['functions']if 458<=f['handler_id']<=465}
    require(set(bindings)==set(range(458,466)),'NVN typed consumer domain differs')
    counts=Counter();digest=hashlib.sha256();crossing=None;native=0;pending=None;returns=0
    for line,row in trace_rows(trace):
        if pending is not None:
            require(row['event']==0 and row['error']==row['service']==0 and row['pc']==pending['next_pc']and
                row['retired']==pending['retired']+1,'NVN did not retire the original typed caller continuation')
            returns+=1;pending=None
        if row['event']==3:native+=1
        if crossing is None and int(row['pc'],16)==entry:
            require(row['event']==0 and row['word']==word and row['retired']==before['retired']+1 and
                row['error']==row['service']==0 and int(row['next_pc'],16)==entry+4 and native==before['native_calls'],
                'NVN loader is not its original STEP at the retained checkpoint')
            restored=digest.copy();restored.update(stop_bytes)
            require(restored.hexdigest()==before['trace_sha256'],'NVN preceding complete refresh prefix changed');crossing=row
        if row['event']==3 and row['service']in bindings:
            b=bindings[row['service']]
            require(crossing is not None and int(row['pc'],16)==b['entry']and row['word']==b['entry_word']and
                row['error']==0 and row['pc']!=row['next_pc']and 4<=int(row['next_pc'],16)<1<<39 and
                int(row['next_pc'],16)%4==0,'NVN typed source or canonical return differs')
            counts[row['service']]+=1;pending=row
        digest.update(line)
    owner=execution.get('nvn',{})
    require(owner.get('device_ready')is True and owner.get('initializations')==counts[459]==1 and
        owner.get('finalizations')==counts[460]==0 and owner.get('lookups')==counts[458]>=735 and
        owner.get('integer_queries')==counts[461]>=2 and owner.get('state_updates')==counts[462]+counts[464]and
        owner.get('state_queries')==counts[463]+counts[465]and owner.get('window_origin')in(0,1)and owner.get('depth_mode')in(0,1),
        'NVN owned state/call evidence differs')
    require(crossing is not None and pending is None and returns==sum(counts.values())and
        native==execution['native_calls']and digest.hexdigest()==execution['trace_sha256'],'NVN full trace proof is incomplete')
    return dict(format='oot-nvn-progress',loader_step=crossing,typed_calls=dict(counts),original_caller_returns=returns,
        original_prefix_sha256=before['trace_sha256'],trace_sha256=digest.hexdigest(),game_frame_proven=False)
