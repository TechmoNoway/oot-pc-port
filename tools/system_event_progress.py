"""Full prefix/producer/early-constructor continuation proof for VSync events."""
import hashlib,json
from application_frontier import module_identities,trace_rows,validate_site,verify_full_trace
from input_formats import require
from system_event_audit import PUBLIC

def verify_events_progress_trace(old_trace,before,old_bundle,trace,execution,bundle):
    verify_full_trace(old_trace,before);verify_full_trace(trace,execution)
    identities=module_identities(bundle)
    require(module_identities(old_bundle)==identities,'event original module identity changed')
    audit=bundle.get('native_audit',{});domain=audit.get('system_events',{})
    require(old_bundle.get('native_audit',{}).get('objects_runtime')is True and
        old_bundle['native_audit'].get('events_runtime')is not True and audit.get('events_runtime')is True and
        domain.get('consumer_closure')is True and domain.get('original_consumers_retained')is True and
        audit.get('display_objects',{}).get('declaration',{}).get('flags')==1 and len(domain.get('census',[]))==256,
        'event source producer/consumer closure differs')
    typed=[r for r in audit.get('functions',[])if r.get('handler_id')==456]
    require(len(typed)==1,'event typed binding domain differs');binding=typed[0]
    old=[r for r in old_bundle['native_audit']['functions']if r.get('entry')==binding.get('entry')]
    keys=('symbol','module','entry','size','body_sha256','symbol_metadata','entry_instruction')
    require(len(old)==1 and old[0].get('handler_id')==31 and binding.get('names')==[PUBLIC]and
        binding.get('returns_value')is True and binding.get('return_register')=='w0'and
        all(binding.get(k)==old[0].get(k)==domain.get('public',{}).get(k)for k in keys),
        'event public source/body/Result ABI differs')
    entry=binding['entry'];word=binding.get('entry_word');ins=binding['entry_instruction']
    validate_site(dict(address=entry,word=word,module='sdk',source_sha256=identities['sdk'][1],word_sha256=ins.get('sha256')),
        bundle,entry,word)
    require(before.get('pc')==hex(entry)and before.get('word')==word and before.get('error')==9 and
        before.get('service')==31 and before.get('native_handler_stop')is True,'event baseline is not its original guard')
    stop=dict(pc=before['pc'],next_pc=before['pc'],retired=before['retired'],word=word,event=2,error=9,service=31)
    stop_bytes=json.dumps(stop,separators=(',',':')).encode()+b'\n'
    early=domain.get('early_create',{});early_entry=early.get('entry')
    require(type(early_entry)is int and early.get('size')==104,'event lacks its original early creation route')
    branch=domain.get('early_inprocess_branch',{})
    validate_site(dict(address=branch.get('address'),word=branch.get('word'),module='sdk',source_sha256=identities['sdk'][1],
        word_sha256=branch.get('sha256')),bundle,early_entry+20,branch.get('word'))
    retained={r.get('symbol')for r in domain.get('consumers',[])}|{early.get('symbol')}
    require(retained==set(domain.get('retained_symbols',[]))and
        not any(r.get('entry')==early_entry for r in audit['functions']),'early event creation was replaced or guarded')
    count=native=0;crossing=continuation=None;need=False;digest=hashlib.sha256();early_steps=[];branches=[]
    for line,row in trace_rows(trace):
        if need:
            require(row['event']==0 and row['error']==row['service']==0 and row['pc']==crossing['next_pc']and
                row['retired']==crossing['retired']+1,'event did not retire its original caller continuation')
            continuation=row;need=False
        if int(row['pc'],16)==early_entry and row['event']==0:
            require(row['word']==early.get('entry_instruction',{}).get('word')and row['retired']<before['retired'],
                'early event original entry differs');early_steps.append(row)
        if int(row['pc'],16)==early_entry+20 and row['event']==0:
            require(row['word']==branch['word']and int(row['next_pc'],16)==early_entry+44,
                'early event did not retain its original in-process branch');branches.append(row)
        if row['event']==3:
            native+=1
            if row['service']==456:
                require(crossing is None and int(row['pc'],16)==entry and row['word']==word and row['error']==0 and
                    row['retired']==before['retired']and native==before['native_calls']+1 and
                    4<=int(row['next_pc'],16)<1<<39 and int(row['next_pc'],16)%4==0 and row['next_pc']!=row['pc'],
                    'event source/return/checkpoint differs')
                restored=digest.copy();restored.update(stop_bytes)
                require(restored.hexdigest()==before['trace_sha256'],'original prefix before event publication changed')
                crossing=row;need=True;count+=1
        digest.update(line)
    owner=execution.get('display_objects',{});old_owner=before.get('display_objects',{})
    require(execution.get('events_runtime')is True and owner.get('event_open')==1 and owner.get('vsync_events')==count==1 and
        owner.get('calls')==old_owner.get('calls',0)+1 and
        all(owner.get(k)==old_owner.get(k)for k in('display_open','layer_open','references','opens','creates','closes','destroys',
            'window_getters','waits','resets','clears','handle_closes')),'event real owner/publication counters differ')
    require(crossing is not None and continuation is not None and not need and len(early_steps)==len(branches)==2 and
        native==execution.get('native_calls')and digest.hexdigest()==execution['trace_sha256'],'event full proof is incomplete')
    return dict(format='oot-system-event-progress',crossing=crossing,continuation=continuation,
        early_original_creations=early_steps,early_inprocess_branches=branches,
        original_prefix_sha256=before['trace_sha256'],trace_sha256=digest.hexdigest(),
        publications=count,runtime_authority_granted=False)
