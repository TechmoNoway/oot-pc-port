"""Restore the entire preceding VSync prefix and prove a retired original caller."""
import hashlib,json
from application_frontier import module_identities,trace_rows,validate_site,verify_full_trace
from display_refresh_audit import PUBLIC
from input_formats import require

def verify_refresh_progress_trace(old_trace,before,old_bundle,trace,execution,bundle):
    verify_full_trace(old_trace,before);verify_full_trace(trace,execution)
    identities=module_identities(bundle)
    require(module_identities(old_bundle)==identities,'refresh original module identity changed')
    audit=bundle.get('native_audit',{});domain=audit.get('display_refresh',{})
    require(old_bundle.get('native_audit',{}).get('events_runtime')is True and
        old_bundle['native_audit'].get('refresh_runtime')is not True and audit.get('refresh_runtime')is True and
        domain.get('consumer_closure')is True and len(domain.get('consumer_census',[]))==22 and
        (domain.get('enabled_bits'),domain.get('update_mask'),domain.get('request_command'))==(2,2,0x13d)and
        old_bundle['native_audit']['display_objects']['declaration']['flags']==1 and
        audit.get('display_objects',{}).get('declaration',{}).get('flags')==3,
        'refresh source/consumer closure differs')
    typed=[r for r in audit.get('functions',[])if r.get('handler_id')==457]
    require(len(typed)==1,'refresh typed binding domain differs');binding=typed[0]
    old=[r for r in old_bundle['native_audit']['functions']if r.get('entry')==binding.get('entry')]
    keys=('symbol','module','entry','size','body_sha256','symbol_metadata','entry_instruction')
    require(len(old)==1 and old[0].get('handler_id')==31 and binding.get('names')==[PUBLIC]and
        binding.get('returns_value')is False and binding.get('return_register')is None and
        all(binding.get(k)==old[0].get(k)==domain.get('public',{}).get(k)for k in keys),
        'refresh public source/body/void ABI differs')
    entry=binding['entry'];word=binding.get('entry_word');ins=binding['entry_instruction']
    validate_site(dict(address=entry,word=word,module='sdk',source_sha256=identities['sdk'][1],word_sha256=ins.get('sha256')),
        bundle,entry,word)
    require(before.get('pc')==hex(entry)and before.get('word')==word and before.get('error')==9 and
        before.get('service')==31 and before.get('native_handler_stop')is True,'refresh baseline is not its original guard')
    stop=dict(pc=before['pc'],next_pc=before['pc'],retired=before['retired'],word=word,event=2,error=9,service=31)
    stop_bytes=json.dumps(stop,separators=(',',':')).encode()+b'\n'
    native=count=0;crossing=continuation=None;need=False;digest=hashlib.sha256()
    for line,row in trace_rows(trace):
        if need:
            require(row['event']==0 and row['error']==row['service']==0 and row['pc']==crossing['next_pc']and
                row['retired']==crossing['retired']+1,'refresh did not retire its original caller continuation')
            continuation=row;need=False
        if row['event']==3:
            native+=1
            if row['service']==457:
                require(crossing is None and int(row['pc'],16)==entry and row['word']==word and row['error']==0 and
                    row['retired']==before['retired']and native==before['native_calls']+1 and
                    4<=int(row['next_pc'],16)<1<<39 and int(row['next_pc'],16)%4==0 and row['next_pc']!=row['pc'],
                    'refresh source/return/checkpoint differs')
                restored=digest.copy();restored.update(stop_bytes)
                require(restored.hexdigest()==before['trace_sha256'],'original prefix before refresh declaration changed')
                crossing=row;need=True;count+=1
        digest.update(line)
    owner=execution.get('display_objects',{});old_owner=before.get('display_objects',{});refresh=execution.get('display_refresh',{})
    require(execution.get('refresh_runtime')is True and execution.get('events_runtime')is True and
        owner.get('calls')==old_owner.get('calls',0)+1 and
        all(owner.get(k)==old_owner.get(k)for k in('display_open','layer_open','event_open','references','opens','creates',
            'closes','destroys','window_getters','vsync_events','waits','resets','clears','handle_closes'))and
        refresh.get('updates')==count==1 and refresh.get('ignored')==0 and refresh.get('update_mask')==2 and
        refresh.get('capability_bits')in (0,2),'refresh real owner/declaration counters differ')
    require(crossing is not None and continuation is not None and not need and native==execution.get('native_calls')and
        digest.hexdigest()==execution['trace_sha256'],'refresh full proof is incomplete')
    return dict(format='oot-display-refresh-progress',crossing=crossing,continuation=continuation,
        original_prefix_sha256=before['trace_sha256'],trace_sha256=digest.hexdigest(),updates=count,
        physical_mode_changed=False,runtime_authority_granted=False)
