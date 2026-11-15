"""Full original-prefix, constructor and returned-object continuation evidence."""
import hashlib,json,re
from application_frontier import module_identities,trace_rows,validate_site,verify_full_trace
from display_objects_audit import FUNCTIONS
from input_formats import require

def verify_objects_progress_trace(old_trace,before,old_bundle,trace,execution,bundle):
    verify_full_trace(old_trace,before);verify_full_trace(trace,execution)
    identities=module_identities(bundle)
    require(module_identities(old_bundle)==identities,'object original module identities changed')
    audit=bundle.get('native_audit',{});domain=audit.get('display_objects',{})
    require(old_bundle.get('native_audit',{}).get('display_runtime')is True and
        old_bundle.get('native_audit',{}).get('objects_runtime')is not True and audit.get('objects_runtime')is True and
        domain.get('original_construction_retained')is True and
        domain.get('skipped_history_and_driver_consumers_guarded')is True and
        domain.get('declaration',{}).get('flags')==0,'object profile or source closure differs')
    proof=domain.get('vtables',{})
    require(len(proof.get('tables',[]))==8 and proof.get('slot_count')==103 and len(proof.get('targets',[]))==85,
        'object complete virtual consumer census differs')
    rows=audit.get('functions',[]);sources={};keys=('symbol','module','entry','size','body_sha256','symbol_metadata','entry_instruction')
    typed=[r for r in rows if 451<=r.get('handler_id',0)<=456]
    require(len(typed)==5,'object typed domain differs')
    for handler,name,size,returns in FUNCTIONS:
        candidates=[r for r in typed if r.get('handler_id')==handler]
        require(len(candidates)==1,'missing object typed handler');row=candidates[0]
        original=[r for r in old_bundle['native_audit']['functions']if r.get('entry')==row.get('entry')]
        declared=[r for r in domain.get('public_contracts',[])if r.get('symbol')==name]
        require(len(original)==len(declared)==1 and original[0].get('handler_id')==31 and
            row.get('names')==[name]and row.get('size')==size and row.get('returns_value')is returns and
            row.get('return_register')==('w0'if returns else None)and
            all(row.get(k)==original[0].get(k)==declared[0].get(k)for k in keys)and
            isinstance(row.get('body_sha256'),str)and re.fullmatch('[0-9a-f]{64}',row['body_sha256']),
            'object public original body/ABI differs')
        instruction=row['entry_instruction'];entry=row['entry'];word=row.get('entry_word')
        site=dict(address=entry,word=word,module='sdk',source_sha256=identities['sdk'][1],word_sha256=instruction.get('sha256'))
        require(instruction.get('address')==entry and instruction.get('word')==word,'object original entry differs')
        validate_site(site,bundle,entry,word);sources[handler]=row
    for target in proof['targets']:
        matches=[r for r in rows if r.get('entry')==target.get('entry')]
        require(len(matches)==1 and matches[0].get('handler_id')==31 and
            all(matches[0].get(k)==target.get(k)for k in('size','body_sha256')),'object virtual consumer escaped its guard')
    first=sources[451]
    require(before.get('native_handler_stop')is True and before.get('error')==9 and before.get('service')==31 and
        before.get('pc')==hex(first['entry'])and before.get('word')==first['entry_word'],
        'object baseline is not its original open-display guard')
    required=domain.get('constructor',{}).get('required_original_steps',[])
    require(len(required)==4 and len({s.get('address')for s in required})==4,'missing original object materialization steps')
    expected={s['address']:s for s in required};observed={}
    for site in required:
        validate_site(dict(address=site['address'],word=site['word'],word_sha256=site['sha256'],module='sdk',
            source_sha256=identities['sdk'][1]),bundle,site['address'],site['word'])
    counts=dict.fromkeys(sources,0);native=0;crossing=continuation=None;pending=None;digest=hashlib.sha256()
    stop=dict(pc=before['pc'],next_pc=before['pc'],retired=before['retired'],word=before['word'],event=2,error=9,service=31)
    stop_bytes=json.dumps(stop,separators=(',',':')).encode()+b'\n'
    for line,row in trace_rows(trace):
        pc=int(row['pc'],16)
        if pending is not None:
            require(row['event']==0 and row['error']==row['service']==0 and row['pc']==pending['next_pc']and
                row['retired']==pending['retired']+1,'object API did not retire its original caller continuation')
            if continuation is None:continuation=row
            pending=None
        if pc in expected and row['event']==0:
            require(pc not in observed and row['word']==expected[pc]['word']and row['error']==row['service']==0 and
                int(row['next_pc'],16)==pc+4 and row['retired']<=before['retired'],'object original constructor observation differs')
            observed[pc]=row
        if row['event']==3:
            native+=1
            if row['service']in sources:
                source=sources[row['service']];target=int(row['next_pc'],16)
                require(pc==source['entry']and row['word']==source['entry_word']and row['error']==0 and
                    target%4==0 and 4<=target<1<<39 and target!=pc,'object native source/return differs')
                counts[row['service']]+=1;pending=row
                if crossing is None:
                    require(row['service']==451 and row['retired']==before['retired']and native==before['native_calls']+1,
                        'object open-display crossing moved')
                    restored=digest.copy();restored.update(stop_bytes)
                    require(restored.hexdigest()==before['trace_sha256'],'original prefix before returned objects changed')
                    crossing=row
        digest.update(line)
    report=execution.get('display_objects',{})
    require(execution.get('objects_runtime')is True and report.get('display_open')==report.get('layer_open')==1 and
        report.get('event_open')==0 and report.get('references')==1 and report.get('calls')==2 and
        report.get('opens')==counts[451]==1 and report.get('creates')==counts[453]==1 and
        all(report.get(k)==0 for k in('closes','destroys','window_getters','vsync_events','waits','resets','clears','handle_closes'))and
        all(counts[k]==0 for k in(452,454,455)),'object real owner/call counts differ')
    require(crossing is not None and continuation is not None and pending is None and len(observed)==4 and
        native==execution.get('native_calls')and digest.hexdigest()==execution['trace_sha256'],
        'object constructor/crossing/full trace proof is incomplete')
    return dict(format='oot-display-objects-progress',crossing=crossing,continuation=continuation,
        original_constructor_steps=list(observed.values()),object_events=counts,
        original_prefix_sha256=before['trace_sha256'],trace_sha256=digest.hexdigest(),runtime_authority_granted=False)
