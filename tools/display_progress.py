"""Read-only VI parent-replacement proof; grants no runtime capability."""
import hashlib,re
from application_frontier import module_identities,trace_rows,validate_site,verify_full_trace
from display_audit import INITIALIZE
from input_formats import require

def verify_display_progress_trace(old_trace,baseline_execution,baseline_bundle,trace,execution,current_bundle):
    verify_full_trace(old_trace,baseline_execution);verify_full_trace(trace,execution)
    require(module_identities(baseline_bundle)==module_identities(current_bundle),'display original modules changed')
    old_audit=baseline_bundle.get('native_audit',{});audit=current_bundle.get('native_audit',{})
    domain=audit.get('display_initialization',{})
    require(old_audit.get('graphics_runtime') is True and old_audit.get('display_runtime') is not True and
            audit.get('display_runtime') is True and domain.get('skipped_provider_closure') is True and
            len(domain.get('original_constructors',[]))==3 and
            all(r.get('original_execution_retained') is True for r in domain['original_constructors']),
            'display lacks its source-audited profile/retained constructor closure')
    typed=[r for r in audit.get('functions',[]) if r.get('handler_id')==450]
    require(len(typed)==1,'display typed binding domain differs')
    binding=typed[0];declared=domain.get('initialize',{})
    keys=('symbol','module','entry','size','body_sha256','symbol_metadata','entry_instruction')
    require(binding.get('names')==[INITIALIZE] and binding.get('symbol')==INITIALIZE and binding.get('module')=='sdk' and
            binding.get('returns_value') is False and binding.get('return_register') is None and
            all(binding.get(k)==declared.get(k) for k in keys) and isinstance(binding.get('body_sha256'),str) and
            re.fullmatch('[0-9a-f]{64}',binding['body_sha256']),'display source body or void ABI differs')
    entry=binding['entry'];word=binding.get('entry_word');instruction=binding.get('entry_instruction',{})
    require(instruction.get('address')==entry and instruction.get('word')==word and
            not any(r.get('entry')==entry for r in old_audit.get('functions',[])),
            'display source entry differs or historical entry was already replaced')
    site=dict(address=entry,word=word,module='sdk',source_sha256=module_identities(current_bundle)['sdk'][1],
        word_sha256=instruction.get('sha256'));validate_site(site,current_bundle,entry,word)
    old_digest=hashlib.sha256();old_native=0;old_step=None
    for line,row in trace_rows(old_trace):
        if row['event']==3:old_native+=1
        old_digest.update(line)
        if int(row['pc'],16)==entry:
            require(row['event']==0 and row['error']==0 and row['service']==0 and row['word']==word and
                    int(row['next_pc'],16)==entry+4 and row['retired']>0,
                    'historical VI initializer was not entered by its original STEP')
            old_step=row;old_step_bytes=line;old_prefix=old_digest.hexdigest();break
    require(old_step is not None,'historical full trace has no original VI initializer entry')
    display=execution.get('application_display',{})
    require(execution.get('display_runtime') is True and display.get('ready') is True and
            display.get('presentation_supported') is True and
            all(type(display.get(k)) is int and 0<display[k]<1<<64 for k in ('calls','initializations')) and
            display['calls']==display['initializations'],'display real backend readiness/counters differ')
    graphics=execution.get('application_graphics',{})
    require(execution.get('graphics_runtime') is True and graphics.get('ready') is True and
            all(type(graphics.get(k)) is int and 0<=graphics[k]<1<<64 for k in ('calls','boots','checks')) and
            graphics['boots']>0 and graphics['calls']==graphics['boots']+graphics['checks'],
            'display prerequisite graphics owner readiness/counters differ')
    digest=hashlib.sha256();crossing=continuation=None;native=initializations=0;need_continuation=False
    boots=checks=0
    for line,row in trace_rows(trace):
        if need_continuation:
            require(row['event']==0 and row['pc']==crossing['next_pc'] and row['error']==0 and row['service']==0 and
                    row['retired']==old_step['retired'],'display did not resume the original caller')
            continuation=row;need_continuation=False
        if row['event']==3:
            native+=1
            if row['service']==448:boots+=1
            elif row['service']==449:checks+=1
            if row['service']==450:
                target=int(row['next_pc'],16)
                require(int(row['pc'],16)==entry and row['word']==word and row['error']==0 and
                        4<=target<1<<39 and target%4==0 and target!=entry,'display native event/source/return differs')
                initializations+=1
                if crossing is None:
                    require(row['retired']==old_step['retired']-1 and native==old_native+1,
                            'display crossing moved or retired an original instruction')
                    restored=digest.copy();restored.update(old_step_bytes)
                    require(restored.hexdigest()==old_prefix,'original prefix before VI initialization changed')
                    crossing=row;need_continuation=True
        digest.update(line)
    require(crossing is not None and continuation is not None and not need_continuation and
            initializations==display['calls'] and boots==graphics['boots'] and checks==graphics['checks'] and
            native==execution['native_calls'] and
            digest.hexdigest()==execution['trace_sha256'],'display crossing/full counters/digest differ')
    return dict(format='oot-application-display-progress',crossing=crossing,continuation=continuation,
        original_entry_step=old_step,original_entry_prefix_sha256=old_prefix,
        historical_trace_sha256=baseline_execution['trace_sha256'],trace_sha256=digest.hexdigest(),
        initialize_events=initializations,runtime_authority_granted=False)
