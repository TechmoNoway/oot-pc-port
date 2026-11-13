"""Read-only whole-boot prefix proof; it grants no execution capability."""
import hashlib,re
from application_frontier import module_identities,trace_rows,validate_site,verify_full_trace
from graphics_audit import BOOT,PUBLIC,CHECK
from input_formats import require

def verify_graphics_progress_trace(old_trace,baseline_execution,baseline_bundle,trace,execution,current_bundle):
    """Require both native full traces and freshly source-audited bundles.

    The replacement is at the parent boot entry, earlier than the historical
    internal resource getter. Restore its original first STEP into the prefix;
    require a real original caller instruction after the successful native call.
    """
    verify_full_trace(old_trace,baseline_execution);verify_full_trace(trace,execution)
    require(module_identities(baseline_bundle)==module_identities(current_bundle),'graphics original modules changed')
    audit=current_bundle.get('native_audit',{});domain=audit.get('graphics_bootstrap',{})
    require(audit.get('graphics_runtime') is True and domain.get('skipped_provider_closure') is True,
            'graphics lacks its source-audited provider closure')
    expected={BOOT:448,PUBLIC:448,CHECK:449};sources={};keys=('symbol','module','entry','size','body_sha256','symbol_metadata','entry_instruction')
    typed=[f for f in audit.get('functions',[]) if f.get('handler_id') in (448,449)]
    require(len(typed)==3 and {tuple(f.get('names',[])) for f in typed}=={(n,) for n in expected},
            'graphics typed binding domain differs')
    for name,handler in expected.items():
        f=next(f for f in typed if f['names']==[name])
        declared=domain.get('boot' if name==BOOT else 'public' if name==PUBLIC else 'check',{})
        require(f.get('handler_id')==handler and f.get('returns_value') is False and f.get('return_register') is None and
                all(f.get(k)==declared.get(k) for k in keys) and isinstance(f.get('body_sha256'),str) and
                re.fullmatch('[0-9a-f]{64}',f['body_sha256']),'graphics source body or void ABI differs')
        entry=f['entry'];word=f.get('entry_word');instruction=f.get('entry_instruction',{})
        require(f.get('module')=='sdk' and instruction.get('address')==entry and instruction.get('word')==word,
                'graphics source entry differs')
        site=dict(address=entry,word=word,module='sdk',source_sha256=module_identities(current_bundle)['sdk'][1],
                  word_sha256=instruction.get('sha256'))
        validate_site(site,current_bundle,entry,word);sources[entry]=(handler,site)
    boot=domain['boot'];entry=boot['entry'];word=boot['entry_instruction']['word']
    require(not any(f.get('entry')==entry for f in baseline_bundle.get('native_audit',{}).get('functions',[])),
            'historical boot entry was already a native replacement')
    old_digest=hashlib.sha256();old_step=None;old_prefix=None;old_native=0
    for line,row in trace_rows(old_trace):
        if row['event']==3:old_native+=1
        old_digest.update(line)
        if int(row['pc'],16)==entry:
            require(row['event']==0 and row['error']==0 and row['service']==0 and row['word']==word and
                    int(row['next_pc'],16)==entry+4 and row['retired']>0,
                    'historical boot was not entered by its original STEP')
            old_step=row;old_prefix=old_digest.hexdigest();old_step_bytes=line;break
    require(old_step is not None,'historical full trace has no original boot entry')
    g=execution.get('application_graphics',{})
    require(g.get('ready') is True and all(type(g.get(k)) is int and 0<=g[k]<1<<64 for k in ('calls','boots','checks')) and
            g['boots']>0 and g['calls']==g['boots']+g['checks'],'graphics backend readiness/counters differ')
    digest=hashlib.sha256();crossing=None;continuation=None;native=boots=checks=0;need_continuation=False
    for line,row in trace_rows(trace):
        if need_continuation:
            require(row['event']==0 and row['pc']==crossing['next_pc'] and row['error']==0 and row['service']==0 and
                    row['retired']==old_step['retired'],'graphics did not resume the original caller')
            continuation=row;need_continuation=False
        if row['event']==3:
            native+=1
            if row['service'] in (448,449):
                source=sources.get(int(row['pc'],16));target=int(row['next_pc'],16)
                require(source is not None and row['service']==source[0] and row['word']==source[1]['word'] and
                        row['error']==0 and 4<=target<1<<39 and target%4==0 and target!=int(row['pc'],16),
                        'graphics native event/source/return differs')
                if row['service']==448:boots+=1
                else:checks+=1
                if crossing is None:
                    require(row['service']==448 and int(row['pc'],16)==entry and
                            row['retired']==old_step['retired']-1 and native==old_native+1,
                            'graphics boot crossing moved or retired an original instruction')
                    restored=digest.copy();restored.update(old_step_bytes)
                    require(restored.hexdigest()==old_prefix,'original prefix before graphics boot changed')
                    crossing=row;need_continuation=True
        digest.update(line)
    require(crossing is not None and continuation is not None and not need_continuation and
            boots==g['boots'] and checks==g['checks'] and native==execution['native_calls'] and
            digest.hexdigest()==execution['trace_sha256'],'graphics crossing/full counters/digest differ')
    return dict(format='oot-application-graphics-progress',crossing=crossing,continuation=continuation,
        original_entry_step=old_step,original_entry_prefix_sha256=old_prefix,
        historical_trace_sha256=baseline_execution['trace_sha256'],trace_sha256=digest.hexdigest(),
        boot_events=boots,check_events=checks,runtime_authority_granted=False)
