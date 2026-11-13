"""Read-only application cohort counts and private source-bound trace proofs.

Site records select no code and grant no runtime permission. The runtime runner
must verify a full trace against its native all-row digest before using a proof.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from input_formats import InputError,require
from link_exefs import build_destination
from sdk_init_instructions import decode_sdk_init_instruction,sdk_init_vector_kind,sdk_init_atomic_kind

FAMILIES=('simd_integer_fp','simd_orr','simd_dup_element','simd_ins_element','simd_cmeq','simd_bif')


def summarize_boundaries(manifest):
    counts=dict.fromkeys(FAMILIES,0);atomics={'compare_exchange_narrow':0};supported=unsupported=0
    rows=manifest.get('application_word_boundaries',[])
    for row in rows:
        word,pc=row['word'],row['address']
        family=sdk_init_vector_kind(word,application=True)
        if family in counts:counts[family]+=1
        elif sdk_init_atomic_kind(word,True)=='compare_exchange_narrow':atomics['compare_exchange_narrow']+=1
        else:
            try:decode_sdk_init_instruction(word,pc,application=True)
            except InputError:unsupported+=1
            else:supported+=1
    return dict(format='oot-application-frontier',families=counts,atomic_families=atomics,already_supported=supported,
                remaining_unsupported=unsupported,total_records=len(rows),runtime_authority_granted=False)


def module_identities(bundle):
    rows=bundle.get('entry_audit',{}).get('modules',[])
    result={}
    for m in rows:
        require(isinstance(m.get('name'),str) and m['name'] not in result,'missing/duplicate original module')
        require(type(m.get('base')) is int and all(isinstance(m.get(k),str) and
            re.fullmatch('[0-9a-f]{64}',m[k]) for k in ('source_sha256','text_sha256')),'invalid original module identity')
        result[m['name']]=(m['base'],m['source_sha256'],m['text_sha256'])
    require(bool(result),'missing original module identities')
    return result


def validate_site(site,bundle,pc,word):
    require(type(site.get('address')) is int and site['address']==pc and
            type(site.get('word')) is int and site['word']==word and
            site.get('word_sha256')==hashlib.sha256(struct.pack('<I',word)).hexdigest(),
            'frontier word/address/hash differs')
    modules=bundle.get('entry_audit',{}).get('modules',[])
    owners=[m for m in modules if m.get('name')==site.get('module')]
    require(len(owners)==1 and isinstance(site.get('source_sha256'),str) and
            re.fullmatch('[0-9a-f]{64}',site['source_sha256']) and
            owners[0].get('source_sha256')==site['source_sha256'],'frontier original module/source differs')


def trace_rows(path):
    """Bound line sizes, reject malformed/truncated rows, normalize native CRLF."""
    with Path(path).open('rb') as stream:
        while line:=stream.readline(1025):
            require(len(line)<=1024 and line.endswith(b'\n'),'truncated/oversized trace row')
            try:row=json.loads(line)
            except (ValueError,UnicodeError) as error:raise InputError('invalid trace JSON') from error
            require(isinstance(row,dict) and set(row)=={'pc','next_pc','retired','word','event','error','service'},
                    'invalid trace fields')
            require(all(isinstance(row[k],str) and re.fullmatch('0x[0-9a-f]+',row[k]) and
                        int(row[k],16)<1<<64 for k in ('pc','next_pc')) and
                    all(type(row[k]) is int and 0<=row[k]<1<<64 for k in ('retired','word','event','error','service')) and
                    row['word']<=0xffffffff and row['event']<=3,'invalid trace values')
            yield line.replace(b'\r\n',b'\n'),row


def verify_progress_trace(trace,baseline_execution,baseline_bundle,current_bundle):
    require(module_identities(baseline_bundle)==module_identities(current_bundle),
            'original source/text identities changed across progress proof')
    e=baseline_execution
    require(e.get('error')==8 and type(e.get('word')) is int and 0<=e['word']<=0xffffffff and
            type(e.get('retired')) is int and e['retired']>0,'baseline is not an original instruction frontier')
    require(isinstance(e.get('pc'),str) and re.fullmatch('0x[0-9a-f]+',e['pc']), 'invalid baseline PC')
    pc,word=int(e['pc'],16),e['word']
    family=sdk_init_vector_kind(word,True)
    narrow=sdk_init_atomic_kind(word,True)=='compare_exchange_narrow'
    require(family in FAMILIES or narrow,'frontier is outside a supported application cohort')
    field='application_atomic_sites' if narrow else 'application_simd_sites'
    old=[r for r in baseline_bundle.get('application_word_boundaries',[]) if r.get('address')==pc]
    new=[r for key in ('application_simd_sites','application_atomic_sites')
         for r in current_bundle.get(key,[]) if r.get('address')==pc]
    require(len(old)==len(new)==1 and old[0].get('semantic_error'),'missing/duplicate source-bound frontier site')
    require(new[0] in current_bundle.get(field,[]),'frontier site belongs to the wrong instruction domain')
    validate_site(old[0],baseline_bundle,pc,word);validate_site(new[0],current_bundle,pc,word)
    require(all(old[0][k]==new[0][k] for k in ('module','source_sha256','word_sha256')),'frontier source site changed')
    crossing=None;digest=hashlib.sha256()
    for line,row in trace_rows(trace):
        digest.update(line)
        if (row['retired']==e['retired']+1 and row['pc']==e['pc'] and row['word']==word and
            row['event']==row['error']==row['service']==0 and int(row['next_pc'],16)==pc+4):
            require(crossing is None,'duplicate frontier crossing');crossing=row
    require(crossing is not None,'original frontier did not retire at the expected checkpoint')
    return dict(format='oot-application-progress',crossing=crossing,trace_sha256=digest.hexdigest(),
                source_site=new[0],runtime_authority_granted=False)


def verify_full_trace(path,execution):
    """CLI guard: compact storage cannot stand in for native full-row evidence."""
    digest=hashlib.sha256();count=steps=0;last=None
    for line,row in trace_rows(path):
        require(last is None,'trace contains records after stop')
        digest.update(line);count+=1
        if row['event']==2:last=row
        else:steps+=1
    require(last is not None and digest.hexdigest()==execution.get('trace_sha256') and
            count==execution.get('trace_rows')==steps+1 and steps==execution.get('trace_steps') and
            steps==execution.get('retired',-1)+execution.get('native_calls',0) and
            last['retired']==execution.get('retired'),'full trace digest/accounting differs from native report')


def verify_resource_progress_trace(trace,baseline_execution,baseline_bundle,current_bundle,execution,expected_owner):
    """Read-only native resource proof; caller first verifies native full trace.

    Replacing the old STOP row in the prefix hash proves every preceding row
    is unchanged, without loading the historical multi-megabyte full trace.
    A native call consumes work but retires no original instruction.
    """
    require(module_identities(baseline_bundle)==module_identities(current_bundle),'resource original modules changed')
    e=baseline_execution;app='_ZN2nn6applet23GetAppletResourceUserIdEv';am='_ZN2nn2am23GetAppletResourceUserIdEv'
    require(e.get('error')==9 and e.get('native_handler_stop') is True and e.get('service')==31 and
        type(e.get('retired')) is int and e['retired']>0 and type(e.get('native_calls')) is int and e['native_calls']>=0 and
        isinstance(e.get('pc'),str) and re.fullmatch('0x[0-9a-f]+',e['pc']) and
        isinstance(e.get('trace_sha256'),str) and re.fullmatch('[0-9a-f]{64}',e['trace_sha256']),
        'baseline is not a native resource guard frontier')
    pc=int(e['pc'],16)
    old=[f for f in baseline_bundle.get('native_audit',{}).get('functions',[]) if f.get('entry')==pc]
    audit=current_bundle.get('native_audit',{});getters=[f for f in audit.get('functions',[]) if f.get('handler_id')==322]
    require(len(old)==1 and old[0].get('handler_id')==31 and old[0].get('names')==[app] and
        len(getters)==2 and {tuple(f.get('names',[])) for f in getters}=={(app,),(am,)},'resource getter binding domain differs')
    public=next(f for f in getters if f['names']==[app]);domain=audit.get('application_resource_identity',{})
    keys=('symbol','module','entry','size','body_sha256','symbol_metadata','entry_instruction')
    require(all(old[0].get(k)==public.get(k) for k in keys) and public['entry']==pc and
        domain.get('return_bytes')==8 and domain.get('exported_am_consumer_closure') is True,
        'resource source body or ownership domain changed')
    sources={}
    for f in getters:
        named=domain.get('public' if f['names']==[app] else 'getter',{})
        require(f.get('module')=='sdk' and f.get('returns_value') is True and f.get('return_register')=='X0' and
            all(f.get(k)==named.get(k) for k in keys) and
            isinstance(f.get('body_sha256'),str) and re.fullmatch('[0-9a-f]{64}',f['body_sha256']),
            'resource accessor lacks its source-proved full-width ABI')
        word=f.get('entry_word');entry=f['entry'];instruction=f.get('entry_instruction',{})
        require(instruction.get('address')==entry and instruction.get('word')==word and
            type(word) is int and 0<=word<=0xffffffff,'resource accessor entry word differs')
        source=dict(address=entry,word=word,module='sdk',source_sha256=module_identities(current_bundle)['sdk'][1],
                    word_sha256=instruction.get('sha256'))
        validate_site(source,current_bundle,entry,word);sources[entry]=source
    require(public['entry_word']==e.get('word') and old[0].get('entry_word')==e.get('word'),
            'resource former guard word changed')
    resource=execution.get('application_resource',{})
    require(type(expected_owner) is int and 0<expected_owner<1<<64 and
        type(execution.get('native_calls')) is int and execution['native_calls']>=0 and
        type(resource.get('logical_process_id')) is int and resource['logical_process_id']==expected_owner and
        type(resource.get('active')) is int and resource['active']==1 and
        type(resource.get('queries')) is int and 0<resource['queries']<1<<64,'resource owner/counter report differs')
    stop=dict(pc=e['pc'],next_pc=e['pc'],retired=e['retired'],word=e['word'],event=2,error=9,service=31)
    stop_bytes=json.dumps(stop,separators=(',',':')).encode()+b'\n'
    digest=hashlib.sha256();crossing=None;native=queries=0
    for line,row in trace_rows(trace):
        if row['event']==3:native+=1
        if row['event']==3 and row['service']==322:
            source=sources.get(int(row['pc'],16));target=int(row['next_pc'],16)
            require(source is not None and row['word']==source['word'] and row['error']==0 and
                row['retired']>=e['retired'] and 4<=target<1<<39 and target%4==0 and target!=int(row['pc'],16),
                'resource event word/source/return/checkpoint differs')
            queries+=1
            if row['pc']==e['pc'] and row['retired']==e['retired']:
                require(crossing is None and native==e['native_calls']+1,'duplicate or displaced native resource crossing')
                prefix=digest.copy();prefix.update(stop_bytes)
                require(prefix.hexdigest()==e['trace_sha256'],'original trace prefix before the resource guard changed')
                crossing=row
        digest.update(line)
    require(crossing is not None and queries==resource['queries'] and native==execution.get('native_calls') and
        digest.hexdigest()==execution.get('trace_sha256'),'resource crossing/counters/full digest differ')
    return dict(format='oot-application-resource-progress',crossing=crossing,source_site=sources[pc],
        original_prefix_sha256=e['trace_sha256'],trace_sha256=digest.hexdigest(),resource_events=queries,
        logical_process_id=expected_owner,runtime_authority_granted=False)


def private_json(path):
    path=build_destination(Path(path))
    require(path.is_file() and path.stat().st_size<=128*1024*1024,'invalid private report input')
    return json.loads(path.read_text(encoding='utf-8'))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='mode',required=True)
    survey=commands.add_parser('survey');survey.add_argument('--manifest',type=Path,required=True)
    progress=commands.add_parser('progress')
    progress.add_argument('--resource-owner',type=int,help='explicit native resource proof for the declared logical owner')
    for name in ('baseline','run','trace'):progress.add_argument('--'+name,type=Path,required=True)
    for command in (survey,progress):command.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        output=build_destination(args.output);require(not output.exists(),'choose a fresh private output file')
        if args.mode=='survey':report=summarize_boundaries(private_json(args.manifest))
        else:
            old=private_json(args.baseline)['iterations'][-1];new=private_json(args.run)['iterations'][-1]
            trace=build_destination(args.trace);verify_full_trace(trace,new['execution'])
            old_bundle=private_json(Path(old['bundle'])/'manifest.json');new_bundle=private_json(Path(new['bundle'])/'manifest.json')
            if args.resource_owner is not None:
                report=verify_resource_progress_trace(trace,old['execution'],old_bundle,new_bundle,new['execution'],args.resource_owner)
            else:report=verify_progress_trace(trace,old['execution'],old_bundle,new_bundle)
            require(report['trace_sha256']==new['execution']['trace_sha256'],'trace changed during progress verification')
        output.parent.mkdir(parents=True,exist_ok=True)
        with output.open('x',encoding='utf-8') as stream:stream.write(json.dumps(report,indent=2)+'\n')
    except (OSError,ValueError,KeyError,TypeError) as error:parser.exit(1,f'{error}\n')


if __name__=='__main__':main()
