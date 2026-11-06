"""Static policy-6 dependency frontiers and bounded original-byte target probes."""

from bisect import bisect_right
from collections import ChainMap, Counter, defaultdict
import hashlib
import heapq

from arm64_analysis import NONLOCAL, plt_stubs
from input_formats import require
from leaf_verifier import verify_leaf
from pauth_lifter import MODEL
from profile_survey import Syntax, metadata_windows, discover, check_profile, rejection, proof_summary

POLICY = 'lr-pair-read-stack-dag-v6'


def audit_callees(modules, sample_limit=16, max_words=256, progress=None):
    require(type(sample_limit) is int and 0 <= sample_limit <= 4096, 'audit samples must be 0-4096')
    require(type(max_words) is int and 1 <= max_words <= 256, 'audit word limit must be 1-256')
    require(modules and len({m.name for m in modules}) == len(modules), 'invalid audit modules')
    spans=sorted((m.base,m.base+len(m.image)) for m in modules)
    require(all(a[1] <= b[0] for a,b in zip(spans,spans[1:])), 'audit module ranges overlap')
    syntax, regions, catalog, module_rows, offsets = Syntax(), {}, {}, [], {}
    stubs, sized_symbols = {}, {}
    for m in modules:
        rows = list(metadata_windows(m, max_words))
        require(len(rows) <= 2000000, 'excessive audit metadata entries')
        offsets[m.name] = [r[0] for r in rows]
        sized_symbols[m.name] = [(s.value, s.value+s.size) for s in m.symbols
            if 0 < s.section < 0xff00 and s.kind == 2 and s.size and m.is_code(s.value)]
        stubs.update({m.base+off: item for off,item in plt_stubs(m).items()})
        blocked = Counter()
        for i,(off,end,sources,limits) in enumerate(rows):
            r,failure = discover(m,off,end,sources,syntax,True)
            catalog[m.base+off] = {'module':m.name,'offset':off,'end_offset':end,
                'metadata_sources':sources,'limiting_evidence':limits,'failure':failure}
            if r is None: blocked[failure['reason']] += 1
            else: regions[r.entry] = r
            if progress and (i % 10000 == 0 or i+1 == len(rows)): progress(m.name,'discovery',i+1,len(rows))
        module_rows.append({'name':m.name,'base':m.base,'source_sha256':m.source_sha256,
            'linked_text_sha256':hashlib.sha256(m.image[m.ranges[0][0]:m.ranges[0][1]]).hexdigest(),
            'metadata_entry_candidates':len(rows),'complete_regions':len(rows)-sum(blocked.values()),
            'discovery_blocked':sum(blocked.values()),'discovery_reasons':dict(sorted(blocked.items()))})
    leaves = {}
    for entry,r in regions.items():
        try: verify_leaf(r.data,entry)
        except ValueError: pass
        else: leaves[entry] = r.data
    outcomes, rejected, details = {}, Counter(), Counter()
    for i,(entry,r) in enumerate(regions.items()):
        try:
            p,_,_ = check_profile('lr_calls',r,regions,leaves)
            outcomes[entry] = {'status':'accepted','verification':proof_summary(p)}
        except ValueError as error:
            category,detail = rejection(error)
            outcomes[entry] = {'status':'rejected','reason':category,'detail':detail}
            rejected[category] += 1; details[detail] += 1
        if progress and (i % 10000 == 0 or i+1 == len(regions)): progress('all','policy6',i+1,len(regions))
    for row in module_rows:
        entries=[e for e,r in regions.items() if r.module.name==row['name']]
        row['policy6']={'accepted_regions':sum(outcomes[e]['status']=='accepted' for e in entries),
            'accepted_instruction_words':sum(outcomes[e]['verification']['instruction_count'] for e in entries if outcomes[e]['status']=='accepted'),
            'rejected':dict(sorted(Counter(outcomes[e]['reason'] for e in entries if outcomes[e]['status']=='rejected').items()))}

    def owner(target):
        return next((m for m in modules if m.base <= target < m.base+len(m.image)),None)

    def classify(target, include_plt=True):
        m = owner(target)
        row = {'address':target}
        if m:
            row.update(module=m.name,offset=target-m.base)
        if target % 4: row['kind'] = 'unaligned_target'
        elif include_plt and target in stubs:
            stub = stubs[target]; resolved = int(stub['resolved_address'],16)
            row.update(kind='plt_stub',plt_snapshot={'symbol':stub['symbol'],'got_offset':stub['got_offset'],
                'nonlocal_return_symbol':stub['symbol'] in NONLOCAL,'resolved_address':resolved,
                'resolved_target':classify(resolved,False),'runtime_target_set_proven':False})
        elif target in leaves: row['kind'] = 'verified_register_leaf'
        elif target in regions:
            row.update(kind='discovered_metadata_region',policy6=outcomes[target])
        elif target in catalog:
            row.update(kind='discovery_blocked_metadata_entry',metadata=catalog[target])
        elif m and m.is_code(target-m.base):
            row['kind'] = 'unseeded_text_target'
        elif m:
            off=target-m.base
            mapped=any(lo <= off < hi for lo,hi in m.ranges) or m.bss_start <= off < m.bss_end
            row['kind'] = 'mapped_nontext_target' if mapped else 'unmapped_module_gap'
        else: row['kind'] = 'unmapped_target'
        return row

    # Count each declared caller-region/target edge once, not BL instruction sites.
    callers=defaultdict(set)
    for entry,r in regions.items():
        for target in r.calls: callers[target].add(entry)
    edge_kinds=Counter();target_kinds=Counter()
    for target,entries in sorted(callers.items()):
        kind=classify(target)['kind'];target_kinds[kind]+=1;edge_kinds[kind]+=len(entries)

    blocked_roots=[];root_refs=defaultdict(set);frontier_callers=defaultdict(set)
    for entry,outcome in outcomes.items():
        if outcome.get('reason') != 'call_dependency': continue
        pending,seen,missing=[entry],set(),set()
        while pending:
            current=pending.pop()
            if current in seen: continue
            seen.add(current)
            require(len(seen) <= 32,'audit dependency closure exceeds production registry limit')
            for target in regions[current].calls:
                if target in leaves: continue
                if target in regions:
                    if target not in seen: pending.append(target)
                else:
                    missing.add(target);frontier_callers[target].add(current)
        require(missing,'production dependency failure has no unregistered frontier')
        for target in missing: root_refs[target].add(entry)
        blocked_roots.append({'entry':entry,'module':regions[entry].module.name,'offset':regions[entry].offset,
            'closure_frames':len(seen),'missing_targets':sorted(missing)})

    region_spans,region_starts,symbol_ends={},{},{}
    for m in modules:
        rows=sorted((r.offset,r.offset+len(r.data)) for r in regions.values() if r.module is m)
        region_spans[m.name],region_starts[m.name]=rows,[r[0] for r in rows]
        intervals=iter(sorted(sized_symbols[m.name]));upcoming=next(intervals,None);ends=[]
        for target in sorted(t for t in root_refs if m.base <= t < m.base+len(m.image)):
            off=target-m.base
            while upcoming is not None and upcoming[0] <= off:
                heapq.heappush(ends,upcoming[1]);upcoming=next(intervals,None)
            while ends and ends[0] <= off: heapq.heappop(ends)
            if ends: symbol_ends[target]=ends[0]

    def probe(target):
        m=owner(target)
        if not m or not m.is_code(target-m.base): return None
        off=target-m.base;index=bisect_right(offsets[m.name],off)
        limits={'text_end':m.ranges[0][1],'word_limit':off+max_words*4}
        if index < len(offsets[m.name]): limits['next_metadata_entry']=offsets[m.name][index]
        if target in symbol_ends: limits['enclosing_symbol_end']=symbol_ends[target]
        end=min(limits.values())
        r,failure=discover(m,off,end,['direct_call_diagnostic'],syntax,True)
        prior=bisect_right(region_starts[m.name],off)-1
        overlap=prior >= 0 and region_spans[m.name][prior][0] < off < region_spans[m.name][prior][1]
        result={'diagnostic_only':True,'admitted_to_registry':False,'window_bytes':end-off,
            'limiting_evidence':sorted(k for k,v in limits.items() if v==end),
            'overlaps_discovered_span':overlap}
        if failure:
            result.update(status='discovery_blocked',failure=failure)
        else:
            result.update(byte_count=len(r.data),source_sha256=hashlib.sha256(r.data).hexdigest())
            try: p=verify_leaf(r.data,target)
            except ValueError:
                try: p,_,_=check_profile('lr_calls',r,ChainMap({target:r},regions),leaves)
                except ValueError as error:
                    category,detail=rejection(error);result.update(status='policy_rejected',reason=category,detail=detail)
                else: result.update(status='policy6_candidate',verification=proof_summary(p))
            else: result.update(status='register_leaf_candidate',verification=proof_summary(p))
        return result

    targets=[];frontier_kinds=Counter();probe_status=Counter();discovery_reasons=Counter();unsupported=Counter()
    unsupported_categories,plt_kinds,plt_policy=Counter(),Counter(),Counter();plt_targets=set()
    for i,target in enumerate(sorted(root_refs)):
        row=classify(target);frontier_kinds[row['kind']]+=1
        row.update(caller_region_count=len(frontier_callers[target]),caller_entries=sorted(frontier_callers[target]),
            blocked_root_references=len(root_refs[target]),blocked_root_entries=sorted(root_refs[target]))
        if row['kind']=='unseeded_text_target':
            row['probe']=probe(target);probe_status[row['probe']['status']]+=1
        if row['kind']=='plt_stub':
            snapshot=row['plt_snapshot'];resolved=snapshot['resolved_target'];plt_targets.add(snapshot['resolved_address'])
            plt_kinds[resolved['kind']]+=1
            if resolved['kind']=='discovered_metadata_region':plt_policy[resolved['policy6'].get('reason','accepted')]+=1
        failure=row.get('metadata',{}).get('failure') or row.get('probe',{}).get('failure')
        if failure:
            discovery_reasons[failure['reason']]+=1
            if 'mnemonic' in failure:
                unsupported[failure['mnemonic']]+=1;unsupported_categories[failure['category']]+=1
        targets.append(row)
        if progress and (i % 1000 == 0 or i+1 == len(root_refs)): progress('all','frontier',i+1,len(root_refs))
    ranked=sorted(targets,key=lambda r:(-r['blocked_root_references'],-r['caller_region_count'],r['address']))
    accepted=[r for r in outcomes.values() if r['status']=='accepted']
    return {'schema_version':1,'format':'arm64-callee-dependency-audit','policy':POLICY,'pauth_model':MODEL,
        'guest_code_executed':False,'translation_performed':False,'native_callbacks_registered':False,
        'function_identity_proven':False,'runtime_read_ranges_supplied':False,'decoder':syntax.metadata,
        'method':{'seeds':['module_entry','unwind_table','defined_function_symbol'],'max_words':max_words,
            'root_proofs':'unchanged production policy6 and actual verified callee closures',
            'edge_unit':'distinct declared caller-region/target pairs; not instruction-site or runtime frequency',
            'frontier_scope':'all unregistered targets in closures whose production first failure is call_dependency',
            'probes':'original bytes bounded by next metadata entry, enclosing symbol end, text end and word limit; diagnostic only',
            'probe_dependencies':'existing discovered regions and verified leaves only; probes never satisfy other dependencies',
            'plt_resolution':'recognized relocation-backed stub and linked GOT snapshot; never a runtime target-set or ABI proof',
            'ranking':'distinct blocked-root references overlap and are not predicted acceptance gains'},
        'modules':module_rows,'totals':{'metadata_entry_candidates':len(catalog),'complete_regions':len(regions),
            'discovery_blocked':len(catalog)-len(regions),'accepted_regions':len(accepted),
            'accepted_instruction_words':sum(r['verification']['instruction_count'] for r in accepted),
            'rejected':dict(sorted(rejected.items())),'rejection_details':dict(details.most_common()),
            'direct_call_edges':sum(len(v) for v in callers.values()),'unique_direct_targets':len(callers),
            'direct_edge_kinds':dict(sorted(edge_kinds.items())),'direct_target_kinds':dict(sorted(target_kinds.items())),
            'dependency_blocked_roots':len(blocked_roots),'unique_frontier_targets':len(targets),
            'frontier_edge_count':sum(len(v) for v in frontier_callers.values()),'frontier_target_kinds':dict(sorted(frontier_kinds.items())),
            'unseeded_probe_status':dict(sorted(probe_status.items())),
            'frontier_discovery_reasons':dict(discovery_reasons.most_common()),
            'frontier_first_unsupported_mnemonics':dict(unsupported.most_common()),
            'frontier_first_unsupported_categories':dict(unsupported_categories.most_common()),
            'plt_snapshot_target_kinds':dict(sorted(plt_kinds.items())),
            'plt_unique_snapshot_targets':len(plt_targets),'plt_discovered_target_policy6':dict(sorted(plt_policy.items()))},
        'blocked_roots':sorted(blocked_roots,key=lambda r:r['entry']),'targets':targets,
        'ranked_target_samples':ranked[:sample_limit],'ranked_samples_truncated':len(ranked)>sample_limit}


def compare_baseline(report, baseline):
    require(isinstance(baseline,dict) and baseline.get('schema_version')==1 and
        baseline.get('format')=='arm64-function-profile-survey' and isinstance(baseline.get('policies'),dict) and
        baseline['policies'].get('lr_calls')==POLICY,'baseline must contain the policy-6 survey')
    require(isinstance(baseline.get('method'),dict) and baseline['method'].get('max_words')==report['method']['max_words'],
        'baseline discovery limits differ')
    require(baseline.get('pauth_model')==MODEL and baseline.get('decoder')==report['decoder'],
        'baseline model or decoder differs')
    modules=baseline.get('modules')
    require(isinstance(modules,list) and all(isinstance(m,dict) and isinstance(m.get('name'),str) for m in modules),
        'invalid baseline modules')
    rows={m['name']:m for m in modules}
    require(len(rows)==len(modules)==len(report['modules']),'baseline module set differs')
    for m in report['modules']:
        b=rows.get(m['name'],{})
        require(all(b.get(k)==m[k] for k in ('base','source_sha256','linked_text_sha256','metadata_entry_candidates')),
            'baseline module identity differs')
        require(isinstance(b.get('profiles'),dict) and isinstance(b['profiles'].get('lr_calls'),dict) and
            all(b['profiles']['lr_calls'].get(k)==v for k,v in m['policy6'].items()),'baseline module policy outcomes differ')
    total=baseline.get('totals')
    require(isinstance(total,dict) and isinstance(total.get('profiles'),dict) and isinstance(total['profiles'].get('lr_calls'),dict),
        'invalid baseline totals')
    profile=total['profiles']['lr_calls']
    require(all(total.get(k)==report['totals'][k] for k in ('metadata_entry_candidates','complete_regions','discovery_blocked')) and
        all(profile.get(k)==report['totals'][k] for k in ('accepted_regions','accepted_instruction_words','rejected')),
        'baseline discovery or production policy outcomes differ')
    report['baseline_comparison']={'module_hashes_match':True,'discovery_counts_match':True,'policy_outcomes_match':True}
