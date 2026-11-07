"""Prepare a private, explicitly RAW NSO startup prefix and trusted native C."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
from types import SimpleNamespace

from arm64_lifter import body, constant
from arm64_analysis import plt_stubs
from input_formats import require
from link_exefs import build_destination
from module_linker import Linker
from pauth_lifter import WORDS, decode_pauth_instruction, MODEL
from prepare_runtime import pack_regions, STACK_BASE, STACK_SIZE
from startup_audit import audit_entry, audit_startup

CONTEXT = dict(tls_base=0x7100000000, tls_size=0x1000,
               heap_base=0x6000000000, heap_capacity=0x4000000,
               main_thread_handle=0x8000, tick_frequency=0)


def owner(modules, pc):
    matches = [m for m in modules if m.is_code(pc-m.base)]
    require(len(matches) == 1, 'startup instruction is not in exactly one original text region')
    return matches[0]


def selection(linker, max_instructions=8192, extra_entries=(), sdk=False):
    require(not linker.started and not linker.applied, 'startup requires fresh raw, unrelocated images')
    audit = audit_entry(linker, max_instructions, extra_entries, sdk=sdk)
    nodes = {n['address']: dict(n) for n in audit['entry_graph']['nodes']}
    limit = 65536 if sdk else 16384
    require(nodes and len(nodes) <= limit, 'invalid startup selection size')
    # A declared boundary is a real original word, never a fabricated instruction.
    for n in list(nodes.values()):
        if n.get('semantic_supported') or 'service_immediate' in n:
            pc = n['address'] + 4
            try:
                m = owner(linker.modules, pc)
            except ValueError:
                if n.get('form') not in ('branch_immediate','branch_condition','compare_branch','test_branch','branch_register','retaa','retab'):
                    n['semantic_supported'] = False
                    n['selection_stop'] = 'fallthrough leaves original executable text'
                continue
            if pc not in nodes:
                nodes[pc] = dict(address=pc, word=int.from_bytes(m.read(pc-m.base,4),'little'),
                                 semantic_supported=False, selection_stop='unselected continuation')
    require(len(nodes) <= limit, 'startup selection including stops exceeds limit')
    return audit, [nodes[p] for p in sorted(nodes)]


def emit_startup(linker, nodes, package_manifest, config=None, relocation_probes=(), sdk_config=None, sdk_goal=None):
    cfg = dict(CONTEXT if config is None else config)
    require(set(cfg) == set(CONTEXT) and all(type(x) is int and 0 <= x < 1 << 64 for x in cfg.values()),
            'startup context requires explicit unsigned integer fields')
    instructions, rows = [], []
    for n in nodes:
        pc, word = n['address'], n['word']
        m = owner(linker.modules, pc)
        require(word == int.from_bytes(m.read(pc-m.base,4),'little'), 'startup node differs from original bytes')
        kind, a, b = 4, pc, pc
        if 'selection_stop' not in n and word & 0xffe0001f == 0xd4000001:
            kind, a, b = 3, pc+4, pc+4
        elif n.get('semantic_supported'):
            if sdk_config is not None:
                from sdk_instructions import decode_sdk_instruction
                i = decode_sdk_instruction(word,pc)
            else:
                i = decode_pauth_instruction(word,pc)
            kind, a, b = 0, pc+4, pc+4
            if i.form in ('sdk_system','sdk_atomic'): kind = 5
            else: instructions.append(i)
            if i.form == 'branch_immediate': kind,a,b = 1,i.target,i.target
            elif i.form in ('branch_condition','compare_branch','test_branch'): kind,a,b = 1,i.target,pc+4
            elif i.form in ('branch_register','retaa','retab'): kind,a,b = 2,0,0
        rows.append((pc,word,kind,a,b))
    require(rows and len(rows) <= (65536 if sdk_config is not None else 16384) and len({r[0] for r in rows}) == len(rows), 'invalid startup rows')
    lines = ['/* Private original-byte startup selection. Not a whole-game translation. */',
             '#include "startup_dispatch.h"', '#include "startup_cli.h"',
             '#if OOT_STARTUP_DISPATCH_VERSION != 1 || OOT_LIFT_ABI_VERSION != 2 || OOT_PAUTH_ABI_VERSION != 1',
             '#error Regenerate the startup selection', '#endif']
    callbacks={}
    # Small native functions keep compiler optimization bounded even when a
    # startup selection contains thousands of disjoint instruction addresses.
    for start in range(0,len(instructions),64):
        name=f'oot_pauth_lift_startup_{start//64}'
        lines += [f'static int {name}(OotArm64State *s, OotGuestMemory *memory,',
            '    const OotPauth *pauth, uint64_t budget, uint64_t *executed)', '{',
            '    uint64_t count = 0;', '    if (!s || !executed || oot_pauth_model(pauth) != OOT_PAUTH_QARMA5_VA39) return OOT_PAUTH_LIFT_CONFIGURATION;',
            '    *executed = 0;', '    oot_memory_clear_fault(memory);', '    for (;;) {', '        switch (s->pc) {']
        for i in instructions[start:start+64]:
            callbacks[i.pc]=name
            lines += [f'        case {constant(i.pc)}: {{ /* {i.form} */',
                      '            if (count == budget) { *executed = count; return OOT_LIFT_BUDGET; }']
            if i.word in WORDS:
                lines += [f'            if (oot_pauth_step(pauth,s,UINT32_C(0x{i.word:08x})) == OOT_PAUTH_REJECTED)',
                          '                { *executed = count; return OOT_PAUTH_LIFT_CONFIGURATION; }']
            else:
                lines += ['            '+line for line in body(i)]
            lines += ['            ++count;', '            break;', '        }']
        lines += ['        default: *executed = count; return OOT_LIFT_DISPATCH;', '        }', '    }', '}']
    lines += ['static const OotStartupInstruction oot_startup_words[] = {']
    for pc,word,kind,a,b in rows:
        lines.append(f'    {{{constant(pc)}, UINT32_C(0x{word:08x}), {kind}, {constant(a)}, {constant(b)}, '+
                     ('NULL' if kind >= 3 else callbacks[pc])+'},')
    lines += ['};', 'static const OotStartupSpan oot_startup_spans[] = {']
    spans = []
    for pc,*_ in rows:
        if spans and spans[-1][0]+spans[-1][1] == pc and spans[-1][1] < 65536:
            spans[-1][1] += 4
        else: spans.append([pc,4])
    require(len(spans) <= (1024 if sdk_config is not None else 256), 'startup selection has too many disjoint text spans')
    for pc,size in spans:
        m=owner(linker.modules,pc)
        digest=hashlib.sha256(m.read(pc-m.base,size)).digest()
        lines.append(f'    {{{constant(pc)}, {size}, {{'+','.join(f'0x{x:02x}' for x in digest)+'}},')
    digest=bytes.fromhex(package_manifest['body_sha256'])
    lines += ['};', 'static const OotStartupProgram oot_startup_program = {',
              '    OOT_STARTUP_DISPATCH_VERSION, '+('OOT_STARTUP_RAW_IMAGE | OOT_STARTUP_SDK_RUNTIME' if sdk_config is not None else 'OOT_STARTUP_RAW_IMAGE')+', '+constant(linker.modules[0].base)+',',
              '    {'+','.join(f'0x{x:02x}' for x in digest)+'},',
              f'    oot_startup_words, {len(rows)}, oot_startup_spans, {len(spans)}', '};',
              'OOT_LIFT_EXPORT const OotStartupProgram *oot_startup_compiled_program(void) { return &oot_startup_program; }',
              'static const OotStartupConfig oot_startup_config = {'+', '.join(constant(cfg[k]) for k in CONTEXT)+'};',
              'OOT_LIFT_EXPORT const OotStartupConfig *oot_startup_compiled_config(void) { return &oot_startup_config; }', '']
    if sdk_config is not None:
        fields=('core_mask','priority_mask','aslr_base','aslr_size','alias_base','alias_size','program_id','is_application','total_memory',
                'main_thread_id','main_thread_priority','main_thread_core')
        require(set(sdk_config)==set(fields) and all(type(sdk_config[k]) is int and 0 <= sdk_config[k] < 1<<64 for k in fields), 'invalid SDK model fields')
        # Real entropy is supplied privately at execution, never compiled into C.
        lines += ['static const OotSdkConfig oot_sdk_config = { OOT_SDK_CONTEXT_VERSION, OOT_SDK_PROCESS_INFO | OOT_SDK_NO_REMOTE_ARENA | OOT_SDK_MAIN_THREAD | OOT_SDK_NO_ALIAS_EXTRA | OOT_SDK_PAGE_ALLOCATION | OOT_SDK_OBSERVED_MAIN_TLR, {0,0,0,0}, '+', '.join(constant(sdk_config[k]) for k in fields)+' };',
                  'const OotSdkConfig *oot_startup_compiled_sdk_config(void) { return &oot_sdk_config; }']
    else:
        lines += ['const OotSdkConfig *oot_startup_compiled_sdk_config(void) { return NULL; }']
    if sdk_goal is not None:
        require(sdk_config is not None, 'SDK goal requires SDK configuration')
        stages=sdk_goal['mandatory_stage_entries']; goal=sdk_goal['goal_entry']
        lines += ['static const uint64_t oot_sdk_stages[] = {'+', '.join(constant(pc) for pc in stages)+'};',
                  'static const OotSdkGoal oot_sdk_goal = { OOT_STARTUP_SDK_GOAL_VERSION, '+str(len(stages))+', '+constant(goal['thunk_entry'])+', '+constant(goal['entry'])+', UINT32_C(0x'+format(goal['thunk_word'],'08x')+'), oot_sdk_stages };',
                  'const OotSdkGoal *oot_startup_compiled_sdk_goal(void) { return &oot_sdk_goal; }']
    else:
        lines += ['const OotSdkGoal *oot_startup_compiled_sdk_goal(void) { return NULL; }']
    if relocation_probes:
        lines += ['static const OotStartupProbe oot_startup_probes[] = {']
        lines += [f'    {{{constant(a)}, {constant(v)}}},' for a,v in relocation_probes]
        lines += ['};',f'OOT_LIFT_EXPORT const OotStartupProbe *oot_startup_compiled_probes(size_t *count) {{ *count={len(relocation_probes)}; return oot_startup_probes; }}']
    else:
        lines += ['OOT_LIFT_EXPORT const OotStartupProbe *oot_startup_compiled_probes(size_t *count) { *count=0; return NULL; }']
    return '\n'.join(lines), dict(instruction_count=len(rows),translated_instructions=len(instructions),
        span_count=len(spans),context=cfg,pauth_model=MODEL,process_abi='experimental-nso-x0-zero-x1-handle',
        switch2_startup_abi_proven=False,heap_tls_sdk_layout_proven=False,
        image_phase='raw-before-rtld-relocation',function_identity_proven=False,
        initializers_automatically_invoked=False, sdk_runtime=sdk_config is not None,
        sdk_model=sdk_config, sdk_remote_arena='absent' if sdk_config is not None else None,
        sdk_goal_bound=sdk_goal is not None)


def relative_probes(raw, linked):
    """Independent offline expected values for the entry module's RELR/RELATIVE slots."""
    m,expected=raw.modules[0],linked.modules[0]
    offsets=set();cursor=None
    for (word,) in struct.iter_unpack('<Q',m.relr):
        if not word & 1:
            offsets.add(word);cursor=word+8
        else:
            require(cursor is not None,'invalid startup RELR bitmap')
            offsets.update(cursor+bit*8 for bit in range(63) if word & (1<<(bit+1)))
            cursor+=63*8
    for _,table in m.rela:
        for offset,info,_ in struct.iter_unpack('<QQq',table):
            if info & 0xffffffff == 1027:offsets.add(offset)
    require(len(offsets)<=65536,'too many startup relative probes')
    return [(m.base+o,expected.unpack('<Q',o,memory=True)[0]) for o in sorted(offsets)]


def startup_page_regions(modules):
    """Explicit NSO process model: zero-padded 4 KiB pages, including RW BSS."""
    result=[]
    for m in modules:
        require(all(a%4096==0 for a,_ in m.ranges),'startup NSO segments must start on 4 KiB pages')
        text,rodata,data=m.ranges
        rounded=[(text[0],(text[1]+4095)&~4095),(rodata[0],(rodata[1]+4095)&~4095),
                 (data[0],(m.bss_end+4095)&~4095)]
        require(all(a<=b for a,b in rounded) and all(x[1]<=y[0] for x,y in zip(rounded,rounded[1:])),
                'startup page rounding overlaps segments')
        require(rounded[-1][1]<=len(m.image),'startup page rounding exceeds verified zero backing')
        result.append(SimpleNamespace(name=m.name,base=m.base,image=m.image,ranges=rounded,
            bss_start=rounded[-1][1],bss_end=rounded[-1][1]))
    return result


def prepare_bundle(linker, output, max_instructions=8192, extra_entries=(), config=None, stack_size=STACK_SIZE, shared_package=None, sdk_metadata=None):
    output=build_destination(Path(output))
    require(not output.exists(), 'choose a fresh startup bundle directory')
    sdk = sdk_metadata is not None
    entry,nodes=selection(linker,max_instructions,extra_entries,sdk=sdk)
    # Audit relocation and initializer targets on an independent copy. The bytes
    # packaged for the original loader are deliberately not those linked bytes.
    verified=deepcopy(linker)
    require(verified.apply()['link_complete'], 'startup preparation requires a complete independent offline link')
    linked_audit=audit_startup(verified,max_instructions)
    sdk_goal = None
    if sdk:
        from sdk_startup_audit import audit_sdk_startup
        require(sdk_metadata.get('declarations_complete') is True, 'SDK requires explicit NPDM process declarations')
        sdk_goal=audit_sdk_startup(verified)
        identity=sdk_goal['observed_process_model']['thread_identity']
        require(identity.get('available') is True and identity['tls_offset']==0x110 and identity['field_width']==4 and
                0<CONTEXT['main_thread_handle']<=identity['supported_logical_handle_max'],
                'SDK requires an original-byte proof for its observed main-thread TLS identity model')
    # Preselect bounded potential callees of exact relocation-backed PLT stubs.
    # The snapshot selects original code for compilation, never a live target:
    # the original LDR/BR still runs, and native dispatch checks its actual PC.
    linked_targets={m.base+off+12:int(p['resolved_address'],16)
        for m in verified.modules for off,p in plt_stubs(m).items()}
    lookahead=[];merged={n['address']:n for n in nodes}
    for _ in range(8):
        targets=sorted({linked_targets[pc] for pc in merged if pc in linked_targets and linked_targets[pc] not in merged})
        targets=[pc for pc in targets if any(m.is_code(pc-m.base) for m in linker.modules)]
        if not targets or len(extra_entries)+len(lookahead)+len(targets)>(1024 if sdk else 256):break
        proposed=lookahead+targets
        _,more=selection(linker,max_instructions,tuple(extra_entries)+tuple(proposed),sdk=sdk)
        updated=dict(merged)
        for n in more:
            if n['address'] not in updated or ('selection_stop' in updated[n['address']] and 'selection_stop' not in n):
                updated[n['address']]=n
        if len(updated)>(65536 if sdk else 16384):break
        # Bound fragmentation before accepting a larger compiled selection.
        pcs=sorted(updated);spans=1+sum(b!=a+4 for a,b in zip(pcs,pcs[1:]))
        if spans>(1024 if sdk else 256):break
        merged=updated;lookahead=proposed
    if sdk_goal:
        # Bind goal markers even before discovery reaches them. These rows stop
        # if reached without all earlier stages; they never skip original code.
        for pc in sdk_goal['mandatory_stage_entries']+[sdk_goal['goal_entry']['thunk_entry'],sdk_goal['goal_entry']['entry']]:
            if pc not in merged:
                m=owner(linker.modules,pc)
                merged[pc]=dict(address=pc,word=m.unpack('<I',pc-m.base)[0],semantic_supported=False,selection_stop='unselected SDK goal marker')
        thunk=merged[sdk_goal['goal_entry']['thunk_entry']]
        thunk.pop('selection_stop',None)
        thunk['semantic_supported']=True
    nodes=[merged[p] for p in sorted(merged)]
    package,manifest=pack_regions(startup_page_regions(linker.modules),verified.report(),STACK_BASE,stack_size)
    manifest.update(format='oot-raw-startup-memory',schema_version=1,
        image_phase='raw-before-rtld-relocation',offline_link_applied_to_package=False,
        offline_link_audit_on_independent_copy=True,page_size=4096,
        segment_padding_zero=True,writable_data_and_bss_share_pages=True)
    probes=relative_probes(linker,verified)
    sdk_config=None
    if sdk:
        config=dict(CONTEXT,heap_capacity=0x40000000)
        sdk_config={k:int(sdk_metadata[k]) for k in ('core_mask','priority_mask','program_id','is_application')}
        sdk_config.update(aslr_base=0,aslr_size=1<<39,alias_base=0x5000000000,alias_size=0x80000000,
            total_memory=manifest['backing_bytes']+config['tls_size']+config['heap_capacity'],
            main_thread_id=1,main_thread_priority=sdk_metadata['main_thread_priority'],main_thread_core=sdk_metadata['main_thread_core'])
    source,summary=emit_startup(linker,nodes,manifest,config,probes,sdk_config,sdk_goal)
    summary['relative_relocation_probes']=len(probes)
    summary['linked_plt_lookahead_targets']=len(lookahead)
    output.mkdir(parents=True)
    if shared_package is not None:
        shared_package=build_destination(Path(shared_package))
        require(shared_package.read_bytes()==package,'shared raw package differs from fresh verified input')
        try:os.link(shared_package,output/'startup.ootmem')
        except OSError:(output/'startup.ootmem').write_bytes(package)
    else:(output/'startup.ootmem').write_bytes(package)
    (output/'startup.c').write_text(source,encoding='utf-8')
    report=dict(schema_version=1,format='oot-startup-bundle',guest_code_executed=False,
        game_translation_performed=True,native_callbacks_registered=False,
        source_sha256=hashlib.sha256(source.encode()).hexdigest(),selection=summary,
        package=manifest,entry_audit=entry,initializer_audit=linked_audit,sdk_audit=sdk_goal,sdk_npdm=sdk_metadata,
        static_plt_lookahead=dict(entries=lookahead,live_targets_proven=False,
            scope='diagnostic linked-snapshot code selection; original stub instructions and runtime target checks remain active'),
        selection_boundaries=[dict(address=n['address'],word=n['word'],reason=n['selection_stop']) for n in nodes if 'selection_stop' in n])
    (output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return report
