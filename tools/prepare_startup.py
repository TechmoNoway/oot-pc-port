"""Prepare a private, explicitly RAW NSO startup prefix and trusted native C."""
from copy import copy, deepcopy
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
from startup_audit import (MAX_INIT_ENTRIES, MAX_INIT_INSTRUCTIONS, MAX_INSTRUCTIONS,
                           audit_entry, audit_startup)

CONTEXT = dict(tls_base=0x7100000000, tls_size=0x1000,
               heap_base=0x6000000000, heap_capacity=0x4000000,
               main_thread_handle=0x8000, tick_frequency=0)


def owner(modules, pc):
    matches = [m for m in modules if m.is_code(pc-m.base)]
    require(len(matches) == 1, 'startup instruction is not in exactly one original text region')
    return matches[0]


def application_source_site(modules,node):
    m=owner(modules,node['address'])
    if m.name=='hostboot' or node.get('native_boundary'):return None
    word=node['word']
    require(word==m.unpack('<I',node['address']-m.base)[0],'application site differs from original word')
    return dict(address=node['address'],word=word,module=m.name,source_sha256=m.source_sha256,
                word_sha256=hashlib.sha256(struct.pack('<I',word)).hexdigest())


def application_atomic_sites(modules,nodes):
    from sdk_init_instructions import sdk_init_atomic_kind
    records=[]
    for n in nodes:
        if sdk_init_atomic_kind(n['word'],True)!='compare_exchange_narrow':continue
        record=application_source_site(modules,n)
        if record is not None:records.append(record)
    return records


def application_sites(modules,nodes):
    """Private original-word records, never selection or execution authority."""
    from application_frontier import FAMILIES
    from sdk_init_instructions import sdk_init_vector_kind
    simd=[];services=[]
    for n in nodes:
        record=application_source_site(modules,n)
        if record is None:continue
        word=n['word']
        is_simd=sdk_init_vector_kind(word,application=True) in FAMILIES
        is_svc=word&0xffe0001f==0xd4000001
        if not is_simd and not is_svc:continue
        if is_simd:simd.append(record)
        if is_svc:services.append(dict(record,service=word>>5&65535))
    return simd,services


def selection(linker, max_instructions=8192, extra_entries=(), sdk=False, native_entries=(), sdk_init=False,decode_cache=None,application=False):
    require(not linker.started and not linker.applied, 'startup requires fresh raw, unrelocated images')
    if sdk_init:
        require(type(max_instructions) is int and 1<=max_instructions<=MAX_INIT_INSTRUCTIONS,
                'SDK initialization selection exceeds its finite row limit')
    graph_limit=min(max_instructions,MAX_INIT_INSTRUCTIONS-16384) if sdk_init else max_instructions
    audit = audit_entry(linker, graph_limit, extra_entries, sdk=sdk,native_entries=native_entries,sdk_init=sdk_init,decode_cache=decode_cache,application=application)
    nodes = {n['address']: dict(n) for n in audit['entry_graph']['nodes']}
    limit = MAX_INIT_INSTRUCTIONS if sdk_init else 65536 if sdk else 16384
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


def emit_startup(linker, nodes, package_manifest, config=None, relocation_probes=(), sdk_config=None, sdk_goal=None, native_functions=(), original_oe_entry=0, sdk_init=False, units=None, entry_override=None, host_linked=False, host_constructors=(), application=False,graphics=False,display=False):
    require(type(display) is bool and (not display or graphics),'display emission requires the separate graphics profile')
    require(type(graphics) is bool and (not graphics or application),'graphics emission requires the separate application profile')
    require(type(application) is bool and (not application or (host_linked and sdk_init and sdk_goal is not None)),
            'application emission requires host-linked initialization and its original goal')
    require(type(sdk_init) is bool and (not sdk_init or (native_functions and sdk_config is not None)),'SDK initialization requires native providers')
    require(not native_functions or sdk_config is not None,'native functions require SDK model')
    require(type(original_oe_entry) is int and (not original_oe_entry or native_functions) and
        (not original_oe_entry or any(n['address']==original_oe_entry for n in nodes)),
        'original OE observation requires selected native-profile code')
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
                if sdk_init:
                    from sdk_init_instructions import decode_sdk_init_instruction
                    i = decode_sdk_init_instruction(word,pc,application=application)
                else:i = decode_sdk_instruction(word,pc)
            else:
                i = decode_pauth_instruction(word,pc)
            kind, a, b = 0, pc+4, pc+4
            if i.form in ('sdk_system','sdk_atomic','sdk_barrier','sdk_pointer','sdk_init_atomic'): kind = 5
            elif i.form=='sdk_init_vector':kind=6
            else: instructions.append(i)
            if i.form == 'branch_immediate': kind,a,b = 1,i.target,i.target
            elif i.form in ('branch_condition','compare_branch','test_branch'): kind,a,b = 1,i.target,pc+4
            elif i.form in ('branch_register','retaa','retab'): kind,a,b = 2,0,0
        rows.append((pc,word,kind,a,b))
    require(rows and len(rows) <= (MAX_INIT_INSTRUCTIONS if sdk_init else 65536 if sdk_config is not None else 16384) and len({r[0] for r in rows}) == len(rows), 'invalid startup rows')
    lines = ['/* Private original-byte startup selection. Not a whole-game translation. */',
             '#include "startup_dispatch.h"', '#include "startup_cli.h"',
             '#if OOT_STARTUP_DISPATCH_VERSION != 1 || OOT_LIFT_ABI_VERSION != 2 || OOT_PAUTH_ABI_VERSION != 1',
             '#error Regenerate the startup selection', '#endif']
    callbacks={}
    # Small native functions keep compiler optimization bounded even when a
    # startup selection contains thousands of disjoint instruction addresses.
    groups={}
    if units is None:
        groups={n:instructions[n:n+64] for n in range(0,len(instructions),64)}
    else:
        require(isinstance(units,dict) and not units,'source units must be an empty owned mapping')
        for i in instructions:groups.setdefault(i.pc>>8,[]).append(i)
    metadata=lines
    for group, members in groups.items():
        name=f'oot_pauth_lift_startup_{group//64}' if units is None else f'oot_pauth_lift_pc_{group:x}'
        if units is not None:
            metadata += [f'extern int {name}(OotArm64State *, OotGuestMemory *, const OotPauth *, uint64_t, uint64_t *);']
            lines=[]
        lines += [f'{"static " if units is None else ""}int {name}(OotArm64State *s, OotGuestMemory *memory,',
            '    const OotPauth *pauth, uint64_t budget, uint64_t *executed)', '{',
            '    uint64_t count = 0;', '    if (!s || !executed || oot_pauth_model(pauth) != OOT_PAUTH_QARMA5_VA39) return OOT_PAUTH_LIFT_CONFIGURATION;',
            '    *executed = 0;', '    oot_memory_clear_fault(memory);', '    for (;;) {', '        switch (s->pc) {']
        for i in members:
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
        if units is not None:
            chunk=f'lift_{members[0].pc>>16:x}.c'
            units[chunk]=units.get(chunk,'#include "pauth.h"\n')+'\n'.join(lines)+'\n'
            lines=metadata
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
    require(len(spans) <= (8192 if sdk_init else 1024 if sdk_config is not None else 256), 'startup selection has too many disjoint text spans')
    for pc,size in spans:
        m=owner(linker.modules,pc)
        digest=hashlib.sha256(m.read(pc-m.base,size)).digest()
        lines.append(f'    {{{constant(pc)}, {size}, {{'+','.join(f'0x{x:02x}' for x in digest)+'}},')
    digest=bytes.fromhex(package_manifest['body_sha256'])
    lines += ['};', 'static const OotStartupProgram oot_startup_program = {',
              '    OOT_STARTUP_DISPATCH_VERSION, '+('OOT_STARTUP_DISPLAY | ' if display else '')+('OOT_STARTUP_GRAPHICS | ' if graphics else '')+('OOT_STARTUP_APPLICATION | ' if application else '')+('OOT_STARTUP_HOST_LINKED | OOT_STARTUP_SDK_RUNTIME | OOT_STARTUP_NATIVE_RUNTIME | OOT_STARTUP_INIT_RUNTIME' if host_linked else 'OOT_STARTUP_RAW_IMAGE | OOT_STARTUP_SDK_RUNTIME | OOT_STARTUP_NATIVE_RUNTIME | OOT_STARTUP_INIT_RUNTIME' if sdk_init else 'OOT_STARTUP_RAW_IMAGE | OOT_STARTUP_SDK_RUNTIME | OOT_STARTUP_NATIVE_RUNTIME' if native_functions else 'OOT_STARTUP_RAW_IMAGE | OOT_STARTUP_SDK_RUNTIME' if sdk_config is not None else 'OOT_STARTUP_RAW_IMAGE')+', '+constant(entry_override if entry_override is not None else linker.modules[0].base)+',',
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
        flags='OOT_SDK_PROCESS_INFO | OOT_SDK_NO_REMOTE_ARENA | OOT_SDK_MAIN_THREAD | OOT_SDK_NO_ALIAS_EXTRA | OOT_SDK_PAGE_ALLOCATION | OOT_SDK_OBSERVED_MAIN_TLR'
        if native_functions:flags+=' | OOT_SDK_NATIVE_FUNCTIONS'
        if sdk_init:flags+=' | OOT_SDK_INITIALIZATION'
        if application:flags+=' | OOT_SDK_APPLICATION'
        if graphics:flags+=' | OOT_SDK_GRAPHICS'
        if display:flags+=' | OOT_SDK_DISPLAY'
        lines += ['static const OotSdkConfig oot_sdk_config = { OOT_SDK_CONTEXT_VERSION, '+flags+', {0,0,0,0}, '+', '.join(constant(sdk_config[k]) for k in fields)+' };',
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
    if native_functions:
        lines += ['static const OotNativeFunction oot_native_functions[] = {']
        for f in native_functions:
            digest=bytes.fromhex(f['body_sha256'])
            lines += ['    {OOT_NATIVE_FUNCTION_VERSION, '+str(f['handler_id'])+', '+constant(f['entry'])+', '+str(f['size'])+', {'+','.join(f'0x{x:02x}' for x in digest)+'}},']
        lines += ['};',f'const OotNativeFunction *oot_startup_compiled_native_functions(size_t *count) {{ *count={len(native_functions)}; return oot_native_functions; }}']
    else:
        lines += ['const OotNativeFunction *oot_startup_compiled_native_functions(size_t *count) { *count=0; return NULL; }']
    lines += ['uint64_t oot_startup_compiled_original_oe_entry(void) { return '+constant(original_oe_entry)+'; }']
    if relocation_probes:
        lines += ['static const OotStartupProbe oot_startup_probes[] = {']
        lines += [f'    {{{constant(a)}, {constant(v)}}},' for a,v in relocation_probes]
        lines += ['};',f'OOT_LIFT_EXPORT const OotStartupProbe *oot_startup_compiled_probes(size_t *count) {{ *count={len(relocation_probes)}; return oot_startup_probes; }}']
    else:
        lines += ['OOT_LIFT_EXPORT const OotStartupProbe *oot_startup_compiled_probes(size_t *count) { *count=0; return NULL; }']
    if host_constructors:
        lines+=['static const OotStartupConstructor oot_host_constructors[]={']
        for c in host_constructors:
            lines+=['{'+','.join(constant(c[k]) for k in ('entry','body_entry','return_pc'))+','+str(c['size'])+', {'+','.join('0x'+c['body_sha256'][i:i+2] for i in range(0,64,2))+'}},']
        lines+=['};',f'const OotStartupConstructor *oot_startup_compiled_constructors(size_t *n){{*n={len(host_constructors)};return oot_host_constructors;}}']
    else:lines+=['const OotStartupConstructor *oot_startup_compiled_constructors(size_t *n){*n=0;return NULL;}']
    if sdk_init and units is not None:
        from startup_fast import emit_fast
        fast_lines,fast_count=emit_fast(linker,rows,units,sdk_goal,native_functions)
        lines+=fast_lines
    else:
        lines+=['const OotStartupFastFunction *oot_startup_compiled_fast_functions(size_t *n){*n=0;return NULL;}']
    return '\n'.join(lines), dict(instruction_count=len(rows),translated_instructions=len(instructions),
        span_count=len(spans),context=cfg,pauth_model=MODEL,process_abi='experimental-nso-x0-zero-x1-handle',
        switch2_startup_abi_proven=False,heap_tls_sdk_layout_proven=False,
        image_phase='raw-before-rtld-relocation',function_identity_proven=False,
        initializers_automatically_invoked=False, sdk_runtime=sdk_config is not None,
        sdk_model=sdk_config, sdk_remote_arena='absent' if sdk_config is not None else None,
        sdk_goal_bound=sdk_goal is not None,native_functions=len(native_functions))


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


def sdk_init_constructor_entries(raw, linked, audit):
    """Select potential original constructors from one fresh linked snapshot.

    This grants no runtime targets and invokes no callbacks. The packaged image
    remains raw; its original DT_INIT loops and checked slot trampolines execute
    normally, including deferred constructor passes and current target checks.
    """
    require(not raw.started and not raw.applied and linked.report().get('link_complete') is True,
            'constructor selection requires fresh raw images and a complete independent link')
    originals = {module.name: module for module in raw.modules}
    modules = {module.name: module for module in linked.modules}
    require(len(originals) == len(raw.modules) and set(originals) == set(modules) and
            len(modules) == len(linked.modules), 'constructor selection has ambiguous module identities')
    records = audit.get('modules', [])
    require(len(records) == len(modules) and len({record['name'] for record in records}) == len(modules),
            'constructor audit does not describe exactly the original module set')
    entries = set()
    slots = 0
    dynamic_count = 0
    for record in records:
        name = record['name']
        require(name in modules, 'constructor audit names an unknown module')
        module, original = modules[name], originals[name]
        begin, end = original.ranges[0]
        digest = hashlib.sha256(original.read(begin, end - begin)).hexdigest()
        require((module.base, module.source_sha256, module.ranges[0]) ==
                (original.base, original.source_sha256, original.ranges[0]) and
                record['base'] == original.base and record['source_sha256'] == original.source_sha256 and
                original.header['segments'][0].get('hash_verified') is True and
                digest == original.header['segments'][0]['sha256'] == record['linked_text_sha256'] and
                module.read(begin, end - begin) == original.read(begin, end - begin),
                'constructor snapshot differs from verified original text/source identity')
        initializer = record['dynamic_functions']['init']
        expected_init = module.base + module.dynamic[12] if module.dynamic.get(12) else None
        require((initializer['address'] if initializer is not None else None) == expected_init,
                'constructor DT_INIT metadata differs from its original dynamic table')
        if expected_init is not None:
            require(owner(raw.modules, expected_init).name == name,
                    'constructor DT_INIT is outside its original module text')
            entries.add(expected_init)
            dynamic_count += 1
        array = record['arrays']['init']
        present = 25 in module.dynamic or 27 in module.dynamic
        require((array is not None) == present, 'constructor array metadata differs from original presence')
        if array is None:
            continue
        require(25 in module.dynamic and 27 in module.dynamic and
                array['offset'] == module.dynamic[25] and module.dynamic[27] % 8 == 0 and
                array['count'] == module.dynamic[27] // 8 == len(array['slots']),
                'constructor array metadata differs from its original dynamic bounds')
        data = module.read(array['offset'], module.dynamic[27])
        require(hashlib.sha256(data).hexdigest() == array['sha256'],
                'constructor array snapshot checksum differs from its audited linked bytes')
        for index, slot in enumerate(array['slots']):
            value = struct.unpack_from('<Q', data, index * 8)[0]
            require(slot['index'] == index and slot['value'] == value,
                    'constructor slot differs from its audited linked pointer')
            if value in (0, (1 << 64) - 1):
                require(slot['kind'] == ('null' if value == 0 else 'sentinel'),
                        'constructor null/sentinel classification differs from original bytes')
                continue
            target_owner = owner(raw.modules, value)
            require(slot['kind'] == 'code' and slot['module'] == target_owner.name and
                    slot['offset'] == value - target_owner.base,
                    'constructor target is not its exact original mapped text')
            entries.add(value)
            slots += 1
    entries = sorted(entries)
    require(len(entries) <= MAX_INIT_ENTRIES and raw.modules[0].base not in entries,
            'constructor selection exceeds its finite root limit or aliases the process entry')
    return entries, dict(entries=entries, code_slots=slots, unique_potential_targets=len(entries),
        dt_init_functions=dynamic_count, original_text_verified=True,
        guest_code_executed=False, constructor_execution_proven=False,
        live_targets_proven=False, runtime_authority_granted=False,
        scope='linked-snapshot selection only; original callbacks, array loops and target checks remain')


def compact_sdk_init_nodes(entry):
    """Retain an exact ordered row fingerprint after complete source emission."""
    graph=entry['entry_graph']
    binding=hashlib.sha256()
    for node in sorted(graph['nodes'],key=lambda row:row['address']):
        binding.update(struct.pack('<QI',node['address'],node['word']))
    graph['node_binding']=dict(count=len(graph['nodes']),sha256=binding.hexdigest(),
        encoding='ascending-address little-endian uint64 address, uint32 original word',
        complete_rows_retained_in='startup.c',report_nodes_compacted=True)
    graph['nodes']=[]


def sdk_init_vtable_entries(raw, linked, observed_entries=(), *, module_name="sdk", object_prefix="_ZTVNSt3__1"):
    """Select exact relocation-backed SDK libc++ vtable code-pointer slots.

    Original NSO data may become RELRO only after its original protection path.
    These snapshot hints neither seal that memory nor approve live callbacks.
    """
    from sdk_startup_audit import _symbol_record
    require((module_name=='sdk' and object_prefix=='_ZTVNSt3__1') or (module_name=='main' and object_prefix is None),
            'application main selection permits observed neighborhoods only')
    prefix=object_prefix
    require(not raw.started and not raw.applied and linked.report().get('link_complete') is True,
            'vtable selection requires fresh raw images and a complete independent link')
    sources=[module for module in raw.modules if module.name==module_name]
    snapshots=[module for module in linked.modules if module.name==module_name]
    require(len(sources)==len(snapshots)==1,'vtable selection requires exactly one original SDK module')
    source,module=sources[0],snapshots[0]
    require((source.base,source.source_sha256,source.ranges)==(module.base,module.source_sha256,module.ranges) and
            len(source.symbols)==len(module.symbols),'vtable linked snapshot has a different original SDK identity')
    expected_count=(source.unpack('<II',source.dynamic[4])[1] if 4 in source.dynamic else
                    source.dynamic[39]//24 if 39 in source.dynamic else source.gnu_symbol_count())
    require(expected_count==len(source.symbols),'vtable parsed symbols differ from the original bounded table')
    for index,(begin,end) in enumerate(source.ranges):
        segment=source.header['segments'][index]
        require(segment.get('hash_verified') is True and
                hashlib.sha256(source.read(begin,end-begin)).hexdigest()==segment['sha256'],
                'vtable selection requires unchanged verified original SDK segments')
    begin,end=source.ranges[0]
    require(source.read(begin,end-begin)==module.read(begin,end-begin),
            'vtable snapshot changes original SDK text')
    expected_rela=[]
    for pointer,size_tag,label in ((7,8,'rela'),(23,2,'plt')):
        if pointer in source.dynamic:
            expected_rela.append((label,source.read(source.dynamic[pointer],source.dynamic[size_tag])))
    require(source.rela==expected_rela and source.relr==(
            source.read(source.dynamic[36],source.dynamic[35]) if 36 in source.dynamic else b''),
            'vtable parsed relocation recipes differ from original source bytes')
    relocations={};cursor=None
    for (word,) in struct.iter_unpack('<Q',source.relr):
        if not word&1:offsets=(word,);cursor=word+8
        else:
            require(cursor is not None,'vtable RELR bitmap has no original cursor')
            offsets=tuple(cursor+bit*8 for bit in range(63) if word&(1<<(bit+1)))
            cursor+=63*8
        for offset in offsets:
            require(offset not in relocations,'vtable pointer has duplicate original relocations')
            relocations[offset]=dict(kind='RELR')
    for _,table in source.rela:
        for offset,info,addend in struct.iter_unpack('<QQq',table):
            kind,index=info&0xffffffff,info>>32
            if kind not in (257,1025,1026,1027):continue
            require(offset not in relocations,'vtable pointer has overlapping original relocations')
            relocations[offset]=dict(kind=kind,symbol_index=index,addend=addend)
    strings=source.read(source.dynamic[5],source.dynamic[10])
    resolver=copy(raw);resolve_source=copy(source)
    resolve_source.weak_zero=source.weak_zero.copy();resolve_source.unresolved=source.unresolved.copy()
    entries=set();objects=[];slots=[];unrelocated=0
    for index,symbol in enumerate(source.symbols):
        record=source.read(source.dynamic[6]+index*24,24)
        name_offset=struct.unpack_from('<I',record)[0]
        require(name_offset<len(strings),'vtable original symbol name exceeds its string table')
        stop=strings.find(b'\0',name_offset)
        require(stop>=0,'vtable original symbol name is unterminated')
        original_name=strings[name_offset:stop].decode('utf-8')
        if prefix is None or not (original_name.startswith(prefix) or symbol.name.startswith(prefix)):continue
        metadata=_symbol_record(source,index,symbol)
        require(module.symbols[index]==symbol,'vtable linked symbol metadata differs from original bytes')
        if not symbol.section:continue
        require(symbol.kind==1 and symbol.binding in (1,2) and symbol.visibility in (0,3) and
                symbol.value%8==0 and 16<=symbol.size<=65536 and symbol.size%8==0,
                'SDK libc++ vtable is not an exact aligned exported object extent')
        origins=[number for number in (1,2) if source.ranges[number][0]<=symbol.value and
                 symbol.value+symbol.size<=source.ranges[number][1]]
        require(len(origins)==1,'SDK libc++ vtable is outside original read-only/data file bytes')
        original=source.read(symbol.value,symbol.size);snapshot=module.read(symbol.value,symbol.size)
        objects.append(dict(symbol=symbol.name,entry=source.base+symbol.value,size=symbol.size,
            symbol_metadata=metadata,original_sha256=hashlib.sha256(original).hexdigest(),
            linked_sha256=hashlib.sha256(snapshot).hexdigest(),
            original_segment='rodata' if origins[0]==1 else 'data-potential-relro',
            runtime_read_only_proven=False))
        for at in range(0,symbol.size,8):
            offset=symbol.value+at;value=struct.unpack_from('<Q',snapshot,at)[0]
            if offset not in relocations:
                require(snapshot[at:at+8]==original[at:at+8],
                        'vtable unrelocated slot differs from unchanged original bytes')
                if source.is_code(value-source.base):unrelocated+=1
                continue
            require(offset%8==0 and offset//4 in module.touched and offset//4+1 in module.touched,
                    'vtable code pointer lacks its complete applied eight-byte relocation')
            relocation=relocations[offset]
            if relocation['kind']=='RELR':expected=struct.unpack_from('<Q',original,at)[0]+source.base
            elif relocation['kind']==1027:expected=source.base+relocation['addend']
            else:
                symbol_index=relocation['symbol_index']
                _symbol_record(source,symbol_index,source.symbols[symbol_index])
                resolved,_=resolver.resolve(resolve_source,symbol_index)
                require(resolved is not None,'vtable pointer source symbol is unresolved')
                expected=resolved+relocation['addend']
            require(value==expected&((1<<64)-1),
                    'vtable linked pointer differs from its original relocation recipe')
            if not source.is_code(value-source.base):continue
            entries.add(value)
            slots.append(dict(symbol=symbol.name,slot=source.base+offset,target=value,
                relocation=relocations[offset],
                original_pointer_sha256=hashlib.sha256(original[at:at+8]).hexdigest(),
                linked_pointer_sha256=hashlib.sha256(snapshot[at:at+8]).hexdigest()))
    # Bounded code-pointer neighborhoods around explicitly observed targets.
    # They select possible text only; they do not assert an anonymous vtable extent.
    neighbors=[]
    if observed_entries:
        from bisect import bisect_left
        observed_entries=set(observed_entries)
        expected_slots={}
        for offset,recipe in relocations.items():
            if not any(a<=offset and offset+8<=b for a,b in source.ranges[1:]):continue
            if recipe['kind']=='RELR':expected=source.unpack('<Q',offset)[0]+source.base
            elif recipe['kind']==1027:expected=source.base+recipe['addend']
            else:
                index=recipe['symbol_index'];_symbol_record(source,index,source.symbols[index])
                resolved,_=resolver.resolve(resolve_source,index)
                if resolved is None:continue
                expected=resolved+recipe['addend']
            expected&=(1<<64)-1
            if source.is_code(expected-source.base):expected_slots[offset]=expected
        anchors=sorted(off for off,value in expected_slots.items() if value in observed_entries)
        for offset,expected in expected_slots.items():
            near=bisect_left(anchors,offset-128)
            if near==len(anchors) or anchors[near]>offset+128:continue
            require(offset%8==0 and offset//4 in module.touched and offset//4+1 in module.touched,
                    'observed callback neighbor lacks its complete applied relocation')
            require(module.unpack('<Q',offset)[0]==expected,'observed callback neighbor differs from original relocation recipe')
            entries.add(expected);neighbors.append(dict(slot=source.base+offset,target=expected,recipe=relocations[offset]))
    require(len(entries)<=MAX_INIT_ENTRIES,'SDK libc++ vtable targets exceed the finite root limit')
    entries=sorted(entries)
    return entries,dict(entries=entries,objects=objects,slots=slots,
        unique_potential_targets=len(entries),unrelocated_code_values_ignored=unrelocated,observed_neighbors=neighbors,
        namespace=(module_name+' bounded observed code-pointer neighborhoods') if module_name!='sdk' else ('SDK libc++ objects and bounded observed code-pointer neighborhoods' if observed_entries else 'SDK defined libc++ std::__1 vtable objects only'),
        guest_code_executed=False,live_targets_proven=False,runtime_authority_granted=False,
        scope='exact original object and relocation-backed linked pointer selection; original loads and indirect checks remain')


def extend_application_selection(linker,merged,application_entry,application_entries,native_entries,linked_targets,decode_cache):
    # Do not let application discovery redistribute the already-verified
    # initialization selection or its bounded PLT lookahead.
    require(isinstance(application_entries,(tuple,list)) and len(application_entries)<=1024,
            'application diagnostic root limit exceeded')
    app_roots=tuple(dict.fromkeys((application_entry,*application_entries)))
    room=min(65536,MAX_INIT_INSTRUCTIONS-len(merged)-512)
    require(room>=4096,'initialization leaves no bounded application selection room')
    app_lookahead=[];app_nodes={}
    for _ in range(8):
        app_audit,more=selection(linker,room,app_roots+tuple(app_lookahead),sdk=True,
            native_entries=native_entries,sdk_init=True,decode_cache=decode_cache,application=True)
        updated=dict(merged)
        for node in more:
            pc=node['address']
            if pc not in updated or ('selection_stop' in updated[pc] and 'selection_stop' not in node) or (not updated[pc].get('semantic_supported') and not updated[pc].get('native_boundary') and node.get('semantic_supported')):updated[pc]=node
        pcs=sorted(updated)
        if len(updated)>MAX_INIT_INSTRUCTIONS or 1+sum(b!=a+4 for a,b in zip(pcs,pcs[1:]))>8192:break
        merged=updated;app_nodes.update({node['address']:node for node in more})
        targets=sorted({linked_targets[pc] for pc in app_nodes if pc in linked_targets and
            (linked_targets[pc] not in merged or 'selection_stop' in merged[linked_targets[pc]])})
        targets=[pc for pc in targets if pc not in app_roots and pc not in app_lookahead and
            any(m.is_code(pc-m.base) for m in linker.modules)]
        if not targets:break
        app_lookahead+=targets
        if len(app_roots)+len(app_lookahead)>2048:break
    require(application_entry in merged,'application entry selection is absent')
    evidence=dict(roots=list(app_roots),selected_rows=len(app_nodes),row_budget=room,
        static_plt_targets=app_lookahead,original_bytes_only=True,runtime_targets_authorized=False)
    return merged,evidence


def prepare_bundle(linker, output, max_instructions=8192, extra_entries=(), config=None, stack_size=STACK_SIZE, shared_package=None, sdk_metadata=None, native_sdk=False, sdk_init=False, host_linked=False,decode_cache=None,application=False,application_entries=(),graphics=False,display=False):
    require(type(display) is bool and (not display or graphics),'display requires separate graphics mode')
    require(type(graphics) is bool and (not graphics or application),'graphics requires separate application mode')
    output=build_destination(Path(output))
    require(not output.exists(), 'choose a fresh startup bundle directory')
    sdk = sdk_metadata is not None
    require(type(native_sdk) is bool and (not native_sdk or sdk),'native SDK requires verified SDK metadata')
    require(type(sdk_init) is bool and (not sdk_init or native_sdk),'SDK initialization requires native SDK')
    require(type(host_linked) is bool and (not host_linked or sdk_init),'host-linked boot requires SDK initialization')
    require(type(application) is bool and (not application or host_linked),'application execution requires separate host-linked boot')
    require(application or not application_entries,'application roots require explicit application mode')
    if sdk_init and decode_cache is None:
        from startup_audit import StartupDecodeCache
        decode_cache=StartupDecodeCache()
    entry,nodes=selection(linker,max_instructions,extra_entries,sdk=sdk,sdk_init=sdk_init,decode_cache=decode_cache)
    # Audit relocation and initializer targets on an independent copy. The bytes
    # packaged for the original loader are deliberately not those linked bytes.
    verified=deepcopy(linker)
    require(verified.apply()['link_complete'], 'startup preparation requires a complete independent offline link')
    linked_audit=audit_startup(verified,min(max_instructions,MAX_INSTRUCTIONS))
    native_audit=None;native_functions=[];native_entries=();original_oe_entry=0
    constructor_selection=None
    vtable_selection=None
    if sdk_init:
        constructors,constructor_selection=sdk_init_constructor_entries(linker,verified,linked_audit)
        vtables,vtable_selection=sdk_init_vtable_entries(linker,verified,extra_entries)
        extra_entries=tuple(dict.fromkeys((*extra_entries,*constructors,*vtables)))
        require(len(extra_entries)<=MAX_INIT_ENTRIES,'constructor and explicit roots exceed SDK initialization limit')
    if native_sdk:
        if sdk_init:
            if application:
                from application_audit import audit_application
                native_audit=audit_application(verified)
                if graphics:
                    from graphics_audit import extend_graphics_audit
                    native_audit=extend_graphics_audit(verified,native_audit)
                    if display:
                        from display_audit import extend_display_audit
                        native_audit=extend_display_audit(verified,native_audit)
            else:
                from sdk_init_audit import audit_sdk_init
                native_audit=audit_sdk_init(verified)
        else:
            from native_sdk_audit import audit_native_sdk
            native_audit=audit_native_sdk(verified)
        native_functions=native_audit['functions']
        if not sdk_init:
            require(native_audit.get('original_oe_initialize') is not None,'native SDK requires the original OE observation metadata')
            original_oe_entry=native_audit['original_oe_initialize']['entry']
        native_entries=tuple(f['entry'] for f in native_functions)
        entry,nodes=selection(linker,max_instructions,extra_entries,sdk=True,native_entries=native_entries,sdk_init=sdk_init,decode_cache=decode_cache)
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
        if not targets or len(extra_entries)+len(lookahead)+len(targets)>(MAX_INIT_ENTRIES if sdk_init else 1024 if sdk else 256):break
        proposed=lookahead+targets
        _,more=selection(linker,max_instructions,tuple(extra_entries)+tuple(proposed),sdk=sdk,native_entries=native_entries,sdk_init=sdk_init,decode_cache=decode_cache)
        updated=dict(merged)
        for n in more:
            if n['address'] not in updated or ('selection_stop' in updated[n['address']] and 'selection_stop' not in n):
                updated[n['address']]=n
        if len(updated)>(MAX_INIT_INSTRUCTIONS if sdk_init else 65536 if sdk else 16384):break
        # Bound fragmentation before accepting a larger compiled selection.
        pcs=sorted(updated);spans=1+sum(b!=a+4 for a,b in zip(pcs,pcs[1:]))
        if spans>(8192 if sdk_init else 1024 if sdk else 256):break
        merged=updated;lookahead=proposed
    application_selection=None
    application_pointers=None
    if application:
        pointer_entries,application_pointers=sdk_init_vtable_entries(linker,verified,application_entries,module_name='main',object_prefix=None)
        selected_application_entries=tuple(dict.fromkeys((*application_entries,*pointer_entries)))
        merged,application_selection=extend_application_selection(linker,merged,sdk_goal['goal_entry']['entry'],
            selected_application_entries,native_entries,linked_targets,decode_cache)
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
    for f in native_functions:
        pc=f['entry'];m=owner(linker.modules,pc)
        if sdk_init and pc not in merged:continue
        merged[pc]=dict(address=pc,word=m.unpack('<I',pc-m.base)[0],semantic_supported=False,
            native_boundary=True,selection_stop='native SDK function boundary')
    if original_oe_entry and original_oe_entry not in merged:
        m=owner(linker.modules,original_oe_entry)
        merged[original_oe_entry]=dict(address=original_oe_entry,word=m.unpack('<I',original_oe_entry-m.base)[0],
            semantic_supported=False,selection_stop='unselected continuation')
    nodes=[merged[p] for p in sorted(merged)]
    if sdk_init:
        require(set(constructor_selection['entries'])|set(vtable_selection['entries'])<=set(merged),
                'SDK initialization instruction budget omitted original constructor roots')
        constructor_selection['selected_root_rows']=len(constructor_selection['entries'])
        constructor_selection['last_cfg_truncated']=entry['entry_graph']['truncated']
    boot=None;entry_override=None;emitter=linker
    package_modules=linker.modules
    if host_linked:
        from host_boot import make_boot
        module,boot_nodes,boot=make_boot(linker,sdk_goal,linked_audit,CONTEXT['main_thread_handle'])
        nodes=[n for n in nodes if owner(linker.modules,n['address']).name!='rtld']+boot_nodes
        nodes.sort(key=lambda n:n['address']);entry_override=module.base
        emitter=copy(linker);emitter.modules=[*linker.modules,module]
        package_modules=[*verified.modules,module]
    package,manifest=pack_regions(startup_page_regions(package_modules),verified.report(),STACK_BASE,stack_size)
    manifest.update(format='oot-raw-startup-memory',schema_version=1,
        image_phase='raw-before-rtld-relocation',offline_link_applied_to_package=False,
        offline_link_audit_on_independent_copy=True,page_size=4096,
        segment_padding_zero=True,writable_data_and_bss_share_pages=True)
    probes=relative_probes(linker,verified)
    sdk_config=None
    if sdk:
        config=dict(CONTEXT,heap_capacity=0x80000000 if sdk_init else 0x40000000)
        if sdk_init:
            from sdk_init_audit import sdk_init_tick_frequency
            config['tick_frequency']=sdk_init_tick_frequency(verified)
        sdk_config={k:int(sdk_metadata[k]) for k in ('core_mask','priority_mask','program_id','is_application')}
        sdk_config.update(aslr_base=0,aslr_size=1<<39,alias_base=0x5000000000,alias_size=0x80000000,
            total_memory=manifest['backing_bytes']+config['tls_size']+(0x100000000 if sdk_init else config['heap_capacity']),
            main_thread_id=1,main_thread_priority=sdk_metadata['main_thread_priority'],main_thread_core=sdk_metadata['main_thread_core'])
    units={} if sdk_init else None
    source,summary=emit_startup(emitter,nodes,manifest,config,probes,sdk_config,sdk_goal,native_functions,original_oe_entry,sdk_init,units,entry_override,host_linked,boot['module_order'] if boot else (),application,graphics,display)
    summary['sdk_init_providers']=sdk_init
    summary['relative_relocation_probes']=len(probes)
    summary['linked_plt_lookahead_targets']=len(lookahead)
    if sdk_init:summary['potential_constructor_targets']=constructor_selection['unique_potential_targets']
    if sdk_init:summary['potential_vtable_targets']=vtable_selection['unique_potential_targets']
    output.mkdir(parents=True)
    if shared_package is not None:
        shared_package=build_destination(Path(shared_package))
        require(shared_package.read_bytes()==package,'shared raw package differs from fresh verified input')
        try:os.link(shared_package,output/'startup.ootmem')
        except OSError:(output/'startup.ootmem').write_bytes(package)
    else:(output/'startup.ootmem').write_bytes(package)
    (output/'startup.c').write_text(source,encoding='utf-8')
    if units is not None:
        from startup_sources import write_sources
        write_sources(output,dict(units,**{'startup.c':source}))
    if sdk_init:
        # Hundreds of thousands of original rows remain fully bound in the
        # generated source. Retain their ordered address/word fingerprint here
        # without duplicating a large disassembly graph in the runner manifest.
        compact_sdk_init_nodes(entry)
    report=dict(schema_version=1,format='oot-startup-bundle',guest_code_executed=False,
        game_translation_performed=True,native_callbacks_registered=False,
        source_sha256=hashlib.sha256(source.encode()).hexdigest(),selection=summary,
        package=manifest,entry_audit=entry,initializer_audit=linked_audit,sdk_audit=sdk_goal,sdk_npdm=sdk_metadata,native_audit=native_audit,
        static_plt_lookahead=dict(entries=lookahead,live_targets_proven=False,
            scope='diagnostic linked-snapshot code selection; original stub instructions and runtime target checks remain active'),
        selection_boundaries=[dict(address=n['address'],word=n['word'],reason=n['selection_stop']) for n in nodes if 'selection_stop' in n])
    if application:
        report['application_runtime']=True;summary['application_runtime']=True
        if graphics:report['graphics_runtime']=True;summary['graphics_runtime']=True
        if display:report['display_runtime']=True;summary['display_runtime']=True
        report['application_selection']=application_selection
        report['application_pointer_selection']=application_pointers
        report['application_simd_sites'],report['application_svc_sites']=application_sites(emitter.modules,nodes)
        report['application_atomic_sites']=application_atomic_sites(emitter.modules,nodes)
        report['application_word_boundaries']=[dict(address=n['address'],word=n['word'],
            module=owner(linker.modules,n['address']).name,
            source_sha256=owner(linker.modules,n['address']).source_sha256,
            word_sha256=hashlib.sha256(struct.pack('<I',n['word'])).hexdigest(),
            semantic_error=n['semantic_error']) for n in nodes if n.get('semantic_error') and not n.get('native_boundary')]
    if host_linked:
        manifest.update(image_phase='host-offline-linked',offline_link_applied_to_package=True)
        summary.update(image_phase='host-offline-linked',host_linked=True)
        report['host_boot']=boot
    if sdk_init:
        report['static_constructor_selection']=constructor_selection
        report['static_vtable_selection']=vtable_selection
    (output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return report
