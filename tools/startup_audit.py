"""Original-byte startup evidence; this module never translates or executes code."""

from collections import Counter, deque
import hashlib
import struct

from arm64_analysis import plt_stubs
from arm64_decode import (CALL, CONDITIONAL, INDIRECT_CALL, INDIRECT_JUMP, JUMP,
                          RETURN, TRAP, Decoder, direct_target, flow_kind)
from input_formats import InputError, require
from module_linker import MAX_SYMBOLS
from pauth_lifter import decode_pauth_instruction

FORMAT = "oot-startup-audit"
MAX_INSTRUCTIONS = 65536
MAX_INIT_INSTRUCTIONS = 524288
MAX_INIT_ENTRIES = 16384

def _decode_entry_word(syntax,word,pc,sdk,sdk_init):
    decoded=next(iter(syntax.engine.disasm(struct.pack('<I',word),pc)),None)
    mnemonic=decoded.mnemonic if decoded else '.word'
    operands=decoded.op_str if decoded else ''
    form,error=None,None
    try:
        if sdk_init:
            from sdk_init_instructions import decode_sdk_init_instruction
            instruction=decode_sdk_init_instruction(word,pc)
        elif sdk:
            from sdk_instructions import decode_sdk_instruction
            instruction=decode_sdk_instruction(word,pc)
        else:instruction=decode_pauth_instruction(word,pc)
        form=instruction.form
    except InputError as failure:error=str(failure)
    return mnemonic,operands,flow_kind(word,mnemonic),form,error

class StartupDecodeCache:
    """Owned in-memory memo of pure decodes, never serialized authority.

    PC, exact original word and profile are all part of the key. Roots, native
    boundaries, edges, provenance and original-byte reads are rebuilt each time.
    """
    def __init__(self,limit=MAX_INIT_INSTRUCTIONS*2):
        require(type(limit) is int and 1<=limit<=MAX_INIT_INSTRUCTIONS*2,'invalid decode cache capacity')
        self._rows={};self.limit=limit;self.hits=self.misses=0
    def decode(self,syntax,word,pc,sdk,sdk_init):
        key=(word,pc,sdk,sdk_init)
        if key in self._rows:self.hits+=1;return self._rows[key]
        self.misses+=1;row=_decode_entry_word(syntax,word,pc,sdk,sdk_init)
        if len(self._rows)<self.limit:self._rows[key]=row
        return row
REFERENCES = [
    {"url": "https://github.com/Atmosphere-NX/Atmosphere/blob/master/docs/components/modules/loader.md",
     "scope": "Switch loader convention: process entry is the first loaded NSO; not a recovered Switch 2 register ABI"},
    {"url": "https://github.com/switchbrew/libnx/blob/master/nx/source/runtime/init.c",
     "scope": "Homebrew initialization reference only; not a retail constructor order or service ABI"},
]


def _owner(modules, address):
    return next((m for m in modules if m.is_code(address - m.base)), None)


def _target(modules, value):
    if value == 0:
        return {"kind": "null"}
    if value == (1 << 64) - 1:
        return {"kind": "sentinel"}
    owner = _owner(modules, value)
    if owner:
        return {"kind": "code", "module": owner.name, "offset": value - owner.base}
    return {"kind": "non_code"}


def _array(module, modules, pointer_tag, size_tag, label):
    present = pointer_tag in module.dynamic or size_tag in module.dynamic
    if not present:
        return None
    require(pointer_tag in module.dynamic and size_tag in module.dynamic,
            f"{module.name}: incomplete {label} metadata")
    offset, size = module.dynamic[pointer_tag], module.dynamic[size_tag]
    require(size % 8 == 0 and size // 8 <= MAX_SYMBOLS,
            f"{module.name}: invalid {label} array size")
    module.check_range(offset, size)
    data = bytes(module.image[offset:offset + size])
    slots, counts, seen = [], Counter(), Counter()
    for index, (value,) in enumerate(struct.iter_unpack("<Q", data)):
        target = _target(modules, value)
        counts[target["kind"]] += 1
        duplicate = target["kind"] == "code" and seen[value] != 0
        if duplicate:
            counts["duplicate_code_slots"] += 1
        if target["kind"] == "code":
            seen[value] += 1
        slots.append(dict(index=index, value=value, duplicate_code_slot=duplicate,
                          **target))
    return dict(offset=offset, count=len(slots), sha256=hashlib.sha256(data).hexdigest(),
                classification=dict(sorted(counts.items())), unique_code_targets=len(seen),
                slots=slots, slot_order_preserved=True,
                execution_order_proven=False)


def _module(module, modules):
    arrays = {name: _array(module, modules, pointer, size, name)
              for pointer, size, name in ((32, 33, "preinit"), (25, 27, "init"),
                                           (26, 28, "fini"))}
    functions = {}
    for tag, name in ((12, "init"), (13, "fini")):
        offset = module.dynamic.get(tag, 0)
        functions[name] = None if not offset else dict(address=module.base + offset,
                                                       **_target(modules, module.base + offset))
    begin, end = module.ranges[0]
    return dict(name=module.name, base=module.base, build_id=module.header["build_id"],
                source_sha256=module.source_sha256,
                linked_text_sha256=hashlib.sha256(module.image[begin:end]).hexdigest(),
                needed=list(module.needed), soname=module.soname,
                dynamic_functions=functions, arrays=arrays)


def _entry_evidence(module, syntax):
    word = module.unpack("<I", 0)[0]
    instruction = next(iter(syntax.engine.disasm(struct.pack("<I", word), module.base)), None)
    mnemonic = instruction.mnemonic if instruction else ".word"
    kind = flow_kind(word, mnemonic)
    target = direct_target(word, module.base) if kind in (CALL, JUMP, CONDITIONAL) else None
    return dict(module=module.name, address=module.base, offset=0, word=word,
                mnemonic=mnemonic,
                loader_convention="first supplied module, text offset zero",
                original_header_branch=(kind == JUMP and module.is_code(target - module.base)
                                        and target >= module.base + 12),
                branch_target=target, startup_register_abi_proven=False,
                initial_register_values_supplied=False,
                cross_module_initialization_order_proven=False)


def _entry_graph(modules, entry, syntax, max_instructions, linked=True, extra_entries=(), sdk=False, native_entries=(), sdk_init=False,decode_cache=None):
    require(type(sdk_init) is bool,'SDK initialization must be an explicit boolean')
    require(decode_cache is None or isinstance(decode_cache,StartupDecodeCache),'invalid owned startup decode cache')
    require(isinstance(native_entries,(list,tuple)) and len(native_entries)<=(4096 if sdk_init else 64) and
            len(set(native_entries))==len(native_entries) and
            all(type(pc) is int and _owner(modules,pc) is not None for pc in native_entries) and
            (sdk or not native_entries) and (not sdk_init or sdk),'invalid native SDK boundaries')
    native_entries=set(native_entries)
    require(isinstance(extra_entries, (list, tuple)) and len(extra_entries) <= (MAX_INIT_ENTRIES if sdk_init else 1024 if sdk else 256),
            "too many additional startup entries")
    require(all(type(pc) is int and _owner(modules, pc) is not None for pc in extra_entries),
            "additional startup entry is not aligned mapped text")
    require(len(set(extra_entries)) == len(extra_entries) and entry not in extra_entries,
            "duplicate additional startup entry")
    roots = [entry, *extra_entries]
    pending, queued, nodes, frontier, services, systems = deque((pc, 0) for pc in roots), set(roots), [], [], [], []
    bridges = {}
    for module in modules:
        for offset, record in plt_stubs(module).items():
            target_field = "linked_snapshot_target" if linked else "unrelocated_slot_value"
            bridges[module.base + offset + 12] = dict(entry=module.base + offset,
                symbol=record["symbol"], got=module.base + record["got_offset"],
                image_state="offline-linked" if linked else "raw", live_target_proven=False,
                **{target_field: int(record["resolved_address"], 16)})
    while pending and len(nodes) < max_instructions:
        pc, distance = pending.popleft()
        module = _owner(modules, pc)
        if module is None:
            frontier.append(dict(address=pc, kind="unmapped_code_target", distance=distance))
            continue
        word = module.unpack("<I", pc - module.base)[0]
        mnemonic,operands,flow,form,semantic_error=(decode_cache.decode(syntax,word,pc,sdk,sdk_init) if decode_cache is not None else
            _decode_entry_word(syntax,word,pc,sdk,sdk_init))
        row = dict(address=pc, module=module.name, offset=pc - module.base,
                   word=word, mnemonic=mnemonic,
                   operands=operands, distance=distance,
                   edges=[], semantic_supported=False)
        reason = None
        if semantic_error is not None:
            row["semantic_error"] = semantic_error
            reason = "unsupported_semantics"
        else:
            row.update(semantic_supported=True, form=form)
        if mnemonic == "svc":
            svc = (word >> 5) & 0xffff
            row["service_immediate"] = svc
            services.append(dict(address=pc, immediate=svc, distance=distance,
                                 runtime_path_proven=False))
            reason = "supervisor_call_boundary"
        elif mnemonic in ("mrs", "msr"):
            systems.append(dict(address=pc, mnemonic=mnemonic, operands=row["operands"],
                                distance=distance, runtime_path_proven=False))
        if flow == TRAP:
            reason = "trap_or_undefined"
        elif flow in (INDIRECT_CALL, INDIRECT_JUMP):
            reason = "indirect_call" if flow == INDIRECT_CALL else "indirect_jump"
            if pc in bridges:
                row["plt_snapshot"] = bridges[pc]
        elif flow == RETURN:
            row["return_boundary"] = True
        if pc in native_entries:
            row.update(semantic_supported=False,native_boundary=True)
            reason='native_sdk_boundary'
        if reason:
            frontier.append(dict(address=pc, module=module.name, kind=reason,
                                 word=word, mnemonic=mnemonic, distance=distance))
        if pc not in native_entries and ((not reason and flow != RETURN) or (sdk and (mnemonic == "svc" or flow == INDIRECT_CALL))):
            targets = [direct_target(word, pc)] if flow == JUMP else (
                [direct_target(word, pc), pc + 4] if flow in (CALL, CONDITIONAL) else [pc + 4])
            row["edges"] = targets
            if flow == CALL or (sdk and flow == INDIRECT_CALL):
                row["continuation_requires_return"] = True
            for target in targets:
                if target not in queued:
                    queued.add(target)
                    pending.append((target, distance + 1))
        nodes.append(row)
    return dict(entry=entry, additional_entries=list(extra_entries),
                root_provenance=[dict(address=entry, selection="loader-convention entry"),
                    *[dict(address=pc, selection="explicit diagnostic code root; not function identity")
                      for pc in extra_entries]], nodes=nodes, instruction_count=len(nodes),
                frontier=frontier, frontier_counts=dict(Counter(x["kind"] for x in frontier)),
                services=services, system_register_boundaries=systems,
                truncated=bool(pending), pending_addresses=[pc for pc, _ in pending],
                method="bounded static CFG; both condition edges; direct call target and possible return continuation",
                indirect_targets_followed=False, runtime_path_proven=False,
                complete_function_closure_proven=False)


def audit_entry(linker, max_instructions=8192, extra_entries=(), sdk=False, native_entries=(), sdk_init=False,decode_cache=None):
    """Inspect raw or linked entry text; unresolved data never becomes a target."""
    require(type(sdk_init) is bool and (not sdk_init or sdk), 'SDK initialization requires explicit SDK mode')
    require(type(max_instructions) is int and 1 <= max_instructions <= (MAX_INIT_INSTRUCTIONS if sdk_init else MAX_INSTRUCTIONS),
            "startup instruction limit exceeds its explicit profile")
    require(linker.modules, "startup audit requires modules")
    syntax = Decoder()
    modules = linker.modules
    return dict(schema_version=1, format="oot-startup-entry-audit",
                image_state="offline-linked" if linker.applied else "raw",
                guest_code_executed=False, translation_performed=False,
                native_callbacks_registered=False, runtime_capabilities_granted=False,
                startup_abi_proven=False, decoder=syntax.metadata,
                modules=[dict(name=m.name, base=m.base, source_sha256=m.source_sha256,
                    text_sha256=hashlib.sha256(m.image[m.ranges[0][0]:m.ranges[0][1]]).hexdigest())
                    for m in modules],
                entry_evidence=_entry_evidence(modules[0], syntax),
                entry_graph=_entry_graph(modules, modules[0].base, syntax, max_instructions,
                                         linked=linker.applied, extra_entries=extra_entries, sdk=sdk,native_entries=native_entries,sdk_init=sdk_init,decode_cache=decode_cache))


def audit_startup(linker, max_instructions=8192, sample_limit=32):
    require(type(max_instructions) is int and 1 <= max_instructions <= MAX_INSTRUCTIONS,
            "startup instruction limit must be 1-65536")
    require(type(sample_limit) is int and 0 <= sample_limit <= 4096,
            "startup sample limit must be 0-4096")
    link = linker.report()
    require(link.get("link_complete") is True, "startup audit requires a complete offline link")
    modules = linker.modules
    require(modules, "startup audit requires modules")
    syntax = Decoder()
    records = [_module(module, modules) for module in modules]
    graph = _entry_graph(modules, modules[0].base, syntax, max_instructions)
    init_slots = [slot for module in records if module["arrays"]["init"] is not None
                  for slot in module["arrays"]["init"]["slots"]]
    counts = Counter(slot["kind"] for slot in init_slots)
    unique = {slot["value"] for slot in init_slots if slot["kind"] == "code"}
    return dict(schema_version=1, format=FORMAT, guest_code_executed=False,
                translation_performed=False, native_callbacks_registered=False,
                runtime_capabilities_granted=False, initialization_order_proven=False,
                startup_abi_proven=False, decoder=syntax.metadata, references=REFERENCES,
                limits=dict(max_instructions=max_instructions, sample_limit=sample_limit),
                offline_link=link, entry_evidence=_entry_evidence(modules[0], syntax),
                modules=records, entry_graph=graph,
                frontier_samples=graph["frontier"][:sample_limit],
                initializer_summary=dict(init_array_slots=len(init_slots),
                    classification=dict(sorted(counts.items())), unique_code_targets=len(unique),
                    duplicate_code_slots=counts["code"] - len(unique),
                    dt_init_functions=sum(bool(m["dynamic_functions"]["init"]) for m in records)),
                obligations=["recover entry register and thread ABI before execution",
                    "separate raw rtld self-relocation from already offline-linked images",
                    "prove actual module/constructor invocation order; table order alone is insufficient",
                    "verify each executed path and dynamic memory/service/indirect-call requirements"],
                scope="original-byte startup evidence; potential control flow is not an executable startup contract")
