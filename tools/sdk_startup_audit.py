"""Private, original-byte SDK startup metadata; never translate or execute code."""

from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from arm64_analysis import plt_stubs
from arm64_decode import (CALL, CONDITIONAL, INDIRECT_CALL, INDIRECT_JUMP, JUMP,
                          Decoder, direct_target, flow_kind)
from input_formats import InputError, require, inspect_npdm, in_bounds
from link_exefs import build_destination, load_prepared
from module_linker import Linker
from startup_audit import _module

FORMAT = "oot-sdk-startup-audit"
SDK_START_SYMBOL = "_ZN2nn4init5StartEmmPFvvES2_S2_"
# These are exact dynamic symbol names, not demangled-name or address aliases.
STAGE_SYMBOLS = (
    ("sdk_start", "sdk", SDK_START_SYMBOL),
    ("libc0", "sdk", "_init_libc0"),
    ("os_init", "sdk", "nnosInitialize"),
    ("libc1", "sdk", "_init_libc1"),
    ("sdk_module_init", "sdk", "nninitInitializeSdkModule"),
    ("app_startup", "main", "nninitStartup"),
    ("libc2", "sdk", "_init_libc2"),
    ("nn_main", "main", "nnMain"),
    ("sdk_module_fini", "sdk", "nninitFinalizeSdkModule"),
    ("quick_exit", "sdk", "nnosQuickExit"),
)
THREAD_IDENTITY_SYMBOLS = (
    ("enter", "sdk", "_ZN2nn2os6detail23InternalCriticalSection5EnterEv"),
    ("leave", "sdk", "_ZN2nn2os6detail23InternalCriticalSection5LeaveEv"),
    ("enter_slow", "sdk", "_ZN2nn2os6detail36EnterInternalCriticalSectionNoInlineEPNS1_27InternalCriticalSectionTypeEjj"),
    ("leave_slow", "sdk", "_ZN2nn2os6detail36LeaveInternalCriticalSectionNoInlineEPNS1_27InternalCriticalSectionTypeEjj"),
)
NPDM_REFERENCES = [
    {"url": "https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libmesosphere/include/mesosphere/kern_k_capabilities.hpp",
     "scope": "capability field layout reference; not a recovered Switch 2 kernel ABI"},
    {"url": "https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libmesosphere/source/kern_k_capabilities.cpp",
     "scope": "inclusive numeric core and priority range interpretation reference"},
    {"url": "https://github.com/Atmosphere-NX/Atmosphere/blob/master/stratosphere/loader/source/ldr_process_creation.cpp",
     "scope": "ACI0 application-type interpretation reference; no signature or authority proof"},
]


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _owner(modules, address):
    owners = [module for module in modules if module.is_code(address - module.base)]
    require(len(owners) <= 1, "SDK audit: ambiguous code ownership")
    return owners[0] if owners else None


def _instruction(module, address, syntax):
    offset = address - module.base
    require(module.is_code(offset), "SDK audit: instruction is not mapped aligned text")
    data = module.read(offset, 4)
    word = struct.unpack("<I", data)[0]
    ins = next(iter(syntax.engine.disasm(data, address)), None)
    return dict(address=address, module=module.name, offset=offset, word=word,
                sha256=_sha(data), mnemonic=ins.mnemonic if ins else ".word",
                operands=ins.op_str if ins else "")


def _symbol_record(module, index, symbol):
    """Check parsed metadata against its actual dynamic symbol and string bytes."""
    data = module.read(module.dynamic[6] + index * 24, 24)
    name, info, other, section, value, size = struct.unpack("<IBBHQQ", data)
    strings = module.read(module.dynamic[5], module.dynamic[10])
    require(name < len(strings), "SDK audit: symbol string exceeds original table")
    end = strings.find(b"\0", name)
    require(end >= 0, "SDK audit: symbol string has no terminator")
    try:
        actual_name = strings[name:end].decode("utf-8")
    except UnicodeDecodeError:
        require(False, "SDK audit: invalid symbol string encoding")
    require((actual_name, info >> 4, info & 15, other & 3, section, value, size) ==
            (symbol.name, symbol.binding, symbol.kind, symbol.visibility,
             symbol.section, symbol.value, symbol.size),
            "SDK audit: parsed symbol does not match original symbol bytes")
    return dict(index=index, binding=symbol.binding, kind=symbol.kind,
                visibility=symbol.visibility, section=symbol.section,
                value=symbol.value, size=symbol.size, record_sha256=_sha(data),
                name_sha256=_sha(strings[name:end + 1]))


def _stage(modules, stage_id, expected_module, name, syntax):
    definitions = [(module, index, symbol) for module in modules
                   for index, symbol in enumerate(module.symbols)
                   if symbol.name == name and symbol.section != 0]
    require(len(definitions) == 1,
            f"SDK audit: missing or ambiguous definition of {name}")
    module, index, symbol = definitions[0]
    require(module.name == expected_module and symbol.kind == 2 and
            symbol.binding in (1, 2) and symbol.visibility in (0, 3),
            f"SDK audit: {name} is not the expected exported function")
    require(symbol.size > 0 and symbol.size % 4 == 0 and
            module.is_code(symbol.value) and
            module.is_code(symbol.value + symbol.size - 4),
            f"SDK audit: invalid function text extent for {name}")
    metadata = _symbol_record(module, index, symbol)
    entry = module.base + symbol.value
    return dict(id=stage_id, symbol=name, module=module.name, entry=entry,
                offset=symbol.value, size=symbol.size,
                body_sha256=_sha(module.read(symbol.value, symbol.size)),
                symbol_metadata=metadata,
                entry_instruction=_instruction(module, entry, syntax),
                function_identity_proven=False, runtime_visit_proven=False)


def _resolve_call(modules, target, bridges, syntax):
    """Describe exact B/PLT snapshots; this never grants an indirect target."""
    steps, seen, symbol = [], set(), None
    for _ in range(16):
        require(target not in seen, "SDK audit: cyclic call thunk chain")
        seen.add(target)
        owner = _owner(modules, target)
        require(owner is not None, "SDK audit: call thunk target is not mapped text")
        if target in bridges:
            bridge = bridges[target]
            data = owner.read(target - owner.base, 16)
            steps.append(dict(kind="relocation_backed_plt_snapshot", entry=target,
                              words=list(struct.unpack("<4I", data)), sha256=_sha(data),
                              symbol=bridge["symbol"], got=owner.base + bridge["got_offset"],
                              linked_target=int(bridge["resolved_address"], 16),
                              live_target_proven=False))
            symbol = bridge["symbol"]
            target = int(bridge["resolved_address"], 16)
            # The resolved function may itself be a B thunk; keep its symbol entry.
            break
        row = _instruction(owner, target, syntax)
        if row["word"] & 0xFC000000 != 0x14000000:
            break
        target = direct_target(row["word"], target)
        steps.append(dict(kind="direct_branch_thunk", target=target, **row))
    else:
        require(False, "SDK audit: excessive call thunk chain")
    require(_owner(modules, target) is not None,
            "SDK audit: resolved call snapshot is not mapped text")
    return dict(resolved_entry=target, relocation_symbol=symbol,
                resolution_steps=steps, live_target_proven=False)


def audit_sdk_thread_identity(linker):
    """Recognize an original SDK lock-identity profile before supplying its TLS field.

    This proves only the inspected SDK's register roles and observed field offset.
    It does not recover a general kernel TLS layout or grant threading services.
    Missing symbols and unrecognized profiles are errors for this strict API.
    """
    require(linker.report().get("link_complete") is True,
            "SDK thread identity audit requires a complete offline link")
    modules = linker.modules
    sdk = [module for module in modules if module.name == "sdk"]
    require(len(sdk) == 1, "SDK thread identity requires one SDK module")
    module = sdk[0]
    begin, end = module.ranges[0]
    actual = _sha(module.read(begin, end - begin))
    require(module.header["segments"][0].get("hash_verified") is True and
            actual == module.header["segments"][0].get("sha256"),
            "SDK thread identity requires unchanged original text")
    syntax = Decoder()
    syntax.engine.detail = True
    functions = {name: _stage(modules, name, owner, symbol, syntax)
                 for name, owner, symbol in THREAD_IDENTITY_SYMBOLS}
    require(len({row["entry"] for row in functions.values()}) == 4,
            "SDK thread identity functions must have distinct entries")

    def instructions(name):
        function = functions[name]
        require(function["size"] <= 1024, "SDK thread identity function exceeds profile limit")
        rows = list(syntax.engine.disasm(module.read(function["offset"], function["size"]),
                                        function["entry"]))
        require(len(rows) * 4 == function["size"] and
                all(row.size == 4 and row.mnemonic != ".word" for row in rows),
                "SDK thread identity requires complete instruction decoding")
        return rows

    def is_op(row, mnemonic, operands):
        return row.mnemonic == mnemonic and row.op_str == operands

    def word(row):
        return int.from_bytes(row.bytes, "little")

    def branch(row, kind, target):
        return (flow_kind(word(row), row.mnemonic) == kind and
                direct_target(word(row), row.address) == target)

    def writes(row, registers):
        _, modified = row.regs_access()
        return bool({row.reg_name(reg).lstrip("wx") for reg in modified} & registers)

    def tls_read(rows):
        # The read register may vary; W2 is the ABI's lock/requesting identity.
        register = word(rows[0]) & 31
        require(word(rows[0]) & ~31 == 0xd53bd060 and 8 <= register <= 17,
                "SDK thread identity must start with MRS TPIDRRO_EL0")
        require(is_op(rows[1], "ldr", f"w2, [x{register}, #0x110]"),
                "SDK thread identity offset/width/register role is unrecognized")

    enter, leave = instructions("enter"), instructions("leave")
    require(len(enter) == 7 and len(leave) == 8,
            "SDK thread identity fast-path shape is unrecognized")
    tls_read(enter)
    tls_read(leave)
    require(is_op(enter[2], "mov", "w1, wzr") and
            is_op(enter[3], "casa", "w1, w2, [x0]") and
            is_op(enter[4], "cbnz", f"w1, #{enter[6].address:#x}") and
            branch(enter[4], CONDITIONAL, enter[6].address) and
            is_op(enter[5], "ret", "") and
            branch(enter[6], JUMP, functions["enter_slow"]["entry"]),
            "SDK thread identity acquire/slow-path role is unrecognized")
    require(is_op(leave[2], "mov", "w1, w2") and
            is_op(leave[3], "casl", "w1, wzr, [x0]") and
            is_op(leave[4], "cmp", "w1, w2") and leave[5].mnemonic == "b.ne" and
            branch(leave[5], CONDITIONAL, leave[7].address) and
            is_op(leave[6], "ret", "") and
            branch(leave[7], JUMP, functions["leave_slow"]["entry"]),
            "SDK thread identity release/slow-path role is unrecognized")

    slow = instructions("enter_slow")
    captures = [index for index in range(len(slow) - 1)
                if is_op(slow[index], "mov", "w19, w2") and
                is_op(slow[index + 1], "mov", "x20, x0")]
    calls = [index + 3 for index in range(len(slow) - 3)
             if is_op(slow[index], "and", "w0, w1, #0xbfffffff") and
             is_op(slow[index + 1], "mov", "x1, x20") and
             is_op(slow[index + 2], "mov", "w2, w19") and
             flow_kind(word(slow[index + 3]), slow[index + 3].mnemonic) == CALL]
    require(len(captures) == len(calls) == 1 and captures[0] + 1 < calls[0] - 3,
            "SDK thread identity slow-path input/argument chain is unrecognized")
    capture, call = captures[0], calls[0]
    for index, row in enumerate(slow[:call]):
        flow = flow_kind(word(row), row.mnemonic)
        require(flow not in (CALL, INDIRECT_CALL, INDIRECT_JUMP),
                "SDK thread identity slow path calls before binding service arguments")
        require(index in (capture, capture + 1) or not writes(row, {"19", "20"}),
                "SDK thread identity captured inputs are clobbered")
        require(index >= capture or not writes(row, {"0", "2"}),
                "SDK thread identity input roles are clobbered before capture")
        if flow in (JUMP, CONDITIONAL):
            target = direct_target(word(row), row.address)
            require(not (index < capture and slow[capture].address <= target <= slow[call].address) and
                    target not in {slow[n].address for n in range(call - 2, call + 1)},
                    "SDK thread identity branch can skip its argument binding")

    def service_wrapper(row, immediate):
        target = direct_target(word(row), row.address)
        owner = _owner(modules, target)
        require(owner is module, "SDK thread identity service wrapper is not SDK text")
        data = module.read(target - module.base, 8)
        svc, ret = struct.unpack("<II", data)
        require(svc & 0xffe0001f == 0xd4000001 and (svc >> 5) & 0xffff == immediate and
                ret == 0xd65f03c0,
                "SDK thread identity service wrapper is unrecognized")
        return dict(entry=target, size=8, sha256=_sha(data), svc=immediate,
                    instructions=[_instruction(module, target + n, syntax) for n in (0, 4)])

    lock_wrapper = service_wrapper(slow[call], 0x1a)
    release = instructions("leave_slow")
    unlock_calls = [index + 3 for index in range(len(release) - 3)
                    if is_op(release[index], "orr", "w8, w2, #0x40000000") and
                    is_op(release[index + 1], "cmp", "w1, w8") and
                    release[index + 2].mnemonic == "b.ne" and
                    flow_kind(word(release[index + 3]), release[index + 3].mnemonic) == CALL]
    require(len(unlock_calls) == 1, "SDK thread identity release ownership check is unrecognized")
    unlock_call = unlock_calls[0]
    require(all(not writes(row, {"0", "1", "2"}) for row in release[:unlock_call - 3]) and
            all(flow_kind(word(row), row.mnemonic) not in (JUMP, CONDITIONAL)
                for row in release[:unlock_call - 3]) and
            all(flow_kind(word(row), row.mnemonic) not in (CALL, INDIRECT_CALL, INDIRECT_JUMP)
                for row in release[:unlock_call]) and
            direct_target(word(release[unlock_call - 1]), release[unlock_call - 1].address) >
                release[unlock_call].address,
            "SDK thread identity release can bypass or clobber its ownership check")
    unlock_wrapper = service_wrapper(release[unlock_call], 0x1b)
    for name, function in functions.items():
        function["instructions"] = [_instruction(module, row.address, syntax)
                                    for row in instructions(name)]
    return dict(schema_version=1, format="oot-sdk-thread-identity-audit", available=True,
                profile="observed-sdk-main-thread-lock-identity-v1", module=module.name,
                source_sha256=module.source_sha256, original_text_sha256=actual,
                tls_offset=0x110, field_width=4, supported_logical_handle_max=0x3fffffff,
                waiter_flag=0x40000000, observed_owner_mask=0xbfffffff,
                functions=functions, arbitrate_lock=lock_wrapper,
                arbitrate_unlock=unlock_wrapper,
                provenance="exact original SDK exported functions and service-argument register dataflow",
                observed_role="current-thread lock ownership and requesting-thread handle",
                guest_code_executed=False, retail_tls_layout_proven=False,
                guest_threading_supported=False, sdk_thread_object_manufactured=False)


def audit_sdk_startup(linker):
    """Bind SDK stage/nnMain goal metadata to a complete offline-linked snapshot.

    The result is private diagnostic metadata. Ordered entries are an observation
    requirement for a separate original-instruction runner, never proof that the
    initialization path has run or that initializer table order is invocation order.
    """
    require(linker.report().get("link_complete") is True,
            "SDK audit requires a complete offline link")
    modules = linker.modules
    require(modules and len({module.name for module in modules}) == len(modules),
            "SDK audit requires uniquely named modules")
    identities = []
    for module in modules:
        begin, end = module.ranges[0]
        actual = _sha(module.read(begin, end - begin))
        require(module.header["segments"][0].get("hash_verified") is True and
                actual == module.header["segments"][0].get("sha256"),
                f"SDK audit: original text checksum mismatch for {module.name}")
        identities.append(dict(name=module.name, base=module.base,
                               source_sha256=module.source_sha256,
                               original_text_sha256=actual,
                               build_id=module.header["build_id"]))
    syntax = Decoder()
    stages = [_stage(modules, *spec, syntax) for spec in STAGE_SYMBOLS]
    by_id = {stage["id"]: stage for stage in stages}
    # A differently named stage at the same entry is not an independent visit.
    require(len({stage["entry"] for stage in stages}) == len(stages),
            "SDK audit: distinct stage symbols alias one function entry")
    main = by_id["nn_main"]
    word = main["entry_instruction"]["word"]
    require(main["size"] == 4 and word & 0xFC000000 == 0x14000000,
            "SDK audit: nnMain must be an exact four-byte unconditional B thunk")
    entry = direct_target(word, main["entry"])
    owner = _owner(modules, entry)
    require(owner is not None and owner.name == "main" and entry != main["entry"],
            "SDK audit: nnMain branch target is not distinct main text")
    goal_ins = _instruction(owner, entry, syntax)
    require(goal_ins["mnemonic"] != ".word" and goal_ins["word"] != 0,
            "SDK audit: nnMain target has no decoded original instruction")
    goal = dict(entry=entry, module=owner.name, offset=entry - owner.base,
                first_word=goal_ins["word"], first_instruction_sha256=goal_ins["sha256"],
                instruction=goal_ins, thunk_entry=main["entry"], thunk_word=word,
                thunk_sha256=main["body_sha256"], runtime_reached=False,
                provenance="exact original nnMain symbol extent and unconditional B word")
    bridges = {module.base + offset: record for module in modules
               for offset, record in plt_stubs(module).items()}
    start = by_id["sdk_start"]
    require(start["size"] <= 16384, "SDK audit: excessive SDK Start body")
    start_owner = _owner(modules, start["entry"])
    calls = []
    for pc in range(start["entry"], start["entry"] + start["size"], 4):
        row = _instruction(start_owner, pc, syntax)
        if row["word"] & 0xFC000000 == 0x94000000:
            target = direct_target(row["word"], pc)
            resolved = _resolve_call(modules, target, bridges, syntax)
            candidates = [stage for stage in stages
                          if stage["entry"] in (target, resolved["resolved_entry"])]
            require(len(candidates) <= 1, "SDK audit: ambiguous call stage resolution")
            matched = candidates[0] if candidates else None
            if matched and resolved["relocation_symbol"] is not None:
                require(resolved["relocation_symbol"] == matched["symbol"],
                        "SDK audit: PLT symbol and resolved stage do not match")
            calls.append(dict(kind="direct_call", target=target, continuation=pc + 4,
                              stage_id=matched["id"] if matched else None,
                              **row, **resolved))
        elif row["word"] & 0xFFFFFC1F == 0xD63F0000:
            calls.append(dict(kind="indirect_call", register=(row["word"] >> 5) & 31,
                              continuation=pc + 4, callback_role_proven=False,
                              target_proven=False, **row))
    main_calls = [call for call in calls if call.get("stage_id") == "nn_main"]
    require(len(main_calls) == 1, "SDK audit: SDK Start must have one exact nnMain call")
    before = [call for call in calls if call["address"] < main_calls[0]["address"]]
    expected = {stage["id"] for stage in stages[:7]} - {"sdk_start"}
    matched = [call["stage_id"] for call in before if call.get("stage_id")]
    require(set(matched) == expected and len(matched) == len(expected),
            "SDK audit: mandatory pre-nnMain call stages are missing or duplicated")
    mandatory_ids = ["sdk_start", *matched]
    observations = [_module(module, modules) for module in modules]
    slots = [slot for record in observations if record["arrays"]["init"] is not None
             for slot in record["arrays"]["init"]["slots"]]
    counts = Counter(slot["kind"] for slot in slots)
    thread_names = {spec[2] for spec in THREAD_IDENTITY_SYMBOLS}
    thread_identity = (audit_sdk_thread_identity(linker)
                       if any(symbol.section and symbol.name in thread_names
                              for module in modules for symbol in module.symbols)
                       else dict(available=False,
                                 reason="required exported SDK lock-identity profile is absent"))
    return dict(schema_version=1, format=FORMAT, image_state="offline-linked",
                guest_code_executed=False, translation_performed=False,
                native_callbacks_registered=False, runtime_capabilities_granted=False,
                startup_completed=False, initialization_order_proven=False,
                startup_abi_proven=False, modules=identities, stages=stages,
                sdk_start_calls=calls, mandatory_stage_ids=mandatory_ids,
                mandatory_stage_entries=[by_id[name]["entry"] for name in mandatory_ids],
                mandatory_stage_order="ascending original SDK Start callsite PCs; actual visits required",
                main_thunk=main, goal_entry=goal,
                observed_process_model=dict(thread_identity=thread_identity),
                initializer_observations=dict(modules=observations,
                    init_array_slots=len(slots), classification=dict(sorted(counts.items())),
                    dt_init_functions=sum(bool(record["dynamic_functions"]["init"])
                                          for record in observations),
                    execution_order_proven=False),
                completion_obligations=[
                    "execute original raw-rtld startup, not the offline-linked audit image",
                    "observe all mandatory stage entries and original nnMain thunk retirement",
                    "reach the decoded nnMain branch target through the original call path",
                    "observe required module/constructor callbacks; table order is not invocation proof",
                    "report unsupported service, instruction or external requirement instead of skipping it"],
                diagnostic_requirements=[
                    "OS initialization includes entropy, address-space, threads, TLS and memory queries",
                    "SDK module initialization may require applet, add-on-content, parental-control and filesystem services",
                    "application startup heap demand must fit the declared explicit process model",
                    "PLT snapshots select original code; live GOT binding and original stubs still require checks"],
                scope="original-byte diagnostic goal metadata; no runtime completion or function identity proof")


def inspect_sdk_npdm(raw):
    """Read ACI0 declarations without claiming signed authority or retail effects.

    Field interpretation follows the cited primary reference. Missing supported
    declarations remain None; no masks or application type are guessed.
    """
    require(isinstance(raw, (bytes, bytearray)) and len(raw) <= 0x8000,
            "SDK NPDM input must be bytes of at most 32768 bytes")
    base = inspect_npdm(raw)
    aci, size = struct.unpack_from("<II", raw, 112)
    result = dict(**{key: value for key, value in base.items()
                     if key not in ("format", "signatures_checked")},
                  schema_version=1, format="oot-sdk-npdm-audit", source_sha256=_sha(raw),
                  core_mask=None, priority_mask=None, program_type=None,
                  is_application=None, aci0_capabilities=[], declarations_complete=False,
                  signatures_checked=False, acid_limits_checked=False,
                  retail_kernel_effects_proven=False, references=NPDM_REFERENCES,
                  provenance="ACI0 byte declarations interpreted with a primary reference; not verified kernel authority")
    if not size:
        result["unproven_inputs"] = ["ACI0", "core_mask", "priority_mask", "is_application"]
        return result
    regions = []
    for field, at in (("filesystem", 0x20), ("services", 0x28), ("kernel", 0x30)):
        offset, length = struct.unpack_from("<II", raw, aci + at)
        require(in_bounds(offset, length, size) and (not length or offset >= 64),
                f"SDK NPDM ACI0 {field} region exceeds its block or overlaps its header")
        if length:
            require(not any(offset < right and left < offset + length for left, right in regions),
                    "SDK NPDM ACI0 regions overlap")
            regions.append((offset, offset + length))
        if field == "kernel":
            kac_offset, kac_size = offset, length
    require(kac_offset % 4 == 0 and kac_size % 4 == 0,
            "SDK NPDM kernel capability table is not four-byte aligned")
    result["aci0"] = dict(offset=aci, size=size, kernel_offset=kac_offset,
                          kernel_size=kac_size,
                          kernel_sha256=_sha(raw[aci + kac_offset:aci + kac_offset + kac_size]))
    seen = set()
    for index, (word,) in enumerate(struct.iter_unpack("<I", raw[aci + kac_offset:aci + kac_offset + kac_size])):
        trailing = 0
        while trailing < 32 and word & (1 << trailing):
            trailing += 1
        row = dict(index=index, word=word, type_bits=trailing, interpreted=False)
        if trailing in (3, 13):
            require(trailing not in seen, "SDK NPDM duplicate singleton capability")
            seen.add(trailing)
        if trailing == 3:
            low_priority, high_priority = (word >> 4) & 63, (word >> 10) & 63
            minimum_core, maximum_core = (word >> 16) & 255, (word >> 24) & 255
            require(high_priority <= low_priority and minimum_core <= maximum_core < 64,
                    "SDK NPDM unsupported or reversed core/priority range")
            core_mask = ((1 << (maximum_core - minimum_core + 1)) - 1) << minimum_core
            priority_mask = ((1 << (low_priority - high_priority + 1)) - 1) << high_priority
            require(base["main_thread_core"] < 64 and core_mask & (1 << base["main_thread_core"]),
                    "SDK NPDM main thread core is outside its declared range")
            require(base["main_thread_priority"] < 64 and priority_mask & (1 << base["main_thread_priority"]),
                    "SDK NPDM main thread priority is outside its declared range")
            result.update(core_mask=core_mask, priority_mask=priority_mask)
            row.update(kind="core_priority", interpreted=True, minimum_core=minimum_core,
                       maximum_core=maximum_core, minimum_numeric_priority=high_priority,
                       maximum_numeric_priority=low_priority)
        elif trailing == 13:
            require(word >> 17 == 0, "SDK NPDM program type has reserved bits set")
            program_type = (word >> 14) & 7
            result["program_type"] = program_type
            if program_type in (0, 1, 2):
                result["is_application"] = program_type == 1
            row.update(kind="program_type", interpreted=program_type in (0, 1, 2),
                       program_type=program_type)
        elif trailing == 32:
            row.update(kind="padding", interpreted=True)
        else:
            row["kind"] = "uninterpreted_capability"
        result["aci0_capabilities"].append(row)
    result["program_id"] = int(base["program_id"], 16)
    result["unproven_inputs"] = [name for name in ("core_mask", "priority_mask", "is_application")
                                if result[name] is None]
    result["declarations_complete"] = not result["unproven_inputs"]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prepared", type=Path,
                        help="directory produced by tools/prepare_exefs.py")
    parser.add_argument("--report", type=Path, required=True,
                        help="fresh private JSON path under build/")
    args = parser.parse_args()
    try:
        destination = build_destination(args.report)
        require(not destination.exists(), "choose a fresh SDK startup report path")
        linker = Linker(load_prepared(args.prepared))
        manifest = json.loads((args.prepared / "manifest.json").read_text(encoding="utf-8"))
        record = next((entry for entry in manifest["files"]
                       if entry["name"] == "main.npdm"), None)
        require(record is not None, "SDK startup audit requires a verified prepared NPDM")
        require(record["bytes"] <= 32768, "SDK NPDM exceeds size limit")
        with (args.prepared / "main.npdm").open("rb") as stream:
            raw = stream.read(32769)
        require(len(raw) == record["bytes"] and _sha(raw) == record["sha256"],
                "SDK NPDM differs from the verified prepared record")
        npdm = inspect_sdk_npdm(raw)
        linker.apply()
        report = audit_sdk_startup(linker)
        report["npdm"] = npdm
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(report, indent=2) + "\n")
        print(json.dumps(dict(report=str(destination), format=FORMAT,
                              stages=len(report["stages"]),
                              mandatory_stages=len(report["mandatory_stage_entries"]),
                              npdm_declarations_complete=npdm["declarations_complete"],
                              guest_code_executed=False,
                              startup_completed=False)))
        return 0
    except (InputError, OSError, ValueError) as error:
        print(f"SDK startup audit failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
