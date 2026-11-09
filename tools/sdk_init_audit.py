"""Private exact-export bindings for the opt-in native SDK initialization model.

The report describes replacements and deterministic unsupported boundaries. It
does not execute any code or establish that startup has completed.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct
import sys
import re

from arm64_decode import Decoder, direct_target
from input_formats import InputError, require
from link_exefs import build_destination, load_prepared
from module_linker import Linker
from native_sdk_audit import audit_native_sdk
from sdk_startup_audit import STAGE_SYMBOLS, _stage, _symbol_record

FORMAT = 'oot-sdk-init-audit'
GUARD_ID = 31
MAX_FUNCTIONS = 4096

# IDs are the native_platform/native_services contracts, not original enum or
# syscall numbers. Return types are separately declared because Itanium names
# generally do not encode a non-template function's return type.
FUNCTIONS = (
    (64, 'oe_initialize', '_ZN2nn2oe10InitializeEv', 'void Initialize()', False),
    (66, 'oe_operation_mode', '_ZN2nn2oe16GetOperationModeEv', 'OperationMode GetOperationMode()', True),
    (67, 'oe_performance_mode', '_ZN2nn2oe18GetPerformanceModeEv', 'PerformanceMode GetPerformanceMode()', True),
    (68, 'oe_focus', '_ZN2nn2oe20GetCurrentFocusStateEv', 'FocusState GetCurrentFocusState()', True),
    (69, 'oe_cpu_boost', '_ZN2nn2oe15SetCpuBoostModeENS0_12CpuBoostModeE', 'void SetCpuBoostMode(CpuBoostMode)', False),
    (70, 'oe_focus_handling', '_ZN2nn2oe20SetFocusHandlingModeENS0_17FocusHandlingModeE', 'void SetFocusHandlingMode(FocusHandlingMode)', False),
    (71, 'oe_resume_notifications', '_ZN2nn2oe28SetResumeNotificationEnabledEb', 'void SetResumeNotificationEnabled(bool)', False),
    (72, 'oe_operation_notifications', '_ZN2nn2oe42SetOperationModeChangedNotificationEnabledEb', 'void SetOperationModeChangedNotificationEnabled(bool)', False),
    (73, 'oe_performance_notifications', '_ZN2nn2oe44SetPerformanceModeChangedNotificationEnabledEb', 'void SetPerformanceModeChangedNotificationEnabled(bool)', False),
    (74, 'oe_graphics_scale', '_ZN2nn2oe23GetCurrentGraphicsScaleEv', 'GraphicsScale GetCurrentGraphicsScale()', True),
    (128, 'aoc_initialize', '_ZN2nn3aoc10InitializeEv', 'void Initialize()', False),
    (129, 'aoc_finalize', '_ZN2nn3aoc8FinalizeEv', 'void Finalize()', False),
    (144, 'err_context_writer', '_ZN2nn3err26InitializeContextWriterApiEv', 'void InitializeContextWriterApi()', False),
    (160, 'diag_abort_observer', '_ZN2nn4diag34InitializeApplicationAbortObserverEv', 'void InitializeApplicationAbortObserver()', False),
    (176, 'pctl_initialize', '_ZN2nn4pctl10InitializeEv', 'void Initialize()', False),
    (192, 'fs_initialize', '_ZN2nn2fs24InitializeForApplicationEv', 'void InitializeForApplication()', False),
    (193, 'fs_access_log', '_ZN2nn2fs28SetLocalApplicationAccessLogEb', 'void SetLocalApplicationAccessLog(bool)', False),
    (194, 'fs_result_handled', '_ZN2nn2fs29SetResultHandledByApplicationEb', 'void SetResultHandledByApplication(bool)', False),
    (208, 'time_initialize', '_ZN2nn4time10InitializeEv', 'Result Initialize()', True),
    (224, 'os_system_tick', '_ZN2nn2os13GetSystemTickEv', 'Tick GetSystemTick()', True),
    (256, 'math_log', 'log', 'double log(double); D0 only, finite positive domain', True),
)

# OE initialization normally constructs the applet client too. Its direct public
# consumers must not fall through to original code with that object absent.
NAMESPACES = ('2oe', '6applet', '3aoc', '3err', '4pctl', '2fs', '4time')
GUARD_PREFIXES = tuple(prefix + namespace for namespace in NAMESPACES
                       for prefix in ('_ZN2nn', '_ZNK2nn'))


def _in_family(name):
    return (name in ('log','_ZN2nn2os13GetSystemTickEv') or name.startswith(GUARD_PREFIXES) or
            (name.startswith(('_ZN2nn4diag', '_ZNK2nn4diag')) and 'Abort' in name))


def sdk_init_tick_frequency(linker):
    """Read the original pure SDK frequency getter, never infer a console rate."""
    row=_stage(linker.modules,'tick_frequency','sdk','_ZN2nn2os22GetSystemTickFrequencyEv',Decoder())
    module=next(m for m in linker.modules if m.name=='sdk')
    require(row['size']==12,'unsupported SDK tick-frequency getter extent')
    a,b,ret=module.unpack('<3I',row['offset'])
    require(a&0xffe0001f==0x52800000 and b&0xffe0001f==0x72a00000 and ret==0xd65f03c0,
            'SDK tick frequency is not an original constant W0 getter')
    frequency=((a>>5)&65535)|(((b>>5)&65535)<<16)
    require(0<frequency<=1000000000,'SDK tick frequency exceeds the bounded QPC conversion model')
    return frequency


def _original_zero_constructor(module,symbol):
    """Only original default constructors writing zero to their own this object.

    No resources, provider globals, calls, loads or validity result are supplied.
    These remain ordinary checked guest stores, including normal pointer faults.
    """
    if not re.search(r'C[12]Ev$',symbol.name) or symbol.kind!=2 or not symbol.section or not 8<=symbol.size<=128 or symbol.size%4:return False
    from sdk_init_instructions import decode_sdk_init_instruction
    words=module.unpack('<'+str(symbol.size//4)+'I',symbol.value)
    if words[-1]!=0xd65f03c0:return False
    for n,word in enumerate(words[:-1]):
        try:i=decode_sdk_init_instruction(word,module.base+symbol.value+n*4)
        except InputError:return False
        if (i.form not in ('loadstore_unsigned','loadstore_unscaled','loadstore_pair') or i.load or
            i.rn!=0 or i.rd!=31 or i.writeback or i.immediate<0 or
            i.immediate+i.access_size*(2 if i.form=='loadstore_pair' else 1)>256 or
            (i.form=='loadstore_pair' and i.rt2!=31)):return False
    return True


def _merge_bindings(functions):
    """ICF aliases are safe only when the complete body and handler agree."""
    merged = {}
    for original in functions:
        row = dict(original)
        row['names'] = list(row.get('names', [row['symbol']]))
        existing = merged.get(row['entry'])
        if existing is None:
            merged[row['entry']] = row
            continue
        require((existing['handler_id'], existing['size'], existing['body_sha256'],
                 existing['returns_value']) ==
                (row['handler_id'], row['size'], row['body_sha256'], row['returns_value']),
                'SDK init export aliases disagree on their complete body or ABI contract')
        existing['names'] = sorted(set(existing['names'] + row['names']))
        existing.setdefault('alias_metadata', []).append(dict(
            symbol=row['symbol'], symbol_metadata=row['symbol_metadata']))
    result = sorted(merged.values(), key=lambda row: row['entry'])
    require(len(result) <= MAX_FUNCTIONS and
            all(a['entry'] + a['size'] <= b['entry'] for a, b in zip(result, result[1:])),
            'SDK init function extents overlap or exceed the finite registry limit')
    return result


def _select_bindings(linker, module, decoder, logging_functions):
    supported = {symbol: (handler, name, signature, returns)
                 for handler, name, symbol, signature, returns in FUNCTIONS}
    require(len(supported) == len(FUNCTIONS), 'SDK init contracts have duplicate symbol names')
    rows = [dict(row) for row in logging_functions]
    selected = set()
    counts = Counter()
    symbol_counts = []
    if 39 in module.dynamic:
        require(module.dynamic[39] % 24 == 0, 'SDK init original symbol-table size is invalid')
        symbol_counts.append(module.dynamic[39] // 24)
    if 4 in module.dynamic:
        symbol_counts.append(module.unpack('<II', module.dynamic[4])[1])
    if not symbol_counts and 0x6ffffef5 in module.dynamic:
        symbol_counts.append(module.gnu_symbol_count())
    require(symbol_counts and all(count == len(module.symbols) for count in symbol_counts),
            'SDK init parsed symbol census differs from its original bounded table')
    strings = module.read(module.dynamic[5], module.dynamic[10])
    for index, symbol in enumerate(module.symbols):
        # Enumerate from the original name as well as the parsed name. Otherwise
        # changing a parsed guard's namespace/kind could silently omit it before
        # _stage has an opportunity to check the original dynamic symbol.
        original = module.read(module.dynamic[6] + index * 24, 24)
        name_offset = struct.unpack_from('<I', original)[0]
        require(name_offset < len(strings), 'SDK init symbol string exceeds its original table')
        end = strings.find(b'\0', name_offset)
        require(end >= 0, 'SDK init symbol string has no original terminator')
        try:
            original_name = strings[name_offset:end].decode('utf-8')
        except UnicodeDecodeError as error:
            raise InputError('SDK init symbol name has invalid original encoding') from error
        if _in_family(original_name) or _in_family(symbol.name):
            _symbol_record(module, index, symbol)
        if not symbol.section or not _in_family(symbol.name):
            continue
        if symbol.kind != 2:
            counts['non_function_symbols'] += 1
            continue
        handler, name, signature, returns = supported.get(symbol.name,
            (GUARD_ID, 'guard_' + symbol.name, 'unsupported SDK initialization-model consumer', False))
        if handler==GUARD_ID and _original_zero_constructor(module,symbol):
            counts['original_zero_constructor_exports']+=1
            continue
        record = _stage(linker.modules, name, 'sdk', symbol.name, decoder)
        if handler==224:
            require(record['size']==8 and module.unpack('<2I',record['offset'])==(0xd53be020,0xd65f03c0),
                    'system tick replacement requires the exact original counter-read/return body')
        record.update(handler_id=handler, signature=signature, returns_value=returns,
            return_register='d0' if handler==256 else 'x0' if returns else None,
            implementation='guard' if handler == GUARD_ID else 'native-host-sdk-init',
            original_body_executed=False, native_execution_proven=False,
            entry_word=record['entry_instruction']['word'], names=[symbol.name])
        rows.append(record)
        selected.add(symbol.name)
        counts['guarded_exports' if handler == GUARD_ID else 'supported_exports'] += 1
    require(set(supported) <= selected,
            'SDK init audit is missing a required exact native-provider export: ' +
            ', '.join(sorted(set(supported) - selected)))
    # A definition in a different module must not disappear behind SDK-only
    # enumeration. _stage catches same-name duplicates for selected names.
    require(not any(owner.name != 'sdk' and symbol.section and _in_family(symbol.name)
                    for owner in linker.modules for symbol in owner.symbols),
            'SDK init namespace has a definition outside its expected module')
    return _merge_bindings(rows), dict(counts)


def _progress(linker, functions, decoder):
    required = []
    # nnMain's exact B thunk and target transition remain the startup goal;
    # merely intercepting any of these entries cannot satisfy it.
    for name, owner, symbol in STAGE_SYMBOLS[:8]:
        record = _stage(linker.modules, name, owner, symbol, decoder)
        require(all(record['entry'] + record['size'] <= row['entry'] or
                    row['entry'] + row['size'] <= record['entry'] for row in functions),
                'SDK init replacement overlaps an original required startup stage')
        record.update(original_entry_retirement_required=True, native_replacement_allowed=False,
                      completed_body_proven=False)
        required.append(record)
    main = required[-1]
    word = main['entry_instruction']['word']
    require(main['size'] == 4 and word & 0xfc000000 == 0x14000000,
            'SDK init audit requires the exact original nnMain B thunk')
    target = direct_target(word, main['entry'])
    owners = [owner for owner in linker.modules if owner.is_code(target - owner.base)]
    require(len(owners) == 1 and owners[0].name == 'main' and target != main['entry'],
            'SDK init audit requires a distinct original nnMain target in main text')
    require(not any(row['entry'] <= target < row['entry'] + row['size'] for row in functions),
            'SDK init replacement covers the original nnMain target')
    time = _stage(linker.modules, 'time_startup', 'sdk', 'nntimeStartup', decoder)
    require(all(time['entry'] + time['size'] <= row['entry'] or
                row['entry'] + row['size'] <= time['entry'] for row in functions),
            'SDK init replacement overlaps the original time-startup wrapper')
    time.update(native_replacement_allowed=False, completed_body_proven=False)
    return dict(required_original_stages=required, original_time_startup=time,
        nn_main_target=target,
        ordered_retirements_proven=False, nn_main_transition_proven=False,
        callback_tables_executed=False, initialization_completed=False)


def audit_sdk_init(linker):
    """Bind supported providers plus complete exported consumer guard families."""
    logging = audit_native_sdk(linker)
    module = next(owner for owner in linker.modules if owner.name == 'sdk')
    decoder = Decoder()
    decoder.engine.detail = True
    functions, census = _select_bindings(linker, module, decoder, logging['functions'])
    original_constructors=[_stage(linker.modules,'original_zero_constructor','sdk',symbol.name,decoder)
        for symbol in module.symbols if _in_family(symbol.name) and _original_zero_constructor(module,symbol)]
    progress = _progress(linker, functions, decoder)
    report = dict(logging)
    report.update(format=FORMAT, schema_version=1, functions=functions, export_census=census,
        original_zero_constructors=original_constructors,
        registry_limit=MAX_FUNCTIONS, progress=progress,
        guard_policy=dict(prefixes=list(GUARD_PREFIXES), diagnostic_family='nn::diag exports containing Abort',
            unsupported_handler_id=GUARD_ID, exported_function_consumer_closure=True,
            private_direct_access_closure_proven=False,
            original_body_exception='source-proved default constructors containing only bounded zero stores through this and standard RET',
            exact_entry_only=True, interior_entry_allowed=False,
            alias_policy='merge only identical complete body, handler and return ABI'),
        provider_contracts=dict(
            platform='explicit local operation/performance/focus/graphics model; no applet session or SDK object',
            aoc='owned provider lifecycle; no fabricated addon-content service object',
            err='owned bounded error-context store; opaque guest writer APIs guarded',
            abort='owned native abort-observer policy; guest holder/callback APIs guarded',
            pctl='owned explicit local policy; all unsupported policy queries guarded',
            fs='owned application initialization mode and two boolean flags; no mounted filesystem implied',
            time='owned explicit user-mode clock configuration and initialization refcount; Result success, queries guarded'),
        scope='bounded native SDK initialization providers and exact unsupported consumer entries; original startup stages remain required',
        remaining_platform_scope='private state consumers require explicit audit; graphics, account, input, filesystem mounting and gameplay remain unsupported')
    if report['original_oe_initialize'] is not None:
        report['original_oe_initialize'] = dict(report['original_oe_initialize'],
            observation_only=False, original_entry_retirement_required=False,
            replacement_handler_id=64, native_execution=False)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prepared', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    try:
        destination = build_destination(args.report)
        require(not destination.exists(), 'choose a fresh SDK initialization report path')
        linker = Linker(load_prepared(args.prepared))
        linker.apply()
        report = audit_sdk_init(linker)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps(dict(report=str(destination), format=FORMAT,
            functions=len(report['functions']),
            native_operations=sum(row['handler_id'] != GUARD_ID for row in report['functions']),
            guest_code_executed=False, sdk_initialization_completed=False)))
        return 0
    except (InputError, OSError, ValueError) as error:
        print(f'SDK initialization audit failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
