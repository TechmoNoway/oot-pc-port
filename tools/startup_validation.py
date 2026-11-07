"""Synthetic original-byte startup dispatch, native prefixes and stop isolation."""

from copy import deepcopy
from ctypes import (CFUNCTYPE, POINTER, Structure, byref, c_char, c_char_p, c_int,
                    c_size_t, c_uint8, c_uint32, c_uint64, c_void_p, cast,
                    create_string_buffer, memmove, sizeof, string_at)
from importlib.metadata import version
import argparse
import json
import os
from pathlib import Path
import random
import struct
import sys

from input_formats import InputError, require
from lifter_validation import compile_library
from lifter_validation_types import Memory, State
from memory_validation import transfer
from module_linker import Linker, Module
from pair_validation import pair
from pauth_validation import KEYS, Reference
from prepare_runtime import pack_regions
from prepare_startup import CONTEXT, emit_startup, selection, startup_page_regions

ROOT = Path(__file__).resolve().parent.parent
STACK = 0x7000000000
STACK_SIZE = 4096
READY, YIELDED, STOPPED, REJECTED, CONTRACT = range(5)


class Config(Structure):
    _fields_ = [(name, c_uint64) for name in CONTEXT]


class Instruction(Structure):
    _fields_ = [('pc', c_uint64), ('word', c_uint32), ('kind', c_uint32),
                ('next_a', c_uint64), ('next_b', c_uint64), ('run', c_void_p)]


class Span(Structure):
    _fields_ = [('entry', c_uint64), ('size', c_uint32), ('sha256', c_uint8 * 32)]


class Program(Structure):
    _fields_ = [('version', c_uint32), ('flags', c_uint32), ('entry', c_uint64),
                ('body_sha256', c_uint8 * 32), ('instructions', POINTER(Instruction)),
                ('instruction_count', c_size_t), ('spans', POINTER(Span)), ('span_count', c_size_t)]


class Report(Structure):
    _fields_ = [('pc', c_uint64), ('retired', c_uint64), ('status', c_uint32),
                ('error', c_uint32), ('word', c_uint32), ('service', c_uint32)]


class Trace(Structure):
    _fields_ = [('pc', c_uint64), ('next_pc', c_uint64), ('retired', c_uint64),
                ('word', c_uint32), ('event', c_uint32), ('error', c_uint32), ('service', c_uint32)]


class ServiceReport(Structure):
    _fields_ = [('status', c_uint32), ('id', c_uint32), ('error', c_uint32),
                ('text_size', c_uint32), ('result', c_uint64), ('text', c_char * 4097)]


TRACE = CFUNCTYPE(None, POINTER(Trace), c_void_p)


def bindings(lib):
    signatures = {
        'oot_runtime_open': ([c_char_p, c_void_p, c_size_t], c_void_p),
        'oot_runtime_close': ([c_void_p], None),
        'oot_runtime_memory': ([c_void_p], POINTER(Memory)),
        'oot_pauth_create': ([c_uint32, c_void_p], c_void_p),
        'oot_pauth_destroy': ([c_void_p], None),
        'oot_startup_context_create': ([c_void_p, POINTER(Config), POINTER(c_uint32)], c_void_p),
        'oot_startup_context_destroy': ([c_void_p], None),
        'oot_startup_context_memory': ([c_void_p], POINTER(Memory)),
        'oot_startup_context_heap_size': ([c_void_p], c_uint64),
        'oot_startup_context_initial_state': ([c_void_p, c_uint64, POINTER(State)], c_int),
        'oot_startup_context_service': ([c_void_p, c_uint32, POINTER(State), POINTER(ServiceReport)], c_int),
        'oot_startup_dispatch_create': ([c_void_p, c_void_p, c_void_p, POINTER(Program), c_uint64, POINTER(c_uint32)], c_void_p),
        'oot_startup_dispatch_destroy': ([c_void_p], c_int),
        'oot_startup_dispatch_begin': ([c_void_p, POINTER(State), POINTER(Report)], c_int),
        'oot_startup_dispatch_run': ([c_void_p, POINTER(State), c_uint64, c_void_p, c_void_p, POINTER(Report)], c_int),
        'oot_startup_dispatch_abort': ([c_void_p], c_int),
    }
    for name, (args, result) in signatures.items():
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = args, result


def branch(pc, target, call=False):
    return (0x94000000 if call else 0x14000000) | (((target-pc)//4) & 0x3ffffff)


def fixture(name='loop'):
    # Test-only imports keep fixtures independent of private game inputs.
    if str(ROOT/'tests') not in sys.path:
        sys.path.insert(0, str(ROOT/'tests'))
    from test_arm64_analysis import synthetic_module
    from test_module_linker import change_memory
    companion = None
    if name == 'chunks':
        # Two artificial NSOs exceed the emitter's 64-instruction chunk. The
        # direct BL crosses chunk 0 -> 1; CBNZ in the second NSO crosses 1 -> 0.
        base, sdk = 0x100000000, 0x100200000
        words = {0: branch(0, 0x10), 0x10: 0xaa1e03f3,
                 0x70: 0xb4000183, 0x74: branch(base+0x74, sdk+0xa0, True),
                 0x78: branch(0x78, 0xa0), 0xf4: 0xaa1303fe, 0xf8: 0xd4000fe1}
        words.update({pc: 0x91000400 for pc in range(0x14, 0x70, 4)})
        words.update({pc: 0x91000c00 for pc in range(0xa0, 0xf4, 4)})
        companion = {0: branch(0, 0xa0), 0x78: branch(0x78, 0xd0),
                     0xa0: 0xd503237f, 0xa4: pair(2, False, 29, 30, 31, 3, -2),
                     0xa8: 0x910003fd, 0xac: 0xb5000002 | (((0x10-0xac)//4 & 0x7ffff) << 5),
                     0xb0: branch(0xb0, 0xd0), 0xf0: pair(2, True, 29, 30, 31, 1, 2),
                     0xf4: 0xd65f0fff}
        companion.update({pc: 0x91001400 for pc in range(0x10, 0x78, 4)})
        companion.update({pc: 0x91001c00 for pc in range(0xd0, 0xf0, 4)})
        extras = ()
    elif name == 'loop':
        words = {0: branch(0, 0x10), 0x60: 0xd4000fe1,
                 0xa0: 0xb4000123, 0xa4: pair(2, False, 4, 5, 1, 1, 2),
                 0xa8: 0xf1000463, 0xac: 0x54ffffc1,
                 0xb0: pair(2, True, 6, 7, 2, 1, 2),
                 0xb4: 0xca0700c0, 0xb8: 0xd65f03c0,
                 0xc4: 0xd2800000, 0xc8: 0xd65f03c0}
        for root, sign, auth in ((0x10, 0xd503233f, 0xd50323bf), (0x40, 0xd503237f, 0xd50323ff)):
            words.update({root: sign, root+4: pair(2, False, 29, 30, 31, 3, -4),
                          root+8: 0x910003fd, root+12: branch(root+12, 0xa0, True),
                          root+16: pair(2, True, 29, 30, 31, 1, 4), root+20: auth,
                          root+24: branch(root+24, 0x60)})
        extras = (0x40,)
    elif name == 'indirect':
        words = {0: branch(0, 0x10), 0x10: 0xd63f0140,
                 0x14: 0xb4000040, 0x18: branch(0x18, 0x60),
                 0x1c: branch(0x1c, 0x60), 0x40: 0x91001c00,
                 0x44: 0xd65f03c0, 0x60: 0xd4000fe1}
        extras = (0x14, 0x40)
    elif name == 'services':
        words = {0: branch(0, 0x10), 0x10: 0xd4000021,
                 0x14: transfer(3, 0, 4, 1), 0x18: 0xaa0203e0,
                 0x1c: 0xaa0303e1, 0x20: 0xd40004e1,
                 0x24: 0xd4000ee1}
        extras = (0x14, 0x24)
    else:
        raise ValueError('unknown synthetic startup fixture')
    raw = synthetic_module(words, rela=((0x2008, 1027, 0, 0x40),))
    raw = change_memory(raw, 0x2040, bytes(range(128)))
    modules = [Module('main', raw)]
    if companion is not None:
        modules.append(Module('sdk', synthetic_module(companion)))
    linker = Linker(modules)
    config = dict(CONTEXT, heap_capacity=0x200000)
    audit, nodes = selection(linker, extra_entries=[linker.modules[0].base+x for x in extras])
    regions = startup_page_regions(linker.modules) if name == 'chunks' else linker.modules
    blob, manifest = pack_regions(regions, {'synthetic_raw': True}, STACK, STACK_SIZE)
    source, summary = emit_startup(linker, nodes, manifest, config)
    source = source.replace('oot_startup_', 'oot_'+name+'_').replace('oot_pauth_lift_startup', 'oot_pauth_lift_'+name)
    source += f'\nOOT_LIFT_EXPORT const OotStartupProgram *oot_test_program_{name}(void) {{ return oot_{name}_compiled_program(); }}\n'
    return dict(name=name, linker=linker, nodes=nodes, audit=audit, blob=blob,
                manifest=manifest, source=source, config=config, summary=summary)


def snapshot(lib, context):
    memory = lib.oot_startup_context_memory(context).contents
    return {r.base: string_at(r.data, r.size) for r in memory.regions[:memory.count]}


def copied_program(lib, name):
    getter = getattr(lib, 'oot_test_program_'+name)
    getter.argtypes, getter.restype = [], POINTER(Program)
    p = Program.from_buffer_copy(getter().contents)
    ins = (Instruction*p.instruction_count)(*[Instruction.from_buffer_copy(i) for i in p.instructions[:p.instruction_count]])
    spans = (Span*p.span_count)(*[Span.from_buffer_copy(s) for s in p.spans[:p.span_count]])
    p.instructions, p.spans = ins, spans
    return p, ins, spans


class Session:
    def __init__(self, lib, fixture, directory, program=None, limit=100000):
        self.lib, self.fixture = lib, fixture
        self.image = self.context = self.keys = self.dispatcher = None
        self.report, self.error = Report(), c_uint32()
        self.keep = copied_program(lib, fixture['name']) if program is None else program
        self.program = self.keep[0]
        path = Path(directory)/(fixture['name']+'.ootmem')
        path.write_bytes(fixture['blob'])
        message = create_string_buffer(192)
        self.image = lib.oot_runtime_open(os.fsencode(path), message, len(message))
        require(self.image, f'synthetic startup image failed: {message.value!r}')
        config = Config(**fixture['config'])
        self.context = lib.oot_startup_context_create(self.image, byref(config), byref(self.error))
        require(self.context, f'synthetic startup context failed: {self.error.value}')
        self.keys = lib.oot_pauth_create(1, (c_uint64*4)(*KEYS))
        require(self.keys, 'synthetic startup PAC allocation failed')
        self.dispatcher = lib.oot_startup_dispatch_create(self.image, self.context, self.keys,
                                                         byref(self.program), limit, byref(self.error))
        require(self.dispatcher, f'synthetic startup dispatcher failed: {self.error.value}')

    def close(self):
        if self.dispatcher:
            require(self.lib.oot_startup_dispatch_destroy(self.dispatcher), 'startup destroy failed')
        if self.context: self.lib.oot_startup_context_destroy(self.context)
        if self.keys: self.lib.oot_pauth_destroy(self.keys)
        if self.image: self.lib.oot_runtime_close(self.image)
        self.dispatcher = self.context = self.keys = self.image = None

    def initial(self):
        state = State()
        require(self.lib.oot_startup_context_initial_state(self.context, self.program.entry, byref(state)),
                'startup initial state failed')
        return state

    def begin(self, state):
        require(self.lib.oot_startup_dispatch_begin(self.dispatcher, byref(state), byref(self.report)) == READY,
                f'startup begin failed: {self.report.error}')

    def run(self, state, budget, sink=None):
        return self.lib.oot_startup_dispatch_run(self.dispatcher, byref(state), budget,
                                               cast(sink, c_void_p) if sink else None, None, byref(self.report))


def reference_trace(f, state, max_steps=1000):
    reference = Reference()
    reference.keys(KEYS)
    modules = f['linker'].modules
    for module in modules:
        reference.u.mem_map(module.base, len(module.image))
        reference.u.mem_write(module.base, bytes(module.image))
    reference.u.mem_map(f['config']['tls_base'], f['config']['tls_size'])
    reference.u.mem_write(STACK, bytes(STACK_SIZE))
    regions = [(r['base'], r['size']) for r in f['manifest']['regions']]
    regions.append((f['config']['tls_base'], f['config']['tls_size']))
    def memory():
        return {base: bytes(reference.u.mem_read(base, size)) for base, size in regions}
    states, memories = [State.from_buffer_copy(state)], [memory()]
    current = State.from_buffer_copy(state)
    for _ in range(max_steps):
        module = next(m for m in modules if m.is_code(current.pc-m.base))
        word = int.from_bytes(module.read(current.pc-module.base, 4), 'little')
        if word & 0xffe0001f == 0xd4000001:
            return states, memories
        current = reference.step(current, word)
        states.append(State.from_buffer_copy(current))
        memories.append(memory())
    raise ValueError('synthetic startup reference exceeded limit')


BAD_SOURCE = '''
static unsigned oot_start_bad_mode;
OOT_LIFT_EXPORT void oot_test_start_bad_set(unsigned mode) { oot_start_bad_mode = mode; }
OOT_LIFT_EXPORT int oot_test_start_bad(OotArm64State *s, OotGuestMemory *m, const OotPauth *p, uint64_t budget, uint64_t *n)
{
    const OotStartupProgram *program = oot_loop_compiled_program();
    size_t index;
    int status;
    for (index = 0; index < program->instruction_count; ++index)
        if (program->instructions[index].pc == s->pc) break;
    if (index == program->instruction_count || !program->instructions[index].run) return 777;
    status = program->instructions[index].run(s,m,p,budget,n);
    switch (oot_start_bad_mode) {
    case 1: *n = 0; break;
    case 2: s->pc += 4; break;
    case 3: status = 777; break;
    case 4: s->x[18] ^= 1; break;
    case 5: if (m->count) m->regions[0].data[0] ^= 1; break;
    case 6: m->valid = 0; break;
    case 7: m->regions = NULL; break;
    case 8: m->fault.reason = 1; break;
    }
    return status;
}
'''


def compile_validation(mode='cmake'):
    require(version('unicorn') == '2.1.4', 'pinned startup PAuth reference required')
    fixtures = {name: fixture(name) for name in ('loop', 'indirect', 'services', 'chunks')}
    source = '\n'.join(f['source'] for f in fixtures.values()) + BAD_SOURCE
    lib, build = compile_library([], mode, extra_source=source, startup=True)
    bindings(lib)
    lib.oot_test_start_bad_set.argtypes = [c_uint32]
    lib.oot_test_start_bad.restype = c_int
    return lib, build, fixtures


def run_validation(mode='cmake', compiled=None):
    lib, build, fixtures = compile_validation(mode) if compiled is None else compiled
    rng, whole, prefixes = random.Random(0xB007C0DE), 0, 0
    f = fixtures['loop']
    for key in range(2):
        for count in (0, 1, 2, 3, 8):
            for flags in range(16):
                for budget in (1, 3, 10000):
                    p, ins, spans = copied_program(lib, 'loop')
                    if key: p.entry = f['linker'].modules[0].base+0x40
                    session = Session(lib, f, build['directory'], (p, ins, spans))
                    try:
                        state = session.initial()
                        state.x[:] = [rng.getrandbits(64) for _ in range(31)]
                        state.x[1] = f['linker'].modules[0].base+0x2100+(count % 3)
                        state.x[2] = f['linker'].modules[0].base+0x2040+(count % 3)
                        state.x[3], state.x[30], state.nzcv = count, 0x1000000, flags << 28
                        start = State.from_buffer_copy(state)
                        states, memories = reference_trace(f, state)
                        events = []
                        @TRACE
                        def sink(row, _): events.append((row.contents.pc, row.contents.next_pc, row.contents.retired, row.contents.event))
                        session.begin(state)
                        require(session.run(state, 0, sink) == YIELDED and session.report.retired == 0 and not events,
                                'startup zero budget executed work')
                        for _ in range(300):
                            status = session.run(state, budget, sink)
                            n = session.report.retired
                            require(state.values() == states[n].values() and snapshot(lib, session.context) == memories[n],
                                    'startup full state or mapped bytes differ from reference prefix')
                            prefixes += 1
                            if status == STOPPED:
                                require(session.report.error == 9 and session.report.service == 0x7f and n == len(states)-1,
                                        'startup did not stop before unsupported service')
                                break
                            require(status == YIELDED and session.report.error == 0, 'startup prefix unexpectedly failed')
                        else: raise ValueError('startup synthetic run exceeded schedule')
                        require(state.sp == start.sp and state.x[29] == start.x[29] and state.x[30] == start.x[30],
                                'startup PAC frame did not restore independent state')
                        require(state.x[1] == start.x[1]+16*count and state.x[3] == 0, 'startup fill independent pointer/count mismatch')
                        source = memories[0][f['linker'].modules[0].base+0x2000]
                        offset = start.x[2]-(f['linker'].modules[0].base+0x2000)
                        formula = int.from_bytes(source[offset:offset+8], 'little') ^ int.from_bytes(source[offset+8:offset+16], 'little') if count else 0
                        require(state.x[0] == formula, 'startup independent result mismatch')
                        expected_fill = (start.x[4].to_bytes(8, 'little')+start.x[5].to_bytes(8, 'little'))*count
                        data = snapshot(lib, session.context)[f['linker'].modules[0].base+0x2000]
                        offset = start.x[1]-(f['linker'].modules[0].base+0x2000)
                        require(data[offset:offset+len(expected_fill)] == expected_fill, 'startup independent fill bytes mismatch')
                        before = state.values(), snapshot(lib, session.context), session.report.retired
                        require(session.run(state, 999) == STOPPED and (state.values(), snapshot(lib, session.context), session.report.retired) == before,
                                'startup stopped state was not idempotent')
                        require(events[-1][3] == 2 and len([e for e in events if e[3] == 0]) == n,
                                'startup trace retirement mismatch')
                        whole += 1
                    finally: session.close()
    report = dict(schema_version=1, result='passed', synthetic_only=True, game_code_executed=False,
                  whole_call_cases=whole, prefix_checks=prefixes, native_build=build,
                  reference=dict(unicorn=version('unicorn'), pauth_enabled=True))
    path = ROOT/f'build/lifter-validation/{mode}-startup-dispatch-report.json'
    path.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', choices=('cmake', 'gcc'), default='cmake')
    args = parser.parse_args()
    try:
        report = run_validation(args.compiler)
        print(json.dumps({key: report[key] for key in
                          ('result', 'whole_call_cases', 'prefix_checks', 'synthetic_only', 'game_code_executed')}))
        return 0
    except (InputError, OSError, ValueError) as error:
        print(f'Startup validation failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
