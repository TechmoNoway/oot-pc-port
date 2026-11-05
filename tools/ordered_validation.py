"""Independent values/faults, native inter-thread publication, and raw PAC frames."""

import argparse
from ctypes import POINTER, byref, c_uint32, c_uint64, c_void_p, cast
from importlib.metadata import version
import json
from pathlib import Path
import struct

from input_formats import require
from lifter_validation import compile_library
from lifter_validation_types import BASE, Memory, Program, RegionSpec, State
from memory_validation import initialize_native_memory, validate_memory_program
from ordered_programs import DATA, ordered_programs, rcpc
from pauth_lifter import emit_pauth_c
from pauth_validation import KEYS, Reference, bindings as pauth_bindings, STACK, EXIT

ROOT=Path(__file__).resolve().parent.parent


def policy_checks(lib):
    load=lib.oot_memory_load_rcpc
    load.argtypes,load.restype=[POINTER(Memory),c_uint64,c_uint32,c_uint32,POINTER(c_uint64)],c_uint32
    checks=0
    def attempt(specs,address,width,sp,reason,failing=None):
        nonlocal checks
        memory,table,buffers=initialize_native_memory(lib,specs);value=c_uint64(0x123456789ABCDEF0)
        before=[bytes(b) for b in buffers]
        result=load(byref(memory),address,width,sp,byref(value))
        require(result==0 and value.value==0x123456789ABCDEF0 and before==[bytes(b) for b in buffers] and
                memory.fault.values()==(address,address if failing is None else failing,width,1,reason),"ordered policy fault mutated output/backing or diagnostics")
        checks+=1
    for width in (2,4,8):
        for offset in range(1,width):attempt((RegionSpec(DATA,bytes(32)),),DATA+offset,width,0,5)
    for width in (1,2,4,8):
        attempt((RegionSpec(DATA,bytes(32)),),DATA+8,width,1,5)
        attempt((RegionSpec(DATA,b"\x01\x02\x03"),RegionSpec(DATA+3,bytes(5),2)),DATA,8,0,2,DATA+3)
    for width,sp in ((0,0),(3,0),(16,0),(8,2)):
        attempt((),DATA,width,sp,4)
    memory,table,buffers=initialize_native_memory(lib,(RegionSpec(DATA,b"\x01\x02\x03"),RegionSpec(DATA+3,b"\x04\x05\x06\x07\x08")))
    value=c_uint64()
    require(load(byref(memory),DATA,8,0,byref(value))==1 and value.value==0x0807060504030201,"ordered cross-region LE load failed")
    require(load(byref(memory),DATA+1,8,0,byref(value))==0 and memory.fault.reason==5,"ordered alignment precondition ignored")
    require(load(byref(memory),DATA,8,0,byref(value))==1 and memory.fault.reason==0,"ordered retry did not clear stale fault")
    before=value.value
    require(load(None,DATA,8,0,byref(value))==0 and value.value==before,"null ordered memory changed output")
    require(load(byref(memory),DATA,8,0,None)==0 and memory.fault.reason==4,"null ordered output accepted")
    invalid=Memory()
    require(load(byref(invalid),DATA+1,8,0,byref(value))==0 and invalid.fault.reason==4,
            "invalid ordered view must reject configuration before address alignment")
    return checks+6


def pac_checks(lib):
    pauth_bindings(lib)
    key_data=(c_uint64*4)(*KEYS);context=lib.oot_pauth_create(1,key_data)
    require(context,"ordered PAC context allocation failed")
    reference=Reference();reference.keys(KEYS);reference.u.mem_map(DATA,4096)
    cases=prefixes=0
    try:
        for size in range(4):
            words=[0xD503237F,0xA9BF7BFD,0x910003FD,rcpc(size),0xA8C17BFD,0xD65F0FFF]
            reference.code(struct.pack('<6I',*words))
            fn=getattr(lib,f"oot_pauth_lift_ordered{size}")
            fn.argtypes,fn.restype=[POINTER(State),POINTER(Memory),c_void_p,c_uint64,POINTER(c_uint64)],c_uint32
            for offset in (0,16,256,4080):
                data=bytes(range(256))*16;reference.u.mem_write(DATA,data);reference.u.mem_write(STACK,bytes(4096))
                memory,table,buffers=initialize_native_memory(lib,(RegionSpec(DATA,data,1),RegionSpec(STACK,bytes(4096))))
                actual=State();actual.x[:]=[0xA5A5A5A5A5A5A5A5]*31
                actual.pc,actual.sp,actual.x[30],actual.x[1],actual.nzcv=BASE,STACK+0x800,EXIT,DATA+offset,0xF0000000
                expected=State.from_buffer_copy(actual)
                for word in words:
                    expected=reference.step(expected,word);count=c_uint64()
                    status=fn(byref(actual),byref(memory),context,1,byref(count))
                    require(status==(0 if word==words[-1] else 1) and count.value==1 and actual.values()==expected.values() and
                            bytes(buffers[1])==bytes(reference.u.mem_read(STACK,4096)),"ordered PAC frame prefix differs from reference")
                    prefixes+=1
                require(actual.x[0]==int.from_bytes(data[offset:offset+(1<<size)],'little'),"ordered PAC independent value mismatch")
                cases+=1
            # An acquire fault preserves the retired signed frame and resumes at the load.
            memory,table,buffers=initialize_native_memory(lib,(RegionSpec(DATA,bytes(4096),2),RegionSpec(STACK,bytes(4096))))
            actual=State();actual.pc,actual.sp,actual.x[30],actual.x[1]=BASE,STACK+0x800,EXIT,DATA
            count=c_uint64()
            require(fn(byref(actual),byref(memory),context,32,byref(count))==2 and count.value==3 and actual.pc==BASE+12 and memory.fault.reason==2,
                    "ordered fault did not preserve retired PAC/frame prefix")
            before=actual.values();backing=[bytes(b) for b in buffers]
            require(fn(byref(actual),byref(memory),context,32,byref(count))==2 and count.value==0 and actual.values()==before and backing==[bytes(b) for b in buffers],
                    "ordered PAC fault retry repeated signing or mutated memory")
            table[0].permissions=1
            require(lib.oot_memory_init(byref(memory),table,len(table))==1,"ordered permission repair must reinitialize the quiescent view")
            require(fn(byref(actual),byref(memory),context,32,byref(count))==0 and count.value==3 and actual.pc==EXIT and actual.sp==STACK+0x800,
                    "ordered PAC frame did not resume after permission repair")
            cases+=1
    finally:lib.oot_pauth_destroy(context)
    return cases,prefixes


def run_validation(mode='cmake'):
    require(version('unicorn')=='2.1.4','pinned ordered-load reference required')
    programs=ordered_programs()+[Program(f'ordered_reader{s}',[rcpc(s)],[],memory=True) for s in range(4)]
    source='#define OOT_ORDERED_STRESS_SHARED\n#include "'+(ROOT/'tests/ordered_memory_test.c').as_posix()+'"\n'
    for size in range(4):
        words=[0xD503237F,0xA9BF7BFD,0x910003FD,rcpc(size),0xA8C17BFD,0xD65F0FFF]
        source+=emit_pauth_c(struct.pack('<6I',*words),BASE,f'oot_pauth_lift_ordered{size}')[0]
    lib,build=compile_library(programs,mode,source)
    comparisons=sum(validate_memory_program(lib,p) for p in programs)
    policy=policy_checks(lib);pac,prefixes=pac_checks(lib)
    stress=lib.oot_ordered_memory_stress;stress.argtypes,stress.restype=[c_void_p,c_uint64,c_uint32,c_uint32],c_uint32
    for size in range(4):
        reader=cast(getattr(lib,f'oot_lift_ordered_reader{size}'),c_void_p)
        require(stress(reader,BASE,1<<size,10000)==1,'native generated RCpc publication/atomicity stress failed')
    report={'schema_version':1,'result':'passed','game_code_executed':False,
            'model':'serialized-normal-memory-aligned-rcpc-v1','state_abi_version':2,
            'reference':{'engine':'Unicorn','version':version('unicorn'),'cpu':'MAX','required_feature':'FEAT_LRCPC'},
            'value_fault_comparisons':comparisons,'policy_checks':policy,'pac_frame_cases':pac,'pac_prefix_checks':prefixes,
            'native_publication_rounds':40000,'native_scalar_atomicity_rounds':40000,'native_pair_atomicity_rounds':40000,
            'weak_memory_outcome_equivalence_claimed':False,'native_build':build}
    path=Path(build['directory'])/'ordered-report.json';path.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return report,path


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--compiler',choices=('cmake','gcc'),default='cmake')
    report,path=run_validation(parser.parse_args().compiler)
    print(json.dumps({k:v for k,v in report.items() if k!='native_build'},indent=2));print(path)
