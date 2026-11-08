"""Synthetic original-body-bound native SDK calls and precise host boundaries."""
from ctypes import (POINTER, Structure, byref, c_int, c_size_t, c_uint8,
                    c_uint32, c_uint64, c_void_p, cast, create_string_buffer,
                    string_at)
import hashlib
import os
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from lifter_validation import compile_library
from pauth_validation import KEYS
from prepare_runtime import pack_regions
from prepare_startup import CONTEXT
from startup_validation import Config,Instruction,Program,Report,Span,State,TRACE,bindings,snapshot
from test_sdk_instructions import SdkConfig,SdkGoal

BASE,STACK=0x1000000,0x7000000000
ENTRY=BASE+64
STOP=0xd4200000


class NativeFunction(Structure):
    _fields_=[('version',c_uint32),('id',c_uint32),('entry',c_uint64),
              ('size',c_uint32),('sha256',c_uint8*32)]


SOURCE=r'''
#include "startup_dispatch.h"
OOT_LIFT_EXPORT int oot_native_test_value(OotArm64State *s,OotGuestMemory *m,
 const OotPauth *p,uint64_t budget,uint64_t *retired) {
 (void)m;(void)p;
 if(!s||!retired||budget!=1) return OOT_LIFT_MEMORY_FAULT;
 if(s->pc==UINT64_C(0x1000000)) s->x[0]=7;
 else if(s->pc==UINT64_C(0x1000008)) ++s->x[0];
 else return OOT_LIFT_MEMORY_FAULT;
 s->pc+=4;*retired=1;return OOT_LIFT_BUDGET;
}
OOT_LIFT_EXPORT int oot_native_test_call(OotArm64State *s,OotGuestMemory *m,
 const OotPauth *p,uint64_t budget,uint64_t *retired) {
 (void)m;(void)p;
 if(!s||!retired||budget!=1) return OOT_LIFT_MEMORY_FAULT;
 s->x[30]=s->pc+4;s->pc=UINT64_C(0x1000040);*retired=1;return OOT_LIFT_DISPATCH;
}
OOT_LIFT_EXPORT int oot_native_test_goal(OotArm64State *s,OotGuestMemory *m,
 const OotPauth *p,uint64_t budget,uint64_t *retired) {
 (void)m;(void)p;
 if(!s||!retired||budget!=1) return OOT_LIFT_MEMORY_FAULT;
 s->pc=UINT64_C(0x1000010);*retired=1;return OOT_LIFT_DISPATCH;
}
OOT_LIFT_EXPORT uint64_t oot_native_test_calls(OotStartupContext *c) {
 const OotSdkNative *n=oot_startup_context_native(c);return n?n->calls:0;
}
OOT_LIFT_EXPORT uint64_t oot_native_test_initializations(OotStartupContext *c) {
 const OotSdkNative *n=oot_startup_context_native(c);return n?n->logging_initializations:0;
}
'''


def branch(pc,target,link=False):
    return (0x94000000 if link else 0x14000000)|(((target-pc)//4)&0x3ffffff)


class Session:
    def __init__(self,test,goal=False,direct=False,handler=1,extra_rows=(),interior_branch=False,native=True):
        self.test,self.lib=test,test.lib
        self.error,self.report=c_uint32(),Report()
        self.dispatcher=self.context=self.keys=self.image=None
        words={0:0xd28000e0,4:branch(BASE+4,ENTRY+4 if interior_branch else ENTRY,True),
               8:0x91000400,12:branch(BASE+12,BASE+16) if goal else branch(BASE+12,ENTRY,True),
               16:STOP,64:0xd503237f,68:0xd65f03c0,72:STOP}
        data=bytearray(4096)
        for offset,word in words.items():struct.pack_into('<I',data,offset,word)
        module=SimpleNamespace(name='native_sdk',base=BASE,
            ranges=((0,4096),(4096,4096),(4096,4096)),bss_start=4096,bss_end=4096,image=data)
        blob,manifest=pack_regions([module],{'synthetic_raw':True},STACK,4096)
        path=Path(test.build['directory'])/'native-sdk-dispatch.ootmem';path.write_bytes(blob)
        message=create_string_buffer(192)
        self.image=self.lib.oot_runtime_open(os.fsencode(path),message,len(message))
        if not self.image:raise AssertionError(message.value)
        cfg=dict(CONTEXT,heap_capacity=0x200000)
        self.config=Config(**cfg)
        self.sdk=SdkConfig(version=1,flags=1|2|8|(128 if native else 0),
            entropy=(c_uint64*4)(1,2,3,4),core_mask=1,priority_mask=(1<<64)-1,
            aslr_base=0,aslr_size=1<<39,alias_base=0x5000000000,alias_size=0x200000,
            program_id=0x1000,is_application=1,
            total_memory=manifest['backing_bytes']+cfg['tls_size']+cfg['heap_capacity'],
            main_thread_id=1,main_thread_priority=44,main_thread_core=0)
        self.context=self.lib.oot_startup_context_create_sdk(self.image,byref(self.config),byref(self.sdk),byref(self.error))
        if not self.context:raise AssertionError(self.error.value)
        self.keys=self.lib.oot_pauth_create(1,(c_uint64*4)(*KEYS))
        if not self.keys:raise AssertionError('PAC context allocation failed')
        rows=[]
        for offset in sorted(set([0,4,8,12,16,64,*extra_rows])):
            pc=BASE+offset;word=words[offset]
            kind,a,b,callback=4,pc,pc,None
            if offset in (0,8):kind,a,b,callback=0,pc+4,pc+4,self.lib.oot_native_test_value
            elif offset in (4,12):
                target=(ENTRY+4 if interior_branch else ENTRY) if offset==4 else (BASE+16 if goal else ENTRY)
                kind,a,b,callback=1,target,target,self.lib.oot_native_test_goal if goal and offset==12 else self.lib.oot_native_test_call
            rows.append(Instruction(pc,word,kind,a,b,cast(callback,c_void_p).value if callback else None))
        self.instructions=(Instruction*len(rows))(*rows)
        span_bytes=max(row.pc-BASE for row in rows)+4
        self.spans=(Span*1)(Span(BASE,span_bytes,(c_uint8*32).from_buffer_copy(hashlib.sha256(data[:span_bytes]).digest())))
        self.program=Program(1,7 if native else 3,ENTRY if direct else BASE,
            (c_uint8*32).from_buffer_copy(bytes.fromhex(manifest['body_sha256'])),
            self.instructions,len(rows),self.spans,1)
        self.function=NativeFunction(1,handler,ENTRY,8,
            (c_uint8*32).from_buffer_copy(hashlib.sha256(data[64:72]).digest()))
        self.data,self.words=data,words

    def create(self,limit=1000,mode='native'):
        self.dispatcher=getattr(self.lib,'oot_startup_dispatch_create'+('_'+mode if mode else ''))(
            self.image,self.context,self.keys,byref(self.program),limit,byref(self.error))
        return self.dispatcher

    def bind(self,functions=None,count=1):
        return self.lib.oot_startup_dispatch_set_native_functions(self.dispatcher,
            byref(self.function) if functions is None else functions,count,byref(self.error))

    def initial(self):
        s=State()
        assert self.lib.oot_startup_context_initial_state(self.context,self.program.entry,byref(s))
        for n in range(31):s.x[n]=0x1234000000000000+n
        s.x[30]=BASE+16;s.nzcv=0xa0000000
        return s

    def begin(self,state):return self.lib.oot_startup_dispatch_begin(self.dispatcher,byref(state),byref(self.report))
    def run(self,state,budget,sink=None):
        return self.lib.oot_startup_dispatch_run(self.dispatcher,byref(state),budget,
            cast(sink,c_void_p) if sink else None,None,byref(self.report))
    def close(self):
        if self.dispatcher:self.lib.oot_startup_dispatch_destroy(self.dispatcher)
        if self.keys:self.lib.oot_pauth_destroy(self.keys)
        if self.context:self.lib.oot_startup_context_destroy(self.context)
        if self.image:self.lib.oot_runtime_close(self.image)
        self.dispatcher=self.context=self.keys=self.image=None


class NativeSdkDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib,cls.build=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),SOURCE,startup=True)
        bindings(cls.lib)
        signature={
            'oot_startup_context_create_sdk':([c_void_p,POINTER(Config),POINTER(SdkConfig),POINTER(c_uint32)],c_void_p),
            'oot_startup_dispatch_create_sdk':([c_void_p,c_void_p,c_void_p,POINTER(Program),c_uint64,POINTER(c_uint32)],c_void_p),
            'oot_startup_dispatch_create_native':([c_void_p,c_void_p,c_void_p,POINTER(Program),c_uint64,POINTER(c_uint32)],c_void_p),
            'oot_startup_dispatch_set_native_functions':([c_void_p,POINTER(NativeFunction),c_size_t,POINTER(c_uint32)],c_int),
            'oot_startup_dispatch_native_calls':([c_void_p],c_uint64),
            'oot_startup_dispatch_set_sdk_goal':([c_void_p,POINTER(SdkGoal),POINTER(c_uint32)],c_int),
            'oot_startup_dispatch_sdk_stages_completed':([c_void_p],c_uint32),
            'oot_startup_context_native_call':([c_void_p,c_uint32,POINTER(State),c_void_p],c_int),
            'oot_native_test_calls':([c_void_p],c_uint64),
            'oot_native_test_initializations':([c_void_p],c_uint64),
        }
        for name,(arguments,result) in signature.items():
            f=getattr(cls.lib,name);f.argtypes,f.restype=arguments,result

    def session(self,**kw):
        s=Session(self,**kw);self.addCleanup(s.close);return s

    def test_native_events_preserve_all_state_and_original_retirement_across_prefixes(self):
        for quantum in (1,2,3,100):
            s=self.session();self.assertTrue(s.create());self.assertTrue(s.bind())
            state=s.initial();expected=[State.from_buffer_copy(state)]
            # The native calls return directly without executing PAC or RET.
            for operation in ('mov','bl','native','add','bl','native'):
                next_state=State.from_buffer_copy(expected[-1])
                if operation=='mov':next_state.x[0]=7;next_state.pc+=4
                elif operation=='add':next_state.x[0]+=1;next_state.pc+=4
                elif operation=='bl':next_state.x[30]=next_state.pc+4;next_state.pc=ENTRY
                else:next_state.pc=next_state.x[30]
                expected.append(next_state)
            self.assertEqual(s.begin(state),0);before=snapshot(self.lib,s.context)
            events=[]
            @TRACE
            def trace(row,_):
                r=row.contents;events.append((r.pc,r.next_pc,r.retired,r.word,r.event,r.error,r.service))
            for _ in range(10):
                status=s.run(state,quantum,trace)
                calls=self.lib.oot_startup_dispatch_native_calls(s.dispatcher)
                self.assertEqual(state.values(),expected[s.report.retired+calls].values())
                self.assertEqual(snapshot(self.lib,s.context),before)
                if status==2:break
                self.assertEqual(status,1)
            else:self.fail('native SDK synthetic program did not stop')
            self.assertEqual((s.report.retired,calls,s.report.error),(4,2,8))
            self.assertEqual(self.lib.oot_native_test_initializations(s.context),2)
            self.assertEqual([r[4] for r in events],[0,0,3,0,0,3,2])
            self.assertEqual([r[2] for r in events],[1,2,2,3,4,4,4])
            self.assertEqual([r[6] for r in events if r[4]==3],[1,1])
            self.assertEqual(events[2][3],0xd503237f)

    def test_work_quota_counts_native_calls_without_original_retirement(self):
        for limit,retired,calls,pc in ((1,1,0,BASE+4),(2,2,0,ENTRY),(3,2,1,BASE+8),
                (4,3,1,BASE+12),(5,4,1,ENTRY),(6,4,2,BASE+16)):
            s=self.session();self.assertTrue(s.create(limit));self.assertTrue(s.bind());state=s.initial()
            self.assertEqual(s.begin(state),0);self.assertEqual(s.run(state,100),2)
            self.assertEqual((s.report.error,s.report.retired,self.lib.oot_startup_dispatch_native_calls(s.dispatcher),state.pc),
                (12,retired,calls,pc))
        s=self.session();self.assertTrue(s.create());state=s.initial()
        self.assertEqual(s.begin(state),3);self.assertEqual(s.report.error,17)
        self.assertTrue(s.bind());self.assertEqual(s.begin(state),0)
        before=state.values();self.assertEqual(s.run(state,0),1)
        self.assertEqual(state.values(),before)

    def test_copied_bindings_lifetimes_and_body_hashes(self):
        s=self.session();self.assertTrue(s.create());self.assertTrue(s.bind())
        s.function.id,s.function.entry,s.function.sha256[0]=31,BASE,0
        context=s.context;self.lib.oot_startup_context_destroy(s.context);s.context=None
        self.lib.oot_runtime_close(s.image);s.image=None
        self.lib.oot_pauth_destroy(s.keys);s.keys=None
        state=s.initial() if s.context else State()
        state.pc=BASE;state.sp=STACK+4096
        self.assertEqual(s.begin(state),0);self.assertEqual(s.run(state,100),2)
        self.assertEqual((s.report.error,self.lib.oot_startup_dispatch_native_calls(s.dispatcher)),(8,2))
        self.assertEqual(self.lib.oot_native_test_initializations(context),2)
        s=self.session();self.assertTrue(s.create());self.assertTrue(s.bind());state=s.initial()
        self.assertEqual(s.begin(state),0)
        memory=self.lib.oot_runtime_memory(s.image).contents
        memory.regions[0].data[68]^=1
        before=state.values();self.assertEqual(s.run(state,100),2)
        self.assertEqual((s.report.error,state.values(),self.lib.oot_native_test_calls(s.context)),(4,before,0))
        # Even a trusted trace sink cannot change the unselected function body
        # between BL and interception within one quantum without detection.
        s=self.session();self.assertTrue(s.create());self.assertTrue(s.bind());state=s.initial()
        self.assertEqual(s.begin(state),0)
        memory=self.lib.oot_runtime_memory(s.image).contents
        @TRACE
        def changed_body(row,_):
            if row.contents.pc==BASE+4:memory.regions[0].data[68]^=1
        self.assertEqual(s.run(state,100,changed_body),2)
        self.assertEqual((s.report.error,s.report.retired,self.lib.oot_native_test_calls(s.context)),(4,2,0))

    def test_bad_native_metadata_and_old_constructor_profiles_are_rejected(self):
        for field,value in (('version',2),('id',2),('entry',ENTRY+1),('size',0),('size',7),('size',65540),('entry',1<<39)):
            s=self.session();self.assertTrue(s.create());setattr(s.function,field,value)
            self.assertFalse(s.bind());self.assertEqual(s.error.value,17)
        s=self.session();self.assertTrue(s.create());s.function.sha256[0]^=1
        self.assertFalse(s.bind());self.assertEqual(s.error.value,4)
        s=self.session();self.assertTrue(s.create())
        overlap=(NativeFunction*2)(s.function,s.function)
        self.assertFalse(s.bind(overlap,2));self.assertEqual(s.error.value,17)
        for mode,flags,native in (('',1,True),('sdk',3,True),('sdk',7,True),('native',3,True),('native',7,False)):
            s=self.session(native=native);s.program.flags=flags
            self.assertFalse(s.create(mode=mode));self.assertEqual(s.error.value,1)
        s=self.session(native=False);self.assertTrue(s.create(mode='sdk'))
        self.assertFalse(s.bind());self.assertEqual(s.error.value,17)

    def test_invalid_returns_interiors_guards_and_handler_faults_have_no_effect(self):
        for target in (0,BASE+1,(1<<39),0xffffffffffffffff,BASE+32,ENTRY):
            s=self.session(direct=True);self.assertTrue(s.create());self.assertTrue(s.bind())
            state=s.initial();state.x[30]=target;before=state.values();self.assertEqual(s.begin(state),0)
            self.assertEqual(s.run(state,100),2)
            self.assertEqual((s.report.error,s.report.retired,self.lib.oot_startup_dispatch_native_calls(s.dispatcher)),(10,0,0))
            self.assertEqual(state.values(),before);self.assertEqual(self.lib.oot_native_test_calls(s.context),0)
        s=self.session(direct=True,extra_rows=(68,));self.assertTrue(s.create());self.assertTrue(s.bind())
        state=s.initial();state.x[30]=ENTRY+4;self.assertEqual(s.begin(state),0);self.assertEqual(s.run(state,1),2)
        self.assertEqual((s.report.error,self.lib.oot_native_test_calls(s.context)),(18,0))
        s=self.session(interior_branch=True,extra_rows=(68,));self.assertTrue(s.create());self.assertTrue(s.bind())
        state=s.initial();self.assertEqual(s.begin(state),0);self.assertEqual(s.run(state,100),2)
        self.assertEqual((s.report.error,s.report.retired,state.x[30]),(18,1,BASE+16))
        for handler,error in ((31,9),(5,19)):
            s=self.session(direct=True,handler=handler);self.assertTrue(s.create());self.assertTrue(s.bind())
            if handler==5:
                initial=s.initial();self.assertEqual(self.lib.oot_startup_context_native_call(s.context,1,byref(initial),None),0)
            state=s.initial();state.x[0]=0;state.x[1]=0;before=state.values();memory=snapshot(self.lib,s.context)
            self.assertEqual(s.begin(state),0);self.assertEqual(s.run(state,100),2)
            self.assertEqual((s.report.error,s.report.service,s.report.retired),(error,handler,0))
            self.assertEqual(state.values(),before);self.assertEqual(snapshot(self.lib,s.context),memory)
            self.assertEqual(self.lib.oot_native_test_calls(s.context),int(handler==5))

    def test_goal_entries_cannot_be_satisfied_or_covered_by_native_functions(self):
        for binding_first in (False,True):
            s=self.session(goal=True,extra_rows=(68,));self.assertTrue(s.create())
            stages=(c_uint64*2)(BASE,BASE+8)
            goal=SdkGoal(1,2,BASE+12,BASE+16,s.words[12],stages)
            if binding_first:self.assertTrue(s.bind())
            self.assertTrue(self.lib.oot_startup_dispatch_set_sdk_goal(s.dispatcher,byref(goal),byref(s.error)))
            if not binding_first:self.assertTrue(s.bind())
            bad_stages=(c_uint64*2)(BASE,ENTRY+4)
            bad=SdkGoal(1,2,BASE+12,BASE+16,s.words[12],bad_stages)
            self.assertFalse(self.lib.oot_startup_dispatch_set_sdk_goal(s.dispatcher,byref(bad),byref(s.error)))
            self.assertEqual(s.error.value,16)
            state=s.initial();self.assertEqual(s.begin(state),0);self.assertEqual(s.run(state,100),2)
            self.assertEqual((s.report.error,s.report.retired,self.lib.oot_startup_dispatch_native_calls(s.dispatcher)),(15,4,1))
            self.assertEqual(self.lib.oot_startup_dispatch_sdk_stages_completed(s.dispatcher),2)
        s=self.session(goal=True,extra_rows=(68,));self.assertTrue(s.create())
        stages=(c_uint64*2)(BASE,ENTRY+4)
        goal=SdkGoal(1,2,BASE+12,BASE+16,s.words[12],stages)
        self.assertTrue(self.lib.oot_startup_dispatch_set_sdk_goal(s.dispatcher,byref(goal),byref(s.error)))
        self.assertFalse(s.bind());self.assertEqual(s.error.value,17)

    def test_reentry_state_checks_and_image_replay_remain_closed(self):
        s=self.session();self.assertTrue(s.create());self.assertTrue(s.bind());state=s.initial()
        self.assertEqual(s.begin(state),0);attempts=[]
        @TRACE
        def trace(row,_):
            if row.contents.event!=3:return
            error=c_uint32();report=Report();copy=State.from_buffer_copy(state)
            attempts.append(self.lib.oot_startup_dispatch_set_native_functions(s.dispatcher,byref(s.function),1,byref(error)))
            attempts.append(error.value)
            attempts.append(self.lib.oot_startup_dispatch_run(s.dispatcher,byref(copy),1,None,None,byref(report)))
            attempts.append(report.error)
            attempts.append(self.lib.oot_startup_dispatch_destroy(s.dispatcher))
        self.assertEqual(s.run(state,3,trace),1)
        self.assertEqual(attempts,[0,6,3,6,0])
        tampered=State.from_buffer_copy(state);tampered.x[18]^=1
        self.assertEqual(s.run(tampered,1),3);self.assertEqual(s.report.error,5)
        self.assertEqual(self.lib.oot_startup_dispatch_native_calls(s.dispatcher),1)
        self.assertTrue(self.lib.oot_startup_dispatch_abort(s.dispatcher))
        state=s.initial();self.assertEqual(s.begin(state),3);self.assertEqual(s.report.error,3)


if __name__=='__main__':unittest.main()
