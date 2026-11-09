"""Synthetic initialization profile: large bound registries and original goals."""

from ctypes import (POINTER, byref, c_int, c_size_t, c_uint8, c_uint32, c_uint64,
                    c_void_p, cast, create_string_buffer)
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
from test_native_sdk_dispatch import NativeFunction,branch

BASE,STACK=0x1000000,0x7000000000
ENTRY=BASE+256
STOP=0xd4200000

SOURCE=r'''
#include "startup_dispatch.h"
OOT_LIFT_EXPORT int oot_init_test_call(OotArm64State *s,OotGuestMemory *m,
 const OotPauth *p,uint64_t budget,uint64_t *retired) {
 uint64_t target;
 (void)m;(void)p;
 if(!s||!retired||budget!=1) return OOT_LIFT_MEMORY_FAULT;
 switch(s->pc) {
 case UINT64_C(0x1000000):target=UINT64_C(0x1000100);break;
 case UINT64_C(0x1000008):target=UINT64_C(0x1000108);break;
 case UINT64_C(0x100000c):target=UINT64_C(0x1000110);break;
 case UINT64_C(0x1000010):target=UINT64_C(0x1000118);break;
 default:return OOT_LIFT_MEMORY_FAULT;
 }
 s->x[30]=s->pc+4;s->pc=target;*retired=1;return OOT_LIFT_DISPATCH;
}
OOT_LIFT_EXPORT int oot_init_test_tail(OotArm64State *s,OotGuestMemory *m,
 const OotPauth *p,uint64_t budget,uint64_t *retired) {
 (void)m;(void)p;
 if(!s||!retired||budget!=1) return OOT_LIFT_MEMORY_FAULT;
 s->pc=UINT64_C(0x1000100);*retired=1;return OOT_LIFT_DISPATCH;
}
OOT_LIFT_EXPORT int oot_init_test_move(OotArm64State *s,OotGuestMemory *m,
 const OotPauth *p,uint64_t budget,uint64_t *retired) {
 (void)m;(void)p;
 if(!s||!retired||budget!=1) return OOT_LIFT_MEMORY_FAULT;
 s->x[0]=1;s->pc+=4;*retired=1;return OOT_LIFT_BUDGET;
}
OOT_LIFT_EXPORT int oot_init_test_goal(OotArm64State *s,OotGuestMemory *m,
 const OotPauth *p,uint64_t budget,uint64_t *retired) {
 (void)m;(void)p;
 if(!s||!retired||budget!=1) return OOT_LIFT_MEMORY_FAULT;
 s->pc=UINT64_C(0x1000014);*retired=1;return OOT_LIFT_DISPATCH;
}
OOT_LIFT_EXPORT uint64_t oot_init_test_state(OotStartupContext *c,unsigned field) {
 const OotNativePlatform *p=oot_startup_context_platform(c);
 const OotSdkNative *n=oot_startup_context_native(c);
 if(!p||!n)return UINT64_MAX;
 switch(field){case 0:return p->initialized;case 1:return p->cpu_boost_mode;
 case 2:return p->initialization_calls;case 3:return p->queries;
 case 4:return n->calls;default:return p->generations;}
}
'''


class InitSession:
    def __init__(self,test,guard=False,tail=False,extra_rows=(),enabled=True,interior=False):
        self.test,self.lib=test,test.lib
        self.error,self.report=c_uint32(),Report()
        self.dispatcher=self.context=self.keys=self.image=None
        words={0:branch(BASE,ENTRY+4 if interior else ENTRY,not tail),4:0x52800020,
            8:branch(BASE+8,ENTRY+8,True),12:branch(BASE+12,ENTRY+16,True),
            16:branch(BASE+16,ENTRY+24,True) if guard else branch(BASE+16,BASE+20),20:STOP}
        data=bytearray(65536)
        for offset in range(256,len(data),8):struct.pack_into('<II',data,offset,0xd503237f,0xd65f03c0)
        for offset,word in words.items():struct.pack_into('<I',data,offset,word)
        module=SimpleNamespace(name='sdk_init',base=BASE,
            ranges=((0,len(data)),(len(data),len(data)),(len(data),len(data))),
            bss_start=len(data),bss_end=len(data),image=data)
        blob,manifest=pack_regions([module],{'synthetic_raw':True},STACK,4096)
        path=Path(test.build['directory'])/'sdk-init-dispatch.ootmem';path.write_bytes(blob)
        message=create_string_buffer(192)
        self.image=self.lib.oot_runtime_open(os.fsencode(path),message,len(message))
        if not self.image:raise AssertionError(message.value)
        cfg=dict(CONTEXT,heap_capacity=0x200000)
        self.config=Config(**cfg)
        self.sdk=SdkConfig(version=1,flags=1|2|8|128|(256 if enabled else 0),
            entropy=(c_uint64*4)(1,2,3,4),core_mask=1,priority_mask=(1<<64)-1,
            aslr_base=0,aslr_size=1<<39,alias_base=0x5000000000,alias_size=0x200000,
            program_id=0x1000,is_application=1,
            total_memory=manifest['backing_bytes']+cfg['tls_size']+cfg['heap_capacity'],
            main_thread_id=1,main_thread_priority=44,main_thread_core=0)
        self.context=self.lib.oot_startup_context_create_sdk(self.image,byref(self.config),byref(self.sdk),byref(self.error))
        if not self.context:raise AssertionError(self.error.value)
        self.keys=self.lib.oot_pauth_create(1,(c_uint64*4)(*KEYS))
        if not self.keys:raise AssertionError('PAC allocation failed')
        rows=[]
        for offset in sorted(set([0,4,8,12,16,20,*extra_rows])):
            pc=BASE+offset;word=struct.unpack_from('<I',data,offset)[0]
            kind,a,b,callback=4,pc,pc,None
            if offset==4:kind,a,b,callback=0,pc+4,pc+4,self.lib.oot_init_test_move
            elif offset in (0,8,12,16):
                target=(ENTRY+4 if interior else ENTRY) if offset==0 else (
                    ENTRY+8 if offset==8 else ENTRY+16 if offset==12 else ENTRY+24 if guard else BASE+20)
                callback=self.lib.oot_init_test_tail if tail and offset==0 else (
                    self.lib.oot_init_test_goal if offset==16 and not guard else self.lib.oot_init_test_call)
                kind,a,b=1,target,target
            rows.append(Instruction(pc,word,kind,a,b,cast(callback,c_void_p).value if callback else None))
        self.instructions=(Instruction*len(rows))(*rows)
        spans=[Span(BASE,24,(c_uint8*32).from_buffer_copy(hashlib.sha256(data[:24]).digest()))]
        for offset in sorted(set(extra_rows)):
            if offset>=24:spans.append(Span(BASE+offset,4,(c_uint8*32).from_buffer_copy(hashlib.sha256(data[offset:offset+4]).digest())))
        self.spans=(Span*len(spans))(*spans)
        self.program=Program(1,15 if enabled else 7,BASE,
            (c_uint8*32).from_buffer_copy(bytes.fromhex(manifest['body_sha256'])),
            self.instructions,len(rows),self.spans,len(spans))
        self.data,self.words=data,words
        self.functions=self.make_functions(4 if guard else 3)

    def make_functions(self,count):
        functions=(NativeFunction*count)()
        for n in range(count):
            entry=ENTRY+n*8
            functions[n]=NativeFunction(1,(64,69,68)[n] if n<3 else 31,entry,8,
                (c_uint8*32).from_buffer_copy(hashlib.sha256(self.data[entry-BASE:entry-BASE+8]).digest()))
        return functions

    def create(self,limit=1000,mode='init'):
        self.dispatcher=getattr(self.lib,'oot_startup_dispatch_create'+('_'+mode if mode else ''))(
            self.image,self.context,self.keys,byref(self.program),limit,byref(self.error))
        return self.dispatcher

    def bind(self,functions=None,count=None):
        functions=self.functions if functions is None else functions
        return self.lib.oot_startup_dispatch_set_native_functions(self.dispatcher,
            functions,len(functions) if count is None else count,byref(self.error))

    def initial(self):
        s=State();assert self.lib.oot_startup_context_initial_state(self.context,BASE,byref(s))
        for n in range(31):s.x[n]=0x1234000000000000+n
        s.x[30]=BASE+20;s.nzcv=0xa0000000
        return s

    def goal(self,stages=None):
        stages=(c_uint64*2)(BASE,BASE+4) if stages is None else stages
        goal=SdkGoal(1,len(stages),BASE+16,BASE+20,self.words[16],stages)
        return self.lib.oot_startup_dispatch_set_sdk_goal(self.dispatcher,byref(goal),byref(self.error))

    def begin(self,state):return self.lib.oot_startup_dispatch_begin(self.dispatcher,byref(state),byref(self.report))
    def run(self,state,budget,sink=None):
        return self.lib.oot_startup_dispatch_run(self.dispatcher,byref(state),budget,
            cast(sink,c_void_p) if sink else None,None,byref(self.report))
    def provider(self):return tuple(self.lib.oot_init_test_state(self.context,n) for n in range(6))
    def close(self):
        if self.dispatcher:self.lib.oot_startup_dispatch_destroy(self.dispatcher)
        if self.keys:self.lib.oot_pauth_destroy(self.keys)
        if self.context:self.lib.oot_startup_context_destroy(self.context)
        if self.image:self.lib.oot_runtime_close(self.image)
        self.dispatcher=self.context=self.keys=self.image=None


class SdkInitDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib,cls.build=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),SOURCE,startup=True)
        bindings(cls.lib)
        signatures={
            'oot_startup_context_create_sdk':([c_void_p,POINTER(Config),POINTER(SdkConfig),POINTER(c_uint32)],c_void_p),
            **{'oot_startup_dispatch_create_'+name:([c_void_p,c_void_p,c_void_p,POINTER(Program),c_uint64,POINTER(c_uint32)],c_void_p)
                for name in ('sdk','native','init')},
            'oot_startup_dispatch_set_native_functions':([c_void_p,POINTER(NativeFunction),c_size_t,POINTER(c_uint32)],c_int),
            'oot_startup_dispatch_native_calls':([c_void_p],c_uint64),
            'oot_startup_dispatch_set_sdk_goal':([c_void_p,POINTER(SdkGoal),POINTER(c_uint32)],c_int),
            'oot_startup_dispatch_sdk_stages_completed':([c_void_p],c_uint32),
            'oot_startup_context_handler_valid':([c_void_p,c_uint32],c_int),
            'oot_startup_context_returns_value':([c_void_p,c_uint32],c_int),
            'oot_init_test_state':([c_void_p,c_uint32],c_uint64)}
        for name,(arguments,result) in signatures.items():
            function=getattr(cls.lib,name);function.argtypes,function.restype=arguments,result

    def session(self,**kw):
        session=InitSession(self,**kw);self.addCleanup(session.close);return session

    def test_unselected_whole_functions_and_scalar_getters_reach_original_goal(self):
        for quantum in (1,2,3,100):
            s=self.session();self.assertTrue(s.create());self.assertTrue(s.bind());self.assertTrue(s.goal())
            state=s.initial();initial=State.from_buffer_copy(state);events=[]
            @TRACE
            def trace(row,_):
                r=row.contents;events.append((r.pc,r.next_pc,r.retired,r.event,r.service))
            self.assertEqual(s.begin(state),0);before=snapshot(self.lib,s.context)
            for _ in range(12):
                status=s.run(state,quantum,trace)
                self.assertEqual(snapshot(self.lib,s.context),before)
                if status==2:break
                self.assertEqual(status,1)
            else:self.fail('synthetic initialization goal did not stop')
            self.assertEqual((s.report.error,s.report.retired,state.pc,state.x[0]),(15,5,BASE+20,1))
            self.assertEqual(s.provider(),(1,1,1,1,3,1))
            self.assertEqual(self.lib.oot_startup_dispatch_native_calls(s.dispatcher),3)
            self.assertEqual(self.lib.oot_startup_dispatch_sdk_stages_completed(s.dispatcher),2)
            self.assertEqual([event[3] for event in events],[0,3,0,0,3,0,3,0,2])
            for n in range(1,30):self.assertEqual(state.x[n],initial.x[n])
            self.assertEqual((state.sp,state.nzcv),(initial.sp,initial.nzcv))

    def test_initialization_registry_accepts_4096_and_rejects_over_cap(self):
        s=self.session();self.assertTrue(s.create())
        functions=s.make_functions(4096);self.assertTrue(s.bind(functions))
        self.assertFalse(s.bind(functions,count=4097));self.assertEqual(s.error.value,17)
        # A rejected replacement keeps the complete previously accepted table.
        state=s.initial();self.assertEqual(s.begin(state),0);self.assertEqual(s.run(state,100),2)
        self.assertEqual((s.report.retired,s.provider()),(5,(1,1,1,1,3,1)))

    def test_old_profiles_contexts_handlers_and_selected_entry_requirement_stay_separate(self):
        for mode,flags,enabled in (('',1,True),('sdk',3,True),('native',7,True),
            ('init',15,False),('init',7,True),('native',15,False)):
            s=self.session(enabled=enabled);s.program.flags=flags
            self.assertFalse(s.create(mode=mode));self.assertEqual(s.error.value,1)
        s=self.session(enabled=False);self.assertTrue(s.create(mode='native'))
        functions=s.make_functions(1);functions[0].id=1
        self.assertFalse(s.bind(functions));self.assertEqual(s.error.value,17)
        self.assertFalse(self.lib.oot_startup_context_handler_valid(s.context,64))
        self.assertFalse(self.lib.oot_startup_context_returns_value(s.context,68))
        s=self.session();self.assertTrue(self.lib.oot_startup_context_handler_valid(s.context,64))
        self.assertTrue(self.lib.oot_startup_context_returns_value(s.context,68))

    def test_body_checks_are_complete_at_binding_and_before_each_actual_call(self):
        s=self.session();self.assertTrue(s.create());s.functions[0].sha256[0]^=1
        self.assertFalse(s.bind());self.assertEqual(s.error.value,4)
        for in_trace in (False,True):
            s=self.session();self.assertTrue(s.create());self.assertTrue(s.bind())
            state=s.initial();memory=self.lib.oot_runtime_memory(s.image).contents
            self.assertEqual(s.begin(state),0)
            @TRACE
            def mutate(row,_):
                if row.contents.pc==BASE:memory.regions[0].data[260]^=1
            if not in_trace:memory.regions[0].data[260]^=1
            self.assertEqual(s.run(state,100,mutate if in_trace else None),2)
            self.assertEqual((s.report.error,s.report.retired,s.provider()),(4,1,(0,0,0,0,0,0)))
        # Unused bodies outside the selected spans are checked when called,
        # rather than hashing thousands of inactive guards every quantum.
        s=self.session();self.assertTrue(s.create());self.assertTrue(s.bind(s.make_functions(4096)))
        self.assertTrue(s.goal());state=s.initial();self.assertEqual(s.begin(state),0)
        memory=self.lib.oot_runtime_memory(s.image).contents;memory.regions[0].data[256+4095*8+4]^=1
        self.assertEqual(s.run(state,100),2);self.assertEqual(s.report.error,15)

    def test_native_guard_is_a_real_boundary_with_no_success_or_retirement(self):
        s=self.session(guard=True);self.assertTrue(s.create());self.assertTrue(s.bind())
        state=s.initial();self.assertEqual(s.begin(state),0);self.assertEqual(s.run(state,100),2)
        self.assertEqual((s.report.error,s.report.service,s.report.retired,state.pc),(9,31,5,ENTRY+24))
        self.assertEqual(s.provider(),(1,1,1,1,3,1))
        self.assertEqual(self.lib.oot_startup_dispatch_native_calls(s.dispatcher),3)

    def test_native_interiors_and_unregistered_returns_do_not_mutate_provider(self):
        s=self.session(interior=True);self.assertTrue(s.create());self.assertTrue(s.bind())
        state=s.initial();before=state.values();self.assertEqual(s.begin(state),0)
        self.assertEqual(s.run(state,100),2)
        self.assertEqual((s.report.error,s.report.retired,state.values()),(18,0,before))
        for return_pc in (0,BASE+1,BASE+24,ENTRY,ENTRY+4,1<<39):
            s=self.session(tail=True);self.assertTrue(s.create());self.assertTrue(s.bind())
            state=s.initial();state.x[30]=return_pc;self.assertEqual(s.begin(state),0)
            self.assertEqual(s.run(state,100),2)
            self.assertEqual((s.report.error,s.report.retired,s.provider()),(10,1,(0,0,0,0,0,0)))
            self.assertEqual((state.pc,state.x[30]),(ENTRY,return_pc))

    def test_goal_and_stage_coverage_cannot_be_hidden_by_large_native_table(self):
        for binding_first in (False,True):
            s=self.session(extra_rows=(260,));self.assertTrue(s.create())
            if binding_first:self.assertTrue(s.bind())
            self.assertTrue(s.goal())
            if not binding_first:self.assertTrue(s.bind())
            self.assertFalse(s.goal((c_uint64*2)(BASE,ENTRY+4)));self.assertEqual(s.error.value,16)
        s=self.session();self.assertTrue(s.create());self.assertTrue(s.goal())
        covered=(NativeFunction*1)(NativeFunction(1,31,BASE+4,4,
            (c_uint8*32).from_buffer_copy(hashlib.sha256(s.data[4:8]).digest())))
        self.assertFalse(s.bind(covered));self.assertEqual(s.error.value,17)

    def test_copied_registry_lifetimes_work_quota_and_reentry_are_preserved(self):
        for limit,retired,calls,pc in ((1,1,0,ENTRY),(2,1,1,BASE+4),(4,3,1,ENTRY+8),
                (5,3,2,BASE+12),(6,4,2,ENTRY+16),(7,4,3,BASE+16),(8,5,3,BASE+20)):
            s=self.session();self.assertTrue(s.create(limit));self.assertTrue(s.bind())
            state=s.initial();self.assertEqual(s.begin(state),0);self.assertEqual(s.run(state,100),2)
            self.assertEqual((s.report.error,s.report.retired,
                self.lib.oot_startup_dispatch_native_calls(s.dispatcher),state.pc),(12,retired,calls,pc))
        s=self.session();self.assertTrue(s.create());self.assertTrue(s.bind())
        s.functions[0].id=31;s.functions[0].sha256[0]^=1
        state=s.initial();self.assertEqual(s.begin(state),0);attempts=[]
        @TRACE
        def reenter(row,_):
            if row.contents.event!=3:return
            error=c_uint32()
            attempts.extend((self.lib.oot_startup_dispatch_set_native_functions(s.dispatcher,s.functions,3,byref(error)),
                error.value,self.lib.oot_startup_dispatch_destroy(s.dispatcher)))
        self.assertEqual(s.run(state,2,reenter),1);self.assertEqual(attempts,[0,6,0])
        self.assertEqual(s.provider(),(1,0,1,0,1,1))
        self.lib.oot_runtime_close(s.image);s.image=None
        self.lib.oot_pauth_destroy(s.keys);s.keys=None
        self.lib.oot_startup_context_destroy(s.context);s.context=None
        self.assertEqual(s.run(state,100),2)
        self.assertEqual((s.report.error,s.report.retired,self.lib.oot_startup_dispatch_native_calls(s.dispatcher)),(8,5,3))


if __name__=='__main__':unittest.main()
