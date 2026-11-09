"""Synthetic public native-call reports agree with transactional outcomes."""

from ctypes import (POINTER,byref,c_uint8,c_void_p,cast,memmove,sizeof)
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from lifter_validation_types import State
from startup_validation import snapshot
from test_native_sdk_runtime import NativeReport
import test_sdk_init_context as fixture


class SdkInitReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.SdkInitContextTests.setUpClass()
        cls.lib=fixture.SdkInitContextTests.lib

    def helper(self):
        helper=fixture.SdkInitContextTests()
        self.addCleanup(helper.doCleanups)
        return helper

    def context(self):
        helper=self.helper();context,config,sdk=helper.create(capacity=fixture.ALIGN)
        return helper,context,config

    def call(self,context,handler,state,status,error=None):
        report=NativeReport.from_buffer_copy(bytes([0xa5])*sizeof(NativeReport))
        before=bytes(state) if state is not None else None
        pointer=byref(state) if state is not None else None
        self.assertEqual(self.lib.oot_startup_context_native_call(context,handler,pointer,byref(report)),status)
        self.assertEqual((report.status,report.handler,report.log_size),(status,handler,0))
        if error is not None:self.assertEqual(report.error,error)
        if status and state is not None:self.assertEqual(bytes(state),before)
        return report

    def test_null_raw_and_non_native_contexts_return_explicit_unsupported_reports(self):
        helper=self.helper();state=helper.state()
        self.call(None,64,state,1,0)
        image=helper.image();config,sdk=helper.config(flags=1,capacity=fixture.ALIGN)
        from ctypes import c_uint32
        error=c_uint32()
        raw=self.lib.oot_startup_context_create(image,byref(config),byref(error))
        self.assertTrue(raw,error.value);self.addCleanup(self.lib.oot_startup_context_destroy,raw)
        sdk_context=self.lib.oot_startup_context_create_sdk(image,byref(config),byref(sdk),byref(error))
        self.assertTrue(sdk_context,error.value);self.addCleanup(self.lib.oot_startup_context_destroy,sdk_context)
        for context in (raw,sdk_context):
            before=snapshot(self.lib,context)
            for handler in (1,31,64,128,208,0xffffffff):self.call(context,handler,state,1,0)
            self.assertEqual(snapshot(self.lib,context),before)

    def test_malformed_state_reports_fault_without_provider_or_guest_effects(self):
        helper,context,config=self.context()
        providers=helper.providers(context);memory=snapshot(self.lib,context)
        for field,value in (('pc',1<<39),('pc',fixture.BASE+1),('nzcv',1)):
            state=helper.state();setattr(state,field,value)
            self.call(context,64,state,2,2)
        self.call(context,64,None,2,2)
        # These preconditions belong to the provider; retain its finer error.
        for field,value in (('sp',0x7000001008),('pc',0)):
            state=helper.state();setattr(state,field,value)
            self.call(context,64,state,2,1)
        state=helper.state();state.x[30]=0
        self.call(context,64,state,2,1)
        self.assertEqual(helper.providers(context),providers)
        self.assertEqual(snapshot(self.lib,context),memory)

    def test_bad_live_metadata_reports_fault_and_preserves_existing_state(self):
        helper,context,config=self.context()
        providers=helper.providers(context);before=snapshot(self.lib,context)
        memory=self.lib.oot_startup_context_memory(context).contents
        saved_valid,saved_count=memory.valid,memory.count
        try:
            memory.valid=0;self.call(context,64,helper.state(),2,2)
            memory.valid=saved_valid
            memory.count=saved_count-1;self.call(context,64,helper.state(),2,2)
            memory.count=saved_count
            permissions=memory.regions[0].permissions
            try:
                memory.regions[0].permissions^=2
                self.call(context,64,helper.state(),2,2)
            finally:memory.regions[0].permissions=permissions
        finally:memory.valid=saved_valid;memory.count=saved_count
        self.assertEqual(helper.providers(context),providers)
        self.assertEqual(snapshot(self.lib,context),before)

    def test_provider_input_ownership_fault_is_normalized_in_the_public_report(self):
        helper,context,config=self.context()
        memory=self.lib.oot_startup_context_memory(context).contents
        tls=next(region for region in memory.regions[:memory.count] if region.base==config.tls_base)
        # Deliberately place the input record in owned synthetic guest backing.
        # The provider rejects that alias before changing any candidate/bytes.
        pointer=cast(byref(tls.data.contents,512),POINTER(State))
        state=helper.state();memmove(pointer,byref(state),sizeof(State))
        before=snapshot(self.lib,context);providers=helper.providers(context)
        report=NativeReport()
        self.assertEqual(self.lib.oot_startup_context_native_call(context,64,pointer,byref(report)),2)
        self.assertEqual((report.status,report.handler,report.error,report.log_size),(2,64,2,0))
        self.assertEqual(bytes(pointer.contents),bytes(state))
        self.assertEqual(snapshot(self.lib,context),before)
        self.assertEqual(helper.providers(context),providers)

    def test_overlapping_report_and_register_spans_are_rejected_without_writes(self):
        helper,context,config=self.context();providers=helper.providers(context)
        memory=snapshot(self.lib,context)
        storage=(c_uint8*(sizeof(State)+64))()
        state=State.from_buffer(storage,32)
        initial=helper.state();memmove(byref(state),byref(initial),sizeof(State))
        for offset in (-15,0,8,sizeof(State)-1):
            report=cast(byref(storage,32+offset),POINTER(NativeReport))
            before=bytes(storage)
            self.assertEqual(self.lib.oot_startup_context_native_call(context,64,byref(state),report),2)
            self.assertEqual(bytes(storage),before)
            self.assertEqual(helper.providers(context),providers)
        self.assertEqual(snapshot(self.lib,context),memory)
        # Exactly adjacent private records are separate and remain usable.
        for offset in (-sizeof(NativeReport),sizeof(State)):
            memmove(byref(state),byref(initial),sizeof(State))
            report=cast(byref(storage,32+offset),POINTER(NativeReport))
            self.assertEqual(self.lib.oot_startup_context_native_call(context,64,byref(state),report),0)
            self.assertEqual((report.contents.status,report.contents.handler,report.contents.error),(0,64,0))
            self.assertEqual(state.pc,initial.x[30])

    def test_guard_and_provider_errors_keep_specific_status_and_optional_report(self):
        helper,context,config=self.context()
        self.call(context,31,helper.state(),1,6)
        self.call(context,66,helper.state(),1,2)
        self.call(context,0xffffffff,helper.state(),1,0)
        state=helper.state();self.call(context,64,state,0,0)
        native=self.lib.oot_startup_context_native(context).contents
        native.calls=(1<<64)-1
        self.call(context,66,helper.state(),2,5)
        before=helper.providers(context)
        self.assertEqual(self.lib.oot_startup_context_native_call(context,64,None,None),2)
        self.assertEqual(helper.providers(context),before)


if __name__=='__main__':unittest.main()
