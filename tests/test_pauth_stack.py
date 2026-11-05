"""PAC policy v4/schema 5, strict original-byte proofs, and native DAG execution."""

from copy import deepcopy
from ctypes import byref, c_uint32, c_uint64, create_string_buffer
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from dispatcher_validation import EXIT, Report
from input_formats import InputError
from lifter_validation import compile_library
from lifter_validation_types import State
from module_linker import Linker, Module
from pauth_lifter import MODEL
from pauth_validation import KEYS
from pauth_stack_validation import (PauthAssembler, bindings, synthetic_programs, matrix_programs,
                                    run_validation, immediate, add_immediate)
from prepare_exefs import prepare
from prepare_registry import build_bundle
from profile_survey import survey_modules
from stack_layout_verifier import (verify_layout_stack_functions, verify_pauth_stack_functions,
                                   SIGN, AUTH, RECORD_RESTORE)
from test_module_linker import fixture, change_memory, symbol
from test_profile_survey import programs_module


def bundle_fixture(explicit=False):
    base = Linker([Module("main", fixture())]).modules[0].base
    p = PauthAssembler("pac_bundle" + str(int(explicit)), base + 0x10, 64, 48, ((32, (19,)),),
                       key=int(explicit), explicit_auth=explicit)
    p.emit(add_immediate(19, 0, 1), 0xAA1303E0)
    p = p.finish(); raw = fixture(symbols=[symbol(p.name,value=0x10,size=len(p.data))])
    raw = change_memory(raw, 0x94, struct.pack("<i",0x1100-0x80))  # No synthetic unwind table.
    raw = change_memory(raw, 0x10, p.data)
    linker = Linker([Module("main", raw)]); assert linker.apply()["link_complete"]
    config = {"schema_version": 5, "pauth_model": MODEL, "root": p.name, "stack_size": 4096,
        "return_sites": [EXIT], "frames": [{"name": p.name, "module": "main", "offset": 0x10, "size": len(p.data)}], "leaves": []}
    return raw, linker, config


class PauthPolicyTests(unittest.TestCase):
    def test_signed_lr_phases_original_hashes_and_old_policy_rejection(self):
        frames, leaves = synthetic_programs(); code, leaf = {p.base: p.data for p in frames}, {p.base:p.data for p in leaves}
        before = deepcopy(code); proofs = verify_pauth_stack_functions(code, leaf, frames[0].base)
        p = proofs[frames[0].base]
        self.assertEqual((p["max_depth"], p["max_stack_bytes"]), (3, 208))
        self.assertEqual((p["steps"][0]["kind"], p["states"][0]), (SIGN, {"sp":1,"fp":0,"lr":3,"owner":0}))
        r = next(i for i,s in enumerate(p["steps"]) if s["kind"] == RECORD_RESTORE)
        self.assertEqual(p["states"][r]["lr"],3);self.assertEqual(p["states"][-1]["lr"],3)
        child = proofs[frames[1].base]
        self.assertEqual(child["steps"][-2]["kind"], AUTH);self.assertEqual(child["states"][-2]["lr"],1)
        self.assertEqual(code,before)
        with self.assertRaises(InputError): verify_layout_stack_functions(code,leaf,frames[0].base)

    def test_mismatched_keys_missing_sign_duplicate_pac_and_early_auth_rejected(self):
        frames, leaves = synthetic_programs(); root = frames[0]
        for index, word in ((0, 0xD503201F), (1, 0xD503237F), (6, 0xD50323FF), (-1,0xD65F0BFF), (-1,0xD65F03C0)):
            data={p.base:p.data for p in frames};words=root.words.copy();words[index]=word
            data[root.base]=struct.pack(f"<{len(words)}I",*words)
            with self.subTest(index=index,word=hex(word)), self.assertRaises(InputError):
                verify_pauth_stack_functions(data,{p.base:p.data for p in leaves},root.base)

    def test_matrix_both_keys_return_styles_and_all_saved_registers(self):
        for p in matrix_programs():
            v=verify_pauth_stack_functions({p.base:p.data},{},p.base)[p.base]
            self.assertEqual(v["saved_registers"],list(range(19,29)))
            self.assertEqual(v["pauth_model"],MODEL)

    def test_branch_cannot_bypass_auth_or_reenter_sign(self):
        a=PauthAssembler("bad",0x1000,32,key=0,explicit_auth=True)
        a.branch("bad",0x14000000,26);a.label("bad");a.emit(immediate(0,1));p=a.finish()
        for target in (0,len(p.words)-2,len(p.words)-1):
            words=p.words.copy();words[4]=0x14000000|((target-4)&0x3ffffff)
            with self.subTest(target=target),self.assertRaises(InputError):
                verify_pauth_stack_functions({p.base:struct.pack(f"<{len(words)}I",*words)},{},p.base)


class PauthBundleSurveyTests(unittest.TestCase):
    def test_schema_five_requires_model_and_preserves_earlier_schemas(self):
        _,linker,config=bundle_fixture();before=bytes(linker.modules[0].image)
        blob,source,m=build_bundle(linker,config)
        self.assertEqual((m["schema_version"],m["profile"],m["pauth_model"]),(5,"pauth-stack-dag",MODEL))
        self.assertFalse(m["keys_embedded"]);self.assertIn("oot_stack_create_pauth",source)
        self.assertEqual(bytes(linker.modules[0].image),before)
        for key,value in (("schema_version",4),("pauth_model",None),("pauth_model","qarma3"),("return_sites",[1<<39])):
            bad=deepcopy(config);bad[key]=value
            with self.assertRaises(InputError):build_bundle(linker,bad)

    def test_real_pac_survey_keeps_bytes_and_default_acceptance_separate(self):
        a=PauthAssembler("root",0x10,32,key=0);a.emit(immediate(0,1));p=a.finish()
        m=programs_module([("root",0x10,p.data)]);before=bytes(m.image)
        default=survey_modules([m]);pac=survey_modules([m],pauth=True)
        self.assertTrue(all(r["accepted_regions"]==0 for r in default["totals"]["profiles"].values()))
        row=pac["totals"]["profiles"]["pauth_stack"]
        self.assertEqual(row["accepted_regions"],1)
        self.assertEqual(row["considered_candidates"],row["discovery_blocked"]+row["accepted_regions"]+sum(row["rejected"].values()))
        self.assertEqual(bytes(m.image),before);self.assertFalse(pac["translation_performed"])
        self.assertFalse(pac["native_callbacks_registered"])

    def test_pac_cli_bundle_and_static_survey_use_fresh_paths(self):
        raw,_,config=bundle_fixture(True)
        with tempfile.TemporaryDirectory(dir=ROOT/"build") as temporary:
            folder=Path(temporary);src,prepared,selection,out,report=[folder/n for n in ("main","prepared","selection.json","bundle","survey.json")]
            src.write_bytes(raw);prepare(src,prepared);selection.write_text(json.dumps(config))
            args=[sys.executable,"-B",str(ROOT/"tools/prepare_registry.py"),str(prepared),"--config",str(selection),"--output",str(out)]
            result=subprocess.run(args,capture_output=True,text=True);self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads((out/"manifest.json").read_text())["profile"],"pauth-stack-dag")
            result=subprocess.run([sys.executable,"-B",str(ROOT/"tools/survey_function_profiles.py"),str(prepared),"--pauth","--report",str(report)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(json.loads(report.read_text())["pauth_model"],MODEL)
            self.assertNotEqual(subprocess.run(args,capture_output=True).returncode,0)


@unittest.skipUnless(os.name=="nt" and importlib.util.find_spec("unicorn"),"native Windows and pinned Unicorn required")
class NativePauthStackTests(unittest.TestCase):
    def test_pac_dag_matrix_max_depth_faults_and_retained_context(self):
        r,path=run_validation(os.environ.get("OOT_LIFTER_COMPILER","cmake"))
        self.assertEqual(r["whole_call_cases"],93);self.assertGreater(r["prefix_step_checks"],2000)
        self.assertEqual((r["native_fault_modes"],r["matrix_layouts"],r["max_depth"]),(11,8,16))
        self.assertFalse(r["game_code_executed"]);self.assertTrue(path.is_file())

    def test_actual_schema_five_factory_for_both_return_styles(self):
        sources,blobs=[],[]
        for explicit in (False,True):
            _,linker,config=bundle_fixture(explicit);blob,source,m=build_bundle(linker,config)
            sources.append(source.replace("oot_create_bound_registry","oot_create_bundle1") if explicit else source);blobs.append((blob,m))
        lib,_=compile_library([],os.environ.get("OOT_LIFTER_COMPILER","cmake"),"\n".join(sources));bindings(lib)
        keys=(c_uint64*4)(*KEYS);ctx=lib.oot_pauth_create(1,keys)
        try:
            with tempfile.TemporaryDirectory(dir=ROOT/"build") as temporary:
                for i,(blob,m) in enumerate(blobs):
                    path=Path(temporary)/f"image{i}.ootmem";path.write_bytes(blob)
                    message,error,report=create_string_buffer(192),c_uint32(),Report()
                    image=lib.oot_runtime_open(os.fsencode(path),message,len(message));self.assertTrue(image,message.value)
                    factory=getattr(lib,"oot_create_bundle1") if i else lib.oot_create_bound_registry;factory.argtypes,factory.restype=lib.oot_create_bound_registry.argtypes,lib.oot_create_bound_registry.restype
                    d=factory(image,ctx,byref(error));self.assertTrue(d,error.value);lib.oot_runtime_close(image)
                    try:
                        s=State();s.pc,s.sp,s.x[30],s.x[0],s.x[19]=m["root"]["entry"],m["image"]["initial_sp"],EXIT,9,0xA5
                        self.assertEqual(lib.oot_stack_begin(d,byref(s),EXIT,byref(report)),0)
                        self.assertEqual(lib.oot_stack_run(d,byref(s),1000,byref(report)),2)
                        self.assertEqual((s.x[0],s.x[19],s.pc),(10,0xA5,EXIT))
                    finally:lib.oot_stack_destroy(d)
        finally:lib.oot_pauth_destroy(ctx)


if __name__=="__main__":unittest.main()
