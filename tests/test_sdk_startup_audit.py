"""Synthetic SDK symbols/calls and NPDM declarations; no game code execution."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from arm64_decode import Decoder
from input_formats import InputError
from module_linker import Linker, Module
from sdk_startup_audit import (STAGE_SYMBOLS, THREAD_IDENTITY_SYMBOLS, _resolve_call,
                               audit_sdk_startup, audit_sdk_thread_identity, inspect_sdk_npdm)
from test_arm64_analysis import RET, branch, plt_fixture, synthetic_module
from test_module_linker import symbol


OFFSETS = {"sdk_start": 0x40, "libc0": 0xa0, "os_init": 0xa4,
           "libc1": 0xa8, "sdk_module_init": 0xac, "app_startup": 0x40,
           "libc2": 0xb0, "nn_main": 0x44, "sdk_module_fini": 0xb4,
           "quick_exit": 0xb8}


def sdk_fixture(*, bad_main_word=None, missing=None, hidden=None, alias=False,
                omit_call=None):
    """A complete synthetic pair whose Start calls six stages then nnMain."""
    offsets = dict(OFFSETS)
    if alias:
        offsets["quick_exit"] = offsets["sdk_module_fini"]
    symbols = {name: [symbol(export, value=offsets[stage],
                             visibility=2 if stage == hidden else 0,
                             size=32 if stage == "sdk_start" else 4)
                      for stage, owner, export in STAGE_SYMBOLS
                      if owner == name and stage != missing]
               for name in ("main", "sdk")}

    def modules(bases=None):
        main_words = {0: branch(0, 0x40), 0x40: RET,
                      0x44: branch(0x44, 0x50) if bad_main_word is None else bad_main_word,
                      0x50: RET}
        sdk_words = {0: branch(0, 0x40), 0x5c: RET,
                     **{offsets[stage]: RET for stage, owner, _ in STAGE_SYMBOLS
                        if owner == "sdk" and stage != "sdk_start"}}
        for index, stage in enumerate(("libc0", "os_init", "libc1", "sdk_module_init",
                                       "app_startup", "libc2", "nn_main")):
            owner = "main" if stage in ("app_startup", "nn_main") else "sdk"
            pc = 0x40 + index * 4
            sdk_words[pc] = (0xd503201f if stage == omit_call else
                             branch(pc + bases["sdk"], offsets[stage] + bases[owner], True)
                             if bases else RET)
        return [Module(name, synthetic_module(words, symbols=symbols[name]))
                for name, words in (("main", main_words), ("sdk", sdk_words))]

    provisional = Linker(modules())
    linker = Linker(modules({module.name: module.base for module in provisional.modules}))
    assert linker.apply()["link_complete"]
    return linker


def npdm_fixture(words=(), *, core=1, priority=20,
                 aci=True, region_offset=64, region_size=None):
    data = bytearray(256)
    data[:4] = b"META"
    data[12], data[14], data[15] = 1, priority, core
    struct.pack_into("<I", data, 28, 0x20000)
    if aci:
        struct.pack_into("<II", data, 112, 128, 128)
        data[128:132] = b"ACI0"
        struct.pack_into("<Q", data, 144, 0x0100123456789000)
        struct.pack_into("<II", data, 128 + 0x30, region_offset,
                         len(words) * 4 if region_size is None else region_size)
        if region_offset >= 64 and region_offset + len(words) * 4 <= 128:
            struct.pack_into(f"<{len(words)}I", data, 128 + region_offset, *words)
    return bytes(data)


def core_priority(min_core=1, max_core=3, min_priority=10, max_priority=30):
    return 7 | (max_priority << 4) | (min_priority << 10) | (min_core << 16) | (max_core << 24)


def thread_identity_fixture(*, offset=0x110, changes=None, before_capture=(), after_capture=()):
    """Small artificial lock fast paths and argument forwarding; no captured body."""
    entries = dict(enter=0x20, leave=0x40, enter_slow=0xa0, leave_slow=0xc0)
    svc_lock, svc_unlock = 0xe0, 0xe8
    # Use X9 for the artificial TLS read. Service forwarding needs no frame,
    # real thread object, scheduler, waiting loop or guest-code execution.
    load = 0xb9400000 | ((offset // 4) << 10) | (9 << 5) | 2
    acquire = [0xd53bd069, load, 0x2a1f03e1, 0x88e17c02,
               0x35000041, RET, branch(0x38, entries["enter_slow"])]
    release = [0xd53bd069, load, 0x2a0203e1, 0x88a1fc1f,
               0x6b02003f, 0x54000041, RET, branch(0x5c, entries["leave_slow"])]
    slow = [*before_capture, 0x2a0203f3, 0xaa0003f4, *after_capture,
            0x12017820, 0xaa1403e1, 0x2a1303e2]
    slow += [branch(entries["enter_slow"] + len(slow) * 4, svc_lock, True), RET]
    slow_release = [0x32020048, 0x6b08003f, 0x54000041,
                    branch(0xcc, svc_unlock, True), RET]
    blocks = dict(enter=acquire, leave=release, enter_slow=slow, leave_slow=slow_release)
    words = {0: branch(0, entries["enter"]), svc_lock: 0xd4000341,
             svc_lock + 4: RET, svc_unlock: 0xd4000361, svc_unlock + 4: RET}
    for name, block in blocks.items():
        words.update({entries[name] + index * 4: value for index, value in enumerate(block)})
    words.update(changes or {})
    raw = synthetic_module(words, symbols=[symbol(export, value=entries[name],
                                                  size=len(blocks[name]) * 4)
                                           for name, _, export in THREAD_IDENTITY_SYMBOLS])
    linker = Linker([Module("sdk", raw)])
    assert linker.apply()["link_complete"]
    return linker


class SdkStartupAuditTests(unittest.TestCase):
    def test_original_symbols_exact_calls_goal_and_unchanged_images(self):
        linker = sdk_fixture()
        before = [bytes(module.image) for module in linker.modules]
        report = audit_sdk_startup(linker)
        self.assertEqual(report["format"], "oot-sdk-startup-audit")
        self.assertEqual(report["mandatory_stage_ids"],
                         [stage[0] for stage in STAGE_SYMBOLS[:7]])
        self.assertEqual(report["goal_entry"]["entry"], linker.modules[0].base + 0x50)
        self.assertEqual(report["goal_entry"]["first_word"], RET)
        self.assertEqual(report["main_thunk"]["size"], 4)
        self.assertFalse(report["goal_entry"]["runtime_reached"])
        self.assertFalse(report["observed_process_model"]["thread_identity"]["available"])
        for flag in ("guest_code_executed", "translation_performed", "startup_completed",
                     "initialization_order_proven", "startup_abi_proven",
                     "native_callbacks_registered", "runtime_capabilities_granted"):
            self.assertIs(report[flag], False)
        self.assertEqual([bytes(module.image) for module in linker.modules], before)
        calls = report["sdk_start_calls"]
        self.assertEqual(len(calls), 7)
        self.assertEqual([row["stage_id"] for row in calls],
                         ["libc0", "os_init", "libc1", "sdk_module_init",
                          "app_startup", "libc2", "nn_main"])
        self.assertTrue(all(not call["live_target_proven"] for call in calls))
        self.assertEqual(report["stages"][0]["body_sha256"],
                         hashlib.sha256(before[1][0x40:0x60]).hexdigest())

    def test_requires_complete_link_and_original_text_checksum(self):
        linker = sdk_fixture()
        linker.applied = False
        with self.assertRaisesRegex(InputError, "complete offline link"):
            audit_sdk_startup(linker)
        linker.applied = True
        linker.modules[0].image[0x50] ^= 1
        with self.assertRaisesRegex(InputError, "original text checksum"):
            audit_sdk_startup(linker)

    def test_missing_hidden_aliased_or_duplicate_symbol_rejected(self):
        for kwargs in ({"missing": "libc1"}, {"hidden": "libc1"}, {"alias": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(InputError):
                audit_sdk_startup(sdk_fixture(**kwargs))
        linker = sdk_fixture()
        linker.modules[0].symbols.append(linker.modules[1].symbols[1])
        with self.assertRaisesRegex(InputError, "ambiguous definition"):
            audit_sdk_startup(linker)

    def test_parsed_symbol_must_match_original_table(self):
        linker = sdk_fixture()
        module = linker.modules[1]
        module.symbols[1] = replace(module.symbols[1], size=28)
        with self.assertRaisesRegex(InputError, "original symbol bytes"):
            audit_sdk_startup(linker)

    def test_invalid_main_thunks_and_missing_stages_rejected(self):
        for word in (RET, branch(0x44, 0x44), branch(0x44, 0x50, True),
                     branch(0x44, 0x2000)):
            with self.subTest(word=word), self.assertRaises(InputError):
                audit_sdk_startup(sdk_fixture(bad_main_word=word))
        with self.assertRaisesRegex(InputError, "stages are missing"):
            audit_sdk_startup(sdk_fixture(omit_call="libc1"))

    def test_plt_resolution_is_snapshot_only_and_cycles_rejected(self):
        caller, owner = plt_fixture("synthetic_sdk")
        from arm64_analysis import plt_stubs
        bridges = {caller.base + offset: row for offset, row in plt_stubs(caller).items()}
        report = _resolve_call([caller, owner], caller.base + 0xc0, bridges, Decoder())
        self.assertEqual(report["resolved_entry"], owner.base + 0x40)
        self.assertEqual(report["relocation_symbol"], "synthetic_sdk")
        self.assertFalse(report["live_target_proven"])
        self.assertEqual(report["resolution_steps"][0]["words"],
                         [0xd0000010, 0xf9400211, 0x91000210, 0xd61f0220])
        loop = Module("main", synthetic_module({0: branch(0, 0x40),
                                                0x40: branch(0x40, 0x44),
                                                0x44: branch(0x44, 0x40)}))
        Linker([loop]).apply()
        with self.assertRaisesRegex(InputError, "cyclic"):
            _resolve_call([loop], loop.base + 0x40, {}, Decoder())

    def test_cli_rejects_outputs_outside_private_build_root(self):
        destination = ROOT / "sdk-startup-audit-should-not-exist.json"
        result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/sdk_startup_audit.py"),
                                 "missing", "--report", str(destination)],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Output must be", result.stderr)
        self.assertFalse(destination.exists())

    def test_cli_writes_bound_audit_and_npdm_without_execution(self):
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="sdk-audit-", dir=ROOT / "build") as temporary:
            directory = Path(temporary)
            linker = sdk_fixture()
            records = []
            for module in linker.modules:
                # Recover the synthetic unrelocated NSO container from its
                # unchanged three sections and checksummed original header.
                # This fixture has no relocations, so rebuilding the container
                # does not export a captured executable or runtime state.
                raw = bytearray(256)
                raw[:4] = b"NSO0"
                struct.pack_into("<I", raw, 12, 0x38)
                struct.pack_into("<I", raw, 60, module.header["bss_size"])
                for index, segment in enumerate(module.header["segments"]):
                    content = module.read(segment["memory_offset"], segment["memory_size"])
                    struct.pack_into("<III", raw, 16 + index * 16,
                                     len(raw), segment["memory_offset"], len(content))
                    raw[160 + index * 32:192 + index * 32] = hashlib.sha256(content).digest()
                    raw += content
                (directory / module.name).write_bytes(raw)
                records.append(dict(name=module.name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
            raw = npdm_fixture((core_priority(), 0x5fff))
            (directory / "main.npdm").write_bytes(raw)
            records.append(dict(name="main.npdm", bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
            (directory / "manifest.json").write_text(json.dumps(dict(
                schema_version=1, format="prepared-exefs", files=records)), encoding="utf-8")
            destination = directory / "audit.json"
            command = [sys.executable, "-B", str(ROOT / "tools/sdk_startup_audit.py"),
                       str(directory), "--report", str(destination)]
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout)
            self.assertEqual(summary["mandatory_stages"], 7)
            self.assertFalse(summary["guest_code_executed"])
            report = json.loads(destination.read_text(encoding="utf-8"))
            self.assertTrue(report["npdm"]["declarations_complete"])
            self.assertFalse(report["guest_code_executed"])
            duplicate = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(duplicate.returncode, 0)
            self.assertIn("fresh SDK startup report", duplicate.stderr)


class SdkNpdmAuditTests(unittest.TestCase):
    def test_declared_inclusive_masks_and_application_type(self):
        raw = npdm_fixture((core_priority(), 0x5fff, 0xffffffff, 0))
        report = inspect_sdk_npdm(raw)
        self.assertEqual(report["core_mask"], 0b1110)
        self.assertEqual(report["priority_mask"], ((1 << 21) - 1) << 10)
        self.assertEqual(report["program_id"], 0x0100123456789000)
        self.assertTrue(report["is_application"])
        self.assertTrue(report["declarations_complete"])
        self.assertEqual(report["unproven_inputs"], [])
        self.assertEqual(report["aci0_capabilities"][-1]["kind"], "uninterpreted_capability")
        self.assertEqual(report["source_sha256"], hashlib.sha256(raw).hexdigest())
        for flag in ("signatures_checked", "acid_limits_checked", "retail_kernel_effects_proven"):
            self.assertFalse(report[flag])

    def test_missing_fields_remain_unproven(self):
        report = inspect_sdk_npdm(npdm_fixture((), aci=False))
        self.assertIsNone(report["core_mask"])
        self.assertIsNone(report["priority_mask"])
        self.assertIsNone(report["is_application"])
        self.assertFalse(report["declarations_complete"])
        report = inspect_sdk_npdm(npdm_fixture((core_priority(), 0x1dfff)))
        self.assertIsNone(report["is_application"])
        self.assertEqual(report["program_type"], 7)
        self.assertEqual(report["unproven_inputs"], ["is_application"])
        for program_type in (0, 2):
            report = inspect_sdk_npdm(npdm_fixture((core_priority(), 0x1fff | (program_type << 14))))
            self.assertIs(report["is_application"], False)

    def test_reversed_ranges_out_of_range_thread_and_duplicate_rejected(self):
        cases = [(core_priority(min_core=5, max_core=3),),
                 (core_priority(min_priority=30, max_priority=10),),
                 (core_priority(max_core=64),),
                 (core_priority(), core_priority()),
                 (0x5fff, 0x5fff), (0x25fff,)]
        for words in cases:
            with self.subTest(words=words), self.assertRaises(InputError):
                inspect_sdk_npdm(npdm_fixture(words))
        for kwargs in ({"core": 0}, {"priority": 31}):
            with self.subTest(kwargs=kwargs), self.assertRaises(InputError):
                inspect_sdk_npdm(npdm_fixture((core_priority(),), **kwargs))

    def test_region_bounds_alignment_overlap_and_input_type(self):
        cases = [npdm_fixture((core_priority(),), region_offset=60),
                 npdm_fixture((core_priority(),), region_offset=128),
                 npdm_fixture((core_priority(),), region_offset=65),
                 npdm_fixture((core_priority(),), region_size=3)]
        overlap = bytearray(npdm_fixture((core_priority(),)))
        struct.pack_into("<II", overlap, 128 + 0x20, 64, 4)
        cases += [bytes(overlap), b"META", bytes(32769), "META"]
        for raw in cases:
            with self.subTest(length=len(raw)), self.assertRaises(InputError):
                inspect_sdk_npdm(raw)


class SdkThreadIdentityAuditTests(unittest.TestCase):
    def test_original_role_binding_and_private_hash_evidence(self):
        linker = thread_identity_fixture()
        before = bytes(linker.modules[0].image)
        report = audit_sdk_thread_identity(linker)
        self.assertEqual(report["format"], "oot-sdk-thread-identity-audit")
        self.assertTrue(report["available"])
        self.assertEqual((report["tls_offset"], report["field_width"]), (0x110, 4))
        self.assertEqual(report["supported_logical_handle_max"], 0x3fffffff)
        self.assertEqual(report["waiter_flag"], 0x40000000)
        self.assertEqual(report["observed_owner_mask"], 0xbfffffff)
        self.assertEqual(report["arbitrate_lock"]["svc"], 0x1a)
        self.assertEqual(report["arbitrate_unlock"]["svc"], 0x1b)
        self.assertEqual(set(report["functions"]), {"enter", "leave", "enter_slow", "leave_slow"})
        for record in report["functions"].values():
            self.assertEqual(record["body_sha256"], hashlib.sha256(
                before[record["offset"]:record["offset"] + record["size"]]).hexdigest())
            self.assertEqual(len(record["instructions"]) * 4, record["size"])
        self.assertFalse(report["retail_tls_layout_proven"])
        self.assertFalse(report["guest_threading_supported"])
        self.assertFalse(report["guest_code_executed"])
        self.assertEqual(bytes(linker.modules[0].image), before)
        # The profile checks register provenance rather than one copied body.
        self.assertTrue(audit_sdk_thread_identity(thread_identity_fixture(
            after_capture=(0xd503201f,)))["available"])

    def test_offset_atomic_identity_and_slow_service_roles_must_match(self):
        cases = [dict(offset=0x114),
                 dict(changes={0x20: 0xd53bd060, 0x24: 0xb9411002}),  # destroys mutex input
                 dict(changes={0x2c: 0x88e17c03}),  # wrong acquired owner source
                 dict(changes={0x4c: 0x88a1fc02}),  # release writes the identity, not zero
                 dict(changes={0x38: branch(0x38, 0xa4)}),
                 dict(changes={0xa0: 0x2a0303f3}),  # captures W3, not requesting W2
                 dict(changes={0xac: 0xaa1503e1}),  # wrong mutex base forwarded
                 dict(changes={0xe0: 0xd4000361}),  # unlock service in lock wrapper
                 dict(changes={0xe4: 0xd503201f}),  # wrapper does not return
                 dict(changes={0xc0: 0x32010048})]  # different waiter marker
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), self.assertRaises(InputError):
                audit_sdk_thread_identity(thread_identity_fixture(**kwargs))

    def test_captured_registers_and_initial_inputs_cannot_be_clobbered(self):
        for kwargs in (dict(after_capture=(0x2a1f03f3,)),
                       dict(after_capture=(0xaa1f03f4,)),
                       dict(before_capture=(0x2a1f03e2,)),
                       dict(before_capture=(branch(0xa0, 0xe0, True),))):
            with self.subTest(kwargs=kwargs), self.assertRaises(InputError):
                audit_sdk_thread_identity(thread_identity_fixture(**kwargs))

    def test_original_hash_complete_link_and_required_symbols_remain_required(self):
        linker = thread_identity_fixture()
        linker.applied = False
        with self.assertRaisesRegex(InputError, "complete offline link"):
            audit_sdk_thread_identity(linker)
        linker.applied = True
        linker.modules[0].image[0x24] ^= 4
        with self.assertRaisesRegex(InputError, "unchanged original text"):
            audit_sdk_thread_identity(linker)
        with self.assertRaisesRegex(InputError, "missing or ambiguous"):
            audit_sdk_thread_identity(sdk_fixture())


if __name__ == "__main__":
    unittest.main()
