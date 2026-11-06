"""Failure isolation and provenance guards for complete milestone automation."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/"tools"))
from input_formats import InputError
from run_milestone import MilestoneRun, compare_profiles, STATIC_FLAGS


def profile():
    return {"schema_version": 1, "format": "arm64-function-profile-survey", **dict.fromkeys(STATIC_FLAGS, False),
            "decoder": {"name": "synthetic"}, "method": {"max_words": 256}, "policies": {"leaf": "v1"}, "pauth_model": None,
            "modules": [{"name": "synthetic", "base": 0x1000, "build_id": "11"*32, "source_sha256": "22"*32,
                         "linked_text_sha256": "33"*32, "metadata_entry_candidates": 3}],
            "totals": {"metadata_entry_candidates": 3, "complete_regions": 2, "profiles": {"leaf": {"accepted_regions": 1}}},
            "eligible_plt_leaf_bridges": 0}


class ProfileComparisonTests(unittest.TestCase):
    def test_valid_changes_are_reported_without_fixed_acceptance_expectations(self):
        a = profile(); b = deepcopy(a); b["totals"]["complete_regions"] = 3
        b["totals"]["profiles"]["leaf"]["accepted_regions"] = 2
        r = compare_profiles(a, b)
        self.assertTrue(r["source_text_hashes_match"])
        self.assertEqual((r["before"]["complete_regions"], r["after"]["complete_regions"]), (2, 3))

    def test_changed_or_missing_source_identity_and_module_sets_are_rejected(self):
        for change in ("source_sha256", "linked_text_sha256", "build_id", "base", "metadata_entry_candidates"):
            a = profile(); b = deepcopy(a); b["modules"][0][change] = "changed"
            with self.subTest(change=change), self.assertRaises(InputError): compare_profiles(a, b)
        a = profile(); b = deepcopy(a); del a["modules"][0]["source_sha256"]; del b["modules"][0]["source_sha256"]
        with self.assertRaises(InputError): compare_profiles(a, b)
        for modules in ([], profile()["modules"]*2):
            a = profile(); b = deepcopy(a); b["modules"] = modules
            with self.assertRaises(InputError): compare_profiles(a, b)

    def test_changed_policy_model_limits_and_runtime_actions_cannot_pass(self):
        for key in ("policies", "decoder", "method", "pauth_model"):
            a = profile(); b = deepcopy(a); b[key] = "changed"
            with self.subTest(key=key), self.assertRaises(InputError): compare_profiles(a, b)
        for key in STATIC_FLAGS:
            for side in (0, 1):
                rows = [profile(), profile()]; rows[side][key] = True
                with self.subTest(key=key, side=side), self.assertRaises(InputError): compare_profiles(*rows)


class MilestoneStateTests(unittest.TestCase):
    def test_failed_command_is_recorded_and_never_marked_complete(self):
        with tempfile.TemporaryDirectory(dir=ROOT/"build") as temporary:
            run = MilestoneRun(Path(temporary)/"run", "test", ["probe"])
            with patch("run_milestone.subprocess.run", return_value=subprocess.CompletedProcess([], 7)):
                with self.assertRaises(InputError): run.command("probe", ["synthetic-command"], {})
            r = json.loads((run.output/"run.json").read_text())
            self.assertEqual((r["status"], r["stages"]["probe"]["status"]), ("failed", "failed"))
            self.assertTrue((run.output/"probe.log").is_file())
            with self.assertRaises(InputError): run.finish()

    def test_pending_stages_and_changed_sources_prevent_completion(self):
        with tempfile.TemporaryDirectory(dir=ROOT/"build") as temporary:
            with patch("run_milestone.source_digest", return_value="before"):
                run = MilestoneRun(Path(temporary)/"run", "test", ["probe", "later"])
            run.action("probe", lambda: None)
            with self.assertRaises(InputError): run.finish()
            run.action("later", lambda: None)
            with patch("run_milestone.source_digest", return_value="changed"):
                with self.assertRaises(InputError): run.finish()
            with patch("run_milestone.source_digest", return_value="before"): run.finish()
            self.assertEqual(json.loads((run.output/"run.json").read_text())["status"], "passed")

    def test_fresh_build_only_outputs_and_one_attempt_per_stage(self):
        with self.assertRaises(InputError): MilestoneRun(ROOT/"outside-build", "test", ["probe"])
        with tempfile.TemporaryDirectory(dir=ROOT/"build") as temporary:
            run = MilestoneRun(Path(temporary)/"run", "test", ["probe"])
            with self.assertRaises(InputError): MilestoneRun(run.output, "test", ["probe"])
            run.action("probe", lambda: None)
            with self.assertRaises(InputError): run.action("probe", lambda: None)


if __name__ == "__main__": unittest.main()
