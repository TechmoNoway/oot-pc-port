"""Validate a complete milestone and collect private evidence; never publish or run game code."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from threading import Lock
import time
import xml.etree.ElementTree as ET

from callee_audit import compare_baseline
from input_formats import InputError, require
from lifter_validation import find_cmake
from link_exefs import build_destination

ROOT = Path(__file__).resolve().parent.parent
STATIC_FLAGS = ("guest_code_executed", "translation_performed", "native_callbacks_registered",
                "runtime_read_ranges_supplied", "runtime_got_targets_checked")


def read_json(path):
    require(path.stat().st_size <= 64*1024*1024, "report/config exceeds size limit")
    return json.loads(path.read_text(encoding="utf-8"))


def source_digest():
    digest = hashlib.sha256()
    paths = [ROOT / "CMakeLists.txt"]
    for folder, suffixes in (("src", (".c", ".h")), ("tools", (".py", ".txt", ".c")),
                              ("tests", (".py", ".c")), ("config/milestones", (".json",))):
        paths += [p for p in (ROOT/folder).rglob("*") if p.is_file() and p.suffix in suffixes]
    for path in sorted(paths):
        require(path.resolve().is_relative_to(ROOT), "source fingerprint escaped checkout")
        digest.update(path.relative_to(ROOT).as_posix().encode()+b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def compare_profiles(before, after):
    for r in (before, after):
        require(r.get("format") == "arm64-function-profile-survey" and r.get("schema_version") == 1, "invalid profile report")
        require(all(r.get(k) is False for k in STATIC_FLAGS), "survey contains runtime actions or capabilities")
        require(isinstance(r.get("modules"), list) and r["modules"], "missing profile modules")
        for m in r["modules"]:
            require(all(k in m for k in ("name", "base", "build_id", "source_sha256", "linked_text_sha256", "metadata_entry_candidates")), "missing source/text identity")
    require(all(before.get(k) == after.get(k) for k in ("decoder", "method", "policies", "pauth_model")), "baseline model/decoder/policies/limits differ")
    a, b = ({m["name"]: m for m in r["modules"]} for r in (before, after))
    require(len(a) == len(before["modules"]) and len(b) == len(after["modules"]) and a.keys() == b.keys(), "baseline module set differs")
    for name in a:
        require(all(a[name].get(k) == b[name].get(k) for k in ("base", "build_id", "source_sha256", "linked_text_sha256", "metadata_entry_candidates")), "baseline source/text identity differs")
    require(before["totals"]["metadata_entry_candidates"] == after["totals"]["metadata_entry_candidates"], "metadata denominator differs")
    return {"source_text_hashes_match": True, "model_decoder_policies_limits_match": True,
            "before": before["totals"], "after": after["totals"],
            "eligible_bridges_before": before["eligible_plt_leaf_bridges"],
            "eligible_bridges_after": after["eligible_plt_leaf_bridges"]}


class MilestoneRun:
    def __init__(self, output, name, stages):
        self.output = build_destination(output)
        require(not self.output.exists(), "choose a fresh milestone output directory")
        self.output.mkdir(parents=True)
        self.lock, self.started_ns = Lock(), time.time_ns()
        self.manifest = {"schema_version": 1, "name": name, "status": "running",
            "started_utc": datetime.now(timezone.utc).isoformat(), "source_sha256": source_digest(),
            "stages": {name: {"status": "pending"} for name in stages}}
        self.save()

    def save(self):
        temporary = self.output/"run.tmp"
        temporary.write_text(json.dumps(self.manifest, indent=2)+"\n", encoding="utf-8")
        temporary.replace(self.output/"run.json")

    def action(self, name, callback, command=None):
        with self.lock:
            row = self.manifest["stages"][name]
            require(row["status"] == "pending", "milestone stage already attempted")
            row.update(status="running", command=command); self.save()
        print(f"Starting {name}", flush=True)
        started = time.monotonic()
        try:
            value = callback()
        except Exception as error:
            with self.lock:
                row.update(status="failed", error=str(error), seconds=round(time.monotonic()-started, 3))
                self.manifest.update(status="failed", error=str(error)); self.save()
            raise
        with self.lock:
            row.update(status="passed", seconds=round(time.monotonic()-started, 3)); self.save()
        print(f"Passed {name}", flush=True)
        return value

    def command(self, name, argv, env):
        def invoke():
            with (self.output/(name+".log")).open("w", encoding="utf-8") as log:
                result = subprocess.run(list(map(str, argv)), cwd=ROOT, env=env, stdout=log,
                                        stderr=subprocess.STDOUT, timeout=1800)
            require(result.returncode == 0, f"{name} failed; see {name}.log")
        return self.action(name, invoke, list(map(str, argv)))

    def finish(self):
        require(self.manifest["status"] != "failed" and all(r["status"] == "passed" for r in self.manifest["stages"].values()), "milestone has incomplete/failed stages")
        require(source_digest() == self.manifest["source_sha256"], "source changed during validation; run again with fresh output")
        self.manifest.update(status="passed", finished_utc=datetime.now(timezone.utc).isoformat()); self.save()


def collect_native(run, native, config):
    reports = {}
    for mode in ("cmake", "gcc"):
        path = ROOT/f"build/lifter-validation/{mode}-report.json"
        require(path.stat().st_mtime_ns >= run.started_ns, "stale native differential report")
        r = read_json(path)
        require(r["result"] == "passed" and r["synthetic_only"] and r["game_code_executed"] is False, "invalid native differential evidence")
        compiler = r["native_build"]["compiler"]
        require(("MSVC" in compiler) if mode == "cmake" else ("gcc" in compiler.lower()), "required compiler was not exercised")
        shutil.copyfile(path, run.output/path.name); reports[mode] = r
        for label in config["factory_reports"]:
            path = ROOT/f"build/lifter-validation/{mode}-{label}-dispatch-report.json"
            require(path.stat().st_mtime_ns >= run.started_ns, "stale factory report")
            f = read_json(path)
            require(f["synthetic_only"] and f["game_code_executed"] is False and f["whole_call_cases"] > 0 and f["prefix_checks"] >= f["whole_call_cases"], "invalid factory evidence")
            shutil.copyfile(path, run.output/path.name)
    require(reports["cmake"]["trial_count"] == reports["gcc"]["trial_count"] and reports["cmake"]["forms"] == reports["gcc"]["forms"], "compiler evidence covers different cases")
    junit = ET.parse(run.output/"ctest.xml").getroot()
    require(int(junit.get("failures", "0")) == 0 and int(junit.get("errors", "0")) == 0, "CTest reported failures")
    names = {t.get("name") for t in junit.iter("testcase")}
    require({"host_self_test", "guest_memory_self_test", "ordered_memory_self_test", "pauth_self_test", "leaf_dispatch_self_test", "python_tests"} <= names, "required CTest groups did not execute")
    require(not list(junit.iter("skipped")) and not list(junit.iter("failure")) and not list(junit.iter("error")), "CTest contains skipped or failed groups")
    log = native/"Testing/Temporary/LastTest.log"
    require(log.stat().st_mtime_ns >= run.started_ns, "stale CTest log")
    text = log.read_text(encoding="utf-8", errors="replace")
    counts = re.findall(r"Ran (\d+) tests in", text)
    require(counts and "\nOK\n" in text and "OK (skipped=" not in text, "complete Python suite did not pass without skips")
    shutil.copyfile(log, run.output/"ctest-details.log")
    return {"native_trials_per_compiler": reports["cmake"]["trial_count"], "python_tests": int(counts[-1]),
            "ctest_groups": len(names), "compilers": {k: v["native_build"]["compiler"] for k, v in reports.items()}}


def execute(config, output, native_only=False):
    require(os.name == "nt", "milestone runner requires Windows")
    require(isinstance(config, dict) and config.get("schema_version") == 1 and isinstance(config.get("name"), str) and re.fullmatch(r"[a-z][a-z0-9-]*", config["name"]), "invalid milestone config")
    require(all(isinstance(config.get(k), str) and config[k] for k in ("native_build", "prepared", "baseline_default", "baseline_plt")), "missing milestone paths")
    for key in ("gcc_tests", "factory_reports"):
        require(isinstance(config.get(key), list) and config[key] and len(set(config[key])) == len(config[key]), "missing/duplicate milestone checks")
    require(all(re.fullmatch(r"test_[a-z0-9_*]+\.py", p) for p in config["gcc_tests"]), "invalid GCC test pattern")
    require(all(re.fullmatch(r"[a-z][a-z0-9-]*", p) for p in config["factory_reports"]), "invalid factory report name")
    native = build_destination(ROOT/config["native_build"])
    cache = (native/"CMakeCache.txt").read_text(encoding="utf-8")
    require("CMAKE_GENERATOR:INTERNAL=Visual Studio" in cache, "configure a Visual Studio native build first")
    interpreters = re.findall(r"^_?Python3_EXECUTABLE:[^=]+=(.+)$", cache, re.MULTILINE)
    require(interpreters and all(Path(p).resolve() == Path(sys.executable).resolve() for p in interpreters), "CMake must use this project Python interpreter")
    require(re.search(r"^OOT_ZBIC_SOURCE:PATH=.+$", cache, re.MULTILINE), "configure the pinned ZBIC helper before milestone validation")
    prepared = (ROOT/config["prepared"]).resolve()
    if not native_only:
        require((prepared/"manifest.json").is_file(), "prepared inputs are missing")
        for key in ("baseline_default", "baseline_plt"): read_json(ROOT/config[key])
        destination = build_destination(output)
        require(not destination.is_relative_to(prepared) and not prepared.is_relative_to(destination), "milestone output overlaps prepared inputs")
    cmake = Path(find_cmake()); ctest = cmake.with_name("ctest.exe")
    gcc = shutil.which("gcc") or "C:/msys64/ucrt64/bin/gcc.exe"
    require(Path(gcc).is_file(), "GCC is required for milestone validation")
    env = os.environ.copy(); env["PATH"] = str(Path(gcc).parent)+os.pathsep+env.get("PATH", "")
    stages = ["native-configure", "native-build", "msvc-suite", "gcc-common"] + ["gcc-tests-"+str(i) for i in range(len(config["gcc_tests"]))]
    stages += ["native-evidence"] + ([] if native_only else ["survey-default", "survey-plt", "callee-audit", "comparison"]) + ["summary"]
    run = MilestoneRun(output, config["name"], stages)
    run.manifest["scope"] = "synthetic native only" if native_only else "synthetic native and static private game analysis"
    run.manifest["config"] = config; run.save()
    py = [sys.executable, "-B"]
    try:
        run.command("native-configure", [cmake, "-S", ROOT, "-B", native], env)
        run.command("native-build", [cmake, "--build", native, "--config", "Release"], env)
        def msvc():
            e = dict(env, OOT_LIFTER_COMPILER="cmake")
            run.command("msvc-suite", [ctest, "--test-dir", native, "-C", "Release", "--output-on-failure", "--output-junit", run.output/"ctest.xml"], e)
        def gcc_lane():
            e = dict(env, OOT_LIFTER_COMPILER="gcc")
            run.command("gcc-common", py+["tools/lifter_validation.py", "--compiler", "gcc"], e)
            for i, pattern in enumerate(config["gcc_tests"]):
                run.command("gcc-tests-"+str(i), py+["-m", "unittest", "discover", "-s", "tests", "-p", pattern, "-v"], e)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(msvc), pool.submit(gcc_lane)]
            for future in futures: future.result()
        summary = run.action("native-evidence", lambda: collect_native(run, native, config))
        if not native_only:
            def survey(scope):
                argv = py+["tools/survey_function_profiles.py", prepared, "--report", run.output/(scope+".json")]
                if scope == "plt": argv += ["--plt"]
                run.command("survey-"+scope, argv, env)
            with ThreadPoolExecutor(max_workers=2) as pool: list(pool.map(survey, ("default", "plt")))
            run.command("callee-audit", py+["tools/survey_callees.py", prepared, "--baseline", run.output/"plt.json", "--report", run.output/"callees.json"], env)
            def compare():
                comparisons = {scope: compare_profiles(read_json(ROOT/config["baseline_"+scope]), read_json(run.output/(scope+".json"))) for scope in ("default", "plt")}
                audit = read_json(run.output/"callees.json"); compare_baseline(audit, read_json(run.output/"plt.json"))
                for scope, comparison in comparisons.items():
                    require(not any(comparison["after"]["first_unsupported_mnemonics"].get(m, 0) for m in config.get("cleared_mnemonics", [])), f"selected instruction frontier remains in {scope}")
                require(not any(audit["totals"]["frontier_first_unsupported_mnemonics"].get(m, 0) for m in config.get("cleared_mnemonics", [])), "selected callee frontier remains")
                (run.output/"comparison.json").write_text(json.dumps(comparisons, indent=2)+"\n", encoding="utf-8")
                summary["profiles"] = {s: {"before": {k: v["accepted_regions"] for k, v in c["before"]["profiles"].items()},
                    "after": {k: v["accepted_regions"] for k, v in c["after"]["profiles"].items()},
                    "discovered_before": c["before"]["complete_regions"], "discovered_after": c["after"]["complete_regions"]} for s, c in comparisons.items()}
                summary["remaining_integer_frontier"] = audit["totals"]["frontier_first_unsupported_categories"].get("integer", 0)
            run.action("comparison", compare)
        def publish_summary():
            (run.output/"summary.json").write_text(json.dumps(summary, indent=2)+"\n", encoding="utf-8")
            lines = ["# Milestone validation", "", f"Milestone: {config['name']}", "", f"Python tests: {summary['python_tests']}; CTest groups: {summary['ctest_groups']}; native comparisons per compiler: {summary['native_trials_per_compiler']}."]
            for scope, row in summary.get("profiles", {}).items(): lines += ["", f"{scope}: {row['before']} -> {row['after']} (overlapping structural candidates)."]
            lines += ["", "All executed code is synthetic. Static game analysis grants no runtime capabilities. See run.json for final status and per-stage logs."]
            (run.output/"summary.md").write_text("\n".join(lines)+"\n", encoding="utf-8")
        run.action("summary", publish_summary); run.finish()
    except Exception as error:
        with run.lock:
            run.manifest.update(status="failed", error=str(error)); run.save()
        raise
    print(json.dumps({"status": "passed", "output": str(run.output), **summary}), flush=True)
    return run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT/"config/milestones/integer-frontier.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--native-only", action="store_true", help="validate synthetic code without private game inputs/surveys")
    args = parser.parse_args()
    try:
        execute(read_json(args.config), args.output, args.native_only)
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, ET.ParseError) as error:
        print(f"Milestone validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__": raise SystemExit(main())
