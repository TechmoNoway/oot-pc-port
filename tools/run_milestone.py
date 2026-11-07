"""Validate a complete milestone and collect private evidence; never publish or run game code."""

import argparse
from copy import deepcopy
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


def startup_evidence(report, expected_error, expected_info=None, sdk_stages=None, expected_service=None, expected_port=None):
    """Validate a declared endpoint without equating a diagnostic with boot."""
    require(report['status']=='diagnostic-complete' and report['game_code_executed'] is True and
            report['startup_completed'] is False and report['switch2_startup_abi_proven'] is False,
            'invalid startup experiment scope')
    last=report['iterations'][-1];e=last['execution']
    require(e['retired']>0 and e['status']==2 and e['error']==expected_error,'startup experiment did not reach its declared boundary')
    require(e.get('get_info_request')==expected_info,'startup stopped at a different service request')
    if expected_service is not None:require(e['service']==expected_service,'startup stopped at a different service')
    require(e.get('named_port')==expected_port,'startup stopped at a different named port')
    require(e.get('relative_relocation_probes',0)>0 and e['relative_relocation_probes']==e['relative_relocations_matching_offline_link'],
            'raw rtld self-relocation differs from independent offline expected values')
    if sdk_stages is not None:
        complete=expected_error==15
        require(report.get('sdk_runtime') is True and e.get('sdk_runtime') is True and
                e.get('sdk_stages_completed')==sdk_stages and report.get('sdk_initialization_completed') is complete and
                e.get('sdk_initialization_completed') is complete and e.get('game_entry_reached') is complete,
                'SDK stage/completion evidence differs from the declared goal')
    result={k:e[k] for k in ('status','error','pc','retired','word','service','startup_completed',
        'relative_relocation_probes','relative_relocations_matching_offline_link','trace_sha256')}
    for k in ('get_info_request','named_port','sdk_stages_completed','sdk_initialization_completed','game_entry_reached'):
        if k in e:result[k]=e[k]
    result['compiler']=last['compiler']
    return result


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


def compare_memory(plt, memory):
    require(memory.get('runtime_write_ranges_supplied') is False, 'memory survey supplied runtime write capabilities')
    require(memory.get('policies') == {'plt_leaf':'plt-leaf-stack-dag-v7','checked_memory':'checked-memory-stack-dag-v8'}, 'invalid memory policies')
    require(isinstance(memory.get('memory_clusters'),dict) and memory['memory_clusters'].get('runtime_capabilities_granted') is False,
            'missing static memory/callee cluster evidence')
    # Compare the shared production policy and every module, on identical inputs.
    normalized=[]
    for source in (plt,memory):
        r=deepcopy(source);r['policies']={'plt_leaf':'plt-leaf-stack-dag-v7'}
        r['totals']['profiles']={'plt_leaf':r['totals']['profiles']['plt_leaf']}
        for m in r['modules']:m['profiles']={'plt_leaf':m['profiles']['plt_leaf']}
        normalized.append(r)
    comparison=compare_profiles(*normalized)
    require(comparison['before']==comparison['after'], 'memory survey changed shared policy outcomes')
    a,b=({m['name']:m for m in r['modules']} for r in normalized)
    require(all(a[n]['profiles']==b[n]['profiles'] for n in a), 'memory survey changed per-module policy outcomes')
    return {'source_text_hashes_match':True, 'shared_policy_outcomes_match':True,
            'profiles':memory['totals']['profiles'],'clusters':memory['memory_clusters']}


def compare_memory_callees(before, after):
    require(after.get('runtime_write_ranges_supplied') is False, 'callee survey supplied write capabilities')
    require(after.get('policies') == {'checked_memory':'checked-memory-stack-dag-v8','memory_callees':'memory-callee-stack-dag-v9'}, 'invalid memory callee policies')
    cohort=after.get('memory_callee_cohort')
    require(isinstance(cohort,dict) and cohort.get('runtime_capabilities_granted') is False and cohort.get('game_code_executed') is False and cohort.get('original_bytes_only') is True,
            'missing static original-byte callee cohort')
    normalized=[]
    for source in (before,after):
        r=deepcopy(source);r['policies']={'checked_memory':'checked-memory-stack-dag-v8'}
        r['totals']['profiles']={'checked_memory':r['totals']['profiles']['checked_memory']}
        for m in r['modules']:m['profiles']={'checked_memory':m['profiles']['checked_memory']}
        normalized.append(r)
    c=compare_profiles(*normalized)
    require(c['before']==c['after'],'shared memory policy outcomes changed')
    a,b=({m['name']:m for m in r['modules']} for r in normalized)
    require(all(a[n]['profiles']==b[n]['profiles'] for n in a),'shared per-module memory outcomes changed')
    baseline_frontier=before.get('memory_clusters',{}).get('remaining_callee_frontier')
    if baseline_frontier is not None:
        require(all(cohort['prior_missing_frontier'][k]==baseline_frontier[k] for k in ('dependency_blocked_roots','unique_missing_targets','unique_caller_target_edges')),
                'prior callee frontier does not reproduce the memory baseline')
    return dict(source_text_hashes_match=True,shared_policy_outcomes_match=True,profiles=after['totals']['profiles'],cohort=cohort)


def compare_bounded_memory(before, after):
    require(after.get('runtime_write_ranges_supplied') is False,'bounded survey supplied runtime capabilities')
    require(after.get('policies') == {'memory_callees':'memory-callee-stack-dag-v9','bounded_callees':'bounded-callee-stack-dag-v10'},'invalid bounded policies')
    cohort=after.get('bounded_memory_cohort')
    require(isinstance(cohort,dict) and cohort.get('runtime_capabilities_granted') is False and cohort.get('game_code_executed') is False and cohort.get('original_bytes_only') is True,'invalid bounded cohort')
    require(cohort.get('previous_memory_candidates_lost')==0 and cohort.get('previously_accepted_lost')==0,'bounded policy lost previous candidates')
    normalized=[]
    for source in (before,after):
        r=deepcopy(source);r['policies']={'memory_callees':'memory-callee-stack-dag-v9'}
        r['totals']['profiles']={'memory_callees':r['totals']['profiles']['memory_callees']}
        for m in r['modules']:m['profiles']={'memory_callees':m['profiles']['memory_callees']}
        normalized.append(r)
    c=compare_profiles(*normalized);require(c['before']==c['after'],'shared memory callee outcomes changed')
    a,b=({m['name']:m for m in r['modules']} for r in normalized)
    require(all(a[n]['profiles']==b[n]['profiles'] for n in a),'shared per-module callee outcomes changed')
    baseline=before.get('memory_callee_cohort',{}).get('remaining_missing_frontier')
    if baseline is not None:
        require(all(cohort['prior_missing_frontier'][k]==baseline[k] for k in ('dependency_blocked_roots','unique_missing_targets','unique_caller_target_edges')),'bounded prior frontier differs')
    return dict(source_text_hashes_match=True,shared_policy_outcomes_match=True,profiles=after['totals']['profiles'],cohort=cohort)


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
    if config.get('startup_experiment'):require('startup_context_self_test' in names,'startup context self-test did not execute')
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
    require(type(config.get('memory_survey',False)) is bool and type(config.get('preserve_baseline_outcomes',False)) is bool, 'invalid milestone scope flags')
    require(type(config.get('memory_callee_survey',False)) is bool,'invalid memory callee scope flag')
    if config.get('memory_callee_survey'):require(isinstance(config.get('baseline_memory'),str) and config['baseline_memory'],'memory callee milestone requires prior memory baseline')
    require(type(config.get('bounded_memory_survey',False)) is bool,'invalid bounded scope flag')
    require(type(config.get('startup_experiment',False)) is bool,'invalid startup scope flag')
    require(type(config.get('sdk_experiment',False)) is bool,'invalid SDK scope flag')
    if config.get('sdk_experiment'):
        require(config.get('startup_experiment') is True and isinstance(config.get('baseline_startup'),str),'SDK milestone requires prior raw startup evidence')
        require(type(config.get('sdk_expected_error')) is int and config['sdk_expected_error'] in (8,9,10,11,12,15),'SDK requires a declared stop or initialization goal')
        require(type(config.get('sdk_required_stages')) is int and 0<config['sdk_required_stages']<=32,'SDK requires a declared stage count')
    if config.get('startup_experiment'):
        require(config.get('bounded_memory_survey') is True and isinstance(config.get('baseline_bounded'),str),'startup milestone requires the prior bounded baseline')
        require(type(config.get('startup_expected_error')) is int and config['startup_expected_error'] in (8,9,10,11,12),'startup milestone requires an explicit diagnostic stop')
    if config.get('bounded_memory_survey'):require(isinstance(config.get('baseline_callees'),str) and config['baseline_callees'],'bounded milestone requires callee baseline')
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
        if config.get('memory_callee_survey'):read_json(ROOT/config['baseline_memory'])
        if config.get('bounded_memory_survey'):read_json(ROOT/config['baseline_callees'])
        destination = build_destination(output)
        require(not destination.is_relative_to(prepared) and not prepared.is_relative_to(destination), "milestone output overlaps prepared inputs")
    cmake = Path(find_cmake()); ctest = cmake.with_name("ctest.exe")
    gcc = shutil.which("gcc") or "C:/msys64/ucrt64/bin/gcc.exe"
    require(Path(gcc).is_file(), "GCC is required for milestone validation")
    env = os.environ.copy(); env["PATH"] = str(Path(gcc).parent)+os.pathsep+env.get("PATH", "")
    stages = ["native-configure", "native-build", "msvc-suite", "gcc-common"] + ["gcc-tests-"+str(i) for i in range(len(config["gcc_tests"]))]
    if config.get('sdk_experiment'):stages += ['gcc-sdk-context-build','gcc-sdk-context-test']
    stages += ["native-evidence"] + ([] if native_only else ["survey-default", "survey-plt", "callee-audit", "comparison"]) + ["summary"]
    if not native_only and config.get('memory_survey'): stages.insert(stages.index('comparison'),'survey-memory')
    if not native_only and config.get('memory_callee_survey'): stages.insert(stages.index('comparison'),'survey-memory-callees')
    if not native_only and config.get('bounded_memory_survey'): stages.insert(stages.index('comparison'),'survey-bounded-memory')
    if not native_only and config.get('startup_experiment'):
        stages.insert(stages.index('comparison'),'startup-audit')
        for mode in ('cmake','gcc'):stages.insert(stages.index('summary'),'startup-experiment-'+mode)
    if not native_only and config.get('sdk_experiment'):
        stages.insert(stages.index('comparison'),'sdk-audit')
        for mode in ('cmake','gcc'):stages.insert(stages.index('summary'),'sdk-experiment-'+mode)
    run = MilestoneRun(output, config["name"], stages)
    run.manifest["scope"] = "synthetic native only" if native_only else "synthetic native and static private game analysis"
    if not native_only and config.get('startup_experiment'):
        run.manifest['scope']='synthetic validation, static audits and explicitly authorized experimental original startup execution'
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
            if config.get('sdk_experiment'):
                exe=run.output/'sdk-context-test.exe'
                run.command('gcc-sdk-context-build',[gcc,'-std=c17','-O2','-Wall','-Wextra','-Wpedantic','-Werror',
                    '-D_CRT_SECURE_NO_WARNINGS','-D_WIN32_WINNT=0x0A00','-I',ROOT/'src',ROOT/'tests/startup_context_test.c',
                    *[ROOT/'src'/(name+'.c') for name in ('startup_context','runtime_image','guest_memory','host_win32')],'-lbcrypt','-o',exe],e)
                run.command('gcc-sdk-context-test',[exe,run.output/'sdk-context-test.ootmem'],e)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(msvc), pool.submit(gcc_lane)]
            for future in futures: future.result()
        summary = run.action("native-evidence", lambda: collect_native(run, native, config))
        if not native_only:
            def survey(scope):
                argv = py+["tools/survey_function_profiles.py", prepared, "--report", run.output/(scope+".json")]
                if scope == "plt": argv += ["--plt"]
                if scope == "memory": argv += ["--memory"]
                if scope == "memory-callees": argv += ["--memory-callees"]
                if scope == "bounded-memory": argv += ["--bounded-memory"]
                run.command("survey-"+scope, argv, env)
            scopes=['default','plt']+(['memory'] if config.get('memory_survey') else [])+(['memory-callees'] if config.get('memory_callee_survey') else [])+(['bounded-memory'] if config.get('bounded_memory_survey') else [])
            with ThreadPoolExecutor(max_workers=2) as pool: list(pool.map(survey,scopes))
            run.command("callee-audit", py+["tools/survey_callees.py", prepared, "--baseline", run.output/"plt.json", "--report", run.output/"callees.json"], env)
            if config.get('startup_experiment'):
                run.command('startup-audit',py+['tools/audit_startup.py',prepared,'--report',run.output/'startup-audit.json'],env)
            if config.get('sdk_experiment'):
                run.command('sdk-audit',py+['tools/sdk_startup_audit.py',prepared,'--report',run.output/'sdk-audit.json'],env)
            def compare():
                comparisons = {scope: compare_profiles(read_json(ROOT/config["baseline_"+scope]), read_json(run.output/(scope+".json"))) for scope in ("default", "plt")}
                audit = read_json(run.output/"callees.json"); compare_baseline(audit, read_json(run.output/"plt.json"))
                for scope, comparison in comparisons.items():
                    if config.get('preserve_baseline_outcomes'):
                        require(comparison['before']==comparison['after'], 'existing policy baseline outcomes changed')
                        before,after=(read_json(p) for p in (ROOT/config['baseline_'+scope],run.output/(scope+'.json')))
                        a,b=({m['name']:m for m in r['modules']} for r in (before,after))
                        require(all(a[n]['profiles']==b[n]['profiles'] for n in a), 'existing per-module policy baseline outcomes changed')
                    require(not any(comparison["after"]["first_unsupported_mnemonics"].get(m, 0) for m in config.get("cleared_mnemonics", [])), f"selected instruction frontier remains in {scope}")
                require(not any(audit["totals"]["frontier_first_unsupported_mnemonics"].get(m, 0) for m in config.get("cleared_mnemonics", [])), "selected callee frontier remains")
                (run.output/"comparison.json").write_text(json.dumps(comparisons, indent=2)+"\n", encoding="utf-8")
                summary["profiles"] = {s: {"before": {k: v["accepted_regions"] for k, v in c["before"]["profiles"].items()},
                    "after": {k: v["accepted_regions"] for k, v in c["after"]["profiles"].items()},
                    "discovered_before": c["before"]["complete_regions"], "discovered_after": c["after"]["complete_regions"]} for s, c in comparisons.items()}
                summary["remaining_integer_frontier"] = audit["totals"]["frontier_first_unsupported_categories"].get("integer", 0)
                if config.get('memory_survey'):
                    evidence=compare_memory(read_json(run.output/'plt.json'),read_json(run.output/'memory.json'))
                    (run.output/'memory-comparison.json').write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
                    summary['memory_profiles']={k:v['accepted_regions'] for k,v in evidence['profiles'].items()}
                    summary['memory_clusters']={k:v for k,v in evidence['clusters'].items() if k not in ('samples','remaining_callee_frontier')}
                    summary['memory_callee_frontier']={k:v for k,v in evidence['clusters']['remaining_callee_frontier'].items() if k!='samples'}
                if config.get('memory_callee_survey'):
                    evidence=compare_memory_callees(read_json(ROOT/config['baseline_memory']),read_json(run.output/'memory-callees.json'))
                    (run.output/'memory-callee-comparison.json').write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
                    summary['memory_callee_profiles']={k:v['accepted_regions'] for k,v in evidence['profiles'].items()}
                    summary['memory_callee_cohort']={k:v for k,v in evidence['cohort'].items() if k not in ('samples','rejected','prior_missing_frontier','remaining_missing_frontier')}
                    for key in ('prior_missing_frontier','remaining_missing_frontier'):
                        summary['memory_callee_cohort'][key]={k:v for k,v in evidence['cohort'][key].items() if k!='samples'}
                if config.get('bounded_memory_survey'):
                    evidence=compare_bounded_memory(read_json(ROOT/config['baseline_callees']),read_json(run.output/'bounded-memory.json'))
                    (run.output/'bounded-comparison.json').write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
                    summary['bounded_profiles']={k:v['accepted_regions'] for k,v in evidence['profiles'].items()}
                    summary['bounded_cohort']={k:v for k,v in evidence['cohort'].items() if k not in ('samples','rejected','prior_missing_frontier','remaining_missing_frontier')}
                    for key in ('prior_missing_frontier','remaining_missing_frontier'):
                        summary['bounded_cohort'][key]={k:v for k,v in evidence['cohort'][key].items() if k!='samples'}
                if config.get('startup_experiment'):
                    old,new=(read_json(p) for p in (ROOT/config['baseline_bounded'],run.output/'bounded-memory.json'))
                    c=compare_profiles(old,new)
                    require(c['before']==c['after'] and old['bounded_memory_cohort']==new['bounded_memory_cohort'],'startup changed bounded policy outcomes')
                    require({m['name']:m['profiles'] for m in old['modules']}=={m['name']:m['profiles'] for m in new['modules']},'startup changed per-module bounded outcomes')
                    a=read_json(run.output/'startup-audit.json')
                    require(a.get('format')=='oot-startup-audit' and all(a.get(k) is False for k in ('guest_code_executed','translation_performed','native_callbacks_registered','runtime_capabilities_granted','startup_abi_proven','initialization_order_proven')),'invalid startup audit scope')
                    identities=lambda r:{m['name']:tuple(m.get(k) for k in ('base','source_sha256','linked_text_sha256')) for m in r['modules']}
                    require(identities(a)==identities(new),'startup audit input identities differ')
                    require(not a['entry_graph']['truncated'],'startup entry audit was truncated')
                    summary['startup_audit']={'initializer_summary':a['initializer_summary'],'entry_instructions':a['entry_graph']['instruction_count'],'static_frontier':a['entry_graph']['frontier_counts']}
            run.action("comparison", compare)
            if config.get('startup_experiment'):
                experiments={}
                seeds=[]
                if config.get('sdk_experiment'):
                    baseline=read_json(ROOT/config['baseline_startup'])
                    require(baseline['format']=='oot-startup-experiment' and baseline['startup_completed'] is False,'invalid prior startup evidence')
                    seeds=baseline['iterations'][-1]['additional_entries']
                for mode in ('cmake','gcc'):
                    folder=run.output/('startup-'+mode)
                    args=py+['tools/build_startup.py',prepared,'--output',folder,'--compiler',mode,'--execute','--expand-targets','64','--limit','100000000','--quantum','10000']
                    for pc in seeds:args+=['--extra-entry',str(pc)]
                    run.command('startup-experiment-'+mode,args,env)
                    experiments[mode]=startup_evidence(read_json(folder/'run.json'),config['startup_expected_error'],config.get('startup_expected_get_info'))
                    if config.get('sdk_experiment'):
                        prior=baseline['iterations'][-1]['execution']
                        require(all(experiments[mode][k]==prior[k] for k in ('status','error','pc','retired','word','service','trace_sha256')),'legacy original startup prefix changed')
                require(all(experiments['cmake'][k]==experiments['gcc'][k] for k in ('status','error','pc','retired','word','service','trace_sha256')),'native compilers reached different startup prefixes')
                summary['startup_experiments']=experiments
            if config.get('sdk_experiment'):
                audit=read_json(run.output/'sdk-audit.json')
                require(audit['format']=='oot-sdk-startup-audit' and audit['guest_code_executed'] is False and audit['startup_completed'] is False and audit['npdm']['declarations_complete'] is True,'invalid SDK audit scope')
                original=read_json(run.output/'startup-audit.json')
                require({m['name']:(m['base'],m['source_sha256'],m['original_text_sha256']) for m in audit['modules']}==
                        {m['name']:(m['base'],m['source_sha256'],m['linked_text_sha256']) for m in original['modules']},'SDK audit source/text identities differ')
                require(config['sdk_required_stages']<=len(audit['mandatory_stage_entries']),'SDK required stage count exceeds audited stages')
                if config['sdk_expected_error']==15:
                    require(config['sdk_required_stages']==len(audit['mandatory_stage_entries']),'SDK initialization requires every audited stage')
                entropy=run.output/'process-entropy.bin'
                with entropy.open('xb') as stream:stream.write(os.urandom(32))
                sdk_experiments={}
                for mode in ('cmake','gcc'):
                    folder=run.output/('sdk-'+mode)
                    args=py+['tools/build_startup.py',prepared,'--output',folder,'--compiler',mode,'--sdk','--entropy-file',entropy,'--execute','--expand-targets','64','--limit','1000000000','--quantum','10000']
                    for pc in seeds:args+=['--extra-entry',str(pc)]
                    run.command('sdk-experiment-'+mode,args,env)
                    result=read_json(folder/'run.json')
                    require(result['entropy_input_sha256']==hashlib.sha256(entropy.read_bytes()).hexdigest(),'SDK experiment used different private process entropy')
                    bundle=read_json(Path(result['iterations'][-1]['bundle'])/'manifest.json')
                    require(bundle['sdk_npdm']['source_sha256']==audit['npdm']['source_sha256'] and
                            bundle['sdk_audit']['goal_entry']==audit['goal_entry'] and
                            bundle['sdk_audit']['mandatory_stage_entries']==audit['mandatory_stage_entries'],'SDK executable was generated from different goal/metadata evidence')
                    sdk_experiments[mode]=startup_evidence(result,config['sdk_expected_error'],config.get('sdk_expected_get_info'),config['sdk_required_stages'],config.get('sdk_expected_service'),config.get('sdk_expected_port'))
                require(all(sdk_experiments['cmake'][k]==sdk_experiments['gcc'][k] for k in ('status','error','pc','retired','word','service','trace_sha256','sdk_stages_completed','sdk_initialization_completed')),'native compilers reached different SDK prefixes')
                summary['sdk_experiments']=sdk_experiments
                summary['sdk_initialization_completed']=config['sdk_expected_error']==15
        def publish_summary():
            (run.output/"summary.json").write_text(json.dumps(summary, indent=2)+"\n", encoding="utf-8")
            lines = ["# Milestone validation", "", f"Milestone: {config['name']}", "", f"Python tests: {summary['python_tests']}; CTest groups: {summary['ctest_groups']}; native comparisons per compiler: {summary['native_trials_per_compiler']}."]
            for scope, row in summary.get("profiles", {}).items(): lines += ["", f"{scope}: {row['before']} -> {row['after']} (overlapping structural candidates)."]
            if 'memory_profiles' in summary:
                clusters, frontier = summary['memory_clusters'], summary['memory_callee_frontier']
                lines += ['', f"Memory policies: {summary['memory_profiles']}; newly accepted roots: {clusters['newly_accepted_roots']}; distinct upgraded frame edges: {clusters['unique_frame_call_edges']}.",
                    '', f"Remaining callee frontier: {frontier['dependency_blocked_roots']} blocked roots, {frontier['unique_missing_targets']} unique missing targets, {frontier['unique_caller_target_edges']} distinct caller/target edges. Root references overlap."]
            lines += ["", ("Native regression execution is synthetic. Separate opt-in startup experiments execute selected original instructions under an experimental process model; startup is not complete." if 'startup_experiments' in summary else "All executed code is synthetic.")+" Static game analysis grants no runtime capabilities. See run.json for final status and per-stage logs."]
            if 'memory_callee_profiles' in summary:
                cohort=summary['memory_callee_cohort']
                lines += ['',f"Memory callees: {summary['memory_callee_profiles']}; newly accepted roots: {cohort['newly_accepted_roots']}; used memory leaves: {cohort['unique_used_memory_leaves']}; distinct upgraded closure edges: {cohort['unique_call_edges']}."]
            if 'bounded_profiles' in summary:
                c=summary['bounded_cohort']
                lines += ['',f"Bounded memory: {summary['bounded_profiles']}; new leaves: {c['candidate_memory_leaves']} ({c['new_loop_leaves']} loops); upgraded roots: {c['newly_accepted_roots']}; distinct closure edges: {c['unique_call_edges']}."]
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
