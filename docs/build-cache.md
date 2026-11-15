# Verified build reuse and checkpoint recovery

`tools/object_cache.py` shares compiled C objects between startup profiles and
synthetic native fixture libraries. MSVC still uses the historical `cmake` mode
name: CMake discovers Visual Studio, then these helpers invoke its compiler
directly. The host project and required CTest groups retain Visual Studio/CMake.

Each lookup preprocesses the actual source and all headers. Keys bind that stream,
compiler components, flags and relevant environment; GCC also binds driver specs
and target. Only diagnostic line-marker directories are normalized. Expanded
file/time strings stay intact, and debug/source-location builtins retain full
paths. Compilation receives the untouched preprocessed stream. Reads verify object
size/hash; corrupt entries are quarantined and concurrent publication is atomic.
Each link verifies private object copies. Executables, test outcomes and traces
are never substituted from the shared cache. Separate DLLs retain independent
runtime globals. Same-size/same-timestamp header changes still invalidate objects.

The default private store is `build/object-cache/v1/`. Startup `build.json` and
fixture metadata record reuse counts, object keys/hashes, compiler identity and
preprocessing/compilation/link timings.

## Controlled synthetic measurement

An isolated empty store and a second build in another directory gave these local
measurements. Every build links and executes a fresh synthetic startup executable;
all retire 1,502 instructions with the same full trace digest.

| Compiler | Cold build | Warm build | Cold objects | Warm objects |
| --- | ---: | ---: | --- | --- |
| MSVC 19.44 | 7.535 s | 2.185 s | 20 compiled | 20 reused |
| GCC 14.2 | 7.509 s | 3.874 s | 20 compiled | 20 reused |

Both measurements run in one Python process; cold MSVC includes initial compiler
environment discovery. These are single synthetic measurements, not whole-game build benchmarks. Raw
private evidence is `build/cache-benchmark-20261115-final/report.json`.

The complete local capability run also records cross-profile reuse:

| Profile | MSVC build | GCC build | Objects compiled / reused |
| --- | ---: | ---: | --- |
| Graphics | 44.201 s | 83.341 s | 18 / 317 |
| Display | 39.571 s | 75.556 s | 7 / 328 |

The previous local GCC graphics/display builds took 353.4/338.1 seconds and
compiled all 335 objects in separate caches. This is an observed run comparison,
not an otherwise identical benchmark. Source preparation, execution and proof
verification remain separate costs.

## Interrupted validation

Fresh validation requires a new output directory. Repeat the exact configuration
and output with `--resume` for an interrupted schema-2 run:

```powershell
.venv\Scripts\python.exe -B tools/run_milestone.py `
  --config build/milestones/build-cache-v3/local-config.json `
  --output build/milestones/build-cache-v3/validation --resume
```

Recovery requires identical source/configuration/inputs/toolchain, verified owned
artifacts, unchanged native build binaries/rules and exclusive run ownership.
Actual NUP/RomFS inputs are hashed without copying. Per-command arguments and
relevant environment must match. A gated Windows Job Object owns each command
tree before execution; owner termination kills descendants. A recorded command
that is still active prevents recovery.
Direct post-command startup replays use the same gated ownership and drain their
captured output after timeout cleanup. Run one full milestone at a time per
checkout; the synthetic native report destinations are shared.
Checkpoint publication tolerates brief Windows reader/delete-sharing conflicts
with a bounded retry. Persistent denial preserves the last committed checkpoint
and reports an error. It cannot silently mark a stage successful.

Sealed completed commands can be reused. Postconditions and compiler/cohort
comparisons run again; new full proofs use fresh attempt directories. Interrupted
command outputs/logs are retained separately and that command runs again. Original
entropy is sealed and retained. Failed runs, changed inputs/source or damaged
evidence require a fresh output. Incomplete verification cannot finish passed.

The full configuration is [`build-cache.json`](../config/milestones/build-cache.json).
A private local copy can relocate prepared inputs and historical baseline paths.
This milestone changes build/validation infrastructure, not guest runtime APIs.

## Full validation

`build/milestones/build-cache-v3/validation/run.json` passes all 52 stages with
718 Python tests, seven CTest groups and 283,401 common native/reference
comparisons per compiler. Its current-source gate is
`5f0d3cae98204560d03fc5aa8e397550a8af988d83b2c84e952229648b81c01a`.
Both original display proofs retain digest
`e330868f9e2bbdff0c7bf2b88258ecac138974fd33c7303b8ca2147d1a98bc21`.

The controller was deliberately terminated during the MSVC display full replay,
then the ordinary `--resume` path completed the same run. All commands remained
subject to sealed artifacts/input/toolchain checks and original postconditions.
Fresh proof traces live under `replay-attempt-2/`; canonical JSON reports point
to those actual traces. The interrupted partial trace is retained. The final
manifest records one recovery and every stage verified; no failed or earlier run
was promoted. Earlier v1/v2 attempts remain explicitly incomplete/failed.
