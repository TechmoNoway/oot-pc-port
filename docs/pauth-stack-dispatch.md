# PAC-aware verified dispatch

Policy `pauth-layout-stack-dag-v4` is an explicit opt-in extension of the fixed-layout frame model. Registry schema 5 requires `pauth_model: "qarma5-va39-tbi0-basic"`. Policies 1-3, registry schemas 1-4, their callback layouts, and default survey behavior keep their existing rules.

The verifier decodes every original word with the separate PAC decoder. It does not remove PAC instructions, replace returns, adjust branches, or change source hashes. Every framed function requires exactly one PACIASP/PACIBSP at entry, followed by a supported combined or split fixed frame. Matching RETAA/RETAB or matching AUTIASP/AUTIBSP followed by RET X30 must end the function. Branches cannot enter signing, frame setup, authentication, or the middle of the restore tail. Saved X19-X28 slots, sparse layouts, local-memory restrictions, finite CFG/call bounds, and exact FP/SP phases are inherited from the fixed-layout policy.

All framed callees in a schema-5 closure must satisfy this PAC policy. Ordinary verified register-only leaves remain valid callees. Mixed unsigned framed callees, PAC register-only leaves, loops, indirect calls, and tail calls are outside this profile. Missing dependencies are rejected; surveys never synthesize replacements.

## Context and state ownership

`OotStackPauthFunction` wraps the existing layout descriptor, supplies a distinct PAC callback pointer, and declares exact signing/authentication words. The old callback slot must be NULL. C validates the complete descriptor, matching keys, CFG, frame ownership phases, and weighted instruction bounds before registration. Only trusted compiled native symbols may populate these callback slots.

`oot_stack_create_pauth` retains the verified runtime image and the immutable `OotPauth` context. `oot_pauth_retain` and `oot_pauth_destroy` provide single-threaded reference counting; the caller may release its own handles while the dispatcher continues. Contexts cannot be replaced during a call or yield. Keys are never embedded in generated bundles or manifests. Existing code/snapshot hashes bind the original bytes, while the retained context defines the key identity for all activations in that dispatcher.

Each activation tracks its canonical entry LR and its signed LR separately. The signing step must produce the exact expected PAC bits for the entry SP/key. The frame record must store that signed LR. BL changes the live LR to its continuation; returning from a PAC child may leave the child's signed LR live until the parent restores its own record. Record restoration/deallocation must recover the parent's exact signed LR. AUT must restore the original canonical LR. RETAA/RETAB must preserve the signed LR and branch to the caller-approved canonical return.

The dispatcher performs authentication preflight against that approved return before accepting AUT/RET effects. Failed authentication or a callback contract failure latches a contract fault and leaves that step unretired and uncommitted. This is a project verification boundary: the standalone basic PAuth model still retires an AUT failure with a poisoned pointer. Do not confuse the dispatcher's transactional rejection with an architectural FPAC exception.

All current and ancestor frames stay byte-for-byte protected across yields while allocated, including the interval after restoring FP/LR but before deallocation. Checkpoint edits, changed code, incorrect PAC/SP/FP/LR, skipped signing, bad edges/counts/statuses, and unauthorized stack writes fail before committing the offending step. Ordinary local accesses use the existing private frame window and whole-store preflight. Guest return values never become native code pointers.

## Preparing an explicit bundle

Schema 5 uses the existing prepared-input/complete-link path and explicit function selections:

```json
{
  "schema_version": 5,
  "pauth_model": "qarma5-va39-tbi0-basic",
  "root": "root",
  "frames": [{"name": "root", "module": "main", "offset": 16, "size": 40}],
  "leaves": [],
  "return_sites": [4297097216],
  "stack_size": 4096
}
```

The ranges above are illustrative synthetic values, not a game selection. Use `tools/prepare_registry.py` as documented for other bound registries. Output stays under a fresh `build/` directory. Schema 5 emits an `oot_create_bound_registry(image, pauth, error)` factory with the additional context argument. It generates no keys. Creating a registry does not begin execution or establish a process startup ABI. Current validation only compiles and registers synthetic selections.

## Validation and survey

```powershell
.venv\Scripts\python.exe -B tools\pauth_stack_validation.py --compiler cmake
.venv\Scripts\python.exe -B tools\pauth_stack_validation.py --compiler gcc
.venv\Scripts\python.exe -B tools\survey_function_profiles.py build/prepared/oot111 `
  --pauth --report build/function-profiles/oot111-pauth-v4.json
```

The native tests pass 93 complete cases and 2,205 reference-prefix checks on both MSVC and GCC. They exercise nested branching calls into PAC frames and ordinary leaves, both keys and return styles, all ten saved registers, eight layout combinations, the full 16-frame/4,096-byte stack boundary, zero/partial budgets, 11 malformed callback modes, altered descriptors/hashes/checkpoints, ancestor-frame corruption, and retained context/image ownership. Separate tests compile actual schema-5 factories and verify CLI rollback/output boundaries. All code, data, and keys used for execution are synthetic.

The fresh local 1.1.1 PAC survey considers 284,396 metadata entries and discovers 115,164 bounded semantic regions. The real policy accepts **1,686 PAC framed candidate regions**, containing 13,494 declared instruction words: 1,685 in main and one in sdk. The default survey still accepts 40,038 register-only leaf candidates and zero framed candidates under its older policies. Module source and linked-text hashes match across both surveys. These are structural candidate-region results, not original function identity, universal semantic equivalence, whole-game coverage, or runtime readiness.

The PAC survey before RCpc support exposed 39,893 first unsupported ordered/atomic frontiers, including 34,202 LDAPRB frontiers. The [RCpc load milestone](ordered-loads.md) now supplies that raw semantic subset and its memory/threading contract. Its broader discovery reaches 127,551 regions, while this profile's acceptance remains 1,686 because its permitted memory effects are unchanged. Frame-local memory restrictions, function-size limits, unavailable callees, indirect control flow, and additional instruction families remain blockers. Full private reports stay ignored. No game callbacks were generated, registered, or executed by either survey.

The separate [checked-read policy 5/schema 6](checked-reads.md) adds explicit readable retained-image ranges and private operand snapshots. This policy-4 constructor and its permissions remain unchanged. The newer static survey accepts 1,688 structural candidates, with dynamic address/ownership/alignment obligations and no runtime ranges granted by the survey.
