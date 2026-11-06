# Checked memory and callee clusters

Policy 8 (`checked-memory-stack-dag-v8`) adds checked scalar and paired integer stores to the existing PAC/LR-pair frame and exact PLT-to-register-leaf contracts. Schema 9 and `oot_stack_create_memory` are explicit opt-ins. Policies 1-7, their constructors and descriptor layouts keep their previous permissions. Game callbacks are neither generated nor executed by this milestone's surveys or tests.

## Effects and permissions

The new policy uses the existing copied `OotStackCallFunction` layout with policy version 8. Its `read_words` table contains the exact original opcode at each READ or WRITE step, and zero elsewhere. The native constructor decodes those words, verifies the declared effect/destination domain, binds them to retained read-only text and checks the original code hashes. The old read constructors still accept only READ words at checked-effect steps.

Accepted stores are STRB/STRH/STR W/X with unsigned scaled immediate, signed unscaled immediate or UXTW/LSL/SXTW/SXTX register offset; and offset STP W/X. Register 31 supplies zero for transferred values. Same-source pairs and base/index/source aliases read the pre-instruction register values. Writeback, non-temporal/vector stores, release/atomic/RMW stores and pointer-authenticated memory forms remain excluded. The raw lifter has a wider address-mode domain; that does not expand this verified policy.

Reads keep the existing [checked-read operand protocol](checked-reads.md). Read and write grants are separate copied lists of 0-128 sorted, disjoint, nonempty ranges. Each grant must fit wholly within a single retained image region with the corresponding permission. An empty list grants no external access of that kind. A readable range does not imply a write grant, and a write grant does not imply a read grant. The runtime checks the whole operand against one grant; adjacent grants cannot be combined. Writable data and BSS may evolve between yields without invalidating the initial snapshot identity.

Unreserved bytes of the current owned frame remain accessible, including through GPR aliases. FP/LR records and saved-register slots, parent/ancestor locals, unowned stack bytes, frame-crossing accesses and the rest of the stack are excluded. SP/FP-based addresses must remain inside the current frame. General heap buffers, MMIO, address tagging, guest threading and a process ABI are not provided.

## Store transaction

For each WRITE instruction the dispatcher performs these steps:

1. Decode its bound original word using the suspended checkpoint, then validate the complete effective address against ownership or an explicit write grant.
2. Probe the real backend for whole-operand write permission without reading or changing backing bytes. `oot_memory_probe` uses the same serialized backend lock as every scalar/pair/acquire transfer. A probe is not a reservation; commit checks again.
3. Independently compute the exact little-endian bytes and full next integer state. The callback gets one private write-only operand window of 1-16 bytes, initialized to the complement of the expected bytes. No readable image/frame window is supplied for this step.
4. Run exactly one callback instruction. Validate its status, retirement, PC edge, every register/SP/NZCV, all operand bytes, window pointer/count/validity and region base/size/backing/permissions. An omitted or partial write cannot pass because untouched bytes differ from the expected bytes.
5. After every contract check passes, commit through the real scalar or paired store backend. A pair is committed as one whole-pair transfer. Update the owned-frame checkpoint when the target was local, then publish the next CPU checkpoint and one retired instruction.

Range denial (`OOT_STACK_BAD_WRITE_RANGE`, 56) and backend failure (`OOT_STACK_BAD_MEMORY`, 50) occur before the callback or at checked commit, retire nothing and preserve guest state/backing for that access. The same checkpoint is retriable. A callback effect violation (`OOT_STACK_BAD_WRITE_EFFECT`, 57), bad count/status/edge or illegal memory access latches a contract fault and cannot commit the staged operand. Earlier retired instructions retain their effects. This is the project's deterministic whole-transfer fault policy, not a model of hardware partial writes.

The registry retains its image and immutable PAC key context; copied functions, effect words, flow/layout tables and grants survive caller storage changes or releases. Signed LR, saved slots, all ancestor checkpoints, exact PLT instructions/current GOT binding and bounded budgets/depth stay enforced. Callbacks remain trusted native code; the operand window is a protocol boundary, not a security sandbox. Runtime/dispatcher APIs remain single-threaded.

## Bundle and survey interfaces

Schema 9 uses the existing explicit frame/leaf selections, PAC model and return sites. It requires `read_ranges` and `write_ranges` lists, either of which may be empty. Range entries specify `module`, `offset`, `size`. `plts` may be absent or empty when no stub is called; supplied stubs must pass the unchanged relocation-backed, nonlocal-free, single registered ordinary-leaf proof. No guest PC is cast into a native function pointer.

```powershell
.venv\Scripts\python.exe -B tools/run_milestone.py `
  --config config/milestones/checked-memory.json `
  --output build/milestones/checked-memory-v3
```

The reviewed config selects complete MSVC CTest/Python and GCC common/new-capability checks, fresh default/PLT/memory surveys and the policy-6 callee audit. Existing profile totals and per-module outcomes must match the preceding integer-frontier baseline. The new memory survey must reproduce the fresh shared policy-7 outcomes, input/text identities, metadata limits, decoder and PAC model. A source fingerprint mismatch rejects completion.

A separate static report is available with `tools/survey_function_profiles.py <prepared> --memory --report <fresh-build-path>`. It compares the real policy-7 and policy-8 verifiers on unchanged bytes and actual transitive callees. `memory_clusters` separates newly accepted roots, distinct frame/edge unions, connected components and transitions from former memory-first rejections. Its remaining callee frontier distinguishes unique missing targets, caller-region/target edges and overlapping blocked-root references, preserving metadata discovery failures and diagnostic PLT target snapshots. These reports supply no live read/write grants or GOT guarantees and never emit or execute game C.

## Evidence and limits

The synthetic checked-memory suite covers 62 address/source combinations across byte, halfword, W/X and paired stores, aligned/unaligned addresses, ZR and aliases, local SP/FP accesses, BSS, mixed PAC/LR-pair caller/callee/PLT execution, all incoming NZCV values and a 16-frame/4096-byte stack. It compares 887 complete calls and 11,551 yielded prefixes per compiler with the pinned enabled QARMA5 reference, including every register and all stack/RW/BSS bytes. Independent little-endian byte results and a whole-call formula supplement the reference.

Negative cases cover 12 faulty callbacks, omitted writes, changed bound words, load-in-WRITE metadata, protected/ancestor slots, operand and capability boundaries, a pair crossing a grant, adjacent grants, readable-only data, backend permission failures/retry, prior constructor rejection, copied metadata and retained lifetimes. Two actual schema-9 factories exercise both signing keys, authentication return styles and a synthetic relocation-backed PLT: 160 calls and 4,000 single-instruction prefixes per compiler. All executed code and inputs in these tests are synthetic.

The local 1.1.1 static results and remaining callee frontier are recorded in [the function-profile report](function-profile-survey.md). Acceptance describes bounded structural candidates with runtime obligations, not original function identity, complete instruction coverage or game readiness. Unframed memory helpers, further frame/save layouts, cyclic/wider/indirect calls, SIMD/FP, atomics and host services remain separate work.
