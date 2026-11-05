# ARM64 instruction and control-flow survey

The survey reads verified prepared modules, performs the existing offline link, and analyzes text without executing any guest instructions. It uses Capstone for syntax decoding and project code for metadata, branch targets, PLT recognition, and report construction. It does not generate C or implement instruction semantics.

## Run

Use a project environment so the analysis dependency does not change global Python packages:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --only-binary=:all: -r tools/requirements-analysis.txt
.\.venv\Scripts\python.exe -B tools/analyze_arm64.py build/prepared/oot111 --report build/arm64-report.json
```

The decoder distribution is pinned in `tools/requirements-analysis.txt`. The report records both its distribution version and the binding's version string, which can differ. The dependency remains inside the ignored environment. Windows CI installs the same dependency before running tests.

The report must be under `build/` and outside the prepared input. Syntax-scan progress goes to stderr. Game-derived findings, instruction words, addresses, and assembly-derived counts stay local in the report.

## Discovery method

1. Recheck prepared-file hashes and NSO hashes, construct private module images, and require a complete offline relocation pass.
2. Collect candidate entry addresses from module offset zero, ELF function symbols, init/fini functions and arrays, code pointers stored by relocations, and unwind-header lookup tables.
3. Recognize canonical `ADRP X16; LDR X17; ADD X16; BR X17` PLT stubs only when the computed GOT slot has a matching symbol relocation and the ADD/LDR offsets agree.
4. Decode aligned text in bounded chunks. A successful linear decode is recorded separately from discovered code because data can also form valid instruction encodings.
5. Walk static edges from the candidates. Direct calls add entry candidates; conditional branches follow both possible edges; unconditional branches, returns, traps, and indirect jumps end their current path. Indirect calls retain a possible normal continuation.
6. Mark text referenced by PC-relative literal loads as potential literal data. A conflicting code path remains visible rather than silently discarded. Other unvisited words remain unclassified.

The supported unwind header is version 1 with encodings `1b/03/3b`: PC-relative signed 32-bit EH-frame pointer, unsigned 32-bit entry count, and header-relative signed 32-bit lookup pairs. The table is bounded and sorted; referenced locations are checked. FDE bodies and their CFI instructions are not interpreted, and exact function extents are not established from this table.

An entry candidate is not proof of a distinct function. Address-taken labels and tail-sharing code can produce candidates too. Metadata-rooted discovery is an approximation, not proof of reachability from the game's initial state. Generic calls conservatively retain fallthrough even when a callee may not return; recognized direct `longjmp` calls are an exception.

## Nonlocal calls

Recognized direct branch/call targets through PLT entries named `setjmp`, `_setjmp`, `sigsetjmp`, `__sigsetjmp`, `longjmp`, `_longjmp`, or `siglongjmp` are reported. A `setjmp` call records its continuation offset. A recognized `longjmp` call has no ordinary fallthrough. The nearest known entry candidate is included as a diagnostic hint, not an exact function-ownership proof.

This does not implement nonlocal returns or find arbitrary indirect calls to those functions. A future lifter must preserve guest state and restore the correct host continuation; merely accepting a mnemonic or restoring the ARM64 PC is insufficient.

## Interpreting the report

- `linear_syntax_decoded_words` covers decodable words throughout text, including possible data. It is not code coverage.
- `discovered_code_words` counts decoded words visited by the metadata-rooted traversal. `undecoded_code_frontiers` records places where a rooted path stopped at an undecoded word. Those words may require decoder support or closer code/data inspection.
- `literal_candidate_words` counts unvisited literal hints. `unclassified_words` counts the rest of the unvisited text. `code_literal_conflict_words` exposes ambiguity.
- `function_entry_candidate_count` and `candidate_source_counts` preserve the nature of the entry evidence; source counts overlap.
- Mnemonic and encoding-family histograms describe discovered syntax. SIMD memory operations can remain in the load/store family; ordered/atomic and authentication groups are mnemonic refinements, not an exhaustive architectural feature model.
- Unresolved indirect calls and branches are counted and sampled. Jump tables and arbitrary register values are not resolved yet. In-module direct edges are followed; external direct targets are reported rather than guessed.
- Schema version 2 separates syntax from semantic coverage. With `--lifter-coverage`, `lifter_supported_encoding_words`, `lifter_unsupported_encoding_words`, and `lifter_form_counts` classify discovered syntax using the [C lifter's](arm64-lifter.md) exact encoding decoder. Without this option the counts are null. Supported encodings do not imply complete functions, resolved indirect calls, or successful game execution. This census does not generate or execute translated code.
- `all_code_discovered`, `coverage_is_complete`, `nonlocal_runtime_implemented`, and `guest_code_executed` remain false. Zero undecoded frontiers does not remove unresolved indirect targets or unclassified words.

`--samples N` bounds general diagnostic samples from zero to 4096. Nonlocal direct-call records are retained in full. The tool does not write a complete CFG or translated functions in this milestone.

## Validation and next work

Synthetic tests cover branch displacements, literal widths, indirect boundaries, metadata entries, PLT/GOT matching, nonlocal continuations, undecoded frontiers, ambiguous literals, report accounting, and deterministic output. Run the full suite using the project environment. Decoder integration tests skip when the optional analysis dependency is missing; CI installs it so those tests run.

The integer/control-flow subset now has [native differential verification](arm64-lifter.md). Checked guest-memory access and load/store translation are next. Indirect-target recovery, pointer authentication, atomic/exclusive behavior, SIMD/FP, and nonlocal returns require separate semantic work.

References: [Capstone Python API](https://www.capstone-engine.org/lang_python.html), [Arm A64 instruction set](https://developer.arm.com/documentation/ddi0602/latest), and [ELF function symbol metadata](https://gabi.xinuos.com/elf/05-symtab.html).
