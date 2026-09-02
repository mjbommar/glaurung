# Decompiler roadmap diary — 2026-08-31

> **Kind:** record · **Date:** 2026-09-01

## Entry 1 — Full-corpus evidence changes the order

The pinned full DecBench run accounted for 803 binaries and 94,575 functions.
Glaurung returned 94,358 bodies. Its strongest relative results are optimized
and inlined; its large-function absolute perfection is near zero.

Decision: preserve the optimized deterministic core and prioritize its tail:
missing-body identity, large functions, O2 structure, PE/PDB, controlled
malware-shaped assets, then broader matrix work. Adding an LLM is not a
response to this evidence.

Durable plan:
[real-binary-decompiler-roadmap-2026-08-31.md](../../../development/roadmap/real-binary-decompiler.md).

## Entry 2 — “217 decompiler failures” was the wrong model

I read every terminal decompile checkpoint rather than inferring from final
metric nulls.

Observed:

* 803/803 commands returned zero and parsed;
* no conversion, duplicate-address, or outside-return errors occurred;
* 186 manifest names never resolved to requested addresses;
* 31 requested ARM addresses returned no body;
* PE accounts for 171 rows, all in the first class;
* ARM accounts for all 31 genuine no-body returns;
* four PE malware projects account for 171/217 rows.

Most of the 217 belong first to function identity and format semantics, not
structuring or rendering. The complete ledger is
[decbench-full-failure-taxonomy-2026-08-31.md](../campaigns/decbench-full-failure-taxonomy-2026-08-31.md).

Confidence is high for the mechanisms and counts, provisional for root-cause
families. Checkpoints prove what happened, not why each identity was missing.

## Entry 3 — The compile denominator has a separate evaluator gap

Thirteen O2 Dexter functions have bodies and byte-match values but no compile
fact because original PE function bytes were unavailable to the evaluator.
They are not among the 217. Track them as E1 evaluator byte-extraction gaps.
Keep body coverage, compilation evidence, and metric availability as separate
contracts.

## Entry 4 — Test and asset estate implications

The generated inventory and test-estate plan correctly identified skew and
reachability first. Subsequent commits wired dead triage tests, added CI,
repaired adversarial assets, removed 12.9 MB of unused images/broken metadata,
and added a reachability ratchet.

Two new conclusions:

1. Inventory regeneration must be atomic. The live README/findings say 77
   unreachable entries while `coverage.md` still embeds the original 89-entry
   snapshot.
2. Reachability cannot say whether tests resemble real binaries. Add oracle,
   format, architecture, compiler, optimization, stripping,
   packing/obfuscation, language, size, provenance/license, and ground-truth
   strength to the schema.

## Entry 5 — Fixtures without benchmark leakage

The full-run failures motivate independent fixtures, not copied bodies:

* PE entry/TLS/SEH/import/export/application-thread identity;
* Cortex-M SVC/PendSV/SysTick vectors with Thumb aliases;
* O0/O2/O2-noinline helper presence and folding;
* ARM linker veneers;
* ELF `printf`/`__printf__` aliases;
* large switches, state machines, cleanup ladders, irreducible CFGs, and
  alias-heavy large functions.

Each fixture starts with a failing test and lands with its runner, baselines,
provenance, and oracle. DecBench remains held out.

## Next experiment

Build an address-identity report for one representative of each provisional
F1 family:

1. Dexter `DllEntryPoint` or a TLS alias;
2. Mydoom `malloc` or `massmail_main_th`;
3. x0r-usb `RemoteUSBThread`;
4. U-Boot `j_sub_608002ec`;
5. gzip `__printf__`.

Capture original manifest VA, original/stripped section,
symbol/import/export identity, alias set, discovered start, and exact rejection
point. Only then should family labels become root causes or product changes.

## Entry 6 — Two causes proved

The representative trace generalized across all rows rather than remaining a
five-sample anecdote.

For F1, canonicalizing only for analysis (strip leading underscores and a
terminal i386 stdcall `@N`) finds a real nonzero function symbol for 33/186
rows. The production resolver tries only `name` and `_name`; it therefore
misses `_RemoteUSBThread@4`, `_massmail_main_th@4`, `_DetectShutdown@16`,
`_DllEntryPoint@12`, and their peers. All fifteen x0r-usb misses are this
class. This is now F1a. The other 153 names remain F1b and are not presumed to
have the same fix.

For F2, disassembly of all 14 unique missing names shows every function begins
with or immediately requires Cortex-M `MRS`/`MSR` access to `BASEPRI`,
`BASEPRI_MAX`, `IPSR`, or `PSP`. This covers all 31 occurrences across six
firmware/RTOS projects. Current ARM32 lift code has no matching implementation.
This is F2a, a special-register lift gap, not a generic Thumb normalization
failure.

Roadmap consequence: stdcall identity and ARM32 MRS/MSR are now the first two
TDD increments. They have bounded predicted impact (33 and 31 rows) and need
independent fixtures before product changes.

## Entry 7 — Every F1 row has a binary-evidence class

Comparing all 186 unresolved names against the exposed Glaurung map, the full
object function table, and the PE import table yields an exhaustive partition:

* F1a: 33 decorated local code symbols;
* F1b: 63 import-only identities with no local function body;
* F1c: 90 names absent from both function symbols and imports.

No object-table function was hidden by Glaurung beyond the 33 decoration
matches. F1b is not repaired by decompiling an IAT slot: the honest output is
an external/import fact, with DecBench deciding whether that fact is excluded
or represented in scoring. F1c remains a provenance problem: 75 PE
entry/TLS/SEH-style aliases, ten U-Boot veneer/start labels, three Crazyflie
`start` labels, and two gzip `__printf__` labels.

The taxonomy is now complete at the evaluated-binary evidence boundary. The
next research step is upstream source-CFG provenance for F1c, not more symbol
normalization guesses.

## Entry 8 — F1c is mostly a manifest consistency defect

The published source-CFG maps close another boundary:

* 88/90 F1c names are absent from their binary's source-CFG map as well as all
  binary identities;
* only the two gzip `__printf__` rows have source CFGs;
* each `__printf__` CFG is one node containing mostly unsupported source
  statements and `return retval`, with no final-image symbol or import.

The 88 are now F1c manifest-only rows. No address-based decompiler can recover
them from the supplied evidence, so the right control is a dataset consistency
validator, not guessed function discovery. The two gzip rows become F1d and
need source/preprocessor/build provenance before deciding whether they are
eliminated wrappers or an extraction error.

This completes classification of every missing-body row at all evidence layers
available in the published full dataset: manifest, source CFG, symbols/imports,
request construction, discovery, and body return.

## Entry 9 — Large is a curve, not a preset

I bucketed all 94,358 returned bodies by recovered-C line count. Compilation
falls from 84.6% at 25–49 lines to 74.1% at 50–99, 67.7% at 100–199, 56.7% at
200–499, and 36.2% at 500–999. Perfect GED falls from 21.8% to 5.4%, 0.9%,
0.6%, and 0.3% over the same buckets. No 100+ line body is byte-perfect; no
1,000+ line body is perfect on GED, type, or byte.

This makes the official `large` rank a weak guide to engineering order. The
problem begins below the preset threshold and mixes source shape, output
expansion, ABI/type complexity, and true scaling. The next asset must be a
controlled size-by-shape ladder with per-phase telemetry, not a bag of very
large binaries.

Detailed plan:
[large-function-plan-2026-08-31.md](../../../development/roadmap/large-functions.md).

## Entry 10 — The inventory cannot currently reproduce itself

The count drift has a structural cause, not just a missed refresh. The
generator writes JSON, YAML, and unreachable JSON, but never writes
`coverage.md`. More importantly, its five required survey-fragment inputs are
not committed anywhere. No CI/test invokes it and there is no `--check` mode.

The current machine-readable snapshot is internally consistent at commit
`78ad620e`: 984 entries and 77 unreachable. `coverage.md` remains a separate
manual snapshot at `2ce51f9d`: 986 and 89. Editing those two numbers would not
make the inventory authoritative.

Decision: recover canonical territory JSONL from the retained `territory`
field, version the schema, generate every derived view atomically, add a
read-only stale check, then migrate reachability from substring inference to
explicit runner records. New real-binary dimensions are added after the
renewable substrate exists.

Detailed plan:
[test-inventory-authority-plan-2026-08-31.md](../../../development/roadmap/test-inventory-authority.md).

## Entry 11 — The real-world gap is oracle depth, not sample count

The asset audit changed the R5 starting point. `tests/realistic_corpus/`
already builds real x86-64 ELF executables from owned source, carries 83
ground-truth addresses, records tool versions, and constructs eleven ordinary
and hostile variants. It is valuable infrastructure, but its current baseline
is dominated by discovery recall. A discovered address is not evidence that a
useful or semantically faithful body was recovered.

The rest of the estate is uneven. Ten packed samples cover UPX9 only; the
adversarial set is mainly parser/triage evidence; 30 genuine Windows binaries
have hashes and discovery evidence but neither source truth nor blanket
redistribution permission; Mach-O is thin; and the MSVC/PDB lane may skip when
its fetched assets are absent. `samples/binaries/index.json` lists only 552
paths while 736 files currently exist, so it is not an authority.

Decision: first promote the existing realistic corpus to classified body
accounting, a selected compile/execution oracle, suspicious-signal predicates,
and mandatory release-lane execution. Next add source-grounded PE and ARM
families. Keep third-party production binaries as internal robustness probes,
never as semantic ground truth, and commit only inert hostile demonstrations.

Detailed plan:
[real-world-malware-asset-plan-2026-08-31.md](../../../development/roadmap/real-world-malware-assets.md).

## Entry 12 — A wired measurement is not yet a performance gate

The repository already moved beyond the original estate finding: commit
`a5f47189` added `tools/perf_gate.py` and wired it into
`scripts/decbench-local-gate.sh`. It measures the shipped Python
`decompile_all` path on three committed binaries and prefers retired
instructions over noisy wall time. Ten Criterion targets and a cold/warm
profiler provide substantial diagnostic depth.

The acceptance claim is still false. `bench/perf_baseline.json` does not
exist. Missing baselines, unit mismatches, and partial reference measurements
exit zero, so the surrounding script prints `ok` without a comparison. The
report lacks build and input hashes, release-profile proof, completeness,
output, and RSS fields. The wall-clock path ignores the child's return code.

Determinism is in better shape than the old plan suggests:
`test_decompile_determinism.py` exercises repeated same-process calls,
sequential and concurrent subprocesses, x86-64 ELF, ARM64 ELF, PE, and known
Rust DecBench-render flippers. What is missing is a retained release artifact
binding those results to the same build, assets, body counts, and performance
samples.

Decision: preserve these tools, make measurement outcomes typed and fail
closed, pin release/input/host provenance, and ratchet cost only alongside
body/refusal completeness and deterministic output. No fresh baseline is
valid today because concurrent Rust edits make the installed extension stale;
`build_guard.py` correctly refuses it.

Detailed plan:
[performance-determinism-ratchet-plan-2026-08-31.md](../../../development/roadmap/performance-determinism-ratchet.md).

## Entry 13 — Structural coverage is broad at O0 and sparse where optimization matters

The structural baseline is stronger than a simple goto counter: it covers 751
C/C++ functions and 2,253 function/style closure rows, requires assertions for
structural-only functions, and retains definition-before-use evidence. But its
binary builder is pinned to GCC `-O0 -g`. The 37 functions with declared shape
predicates include only eleven goto-free, six switch, three for-loop, and two
head-tested-while assertions. Seven Rust fixtures are explicitly skipped.

Focused O2 tests exist, but they do not make O2 a baseline population. Clang is
also absent from the structural baseline. Therefore the current gate can prove
that an O0 body is closed while remaining blind to corpus-wide optimized goto
soup, duplicated conditions, cast/temporary pressure, and output expansion.

Decision: parameterize the existing runner rather than create a parallel
harness; add GCC O2, Clang O0, and Clang O2 one lane at a time; split semantic
invariants from readability observations; then add lane-scoped optimized shape
predicates and distribution metrics. Fix dropped values and call arity before
cosmetic simplification, and join every readability change to execution,
def-use, architecture, performance, and suspicious-signal guards.

Detailed plan:
[optimized-structural-quality-plan-2026-08-31.md](../../../development/roadmap/optimized-structural-quality.md).

## Entry 14 — Format breadth is not format parity

The live estate contains 98 detected PE files but only one Mach-O. PE breadth
comes from many MinGW examples and 30 internal vendor binaries; it does not
provide a coherent source/PDB/body/structure matrix. The eight documented
Microsoft PE/PDB pairs are entirely absent locally, and their tests often skip
or return early. The README claims CI fetches and caches them, but no workflow
does. A Rust early return is counted as a pass, making missing evidence less
visible than a pytest skip.

Mach-O is healthier than the old Phase 4 plan says. Its one committed x86-64
sample now feeds reachable Rust and Python tests for imports, stubs, lazy
pointers, ordering, and evidence integration. It still proves no ARM64,
decompiled-body semantics, DWARF types, chained-fixup behavior, or universal
slice identity.

The necessary toolchains are present: clang-cl/lld-link 21.1.8, Zig 0.15.2,
and MinGW GCC 13 for i686/x86-64. Wine is absent. Decision: build hermetic
static semantic lanes first, never fake Windows execution; distinguish local
bodies from imports/thunks/stubs before scoring; use clang-cl PDBs for the
network-free baseline; and retain fetched Microsoft pairs only for genuine
MSVC/PDB producer quirks.

Detailed plan:
[pe-pdb-macho-parity-plan-2026-08-31.md](../../../development/roadmap/pe-pdb-macho-parity.md).

## Entry 15 — The roadmap now has an evidence authority for every workstream

The package audit maps R0 through R6 to dedicated detailed plans and R7 to the
existing focused fuzzing, thin-module, and matrix-extension plans. Writing a
second R7 design would duplicate current work without changing priority. The
remaining need was a single entry point that separates completed research from
unimplemented product acceptance.

The result also exposes the dependency spine. Inventory authority makes every
new fixture durable. Identity/body accounting feeds format parity. Large-
function telemetry feeds optimized quality. Format and hostile cells feed the
performance/determinism release report. Breadth work is useful but does not
displace demonstrated missing-body, scaling, or fail-open measurement defects.

The failure taxonomy remains exact: `33 + 63 + 88 + 2 + 31 = 217`, with
thirteen evaluator compile-evidence rows tracked separately as E1. No milestone
is marked implemented merely because its plan is detailed.

Package index:
[decompiler-roadmap-package-2026-08-31.md](../../../development/roadmap/README.md).

## Entry 16 — Git history overtook the original plan

The 2026-09-01 history review found several roadmap statements had become
false. F1a landed with a real PE32 fixture and collision-safe resolver, and the
F1b product core now distinguishes imports from absent symbols (`0d6b30d1`).
The readability census expanded to 3,580 rows across both corpora and all four
GCC/Clang O0/O2 lanes (`1329382d`). Its evidence rejected the dispatch
relaxation: +162 gotos for -37 breaks. Closure/effect expectations remain
lane-independent.

R6 moved from no baseline to an initial three-reference instruction baseline
that rejects an injected 10% regression (`a938d897`). It still fails open on
missing, partial, and incomparable evidence and lacks release provenance,
completeness, RSS, and output identity. PE reporting/PDB/RSDS fixes landed
(`610d3afd`), while the clang-cl experiment documented `/nodefaultlib` and a
TLS-fixture toolchain limit (`8fb47f62`) rather than completing R4.

Decision: refresh current-state language and remove completed work from the
immediate queues without weakening acceptance. No fresh full DecBench rerun
exists, so predicted F1a row recovery is not yet submission evidence.
