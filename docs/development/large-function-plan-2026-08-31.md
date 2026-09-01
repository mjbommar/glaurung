# Large-function decompiler plan — 2026-08-31

This plan implements R2 of the
[real-binary roadmap](real-binary-decompiler-roadmap-2026-08-31.md). It is
based on the pinned full-run function data, not on the favorable relative rank
of a weak absolute leaderboard.

## What the evidence says

The candidate artifact records a recovered-C line count for 94,358 returned
bodies. Compilation and perfect-score rates collapse as that output grows:

| recovered C lines | bodies | compiles | perfect GED | perfect type | perfect byte |
|---|---:|---:|---:|---:|---:|
| 0–4 | 13,386 | 13,383/13,383 | 3,962/12,363 | 509/11,552 | 1,204/13,386 |
| 5–9 | 12,091 | 11,751/12,090 | 9,806/11,287 | 2,804/9,680 | 2,848/12,091 |
| 10–24 | 21,133 | 19,101/21,128 | 11,052/19,860 | 3,861/18,436 | 1,348/21,133 |
| 25–49 | 18,298 | 15,469/18,294 | 3,790/17,353 | 2,007/17,683 | 135/18,298 |
| 50–99 | 14,719 | 10,910/14,719 | 742/13,844 | 720/14,570 | 28/14,719 |
| 100–199 | 9,450 | 6,402/9,450 | 85/9,047 | 171/9,420 | 0/9,450 |
| 200–499 | 4,282 | 2,426/4,282 | 24/4,218 | 19/4,272 | 0/4,282 |
| 500–999 | 735 | 266/735 | 2/732 | 0/735 | 0/735 |
| 1,000+ | 264 | 100/264 | 0/259 | 0/264 | 0/264 |

The inflection is visible before the official `large` preset: at 50–99 lines,
compile success is 74.1% and perfect GED 5.4%; at 200–499 lines those fall to
56.7% and 0.6%. No function at 100+ recovered lines is byte-perfect, and none at
1,000+ lines is perfect on any metric.

These are correlations with recovered-output size, not proof that size causes
each failure. The longest outputs include parsers, protocol/state machines,
decompression, configuration handling, crypto rounds, and large dispatchers.
Shape and ABI/type complexity are confounders to measure explicitly.

The official replacement simulation has 1,987 non-normalized large functions.
Glaurung has 24 Union-perfect rows (1.21%), six GED-perfect rows (0.30%),
eighteen type-perfect rows (0.91%), and zero byte-perfect rows. Second place in
Union and first in type therefore does not mean this class is solved.

## Questions the current estate cannot answer

1. At which pipeline phase does time or memory grow superlinearly?
2. Is compile failure dominated by rendering, undefined values, prototypes, or
   unsupported C constructs?
3. Does GED loss come from missing CFG edges, structuring, or granularity?
4. Are repeated large functions across binaries one replicated defect?
5. Which source shapes predict failure after controlling for line count?
6. Does a timeout/refusal preserve partial evidence, or silently truncate?

## L0 — Telemetry before corpus growth

Add per-function phase telemetry to the existing bench/report path:

```text
identity_ms, discovery_ms, lift_ms, ssa_ms, dataflow_ms,
structure_ms, type_ms, render_ms, total_ms,
input_bytes, discovered_blocks, discovered_edges,
lifted_blocks, llir_ops, mir_nodes, phi_nodes,
structured_regions, gotos, output_lines, output_bytes,
undefined_reads, peak_function_scratch_bytes,
terminal_phase, terminal_reason
```

Requirements:

* disabled or near-zero-overhead by default;
* deterministic JSON schema and stable phase names;
* records emitted on success, refusal, and timeout;
* no whole-process RSS presented as per-function allocation;
* phase counters reconcile; synthetic blocks are separately counted.

Acceptance: the same function run twice on the same release build has identical
non-timing fields. Timing is summarized separately and is never a semantic
oracle.

## L1 — Small source-grounded size ladder

Add a named `@large` set, initially 18 functions: six shapes at three scales.
Each is compiled by GCC and Clang at O0/O2; source and generator are committed.

| shape | small | medium | large | oracle focus |
|---|---:|---:|---:|---|
| dense switch | 32 cases | 256 | 1,024 | switch recovery and indirect dispatch |
| sparse switch | 16 | 128 | 512 | compare tree and fallthrough |
| parser state machine | 20 states | 100 | 400 | loops, transitions, error exits |
| cleanup ladder | 16 resources | 64 | 256 | postdominators and shared exits |
| expression/phi DAG | 32 joins | 256 | 1,024 | SSA/phi pressure and expression growth |
| nested loop/condition | depth 4 | 8 | 12 | structuring and condition complexity |

Generators emit ordinary C source, not precomputed binaries or expected
decompiler output. Seed and parameters are fixed; source hashes are recorded.

Every function has an execution differential over deterministic boundary and
seeded inputs, compile verdict, source/recovered CFG counts, shape-specific
structural predicates, def-use census, and phase/resource telemetry.

This first tier is diagnostic. It isolates scaling under real compilers rather
than trying to resemble a whole production program.

## L2 — Production-shape corpus

Select a small, license-clean corpus by shape rather than popularity:

* decompression loop/state machine;
* configuration parser with repeated option cases;
* protocol message dispatcher;
* command-line parser;
* cryptographic compression round;
* filesystem copy/error-cleanup function;
* generated parser function;
* firmware command dispatcher.

Each asset records upstream URL/revision, license decision, source
path/function, standalone patches, container/toolchain digest and flags,
source/object/binary SHA-256, input vectors, and why it adds a new shape.

Prefer controlled variants of one source over many unrelated binaries:
GCC/Clang O0/O2, one LTO variant, stripped twin, and ARM64 where portable.

## L3 — Failure decomposition

Replace one scalar “large failed” bucket with terminal classes:

| class | definition |
|---|---|
| identity/discovery | requested source function lacks an admissible image identity or complete CFG |
| lift | owned bytes fail to decode/lift with explicit address and instruction class |
| SSA/dataflow | construction fails, exceeds a budget, or leaves unexplained undefined reads |
| structure | body exists but region recovery exceeds budget or emits irreducible fallback |
| type/prototype | C fails because declarations, types, or arity are inconsistent |
| render | valid internal body cannot be expressed as compilable C |
| semantic | compiles but execution differential fails |
| metric-only | semantic gates pass but GED/type/byte perfection does not |

Classification uses the earliest proven failing phase. Metric-only is never
used when a stronger behavioral failure exists. Compile failures store a
compiler-diagnostic fingerprint and are grouped before choosing fixes.

## L4 — Ratchets and budgets

Per-function safety limits remain explicit and configurable. Gates ratchet
observed values rather than selecting arbitrary “fast enough” numbers:

* no panic, abort, or process-wide OOM;
* every timeout names its phase and preserves preceding evidence;
* no silent missing blocks/edges;
* no new opaque memory-clobbering intrinsic without instruction identity;
* compile and execution results cannot regress;
* structural regressions require a recorded reason;
* release instruction count may not regress >5% on stable references;
* wall time >25% or max RSS >50% follows the performance-plan environment
  contract.

Use three repeated timing runs and report median plus spread. Never tighten a
wall-clock baseline under unrecorded machine load.

## L5 — Prioritized engineering from evidence

After L0–L3 produce a report, choose work in this order:

1. crashes, OOMs, and silent truncation;
2. superlinear phase behavior reproduced by the generated ladder;
3. high-frequency compile-diagnostic families;
4. semantic differential failures;
5. structural failures shared across production shapes;
6. type/metric improvements that do not weaken earlier contracts.

Do not special-case `BZ2_decompress`, `yyparse`, or another named DecBench
function. Reproduce its independently identified shape in L1/L2.

## Test and baseline integration

The `@large` set is named in `tests/decompiler_fixtures/sets.toml`; its runner is
recorded in the generated inventory. New fixtures refresh execution,
structural, architecture, and def-use baselines under standing discipline.

Add a fast canary containing the small scale of all six shapes. Medium/large
scales remain in the opt-in pre-push gate until measured runtime supports a
smaller default subset.

The completion gate includes:

```bash
tools/dectest.py @large
uv run pytest python/tests/test_decompiler_fixture_structural.py -m slow
uv run pytest python/tests/test_decompiler_defuse_census.py -m ""
cargo test --features python-ext
```

An architecture selector is added once a portable subset exists; `--arch`
always accompanies explicit selectors per `CLAUDE.md`.

## Milestones

| milestone | exit |
|---|---|
| L0 | Stable per-function phase/resource schema with success and failure tests. |
| L1 | 18-function generated ladder runs with execution, structure, def-use, and telemetry evidence. |
| L2 | At least eight provenance-complete production shapes and controlled build twins. |
| L3 | Every corpus failure has one earliest-phase class; compiler diagnostics grouped. |
| L4 | Resource/semantic/structural ratchets run in the documented gate. |
| L5 | First two evidence-selected fixes land with independent reproductions and no regressions. |

## Stop conditions

Stop and revise if output line count does not correlate with the measured
internal scaling variable; a generated case is optimized away; the oracle
cannot distinguish source undefined behavior; an asset lacks
redistribution/provenance; or a supposed quality improvement merely changes
metric normalization without improving behavioral evidence.
