# WP1 Bounded MIR Definedness Trial

> **Kind:** record · **Date:** 2026-09-02

Status: **rejected for production use**

Date: 2026-09-02

Source revision: `44c3a275` plus temporary, subsequently removed trial code

Scope: local Glaurung evaluation only; no DecBench run or upstream action

## Question and decision rule

WP1 asked whether the existing verified MIR and `DefinitionOracle` could own a
production, path-sensitive used-before-definition query for functions that the
structured AST walk declines because they contain gotos.

The trial could retain this production consumer only if it stayed below 10%
fixture-matrix wall-time overhead and either produced a verdict unavailable to
the structured walk or provided complete clean proofs for the applicable
population at a cost not better deferred to WP3's authoritative SSA work.

The trial failed the performance condition. The read-only scalar-MIR consumer
added approximately 19.5% median wall time in the bounded same-binary A/B
measurement. It is therefore rejected without weakening the threshold. All
temporary production and test changes were removed; scored pseudocode is
unchanged by WP1.

## What was implemented temporarily

The trial exercised the real decompile pipeline and existing
`DefinitionOracle::all_paths_defined` query. It temporarily:

- constructed scalar MIR from the numbered LLIR used by the production path;
- queried every generated-value use for all-paths definedness;
- recorded a read-only health result with `analysis=MIR`, completeness,
  queried value, use site, predecessor addresses, and decline reason;
- persisted the health record through the Python binding;
- wired the consumer through the four decompile entry points; and
- added an end-to-end real-binary assertion on the wide-switch fixture.

A synthetic CFG diamond provided the RED control: a generated value was
defined on only one predecessor and read at the join. MIR reported the missing
path with predecessor evidence. This establishes that the query itself can
express the target defect class; it does not establish acceptable production
cost or unique value on real binaries.

The first implementation also constructed the full memory model and
MemorySSA. Because this query concerns scalar generated values, the measured
version removed that unnecessary work and built scalar MIR only. The optimized
version still exceeded the hard limit.

## Real-binary observations

The bounded probes produced complete clean results:

| probe | generated uses queried | completeness | findings |
|---|---:|---|---:|
| wide-switch fixture | 3,368 | complete | 0 |
| gcc-O2 Duff fixture | 144 | complete | 0 |

These are useful implementation controls, but neither is a unique real-binary
verdict unavailable to the current production output. The planned population
sweep was stopped once the hard performance condition had already failed;
WP1 therefore makes no claim about complete-corpus coverage.

## Performance evidence

The scalar-MIR version was measured by alternately enabling and explicitly
bypassing the consumer on the same
`09_memory_effects-clang-O2.so` binary. Each arm had two warmups followed by 12
samples.

| mode | median wall time | median peak RSS |
|---|---:|---:|
| bypassed | 0.034864954 s | 66,904 KiB |
| enabled | 0.041680032 s | 71,100 KiB |
| delta | **+19.5%** | **+4,196 KiB (+6.3%)** |

The enabled arm analyzed nine functions. The bypass arm recorded nine explicit
timing-bypass declines, confirming that both arms traversed the same requested
function set. Short measurements can contain host noise, but a roughly 19.5%
median increase is too far beyond the plan's less-than-10% requirement to
justify promotion. A prior whole-binary experiment that built the fuller MIR
model had already measured approximately +13%, so neither construction route
has demonstrated compliance.

Reusing the pipeline's existing SSA object was considered and rejected for
this trial. That SSA precedes value numbering, while the MIR query consumes
numbered LLIR. Reusing it would silently join incompatible value identities.
WP3 exists to establish stable authoritative identity across those stages.

## Reference and responsibility inventory

The rejected consumer does **not** by itself authorize deletion of the entire
MIR/MemorySSA substrate. The inventoried implementation is approximately 9,270
lines across the following files:

- `src/ir/mir/`: `builder.rs`, `memory.rs`, `memory_tests.rs`, `mod.rs`,
  `model.rs`, `query.rs`, `query_tests.rs`, `verify.rs`, and
  `verify_objects.rs`;
- `src/ir/memory_ssa.rs` and `src/ir/memory_ssa_tests.rs`; and
- `src/ir/memory_objects/ast.rs`, `mir.rs`, `partition.rs`,
  `partition_tests.rs`, `shape.rs`, and `shape_tests.rs`, plus the
  `src/ir/memory_objects.rs` module root.

Production or production-adjacent references were found in:

- `src/python_bindings/ir/pipeline.rs`: `PreparedLlir::mir` remains dead-code
  allowed, and the other construction path is diagnostic-only under
  `GLAURUNG_DUMP_PASSES`;
- `src/ir/memory_objects.rs` and `src/ir/memory_objects/mir.rs`: MIR object
  adapters and joins;
- `src/ir/memory_objects/ast.rs` and `src/ir/high_variables.rs`: the distinct
  AST compatibility object model that still has the production consumer;
- `src/ir/regview.rs`, `src/program/types.rs`, and
  `src/program/types_tests.rs`: stable-value/type join support; and
- `src/ir/mod.rs`: module exposure.

The remaining callers of MIR lowering and its query surface are tests or
diagnostics, including the test caller in `src/python_bindings/ir.rs` and the
MIR memory, query, partition, and shape suites. MemorySSA is also used by the
MIR memory/object implementation and its independent tests.

Those files contain independent builder, verifier, object-shape, memory-effect,
and type-join responsibilities. Deleting them now would exceed WP1's evidence.
Any selective deletion must follow WP10: identify retained LLIR invariants,
port them first, remove exact superseded callers, and pass the release profile.

## Outcome and next action

- **Rejected:** constructing MIR during every production decompile solely for
  this definedness query.
- **Not claimed:** full-population MIR coverage, a decompiler quality gain, or
  a scored-output change.
- **Retained:** the existing dormant/diagnostic substrate pending a WP10
  responsibility-by-responsibility deletion decision.
- **Deferred:** goto-aware used-before-definition over the authoritative stable
  SSA identity from WP3, or over the AST label CFG if that proves cheaper and
  complete after WP3 establishes the comparison boundary.

This closes the two-day experiment and unblocks competing implementations. It
does not make MIR a production authority.
