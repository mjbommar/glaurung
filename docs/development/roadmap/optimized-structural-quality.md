# Optimized structural-quality plan

> **Kind:** plan · **Status:** proposed

This plan makes roadmap R3 measurable and actionable. It joins the source-
grounded fixture matrix, the three-way parity findings, and the full-run
optimized/large quality evidence without using DecBench bodies as fixtures.

## Progress

The readability census now has 3,580 entries across both fixture corpora and
GCC/Clang O0/O2 (`1329382d`), reporting 85 switches, 4,604 gotos, and 545
breaks. A dispatch-loop relaxation was measured and reverted: it added 162
gotos while removing only 37 breaks, and all seven of its readability
regressions were at **-O0**, not at the O2 lane the census was scoped to
assume. Closure and effect expectations still contain 2,253 and 37 rows
without lane keys; schema v2 and optimized shape predicates remain open.

## Current evidence

The existing structural lane is real and fail-closed within its scope:

* `structural_baseline.json` contains 2,253 closed render-style rows over 751
  C/C++ functions;
* all structural-only functions in that scope have declared assertions;
* 37 functions carry effect/shape predicates;
* the predicate inventory is 23 `nonempty`, 11 `goto_free`, ten
  `memory_store`, six `switch`, five `void_signature`, four `indirect_call`,
  three `for_loop`, and two `head_tested_while` checks;
* definition-before-use diagnostics retain 25 known violations in 13
  functions; and
* the lane independently checks render closure and `--all`/`--vas` agreement.

The closure/effects portion is built only with pinned GCC `-O0 -g`. Seven Rust
fixtures are reported as skipped. Clang/O2 are now readability dimensions, but
not closure/effect dimensions; Phase 7.5 therefore remains open.

The parity sample says Glaurung preserves types and important runtime address
expressions well but renders more IR-like conditions, temporaries, casts, and
control flow than angr/Ghidra. The full corpus reinforces the scale of the
problem: favorable optimized relative rank coexists with weak absolute GED,
and quality drops sharply as recovered output grows. Execution equivalence
cannot see goto soup or needless expression complexity.

## Measurement principles

1. Source-grounded predicates define quality; reference decompilers are
   diagnostic oracles, not truth.
2. O0 and O2 are separate populations. Never overwrite one with the other.
3. GCC and Clang are separate producers. A shared aggregate must retain both
   denominators.
4. Semantic invariants are hard gates. Readability metrics ratchet only after
   execution, def-use, and structure checks remain green.
5. A source construct is asserted only where optimization did not legitimately
   eliminate it. Machine-code and source CFG evidence decide applicability.
6. Exact rendered text is not the oracle. Parseable structure, counts,
   dependencies, and execution behavior are.

## Schema v2

Key every row by fixture, compiler, optimization, function, render style, and
input SHA-256. Record:

* emitted/refused state and closure;
* source and recovered blocks/edges/cyclomatic complexity where available;
* loop-kind multiset, switch/case/default shape, goto and label counts;
* condition count, maximum condition depth, Boolean operator count, duplicate
  normalized conditions, and flag-local leakage;
* cast count, redundant/nested cast count, temporary/local count, single-use
  temporary count, maximum expression depth, and output lines/bytes;
* indirect/direct call shape, call arity, pointer/array declarator shape, and
  named signal dependencies;
* definition-before-use violations and placeholder/fabricated targets;
* compile/execution verdict, structured refusal, and phase/resource evidence.

Store raw observations separately from declared expectations. The baseline is
an accepted comparison point, not a file that declares every current defect
correct.

## Corpus tiers

### Tier 1 — full closure and health matrix

Run every eligible C/C++ fixture at GCC/Clang O0/O2. For every required
function, require emission or a typed refusal, closed DecBench control flow,
no new undefined reads, and no fabricated dispatch target. This is broad and
cheap enough to establish denominators.

### Tier 2 — declared source-shape fixtures

Extend manifest declarations for representative loops, switches, if/else
chains, early returns, short-circuit expressions, recursion, indirect calls,
cleanup ladders, state machines, and inlined call bodies. Declare applicability
per compiler/optimization lane.

The first additions should cover:

* inlined static counter and call argument threading;
* variadic/call-site arity;
* page alignment and prohibition on symbol snapping;
* `char **argv`-like pointer/array flow;
* optimized loop kind, returning arm, dense/sparse switch, and cleanup ladder;
* repeated CMOV/SETcc conditions and comparison fusion; and
* a large but bounded state-machine/control-flow fixture.

### Tier 3 — readability characterization

Run condition, cast, temporary, expression-depth, and output-expansion metrics
over the full Tier-1 population. Initially characterize distributions by
compiler/optimization and size bucket. Ratchet selected robust percentiles and
worst offenders only after two clean reproductions; do not invent targets from
one snapshot.

### Tier 4 — optional reference comparison

For a small fixed diagnostic set, retain outputs from pinned angr/Ghidra
versions and compare source-level constructs. Changes here inform hypotheses.
They never override source, execution, or machine-code evidence and never gate
a fresh checkout on proprietary/large external tools.

## Implementation sequence

### A — parameterize the current structural runner

RED tests first prove that compiler and optimization are part of every key,
that a missing lane is reported rather than dropped, and that generation cannot
overwrite O0 with O2. Reuse `fixture_harness.ensure_fixture`; do not add another
compiler pipeline.

Start with `gcc:O0` compatibility, add `gcc:O2`, then `clang:O0`, then
`clang:O2`, one baseline change at a time. Record exact toolchain fingerprint
and binary hash.

Exit: four complete C/C++ lane populations, with explicit build/unsupported
rows and no silent shortening.

### B — split hard invariants from accepted observations

Closure, body accounting, no placeholder target, declared effects, and no new
def-use violation are invariants. Counts and complexity are observations with
directional ratchets. Improvements must remain visible, but a benign count
change should not be confused with a semantic regression.

Exit: reports state whether failure is semantic, structural, readability,
infrastructure, or baseline drift.

### C — add optimized shape declarations

Add manifest-v2 expectations scoped by lane. A source loop may become a direct
formula at O2; the declaration can say `eliminated_allowed` only with an
independent source/machine-code rationale. Goto-free is required for reducible
source shapes, not Duff's device, computed goto, or deliberate cleanup ladders.

Exit: every R3 motivating shape has a source-built GCC/Clang O2 predicate and
negative control.

### D — land the parity fixes in evidence order

1. Inlined-body register threading, because it is a bounded dropped-value bug.
2. Variadic/call-site arity, because missing live arguments affect semantics
   and types before readability.
3. Narrow use-site pointer/array declarators, explicitly separate from the
   recursive type-model project.
4. Cross-call type propagation and aggregate-field recovery.

Each begins with a real failing optimized fixture. Run execution differential,
structural lanes, def-use census, all architecture lanes, and performance
ratchet before accepting it.

### E — condition and expression simplification

Normalize Boolean expressions only with width/signedness proof. The comparison-
fusion regression is the permanent warning: peeling a cast changed a 64-bit
condition into a 32-bit one while making output prettier.

Prioritize duplicate condition elimination, flag-comparison fusion, pure
select/ternary recovery, single-use temporary substitution, and redundant cast
removal. Stop substitution at effectful expressions, volatile memory, alias
ambiguity, sequencing boundaries, or excessive expression depth.

Exit: motivating metrics improve without any execution, def-use, architecture,
signal-preservation, or resource regression.

### F — join the large-function curve

Apply the same schema to the size-by-shape ladder. Report quality as a curve,
not one average: 0–24, 25–49, 50–99, 100–199, 200–499, 500–999, and 1,000+
output lines. Attribute terminal phase and distinguish source complexity from
output expansion.

Exit: no readability transform can improve small-function medians while
silently exploding large output, time, or RSS.

## Initial ratchets

These are safe before distribution calibration:

* zero missing required lane/function rows;
* zero untyped empty bodies;
* DecBench render control-flow closed for every emitted body;
* no new def-before-use violation;
* no new placeholder/fabricated direct target;
* all declared signal dependencies remain present;
* every declared reducible source shape retains its lane-scoped goto contract;
* compile/execution verdict never regresses; and
* no performance/resource breach from R6.

Condition/cast/temporary percentile thresholds are deliberately deferred until
the four-lane baseline is captured twice on identical inputs.

## TDD and verification

Focused sequence for each increment:

```bash
uv run pytest python/tests/test_decompiler_fixture_structural.py -xvs
tools/dectest.py <fixture>:gcc:O2 --show
tools/dectest.py <fixture>:clang:O2 --show
uv run pytest python/tests/test_decompiler_defuse_census.py -q
```

Any product change then runs all gates required by `CLAUDE.md`, including the
explicit i386, ARMv7, AArch64, and x86_64-gcc15 selectors for lifter, renderer,
ABI, or type changes. Structural baseline regeneration follows
`tools/build_guard.py` and is reviewed as evidence, never used to erase a red
result.

## Completion evidence

R3 is complete only when:

1. GCC/Clang O0/O2 structural populations run with stable denominators;
2. optimized loop, switch, conditional, inlined, pointer/array, call-arity,
   and suspicious-signal fixtures have lane-scoped predicates;
3. readability distributions and size curves are retained and ratcheted;
4. priority parity defects are fixed or have precise typed limitations;
5. execution, def-use, architecture, performance, and signal gates show no
   regression; and
6. one pinned internal report binds inputs, build, observations, baselines,
   and optional reference outputs.

No DecBench body becomes a fixture, and no result is published by this work.
