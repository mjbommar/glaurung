# Semantics-preserving structuring: architecture and migration plan

**Status:** proposed · **Scope:** the decompiler middle (CFG → structure → typed
lowering → render). **Not** a framework redesign — the Rust-core / PyO3 / KB /
LLM organization is not implicated by the evidence.

## 1. Why this document exists

The decompiler's correctness bugs rhyme. Conditional-edge polarity, return-value
loss, the do-while block-swallow, and the short-circuit empty-branch are the same
failure at bottom: **a basic block is dropped or mis-attached during structuring,
and nothing catches it.** We have fixed four variants by hand. Patching one CFG
silhouette at a time is a losing game — the defect is above the line, in how the
middle is designed, not in any single pass.

This is a *narrow* architectural correction, not a rewrite. It has four parts,
each with a verifiable contract, migrated behind the execution-differential
fixture gate (`tests/decompiler_fixtures/`, see that README) so no step can
regress semantics silently.

## 2. Root causes (evidence-based)

1. **Edge semantics are not first-class.** `src/analysis/cfg.rs` builds edges as
   `ControlFlowEdgeKind::{Fallthrough,Branch}` and then the structurer
   (`src/ir/structure.rs`) *reconstructs* taken/fallthrough meaning from the
   terminating instruction via `cond_taken`. Information that existed upstream is
   discarded and re-derived — so every structuring algorithm we could write still
   starts by rebuilding what should have been carried.

2. **The structurer is a tree-matcher fighting a graph.** `detect_if_shape` is a
   sequence of special cases (if-then, if-then-else, early-exit, shared-exit-goto,
   both-terminate) plus a `visited` set. A block with multiple predecessors that
   is not a loop header — a *shared join*, precisely what `a && b` produces — fits
   no case cleanly, is consumed once, and renders empty on the other path.

3. **The IR is under-typed for machine width.** Width/sign/pointer-ness are
   recovered late and heuristically, which is why ZExt/SExt/Trunc/Concat and
   sign-extension leak.

4. **Stages have no semantic contract.** Any pass can emit garbage; we only learn
   from the differential gate after the fact. `src/ir/verify.rs` exists but does
   not check the invariants that would stop these bugs at their source.

5. **Four public entry points and scattered ABI logic are correctness
   boundaries, not cleanup.** `decompile_at`, `decompile_range_at`,
   `decompile_all`, `decompile_many` (`src/python_bindings/ir.rs`) can order or
   omit passes differently, so the *same* function can decompile differently by
   API. ABI facts (live-ins, returns, clobbers, arg locations, stack behavior,
   tail calls) are spread across `call_args.rs`, `value_split.rs`,
   `dead_stores.rs`, `types_recover.rs`, `ssa.rs` — not one descriptor.

## 3. Design principles

### 3.1 Typed edges are the foundation (before any structurer)

The CFG/LLIR must carry **typed edges as first-class data**, produced once at
construction and never re-derived:

```
EdgeKind = Taken | Fallthrough | SwitchCase(value) | SwitchDefault
         | Call | Return | TailCall | Exception
```

`ControlFlowEdgeKind` today (`Fallthrough`/`Branch`) is too coarse: `Branch`
conflates the taken conditional edge, the switch cases, and tail calls. Enriching
it and having the structurer *consume* it (not reconstruct via `cond_taken`) is
step zero. Polarity then cannot invert, because "taken" is data, not a heuristic
over block indices.

### 3.2 The structurer must be **total**, not merely a better matcher

The primary contract is coverage, independent of which algorithm (intervals,
SESE regions, SAILR, DREAM, "No More Gotos") we ultimately choose:

- **Block coverage:** every reachable block appears in the output exactly the
  number of times its semantics require.
- **Edge coverage:** every CFG edge is either structured into a high-level
  construct or emitted as an explicit `goto`.
- **Shared joins emitted once:** a block with >1 predecessor that is not
  replicated is emitted once, reached by labels/gotos — never dropped, never
  duplicated with divergent bodies.
- **Closed targets:** every emitted local jump target has a label.
- **Graceful fallback:** failure to recognize a construct produces **correct
  goto-based output**, never plausible-but-wrong structure.

The contract matters more than the algorithm. A dumb structurer that always emits
gotos is *correct*; a clever one that drops a block is not. We optimize
prettiness (fewer gotos) only after totality holds.

### 3.3 Three-layer type model — do not collapse

Width is machine truth; signedness and pointer-ness are *interpretations*.
Folding all three into one authoritative type turns a bad inference into wrong
semantics.

```
Machine value     : exact bit-width + definition site + storage + effects   (TRUTH)
Operation / use   : signed-vs-unsigned interpretation at a use              (per-use)
Recovered type    : constraint-derived hypothesis + confidence             (fallible)
```

Typed SSA **prevents width erasure by construction** (a Trunc/ZExt cannot silently
become a plain assign because width is carried on every value). It **cannot** make
sign/pointer recovery infallible — those stay hypotheses with confidence, and a
low-confidence hypothesis must render as an honest cast/unknown, not as asserted
semantics.

### 3.4 One pipeline, one ABI descriptor

All public entry points (`at`/`range`/`all`/`many`) must funnel through a single
pipeline with a fixed pass order over a reusable analysis session, so the API
chosen cannot change the answer. ABI becomes one explicit descriptor
(convention → live-ins, return locations, clobbers, arg slots, stack cleanup,
tail-call shape), selected as session configuration, consumed by every pass —
not re-derived per renderer.

## 4. Target architecture

```
CFG with typed edges
      ↓ verify: edge/block closure, every target labeled
Semantics-preserving typed LLIR / SSA
      ↓ verify: widths preserved, def-before-use, effects preserved
Graph-aware region recovery (total structurer)
      ↓ verify: block + edge coverage, shared-join-once
Structured AST + explicit goto fallback
      ↓ verify: control-flow equivalence to the CFG
Pure renderers (plain / c / decbench — no semantic decisions)
```

Each `↓` is a verifier gate that **fails** rather than passes bad output
downstream. Renderers become pure: they may not make control-flow or typing
decisions, only format an already-correct AST.

## 5. The verifier comes first

Before replacing the structurer, extend `src/ir/verify.rs` with the checks that
would have caught every bug in §2:

- **edge coverage** — every CFG edge accounted for in the region tree;
- **block coverage** — every reachable block represented;
- **closed targets** — no `goto` to an absent label (the structural lane already
  measures this externally across render styles; make it an internal invariant);
- **def-before-use** — no value used before definition on any path;
- **effect preservation** — stores/volatile/intrinsic effects survive lowering
  (the differential gate proves this externally; the verifier should assert it).

These run in the *existing* pipeline immediately, converting silent corruption
into loud failure at the source — value even before the structurer rewrite.

## 6. Migration plan

1. **Harden + CI-wire the fixture gate.** (In progress: portable/deterministic/
   exact-ABI harness, structural lane with executed assertions, four-lane
   gcc/clang×O0/O2 baseline, ratchet, CI workflow.)
2. **Add CFG/region/AST invariants** (§5) to the *current* pipeline.
3. **Land the scoped short-circuit repair** — a data point; keeps the burn-down
   moving; validates the gate catches the fix.
4. **Write typed-edge + structurer specs** — enrich `EdgeKind`, have the
   structurer consume it; formalize the §3.2 contract and compare algorithms.
5. **Introduce the new structurer behind a feature flag.**
6. **Shadow mode:** run old and new structurers on every function; differential-
   test both against the gate.
7. **Switch only when** the new structurer has *no semantic regressions* and
   *materially fewer explicit gotos* than the old one.
8. **Build the typed SSA/HLIR layer** (§3.3) next.
9. **Centralize the four public entry points** around the single pipeline.
10. **Make the ABI descriptor part of analysis-session configuration.**

## 7. Readiness gate for the structurer rewrite

A major structurer replacement must **not** begin until the fixture gate is a
sufficient regression net:

- four-lane host matrix (gcc/clang × O0/O2) baselined **and enforced in CI**;
- signatures modeled exactly (widths/signedness/pointer element/const) —
  *done* in phase 2;
- structural cases carry **executed** assertions (indirect call, memory effects,
  switch discriminants, unresolved gotos, vtable/EH) — *done* in phase 2;
- the ratchet is live so an improvement cannot silently regress later.

Until then, step 3 (scoped repairs) and step 2 (in-pipeline invariants) are the
safe, high-leverage work.

## 8. Non-goals

- Not a framework redesign; the Rust/Python/KB/LLM top-level shape stays.
- Not a commitment to a specific structuring algorithm — the totality contract
  (§3.2) is the commitment; the algorithm is chosen in step 4 against it.
- Not "make type recovery infallible" — §3.3 explicitly keeps sign/pointer as
  fallible hypotheses; the win is *width cannot be erased*, not *inference cannot
  be wrong*.
