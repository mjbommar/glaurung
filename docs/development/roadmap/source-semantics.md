# Source semantics: types, reachability, and the solver

> **Kind:** plan · **Status:** proposed

What to build on top of the source front end now that the three dependence
graphs exist, in the order that makes each next thing cheaper. Nothing here is
scheduled; this records what is reachable, what it costs, and what the evidence
would have to be.

Every number in this document was measured on 2026-09-05 at engine commit
`7275fa7a`, and the command that produced it is written next to it.

## Where this starts

Four stages landed in the last two days, and they change what is cheap:

| what | where | what it gives the next stage |
|---|---|---|
| Scope-resolved bindings | `src/csource/dataflow/events.rs` | a name is a *variable in a scope*, not a string. Every def and use already resolves to one |
| Reaching definitions | `src/csource/dataflow/solve.rs` | which write each read sees; dead stores fall out |
| Post-dominance, control dependence | `src/syntax/dominance.rs` | which branch decides each statement; a backward slice |
| C to LLIR | `src/csource/lower/` | the one interpreter, the symbolic engine, and every solver behind the `Solver` trait |

Measured against `tests/decompiler_fixtures/src` (196 files, 900 functions):
22,874 data-dependence edges, 12,387 control-dependence edges, 12 dead stores,
15,633 nodes placed in a post-dominator tree
(`cargo test --lib csource::dataflow -- --nocapture`,
`cargo test --lib syntax::dominance -- --nocapture`).

Two consequences worth stating plainly, because they are what the rest of this
document is built on.

**A binding is one node away from its declared type.** The scope table built
for the dataflow analysis pairs each `DeclName` with the `DeclSpecifiers` that
precedes it. Probed at `7275fa7a` on
`int f(const char *name, int n) { unsigned long total = 0; struct point *p; float ratio; ... }`,
the tree yields `unsigned long` → `total`, `struct point` → `p`, `float` →
`ratio` directly. Nothing has to be inferred; the data is there and unread.

**The solver is already wired.** `Cargo.toml` pins `axeyum-solver` and
`axeyum-ir` at rev `c38a9515`, feature `solver-axeyum`, behind
`src/symbolic/solver/axeyum_backend.rs`. C reaches LLIR, LLIR runs on
`src/exec/interp.rs` over the `Domain` trait that `src/symbolic/symdomain.rs`
implements, and the solver sits behind that. **No new dependency, no new
engine, and no C or C++ in the default build** is needed for anything in phase
3 below — though as the measurement in that phase shows, the lowering's
coverage, not the solver, is what gates it.

## What this is competing with, honestly

`joern-export`'s frontends directory holds twelve language front ends
(`c2cpg`, `csharpsrc2cpg`, `ghidra2cpg`, `gosrc2cpg`, `javasrc2cpg`,
`jimple2cpg`, `jssrc2cpg`, `kotlin2cpg`, `php2cpg`, `pysrc2cpg`,
`rubysrc2cpg`, `swiftsrc2cpg`). We have one, C, and
[requirements.md](../../design/static-c-analysis/requirements.md) section 8
declines the code property graph, the query language, and every other language
on purpose.

So this plan does not chase breadth. It chases the one axis where the
architecture gives us something Joern structurally cannot have: **Joern's
reachability is graph-shaped — if an edge exists, the path counts. Ours can ask
a solver whether the path is satisfiable.** `if (x > 10 && x < 5)` is reachable
in a code property graph and unsatisfiable in ours. That is the whole thesis of
phase 3, and phases 1 and 2 exist to make it reachable.

## Phase 1 — Declared types on bindings

**Deliverable.** Every `Binding` carries the type as written, and
`glaurung.source` exposes it.

**Why first.** It is the cheapest of the three and both of the others get
better with it. It is also the only one whose data is already in the tree.

**Scope.** The type *as spelled*, not resolved. `#include` is not processed
(`REQ-GEN`: this reads one translation unit), so a typedef from a header is an
opaque name and is recorded as one. Storing `uint32_t` and being unable to say
it is 4 bytes is honest and useful; claiming to know is neither.

What to record per binding: the specifier text, a pointer depth, an array
suffix count, and the four flags C spells in specifiers (`const`, `volatile`,
`static`, `extern`). `src/metrics/type_name.rs` already normalizes type
spellings for the DecBench metric and is the natural place to reuse rather than
reinvent — with the caveat recorded there that it reproduces four defects in
the reference implementation on purpose, so a *general* consumer wants a
different entry point into the same table.

**What it unlocks, in payoff order.**

1. **Typed dead stores.** Today an unread `int x = f();` is one finding.
   Knowing the binding is a `FILE *` or a lock handle makes the same finding a
   leak. The dead-store census already exists; this changes what each row
   means.
2. **A source-side type column.** `src/metrics/type_match.rs` scores recovered
   types against DWARF. Reading the *source* type gives an independent third
   column instead of two readings of the same binary — which is exactly the
   trap [traps.md](../traps.md) records under "our own emulator is not an
   oracle".
3. **Type-flow conflict.** A binding whose reaching definitions disagree about
   type is the shape of a decompiler's `undefined8` recovery failure, findable
   in the recovered C without the binary.

**Gate.** Every binding in the 196-file corpus resolves to a specifier or is
explicitly `None` with a reason; the count of `None` is reported and does not
grow. A Rust test asserts the pairing on hand-written C covering: multiple
declarators in one declaration (`int a = 1, *b, c[4];`), a struct tag, a
function pointer, and a parameter.

**Cost.** Days. No new dependency.

## Phase 2 — Interprocedural dataflow

**Deliverable.** Dependence that crosses a call edge, and a `reaches` query
over it.

**Why second.** This is the actual capability gap against Joern, and after
phase 1 it is mostly plumbing: `SourceReport.call_graph()` exists, the
intraprocedural DDG exists, and what is missing is threading one through the
other.

**The design decision that matters.** Summaries, not inlining. For each
function compute, once, which parameters flow to the return, which flow to
which out-parameter, and which reach a call it makes. Then a caller applies the
summary rather than re-analysing the callee. Inlining is simpler to write and
does not terminate on recursion; summaries do, at a fixed point over the call
graph, and the call graph is already there.

**Where it must refuse.** An indirect call has no name — `call_graph()`
contributes no edge for one, deliberately — so a summary cannot be applied and
the analysis reports **unknown** rather than assuming either "flows" or "does
not". The same for a call to a function this translation unit does not define:
`memcpy` is an edge to a name, and what it does with its arguments is not
knowable from here. A curated table of libc effects is the obvious next
increment and should be its own decision, not smuggled in.

**What it unlocks.** `reaches(source, sink)` — does a value from here arrive
there — which is the query Joern is used for. On decompiler output it answers
"does this recovered function propagate an attacker-controlled length into a
memcpy", which is the shape the `llm/` findings runner and the CWE sweep both
want and neither can currently ask.

**Gate.** A hand-written corpus of source/sink pairs with a known answer, run
both ways: every true pair is found, and every deliberately-broken pair (a
sanitizer between them) is not. Plus the totality rule the rest of the front end
keeps: an unresolvable call costs an `unknown`, never a silent yes or no.

**Cost.** Two to three weeks. No new dependency.

## Phase 3 — Path feasibility, on the solver

**Deliverable.** For a path through the source CFG, a verdict:
**feasible** with a concrete witness, **infeasible** with the constraint that
kills it, or **unknown**.

**Why this is the interesting one.** Everything up to here is a better version
of what a code property graph does. This is the part it cannot do at all. A
reachability answer that has *never been checked for satisfiability* reports
paths that no input can take, and on decompiler output — where the structurer
invents dispatch and duplicates guards — that is not a rare case.

**How it is built, and why nothing new is needed.**
[roadmap.md](../../design/static-c-analysis/roadmap.md) section 6 records the
chain already: `src/csource/lower` produces an `LlirFunction`;
`src/exec/interp.rs` is *the one* interpreter and steps `Op`s over a `Domain`;
`src/symbolic/symdomain.rs` implements that `Domain`; `src/symbolic/solver/`
holds the `Solver` trait with `axeyum_backend.rs` behind it. A path is a
sequence of CFG edges, its branch conditions are terms, and asking whether
their conjunction is satisfiable is a call the stack already supports.

**The honest limit, stated before the capability.** `src/csource/lower` accepts
scalar-integer C and errors rather than approximating outside it — no `goto`,
no floating point, no aggregates. So phase 3 answers on a subset and **says
which**: a path containing a construct the lowering refuses returns `unknown`
with the construct named, exactly as `LowerError` already does. A tool that
reports "infeasible" when it means "I could not lower this" is worse than one
that reports nothing.

**Three things to build on it, in increasing ambition.**

1. **Infeasible-path pruning.** Take the reachability answer from phase 2 and
   drop the paths a solver refutes. This is the cheapest, and it makes every
   number above it more precise rather than adding a new surface.
2. **Guard duplication detection.** The structurer emits the same test twice on
   one path — `if (x > 0) { ... if (x > 0) { ... } }` — often enough that it
   has its own defect class. The second test is provably redundant, which is a
   solver query and a readability finding the execution differential cannot
   see, in the same family as the dead-store and control-depth counts.
3. **Bounded property checking on recovered C.** `axeyum-verify` is a
   `#[axeyum::verify]` proc-macro that bounded-checks a **Rust** function for
   panics, integer overflow, `unwrap` failures and assertion violations over a
   whitelisted subset, emitting a runnable failing test for a counterexample
   and `Unknown` — never a wrong verdict — outside the fragment. That is
   structurally the same pipeline we would want for C, over the same solver,
   and it is worth reading before designing ours rather than after. The
   glaurung analogue: given a recovered function, is there an input that
   overflows this index, divides by this zero, or shifts by this width. On
   decompiler output that is a *finding about the binary*, which is the whole
   product.

**Gate.** The one that matters here is a differential, not a count. For every
path a solver calls feasible, the concrete emulator must be able to run it with
the witness the solver produced. A disagreement is a bug in one of the two, and
[traps.md](../traps.md)'s "our own emulator is not an oracle" applies with full
force: when the solver and the emulator agree, that is two readings of our own
semantics, so the tie-break is compiling the C and running it under `gcc` at
`-O0` and `-O1`.

**Cost, and the number that decides it.** Measured before writing this
paragraph, because the answer changes what phase 3 is:

```
lower_named_function over tests/decompiler_fixtures/src, 2026-09-05 at 7275fa7a
  168 / 900 functions reach LLIR = 18.7%

  325  pointer type as a ...
  152  call expression
   51  floating-point type (no FP ...)
   38  switch statement
   19  struct type as a ...
   17  struct type
   13  pointer, array or function ...
   12  array subscript
```

**So phase 3 is a research increment on a narrow slice, and must be scoped as
one.** Four fifths of the corpus does not reach LLIR at all, and the reason is
not exotic: pointers and calls are 477 of the 732 refusals. A "path feasibility"
feature that silently answers `unknown` on 81% of functions would be a worse
product than not shipping it.

That reorders the work. **Widening the lowering is the prerequisite, and it is
its own phase**, not a footnote to this one:

| refusal class | count | what it needs |
|---|---:|---|
| pointer types | 325 | a memory model in the lowering; `ir::abi` already models the ABI half |
| call expressions | 152 | a call op with a summary or an uninterpreted result |
| floating point | 51 | the solver has an FP route; the lowering has no FP type |
| `switch` | 38 | a jump-table lowering; `analysis::jump_tables` does this for binaries |
| aggregates | 36+ | struct and union member access |

Pointers and calls alone would take coverage from 18.7% to roughly 71% if the
counts are independent, which they are not — a function refused for a pointer
may also contain a call — so the honest reading is "the two together are where
the coverage is", not a predicted number. **Measure again after each**, and let
the number decide whether phase 3 is worth starting.

## Phase 4 — The query surface, reframed

**Deliverable.** Source facts in the `.glaurung` knowledge base, with
`set_by` provenance.

**Why not CPGQL.** Cloning a query language is a large amount of work whose
only unique benefit is running someone else's existing Joern queries unchanged.
That is a *compatibility* requirement, not a capability one, and nobody has
asked for it. Meanwhile the KB is already a queryable store with provenance,
already holds names, types, prototypes and xrefs, and already has "manual
always wins" resolved — and "source facts into the knowledge base" is already a
row in [roadmap.md](../../design/static-c-analysis/roadmap.md) section 8's S7
table.

So: types from phase 1, dependence edges from phase 2, and feasibility verdicts
from phase 3 become KB rows with `set_by = "source"`. The query surface is then
whatever queries the KB — including the LLM tools in `python/glaurung/llm/`,
which is a consumer Joern does not have.

**Cost.** Small once phases 1–3 exist; it is a serialization layer, not an
analysis.

## What this deliberately does not do

Recorded so each stays a decision rather than an oversight.

* **No C++.** It cannot be parsed without simultaneous semantic analysis —
  `A<B>(c)` is a call or a template instantiation depending on name lookup —
  and Eclipse CDT has a C++ mode that DecBench's own upstream disables anyway.
  What we consume is decompiler output, which is C-shaped even for C++
  binaries; the useful work there is demangling and vtable recovery, which
  `src/demangle` and the decompiler already do.
* **No code property graph.** `requirements.md` section 8, unchanged.
* **No `#include` resolution.** One translation unit is the contract.
* **No alias analysis in phases 1–2.** The dataflow over-approximates on
  purpose — a store through a pointer kills nothing — which loses precision and
  never loses an edge. Phase 3's solver is the principled way to recover some
  of it, not a hand-written points-to pass.

## Sequencing

The measurement that was supposed to come first has been taken (18.7%), and it
moves phase 3 behind a prerequisite:

1. **Phase 1, declared types.** Days. Makes everything after it better, and its
   data is already in the tree.
2. **Phase 2, interprocedural dataflow.** Two to three weeks. Closes the real
   gap against Joern, and needs nothing from the lowering.
3. **Phase 2.5, widen the lowering** — pointers first, then calls. This is the
   prerequisite phase 3 does not have. Re-measure coverage after each; the
   number is the gate on whether to continue.
4. **Phase 3, path feasibility.** Only once coverage justifies it. If pointers
   and calls do not move 18.7% substantially, stop here and bank phases 1, 2
   and 4 — they are worth having on their own and none of them needs a solver.
5. **Phase 4, KB facts.** Cheap once 1 and 2 exist; can be done in parallel.

Note what this ordering protects: phases 1, 2 and 4 deliver a better product
than Joern on our one language without the solver being involved at all. Phase 3
is the differentiated bet, and it is correctly last because it is the one whose
prerequisite is measured and currently unmet.

## Related

* [static C analysis roadmap](../../design/static-c-analysis/roadmap.md) — S4's
  "why this is the multiplier", and the S7 table three of these rows come from
* [requirements.md](../../design/static-c-analysis/requirements.md) section 8 —
  the non-requirements this plan does not reopen
* [source metrics reference](../../reference/source-metrics.md) — the surface
  phases 1 and 2 extend
* [traps.md](../traps.md) — "our own emulator is not an oracle", which decides
  how phase 3 has to be gated
