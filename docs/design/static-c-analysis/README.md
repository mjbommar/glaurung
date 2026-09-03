# Static C analysis in Glaurung

> **Kind:** design · **Status:** proposed

Glaurung has always been intended to carry both halves of program analysis:
binary and dynamic on one side, static and source on the other. Today it has
only the first. It **emits** C — the decompiler's whole output is C — and it
cannot **read** C. That asymmetry is why a 1.9 GB JVM sits inside the DecBench
loop, why `tools/roundtrip_review.py` matches braces with a regular expression,
and why every question of the form *"is what we emitted structurally what was
compiled?"* has to leave the process to get an answer.

This directory plans the second half. It starts where the evidence is: a
pure-Rust C front end whose first scored milestone is reproducing Joern's
structural judgement exactly, on an 85,645-cell oracle that already exists
offline. It ends somewhere considerably more interesting than a metric.

Nothing here is built and nothing here is scheduled. The live plan is
[`development/roadmap/`](../../development/roadmap/README.md).

## The documents

| document | what it holds |
|---|---|
| [roadmap.md](roadmap.md) | **the plan** — seven stages from lexer to bounded source-versus-decompiled equivalence checking, what each stage unlocks, its gate, and its stop condition |
| [architecture.md](architecture.md) | where the code lives and how it layers: the general front end, the Joern-parity layer above it, the LLIR lowering beside it, the dependency-purity policy, and the parser-strategy evidence |
| [`../source-front-ends/`](../source-front-ends/README.md) | *(sibling)* the language-neutral substrate this front end is built on — `src/syntax/`, its requirements and components, and the benchmark harness |
| [joern-behavior.md](joern-behavior.md) | what Joern and pyjoern actually do, stage by stage, with a census over the 800 published source CFGs — the reference behaviour the parity milestone reproduces |
| [requirements.md](requirements.md) | the lifted contract, layered: general front-end requirements that outlive the metric, and parity requirements that exist only to match Joern |
| [parity-plan.md](parity-plan.md) | stage S3 in full: the five-level oracle ladder, the gates, the risk table |
| [implementation-inventory.md](implementation-inventory.md) | 45 components with IDs, mathematics, data structures, sizing and an acceptance test each; the build waves; the three landmines; what the sibling `axeyum` crate already establishes |

## Why now

**1. The oracle is extraordinary, free, and will not improve.** The
materialized DecBench tree holds 800 serialized Joern source CFGs (91,548
functions), 88,963 stored per-function GED values — **85,645 of them in a
complete triple** with a published source CFG and the exact C that
produced each one — 785 complete triples. A new C front end almost never gets
an external correctness signal like that; most are validated by "it parses my
test files." This one can be validated against a third-party tool's structural
judgement on 91,548 real functions, offline, with no Joern run. It is pinned to
a dataset revision and it is as good as it will ever be.

**2. The scope has an externally imposed stopping condition.** "A C parser" as a
general brief has none, and grows a type checker, then a semantic analyzer, then
a code property graph. "The smallest C front end that reproduces the oracle" has
a number that says when to stop. §8 of [requirements.md](requirements.md) is the
list of things this deliberately does not do.

**3. It is pure Rust with no new dependency.** 20 of the 45 components in
[implementation-inventory.md](implementation-inventory.md) need nothing that is
not already in the crate, and the C front end itself needs nothing at all. That
is rare among the large components still unbuilt.

**4. The static half is already blocked on it.**
[`agentic-source-recovery/`](../agentic-source-recovery/README.md) scores itself
on GED (`evaluation/02-decbench-experiment-design.md`,
`03-baselines-ablations-and-scorecards.md`), so that entire 20-document plan
inherits the Joern dependency and cannot iterate cheaply without this.

**5. The payoff is not the metric.** Once C reaches LLIR, it reaches the
interpreter — and `src/exec/interp.rs` is *the one* interpreter, run over a
`Domain` trait that the concrete emulator and the symbolic engine both
implement. A source front end therefore inherits concrete emulation, symbolic
execution, and the solver backends without writing any of them. Stage S5 of
[roadmap.md](roadmap.md) is what that makes possible: **bounded equivalence
checking between the original source function and the decompiled one**, which
is a categorically stronger oracle than any structural distance.

## Scope

**In:** C. Reading it, not writing it. Tokens, AST, control flow, and enough
lowering to reach LLIR.

**Out, for now:** C++ (upstream disables its two C++ projects for the same
reason), other languages, a code property graph, a linter, a type checker, and
anything that would make Glaurung a compiler. The layering in
[architecture.md](architecture.md) is designed so that a second language front
end could be added later without touching the CFG or lowering layers, but no
second language is planned.

## Related

* [`development/decompiler-testing.md`](../../development/decompiler-testing.md)
  — the DecBench lanes, including the existing Joern-free scoring path.
* [`development/testing-gates.md`](../../development/testing-gates.md) — why the
  DecBench lanes are opt-in.
* [`architecture/decompiler-pipeline.md`](../../architecture/decompiler-pipeline.md)
  — the binary half, which this mirrors from the other direction.
* [`architecture/execution-engine.md`](../../architecture/execution-engine.md) —
  the interpreter and `Domain` trait that stage S4 targets.
