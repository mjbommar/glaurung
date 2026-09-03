# Static C analysis: the roadmap

> **Kind:** plan · **Status:** proposed

Seven stages, from a tokenizer to bounded equivalence checking between original
source and recovered source. Each stage ships something usable on its own, ends
at a gate that can be run without the next stage existing, and carries a stop
condition.

The frame is [`README.md`](README.md); the code layout is
[`architecture.md`](architecture.md); the component list is
[`implementation-inventory.md`](implementation-inventory.md). Stage S3 is
specified in full in [`parity-plan.md`](parity-plan.md).

## 0. How this is judged

The roadmap's two-track rule applies
([`development/roadmap/README.md`](../../development/roadmap/README.md)): this is
an **ARCHITECTURE** programme, not a CORRECTNESS one. Stages S0–S4 will move
**zero decompiler fixture cells**, and asking them to promise cell movement
would get them over-sold and then judged by the wrong standard. They succeed
when a boundary holds and a capability exists that something else can be built
on.

S5 and S6 are different: they produce oracles and metrics, and are judged on
what they can prove about the decompiler that nothing today can.

Two rules carried from the sibling `axeyum` workspace, both paid for by
incidents there, both binding here:

* **Explicit-stack traversal, never native recursion, in the lexer and parser.**
  A recursive scan overflowed the stack and aborted the process, so no
  first-class result could be reported and the harness read the exit as a crash
  (`fcc8760d`). Decompiler C is adversarial in exactly that way — nested casts,
  parenthesised spines, long `||` chains — and a parser that aborts cannot report
  a per-function failure, which is precisely the whole-file voiding mode this
  programme exists to remove.
* **A degenerate-case generator per underspecified construct.** A wrong `unsat`
  shipped there (`a946f925`) because the differential fuzz structurally could
  not emit the degenerate argument. A corpus sweep that avoids the corner is not
  a gate. Ours are listed in §9.

## 1. The stages at a glance

```
S0 kernel ─┬─> S1 lexer/parser ──> S2 general CFG ─┬─> S3 Joern parity + GED
           │                            │          │
           │                            └──────────┴─> S4 C -> LLIR ──> S5 equivalence
           │                                                    │
           └──> S6 type_match (independent) <───────────────────┘
                S7 the static surface (needs S2, richer with S4)
```

S3 is the only stage with a large external oracle, which is why it comes early
even though it is not the interesting one. S4 is the multiplier. S6 is
independent of everything and can be done whenever.

| stage | deliverable | gate | moves cells? |
|---|---|---|---|
| S0 | shared kernel | byte-exact against the reference's pure functions | no |
| S1 | `src/syntax` substrate + `src/csource` lexer, AST, parser | parse coverage over 210 in-repo `.c` files and 1,606 stored decompiled `.c` | no |
| S2 | general source CFG | structural invariants and per-construct fixtures | no |
| S3 | Joern-parity layer + GED | 85,645 reproducible GED cells matched exactly | no |
| S4 | C → LLIR lowering | the existing interpreter runs a lowered C function | no |
| S5 | bounded equivalence checking | a known-good and a known-bad decompilation are separated | **the point** |
| S6 | native `type_match` | per-function `(tp, fp, fn)` equality with the reference | no |
| S7 | the static analysis surface | per-capability, see §8 | varies |

## 2. S0 — Shared kernel

**Deliverable.** K-1..K-4 of [`implementation-inventory.md`](implementation-inventory.md):
canonical-JSON SHA-256 keying, the measurement tri-state, aggregation
primitives, ordered-output discipline.

**Why first.** Every later gate is a diff, and a diff against non-deterministic
output is not a gate. `BTreeMap` everywhere, no hash-map iteration order in
anything that reaches output.

**Gate.** Byte-identical digest to `decbench.caching.stable_hash` on a fixture of
nested maps, sets, floats and bytes; a metric returning an abstention leaves the
denominator while one returning `0.0` does not.

**Stop condition.** None. Half a day.

## 3. S1 — The C front end

**Deliverable.** Two modules, not one.

* `src/syntax/` — the language-neutral substrate (`SB-1..SB-9`): source maps and
  spans, interning, the struct-of-arrays token buffer, diagnostics, the parser
  event stream, the arena tree, recovery primitives. Specified in
  [`../source-front-ends/substrate.md`](../source-front-ends/substrate.md), and
  sized `S`/`M` throughout — the substrate is small, the grammars are what is
  large.
* `src/csource/{lex,ast,parse}` — the C grammar on top of it: token kinds, node
  tags, a Pratt expression parser and a recursive-descent statement parser with
  error recovery (F-4..F-7).

Both pure Rust, no new dependency, no `unsafe`. They are separate modules from
the first commit so that extraction is never needed and the boundary test can
be written before anything has crossed it.

The parser-strategy question is settled and the evidence is recorded in
[`architecture.md`](architecture.md) §4: the two off-the-shelf routes both fail
on requirements we cannot drop. `lang-c` is pure Rust but PEG-based, so a parse
error fails the whole file — disqualifying, because ill-formed decompiler output
is the dominant input. `tree-sitter-c` has the error recovery but ships a
generated C `parser.c`; the `tree-sitter-c2rust` fork transpiles only the
*runtime*, so a grammar crate still compiles C, and the transpiled runtime is
little-endian-only and non-idiomatic `unsafe`. Writing it is also not
unprecedented here: `src/analysis/java_class/` is 2,929 lines of hand-written
class-file and bytecode front end already in the crate.

**Gate — coverage, measured on real inputs we already have.** The instrument is
the four-axis harness in
[`../source-front-ends/benchmarks.md`](../source-front-ends/benchmarks.md), in
which coverage outranks throughput: a change that is faster and loses a function
is rejected.

* 210 C files in-repo — 196 under `tests/decompiler_fixtures/src/` and 14 under
  `tests/decbench_corpus/src/`, 21,296 lines total
  (`cat tests/decompiler_fixtures/src/*.c tests/decbench_corpus/src/*.c | wc -l`).
  Every one must parse with zero errors; these are clean C we own.
* 1,606 stored decompiled `.c` artifacts (~200 MB) in the materialized tree.
  Report files parsed, functions found, functions Joern found that we did not (a
  loss), and functions we found that Joern did not (a gain). Target: source-side
  loss at most Joern's own 5.01%, decompiled-side loss at most the best rate any
  decompiler gets from Joern today (kuna 0.00%, ghidra 0.04%) —
  [`joern-behavior.md`](joern-behavior.md) §5.
* No input may abort the process, exhaust the stack, or take unbounded time.

**Stop condition.** If coverage stalls more than five percentage points off the
target with no visible path to closing it, the difficulty really was Eclipse
CDT's error recovery rather than C. Reconsider: take `tree-sitter-c` and accept
the C dependency, or stop the programme.

**Status: the substrate and the lexer have landed, and the lexer clears the
gate.** `src/syntax/` implements `SB-1`..`SB-9`; `src/csource/lex/` implements
`F-4` on top of it.

```
in-repo corpus: 210 files, 21296 lines, 123409 tokens, 0 diagnostics
decompiled:     534 files, 2726306 lines, 26172752 tokens, 0 diagnostics
```

```bash
cargo test --features python-ext --lib csource::lex -- --nocapture
```

The committed test keeps a 14-file slice so the ordinary lane stays fast; the
534-file sweep was run ad hoc, in a debug build, in 11.4 seconds.

**That second row is weaker than it looks, and the weakness is the point.** The
materialized tree holds only Glaurung's *own* decompiler output — generated C
with no stray bytes; `grep -rl 'undefined4\|__usercall'` over it returns
nothing. Zero diagnostics per KLOC there is real but is **not** evidence that
the lexer survives Ghidra or IDA text, which is the input the loss rates in
[`joern-behavior.md`](joern-behavior.md) §5 were measured on. Closing that gap
needs a corpus with other decompilers' columns in it, and until then the
decompiled-side half of this gate is untested against its hardest case.

What remains for S1 is the parser (`F-5`..`F-7`); the lexer alone does not
satisfy the stage.

## 4. S2 — The general source CFG

**Deliverable.** `src/csource/cfg` — a **correct** control-flow graph: real
successors, real join points, real loop back edges. Not Joern-shaped. This is
the artifact that outlives the metric, and it is what S4, S5 and S7 build on.

**Gate.** Structural invariants that hold for any well-formed C function, each
with a named fixture: every node reachable from entry; every exit path reaches
the function end; back edges correspond to source loops; `break` and `continue`
target the enclosing construct; `switch` fall-through is an edge; a `goto`'s
target exists. Plus the per-construct fixtures listed in
[`parity-plan.md`](parity-plan.md) Phase 2.

**Stop condition.** None; this is the core of the work.

## 5. S3 — Joern parity and GED

**Deliverable.** The parity layer over S2 — Joern's expression-level node
granularity, chain coalescing, derived entry/exit flags, the singleton-funcend
rule, degeneracy, per-TU resolution, the DecBench serialization — plus the GED
distance itself (F-8..F-17, G-1..G-4).

Specified in full in [`parity-plan.md`](parity-plan.md), which is this stage and
nothing else. Its five-level oracle ladder runs from byte-exact pure-function
ports (L0) through the 85,645-cell reproduction (L3) to a DecBench provider A/B
(L4).

**What it unlocks.** Joern leaves the loop. The 56-cell matrix gate stops
spawning a JVM per cell. A structural distance becomes something the ordinary
iteration loop can compute, rather than an opt-in 37-minute lane. The
`agentic-source-recovery` evaluation design stops being gated on an external
tool.

**Stop condition.** If the Phase-0 gate shows the stored GED values cannot be
reproduced from the published source CFGs plus the stored C, there is no offline
oracle; re-plan with budgeted Joern runs before continuing.

## 6. S4 — C to LLIR

**Deliverable.** A lowering from the S1 AST to `LlirFunction`.

**Why this is the multiplier.** `src/exec/interp.rs` is *the one* interpreter:
`run_function(&LlirFunction, &mut Budget)` steps `Op`s over a `Domain` trait
that both the concrete emulator (`src/exec/concrete.rs`) and the symbolic engine
(`src/symbolic/symdomain.rs`) implement — "no duplicated semantics", as
`src/symbolic/mod.rs` puts it. So a front end that reaches LLIR inherits, with
no new engine code:

* concrete execution of C functions;
* symbolic execution over the same semantics;
* every solver backend behind the `Solver` trait (`src/symbolic/solver/mod.rs`),
  including the pure-Rust `axeyum` under `solver-axeyum` and Z3 under
  `solver-z3`;
* the taint, sink and exploration machinery layered on those.

**Gate.** A lowered C function and the same function compiled and lifted from
its binary produce the same observable result under `exec` for a corpus of
inputs. Start with the 196 fixture sources: they are single-construct by design,
the harness already builds each one at several compiler/opt combinations
(`tests/decompiler_fixtures/build/`, gitignored, plus a handful of checked-in
`canary/*.so`), and the differential machinery to run both sides already exists
in `src/exec/oracle.rs` and the fixture harness.

**Scope discipline.** Lowering only needs to cover what the fixtures and the
corpus contain. It is not a C compiler: no linking, no ABI lowering beyond what
`ir::abi` already models, no preprocessor.

**Stop condition.** If semantic divergence between lowered-C and lifted-binary
cannot be driven down on the single-construct fixtures, S5 is not reachable and
the programme ends at S3 with the metric win banked.

## 7. S5 — Bounded equivalence checking

**Deliverable.** Given a source function and a decompiled function, lower both
to LLIR, execute both symbolically over the same `Domain`, assert equality of
outputs under equal inputs, and hand the query to a solver.

**Why it matters.** Every oracle the project has today is a proxy. GED measures
degree sequences. `byte_match` measures assembly line overlap after a
best-effort recompile. The execution differential is blind to structure — it is
a recorded trap that goto soup passes every fixture. **A bounded equivalence
check is not a proxy.** It answers the actual question: does the recovered
function compute the same thing as the original, for all inputs within the
bound?

This is where the sibling solver earns its place. `axeyum` is already a pinned
optional dependency behind `solver-axeyum`, it is pure Rust, and the query shape
— quantifier-free bitvectors — is exactly its minimal consumer profile
([`decisions/solver-002-axeyum-as-default-backend.md`](../../decisions/solver-002-axeyum-as-default-backend.md)).

**Gate.** Separation, not coverage. Take fixtures where the decompilation is
known correct and fixtures with a known-injected defect, and require the checker
to say *equivalent* for the first set and *not equivalent, with a witness* for
the second. A checker that says "unknown" for everything passes no gate.

**Honest limits, to be stated wherever a result is quoted.** Bounded means
bounded: loops are unrolled to a depth, memory is modelled to a size, and
`unknown` is a first-class outcome rather than a failure — the same rule the
sibling workspace enforces. An `unknown` is not evidence of equivalence, and a
counterexample is only as good as the input model.

**Stop condition.** If the separation gate cannot be met on hand-built
known-good and known-bad pairs, the checker is not an oracle and must not be
quoted as one.

## 8. S6 and S7 — the rest

**S6 — native `type_match`** (T-1..T-8). Fully independent of every other stage:
it needs DWARF, which `gimli` already reads, and nothing else. Pure Rust, zero
new dependencies, every component with a cheap equality test against the
reference. Do it whenever there is a gap.

`byte_match` is deliberately **not** a stage. B-4 shells out to
gcc / MinGW / arm-none-eabi; no amount of building things ourselves removes an
external toolchain, and it is worth the least — 5 of our 82 published Union
points against GED's 69.

**S7 — the static analysis surface.** What S2 (and, where noted, S4) makes
possible. Each is a separate increment with its own justification; none is
scheduled by appearing here.

| capability | needs | replaces or enables |
|---|---|---|
| Function extraction by name from source | S1 | `tools/roundtrip_review.py:source_of`, which matches braces with a regex and says in its own docstring that "a real parser would be more robust" |
| Source-versus-decompiled structural comparison as a product feature | S2 | today this exists only as a DecBench metric, computed out of process |
| Source call graph and def-use | S2 | a ground-truth companion to `analysis::xrefs` and the def-use census |
| Source-side identity and similarity | S1 | feeds `src/identity` and `src/similarity` with token- and structure-level source features |
| Source facts into the knowledge base | S1 | real names, prototypes and types with a `set_by` provenance, when source is available |
| Path feasibility in the source CFG | S4 | prunes infeasible paths using the existing solver seam |
| Recovered-source validation for the agent loop | S2, S5 | [`agentic-source-recovery/`](../agentic-source-recovery/README.md) currently has no way to check its own output beyond compiling it |

## 9. The degenerate cases

Per the fuzz seed-class rule in §0, each of these needs a generator that
deliberately emits it. The 85,645-cell oracle is a corpus sweep; on its own it is
a gate for none of them.

| case | why the corpus will not cover it | stage |
|---|---|---|
| computed `goto` (`goto *p`) | rare, concentrated in parser-generated code such as `yyparse` | S2 |
| an unparseable construct inside an otherwise parseable function | needs deliberate corruption | S1 |
| an empty `then` branch | elided by any block-first CFG builder, but a node in Joern | S2, S3 |
| a function with more than one entry-flagged node | 1,334 exist, and normalizing them away is the natural bug | S3 |
| a function whose funcend is *not* a singleton | the other half of the 49.0%/51.0% split | S3 |
| a diff that hits the one-second deadline | only reachable with a large function and a slow machine | S6 (`byte_match` only) |
| deeply nested expressions | the stack-overflow-aborts-the-process case | S1 |
| a solver `unknown` | must be a first-class outcome, never an error or a pass | S5 |

## 10. Sequencing advice

**Do S0, then S3's distance half (G-1, G-2, G-4) before S1.** The LSAP is `S`-sized
and brute-force checkable for small `n`; feeding it `rebuild_cfg` output from the
published source CFGs on *both* sides certifies the scoring half before the hard
half starts, and it is the piece most likely to be reused elsewhere in the crate.

**Keep S1/S2 and S3 in separate modules from the first commit.** S3's layer
exists to reproduce another tool's quirks. If those quirks leak into S1 or S2,
the general asset becomes good for one metric and nothing else, and S4 inherits
a CFG shaped by a JVM program's expression granularity.

**Do not let S3's success end the programme.** Banking the metric win and
stopping is the likeliest failure mode here, because S3 is the stage with the
number attached. S4 is what makes the front end worth more than Joern was.
