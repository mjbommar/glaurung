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
| S3 | Joern-parity layer + GED | 85,645 reproducible GED cells matched exactly — **93.1636% (79,790) as of 2026-09-04, 0 uncovered** | no |
| S4 | C → LLIR lowering | the existing interpreter runs a lowered C function | no |
| S5 | bounded equivalence checking | a known-good and a known-bad decompilation are separated | **the point** — landed `6df1c627`, §7 |
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

**S1 is complete.** The parser (`F-5`..`F-7`) landed too, and clears the same
gate on the same corpora:

```
in-repo:    210 files, 21296 lines, 930 functions, 0 errors, 0 empty files
decompiled:  14 files, 62716 lines, 1558 functions, 0 errors
full sweep: 1606 files, 11917994 lines, 188716 functions, 0 errors, 7.4 s
```

```bash
cargo test --features python-ext --lib csource::parse -- --nocapture
GLAURUNG_PARSE_FULL_CORPUS=1 cargo test --release --features python-ext \
  --lib csource::parse -- --nocapture      # the 1,606-file sweep
```

The sweep is behind a demand switch so the ordinary lane stays at about a
second, and it paid for itself: it took the parser from 1,410 errors to 8 to 0
across two tightenings of one shape test.

Two results worth carrying forward. **No typedef table was needed** — §9's open
question 1 predicted this and the corpora confirm it, with the falsifier
written down (`a * b(c);`, a discarded call, would force a typedef *name set*
into `look.rs`). And **there is no native recursion anywhere in the front end**:
the parser is one loop over a task stack, tested at 20,000 levels of nesting
across five shapes plus 50,000 unbalanced openers, with no abort and no hang.

The same honesty caveat attaches to the sweep as to the lexer's: every artifact
in it is Glaurung's own output, so zero errors per KLOC measures a well-formed
emitter rather than an adversarial one.

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

**S2 is complete.** `src/csource/cfg/` lowers the AST to `Flow` events and the
substrate builds the graph:

```
in-repo:     210 files,     930 functions,     930 CFGs, 0 validation failures
decompiled:   14 files,   1,558 functions,   1,558 CFGs, 0 validation failures
full tree: 1,606 files, 188,716 functions, 188,716 CFGs, 6.8 M nodes, 7.6 M edges
```

```bash
cargo test --features python-ext --lib csource::cfg -- --nocapture
GLAURUNG_PARSE_FULL_CORPUS=1 cargo test --release --features python-ext \
  --lib csource::cfg -- --nocapture          # the 1,606-file sweep, ~4 min debug
```

**`REQ-CFG-6` is the component's whole point, and it is measured.** The parser
deliberately leaves `&&`, `||` and `?:` as ordinary expressions; turning them
into forks is this layer's job, and a graph that treats `if (a && b)` as one
condition is wrong in exactly the way GED measures. **625 forks across 350 of
930 in-repo functions; 65,168 across 25,962 of 188,716 on the tree.** The census
is probed rather than asserted non-zero: one body measures 3 with the
short-circuit operators, 0 with each swapped for its bitwise cousin, 4 with one
added.

Three results worth carrying, each of which cost something to find:

* **Live labels are a fixpoint, not a scan.** A label is a jump target only if a
  *reachable* `goto` names it. Taking every `goto` at face value kept 4,028
  unreachable nodes alive on the zlib lane alone, all descending from one dead
  `goto` in `inflate`.
* **The consumer found two defects in the substrate**, and they were fixed in
  the substrate rather than tolerated here — see
  [`../source-front-ends/substrate.md`](../source-front-ends/substrate.md) §5.
  The C side's allowance was deleted, not re-baselined, and replaced by a
  regression test that drives both reproducers.
* **2,324 of 188,716 functions legitimately fail `REQ-GEN-1`'s second
  invariant.** `spin: g(); goto spin;` reaches the function end on no path, so
  "every path reaches the end" is false *of the program*. The allowance for it
  is structural and narrow — it admits nothing unless every stranded node still
  has a successor, which is what makes the set a cycle rather than a dead end —
  and unlike the substrate defects it does not go away when anything is fixed.
  Inventing an exit edge would be a lie about what can happen.

The same corpus caveat as S1 applies to the sweep: every artifact in it is
Glaurung's own output.

## 5. S3 — Joern parity and GED

**Status, 2026-09-04: the layer exists and is measured.** F-9, F-10, F-11,
F-12, F-13, F-14 and F-15 are implemented in `src/csource/joern/`, the PyO3
provider is wired, and `tools/source_cfg_parity.py --provider glaurung` scores
**79,790 of 85,645 cells exact (93.1636%) with zero uncovered**. The command and
the component-by-component progression are in
[`parity-plan.md`](parity-plan.md) §3, Phase 3. Not yet done: F-16 per-TU
resolution, F-17's on-disk `--source-cfgs` round trip, and the ratchet.

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

> **Landed** at `6df1c627` (2026-09-04). `src/csource/equiv/`, scored by
> `csource::equiv::scorecard_tests` over 1,810 labelled mutants from
> `tools/metric_mutation.py`'s own catalogue across 207 fixture functions:
>
> ```
> sensitivity  429/443 decided (96.8%)     GED on the same instrument: 21.8%
> specificity  513/513 decided (100.0%)    GED: 95.3%
> unknown      31 abstentions, never folded into either ratio
> ```
>
> Specificity is the number that stands unqualified: zero false alarms across
> all fourteen semantics-preserving classes, including `demorgan`,
> `if-else-swap` and `duplicate-tail` — the population every structural metric
> in this programme is blind on.
>
> Sensitivity is a floor rather than a score. The catalogue labels a *class*,
> and whether a rewrite changes behaviour depends on the function it lands in.
> Of seventeen cells labelled behaviour-changing that came back `Equivalent`,
> sixteen were read and are genuine equivalences — two of them for reasons no
> reading of the diff gives you (`INT_MIN * 100` being exactly 0 modulo 2^32;
> `median(a, a, c) == a` either way). The seventeenth was a real unsoundness and
> is the subsection below. So the gate is a named list, `VERIFIED_EQUIVALENT`,
> not a percentage: anything else proved equivalent fails, a listed cell that
> turns `Different` fails, and one that turns `Unknown` is reported rather than
> asserted because the solver wall is wall-clock and would otherwise make the
> test flaky on a loaded machine.
>
> **What building it found.** Three defects in shipped code that no existing
> gate could see, each fixed and each proved against something outside our own
> code:
>
> * `src/csource/lower` evaluated shifts on 64-bit temporaries, so `1u << 32`
>   gave 0 where hardware gives 1 (`828becda`). This produced the false
>   `Equivalent` above. Confirmed against gcc, and independently by the S4
>   differential dropping to `diverged: 0`.
> * The SMT lowering disagreed with `src/exec/concrete.rs` on shift distance and
>   divide-by-zero, so an `unsat` — read as "equivalent" — was computed under
>   semantics our own executor contradicts (`9c8c1e67`). Note the guard that
>   existed was asymmetric: `WitnessUnconfirmed` replays a model and so protects
>   `Different`; an `unsat` carries no model.
> * `Symbolic::constant_value` walked a hash-consed DAG as a tree; a 65-node DAG
>   timed out past 90 s in release and now folds in 0.03 s (`9c8c1e67`).
> * Adjacent: `src/symbolic/solver/pipe.rs` had no wall and a stdin deadlock
>   (`84cf6766`).
>
> **Outstanding.** The unsat coverage guard described below is specified and not
> built: before accepting an `unsat`, ask whether an input can reach a shift
> whose count is not provably below the operand width, or a divisor not provably
> non-zero, and downgrade to `Unknown` when that is satisfiable. Its value
> dropped once the SMT and concrete domains were aligned, but it is the
> structural fix rather than the instance fix. Also: `goto-ify` declines all ten
> of its pairs because S4 has no `goto`, so the one semantics-preserving class
> that destroys control-flow structure is invisible to this checker.

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
it needs DWARF, which `gimli` already reads, and nothing else.

**Two of its eight components have landed** in `src/metrics/`, both because
there was idle capacity rather than because S6 was scheduled. `type_name.rs`
is T-2 and T-3, and `calibrate.rs` is T-4 and T-5. Each was differentialled
against the live reference rather than against inputs we chose:

```
type_name : 122 candidate strings, 122/122 form-sets agreeing,
            14,884/14,884 pairwise verdicts agreeing
calibrate : 3,800 cases (3,000 per-function, 800 binary-wide), 3,800 agreeing
```

Between them they found **four defects in the reference implementation**, all
reproduced rather than fixed, because parity is the contract and a corrected
port would score functions differently from the benchmark it mirrors:
`normalize_type("long long int")` emits the non-C spelling `"long long long"`;
`"_Bool"` emits `"_bool"`; the calibration guard compares a raw list length
against a deduplicated count, so one slot described twice abstains; and that
guard's zero fallback is provably unreachable. Each carries an assertion, so a
future cleanup that removes the quirk fails the suite.

`calibrate.rs` also runs in `O(|G|·|D|)` where the reference is `O(|G|·|D|²)`,
and its differential was measured for *sensitivity* — three deliberate
deviations produced 229, 55 and 134 disagreements out of 3,800. Two of those
probes initially caught almost nothing, which exposed a gap in the generated
corpus rather than a passing test. Pure Rust, zero
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
