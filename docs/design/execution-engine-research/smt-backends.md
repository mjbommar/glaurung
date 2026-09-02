# SMT backends for Rust symbolic execution (QF_BV)

> **Kind:** design · **Status:** proposed

Binary symbolic execution lives in **QF_ABV** — quantifier-free arrays and
bitvectors: memory as arrays of bitvectors, registers and flags as bitvectors.
The solvers that win QF_ABV in SMT-COMP are BV/array specialists, not
general-purpose provers.

This is a survey of the option space, kept because the *shape* of the trade-offs
is durable even though our own answer has changed twice. What Glaurung actually
ships is [`architecture/solver-backends.md`](../../architecture/solver-backends.md);
the decision is [`exec-0005`](../../decisions/exec-0005-native-solver-first.md).
Versions below were read from `Cargo.toml` and `Cargo.lock` at `b8884687`, not
from the vendors' latest announcements — re-read before quoting.

## Where we landed, so the survey is read correctly

The 2026-06 survey recommended a **pipe-first** design with `easy-smt` speaking
to a Bitwuzla binary. That was reversed the same month: a native Rust engine
should not shell out, and "lean base build" is achieved by feature-gating, not by
refusing native bindings. `easy-smt` was never taken as a dependency
(`rg 'easy-smt' Cargo.lock` finds nothing); the pipe fallback is a hand-rolled
`std::process::Command` in `src/symbolic/solver/pipe.rs`.

The survey's second miss is more interesting. It concluded that "there is no
mature pure-Rust SMT solver competitive on QF_BV", which was true of the
*existing* field and false as a statement about what could be built. The project
went on to build one — see §axeyum below.

## Candidates

### Z3 — the `z3` crate, **0.12** (`z3-sys` 0.8), prove-rs/z3.rs

Mature, safe, and the one we ship as the preferred backend (`solver-z3`). The
Rust `Solver` exposes `push`/`pop`/`assert`/`check`/`check_assumptions(&[Bool])`/
`get_model`/`reset`; `check_assumptions` is exactly the assumption-literal
mechanism path-by-path exploration wants. Build story is best-in-class —
`bundled` (static CMake), `gh-release` (prebuilt libz3), `vcpkg`, or system — and
we use **system libz3** (`libz3-dev`); no wheel build enables the feature at all.
**Gotcha:** `Context` and `Solver` are `!Send + !Sync`, so one context per worker
thread, which is why the warm paths in our backends are thread-local. Correct on
QF_ABV, and roughly 5× slower than Bitwuzla cumulatively in the CAV'23 numbers.

> The 2026-06 survey wrote "`z3` 0.20.0 / `z3-sys` 0.11". Neither number was
> right for this repository at any point; the pin has been `z3 = "0.12"`.

### Bitwuzla — the C API directly, **0.9.1**

The performance pick, and a BV/array/FP specialist (the maintained successor to
Boolector). We bind the **official C API directly** in
`src/symbolic/solver/bitwuzla_backend.rs`, with `build.rs` requiring
`BITWUZLA_LIB_DIR` and rejecting any linked version other than 0.9.1. The
third-party `bitwuzla-sys` 0.8 crate the survey recommended is **not** a
dependency: it was version-mismatched against the API we needed, and writing the
safe layer ourselves was the smaller risk once everything sits behind our own
trait anyway.

Crucially, this backend is **not a production backend**. It exists as a
topology-equivalent neutral measurement cell so a warm-versus-cold claim can be
tested against an in-process solver that is neither project participant
([`solver-031`](../../decisions/solver-031-pinned-bitwuzla-measurement-cell.md)).
Its C dependency is precisely what a shippable engine is trying to avoid.

### axeyum — pure Rust, in-process, pinned by git rev

The backend the survey said did not exist. `axeyum-solver` (with
`default-features = false, features = ["qfbv"]`) and `axeyum-ir`, both from
`github.com/mjbommar/axeyum` at rev `c38a9515`, bit-blast QF_BV to a pure-Rust
SAT core and emit **DRAT-checked unsat proofs**. No libz3, no C, no subprocess,
so a wheel *could* carry it — which is the entire point.

What that buys and what it costs:

- **Buys:** deployability (nothing to install, nothing to link, WASM-plausible);
  proof-carrying unsat, which fits an evidence culture where a verdict should
  cite something; and a retained-session API rich enough for the warm and
  direct-delta paths our explorer wanted.
- **Costs:** cold one-shot solving of lifter-shaped formulas is *slower* than z3.
  The honest boundary is that retained path lineage can amortize lowering and
  win, while a cold one-shot comparison does not. See
  [`solver-014`](../../decisions/solver-014-source-prefix-production-win.md).
- **The trap it walked into first:** an early measurement reported axeyum
  12–29× faster. It was an artifact — un-coerced width mismatches made axeyum
  *error out* on ~98% of queries rather than solve them, and a fast non-answer is
  not a fast answer. The retraction is in
  [`history/axeyum-integration-2026-07/PAPER-NOTES.md`](../../history/axeyum-integration-2026-07/PAPER-NOTES.md),
  and the structural fix — enforcing declared operand widths at every solver
  boundary — is
  [`solver-016`](../../decisions/solver-016-enforce-declared-concat-widths.md).
  This is the single most important lesson in this file: **instrument
  unknown/error counts per backend, always**, or a performance comparison will
  eventually measure dropped work.

### cvc5 — `cvc5-rs` (official)

Project-maintained, strong on quantifiers and strings, trails Bitwuzla on pure
QF_ABV. We use it only as an *external* neutral control through the pipe, never
as a linked backend.

### Boolector, Yices2 — do not adopt

Boolector is superseded by Bitwuzla. Its high-level Rust crate remains the best
existing *reference* for what a good BV/array Rust API looks like (it is what the
`haybale` symbolic executor uses), and that is the only reason to open it.
Yices2 is not thread-safe and has weak array ergonomics.

## Pipe versus native FFI

| | Subprocess (SMT-LIB2 pipe) | Native FFI / in-process |
|---|---|---|
| How | render a script, spawn a binary, parse `sat`/`unsat`/`unknown` | link a library, or link pure Rust |
| Pros | zero build dependency; solver-agnostic — swap by changing the spawn command; trivial to log and replay a query | lowest latency; retained incremental state; rich model API; no PATH dependence |
| Cons | per-query process spawn and text serialization; must locate a solver **binary** at run time; no incrementality across queries | heavy C/C++ build (unless pure Rust); platform and static-link pain; thread-safety constraints |
| Ours | `pipe::PipeSolver`, tried last | `solver-z3`, `solver-axeyum`, `solver-bitwuzla` |

The decisive datum is that binary symbolic execution issues **very many small
queries**, so a per-call fixed floor — process spawn, or FFI plus context
construction plus marshalling — dominates the actual solving on most of the
distribution. That is why the pipe is a fallback rather than the design, and it
is also the mechanism behind axeyum's cold-path advantage on small formulas.

## Cross-cutting

- **Incrementality.** Prefer **assumption literals** (`check-sat-assuming`) over
  deep `push`/`pop` nesting for one-off queries: stateless per check, friendlier
  to caching. But a *retained* session driven by assertion deltas is a different
  and stronger mechanism, and it is what our `IncrementalSolver` trait exposes;
  the explorer's fork tree maps onto scope push/pop naturally, provided each
  session has exactly one owner. That ownership rule is not optional — it is what
  [`solver-011`](../../decisions/solver-011-first-class-direct-delta-session.md)
  and [`solver-013`](../../decisions/solver-013-source-ancestry-sibling-reuse.md)
  spend their length on.
- **Caching is our job, not the solver's.** Canonicalize the path-constraint
  conjunction, key a cache on it, and try the last model as a cheap concrete
  pre-check before asking anyone. KLEE and claripy both do counterexample and
  independence caching; ours is `solver/constraint_cache.rs`, and the cheapest
  win of all — skipping the solve when the branch predicate shares no free symbol
  with the path condition — lives in the explorer, not in a backend.
- **Thread safety.** No mainstream solver shares a context across threads. Design
  for one instance per worker from the start; retrofitting it is painful.
- **Distribution.** Keep every solver behind a Cargo feature. Our `default` is
  `["triage-core"]` and carries no solver; `python-ext` adds the emulator and
  still no solver. A pure-Rust backend is the only one that can change that
  without changing what a wheel has to link.
- **Grade against construction-truth, not against the other solver.** If a case's
  verdict is known by construction — a SAT case with an explicit witness, an
  UNSAT case built as `t == v ∧ t == v^1` — then a wrong answer from *either*
  side is caught, rather than only disagreement. Trusting one solver as the
  oracle hides the case where both are wrong the same way.

## What this survey got right, and what it got wrong

| Survey said | Outcome |
|---|---|
| Abstract behind a `Solver` trait | **Right**, and the trait stayed to one method for a long time. |
| `easy-smt` pipe first, Bitwuzla binary by default | **Wrong**, reversed within the month; `easy-smt` was never a dependency. |
| `z3` 0.20 / `z3-sys` 0.11 | **Wrong version**; the pin is `z3 = "0.12"`. |
| `bitwuzla-sys` 0.8 for a native Bitwuzla | **Wrong crate**; we bind the 0.9.1 C API directly, and only as a benchmark cell. |
| `default = []` | **Wrong**; `default = ["triage-core"]`. The *intent* — no solver in the base build — held. |
| Assumption literals over deep push/pop | **Right for one-shot**, incomplete: retained delta-driven sessions turned out to be the real lever. |
| No mature pure-Rust QF_BV SMT solver; bit-blasting to a Rust SAT core is a worthwhile future backend | **Right about the field, and the "future backend" was then built** — see §axeyum. |
| Thread-safety forces one context per worker | **Right**, and it shaped the warm-path design. |

## Sources

- [prove-rs/z3.rs](https://github.com/prove-rs/z3.rs), [z3 Solver docs](https://docs.rs/z3/latest/z3/struct.Solver.html)
- [Bitwuzla C API](https://bitwuzla.github.io/docs/c/api.html), [CAV'23 benchmarks](https://cs.stanford.edu/~preiner/publications/2023/NiemetzP-CAV23.pdf)
- [boolector high-level crate](https://docs.rs/boolector), [haybale](https://github.com/PLSysSec/haybale)
- [cvc5-rs](https://github.com/cvc5/cvc5-rs), [easy-smt](https://github.com/elliottt/easy-smt), [maturin distribution](https://www.maturin.rs/distribution)
- [axeyum](https://github.com/mjbommar/axeyum)
