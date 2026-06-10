# SMT Backends for Rust Symbolic Execution (QF_ABV)

Binary symbolic execution lives in **QF_ABV** (quantifier-free arrays +
bitvectors): memory = arrays of bitvectors, registers/flags = bitvectors. The
solvers that win QF_ABV in SMT-COMP are BV/array specialists, not
general-purpose solvers.

## TL;DR

> **Updated 2026-06-10 (implementation):** the engine went **native-first**, not
> pipe-first — see [ADR-0005](../05-decisions/adr-0005-smt-pipe-then-native-optional.md).
> The native `z3` crate links libz3 in-process (feature `solver-z3`) and is the
> primary backend; the SMT-LIB2 pipe is the zero-build fallback. Rationale: a
> native Rust engine shouldn't shell out, and "lean base build" is achieved by
> feature-gating, not by avoiding native bindings. The research below (which
> argued pipe-first for distribution convenience) is kept for context.

**Abstract behind a `Solver` trait. (Implemented:) native `z3` crate primary,
SMT-LIB2 pipe fallback, all feature-gated so the base build needs no solver.
Bitwuzla remains an attractive optional native backend for QF_ABV speed.**

## Candidates

### Z3 — `z3` 0.20.0 / `z3-sys` 0.11.x (prove-rs/z3.rs)
Mature, default-safe. `Solver` exposes `push`/`pop`/`assert`/`check`/
`check_assumptions(&[Bool])`/`get_model`/`reset` — `check_assumptions` is exactly
the assumption-literal mechanism for path-by-path exploration. **Build is
best-in-class:** features `bundled` (static CMake build), `gh-release` (download
prebuilt libz3), `vcpkg`, system. **Gotcha:** `Context`/`Solver` are `!Send +
!Sync` → one context per worker thread. Correct on QF_ABV but ~5× slower than
Bitwuzla cumulatively (CAV'23).

### Bitwuzla — `bitwuzla-sys` 0.8.0 (Jun 2025)
The performance pick; BV/array/FP specialist (maintained successor to Boolector).
C API has `bitwuzla_push/pop`, `bitwuzla_check_sat_assuming`,
`bitwuzla_get_unsat_core`. `vendor-cadical` builds a static lib — **UNIX-only**
(Windows needs a prebuilt/system lib). **No high-level safe wrapper** — you write
the safe layer (fine, it's behind our trait). Third-party, low-commit binding —
be ready to fork/patch; the engine itself is excellent and active.

### Boolector — `boolector` 0.4.3 (high-level) / `boolector-sys` 0.7.2
Superseded by Bitwuzla; **don't adopt new.** But the high-level `boolector` crate
(used by the `haybale` Rust symbolic executor) is the **best existing reference**
for what a good BV/array ↔ Rust API looks like.

### cvc5 — `cvc5-rs` 0.4.0 (official, Apr 2026)
Project-maintained (a plus). Strong on quantifiers/strings, trails Bitwuzla on
pure QF_ABV. Keep as a secondary backend behind the trait.

### Yices2 — **avoid**: not thread-safe, weak array ergonomics.

## Pipe vs native FFI

| | Subprocess (SMT-LIB2 pipe) | Native FFI |
|---|---|---|
| Crates | `easy-smt` 0.3.2, `smtlib`, `rsmt2` | `z3`, `bitwuzla-sys`, `cvc5-rs` |
| Pros | **Zero C/C++ build deps; wheel builds clean**; solver-agnostic (swap by changing the spawn command); trivial logging/replay | Lowest latency; in-process incremental state; rich model API |
| Cons | Per-query IPC + text serialization; must ship/locate a solver *binary* at runtime | Heavy C/C++ build; static-link/platform pain; thread-safety constraints; complicates the wheel |

`easy-smt` is production-proven (Cranelift/Wasmtime verification). `push`/`pop`/
`check-sat-assuming` are available as SMT-LIB2 commands over the pipe.

## Cross-cutting

- **Incrementality:** prefer **assumption literals** (`check-sat-assuming`) over
  deep `push`/`pop` nesting — stateless per check, plays better with caching.
- **Caching is OUR job, not the solver's:** canonicalize each path-constraint
  conjunction, key a cache → sat/unsat/model; try last models as a cheap concrete
  pre-check; keep a warm solver per path-prefix and push only the delta. (KLEE/
  claripy do counterexample + independence caching.)
- **Distribution:** keep SMT behind a Cargo feature (`default = []`); base wheel
  has no C++ solver. Z3 `gh-release`/`bundled` is the most wheel-friendly native
  option (all 3 OSes); Bitwuzla vendoring is UNIX-only (Windows → Z3 or pipe).
- **Thread-safety:** no mainstream solver shares a context across threads → the
  `Solver` trait carries a `fn fresh() -> Self` factory; one instance per worker.

## Recommendation (→ Phase 4, ADR-0005)

1. `Solver` trait: `assert`, `push`/`pop`, `check_assuming(&[Lit]) -> SatResult`,
   `get_model`, `fresh()`.
2. First backend: **`easy-smt` pipe**, defaulting to the Bitwuzla binary, Z3
   fallback. Fastest path to a correct engine, zero build/distribution cost.
3. Later, behind optional features: `solver-bitwuzla` (`bitwuzla-sys`,
   `vendor-cadical`, UNIX) for speed; `solver-z3` (`z3`, `gh-release`/`bundled`)
   for portability + the cleanest Windows wheel.
4. `default = []` — base wheel builds with no solver dependency.

### Crate cheat-sheet
- `z3` **0.20.0** — `bundled`/`gh-release`/`vcpkg`/`bindgen`/`z3_4_16`
- `bitwuzla-sys` **0.8.0** — `vendor-cadical` (UNIX); binds Bitwuzla 0.9.x
- `boolector` **0.4.3** (reference API) / `boolector-sys` 0.7.2
- `cvc5-rs`/`cvc5-sys` **0.4.0** — `static`
- `easy-smt` **0.3.2** (pipe) · `smtlib` · `rsmt2`

> Update (2026-06-10): an earlier note here claimed "no solver installed, so the
> engine must locate/ship it" — that was used to justify pipe-first and was a
> premature conclusion (the dev box had no solver only because none had been
> installed; `apt-get install z3 libz3-dev` resolves it, and the `z3` crate then
> links libz3 in-process). The implemented engine links z3 natively
> (`solver-z3`) and verified solving end-to-end; the symbolic `Domain` emits valid
> SMT-LIB2 (`(bvadd …)`, `(ite (= …) (_ bv1 1) (_ bv0 1))`) and z3 returns models
> as Rust values.

## Sources

- [prove-rs/z3.rs](https://github.com/prove-rs/z3.rs), [z3 Solver docs](https://docs.rs/z3/latest/z3/struct.Solver.html)
- [bitwuzla-sys](https://github.com/fatemender/bitwuzla-sys), [Bitwuzla C API](https://bitwuzla.github.io/docs/c/api.html), [CAV'23 benchmarks](https://cs.stanford.edu/~preiner/publications/2023/NiemetzP-CAV23.pdf)
- [boolector high-level](https://docs.rs/boolector), [haybale](https://github.com/PLSysSec/haybale)
- [cvc5-rs](https://github.com/cvc5/cvc5-rs), [easy-smt](https://github.com/elliottt/easy-smt), [maturin distribution](https://www.maturin.rs/distribution)
