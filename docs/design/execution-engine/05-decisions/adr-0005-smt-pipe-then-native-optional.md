# ADR-0005 — SMT Backend: Native-First (`z3` crate), Pipe as Fallback

**Status:** Accepted (revised 2026-06-10 — reversed the original "pipe-first") ·
**Date:** 2026-06

> **Revision note.** This ADR originally said "pipe first, native optional." That
> was wrong for this project and is reversed below. The original reasoning —
> "avoid a C/C++ build dependency in the base wheel" — is satisfied by
> **feature-gating**, not by avoiding native bindings. Glaurung is a native Rust
> engine; shelling out to an external `z3` binary (or depending on a Python
> `z3-solver` package) is exactly the kind of non-Rust coupling the project
> avoids. The original ADR optimized for author convenience and dressed it up as
> a distribution argument.

## Context

Symbolic execution needs an SMT solver over QF_BV (bit-vectors + arrays). Three
ways to obtain one: (a) link a native solver into the Rust build via a crate;
(b) spawn an external solver binary and speak SMT-LIB2 over a pipe; (c) depend on
a Python package that bundles a binary. The engine is otherwise entirely
in-process Rust (emulator, register file, memory, `Domain`, `Expr` IR).

## Decision

1. **Primary backend: the native `z3` crate, linked in-process**, behind the
   `solver-z3` cargo feature. The bit-vector `Expr` IR is translated directly to
   z3 AST; results come back as Rust values. No subprocess, no PATH discovery, no
   Python. This is consistent with the rest of the engine.
2. **Fallback backend: the SMT-LIB2 pipe** (`PipeSolver`) — spawns a solver
   binary (`bitwuzla`/`z3`/`cvc5`, or `$GLAURUNG_SMT_SOLVER`). Zero build
   dependency; used when no native solver is compiled in. Kept because it's
   genuinely useful in minimal/build-constrained environments, not as the
   recommended path.
3. **One `Solver` trait** (`check(pool, asserts) -> SolveResult`) with both
   backends behind it; `solve()` prefers native when `solver-z3` is on, else the
   pipe. A future **pure-Rust** backend (bit-blast → SAT, e.g. `varisat`/`splr`)
   can implement the same trait.
4. **Base build stays lean by feature-gating**, not by avoiding native code:
   `default` has no solver; `symbolic` builds the `Expr` IR + pipe fallback (pure
   Rust, no link); `solver-z3` links libz3.

## On pure-Rust solvers

There is no mature pure-Rust *SMT* solver competitive on QF_BV; the strong ones
(z3, bitwuzla, cvc5, yices, boolector) are C/C++. Pure-Rust *SAT* solvers do
exist (`varisat`, `splr`, `batsat`, `creusat`). The fully-Rust route is therefore
**bit-blasting QF_BV → CNF → a pure-Rust SAT solver** — viable for the small
bounded constraints binary symbex produces, slower on hard instances. This is a
worthwhile future `Solver` backend; native z3 is the pragmatic high-performance
default today.

## Alternatives rejected

- **Pipe-first / pipe-only** (the original decision) — shells out to an external
  process; not self-contained; couples to a runtime binary on PATH or a Python
  package. Demoted to fallback.
- **Python `z3-solver` dependency** — couples a Rust-spawned binary to a Python
  package; only helps the wheel consumer, nothing for cargo consumers; not
  Rust-native. Rejected for the core.
- **Bitwuzla-only native** — fastest on QF_BV, but the Rust binding is thin and
  UNIX-only to vendor; revisit as an optional `solver-bitwuzla` backend later.

## Distribution by consumer

- **cargo / Rust consumers:** `--features solver-z3` links libz3 (system lib, or
  the `z3` crate's `bundled`/`gh-release` for a self-contained build). Pure-Rust
  symbolic-without-solving needs only `symbolic`.
- **pip / wheel consumers:** build the wheel with `solver-z3` so libz3 is linked
  into the extension — no external binary, no Python solver dep. (An optional
  `glaurung[symbolic]` extra could ship a solver binary for the pipe fallback,
  but it isn't the primary mechanism.)

## Consequences

- (+) Self-contained, in-process, Rust-API solving; deterministic; consistent
  with the rest of the engine.
- (+) Caching/independence (Phase 4) live in our code over the `Expr` IR,
  independent of backend.
- (−) `solver-z3` adds a C/C++ link (libz3) and build time — bounded by the
  feature gate; the base build is unaffected.
- (−) z3's `Context` is `!Send + !Sync` → one solver context per worker thread
  (matches the per-worker exploration model anyway).

## Implementation status (2026-06-10)

Implemented: `Solver` trait (`symbolic/solver/mod.rs`); native `Z3Solver`
(`solver/z3_backend.rs`, feature `solver-z3`) — solves QF_BV in-process, returns
Rust models; `PipeSolver` fallback (`solver/pipe.rs`). Verified end-to-end: a
constraint built by running the **interpreter over the symbolic `Domain`** solves
to the expected input via linked z3 (`x + 1 == 0x100` → `x = 0xff`); unsat
detection works. libz3 is linked via the system library (`libz3-dev`); the wheel
path will use `bundled`/`gh-release`.
