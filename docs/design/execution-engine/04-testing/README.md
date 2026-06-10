# Testing Strategy

Glaurung is TDD with **real fixtures only** (no mock CPU state, no fake analysis
output — `CLAUDE.md`). Execution semantics are uniquely amenable to *differential*
testing, which is the backbone here.

## Layers

1. **Unit semantics** — per-op, per-helper Rust tests with hand-computed expected
   values (arithmetic tables, ext/trunc, flag predicates, memory endianness).
2. **Differential oracle** — single-step our interpreter and Unicorn on identical
   pre-state, diff full register file + flags + memory writes. The primary
   correctness net. → [`differential-oracle.md`](differential-oracle.md).
3. **Function-level** — emulate real function slices from `samples/`/`tests/
   fixtures/` and assert on outputs (return values, memory writes, resolved
   targets). → [`fixtures-and-corpus.md`](fixtures-and-corpus.md).
4. **Symbolic** — solve fixture constraints to known models; replay witnesses
   concretely to confirm they reach the target (concrete validation of symbolic
   results).
5. **Determinism** — every entry point run **twice**, asserting byte-identical
   output. Catches `HashMap`-iteration and host-entropy leaks early. →
   [`../02-architecture/determinism.md`](../02-architecture/determinism.md).
6. **Regression conversion** — every divergence the oracle finds becomes a
   permanent, minimal fixture-backed test (the TDD rule).
7. **Scorecard** — `glaurung.bench` tracks strings-recovered / indirect-edges-
   resolved so engine quality is a tracked number, not a vibe.

## Rust vs Python split

- Rust (`cargo test`): unit semantics, differential oracle, function-level,
  symbolic, determinism. Feature-gated: `--features exec,dev-oracle` and
  `--features symbolic`.
- Python (`uvx pytest python/tests/`): PyO3 surface, CLI smoke, agent-tool
  registration, KB writeback/provenance.

## Solver-dependent tests

Skip cleanly with a clear message when no `z3`/`bitwuzla` binary is present (none
on the dev box as of 2026-06). CI installs a solver (Bitwuzla preferred). Solver
absence never fails the base build or non-symbolic tests.

## What "done" means for any phase

`cargo test` (with the phase's features) + `uvx pytest` + `ruff` + `ty` all green,
**and** the phase's differential/scorecard exit criteria met. Surface real results
faithfully — if the corpus pass-rate is 92%, say 92% and list the divergences as
open fixtures; never round up.
