# Phase 5 — Symbolic Exploration (Forking, Constraints, Directed Search)

**Goal:** multi-path exploration — fork at feasible symbolic branches, manage path
constraints, explore with bounded directed search, and emit concrete witnesses.
Specs: [`symbolic-engine.md`](../02-architecture/symbolic-engine.md),
[`../01-research/symbolic-execution-survey.md`](../01-research/symbolic-execution-survey.md).

**Feature gate:** `symbolic`. **Gated by Phase 4.** **Primary risk:** state
explosion (mitigated by concolic-default + concretize-with-threshold + bounds).

## Tasks

- **5.1 `symbolic/symstate.rs`** — the `SymState` (regs/mem/constraints/solver/
  taint/dist_to_sink) with persistent-map registers + COW memory for cheap forks.
  *Test:* fork shares structure until first write; independent mutation.
- **5.2 `symbolic/symmem.rs`** — concretize-with-threshold symbolic memory: concrete
  addr fast-path; symbolic write → concretize (max-strategy option); symbolic read
  → ≤1024 B bounded `Ite`, else concretize. *Test:* a symbolic-index read within
  threshold yields an `Ite`; beyond threshold concretizes; a write concretizes.
- **5.3 `symbolic/explore.rs`** — the worklist engine: select state, `run()` to the
  next fork, branch into stashes (`active`/`deadended`/`found`/`avoided`/
  `unconstrained`); `check_assuming` to prune UNSAT forks. *Test:* a diamond CFG
  explores exactly the feasible paths.
- **5.4 Directed search** — `(dist_to_sink, state_id)` priority queue using ICFG
  shortest-distance; `find`/`avoid` target sets; random-path tie-break to avoid
  loop fork-bombs. *Test:* reaches a designated target block before exhausting the
  budget on a fixture with a deep decoy branch.
- **5.5 Bounds & spilling** — max-states cap, depth/loop bounds, spill-to-disk
  threshold. *Test:* a fork bomb is capped, not OOM; output deterministic.
- **5.6 Witness extraction** — on `found`, `get_model` → a concrete input that
  reaches the target; replay it concretely to confirm it actually reaches the
  target (concrete validation of the symbolic result). *Test:* witness replays to
  the target deterministically.
- **5.7 Determinism under exploration** — run-twice byte-identical
  (witnesses + visited order). *Test:* enforced.
- **5.8 (Optional) Veritesting** — summarize call-free regions into one
  disjunctive formula; drop to DSE at transition points. *Test:* path count drops
  on a branchy-but-call-free fixture, results unchanged.

## Deliverables

- `src/symbolic/{symstate,symmem,explore}.rs`.
- An `explore(binary, entry, symbolize, targets, budget) -> Vec<Witness>` entry
  point.

## Exit criteria

- Directed search reaches a target block in a real IOCTL handler within a bounded
  budget and emits a **concrete witness** that, replayed concretely, reaches the
  target.
- No state explosion on the test corpus (bounds + concretization hold); runs are
  deterministic (run-twice identical).
- `cargo test --features symbolic` green (solver tests skip without a solver
  binary; CI provides one).

## Notes

This is the **symbolic successor to `ioctl_taint`**: the static pass cheaply
nominates candidate sinks + taint sources; this phase confirms reachability and
produces an attacker-input witness. Keep the static pass as the fast pre-filter —
do not replace it; the two compose.
