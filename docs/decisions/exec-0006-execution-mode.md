# ADR-0006 — Execution Mode: Symbolic DFS with Constant Folding and Solver-Pruned Forking

> **Kind:** decision · **Status:** maintained

**ADR status:** Supersedes the never-implemented "directed concolic" ADR of 2026-06 · **Date:** 2026-06

> **This ADR replaces an aspiration with the engine that exists.** The 2026-06
> original decided *directed concolic execution*: a concrete seed carried
> forward with symbolic terms beside it (`Val = (ExprId, u128)`), forking gated
> by a taint mask, and a search directed by ICFG shortest-distance to a sink.
> **None of those three mechanisms was ever built**, and the ADR that named the
> engine's operating mode described a mode the engine does not have. The
> original text is preserved in `git log` on this path; what follows is the
> decision as the code actually embodies it.

## Context

The targets are real malware and Windows drivers. Pure symbolic execution is
sound in principle and explodes in practice (KLEE reports ~96k concurrent
states within minutes; unmodelled instructions and environment stall progress).
Something has to give, and the question is *which* guarantee.

## Decision

Run **pure symbolic execution over one shared expression pool**, made tractable
by four mechanisms that are not a concrete seed:

1. **Symbolic values, folded eagerly at construction.** `Symbolic::Val = ExprId`
   (`src/symbolic/symdomain.rs`) — an index into a hash-consed `ExprPool`, with
   no concrete shadow. `as_branch` evaluates the condition's DAG with the
   *concrete* domain's own semantics when it is symbol-free, so a branch that is
   determined does not reach the solver at all; only a genuinely symbolic
   predicate returns `BranchDecision::Fork`.
2. **Seed only what the attacker controls.** `symbolic/ioctl.rs::seed_irp` mints
   fresh symbols for the WDM IRP fields (`SystemBuffer`, `UserBuffer`,
   `IoControlCode`, the two lengths, `Type3InputBuffer`) at fixed concrete base
   addresses; everything else starts concrete or zero. `seed_linux_ioctl` and
   `seed_tainted_args` are the Linux and generic-function equivalents.
3. **DFS with a LIFO worklist, pruned by the solver.** `explore::run_worklist`
   pops states from a `Vec`, forks on symbolic branches, appends the branch
   predicate to the path condition, and drops the successor when the solver says
   `Unsat`. `can_skip_feasibility_check` skips the solve entirely when the
   predicate's free symbols do not intersect the path condition's — either
   polarity is then independently satisfiable. There is no priority queue, no
   distance-to-sink, and no random-path tie-break.
4. **Bound the work four ways instead of steering it.** A max-state cap; a
   per-block revisit cap (`MAX_BLOCK_VISITS = 8`, the loop-bomb defence);
   `DEFAULT_SOLVER_BUDGET = (6000 solves, 24 timeouts)` per function; and an
   optional wall-clock deadline (`solver::set_time_budget`) checked per
   instruction. Whichever trips first, the worklist records *why* it stopped.

Taint exists, but it labels findings rather than gating forks: `TaintSpec`
carries a stable label set per symbol, and `provenance_of` is consulted when a
sink is *reported*, not when a branch is *taken* — see
[`solver-027`](solver-027-preserve-taint-provenance.md).

## Rationale

The engine is a **bug-finder**, not a verifier, and what the driver workflow
wants is a concrete witness: an IOCTL input that reaches the sink. Constant
folding plus symbol-disjointness pruning turns out to remove most of what a
concrete seed was supposed to remove, without the machinery of maintaining two
values per register, and without the concolic model's characteristic weakness
(only reasoning near one trace). What it does not remove is state explosion in
loops, which is why the four bounds above exist and why an obfuscated driver is
detected by its *timeout count* rather than by a static heuristic.

## Alternatives rejected

- **Directed concolic (the original decision).** Rejected in practice rather
  than on paper: `Val = (ExprId, u128)` doubles the value representation for a
  benefit that eager folding already delivers, and the ICFG shortest-distance
  ordering it depends on was never worth building ahead of the bounds that
  actually stop runaway exploration. If directed search is ever added, it is an
  ordering change in `run_worklist`, not a change of domain.
- **Static analysis alone.** `src/analysis/ioctl_taint.rs` is cheap and useful,
  but it nominates candidate sinks; it cannot prove one reachable or emit an
  input that reaches it. The two compose: the static pass filters, the symbolic
  engine confirms and witnesses.
- **Veritesting / state merging.** Not built; it is the obvious next lever if
  loop-heavy drivers stay the binding constraint.

## Consequences

- (+) One value representation, one interpreter, and no seed-selection problem.
- (+) Every reported sink comes with a model, so a finding is checkable.
- (−) **Incomplete**, and now for a different reason than the original ADR gave:
  not "only near the seed" but "only within the state, block-visit, solve and
  time budgets". A path beyond `MAX_BLOCK_VISITS` re-entries is simply not
  explored, and the stop reason says so.
- (−) Depth-first order means the first witness found is not the shallowest.
- Pairs with [exec-0004](exec-0004-symbolic-memory.md): concretizing addresses
  and bounding exploration are two deliberate surrenders of soundness for the
  ability to reach the target at all.

Verified with `rg -n 'type Val' src/symbolic/symdomain.rs`,
`rg -n 'BinaryHeap|dist_to_sink' src/symbolic` (no hits),
`rg -n 'MAX_BLOCK_VISITS|DEFAULT_SOLVER_BUDGET|fn run_worklist' src/symbolic`.

→ [`architecture/execution-engine.md`](../architecture/execution-engine.md)
