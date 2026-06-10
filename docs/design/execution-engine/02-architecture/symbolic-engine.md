# Symbolic / Concolic Engine

Built on the concrete emulator by swapping in the `Symbolic` `Domain` and adding
state forking, path constraints, a solver layer, symbolic memory, and search.
**Default mode is directed concolic** — tractability over completeness (ADR-0006).

## Symbolic value & expression

```rust
pub enum Expr {                  // hash-consed (interned) → structural sharing + cheap caching
    Const { value: u128, width: Width },
    Sym   { id: SymId, width: Width },          // a free input variable
    BinOp { op: BinOp, a: ExprId, b: ExprId, width: Width },
    ZExt | SExt | Trunc | Extract | Concat | Ite | Cmp { … },
}
pub struct ExprPool { /* interner: HashMap<Expr, ExprId> + Vec<Expr> */ }
```

The `Symbolic` domain's `Val = ExprId`. For **concolic**, carry a concrete
shadow: `Val = (ExprId, u128)` (Triton model) so we always have a concrete value
to fall back on and to choose branch directions.

## Symbolic state

```rust
pub struct SymState {
    id: StateId,                       // stable, monotonic — determinism + tie-break
    regs: RegFile<Symbolic>,           // persistent/COW
    mem:  SymMemory,                   // concretize-with-threshold (below)
    pc:   u64,
    constraints: ConstraintSet,        // path condition, independence-partitioned
    solver: SolverHandle,              // incremental, seeded
    taint: TaintMask,                  // over-approx: gate solver queries (Triton)
    dist_to_sink: u32,                 // ICFG distance — search priority key
}
```

Forking is cheap via persistent `regs` + COW `mem` (KLEE object-COW / wtf
dirty-restore). On a `Flow::Fork` from the interpreter: clone the state, push
`cond` into one and `¬cond` into the other, `solver.check_assuming` each, discard
UNSAT.

## Symbolic memory — concretize-with-threshold (Mayhem/angr default)

Per [ADR-0004](../05-decisions/adr-0004-memory-model-concretize-threshold.md) and
the memory-models survey:

- **Concrete address** → direct paged access (the common case; off the solver
  entirely). Most of memory stays concrete in concolic mode.
- **Symbolic-address write** → **concretize to a single value** (default; use
  `max` when hunting overflows to maximize sink-trigger probability), record the
  binding constraint.
- **Symbolic-address read** → if the solver-derived address range ≤ **1024 bytes**,
  build a bounded `Ite` tree over the candidate bytes; else concretize.

This keeps formulas small, keeps state merging trivial (per-byte `Ite`), and
avoids KLEE-style `n+1` per-object forking on huge kernel address spaces. It is
**incomplete** (silently drops some reachable states) — an accepted trade for
reaching sinks on real drivers.

## Solver layer

```rust
pub trait Solver {
    fn fresh() -> Self;                                  // one per worker (no shared contexts)
    fn assert(&mut self, c: &Constraint);
    fn push(&mut self); fn pop(&mut self, n: u32);
    fn check_assuming(&mut self, lits: &[Lit]) -> SatResult;   // prefer assumptions over deep push/pop
    fn get_model(&mut self) -> Option<Model>;
}
```

- **Default backend:** `easy-smt` SMT-LIB2 **pipe**, defaulting to the Bitwuzla
  binary, Z3 fallback. Zero compiled deps → base wheel stays clean
  ([ADR-0005](../05-decisions/adr-0005-smt-pipe-then-native-optional.md)).
- **Optional native** backends behind features (`solver-z3`, `solver-bitwuzla`).
- **Caching is ours, not the solver's** (`symbolic/cache.rs`):
  - **Constraint independence partitioning** — split the path condition by shared
    symbols; query only the relevant subset.
  - **Counterexample cache** keyed on constraint sets with subset/superset
    inference (subset-of-UNSAT is UNSAT; superset-of-SAT is SAT; a subset's model
    often satisfies the superset).
  - **Taint gating** — never query the solver for a branch whose condition isn't
    input-tainted.
  - **Optimistic solving** (QSYM) — when the full path constraint is UNSAT/slow,
    solve a relaxed subset to still emit a candidate witness.

KLEE's data: independence + cex-caching cut queries to ~5% and ~halved solver
share of runtime — the single biggest lever, bigger than any search heuristic.

## Exploration & search

```rust
pub struct Explorer {
    worklist: BinaryHeap<(Priority, StateId, SymState)>,  // ordered → deterministic
    stashes: Stashes,   // active / deadended / found / avoided / unconstrained
    strategy: Strategy, // Directed{targets} | Dfs | RandomPath | Coverage
    budget: ExplorationBudget,  // max states, max depth, spill-to-disk threshold
}
```

- **Directed (default for sink-finding):** priority = `(dist_to_sink, state_id)`
  using ICFG shortest-distance (SDSE); `find = sink_addrs`, `avoid = cleanup/error
  addrs`. Random-path selection as anti-starvation tie-break (KLEE).
- **Veritesting** (later): summarize call-free regions into one disjunctive
  formula instead of forking; drop to DSE at syscalls/indirect jumps/unresolvable
  memory.
- **Bounds from day one:** max-states cap, depth/loop bounds (`LoopSeer`/
  `LengthLimiter` analogs), spill-to-disk — because real runs hit 50k+ states.

## Determinism

Ordered `BinaryHeap` keyed on `(priority, state_id)`; seeded single-threaded
solver with fixed tactic; deterministic segmented allocator with fixed bases (so
witnesses replay); stable tie-break on `state_id`. See
[`determinism.md`](determinism.md).

## Relationship to `ioctl_taint`

The static `ioctl_taint` pass (flat-lattice abstract interpretation over LLIR)
becomes the **fast pre-filter**: it cheaply finds *candidate* sinks and the
taint sources; the symbolic engine then *confirms* a sink is reachable and emits a
concrete witness. They share the IR, the taint-source taxonomy, and the CFG. The
abstract-interpretation `Domain` (an `Interval`/taint domain) could eventually
unify them under the same interpreter.

## References
- [`../01-research/symbolic-execution-survey.md`](../01-research/symbolic-execution-survey.md)
- [`../05-decisions/adr-0004-memory-model-concretize-threshold.md`](../05-decisions/adr-0004-memory-model-concretize-threshold.md), [`adr-0006-concolic-default.md`](../05-decisions/adr-0006-concolic-default.md)
