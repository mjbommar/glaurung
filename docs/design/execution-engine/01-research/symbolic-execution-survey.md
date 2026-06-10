# Symbolic / Concolic Execution — Architecture Survey

Distilled from angr, KLEE, Triton, Manticore, S2E, BINSEC, SymCC/SymQEMU, QSYM,
SAGE, veritesting, and the Borzacchiello et al. memory-models survey. Framing
finding: **the engines that win on real binaries are not the most precise — they
are the ones that aggressively concretize, run concolically, cache, and merge.**
Every scalable design point is a controlled surrender of completeness.

## 1. State representation & cheap forking

A symbolic state = registers + memory + **path constraint** + solver handle
(angr models it as swappable *plugins*; KLEE as an OS-for-symbolic-processes).
Storage holds **expression trees**, not raw bytes.

- **Cheap forking is the whole ballgame.** KLEE: object-level **copy-on-write**
  with an immutable persistent heap → clone in constant time. angr: page-level
  COW. Object-level gives finer sharing; page-level matches how binaries touch
  memory.
- **State counts are brutal.** KLEE recorded **95,982 concurrent states** (max) /
  ~51k avg on coreutils within minutes; the bound is RAM. **Design for spilling,
  capping, and merging from day one.**

→ Our choice: persistent maps for registers (`im`/`rpds`-style structural
sharing) + page-COW memory. See [`../02-architecture/machine-state.md`](../02-architecture/machine-state.md).

## 2. Symbolic memory models (the hard part)

Taxonomy (Borzacchiello survey): {Bitvector vs Array theory} × {flat vs
segmented} layout. A write through a symbolic pointer can touch *any* byte — up to
2⁴⁸ on x86-64. Four real strategies:

| Strategy | Who | Tradeoff |
|---|---|---|
| Full SMT array theory (read-over-write) | BINSEC, KLEE object-arrays | Precise/sound; queries get complex; hard to merge across parallel states |
| Segmented arrays + fork-per-object | KLEE | Solver ignores unreferenced arrays (fast); forks **n+1** states per symbolic access — explodes on big address spaces |
| **Concretize with threshold** | **angr/Mayhem ("partial model")** | **The binary-analysis default.** Writes through symbolic addrs → concretize to one value; reads → if range ≤ **1024 bytes** build a bounded ITE, else concretize. Incomplete (silently drops some buggy states) but the only thing that scales and merges cleanly |
| ITE trees / index-based / MemSight | pure-BV engines, MemSight | Lengthy for big objects; MemSight maps addr-expr→value with paged interval tree + COW (65,536-state KLEE case → 30 min) |

**Practitioner default for binaries: concretize-with-threshold.** angr exposes
named strategies (`any`/`max`/`range`/`nonzero`/`single`). Security trick:
concretize a symbolic *write* to its **max** address to maximize overflow-trigger
probability — directly useful for sink-finding. → ADR-0004.

## 3. Path-explosion mitigation

- **Veritesting (MergePoint)** — alternate Dynamic SE with Static SE: summarize a
  *bounded* call-free region into one disjunctive (ITE) formula instead of
  forking; drop back to DSE at transition points (syscalls, indirect jumps,
  unresolvable memory). ~2× bugs, orders of magnitude more paths, ~$0.28/bug.
- **State merging** wins when many paths reconverge over branchy-but-call-free
  code; loses when merged formulas pile disjunctions the solver chokes on, or
  memory layouts can't reconcile.
- **Function summaries / SimProcedures** — replace a function with a model that
  minimizes forks.
- **Under-constrained SE (UC-KLEE)** — check a *single function* from
  unconstrained inputs with lazy initialization + k-bounding. **Highly relevant:
  symbolically check one IOCTL handler without booting Windows.**
- **Loop bounding / length limits / constraint subsumption (SAGE).**

## 4. Concolic vs pure symbolic

Concolic = run on a real concrete input, carry symbolic expressions alongside,
**fork/query only at input-dependent branches**. Why it's more tractable on real
binaries: there's always a concrete fallback — symbolic side too hard (symbolic
syscall, unmodeled instruction, huge symbolic pointer) → use the concrete value
and keep going. No "environment problem" stall. The cost is completeness (you
explore the neighborhood of the concrete trace) — exactly right for *bug-finding*.

- **SAGE** — generational search: negate branches one at a time along the trace,
  solve for new inputs.
- **Triton** — concrete+symbolic in lockstep; uses **over-approximate taint to gate
  whether a query is even worth asking** (untainted data needs no symbolic
  reasoning).
- **SymCC/SymQEMU** — compile symbolic handling *into* the target (or QEMU TCG)
  rather than interpreting → up to ~12× over KLEE, ~10× over QSYM. (Future
  optimization for us; not v1.)
- **QSYM** — DBT concolic + **optimistic solving** (solve a relaxed subset when the
  full constraint is UNSAT/slow), pruning via a companion fuzzer.

→ **Concolic is our default mode.** ADR-0006.

## 5. Solver interaction (biggest single lever)

KLEE's canonical numbers: no-opt → **13,717 queries / 300 s**; all-opt → **699
queries / 20 s**; STP share 92% → 41%; queries to ~5% of original. In impact
order:

1. **Constraint independence / query splitting** — partition the path condition by
   which symbolic vars each constraint references; send the solver only the
   relevant subset. The multiplier that makes caching work.
2. **Counterexample cache** keyed on constraint sets with **subset/superset
   inference** (subset of UNSAT is UNSAT; superset of SAT is SAT; a subset's
   model often satisfies the superset).
3. Expression rewriting / simplification; constraint-set simplification;
   implied-value concretization.

"Almost always, the cost of constraint solving dominates." → caching/independence
live in **our** engine, not the solver. ADR-0005, Phase 4.

## 6. Search strategies

DFS (low memory, loops trap it), BFS (memory-hungry), random. KLEE round-robins
**Random Path Selection** (walk a fork-tree from the root, equal-prob branches →
favors states high in the tree, avoids fork-bombing loops) and
**Coverage-Optimized**. For us the key is **directed search toward a sink**:

- **Shortest-Distance SE (SDSE)** — order the worklist by ICFG distance to the
  target; always expand the closest state. (Our IOCTL sink-finding.)
- **Call-Chain-Backward SE / Mix-CCBSE** — search backward from the target.
- angr's `Explorer`: `find=<sink>` / `avoid=<addrs>` stashes.

→ Phase 5: a sink-distance-ordered priority queue + random-path tie-break.

## 7. Engine structure

Central loop: select a state, execute one unit, distribute successors into
stashes (`active`/`deadended`/`found`/`avoided`/`unconstrained`). Conditional
branch: if provably true/false, update PC; else clone + fork. Dangerous ops
(div, deref) implicitly branch on the error condition. **SimProcedures** hook
functions to minimize forks. **SimOS** owns syscall dispatch (per-ABI number
maps); a `posix` plugin models argv/env/fds. Manticore decouples the core engine
from the execution environment — the model we want for "Linux *and* Windows-kernel
ABIs later".

## 8. Determinism

KLEE depends on it for replay. Levers: **ordered worklist** (never hash-set
iteration order), **fixed solver seed + single-thread or fixed scheduling**,
**deterministic allocation** (bump/segmented, fixed bases — "code that depends on
memory addresses won't replay" otherwise), **stable tie-breaking** on state id.
→ [`../02-architecture/determinism.md`](../02-architecture/determinism.md).

## Recommended architecture for our use case (driver/malware sink-finder)

**Directed concolic, not pure symbolic.** Drive forward along a concrete seed
(synthesized IRP/IOCTL buffer); symbolize only attacker-controlled input (buffer +
length); fork only at input-dependent branches; veritest call-free regions.

```
State { id, regs: CowMap, mem: PagedCowMem, pc, constraints (independence-partitioned),
        solver_handle, taint, dist_to_sink }
```

- **Memory:** BV + flat + concretize-with-threshold (1024 B); writes → concretize
  to max when hunting overflows.
- **Solver:** incremental per-state + independence partitioning + counterexample
  cache (subset/superset); gate queries behind taint; optimistic solving fallback.
- **Search:** priority queue on `(dist_to_sink, state_id)`; random-path tie-break.
- **Hash-cons (intern) the symbolic `Expr`** so equal terms share nodes and
  caching/rewriting is cheap.

## Sources

- [KLEE (OSDI'08)](https://llvm.org/pubs/2008-12-OSDI-KLEE.pdf) — COW, segmented arrays, solver-opt table, search, 95,982 states.
- [Memory Models in Symbolic Execution (STVR'19)](http://www.diag.uniroma1.it/delia/papers/svtr19.pdf) — flat/segmented×BV/ABV, 1024-byte threshold, MemSight.
- [angr states/plugins](https://docs.angr.io/en/latest/core-concepts/states.html), [concretization strategies](https://docs.angr.io/en/latest/advanced-topics/concretization_strategies.html), [simulation managers](https://docs.angr.io/en/latest/core-concepts/pathgroups.html), [SimProcedures](https://docs.angr.io/extending-angr/simprocedures), [environment/SimOS](https://docs.angr.io/en/latest/extending-angr/environment.html)
- [Veritesting (CACM'16)](https://cacm.acm.org/magazines/2016/6/202649-enhancing-symbolic-execution-with-veritesting/fulltext), [SAGE (CACM'12)](https://cacm.acm.org/magazines/2012/3/146240-sage-whitebox-fuzzing-for-security-testing/fulltext)
- [Triton under the hood](https://blog.quarkslab.com/triton-under-the-hood.html), [SymQEMU (NDSS'21)](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_2B-2_24118_paper.pdf), [SymCC](https://www.s3.eurecom.fr/tools/symbolic_execution/symcc.html), [QSYM (USENIX'18)](https://taesoo.kim/pubs/2018/yun:qsym.pdf)
- [Directed SE (SAS'11)](https://www.cs.umd.edu/~mwh/papers/dse-sas11.pdf), [UC-KLEE (USENIX'15)](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ramos.pdf), [Manticore (ASE'19)](https://arxiv.org/pdf/1907.03890)
