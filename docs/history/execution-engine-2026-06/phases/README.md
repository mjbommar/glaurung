# Implementation Phases

> **Kind:** record · **Date:** 2026-06-10

Top-down, dependency-ordered. Each phase file lists **tasks**, **deliverables**,
**tests**, and **exit criteria**. Every phase ships something testable; no phase
depends on a later one.

## Phase map & dependencies

```
Phase 0 ── IR hardening ─────────────┐ (FOUNDATION — sequential, blocks everything)
                                      ▼
Phase 1 ── Concrete emulator x86-64 ──┬──────────────┐ (KEYSTONE: Domain trait + step())
                                      ▼              ▼
Phase 2 ── Coverage + ARM64          Phase 3 ── Snapshots / hooks / OS layer
   (helpers, SIMD, arm64 parity)        (COW, Unicorn-style hooks, SimProcedures)
                                      └──────┬───────┘
                                             ▼
Phase 4 ── Concolic + SMT ──────────────────┐ (Solver trait, easy-smt pipe, Symbolic Domain)
                                             ▼
Phase 5 ── Symbolic exploration ─────────────┐ (forking, constraints, directed search)
                                             ▼
Phase 6 ── PyO3 + agent tools ───────────────┐ (Python surface, L1–L5 tools, KB writeback)
                                             ▼
Phase 7 ── Applications ─────────────────────┘ (string-decrypt, indirect-jump, IOCTL sink-finding)
```

- **0 → 1** strictly sequential; the bulk of conceptual risk.
- **2 and 3** can proceed in parallel once 1 lands.
- **4 gates 5.** **6 and 7** ride on whatever subset exists (6 can surface the
  concrete emulator before 4/5 are done).

## Phase index

| Phase | File | Feature gate | Net new modules |
|---|---|---|---|
| 0 | [`phase-0-ir-hardening.md`](phase-0-ir-hardening.md) | (none — in `src/ir`) | `ir/verify.rs` |
| 1 | [`phase-1-concrete-emulator.md`](phase-1-concrete-emulator.md) | `exec` | `exec/{domain,concrete,interp,state,memory,liftcache,budget}` + `exec/arch/x86_64` |
| 2 | [`phase-2-coverage-and-arm64.md`](phase-2-coverage-and-arm64.md) | `exec` | `exec/helpers/*`, `exec/arch/arm64` |
| 3 | [`phase-3-snapshots-hooks-os.md`](phase-3-snapshots-hooks-os.md) | `exec` | `exec/hooks`, `os/*` |
| 4 | [`phase-4-concolic-and-smt.md`](phase-4-concolic-and-smt.md) | `symbolic` | `symbolic/{expr,symdomain,solver,cache}` |
| 5 | [`phase-5-symbolic-exploration.md`](phase-5-symbolic-exploration.md) | `symbolic` | `symbolic/{symstate,symmem,explore}` |
| 6 | [`phase-6-pyo3-and-agent-tools.md`](phase-6-pyo3-and-agent-tools.md) | `python-ext` | `python_bindings/exec.rs`, `python/glaurung/llm` tools |
| 7 | [`phase-7-applications.md`](phase-7-applications.md) | varies | analyzers wiring engine → KB |

## Cross-phase invariants (hold at every step)

- **TDD, real fixtures.** No instruction-semantics work merges without a
  differential test on a real binary. → [`../04-testing/`](../testing).
- **Determinism.** Each entry point passes the run-twice byte-identical test. →
  [`../02-architecture/determinism.md`](../architecture/determinism.md).
- **Build hygiene.** `exec` is pure Rust (no new C deps). `symbolic` adds only the
  pipe (no compiled dep). Native solvers + Unicorn oracle are opt-in features. The
  default wheel always builds.
- **`ruff` + `ty` + `cargo test` green** before any phase is called done.

## Rough sizing (order-of-magnitude, not a schedule)

| Phase | Relative effort | Primary risk |
|---|---|---|
| 0 | M | breaking existing IR consumers |
| 1 | L | instruction-semantics correctness |
| 2 | L | SIMD/FP breadth |
| 3 | M | OS-model surface area |
| 4 | M | solver integration + caching correctness |
| 5 | L | state explosion |
| 6 | S–M | PyO3 hook/GIL ergonomics |
| 7 | M | real-sample robustness |
