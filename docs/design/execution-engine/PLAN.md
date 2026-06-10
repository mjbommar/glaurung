# PLAN — Execution Engine (canonical task checklist)

> The single ordered backlog for building Glaurung's native emulation + symbolic
> execution. This is the **what-to-do, in order**. For the **where-are-we** and
> the resume procedure, see [`STATUS.md`](STATUS.md). For the **why/how**, see the
> architecture specs in [`02-architecture/`](02-architecture/) linked per task.
>
> Convention: `[ ]` todo · `[~]` in progress · `[x]` done. Keep checkboxes in sync
> with `STATUS.md` (STATUS is the narrative; PLAN is the checklist).

## Critical path (one line)

`Phase 0 (IR hardening) → Phase 1 (Domain trait + concrete x64) → [Phase 2 ∥ Phase 3] → Phase 4 (concolic+SMT) → Phase 5 (exploration) → Phase 6 (PyO3/agent) → Phase 7 (apps)`

Phases 2 and 3 may run in parallel. Phase 6 can surface the concrete emulator
(after Phase 3) before 4/5 land. Phase 7 apps 7.1–7.3 need only Phases 1–3.

## Global definition of done (every phase)

- `cargo test` (with the phase's features) green; `uvx pytest python/tests/` green
  for any Python touched.
- `uvx ruff format` + `uvx ruff check` + `uvx ty check` clean on touched Python.
- Determinism test (run-twice byte-identical) passes for any new entry point.
- The phase's exit criteria (in its phase file) met; divergences filed as
  fixture-backed regression tests, pass-rates reported honestly.

---

## Phase 0 — IR hardening  *(no feature gate; spec: [executable-llir](02-architecture/executable-llir.md), [phase file](03-phases/phase-0-ir-hardening.md))*

- [x] 0.1 `Width(u16)` newtype + consts/accessors; width via **`VReg`** (`phys_reg_width` table + `VReg::width()`), not by reshaping `Value` — see Q1 in STATUS. `Value::Const` stays `i64`.
- [x] 0.2 *(folded into 0.1 by the Q1 decision)* operation width is **derived from the `dst` VReg** (and `MemOp.size`), not stored on `Bin`/`Un`/`Cmp`; explicit widths live on the new width-change ops. Wrap-at-width is the executor's job (Phase 1).
- [x] 0.3 Add ops: `ZExt`/`SExt`/`Trunc`/`Extract`/`Concat`/`Ite` (additive; consumers + Display wired)
- [x] 0.4 `MemOp.endian` (`Endian` enum, default Little; `MemOp::plain` + all literals updated)
- [x] 0.5 `Op::Intrinsic{name,ins,outs,reads_mem,writes_mem}` added; `Unknown` retained as deprecated (lifter still emits it until 0.7)
- [x] 0.6 `src/ir/verify.rs` — width-change invariants, undefined-temp, mem-size, residual-`Unknown` tracking; **passes on real lifted `samples/` functions** (no fatal errors)
- [x] 0.7 **No residual `Unknown` after lift** — `lift_function_from_bytes` now runs a lowering pass (`lower_unknowns` → `Op::opaque` conservative `Intrinsic`); verified zero residual `Unknown` on real x86-64 + ARM64 `samples/`. Decompiler output preserved (ast `Intrinsic` arm mirrors old `Unknown`, incl. `semantic_comment_for_unknown`). PyO3 dict conversion handles all new ops. *Deferred to Phase 1 (need is concrete there):* (a) explicit 32-bit zero-extend → better done in the `RegFile` write logic via `RegLayout` than as lifter `ZExt` ops; (b) flags via `INT_CARRY`-style predicate ops → precision for symbolic, current condition-code `Cmp` model is adequate until Phase 4.
- [ ] 0.8 *(deferred to Phase 1)* extend `src/ir/dce.rs` for flag producer/consumer materialization — an optimization; existing dead-flag DCE suffices for now.
- [x] 0.9 consumers (`use_def`, `ast`, `ioctl_taint`, `python_bindings/ir`) handle the new ops soundly
- [x] **Exit (core):** verifier `verify_fatal` empty on corpus ✅; **no residual `Unknown` after lift** ✅; new types/ops tested ✅; full suite green ✅ (modulo 2 pre-existing WinAPI failures unrelated to this work); Python IR/decompile tests green ✅. *Carried into Phase 1:* 0.8 + the two 0.7 refinements above.

## Phase 1 — Concrete emulator (x86-64) — KEYSTONE  *(feature `exec`; spec: [value-domain-trait](02-architecture/value-domain-trait.md), [phase file](03-phases/phase-1-concrete-emulator.md))*

- [x] 1.1 `exec/domain.rs` — `Domain` trait (bit-vector primitives + `as_branch`/`as_u64`); `exec` Cargo feature added; module wired into `lib.rs`
- [x] 1.2 `exec/concrete.rs` — `Concrete: Domain` (masked `u128`, modular-at-width arithmetic, signed/unsigned cmp, zext/sext/trunc/extract/concat/ite); 14 unit tests incl. the end-to-end prototype sequence
- [~] 1.3 `exec/state.rs` — `RegFile<D>` (generic over `Domain`) with **correct x86-64 sub-register semantics** done & tested (eax zeroes upper rax; ax/al preserve; ah=[8:16); r8d zeroes r8); flags/temps stored separately. *Remaining:* `exec/arch/x86_64.rs` `CpuModel` (calling convention + syscall descriptor — needed for Phase 3 OS layer).
- [~] 1.4 `exec/memory.rs` — byte-addressed `Memory<D>` (load/store via domain `concat`/`extract`, both endiannesses, unmapped→0); 5 tests. *Remaining:* paged softmmu + perms + dirty-page COW (Phase 3).
- [~] 1.5 `exec/interp.rs` — the ONE `step()` + `run_block()` over `Domain`; `Flow::{Next,Jump,Branch,Call,Return,Halt}`; registers/arith/width-change/select/load/store/branch; 6 tests incl. prototype sequence, sub-register arithmetic, memory round-trip. *Remaining:* multi-block `run_function` (follow Jump/Branch via CFG + budget).
- [x] 1.5+ `run_function` — multi-block driver following `Jump`/`Branch`/fall-through with a budget; `Outcome::{Returned,Halted,BudgetExhausted,NoBlock,CalledOut}`. Tests: countdown loop (sums to 6), budget-bounded infinite loop, call/return, **a real lifted `samples/` function executed end-to-end**.
- [ ] 1.6 `exec/liftcache.rs` — lift-once block cache + successor caching *(deferred; the run bridge re-uses an already-lifted `LlirFunction`, so this is an optimization for repeated lifting)*
- [x] 1.7 `exec/budget.rs` — instruction budget → `Outcome::BudgetExhausted` (deterministic; loop/region fencing later)
- [~] 1.8 `exec/helpers.rs` — `HelperRegistry<D>` (fn-pointer dispatch from `Intrinsic`) + deterministic `rdtsc`/`rdtscp` (virtual TSC) and `cpuid` (fixed). *Remaining:* operand-carrying helpers (`bswap`/`rol`/`div`/SIMD) need the lifter to emit richer `Intrinsic`s (Phase 2).
- [x] 1.9 **Differential oracle vs Unicorn** — `src/exec/oracle.rs` (feature `dev-oracle`, links **system** libunicorn via pkg-config — `apt install pkg-config libunicorn-dev`; the earlier "vendored-QEMU won't compile" was a self-inflicted dead end, the system lib links fine and is never shipped). `diff_x86_64(code, init)` runs real bytes on our emulator and Unicorn and compares GPRs. **Immediately caught a real `movsx` sign-extension bug** (lifted as zero-extend) — now fixed. A 13-instruction inventory matches Unicorn (mov/lea/movzx/movsx/imul/inc/dec/neg/not/xchg/test+sete/shl-cl/add). Self-contained hand-verified corpus also retained. ([spec](04-testing/differential-oracle.md))
- [ ] 1.10 Determinism test (run-twice identical)
- [ ] **Exit:** ≥95% Unicorn match on x64 corpus + sample slices; 0 unsupported-intrinsic halts on corpus; determinism green

## Phase 2 — Coverage + ARM64  *(feature `exec`; ∥ Phase 3; [phase file](03-phases/phase-2-coverage-and-arm64.md))*

- [x] 2.2 **ARM64 register layout** in `exec/state.rs` (`RegArch::AArch64`): `x0..x30`/`w0..w30` (w zero-extends parent), `sp` 64-bit, `lr`=x30/`fp`=x29 aliases, `xzr`/`wzr` zero register; `Machine::new_with_arch`. Independent of x86-64 layout (resolves the `sp` name collision). 4 unit tests.
- [x] 2.2+ **ARM64 execution end-to-end** — runs a real lifted AArch64 `samples/` function via the arch-agnostic interpreter (graceful outcome + progress). The flag mapping is free (condition-code flags already shared with x86).
- [ ] 2.1 ARM64 IR hardening in `lift_arm64.rs` (per-op widths) — partially covered (it already emits `Intrinsic` via the Phase-0 lowering); explicit widths still derived, not stored.
- [ ] 2.3 ARM64 scalar helpers (`udiv`/`sdiv`, `madd`/`msub`, `rev`, `clz`) *(emitted as `Intrinsic`→halt until added)*
- [ ] 2.4 x86 SIMD helpers · 2.5 ARM64 NEON · 2.6 software FP · 2.7 atomics *(need richer lifter intrinsics; deferred)*
- [ ] 2.8 Differential corpus for ARM64/SIMD/FP (gated on the Unicorn oracle or a hand-verified corpus)
- [~] **Exit:** ARM64 concrete execution of real functions works ✅; SIMD/FP/atomics coverage + oracle-match deferred

## Phase 3 — Snapshots / hooks / OS layer  *(feature `exec`; ∥ Phase 2; [phase file](03-phases/phase-3-snapshots-hooks-os.md))*

- [~] 3.1 Snapshots — `Machine` is `Clone`, so snapshot/restore works today via clone (correct, O(state)). Dirty-page COW is a perf optimization (later).
- [ ] 3.2 `exec/hooks.rs` — Unicorn-style hook taxonomy *(deferred; callback/borrow design — apps can read state/memory post-run for now)*
- [ ] 3.3 SMC coherence *(deferred with the lift cache, 1.6)*
- [x] 3.4 `exec/simproc.rs` — **SimProcedure registry** (`SimProcRegistry<D>`, fn-pointer summaries by target VA). `step` replaces a modeled call with its summary and continues; unmodeled calls still surface as `CalledOut`. Verified: a function runs *through* a modeled call to `ret`. 3 tests.
- [ ] 3.5 `os/linux.rs` — libc subset + Linux syscalls over a deterministic allocator *(registers summaries via 3.4; not started)*
- [ ] 3.6 `os/windows.rs` — IRP seeding + `nt!`/`ntoskrnl` stubs *(uses 3.4; not started)*
- [ ] 3.7 Win64/SysV CC selection from binary OS
- [~] **Exit:** SimProcedure mechanism lets functions run through modeled calls ✅; full libc/Windows stub sets + hooks + dirty-page snapshots remain

## Phase 4 — Concolic + SMT  *(feature `symbolic`; gates Phase 5; [phase file](03-phases/phase-4-concolic-and-smt.md))*

- [x] 4.1 `symbolic/expr.rs` — hash-consed bit-vector `Expr` IR (interning, width tracking, SMT-LIB2 render, `collect_syms`); 4 tests
- [x] 4.2 `symbolic/symdomain.rs` — `Symbolic: Domain` building `Expr` terms; `as_branch` folds constants / forks on symbolic; **keystone test: the one interpreter drives it and emits a solver-ready constraint**
- [x] 4.3 `Solver` trait + `symbolic/solver/{mod,pipe,z3_backend}.rs` — **native `z3` crate is primary (in-process, links libz3)**; SMT-LIB2 **pipe is the fallback** (revised per ADR-0005, native-first). Both behind the trait.
- [x] 4.4 Expr → SMT-LIB2 lowering (`render_smtlib`) **and** Expr → z3 AST (`to_bv`); both tested
- [ ] 4.5 `symbolic/cache.rs` — independence partitioning + cex cache + taint gating *(not started)*
- [x] 4.6 Native backend `solver/z3_backend.rs` (feature `solver-z3`) — **done & verified solving in-process** (`x+1==0x100`→`x=0xff`; unsat detection). `bitwuzla` backend still optional/future.
- [~] 4.7 Concolic driver — symbolic-execute-then-solve demonstrated end-to-end (`symbolic_execute_then_solve_for_input`); the generational negate-one-branch loop is Phase 5.
- [x] **Exit (core):** one `step()` drives both domains ✅; solver solves fixtures via **native z3** ✅ (and pipe ✅); caching (4.5) deferred to a later increment.

## Phase 5 — Symbolic exploration  *(feature `symbolic`; [phase file](03-phases/phase-5-symbolic-exploration.md))*

- [~] 5.1 state forking — `Machine<Symbolic>` is `Clone` (per-fork pool copy; shared COW pool is a future optimization). A lightweight `State` (machine + pc + path constraints) lives in `explore.rs`; a dedicated `symstate.rs` with persistent maps is the optimization step.
- [ ] 5.2 `symbolic/symmem.rs` — concretize-with-threshold (1024 B) symbolic memory *(not started; symbolic load/store addresses currently halt via `as_u64`→None)*
- [x] 5.3 `symbolic/explore.rs` — DFS worklist; forks at symbolic `CondJump`; **prunes infeasible paths with the solver**; `find_input_reaching(lf, target, seed, max_states)`. Tests (native z3): finds `rdi=42` reaches the target block; unreachable → Unsat.
- [ ] 5.4 Directed search (`(dist_to_sink, state_id)` PQ; find/avoid; random-path tie-break) *(currently plain DFS)*
- [~] 5.5 Bounds — `max_states` cap (→ `Unknown`); spill-to-disk + loop bounds later
- [~] 5.6 Witness extraction — `Sat(model)` is the reaching witness; concrete-replay validation not yet wired
- [~] 5.7 Determinism — DFS LIFO + deterministic pool clone + single-threaded z3 are deterministic; formal run-twice test pending
- [ ] 5.8 (Optional) veritesting
- [ ] **Exit:** directed search reaches a target in a real IOCTL handler + emits replayable witness; no explosion; deterministic

## Phase 6 — PyO3 + agent tools  *(feature `python-ext`; [phase file](03-phases/phase-6-pyo3-and-agent-tools.md))*

- [~] 6.1 `src/python_bindings/exec.rs` — **`glaurung.engine.emulate_function(path, va, arch, max_steps)`** done (lifts + runs + returns outcome/steps/regs dict; x86-64 + arm64). `python-ext` now bundles the pure-Rust `exec` engine. 6 Python tests incl. determinism + error cases. *Remaining:* an `Emulator` class (incremental control) and `find_inputs` (needs the wheel built with `symbolic`).
- [ ] 6.2 Hook callbacks across the GIL *(deferred with the hook API)*
- [ ] 6.3 CLI: `glaurung emulate`, `glaurung find-inputs` *(not started)*
- [ ] 6.4 LLM agent tools (`emulate_stub`/`resolve_indirect`/`reach_block`) + L1–L5 routing + cost guards *(not started)*
- [ ] 6.5 KB writeback with `auto` provenance *(not started)*
- [~] **Exit:** Python drives the concrete emulator deterministically ✅ (multi-arch); symbolic `find_inputs` surface, `Emulator` class, CLI, agent tools, KB writeback remain

## Phase 7 — Applications  *(varies; [phase file](03-phases/phase-7-applications.md))*

- [ ] 7.1 Concrete string/payload decryption → KB *(needs 1–3)*
- [ ] 7.2 Indirect control-flow resolution → CFG/KB *(needs 1–3)*
- [ ] 7.3 Computed-constant / API-hash resolution *(needs 1–3)*
- [ ] 7.4 IOCTL sink-finding with witnesses *(needs 4–5)*
- [ ] 7.5 Opaque-predicate / dead-code detection *(needs 4)*
- [ ] 7.6 LLM-driven micro-experiments *(needs 6)*
- [ ] Scorecard: add strings-recovered + indirect-edges-resolved to `glaurung.bench`
- [ ] **Exit:** 7.1 + 7.2 end-to-end on real `samples/`, scorecard shows measurable gain; 7.4 on a vulnerable-driver fixture

---

## Decisions already locked (don't re-litigate without a new ADR)

- One `Domain`-generic interpreter ([ADR-0001](05-decisions/adr-0001-single-domain-core.md))
- Harden LLIR in place, not a new tier ([ADR-0002](05-decisions/adr-0002-executable-ir-vs-new-tier.md))
- Cached interpreter, not JIT, for v1 ([ADR-0003](05-decisions/adr-0003-interpreter-not-jit.md))
- Symbolic memory: concretize-with-threshold ([ADR-0004](05-decisions/adr-0004-memory-model-concretize-threshold.md))
- `Solver` trait, pipe first, native/solver all optional ([ADR-0005](05-decisions/adr-0005-smt-pipe-then-native-optional.md))
- Directed concolic default ([ADR-0006](05-decisions/adr-0006-concolic-default.md))
