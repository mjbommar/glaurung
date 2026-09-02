# Docs audit — execution-engine, roundtrip, axeyum-integration, research, IOC_VALIDATOR_V2, benchmarks

> **Kind:** record · **Date:** 2026-09-02

Repo: `/home/mjbommar/projects/personal/glaurung` @ `b8884687` (master, 2026-09-02).
Scope: 55 `.md` files + 894 non-md data/script files. All verification against code, `Cargo.toml`, `src/lib.rs`, `build.rs`, `.github/workflows/`, `scripts/`, and `git log`. Read-only; nothing in the repo was modified.

---

## Executive summary

1. **`docs/design/execution-engine/` is a June-2026 design tree that was overtaken by its own implementation on the day it was committed and never caught up.** `README.md` says "Status: design / planning (2026-06). **No code yet**" — it was committed in `47e1bee8`, the *same commit that created `src/exec/`*. `STATUS.md` says, four paragraphs below a table claiming Phases 0–6 are done, "**No Rust/Python implementation code has been written yet. `src/exec/`, `src/os/`, `src/symbolic/`… do not exist.**" Both are false. Reality: `src/exec/` = 3,591 LOC, `src/symbolic/` = 21,459 LOC across 26 files.
2. **The design tree's last real update was 2026-06-11; 100 commits have landed in `src/symbolic/` since.** It has no mention of the axeyum backend (July, ~5,100 LOC), the Bitwuzla cell (July, 1,355 LOC), `ordered_trace`/`ordered_replay` (3,066 LOC), `constraint_cache` (1,089 LOC), or the 2026-08-17 fix that made three solver backends compile again.
3. **Feature ground truth has drifted from every doc that states it.** Actual: `default = ["triage-core"]`; `python-ext = [pyo3, pyo3/extension-module, **exec**]`; `symbolic = ["exec"]`; plus `dev-oracle`, `solver-z3`, `solver-axeyum`, `solver-axeyum-text`, `solver-bitwuzla`. `02-architecture/README.md` lists a five-feature block that is wrong in three places and omits four features.
4. **The proposed module layout in `02-architecture/README.md` is ~50% fiction.** `src/os/`, `exec/arch/`, `exec/helpers/`, `exec/hooks.rs`, `exec/liftcache.rs`, `symbolic/symstate.rs`, `symbolic/symmem.rs`, `symbolic/cache.rs` were never created; nine modules that do exist are undocumented.
5. **ADR-0006 ("directed concolic is the default") was never implemented.** `src/symbolic/symdomain.rs:93` is `type Val = ExprId` — pure symbolic with constant folding, no concrete shadow, no `(ExprId, u128)`, no taint gating, no directed search (`explore.rs` has no `BinaryHeap`/`dist_to_sink`). The one ADR that sets the engine's operating mode describes something that does not exist.
6. **`docs/axeyum-integration/` is the opposite case: honest, well-classified, and the *real* decision record** (31 ADRs, 1,160 lines) — but its `README.md` still says "**Current source gate: failing**" over an `E0004` that was fixed on 2026-08-17 in `114a5c4c`.
7. **That stale status is pinned in place by a test.** `python/tests/test_verify_tutorial.py:402` asserts `"Current source gate: failing" in axeyum_index[:2200]`. A passing test suite currently *requires* the docs to claim a build is broken that has been green for two weeks.
8. **`docs/axeyum-integration/` is not only docs.** `src/symbolic/ordered_trace.rs` shells out to `docs/axeyum-integration/capture/validate_ordered_trace.py` at four test sites. 842 `.smt2` files (3.9 MB) and 9 Python tools with 4 self-tests live under `docs/`. Deleting or moving this tree breaks Rust tests.
9. **`docs/design/roundtrip/gcc-O0.md` is a stale generated dump whose headline number is wrong by 2.5×.** It reports "9 of 25 executed functions behave correctly (36%)"; `docs/design/decbench-submission-readiness.md:653` reports "**24 of 26 … (92%)**" at a later commit, and explicitly says "the declaration alone took it from 36% to 84%". A reader landing on the `roundtrip/` directory gets the pre-fix number.
10. **`docs/benchmarks/` is a 2026-04-25 generated scorecard that nothing reads.** `baseline.json` records `glaurung_commit eac96ac2` (4 months old); no code, script, CI job, or test references `docs/benchmarks/`. `glaurung.bench` writes wherever `--output` says and compares against nothing.
11. **`docs/IOC_VALIDATOR_V2.md` is fully accurate and current** — every module, function, and test file it names exists and matches. It is the single best file in this scope. (Its V1 sibling `ioc_validator.py` has no doc at all.)
12. **`docs/research/` holds one file, a December-2024 PyO3 plan, correctly banner-labelled historical.** A one-file directory is not a directory.
13. **Real knowledge that exists ONLY in docs and would be lost:** the four `01-research/` literature syntheses (VEX/P-code/BIL/BNIL/ESIL totality+width lessons; KLEE's 13,717→699 query numbers; the concretize-with-1024-byte-threshold taxonomy; the QF_BV solver landscape) and the six ADRs' *rejected alternatives*. None of this is recoverable from code.
14. **Two colliding ADR namespaces.** `Cargo.toml:99` says axeyum is "Intended default once validated (**ADR-002**)" — that is `axeyum-integration/07-decision-log.md` ADR-002, not `execution-engine/05-decisions/adr-0002` (harden LLIR in place). Anyone following the Cargo comment lands in the wrong file.
15. Recommended shape: **archive the execution-engine phase/status/plan layer wholesale**, keep and re-verify `01-research/` + `05-decisions/`, write one new `docs/design/execution-engine/README.md` from source, keep `axeyum-integration/` almost intact but move `capture/` out of `docs/` into `tools/` or `tests/`, delete `docs/design/roundtrip/` and `docs/benchmarks/`, and fold `docs/research/` away.

---

## Per-file table

### `docs/design/execution-engine/` — top level

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `docs/design/execution-engine/README.md` | 112 | 2026-06-10 `47e1bee8` | index | **stale** | Banner: "Status: **design / planning** (2026-06). **No code yet.**" — but this file's own commit `47e1bee8` is titled "exec: native execution engine — concrete emulator + symbolic execution (Phases 0–6 cores)" and created `src/exec/`. Phase map still shows Phase 4 as "easy-smt pipe"; `easy-smt` is not in `Cargo.toml` or `Cargo.lock`, and `src/symbolic/solver/pipe.rs` is a hand-rolled `std::process::Command`. | **rewrite** — a from-source orientation page for `src/exec` + `src/symbolic`; drop the "no code yet" framing and the phase map. |
| `docs/design/execution-engine/STATUS.md` | 404 | 2026-06-11 `a25835d7` | record | **stale** (self-contradicting) | Two mutually exclusive claims in one file: the "At a glance" table says "🟢 Usable multi-arch engine — cores of Phases 0,1,2,3,4,5,6", and §"What exists today" says "**No Rust/Python implementation code has been written yet. `src/exec/`, `src/os/`, `src/symbolic/`, and `src/python_bindings/exec.rs` do not exist.**" All four exist (`src/python_bindings/exec.rs` registers `glaurung.engine`). Test counts "52 exec + 18 symbolic Rust tests" vs actual 76 `#[test]` in `src/exec/` and 195 in `src/symbolic/`. "Last updated 2026-06-10"; worklog ends 2026-06-11; 100 commits have touched `src/symbolic/` since. Says `bitwuzla` backend is "carried forward / optional" — `src/symbolic/solver/bitwuzla_backend.rs` is 1,355 LOC, landed 2026-07-19 (`2961d7c1`). | **archive** — genuinely valuable as a dated record of the June IOCTLance push (the worklog is the only account of the loop-bound / obfuscation work), but it must stop being the "read this first" page. |
| `docs/design/execution-engine/PLAN.md` | 130 | 2026-08-05 `fcca960b` | roadmap/plan | **mostly-current** (checkbox level) | Best-maintained file in the tree; most `[x]`/`[~]`/`[ ]` marks still hold. Verified still-open: no `exec/liftcache.rs` (1.6), no `exec/hooks.rs` (3.2), no `src/exec/arch/` or `src/exec/os/` (1.3, 3.5, 3.6), no `emulate`/`find-inputs` in `python/glaurung/cli/main.py` (6.3). Verified **wrong**: 4.5 "`symbolic/cache.rs` … *not started*" — `src/symbolic/solver/constraint_cache.rs` is 1,089 LOC; 4.6 "`bitwuzla` backend still optional/future" — it exists. Blind to everything after 2026-06: no axeyum, no `ordered_trace`, no `native_trace`, no `concretization.rs`. | **rewrite** as a short "what's actually left" list, or **archive** with PLAN/STATUS together. Do not carry the checkboxes forward unaudited. |
| `docs/design/execution-engine/00-motivation-and-goals.md` | 99 | 2026-06-10 `47e1bee8` | design-proposal | **mostly-current** | The goals/non-goals (G1–G7, N1–N6) still describe the built system accurately, *except* G6 ("base wheel builds with no SMT/C++ deps") which is now over-satisfied and under-described — `python-ext` pulls `exec` but not `symbolic`, so the wheel has an emulator and no solver at all. Opening claim "There is **no emulation and no symbolic execution** today" is false. Success-criteria table is a per-phase gate table that nothing enforces. | **revise** — strip the "today there is none" framing and the phase table; keep G1–G7/N1–N6 as the charter. |

### `docs/design/execution-engine/01-research/`

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `01-research/README.md` | 27 | 2026-06-10 `47e1bee8` | index | **mostly-current** | Index over the four syntheses; its one-line takeaway for `smt-backends.md` ("default Bitwuzla, Z3 fallback") is contradicted by that file's own 2026-06-10 revision note (native z3 first) and by `src/symbolic/solver/mod.rs` (`solve()` prefers z3, then axeyum, then pipe). | **revise** — fix the smt-backends takeaway line. |
| `01-research/ir-design-lessons.md` | 149 | 2026-06-10 `47e1bee8` | reference | **current** | External-literature synthesis (VEX dirty calls, P-code `CALLOTHER`, BIL typed `Unknown`, BNIL intrinsics, ESIL, Miasm, Triton). Not verifiable against our code and does not need to be. Its P0-a recommendation ("typed `Const{value,width}`") was *rejected* in implementation (`src/ir/types.rs:150` — `Value::Const(i64)` survives; see PLAN Q1), which is worth a footnote. Sources are live URLs. | **keep** — highest-value file in the tree; add one line noting which recommendations were adopted vs rejected. |
| `01-research/symbolic-execution-survey.md` | 159 | 2026-06-10 `47e1bee8` | reference | **current** | angr/KLEE/Triton/QSYM/SymCC/veritesting/memory-model synthesis with the concrete numbers (KLEE 95,982 concurrent states; 13,717 queries/300 s → 699/20 s; the 1024-byte concretization threshold; SDSE/CCBSE). Timeless; no code claims to check. | **keep**. |
| `01-research/emulator-engineering.md` | 152 | 2026-06-10 `47e1bee8` | reference | **current** | QEMU TCG / Unicorn / bochscpu / wtf / Lucid / snapchange synthesis. §8's differential-oracle recommendation is the one part that *did* ship (`src/exec/oracle.rs`, `dev-oracle` feature, links system libunicorn via `unicorn-engine = "2.1.5"`). | **keep**. |
| `01-research/smt-backends.md` | 109 | 2026-06-10 `47e1bee8` | reference | **stale** in its specifics | Crate cheat-sheet is wrong on every line that matters now: says `z3` **0.20.0**, `Cargo.toml:39` pins `z3 = "0.12"`; recommends `bitwuzla-sys` 0.8.0, but `src/symbolic/solver/bitwuzla_backend.rs` binds the **Bitwuzla 0.9.1 C API directly** with a `BITWUZLA_LIB_DIR` gate in `build.rs` and no `bitwuzla-sys` dependency; recommends `easy-smt` 0.3.2, which is absent from `Cargo.lock`; says `default = []`, actual is `default = ["triage-core"]`. Has **no mention of axeyum**, the pure-Rust backend the project actually built and pinned (`Cargo.toml:43-44`, git rev `c38a9515`). Its own §"TL;DR" already carries a 2026-06-10 correction reversing its main recommendation. | **rewrite** — the *survey framing* (QF_ABV, pipe-vs-FFI trade table, incrementality/caching, thread-safety) is still the right content; every version number and the recommendation must be redone from `Cargo.toml`, and axeyum added. |

### `docs/design/execution-engine/02-architecture/`

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `02-architecture/README.md` | 106 | 2026-06-10 `47e1bee8` | architecture | **stale** | Two concrete blocks are wrong. (a) *Module layout*: proposes `src/os/{mod,simproc,linux,windows}.rs` — never created (SimProcs are `src/exec/simproc.rs`); `exec/{hooks,liftcache}.rs`, `exec/helpers/`, `exec/arch/` — none exist (`helpers.rs` is a flat file; there is no `arch/`); `symbolic/{symstate,symmem,cache}.rs` — none exist; `solver/{z3,bitwuzla}.rs` — actual names are `z3_backend.rs`/`bitwuzla_backend.rs`. Undocumented modules that DO exist: `exec/oracle.rs`, `exec/simproc.rs`, `symbolic/{concretization,ioctl,native_trace,ordered_replay,ordered_trace}.rs`, `symbolic/solver/{constraint_cache,axeyum_backend}`. (b) *Cargo features block*: gives 5 features; actual is 9. `dev-oracle` shown as `["dep:unicorn-engine"]`, actual `["exec", "dep:unicorn-engine"]`; `solver-bitwuzla` shown as `["symbolic","dep:bitwuzla-sys"]`, actual `["symbolic"]` with a `build.rs` link; missing `triage-*`, `solver-axeyum`, `solver-axeyum-text`. Claim "`symbolic` adds the pipe solver (still no compiled dep; needs a solver *binary* at runtime)" is now half-wrong — `solver-axeyum` gives an in-process pure-Rust solver. | **rewrite** — regenerate the tree and the feature block from `src/` and `Cargo.toml`. |
| `02-architecture/executable-llir.md` | 133 | 2026-08-07 `03e63eeb` | architecture | **superseded** | Its "Target shape" strawman was explicitly overruled during implementation. Doc proposes `Value::Reg(VReg, Width)` and `Const { value: u128, width }`; `src/ir/types.rs:146-154` still has `Reg(VReg)` / `Const(i64)` / `Addr(u64)`, because PLAN Q1 (resolved 2026-06-10) decided width lives on `VReg` and is derived from `dst`, not stored on `Bin`/`Un`/`Cmp`. So the file's central code block describes a design that was considered and rejected. What *did* ship and is not described here: `Op::Undef` (poison for architecturally-undefined values), the `lower_unknowns` pass, and `src/ir/verify.rs` (12,201 bytes — the one deliverable the doc predicted correctly). `Op::Unknown` still exists at `types.rs:503` as deprecated, matching the migration plan. | **rewrite** — replace the strawman with what `src/ir/types.rs` actually became, and record Q1's rejection as the interesting part. |
| `02-architecture/value-domain-trait.md` | 133 | 2026-06-10 `47e1bee8` | architecture | **mostly-current** | The keystone idea shipped, and `src/exec/domain.rs` even cites this file. Signature drift: doc's trait has `type Mem`, `fn load`, `fn store`, `fn concretize_addr`; the real trait has none of those and instead has `as_u64` and a 4-arg `concat(hi, lo, hi_w, lo_w)`. Doc's "three implementations" table promises `Concrete` `Val=(u128,Width)`; real `Concrete` masks a `u128`. Doc's concolic claim (`Val = (ExprId, u128)`) is not implemented — `symdomain.rs:93` is `type Val = ExprId`. | **revise** — resync the trait listing with `src/exec/domain.rs`; delete or re-scope the concolic paragraph (see ADR-0006). |
| `02-architecture/machine-state.md` | 123 | 2026-06-10 `47e1bee8` | architecture | **stale** | Specifies a flat byte-offset `RegFile { cells, layout: &'static RegLayout }`, a `Memory<D>` with `perms`/`dirty`/`baseline`/`code_pages`, a `HookKind`/`Hook` API, and a `LiftCache`. `src/exec/state.rs` (20,849 B) uses named arch register layouts (`RegArch::AArch64`, `Machine::new_with_arch`), not a `&'static RegLayout` descriptor. `src/exec/memory.rs` (8,519 B) has no perms, no dirty-page COW, no `code_pages`. `exec/hooks.rs` and `exec/liftcache.rs` do not exist; snapshots are `Machine: Clone`. Roughly half this file is unbuilt design. | **archive** as the aspirational spec; extract the snapshot/hook sections into a "not built" backlog note. |
| `02-architecture/arch-abstraction.md` | 91 | 2026-06-10 `47e1bee8` | architecture | **stale** | Specifies `trait CpuModel` with `reg_layout`/`default_cc`/`syscall`, implemented in `src/exec/arch/x86_64.rs` and `src/exec/arch/arm64.rs`. **Neither file nor the `arch/` directory exists**; there is no `CpuModel` trait in `src/exec/`. Its "What exists today" section (the `Architecture` enum, `core::register::Register`, `lift_function::supports_arch`) is still accurate. | **archive** — this is unbuilt design, not documentation of the system. |
| `02-architecture/helpers-and-intrinsics.md` | 87 | 2026-06-10 `47e1bee8` | architecture | **mostly-current** | `Op::Intrinsic` shipped (`src/ir/types.rs:479`, with the doc's exact footprint fields), and `src/exec/helpers.rs` (19,562 B) implements the registry. The per-domain behaviour table and the "sound fallback" rules (concrete halts on `UnsupportedIntrinsic`; symbolic havocs declared outs) are the load-bearing semantics and are worth keeping. Coverage roadmap is optimistic — PLAN 2.3–2.7 (ARM64 scalar, SIMD, FP, atomics) are all still `[ ]`. | **revise** — keep the semantics, mark the coverage roadmap as unfinished. |
| `02-architecture/os-abi-layer.md` | 82 | 2026-06-10 `47e1bee8` | architecture | **stale** | Specifies `OsLayer<D>` with `summaries`/`syscalls` maps in `src/os/`. What shipped is `src/exec/simproc.rs` (4,547 B, `SimProcRegistry<D>` keyed by target VA) — a much thinner mechanism, no sentinel-address/unmapped-fetch dispatch, no libc set, no syscall table. PLAN 3.5/3.6 confirm "not started". The Windows/IRP half was superseded by `src/symbolic/ioctl.rs` (1,666 LOC), which the doc predates and does not mention. | **archive**; fold the surviving Windows-IRP paragraph into whatever documents `src/symbolic/ioctl.rs`. |
| `02-architecture/symbolic-engine.md` | 129 | 2026-06-10 `47e1bee8` | architecture | **stale** | `Expr` shape matches `src/symbolic/expr.rs` closely (good). Everything else drifted: `SymState { taint, dist_to_sink, solver: SolverHandle }` does not exist; the `Solver` trait shown (`push`/`pop`/`check_assuming`/`get_model`/`fresh`) is not the shipped one (`fn check(&mut self, pool, asserts) -> SolveResult`, one method — plus a separate `IncrementalSolver` at `mod.rs:93` the doc never mentions); "Default backend: `easy-smt` SMT-LIB2 pipe, defaulting to the Bitwuzla binary" contradicts `solve()`'s z3 > axeyum > pipe cascade; `Explorer` with a `BinaryHeap` and `Strategy` does not exist (`explore.rs` is a DFS worklist, no `BinaryHeap`, no `dist_to_sink`). `symbolic/cache.rs` is `solver/constraint_cache.rs`. | **rewrite** from `src/symbolic/` — this is the file most worth having and least accurate. |
| `02-architecture/determinism.md` | 61 | 2026-06-10 `47e1bee8` | architecture | **mostly-current** | The rules are house policy and remain right. Rule 6 ("Budgets are instruction counts, **not** timeouts, for the deterministic core") is contradicted by shipped code: `STATUS.md`'s own worklog describes a per-function **wall-clock deadline checked per instruction** and a 250 ms z3 per-solve timeout, and `SolveUnknownReason`/`check_timeout_ms` exist in `src/symbolic/solver/`. Rule 3's `BinaryHeap` claim describes an explorer that was never built. | **revise** — reconcile rule 6 with the timeout mechanisms that actually ship; keep the rest. |

### `docs/design/execution-engine/03-phases/`

All eight phase files plus the index describe a plan whose "cores" landed in one commit on 2026-06-10 and whose remainder is mostly unbuilt. They are uniformly **historical** — accurate as a record of intent, misleading as a status source, and duplicative of `PLAN.md` (which carries the same task IDs with checkboxes).

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `03-phases/README.md` | 67 | 2026-06-10 `47e1bee8` | roadmap/plan | **stale** | "Net new modules" column names `exec/liftcache`, `exec/arch/x86_64`, `exec/helpers/*`, `exec/arch/arm64`, `exec/hooks`, `os/*`, `symbolic/{symstate,symmem,cache}` — **none of these exist**. Only `ir/verify.rs`, `exec/{domain,concrete,interp,state,memory,budget}`, `symbolic/{expr,symdomain,solver}`, `python_bindings/exec.rs` shipped. | **archive** with the rest of `03-phases/`. |
| `03-phases/phase-0-ir-hardening.md` | 63 | 2026-08-05 `fcca960b` | roadmap/plan | **historical** | Task 0.1 ("change `Value::Const(i64)` → `Const{value,width}`") was rejected in implementation; `types.rs:150` still `Const(i64)`. 0.6 (`src/ir/verify.rs`) shipped. 0.8 (flag DCE) still open per PLAN. Exit criterion "every lifted op carries an explicit width" was not met as written — width is derived from `dst`/`VReg`. | **archive**. |
| `03-phases/phase-1-concrete-emulator.md` | 92 | 2026-06-10 `47e1bee8` | roadmap/plan | **historical** | Tasks 1.3/1.6/1.8 reference `exec/arch/x86_64.rs`, `exec/liftcache.rs`, `exec/helpers/x86.rs` — none exist. Exit criterion "≥95% Unicorn match" was never reported; STATUS's worklog reports "26/26 match" on a hand-picked inventory, which is a different measurement. Contains the *only* surviving copy of the validated `Domain` prototype (§Prototype) — that snippet is real knowledge worth preserving. | **archive**, but lift the prototype snippet into whatever replaces `value-domain-trait.md`. |
| `03-phases/phase-2-coverage-and-arm64.md` | 53 | 2026-06-10 `47e1bee8` | roadmap/plan | **historical** | 2.2 references `exec/arch/arm64.rs` (absent; ARM64 layout is `RegArch::AArch64` inside `exec/state.rs`). 2.3–2.8 (ARM64 scalar helpers, x86 SIMD, NEON, software FP, atomics, ARM64 differential corpus) are all still `[ ]` in PLAN — this phase is ~20% done. | **archive**. |
| `03-phases/phase-3-snapshots-hooks-os.md` | 61 | 2026-06-10 `47e1bee8` | roadmap/plan | **historical** | Only 3.4 (SimProcedure registry) shipped, and as `src/exec/simproc.rs`, not `os/simproc.rs`. 3.1 COW, 3.2 hooks, 3.3 SMC, 3.5 linux, 3.6 windows, 3.7 CC selection all unbuilt. | **archive**. |
| `03-phases/phase-4-concolic-and-smt.md` | 72 | 2026-06-10 `47e1bee8` | roadmap/plan | **historical** | 4.1/4.2/4.3/4.4/4.6 shipped. 4.2's spec (`Val=(ExprId,u128)` concolic with concrete shadow) did **not** ship. 4.3's `easy-smt` did not ship. 4.5 caching partially shipped as `solver/constraint_cache.rs`. Carries a useful 2026-06-10 correction note on solver availability. | **archive**. |
| `03-phases/phase-5-symbolic-exploration.md` | 61 | 2026-06-10 `47e1bee8` | roadmap/plan | **historical** | 5.1 `symstate.rs`, 5.2 `symmem.rs` never created; 5.4 directed search never built (no `BinaryHeap` in `explore.rs`); 5.8 veritesting not started. 5.3 `explore.rs` shipped and grew to 1,768 LOC + a 5-file `explore/` submodule after the 2026-08-17 split (`89111140`). | **archive**. |
| `03-phases/phase-6-pyo3-and-agent-tools.md` | 61 | 2026-08-05 `fcca960b` | roadmap/plan | **historical** | Only 6.1 partially shipped: `src/python_bindings/exec.rs` exposes exactly ONE function, `glaurung.engine.emulate_function` (registered at `exec.rs:117`, surfaced at `python/glaurung/__init__.py:126-128`); the `Emulator` class, `find_inputs`, `map`/`read_mem`/`add_hook`/`snapshot` do not exist. 6.3's `glaurung emulate` / `glaurung find-inputs` are absent from `python/glaurung/cli/commands/` (39 command modules, none of them these). 6.4/6.5 not started. | **archive**. |
| `03-phases/phase-7-applications.md` | 75 | 2026-06-10 `47e1bee8` | roadmap/plan | **historical** | Entirely unstarted (PLAN: 7.1–7.6 all `[ ]`). 7.4 (IOCTL sink-finding with witnesses) is arguably the one that *did* happen, via `src/symbolic/ioctl.rs` + `examples/ioctlance.rs`, but by a different route than described. Scorecard metrics ("strings-recovered", "indirect-edges-resolved") were never added to `glaurung.bench`. | **archive**, or **revise** 7.4 into a note pointing at `src/symbolic/ioctl.rs`. |

### `docs/design/execution-engine/04-testing/`

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `04-testing/README.md` | 47 | 2026-08-05 `fcca960b` | design-proposal | **mostly-current** | The six-layer strategy is sound and partly realised. "none [no solver] on the dev box as of 2026-06" is stale — `STATUS.md` itself records `apt install z3 libz3-dev`. Understates reality: CI now runs `cargo test --features symbolic` (`.github/workflows/test-suite.yml`, added 2026-09-01) and `scripts/feature-build-gate.sh` type-checks 10 feature lanes including `solver-axeyum`, `solver-bitwuzla`, `solver-z3`, `all-features`. | **revise** — point at the real gates (`test-suite.yml` symbolic lane, `feature-build-gate.sh`). |
| `04-testing/differential-oracle.md` | 50 | 2026-06-10 `47e1bee8` | design-proposal | **mostly-current** | The one testing doc whose subject shipped: `src/exec/oracle.rs` (14,586 B) behind `dev-oracle`, linking system libunicorn (`unicorn-engine = "2.1.5"`, `dynamic_linkage`). The EXAMINER caveat (Unicorn itself diverges from ARM silicon) is real, non-obvious knowledge that exists only here. Pass-rate reporting ("target ≥95%") was never operationalised — no committed corpus, no pass-rate artifact. | **revise** — record what the oracle actually covers today (STATUS says 26/26 on a hand-built inventory) and drop the unenforced ≥95% target, or make it a gate. |
| `04-testing/fixtures-and-corpus.md` | 49 | 2026-06-10 `47e1bee8` | design-proposal | **stale** | Proposes `tests/fixtures/exec/{corpus,slices,constraints,decrypt,drivers}` — **none of these directories exist**. The scorecard-integration paragraph (`glaurung.bench` gains strings-recovered / indirect-edges-resolved) never happened. The *rules* section (no fabricated CPU state; seeded generated corpora are acceptable; expected values recorded from a trusted source) is real policy worth keeping. | **revise** to keep the rules, delete the never-built layout and scorecard sections; or **merge-into** `04-testing/README.md` (both are short). |

### `docs/design/execution-engine/05-decisions/`

The ADRs are the most durable part of the tree — a decision + its *rejected alternatives* is not recoverable from source. Two of six no longer match the implementation.

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `05-decisions/README.md` | 19 | 2026-06-10 `47e1bee8` | index | **mostly-current** | Six-row index; accurate. Does not warn that ADR-0006 is unimplemented, and does not cross-reference the *other* ADR series in `axeyum-integration/07-decision-log.md` (31 ADRs) that `Cargo.toml:99` cites as "ADR-002". | **revise** — add the cross-reference and a status column (implemented / aspirational). |
| `05-decisions/adr-0001-single-domain-core.md` | 48 | 2026-06-10 `47e1bee8` | design-proposal | **current** | Held up: `src/exec/domain.rs` is the trait, `Concrete` and `Symbolic` are the two impls, `interp.rs`'s `step()` is written once. Its "(−) the memory model must also be domain-parameterized (`type Mem`)" consequence did not materialise — the real trait has no `type Mem`. | **keep** — fix the one `type Mem` line. |
| `05-decisions/adr-0002-executable-ir-vs-new-tier.md` | 46 | 2026-06-10 `47e1bee8` | design-proposal | **current** | Held up exactly: LLIR evolved in place, `Op::Unknown` retained as deprecated (`types.rs:503`) with a lowering pass, `src/ir/verify.rs` shipped as the safety net. Note the ADR-number collision with axeyum ADR-002. | **keep**. |
| `05-decisions/adr-0003-interpreter-not-jit.md` | 47 | 2026-06-10 `47e1bee8` | design-proposal | **current** | Held. `src/exec/interp.rs` (48,300 B) is an interpreter; no JIT exists. The "cached" half of "cached IR interpreter" never shipped (`exec/liftcache.rs` absent, PLAN 1.6 deferred) — worth one word of correction. | **keep** — note the lift cache is still absent. |
| `05-decisions/adr-0004-memory-model-concretize-threshold.md` | 53 | 2026-06-10 `47e1bee8` | design-proposal | **superseded** | Specifies concretize-with-1024-byte-threshold for symbolic reads. Not implemented as specified: `src/symbolic/concretization.rs` (388 LOC) implements a `ConcretizationPolicy` seam with `AnyModel` default and least/greatest/site-hash policies (see `axeyum-integration/08-concretization-policy.md` and its ADR-026, "Make concretization a first-class policy"), selected by `GLAURUNG_CONCRETIZATION_POLICY`. PLAN 5.2 confirms "currently the 'any' strategy"; the 1024-byte ITE-tree read path was never built. There is no `symmem.rs`. | **revise** or **merge-into** the axeyum concretization ADR — as written it describes a design the project consciously replaced without amending this file. |
| `05-decisions/adr-0005-smt-pipe-then-native-optional.md` | 92 | 2026-06-10 `47e1bee8` | design-proposal | **mostly-current** | Content is right (native-first, pipe fallback, one `Solver` trait, feature-gated) and it honestly documents its own reversal. But: **the filename still says the reversed decision** (`pipe-then-native-optional`), and its "On pure-Rust solvers" section says "There is no mature pure-Rust *SMT* solver competitive on QF_BV … bit-blasting to a pure-Rust SAT solver … is a worthwhile future `Solver` backend" — the project then *built* that backend (`solver-axeyum`, `src/symbolic/solver/axeyum_backend*`, ~5,100 LOC, 2026-07-13) and this ADR was never amended. Also says `z3` crate `bundled`/`gh-release` for the wheel; the wheel ships neither (`python-ext` has no solver). | **revise** — rename the file, add the axeyum outcome, correct the wheel statement. |
| `05-decisions/adr-0006-concolic-default.md` | 54 | 2026-06-10 `47e1bee8` | design-proposal | **stale / never implemented** | Every mechanism it names is absent. `Val = (ExprId, u128)` → `symdomain.rs:93` is `type Val = ExprId`. "Fork/query only at input-dependent branches (taint-gated)" → `explore.rs` uses a `shares_symbols` check, not a taint mask. "Search is **directed** toward target sinks (ICFG shortest-distance), with random-path tie-break" → `explore.rs` is DFS; no `BinaryHeap`, no `dist_to_sink`, PLAN 5.4 is `[ ]`. "Run forward along a concrete seed" → the engine seeds symbolic IRP fields (`symbolic/ioctl.rs::seed_irp`), not a concrete trace. The ADR that defines the engine's operating mode describes a mode the engine does not have. | **rewrite** — either as "what we intended and why we didn't get there", or replace with an accurate ADR describing DFS + constant-folding + solver-pruned forking. |

### `docs/design/roundtrip/`

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `docs/design/roundtrip/gcc-O0.md` | 910 | 2026-07-26 `0e1cb531` | generated | **stale** | Header: "GENERATED. Regenerate with `tools/roundtrip_review.py --out docs/design/roundtrip/gcc-O0.md`. Snapshot taken 2026-07-26 at commit `ea9d4b8`. It WILL go stale." It did. **Headline "9 of 25 executed functions behave correctly (36%)"** vs `docs/design/decbench-submission-readiness.md:653` "**24 of 26 executed functions behave correctly at gcc -O0 (92%)**", which explicitly narrates the path 36% → 84% → 92%. Its named failures (`signs`, `structs:dist2`) are exactly the ones the later doc says were fixed or explained. Tooling still exists and matches: `tools/roundtrip_review.py` has `--out` (line 250) and reads `tests/decbench_corpus/src` (14 `.c` files, present); sibling tools `roundtrip3.py`, `arch_roundtrip.py`, `recompile_fidelity.py` all present. Two caveats for regeneration: `--workdir` defaults to `/tmp`, which CLAUDE.md forbids, and the corpus is DecBench-derived. Directory is also organisationally odd — the four other round-trip docs (`docs/design/multi-decompiler-roundtrip-2026-08-04.md`, `docs/analysis/decompiler/2026-07-27-three-way-roundtrip-diary.md`, etc.) sit outside it. | **delete** — it is a regenerable dump with a wrong headline number, superseded by `decbench-submission-readiness.md`. If the artefact is wanted, generate it on demand into a gitignored path; do not keep a 910-line snapshot of decompiler output in `docs/`. The directory goes with it. |

### `docs/axeyum-integration/` — prose

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `axeyum-integration/README.md` | 123 | 2026-08-07 `0ec35a2e` | index | **mostly-current, one hard error** | Correct on the important things: axeyum is opt-in behind `solver-axeyum`, priority is z3 > axeyum > pipe, `python-ext` gets `exec` not `symbolic`, "do not use the earlier target of making Axeyum the default as a statement of shipped configuration" (correctly retracting its own ADR-002). **Wrong:** §"Current source gate: **failing**" describes an `E0004` from `BinOp::LogicalAnd`/`LogicalOr` missing in the axeyum translator — fixed on 2026-08-17 in `114a5c4c` ("cargo build --features solver-axeyum went from E0004 to clean"); `LogicalAnd` is handled at `axeyum_backend.rs:1566-1592` and `z3_backend.rs:506`. Also references branches `sec/axeyum-backend` and `axeyum-concretization-policy-a0` — **neither exists** locally or on `origin` (only `master` and three `decbench/`/`decompiler/` branches). And it names `9ace064`/`931d8a8`/`07ea0c1` as the authorities for landed work. | **revise** — delete the "Current source gate: failing" section (and the test that pins it, `python/tests/test_verify_tutorial.py:402`); replace branch names with merged commits. Otherwise **keep**: this is a good index. |
| `axeyum-integration/00-motivation-and-goals.md` | 110 | 2026-08-07 `0ec35a2e` | design-proposal | **historical** (correctly banner-labelled) | Banner says so. Its core factual claim is still exactly right and verified: "`symbolic` is **not** in `default` and **not** pulled by `python-ext` … so the shipped wheel has no symbolic engine at all today" — `Cargo.toml:83-88` confirms. | **keep**. |
| `axeyum-integration/01-current-state.md` | 216 | 2026-08-07 `0ec35a2e` | reference | **historical** (correctly labelled "state snapshot from 2026-07-13") | Cited line numbers have drifted: says `solve()` at `mod.rs:106`, actual `:931`; `Solver` trait at `:46`, actual `:82`; `Model` at `:22`, actual `:37`. Values still correct: `Assert = (ExprId, bool)`, `DEFAULT_SOLVER_BUDGET = (6000, 24)` (`mod.rs:124`), 11 `Expr` variants, `z3` crate 0.12, 250 ms timeout. Says "No push/pop, assumptions, unsat-core, or get-value in the trait" — a second trait `IncrementalSolver` (`mod.rs:93`) has since been added. Says branch `sec/ioctlance-parity`, gone. | **keep** as a dated interface snapshot; it is explicitly labelled and its provenance value is real. |
| `axeyum-integration/02-interface-mapping.md` | 222 | 2026-08-07 `0ec35a2e` | reference | **mostly-current** | Cited *from source*: `src/symbolic/solver/axeyum_backend/translate.rs:63` refers readers to this file, and `axeyum_backend.rs:15` points at the directory. That makes it a live contract document, not a plan. Its own banner correctly says "verify exact operator coverage against `axeyum_backend.rs` and its tests". | **keep**. |
| `axeyum-integration/03-architecture.md` | 174 | 2026-08-07 `0ec35a2e` | architecture | **historical** (correctly labelled) | Banner defers to `Cargo.toml` and `solver/mod.rs`. Content predates the retained-session / warm-path / direct-delta machinery that now dominates `axeyum_backend/` (`warm_paths.rs` 1,439 LOC, `snapshot.rs`, `profile.rs`). | **keep** as record; the current architecture needs a new page. |
| `axeyum-integration/04-phased-plan.md` | 228 | 2026-08-07 `0ec35a2e` | roadmap/plan | **historical** (correctly labelled) | P0–P3 landed; P4 ("axeyum is the default") explicitly abandoned per the README; P5 partial; P6 (AArch64/Android reachability) not started. Banner says "Do not infer current completion from this checklist alone" — honest. | **archive**. |
| `axeyum-integration/05-risks-and-open-questions.md` | 179 | 2026-08-07 `0ec35a2e` | design-proposal | **historical** (correctly labelled) | R1 (perf gap) is the one that materialised and is now documented far better in `PAPER-NOTES.md` and ADRs 011–021. | **archive** or **merge-into** `07-decision-log.md`. |
| `axeyum-integration/06-validation-and-ci.md` | 96 | 2026-08-07 `0ec35a2e` | design-proposal | **mostly-current** | The differential-oracle-for-solvers pattern shipped: `solve()` has a shadow-differential mode gated by `GLAURUNG_SHADOW_DIFF` (`mod.rs:622`+) that runs 4 or 6 cells per query with z3 authoritative. Doc predates the 4/6-cell rotation and the `feature-build-gate.sh` lanes. | **revise** — bring it up to the shipped shadow-diff harness and the real CI lanes. |
| `axeyum-integration/07-decision-log.md` | 1160 | 2026-08-07 `0ec35a2e` | record | **current** | **31 ADRs** (ADR-001 … ADR-031), each with context/decision/evidence. This is the *actual* decision record of the solver work and is far richer than `execution-engine/05-decisions/`. ADR-002 ("Axeyum is the default backend") is superseded by the README, which says so. ADR-025/026/027/028/029/030/031 govern behaviour that is live in `src/symbolic/`. | **keep** — highest-value record in this scope. Consider renaming to `DECISIONS.md` and reconciling the ADR-number collision with `execution-engine/05-decisions/`. |
| `axeyum-integration/08-concretization-policy.md` | 169 | 2026-08-07 `0ec35a2e` | reference | **current** | Documents the `ConcretizationPolicy` seam that `src/symbolic/concretization.rs` implements, and the `GLAURUNG_CONCRETIZATION_POLICY` env var — **verified present** in that file. This is the doc that actually supersedes `execution-engine/05-decisions/adr-0004`. Cites branch `axeyum-concretization-policy-a0` at `07ea0c1` — branch gone. | **keep**; fix the branch reference. |
| `axeyum-integration/09-taint-provenance-and-finding-labels.md` | 178 | 2026-08-07 `0ec35a2e` | reference | **current** | Documents why raw symbolic sinks are not findings, and the confidence partition behind `IOCTLANCE_ANNOTATE_CONFIDENCE` — **verified present** in `examples/ioctlance.rs`. Non-obvious, load-bearing methodology. | **keep**. |
| `axeyum-integration/FEEDBACK-LOG.md` | 529 | 2026-08-07 `0ec35a2e` | record | **historical** | Append-only diary of `[AXEYUM]` (upstream feedback) and `[GLAURUNG]` items. Honestly banner-labelled "revision-bound". Environment line names branch `sec/axeyum-backend`, gone. | **keep** as a record; it is the only account of the integration's failure modes. |
| `axeyum-integration/PAPER-NOTES.md` | 404 | 2026-08-07 `0ec35a2e` | record | **historical** | Contains a prominent, correct self-retraction: "!!! MAJOR CORRECTION (2026-07-13) — an earlier version claimed axeyum was 12-29x faster than z3. **That was wrong**", traced to an un-coerced width-mismatch bug making axeyum error out on ~98% of queries. That retraction is exactly the kind of thing that must survive a rewrite. | **keep** (archive area is fine). |
| `axeyum-integration/benchmark/README.md` | 226 | 2026-07-28 `e43167c2` | reference | **mostly-current** | Genuinely reproducible: `run_benchmark.sh` exists and is coherent; the five tiers map to real examples (`axeyum_bench_primitives`, `axeyum_diff`, `axeyum_sweep`, `axeyum_incremental`, `ioctlance`) all declared in `Cargo.toml:174-191` with `required-features`; the sample and PDB paths it uses (`samples/binaries/platforms/windows/vendor/realworld`, `tests/fixtures/msvc-pdb`) both exist. Its snapshot banner is honest. Gap: `results/provenance.txt` records `axeyum_rev 1cc19181`, `Cargo.toml:43` now pins `c38a9515` — the checked-in numbers predate the current solver pin. | **keep**; note the axeyum-rev drift. |
| `axeyum-integration/benchmark/REVIEWER-CHECKLIST.md` | 302 | 2026-08-07 `0ec35a2e` | record | **historical** | A skeptical-reviewer self-critique for a future paper. Not project documentation; valuable as methodology. Correctly labelled. | **archive** (or move to a `research/` area with `PAPER-NOTES.md`). |
| `axeyum-integration/capture/README.md` | 1433 | 2026-08-07 `0ec35a2e` | reference | **mostly-current** | The corpus-capture protocol. Its `GLAURUNG_DUMP_QUERIES` hook is **real** (`src/symbolic/solver/mod.rs:622-636`). At 1,433 lines it is the second-longest file in scope and mixes a live procedure with many dated result sections — the banner says so. | **revise** — split the ~100-line live procedure from the ~1,300 lines of dated results. |

### `docs/axeyum-integration/` — non-prose (894 files). Live infrastructure, not a dump.

| path (group) | files | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|
| `benchmark/run_benchmark.sh` | 1 | generated-input (script) | **current** | Drives all five tiers with `FEATURES="solver-z3,solver-axeyum"` and `GLAURUNG_SHADOW_DIFF=1`; stamps `results/provenance.txt`. Executable, coherent, paths verified. | **keep** — but a runnable benchmark harness belongs in `tools/` or `bench/`, not `docs/`. |
| `benchmark/results/` — `provenance.txt`, `tier0-primitives.jsonl` (54 KB), `tier0-primitives.table.txt`, `tier1-families.txt`, `tier1b-sweep.txt`, `tier2-incremental.txt`, `tier3-drivers.txt` | 7 | generated | **historical** | Immutable snapshot: `glaurung_rev 9ace0640`, `axeyum_rev 1cc19181`, 2026-07-17, i9-12900K, rustc 1.97.0-nightly. Regenerable by the script above. Self-labelled "not current performance claims". | **keep** as evidence (they are the paper's numbers); move out of `docs/`. |
| `capture/validate_ordered_trace.py` (37,917 B) | 1 | generated-input (live tool) | **current** | **Invoked from Rust at four test sites**: `src/symbolic/ordered_trace.rs:1539, 1767, 1868, 1938` all `.join("docs/axeyum-integration/capture/validate_ordered_trace.py")`. Moving or deleting this file breaks `cargo test --features symbolic`. | **keep + MOVE with a code change** — a Rust test dependency must not live under `docs/`. |
| `capture/lineage_gate.py` (44,872 B), `build_corpus.py`, `shard_corpus.py`, `validate_shadow_splits.py` | 4 | generated-input (tools) | **unverifiable** (not exercised by any gate) | Referenced only by their own sibling tests and `capture/README.md`. `pytest.ini` sets `testpaths = python/tests`, so their four `test_*.py` files are **never collected** by `uv run pytest`; no CI workflow references them. ~44 KB of ungated analysis tooling. | **keep + move to `tools/axeyum/`**; either wire the self-tests into the suite or mark them explicitly out-of-gate. |
| `capture/test_build_corpus.py`, `test_lineage_gate.py` (28,731 B), `test_shard_corpus.py`, `test_validate_shadow_splits.py` | 4 | generated-input (tests) | **unverifiable** | Real pytest files outside `testpaths`. Nothing runs them. | **keep + move**; wire into `python/tests/` or state they are manual. |
| `capture/lineage-*.json` (13 files, ~8–16 KB each) + `manifest-representative-v1.json` (44 KB) | 14 | generated | **historical** | Lineage evidence packs named for ADRs 010–021 (`adaptive-cache-on/off`, `direct-candidate`, `owner-transfer`, `serial-sibling`, `model-completion-*`). Each is a measurement artifact for a specific decision-log entry. | **keep** as ADR evidence; move under a `evidence/` path outside `docs/`. |
| `capture/excluded-hashes.txt` | 1 | generated | **historical** | Exclusion list for the corpus build. | **keep** with the corpus. |
| `capture/shadow-splits/{tcpip,dxgkrnl}-60s-{a6a5cc0,d60ed0f}/*.smt2` | 842 | generated (data dump) | **historical** | 3.9 MB of SHA256-named QF_BV queries captured from real Windows drivers, plus one `shadow-splits.tsv` index per directory. `tcpip-60s-a6a5cc0` alone is 789 files / 3.7 MB. Regenerable via the documented `GLAURUNG_DUMP_QUERIES` procedure. Directory names encode the glaurung revisions (`a6a5cc0`, `d60ed0f`). | **archive out of the repo, or out of `docs/` at minimum.** Regenerable evidence at this volume should not sit in a documentation tree; if it must be versioned, put it under `tests/corpora/` or Git LFS. |
| `capture/shadow-splits/*/shadow-splits.tsv` | 4 | generated | **historical** | Per-capture verdict indexes. | **keep with the corpus.** |

### `docs/research/`, `docs/IOC_VALIDATOR_V2.md`, `docs/benchmarks/`

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `docs/research/pyext-separation.md` | 311 | 2026-08-07 `0ec35a2e` | roadmap/plan | **historical** (correctly labelled) | Banner: "historical separation plan (December 2024) … not current architecture truth". Verified: its premise held (`pyo3` optional behind `python-ext`, `Cargo.toml`), but its ❌ TODO list is still TODO — `src/py/` was never created, and core modules still carry `#[pyclass]`. Contains a genuinely useful `cfg_attr(pyo3)` gotcha section (`#[cfg_attr(feature="python-ext", pymethods)]` does not work) that is real, non-obvious Rust/PyO3 knowledge. Its `.pyi` advice ("keep `.pyi` stubs in sync") is *contradicted* by current CLAUDE.md policy ("**Never hand-write a `.pyi`**" — generate with `tools/gen_native_stub.py`). | **archive**, first lifting the `cfg_attr` gotcha into contributor docs. A directory holding one file should not exist. |
| `docs/IOC_VALIDATOR_V2.md` | 103 | 2026-08-07 `0ec35a2e` | reference | **current** | Every claim verified. `python/glaurung/llm/agents/ioc_validator_v2.py` exists (5,837 B) and defines exactly the named symbols: `IOCType`, `IOCCandidate`, `IOCValidationDecision`, `IOCValidationOutput`, `ValidatedIOC`, `create_ioc_validator_v2`, `validate_iocs_v2`, `filter_iocs_from_artifact_v2`. `python/tests/test_ioc_validator_v2.py` exists (7,521 B). The documented `unrecognized sample kinds → IOCType.HOSTNAME` limitation is stated as a limitation, not a feature. `V2 is shipped.` Two nits: it is a top-level `SCREAMING_CASE.md` in a `docs/` tree that is otherwise all lowercase directories, and it is **not listed in `docs/README.md`**. The V1 module `ioc_validator.py` has no doc at all. | **keep** — but move to `docs/llm/ioc-validator-v2.md` and index it; add a line on V1's status. |
| `docs/benchmarks/baseline.md` | 31 | 2026-08-31 `3cf45986` | generated | **stale** | Header: "Glaurung benchmark — **2026-04-25**T16:41 … `_glaurung HEAD: eac96ac271df_`". `eac96ac2` is 2026-04-25 — four months before HEAD. Moved into `docs/` on 2026-08-31 by a top-level-consolidation commit (`R100 benchmarks/baseline.json → docs/benchmarks/baseline.json`) without being refreshed. | **delete** — regenerable via `uv run python -m glaurung.bench --output <path>`. |
| `docs/benchmarks/baseline.json` | 710 | 2026-08-31 `3cf45986` | generated | **stale / orphaned** | Records `"glaurung_commit": "eac96ac271df22f5482f827795f7a7cfa7d88845"`, `"schema_version": "1"`. **Nothing reads it**: grep across `*.py`, `*.rs`, `*.sh`, `*.yml`, `*.toml` finds zero consumers of `docs/benchmarks` or `benchmarks/baseline`. `python/glaurung/bench/__main__.py` writes to `--output` (default stdout) and never compares against a baseline. So this is a "baseline" that gates nothing — the exact failure mode CLAUDE.md warns about for the six decompiler baselines, except here there is not even a refresh path. | **delete** (with `baseline.md` and the directory). If a bench ratchet is wanted, build it as a real gate with a refresh command, not an orphaned artifact. |

---

## Directory-level summaries

### `docs/design/execution-engine/` (38 files, 3,396 lines)

**What it is really for:** it was a top-down design effort written in a single 2026-06-10 session (research → architecture → phases → testing → ADRs), immediately followed by an implementation sprint that shipped "cores of Phases 0–6" *in the same commit*. It has functioned since as a frozen artifact of that session.

**Live vs record:** roughly **20% live** (the four research syntheses, four of six ADRs, the helpers/intrinsics semantics, the differential-oracle spec), **80% record or aspiration**. The `03-phases/` tree (9 files) is entirely historical and duplicates `PLAN.md`'s task IDs. Three of eight `02-architecture/` files (`machine-state`, `arch-abstraction`, `os-abi-layer`) describe modules that were never created.

**The core problem:** there is no accurate description anywhere of `src/exec/` + `src/symbolic/` as they exist today — 25,050 LOC with an entire solver-backend subsystem, an ordered-replay/trace system, and a Windows-driver detector suite, none of which this tree mentions. The tree's two "read this first" files both assert that no code exists.

**Clean structure:** one accurate `README.md` written from source; `research/` and `decisions/` kept and re-verified; everything phase/status/plan-shaped moved to an archive.

### `docs/design/roundtrip/` (1 file, 910 lines)

Not a directory's worth of anything: a single generated snapshot of decompiler output whose headline metric is 2.5× wrong and whose subject is covered more accurately by `docs/design/decbench-submission-readiness.md`. Four other round-trip documents live *outside* this directory. **Fold it away.**

### `docs/axeyum-integration/` (16 md + 894 data/script files, 4.7 MB)

**What it is really for:** the design, decision, evidence, and benchmark record for integrating `axeyum` — the author's own pure-Rust SMT solver (`github.com/mjbommar/axeyum`, pinned at rev `c38a9515`) — as an in-process, wheel-shippable backend behind `solver-axeyum`. The integration is **real and substantial**: 12 Rust files reference axeyum, `src/symbolic/solver/axeyum_backend*` is ~5,100 LOC, five `examples/axeyum_*.rs` binaries exist with `required-features`, and `feature-build-gate.sh` type-checks three axeyum lanes.

**Live vs record:** the prose is unusually well-disciplined — 15 of 16 files open with an explicit status banner distinguishing "maintained" from "historical", and two carry prominent self-retractions (the 12–29× perf claim; the axeyum-as-default target). This is the best-maintained documentation in my scope. Live: `07-decision-log.md`, `08-concretization-policy.md`, `09-taint-provenance…`, `02-interface-mapping.md`, `benchmark/README.md`. Historical-but-valuable: the rest.

**The two problems are structural, not editorial:**
- One factual error survives (`README.md`'s "Current source gate: failing"), and it is **enforced by a test** (`python/tests/test_verify_tutorial.py:402`), so it cannot be fixed without also fixing the test.
- **894 non-prose files, 4.7 MB, live under `docs/`** — including a script four Rust tests execute (`capture/validate_ordered_trace.py`), 44 KB of ungated Python tooling with its own uncollected test suite, and an 842-file / 3.9 MB `.smt2` corpus. A documentation tree is the wrong home for a test dependency and a binary-derived corpus.

**Clean structure:** prose stays (as `docs/symbolic/solver-integration/`); `capture/` and `benchmark/` move to `tools/` + `tests/corpora/` with the Rust path updated; the `.smt2` corpus leaves the repo or goes to LFS.

### `docs/research/` (1 file)

A single correctly-labelled December-2024 plan. Not a directory.

### `docs/benchmarks/` (2 files)

A four-month-old generated scorecard that no code, script, test, or CI job reads, moved here by a directory-consolidation commit without refresh. Pure orphan.

### `docs/IOC_VALIDATOR_V2.md` (1 file)

Accurate, current, well-written, and misfiled (top-level `SCREAMING_CASE.md`, absent from `docs/README.md`).

---

## Cross-cutting findings

### A. Docs vs code — the significant contradictions

| # | Claim | Where | Reality |
|---|---|---|---|
| 1 | "No code yet" / "`src/exec/`, `src/symbolic/` … do not exist" | `execution-engine/README.md:3`, `STATUS.md` §What exists today | Both created by the *same commit* that wrote those lines (`47e1bee8`, 2026-06-10). Today: 3,591 + 21,459 LOC. |
| 2 | "52 exec + 18 symbolic Rust tests" | `STATUS.md` At-a-glance | 76 `#[test]` in `src/exec/`, 195 in `src/symbolic/`. (The 6 Python tests figure is still right.) |
| 3 | Concolic default: `Val = (ExprId, u128)`, taint-gated, directed search | ADR-0006, `symbolic-engine.md`, `phase-4` | `symdomain.rs:93` = `type Val = ExprId`. No concrete shadow, no taint mask, no `BinaryHeap`, no `dist_to_sink`. |
| 4 | Symbolic reads: bounded ITE tree when range ≤ 1024 bytes | ADR-0004, `symbolic-engine.md` | Never built. `concretization.rs` implements a policy seam, `AnyModel` default; PLAN 5.2 says "currently the 'any' strategy". |
| 5 | `easy-smt` is the default pipe backend | `smt-backends.md`, `symbolic-engine.md`, `phase-4`, `03-phases/README.md` | Not a dependency (absent from `Cargo.lock`). `pipe.rs` hand-rolls `std::process::Command`. |
| 6 | `bitwuzla-sys` 0.8.0 crate | `smt-backends.md` | `bitwuzla_backend.rs` binds the Bitwuzla **0.9.1 C API directly**, gated on `BITWUZLA_LIB_DIR` in `build.rs`. |
| 7 | `z3` crate 0.20.0 | `smt-backends.md` | `Cargo.toml:39` — `z3 = "0.12"`. |
| 8 | `default = []` | `smt-backends.md`, `02-architecture/README.md` | `default = ["triage-core"]`. |
| 9 | Feature list of 5 (`exec`, `symbolic`, `solver-z3`, `solver-bitwuzla`, `dev-oracle`) | `02-architecture/README.md` | 9 features; `dev-oracle` also pulls `exec`; `solver-axeyum`, `solver-axeyum-text`, `triage-*` absent from the doc. |
| 10 | Module tree with `src/os/`, `exec/arch/`, `exec/helpers/`, `exec/hooks.rs`, `exec/liftcache.rs`, `symbolic/{symstate,symmem,cache}.rs` | `02-architecture/README.md`, `03-phases/README.md`, and 5 phase files | None exist. |
| 11 | `Value::Const { value: u128, width }` | `executable-llir.md`, `phase-0`, `ir-design-lessons.md` P0-a | `types.rs:150` — `Const(i64)`; explicitly overruled by PLAN Q1. |
| 12 | `Domain` has `type Mem`, `load`, `store`, `concretize_addr` | `value-domain-trait.md`, ADR-0001, `phase-1` | Real trait has none; has `as_u64` and a 4-arg `concat`. |
| 13 | "Current source gate: failing" (`E0004` on `LogicalAnd`) | `axeyum-integration/README.md` | Fixed 2026-08-17 in `114a5c4c`. Pinned by `python/tests/test_verify_tutorial.py:402`. |
| 14 | Branches `sec/axeyum-backend`, `axeyum-concretization-policy-a0`, `sec/ioctlance-parity` | axeyum README, 01, 08, 09, FEEDBACK-LOG | None exist locally or on `origin`. |
| 15 | Budgets are instruction counts, "not timeouts" | `determinism.md` rule 6 | Wall-clock per-function deadlines + 250 ms per-solve z3 timeouts ship (`STATUS` worklog; `check_timeout_ms` in `solver/`). |
| 16 | `tests/fixtures/exec/{corpus,slices,constraints,decrypt,drivers}` | `fixtures-and-corpus.md` | None exist. |
| 17 | `glaurung emulate`, `glaurung find-inputs` CLI | `phase-6`, `STATUS` next actions | Not in `python/glaurung/cli/main.py`; no such module among 39 in `cli/commands/`. |
| 18 | `docs/benchmarks/baseline.json` as a baseline | implied by name/location | No consumer anywhere in the repo. |
| 19 | "Keep `.pyi` stubs in sync with wrapper methods" | `research/pyext-separation.md` | Directly contradicts current CLAUDE.md ("Never hand-write a `.pyi`"; generate via `tools/gen_native_stub.py`). |

### B. Docs vs docs

- **36% vs 92%.** `docs/design/roundtrip/gcc-O0.md:13` ("9 of 25 … 36%") vs `docs/design/decbench-submission-readiness.md:653` ("24 of 26 … 92%"). Same metric, same compiler/opt level, the later doc narrating the exact transition.
- **`STATUS.md` contradicts itself** — Phases 0–6 "core done" table, then "no implementation code has been written yet", 30 lines apart.
- **ADR-0004 vs `axeyum-integration/08-concretization-policy.md` + ADR-026** — two different symbolic-memory policies, neither cross-referencing the other; the axeyum one is what ships.
- **ADR-0005 vs `smt-backends.md` §Recommendation** — one says native z3 first, the other says `easy-smt` pipe first; both files carry 2026-06-10 correction notes acknowledging the reversal, but the *recommendation sections* were never rewritten, and ADR-0005's filename still encodes the reversed decision.
- **Two ADR-000X namespaces.** `Cargo.toml:99` cites "ADR-002" meaning axeyum ADR-002 (`07-decision-log.md`), which collides with `execution-engine/05-decisions/adr-0002` (harden LLIR in place).
- **`01-research/README.md`'s smt-backends takeaway** ("default Bitwuzla, Z3 fallback") contradicts the file it summarises and the shipped `solve()` cascade.

### C. Duplicated coverage

- `PLAN.md` ↔ `03-phases/*` ↔ `STATUS.md` §Phase progress — three renderings of the same task list, only one (`PLAN.md`) maintained past June.
- `README.md` §Phase map ↔ `PLAN.md` §Critical path ↔ `03-phases/README.md` §Phase map — the same diagram three times.
- `04-testing/README.md` ↔ `04-testing/fixtures-and-corpus.md` — 96 lines total, heavily overlapping.
- `02-architecture/symbolic-engine.md` ↔ `01-research/symbolic-execution-survey.md` §§2/5/6 — the survey's conclusions restated as design.
- `axeyum-integration/{03-architecture,04-phased-plan,05-risks}.md` ↔ `07-decision-log.md` — the decision log supersedes all three on every point where they differ.
- `docs/design/roundtrip/gcc-O0.md` ↔ `docs/design/decbench-submission-readiness.md` ↔ `docs/design/multi-decompiler-roundtrip-2026-08-04.md` ↔ `docs/analysis/decompiler/2026-07-27-three-way-roundtrip-diary.md`.

### D. Knowledge that exists ONLY in docs (call out explicitly before any deletion)

1. **`01-research/ir-design-lessons.md`** — the mapping of VEX dirty calls / P-code `CALLOTHER` / BIL typed `Unknown` / BNIL `LLIL_INTRINSIC` / ESIL `TRAP` onto our `Op::Intrinsic` choice, and the flags speed-vs-precision taxonomy (lazy `cc_op` blows up symbolically → adopt producer/consumer). Unrecoverable from code.
2. **`01-research/symbolic-execution-survey.md`** — KLEE's 13,717 queries/300 s → 699/20 s optimisation table, the 95,982-concurrent-state figure, the four-way symbolic-memory taxonomy with the 1024-byte threshold, SDSE/CCBSE. This is the entire justification for design choices the code merely embodies.
3. **`01-research/emulator-engineering.md`** — the TB-cache / dirty-page-COW / small-core+helper-split lessons, and the EXAMINER finding that Unicorn itself diverges from ARM silicon in 100k+ streams (i.e. *our oracle is not ground truth*). That caveat is load-bearing for anyone triaging an oracle divergence.
4. **`05-decisions/adr-000{1,2,3,5,6}`** §Alternatives rejected — why not two engines, why not a value-kind enum, why not a separate lower IR tier, why not JIT, why not the Python `z3-solver` package, why not pure symbolic. Rejected alternatives never appear in source.
5. **`03-phases/phase-1-concrete-emulator.md` §Prototype** — the only surviving copy of the standalone `rustc -O` prototype that validated the `Domain` keystone ("the scratch copy under `/tmp` was removed").
6. **`STATUS.md` worklog 2026-06-10/11** — the only account of the obfuscation-handling work: `MAX_BLOCK_VISITS = 8` loop bound, the `ilp60x64_3.sys` never-finishing → 57 s result, the `RtDashPt.sys` null-deref in 9 s, the z3 `SortDiffers` crash on non-1-bit predicates, the exponential `collect_syms`/`to_bv` DAG recursion without a visited set, and the honest precision limitation (306 raw arbitrary-writes vs 19 ground-truth).
7. **`axeyum-integration/PAPER-NOTES.md` §MAJOR CORRECTION** — that the 12–29× speedup was an artifact of un-coerced width mismatches causing ~98% fast-failures. The strongest anti-self-deception record in the repo.
8. **`axeyum-integration/07-decision-log.md`** — 31 ADRs governing live behaviour (warm paths, direct deltas, lineage capacity, concretization policy, finding-confidence partitions, the pinned Bitwuzla measurement cell). Deleting this loses the *why* behind ~5,100 LOC.
9. **`axeyum-integration/09-taint-provenance-and-finding-labels.md`** — why raw symbolic sinks are not findings, and how the confidence partition separates diagnostics from claims.
10. **`research/pyext-separation.md` §Critical Patterns** — the `#[cfg_attr(feature="python-ext", pymethods)]` does-not-work gotcha and the correct `#[cfg(...)] #[pymethods]` form.
11. **`04-testing/fixtures-and-corpus.md` §Rules** — the "generated instruction corpora are acceptable because they exercise the real decoder on real encodings; the generator is seeded and committed" carve-out from the no-mock rule.

### E. Structural / process findings

- **A test enforces a stale doc.** `python/tests/test_verify_tutorial.py:402` requires the axeyum README to say "Current source gate: failing". The docs-classification test suite (`test_specialized_docs_mark_live_implementation_and_historical_plans`, `test_agentic_plan_docs_are_classified_and_status_is_refreshed`, etc.) is a good idea — it is why the axeyum banners exist and are honest — but pinning a *transient factual status string* rather than a *classification* turns it into a staleness ratchet. The same pattern pins `"Refresh audit: 2026-08-07"` and specific SHAs for the agentic docs.
- **Documentation contains executable test infrastructure.** `src/symbolic/ordered_trace.rs` runs a script from `docs/`. Any docs reorganisation must be treated as a code change.
- **`docs/README.md` does not index `docs/design/execution-engine/`, `docs/benchmarks/`, or `docs/IOC_VALIDATOR_V2.md`.** Two of the three largest design efforts in this scope are reachable only by directory listing.
- **Useful counter-observation:** CLAUDE.md's own note that `python-ext` excludes `exec` is out of date — `Cargo.toml:83` reads `python-ext = ["pyo3", "pyo3/extension-module", "exec"]`, and the wheel does ship the emulator. Its `symbolic` claim (26 files / 21,459 LOC not built by `--features python-ext`) is **exactly right**, and CI has since added a `cargo test --features symbolic` lane (2026-09-01).

---

## Proposed new structure for this scope

```
docs/
├── execution-engine/                                    (was docs/design/execution-engine/)
│   ├── README.md                                        NEW — what src/exec + src/symbolic actually are,
│   │                                                    written from source: module map, the 9 Cargo
│   │                                                    features, entry points (glaurung.engine.emulate_function,
│   │                                                    explore, ioctl), what is NOT built (hooks, COW,
│   │                                                    OS layer, directed search, CLI).
│   ├── design-rationale.md                              MERGE of 00-motivation-and-goals + 01-research/README
│   │                                                    + 02-architecture/{value-domain-trait,helpers-and-
│   │                                                    intrinsics,determinism} — the why, resynced to code.
│   ├── research/                                        KEEP (re-verify smt-backends)
│   │   ├── ir-design-lessons.md                         keep as-is + adopted/rejected footnote
│   │   ├── symbolic-execution-survey.md                 keep as-is
│   │   ├── emulator-engineering.md                      keep as-is
│   │   └── smt-backends.md                              REWRITE of old — real crate versions, add axeyum
│   ├── decisions/                                       KEEP, re-verified, status column added
│   │   ├── adr-0001-single-domain-core.md               keep (fix `type Mem` line)
│   │   ├── adr-0002-harden-llir-in-place.md             keep (renamed, disambiguated from axeyum ADR-002)
│   │   ├── adr-0003-interpreter-not-jit.md              keep (note: lift cache never built)
│   │   ├── adr-0004-symbolic-memory.md                  REWRITE of adr-0004 — supersede with the shipped
│   │   │                                                ConcretizationPolicy seam; cross-ref axeyum ADR-026
│   │   ├── adr-0005-native-solver-first.md              REWRITE of adr-0005 — rename, add the axeyum outcome
│   │   └── adr-0006-execution-mode.md                   REWRITE of adr-0006 — describe the DFS + constant-
│   │                                                    folding + solver-pruning engine that exists
│   └── testing.md                                       MERGE of 04-testing/{README,differential-oracle,
│                                                        fixtures-and-corpus} — the oracle, the rules, the
│                                                        real gates (test-suite.yml symbolic lane,
│                                                        feature-build-gate.sh)
│
├── symbolic/solver-integration/                         (was docs/axeyum-integration/, prose only)
│   ├── README.md                                        REWRITE of old README — drop "source gate: failing",
│   │                                                    replace branch names with merged commits
│   ├── interface-mapping.md                             keep (cited from src/.../translate.rs:63)
│   ├── concretization-policy.md                         keep
│   ├── taint-provenance-and-findings.md                 keep
│   ├── DECISIONS.md                                     keep (was 07-decision-log.md, 31 ADRs) — renumber
│   │                                                    or prefix to end the ADR-002 collision
│   ├── validation.md                                    REVISE of 06-validation-and-ci — the shipped
│   │                                                    GLAURUNG_SHADOW_DIFF 4/6-cell harness
│   └── benchmark.md                                     REVISE of benchmark/README — method only; results
│                                                        and the script move out (below)
│
├── llm/ioc-validator-v2.md                              MOVE of docs/IOC_VALIDATOR_V2.md (unchanged content),
│                                                        indexed from docs/README.md; add V1 status line
│
└── history/                                             ARCHIVED — clearly marked, not guidance
    ├── execution-engine-2026-06/
    │   ├── STATUS.md                                    archived (worklog is the value)
    │   ├── PLAN.md                                      archived
    │   ├── phases/                                      archived (all 9 files)
    │   └── architecture-as-designed/                    archived (machine-state, arch-abstraction,
    │                                                    os-abi-layer, executable-llir, symbolic-engine,
    │                                                    02-architecture/README) — the unbuilt half
    ├── axeyum-integration-2026-07/
    │   ├── 00-motivation-and-goals.md                   archived
    │   ├── 01-current-state.md                          archived (dated interface snapshot)
    │   ├── 03-architecture.md                           archived
    │   ├── 04-phased-plan.md                            archived
    │   ├── 05-risks-and-open-questions.md               archived
    │   ├── FEEDBACK-LOG.md                              archived
    │   ├── PAPER-NOTES.md                               archived (keep the MAJOR CORRECTION)
    │   └── REVIEWER-CHECKLIST.md                        archived
    └── pyext-separation-2024-12.md                      ARCHIVED (was docs/research/) — lift the
                                                         cfg_attr/pymethods gotcha out first

OUT OF docs/ ENTIRELY:
  tools/axeyum/validate_ordered_trace.py                 MOVE — src/symbolic/ordered_trace.rs must be
                                                         updated at 4 call sites (:1539,:1767,:1868,:1938)
  tools/axeyum/{build_corpus,lineage_gate,shard_corpus,validate_shadow_splits}.py + capture/README procedure
  python/tests/axeyum/test_*.py                          MOVE the 4 self-tests into testpaths so they run
  bench/axeyum/run_benchmark.sh + results/               MOVE the harness and its 7 result files
  tests/corpora/axeyum-qfbv/ (or LFS, or out of tree)    MOVE the 842 .smt2 + 4 .tsv + 14 lineage JSONs

DELETED:
  docs/design/roundtrip/gcc-O0.md                        regenerable dump, headline number 2.5x wrong,
                                                         superseded by decbench-submission-readiness.md
  docs/benchmarks/baseline.md, baseline.json             4-month-old orphan; nothing reads it
```

Net: 55 `.md` → ~20 live + ~18 archived; 894 data/script files leave `docs/` entirely (one of them requiring a Rust code change).

---

## Ground truth established (for other auditors and the plan writer)

**Cargo features (`Cargo.toml`, verbatim, 9 total):**
```
default              = ["triage-core"]
triage-core          = []
triage-heuristics    = []
triage-containers    = []
triage-parsers-extra = ["goblin", "pelite"]
python-ext           = ["pyo3", "pyo3/extension-module", "exec"]     # NOTE: pulls exec
exec                 = []                                            # pure Rust
symbolic             = ["exec"]                                      # pure Rust
dev-oracle           = ["exec", "dep:unicorn-engine"]                # links system libunicorn
solver-z3            = ["symbolic", "dep:z3"]                        # z3 crate 0.12, links libz3
solver-axeyum        = ["symbolic", "dep:axeyum-solver", "dep:axeyum-ir"]
solver-bitwuzla      = ["symbolic"]                                  # direct C API, BITWUZLA_LIB_DIR via build.rs
solver-axeyum-text   = ["solver-axeyum", "axeyum-solver/full"]
```
`src/lib.rs:75-76` gates `exec`; `:80-81` gates `symbolic`; `:93-94` gates `python_bindings`.

**Sizes:** `src/exec/` = 10 files, 3,591 LOC (`budget, concrete, domain, helpers, interp, memory, mod, oracle, simproc, state`). `src/symbolic/` = 26 files, **21,459 LOC** (matches CLAUDE.md exactly). Largest: `solver/axeyum_backend.rs` 1,994; `solver/mod.rs` 1,935; `ordered_trace.rs` 1,946; `explore.rs` 1,768; `ioctl.rs` 1,666; `solver/axeyum_backend/warm_paths.rs` 1,439; `solver/bitwuzla_backend.rs` 1,355; `ordered_replay.rs` 1,120; `solver/constraint_cache.rs` 1,089.

**Tests:** 76 `#[test]` in `src/exec/`, 195 in `src/symbolic/`, 6 in `python/tests/test_exec_engine.py`. CI runs `cargo test --features symbolic` (`.github/workflows/test-suite.yml`, added 2026-09-01; 103 symbolic tests execute, 92 more are behind the solver features and stay out).

**Feature gate lanes (`scripts/feature-build-gate.sh`):** `python-ext`, `exec`, `symbolic`, `solver-axeyum`, `solver-axeyum-text`, `solver-bitwuzla`, `triage-parsers-extra`, `solver-z3`, `solver-z3,solver-axeyum`, `all-features` (+ 2 more lanes). `cargo check --all-targets` only — type-checks, does not run.

**Solver reality:** one seam, `pub fn solve(pool, asserts) -> SolveResult` at `src/symbolic/solver/mod.rs:931`. Two traits: `Solver` (`:82`, one method) and `IncrementalSolver` (`:93`). `DEFAULT_SOLVER_BUDGET = (6000, 24)` at `:124`. Backend priority **z3 > axeyum > pipe**. `PipeSolver` prefers `$GLAURUNG_SMT_SOLVER`, then `bitwuzla`, `z3`, `cvc5` on PATH. `easy-smt` is NOT a dependency.

**Domains:** `src/exec/domain.rs::Domain` has `constant, binop, unop, cmp, zext, sext, trunc, extract, concat(hi,lo,hi_w,lo_w), ite, as_branch, as_u64` — **no `type Mem`, no `load`/`store`, no `concretize_addr`**. `Symbolic::Val = ExprId` (`symdomain.rs:93`) — not a concolic pair.

**IR:** `Value = Reg(VReg) | Const(i64) | Addr(u64)` (`src/ir/types.rs:146`) — width lives on `VReg`, not `Value`. `Op::Unknown` survives as deprecated (`:503`); `Op::Intrinsic` (`:479`) and `Op::Undef` (`:297`) exist. `src/ir/verify.rs` exists (12,201 B).

**Modules that do NOT exist** (referenced by design docs): `src/os/`, `src/exec/arch/`, `src/exec/os/`, `src/exec/helpers/` (dir), `src/exec/hooks.rs`, `src/exec/liftcache.rs`, `src/symbolic/symstate.rs`, `src/symbolic/symmem.rs`, `src/symbolic/cache.rs`, `src/symbolic/solver/z3.rs`, `src/symbolic/solver/bitwuzla.rs`, `tests/fixtures/exec/`.

**Python surface:** `src/python_bindings/exec.rs` registers submodule `engine` (`:117-124`), surfaced at `python/glaurung/__init__.py:126-128`. **One function: `glaurung.engine.emulate_function`.** No `Emulator` class, no `find_inputs`. No `emulate` / `find-inputs` CLI command (39 modules in `python/glaurung/cli/commands/`, none of them these).

**Env vars that exist and are documented:** `GLAURUNG_SHADOW_DIFF` (`solver/mod.rs`), `GLAURUNG_DUMP_QUERIES` (`solver/mod.rs:636`), `GLAURUNG_CONCRETIZATION_POLICY` (`concretization.rs`), `GLAURUNG_AXEYUM_DIRECT_DELTA` (`ordered_replay.rs`, `axeyum_backend.rs`), `GLAURUNG_ENGINE_CONSTRAINT_CACHE` (`constraint_cache.rs`), `IOCTLANCE_ANNOTATE_CONFIDENCE` (`examples/ioctlance.rs`), `GLAURUNG_SMT_SOLVER` (`pipe.rs`), `AXEYUM_SOURCE_REPO` (`ordered_replay.rs`).

**Examples (`Cargo.toml:155-191`):** `ioctl_scan`, `ioctlance` (`symbolic`); `ordered_native_replay`, `linux_symbolic_cve`, `axeyum_infeasible_path_proof` (`solver-axeyum`); `axeyum_diff`, `axeyum_bench_primitives`, `axeyum_sweep`, `axeyum_incremental` (`solver-z3,solver-axeyum`).

**axeyum:** an external pure-Rust SMT solver by the same author — `github.com/mjbommar/axeyum`, pinned at rev `c38a9515e68e7427b1a41a7598805cf60686bd58`, crates `axeyum-solver` (`default-features=false, features=["qfbv"]`) and `axeyum-ir`. The integration is real: 12 Rust files reference it, ~5,100 LOC of backend. The benchmark's `provenance.txt` records the older rev `1cc19181` — checked-in numbers predate the current pin.

**Round-trip:** `tools/{roundtrip3,roundtrip_review,arch_roundtrip,recompile_fidelity}.py` all exist. `roundtrip_review.py` has `--out` (`:250`), reads `tests/decbench_corpus/src` (14 `.c` files, present), and defaults `--workdir /tmp` (which CLAUDE.md forbids). Current gcc-O0 execution-differential figure is **92% (24/26)**, not the 36% in `docs/design/roundtrip/gcc-O0.md`.

**Dates:** `src/exec/` and `src/symbolic/` both created 2026-06-10 (`47e1bee8`). 30 commits to `src/exec/` (last 2026-08-15), 100 to `src/symbolic/` (last 2026-08-19). axeyum backend 2026-07-13 (`b000ff15`); Bitwuzla cell 2026-07-19 (`2961d7c1`); the three-backend `LogicalAnd` fix + 11-config feature gate 2026-08-17 (`114a5c4c`); `explore.rs` split 2,742→901 same day (`89111140`). Execution-engine docs last substantively updated **2026-06-11**.
