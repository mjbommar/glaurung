# STATUS — Execution Engine

> Living progress tracker and **restart anchor**. Read this first when (re)starting
> work on the execution engine. Update it at the end of every work session.
> The ordered checklist lives in [`PLAN.md`](PLAN.md); keep the two in sync.

## At a glance

| Field | Value |
|---|---|
| **Overall status** | 🟢 **Usable multi-arch engine** — cores of Phases 0,1,2,3,4,5,6. Concrete emulator runs real x86-64+ARM64 functions and is **exposed to Python** (`glaurung.engine`); symbolic exec finds inputs reaching a target via in-process z3. 52 exec + 18 symbolic Rust tests + 6 Python tests green. |
| **Current phase** | Cores of Phases 0–6 done. **Remaining is breadth + product/design surface.** |
| **Next action** | Breadth/integration (each somewhat design-laden): symbolic `find_inputs` Python surface; CLI `emulate`/`find-inputs` (6.3); agent tools + KB writeback (6.4/6.5); symbolic addresses (5.2); libc/Windows SimProc stubs (3.5/3.6); SIMD/FP helpers; Phase 7 applications (string-decrypt, indirect-resolution). |
| **Carried forward** | 0.8 (flag DCE); 1.6 (lift cache); 1.8 operand-carrying helpers; 4.5 (constraint caching); `bitwuzla` native backend (optional). |
| **Blockers** | **None.** (Both earlier "environment-blocked" calls were wrong/premature and are now disproven: the native z3 solver works (apt `z3 libz3-dev` + `z3` crate, in-process), and the **Unicorn differential oracle works** via the system lib (apt `pkg-config libunicorn-dev`) — it already caught + fixed a `movsx` bug. Nothing is blocked.) |
| **Last updated** | 2026-06-10 |
| **Updated by** | Claude (impl session) |

## Phase progress

| Phase | Status | Notes |
|---|---|---|
| 0 — IR hardening | ✅ core done | 0.1–0.7 + 0.9 done; 0.8 + two 0.7 refinements carried into Phase 1 |
| 1 — Concrete emulator (x64) | ✅ core done | Domain/Concrete/RegFile/Memory/interpreter/run_function/budget/helpers; runs real lifted fns; 44 exec tests. Deferred: lift cache (1.6), Unicorn oracle (1.9, env-blocked), operand helpers |
| 2 — Coverage + ARM64 | 🟨 core done | **ARM64 register layout + runs real lifted ARM64 functions** (multi-arch achieved). SIMD/FP/atomics helpers deferred (need richer lifter intrinsics). 5 tests |
| 3 — Snapshots/hooks/OS | 🟨 core started | **SimProcedures** (call summaries) let functions run through modeled calls; snapshots via `Machine: Clone`. Hooks, libc/Windows stub sets, dirty-page COW remain |
| 4 — Concolic + SMT | 🟢 core done | `Expr` IR + `Symbolic` domain + `Solver` trait; **native z3 (in-process) solves**, pipe fallback. 15 tests. Caching (4.5) + generational driver (4.7) remain |
| 5 — Symbolic exploration | 🟨 core done | forking (`Machine` clone) + DFS worklist + solver pruning + `find_input_reaching`; 2 tests. Sym memory (5.2), directed search (5.4), concrete-replay (5.6) remain |
| 6 — PyO3 + agent tools | 🟨 core started | **`glaurung.engine.emulate_function`** runs the emulator from Python (x86-64+arm64, deterministic); 6 Python tests. `find_inputs`/`Emulator`/CLI/agent-tools/KB remain |
| 7 — Applications | ⬜ not started | 7.1–7.3 need only Phases 1–3 |

Legend: ⬜ not started · 🟨 in progress · ✅ done · ⛔ blocked

## What exists today (done in the design session, 2026-06-10)

- ✅ Full design tree under `docs/design/execution-engine/` (research, architecture,
  phases, testing, ADRs). Entry point: [`README.md`](README.md).
- ✅ Architecture **keystone validated by prototype**: a standalone Rust file
  (compiled `rustc -O`) proved one `step()` drives both a concrete emulator and a
  symbolic SMT-LIB2 term builder. The prototype is reproduced in
  [`03-phases/phase-1-concrete-emulator.md`](03-phases/phase-1-concrete-emulator.md#prototype)
  (the scratch copy under `/tmp` was removed — reimplement it as the real
  `src/exec/` modules).
- ✅ Six ADRs locked ([`05-decisions/`](05-decisions/)).
- ✅ LLIR gaps verified against the real `src/ir/types.rs`.

**No Rust/Python implementation code has been written yet.** `src/exec/`,
`src/os/`, `src/symbolic/`, and `src/python_bindings/exec.rs` do not exist.

## How to start / restart (procedure)

1. **Read** [`README.md`](README.md) (vision + the keystone) and this file.
2. **Open** [`PLAN.md`](PLAN.md); find the first unchecked task.
3. **Read** that task's phase file in [`03-phases/`](03-phases/) and the
   architecture spec(s) it links.
4. **Confirm decisions** are unchanged in [`05-decisions/`](05-decisions/) — do not
   re-litigate a locked ADR without writing a new one.
5. **Implement TDD**: write/extend the test first (real fixtures only), then the
   code. See [`04-testing/`](04-testing/).
6. **On finishing a task:** tick it in `PLAN.md`, update the "Phase progress" table
   and "Next action"/"Last updated" here, and add a line to the Worklog below.

## Environment prerequisites (per phase, when reached)

- **Phase 1+ (`exec`):** pure Rust, no new deps. `cargo test --features exec`.
- **Phase 4 (`symbolic`):** pure Rust; builds the `Expr` IR + pipe fallback with
  no link. `cargo test --features symbolic`.
- **Phase 4 native solver (`solver-z3`):** links libz3. On this box: installed via
  `sudo apt-get install -y z3 libz3-dev` (libz3 4.13.3). `cargo test --features
  solver-z3`. For the shipped wheel, use the `z3` crate's `bundled`/`gh-release`
  instead of the system lib (reproducible). The pipe fallback also finds the
  `z3` binary on PATH.
- **Dev-oracle (Unicorn):** `dev-oracle` feature, never shipped. Links the
  **system** Unicorn via pkg-config — `sudo apt-get install -y pkg-config
  libunicorn-dev` (the `unicorn-engine` crate's `build.rs` then skips the vendored
  QEMU compile). `cargo test --features dev-oracle`. (The earlier vendored-build
  failure was a dead end I shouldn't have called "blocked"; the system lib works.)

## Open questions / decisions pending (resolve before the relevant phase)

- [x] **Q1 (Phase 0) — RESOLVED 2026-06-10:** `Width` = newtype `Width(u16)` (bits)
  with associated consts (`W1`/`W8`/…/`W512`) and `bits()`/`bytes()` accessors.
  **Refinement to task 0.1/0.2 representation (low-churn, keeps build green):** we do
  **not** reshape `Value` (the strawman `Const{value,width}` + `Reg(VReg,Width)` is
  ~321 sites incl. tuple-pattern matches → long red build in a 35-file tree).
  Instead: width is a property of every **`VReg`** (`Phys` derivable by name table,
  `Flag` = 1-bit, `Temp` width tracked as a follow-up when the executor needs it);
  the new width-change ops (`ZExt`/`SExt`/`Trunc`/`Extract`/`Concat`/`Ite`) carry
  explicit widths; operation width for `Bin`/`Un`/`Cmp`/`Assign` is derived from the
  `dst` VReg, and `Load`/`Store` width from `MemOp.size`. This matches the validated
  Phase-1 prototype (width-on-op) and is reversible if Phase 1 shows explicit
  per-value width is needed. `Value::Const` stays `i64`, read/masked at the
  consuming op's width.
- [ ] **Q2 (Phase 1):** persistent-map crate for symbolic register/state forking
  (`im` vs `rpds`) — defer until Phase 5 actually needs forking; concrete Phase 1
  uses plain owned state.
- [ ] **Q3 (Phase 4):** ship a solver binary in the wheel vs require the user to
  install one vs offer it as a separate optional package. Tied to
  [ADR-0005](05-decisions/adr-0005-smt-pipe-then-native-optional.md); decide before
  Phase 4 ships externally.
- [ ] **Q4 (Phase 5):** parallel exploration vs strictly single-threaded for
  determinism — default single-threaded; revisit if too slow
  ([determinism spec](02-architecture/determinism.md)).

## Worklog (most recent first)

- **2026-06-11** — **Real-CVE validation + engine performance & precision.**
  Ran against the fork's real-world samples (which carry IOCTLance ground truth)
  and hardened the engine. **Validation:** on `ilp60x64_3.sys` (GT: 19 read/write
  controllable-address) the engine emits `arbitrary-write severity=Arbitrary` at
  attacker-controlled sites — the same class. **Engine perf fixes (correctness-
  preserving):** memoized `ExprPool::collect_syms` and the z3 `to_bv` translation
  — both recursed a *hash-consed DAG* without a visited set, i.e. exponential on
  shared subexpressions (obfuscated code especially); reuse one z3 `Context` per
  thread instead of building one per solve; add a per-solve z3 timeout (250 ms →
  `unknown`, kept feasible) so a pathological formula can't stall the run;
  collapse `record_access` from up to 5 solves to 1 (solve the path once, reuse),
  with an **affine-unit fast path** (`Sym`/`Sym+const` unconstrained ⇒ Arbitrary &
  null-capable with no solve) and a **branch-independence** skip (a predicate
  sharing no symbol with the path can't make it unsat). **Precision/orchestration**
  (`examples/ioctl_scan.rs`): rank findings severity-first; gate the IRP-seed pass
  to functions that chase `Irp->CurrentStackLocation` (0xB8); run the stateful
  sweep only where a free is reachable; parallelize lifting; cap function size and
  per-function states. 40 symbolic tests; 852 lib pass + 2 pre-existing; oracle
  11/11. **Known limitation:** heavily-obfuscated drivers (`ilp60x64`) stay
  expensive — per-function symbolic cost × ~160 functions, with a few crypto/VM
  functions whose every solve hits the timeout; bounded by the size/state caps and
  solve timeout (the same place IOCTLance accepts errored/timed-out states). True
  fixes (directed search, function-level budget, lazy constraint solving) are
  future work.
- **2026-06-10** — **IOCTLance gap closed: 5 of 5 planted bug classes detected.**
  Added stateful multi-invocation exploration and fixed the last reachability
  blocker, so the cross-invocation use-after-free / double-free are now caught.
  - **Unmodeled calls no longer end the path.** They are treated as opaque (havoc
    `rax`, continue) — ending on every `DbgPrint`/helper cut off everything after
    it, including the `ExFreePool` that the free path reaches *after* a log call.
    This also deepens reach for every other detector.
  - **Stateful multi-invocation sweep** (`find_sinks_stateful` /
    `find_function_stateful_sinks`): run the handler N rounds, carrying the
    machine (memory + heap/allocation table) forward and re-seeding a fresh
    request each round; keep the terminal path that advanced the heap lifecycle
    furthest (`progress` = freed≫allocated). Round 1 commits the alloc (pointer
    saved to a global), round 2 the free, round 3 detects use-after-free /
    double-free. `State` is now `Clone`; `uaf_check` moved to cover every
    load/store (concrete *and* symbolic) plus `memcpy` args, since a freed pointer
    held in a global is dereferenced at a concrete address.
  - **Corpus result (`examples/ioctl_scan.rs`, three passes — IRP / tainted-entry
    / stateful):** process_termination, physical_memory, race_condition
    (double-fetch), file_operations, **and use_after_free + double_free** all
    detected. New unit test `cross_invocation_uaf_and_double_free` proves a single
    invocation finds nothing while the stateful sweep finds both (40 symbolic
    tests; oracle 11/11; 852 lib pass + 2 pre-existing WinAPI).
  - Residual quality work (not blocking): the generic arbitrary-read/null-deref
    on IRP buffer pointers are noisy nominators; precision ranking and true
    inter-procedural call-following (vs. assume-tainted-entry) are future polish.
- **2026-06-10** — **Closing the IOCTLance gap on real drivers (0→4 of 5 planted
  bugs).** Drove the engine against the fork's synthetic single-bug `.sys` via
  `examples/ioctl_scan.rs` and fixed the blockers that made it find *nothing*
  real, by reading the actual disassembly rather than guessing:
  - **Register-indirect import resolution.** MSVC emits imports as
    `mov reg,[rip+__imp_Api]; call reg` (lifted `Indirect(Reg)`), which the old
    `summary_for` (only `Direct`/`Indirect(Addr)`) dropped → the modeled API call
    vanished. Now: seed each IAT slot with a self-pointer (`mem[slot]=slot`) and
    resolve a register-indirect callee by concretely evaluating its target — so
    `call reg` lands back on the slot VA and the `CallModel` resolves it.
  - **Taint-through-memory actually fires now.** The old `as_const(val)==Some(0)`
    guard never matched, because an uninitialized multi-byte load is a `Concat`
    of zero bytes, not a bare `Const`. Added `Memory::is_initialized`; a load from
    an attacker pointer into unwritten memory now mints a fresh tainted symbol —
    so `handle = *(SystemBuffer)` stays attacker-controlled into the API call.
  - **Assume-tainted-entry mode** (`find_function_sinks_with_apis` /
    `seed_tainted_args`): dispatchers delegate to `ProcessX(UserBuffer,…)` helpers
    via direct calls the engine does not yet follow; analyzing each helper with
    `rcx/rdx/r8/r9` tainted recovers those sinks without inter-procedural search.
  - Result on the corpus: **process_termination, physical_memory, race_condition
    (double-fetch), file_operations now detected** (were all missed). New unit
    test `register_indirect_import_with_buffer_derived_handle` locks the path in
    (39 symbolic tests; oracle 11/11; 850 lib pass + 2 pre-existing).
  - **Still open — the one honest miss:** `use_after_free`/`double_free` are
    *cross-invocation* (alloc on IOCTL #1, free on #2, use on #3 via a global), so
    a single-invocation symbolic run cannot observe alloc+free+use together. Needs
    stateful multi-invocation exploration (carry globals/heap across IOCTL codes)
    — the next frontier, plus true inter-procedural call-following.
- **2026-06-10** — **Full IOCTLance detector parity (all 13).** Implemented the
  remaining 11 detector classes on the symbolic engine so glaurung now covers the
  same set the IOCTLance fork does, each TDD'd (symbolic suite 27→38; full lib 850
  pass + 2 pre-existing WinAPI fails; Unicorn oracle 11/11; default build clean).
  `SinkKind` grew to 14 variants; sinks keep provenance + arbitrariness severity.
  **(A) Call-argument detectors** via a generalized `ApiSummary`
  (`CopyMemory | Alloc | Free | Probe | DangerousCall{args,kind}`) and a real
  import-table seam `driver_api_model(&BTreeMap<name,va>)`: `process_termination`
  (`ZwTerminateProcess` handle), `physical_memory` (`MmMapIoSpace` phys/size),
  `file_operations` (`ZwCreateFile`/…), `format_string` (`sprintf` fmt arg),
  `probe_bypass` (`ProbeForRead/Write` zero-length **+ region validation** that
  suppresses later derefs built from probed symbols), `shellcode` (attacker
  indirect call target). **(B) Allocation lifecycle**: `ExAllocatePool*`/
  `ExFreePool*` summaries drive a per-path bump allocator + freed-set →
  `double_free` (second free) and `use_after_free` (deref/copy of a freed block).
  **(C) Instruction-level**: `integer_overflow` (tainted add/sub/mul, overflow
  predicate solved at operand width), `stack_buffer_overflow` (attacker-length
  `memcpy` onto the stack window), `race_condition`/double-fetch (same attacker
  pointer read twice on a path). New API: `find_sinks`/`find_ioctl_sinks[_with_apis]`,
  `driver_api_model`. **Mapping to the fork's 13:** arbitrary_rw→Controlled
  Read/Write, null_pointer→NullDeref, +the 11 above. **Still deferred (the only
  real gap left):** the PE→DriverEntry→MajorFunction[14] bridge to populate the
  `CallModel`/`TaintSpec` from a real `.sys` and run end-to-end.
- **2026-06-10** — **IOCTLance detector quality (3 iterations).** Closed the
  precision/breadth/kernel-API gaps the IOCTLance-fork comparison surfaced, all
  TDD'd against `solver-z3` (symbolic suite 21→26, Unicorn oracle still 11/11).
  **(1) Precision** — sinks now carry *provenance* (`TaintSpec` maps each seeded
  IRP symbol to a label; a sink whose address touches no attacker symbol is *not*
  reported — kills the "every symbolic store" over-report) and a *severity* from
  IOCTLance's `0x87` sentinel probe (`Arbitrary` = address satisfiable to a
  chosen sentinel = write-where; `Constrained` = attacker-derived but bounded).
  **(2) Breadth** — generalized the single write sink into `Sink{kind,severity,
  tainted_by,witness}` over `ControlledWrite | ControlledRead | NullDeref`; null
  deref is *path-sensitive* (a `if(p==0) return;` guard makes `p==0` unsat on the
  deref path, so it's correctly suppressed — better than IOCTLance's manual global
  tracking). Found+fixed a latent emulator bug: `Memory::{load,store}` slow path
  did non-wrapping `addr+i`, panicking on a wild concretized address — now
  `wrapping_add` (hardware semantics; oracle unaffected). **(3) Kernel API** —
  `ApiSummary::CopyMemory` + `CallModel` (VA→summary): a `memcpy`/`RtlCopyMemory`
  through an attacker `dst`/`src` is now detected even though it never appears as
  a raw symbolic store; an unmodeled call still ends the path. New API:
  `find_sinks` / `find_ioctl_sinks[_with_apis]`; `find_arbitrary_writes` kept as a
  write-only filter. **Still deferred:** PE→DriverEntry→MajorFunction[14] bridge
  to drive real `.sys`; the `CallModel` is the seam the import table will fill.
- **2026-06-10** — **IOCTLance capability (first cut).** Built the symbolic
  arbitrary-write detector on our own engine. (a) Threaded a controlled-write
  sink collector through the explorer: new `ControlledWrite { store_va, witness }`
  and `find_controlled_writes(lf, seed, max_states)` in `src/symbolic/explore.rs`
  — a store through a *symbolic (input-derived)* address is recorded with a
  solver witness (the input that reaches it) before the address is concretized.
  (b) New `src/symbolic/ioctl.rs`: `seed_irp` lays out a **symbolic IRP** per the
  WDM dispatch ABI (`rcx`=DeviceObject, `rdx`=Irp; IRP/`IO_STACK_LOCATION`
  offsets mirror `src/analysis/ioctl_taint.rs` — SystemBuffer/UserBuffer/lengths/
  IoControlCode/Type3 symbolic, the Irp→stack-location pointer concrete), and
  `find_arbitrary_writes(lf, max_states)` runs it. `IrpSeed` returns the free-symbol
  ids so a witness `Model` is interpretable. (c) Tests (3, all green under
  `solver-z3`): a synthetic gated handler where the engine recovers the exact
  triggering `IoControlCode` (`0x800`) as the witness; the **real x86-64
  machine-bytes** pipeline (lift → symbolic-detect) on a `mov [rax],imm` through
  SystemBuffer; and a negative (no write → no finding). This is the symbolic
  *confirmation* layer above the static `ioctl_taint` *nomination* pass.
  **Deferred (next):** PE memory loader + DriverEntry→MajorFunction[14] traversal
  to drive this from real `.sys` samples; read/OOB-length sinks; null-deref sink.
- **2026-06-10** — Emulator fundamentals pass (correctness · performance · tests),
  committed on the branch. **Correctness:** the Unicorn differential oracle now
  compares **memory** (stack/scratch + rsp), not just GPRs; validated
  load/store/push/pop; **fixed `div`** (was an approximate quotient-only lift —
  now full `rdx:rax` quotient+remainder via a two-output helper) and added `bt`;
  the common-instruction inventory is **26/26 match, 0 diverged**, plus an
  edge-case suite (shift-count masking, sub-register chains, overflow).
  **Performance:** added a criterion benchmark (`benches/emulator.rs`); rewrote
  the register file to an **indexed** model (once_cell slot maps, Vec cells, flag
  array, Cow lowercasing) — arith loop 282µs→182µs (~35%); **paged** the memory
  (single-page fast path) — mem loop 518µs→251µs (~52%). **Tests:** memcpy
  integration, emulator determinism, oracle edge cases. All suites green
  (exec+dev-oracle 66, symbolic 19, default 758 + 2 pre-existing WinAPI).
- **2026-06-10** — Fundamentals run (Unicorn axis + IOCTLance axis), committed on
  branch `glaurung-execution-engine-2026-06`. (a) **Lifter coverage**: closed
  `imul`(3-op)/`rol`/`ror` gaps (oracle-validated, 23/26 match Unicorn, 0
  diverged; `mul`/`bswap`/`bt` remain). (b) **Symbolic addresses**: the explorer
  now concretizes symbolic load/store addresses (solve→eval→bind) instead of
  halting — driver code dereferencing attacker-controlled pointers is now
  explorable. All suites green.
- **2026-06-10** — Unicorn differential oracle (fundamentals; corrects another
  bad "blocked" call). `apt install pkg-config libunicorn-dev` → the
  `unicorn-engine` crate links the system lib (no vendored QEMU compile). Added
  `src/exec/oracle.rs` (`dev-oracle` feature): `diff_x86_64` runs real bytes on
  our emulator + Unicorn and compares GPRs. **It immediately found a real
  `movsx` bug** (lifted as zero-extend instead of sign-extend) — fixed in
  `lift_x86.rs` (now emits explicit `SExt`/`ZExt`). 13-instruction inventory
  matches Unicorn; lift_x86 movzx test updated for the Load+ZExt shape. All
  suites green. This is the validation backbone driving emulation fundamentals.
- **2026-06-10** — Phase 6 core (PyO3 surface). `python-ext` now bundles the
  pure-Rust `exec` engine. Added `src/python_bindings/exec.rs` →
  `glaurung.engine.emulate_function(path, va, arch, max_steps)` returning an
  outcome/steps/regs dict; wired the `engine` submodule into `__init__.py`.
  Verified from Python on real x86-64 (`_start` runs 15 steps → called_out) and
  ARM64 functions; 6 pytest cases incl. determinism + arch/VA error handling.
  ruff clean; `ty` shows only the standard untyped-native-module diagnostics.
- **2026-06-10** — Phase 3 (SimProcedures) + symbolic memory check. Added
  `exec/simproc.rs` (`SimProcRegistry<D>`): `step` replaces a modeled call with a
  Rust summary and continues (functions now run *through* modeled calls to
  `ret`). Confirmed symbolic memory works for the concolic-common case (concrete
  address, symbolic value): a store/load round-trip is value-preserving (z3:
  `loaded != original` is unsat). Symbolic *addresses* (concretize-with-threshold)
  remain. 52 exec + 18 symbolic tests.
- **2026-06-10** — Phase 2 core (ARM64 execution). Made `RegFile` arch-aware
  (`RegArch::{X86_64,AArch64}`): added the AArch64 layout (`x*/w*` with w-reg
  zero-extend, 64-bit `sp`, `lr`/`fp` aliases, `xzr`/`wzr` zero register),
  `Machine::new_with_arch`, and `HelperRegistry::default_aarch64`. **Runs a real
  lifted ARM64 function end-to-end** through the same arch-agnostic interpreter.
  Multi-arch goal (G2) achieved for concrete execution. SIMD/FP/atomics helpers
  deferred (need richer lifter intrinsics). 49 exec tests.
- **2026-06-10** — Phase 5 core (symbolic exploration). Made `Machine`/`RegFile`/
  `Memory`/`HelperRegistry`/`Symbolic`/`ExprPool` cloneable (fork = clone).
  Added `symbolic/explore.rs`: DFS worklist that forks at symbolic `CondJump`,
  prunes infeasible paths with the solver, and `find_input_reaching(lf, target,
  seed, max_states)`. Verified with native z3: a branch on a symbolic `rdi`
  yields the reaching input `rdi=42`; unreachable target → Unsat. 17 symbolic
  tests green (61 engine tests total across exec+symbolic).
- **2026-06-10** — Phase 4 solver, native-first (+ correction of a bad call).
  Built the `Solver` trait (`symbolic/solver/mod.rs`) with **native `z3` crate
  primary** (`z3_backend.rs`, feature `solver-z3`, links libz3, translates `Expr`
  → z3 AST in-process) and the SMT-LIB2 **pipe as fallback** (`pipe.rs`). Verified
  in-process solving: `x+1==0x100` → `x=0xff`, unsat detection, and the
  end-to-end symbolic-execute-then-solve. **Correction:** in the prior increment I
  declared the SMT solver "environment-blocked" after only `uv pip install
  z3-solver` failed against a restricted registry — wrong on two counts: I had
  passwordless sudo (`apt-get install z3 libz3-dev` works), and the project
  convention is `uv add`, not pip. I also prematurely called the Unicorn oracle
  "blocked" after one failed build without investigating. Reversed ADR-0005 to
  **native-first** (the original "pipe-first / avoid C deps" reasoning was
  satisfied by feature-gating; it optimized for my convenience). Corrected the
  false blocker language across STATUS/PLAN. Tests: 15 symbolic (native z3), 44
  exec, 758 default (+2 pre-existing).
- **2026-06-10** — Phase 4 symbolic `Domain` + `Expr` IR + pipe solver (initial).
  Hash-consed `Expr`, `Symbolic: Domain`, keystone test (one interpreter → SMT
  constraint). NOTE: the "no solver in env / deferred" claims written here were
  later found wrong (see entry above).
- **2026-06-10** — Phase 1 close-out (run_function, budget, helpers, validation).
  Added `run_function` (multi-block, budget-bounded), `src/exec/budget.rs`, and
  `src/exec/helpers.rs` (`HelperRegistry` + deterministic `rdtsc`/`cpuid`).
  **Executes a real lifted x86-64 function end-to-end** and a self-contained
  differential corpus (real byte encodings → decode→lift→execute → hand-verified
  results). Discovered the **Unicorn oracle is unbuildable in this env** (QEMU C
  `munmap` implicit-declaration error) → removed the dep, substituted the
  self-contained corpus, documented for a capable CI env. 44 exec tests green.
- **2026-06-10** — Phase 1 tasks 1.4 + 1.5 (memory + interpreter). Added
  `src/exec/memory.rs` (`Memory<D>`: byte-addressed, domain-assembled multi-byte
  load/store, both endiannesses) and `src/exec/interp.rs` (the single `step()` +
  `run_block()` over `Domain`, with a `Flow`/`Halt` model and pragmatic op-width
  inference). **The validated prototype now runs as real lifted-IR execution**:
  tests cover the prototype sequence, sub-register arithmetic (`al += 2` wraps,
  preserves upper rax), conditional branches (JE/JNE), and a `[rsp-8]` store/load
  round-trip — all through the real interpreter. 34 exec tests green; default
  build/suite unaffected.
- **2026-06-10** — Phase 1 task 1.3 (RegFile). Added `src/exec/state.rs`:
  `RegFile<D>` generic over `Domain`, with the x86-64 register layout and
  **correct partial-register semantics** via `extract`/`concat`/`zext` through the
  domain — 9 tests prove eax-zeroes-upper-rax, ax/al-preserve, ah=[8:16),
  r8d-zeroes-r8, flag/temp isolation, lazy-zero cells. 23 exec tests total green;
  default build/suite unaffected.
- **2026-06-10** — Phase 1 start (keystone). Added the `exec` Cargo feature
  (pure Rust, off by default) and `src/exec/`: `domain.rs` (the `Domain` trait —
  bit-vector primitives, `as_branch`, `as_u64`) and `concrete.rs` (`Concrete`
  backend: masked-`u128`, modular-at-width arithmetic, signed/unsigned compares,
  zext/sext/trunc/extract/concat/ite). 14 unit tests pass incl. the end-to-end
  prototype sequence (`rax=0xff; ebx=rax+1=0x100; zf=1`). Default build
  unaffected. Next: RegFile + x86-64 layout, softmmu memory, the single
  `step()`/`run()` interpreter, then execute a lifted block + differential oracle.
- **2026-06-10** — Phase 0 task 0.7 + close-out. Added `Op::opaque()` + a
  `lower_unknowns` pass in `lift_function_from_bytes` → **zero residual
  `Unknown` on real x86-64 + ARM64 `samples/`** (new corpus tests assert it).
  Preserved decompiler output (ast `Intrinsic` arm mirrors old `Unknown` incl.
  semantic comments). Added PyO3 dict conversions for all 7 new ops; rebuilt the
  extension; Python IR/decompile tests green. Confirmed the only failing Python
  CLI tests (`test_decompile_entry_prints_pseudocode`, `pe_import_thunk_map_path`)
  are **pre-existing on HEAD**. Phase 0 core declared complete; 0.8 + two 0.7
  refinements explicitly carried into Phase 1. Lib suite 758 pass / 2 pre-existing.
- **2026-06-10** — Phase 0 impl session. Landed the executable-IR foundation in
  `src/ir/types.rs`: `Width` newtype (+`phys_reg_width`/`VReg::width()`), `Endian`
  + `MemOp.endian`, and new ops `ZExt`/`SExt`/`Trunc`/`Extract`/`Concat`/`Ite`/
  `Intrinsic` (additive; `Unknown` kept as deprecated). Wired the new ops through
  `use_def`, `ast` (decompiler lowering), and `ioctl_taint` (taint transfer)
  soundly. Added `src/ir/verify.rs` (width-change invariants, undefined-temp,
  mem-size, residual-`Unknown` tracking) with unit tests **and a corpus test that
  verifies real lifted `samples/` functions have no fatal errors**. Resolved Q1
  (Width = newtype; width via VReg, not a `Value` reshape — kept the 35-file tree
  green at every step). Full lib suite: 757 pass, 2 pre-existing WinAPI failures
  (confirmed pre-existing on HEAD, unrelated). Not committed (house rule: commit
  only when asked).
- **2026-06-10** — Design session. Produced the full `docs/design/execution-engine/`
  tree; ran 4 deep-research subagents; verified LLIR gaps in `src/ir/types.rs`;
  prototyped & compiled the `Domain`-generic interpreter keystone; locked 6 ADRs.
  Added `PLAN.md` + this `STATUS.md`. Implementation not yet begun.
