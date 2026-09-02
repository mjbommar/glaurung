# Execution engine

> **Kind:** architecture · **Status:** maintained

`src/exec` and `src/symbolic` are one interpreter written over an abstract value
domain. Instantiate the domain with `Concrete` and it is an emulator;
instantiate it with `Symbolic` and it is a symbolic executor. Nothing about
instruction semantics is written twice, and the two cannot drift, because there
is only one `step()`.

Every claim below was checked against the tree at `b8884687`; the commands are in
the "verified with" notes so a reader can re-check rather than trust.

## Size and shape

| Tree | Files | LOC | What it is |
|---|---:|---:|---|
| `src/exec/` | 10 | 3,591 | the machine: domain, interpreter, registers, memory, helpers, budget |
| `src/symbolic/` | 26 | 21,459 | the symbolic domain, expression IR, explorer, solver backends, trace/replay |

Verified with `find src/exec src/symbolic -name '*.rs' | xargs wc -l`.

### `src/exec` — the machine

| File | LOC | Purpose |
|---|---:|---|
| `domain.rs` | 79 | the `Domain` trait and `BranchDecision`. The keystone. |
| `concrete.rs` | 320 | `Concrete`: `Val = u128` masked to the operation's width. |
| `interp.rs` | 1,298 | `Machine<D>`, `step()`, `run_block`, `run_function`; `Flow`/`Halt`/`Outcome`. |
| `state.rs` | 547 | `RegFile<D>`: flat canonical cells with structural sub-register aliasing. |
| `memory.rs` | 230 | `Memory<D>`: sparse 4 KiB pages of `Option<D::Val>` bytes. |
| `helpers.rs` | 526 | `HelperRegistry<D>`: `Op::Intrinsic` name → `fn(&mut Machine<D>, …)`. |
| `simproc.rs` | 135 | `SimProcRegistry<D>`: call summaries keyed by target VA. |
| `budget.rs` | 49 | instruction-count budget; `Budget::default()` is 100,000 steps. |
| `oracle.rs` | 376 | dev-only differential oracle against Unicorn (`dev-oracle`). |
| `mod.rs` | 31 | the re-exports. |

### `src/symbolic` — the symbolic half

| File | LOC | Purpose |
|---|---:|---|
| `symdomain.rs` | 393 | `Symbolic`: `Val = ExprId`. Owns the `ExprPool`. |
| `expr.rs` | 722 | the hash-consed bit-vector `Expr` DAG, SMT-LIB2 rendering, `collect_syms`. |
| `explore.rs` | 1,768 | the DFS worklist, `State`, forking, sink detection entry points. |
| `explore/detect.rs` | 655 | the detectors: overflow, UAF, memory access recording, API summaries. |
| `explore/query.rs` | 429 | concretization under policy, feasibility/controllability predicates, sink construction. |
| `explore/solve.rs` | 405 | traced solving, warm-owner lifecycle, model-choice statistics. |
| `explore/model.rs` | 249 | `TaintSpec`, `Sink`, `SinkKind`, `ApiSummary`, `CallModel`, `Severity`. |
| `explore/stats.rs` | 257 | path/limit statistics, stop-site accounting, the wall-clock deadline. |
| `ioctl.rs` | 1,666 | IRP seeding and the Windows/Linux IOCTL driver entry points. |
| `concretization.rs` | 388 | the `ConcretizationPolicy` seam and its five built-in policies. |
| `ordered_trace.rs` | 1,946 | opt-in ordered lineage/scope/model trace capture. |
| `ordered_replay.rs` | 1,120 | exact native replay of a published ordered trace (`solver-axeyum`). |
| `native_trace.rs` | 638 | deterministic native expression-DAG packs for that replay. |
| `solver/mod.rs` | 1,935 | the `solve()` seam, both traits, budgets, shadow-diff, query dumping. |
| `solver/z3_backend.rs` | 1,019 | native z3 via the `z3` crate (`solver-z3`). |
| `solver/axeyum_backend.rs` (+6 files) | 5,084 | native pure-Rust axeyum (`solver-axeyum`), with warm paths and snapshots. |
| `solver/bitwuzla_backend.rs` | 1,355 | benchmark-only Bitwuzla 0.9.1 C-API cell (`solver-bitwuzla`). |
| `solver/constraint_cache.rs` | 1,089 | bounded result caching above the backends. |
| `solver/pipe.rs` | 289 | the SMT-LIB2 subprocess fallback. |
| `mod.rs` | 52 | the re-exports. |

## The `Domain` trait

```rust
// src/exec/domain.rs
pub trait Domain {
    type Val: Clone + std::fmt::Debug;

    fn constant(&mut self, width: Width, bits: u128) -> Self::Val;
    fn binop(&mut self, op: BinOp, a: &Self::Val, b: &Self::Val, w: Width) -> Self::Val;
    fn unop(&mut self, op: UnOp, a: &Self::Val, w: Width) -> Self::Val;
    fn cmp(&mut self, op: CmpOp, a: &Self::Val, b: &Self::Val, w: Width) -> Self::Val;
    fn zext(&mut self, a: &Self::Val, from: Width, to: Width) -> Self::Val;
    fn sext(&mut self, a: &Self::Val, from: Width, to: Width) -> Self::Val;
    fn trunc(&mut self, a: &Self::Val, to: Width) -> Self::Val;
    fn extract(&mut self, a: &Self::Val, hi: u16, lo: u16) -> Self::Val;
    fn concat(&mut self, hi: &Self::Val, lo: &Self::Val, hi_w: Width, lo_w: Width) -> Self::Val;
    fn ite(&mut self, cond: &Self::Val, t: &Self::Val, e: &Self::Val, w: Width) -> Self::Val;
    fn as_branch(&mut self, cond: &Self::Val) -> BranchDecision;
    fn as_u64(&mut self, v: &Self::Val) -> Option<u64>;
}
```

Twelve methods, all pure bit-vector operations at an explicit `Width`. Three
things it deliberately does **not** have, against what the 2026-06 design
predicted: no `type Mem`, no `load`/`store`, and no `concretize_addr`. Memory is
`Memory<D>` — generic over the domain, not part of it — so one implementation
serves both. The only two places the domains legitimately diverge are
`as_branch` (`Concrete` always answers `Taken`/`NotTaken`; `Symbolic` may answer
`Fork`) and `as_u64` (`Concrete` always `Some`; `Symbolic` may decline).

The two implementations:

- **`Concrete`** — `type Val = u128`, masked to width after every operation
  (`src/exec/concrete.rs:50`). It is a zero-sized struct; there is no state.
- **`Symbolic`** — `type Val = ExprId` (`src/symbolic/symdomain.rs:93`), an index
  into an interned `ExprPool` the domain owns. **There is no concolic shadow
  value**: no `(ExprId, u128)` pair, no concrete seed carried alongside. What
  plays that role is *constant folding* — `as_branch` walks the condition's DAG
  with `Concrete`'s own arithmetic (`Symbolic::constant_value`) and returns a
  decided branch whenever the expression is symbol-free, so only a genuinely
  symbolic predicate reaches the solver.

Verified with `rg -n 'type (Mem|Val)|fn (load|store|concretize_addr)' src/exec/domain.rs src/exec/concrete.rs src/symbolic/symdomain.rs`.

## The interpreter

`Machine<D>` (`src/exec/interp.rs`) holds `regs: RegFile<D>`, `mem: Memory<D>`,
`dom: D`, a `HelperRegistry<D>` and a `SimProcRegistry<D>`. `step()` is written
once over `Domain`; `run_block` walks a `LlirBlock`; `run_function` walks a
`LlirFunction` under a `Budget`. Control leaves through three types:

- `Flow` — what one instruction did (continue, jump, halt, …).
- `Halt` — why a block stopped abnormally: `UnsupportedIntrinsic`,
  `ResidualUnknown`, `UndefinedValue`, `UnexpectedFork`, `UnresolvedAddress`,
  `BudgetExhausted`.
- `Outcome` — why whole-function execution stopped: `Returned`, `Halted(Halt)`,
  `BudgetExhausted`, `NoBlock(va)`.

`Call` and `Return` surface as control flow for the caller to drive, unless a
`SimProcRegistry` entry matches the target VA, in which case the summary applies
its effect and the call returns without entering the callee.

### Registers

`RegFile<D>` follows the flat guest-state model: one full-width canonical cell
per physical register, with every sub-register read and write expressed as
`extract`/`concat`/`zext` **through the domain**, so partial-register aliasing is
structural and identical in both modes. The partial-write rules live here rather
than in the lifter: a 64-bit write replaces the cell; a 32-bit write zeroes the
upper 32 bits; 16- and 8-bit writes preserve the unaffected high bits; `ah`/`bh`/
`ch`/`dh` write bits `[8:16)`. Two layouts exist, selected by `RegArch`
(re-exported from `ir::regview::Arch`): `X86_64` and `AArch64`. There is no
`CpuModel` trait and no `src/exec/arch/` directory.

### Memory

`Memory<D>` is a `HashMap<u64, Box<[Option<D::Val>]>>` of 4 KiB pages holding
byte-width domain values; unset bytes read as zero. Multi-byte accesses assemble
and split through `concat`/`extract` honouring endianness, with a fast path for
accesses that do not cross a page and a per-byte slow path for those that do.
There are **no permissions, no dirty-page copy-on-write, and no code pages**;
snapshots are `Machine: Clone`, which is also how the explorer forks.

### Helpers and intrinsics

Following QEMU's small-core-plus-helpers split, anything exotic lifts to
`Op::Intrinsic { name, ins, outs, reads_mem, writes_mem }` and is executed by a
registered helper rather than bloating `step()`. Helpers are plain `fn` pointers
(not closures) so the registry can be consulted and then the helper called with
`&mut Machine` without aliasing. Two default sets ship:

- `HelperRegistry::default_x86_64()` — `rdtsc`, `rdtscp`, `cpuid`, `bswap`,
  `mul`, `div`.
- `HelperRegistry::default_aarch64()` — `paciasp`, `autiasp`, `dmb`, `csdb` as
  no-ops in this single-threaded, code-integrity model; `mrs_sp_el0` returning a
  stable synthetic task base; `aarch64_{cmn,tst}{32,64}`; `bswap`;
  `byte_swap_16_lanes`.

**The sound-fallback rules are the load-bearing part, and they still hold.** An
intrinsic with no registered helper never produces a silently wrong answer:

- **Concrete mode halts** with `Halt::UnsupportedIntrinsic(name)`, so the caller
  sees exactly where coverage ran out. This is the emulator's analogue of P-code
  halting on an un-injected `CALLOTHER`.
- **Symbolic mode havocs** the *declared* outputs — each `out` becomes a fresh
  symbol — and execution continues as a sound over-approximation, which is what a
  symbolic engine wants for an unmodelled op (VEX dirty-call semantics). The
  footprint declaration (`ins`/`outs`/`reads_mem`/`writes_mem`) is precisely what
  makes that fallback sound for dataflow and taint even with an opaque body.

Determinism is a house rule enforced here: `rdtsc`/`rdtscp` read a **virtual**
monotonic counter and `cpuid` returns a **fixed** feature set — never host time
or host CPU state.

SIMD, x87, software FP, atomics and the ARM64 scalar set are **not** covered.
The coverage roadmap in the 2026-06 design remains unfinished; a corpus that
runs to completion with zero `UnsupportedIntrinsic` halts does not exist.

### Budgets, deadlines, and the determinism rule

There are three independent limits, and they are not all instruction counts:

| Limit | Where | Default |
|---|---|---|
| instructions retired | `exec::Budget` | 100,000 (`Budget::default`) |
| per-function wall clock | `solver::set_time_budget` → `explore::run_worklist`'s `DEADLINE`, checked per instruction | unset |
| per-check solver wall clock | `solver::check_timeout()`, `GLAURUNG_CHECK_TIMEOUT_MS` | 250 ms (max 60,000) |
| per-function solving work | `DEFAULT_SOLVER_BUDGET` | `(6,000 solves, 24 timeouts)` |
| per-block revisits | `explore::MAX_BLOCK_VISITS` | 8 |

The 2026-06 determinism note said budgets are instruction counts "**not**
timeouts, for the deterministic core". That is true of `exec::Budget` and of the
solve/timeout counters, and it is *not* true of the two wall clocks. The honest
rule is narrower: **the concrete core is deterministic; the symbolic explorer is
deterministic only for a fixed deadline.** A run that trips a wall clock records
that it did — `run_worklist` returns a `WorklistStop` naming the reason and
`DEADLINE_OBSERVED` distinguishes a deadline stop from a state-cap stop — so a
nondeterministic result is always labelled as one rather than silently mixed in
with a completed exploration. Anything comparing two runs must fix the deadline
or compare stop reasons first.

Verified with `rg -n 'MAX_BLOCK_VISITS|DEFAULT_SOLVER_BUDGET|DEFAULT_CHECK_TIMEOUT_MS|fn deadline_passed|DEADLINE_OBSERVED' src/symbolic src/exec`.

## The explorer

`explore::run_worklist` is a **DFS worklist**: a `Vec<State>` popped LIFO, each
`State` owning a cloned `Machine<Symbolic>`, its path condition
(`Vec<(ExprId, bool)>`), its `TaintSpec`, and its trace handle. A symbolic branch
forks; a concrete branch follows deterministically.

The two prunings that matter:

- **Constant folding at the branch.** `as_branch` decides symbol-free conditions
  without a solve at all.
- **Symbol disjointness.** `can_skip_feasibility_check(st, pred)`
  (`explore/query.rs:319`) collects the predicate's free symbols and the path
  condition's; when they do not intersect *and* the predicate is not symbol-free,
  either polarity is independently satisfiable and the feasibility solve is
  skipped. A symbol-free expression is deliberately **not** admitted: a syntactic
  `Fork` does not prove a constant DAG satisfiable, and admitting it would
  preserve infeasible paths. The sibling `unconstrained()` does the same test for
  sink severity and null-deref probes.

There is **no directed search**: no `BinaryHeap`, no distance-to-sink, no
random-path tie-break. Verified with `rg -n 'BinaryHeap|dist_to_sink' src/symbolic`
(no hits). Ordering is insertion order into the worklist, which makes a run
reproducible but means the first witness found is not the shallowest.

Entry points: `find_input_reaching`, `find_sinks`, `find_sinks_with_arch`,
`find_sinks_stateful`.

### `ioctl.rs`

The symbolic successor to the static [`ioctl_taint`](ioctl-taint.md) pass: that
pass cheaply *nominates* candidate sinks, this one *confirms* reachability and
emits a concrete input witness. `seed_irp` mints fresh symbols for the WDM IRP
fields at fixed concrete bases — `AssociatedIrp.SystemBuffer` (`Irp+0x18`),
`UserBuffer` (`Irp+0x30`), `Tail.Overlay.CurrentStackLocation` (`Irp+0xB8`), and
off the stack location `OutputBufferLength` (`+0x08`), `InputBufferLength`
(`+0x10`), `IoControlCode` (`+0x18`), `Type3InputBuffer` (`+0x20`) — the same
offsets and the same dispatch ABI (`rcx` = DeviceObject, `rdx` = Irp on x64) that
`ioctl_taint` uses. `seed_linux_ioctl` and `seed_tainted_args` are the Linux and
generic-function equivalents. `find_arbitrary_writes`, `find_ioctl_sinks`,
`find_linux_ioctl_sinks` and their `_with_apis` variants are the public surface.

### Tracing and replay

Three modules exist only to make solver behaviour independently checkable:

- **`ordered_trace.rs`** — opt-in, enabled by `GLAURUNG_ORDERED_TRACE_DIR`.
  Where the ordinary query dump is content-deduplicated (good for cold
  benchmarking, useless for warm reasoning), this preserves path, scope,
  occurrence, and model-choice order. A producer writes a hidden temporary
  directory and publishes it with **one atomic rename**, only after every path is
  terminal and every repeated decided query agrees.
- **`native_trace.rs`** — deterministic typed expression-DAG packs beside the
  SMT-LIB payload, so a replay can drive the production native adapter without
  reparsing text or weakening sort checks. SMT-LIB stays the authoritative,
  cross-tool identity.
- **`ordered_replay.rs`** (`solver-axeyum`) — replays a published trace through
  the production `solve_for_path_delta` adapter in observation order,
  reconstructing source-prefix identity and serial owner leases.

`solver/constraint_cache.rs` is the bounded result cache above the backends
(`GLAURUNG_ENGINE_CONSTRAINT_CACHE`).

## Feature gates: which build compiles what

```
default              = ["triage-core"]
python-ext           = ["pyo3", "pyo3/extension-module", "exec"]
exec                 = []                              # pure Rust
symbolic             = ["exec"]                        # pure Rust
dev-oracle           = ["exec", "dep:unicorn-engine"]  # links system libunicorn
solver-z3            = ["symbolic", "dep:z3"]
solver-axeyum        = ["symbolic", "dep:axeyum-solver", "dep:axeyum-ir"]
solver-bitwuzla      = ["symbolic"]                    # BITWUZLA_LIB_DIR via build.rs
solver-axeyum-text   = ["solver-axeyum", "axeyum-solver/full"]
```

`src/lib.rs:75` gates `exec`, `:80` gates `symbolic`, `:93` gates
`python_bindings`. Two consequences worth stating plainly:

- **The wheel ships the emulator and no solver.** `python-ext` pulls `exec`, so
  `glaurung.engine` exists in an ordinary wheel; `symbolic` is in neither
  `default` nor `python-ext`, so neither the `Expr` IR nor any backend is
  compiled into the extension module.
- **`cargo test --features python-ext` compiles none of `src/symbolic`.** Those
  21,459 lines need `--features symbolic` (or a `solver-*` feature) to be built
  at all, which is why the CI lane and the feature gate below exist.

Verified with `sed -n '/^\[features\]/,/^\[/p' Cargo.toml` and
`rg -n 'cfg\(feature' src/lib.rs`.

## Python surface

One function.

```python
import glaurung
glaurung.engine.emulate_function(binary_path, entry_va, arch="x86_64", max_steps=100000)
# -> {"outcome": …, "detail": …, "steps": …, "regs": {name: int, …}}
```

`src/python_bindings/exec.rs` registers the submodule as `engine` (not `exec`,
which would shadow the Python builtin) and adds exactly one function;
`python/glaurung/__init__.py:126` surfaces it when the extension was built with
it. There is no `Emulator` class, no `find_inputs`, no memory API, no hooks. The
generated stub is `python/glaurung/_native/engine.pyi`.

There is **no CLI command** for the engine: `glaurung emulate` and
`glaurung find-inputs` do not exist, and none of the modules in
`python/glaurung/cli/commands/` provides one.

## Tests and gates

| What | Count / command |
|---|---|
| `#[test]` in `src/exec/` | 76 |
| `#[test]` in `src/symbolic/` | 195 |
| Python tests | 6 in `python/tests/test_exec_engine.py` |
| CI lane | `cargo test --features symbolic` (`.github/workflows/test-suite.yml`), with a guard step that fails the job if fewer than a floor of `symbolic::` tests are even *listed* |
| Feature type-check | `scripts/feature-build-gate.sh` — 12 `cargo check --all-targets` lanes including `exec`, `symbolic`, `solver-z3`, `solver-axeyum`, `solver-axeyum-text`, `solver-bitwuzla`, `solver-z3,solver-axeyum`, and `--all-features` |
| Differential oracle | `cargo test --features dev-oracle` — `src/exec/oracle.rs` runs real x86-64 bytes through both our decode→lift→`run_block` path and Unicorn and reports disagreeing GPRs. Flags are deliberately not compared: we model condition-code registers, not raw EFLAGS. **Unicorn is not ground truth** — it is known to diverge from ARM silicon — so a divergence is a question, not a verdict. |

Counted with `rg -c '#\[test\]' -g '*.rs' src/exec src/symbolic`.

## Not built

Stated explicitly, because the 2026-06 design tree specifies all of it and a
reader arriving from there will look for it:

| Absent | Design source |
|---|---|
| `src/exec/hooks.rs` — Unicorn-style per-instruction/memory hooks | `machine-state.md` |
| dirty-page copy-on-write snapshots, memory permissions, code pages | `machine-state.md` |
| `src/exec/liftcache.rs` — the "cached" half of "cached IR interpreter" | `machine-state.md`, [exec-0003](../decisions/exec-0003-interpreter-not-jit.md) |
| `src/os/` — `OsLayer`, syscall tables, libc/Win32 summary sets | `os-abi-layer.md` |
| `src/exec/arch/` and a `CpuModel` trait | `arch-abstraction.md` |
| `src/symbolic/{symstate,symmem,cache}.rs` | `symbolic-engine.md` |
| directed search (ICFG distance ordering), veritesting, state merging | `symbolic-engine.md`, [exec-0006](../decisions/exec-0006-execution-mode.md) |
| the 1024-byte ITE-tree symbolic read path | [exec-0004](../decisions/exec-0004-symbolic-memory.md) |
| `tests/fixtures/exec/{corpus,slices,constraints,decrypt,drivers}` | `fixtures-and-corpus.md` |
| `glaurung emulate` / `glaurung find-inputs` CLI commands | `phases/phase-6-pyo3-and-agent-tools.md` |
| SIMD, x87, software FP, atomics, ARM64 scalar helper coverage | `helpers-and-intrinsics.md` |

Verified with `ls src/exec src/symbolic` (`src/os` and `tests/fixtures/exec` do
not exist) and `rg -n 'liftcache|CpuModel|symmem|symstate' src/`, whose only hits
are two comments in `src/ir/types.rs` naming `CpuModel` as future work.

## Where the rest of the story is

- Solver backends, their features and build requirements:
  [`solver-backends.md`](solver-backends.md).
- The static pass this engine confirms: [`ioctl-taint.md`](ioctl-taint.md).
- The six decisions, with their rejected alternatives:
  [`decisions/`](../decisions/README.md) (`exec-0001` … `exec-0006`).
- The literature the design came from:
  [`design/execution-engine-research/`](../design/execution-engine-research/).
- The 2026-06 design tree as written, including the parts never built:
  [`history/execution-engine-2026-06/`](../history/execution-engine-2026-06/).

---

## Appendix A — the prototype that validated the keystone

The `Domain` idea was proved before any of this existed, by a standalone
`rustc -O` program in which one `step()` drove both a concrete run and a
symbolic-term-building run. This is the only surviving copy; the scratch file is
gone. Abridged:

```rust
trait Domain { type Val: Clone;
    fn constant(&mut self,w:u16,b:u128)->Self::Val;
    fn add(&mut self,a:&Self::Val,b:&Self::Val,w:u16)->Self::Val;
    fn eq (&mut self,a:&Self::Val,b:&Self::Val,w:u16)->Self::Val; /* … */ }

// Concrete backend (the emulator): Val = u128 masked to width
impl Domain for Concrete { type Val=u128;
    fn add(&mut self,a:&u128,b:&u128,w:u16)->u128 { a.wrapping_add(*b) & mask(w) }
    fn eq (&mut self,a:&u128,b:&u128,_:u16)->u128 { (a==b) as u128 } /* … */ }

// Symbolic backend: Val = SMT-LIB2 term string
impl Domain for Symbolic { type Val=String;
    fn add(&mut self,a:&String,b:&String,_:u16)->String { format!("(bvadd {a} {b})") }
    fn eq (&mut self,a:&String,b:&String,_:u16)->String { format!("(ite (= {a} {b}) (_ bv1 1) (_ bv0 1))") } }

// ONE interpreter, generic over Domain — never duplicated.
fn step<D:Domain>(m:&mut Machine<D>, op:&Op) { /* match op { … } */ }
```

Output:

```
CONCRETE: ebx=0x100 zf=1
SYMBOLIC zf term: (ite (= (bvadd rax_sym (_ bv1 32)) (_ bv256 32)) (_ bv1 1) (_ bv0 1))
```

The shipped trait kept the shape and widened it: `Width` instead of `u16`, the
full operator set instead of `add`/`eq`, and an interned `ExprId` instead of a
formatted string. `Symbolic::render` still emits exactly that SMT-LIB2 form.

## Appendix B — what the June obfuscation work taught

The engine's bounds are not arbitrary; they were set by a two-day push in June
2026 to make it terminate on heavily obfuscated Windows drivers, and the account
of that work exists only in
[`history/execution-engine-2026-06/STATUS.md`](../history/execution-engine-2026-06/STATUS.md).
`ilp60x64_3.sys` ran unboundedly; the fix was three-sided — a cheap CFG back-edge
metric to *detect* flattening, a per-block revisit cap
(`MAX_BLOCK_VISITS = 8`, borrowed from IOCTLance's `LoopSeer`) to bound path
re-entry, and a per-function solve/timeout budget with the *timeout count* as the
obfuscation signal — which took that driver from never-finishing to a clean 57
seconds and let `RtDashPt.sys` produce its ground-truth null-deref in nine. The
same worklog records the z3 `SortDiffers` crash on non-1-bit predicates, the
exponential `collect_syms`/`to_bv` recursion that had no visited set until it was
memoized, and the honest precision limitation that motivated everything in
[`solver/taint-provenance.md`](solver/taint-provenance.md): 306 raw
arbitrary-write rows against 19 ground-truth ones. Read it before assuming a
bound can simply be raised.
