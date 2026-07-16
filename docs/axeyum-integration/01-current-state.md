# 01 - Current state (ground truth)

Exact interfaces both sides, captured 2026-07-13. glaurung working tree on
branch `sec/ioctlance-parity` (the solver/symbolic code is identical on
`master`; line numbers below are from that working tree). axeyum at
workspace `0.1.0`, edition 2024.

---

## A. Glaurung: the solver + symbolic surface

### A.1 The single integration seam

Everything routes through one free function (NOT the trait directly):

```rust
// src/symbolic/solver/mod.rs:106
pub fn solve(pool: &ExprPool, asserts: &[Assert]) -> SolveResult
```

which compile-time-selects a backend (`mod.rs:109-119`): `solver-z3` ->
`Z3Solver`, else `PipeSolver`. It also meters every call (per-thread solve
/ timeout counters) so the explorer can bound work
(`DEFAULT_SOLVER_BUDGET = (6000, 24)`). **A native axeyum backend must be
wired inside `solve()`** so metering + budgets still apply.

### A.2 The `Solver` trait (one method, one-shot, non-incremental)

```rust
// src/symbolic/solver/mod.rs:46
pub trait Solver { fn check(&mut self, pool: &ExprPool, asserts: &[Assert]) -> SolveResult; }
pub type Assert = (ExprId, bool);                 // :45  arbitrary-width BV truthiness
pub struct Model { pub values: BTreeMap<u32,u128> } // :22  Sym id -> value
pub enum SolveResult { Sat(Model), Unsat, Unknown, NoSolver, Error(String) } // :28
```

No push/pop, assumptions, unsat-core, or get-value in the trait. `Sat`
already carries the full model. Each call is stateless over the whole
assert list.

### A.3 The BV IR (`src/symbolic/expr.rs`)

Hash-consed DAG; `ExprId(u32)` indexes an `ExprPool`
(`nodes`, `intern`, `next_sym`). 11 node variants (`expr.rs:19-80`):
`Const{value:u128,width}`, `Sym{id:u32,width}`, `Bin{op:BinOp,a,b,width}`,
`Un{op:UnOp,a,width}`, `Cmp{op:CmpOp,a,b,width}` (result width 1),
`ZExt{a,from,to}`, `SExt{a,from,to}`, `Trunc{a,to}`,
`Extract{a,hi:u16,lo:u16}`, `Concat{hi,lo,hi_w,lo_w}`, `Ite{c,t,e,width}`.
Every node carries an explicit `Width(u16)` (`ir::types`). Pure QF_BV:
**no arrays, no UF, no floats.** Operators:
`BinOp`={Add,Sub,Mul,Div(unsigned),And,Or,Xor,Shl,Shr(logical),Sar(arith)},
`UnOp`={Not,Neg}, `CmpOp`={Eq,Ne,Ult,Ule,Slt,Sle} (lt/le only). Reference
lowering to mirror: `z3_backend.rs:112-199` (+ `coerce` width-normalization
`:98`).

### A.4 How the engine drives it (`src/symbolic/explore.rs`)

Path condition is a growing `Vec<Assert>` per `State`, re-passed whole to
`solve()` each query. DFS worklist; state fork = deep `Machine<Symbolic>`
clone (own `ExprPool` copy). Canonical call site = branch feasibility
(`process_block`, `:596-618`): push `(cond, bit)`, keep the branch unless
`solve(...) == Unsat` (Unknown/NoSolver kept as sound over-approximation);
`shares_symbols` skips the solve when the new predicate shares no free
symbol with the path condition. Other call sites: `find_input_reaching`,
`concretize_addr` (address concretization - **symbolic memory is
concretized, never SMT arrays**), `witness_for_value`, `check_int_overflow`.
No all-SAT / model enumeration.

### A.5 Backends today

- `z3_backend::Z3Solver` (feature `solver-z3`): in-process, **links libz3
  (C/C++)**, `z3` crate 0.12, 250 ms/solve timeout, fresh solver per call,
  memoized DAG->AST translation, asserts lowered as `bv != 0`, model via
  `as_u64()` (**drops > 64-bit symbols**).
- `pipe::PipeSolver` (always compiled inside `symbolic`): SMT-LIB2 over a
  subprocess. Emits `(set-logic QF_BV)`, `(declare-const sym{id}_{w} (_ BitVec w))`,
  expected-true as `(assert (distinct <term> (_ bv0 w)))`, expected-false as
  `(assert (= <term> (_ bv0 w)))`, `(check-sat)`, and `(get-value ...)`.
  Solver chosen by `$GLAURUNG_SMT_SOLVER` (args `--lang smt2`), else
  bitwuzla/z3/cvc5. `build_script` is a reusable SMT-LIB serializer.

### A.6 Features (`Cargo.toml:66-89`) + shipping

`default=["triage-core"]`; `exec` (emulator); `symbolic=["exec"]`
(IR+domain+explore+ioctl+pipe solver); `solver-z3=["symbolic","dep:z3"]`;
`dev-oracle=["exec","dep:unicorn-engine"]` (DEV-ONLY x86-64 emulator
oracle); `python-ext=[...,"exec"]`. **The wheel (`python-ext`) pulls only
`exec` - the symbolic engine is not in the wheel at all today.** Backend
selection is compile-time; the only runtime knob is `$GLAURUNG_SMT_SOLVER`.

### A.7 Arch coupling (matters for G4, not the solver)

Lifter is multi-arch (`lift_arm64.rs` emits the same generic LLIR as
x86/iced), so arm64 *can* flow through the `Symbolic` domain + solver. BUT
the *detection* layer (`explore.rs`, `ioctl.rs`) hard-codes the MS x64 ABI
(`rcx/rdx/r8/r9`, `[rsp+0x20]`, `rax`, `wrmsr/rdmsr`) and x64 WDM IRP
offsets; `Machine::new(Symbolic)` defaults to `RegArch::X86_64`. So there
is no AArch64 symbolic *detection* path yet - the G4 prerequisite, and it
is glaurung-internal (solver-independent).

### A.8 Concurrency

`examples/ioctl_scan.rs` runs symbolic passes **sequentially** because the
z3 crate's shared thread-local `Context` "is not safe under
[parallelism]". A per-instance pure-Rust solver could lift that limit
(see `05` R6).

### A.9 Python

The solver/symbolic engine is **not** exposed to Python (grep-confirmed;
`python-ext` pulls only `exec`). Consumers are Rust `examples/`
(`ioctlance.rs`, `ioctl_scan.rs`, built `--features solver-z3`).

---

## B. Axeyum: the public QF_BV API

### B.1 Crates to depend on

`axeyum-ir` (build terms) + `axeyum-solver` (solve); the rest of the 19
workspace crates come transitively. `axeyum-smtlib` only if parsing text
(we do not). **All crates are `publish = false`** - depend by **path or
git**, never crates.io (`07` ADR-001). Edition 2024, MSRV rust 1.88,
`MIT OR Apache-2.0`, not `no_std` but wasm32-buildable (web-time shim), no
non-optional C deps (`cargo deny`-enforced).

### B.2 Build terms - `axeyum-ir::TermArena`

All builders `(&mut self, ...) -> Result<TermId, IrError>`, width/sort
validated. Sorts (`sort.rs:121`): `Bool` and `BitVec(u32)` are **distinct,
no coercion**. Leaves: `bv_var(name,width)` (`arena.rs:361`),
`bv_const(width,value:u128)` (`:390`), `wide_bv_const(WideUint)` (`:406`,
>128-bit). Ops (all present, mapped in `02`): `bv_add/sub/mul/udiv/urem/
sdiv/srem/smod`, `bv_and/or/xor/not/nand/nor/xnor/neg`, `bv_shl/lshr/ashr`,
`rotate_left/right`, compares `eq,bv_ult/ule/ugt/uge/slt/sle/sgt/sge`
(->Bool) and `bv_comp` (->BitVec(1)), overflow preds `bv_uaddo/...`,
`concat/extract/zero_ext/sign_ext/bv_repeat`, `ite`. `sort_of(t)` queries a
term's sort. Asserting = build a `Sort::Bool` term and hand it to the
solver (no "assert into arena").

### B.3 Solve - `axeyum-solver::IncrementalBvSolver`

Bound to one `TermArena` for its lifetime; warm (state across `check`s).
`new()` / `with_config(SolverConfig)` (only `timeout` honored on the warm
path - `SolverConfig::new().with_timeout(Duration)`). Key methods
(`incremental.rs`): `assert(&arena, term)->Result<(),SolverError>` (:605,
term must be Bool), `push`(:952)/`pop`(:972), `check(&arena)->
Result<CheckResult,_>` (:1055), `check_assuming_core(&arena,&[TermId])->
AssumptionOutcome` (:1183, path-pruning), `block_model` (:1238, all-SAT),
`check_with_memory(&mut arena)` (:999, arrays/UF - unused by glaurung).
Results:
```rust
enum CheckResult { Sat(Model), Unsat, Unknown(UnknownReason) }   // backend.rs:16
enum SolverError { NonBooleanAssertion(TermId), Unsupported(String), Backend(String), Parse(String) }
```
An undecided query is `Unknown`, **never** an error. `Model::get(SymbolId)
-> Option<Value>` (`model.rs:59`); `Value::Bv{width,value:u128}` or
`Value::Wide` (>128-bit limbs).

### B.4 Text bridge (the MVP door) - `axeyum-solver::solve_smtlib`

```rust
solve_smtlib(input: &str, config: &SolverConfig) -> Result<SmtLibOutcome, SolverError>  // smtlib.rs:1683
struct SmtLibOutcome { result: CheckResult, logic: Option<String>, expected_status: Option<String> }
```
Handles a single-query script (`set-logic`/`declare-const`/`assert`/
`check-sat`/`get-value`/push/pop). Value/model accessors:
`solve_smtlib_get_model`, `solve_smtlib_get_value`. **There is no stdin
`sat/unsat` CLI** - only the `axeyum-bench` harness binary. So the pipe
route needs either a ~20-line shim binary or (better) an in-process call to
`solve_smtlib` with glaurung's rendered script.

### B.5 Unsat proofs - `axeyum-solver::proof`

`export_qf_bv_unsat_proof(&arena, &[TermId]) -> UnsatProofOutcome`
(`proof.rs:180`); `Proved(UnsatProof{dimacs, drat, lrat})` |
`Satisfiable` | `Inconclusive`. `UnsatProof::recheck()` re-validates
(RUP+RAT) with no solver. Scope: DRAT certifies the **CNF layer**; the
term->CNF reduction is trusted unless `certify_qf_bv_unsat_end_to_end`
(faithfulness miter). The warm `check()` returns bare `Unsat` - proofs are
a separate one-shot export over the same assertions.

### B.6 Symbolic-exec layer (overlaps glaurung's - we do NOT use it)

`SymbolicExecutor` (`symexec.rs:624`), `SymbolicMemory`,
`bounded_model_check` / `prove_safety_k_induction` (`bmc.rs`). glaurung has
its own executor/explorer, so we integrate **only at the solver-query
seam** (`IncrementalBvSolver` + `Model`). This layer is a reference DFS
shape, not a dependency (ADR-003).

### B.7 Capability limits (honest)

Warm BV path supports the **full scalar QF_BV op set** - every glaurung
operator is covered. It rejects (routes to `Unsupported` or the one-shot
memory path) arrays/UF (`select/store/apply`), Int/Real, `bv2nat`/`int2bv`,
quantifiers, datatypes - **none of which glaurung emits.** So glaurung is
100% inside axeyum's warm QF_BV wheelhouse. Widths decided to 2^16.
**Performance is the open gate**: axeyum's own status is "decides a slice
of real public QF_BV; not yet perf-parity with Z3." Warm incrementality
(shared subterms blasted once, learned clauses retained) is the mitigation
and fits glaurung's many-related-queries shape. The P5 incremental trait and a
path-owned direct-delta adapter now exist, and the explorer can drive them
behind `GLAURUNG_AXEYUM_DIRECT_DELTA=1`. ADR-012's repeated ordered gate proves
its correctness and a causal win over equivalent snapshot topology, but rejects
production admission against serial snapshot on SurfacePen time and NETwtw10
RSS. ADR-013 now lands exact copy-on-write source ancestry and restores safe
serial sibling leasing for the direct candidate. Its fail-closed two-driver
traffic contract and one-process calibration are green; repeated real-driver
time/RSS admission is the remaining gate. See `05` R1.
