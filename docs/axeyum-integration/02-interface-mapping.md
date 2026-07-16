# 02 - Interface mapping

The precise, total translation between glaurung's symbolic IR + solver
trait and axeyum's public API. This is the contract the `axeyum_backend`
implements. Every glaurung construct has a defined axeyum image; there is
no "unsupported" path at the IR level (only engine-level timeout/resource
-> `Unknown`).

## Crates and entry points

| role | glaurung | axeyum |
|---|---|---|
| build BV terms | `symbolic::expr::{Expr, ExprPool, ExprId}` | `axeyum-ir`: `TermArena`, `TermId`, `Sort`, `SymbolId`, `Value` |
| assert + solve | `Solver::check(pool, asserts)` | `axeyum-solver`: `IncrementalBvSolver::{assert, check}`, `CheckResult`, `Model` |
| text bridge (MVP) | `pipe::build_script` (renders SMT-LIB2) | `axeyum-solver::solve_smtlib(&str, &SolverConfig) -> SmtLibOutcome` |
| unsat proof | (none today) | `axeyum-solver::export_qf_bv_unsat_proof(arena, &[TermId]) -> UnsatProofOutcome` |

Minimum dependency for the native backend: **`axeyum-ir` + `axeyum-solver`**
(rest transitive). `axeyum-smtlib` only if we parse text ourselves - we do
not (the MVP hands text straight to `solve_smtlib`).

## The one type-system subtlety: Bool vs BitVec(1)

This is the only non-mechanical part of the mapping, so it is stated
first.

- **glaurung is uniformly BV-typed.** Every `Expr` node has a `Width`.
  A `Cmp` node has width 1 (a BV1), and that BV1 can flow anywhere a BV
  operand is expected (e.g. as an `Ite` condition, or concatenated).
  Asserts test arbitrary-width truthiness: every backend lowers expected-true
  as `e != 0` and expected-false as `e == 0`, using `e`'s actual width. Most
  branch predicates are BV1, but concretization/probe callers can assert a
  wider value directly.
- **axeyum separates `Sort::Bool` from `Sort::BitVec(1)`** with no implicit
  coercion, and `IncrementalBvSolver::assert` requires a **`Bool`** term
  (else `SolverError::NonBooleanAssertion`). axeyum's comparison builders
  (`eq`, `bv_ult`, `bv_slt`, ...) return **`Bool`**; `bv_comp` returns
  `BitVec(1)`.

**Resolution - translate every glaurung `Expr` to an axeyum `BitVec(width)`
term uniformly, and bridge to `Bool` only at two boundaries:**

1. **A glaurung `Cmp`** translates to axeyum's Bool-returning compare, then
   is lifted back to a `BitVec(1)` so it composes like glaurung expects:
   `bv1(cond_bool) := ite(cond_bool, bv_const(1,1), bv_const(1,0))`.
   (Equality specifically may use axeyum `bv_comp(a,b)` directly, which is
   already `BitVec(1)`; either is fine as long as it round-trips.)
2. **A glaurung `Ite` condition** (a BV1) is converted to Bool for axeyum's
   `ite`, which wants a Bool condition:
   `bool(c_bv1) := not(eq(c_bv1, bv_const(1,0)))`  (i.e. `c != 0`).
3. **A top-level assert** `(ExprId e, bool expected)` becomes the axeyum Bool
   `not(eq(T(e), bv_const(width(e), 0)))` when expected is true, or
   `eq(T(e), bv_const(width(e), 0))` when expected is false. This exactly
   mirrors z3 and remains well-sorted for BV1 and wider asserted values.

Everywhere else the translation stays in BitVec, so glaurung's uniform-BV
discipline is preserved and only these three boundaries touch Bool.

## Operator mapping (total)

`T(e)` = axeyum `BitVec` term for glaurung `ExprId e`, memoized on `ExprId`
(preserve hash-consing -> shared subterms bit-blast once, the warm win).
All axeyum builders are `arena.<op>(...) -> Result<TermId, IrError>`.

### Leaves

| glaurung `Expr` | axeyum builder |
|---|---|
| `Const{value, width}` | `arena.bv_const(width.bits(), value)` (u128; `wide_bv_const` if width > 128) |
| `Sym{id, width}` | `arena.bv_var(sym_name(id,width), width.bits())`; record `id -> SymbolId` for model read-back |

`sym_name(id,width)` = glaurung's `"sym{id}_{bits}"` convention
(`ExprPool::sym_name`) - reused so names are stable and debuggable.

### `Bin{op, a, b, width}`  ->  `arena.bv_<op>(T(a), T(b))`

| glaurung `BinOp` | axeyum builder | note |
|---|---|---|
| `Add` | `bv_add` | |
| `Sub` | `bv_sub` | |
| `Mul` | `bv_mul` | |
| `Div` | `bv_udiv` | glaurung Div is **unsigned only** (no signed div/rem exists) |
| `And` | `bv_and` | |
| `Or` | `bv_or` | |
| `Xor` | `bv_xor` | |
| `Shl` | `bv_shl` | |
| `Shr` | `bv_lshr` | **logical** right shift |
| `Sar` | `bv_ashr` | **arithmetic** right shift |

### `Un{op, a, width}`

| glaurung `UnOp` | axeyum builder |
|---|---|
| `Not` | `bv_not` |
| `Neg` | `bv_neg` |

### `Cmp{op, a, b}`  ->  Bool builder, then lift to BitVec(1) (see subtlety)

| glaurung `CmpOp` | axeyum Bool builder | then |
|---|---|---|
| `Eq`  | `eq(T(a),T(b))`   | lift to bv1 (or use `bv_comp`) |
| `Ne`  | `not(eq(T(a),T(b)))` | lift to bv1 |
| `Ult` | `bv_ult(T(a),T(b))` | lift to bv1 |
| `Ule` | `bv_ule(T(a),T(b))` | lift to bv1 |
| `Slt` | `bv_slt(T(a),T(b))` | lift to bv1 |
| `Sle` | `bv_sle(T(a),T(b))` | lift to bv1 |

glaurung emits **only** lt/le (the lifter canonicalizes gt/ge away), so
axeyum's `bv_ugt/uge/sgt/sge` are never needed. `lift to bv1` =
`ite(bool, bv_const(1,1), bv_const(1,0))`.

### Structural

| glaurung `Expr` | axeyum builder | note |
|---|---|---|
| `ZExt{a, from, to}` | `zero_ext(to.bits()-from.bits(), T(a))` | axeyum takes the *extra* bit count |
| `SExt{a, from, to}` | `sign_ext(to.bits()-from.bits(), T(a))` | ditto |
| `Trunc{a, to}` | `extract(to.bits()-1, 0, T(a))` | low `to` bits |
| `Extract{a, hi, lo}` | `extract(hi, lo, T(a))` | result width `hi-lo` (glaurung) - confirm axeyum's inclusive/exclusive convention in P2 unit test |
| `Concat{hi, lo, ..}` | `concat(T(hi), T(lo))` | high operand first (SMT-LIB order); verify operand order in P2 |
| `Ite{c, t, e, width}` | `ite(bool(T(c)), T(t), T(e))` | `c` is BV1 -> Bool via `not(eq(c,0))` |

Two conventions to pin with a unit test in P2 (not assumed): axeyum's
`extract(hi,lo,..)` bit-index inclusivity, and `concat` operand order
(which half is the high bits). Both are checked against z3 on a hand-built
formula, so a wrong guess fails loudly rather than silently.

## Width handling

- glaurung `Width` is an arbitrary `u16` bit count (not only powers of
  two); axeyum accepts BV widths up to 2^16, so every glaurung width is
  representable.
- **Mirror z3's `coerce`**: the z3 backend normalizes operands to each
  node's declared width (`z3_backend.rs:98`) because the pipe/`render`
  path does not coerce. The axeyum translator should coerce identically
  (zero-extend/truncate an operand to the node's declared width before
  applying the op) so the two backends agree by construction. See `05` R3.

## Assert + check flow (native backend)

```
fn check(&mut self, pool, asserts) -> SolveResult:
    let mut arena = TermArena::new();
    let mut solver = IncrementalBvSolver::with_config(
        SolverConfig::new().with_timeout(Duration::from_millis(250)));  // match z3
    let mut memo: HashMap<ExprId, TermId>;
    let mut sym_map: HashMap<u32 /*glaurung Sym id*/, SymbolId>;
    for (e, expected) in asserts:
        let t = translate(e)               // -> BitVec(1)
        let a = arena.eq(t, arena.bv_const(1, expected as u128))  // Bool
        solver.assert(&arena, a)?          // NonBooleanAssertion impossible: `a` is Bool
    match solver.check(&arena):
        Sat(model)  -> SolveResult::Sat(read_model(model, sym_map))
        Unsat       -> SolveResult::Unsat   // (+ optional proof, Phase 3)
        Unknown(_)  -> SolveResult::Unknown
    // any Result::Err(SolverError) or IrError -> SolveResult::Error(msg)
```

One-shot contract: the current `Solver` trait re-passes the full assert
list each call, so the native backend builds a **fresh arena + solver per
`check`** (mirroring z3_backend's fresh per-call solver). This does NOT
exploit axeyum's warm incrementality - that is the P5 incremental-trait
work, where glaurung push/pops as it forks. Correct now; faster later.

## Result + model mapping

| axeyum | glaurung `SolveResult` |
|---|---|
| `CheckResult::Sat(model)` | `Sat(Model{values})` |
| `CheckResult::Unsat` | `Unsat` |
| `CheckResult::Unknown(UnknownReason)` | `Unknown` (metered as timeout by `solve()`) |
| `Err(SolverError)` / `Err(IrError)` | `Error(msg)` |
| (backend never compiled) | `NoSolver` |

Model read-back: for each `(glaurung_id, SymbolId)` in `sym_map`,
`model.get(SymbolId)` -> `Value::Bv{value, ..}` -> insert
`values[glaurung_id] = value` (u128). `Value::Wide` (> 128-bit) cannot fit
glaurung's `u128` model slot - document + skip (see `05` R4; does not
occur for <=128-bit inputs, which is all real IOCTL data). This is a
**strict improvement** over the existing backends, which cap at
`as_u64()` (64-bit).

## Unsat proof (Phase 3)

The warm `check()` returns bare `Unsat` (no proof). To obtain a
DRAT-checked certificate, re-run the one-shot exporter over the same
assertion terms:

```
export_qf_bv_unsat_proof(&arena, &assertion_term_ids) -> UnsatProofOutcome
  Proved(UnsatProof{ dimacs, drat, lrat })  // in-memory text
  Satisfiable | Inconclusive
UnsatProof::recheck() -> Result<bool, _>    // independent RUP+RAT re-check, no solver
```

Scope caveat to record in any verdict that cites it: the DRAT certifies
the **clausal (CNF) layer**; the term->AIG->CNF reduction is trusted
unless `certify_qf_bv_unsat_end_to_end` (a faithfulness miter) is used.
So a proof-carrying "path infeasible" claim is "CNF-unsat DRAT-checked",
strengthenable to end-to-end-certified if we opt into the miter.

## What axeyum offers that glaurung does not yet use (future seams)

- Incremental `push`/`pop`/`assert` + `check_assuming_core` (unsat-core
  path pruning) -> the P5 incremental trait.
- `block_model` all-SAT enumeration -> if glaurung ever wants
  multi-model / input-diversification (it does not today).
- `check_with_memory` (SMT arrays) -> only if glaurung ever models memory
  as arrays instead of concretizing (it does not today).
- `with_timeout` per check -> used from v1 to honor the 250 ms budget.
