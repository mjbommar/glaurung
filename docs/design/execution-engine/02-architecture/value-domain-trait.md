# The `Domain` Trait — The Keystone

> One interpreter, parameterized by an abstract value domain. The concrete
> emulator and the symbolic executor are two `impl`s of `Domain`; the `step()`
> function is written **once**. This is the single most important design decision
> (angr/claripy, Triton, BINSEC, Miasm all converged on it).

## Validated by prototype

A standalone Rust prototype (compiled with `rustc -O`, runs clean) implements this
trait twice — `Concrete` (wrapping `u128`+width) and `Symbolic` (SMT-LIB2 term
strings) — behind a single generic `step()`. Output:

```
CONCRETE: ebx=0x100 zf=1
SYMBOLIC zf term: (ite (= (bvadd rax_sym (_ bv1 32)) (_ bv256 32)) (_ bv1 1) (_ bv0 1))
  -> path constraint to reach zf==1: (= <that term> (_ bv1 1))
OK: one step() function drove BOTH a concrete emulator and a symbolic executor.
```

The same instruction sequence produced a correct concrete result **and** a
solver-ready symbolic constraint, with zero duplicated interpreter logic. The
prototype source is reproduced in
[`../03-phases/phase-1-concrete-emulator.md`](../03-phases/phase-1-concrete-emulator.md#prototype).

## The trait

```rust
/// A typed bit-vector value domain. Implementors define what a "value" is and how
/// the bit-vector primitives behave; the interpreter is generic over this.
pub trait Domain {
    /// The value type: u128+width for Concrete; an interned Expr id for Symbolic.
    type Val: Clone;

    // construction
    fn constant(&mut self, width: Width, bits: u128) -> Self::Val;

    // bitvector arithmetic/logic — all modular at `w`
    fn binop(&mut self, op: BinOp, a: &Self::Val, b: &Self::Val, w: Width) -> Self::Val;
    fn unop(&mut self, op: UnOp, a: &Self::Val, w: Width) -> Self::Val;

    // width changes (total, explicit)
    fn zext(&mut self, a: &Self::Val, from: Width, to: Width) -> Self::Val;
    fn sext(&mut self, a: &Self::Val, from: Width, to: Width) -> Self::Val;
    fn trunc(&mut self, a: &Self::Val, to: Width) -> Self::Val;
    fn extract(&mut self, a: &Self::Val, hi: u16, lo: u16) -> Self::Val;
    fn concat(&mut self, hi: &Self::Val, lo: &Self::Val) -> Self::Val;

    // predicates → 1-bit Val (flags)
    fn cmp(&mut self, op: CmpOp, a: &Self::Val, b: &Self::Val, w: Width) -> Self::Val;
    fn ite(&mut self, c: &Self::Val, t: &Self::Val, e: &Self::Val, w: Width) -> Self::Val;

    // memory — delegated to the memory model, which is itself domain-aware
    fn load(&mut self, mem: &mut Self::Mem, addr: &Self::Val, size: u8, endian: Endian) -> Self::Val;
    fn store(&mut self, mem: &mut Self::Mem, addr: &Self::Val, val: &Self::Val, size: u8, endian: Endian);
    type Mem;

    // control-flow decisions — the interpreter must turn a Val into a branch choice
    /// Concrete: returns Some(bool) always. Symbolic: Some if the bit is constant
    /// under the path condition; None means "both successors feasible" → fork.
    fn as_branch(&mut self, cond: &Self::Val) -> BranchDecision;

    /// Concrete address for an indirect jump / load address when one is needed.
    /// Concrete: the value. Symbolic: a concretization (per strategy) + a recorded
    /// constraint binding the symbolic addr to the chosen concrete value.
    fn concretize_addr(&mut self, v: &Self::Val) -> u64;
}

pub enum BranchDecision { Taken, NotTaken, Fork }
```

> Note: associated type ordering is illustrative; the real definition will place
> `type Mem` near the top. `as_branch`/`concretize_addr` are where concrete and
> symbolic semantics legitimately diverge — and they are the *only* such seams.

## The single interpreter

```rust
pub fn step<D: Domain>(m: &mut Machine<D>, op: &Op) -> Result<Flow, ExecError> {
    match op {
        Op::Bin { dst, op, lhs, rhs, width } => {
            let (a, b) = (m.read(lhs, *width), m.read(rhs, *width));
            let r = m.dom.binop(*op, &a, &b, *width);
            m.write(dst, r);
            Ok(Flow::Next)
        }
        Op::CondJump { cond, target, inverted } => {
            let c = m.read_reg(cond, Width(1));
            match m.dom.as_branch(&c) {
                BranchDecision::Taken    if !inverted => Ok(Flow::Jump(*target)),
                BranchDecision::NotTaken if  inverted => Ok(Flow::Jump(*target)),
                BranchDecision::Fork => Ok(Flow::Fork { cond: c, target: *target, inverted: *inverted }),
                _ => Ok(Flow::Next),
            }
        }
        Op::Intrinsic { name, .. } => m.helpers.dispatch(name, m, op),
        // … one arm per Op, written once …
    }
}
```

`Flow::Fork` is meaningful only in symbolic mode; the concrete `Domain` never
returns `BranchDecision::Fork`, so the emulator's loop never sees it (a debug
assert enforces this). This is how **one** function serves both modes.

## The three implementations

| Domain | `Val` | Used for | Phase |
|---|---|---|---|
| `Concrete` | `(u128, Width)`, masked to width | the emulator | 1 |
| `Symbolic` | interned `ExprId` into a hash-consed bitvector AST | concolic/symbolic | 4 |
| `Interval`/`VSA` (optional, later) | strided interval | fast abstract pre-analysis, jump-table bounds | future |

A **concolic** mode is `Symbolic` carrying a concrete value alongside each `Expr`
(Triton's model): `Val = (ExprId, u128)`. `as_branch` uses the concrete bit to
pick the direction *and* records the constraint; forking is optional/directed.
See [`symbolic-engine.md`](symbolic-engine.md).

## Why a trait and not an enum of value kinds

- Monomorphization → the concrete emulator compiles to tight code with no dynamic
  dispatch in the hot loop (an enum would branch on value-kind every op).
- The symbolic backend's heavier machinery (interning, solver handles) never costs
  the concrete path anything.
- New domains (interval, taint) are added without touching the interpreter.

Trade-off: the interpreter is generic, so it's compiled once per domain (code
size) and the memory model must also be domain-parameterized (`type Mem`). Both
are acceptable and validated by the prototype.

## References
- [`../01-research/ir-design-lessons.md`](../01-research/ir-design-lessons.md) §6
- [`../05-decisions/adr-0001-single-domain-core.md`](../05-decisions/adr-0001-single-domain-core.md)
