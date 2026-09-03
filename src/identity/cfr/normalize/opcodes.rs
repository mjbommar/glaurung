//! Pass (a): same-semantics opcode collapse.
//!
//! # The rule
//!
//! Two spellings that compute the same value become one spelling. Six
//! families, each of which a compiler picks between for reasons that have
//! nothing to do with what the program means:
//!
//! | Before | After | What varies in the wild |
//! |---|---|---|
//! | `intr:x86.smul_hi.64` | `intr:x86.smul_hi` | the operand width, which the label already carries in `width_class` |
//! | `Sub x, C` | `Add x, -C` | `sub rsp,8` against `add rsp,-8`; gcc and clang disagree at different optimisation levels |
//! | `Xor x, x`, `Sub x, x` | `Const 0` | the idiomatic zero; `xor eax,eax` against `mov eax,0` |
//! | `And x, x`, `Or x, x` | copy of `x` | the idiomatic register test |
//! | `Add x, 0`, `Mul x, 1`, `And x, -1`, `Shl x, 0`, ... | copy of `x` | fallout of the `lea` expansion, which seeds a temp with `0` when the address has no base |
//! | `ZExt/SExt/Trunc` with `from == to` | copy | a width-neutral cast the lifter emits for a register view that turns out not to narrow |
//! | `intr:x86.sdiv_quot` / `udiv_quot` | `Div lo, divisor` | a real `idiv` against the magic-multiply sequence pass (f) rewrites to the same node |
//!
//! # Precedent
//!
//! VexIR2Vec's canonicalisation rules 1 and 3, verbatim: *"same-semantics
//! opcodes collapse (`Add8|Add16|Add32` -> `Add`)"* and *"negative immediates
//! converted to positive (`add(-1,t)` -> `sub(+1,t)`)"*. The direction of the
//! `Sub`/`Add` rule here is the **opposite** of VexIR2Vec's, on purpose: this
//! representation buckets constants by magnitude class rather than keeping
//! their values, and `Add x, -C` is the form that leaves the *operator* -- the
//! part that survives into the label -- the same for both spellings.
//! Cranelift's egraph rules and LLVM's `InstCombine` fold the same identities;
//! Diaphora's `CFunc` pseudocode comparison relies on the decompiler having
//! already done it.
//!
//! # Why unsound is fine here
//!
//! `intr:x86.sdiv_quot` takes three inputs -- the high half of the dividend,
//! the low half, and the divisor -- and this pass drops the high half. That is
//! wrong as semantics: a 128-by-64 division is not a 64-by-64 division. It is
//! right as *identity*, because every C-level `a / b` compiles to a sign- or
//! zero-extension of `a` into the high half followed by the wide divide, and
//! the extension is toolchain boilerplate rather than program content. The
//! same reasoning covers `ZExt` with `from == to`: the cast is real in the IR
//! and empty in the program.
//!
//! # Bound
//!
//! One linear scan of the block. Every rule strictly reduces a well-founded
//! measure -- an `Op` becomes a simpler `Op`, never a more complex one -- and
//! no rule can re-fire on its own output, so the pass is idempotent after one
//! visit. The driver's round cap is a backstop, not the mechanism.

use crate::ir::types::{BinOp, LlirBlock, Op, VReg, Value, Width};

/// Rewrite one block in place. Returns whether anything changed.
pub fn run(block: &mut LlirBlock) -> bool {
    let mut changed = false;
    for instruction in &mut block.instrs {
        changed |= collapse(&mut instruction.op);
    }
    changed
}

fn collapse(op: &mut Op) -> bool {
    if let Some(replacement) = rewritten(op) {
        *op = replacement;
        return true;
    }
    // The width-suffix strip is in-place because it does not change the variant.
    if let Op::Intrinsic { name, .. } = op {
        if let Some(stripped) = strip_width_suffix(name) {
            *name = stripped;
            return true;
        }
    }
    false
}

/// `x86.smul_hi.64` -> `x86.smul_hi`.
///
/// Only a trailing `.<decimal digits>` is stripped, and only when what precedes
/// it is not itself empty, so a name that ends in a version-like component for
/// some other reason keeps it unless it is purely numeric.
fn strip_width_suffix(name: &str) -> Option<String> {
    let (head, tail) = name.rsplit_once('.')?;
    if head.is_empty() || tail.is_empty() || !tail.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(head.to_string())
}

fn rewritten(op: &Op) -> Option<Op> {
    match op {
        Op::Bin { dst, op, lhs, rhs } => binary(dst, *op, lhs, rhs),
        Op::ZExt {
            dst, src, from, to, ..
        }
        | Op::SExt {
            dst, src, from, to, ..
        }
        | Op::Trunc {
            dst, src, from, to, ..
        } if from == to => Some(Op::Assign {
            dst: dst.clone(),
            src: src.clone(),
        }),
        Op::Intrinsic {
            name, ins, outs, ..
        } => wide_divide(name, ins, outs),
        _ => None,
    }
}

/// The x86 wide-division intrinsic, reduced to the IR's own division node.
///
/// `ins` is `[dividend_high, dividend_low, divisor]` and `outs` is the single
/// quotient register (`wide_div_ops` in `lift_x86/wide_arith.rs`). Only the
/// quotient form is collapsed: a remainder has no single IR node to collapse
/// onto, and inventing `a - (a / b) * b` for it would manufacture three
/// features where the program has one operation.
fn wide_divide(name: &str, ins: &[Value], outs: &[(VReg, Width)]) -> Option<Op> {
    // Signedness is not distinguished: `BinOp::Div` has one spelling, and the
    // operand types the label carries do not record it either.
    if !matches!(name, "x86.sdiv_quot" | "x86.udiv_quot") {
        return None;
    }
    if ins.len() != 3 || outs.len() != 1 {
        return None;
    }
    Some(Op::Bin {
        dst: outs[0].0.clone(),
        op: BinOp::Div,
        lhs: ins[1].clone(),
        rhs: ins[2].clone(),
    })
}

fn binary(dst: &VReg, kind: BinOp, lhs: &Value, rhs: &Value) -> Option<Op> {
    let copy = |src: &Value| {
        Some(Op::Assign {
            dst: dst.clone(),
            src: src.clone(),
        })
    };
    let zero = || {
        Some(Op::Assign {
            dst: dst.clone(),
            src: Value::Const(0),
        })
    };

    // Same operand on both sides.
    if lhs == rhs && matches!(lhs, Value::Reg(_)) {
        match kind {
            BinOp::Xor | BinOp::Sub => return zero(),
            BinOp::And | BinOp::Or => return copy(lhs),
            _ => {}
        }
    }

    match (kind, lhs, rhs) {
        // Identity on the right.
        (BinOp::Add | BinOp::Sub | BinOp::Or | BinOp::Xor, _, Value::Const(0)) => copy(lhs),
        (BinOp::Shl | BinOp::Shr | BinOp::Sar, _, Value::Const(0)) => copy(lhs),
        (BinOp::Mul, _, Value::Const(1)) => copy(lhs),
        (BinOp::Div, _, Value::Const(1)) => copy(lhs),
        (BinOp::And, _, Value::Const(-1)) => copy(lhs),
        // Identity on the left, for the commutative operators only.
        (BinOp::Add | BinOp::Or | BinOp::Xor, Value::Const(0), _) => copy(rhs),
        (BinOp::Mul, Value::Const(1), _) => copy(rhs),
        (BinOp::And, Value::Const(-1), _) => copy(rhs),
        // Annihilators.
        (BinOp::Mul, _, Value::Const(0)) | (BinOp::Mul, Value::Const(0), _) => zero(),
        (BinOp::And, _, Value::Const(0)) | (BinOp::And, Value::Const(0), _) => zero(),
        // Subtraction of a constant is addition of its negation. `i64::MIN` has
        // no negation in `i64`, so that one spelling stays as it is.
        (BinOp::Sub, _, Value::Const(constant)) => constant.checked_neg().map(|negated| Op::Bin {
            dst: dst.clone(),
            op: BinOp::Add,
            lhs: lhs.clone(),
            rhs: Value::Const(negated),
        }),
        _ => None,
    }
}
