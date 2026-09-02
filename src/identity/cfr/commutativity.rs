//! The commutativity table: which operators may have their operands swapped.
//!
//! This table is the reason `a - b` and `b - a` do not collapse. Any
//! permutation-invariant aggregation over a node's inputs -- which is what a
//! commutative Weisfeiler-Lehman round is -- erases operand order, so an
//! operator that depends on operand order must be mixed **positionally**
//! instead. BSim draws the same line ("commutative ops accumulate inputs
//! order-independently; non-commutative ops preserve operand order") and
//! ProGraML encodes it as a `position` field on every data edge.
//!
//! Every entry below carries its justification. An operator whose algebra is
//! not obvious defaults to [`Mixing::Positional`], which is the safe direction:
//! declaring a commutative operator positional costs recall on operand-swapped
//! twins, while declaring a non-commutative operator commutative silently
//! merges two different functions.

use super::labels::{BinOpKind, CmpOpKind, OpKind};

/// How a node's input labels are combined during a Weisfeiler-Lehman round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mixing {
    /// Order-independent: the inputs are accumulated as a multiset.
    Commutative,
    /// Order-dependent: each input is mixed with its operand position.
    Positional,
}

/// Mixing rule for a binary operator.
pub fn binop_mixing(op: BinOpKind) -> Mixing {
    match op {
        // Integer addition and multiplication are commutative in two's
        // complement at every width, wrapping included, so `a + b` and `b + a`
        // are the same value and must be the same feature.
        BinOpKind::Add | BinOpKind::Mul => Mixing::Commutative,
        // Bitwise AND, OR and XOR are commutative bit by bit.
        BinOpKind::And | BinOpKind::Or | BinOpKind::Xor => Mixing::Commutative,
        // `a - b != b - a` for every `a != b`. This is the canonical reason the
        // table exists: with commutative mixing the two would produce an
        // identical feature multiset, and a subtraction is the most common
        // asymmetric operation in compiled code (every bounds check, every
        // pointer difference, every loop countdown).
        BinOpKind::Sub => Mixing::Positional,
        // Division is neither commutative nor associative; dividend and divisor
        // are different roles.
        BinOpKind::Div => Mixing::Positional,
        // A shift's operands are not even the same kind of thing: one is the
        // value shifted, the other the distance. Swapping them is not a
        // different result, it is a different program.
        BinOpKind::Shl | BinOpKind::Shr | BinOpKind::Sar => Mixing::Positional,
        // `&&` and `||` are short-circuit, left-to-right, source-level
        // operators: `a && b` evaluates `b` only when `a` holds, so swapping
        // them changes which side effects happen. They are also a signal that
        // canonicalisation ran too late -- the CFR is built before
        // `structure_v2`, which is what introduces them -- so seeing one here
        // is a bug, not a shape. Positional either way.
        BinOpKind::LogicalAnd | BinOpKind::LogicalOr => Mixing::Positional,
    }
}

/// Mixing rule for a comparison operator.
pub fn cmpop_mixing(op: CmpOpKind) -> Mixing {
    match op {
        // Equality and disequality are symmetric relations: `a == b` and
        // `b == a` denote the same predicate, and compilers pick the operand
        // order freely (x86 `cmp` direction, ARM `cmp` vs `cmn`).
        CmpOpKind::Eq | CmpOpKind::Ne => Mixing::Commutative,
        // Ordered comparisons reverse under a swap: `a < b` becomes `b < a`,
        // which is a different predicate. Signed and unsigned alike.
        CmpOpKind::Ult | CmpOpKind::Ule | CmpOpKind::Slt | CmpOpKind::Sle => Mixing::Positional,
    }
}

/// Mixing rule for a CFR-G node kind.
pub fn op_mixing(kind: &OpKind) -> Mixing {
    match kind {
        OpKind::Bin(op) => binop_mixing(*op),
        OpKind::Cmp(op) => cmpop_mixing(*op),
        // A phi merges an unordered set of predecessors. Block layout order is
        // masked, so the incoming order is not information -- it is exactly the
        // choice the compiler was free to make. BSim treats `MULTIEQUAL` the
        // same way.
        OpKind::Phi => Mixing::Commutative,
        // The block-entry memory state is a phi over its predecessors' exit
        // states, and merges for the same reason.
        OpKind::MemEntry => Mixing::Commutative,
        // A load's address and the memory state it reads are different roles;
        // so are the base and index of an effective address, which are not
        // interchangeable once a scale is applied.
        OpKind::Load | OpKind::CondLoad => Mixing::Positional,
        // A store's address and its stored value are the classic asymmetric
        // pair: `*p = q` and `*q = p` are different programs.
        OpKind::Store | OpKind::CondStore | OpKind::MemDef => Mixing::Positional,
        // Arguments are in ABI order, which is the callee's contract.
        OpKind::Call => Mixing::Positional,
        // `hi` and `lo` halves; `cond`, `then`, `else`; source and its
        // extension width. All positional by construction.
        OpKind::Concat | OpKind::Ite => Mixing::Positional,
        // Everything else is either unary (where the two rules agree) or
        // nullary (where neither applies). Positional is the conservative
        // default: see the module note.
        _ => Mixing::Positional,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_commutative_set_is_exactly_the_documented_one() {
        let commutative = [
            BinOpKind::Add,
            BinOpKind::Mul,
            BinOpKind::And,
            BinOpKind::Or,
            BinOpKind::Xor,
        ];
        for op in [
            BinOpKind::Add,
            BinOpKind::Sub,
            BinOpKind::Mul,
            BinOpKind::Div,
            BinOpKind::LogicalAnd,
            BinOpKind::LogicalOr,
            BinOpKind::And,
            BinOpKind::Or,
            BinOpKind::Xor,
            BinOpKind::Shl,
            BinOpKind::Shr,
            BinOpKind::Sar,
        ] {
            let expected = if commutative.contains(&op) {
                Mixing::Commutative
            } else {
                Mixing::Positional
            };
            assert_eq!(binop_mixing(op), expected, "{op:?}");
        }
        for op in [CmpOpKind::Eq, CmpOpKind::Ne] {
            assert_eq!(cmpop_mixing(op), Mixing::Commutative, "{op:?}");
        }
        for op in [
            CmpOpKind::Ult,
            CmpOpKind::Ule,
            CmpOpKind::Slt,
            CmpOpKind::Sle,
        ] {
            assert_eq!(cmpop_mixing(op), Mixing::Positional, "{op:?}");
        }
        assert_eq!(op_mixing(&OpKind::Phi), Mixing::Commutative);
        assert_eq!(op_mixing(&OpKind::Store), Mixing::Positional);
        assert_eq!(op_mixing(&OpKind::Load), Mixing::Positional);
    }
}
