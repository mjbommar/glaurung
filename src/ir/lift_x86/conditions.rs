//! x86 condition codes: the `cc` suffix families and their flag expressions.
//!
//! Three different instruction groups — `jcc`, `setcc`, and `cmovcc` — spell the
//! same sixteen condition mnemonics and need the same answer from them, so the
//! decoding (suffix to condition) is separated here from the lowering (condition
//! to LLIR ops). x86 gives most conditions two or three interchangeable
//! spellings (`jz`/`je`, `jnae`/`jb`/`jc`), and the negative forms are recorded
//! as an `inverted` flag on the positive family rather than as sixteen separate
//! cases, which is what keeps [`materialize_condition`] down to eight arms.

use iced_x86::Mnemonic;

use crate::ir::types::{BinOp, Flag, Op, VReg, Value};

pub(super) fn condition_suffix(mnem: Mnemonic, prefix: &str) -> Option<String> {
    let name = format!("{:?}", mnem).to_ascii_lowercase();
    name.strip_prefix(prefix).map(str::to_string)
}

#[derive(Debug, Clone)]
enum ConditionCode {
    Overflow,
    Below,
    Equal,
    BelowEqual,
    Sign,
    Parity,
    Less,
    LessEqual,
}

#[derive(Debug, Clone)]
pub(super) struct Condition {
    code: ConditionCode,
    pub(super) inverted: bool,
}

pub(super) fn condition_for_suffix(suffix: &str) -> Option<Condition> {
    let (code, inverted) = match suffix {
        "e" | "z" => (ConditionCode::Equal, false),
        "ne" | "nz" => (ConditionCode::Equal, true),
        "b" | "c" | "nae" => (ConditionCode::Below, false),
        "ae" | "nb" | "nc" => (ConditionCode::Below, true),
        "be" | "na" => (ConditionCode::BelowEqual, false),
        "a" | "nbe" => (ConditionCode::BelowEqual, true),
        "l" | "nge" => (ConditionCode::Less, false),
        "ge" | "nl" => (ConditionCode::Less, true),
        "le" | "ng" => (ConditionCode::LessEqual, false),
        "g" | "nle" => (ConditionCode::LessEqual, true),
        "s" => (ConditionCode::Sign, false),
        "ns" => (ConditionCode::Sign, true),
        "o" => (ConditionCode::Overflow, false),
        "no" => (ConditionCode::Overflow, true),
        "p" | "pe" => (ConditionCode::Parity, false),
        "np" | "po" => (ConditionCode::Parity, true),
        _ => return None,
    };
    Some(Condition { code, inverted })
}

/// Materialise one of x86's eight positive condition families from the six
/// architectural status flags. Derived conditions are ordinary typed boolean
/// temporaries, never mutable pseudo-flags.
pub(super) fn materialize_condition(condition: &Condition) -> (Vec<Op>, VReg) {
    let atom = |flag| (Vec::new(), VReg::Flag(flag));
    match condition.code {
        ConditionCode::Overflow => atom(Flag::O),
        ConditionCode::Below => atom(Flag::C),
        ConditionCode::Equal => atom(Flag::Z),
        ConditionCode::Sign => atom(Flag::S),
        ConditionCode::Parity => atom(Flag::P),
        ConditionCode::BelowEqual => {
            let out = VReg::Temp(20);
            (
                vec![Op::Bin {
                    dst: out.clone(),
                    op: BinOp::Or,
                    lhs: Value::Reg(VReg::Flag(Flag::C)),
                    rhs: Value::Reg(VReg::Flag(Flag::Z)),
                }],
                out,
            )
        }
        ConditionCode::Less => {
            let out = VReg::Temp(20);
            (
                vec![Op::Bin {
                    dst: out.clone(),
                    op: BinOp::Xor,
                    lhs: Value::Reg(VReg::Flag(Flag::S)),
                    rhs: Value::Reg(VReg::Flag(Flag::O)),
                }],
                out,
            )
        }
        ConditionCode::LessEqual => {
            let less = VReg::Temp(20);
            let out = VReg::Temp(21);
            (
                vec![
                    Op::Bin {
                        dst: less.clone(),
                        op: BinOp::Xor,
                        lhs: Value::Reg(VReg::Flag(Flag::S)),
                        rhs: Value::Reg(VReg::Flag(Flag::O)),
                    },
                    Op::Bin {
                        dst: out.clone(),
                        op: BinOp::Or,
                        lhs: Value::Reg(VReg::Flag(Flag::Z)),
                        rhs: Value::Reg(less),
                    },
                ],
                out,
            )
        }
    }
}

pub(super) fn setcc_condition_for(mnem: Mnemonic) -> Option<Condition> {
    condition_suffix(mnem, "set").and_then(|suffix| condition_for_suffix(&suffix))
}

pub(super) fn cmovcc_condition_for(mnem: Mnemonic) -> Option<Condition> {
    condition_suffix(mnem, "cmov").and_then(|suffix| condition_for_suffix(&suffix))
}
