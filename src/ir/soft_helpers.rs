//! Replace calls to compiler runtime helpers with the arithmetic they perform.
//!
//! A 32-bit target has no divide instruction to lift. GCC therefore lowers
//! `a / b` into `bl __aeabi_uidiv`, and `a / b` together with `a % b` into
//! `bl __aeabi_uidivmod`. Those symbols are libgcc's, they are linked into the
//! object, and nothing in the recovered C can call them: the host rebuild has
//! no such function, so the recovery either fails to link or — worse — reads an
//! undefined value where the quotient should be. On the fixture corpus that is
//! six armv7 measurements (`17_hash_table` and `27_newton_raphson`, both
//! optimisation levels), every one of which recovered as a call with a
//! guessed arity whose result register was never defined.
//!
//! # Why this is exact, and where the 32-bit width comes from
//!
//! The IR's canonical value width is 64 bits — an ARM32 `r0` is modelled as a
//! 64-bit `VReg::Phys`, and nothing truncates it back to the machine's 32.
//! Division is the operation where that matters most: `+`, `-`, `*`, `&`, `|`,
//! `^` and `<<` are all congruent modulo 2^32, so a dirty high half cannot
//! reach the low half, but `/` and `%` read every bit.
//!
//! So the width is stated *here*, on the operands, rather than assumed
//! globally: the emitted lowering zero-extends both operands from 32 bits
//! before dividing. That makes the result exact whenever the low 32 bits of
//! `r0`/`r1` hold the machine's values, which is the invariant the lifter
//! already maintains for every value it produces with congruent arithmetic or a
//! sized load. It is *not* a claim that the register's high half is clean — the
//! lowering does not depend on it.
//!
//! # What is deliberately not modelled
//!
//! * `__aeabi_idiv` / `__aeabi_idivmod` (the signed pair). Not because they are
//!   unlowerable — `Op::SExt { from: W32, to: W64 }` around both operands would
//!   make an ordinary signed `Div` exact under the same precondition. Because
//!   they do not occur anywhere in the fixture corpus, so the lowering would
//!   ship with no real binary behind it; and because the remainder half could
//!   not reuse the wide intrinsic used here, whose `hi` operand would have to be
//!   a sign broadcast of a value whose high half is exactly what this pass
//!   refuses to assume. Adding them needs a fixture first.
//! * `__udivdi3` / `__moddi3` and the rest of the 64-bit soft-division family.
//!   Their operands are register *pairs*, which the AST has no single value for
//!   (see the `adc`/`sbc` note in `lift_arm32`), so there is nothing to divide.
//!   They do not occur in the fixture corpus.
//! * The helpers' register clobbers (`r2`, `r3`, `r12`, `lr`). Replacing the
//!   call drops them, which is an under-approximation — but the compiler that
//!   emitted the call already knows those registers do not survive it and never
//!   reads one across it, so dropping the clobber cannot make correct code
//!   wrong. This mirrors `lift_function::resolve_pc_thunk_calls`, which
//!   replaces a call with a single assignment for the same reason.

use crate::ir::types::{CallTarget, LlirBlock, LlirInstr, Op, VReg, Value, Width};

/// Scratch lane for the pre-clobber quotient in a `__aeabi_uidivmod` expansion.
/// Consumed by the very next op the same expansion emits, so SSA renaming keeps
/// one call site's temporary distinct from the next's.
const DIVMOD_TEMP: u32 = 24;

/// The AAPCS runtime helpers this pass knows the arithmetic meaning of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SoftHelper {
    /// `unsigned __aeabi_uidiv(unsigned num, unsigned den)` — quotient in `r0`.
    UnsignedDivide,
    /// `__aeabi_uidivmod(unsigned num, unsigned den)` — quotient in `r0`,
    /// remainder in `r1`. ARM RTABI 4.3.1.
    UnsignedDivideModulo,
}

impl SoftHelper {
    fn from_symbol(name: &str) -> Option<SoftHelper> {
        match name {
            "__aeabi_uidiv" => Some(SoftHelper::UnsignedDivide),
            "__aeabi_uidivmod" => Some(SoftHelper::UnsignedDivideModulo),
            _ => None,
        }
    }

    /// The ops this helper's call is equivalent to, at the VA of the call.
    ///
    /// Both halves go through the wide-integer intrinsics the AST already
    /// renders exactly (`ast::wide_integer_intrinsic`): the quotient form emits
    /// `(unsigned)((((unsigned long long)(unsigned)hi << 32) | (unsigned)lo) /
    /// (unsigned)den)` with a zero high word, which is precisely a 32-bit
    /// unsigned division of the operands' low halves. Using them rather than a
    /// bare `BinOp::Div` matters twice over: the IR's single `Div` is signed,
    /// and the casts are where the 32-bit width is stated.
    fn expansion(self, va: u64) -> Vec<LlirInstr> {
        let num = Value::Reg(VReg::phys("r0"));
        let den = Value::Reg(VReg::phys("r1"));
        let quotient = |dst: VReg| Op::Intrinsic {
            name: "arm.udiv_quot.32".to_string(),
            ins: vec![Value::Const(0), num.clone(), den.clone()],
            outs: vec![(dst, Width::W32)],
            reads_mem: false,
            writes_mem: false,
        };
        let remainder = |dst: VReg| Op::Intrinsic {
            name: "arm.udiv_rem.32".to_string(),
            ins: vec![Value::Const(0), num.clone(), den.clone()],
            outs: vec![(dst, Width::W32)],
            reads_mem: false,
            writes_mem: false,
        };
        let at = |op: Op| LlirInstr { va, op };
        match self {
            SoftHelper::UnsignedDivide => vec![at(quotient(VReg::phys("r0")))],
            // The remainder reads the ORIGINAL `r0`, so it must be computed
            // before the quotient overwrites it.
            SoftHelper::UnsignedDivideModulo => vec![
                at(remainder(VReg::Temp(DIVMOD_TEMP))),
                at(quotient(VReg::phys("r0"))),
                at(Op::Assign {
                    dst: VReg::phys("r1"),
                    src: Value::Reg(VReg::Temp(DIVMOD_TEMP)),
                }),
            ],
        }
    }
}

/// Rewrite every direct call to a known runtime helper into the arithmetic it
/// performs. `symbol_of` maps a call target VA to its resolved symbol name.
///
/// Runs on the raw LLIR, before SSA and before `abi::annotate_calls`, because
/// the expansion is written in terms of the architectural argument registers
/// and those only exist while the IR is still physical.
pub fn inline_soft_helper_calls<F>(blocks: &mut [LlirBlock], symbol_of: F)
where
    F: Fn(u64) -> Option<String>,
{
    for block in blocks.iter_mut() {
        if !block.instrs.iter().any(is_soft_helper_call(&symbol_of)) {
            continue;
        }
        let mut out: Vec<LlirInstr> = Vec::with_capacity(block.instrs.len() + 2);
        for instr in block.instrs.drain(..) {
            match soft_helper_of(&instr, &symbol_of) {
                Some(helper) => out.extend(helper.expansion(instr.va)),
                None => out.push(instr),
            }
        }
        block.instrs = out;
    }
}

/// Which helper, if any, this instruction calls.
///
/// The Thumb-bit fallback is not optional. An ARM32 Thumb function's `.symtab`
/// entry carries the interworking bit in its value, so libgcc's `__aeabi_uidiv`
/// is recorded at `0x439` while the `bl` that reaches it targets `0x438`. A
/// lookup on the call target alone therefore misses every helper in every
/// Thumb-2 object — which is every armhf binary a distribution ships. Trying
/// `va | 1` cannot mis-fire: the result is used only if it *names* a helper.
fn soft_helper_of<F>(instr: &LlirInstr, symbol_of: &F) -> Option<SoftHelper>
where
    F: Fn(u64) -> Option<String>,
{
    let Op::Call {
        target: CallTarget::Direct(va),
        ..
    } = &instr.op
    else {
        return None;
    };
    symbol_of(*va)
        .and_then(|name| SoftHelper::from_symbol(&name))
        .or_else(|| symbol_of(*va | 1).and_then(|name| SoftHelper::from_symbol(&name)))
}

fn is_soft_helper_call<F>(symbol_of: &F) -> impl Fn(&LlirInstr) -> bool + '_
where
    F: Fn(u64) -> Option<String>,
{
    move |instr: &LlirInstr| soft_helper_of(instr, symbol_of).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn call_block(target: u64) -> Vec<LlirBlock> {
        vec![LlirBlock {
            start_va: 0x1000,
            end_va: 0x1008,
            instrs: vec![
                LlirInstr {
                    va: 0x1000,
                    op: Op::Assign {
                        dst: VReg::phys("r0"),
                        src: Value::Const(7),
                    },
                },
                LlirInstr {
                    va: 0x1004,
                    op: Op::Call {
                        target: CallTarget::Direct(target),
                        effects: None,
                    },
                },
            ],
            succs: vec![],
        }]
    }

    fn names(pairs: &[(u64, &str)]) -> HashMap<u64, String> {
        pairs
            .iter()
            .map(|(va, name)| (*va, name.to_string()))
            .collect()
    }

    #[test]
    fn uidiv_becomes_an_exact_unsigned_thirty_two_bit_quotient() {
        let mut blocks = call_block(0x438);
        let map = names(&[(0x438, "__aeabi_uidiv")]);
        inline_soft_helper_calls(&mut blocks, |va| map.get(&va).cloned());

        assert_eq!(blocks[0].instrs.len(), 2, "the call expands to one op");
        let Op::Intrinsic {
            name, ins, outs, ..
        } = &blocks[0].instrs[1].op
        else {
            panic!("expected an intrinsic, got {:?}", blocks[0].instrs[1].op);
        };
        assert_eq!(name, "arm.udiv_quot.32");
        assert_eq!(
            ins,
            &vec![
                Value::Const(0),
                Value::Reg(VReg::phys("r0")),
                Value::Reg(VReg::phys("r1")),
            ],
            "a zero high word makes this a 32-bit unsigned divide of r0 by r1"
        );
        assert_eq!(outs, &vec![(VReg::phys("r0"), Width::W32)]);
        assert_eq!(blocks[0].instrs[1].va, 0x1004, "the call's VA is preserved");
    }

    #[test]
    fn uidivmod_computes_the_remainder_before_the_quotient_clobbers_r0() {
        let mut blocks = call_block(0x694);
        let map = names(&[(0x694, "__aeabi_uidivmod")]);
        inline_soft_helper_calls(&mut blocks, |va| map.get(&va).cloned());

        let ops: Vec<&Op> = blocks[0].instrs.iter().map(|i| &i.op).collect();
        assert_eq!(ops.len(), 4, "one setup op plus a three-op expansion");
        // The remainder must read the incoming r0, so it is first and lands in
        // a temporary; only then may the quotient overwrite r0.
        let Op::Intrinsic { name, outs, .. } = ops[1] else {
            panic!("expected the remainder first, got {:?}", ops[1]);
        };
        assert_eq!(name, "arm.udiv_rem.32");
        assert_eq!(outs, &vec![(VReg::Temp(DIVMOD_TEMP), Width::W32)]);
        let Op::Intrinsic { name, outs, .. } = ops[2] else {
            panic!("expected the quotient second, got {:?}", ops[2]);
        };
        assert_eq!(name, "arm.udiv_quot.32");
        assert_eq!(outs, &vec![(VReg::phys("r0"), Width::W32)]);
        assert_eq!(
            ops[3],
            &Op::Assign {
                dst: VReg::phys("r1"),
                src: Value::Reg(VReg::Temp(DIVMOD_TEMP)),
            },
            "AAPCS returns the remainder in r1"
        );
    }

    #[test]
    fn the_signed_helpers_are_left_as_calls() {
        // An unsigned divide of a signed operand is a different function, and
        // no fixture in the corpus exercises the signed helpers — so they stay
        // calls until there is a real binary to prove a lowering against.
        for symbol in ["__aeabi_idiv", "__aeabi_idivmod", "__udivdi3", "__moddi3"] {
            let mut blocks = call_block(0x500);
            let map = names(&[(0x500, symbol)]);
            let before = blocks.clone();
            inline_soft_helper_calls(&mut blocks, |va| map.get(&va).cloned());
            assert_eq!(blocks, before, "{symbol} must not be lowered");
        }
    }

    #[test]
    fn a_thumb_symbol_is_found_through_its_interworking_bit() {
        // `.symtab` records the Thumb `__aeabi_uidiv` at 0x439; the `bl` that
        // reaches it targets 0x438. Every armhf object in the corpus is Thumb-2,
        // so without this the pass matched nothing at all.
        let mut blocks = call_block(0x438);
        let map = names(&[(0x439, "__aeabi_uidiv")]);
        inline_soft_helper_calls(&mut blocks, |va| map.get(&va).cloned());
        assert!(
            matches!(blocks[0].instrs[1].op, Op::Intrinsic { .. }),
            "expected the helper to be recognised through the Thumb bit, got {:?}",
            blocks[0].instrs[1].op
        );
    }

    #[test]
    fn an_ordinary_callee_is_untouched() {
        let mut blocks = call_block(0x2000);
        let map = names(&[(0x2000, "strlen")]);
        let before = blocks.clone();
        inline_soft_helper_calls(&mut blocks, |va| map.get(&va).cloned());
        assert_eq!(blocks, before);
    }

    #[test]
    fn an_unresolved_call_target_is_untouched() {
        let mut blocks = call_block(0x2000);
        let before = blocks.clone();
        inline_soft_helper_calls(&mut blocks, |_| None);
        assert_eq!(blocks, before);
    }
}
