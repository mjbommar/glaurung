//! What a calling convention says a call does, recorded on the call itself.
//!
//! An instruction stream does not say which ABI it obeys, so the lifter cannot fill
//! this in: `call 0x1234` is the same bytes under SysV and Win64. The convention is
//! known one level up, where the function is decompiled — so this pass runs there,
//! once, and writes the effects onto every [`Op::Call`].
//!
//! Everything downstream then reads them from the op instead of deciding for itself
//! what a call means. That is the point: before this existed,
//! [`crate::ir::use_def::def_uses`] reported a call as defining nothing and using
//! nothing, so
//!
//! * a read of the return register after a call saw the value from BEFORE it — `fib`
//!   recursed and then used its own argument where the returned value belonged;
//! * the argument-register setup looked dead, so value numbering renamed it out from
//!   under argument reconstruction and calls rendered with no arguments at all;
//! * and every pass that wanted the truth had to special-case calls, which is how the
//!   same ABI knowledge ended up restated in `naming`, `dead_stores`, `value_number`
//!   and the renderers.
//!
//! The effects deliberately describe the ABI, not this program: `result` is written by
//! every call whether or not the source used it. Whether the *program* consumed it is
//! a separate question, answered later (`call_args::attribute_call_results`) and for a
//! different purpose — printing an assignment.

use crate::ir::call_args::CallConv;
use crate::ir::types::{CallEffects, LlirFunction, Op, VReg};

/// The register a callee leaves its return value in.
pub fn return_register(cc: CallConv) -> &'static str {
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 => "rax",
        CallConv::Aarch64 => "x0",
        CallConv::Arm => "r0",
    }
}

/// The integer argument registers, in ABI order.
pub fn argument_registers(cc: CallConv) -> &'static [&'static str] {
    match cc {
        CallConv::SysVAmd64 => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
        CallConv::Win64 => &["rcx", "rdx", "r8", "r9"],
        CallConv::Aarch64 => &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
        CallConv::Arm => &["r0", "r1", "r2", "r3"],
    }
}

/// The effects of any call under `cc`.
///
/// The full argument-register set is listed as uses rather than a recovered arity: the
/// callee is usually unknown, and claiming a narrower set would let dead-code
/// elimination delete an argument setup that a real callee reads. Over-approximating
/// uses keeps code alive that might matter; under-approximating deletes code that
/// does.
pub fn call_effects(cc: CallConv) -> CallEffects {
    CallEffects {
        result: Some(VReg::phys(return_register(cc))),
        args: argument_registers(cc)
            .iter()
            .map(|n| VReg::phys(*n))
            .collect(),
    }
}

/// Write the ABI's call effects onto every call in `lf`.
///
/// Idempotent, and it never overwrites effects a caller already set (a summarised or
/// known callee may describe itself more precisely than the convention's worst case).
pub fn annotate_calls(lf: &mut LlirFunction, cc: CallConv) {
    let effects = call_effects(cc);
    for block in &mut lf.blocks {
        for instr in &mut block.instrs {
            if let Op::Call {
                effects: slot @ None,
                ..
            } = &mut instr.op
            {
                *slot = Some(effects.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{CallTarget, LlirBlock, LlirInstr};

    fn call_at(va: u64) -> LlirInstr {
        LlirInstr {
            va,
            op: Op::Call {
                target: CallTarget::Direct(0x2000),
                effects: None,
            },
        }
    }

    fn func(instrs: Vec<LlirInstr>) -> LlirFunction {
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1000 + 4 * instrs.len() as u64,
                instrs,
                succs: vec![],
            }],
        }
    }

    #[test]
    fn every_call_gets_the_conventions_effects() {
        let mut lf = func(vec![call_at(0x1000), call_at(0x1004)]);
        annotate_calls(&mut lf, CallConv::SysVAmd64);
        for instr in &lf.blocks[0].instrs {
            match &instr.op {
                Op::Call { effects, .. } => {
                    let e = effects.as_ref().expect("annotated");
                    assert_eq!(e.result, Some(VReg::phys("rax")));
                    assert_eq!(e.args.len(), 6);
                    assert_eq!(e.args[0], VReg::phys("rdi"));
                }
                other => panic!("expected a call, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_result_register_and_arguments_follow_the_abi() {
        for (cc, ret, first_arg, argc) in [
            (CallConv::SysVAmd64, "rax", "rdi", 6),
            (CallConv::Win64, "rax", "rcx", 4),
            (CallConv::Aarch64, "x0", "x0", 8),
            (CallConv::Arm, "r0", "r0", 4),
        ] {
            let e = call_effects(cc);
            assert_eq!(e.result, Some(VReg::phys(ret)), "{cc:?} result");
            assert_eq!(e.args[0], VReg::phys(first_arg), "{cc:?} first arg");
            assert_eq!(e.args.len(), argc, "{cc:?} arg count");
        }
    }

    #[test]
    fn annotation_is_idempotent_and_does_not_overwrite() {
        let mut lf = func(vec![call_at(0x1000)]);
        annotate_calls(&mut lf, CallConv::SysVAmd64);
        // A caller that knows the callee may describe it more precisely; a second
        // pass must not flatten that back to the convention's worst case.
        if let Op::Call { effects, .. } = &mut lf.blocks[0].instrs[0].op {
            *effects = Some(CallEffects {
                result: Some(VReg::phys("rax")),
                args: vec![VReg::phys("rdi")],
            });
        }
        annotate_calls(&mut lf, CallConv::SysVAmd64);
        match &lf.blocks[0].instrs[0].op {
            Op::Call { effects, .. } => {
                assert_eq!(effects.as_ref().unwrap().args.len(), 1, "was overwritten");
            }
            other => panic!("expected a call, got {other:?}"),
        }
    }
}
