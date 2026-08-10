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
use crate::ir::use_def::def_uses;

/// The register a callee leaves its return value in.
pub fn return_register(cc: CallConv) -> &'static str {
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 => "rax",
        CallConv::Cdecl32 => "rax",
        CallConv::Aarch64 => "x0",
        CallConv::Arm | CallConv::ArmHardFloat => "r0",
    }
}

/// Bytes in one general-purpose register for this calling convention.
///
/// This is a machine-model fact shared by ABI storage reconstruction and C
/// type spelling.  It must not be inferred from a register name (`rax` is the
/// canonical SSA parent even for i386).
pub fn machine_word_bytes(cc: CallConv) -> u8 {
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Aarch64 => 8,
        CallConv::Cdecl32 | CallConv::Arm | CallConv::ArmHardFloat => 4,
    }
}

/// Low/high general-purpose registers for a scalar integer wider than one
/// machine word.
///
/// The names are the canonical SSA spellings.  Returning `None` is deliberate:
/// 64-bit ABIs keep an eight-byte scalar in one register, and aggregate or FP
/// returns have different storage contracts.
pub fn wide_integer_return_pair(
    cc: CallConv,
    value_width: u8,
) -> Option<(&'static str, &'static str)> {
    if value_width != 8 || machine_word_bytes(cc) != 4 {
        return None;
    }
    match cc {
        CallConv::Cdecl32 => Some(("rax", "rdx")),
        CallConv::Arm | CallConv::ArmHardFloat => Some(("r0", "r1")),
        CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Aarch64 => None,
    }
}

/// Which half of an ILP32 wide integer result a register name denotes.
pub fn wide_integer_return_part(cc: CallConv, name: &str) -> Option<usize> {
    let base = ssa_base(name);
    let (low, high) = wide_integer_return_pair(cc, 8)?;
    if base == low || (cc == CallConv::Cdecl32 && ["eax", "ax", "al"].contains(&base)) {
        Some(0)
    } else if base == high || (cc == CallConv::Cdecl32 && ["edx", "dx", "dl"].contains(&base)) {
        Some(1)
    } else {
        None
    }
}

/// The integer argument registers, in ABI order — canonical (widest) names only.
///
/// Prefer [`argument_slots`] when matching a register NAME found in code: a 32-bit
/// write (`%edi = …`) sets the same parameter slot, and this list does not say so.
pub fn argument_registers(cc: CallConv) -> &'static [&'static str] {
    match cc {
        CallConv::SysVAmd64 => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
        CallConv::Win64 => &["rcx", "rdx", "r8", "r9"],
        CallConv::Cdecl32 => &[],
        CallConv::Aarch64 => &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
        CallConv::Arm => &["r0", "r1", "r2", "r3"],
        // Calls can mix the independent core and VFP allocation banks.  Keep
        // every register candidate as a use until a recovered callee
        // prototype can narrow the exact storage map; over-approximating uses
        // is safe, while omitting s0-s15 deletes real argument setup.
        CallConv::ArmHardFloat => &[
            "r0", "r1", "r2", "r3", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9",
            "s10", "s11", "s12", "s13", "s14", "s15",
        ],
    }
}

/// General-purpose registers an ordinary call may overwrite.
///
/// These are canonical storage names, not every sub-register spelling.  The
/// executable IR records only the result register as a value-producing DEF,
/// while program-level abstract interpreters also need to discard transient
/// facts held in every caller-saved register across the call boundary.
pub fn caller_saved_registers(cc: CallConv) -> &'static [&'static str] {
    match cc {
        CallConv::SysVAmd64 => &["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
        CallConv::Win64 => &["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"],
        CallConv::Cdecl32 => &["rax", "rcx", "rdx"],
        CallConv::Aarch64 => &[
            "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
            "x14", "x15", "x16", "x17", "x18", "x30",
        ],
        CallConv::Arm | CallConv::ArmHardFloat => &["r0", "r1", "r2", "r3", "r12", "lr"],
    }
}

/// Every spelling of each argument slot, in ABI order: the 64-bit name first, then
/// the narrower aliases that write the same logical parameter.
///
/// ONE table. It was previously written out in both `call_args` and `value_number`,
/// and they disagreed about more than formatting — `call_args` matched these names
/// literally while `value_number` had already renamed registers to `canon#version`,
/// so an argument arriving as `rdi#3` matched nothing and every call on that path
/// silently lost all of its arguments. Two copies of a fact are two chances to be
/// out of step with a third thing.
pub fn argument_slots(cc: CallConv) -> &'static [&'static [&'static str]] {
    match cc {
        CallConv::SysVAmd64 => &[
            &["rdi", "edi", "di", "dil"],
            &["rsi", "esi", "si", "sil"],
            &["rdx", "edx", "dx", "dl"],
            &["rcx", "ecx", "cx", "cl"],
            &["r8", "r8d", "r8w", "r8b"],
            &["r9", "r9d", "r9w", "r9b"],
        ],
        CallConv::Win64 => &[
            &["rcx", "ecx", "cx", "cl"],
            &["rdx", "edx", "dx", "dl"],
            &["r8", "r8d", "r8w", "r8b"],
            &["r9", "r9d", "r9w", "r9b"],
        ],
        CallConv::Cdecl32 => &[],
        CallConv::Aarch64 => &[
            &["x0", "w0"],
            &["x1", "w1"],
            &["x2", "w2"],
            &["x3", "w3"],
            &["x4", "w4"],
            &["x5", "w5"],
            &["x6", "w6"],
            &["x7", "w7"],
        ],
        CallConv::Arm | CallConv::ArmHardFloat => &[&["r0"], &["r1"], &["r2"], &["r3"]],
    }
}

/// Every spelling of the return register, widest first.
pub fn return_registers(cc: CallConv) -> &'static [&'static str] {
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 => &["rax", "eax", "ax", "al"],
        // SSA canonicalises EAX and its subregisters to the RAX parent name
        // even when decoding a 32-bit binary, so keep that logical spelling at
        // the head of the alias set as the decompiler's logical return value.
        CallConv::Cdecl32 => &["rax", "eax", "ax", "al"],
        CallConv::Aarch64 => &["x0", "w0"],
        // AAPCS hard-float returns scalar FP values in s0/d0. Keep those
        // storage alternatives visible to value numbering; prototype recovery
        // decides which class is the actual source result.
        CallConv::Arm | CallConv::ArmHardFloat => &["r0", "s0", "d0"],
    }
}

/// General-purpose storage aliases for one scalar result.
pub fn integer_return_registers(cc: CallConv) -> &'static [&'static str] {
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Cdecl32 => &["rax", "eax", "ax", "al"],
        CallConv::Aarch64 => &["x0", "w0"],
        CallConv::Arm | CallConv::ArmHardFloat => &["r0"],
    }
}

/// Floating-point storage aliases for one scalar result.
pub fn float_return_registers(cc: CallConv) -> &'static [&'static str] {
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 => &["xmm0", "ymm0", "zmm0"],
        CallConv::Cdecl32 => &["st0", "xmm0"],
        CallConv::Aarch64 => &["v0", "q0", "d0", "s0", "h0", "b0"],
        CallConv::Arm | CallConv::ArmHardFloat => &["d0", "s0"],
    }
}

/// The non-aliasing ABI result bank containing `name`.
///
/// Integer and floating-point result storage must be tracked independently: a
/// write to `rax` does not overwrite `xmm0`, and a write to `r0` does not
/// overwrite `d0`. Returning the complete class lets reaching-definition
/// consumers use one machine-model owner instead of restating those tables.
pub fn return_register_class(cc: CallConv, name: &str) -> Option<&'static [&'static str]> {
    let base = ssa_base(name);
    for class in [integer_return_registers(cc), float_return_registers(cc)] {
        if class.contains(&base) {
            return Some(class);
        }
    }
    None
}

/// A value-numbered register's underlying name: `rdi#3` -> `rdi`.
///
/// Canonicalising here rather than at each call site is what keeps the slot tables
/// usable on both the value-numbered and the raw pipeline. Matching a versioned
/// name against a bare table is the bug this exists to prevent.
pub fn ssa_base(name: &str) -> &str {
    name.split_once('#').map_or(name, |(base, _)| base)
}

/// The argument slot a register name denotes, tolerating SSA versions and
/// sub-register spellings. `None` when the register is not an argument register.
pub fn argument_slot_of(cc: CallConv, name: &str) -> Option<usize> {
    let canon = ssa_base(name);
    argument_slots(cc)
        .iter()
        .position(|names| names.contains(&canon))
}

/// Whether a register name is the return register, tolerating the same spellings.
pub fn is_return_register(cc: CallConv, name: &str) -> bool {
    return_registers(cc).contains(&ssa_base(name))
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

/// Scalar VFP parameter registers in AAPCS-VFP allocation order.
pub fn arm_hard_float_argument_slots() -> &'static [&'static [&'static str]] {
    &[
        &["s0"],
        &["s1"],
        &["s2"],
        &["s3"],
        &["s4"],
        &["s5"],
        &["s6"],
        &["s7"],
        &["s8"],
        &["s9"],
        &["s10"],
        &["s11"],
        &["s12"],
        &["s13"],
        &["s14"],
        &["s15"],
    ]
}

fn hard_float_result_consumed_after(block: &crate::ir::types::LlirBlock, call_idx: usize) -> VReg {
    let mut candidates = vec!["s0", "d0", "r0"];
    for instruction in &block.instrs[call_idx + 1..] {
        let (definition, uses) = def_uses(&instruction.op);
        for used in uses {
            let VReg::Phys(name) = used else {
                continue;
            };
            let base = ssa_base(&name);
            if candidates.contains(&base) {
                return VReg::phys(base);
            }
        }
        if let Some(VReg::Phys(name)) = definition {
            let base = ssa_base(&name);
            candidates.retain(|candidate| *candidate != base);
            if candidates.is_empty() {
                break;
            }
        }
        if matches!(instruction.op, Op::Call { .. }) || instruction.op.is_return() {
            break;
        }
    }
    VReg::phys("r0")
}

/// Write the ABI's call effects onto every call in `lf`.
///
/// Idempotent, and it never overwrites effects a caller already set (a summarised or
/// known callee may describe itself more precisely than the convention's worst case).
pub fn annotate_calls(lf: &mut LlirFunction, cc: CallConv) {
    for block in &mut lf.blocks {
        for index in 0..block.instrs.len() {
            let mut effects = call_effects(cc);
            if cc == CallConv::ArmHardFloat {
                effects.result = Some(hard_float_result_consumed_after(block, index));
            }
            let instr = &mut block.instrs[index];
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
    fn hard_float_call_uses_both_banks_and_selects_consumed_vfp_result() {
        let mut lf = func(vec![
            call_at(0x1000),
            LlirInstr {
                va: 0x1004,
                op: Op::Intrinsic {
                    name: "vmov.f32".into(),
                    ins: vec![crate::ir::types::Value::Reg(VReg::phys("s0"))],
                    outs: vec![(VReg::phys("s14"), crate::ir::types::Width::W32)],
                    reads_mem: false,
                    writes_mem: false,
                },
            },
        ]);
        annotate_calls(&mut lf, CallConv::ArmHardFloat);

        let Op::Call {
            effects: Some(effects),
            ..
        } = &lf.blocks[0].instrs[0].op
        else {
            panic!("hard-float call was not annotated: {lf:#?}");
        };
        assert_eq!(effects.result, Some(VReg::phys("s0")));
        assert!(effects.args.contains(&VReg::phys("r0")));
        assert!(effects.args.contains(&VReg::phys("s0")));
        assert!(effects.args.contains(&VReg::phys("s15")));
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
    fn cdecl32_uses_the_canonical_accumulator_and_no_register_arguments() {
        let effects = call_effects(CallConv::Cdecl32);
        assert_eq!(effects.result, Some(VReg::phys("rax")));
        assert!(effects.args.is_empty());
        assert!(is_return_register(CallConv::Cdecl32, "eax#9"));
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

    /// Every alias in a slot must map back to that slot, at every width. A missing
    /// alias means a `%edi = …` write is not recognised as setting parameter 0.
    #[test]
    fn every_alias_maps_to_its_own_slot() {
        for cc in [
            CallConv::SysVAmd64,
            CallConv::Win64,
            CallConv::Cdecl32,
            CallConv::Aarch64,
            CallConv::Arm,
        ] {
            for (i, names) in argument_slots(cc).iter().enumerate() {
                for n in *names {
                    assert_eq!(argument_slot_of(cc, n), Some(i), "{cc:?} {n}");
                }
            }
        }
    }

    /// The canonical list and the alias table must agree on order and length, or a
    /// consumer of one disagrees with a consumer of the other about which parameter
    /// a register is.
    #[test]
    fn the_canonical_list_is_the_first_alias_of_each_slot() {
        for cc in [
            CallConv::SysVAmd64,
            CallConv::Win64,
            CallConv::Cdecl32,
            CallConv::Aarch64,
            CallConv::Arm,
        ] {
            let canon = argument_registers(cc);
            let slots = argument_slots(cc);
            assert_eq!(canon.len(), slots.len(), "{cc:?}");
            for (i, names) in slots.iter().enumerate() {
                assert_eq!(names.first(), Some(&canon[i]), "{cc:?} slot {i}");
            }
        }
    }

    /// SSA versions must not defeat the lookup. This is the bug that lost every
    /// call argument on the value-numbered pipeline.
    #[test]
    fn an_ssa_version_does_not_hide_a_slot() {
        assert_eq!(argument_slot_of(CallConv::SysVAmd64, "rdi#3"), Some(0));
        assert_eq!(argument_slot_of(CallConv::SysVAmd64, "edi#17"), Some(0));
        assert_eq!(argument_slot_of(CallConv::Aarch64, "w7#2"), Some(7));
        assert!(is_return_register(CallConv::SysVAmd64, "eax#9"));
        assert!(!is_return_register(CallConv::SysVAmd64, "rbx#1"));
        assert_eq!(ssa_base("rdi#3"), "rdi");
        assert_eq!(ssa_base("rdi"), "rdi");
    }

    /// Win64 does not pass its first argument in `rdi`; a table that said otherwise
    /// would silently mis-order every Windows call.
    #[test]
    fn the_conventions_do_not_share_a_first_argument() {
        assert_eq!(argument_slot_of(CallConv::SysVAmd64, "rdi"), Some(0));
        assert_eq!(argument_slot_of(CallConv::Win64, "rdi"), None);
        assert_eq!(argument_slot_of(CallConv::Win64, "rcx"), Some(0));
        assert_eq!(argument_slot_of(CallConv::SysVAmd64, "rcx"), Some(3));
    }

    /// The return register is the widest spelling, and the alias list leads with it.
    #[test]
    fn the_return_register_leads_its_alias_list() {
        for cc in [
            CallConv::SysVAmd64,
            CallConv::Win64,
            CallConv::Cdecl32,
            CallConv::Aarch64,
            CallConv::Arm,
        ] {
            assert_eq!(
                return_registers(cc).first(),
                Some(&return_register(cc)),
                "{cc:?}"
            );
        }
    }
}
