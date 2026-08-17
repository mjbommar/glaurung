//! Float argument-bank and scalar-float register vocabulary.
//!
//! The ABIs Glaurung lifts differ in whether floating-point arguments arrive in
//! a *separate* register bank (AAPCS-VFP `s0..s15`/`d0..d7`, SysV AMD64
//! `xmm0..xmm7`) or share the integer registers.  Prototype recovery needs two
//! distinct answers from that fact: which live-in registers occupy a float
//! bank slot ([`float_live_in_slots`]), and, when a signature mixes banks, what
//! source order the entry spills imply ([`mixed_entry_spill_order`]).
//!
//! The scalar-float predicates ([`scalar_vfp_register`],
//! [`scalar_float_intrinsic_width`]) are the narrower question of whether one
//! register or one intrinsic denotes a *scalar* float rather than a packed
//! vector lane; they are shared vocabulary and have callers on the raw-register
//! tagging side as well as here.
//!
//! `float_argument_bank_slot`, `is_scalarised_vector_lane` and
//! `scalar_float_intrinsic_name_width` are private helpers of this module.
//! This module reads nothing from its parent.

use std::collections::{HashMap, HashSet};

use crate::ir::types::{BinOp, LlirFunction, MemOp, Op, VReg, Value};
use crate::ir::use_def::{def_uses, use_is_proven_input};

fn scalar_float_intrinsic_name_width(name: &str) -> Option<u8> {
    match name {
        "addss" | "subss" | "mulss" | "divss" => Some(4),
        "addsd" | "subsd" | "mulsd" | "divsd" => Some(8),
        // The x86 conversions, keyed by the width of what they PRODUCE — the
        // question this function answers is "what type does the destination
        // hold". `cvttss2si` and `cvttsd2si` produce an integer, so they are
        // deliberately absent: claiming a float destination for them would
        // type the very register the program then uses as an `int`.
        "sqrtss" | "cvtsd2ss" | "cvtsi2ss.l" | "cvtsi2ss.q" => Some(4),
        "sqrtsd" | "cvtss2sd" | "cvtsi2sd.l" | "cvtsi2sd.q" => Some(8),
        name if [
            "vmov.f32", "vneg.f32", "vadd.f32", "vsub.f32", "vmul.f32", "vdiv.f32",
        ]
        .iter()
        .any(|operation| name.starts_with(operation)) =>
        {
            Some(4)
        }
        name if [
            "vmov.f64", "vneg.f64", "vadd.f64", "vsub.f64", "vmul.f64", "vdiv.f64",
        ]
        .iter()
        .any(|operation| name.starts_with(operation)) =>
        {
            Some(8)
        }
        _ => None,
    }
}

pub(super) fn scalar_vfp_register(register: &VReg) -> bool {
    matches!(register, VReg::Phys(name) if {
        let base = crate::ir::abi::ssa_base(name);
        base.strip_prefix('s').is_some_and(|index| index.parse::<u8>().is_ok())
            || base.strip_prefix('d').is_some_and(|index| index.parse::<u8>().is_ok())
    })
}

pub(super) fn scalar_float_intrinsic_width(
    name: &str,
    ins: &[Value],
    outs: &[(VReg, crate::ir::types::Width)],
) -> Option<u8> {
    if let Some(width) = scalar_float_intrinsic_name_width(name) {
        return Some(width);
    }
    if name != "vmov" {
        return None;
    }
    let ([Value::Reg(source)], [(destination, width)]) = (ins, outs) else {
        return None;
    };
    if scalar_vfp_register(source) || !scalar_vfp_register(destination) {
        return None;
    }
    let width = u8::try_from(width.bytes()).ok()?;
    matches!(width, 4 | 8).then_some(width)
}

/// The float-argument-bank index a register denotes, or `None`.
///
/// Every convention this decompiler models that passes floats in registers does
/// so from a bank that is SEPARATE from the integer one and allocated in its own
/// contiguous order: AAPCS-VFP's `s0..s15`, and the x86-64 SysV / Windows x64
/// SSE class's `xmm0..xmm7`. The bank index is not the source parameter
/// position in a mixed signature — that is what [`mixed_entry_spill_order`]
/// recovers — but it IS the order within the bank, which is what a pure-float
/// signature needs and all a live-in scan can prove.
pub(super) fn float_argument_bank_slot(
    cc: crate::ir::call_args::CallConv,
    register: &VReg,
) -> Option<usize> {
    use crate::ir::call_args::CallConv;
    let VReg::Phys(name) = register else {
        return None;
    };
    let base = crate::ir::abi::ssa_base(name);
    match cc {
        CallConv::Arm | CallConv::ArmHardFloat => base
            .strip_prefix('s')
            .and_then(|index| index.parse::<usize>().ok())
            .filter(|index| *index < 16),
        // Eight SSE argument registers; `xmm8` and above are never parameters,
        // so a scratch use of one must not be read as a ninth. The bound is
        // SysV's for both conventions on purpose: Win64 really passes only
        // four, but over-accepting a bank INDEX costs nothing here — the
        // contiguous-prefix rule in `float_live_in_slots` is what decides which
        // live-ins become parameters, and `abi::sse_argument_registers` holds
        // the exact per-convention counts for the consumers that place storage.
        //
        // A scalar 32-bit transfer (`movd eax, xmm0`, `movss`) lifts as a read
        // of ONE dword LANE, spelled `xmm0_d0`, and `regview::ssa_parent`
        // deliberately declines to merge a lane with its parent. Both spellings
        // name the same ABI register, so both denote the same bank slot; until
        // this accepted the lane, `174_float_compare_classify` at `-O2` — whose
        // entire body is `movd eax, xmm0; shr eax, 31` — reported NO float
        // live-in, and the locked-parameter fallback bound its `float` to `rdi`.
        CallConv::SysVAmd64 | CallConv::Win64 => base
            .strip_prefix("xmm")
            .map(|index| index.split_once("_d").map_or(index, |(whole, _)| whole))
            .and_then(|index| index.parse::<usize>().ok())
            .filter(|index| *index < 8),
        // AAPCS64 passes the first eight floating-point arguments in `v0`-`v7`,
        // a bank as separate from `x0`-`x7` as AAPCS-VFP's is from `r0`-`r3`.
        // The scalar views of one such register are spelled `s{n}` (binary32)
        // and `d{n}` (binary64) and denote the SAME parameter slot, so both
        // spellings map here; which one a given callee reads is a property of
        // the parameter's width, and the caller of this keeps the exact
        // spelling rather than reconstructing it.
        CallConv::Aarch64 => base
            .strip_prefix(['s', 'd'])
            .and_then(|index| index.parse::<usize>().ok())
            .filter(|index| *index < 8),
        CallConv::Cdecl32 => None,
    }
}

/// Whether `name` is a scalarised dword lane rather than a whole register.
///
/// The lifters split a packed operation into four independent 32-bit lanes so
/// ordinary SSA can process it, and `regview` records each lane as a non-parent
/// view of its register. Asked here rather than pattern-matched on the spelling
/// so the naming convention stays owned by one module.
fn is_scalarised_vector_lane(cc: crate::ir::call_args::CallConv, name: &str) -> bool {
    use crate::ir::call_args::CallConv;
    let arch = match cc {
        CallConv::SysVAmd64 | CallConv::Win64 => crate::ir::regview::Arch::X86_64,
        CallConv::Aarch64 => crate::ir::regview::Arch::AArch64,
        CallConv::Cdecl32 | CallConv::Arm | CallConv::ArmHardFloat => return false,
    };
    crate::ir::regview::view(arch, crate::ir::abi::ssa_base(name))
        .is_some_and(|view| !view.is_parent())
}

/// Whether `cc` passes floating-point arguments in a register bank of its own.
pub(super) fn has_float_argument_bank(cc: crate::ir::call_args::CallConv) -> bool {
    use crate::ir::call_args::CallConv;
    matches!(
        cc,
        CallConv::Arm
            | CallConv::ArmHardFloat
            | CallConv::SysVAmd64
            | CallConv::Win64
            | CallConv::Aarch64
    )
}

/// Contiguous scalar VFP registers whose first touch is a read, each paired
/// with the EXACT register spelling that touch used.
///
/// A hard-float argument is a version-zero use.  A scratch/result register is
/// defined before it is read.  Requiring a contiguous `s0..sN` prefix follows
/// AAPCS allocation and rejects isolated callee-saved/scratch registers.
///
/// The spelling is returned because AAPCS64's `v0` has two scalar views —
/// `s0` is binary32 and `d0` binary64 — which this IR's SSA tracks as unrelated
/// identities. Naming the parameter `s0` when the body only ever reads `d0`
/// would leave every use of it undefined, so the observed name is carried out
/// rather than reconstructed from the slot index.
///
/// x86-64 needs one more rule than AAPCS64 does, and it is not symmetric.
/// `s0`/`d0` are two scalar views of one AArch64 register and a body reads one
/// or the other; `xmm1` and its dword lane `xmm1_d0` are a WHOLE register and a
/// PIECE of it, and an x86-64 body routinely reads both. A 128-bit `movapd`
/// lifts to four lane copies, so the first touch of an `xmm` argument can be
/// `xmm1_d0` while every instruction that consumes the VALUE — `mulsd`,
/// `addsd` — reads `xmm1` whole. First-touch-wins therefore picks the transport
/// over the value, which is how binding the lane broke
/// `172_float_double_widths::double_precision_horner`, a function that had been
/// correct. A whole-register live-in read UPGRADES a lane spelling; a lane never
/// downgrades a whole register. The lane survives only when it is all there is —
/// `movd eax, xmm0` and nothing else, which is exactly fixture 174.
pub(super) fn float_live_in_slots(
    lf: &LlirFunction,
    cc: crate::ir::call_args::CallConv,
) -> Vec<(usize, String)> {
    let mut first_touch: HashMap<usize, bool> = HashMap::new();
    let mut spelling: HashMap<usize, String> = HashMap::new();
    // Slots whose storage has been defined. After a definition, a read is no
    // longer evidence about the ENTRY value, so it must not revise the entry
    // spelling either.
    let mut defined: HashSet<usize> = HashSet::new();
    // `LlirFunction::blocks` is a CFG collection, not a guaranteed address or
    // dominance order. A join/return block can therefore precede the entry
    // block in the vector and make the function's final `s0` result definition
    // look like the first touch of its incoming `s0` parameter. Always examine
    // the entry block first; only it has an unconditional machine entry state.
    let blocks = lf
        .blocks
        .iter()
        .filter(|block| block.start_va == lf.entry_va)
        .chain(
            lf.blocks
                .iter()
                .filter(|block| block.start_va != lf.entry_va),
        );
    for block in blocks {
        for instruction in &block.instrs {
            let (definition, uses) = def_uses(&instruction.op);
            // `CallEffects.args` is an ABI-wide may-read set, not evidence
            // that all of those registers entered THIS function live. Real
            // parameter evidence comes from machine instructions before the
            // call; counting the conservative s0-s15 call footprint here
            // inflated every hard-float caller to sixteen parameters.
            // `use_is_proven_input` supersedes the cruder "skip every call"
            // guard: a call's argument registers are an ABI-wide may-read set,
            // not evidence that those registers entered THIS function live.
            // The slot lookup is the CONVENTION's, not ARM's: x86-64 SysV
            // passes floats in `xmm0`-`xmm7`, a bank as separate from the
            // integer one as AAPCS-VFP's `s0`-`s15`.
            for (use_index, used) in uses.into_iter().enumerate() {
                if !use_is_proven_input(&instruction.op, use_index) {
                    continue;
                }
                if let Some(slot) = float_argument_bank_slot(cc, &used) {
                    let VReg::Phys(name) = &used else {
                        continue;
                    };
                    let name = crate::ir::abi::ssa_base(name);
                    match first_touch.entry(slot) {
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            entry.insert(true);
                            spelling.insert(slot, name.to_string());
                        }
                        // Already known live-in, still undefined: a read of the
                        // WHOLE register replaces a lane spelling recorded from
                        // a transport copy. Nothing replaces a whole register.
                        std::collections::hash_map::Entry::Occupied(entry)
                            if *entry.get()
                                && !defined.contains(&slot)
                                && !is_scalarised_vector_lane(cc, name)
                                && spelling.get(&slot).is_some_and(|current| {
                                    is_scalarised_vector_lane(cc, current)
                                }) =>
                        {
                            spelling.insert(slot, name.to_string());
                        }
                        std::collections::hash_map::Entry::Occupied(_) => {}
                    }
                }
            }
            if let Some(definition) = definition {
                if let Some(slot) = float_argument_bank_slot(cc, &definition) {
                    first_touch.entry(slot).or_insert(false);
                    defined.insert(slot);
                }
            }
        }
    }
    let mut live: Vec<usize> = first_touch
        .into_iter()
        .filter_map(|(slot, is_live_in)| is_live_in.then_some(slot))
        .collect();
    live.sort_unstable();
    let mut prefix = Vec::new();
    for slot in live {
        if slot != prefix.len() {
            break;
        }
        let name = spelling.remove(&slot).unwrap_or_default();
        prefix.push((slot, name));
    }
    prefix
}

/// Recover source order for a mixed ARM core/VFP signature from an entry spill
/// sequence.
///
/// GCC's Cortex-M O0 prologue stores incoming parameters in declaration order
/// into strictly descending `sp` slots.  The two conditions are checked
/// independently: instruction order alone could be register-class grouping,
/// and offsets alone could be unrelated saves.  Every candidate must occur
/// exactly once before a control-transfer boundary; otherwise this declines.
pub(super) fn mixed_entry_spill_order(
    lf: &LlirFunction,
    cc: crate::ir::call_args::CallConv,
    candidates: &[VReg],
) -> Option<Vec<VReg>> {
    let entry = lf
        .blocks
        .iter()
        .find(|block| block.start_va == lf.entry_va)?;
    let candidate_set: HashSet<VReg> = candidates.iter().cloned().collect();
    let mut origins: HashMap<VReg, VReg> = candidates
        .iter()
        .cloned()
        .map(|register| (register.clone(), register))
        .collect();
    // The frame registers the entry spills are written through. AAPCS
    // prologues address the frame from `sp`; an x86-64 `-O0` prologue has
    // already established `rbp` by the time it spills its arguments, and a
    // frame-pointer-omitted one spills through `rsp`.
    let mut stack_bases: HashSet<VReg> = match cc {
        crate::ir::call_args::CallConv::SysVAmd64
        | crate::ir::call_args::CallConv::Win64
        | crate::ir::call_args::CallConv::Cdecl32 => {
            HashSet::from([VReg::phys("rbp"), VReg::phys("rsp")])
        }
        _ => HashSet::from([VReg::phys("sp")]),
    };
    let mut spills: Vec<(i64, VReg)> = Vec::new();

    for instruction in &entry.instrs {
        match &instruction.op {
            Op::Assign {
                dst,
                src: Value::Reg(src),
            }
            | Op::ZExt {
                dst,
                src: Value::Reg(src),
                ..
            }
            | Op::SExt {
                dst,
                src: Value::Reg(src),
                ..
            }
            | Op::Trunc {
                dst,
                src: Value::Reg(src),
                ..
            } => {
                if let Some(origin) = origins.get(src).cloned() {
                    origins.insert(dst.clone(), origin);
                }
                if stack_bases.contains(src) {
                    stack_bases.insert(dst.clone());
                }
            }
            Op::Bin {
                dst,
                op: BinOp::Add,
                lhs: Value::Reg(base),
                rhs: Value::Const(0),
            }
            | Op::Bin {
                dst,
                op: BinOp::Add,
                lhs: Value::Const(0),
                rhs: Value::Reg(base),
            } => {
                if stack_bases.contains(base) {
                    stack_bases.insert(dst.clone());
                }
            }
            Op::Store {
                addr:
                    MemOp {
                        base: Some(base),
                        index: None,
                        disp,
                        ..
                    },
                src: Value::Reg(src),
            } if stack_bases.contains(base) => {
                let Some(origin) = origins.get(src).cloned() else {
                    continue;
                };
                if candidate_set.contains(&origin)
                    && !spills.iter().any(|(_, recorded)| recorded == &origin)
                {
                    spills.push((*disp, origin));
                }
            }
            Op::Call { .. } | Op::Jump { .. } | Op::IndirectJump { .. } | Op::CondJump { .. } => {
                break
            }
            op if op.is_return() => break,
            _ => {}
        }
    }

    if spills.len() != candidates.len() || !spills.windows(2).all(|pair| pair[0].0 > pair[1].0) {
        return None;
    }
    Some(spills.into_iter().map(|(_, register)| register).collect())
}
