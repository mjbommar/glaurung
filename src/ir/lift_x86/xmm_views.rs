//! Reconciling the two spellings an XMM register has in this LLIR.
//!
//! [`super::packed`] describes an XMM register as four independent 32-bit dword
//! lanes (`xmm0_d0`..`xmm0_d3`); [`super::scalar_float`] writes and reads the
//! whole-register name (`xmm0`). Both name the same bits, and SSA treats them as
//! unrelated storage. This module is the bridge run once per lifted instruction,
//! after its ops are emitted, so neither producer has to know about the other's
//! spelling.
//!
//! The bridge runs in BOTH directions, in this order:
//!
//! 1. [`split_xmm_scalar_view`] — a scalar write also defines the lanes it
//!    covers, and the lanes the instruction ZEROES.
//! 2. [`synchronise_xmm_views`] — a lane write also redefines the scalar name.
//!
//! Only one of the two can fire for any one instruction: step 1 acts only on the
//! scalar producers ([`scalar_xmm_write`]'s table) and leaves the scalar name in
//! the instruction's definitions, which is exactly what makes step 2 skip the
//! register. Reversing the order would loop: the concat step 2 appends is itself
//! a scalar definition step 1 would then split back into lanes.

use crate::ir::types::{packed_dword_lane, Op, VReg, Value, Width};

/// Keep an XMM register's two representations in step.
///
/// This LLIR gives an XMM register two names: the whole-register spelling that
/// the scalar float operations read and write, and four `_dN` dword lanes that
/// the packed operations do. They describe the same bits and nothing kept them
/// in agreement, so a value written through one view was invisible through the
/// other. GCC's `-O0` float return is exactly that crossing —
/// `movsd -8(%rbp),%xmm0 ; movq %xmm0,%rax ; movq %rax,%xmm0` — and it returned
/// a zero reconstructed from lanes no scalar store had ever written.
///
/// So: after any instruction that writes lane 0 or 1, the whole-register name
/// is redefined from those lanes. [`split_xmm_scalar_view`] is the converse
/// direction, and the two together make the views interchangeable.
///
/// Only the low two lanes participate. They are the 64 bits every scalar
/// operation and every GPR transfer can address; a 128-bit packed value has no
/// scalar spelling to agree with in the first place.
pub(super) fn synchronise_xmm_views(ops: &mut Vec<Op>) {
    use std::collections::BTreeSet;

    let mut already_defined: BTreeSet<String> = BTreeSet::new();
    let mut lane_written: BTreeSet<String> = BTreeSet::new();
    for op in ops.iter() {
        let (definition, _) = crate::ir::use_def::def_uses(op);
        let Some(VReg::Phys(name)) = definition else {
            continue;
        };
        match name.split_once("_d") {
            Some((register, lane)) if matches!(lane, "0" | "1") => {
                lane_written.insert(register.to_string());
            }
            Some(_) => {}
            None => {
                already_defined.insert(name);
            }
        }
    }
    for register in lane_written {
        if already_defined.contains(&register) {
            continue;
        }
        // A register-to-register packed move copies lane N from lane N of ONE
        // source. Rebuilding the destination's scalar view from its own lanes
        // would be correct only if those lanes had been written — and after a
        // `movss`/`movsd` they have not, because a scalar store writes the
        // whole-register name instead. Carrying the SOURCE's scalar view across
        // propagates whichever representation is actually live, which is what
        // `movaps %xmm1,%xmm2` in a float argument setup needs.
        if let Some(source) = single_source_of_lane_copy(ops, &register) {
            ops.push(Op::Assign {
                dst: VReg::phys(&register),
                src: Value::Reg(VReg::phys(source)),
            });
            continue;
        }
        ops.push(Op::Concat {
            dst: VReg::phys(&register),
            hi: Value::Reg(VReg::phys(format!("{register}_d1"))),
            lo: Value::Reg(VReg::phys(format!("{register}_d0"))),
        });
    }
}

/// The single XMM register `register` was copied from, when this instruction is a
/// plain lane-for-lane move of ALL FOUR of its dword lanes.
///
/// `None` as soon as any lane is computed, loaded, zeroed, or taken from a
/// different register — in those cases the destination's own lanes are the only
/// description of its value and the concat above is the right bridge.
///
/// # The count is four, and the comment used to say something else
///
/// This line read "every lane the instruction wrote must be accounted for by the
/// copy", which describes a condition the code does not test: it counts REGISTER
/// COPIES and compares against the literal 4, never against how many lanes the
/// instruction actually wrote. The two readings only come apart for an
/// instruction that writes fewer than four lanes and copies every one of them
/// lane-for-lane from one source — and no such instruction was found.
///
/// Measured 2026-08-18 by logging every call that ends here with a consistent
/// single source and `lanes_seen` in `1..=3` (a superset of the disagreement),
/// across 752 fixture objects (`{gcc,clang} x {O0,O2}` over
/// `tests/decompiler_fixtures/src`) and 376 `samples/binaries` images: 134 hits,
/// every one of them `lanes_seen == 2` with all FOUR lanes written — a packed
/// shuffle that computes lanes 0 and 1 and copies lanes 2 and 3. Both readings
/// decline those, so the general condition would admit exactly nothing extra and
/// widening the code buys nothing. The comment was the wrong half.
///
/// The reason four is also the right number: the fallback this guards is
/// `Op::Concat { hi: _d1, lo: _d0 }`, which rebuilds the scalar view from the
/// destination's own low lanes. Taking the SOURCE's scalar view instead is only
/// equivalent when the destination IS the source, and a partial lane copy does
/// not establish that.
fn single_source_of_lane_copy(ops: &[Op], register: &str) -> Option<String> {
    let mut source: Option<String> = None;
    let mut lanes_seen = 0usize;
    for op in ops {
        let Op::Assign {
            dst: VReg::Phys(dst),
            src: Value::Reg(VReg::Phys(src)),
        } = op
        else {
            continue;
        };
        let Some((dst_register, dst_lane)) = dst.split_once("_d") else {
            continue;
        };
        if dst_register != register {
            continue;
        }
        let (src_register, src_lane) = src.split_once("_d")?;
        if src_lane != dst_lane {
            return None;
        }
        match &source {
            Some(known) if known != src_register => return None,
            Some(_) => {}
            None => source = Some(src_register.to_string()),
        }
        lanes_seen += 1;
    }
    // All four lanes must be accounted for by the copy; see the doc comment for
    // why this is the literal 4 and not the count of lanes written.
    (lanes_seen == 4).then_some(source?)
}

/// Mirror a scalar XMM write into the dword lanes it covers.
///
/// This is the direction the bridge did not have, and its absence erased whole
/// function bodies. Every compiler spells `fabs`, `-x` and `copysign` as a
/// SCALAR load followed by a PACKED mask —
/// `movss -0x4(%rbp),%xmm0 ; xorps %xmm1,%xmm0` is GCC's entire
/// `float negate(float v) { return -v; }` — so the `movss` defined `xmm0` and
/// the `xorps` then read `xmm0_d0`..`xmm0_d3`, four lanes no instruction had
/// ever written. Undefined lanes fold to zero, the mask produced zero, and the
/// recovered body was `return 0;`.
///
/// # The rule is per instruction, and the differences are the point
///
/// A scalar SSE operation writes the low 4 or 8 bytes of its destination. What
/// happens to the bits ABOVE that is NOT uniform, so this is a table and not a
/// rule (Intel SDM Vol. 2, the "Operation" section of each entry):
///
/// ```text
///   movss  xmm, m32     DEST[31:0]  := SRC   DEST[127:32]  := 0      ZEROES
///   movss  xmm, xmm     DEST[31:0]  := SRC   DEST[127:32]  unchanged PRESERVES
///   movsd  xmm, m64     DEST[63:0]  := SRC   DEST[127:64]  := 0      ZEROES
///   movsd  xmm, xmm     DEST[63:0]  := SRC   DEST[127:64]  unchanged PRESERVES
///   addss/subss/mulss/divss/sqrtss/cvtsi2ss/cvtsd2ss
///                       DEST[31:0]  := f(..) DEST[127:32]  unchanged PRESERVES
///   addsd/subsd/mulsd/divsd/sqrtsd/cvtsi2sd/cvtss2sd
///                       DEST[63:0]  := f(..) DEST[127:64]  unchanged PRESERVES
/// ```
///
/// The MOV forms are the only ones whose upper bits depend on the SOURCE
/// operand, and getting that backwards is not cosmetic in either direction:
/// treating `movss xmm, xmm` as zeroing discards a live high half, and treating
/// `movss xmm, m32` as preserving leaves the sign-mask `xorps` reading whatever
/// the register held before — which is the defect above, one instruction later.
///
/// A PRESERVED lane is left undefined here on purpose. Nothing in the LLIR
/// spells "unchanged"; not defining the lane IS unchanged, because a lane is an
/// ordinary physical register whose previous definition still reaches.
///
/// # Spelling
///
/// The lanes are derived from the SCALAR NAME with `Trunc`/`Extract` rather than
/// re-read from the instruction's own source. For the memory forms the
/// alternative would be two or four narrow loads of the same address, which is
/// bit-identical and inference-hostile: `packed_qword_half_move_ops` documents
/// the measurement where splitting one 8-byte access into two 4-byte ones made
/// a spill slot two `int` frame objects and silently dropped half a returned
/// aggregate. One access, unpacked from the value, keeps the width evidence and
/// the lane precision at once.
///
/// That is not an argument from the earlier case, it was measured again here.
/// Building the narrow-load spelling and running `@vector-float` gave the same
/// twelve improvements AND THREE REGRESSIONS —
/// `175_float_matrix_kernel:{clang:O0:dot_product_f32, clang:O0:dot_product_f64,
/// gcc:O0:sum_of_squares_f32}`, all three of them functions whose floats live in
/// a stack frame the extra narrow accesses re-partition.
///
/// The MNEMONIC TABLE was measured the same way. Restricting it to MOVSS/MOVSD
/// and dropping the arithmetic and conversion rows leaves the fixture verdicts
/// identical (twelve improvements, no regressions) but costs one def-use census
/// violation: 298 against 297, `clang:O2` 245 against 244 and `gcc:O2` 115
/// against 114. The rows stay.
///
/// # Interaction with the other direction
///
/// Lanes the lowering already defined for itself are never redefined — that is
/// what keeps `movlpd xmm, m64` (which writes both spellings itself) at one
/// definition per lane. And because this leaves the scalar name defined,
/// [`synchronise_xmm_views`] skips the register entirely, so
/// `single_source_of_lane_copy` is never consulted for a scalar producer and
/// its `lanes_seen == 4` predicate is untouched.
pub(super) fn split_xmm_scalar_view(instr: &iced_x86::Instruction, ops: &mut Vec<Op>) {
    use std::collections::BTreeSet;

    let Some(write) = scalar_xmm_write(instr) else {
        return;
    };
    let register = super::reg_name(instr.op_register(0));

    let mut already_defined: BTreeSet<String> = BTreeSet::new();
    for op in ops.iter() {
        if let (Some(VReg::Phys(name)), _) = crate::ir::use_def::def_uses(op) {
            already_defined.insert(name);
        }
    }
    // The lowering may have declined to model this operand shape and emitted an
    // `Op::Unknown`, which defines nothing. There is then no scalar value to
    // mirror, and inventing lanes from an undefined name would be worse than
    // the gap it closes.
    if !already_defined.contains(&register) {
        return;
    }

    let scalar = Value::Reg(VReg::phys(&register));
    let mut split = vec![Op::Trunc {
        dst: packed_dword_lane(&register, 0),
        src: scalar.clone(),
        from: Width::W64,
        to: Width::W32,
    }];
    if write.bytes == 8 {
        split.push(Op::Extract {
            dst: packed_dword_lane(&register, 1),
            src: scalar,
            hi: 64,
            lo: 32,
        });
    }
    if write.zeroes_upper_bits {
        let first_zeroed = usize::from(write.bytes) / 4;
        split.extend((first_zeroed..4).map(|lane| Op::Assign {
            dst: packed_dword_lane(&register, lane),
            src: Value::Const(0),
        }));
    }
    split.retain(|op| match crate::ir::use_def::def_uses(op).0 {
        Some(VReg::Phys(name)) => !already_defined.contains(&name),
        _ => true,
    });
    ops.extend(split);
}

/// The lane footprint of one scalar XMM write, as the SDM states it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScalarXmmWrite {
    /// Bytes of the destination the instruction defines: 4 for a `*ss` form,
    /// 8 for a `*sd` one.
    bytes: u8,
    /// Whether the destination bits above those bytes become zero (`true`) or
    /// keep the value they already held (`false`).
    zeroes_upper_bits: bool,
}

/// Classify `instr` as a scalar write of an XMM register, or `None`.
///
/// `None` is the answer for every instruction whose lane effect this module has
/// not read out of the SDM, including the packed operations (which write their
/// lanes directly and need no mirror) and the `cvt*2si` family (whose
/// destination is a general-purpose register). Guessing from the mnemonic
/// suffix would be wrong for exactly the cases that matter: `movss` and `addss`
/// share a suffix and disagree about the upper bits.
///
/// The string `movsd` (`Code::Movsd_m32_m32`) shares a mnemonic with the scalar
/// one and is excluded by the register test on operand 0 — it has two memory
/// operands and no register at all.
fn scalar_xmm_write(instr: &iced_x86::Instruction) -> Option<ScalarXmmWrite> {
    use iced_x86::{Mnemonic, OpKind};

    if instr.op_count() != 2 || instr.op_kind(0) != OpKind::Register {
        return None;
    }
    let destination = super::reg_name(instr.op_register(0));
    if !destination
        .strip_prefix("xmm")
        .is_some_and(|index| index.parse::<u8>().is_ok())
    {
        return None;
    }
    // Only the two MOV forms take their upper-bit rule from the source operand.
    let zeroing_move = instr.op_kind(1) == OpKind::Memory;
    let write = match instr.mnemonic() {
        Mnemonic::Movss => ScalarXmmWrite {
            bytes: 4,
            zeroes_upper_bits: zeroing_move,
        },
        Mnemonic::Movsd => ScalarXmmWrite {
            bytes: 8,
            zeroes_upper_bits: zeroing_move,
        },
        Mnemonic::Addss
        | Mnemonic::Subss
        | Mnemonic::Mulss
        | Mnemonic::Divss
        | Mnemonic::Sqrtss
        | Mnemonic::Cvtsi2ss
        | Mnemonic::Cvtsd2ss => ScalarXmmWrite {
            bytes: 4,
            zeroes_upper_bits: false,
        },
        Mnemonic::Addsd
        | Mnemonic::Subsd
        | Mnemonic::Mulsd
        | Mnemonic::Divsd
        | Mnemonic::Sqrtsd
        | Mnemonic::Cvtsi2sd
        | Mnemonic::Cvtss2sd => ScalarXmmWrite {
            bytes: 8,
            zeroes_upper_bits: false,
        },
        _ => return None,
    };
    Some(write)
}
