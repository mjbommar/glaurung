//! The SSE string-primitive family: the packed operations glibc's `strlen`,
//! `strcmp` and `memcmp` are built from, plus their word- and qword-granular
//! neighbours.
//!
//! Every instruction here shares one defect and two possible answers to it.
//!
//! The defect: an unlifted instruction leaves [`Op::Unknown`], and
//! `use_def::def_uses` reports `Unknown` as defining nothing and using nothing.
//! An XMM destination is therefore not "conservatively modelled" -- it is
//! *invisible*. Register dataflow believes the destination was never written,
//! so whatever the register held before flows straight past the instruction
//! into its consumers. `lift_function::lower_unknowns` then rewrites the
//! residue into [`Op::opaque`](crate::ir::types::Op::opaque), which is an
//! `Op::Intrinsic` with EMPTY `ins`/`outs` -- conservative about memory and
//! silent about registers, so the lie survives into the executable IR.
//!
//! The two answers, and how this module chooses between them:
//!
//! * **Lift it.** Used when the operation's granularity is at least 16 bits,
//!   because [`super::packed`] already describes an XMM register as four
//!   32-bit dword lanes and word/dword/qword fields sit inside those lanes at
//!   *static* offsets. `punpckhqdq`, `shufpd`, `pshuflw`, `pshufhw`,
//!   `punpcklwd`, `psrlq`, `pmuludq` and the `pinsr*` family are all exactly
//!   expressible with `Trunc`/`Extract`/`ZExt`/`Bin`, and the result is
//!   constant-foldable.
//!
//! * **Declare the register effect only.** Used for the byte-parallel core --
//!   `pcmpeqb`, `pcmpgtb`, `punpcklbw`, `pmovmskb`, `packssdw`, `pshufb`. These
//!   emit a single-output [`Op::Intrinsic`](crate::ir::types::Op::Intrinsic)
//!   **per destination lane**, whose `ins` name exactly the lanes that lane's
//!   value depends on and whose `outs` name the lane it writes. That fixes the
//!   dataflow lie -- which is the actual defect -- without claiming to compute
//!   the value.
//!
//!   Per-lane single-output is not a stylistic choice. `value_number.rs` tags a
//!   multi-output intrinsic with *nothing* (see its `outs.len() <= 1` guard):
//!   a four-output `pcmpeqb` would leave every operand and every destination
//!   unversioned, which trades one dataflow lie for another. One intrinsic per
//!   lane fits the three-address SSA model exactly and states the real
//!   dependency structure, which for a byte-parallel operation genuinely IS
//!   lane-local. This is the shape `lift_arm64::packed` already uses for NEON
//!   `TBL` (`packed_byte_table_16`) and `USHL` (`packed_signed_shift_u32`).
//!
//! Why not lift the byte-parallel six as well: they ARE expressible -- every
//! byte index in `pcmpeqb`, `punpcklbw` and `pmovmskb` is a compile-time
//! constant, so each is a finite tree of `And`/`Shl`/`Or`/`Ite`. The reason is
//! cost, not impossibility: `pcmpeqb` needs sixteen byte comparisons rebuilt
//! into four lanes (~80 LLIR ops), and its consumers in a real `strlen` are
//! `pmovmskb` and `bsf`, so the exact value buys nothing that the declared
//! dependency does not. `pshufb` is the one true exception -- its byte indices
//! come from a runtime register, so each output byte is a 16-way select on a
//! value only known at execution time, and there is no static expression at
//! all.
//!
//! Both XMM spellings stay consistent for free: every lowering here writes
//! `_dN` lane names, and `super::xmm_views::synchronise_xmm_views` rebuilds the
//! whole-register view from lanes 0 and 1 after the instruction's ops are
//! emitted. It reads definitions through `def_uses`, which reports a
//! single-output intrinsic's `outs[0]` -- so a lane written by an intrinsic
//! participates in the reconciliation exactly as a lane written by an `Assign`
//! does.

use iced_x86::{OpKind, Register};

use crate::ir::types::*;

use super::packed::{is_xmm_register, packed_dword_lane, packed_dword_sources};
use super::{mem_op_of, reg_name, zero_extending_gp_view};

// Temporary numbering. Each lowering below is one machine instruction, so these
// only have to be distinct *within* a single lift; the file-wide convention of
// giving each lowering its own block is kept so a future combination of two
// helpers cannot silently alias. 130.. is the first range `lift_x86` and its
// existing submodules do not use.
const WORD_TEMPS: u32 = 130; // 130..=137 -- eight 16-bit word snapshots
const LANE_TEMPS: u32 = 138; // 138..=141 -- four 32-bit destination snapshots
const SOURCE_TEMPS: u32 = 146; // 146..=149 -- memory-operand lane loads
const SCRATCH_TEMPS: u32 = 150; // 150..=157 -- widening/shifting scratch
const QWORD_TEMPS: u32 = 158; // 158..=163 -- 64-bit intermediates

/// The mnemonic, lowercased, as the census and the opaque-marker path spell it.
fn mnemonic_of(instr: &iced_x86::Instruction) -> String {
    format!("{:?}", instr.mnemonic()).to_ascii_lowercase()
}

fn unknown(instr: &iced_x86::Instruction) -> Vec<Op> {
    vec![Op::Unknown {
        mnemonic: mnemonic_of(instr),
    }]
}

/// Read one 16-bit word out of a 32-bit lane value.
///
/// `half == 0` is the low word, which is a truncation; `half == 1` is the high
/// word, which is a bit extraction. This is the same split
/// `super::packed::packed_word_extract_ops` makes for `PEXTRW`.
fn extract_word(source: Value, half: usize, dst: VReg) -> Op {
    if half == 0 {
        Op::Trunc {
            dst,
            src: source,
            from: Width::W32,
            to: Width::W16,
        }
    } else {
        Op::Extract {
            dst,
            src: source,
            hi: 32,
            lo: 16,
        }
    }
}

/// Build a 32-bit lane from two 16-bit words: `dst = zext(low) | (zext(high) << 16)`.
///
/// Deliberately NOT [`Op::Concat`]: `Concat`'s shift distance is the width of
/// its `lo` operand, and a `VReg::Temp` carries no width, so a concat of two
/// 16-bit temporaries would be read at whatever width the consumer inferred.
/// The existing `Concat` uses in [`super::packed`] concatenate `_dN` lane
/// names, whose width their spelling states. Explicit `ZExt`/`Shl`/`Or` states
/// the width in the ops themselves and cannot be misread.
fn combine_words(dst: VReg, low: VReg, high: VReg, scratch: u32) -> Vec<Op> {
    let widened_low = VReg::Temp(scratch);
    let widened_high = VReg::Temp(scratch + 1);
    vec![
        Op::ZExt {
            dst: widened_low.clone(),
            src: Value::Reg(low),
            from: Width::W16,
            to: Width::W32,
        },
        Op::ZExt {
            dst: widened_high.clone(),
            src: Value::Reg(high),
            from: Width::W16,
            to: Width::W32,
        },
        Op::Bin {
            dst: widened_high.clone(),
            op: BinOp::Shl,
            lhs: Value::Reg(widened_high.clone()),
            rhs: Value::Const(16),
        },
        Op::Bin {
            dst,
            op: BinOp::Or,
            lhs: Value::Reg(widened_low),
            rhs: Value::Reg(widened_high),
        },
    ]
}

/// Snapshot the named dword lanes of the destination register into temporaries.
///
/// Every operation in this module may name the same register twice
/// (`punpcklbw %xmm0,%xmm0` is legal and occurs), and several write lane 0
/// before reading lane 1. Reading the destination up front makes the in-place
/// form exact by construction.
///
/// `lanes` is not a convenience. A snapshot IS a read, and a read of a lane the
/// instruction does not touch is an invented dataflow edge: `punpcklbw` only
/// consumes the low quadword of each operand, so snapshotting lanes 2 and 3
/// would tell the definedness oracle that this instruction reads two values it
/// provably ignores -- and if nothing defined them, that is a definition-before-
/// use violation the machine never justified. Each caller names exactly the
/// lanes its instruction reads, and unnamed lanes come back `None` so a
/// mismatch fails a test rather than silently reading an unwritten temporary.
fn snapshot_destination(
    dst: Register,
    first_temp: u32,
    lanes: &[usize],
) -> (Vec<Op>, [Option<Value>; 4]) {
    let mut ops = Vec::with_capacity(lanes.len());
    let mut values: [Option<Value>; 4] = [None, None, None, None];
    for &lane in lanes {
        let temporary = VReg::Temp(first_temp + lane as u32);
        ops.push(Op::Assign {
            dst: temporary.clone(),
            src: Value::Reg(packed_dword_lane(dst, lane)),
        });
        values[lane] = Some(Value::Reg(temporary));
    }
    (ops, values)
}

/// The snapshot of destination lane `lane`, which the caller asked for.
fn snapshotted(destination: &[Option<Value>; 4], lane: usize) -> Value {
    destination[lane]
        .clone()
        .expect("a lowering read a destination lane it did not snapshot")
}

/// The four source lanes, materialised into temporaries when the source names
/// the SAME register as the destination.
///
/// [`packed_dword_sources`] returns LIVE lane names for a register operand,
/// which is right when the two registers differ and wrong when they do not.
/// `punpcklbw %xmm0,%xmm0`, `shufpd $1,%xmm0,%xmm0` and `packssdw %xmm0,%xmm0`
/// are all legal, and every lowering below that writes lane 0 before reading
/// lane 1 or 2 of its source would otherwise read a lane this same instruction
/// had already overwritten. The destination is snapshotted for exactly this
/// reason by [`snapshot_destination`]; the source needs the same treatment and
/// only when it aliases, so the ordinary two-register form keeps naming its
/// operand directly.
///
/// `SOURCE_TEMPS` is free to reuse here: [`packed_dword_sources`] only spends
/// that range on a MEMORY operand, and a memory operand cannot alias a
/// register.
fn source_lanes(instr: &iced_x86::Instruction, lanes: &[usize]) -> Option<(Vec<Op>, Vec<Value>)> {
    let (mut ops, mut sources) = packed_dword_sources(instr, SOURCE_TEMPS)?;
    if instr.op_kind(1) != OpKind::Register || instr.op_register(1) != instr.op_register(0) {
        return Some((ops, sources));
    }
    // Only the lanes this instruction actually reads, for the same reason
    // [`snapshot_destination`] takes a lane list: a snapshot is a read.
    for &lane in lanes {
        let temporary = VReg::Temp(SOURCE_TEMPS + lane as u32);
        ops.push(Op::Assign {
            dst: temporary.clone(),
            src: sources[lane].clone(),
        });
        sources[lane] = Value::Reg(temporary);
    }
    Some((ops, sources))
}

/// One single-output intrinsic writing one destination lane.
fn lane_intrinsic(dst: Register, lane: usize, name: &str, ins: Vec<Value>) -> Op {
    Op::Intrinsic {
        name: name.to_string(),
        ins,
        outs: vec![(packed_dword_lane(dst, lane), Width::W32)],
        reads_mem: false,
        writes_mem: false,
    }
}

// --- effect-only lowerings ------------------------------------------------

/// `PCMPEQB` / `PCMPGTB`: sixteen independent byte comparisons, each writing an
/// all-ones or all-zero byte mask.
///
/// Lane-local: result lane `N` is a function of lane `N` of both operands and
/// nothing else, so four single-output intrinsics state the dependency exactly.
/// One name serves all four lanes because the function IS the same for each --
/// which also makes them safe to value-number together when their inputs agree.
pub(super) fn packed_byte_compare_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
    {
        return unknown(instr);
    }
    let Some((mut ops, sources)) = source_lanes(instr, &[0, 1, 2, 3]) else {
        return unknown(instr);
    };
    let name = format!("x86.{}", mnemonic_of(instr));
    let dst = instr.op_register(0);
    for (lane, source) in sources.into_iter().enumerate() {
        ops.push(lane_intrinsic(
            dst,
            lane,
            &name,
            vec![Value::Reg(packed_dword_lane(dst, lane)), source],
        ));
    }
    ops
}

/// `PUNPCKLBW`: interleave the low eight bytes of each operand.
///
/// Result byte `2i` is destination byte `i` and result byte `2i+1` is source
/// byte `i`, for `i` in `0..8`. In lane terms result lanes 0 and 1 are two
/// different functions of the SAME pair of input lanes (destination lane 0 and
/// source lane 0), and lanes 2 and 3 the same two functions of lane 1 -- hence
/// the `.lo`/`.hi` name split, without which value numbering would be entitled
/// to collapse two intrinsics that compute different halves.
pub(super) fn packed_byte_unpack_low_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
    {
        return unknown(instr);
    }
    let Some((mut ops, sources)) = source_lanes(instr, &[0, 1]) else {
        return unknown(instr);
    };
    let dst = instr.op_register(0);
    let (snapshot, destination) = snapshot_destination(dst, LANE_TEMPS, &[0, 1]);
    ops.extend(snapshot);
    for input_lane in 0..2 {
        let inputs = vec![
            snapshotted(&destination, input_lane),
            sources[input_lane].clone(),
        ];
        for (half, suffix) in ["lo", "hi"].into_iter().enumerate() {
            ops.push(lane_intrinsic(
                dst,
                input_lane * 2 + half,
                &format!("x86.punpcklbw.{suffix}"),
                inputs.clone(),
            ));
        }
    }
    ops
}

/// `PMOVMSKB`: one bit per source byte, sixteen bits, into a general register.
///
/// This is the escape hatch out of the vector domain -- in every `strlen`,
/// `strcmp` and `memcmp` built on SSE2 the mask it produces is what the
/// following `bsf`/`test` branches on. A single output, four inputs; the
/// 32-bit destination is spelled the way `super::packed::movd_ops` spells one,
/// so the write through `eax` is recorded as defining `rax` zero-extended
/// rather than only its low half.
pub(super) fn packed_byte_sign_mask_ops(instr: &iced_x86::Instruction, bits: u32) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
        || is_xmm_register(instr.op_register(0))
        || !is_xmm_register(instr.op_register(1))
    {
        return unknown(instr);
    }
    let source = instr.op_register(1);
    let mask = VReg::Temp(SCRATCH_TEMPS);
    let destination = reg_name(instr.op_register(0));
    let mut ops = vec![Op::Intrinsic {
        name: "x86.pmovmskb".to_string(),
        ins: (0..4)
            .map(|lane| Value::Reg(packed_dword_lane(source, lane)))
            .collect(),
        outs: vec![(mask.clone(), Width::W32)],
        reads_mem: false,
        writes_mem: false,
    }];
    ops.push(
        if bits == 64 && zero_extending_gp_view(&destination, bits).is_some() {
            Op::ZExt {
                dst: VReg::phys(destination),
                src: Value::Reg(mask),
                from: Width::W32,
                to: Width::W64,
            }
        } else {
            Op::Assign {
                dst: VReg::phys(destination),
                src: Value::Reg(mask),
            }
        },
    );
    ops
}

/// `PACKSSDW`: signed-saturate eight dwords into eight words.
///
/// Saturation is expressible -- two comparisons and two selects per word -- but
/// it is the one member of this family where an off-by-one in the clamp bound
/// produces a plausible wrong number rather than an obviously wrong one, and it
/// occurs six times in the whole sample corpus. Declared, not computed: result
/// lane 0 is a function of destination lanes 0 and 1, lane 1 of destination
/// lanes 2 and 3, and lanes 2 and 3 of the source's four lanes in the same
/// pairing.
pub(super) fn packed_dword_saturating_pack_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
    {
        return unknown(instr);
    }
    let Some((mut ops, sources)) = source_lanes(instr, &[0, 1, 2, 3]) else {
        return unknown(instr);
    };
    let dst = instr.op_register(0);
    let (snapshot, destination) = snapshot_destination(dst, LANE_TEMPS, &[0, 1, 2, 3]);
    ops.extend(snapshot);
    let pairs = [
        (snapshotted(&destination, 0), snapshotted(&destination, 1)),
        (snapshotted(&destination, 2), snapshotted(&destination, 3)),
        (sources[0].clone(), sources[1].clone()),
        (sources[2].clone(), sources[3].clone()),
    ];
    for (lane, (low, high)) in pairs.into_iter().enumerate() {
        ops.push(lane_intrinsic(dst, lane, "x86.packssdw", vec![low, high]));
    }
    ops
}

/// `PSHUFB`: byte shuffle with RUNTIME indices.
///
/// The only member of this family with no static expression at all. Each of the
/// sixteen result bytes selects one of sixteen source bytes -- or zero, when the
/// index's top bit is set -- using an index that is a value in a register, not a
/// field in the encoding. Modelling it as anything other than "every output
/// lane depends on every input lane" would be an invention. (`lift_arm64`'s
/// `packed_byte_table_16` does spell NEON's equivalent as a nested select tree
/// at the AST layer; the same could be done here, and this intrinsic's operand
/// list is deliberately the same shape so that it can be.)
pub(super) fn packed_byte_shuffle_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
    {
        return unknown(instr);
    }
    let Some((mut ops, indices)) = source_lanes(instr, &[0, 1, 2, 3]) else {
        return unknown(instr);
    };
    let dst = instr.op_register(0);
    let (snapshot, table) = snapshot_destination(dst, LANE_TEMPS, &[0, 1, 2, 3]);
    ops.extend(snapshot);
    let inputs: Vec<Value> = (0..4)
        .map(|lane| snapshotted(&table, lane))
        .chain(indices)
        .collect();
    for lane in 0..4 {
        ops.push(lane_intrinsic(
            dst,
            lane,
            &format!("x86.pshufb.lane{lane}"),
            inputs.clone(),
        ));
    }
    ops
}

// --- exact lowerings ------------------------------------------------------

/// `PUNPCKHQDQ`: `dst = [dst_q1, src_q1]`, i.e. lanes `[d2, d3, s2, s3]`.
///
/// A pure lane permutation at 64-bit granularity, so it needs no bit surgery at
/// all -- only the snapshot that keeps the in-place form exact.
pub(super) fn packed_qword_unpack_high_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
    {
        return unknown(instr);
    }
    let Some((mut ops, sources)) = source_lanes(instr, &[2, 3]) else {
        return unknown(instr);
    };
    let dst = instr.op_register(0);
    let (snapshot, destination) = snapshot_destination(dst, LANE_TEMPS, &[2, 3]);
    ops.extend(snapshot);
    for (lane, source) in [
        snapshotted(&destination, 2),
        snapshotted(&destination, 3),
        sources[2].clone(),
        sources[3].clone(),
    ]
    .into_iter()
    .enumerate()
    {
        ops.push(Op::Assign {
            dst: packed_dword_lane(dst, lane),
            src: source,
        });
    }
    ops
}

/// `SHUFPD dst, src, imm8`: select one 64-bit half of each operand.
///
/// `imm[0]` picks which half of the destination becomes the result's low
/// quadword, `imm[1]` which half of the source becomes its high quadword. Both
/// selectors are encoding fields, so this is a static lane permutation.
///
/// Lifting it also opens a gate that being unlifted was holding shut:
/// `ast::float_gate::unmodelled_x86_float_mnemonic` classifies any mnemonic
/// beginning `shuf` as an unmodelled float producer, and one of those anywhere
/// in a function makes the whole function's scalar-float arithmetic render as
/// dropped assignments.
pub(super) fn packed_double_shuffle_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 3
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(2) != OpKind::Immediate8
        || !is_xmm_register(instr.op_register(0))
    {
        return unknown(instr);
    }
    let dst = instr.op_register(0);
    let control = instr.immediate8();
    let low_half = usize::from(control & 1);
    let high_half = usize::from((control >> 1) & 1);
    let Some((mut ops, sources)) = source_lanes(instr, &[high_half * 2, high_half * 2 + 1]) else {
        return unknown(instr);
    };
    let (snapshot, destination) =
        snapshot_destination(dst, LANE_TEMPS, &[low_half * 2, low_half * 2 + 1]);
    ops.extend(snapshot);
    for (lane, source) in [
        snapshotted(&destination, low_half * 2),
        snapshotted(&destination, low_half * 2 + 1),
        sources[high_half * 2].clone(),
        sources[high_half * 2 + 1].clone(),
    ]
    .into_iter()
    .enumerate()
    {
        ops.push(Op::Assign {
            dst: packed_dword_lane(dst, lane),
            src: source,
        });
    }
    ops
}

/// `PMULUDQ`: two unsigned 32x32 -> 64 multiplies, of the LOW dword of each
/// quadword, written back as a full quadword.
///
/// Lanes 1 and 3 of both operands are not read at all -- the odd dwords are
/// discarded, which is the whole point of the instruction -- and the 64-bit
/// product is exact in the existing scalar vocabulary.
pub(super) fn packed_unsigned_dword_multiply_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
    {
        return unknown(instr);
    }
    let Some((mut ops, sources)) = source_lanes(instr, &[0, 2]) else {
        return unknown(instr);
    };
    let dst = instr.op_register(0);
    for quadword in 0..2usize {
        let low_lane = quadword * 2;
        let left = VReg::Temp(QWORD_TEMPS + quadword as u32 * 3);
        let right = VReg::Temp(QWORD_TEMPS + quadword as u32 * 3 + 1);
        let product = VReg::Temp(QWORD_TEMPS + quadword as u32 * 3 + 2);
        ops.extend([
            Op::ZExt {
                dst: left.clone(),
                src: Value::Reg(packed_dword_lane(dst, low_lane)),
                from: Width::W32,
                to: Width::W64,
            },
            Op::ZExt {
                dst: right.clone(),
                src: sources[low_lane].clone(),
                from: Width::W32,
                to: Width::W64,
            },
            Op::Bin {
                dst: product.clone(),
                op: BinOp::Mul,
                lhs: Value::Reg(left),
                rhs: Value::Reg(right),
            },
            Op::Trunc {
                dst: packed_dword_lane(dst, low_lane),
                src: Value::Reg(product.clone()),
                from: Width::W64,
                to: Width::W32,
            },
            Op::Extract {
                dst: packed_dword_lane(dst, low_lane + 1),
                src: Value::Reg(product),
                hi: 64,
                lo: 32,
            },
        ]);
    }
    ops
}

/// `PSRLQ xmm, imm8`: logically shift each 64-bit half right.
///
/// Intel specifies a zero result, not a masked count, for a count above 63 --
/// the same rule `super::packed::packed_dword_immediate_shift_left_ops` applies
/// at 32 bits. The register/memory count form is NOT lifted (it takes the count
/// from the low 64 bits of an XMM register, which is a second quadword read
/// this lowering has no reason to invent); it falls through to the effect-only
/// declaration below, so it is still not invisible.
pub(super) fn packed_qword_immediate_logical_shift_right_ops(
    instr: &iced_x86::Instruction,
) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
    {
        return unknown(instr);
    }
    if instr.op_kind(1) != OpKind::Immediate8 {
        return declare_xmm_effect_ops(instr);
    }
    let dst = instr.op_register(0);
    let count = instr.immediate8();
    let mut ops = Vec::with_capacity(8);
    for quadword in 0..2usize {
        let low_lane = quadword * 2;
        let high_lane = low_lane + 1;
        if count > 63 {
            ops.extend([low_lane, high_lane].into_iter().map(|lane| Op::Assign {
                dst: packed_dword_lane(dst, lane),
                src: Value::Const(0),
            }));
            continue;
        }
        let value = VReg::Temp(QWORD_TEMPS + quadword as u32);
        ops.extend([
            Op::Concat {
                dst: value.clone(),
                hi: Value::Reg(packed_dword_lane(dst, high_lane)),
                lo: Value::Reg(packed_dword_lane(dst, low_lane)),
            },
            Op::Bin {
                dst: value.clone(),
                op: BinOp::Shr,
                lhs: Value::Reg(value.clone()),
                rhs: Value::Const(i64::from(count)),
            },
            Op::Trunc {
                dst: packed_dword_lane(dst, low_lane),
                src: Value::Reg(value.clone()),
                from: Width::W64,
                to: Width::W32,
            },
            Op::Extract {
                dst: packed_dword_lane(dst, high_lane),
                src: Value::Reg(value),
                hi: 64,
                lo: 32,
            },
        ]);
    }
    ops
}

/// `PSHUFLW` / `PSHUFHW`: permute the four words of ONE quadword by an
/// immediate, copying the other quadword through unchanged.
///
/// `high` selects which quadword is shuffled. Both the selectors and the
/// quadword are encoding fields, so every word index here is static: read the
/// four words of the shuffled half into temporaries, then rebuild its two lanes
/// from the selected pair.
pub(super) fn packed_word_shuffle_ops(instr: &iced_x86::Instruction, high: bool) -> Vec<Op> {
    if instr.op_count() != 3
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(2) != OpKind::Immediate8
        || !is_xmm_register(instr.op_register(0))
    {
        return unknown(instr);
    }
    let Some((mut ops, sources)) = source_lanes(instr, &[0, 1, 2, 3]) else {
        return unknown(instr);
    };
    let dst = instr.op_register(0);
    let control = instr.immediate8();
    let shuffled_base = usize::from(high) * 2;
    let copied_base = 2 - shuffled_base;

    // The four words of the shuffled quadword, read before anything is written.
    for word in 0..4usize {
        ops.push(extract_word(
            sources[shuffled_base + word / 2].clone(),
            word % 2,
            VReg::Temp(WORD_TEMPS + word as u32),
        ));
    }
    // The untouched quadword is a straight lane copy.
    for lane in [copied_base, copied_base + 1] {
        ops.push(Op::Assign {
            dst: packed_dword_lane(dst, lane),
            src: sources[lane].clone(),
        });
    }
    for lane in 0..2usize {
        let low = usize::from((control >> (lane * 4)) & 0x3);
        let high_word = usize::from((control >> (lane * 4 + 2)) & 0x3);
        ops.extend(combine_words(
            packed_dword_lane(dst, shuffled_base + lane),
            VReg::Temp(WORD_TEMPS + low as u32),
            VReg::Temp(WORD_TEMPS + high_word as u32),
            SCRATCH_TEMPS + lane as u32 * 2,
        ));
    }
    ops
}

/// `PUNPCKLWD`: interleave the low four words of each operand.
///
/// Result word `2i` is destination word `i` and result word `2i+1` is source
/// word `i`. Every index is static, so unlike its byte-granular sibling
/// `punpcklbw` this one lands exactly inside the 32-bit lane model: each result
/// lane is one destination word beside one source word.
pub(super) fn packed_word_unpack_low_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
    {
        return unknown(instr);
    }
    let Some((mut ops, sources)) = source_lanes(instr, &[0, 1]) else {
        return unknown(instr);
    };
    let dst = instr.op_register(0);
    for word in 0..4usize {
        ops.push(extract_word(
            Value::Reg(packed_dword_lane(dst, word / 2)),
            word % 2,
            VReg::Temp(WORD_TEMPS + word as u32),
        ));
        ops.push(extract_word(
            sources[word / 2].clone(),
            word % 2,
            VReg::Temp(WORD_TEMPS + 4 + word as u32),
        ));
    }
    for lane in 0..4usize {
        ops.extend(combine_words(
            packed_dword_lane(dst, lane),
            VReg::Temp(WORD_TEMPS + lane as u32),
            VReg::Temp(WORD_TEMPS + 4 + lane as u32),
            SCRATCH_TEMPS + lane as u32 * 2,
        ));
    }
    ops
}

/// `PINSRW` / `PINSRD` / `PINSRQ`: deposit a general-register or memory value
/// into one selected field of an XMM register, leaving every other bit alone.
///
/// `field_bytes` is the width of the inserted field, which the mnemonic states.
/// The selector is an immediate, so the destination lane (and, at 16 bits, the
/// half of it) is known statically -- the value written is an ordinary `Or` of
/// a masked lane with a shifted operand, and no other lane is touched at all.
/// That "no other lane" is the point: an unlifted `pinsr*` did not merely fail
/// to describe the inserted field, it failed to describe the three lanes it
/// leaves untouched, because a consumer of those lanes saw no definition here
/// and no definition is exactly what the previous value flows through.
pub(super) fn packed_insert_ops(instr: &iced_x86::Instruction, field_bytes: u32) -> Vec<Op> {
    if instr.op_count() != 3
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(2) != OpKind::Immediate8
        || !is_xmm_register(instr.op_register(0))
    {
        return unknown(instr);
    }
    let dst = instr.op_register(0);
    let selector = usize::from(instr.immediate8());
    let mut ops = Vec::new();

    // The inserted value, as one register value of `field_bytes` width.
    let inserted = match instr.op_kind(1) {
        OpKind::Register if !is_xmm_register(instr.op_register(1)) => {
            Value::Reg(VReg::phys(reg_name(instr.op_register(1))))
        }
        OpKind::Memory => {
            let temporary = VReg::Temp(SCRATCH_TEMPS);
            let mut addr = mem_op_of(instr);
            addr.size = u8::try_from(field_bytes).expect("insert field width fits MemOp");
            ops.push(Op::Load {
                dst: temporary.clone(),
                addr,
            });
            Value::Reg(temporary)
        }
        _ => return declare_xmm_effect_ops(instr),
    };

    match field_bytes {
        8 => {
            let quadword = selector & 1;
            ops.extend([
                Op::Trunc {
                    dst: packed_dword_lane(dst, quadword * 2),
                    src: inserted.clone(),
                    from: Width::W64,
                    to: Width::W32,
                },
                Op::Extract {
                    dst: packed_dword_lane(dst, quadword * 2 + 1),
                    src: inserted,
                    hi: 64,
                    lo: 32,
                },
            ]);
        }
        4 => ops.push(Op::Assign {
            dst: packed_dword_lane(dst, selector & 3),
            src: inserted,
        }),
        _ => {
            // 16 bits: half of one lane survives, so the lane is rebuilt as
            // `(lane & keep) | (value << shift)`.
            let word = selector & 7;
            let lane = packed_dword_lane(dst, word / 2);
            let shift = if word % 2 == 0 { 0 } else { 16 };
            let keep = if shift == 0 { -65536i64 } else { 0xffff_i64 };
            let kept = VReg::Temp(SCRATCH_TEMPS + 1);
            let field = VReg::Temp(SCRATCH_TEMPS + 2);
            ops.extend([
                Op::Bin {
                    dst: kept.clone(),
                    op: BinOp::And,
                    lhs: Value::Reg(lane.clone()),
                    rhs: Value::Const(keep),
                },
                Op::Bin {
                    dst: field.clone(),
                    op: BinOp::And,
                    lhs: inserted,
                    rhs: Value::Const(0xffff),
                },
            ]);
            if shift != 0 {
                ops.push(Op::Bin {
                    dst: field.clone(),
                    op: BinOp::Shl,
                    lhs: Value::Reg(field.clone()),
                    rhs: Value::Const(shift),
                });
            }
            ops.push(Op::Bin {
                dst: lane,
                op: BinOp::Or,
                lhs: Value::Reg(kept),
                rhs: Value::Reg(field),
            });
        }
    }
    ops
}

/// PCMPGTD compares four signed dwords, writing an all-ones lane for true.
///
/// The register form has been lifted for a long time; the MEMORY source form
/// was not, and it was every one of `pcmpgtd`'s twelve appearances in the
/// sample corpus -- all `pcmpgtd (%rip),%xmm`, each silently claiming to write
/// nothing. Routing it through [`source_lanes`] like every other member of this
/// module is the whole fix.
///
/// It lives here rather than beside `packed_dword_compare_equal_ops` in
/// [`super::packed`] for two reasons: it was on the census list this module
/// exists to clear, and moving it is what kept `packed.rs` under the 1,000-line
/// review threshold that the doc comment above pushed it over.
pub(super) fn packed_dword_compare_greater_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
    {
        return vec![Op::Unknown {
            mnemonic: "pcmpgtd".into(),
        }];
    }
    let Some((mut ops, sources)) = source_lanes(instr, &[0, 1, 2, 3]) else {
        return vec![Op::Unknown {
            mnemonic: "pcmpgtd".into(),
        }];
    };
    for (lane, source) in sources.into_iter().enumerate() {
        let dst = packed_dword_lane(instr.op_register(0), lane);
        let condition = VReg::Temp(SCRATCH_TEMPS + lane as u32);
        // dst > src is the signed comparison src < dst. PCMPGTD writes an
        // all-ones mask for true, not the boolean value one.
        ops.push(Op::Cmp {
            dst: condition.clone(),
            op: CmpOp::Slt,
            lhs: source,
            rhs: Value::Reg(dst.clone()),
        });
        ops.push(Op::Ite {
            dst,
            cond: condition,
            t: Value::Const(-1),
            e: Value::Const(0),
            width: Width::W32,
        });
    }
    ops
}

/// The fallback the exact lowerings share: declare the register effect of an
/// XMM-destination instruction without claiming to compute it.
///
/// Reached only for operand shapes the exact lowerings decline -- a
/// register-count `psrlq`, an XMM source to `pinsrw`. It is deliberately NOT
/// reached when operand 0 is not an XMM register: that shape is something this
/// module did not anticipate, and [`Op::Unknown`] keeps it visible to the
/// census in `lift_x86`'s tests rather than papering over it with a
/// conservative marker.
fn declare_xmm_effect_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    let dst = instr.op_register(0);
    let mnemonic = mnemonic_of(instr);
    let (mut ops, sources) = source_lanes(instr, &[0, 1, 2, 3]).unwrap_or((Vec::new(), Vec::new()));
    let (snapshot, destination) = snapshot_destination(dst, LANE_TEMPS, &[0, 1, 2, 3]);
    ops.extend(snapshot);
    let reads_mem = sources.is_empty() && instr.op_kind(1) == OpKind::Memory;
    let inputs: Vec<Value> = (0..4)
        .map(|lane| snapshotted(&destination, lane))
        .chain(sources)
        .collect();
    for lane in 0..4 {
        ops.push(Op::Intrinsic {
            name: format!("x86.{mnemonic}.lane{lane}"),
            ins: inputs.clone(),
            outs: vec![(packed_dword_lane(dst, lane), Width::W32)],
            reads_mem,
            writes_mem: false,
        });
    }
    ops
}
