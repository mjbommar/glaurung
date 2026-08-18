//! Moving ONE 64-bit half of an XMM register.
//!
//! Six mnemonics with one reason to change: `MOVLPS`/`MOVLPD`/`MOVHPS`/`MOVHPD`
//! between a half and memory, and `MOVLHPS`/`MOVHLPS` between the two halves of
//! two registers. What separates all of them from [`super::packed`]'s
//! whole-register moves is the half they do NOT name: `movq xmm, m64` zeroes
//! bits 64..127, whereas every instruction here leaves the other half exactly as
//! it was, so reusing MOVQ's lowering would invent a zero the machine never
//! wrote.
//!
//! Split out of `packed.rs` when `movlhps`/`movhlps` took that file over the
//! 1,000-line review threshold. The cut is along the family boundary rather than
//! at the line count: these six share the lane bookkeeping, the scratch
//! temporary, and the [`XmmHalf`] vocabulary, and nothing else in `packed.rs`
//! uses any of it.

use iced_x86::OpKind;

use crate::ir::types::*;

use super::packed::{is_xmm_register, packed_dword_lane};
use super::{mem_op_of, reg_name};

/// Move ONE 64-bit half of an XMM register to or from memory, leaving the other
/// half of the register alone.
///
/// This is `MOVLPD`/`MOVLPS` (`half == XmmHalf::Low`, lanes `_d0`/`_d1`) and
/// `MOVHPD`/`MOVHPS` (`half == XmmHalf::High`, lanes `_d2`/`_d3`). All four
/// mnemonics encode ONLY memory forms — `iced_x86` has exactly eight `Code`
/// variants for them, `{Movlpd,Movhpd,Movlps,Movhps}_{xmm_m64,m64_xmm}`, and no
/// register/register variant at all. (`MOVLHPS`/`MOVHLPS` are the reg-reg
/// operations, and they are different instructions with their own mnemonics.)
/// The non-memory arm below is therefore unreachable by construction and exists
/// only so a future VEX/EVEX widening cannot silently acquire wrong semantics.
///
/// What separates these from [`packed_qword_move_ops`] is the half NOT named:
/// `movq xmm, m64` zeroes bits 64..127, whereas `movlpd xmm, m64` leaves them
/// exactly as they were, and `movhpd` leaves bits 0..63 alone. Reusing MOVQ's
/// lowering would therefore invent a zero the machine never wrote.
///
/// The MEMORY side is one 64-bit access, because that is what the machine
/// performs. Splitting it into two dword accesses is bit-identical but not
/// inference-identical: the stack-object recovery reads access widths as
/// evidence of the frame layout, and on `hfa197_quad4f_roundtrip` two 4-byte
/// stores made the spill slot two `int` objects, after which the function's
/// own 8-byte reload of it narrowed to the first four bytes and silently
/// dropped the second `float`. One 8-byte access, unpacked into lanes through
/// a temporary, keeps both the lane precision and the real access width.
///
/// The REGISTER side leaves both XMM spellings consistent. A LOW load defines
/// all three names the transferred bits have — lanes `_d0`/`_d1` and the
/// whole-register scalar view, which IS the low quadword. A HIGH load defines
/// `_d2`/`_d3` and deliberately nothing else, because `movhpd` does not touch
/// the low quadword and rebuilding the scalar name would overwrite a live
/// value. A LOW store READS the whole-register spelling rather than the lanes:
/// the two views are synchronised in one direction only — a lane write is
/// mirrored to the scalar name by [`super::synchronise_xmm_views`], a scalar
/// write is not mirrored to the lanes — so the scalar name is the one spelling
/// live under both kinds of producer. A HIGH store has no scalar spelling
/// available and concatenates its two lanes.
///
/// Clang's `-O0` System V code returns a four-`float` aggregate in `xmm0:xmm1`
/// and spills it with `movlpd %xmm0,-0x38(%rbp) ; movlpd %xmm1,-0x30(%rbp)`.
/// Unlifted, those two stores were `Op::Unknown`, which declares no register
/// reads: every consumer of the returned value vanished, the `SsePair` result
/// split had no users left and was dead-code eliminated, and — because
/// `movlpd` ends in `pd` — `ast::float_gate` classified it an unmodelled float
/// producer and shut the whole-function float gate, costing that one function
/// eight further `cvttss2si` conversions.
pub(super) fn packed_qword_half_move_ops(instr: &iced_x86::Instruction, half: XmmHalf) -> Vec<Op> {
    let mnemonic = || format!("{:?}", instr.mnemonic()).to_ascii_lowercase();
    if instr.op_count() != 2 {
        return vec![Op::Unknown {
            mnemonic: mnemonic(),
        }];
    }
    let (low_lane, high_lane) = (half.first_lane(), half.first_lane() + 1);
    let transfer = VReg::Temp(HALF_MOVE_TEMP);
    match (instr.op_kind(0), instr.op_kind(1)) {
        (OpKind::Register, OpKind::Memory) if is_xmm_register(instr.op_register(0)) => {
            let dst = instr.op_register(0);
            let mut addr = mem_op_of(instr);
            addr.size = 8;
            let mut ops = vec![
                Op::Load {
                    dst: transfer.clone(),
                    addr,
                },
                Op::Trunc {
                    dst: packed_dword_lane(dst, low_lane),
                    src: Value::Reg(transfer.clone()),
                    from: Width::W64,
                    to: Width::W32,
                },
                Op::Extract {
                    dst: packed_dword_lane(dst, high_lane),
                    src: Value::Reg(transfer.clone()),
                    hi: 64,
                    lo: 32,
                },
            ];
            if half == XmmHalf::Low {
                // The whole-register spelling IS the low quadword, and this
                // instruction has just defined all of it. State that from the
                // 64-bit value rather than leaving `synchronise_xmm_views` to
                // rebuild it by concatenating the two lanes back together.
                ops.push(Op::Assign {
                    dst: VReg::phys(reg_name(dst)),
                    src: Value::Reg(transfer),
                });
            }
            ops
        }
        (OpKind::Memory, OpKind::Register) if is_xmm_register(instr.op_register(1)) => {
            let src = instr.op_register(1);
            let mut addr = mem_op_of(instr);
            addr.size = 8;
            match half {
                // Read the WHOLE-REGISTER spelling, not the two lanes. The two
                // views are kept in step in one direction only: a lane write is
                // mirrored to the scalar name by `synchronise_xmm_views`, while
                // a scalar write (every `movsd`, every `cvtsi2sd`) leaves the
                // lanes untouched. The scalar name is therefore the spelling
                // that is live under both producers, and reading the lanes here
                // would find nothing after a scalar one.
                XmmHalf::Low => vec![Op::Store {
                    addr,
                    src: Value::Reg(VReg::phys(reg_name(src))),
                }],
                // Bits 64..127 have no scalar spelling to read, so the high
                // half is assembled from the only names that describe it.
                XmmHalf::High => vec![
                    Op::Concat {
                        dst: transfer.clone(),
                        hi: Value::Reg(packed_dword_lane(src, high_lane)),
                        lo: Value::Reg(packed_dword_lane(src, low_lane)),
                    },
                    Op::Store {
                        addr,
                        src: Value::Reg(transfer),
                    },
                ],
            }
        }
        _ => vec![Op::Unknown {
            mnemonic: mnemonic(),
        }],
    }
}

/// `movlhps xmm1, xmm2` / `movhlps xmm1, xmm2` — copy one 64-bit half of the
/// SOURCE into the OTHER half of the destination, leaving the destination's
/// remaining half exactly as it was.
///
/// These are the register/register siblings of [`packed_qword_half_move_ops`],
/// and the pairing is not cosmetic: `MOVLPS`/`MOVHPS` encode memory operands
/// only, so the reg-reg spelling of "move a quadword between halves" had to be
/// two separate mnemonics, and neither had an arm. Over the committed x86-64
/// corpus `movlhps` is six instructions whose destination lanes were entirely
/// invisible to register dataflow.
///
/// * `movlhps`: `DEST[127:64] <- SRC[63:0]`, `DEST[63:0]` unchanged.
/// * `movhlps`: `DEST[63:0] <- SRC[127:64]`, `DEST[127:64]` unchanged.
///
/// The SOURCE's low quadword is read through the WHOLE-REGISTER scalar spelling
/// rather than through lanes `_d0`/`_d1`, for the reason
/// [`packed_qword_half_move_ops`]'s low store gives: the two views are
/// synchronised in one direction only, so the scalar name is the only spelling
/// live under both a lane producer and a scalar one. The source's HIGH quadword
/// has no scalar spelling at all and is assembled from its two lanes.
///
/// Nothing here writes the destination's scalar name. A `movlhps` does not
/// touch bits 0..63, which IS that name, and a `movhlps` writes lanes
/// `_d0`/`_d1`, which [`super::synchronise_xmm_views`] mirrors into it.
pub(super) fn packed_qword_half_swap_ops(
    instr: &iced_x86::Instruction,
    destination_half: XmmHalf,
) -> Vec<Op> {
    let mnemonic = || format!("{:?}", instr.mnemonic()).to_ascii_lowercase();
    if instr.op_count() != 2
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
        || !is_xmm_register(instr.op_register(0))
        || !is_xmm_register(instr.op_register(1))
    {
        return vec![Op::Unknown {
            mnemonic: mnemonic(),
        }];
    }
    let destination = instr.op_register(0);
    let source = instr.op_register(1);
    // The source half is the one the destination half is NOT.
    let source_half = match destination_half {
        XmmHalf::Low => XmmHalf::High,
        XmmHalf::High => XmmHalf::Low,
    };
    let (source_low, source_high) = (source_half.first_lane(), source_half.first_lane() + 1);
    let (destination_low, destination_high) = (
        destination_half.first_lane(),
        destination_half.first_lane() + 1,
    );

    let transfer = VReg::Temp(HALF_MOVE_TEMP);
    let mut ops = match source_half {
        XmmHalf::Low => vec![Op::Assign {
            dst: transfer.clone(),
            src: Value::Reg(VReg::phys(reg_name(source))),
        }],
        XmmHalf::High => vec![Op::Concat {
            dst: transfer.clone(),
            hi: Value::Reg(packed_dword_lane(source, source_high)),
            lo: Value::Reg(packed_dword_lane(source, source_low)),
        }],
    };
    ops.push(Op::Trunc {
        dst: packed_dword_lane(destination, destination_low),
        src: Value::Reg(transfer.clone()),
        from: Width::W64,
        to: Width::W32,
    });
    ops.push(Op::Extract {
        dst: packed_dword_lane(destination, destination_high),
        src: Value::Reg(transfer),
        hi: 64,
        lo: 32,
    });
    ops
}

/// Scratch register for the 64-bit value a `MOVLP*`/`MOVHP*` transfers.
///
/// Temporaries are scoped to one lifted instruction, so this only has to avoid
/// the other temporaries this module spends inside a single lowering.
const HALF_MOVE_TEMP: u32 = 150;

/// Which 64-bit half of an XMM register a `MOVLP*`/`MOVHP*` names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum XmmHalf {
    /// Bits 0..63 — lanes `_d0`, `_d1`. Also the whole-register scalar view.
    Low,
    /// Bits 64..127 — lanes `_d2`, `_d3`.
    High,
}

impl XmmHalf {
    /// The lower-addressed of this half's two dword lanes.
    fn first_lane(self) -> usize {
        match self {
            XmmHalf::Low => 0,
            XmmHalf::High => 2,
        }
    }
}
