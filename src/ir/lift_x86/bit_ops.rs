//! x86 single-bit and bit-population operations.
//!
//! Five mnemonics that share one property: the whole instruction is about
//! *individual bits* of one general-purpose operand, and every one of them was
//! previously an [`Op::Unknown`]. That matters more than it sounds. `Op::Unknown`
//! declares no footprint at all, so a register destination it names is not
//! over-approximated but INVISIBLE — [`crate::ir::use_def`] answers "nothing" to
//! "what does this define", the def-use census believes the destination was
//! never written, and whatever the register held before flows on to every later
//! reader as if the instruction were not there.
//!
//! Over the committed x86-64 sample corpus that was 234 instructions:
//! `tzcnt` 130, `bts` 82, `popcnt` 14, `btr` 6, `btc` 2. Every one of them is a
//! single-destination write with an exact closed form, which is why they are
//! lifted here rather than declared as opaque effects:
//!
//! * `bt`/`bts`/`btr`/`btc` are `CF = (dst >> n) & 1` followed, for the last
//!   three, by `dst |= 1<<n` / `dst &= ~(1<<n)` / `dst ^= 1<<n`. Ordinary LLIR
//!   throughout — the flag write is its own op, exactly as in
//!   [`super::flags`], so nothing here is a multi-output intrinsic.
//! * `tzcnt` and `popcnt` are pure functions of one operand that C spells
//!   exactly, so each becomes a SINGLE-OUTPUT [`Op::Intrinsic`] that
//!   [`crate::ir::ast::lower_ops`] lowers to
//!   [`crate::ir::ast::WideArithmetic`] and the C backend renders as
//!   `__builtin_ctz`/`__builtin_popcount`. One output per destination is the
//!   shape that works: `value_number.rs` tags a multi-output intrinsic with
//!   nothing, so a two-output spelling would leave every operand AND the
//!   destination unversioned — one dataflow lie traded for another.
//! * `rcr` by one is `(CF << (bits-1)) | (dst >> 1)`, which needs CF as an
//!   input value. `adc`/`sbb` already read `VReg::Flag(Flag::C)` that way.
//!
//! **ZF is UNAFFECTED by the whole bit-test family**, not undefined. Intel SDM
//! Vol. 2A, BT/BTS/BTR/BTC: "The CF flag contains the value of the selected bit.
//! The ZF flag is unaffected. The OF, SF, AF, and PF flags are undefined." The
//! `bt` arm this module absorbed poisoned ZF along with the other four, which
//! would destroy a live ZF that a preceding `cmp` had defined and a following
//! `je` still reads.

use iced_x86::OpKind;

use crate::ir::types::*;

use super::flags::{append_undef_flags, unsigned_cmp_value};
use super::{cmp_operand_as_value, reg_name, value_of_operand, zero_extending_gp_view};

/// Temporaries this module spends inside a single lifted instruction.
///
/// Temporaries are scoped to one machine instruction, so these only have to
/// avoid each other and the ones the shared helpers in [`super::flags`] take as
/// arguments — `unsigned_cmp_value` is called with a temp chosen here.
mod temp {
    /// The bit index, once masked to the operand width.
    pub(super) const BIT_INDEX: u32 = 200;
    /// The destination shifted right by the bit index.
    pub(super) const SELECTED: u32 = 201;
    /// `1 << index`, and for `btr` its complement.
    pub(super) const MASK: u32 = 202;
    /// A memory or partial-view source operand, materialised.
    pub(super) const SOURCE: u32 = 203;
    /// The source narrowed to the encoded operand width.
    pub(super) const NARROWED: u32 = 204;
    /// `rcr`'s snapshot of the incoming carry.
    pub(super) const CARRY_IN: u32 = 205;
    /// `rcr`'s outgoing carry — the destination's bit 0, read before the write.
    pub(super) const CARRY_OUT: u32 = 206;
    /// `rcr`'s snapshot of the destination's sign bit, for OF.
    pub(super) const SIGN_BIT: u32 = 207;
    /// `rcr`'s carry bit shifted up into the vacated top position.
    pub(super) const CARRY_TOP: u32 = 208;
}

/// Which member of the `bt` family is being lifted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BitTest {
    /// `bt` — read the bit into CF and leave the destination alone.
    Read,
    /// `bts` — `dst |= 1 << n`.
    Set,
    /// `btr` — `dst &= ~(1 << n)`.
    Reset,
    /// `btc` — `dst ^= 1 << n`.
    Complement,
}

impl BitTest {
    fn mnemonic(self) -> &'static str {
        match self {
            BitTest::Read => "bt",
            BitTest::Set => "bts",
            BitTest::Reset => "btr",
            BitTest::Complement => "btc",
        }
    }

    /// The operation applied to the destination, or `None` for plain `bt`.
    fn update(self) -> Option<BinOp> {
        match self {
            BitTest::Read => None,
            BitTest::Set => Some(BinOp::Or),
            BitTest::Reset => Some(BinOp::And),
            BitTest::Complement => Some(BinOp::Xor),
        }
    }
}

/// `bt`/`bts`/`btr`/`btc reg, imm8|reg` — read one bit into CF and optionally
/// rewrite it.
///
/// The bit index is taken modulo the operand width, which is what the register
/// form of the instruction does; the memory form instead treats the index as a
/// signed bit offset that can address outside the named word, so a memory
/// DESTINATION is deliberately not lifted here rather than being given the
/// register form's semantics. No memory-destination `bt*` appears anywhere in
/// the committed corpus, and inventing the wrong addressing rule for one would
/// be worse than leaving it visible on the census.
///
/// CF is read from the ORIGINAL destination, before the update — otherwise
/// `bts` would always report the bit as already set.
///
/// 16-bit operands are excluded: their destination is a bit-preserving partial
/// view of a 64-bit parent, so the write is a read-modify-write
/// ([`super::partial_write_ops`]) rather than the definition this emits. The
/// corpus contains no 16-bit `bt*`.
pub(super) fn bit_test_ops(instr: &iced_x86::Instruction, kind: BitTest, bits: u32) -> Vec<Op> {
    let unsupported = || {
        vec![Op::Unknown {
            mnemonic: kind.mnemonic().into(),
        }]
    };
    if instr.op_count() != 2 || instr.op_kind(0) != OpKind::Register {
        return unsupported();
    }
    let destination_name = reg_name(instr.op_register(0));
    let Some(width) = phys_reg_width(&destination_name) else {
        return unsupported();
    };
    if !matches!(width, Width::W32 | Width::W64) {
        return unsupported();
    }

    let mut ops = Vec::new();
    let Some(raw_index) = cmp_operand_as_value(instr, 1, VReg::Temp(temp::SOURCE), &mut ops) else {
        return unsupported();
    };
    let modulus = i64::from(width.bits()) - 1;
    let destination = VReg::phys(&destination_name);

    let index = match raw_index {
        Value::Const(constant) => Value::Const(constant & modulus),
        other => {
            let masked = VReg::Temp(temp::BIT_INDEX);
            ops.push(Op::Bin {
                dst: masked.clone(),
                op: BinOp::And,
                lhs: other,
                rhs: Value::Const(modulus),
            });
            Value::Reg(masked)
        }
    };

    // CF = (dst >> index) & 1, from the value before any update.
    let selected = VReg::Temp(temp::SELECTED);
    ops.push(Op::Bin {
        dst: selected.clone(),
        op: BinOp::Shr,
        lhs: Value::Reg(destination.clone()),
        rhs: index.clone(),
    });
    ops.push(Op::Bin {
        dst: VReg::Flag(Flag::C),
        op: BinOp::And,
        lhs: Value::Reg(selected),
        rhs: Value::Const(1),
    });

    if let Some(update) = kind.update() {
        // The width mask keeps a 32-bit `btr`'s complement a small positive
        // constant instead of a 64-bit one whose high half only the parent
        // zero-extension below would clear.
        let width_mask = if width.bits() >= 64 {
            u64::MAX
        } else {
            (1u64 << width.bits()) - 1
        };
        let mask = match &index {
            Value::Const(constant) => {
                let bit = 1u64 << (*constant as u32);
                Value::Const(if kind == BitTest::Reset {
                    (!bit & width_mask) as i64
                } else {
                    (bit & width_mask) as i64
                })
            }
            other => {
                let mask = VReg::Temp(temp::MASK);
                // The `1` is widened to the operand width BEFORE it is shifted,
                // and that is not decoration. The LLIR word is 64 bits, but the
                // C this renders to gives an unadorned literal type `int` — so
                // `1 << 40` in the recovered source is undefined behaviour, and
                // on x86 the host's 32-bit shift silently answers `1 << 8`.
                // Measured: the recovered `value | (1 << (index & 63))`
                // disagreed with the original for EVERY index at or above 32,
                // and at 63 returned 0xffffffff80000000 where the machine
                // returns 0x8000000000000000.
                ops.push(Op::ZExt {
                    dst: mask.clone(),
                    src: Value::Const(1),
                    from: Width::W8,
                    to: width,
                });
                ops.push(Op::Bin {
                    dst: mask.clone(),
                    op: BinOp::Shl,
                    lhs: Value::Reg(mask.clone()),
                    rhs: other.clone(),
                });
                if kind == BitTest::Reset {
                    ops.push(Op::Un {
                        dst: mask.clone(),
                        op: UnOp::Not,
                        src: Value::Reg(mask.clone()),
                    });
                }
                Value::Reg(mask)
            }
        };
        ops.push(Op::Bin {
            dst: destination.clone(),
            op: update,
            lhs: Value::Reg(destination.clone()),
            rhs: mask,
        });
        ops.extend(zero_extend_parent(&destination_name, bits));
    }

    // ZF is UNAFFECTED — see the module documentation. Poisoning it here would
    // destroy a live comparison result the instruction does not touch.
    append_undef_flags(
        &mut ops,
        &[Flag::O, Flag::S, Flag::P, Flag::A],
        "x86 BT/BTS/BTR/BTC define CF and leave OF/SF/PF/AF architecturally \
         undefined; ZF is unaffected",
    );
    ops
}

/// `tzcnt reg, r/m` — count the trailing zeros of the source.
///
/// Exactly representable, and NOT the same instruction as `bsf` even though the
/// encoding is `rep bsf`: on a BMI1 processor `tzcnt(0)` is the OPERAND WIDTH,
/// where `bsf` leaves the destination alone and sets ZF. The zero case is part
/// of the meaning, so it is carried into the AST rather than left to
/// `__builtin_ctz`, which is undefined at zero — the same contract
/// [`crate::ir::ast::WideArithmetic::CountLeadingZeros`] already states for the
/// leading count.
///
/// CF, not ZF, is the flag that reports the zero source here; ZF reports a zero
/// RESULT, i.e. that bit 0 of the source was set. Both are defined; the other
/// four are not.
///
/// This is not a corpus-only shape. `144_inline_asm.c`'s `builtin_bit_intrinsics`
/// compiles `__builtin_ctz` to `tzcnt` under gcc at both -O0 (with a MEMORY
/// source, `tzcnt -0x4(%rbp),%eax`) and -O2, and under clang at -O2 — with no
/// `-mbmi` anywhere, because `rep bsf` decodes as `bsf` on pre-BMI parts and the
/// surrounding C tests for zero itself.
pub(super) fn count_trailing_zeros_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    unary_bit_count_ops(instr, BitCount::TrailingZeros)
}

/// `popcnt reg, r/m` — the population count of the source.
///
/// Every flag is defined: ZF reports a zero SOURCE and CF/OF/SF/PF/AF are
/// CLEARED, not left undefined (Intel SDM Vol. 2B, POPCNT). Assigning them zero
/// rather than poisoning them is the difference between a following `jae`
/// reading a known-taken branch and reading a halt.
pub(super) fn population_count_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    unary_bit_count_ops(instr, BitCount::Population)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BitCount {
    TrailingZeros,
    Population,
}

impl BitCount {
    fn mnemonic(self) -> &'static str {
        match self {
            BitCount::TrailingZeros => "tzcnt",
            BitCount::Population => "popcnt",
        }
    }

    /// The intrinsic stem [`crate::ir::ast::lower_ops`] recognises.
    fn stem(self) -> &'static str {
        match self {
            BitCount::TrailingZeros => "ctz",
            BitCount::Population => "popcnt",
        }
    }
}

/// The shared body of `tzcnt` and `popcnt`: one source, one register
/// destination, one single-output intrinsic, and a flag model that differs only
/// in which flags are defined.
///
/// 32- and 64-bit operands only. The 16-bit forms exist, but the AST renders a
/// sub-64-bit count through an `(unsigned int)` cast — a 32-bit window — so a
/// `.16` spelling would be counted at the wrong width, and the destination
/// would additionally be a bit-preserving partial view. Neither appears in the
/// corpus.
fn unary_bit_count_ops(instr: &iced_x86::Instruction, kind: BitCount) -> Vec<Op> {
    let unsupported = || {
        vec![Op::Unknown {
            mnemonic: kind.mnemonic().into(),
        }]
    };
    if instr.op_count() != 2 || instr.op_kind(0) != OpKind::Register {
        return unsupported();
    }
    let destination_name = reg_name(instr.op_register(0));
    let Some(width) = phys_reg_width(&destination_name) else {
        return unsupported();
    };
    if !matches!(width, Width::W32 | Width::W64) {
        return unsupported();
    }
    // The source must be the same width as the destination: the encoding says
    // so, and a mismatch would mean the operand this counted is not the operand
    // the machine counted.
    match instr.op_kind(1) {
        OpKind::Register => {
            if phys_reg_width(&reg_name(instr.op_register(1))) != Some(width) {
                return unsupported();
            }
        }
        OpKind::Memory => {
            if Width::from_bytes(instr.memory_size().size() as u16) != width {
                return unsupported();
            }
        }
        _ => return unsupported(),
    }

    let mut ops = Vec::new();
    let Some(source) = cmp_operand_as_value(instr, 1, VReg::Temp(temp::SOURCE), &mut ops) else {
        return unsupported();
    };
    // A canonicalised 32-bit register lives in a 64-bit parent whose high half
    // this IR never clears, so both the zero test and the count itself have to
    // name the encoded width.
    let operand = unsigned_cmp_value(source, width, VReg::Temp(temp::NARROWED), &mut ops);
    let destination = VReg::phys(&destination_name);
    let bits = width.bits();

    match kind {
        BitCount::TrailingZeros => {
            ops.push(Op::Cmp {
                dst: VReg::Flag(Flag::C),
                op: CmpOp::Eq,
                lhs: operand.clone(),
                rhs: Value::Const(0),
            });
            ops.push(Op::Intrinsic {
                name: format!("x86.{}.{bits}", kind.stem()),
                ins: vec![operand],
                outs: vec![(destination.clone(), width)],
                reads_mem: false,
                writes_mem: false,
            });
            ops.push(Op::Cmp {
                dst: VReg::Flag(Flag::Z),
                op: CmpOp::Eq,
                lhs: Value::Reg(destination),
                rhs: Value::Const(0),
            });
            append_undef_flags(
                &mut ops,
                &[Flag::O, Flag::S, Flag::P, Flag::A],
                "x86 TZCNT defines CF and ZF; OF/SF/PF/AF are architecturally undefined",
            );
        }
        BitCount::Population => {
            ops.push(Op::Cmp {
                dst: VReg::Flag(Flag::Z),
                op: CmpOp::Eq,
                lhs: operand.clone(),
                rhs: Value::Const(0),
            });
            ops.push(Op::Intrinsic {
                name: format!("x86.{}.{bits}", kind.stem()),
                ins: vec![operand],
                outs: vec![(destination, width)],
                reads_mem: false,
                writes_mem: false,
            });
            ops.extend(
                [Flag::C, Flag::O, Flag::S, Flag::P, Flag::A]
                    .into_iter()
                    .map(|flag| Op::Assign {
                        dst: VReg::Flag(flag),
                        src: Value::Const(0),
                    }),
            );
        }
    }
    ops
}

/// `rcr reg, 1` — rotate right through the carry flag by one.
///
/// The 65-bit (or 33-bit) quantity `CF:dst` rotated right by one is
/// `(CF << (bits-1)) | (dst >> 1)`, with the vacated carry taking the
/// destination's old bit 0. That is exact in ordinary LLIR because CF is an
/// ordinary readable value here, exactly as `adc`/`sbb` already read it.
///
/// Counts other than one are deliberately not lifted. A multi-bit rotate
/// through carry is a rotation of a `bits + 1` wide value, which this IR has no
/// width for below a full second register, and the ISA additionally leaves OF
/// undefined there. `rcr reg, 1` is the only form in the corpus.
pub(super) fn rotate_carry_right_ops(instr: &iced_x86::Instruction, bits_mode: u32) -> Vec<Op> {
    let unsupported = || {
        vec![Op::Unknown {
            mnemonic: "rcr".into(),
        }]
    };
    if instr.op_count() != 2 || instr.op_kind(0) != OpKind::Register {
        return unsupported();
    }
    if !matches!(
        value_of_operand(instr, 1),
        Some(Value::Const(1)) if instr.op_kind(1) != OpKind::Register
    ) {
        return unsupported();
    }
    let destination_name = reg_name(instr.op_register(0));
    let Some(width) = phys_reg_width(&destination_name) else {
        return unsupported();
    };
    if !matches!(width, Width::W32 | Width::W64) {
        return unsupported();
    }

    let destination = VReg::phys(&destination_name);
    let top_shift = i64::from(width.bits()) - 1;
    let carry_in = VReg::Temp(temp::CARRY_IN);
    let carry_out = VReg::Temp(temp::CARRY_OUT);
    let sign_bit = VReg::Temp(temp::SIGN_BIT);
    let carry_top = VReg::Temp(temp::CARRY_TOP);

    // Snapshot everything the rotate reads before anything it writes.
    let mut ops = vec![
        Op::Assign {
            dst: carry_in.clone(),
            src: Value::Reg(VReg::Flag(Flag::C)),
        },
        Op::Bin {
            dst: carry_out.clone(),
            op: BinOp::And,
            lhs: Value::Reg(destination.clone()),
            rhs: Value::Const(1),
        },
    ];
    let narrowed = unsigned_cmp_value(
        Value::Reg(destination.clone()),
        width,
        VReg::Temp(temp::NARROWED),
        &mut ops,
    );
    ops.push(Op::Bin {
        dst: sign_bit.clone(),
        op: BinOp::Shr,
        lhs: narrowed.clone(),
        rhs: Value::Const(top_shift),
    });
    ops.push(Op::Bin {
        dst: sign_bit.clone(),
        op: BinOp::And,
        lhs: Value::Reg(sign_bit.clone()),
        rhs: Value::Const(1),
    });

    // result = (CF << (bits - 1)) | (dst >>> 1), the shift taken at the encoded
    // width so a 32-bit rotate never pulls a stale parent bit down into bit 31.
    // Widened for the same reason the bit mask above is: an unwidened carry
    // shifted left by 63 is an `int` shift in the recovered C, which is
    // undefined and in practice answers zero.
    ops.push(Op::ZExt {
        dst: carry_top.clone(),
        src: Value::Reg(carry_in.clone()),
        from: Width::W1,
        to: width,
    });
    ops.push(Op::Bin {
        dst: carry_top.clone(),
        op: BinOp::Shl,
        lhs: Value::Reg(carry_top.clone()),
        rhs: Value::Const(top_shift),
    });
    ops.push(Op::Bin {
        dst: destination.clone(),
        op: BinOp::Shr,
        lhs: narrowed,
        rhs: Value::Const(1),
    });
    ops.push(Op::Bin {
        dst: destination.clone(),
        op: BinOp::Or,
        lhs: Value::Reg(destination.clone()),
        rhs: Value::Reg(carry_top),
    });
    ops.extend(zero_extend_parent(&destination_name, bits_mode));

    ops.push(Op::Assign {
        dst: VReg::Flag(Flag::C),
        src: Value::Reg(carry_out),
    });
    // For a single-bit right rotate OF is the exclusive-or of the two most
    // significant bits of the RESULT, which are the incoming carry and the
    // destination's old sign bit.
    ops.push(Op::Bin {
        dst: VReg::Flag(Flag::O),
        op: BinOp::Xor,
        lhs: Value::Reg(carry_in),
        rhs: Value::Reg(sign_bit),
    });
    ops
}

/// The explicit record that a 32-bit general-purpose write cleared the upper
/// half of its 64-bit parent, or `None` when the destination is already the
/// whole register.
///
/// [`super::flags::emit_machine_bin_with_flags`] appends the same op after every
/// ordinary ALU operation; a `bts ecx, ebx` that omitted it would leave the IR
/// claiming `rcx`'s high half survived an instruction that architecturally
/// zeroes it.
fn zero_extend_parent(name: &str, bits: u32) -> Option<Op> {
    zero_extending_gp_view(name, bits).map(|_| Op::ZExt {
        dst: VReg::phys(name),
        src: Value::Reg(VReg::phys(name)),
        from: Width::W32,
        to: Width::W64,
    })
}
