//! LLIR value, intrinsic and opcode lowering.
//!
//! The leaf of the lowering pipeline: everything here turns a single LLIR
//! [`Op`] (or one of its operands) into [`Stmt`]/[`Expr`] nodes, with no
//! knowledge of blocks, conditions or regions. [`lower_op`] is the one entry
//! point the rest of the pipeline uses; [`super::lower_conds::lower_block`]
//! calls it once per instruction.
//!
//! The intrinsic recognisers (`memory_fill_intrinsic`, `byte_swap_intrinsic`,
//! `packed_byte_table_intrinsic`, `packed_signed_shift_intrinsic`,
//! `wide_integer_intrinsic`) each answer "is this named intrinsic the shape I
//! model?" and return `None` otherwise, so an unrecognised name falls through
//! to the generic `Expr::Call` form rather than being mis-lowered.

use super::float_gate::scalar_float_intrinsic;
use super::width_semantics::{containing_c_integer_bytes, exact_non_byte_value};
use super::{Expr, ScalarType, Stmt, WideArithmetic};
use crate::ir::types::{BinOp, CallTarget, CmpOp, MemOp, Op, UnOp, VReg, Value, Width};

/// `(int<to>)(int<from>)expr` — an extension that keeps its meaning when folded.
///
/// Emits only the inner cast when the two widths agree (nothing is being extended),
/// and only the outer one when `from` is already the full width.
fn widen_cast(expr: Expr, signed: bool, from: Width, to: Width) -> Expr {
    let fw = containing_c_integer_bytes(from);
    let tw = containing_c_integer_bytes(to);
    let inner = Expr::Cast {
        signed,
        width: fw,
        expr: Box::new(exact_non_byte_value(expr, from, signed)),
    };
    if tw <= fw {
        return inner;
    }
    Expr::Cast {
        signed,
        width: tw,
        expr: Box::new(inner),
    }
}

pub(super) fn lower_value(v: &Value) -> Expr {
    match v {
        Value::Reg(r) => Expr::Reg(r.clone()),
        Value::Const(c) => Expr::Const(*c),
        Value::Addr(a) => Expr::Addr(*a),
    }
}

/// Lower one scalar conversion into the C expression it denotes.
///
/// A conversion whose two ends are the same type is the identity, and emitting
/// `(float)(x)` for it would be noise. Everything else becomes an explicit
/// [`Expr::NumericConvert`] so no later pass has to re-derive, from the
/// destination's declared type alone, whether the bits were converted or
/// reinterpreted.
fn lower_scalar_conversion(source: &Value, from: ScalarType, to: ScalarType) -> Expr {
    let operand = match from {
        ScalarType::Float(width) => lower_float_value(source, width),
        ScalarType::SignedInt(_) => lower_value(source),
    };
    if from == to {
        return operand;
    }
    Expr::NumericConvert {
        from,
        to,
        expr: Box::new(operand),
    }
}

fn lower_float_value(value: &Value, width: u8) -> Expr {
    match value {
        Value::Const(bits) => Expr::FloatConst {
            bits: *bits as u64,
            width,
        },
        _ => lower_value(value),
    }
}

/// Lower an architecture-neutral repeated scalar memory fill into an exact AST
/// loop. The lifter supplies private pointer/count scratch values, so mutating
/// them here cannot overwrite the architectural registers whose post-operation
/// values are represented by subsequent LLIR operations.
fn memory_fill_intrinsic(name: &str, ins: &[Value], outs: &[(VReg, Width)]) -> Option<Stmt> {
    if !outs.is_empty() {
        return None;
    }
    let suffix = name.strip_prefix("memory.fill.")?;
    let (element_width, word_width) = suffix.split_once(".word")?;
    let element_width: u8 = element_width.parse().ok()?;
    let word_width: u8 = word_width.parse().ok()?;
    if !matches!(element_width, 1 | 2 | 4 | 8) || !matches!(word_width, 4 | 8) {
        return None;
    }
    let [Value::Reg(pointer), Value::Reg(remaining), value, direction] = ins else {
        return None;
    };
    let direction_is_set = Expr::Cmp {
        op: CmpOp::Ne,
        lhs: Box::new(lower_value(direction)),
        rhs: Box::new(Expr::Const(0)),
    };
    Some(Stmt::While {
        cond: Expr::Cmp {
            op: CmpOp::Ne,
            lhs: Box::new(Expr::Reg(remaining.clone())),
            rhs: Box::new(Expr::Const(0)),
        },
        body: vec![
            Stmt::Store {
                addr: Expr::Reg(pointer.clone()),
                src: lower_value(value),
                size: element_width,
            },
            Stmt::Assign {
                dst: pointer.clone(),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(pointer.clone())),
                    rhs: Box::new(Expr::Select {
                        cond: Box::new(direction_is_set),
                        if_true: Box::new(Expr::Const(-i64::from(element_width))),
                        if_false: Box::new(Expr::Const(i64::from(element_width))),
                        width: word_width,
                    }),
                },
            },
            Stmt::Assign {
                dst: remaining.clone(),
                src: Expr::Bin {
                    op: BinOp::Sub,
                    lhs: Box::new(Expr::Reg(remaining.clone())),
                    rhs: Box::new(Expr::Const(1)),
                },
            },
        ],
    })
}

#[derive(Clone, Copy)]
pub(super) enum ScalarFloatOperation {
    Move,
    Negate,
    Binary(BinOp),
    /// A value conversion: read the operand as `from` and produce `to`,
    /// exactly as the corresponding C cast would.
    Convert {
        from: ScalarType,
        to: ScalarType,
    },
}

fn wide_integer_intrinsic(
    name: &str,
    ins: &[Value],
    outs: &[(VReg, crate::ir::types::Width)],
) -> Option<(WideArithmetic, u8)> {
    let [(_, output_width)] = outs else {
        return None;
    };
    // The lowerings below are pure C, not x86 semantics: AArch64's `umulh` and
    // `smulh` are the same wide product as x86's `mul`/`imul` high half, and
    // `sdiv`/`udiv` the same wide quotient. ARM32 has no divide instruction at
    // all, but `ir::soft_helpers` lowers the libgcc division helpers into the
    // same exact form. Accept every producer's namespace rather than
    // duplicating the double-width renderer per architecture.
    let (stem, bits) = name
        .strip_prefix("x86.")
        .or_else(|| name.strip_prefix("aarch64."))
        .or_else(|| name.strip_prefix("arm."))?
        .rsplit_once('.')?;
    let bits: u16 = bits.parse().ok()?;
    // 8 is admitted for x86's byte `mul`/`div`, whose product and dividend are
    // `AX` alone. `double_width_ctype` already names the `short` intermediate
    // that width needs, and C's integer promotions compute the whole expression
    // in `int` regardless — so the lowering is the same one, not a special case.
    if output_width.bits() != bits || !matches!(bits, 8 | 16 | 32 | 64) {
        return None;
    }
    let op = match stem {
        "umul_hi" if ins.len() == 2 => WideArithmetic::UnsignedMulHigh,
        "smul_hi" if ins.len() == 2 => WideArithmetic::SignedMulHigh,
        "udiv_quot" if ins.len() == 3 => WideArithmetic::UnsignedDivQuotient,
        "udiv_rem" if ins.len() == 3 => WideArithmetic::UnsignedDivRemainder,
        "sdiv_quot" if ins.len() == 3 => WideArithmetic::SignedDivQuotient,
        "sdiv_rem" if ins.len() == 3 => WideArithmetic::SignedDivRemainder,
        "clz" if ins.len() == 1 => WideArithmetic::CountLeadingZeros,
        _ => return None,
    };
    Some((op, (bits / 8) as u8))
}

/// Lower full-register and lane-local byte swaps to an exact unsigned
/// expression instead of an opaque asm comment. The explicit machine-width
/// casts keep every shift defined and prevent a 32-bit source with its sign bit
/// set from being promoted to a signed C value before the shuffle is complete.
fn byte_swap_intrinsic(name: &str, ins: &[Value], outs: &[(VReg, Width)]) -> Option<Expr> {
    let ([src], [(_, output_width)]) = (ins, outs) else {
        return None;
    };
    if !matches!(*output_width, Width::W32 | Width::W64) {
        return None;
    }

    let bytes = u8::try_from(output_width.bytes()).ok()?;
    let lane_bytes = match name {
        "bswap" => bytes,
        "byte_swap_16_lanes" => 2,
        _ => return None,
    };
    if bytes % lane_bytes != 0 {
        return None;
    }
    let input = Expr::Cast {
        signed: false,
        width: bytes,
        expr: Box::new(lower_value(src)),
    };
    let mut parts = Vec::with_capacity(bytes as usize);
    for source_byte in 0..bytes {
        let source_shift = i64::from(source_byte) * 8;
        let lane_base = (source_byte / lane_bytes) * lane_bytes;
        let lane_offset = source_byte % lane_bytes;
        let destination_byte = lane_base + (lane_bytes - 1 - lane_offset);
        let destination_shift = i64::from(destination_byte) * 8;
        let shifted_down = if source_shift == 0 {
            input.clone()
        } else {
            Expr::Bin {
                op: BinOp::Shr,
                lhs: Box::new(input.clone()),
                rhs: Box::new(Expr::Const(source_shift)),
            }
        };
        let byte = Expr::Bin {
            op: BinOp::And,
            lhs: Box::new(shifted_down),
            rhs: Box::new(Expr::Const(0xff)),
        };
        parts.push(if destination_shift == 0 {
            byte
        } else {
            Expr::Bin {
                op: BinOp::Shl,
                lhs: Box::new(byte),
                rhs: Box::new(Expr::Const(destination_shift)),
            }
        });
    }

    let combined = parts.into_iter().reduce(|lhs, rhs| Expr::Bin {
        op: BinOp::Or,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    })?;
    Some(Expr::Cast {
        signed: false,
        width: bytes,
        expr: Box::new(combined),
    })
}

/// Lower a one-register, 16-byte table lookup into portable scalar C semantics.
///
/// Each intrinsic produces one dword from four table dwords and one dword of
/// byte indices. An index in 0..16 selects that table byte; every other index
/// yields zero, matching AArch64 `TBL` rather than `TBX`. Unsigned casts keep
/// every shift defined even when a table byte sets the source language sign bit.
fn packed_byte_table_intrinsic(name: &str, ins: &[Value], outs: &[(VReg, Width)]) -> Option<Expr> {
    let ([table0, table1, table2, table3, indices], [(_, Width::W32)]) = (ins, outs) else {
        return None;
    };
    if name != "packed_byte_table_16" {
        return None;
    }
    let table: Vec<_> = [table0, table1, table2, table3]
        .into_iter()
        .map(|value| Expr::Cast {
            signed: false,
            width: 4,
            expr: Box::new(lower_value(value)),
        })
        .collect();
    let indices = Expr::Cast {
        signed: false,
        width: 4,
        expr: Box::new(lower_value(indices)),
    };

    let extract_byte = |word: Expr, byte: usize| {
        let shifted = if byte == 0 {
            word
        } else {
            Expr::Bin {
                op: BinOp::Shr,
                lhs: Box::new(word),
                rhs: Box::new(Expr::Const((byte * 8) as i64)),
            }
        };
        Expr::Bin {
            op: BinOp::And,
            lhs: Box::new(shifted),
            rhs: Box::new(Expr::Const(0xff)),
        }
    };

    let mut output_bytes = Vec::with_capacity(4);
    for output_byte in 0..4 {
        let index = extract_byte(indices.clone(), output_byte);
        let mut selected = Expr::Const(0);
        for table_index in (0..16).rev() {
            selected = Expr::Select {
                cond: Box::new(Expr::Cmp {
                    op: CmpOp::Eq,
                    lhs: Box::new(index.clone()),
                    rhs: Box::new(Expr::Const(table_index as i64)),
                }),
                if_true: Box::new(extract_byte(
                    table[table_index / 4].clone(),
                    table_index % 4,
                )),
                if_false: Box::new(selected),
                width: 1,
            };
        }
        let selected = Expr::Cast {
            signed: false,
            width: 4,
            expr: Box::new(selected),
        };
        output_bytes.push(if output_byte == 0 {
            selected
        } else {
            Expr::Bin {
                op: BinOp::Shl,
                lhs: Box::new(selected),
                rhs: Box::new(Expr::Const((output_byte * 8) as i64)),
            }
        });
    }
    let combined = output_bytes.into_iter().reduce(|lhs, rhs| Expr::Bin {
        op: BinOp::Or,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    })?;
    Some(Expr::Cast {
        signed: false,
        width: 4,
        expr: Box::new(combined),
    })
}

/// Lower a signed-count packed shift into C expressions whose shifts are
/// defined for every 32-bit count. AArch64 USHL shifts left for nonnegative
/// counts, right for negative counts, and returns zero when the magnitude is
/// at least 32. The unsigned casts also make INT_MIN negation well-defined.
fn packed_signed_shift_intrinsic(
    name: &str,
    ins: &[Value],
    outs: &[(VReg, Width)],
) -> Option<Expr> {
    let ([value, count], [(_, Width::W32)]) = (ins, outs) else {
        return None;
    };
    if name != "packed_signed_shift_u32" {
        return None;
    }
    let value = Expr::Cast {
        signed: false,
        width: 4,
        expr: Box::new(lower_value(value)),
    };
    let count_unsigned = Expr::Cast {
        signed: false,
        width: 4,
        expr: Box::new(lower_value(count)),
    };
    let count_signed = Expr::Cast {
        signed: true,
        width: 4,
        expr: Box::new(lower_value(count)),
    };
    let zero_unsigned = Expr::Cast {
        signed: false,
        width: 4,
        expr: Box::new(Expr::Const(0)),
    };
    let magnitude = Expr::Bin {
        op: BinOp::Sub,
        lhs: Box::new(zero_unsigned),
        rhs: Box::new(count_unsigned.clone()),
    };
    let guarded_shift = |op: BinOp, amount: Expr| Expr::Select {
        cond: Box::new(Expr::Cmp {
            op: CmpOp::Ule,
            lhs: Box::new(Expr::Const(32)),
            rhs: Box::new(amount.clone()),
        }),
        if_true: Box::new(Expr::Const(0)),
        if_false: Box::new(Expr::Bin {
            op,
            lhs: Box::new(value.clone()),
            rhs: Box::new(amount),
        }),
        width: 4,
    };
    Some(Expr::Select {
        cond: Box::new(Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(count_signed),
            rhs: Box::new(Expr::Const(0)),
        }),
        if_true: Box::new(guarded_shift(BinOp::Shr, magnitude)),
        if_false: Box::new(guarded_shift(BinOp::Shl, count_unsigned)),
        width: 4,
    })
}

fn lower_memop(m: &MemOp) -> Expr {
    let addr = if m.base.is_none() && m.index.is_none() && m.segment.is_none() && m.disp >= 0 {
        Expr::Addr(m.disp as u64)
    } else {
        Expr::Lea {
            base: m.base.clone(),
            index: m.index.clone(),
            scale: m.scale,
            disp: m.disp,
            segment: m.segment.clone(),
        }
    };
    Expr::Deref {
        addr: Box::new(addr),
        size: m.size,
    }
}

fn semantic_comment_for_unknown(mnemonic: &str) -> Option<&'static str> {
    match mnemonic.to_ascii_lowercase().as_str() {
        "sgdt" => Some("sgdt: store global descriptor table register (GDTR)"),
        "sidt" => Some("sidt: store interrupt descriptor table register (IDTR)"),
        "str" => Some("str: store task register selector"),
        "sldt" => Some("sldt: store local descriptor table register selector"),
        "lldt" => Some("lldt: load local descriptor table register selector"),
        "wrmsr" => Some("wrmsr: write model-specific register ecx with edx:eax"),
        "rdmsr" => Some("rdmsr: read model-specific register ecx into edx:eax"),
        "ldmxcsr" => Some("ldmxcsr: load SSE MXCSR control/status register"),
        "stmxcsr" => Some("stmxcsr: store SSE MXCSR control/status register"),
        "swapgs" => Some("swapgs: swap GS base with KernelGSBase MSR"),
        "setssbsy" => Some("setssbsy: mark CET shadow stack busy"),
        "rstorssp" => Some("rstorssp: restore CET shadow stack pointer"),
        "saveprevssp" => Some("saveprevssp: save previous CET shadow stack pointer"),
        _ => None,
    }
}

/// The value a jump-table dispatch switches on, read out of the jump's own
/// target expression.
///
/// A relative-table dispatch computes `table + (i32)table[idx]`, so the index is
/// sitting inside the load's address as `base + idx * scale`. Recovering it here
/// means the `switch` names the value the source switched on instead of a
/// synthetic `dispatch_<va>` that nothing defines.
///
/// Returns `None` rather than guessing when the shape is not recognised — a
/// wrong discriminant would render a switch that reads correct and is not.
pub(super) fn switch_index_of(target: &Expr) -> Option<Expr> {
    fn find_deref(e: &Expr) -> Option<&Expr> {
        match e {
            Expr::Deref { addr, .. } => Some(addr),
            Expr::Bin { lhs, rhs, .. } => find_deref(lhs).or_else(|| find_deref(rhs)),
            Expr::Cast { expr, .. } => find_deref(expr),
            Expr::Un { src, .. } => find_deref(src),
            _ => None,
        }
    }
    /// The `idx` of a `base + idx * scale` address.
    ///
    /// At lowering time the table read is still an `Expr::Lea` — the scaled form
    /// with an explicit `index` field — because the fold that turns it into
    /// `base + idx*4` runs later. Handling only the folded shape found nothing,
    /// which is how the discriminant stayed a placeholder.
    fn scaled_index(addr: &Expr) -> Option<Expr> {
        if let Expr::Lea {
            index: Some(i),
            scale,
            ..
        } = addr
        {
            if *scale > 1 {
                return Some(Expr::Reg(i.clone()));
            }
        }
        if let Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } = addr
        {
            for side in [lhs, rhs] {
                if let Expr::Bin {
                    op: BinOp::Mul,
                    lhs: a,
                    rhs: b,
                } = side.as_ref()
                {
                    if matches!(b.as_ref(), Expr::Const(_)) {
                        return Some((**a).clone());
                    }
                    if matches!(a.as_ref(), Expr::Const(_)) {
                        return Some((**b).clone());
                    }
                }
            }
        }
        None
    }
    scaled_index(find_deref(target)?)
}

/// Lower a single LLIR op to one or more Stmts.
pub(super) fn lower_op(op: &Op, lower_scalar_float: bool) -> Vec<Stmt> {
    fn predicate_expr(cond: &VReg, inverted: bool) -> Expr {
        if inverted {
            Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(Expr::Reg(cond.clone())),
                rhs: Box::new(Expr::Const(0)),
            }
        } else {
            Expr::Reg(cond.clone())
        }
    }

    match op {
        Op::Nop => vec![Stmt::Nop],
        Op::Assign { dst, src } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: lower_value(src),
        }],
        Op::Undef { dst, reason } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: Expr::Unknown(format!("undefined({reason})")),
        }],
        Op::Bin { dst, op, lhs, rhs } => {
            let mut lhs = lower_value(lhs);
            // Arithmetic right shift is signed at the machine operand width.
            // State that width in the expression itself: copy propagation may
            // replace a 32-bit register with a wider zero-extended producer,
            // and plain C `>>` would then fill with zeros before a later cast.
            if *op == BinOp::Sar {
                let width = match &lhs {
                    Expr::Reg(register) => register.width().or_else(|| dst.width()),
                    _ => dst.width(),
                };
                if let Some(width) = width.filter(|width| matches!(width.bits(), 8 | 16 | 32 | 64))
                {
                    lhs = Expr::Cast {
                        signed: true,
                        width: (width.bits() / 8) as u8,
                        expr: Box::new(lhs),
                    };
                }
            }
            vec![Stmt::Assign {
                dst: dst.clone(),
                src: Expr::Bin {
                    op: *op,
                    lhs: Box::new(lhs),
                    rhs: Box::new(lower_value(rhs)),
                },
            }]
        }
        Op::Un { dst, op, src } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: Expr::Un {
                op: *op,
                src: Box::new(lower_value(src)),
            },
        }],
        Op::Cmp { dst, op, lhs, rhs } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: Expr::Cmp {
                op: *op,
                lhs: Box::new(lower_value(lhs)),
                rhs: Box::new(lower_value(rhs)),
            },
        }],
        Op::Load { dst, addr } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: lower_memop(addr),
        }],
        Op::CondLoad {
            dst,
            cond,
            inverted,
            addr,
            fallback,
        } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: Expr::Select {
                cond: Box::new(predicate_expr(cond, *inverted)),
                if_true: Box::new(lower_memop(addr)),
                if_false: Box::new(lower_value(fallback)),
                width: addr.size,
            },
        }],
        Op::Store { addr, src } => vec![Stmt::Store {
            addr: Expr::Lea {
                base: addr.base.clone(),
                index: addr.index.clone(),
                scale: addr.scale,
                disp: addr.disp,
                segment: addr.segment.clone(),
            },
            src: lower_value(src),
            size: addr.size,
        }],
        Op::CondStore {
            cond,
            inverted,
            addr,
            src,
        } => vec![Stmt::If {
            cond: predicate_expr(cond, *inverted),
            then_body: vec![Stmt::Store {
                addr: Expr::Lea {
                    base: addr.base.clone(),
                    index: addr.index.clone(),
                    scale: addr.scale,
                    disp: addr.disp,
                    segment: addr.segment.clone(),
                },
                src: lower_value(src),
                size: addr.size,
            }],
            else_body: None,
        }],
        Op::Jump { target } => vec![Stmt::Goto { target: *target }],
        // A computed transfer. Where it goes lives in the CFG — the arms are
        // real successors, and the structurer turns them into `Region::Switch`
        // — so there is nothing to emit here. It must NOT become a statement:
        // lifting it as `Op::Call` made the dispatch render as
        // `var = (*(code *)(...))();`, which the switch lowering could not
        // recognise as the terminator to drop, so the bogus call survived
        // *inside* the recovered switch.
        //
        // An UNSTRUCTURED indirect jump — one the structurer did not turn into
        // a switch — still has to say so rather than vanish, or the function
        // silently reads as if control fell through.
        Op::IndirectJump { target, .. } => vec![Stmt::IndirectGoto {
            target: lower_value(target),
        }],
        // A CondJump on its own (not absorbed into a structured If/While)
        // becomes a conditional goto. If the CondJump carries `inverted`
        // (i.e. lifted from JNE / JAE / JGE / b.ne / b.hs / ...), wrap the
        // flag as `flag == 0`. `UnOp::Not` is the machine bitwise operation
        // and renders as `~`; applying it to a 0/1 predicate is always truthy.
        Op::CondJump {
            cond,
            target,
            inverted,
        } => {
            vec![Stmt::If {
                cond: predicate_expr(cond, *inverted),
                then_body: vec![Stmt::Goto { target: *target }],
                else_body: None,
            }]
        }
        Op::CondReturn { cond, inverted } => vec![Stmt::If {
            cond: predicate_expr(cond, *inverted),
            then_body: vec![Stmt::Return { value: None }],
            else_body: None,
        }],
        Op::CondReturnValue {
            cond,
            inverted,
            value,
        } => vec![Stmt::If {
            cond: predicate_expr(cond, *inverted),
            then_body: vec![Stmt::Return {
                value: Some(lower_value(value)),
            }],
            else_body: None,
        }],
        Op::Call { target, effects } => {
            let target = match target {
                CallTarget::Direct(a) => Expr::Addr(*a),
                CallTarget::Indirect(v) => lower_value(v),
            };
            // Carry the call's own result register down from the LLIR, where value
            // numbering has already renamed it to the same name the post-call read
            // carries. Re-deriving it at the AST level from ABI register names does
            // not work: after renaming, the read is `var4`, not `rax`, so the two
            // never meet and the AST ends up with a value nobody defines.
            vec![Stmt::Call {
                target,
                args: Vec::new(),
                dst: effects.as_ref().and_then(|e| e.result.clone()),
                call_spec: None,
            }]
        }
        Op::ReturnValue { value } => vec![Stmt::Return {
            value: Some(lower_value(value)),
        }],
        Op::Return => vec![Stmt::Return { value: None }],
        // Width changes must preserve their semantics, not collapse to `dst = src`.
        //
        // An extension states BOTH widths: `(int<to>)(int<from>)src`. The inner cast
        // reinterprets the low `from` bits with the right signedness; the outer one
        // says how wide the result is.
        //
        // The outer cast is not redundant, and leaving it off was a real bug. As an
        // assignment `long d = (int)s` sign-fills correctly, so `(int<from>)src`
        // alone looked sufficient — until `copy_prop` folded it into an expression.
        // `movslq`/`cltq` feeding a 64-bit `imul` then rendered
        // `(int)b * (int)a`, a THIRTY-TWO bit multiply, discarding exactly the high
        // half that the source's `(long)` cast existed to keep: `fixedpoint::fp_mul`
        // returned -65536 where the original returned 0, and `fp_div` raised SIGFPE.
        // An expression that means the same thing wherever it is folded has to carry
        // its own width.
        //
        //   Trunc to W: keep exactly the low W bits. A C cast provides that mask
        //   for byte-aligned widths; arbitrary LLIR widths need it explicitly.
        Op::ZExt { dst, src, from, to } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: widen_cast(lower_value(src), false, *from, *to),
        }],
        Op::SExt { dst, src, from, to } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: widen_cast(lower_value(src), true, *from, *to),
        }],
        Op::Trunc { dst, src, to, .. } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: Expr::Cast {
                signed: false,
                width: containing_c_integer_bytes(*to),
                expr: Box::new(exact_non_byte_value(lower_value(src), *to, false)),
            },
        }],
        // Bit-slice `src[lo:hi]` → (src >> lo) & ((1<<(hi-lo))-1).
        Op::Extract { dst, src, hi, lo } => {
            let shifted = if *lo == 0 {
                lower_value(src)
            } else {
                Expr::Bin {
                    op: BinOp::Shr,
                    lhs: Box::new(lower_value(src)),
                    rhs: Box::new(Expr::Const(*lo as i64)),
                }
            };
            let width = hi.saturating_sub(*lo);
            let mask: i64 = if width >= 64 { -1 } else { (1i64 << width) - 1 };
            vec![Stmt::Assign {
                dst: dst.clone(),
                src: Expr::Bin {
                    op: BinOp::And,
                    lhs: Box::new(shifted),
                    rhs: Box::new(Expr::Const(mask)),
                },
            }]
        }
        // Concatenation: render as `hi | lo` (the shift amount needs operand
        // widths, refined when widths flow through values — Phase 0.7).
        Op::Concat { dst, hi, lo } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: Expr::Bin {
                op: BinOp::Or,
                lhs: Box::new(lower_value(hi)),
                rhs: Box::new(lower_value(lo)),
            },
        }],
        // A pure select is one expression-level assignment, not manufactured
        // control flow. Keeping both arms inside the expression also preserves
        // the three-input use-def semantics of `Op::Ite`.
        Op::Ite {
            dst,
            cond,
            t,
            e,
            width,
        } => vec![Stmt::Assign {
            dst: dst.clone(),
            src: Expr::Select {
                cond: Box::new(Expr::Reg(cond.clone())),
                if_true: Box::new(lower_value(t)),
                if_false: Box::new(lower_value(e)),
                width: containing_c_integer_bytes(*width),
            },
        }],
        // Opaque intrinsic. For the lowered-`Unknown` case (no typed operands)
        // render exactly as the old `Unknown` did — including the semantic
        // comments for known system instructions — so decompiler output is
        // unchanged by the Phase-0 migration. Intrinsics carrying operands
        // (future richer lifting) render with an argument ellipsis.
        Op::Intrinsic {
            name, ins, outs, ..
        } => {
            if let Some(statement) = memory_fill_intrinsic(name, ins, outs) {
                return vec![statement];
            }
            if let (Some(src), Some((dst, _))) =
                (byte_swap_intrinsic(name, ins, outs), outs.first())
            {
                return vec![Stmt::Assign {
                    dst: dst.clone(),
                    src,
                }];
            }
            if let (Some(src), Some((dst, _))) =
                (packed_byte_table_intrinsic(name, ins, outs), outs.first())
            {
                return vec![Stmt::Assign {
                    dst: dst.clone(),
                    src,
                }];
            }
            if let (Some(src), Some((dst, _))) =
                (packed_signed_shift_intrinsic(name, ins, outs), outs.first())
            {
                return vec![Stmt::Assign {
                    dst: dst.clone(),
                    src,
                }];
            }
            if let (Some((op, width)), Some((dst, _))) =
                (wide_integer_intrinsic(name, ins, outs), outs.first())
            {
                return vec![Stmt::Assign {
                    dst: dst.clone(),
                    src: Expr::WideArithmetic {
                        op,
                        args: ins.iter().map(lower_value).collect(),
                        width,
                    },
                }];
            }
            if let (Some((operation, width)), Some((dst, _))) =
                (scalar_float_intrinsic(name, ins, outs), outs.first())
            {
                // Moves and negation retain exact value semantics even when an
                // unrelated opaque VFP status instruction prevents lowering a
                // whole arithmetic region. Keeping these producer edges is
                // essential at AAPCS-VFP call boundaries (`s0/s1/s2` setup).
                // Binary operations still require the closed-value proof above
                // so an unmodeled producer cannot become an invented live-in.
                if lower_scalar_float
                    || matches!(
                        operation,
                        ScalarFloatOperation::Move | ScalarFloatOperation::Negate
                    )
                {
                    let expression = match (operation, ins.as_slice()) {
                        (ScalarFloatOperation::Move, [src]) => Some(lower_float_value(src, width)),
                        (ScalarFloatOperation::Negate, [src]) => Some(Expr::Un {
                            op: UnOp::Neg,
                            src: Box::new(lower_float_value(src, width)),
                        }),
                        (ScalarFloatOperation::Binary(op), [lhs, rhs]) => Some(Expr::Bin {
                            op,
                            lhs: Box::new(lower_float_value(lhs, width)),
                            rhs: Box::new(lower_float_value(rhs, width)),
                        }),
                        (ScalarFloatOperation::Convert { from, to }, [src]) => {
                            Some(lower_scalar_conversion(src, from, to))
                        }
                        _ => None,
                    };
                    if let Some(src) = expression {
                        return vec![Stmt::Assign {
                            dst: dst.clone(),
                            src,
                        }];
                    }
                }
            }
            // An intrinsic that DECLARES a destination must assign to it, even
            // when the value is not modelled. Dropping `outs` here was a
            // dataflow lie with a measurable cost: the LLIR said "this defines
            // `xmm0_d0`", the rendered C said nothing, and every later reader
            // of that lane became an undefined read. It only became visible
            // when the readers were exactly lifted -- the def-use census moved
            // +529 across the three lanes that contain the SSE string family
            // while both gcc lanes, which contain none of it, stayed put.
            //
            // `Expr::Unknown` renders as `__unknown(...)`, which the harness
            // defines as returning 0. That is a WRONG VALUE where the previous
            // behaviour was a stale register -- both are wrong, but only this
            // one is honest about the dataflow, and an execution-differential
            // lane can see the difference either way.
            match semantic_comment_for_unknown(name) {
                Some(comment) => vec![Stmt::Comment(comment.to_string())],
                None => {
                    let call = if ins.is_empty() {
                        name.clone()
                    } else {
                        format!("{}(...)", name)
                    };
                    match outs.first() {
                        Some((dst, _)) => vec![Stmt::Assign {
                            dst: dst.clone(),
                            src: Expr::Unknown(call),
                        }],
                        None => vec![Stmt::Unknown(call)],
                    }
                }
            }
        }
        Op::Unknown { mnemonic } => match semantic_comment_for_unknown(mnemonic) {
            Some(comment) => vec![Stmt::Comment(comment.to_string())],
            None => vec![Stmt::Unknown(mnemonic.clone())],
        },
    }
}
