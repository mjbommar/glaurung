//! The whole-function scalar-float gate, and the tables it is built on.
//!
//! Lowering a float operation to real C arithmetic is only sound when every
//! value feeding that arithmetic has a modelled producer. This module owns that
//! proof ([`scalar_float_semantics_are_closed`]), the per-mnemonic tables it
//! consults, and the guarded diagnostic that makes its verdict observable.
//!
//! It lives beside `ast.rs` rather than inside it because the proof is a
//! self-contained ABI/ISA question, and `ast.rs` is the crate's largest file.

use super::{BinOp, ScalarFloatOperation, ScalarType};
use crate::ir::types::{LlirFunction, Op, VReg, Value};

fn scalar_vfp_register(register: &VReg) -> bool {
    matches!(register, VReg::Phys(name) if {
        let base = crate::ir::abi::ssa_base(name);
        base.strip_prefix('s').is_some_and(|n| n.parse::<u8>().is_ok())
            || base.strip_prefix('d').is_some_and(|n| n.parse::<u8>().is_ok())
            // x86-64 carries every scalar float in an SSE register.
            // Unlike ARM's `s`/`d` banks the name does not state a width, so
            // the width always comes from the instruction, never the register.
            || base.starts_with("xmm")
            // i386 has no SSE in its baseline ABI: its scalar floats live on
            // the x87 stack, which `crate::ir::x87` resolves into the eight
            // absolute slots `st0`..`st7`.
            || crate::ir::x87::is_slot_name(base)
    })
}

pub(super) fn scalar_float_intrinsic(
    name: &str,
    ins: &[Value],
    outs: &[(VReg, crate::ir::types::Width)],
) -> Option<(ScalarFloatOperation, u8)> {
    if let Some(converted) = arm_scalar_conversion_intrinsic(name) {
        return Some(converted);
    }
    let (base, width) = if let Some(base) = name.strip_suffix(".f32") {
        (base, 4)
    } else if let Some(base) = name.strip_suffix(".f64") {
        (base, 8)
    } else if name == "vmov"
        && matches!(ins, [Value::Reg(source)] if !scalar_vfp_register(source))
        && matches!(outs, [(destination, _)] if scalar_vfp_register(destination))
    {
        let [(_, declared_width)] = outs else {
            return None;
        };
        ("vmov", u8::try_from(declared_width.bytes()).ok()?)
    } else if let Some((operation, width)) = outs
        .first()
        .and_then(|(_, declared)| u8::try_from(declared.bytes()).ok())
        .and_then(|declared| x86_scalar_float_intrinsic(name, declared))
    {
        // x86 names its scalar float instructions by mnemonic rather than by
        // an ARM-style `.f32`/`.f64` suffix, so it gets its own table.
        return Some((operation, width));
    } else {
        return None;
    };
    let operation = match base {
        "vmov" => ScalarFloatOperation::Move,
        "vneg" => ScalarFloatOperation::Negate,
        "vadd" => ScalarFloatOperation::Binary(BinOp::Add),
        "vsub" => ScalarFloatOperation::Binary(BinOp::Sub),
        "vmul" => ScalarFloatOperation::Binary(BinOp::Mul),
        "vdiv" => ScalarFloatOperation::Binary(BinOp::Div),
        _ => return None,
    };
    Some((operation, width))
}

/// One end of an ARM-syntax conversion suffix: `f32`, `f64`, `s32` or `s64`.
///
/// Unsigned ends are deliberately absent. [`ScalarType`] has no unsigned
/// variant, so `ucvtf`/`fcvtzu` would have to be spelled as their signed
/// neighbour — which disagrees for every value above the signed maximum, and
/// that disagreement is exactly what `173_float_int_conversions` measures. They
/// stay on the opaque path until the type carries signedness.
fn arm_conversion_end(text: &str) -> Option<ScalarType> {
    Some(match text {
        "f32" => ScalarType::Float(4),
        "f64" => ScalarType::Float(8),
        "s32" => ScalarType::SignedInt(4),
        "s64" => ScalarType::SignedInt(8),
        _ => return None,
    })
}

/// The C meaning of a scalar conversion named in ARM's `vcvt.<to>.<from>`
/// syntax — `vcvt.f64.s32` is `(double)(int)x`.
///
/// ARM32's assembler spells its VFP conversions this way already, and
/// `lift_arm64` emits the same canonical name for AArch64's `scvtf`, `fcvtzs`
/// and `fcvt`, whose mnemonics carry the same two ends in a different notation.
/// One lowering therefore serves both producers, the choice
/// `lower_ops::wide_integer_intrinsic` records for `umulh`/`sdiv`. (Not a link:
/// that function is private to a sibling module, so no path names it from here.)
///
/// The returned width is the RESULT's, matching
/// [`x86_scalar_float_intrinsic`]: it is what types the destination.
fn arm_scalar_conversion_intrinsic(name: &str) -> Option<(ScalarFloatOperation, u8)> {
    let (to, from) = name.strip_prefix("vcvt.")?.split_once('.')?;
    let to = arm_conversion_end(to)?;
    let from = arm_conversion_end(from)?;
    if to == from {
        return None;
    }
    Some((ScalarFloatOperation::Convert { from, to }, to.width()))
}

/// The C meaning of one x86 scalar-SSE intrinsic, as `lift_x86` names it.
///
/// The returned width is the width of the RESULT, which is what the caller
/// needs to spell a float literal and to type the destination. For a
/// conversion, the operand's own width travels inside
/// [`ScalarFloatOperation::Convert`] instead, because the two ends differ —
/// that difference is the entire content of a `cvt*` instruction.
///
/// Deliberately absent: the packed forms, the reciprocal/rsqrt approximations
/// (which are not exactly any C expression), and `cvtss2si`'s round-to-nearest
/// behaviour under a non-default rounding mode. Anything not listed keeps its
/// existing opaque-comment lowering rather than acquiring a plausible wrong
/// meaning.
fn x86_scalar_float_intrinsic(name: &str, out_width: u8) -> Option<(ScalarFloatOperation, u8)> {
    use ScalarFloatOperation::{Binary, Convert};
    use ScalarType::{Float, SignedInt};

    Some(match name {
        "addss" => (Binary(BinOp::Add), 4),
        "subss" => (Binary(BinOp::Sub), 4),
        "mulss" => (Binary(BinOp::Mul), 4),
        "divss" => (Binary(BinOp::Div), 4),
        "addsd" => (Binary(BinOp::Add), 8),
        "subsd" => (Binary(BinOp::Sub), 8),
        "mulsd" => (Binary(BinOp::Mul), 8),
        "divsd" => (Binary(BinOp::Div), 8),
        "cvtss2sd" => (
            Convert {
                from: Float(4),
                to: Float(8),
            },
            8,
        ),
        "cvtsd2ss" => (
            Convert {
                from: Float(8),
                to: Float(4),
            },
            4,
        ),
        "cvtsi2ss.l" => (
            Convert {
                from: SignedInt(4),
                to: Float(4),
            },
            4,
        ),
        "cvtsi2ss.q" => (
            Convert {
                from: SignedInt(8),
                to: Float(4),
            },
            4,
        ),
        "cvtsi2sd.l" => (
            Convert {
                from: SignedInt(4),
                to: Float(8),
            },
            8,
        ),
        "cvtsi2sd.q" => (
            Convert {
                from: SignedInt(8),
                to: Float(8),
            },
            8,
        ),
        // C's float-to-integer conversion truncates toward zero, which is
        // precisely what the `t` forms do; the non-`t` forms follow MXCSR and
        // are only equal to a C cast in the default round-to-nearest mode, so
        // they are left opaque.
        "cvttss2si" => (
            Convert {
                from: Float(4),
                to: SignedInt(out_width),
            },
            4,
        ),
        "cvttsd2si" => (
            Convert {
                from: Float(8),
                to: SignedInt(out_width),
            },
            8,
        ),
        _ => return None,
    })
}

/// Whether this mnemonic is an x86 floating-point instruction the lifter has
/// NOT given semantics to.
///
/// The ARM half of [`scalar_float_semantics_are_closed`] recognises an opaque
/// VFP producer by its leading `v`. x86 has no such marker, so the same
/// protection needs its own predicate — without one, a `shufps` or an
/// approximate-reciprocal that this lifter leaves as a comment would silently
/// become an invented live-in feeding real arithmetic, which is exactly the
/// "`var = var + var`" failure the ARM guard was written to prevent.
///
/// Anything already lowered by [`x86_scalar_float_intrinsic`] is modelled and
/// so is not opaque; everything else that touches float or packed lanes is.
fn unmodelled_x86_float_mnemonic(name: &str) -> bool {
    if x86_scalar_float_intrinsic(name, 4).is_some()
        || x86_scalar_float_intrinsic(name, 8).is_some()
    {
        return false;
    }
    // The x87 CONTROL WORD is a 16-bit integer status value, not a float. GCC
    // saves, modifies and restores it around every float-to-integer cast, so
    // treating those two as opaque float producers would cost every i386
    // conversion function the arithmetic around it — and there is no float
    // value for them to invent, which is what this guard is protecting.
    if matches!(name, "x87.fldcw" | "x87.fnstcw") {
        return false;
    }
    // Everything else `crate::ir::x87` declines to model IS a float producer:
    // the stack slots it leaves undefined are the values later arithmetic
    // would otherwise read as an invented live-in.
    if name.starts_with("x87.") {
        return true;
    }
    const OPAQUE_PREFIXES: [&str; 8] = [
        "cvt", "ucomi", "comi", "sqrt", "rcp", "rsqrt", "shuf", "unpck",
    ];
    const OPAQUE_SUFFIXES: [&str; 4] = ["ss", "sd", "ps", "pd"];
    OPAQUE_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || OPAQUE_SUFFIXES
            .iter()
            .any(|suffix| name.len() > 2 && name.ends_with(suffix))
}

/// Spell one op's contribution to the whole-function scalar-float proof, for
/// [`trace_scalar_float_gate`].
///
/// The proof runs on the POST-SSA function, where copy propagation and value
/// numbering have already rewritten the operands, so the shape the lifter wrote
/// is not the shape the proof sees. `lift_window_at` shows the lifter's
/// version, not this one, which is why the gate's decision cannot be read off
/// the raw lift.
fn scalar_float_gate_note(op: &Op, all_caller_saved: bool) -> Option<String> {
    let spell = |registers: Vec<String>| {
        if registers.is_empty() {
            "[]".to_string()
        } else {
            format!("[{}]", registers.join(","))
        }
    };
    Some(match op {
        Op::Intrinsic {
            name, ins, outs, ..
        } => {
            let verdict = match scalar_float_intrinsic(name, ins, outs) {
                Some((_, width)) => format!("scalar_float=yes width={width}"),
                None if name.starts_with('v') || unmodelled_x86_float_mnemonic(name) => {
                    "opaque_float=yes -> gate SHUTS".to_string()
                }
                None => "scalar_float=no opaque=no -> ignored".to_string(),
            };
            format!(
                "intrinsic {name} ins={} outs={} {verdict}",
                spell(ins.iter().map(|value| format!("{value:?}")).collect()),
                spell(
                    outs.iter()
                        .map(|(register, width)| format!("{}:{}", register, width.bytes()))
                        .collect()
                ),
            )
        }
        Op::Unknown { mnemonic } => format!(
            "unknown {mnemonic} opaque_float={}",
            mnemonic.starts_with('v') || unmodelled_x86_float_mnemonic(mnemonic)
        ),
        Op::Call { effects, .. } => {
            let result = effects.as_ref().and_then(|effects| effects.result.as_ref());
            let verdict = if result.is_some_and(scalar_vfp_register) {
                "vfp result -> saw_scalar_float"
            } else if !all_caller_saved {
                "no vfp result, float regs NOT all caller-saved -> gate SHUTS"
            } else {
                "ignored (every float register here is caller-saved)"
            };
            let result = result.map_or("none".to_string(), VReg::to_string);
            format!("call result={result} {verdict}")
        }
        _ => return None,
    })
}

/// Report, op by op, how the whole-function scalar-float gate was decided.
///
/// Guarded by `GLAURUNG_PASS_HEALTH` in the style of [`crate::ir::health`]. The
/// gate is all-or-nothing across a function, so when it shuts every float
/// operation in the body renders as `/* asm: … */` and the assignment is
/// DROPPED — the emitted C then compiles, runs, and silently carries the
/// destination's previous value. That failure mode is invisible in the output,
/// which is why the decision needs to be observable from outside.
///
/// `float_bank_seen` is reported separately from the caller-saved verdict on
/// purpose: a function that does float arithmetic without ever naming an SSE
/// register is the shape that misled the old predicate, and it is invisible in
/// the recovered C.
fn trace_scalar_float_gate(lf: &LlirFunction, closed: bool) {
    if std::env::var_os("GLAURUNG_PASS_HEALTH").is_none() {
        return;
    }
    // Computed here, not by the caller: `float_registers_are_all_caller_saved`
    // walks every instruction and calls `def_uses`, which allocates a `Vec` and
    // clones each `VReg` name. Passing it as an argument made the caller pay for
    // it on every lowered function whether or not the trace was enabled.
    let all_caller_saved = float_registers_are_all_caller_saved(lf);
    let float_bank_seen = any_physical_register(lf, |base| {
        base.starts_with("xmm") || crate::ir::x87::is_slot_name(base)
    });
    eprintln!(
        "[glaurung-float-gate] function entry_va={:#x} closed={closed} \
         float_registers_are_all_caller_saved={all_caller_saved} \
         float_bank_seen={float_bank_seen}",
        lf.entry_va
    );
    for instruction in lf.blocks.iter().flat_map(|block| &block.instrs) {
        if let Some(note) = scalar_float_gate_note(&instruction.op, all_caller_saved) {
            eprintln!("[glaurung-float-gate]   va={:#x} {note}", instruction.va);
        }
    }
}

/// An x86 register spelling no other lifted architecture can produce.
///
/// The eight legacy general-purpose registers and the instruction pointer, in
/// their 64- and 32-bit forms, plus both float banks. Deliberately absent:
/// `r8`..`r15`, `sp`, `fp`, `ip`, `lr`, `pc` — ARM32 spells its own registers
/// `r0`..`r15` and both ARM banks use the short names, so those would answer
/// "x86" for an AAPCS function.
fn x86_register_base(base: &str) -> bool {
    matches!(
        base,
        "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "rbp"
            | "rsp"
            | "rip"
            | "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "esi"
            | "edi"
            | "ebp"
            | "esp"
            | "eip"
    ) || base.starts_with("xmm")
        || crate::ir::x87::is_slot_name(base)
}

/// Whether every float register this function touches is caller-saved.
///
/// This is a question about the ABI, so it is answered from the ISA. x86-64
/// SysV and i386 both make every SSE register and the whole x87 stack
/// caller-saved; AAPCS does not — `s16`-`s31` and `d8`-`d15` are callee-SAVED
/// there, so a float value really can live across a call and its producer
/// really is unmodelled. The ISA is inferred from the register names in play
/// rather than threaded down as a convention, because [`LlirFunction`] does not
/// carry its architecture.
///
/// Reading the ISA off the FLOAT bank alone is what this used to do, and it is
/// not sound: an x86 function need never name an SSE register even while doing
/// float arithmetic. `197_homogeneous_float_aggregates:gcc:O2:hfa197_tagged_control`
/// converts straight out of a spill slot — `cvttss2si 0xc(%rsp),%eax` — so the
/// whole function looked like AAPCS, its single `Op::Call` shut the gate, and a
/// fully modelled `cvttss2si` lowered to `/* asm: cvttss2si(...) */`. That
/// spelling DROPS the assignment, so the destination silently kept the raw
/// float bits and the emitted C compiled, ran, and was wrong. The integer bank
/// is the reliable witness: every x86 function names it.
///
/// The x87 protection does not rest on this predicate. Where
/// `x87::plan_function` cannot prove the stack depths, `lift_x86` emits each x87
/// instruction as `Op::Unknown { mnemonic: "x87.…" }`, which
/// [`unmodelled_x86_float_mnemonic`] already reports as an opaque float producer
/// — the gate shuts on that arm, one op earlier and for a stated reason.
/// Keeping i386 on the caller-saved side is what stops the
/// `call __x86.get_pc_thunk.*` opening every PIC i386 function from sending its
/// whole body back to opaque comments.
fn float_registers_are_all_caller_saved(lf: &LlirFunction) -> bool {
    any_physical_register(lf, x86_register_base)
}

/// Whether any physical register defined or used in `lf` satisfies `predicate`,
/// which receives the SSA-version-stripped register name.
fn any_physical_register(lf: &LlirFunction, predicate: impl Fn(&str) -> bool) -> bool {
    lf.blocks
        .iter()
        .flat_map(|block| &block.instrs)
        .flat_map(|instruction| {
            let (definition, uses) = crate::ir::use_def::def_uses(&instruction.op);
            definition.into_iter().chain(uses)
        })
        .any(|register| {
            matches!(&register, VReg::Phys(name) if predicate(crate::ir::abi::ssa_base(name)))
        })
}

/// Whether every VFP value used by the scalar arithmetic subset has a modeled
/// producer in this function.
///
/// Register-only hard-float leaves (arguments, exact immediates, arithmetic,
/// and an `s0`/`d0` result) are closed and can be rendered as C. Once an opaque
/// VFP instruction or a call participates, lowering only the arithmetic nodes
/// would be actively misleading: an unmodeled `vldr` followed by
/// `vadd.f32 s0, s15, s15` becomes `var = var + var` with an invented live-in.
/// Keep the entire scalar-float subset opaque until those producers are modeled.
pub(super) fn scalar_float_semantics_are_closed(lf: &LlirFunction) -> bool {
    let closed = scalar_float_semantics_proof(lf);
    trace_scalar_float_gate(lf, closed);
    closed
}

fn scalar_float_semantics_proof(lf: &LlirFunction) -> bool {
    let float_registers_are_all_caller_saved = float_registers_are_all_caller_saved(lf);
    let mut saw_scalar_float = false;
    for instruction in lf.blocks.iter().flat_map(|block| &block.instrs) {
        match &instruction.op {
            Op::Intrinsic {
                name, ins, outs, ..
            } if scalar_float_intrinsic(name, ins, outs).is_some() => {
                saw_scalar_float = true;
            }
            Op::Intrinsic { name, .. } | Op::Unknown { mnemonic: name }
                if name.starts_with('v') || unmodelled_x86_float_mnemonic(name) =>
            {
                return false;
            }
            // AAPCS-VFP call annotation selects s0/d0 only when a subsequent
            // machine instruction actually consumes that storage before it is
            // overwritten.  That is a closed producer edge, unlike the legacy
            // integer-only/default call effect, so scalar lowering may safely
            // continue through it.
            Op::Call {
                effects:
                    Some(crate::ir::types::CallEffects {
                        result: Some(result),
                        ..
                    }),
                ..
            } if scalar_vfp_register(result) => saw_scalar_float = true,
            // A call with no typed VFP result may still clobber the value a
            // later scalar op appears to consume. Keep that region opaque —
            // UNLESS the convention makes that impossible.
            //
            // On x86-64 SysV every SSE register is caller-saved, so no
            // compiler-generated code reads a float value across a call: the
            // value is always spilled and reloaded. There is therefore no
            // unmodelled producer for a call to be, and treating one as opaque
            // costs the whole function its float arithmetic — `dot_product_f64`
            // reduced to `/* asm: mulsd */ /* asm: addsd */` purely because it
            // also called a bounds check that returns an `int`.
            //
            // AAPCS is genuinely different and stays conservative: `s16`-`s31`
            // are callee-SAVED there, so a value really can live across a call
            // and its producer really is unmodelled.
            Op::Call { .. } if !float_registers_are_all_caller_saved => return false,
            Op::Call { .. } => {}
            // Scalar VFP memory traffic is represented by ordinary typed
            // Load/Store nodes. Those operations close dataflow rather than
            // creating an opaque producer.
            Op::Load { dst, .. } | Op::CondLoad { dst, .. } if scalar_vfp_register(dst) => {
                saw_scalar_float = true
            }
            Op::Store {
                src: Value::Reg(src),
                ..
            }
            | Op::CondStore {
                src: Value::Reg(src),
                ..
            } if scalar_vfp_register(src) => saw_scalar_float = true,
            _ => {}
        }
    }
    saw_scalar_float
}
