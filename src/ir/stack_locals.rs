//! Promote stack-relative memory accesses to named locals.
//!
//! A lot of decompiled noise comes from seeing `*(u64)&[%rsp+0x158]` over
//! and over. This pass rewrites every such access whose base is a stack
//! register (rsp/ebp/sp/x29) and whose effective address is a constant
//! displacement into a named local variable. A slot is identified by its
//! `(base, disp)` alone, so a read and a write of the same slot resolve to one
//! local (keeping its def/use chain intact); the recovered access width is
//! carried alongside the name and narrowed to the true load width.
//!
//! Naming:
//! * Positive displacements from rsp/sp — likely caller-allocated scratch —
//!   become `stack_N` where N counts the slot in first-appearance order.
//! * Negative displacements from a frame pointer (rbp/x29) — classic local
//!   variables — become `local_N`.
//! * Zero-displacement `[rsp]` (stack top) becomes `stack_top`.
//!
//! Pointer arithmetic that isn't a concrete load/store (e.g. `rsp = rsp - 8`)
//! is **not** touched — those are stack-pointer updates that should keep
//! the `%rsp` form so a reader can see the prologue/epilogue shape.
//! [`Expr::Lea`] references that *would* appear inside a store or load are
//! folded; bare `Expr::Lea` taken of a stack slot stays untouched so it
//! still reads as `&[%rsp+...]`.

use std::collections::HashMap;

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::types::VReg;

const STACK_BASES: &[&str] = &["rsp", "esp", "sp", "rbp", "ebp", "bp", "x29", "w29", "fp"];
const FRAME_POINTER_BASES: &[&str] = &["rbp", "ebp", "bp", "x29", "w29", "fp"];

fn is_stack_base(name: &str) -> bool {
    STACK_BASES.contains(&name)
}

fn is_frame_pointer(name: &str) -> bool {
    FRAME_POINTER_BASES.contains(&name)
}

/// Opaque key for the (base_name, disp) of a stack slot. Deliberately does NOT
/// include the access size: the *same* memory slot is often read and written at
/// spellings the lowering reports with different sizes (a 4-byte load vs a store
/// whose size we don't thread through), and keying on size would then mint two
/// different local names for one variable — severing its def/use chain. The
/// recovered size is tracked in the map *value* instead (see [`SlotVal`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SlotKey {
    base: String,
    disp: i64,
}

/// The promoted local name for a slot plus the narrowest access width observed
/// for it. Loads report the true width; stores (width unknown here) report the
/// conservative 8, so taking the min lets a real load width win.
type SlotVal = (String, u8);

#[derive(Clone, Copy)]
struct StackContext {
    cc: Option<CallConv>,
}

/// Rewrite stack-relative memory accesses to named locals.
pub fn promote_stack_locals(f: &mut Function) {
    let _ = promote_stack_locals_typed(f, None);
}

/// Like [`promote_stack_locals`], but also returns the recovered byte size of
/// each promoted local (`local_0 -> 4`, `stack_1 -> 8`, ...), taken from the
/// width of the memory accesses that defined the slot. Callers thread this into
/// type recovery so a 4-byte spill slot renders as `int` rather than the
/// blanket `long`. When a name is defined at more than one width the widest is
/// kept (the safest committed size).
pub fn promote_stack_locals_typed(f: &mut Function, cc: Option<CallConv>) -> HashMap<String, u8> {
    let mut map: HashMap<SlotKey, SlotVal> = HashMap::new();
    let mut stack_counter = 0usize;
    let mut local_counter = 0usize;
    let ctx = StackContext { cc };
    let mut sp_delta = Some(0i64);
    rewrite_body(
        &mut f.body,
        &mut map,
        &mut stack_counter,
        &mut local_counter,
        ctx,
        &mut sp_delta,
    );
    map.into_values().collect()
}

/// Where a calling convention puts the arguments that do not fit in registers:
/// how many arrive in registers, and the frame-pointer offset of the first stacked
/// one in a standard frame.
///
/// SysV AMD64: six integer registers, then `[rbp+16]` upward — `[rbp]` holds the
/// saved frame pointer and `[rbp+8]` the return address. AArch64 AAPCS: eight
/// registers, then `[x29+16]`, the frame record being `{fp, lr}`. Win64 and ARM32
/// are deliberately absent: their layouts (a 32-byte shadow space; a different frame
/// record) are not exercised by any fixture here, and guessing at an ABI is how a
/// decompiler invents a parameter that does not exist.
fn stack_arg_layout(cc: CallConv) -> Option<(usize, i64)> {
    match cc {
        CallConv::SysVAmd64 => Some((6, 16)),
        CallConv::Aarch64 => Some((8, 16)),
        CallConv::Win64 | CallConv::Arm => None,
    }
}

fn rewrite_body(
    body: &mut [Stmt],
    map: &mut HashMap<SlotKey, SlotVal>,
    stack_counter: &mut usize,
    local_counter: &mut usize,
    ctx: StackContext,
    sp_delta: &mut Option<i64>,
) {
    for s in body.iter_mut() {
        match s {
            Stmt::IndirectGoto { target } => {
                rewrite_expr(target, map, stack_counter, local_counter, ctx, *sp_delta)
            }
            Stmt::Assign { dst, src } => {
                rewrite_expr(src, map, stack_counter, local_counter, ctx, *sp_delta);
                if is_rsp_reg(dst) {
                    *sp_delta = stack_delta_after_assignment(dst, src, *sp_delta);
                }
            }
            Stmt::Store { addr, src, .. } => {
                // Store's addr is an Lea — we need to rewrite the Lea itself
                // into a Reg reference when the lea points to a stack slot.
                try_promote_lea_to_local(addr, map, stack_counter, local_counter, ctx, *sp_delta);
                rewrite_expr(src, map, stack_counter, local_counter, ctx, *sp_delta);
            }
            Stmt::Call { target, args, .. } => {
                rewrite_expr(target, map, stack_counter, local_counter, ctx, *sp_delta);
                for a in args {
                    rewrite_expr(a, map, stack_counter, local_counter, ctx, *sp_delta);
                }
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    rewrite_expr(e, map, stack_counter, local_counter, ctx, *sp_delta);
                }
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                rewrite_expr(cond, map, stack_counter, local_counter, ctx, *sp_delta);
                let incoming = *sp_delta;
                let mut then_delta = incoming;
                rewrite_body(
                    then_body,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    &mut then_delta,
                );
                let mut else_delta = incoming;
                if let Some(eb) = else_body {
                    rewrite_body(eb, map, stack_counter, local_counter, ctx, &mut else_delta);
                }
                *sp_delta = merge_stack_deltas(then_delta, else_delta);
            }
            Stmt::While { cond, body } => {
                rewrite_expr(cond, map, stack_counter, local_counter, ctx, *sp_delta);
                let incoming = *sp_delta;
                let mut body_delta = incoming;
                rewrite_body(
                    body,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    &mut body_delta,
                );
                *sp_delta = merge_stack_deltas(incoming, body_delta);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                rewrite_body(
                    std::slice::from_mut(init.as_mut()),
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    sp_delta,
                );
                rewrite_expr(cond, map, stack_counter, local_counter, ctx, *sp_delta);
                let loop_entry = *sp_delta;
                let mut body_delta = loop_entry;
                rewrite_body(
                    body,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    &mut body_delta,
                );
                rewrite_body(
                    std::slice::from_mut(step.as_mut()),
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    &mut body_delta,
                );
                *sp_delta = merge_stack_deltas(loop_entry, body_delta);
            }
            Stmt::DoWhile { body, cond } => {
                let incoming = *sp_delta;
                let mut body_delta = incoming;
                rewrite_body(
                    body,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    &mut body_delta,
                );
                rewrite_expr(cond, map, stack_counter, local_counter, ctx, body_delta);
                *sp_delta = merge_stack_deltas(incoming, body_delta);
            }
            Stmt::Push { value } => {
                rewrite_expr(value, map, stack_counter, local_counter, ctx, *sp_delta);
                *sp_delta = sp_delta.map(|delta| delta - 8);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                rewrite_expr(
                    discriminant,
                    map,
                    stack_counter,
                    local_counter,
                    ctx,
                    *sp_delta,
                );
                let incoming = *sp_delta;
                let mut merged: Option<Option<i64>> = None;
                for (_, body) in cases.iter_mut() {
                    let mut case_delta = incoming;
                    rewrite_body(
                        body,
                        map,
                        stack_counter,
                        local_counter,
                        ctx,
                        &mut case_delta,
                    );
                    merged = Some(match merged {
                        Some(prior) => merge_stack_deltas(prior, case_delta),
                        None => case_delta,
                    });
                }
                if let Some(b) = default {
                    let mut default_delta = incoming;
                    rewrite_body(
                        b,
                        map,
                        stack_counter,
                        local_counter,
                        ctx,
                        &mut default_delta,
                    );
                    merged = Some(match merged {
                        Some(prior) => merge_stack_deltas(prior, default_delta),
                        None => default_delta,
                    });
                } else {
                    merged = Some(match merged {
                        Some(prior) => merge_stack_deltas(prior, incoming),
                        None => incoming,
                    });
                }
                *sp_delta = merged.unwrap_or(incoming);
            }
            Stmt::Pop { .. } => {
                *sp_delta = sp_delta.map(|delta| delta + 8);
            }
            Stmt::Label(_) => {
                // A raw label may have incoming gotos from a different stack
                // state; without CFG-aware propagation the safe answer is unknown.
                *sp_delta = None;
            }
            Stmt::Goto { .. } | Stmt::Break | Stmt::Nop | Stmt::Unknown(_) | Stmt::Comment(_) => {}
        }
    }
}

fn is_rsp_reg(reg: &VReg) -> bool {
    matches!(reg, VReg::Phys(name) if matches!(name.as_str(), "rsp" | "esp"))
}

fn stack_delta_after_assignment(dst: &VReg, src: &Expr, before: Option<i64>) -> Option<i64> {
    if !is_rsp_reg(dst) {
        return before;
    }
    match src {
        Expr::Reg(reg) if is_rsp_reg(reg) => before,
        Expr::Bin { op, lhs, rhs } if matches!(lhs.as_ref(), Expr::Reg(reg) if is_rsp_reg(reg)) => {
            let Expr::Const(amount) = rhs.as_ref() else {
                return None;
            };
            match op {
                crate::ir::types::BinOp::Add => before.map(|delta| delta + amount),
                crate::ir::types::BinOp::Sub => before.map(|delta| delta - amount),
                _ => None,
            }
        }
        _ => None,
    }
}

fn merge_stack_deltas(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    (a == b).then_some(a).flatten()
}

/// Promote a `Deref { addr: Lea { base: stack_base, disp, .. } }` into a
/// `Reg(local_name)` reference. Walks sub-expressions so nested derefs fold.
fn rewrite_expr(
    e: &mut Expr,
    map: &mut HashMap<SlotKey, SlotVal>,
    stack_counter: &mut usize,
    local_counter: &mut usize,
    ctx: StackContext,
    sp_delta: Option<i64>,
) {
    match e {
        Expr::Deref { addr, size } => {
            let size_val = *size;
            rewrite_expr(addr, map, stack_counter, local_counter, ctx, sp_delta);
            // After recursion, see whether the addr is a bare Lea of a
            // stack slot; if so, collapse the whole deref into a Reg ref.
            if let Expr::Lea {
                base: Some(VReg::Phys(name)),
                index: None,
                scale: _,
                disp,
                segment: _,
            } = addr.as_ref()
            {
                if is_stack_base(name) {
                    let (key_base, key_disp) = normalized_stack_slot(name, *disp, sp_delta);
                    let key = SlotKey {
                        base: key_base.clone(),
                        disp: key_disp,
                    };
                    let entry = map.entry(key).or_insert_with(|| {
                        (
                            alloc_name(&key_base, key_disp, stack_counter, local_counter, ctx),
                            size_val,
                        )
                    });
                    // A load reports the true access width — let it win.
                    entry.1 = entry.1.min(size_val);
                    let alias = entry.0.clone();
                    *e = Expr::Reg(VReg::phys(alias));
                    return;
                }
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            rewrite_expr(lhs, map, stack_counter, local_counter, ctx, sp_delta);
            rewrite_expr(rhs, map, stack_counter, local_counter, ctx, sp_delta);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            rewrite_expr(cond, map, stack_counter, local_counter, ctx, sp_delta);
            rewrite_expr(if_true, map, stack_counter, local_counter, ctx, sp_delta);
            rewrite_expr(if_false, map, stack_counter, local_counter, ctx, sp_delta);
        }
        Expr::Un { src, .. } => rewrite_expr(src, map, stack_counter, local_counter, ctx, sp_delta),
        Expr::Cast { expr, .. } => {
            rewrite_expr(expr, map, stack_counter, local_counter, ctx, sp_delta)
        }
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. }
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
    }
}

/// Store-address Lea: turn the full `&[base+disp]` into a `Reg(local)`.
fn try_promote_lea_to_local(
    addr: &mut Expr,
    map: &mut HashMap<SlotKey, SlotVal>,
    stack_counter: &mut usize,
    local_counter: &mut usize,
    ctx: StackContext,
    sp_delta: Option<i64>,
) {
    // The store's `addr` carries no access size (our lowering doesn't thread it
    // through), so we record the conservative 8. Because the size lives in the
    // map value and is combined with `min`, a load of the same slot still gets
    // to pin the true, narrower width — and, crucially, the slot resolves to the
    // *same* local name as that load rather than a second one.
    if let Expr::Lea {
        base: Some(VReg::Phys(name)),
        index: None,
        scale: _,
        disp,
        segment: _,
    } = addr
    {
        if is_stack_base(name) {
            let (key_base, key_disp) = normalized_stack_slot(name, *disp, sp_delta);
            let key = SlotKey {
                base: key_base.clone(),
                disp: key_disp,
            };
            let entry = map.entry(key).or_insert_with(|| {
                (
                    alloc_name(&key_base, key_disp, stack_counter, local_counter, ctx),
                    8,
                )
            });
            entry.1 = entry.1.min(8);
            let alias = entry.0.clone();
            *addr = Expr::Reg(VReg::phys(alias));
        }
    }
}

/// Express an rsp-relative slot against the architectural entry rsp when the
/// current delta is known. This makes `[rsp+16]` after one push the same slot as
/// `[entry_rsp+8]`, and gives naming an ABI-stable displacement.
fn normalized_stack_slot(base: &str, disp: i64, sp_delta: Option<i64>) -> (String, i64) {
    if base == "rsp" {
        if let Some(delta) = sp_delta {
            return ("entry_rsp".to_string(), disp + delta);
        }
    }
    (base.to_string(), disp)
}

fn alloc_name(
    base: &str,
    disp: i64,
    stack_counter: &mut usize,
    local_counter: &mut usize,
    ctx: StackContext,
) -> String {
    if disp == 0 {
        return "stack_top".to_string();
    }
    if is_frame_pointer(base) && disp < 0 {
        // Name frame locals by their offset (`[rbp-0xc]` -> `local_c`), the
        // Ghidra/IDA convention. The offset is genuine recovered information and
        // lets an offset-aware consumer align our locals to the ground truth,
        // rather than an appearance-order counter that carries no such signal.
        *local_counter += 1; // keep the counter advancing for any legacy callers
        return format!("local_{:x}", disp.unsigned_abs());
    }
    // A positive frame-pointer offset at or above the ABI's first stacked-argument
    // slot IS AN INCOMING PARAMETER, not a local. Naming it `stack_N` invents a
    // local the function never assigns — which is precisely what the def-before-use
    // verifier reports for `sum_arg7`..`sum_arg10` (`stack_0 is read but never
    // defined`) — and leaves it out of the signature, so the recompiled function
    // reads uninitialised memory instead of its own argument.
    if is_frame_pointer(base) && disp > 0 {
        if let Some((reg_args, first)) = ctx.cc.and_then(stack_arg_layout) {
            if disp >= first && (disp - first) % 8 == 0 {
                return format!("arg{}", reg_args + ((disp - first) / 8) as usize);
            }
        }
    }
    // A frame-pointer-omitted SysV leaf keeps rsp equal to the architectural
    // entry value. [rsp] is the return address; eight-byte slots above it are
    // therefore the arguments that follow the six integer register slots.
    if ctx.cc == Some(CallConv::SysVAmd64)
        && base == "entry_rsp"
        && disp >= 8
        && (disp - 8) % 8 == 0
    {
        return format!("arg{}", 6 + ((disp - 8) / 8) as usize);
    }
    // Positive offsets from rsp are outgoing-arg / scratch slots; negative
    // offsets from rsp are the function's own frame carved out by `sub
    // rsp, N`. We still use `stack_N` for both — a future pass can decide
    // to relabel based on the prologue's sub rsp amount.
    let n = *stack_counter;
    *stack_counter += 1;
    format!("stack_{}", n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Function, Stmt};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }
    fn lea(base: &str, disp: i64) -> Expr {
        Expr::Lea {
            base: Some(reg(base)),
            index: None,
            scale: 0,
            disp,
            segment: None,
        }
    }
    fn deref_of(base: &str, disp: i64, size: u8) -> Expr {
        Expr::Deref {
            addr: Box::new(lea(base, disp)),
            size,
        }
    }

    fn promoted(base: &str, disp: i64, cc: Option<CallConv>) -> String {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src: deref_of(base, disp, 4),
            }],
        };
        promote_stack_locals_typed(&mut f, cc);
        match &f.body[0] {
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(n)),
                ..
            } => n.clone(),
            other => panic!("expected a promoted register, got {other:?}"),
        }
    }

    #[test]
    fn a_positive_frame_offset_is_a_stack_passed_argument_not_a_local() {
        // SysV AMD64: [rbp] is the saved frame pointer, [rbp+8] the return address,
        // so [rbp+16] upward are the arguments that did not fit in the six integer
        // registers. Calling them `stack_N` invents a local the function never
        // assigns, and leaves the parameter out of the signature.
        let cc = Some(CallConv::SysVAmd64);
        assert_eq!(promoted("rbp", 16, cc), "arg6");
        assert_eq!(promoted("rbp", 24, cc), "arg7");
        assert_eq!(promoted("rbp", 32, cc), "arg8");
        assert_eq!(promoted("rbp", 40, cc), "arg9");
    }

    #[test]
    fn an_unchanged_entry_stack_pointer_exposes_optimized_sysv_stack_arguments() {
        // GCC/Clang -O2 omit the frame pointer for leaf functions such as
        // `sum_arg10`. With no prologue adjustment, [rsp] is the return address
        // and [rsp+8], [rsp+16], ... are the arguments after r9. Treating those
        // reads as `stack_N` locals truncates the C signature at six arguments
        // and makes the rebuilt function consume uninitialised locals.
        let mut f = Function {
            name: "sum_arg8".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rsp", 8, 4),
                },
                Stmt::Assign {
                    dst: reg("rdx"),
                    src: deref_of("rsp", 16, 8),
                },
            ],
        };

        let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(matches!(
            &f.body[0],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg6"
        ));
        assert!(matches!(
            &f.body[1],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg7"
        ));
        assert_eq!(sizes.get("arg6"), Some(&4));
        assert_eq!(sizes.get("arg7"), Some(&8));
    }

    #[test]
    fn an_adjusted_stack_pointer_does_not_invent_incoming_arguments() {
        // Once a function carves out a frame, a positive displacement from the
        // new rsp can be a local or outgoing-call slot. It is not safe to map it
        // to an incoming parameter without normalising the stack delta.
        let mut f = Function {
            name: "has_frame".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(32)),
                    },
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rsp", 16, 4),
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(matches!(
            &f.body[1],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "stack_0"
        ));
    }

    #[test]
    fn callee_saved_pushes_are_normalized_before_mapping_stack_arguments() {
        // Clang -O2 `sum_arg8` pushes rbx, then reads a6 from [rsp+16] and a7
        // from [rsp+24]. GCC `sum_arg10` has the same shape with rbp. The
        // current rsp is entry_rsp-8, so those addresses are entry_rsp+8 and
        // entry_rsp+16 respectively.
        let mut f = Function {
            name: "sum_arg8".into(),
            entry_va: 0,
            body: vec![
                Stmt::Push {
                    value: Expr::Reg(reg("rbx")),
                },
                Stmt::Assign {
                    dst: reg("r10"),
                    src: deref_of("rsp", 16, 4),
                },
                Stmt::Assign {
                    dst: reg("r11"),
                    src: deref_of("rsp", 24, 4),
                },
                Stmt::Pop { target: reg("rbx") },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(matches!(
            &f.body[1],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg6"
        ));
        assert!(matches!(
            &f.body[2],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg7"
        ));
    }

    #[test]
    fn aarch64_stacked_arguments_start_after_eight_registers() {
        let cc = Some(CallConv::Aarch64);
        assert_eq!(promoted("x29", 16, cc), "arg8");
        assert_eq!(promoted("x29", 24, cc), "arg9");
    }

    #[test]
    fn frame_locals_and_return_address_slots_are_unaffected() {
        let cc = Some(CallConv::SysVAmd64);
        // Negative frame offsets are the function's own locals.
        assert_eq!(promoted("rbp", -0xc, cc), "local_c");
        // Below the first stacked-argument slot ([rbp+8] is the return address).
        assert_eq!(promoted("rbp", 8, cc), "stack_0");
    }

    #[test]
    fn an_abi_we_do_not_model_keeps_the_conservative_name() {
        // Win64 (32-byte shadow space) and ARM32 have different layouts and no
        // fixture coverage here. Guessing at an ABI would invent a parameter that
        // does not exist, so those keep `stack_N`.
        assert_eq!(promoted("rbp", 16, Some(CallConv::Win64)), "stack_0");
        assert_eq!(promoted("rbp", 16, Some(CallConv::Arm)), "stack_0");
        assert_eq!(promoted("rbp", 16, None), "stack_0");
    }

    #[test]
    fn a_misaligned_positive_offset_is_not_an_argument_slot() {
        // Stacked arguments are 8-aligned from the first slot; anything else is not
        // an argument (it could be a field of a by-value struct).
        assert_eq!(promoted("rbp", 20, Some(CallConv::SysVAmd64)), "stack_0");
    }

    #[test]
    fn load_of_stack_slot_becomes_named_local() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src: deref_of("rsp", 0x158, 8),
            }],
        };
        promote_stack_locals(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("stack_0")));
        }
    }

    #[test]
    fn store_to_stack_slot_becomes_named_local_on_lhs() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Store {
                addr: lea("rsp", 0x10),
                src: Expr::Reg(reg("rax")),
                size: 8,
            }],
        };
        promote_stack_locals(&mut f);
        if let Stmt::Store { addr, src, .. } = &f.body[0] {
            assert_eq!(*addr, Expr::Reg(reg("stack_0")));
            assert_eq!(*src, Expr::Reg(reg("rax")));
        }
    }

    #[test]
    fn same_slot_reused_gets_same_name() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rsp", 0x10),
                    src: Expr::Const(1),
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rsp", 0x10, 8),
                },
            ],
        };
        promote_stack_locals(&mut f);
        let names: Vec<_> = f
            .body
            .iter()
            .filter_map(|s| match s {
                Stmt::Store { addr, .. } => Some(addr.clone()),
                Stmt::Assign { src, .. } => Some(src.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(names[0], Expr::Reg(reg("stack_0")));
        assert_eq!(names[1], Expr::Reg(reg("stack_0")));
    }

    #[test]
    fn different_slots_get_distinct_names() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rsp", 0x10),
                    src: Expr::Const(1),
                    size: 8,
                },
                Stmt::Store {
                    addr: lea("rsp", 0x18),
                    src: Expr::Const(2),
                    size: 8,
                },
            ],
        };
        promote_stack_locals(&mut f);
        let addrs: Vec<_> = f
            .body
            .iter()
            .filter_map(|s| match s {
                Stmt::Store { addr, .. } => Some(addr.clone()),
                _ => None,
            })
            .collect();
        assert_ne!(addrs[0], addrs[1]);
    }

    #[test]
    fn frame_pointer_negative_offsets_get_local_prefix() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src: deref_of("rbp", -0x8, 4),
            }],
        };
        promote_stack_locals(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            // Named by frame offset (Ghidra/IDA convention): `[rbp-0x8]` -> `local_8`.
            assert_eq!(*src, Expr::Reg(reg("local_8")));
        }
    }

    #[test]
    fn same_slot_read_and_write_share_one_local_name() {
        // A store to and a load from the same frame slot must resolve to a
        // single local (its def/use chain stays intact), even though the store
        // path can't see the access width.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rbp", -0xc),
                    src: Expr::Const(0),
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rbp", -0xc, 4),
                },
            ],
        };
        promote_stack_locals(&mut f);
        let store_name = match &f.body[0] {
            Stmt::Store { addr, .. } => addr.clone(),
            _ => panic!("expected store"),
        };
        let load_name = match &f.body[1] {
            Stmt::Assign { src, .. } => src.clone(),
            _ => panic!("expected assign"),
        };
        assert_eq!(store_name, Expr::Reg(reg("local_c")));
        assert_eq!(load_name, Expr::Reg(reg("local_c")));
    }

    #[test]
    fn stack_top_zero_offset_gets_special_name() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src: deref_of("rsp", 0, 8),
            }],
        };
        promote_stack_locals(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("stack_top")));
        }
    }

    #[test]
    fn non_stack_base_is_unchanged() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src: deref_of("rdi", 8, 8),
            }],
        };
        let orig = f.clone();
        promote_stack_locals(&mut f);
        assert_eq!(f, orig, "rdi-based deref must not be promoted");
    }

    #[test]
    fn stack_pointer_update_is_not_touched() {
        // `%rsp = %rsp - 8;` must stay — it's a stack-pointer adjustment,
        // not a slot access.
        use crate::ir::types::BinOp;
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rsp"),
                src: Expr::Bin {
                    op: BinOp::Sub,
                    lhs: Box::new(Expr::Reg(reg("rsp"))),
                    rhs: Box::new(Expr::Const(8)),
                },
            }],
        };
        let orig = f.clone();
        promote_stack_locals(&mut f);
        assert_eq!(f, orig);
    }
}
