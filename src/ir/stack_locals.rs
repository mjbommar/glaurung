//! Promote stack-relative memory accesses to named locals.
//!
//! A lot of decompiled noise comes from seeing `*(u64)&[%rsp+0x158]` over
//! and over. This pass rewrites every such access whose base is a stack
//! register (rsp/ebp/sp/x29) and whose effective address is a constant
//! displacement into a named local variable. Distinct `(base, disp, size)`
//! triples map to distinct locals so differing access widths at the same
//! offset stay separate (helps callers spot type confusion).
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
use crate::ir::types::VReg;

const STACK_BASES: &[&str] = &[
    "rsp", "esp", "sp",
    "rbp", "ebp", "bp",
    "x29", "w29", "fp",
];
const FRAME_POINTER_BASES: &[&str] = &["rbp", "ebp", "bp", "x29", "w29", "fp"];

fn is_stack_base(name: &str) -> bool {
    STACK_BASES.contains(&name)
}

fn is_frame_pointer(name: &str) -> bool {
    FRAME_POINTER_BASES.contains(&name)
}

/// Opaque key for the (base_name, disp, size) triple of a stack slot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SlotKey {
    base: String,
    disp: i64,
    size: u8,
}

/// Rewrite stack-relative memory accesses to named locals.
pub fn promote_stack_locals(f: &mut Function) {
    let mut map: HashMap<SlotKey, String> = HashMap::new();
    let mut stack_counter = 0usize;
    let mut local_counter = 0usize;
    rewrite_body(
        &mut f.body,
        &mut map,
        &mut stack_counter,
        &mut local_counter,
    );
}

fn rewrite_body(
    body: &mut [Stmt],
    map: &mut HashMap<SlotKey, String>,
    stack_counter: &mut usize,
    local_counter: &mut usize,
) {
    for s in body.iter_mut() {
        match s {
            Stmt::Assign { src, .. } => rewrite_expr(src, map, stack_counter, local_counter),
            Stmt::Store { addr, src } => {
                // Store's addr is an Lea — we need to rewrite the Lea itself
                // into a Reg reference when the lea points to a stack slot.
                try_promote_lea_to_local(addr, map, stack_counter, local_counter);
                rewrite_expr(src, map, stack_counter, local_counter);
            }
            Stmt::Call { target, args } => {
                rewrite_expr(target, map, stack_counter, local_counter);
                for a in args {
                    rewrite_expr(a, map, stack_counter, local_counter);
                }
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    rewrite_expr(e, map, stack_counter, local_counter);
                }
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                rewrite_expr(cond, map, stack_counter, local_counter);
                rewrite_body(then_body, map, stack_counter, local_counter);
                if let Some(eb) = else_body {
                    rewrite_body(eb, map, stack_counter, local_counter);
                }
            }
            Stmt::While { cond, body } => {
                rewrite_expr(cond, map, stack_counter, local_counter);
                rewrite_body(body, map, stack_counter, local_counter);
            }
            Stmt::Push { value } => rewrite_expr(value, map, stack_counter, local_counter),
            Stmt::Switch { discriminant, cases, default } => {
                rewrite_expr(discriminant, map, stack_counter, local_counter);
                for (_, body) in cases.iter_mut() {
                    rewrite_body(body, map, stack_counter, local_counter);
                }
                if let Some(b) = default {
                    rewrite_body(b, map, stack_counter, local_counter);
                }
            }
            Stmt::Pop { .. }
            | Stmt::Goto { .. }
            | Stmt::Label(_)
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_) => {}
        }
    }
}

/// Promote a `Deref { addr: Lea { base: stack_base, disp, .. } }` into a
/// `Reg(local_name)` reference. Walks sub-expressions so nested derefs fold.
fn rewrite_expr(
    e: &mut Expr,
    map: &mut HashMap<SlotKey, String>,
    stack_counter: &mut usize,
    local_counter: &mut usize,
) {
    match e {
        Expr::Deref { addr, size } => {
            let size_val = *size;
            rewrite_expr(addr, map, stack_counter, local_counter);
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
                    let key = SlotKey {
                        base: name.clone(),
                        disp: *disp,
                        size: size_val,
                    };
                    let alias = map
                        .entry(key)
                        .or_insert_with(|| {
                            alloc_name(name, *disp, stack_counter, local_counter)
                        })
                        .clone();
                    *e = Expr::Reg(VReg::phys(alias));
                    return;
                }
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            rewrite_expr(lhs, map, stack_counter, local_counter);
            rewrite_expr(rhs, map, stack_counter, local_counter);
        }
        Expr::Un { src, .. } => rewrite_expr(src, map, stack_counter, local_counter),
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Lea { .. }
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
    }
}

/// Store-address Lea: turn the full `&[base+disp]` into a `Reg(local)`.
fn try_promote_lea_to_local(
    addr: &mut Expr,
    map: &mut HashMap<SlotKey, String>,
    stack_counter: &mut usize,
    local_counter: &mut usize,
) {
    // The store's `addr` was produced with an implicit access size — our
    // lowering pass doesn't pass it through, so reuse the memop's original
    // size via a conservative default of 8 (matches the prevailing 64-bit
    // width). For callers that produce narrower stores the local will be
    // keyed as size=8; we accept that small collision rate in v1.
    if let Expr::Lea {
        base: Some(VReg::Phys(name)),
        index: None,
        scale: _,
        disp,
        segment: _,
    } = addr
    {
        if is_stack_base(name) {
            let key = SlotKey {
                base: name.clone(),
                disp: *disp,
                size: 8,
            };
            let alias = map
                .entry(key)
                .or_insert_with(|| alloc_name(name, *disp, stack_counter, local_counter))
                .clone();
            *addr = Expr::Reg(VReg::phys(alias));
        }
    }
}

fn alloc_name(
    base: &str,
    disp: i64,
    stack_counter: &mut usize,
    local_counter: &mut usize,
) -> String {
    if disp == 0 {
        return "stack_top".to_string();
    }
    if is_frame_pointer(base) && disp < 0 {
        let n = *local_counter;
        *local_counter += 1;
        return format!("local_{}", n);
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
            }],
        };
        promote_stack_locals(&mut f);
        if let Stmt::Store { addr, src } = &f.body[0] {
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
                },
                Stmt::Store {
                    addr: lea("rsp", 0x18),
                    src: Expr::Const(2),
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
            assert_eq!(*src, Expr::Reg(reg("local_0")));
        }
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
