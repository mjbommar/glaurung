//! x86-64 prologue / epilogue pattern recognition.
//!
//! Mirror of [`crate::ir::arm64_prologue`] for x86-64. Recognises the
//! canonical GCC/Clang rbp-framed prologue:
//!
//! ```text
//!   push rbp
//!   mov  rbp, rsp
//!   sub  rsp, N         (optional — absent in leaf functions)
//! ```
//!
//! …which after our pipeline lowers to:
//!
//! ```text
//!   push %rbp;
//!   %rbp = %rsp;
//!   %rsp = (%rsp - N);      (optional)
//! ```
//!
//! and collapses it to `// x86-64 prologue: save rbp[, frame N bytes]`.
//! The mirror epilogue (from a `leave; ret;` sequence our lifter
//! decomposes into `rsp = rbp; pop rbp; return;`) collapses into
//! `// x86-64 epilogue: restore rbp` followed by `return;`.
//!
//! Functions compiled with `-fomit-frame-pointer` (the default at -O2)
//! skip the rbp dance and are handled by the pre-existing
//! [`crate::ir::stack_idiom`] pass that turns `push`/`rsp` pairs into
//! `push %X;` and drops the trailing `rsp += N; return;`.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::{BinOp, VReg};

/// Run the pass over `f`'s body.
pub fn recognise_x86_prologue(f: &mut Function) {
    collapse_prologue(&mut f.body);
    collapse_epilogue(&mut f.body);
}

fn is_rbp(v: &VReg) -> bool {
    matches!(v, VReg::Phys(n) if n == "rbp" || n == "ebp")
}

fn is_rsp(v: &VReg) -> bool {
    matches!(v, VReg::Phys(n) if n == "rsp" || n == "esp")
}

fn is_promoted_stack_slot(v: &VReg) -> bool {
    matches!(v, VReg::Phys(name) if name == "stack_top" || name.starts_with("stack_"))
}

fn rsp_sub_width(stmt: &Stmt) -> Option<i64> {
    let Stmt::Assign {
        dst,
        src: Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        },
    } = stmt
    else {
        return None;
    };
    if !is_rsp(dst) || !matches!(lhs.as_ref(), Expr::Reg(reg) if reg == dst) {
        return None;
    }
    match rhs.as_ref() {
        Expr::Const(width) if *width > 0 => Some(*width),
        _ => None,
    }
}

fn collapse_prologue(body: &mut Vec<Stmt>) {
    // Skip leading nops (the lifter emits them for ENDBR64).
    let mut i = 0usize;
    while i < body.len() && matches!(&body[i], Stmt::Nop) {
        i += 1;
    }
    if body.len() - i < 2 {
        return;
    }

    // Step 1: `push %rbp;`. Stack-slot normalisation may preserve the lifter's
    // two-statement form (`rsp -= 8; stack_0 = rbp`) instead of rematerialising
    // `Stmt::Push`; accept it only when the decrement exactly equals the store
    // width and is immediately followed by the canonical frame-pointer setup.
    let set_fp_idx = if matches!(&body[i], Stmt::Push { value: Expr::Reg(v) } if is_rbp(v)) {
        i + 1
    } else if body.len() - i >= 3 {
        match (&body[i + 1], rsp_sub_width(&body[i])) {
            (
                Stmt::Store {
                    addr: Expr::Reg(slot),
                    src: Expr::Reg(value),
                    size,
                },
                Some(width),
            ) if is_promoted_stack_slot(slot) && is_rbp(value) && width == i64::from(*size) => {
                i + 2
            }
            _ => return,
        }
    } else {
        return;
    };
    // Step 2: `%rbp = %rsp;`
    if !matches!(
        &body[set_fp_idx],
        Stmt::Assign { dst, src: Expr::Reg(s) } if is_rbp(dst) && is_rsp(s)
    ) {
        return;
    }
    // Step 3 (optional): `%rsp = (%rsp - N);` or `%rsp = (%rsp + -N);`
    let mut end = set_fp_idx + 1;
    let mut frame_size: Option<i64> = None;
    if end < body.len() {
        if let Stmt::Assign {
            dst,
            src: Expr::Bin { op, lhs, rhs },
        } = &body[end]
        {
            if is_rsp(dst)
                && matches!(lhs.as_ref(), Expr::Reg(r) if r == dst)
                && matches!(rhs.as_ref(), Expr::Const(_))
            {
                if let Expr::Const(n) = rhs.as_ref() {
                    let delta = match op {
                        BinOp::Sub if *n > 0 => Some(*n),
                        BinOp::Add if *n < 0 => Some(-*n),
                        _ => None,
                    };
                    if let Some(d) = delta {
                        frame_size = Some(d);
                        end += 1;
                    }
                }
            }
        }
    }

    let comment = match frame_size {
        Some(n) => format!("x86-64 prologue: save rbp, frame {} bytes", n),
        None => "x86-64 prologue: save rbp".to_string(),
    };
    body.drain(i..end);
    body.insert(i, Stmt::Comment(comment));
}

fn collapse_epilogue(body: &mut Vec<Stmt>) {
    // Returns can remain inside recovered branches/loops. Collapse those
    // lexical epilogues before handling this statement list itself.
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collapse_epilogue(then_body);
                if let Some(else_body) = else_body {
                    collapse_epilogue(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                collapse_epilogue(body);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    collapse_epilogue(case_body);
                }
                if let Some(default_body) = default {
                    collapse_epilogue(default_body);
                }
            }
            _ => {}
        }
    }

    // For every Return, check if the preceding stmts are `rsp = rbp; pop rbp`.
    let return_positions: Vec<usize> = body
        .iter()
        .enumerate()
        .filter(|(_, s)| matches!(s, Stmt::Return { .. }))
        .map(|(i, _)| i)
        .collect();
    for ret_idx in return_positions.into_iter().rev() {
        let mut ret_idx = ret_idx;
        // Pattern A (from `leave`): `rsp = rbp; pop rbp; return;`
        if ret_idx >= 2
            && matches!(&body[ret_idx - 1], Stmt::Pop { target: t } if is_rbp(t))
            && matches!(
                &body[ret_idx - 2],
                Stmt::Assign { dst, src: Expr::Reg(s) } if is_rsp(dst) && is_rbp(s)
            )
        {
            body.drain(ret_idx - 2..ret_idx);
            ret_idx -= 2;
            body.insert(
                ret_idx,
                Stmt::Comment("x86-64 epilogue: restore rbp".to_string()),
            );
            continue;
        }
        // Pattern B: `pop rbp; return;` (no leave, just pop), optionally
        // preceded by a `%rsp = (%rsp + N);` teardown.
        if ret_idx >= 1 && matches!(&body[ret_idx - 1], Stmt::Pop { target: t } if is_rbp(t)) {
            body.remove(ret_idx - 1);
            ret_idx -= 1;
            // Pattern B': `%rsp += N;` immediately before the pop — fold it
            // into the same epilogue collapse.
            if ret_idx > 0 && is_rsp_add(&body[ret_idx - 1]) {
                body.remove(ret_idx - 1);
                ret_idx -= 1;
            }
            body.insert(
                ret_idx,
                Stmt::Comment("x86-64 epilogue: restore rbp".to_string()),
            );
            continue;
        }
        // Pattern B in the pre-rematerialised stack-slot form:
        // `rbp = stack_N; return`, optionally after the frame teardown.
        if ret_idx >= 1
            && matches!(
                &body[ret_idx - 1],
                Stmt::Assign { dst, src: Expr::Reg(slot) }
                    if is_rbp(dst) && is_promoted_stack_slot(slot)
            )
        {
            body.remove(ret_idx - 1);
            ret_idx -= 1;
            if ret_idx > 0 && is_rsp_add(&body[ret_idx - 1]) {
                body.remove(ret_idx - 1);
                ret_idx -= 1;
            }
            body.insert(
                ret_idx,
                Stmt::Comment("x86-64 epilogue: restore rbp".to_string()),
            );
            continue;
        }
        // Pattern C: `%rsp += N; return;` with no rbp restore at all.
        // This is common for -fomit-frame-pointer code where the only
        // epilogue work is tearing down the allocated frame.
        if ret_idx >= 1 && is_rsp_add(&body[ret_idx - 1]) {
            body.remove(ret_idx - 1);
            ret_idx -= 1;
            body.insert(
                ret_idx,
                Stmt::Comment("x86-64 epilogue: tear down frame".to_string()),
            );
        }
    }
}

fn is_rsp_add(s: &Stmt) -> bool {
    matches!(
        s,
        Stmt::Assign {
            dst,
            src: Expr::Bin { op: BinOp::Add, lhs, rhs },
        } if is_rsp(dst)
            && matches!(lhs.as_ref(), Expr::Reg(r) if r == dst)
            && matches!(rhs.as_ref(), Expr::Const(k) if *k > 0)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Function, Stmt};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }

    fn push_rbp() -> Stmt {
        Stmt::Push {
            value: Expr::Reg(reg("rbp")),
        }
    }
    fn mov_rbp_rsp() -> Stmt {
        Stmt::Assign {
            dst: reg("rbp"),
            src: Expr::Reg(reg("rsp")),
        }
    }
    fn sub_rsp(n: i64) -> Stmt {
        Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op: BinOp::Sub,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(n)),
            },
        }
    }

    #[test]
    fn full_prologue_collapses_with_frame_size() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                push_rbp(),
                mov_rbp_rsp(),
                sub_rsp(0x20),
                Stmt::Return { value: None },
            ],
        };
        recognise_x86_prologue(&mut f);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(s) if s.contains("x86-64 prologue") && s.contains("32")
        ));
        assert!(matches!(&f.body[1], Stmt::Return { .. }));
    }

    #[test]
    fn prologue_without_sub_still_collapses() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![push_rbp(), mov_rbp_rsp(), Stmt::Return { value: None }],
        };
        recognise_x86_prologue(&mut f);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(s) if s.contains("x86-64 prologue") && !s.contains("frame")
        ));
    }

    #[test]
    fn promoted_stack_slot_prologue_and_epilogue_collapse() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                sub_rsp(8),
                Stmt::Store {
                    addr: Expr::Reg(reg("stack_0")),
                    src: Expr::Reg(reg("rbp")),
                    size: 8,
                },
                mov_rbp_rsp(),
                sub_rsp(32),
                rsp_add(32),
                Stmt::Assign {
                    dst: reg("rbp"),
                    src: Expr::Reg(reg("stack_0")),
                },
                Stmt::Return { value: None },
            ],
        };

        recognise_x86_prologue(&mut f);

        assert!(matches!(
            &f.body[0],
            Stmt::Comment(text) if text == "x86-64 prologue: save rbp, frame 32 bytes"
        ));
        assert!(matches!(
            &f.body[1],
            Stmt::Comment(text) if text == "x86-64 epilogue: restore rbp"
        ));
        assert!(matches!(&f.body[2], Stmt::Return { .. }));
    }

    #[test]
    fn promoted_stack_slot_epilogue_collapses_inside_a_branch() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::If {
                cond: Expr::Reg(reg("cond")),
                then_body: vec![
                    Stmt::Assign {
                        dst: reg("rbp"),
                        src: Expr::Reg(reg("stack_0")),
                    },
                    Stmt::Return { value: None },
                ],
                else_body: None,
            }],
        };

        recognise_x86_prologue(&mut f);

        assert!(matches!(
            &f.body[0],
            Stmt::If { then_body, .. }
                if matches!(
                    then_body.as_slice(),
                    [Stmt::Comment(text), Stmt::Return { .. }]
                        if text == "x86-64 epilogue: restore rbp"
                )
        ));
    }

    #[test]
    fn prologue_without_mov_rbp_rsp_is_not_collapsed() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![push_rbp(), sub_rsp(0x20), Stmt::Return { value: None }],
        };
        let orig = f.clone();
        recognise_x86_prologue(&mut f);
        assert_eq!(f, orig);
    }

    #[test]
    fn leave_style_epilogue_collapses() {
        // `rsp = rbp; pop rbp; return;`  — the three ops our `leave` lifter
        // emits.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Reg(reg("rbp")),
                },
                Stmt::Pop { target: reg("rbp") },
                Stmt::Return { value: None },
            ],
        };
        recognise_x86_prologue(&mut f);
        assert_eq!(f.body.len(), 2);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(s) if s.contains("x86-64 epilogue")
        ));
    }

    #[test]
    fn pop_rbp_then_ret_collapses() {
        // Non-leave functions may just `pop rbp; ret`.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Pop { target: reg("rbp") },
                Stmt::Return { value: None },
            ],
        };
        recognise_x86_prologue(&mut f);
        assert_eq!(f.body.len(), 2);
        assert!(matches!(&f.body[0], Stmt::Comment(_)));
    }

    fn rsp_add(n: i64) -> Stmt {
        Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(n)),
            },
        }
    }

    #[test]
    fn pop_rbp_epilogue_also_swallows_preceding_rsp_add() {
        // `%rsp += 0x20; pop %rbp; return;` collapses.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                rsp_add(0x20),
                Stmt::Pop { target: reg("rbp") },
                Stmt::Return { value: None },
            ],
        };
        recognise_x86_prologue(&mut f);
        assert_eq!(f.body.len(), 2);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(s) if s.contains("x86-64 epilogue")
        ));
    }

    #[test]
    fn fomit_frame_pointer_epilogue_collapses() {
        // `%rsp += 8; return;` (no rbp involved) collapses to a teardown comment.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![rsp_add(8), Stmt::Return { value: None }],
        };
        recognise_x86_prologue(&mut f);
        assert_eq!(f.body.len(), 2);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(s) if s.contains("tear down frame")
        ));
    }

    #[test]
    fn nops_before_prologue_are_tolerated() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Nop,
                Stmt::Nop,
                push_rbp(),
                mov_rbp_rsp(),
                Stmt::Return { value: None },
            ],
        };
        recognise_x86_prologue(&mut f);
        // Expect: Nop, Nop, Comment, Return.
        assert!(matches!(
            &f.body[2],
            Stmt::Comment(s) if s.contains("x86-64 prologue")
        ));
    }
}
