//! AArch64 prologue / epilogue pattern recognition.
//!
//! The canonical Clang/GCC AArch64 prologue pairs a pre-indexed STP of the
//! frame and link registers with a `mov fp, sp` (or equivalent) to
//! establish the frame:
//!
//! ```text
//!   stp  x29, x30, [sp, #-0x30]!   (pre-indexed, writeback)
//!   mov  x29, sp                   (set fp = sp)
//! ```
//!
//! In our AST (after the pre-indexed STP lifter and stack-local naming run),
//! that lowers to:
//!
//! ```text
//!   store %stack_N = %fp;
//!   store %stack_M = %lr;
//!   %sp = (%sp - K);
//!   %fp = %sp;
//! ```
//!
//! This pass recognises that shape, collapses it into a single prologue
//! comment, and deletes the underlying stmts. The mirror epilogue — `ldp
//! x29, x30, [sp], #K; ret` — becomes a simple `return;`.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::{BinOp, VReg};

/// Run the pass over `f`'s body. Nested arms are currently left alone —
/// prologue stmts always sit at the top-level entry to a function.
pub fn recognise_arm64_prologue(f: &mut Function) {
    collapse_prologue(&mut f.body);
    collapse_epilogue(&mut f.body);
}

fn collapse_prologue(body: &mut Vec<Stmt>) {
    // Look for up to the first ~6 statements matching the prologue shape.
    let mut end = 0usize;
    let mut saw_fp_save = false;
    let mut saw_lr_save = false;
    let mut sp_adjust: Option<i64> = None;
    let mut saw_fp_set = false;

    for (i, s) in body.iter().enumerate() {
        match s {
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(slot)),
                src: Expr::Reg(VReg::Phys(reg)),
            } if slot.starts_with("stack_") => {
                if reg == "fp" || reg == "x29" {
                    saw_fp_save = true;
                } else if reg == "lr" || reg == "x30" {
                    saw_lr_save = true;
                }
                end = i + 1;
            }
            // `sp -= N` or `sp += -N` (the lifter sometimes emits Add with
            // a negative constant for the pre-indexed writeback).
            Stmt::Assign {
                dst,
                src: Expr::Bin { op, lhs, rhs },
            } if is_sp(dst)
                && matches!(lhs.as_ref(), Expr::Reg(r) if r == dst)
                && matches!(rhs.as_ref(), Expr::Const(_)) =>
            {
                if let Expr::Const(n) = rhs.as_ref() {
                    let delta = match op {
                        BinOp::Sub if *n > 0 => Some(*n),
                        BinOp::Add if *n < 0 => Some(-*n),
                        _ => None,
                    };
                    if let Some(d) = delta {
                        sp_adjust = Some(d);
                        end = i + 1;
                        continue;
                    }
                }
                break;
            }
            Stmt::Assign {
                dst: VReg::Phys(fp),
                src: Expr::Reg(sp_ref),
            } if (fp == "fp" || fp == "x29") && is_sp(sp_ref) => {
                saw_fp_set = true;
                end = i + 1;
            }
            // Any other op means the prologue run is over.
            _ => break,
        }
    }
    // Fire when the pattern is unambiguous: saved both fp AND lr to stack
    // slots and adjusted sp. The `mov fp, sp` step is optional — it's
    // often DCE'd away when the function doesn't use fp to address locals.
    if saw_fp_save && saw_lr_save && sp_adjust.is_some() {
        let _ = saw_fp_set;
        body.drain(0..end);
        body.insert(
            0,
            Stmt::Comment(format!(
                "aarch64 prologue: save fp/lr, frame {} bytes",
                sp_adjust.unwrap()
            )),
        );
    }
}

fn collapse_epilogue(body: &mut Vec<Stmt>) {
    // Find every Return and, for each, drop the immediately preceding
    // ABI bookkeeping: a `sp += K` adjust and/or a run of `%fp = %stack_*`
    // / `%lr = %stack_*` / `%varN = %stack_*` restore assigns. Back-to-
    // front so earlier indices stay valid as later ones collapse.
    let return_positions: Vec<usize> = body
        .iter()
        .enumerate()
        .filter(|(_, s)| matches!(s, Stmt::Return { .. }))
        .map(|(i, _)| i)
        .collect();
    for ret_idx in return_positions.into_iter().rev() {
        // 1. Drop a single `sp += K` immediately before Return.
        let mut ret_idx = ret_idx;
        if ret_idx > 0
            && matches!(
                &body[ret_idx - 1],
                Stmt::Assign {
                    dst,
                    src: Expr::Bin { op: BinOp::Add, lhs, rhs },
                } if is_sp(dst)
                    && matches!(lhs.as_ref(), Expr::Reg(r) if r == dst)
                    && matches!(rhs.as_ref(), Expr::Const(k) if *k > 0)
            )
        {
            body.remove(ret_idx - 1);
            ret_idx -= 1;
        }
        // 2. Walk back over a contiguous run of stack-restore assigns.
        let mut run_start = ret_idx;
        while run_start > 0
            && matches!(
                &body[run_start - 1],
                Stmt::Assign {
                    dst: VReg::Phys(_),
                    src: Expr::Reg(VReg::Phys(s)),
                } if s.starts_with("stack_")
            )
        {
            run_start -= 1;
        }
        let run = &body[run_start..ret_idx];
        let mut fp_seen = false;
        let mut lr_seen = false;
        for s in run {
            if let Stmt::Assign {
                dst: VReg::Phys(n),
                ..
            } = s
            {
                if n == "fp" || n == "x29" {
                    fp_seen = true;
                } else if n == "lr" || n == "x30" {
                    lr_seen = true;
                }
            }
        }
        if fp_seen && lr_seen && run_start < ret_idx {
            body.drain(run_start..ret_idx);
            body.insert(
                run_start,
                Stmt::Comment("aarch64 epilogue: restore fp/lr".to_string()),
            );
        }
    }
}

fn is_sp(v: &VReg) -> bool {
    matches!(v, VReg::Phys(n) if n == "sp" || n == "rsp" || n == "esp")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Function, Stmt};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }

    fn store(stack_name: &str, value_reg: &str) -> Stmt {
        Stmt::Store {
            addr: Expr::Reg(reg(stack_name)),
            src: Expr::Reg(reg(value_reg)),
        }
    }

    fn sp_sub(n: i64) -> Stmt {
        Stmt::Assign {
            dst: reg("sp"),
            src: Expr::Bin {
                op: BinOp::Sub,
                lhs: Box::new(Expr::Reg(reg("sp"))),
                rhs: Box::new(Expr::Const(n)),
            },
        }
    }

    fn sp_add(n: i64) -> Stmt {
        Stmt::Assign {
            dst: reg("sp"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(reg("sp"))),
                rhs: Box::new(Expr::Const(n)),
            },
        }
    }

    #[test]
    fn prologue_collapses_to_header_comment() {
        let mut f = Function {
            name: "main".into(),
            entry_va: 0,
            body: vec![
                store("stack_0", "fp"),
                store("stack_1", "lr"),
                sp_sub(48),
                Stmt::Assign {
                    dst: reg("fp"),
                    src: Expr::Reg(reg("sp")),
                },
                Stmt::Nop,
                Stmt::Return { value: None },
            ],
        };
        recognise_arm64_prologue(&mut f);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(s) if s.contains("aarch64 prologue") && s.contains("48")
        ));
        // The stmts after the prologue must be preserved.
        assert!(matches!(&f.body[1], Stmt::Nop));
        assert!(matches!(&f.body[2], Stmt::Return { .. }));
    }

    #[test]
    fn prologue_without_fp_set_still_collapses_when_fp_lr_are_saved() {
        // `mov fp, sp` is optional — the fp-save + lr-save + sp-sub triad
        // is distinctive enough on its own.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                store("stack_0", "fp"),
                store("stack_1", "lr"),
                sp_sub(48),
                Stmt::Return { value: None },
            ],
        };
        recognise_arm64_prologue(&mut f);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(s) if s.contains("aarch64 prologue")
        ));
    }

    #[test]
    fn prologue_without_lr_save_is_not_collapsed() {
        // If only fp is saved (no lr), the pattern is too ambiguous.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![store("stack_0", "fp"), sp_sub(48), Stmt::Return { value: None }],
        };
        let orig = f.clone();
        recognise_arm64_prologue(&mut f);
        assert_eq!(f, orig);
    }

    #[test]
    fn epilogue_restore_fp_lr_collapses_to_comment() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("fp"),
                    src: Expr::Reg(reg("stack_0")),
                },
                Stmt::Assign {
                    dst: reg("lr"),
                    src: Expr::Reg(reg("stack_1")),
                },
                Stmt::Return { value: None },
            ],
        };
        recognise_arm64_prologue(&mut f);
        // Expect: Comment, Return.
        assert_eq!(f.body.len(), 2);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(s) if s.contains("epilogue")
        ));
        assert!(matches!(&f.body[1], Stmt::Return { .. }));
    }

    #[test]
    fn epilogue_without_lr_restore_is_not_collapsed() {
        // Only fp restore and return — ambiguous, must not fire.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("fp"),
                    src: Expr::Reg(reg("stack_0")),
                },
                Stmt::Return { value: None },
            ],
        };
        let orig = f.clone();
        recognise_arm64_prologue(&mut f);
        assert_eq!(f, orig);
    }

    #[test]
    fn epilogue_sp_add_before_return_is_dropped() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Nop,
                sp_add(48),
                Stmt::Return { value: None },
            ],
        };
        recognise_arm64_prologue(&mut f);
        // Expected remaining: Nop, Return (sp_add dropped).
        assert_eq!(f.body.len(), 2);
        assert!(matches!(&f.body[0], Stmt::Nop));
        assert!(matches!(&f.body[1], Stmt::Return { .. }));
    }
}
