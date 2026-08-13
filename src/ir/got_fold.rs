//! Fold a load through a GOT slot into the address that slot will hold.
//!
//! # The defect this removes
//!
//! A `-fPIC` reference to a global that symbol interposition could rebind goes
//! through the GOT even when the global is defined right here:
//!
//! ```text
//!   mov 0x3fe8(%rip),%rax     ; rax = *(void **)0x3fe8   -- the GOT slot
//!   mov (%rax),%eax           ; eax = vis_public_bias
//! ```
//!
//! The renderer replaces a referenced image address with a portable object so
//! the recompiled function addresses storage that exists in the rebuilt unit —
//! but `.got` is deliberately NOT eligible for that treatment. It holds
//! linkage, not program objects, and standing a zero-filled array in for a
//! relocated pointer is meaningless (see [`crate::ir::static_storage`]). So the
//! slot rendered as `*(long *)(&glaurung_global_3fe8[0])`, which is `*(int *)0`
//! at run time: a deterministic segfault, across every function in fixtures
//! 157, 158 and 160 that reads a public global.
//!
//! # Why folding is exact
//!
//! The slot's value is a LINK-TIME fact whenever the symbol is defined in this
//! same image: `R_*_GLOB_DAT` against a defined symbol resolves to that
//! symbol's `st_value`, `R_*_RELATIVE` to its addend. Both are recorded in the
//! file being decompiled. Reading the fold's result is therefore the same value
//! the machine would read, and it lands on an ordinary `.data`/`.bss` address
//! that the portable-storage machinery already knows how to materialise.
//!
//! Interposition is the one thing this discards, and discarding it is correct
//! for the question being asked. A decompilation describes what THIS image
//! does; the alternative — leaving a null dereference in place — describes
//! nothing at all.
//!
//! Slots whose symbol this image does not define are left alone by
//! [`crate::analysis::elf_got::elf_got_target_map`]: those really are filled by
//! the dynamic linker from another object, and no value in this file predicts
//! them.

use std::collections::HashMap;

use crate::ir::ast::{Expr, Function, Stmt};

/// Rewrite every `*(GOT slot)` in `function` to the address it resolves to.
///
/// `targets` maps a GOT slot address to the in-image address the loader stores
/// there — build it once per image with
/// [`crate::analysis::elf_got::elf_got_target_map`].
pub fn fold_got_pointer_loads(function: &mut Function, targets: &HashMap<u64, u64>) {
    if targets.is_empty() {
        return;
    }
    fold_body(&mut function.body, targets);
}

fn fold_body(body: &mut [Stmt], targets: &HashMap<u64, u64>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::Assign { src, .. } => fold_expr(src, targets),
            Stmt::Store { addr, src, .. } => {
                fold_expr(addr, targets);
                fold_expr(src, targets);
            }
            Stmt::Return { value: Some(value) } => fold_expr(value, targets),
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                fold_expr(cond, targets);
                fold_body(then_body, targets);
                if let Some(else_body) = else_body {
                    fold_body(else_body, targets);
                }
            }
            Stmt::While { cond, body } => {
                fold_expr(cond, targets);
                fold_body(body, targets);
            }
            Stmt::DoWhile { body, cond } => {
                fold_body(body, targets);
                fold_expr(cond, targets);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                fold_body(std::slice::from_mut(init.as_mut()), targets);
                fold_expr(cond, targets);
                fold_body(std::slice::from_mut(step.as_mut()), targets);
                fold_body(body, targets);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                fold_expr(discriminant, targets);
                for (_, case_body) in cases.iter_mut() {
                    fold_body(case_body, targets);
                }
                if let Some(default) = default {
                    fold_body(default, targets);
                }
            }
            Stmt::Call { target, args, .. } => {
                fold_expr(target, targets);
                for argument in args.iter_mut() {
                    fold_expr(argument, targets);
                }
            }
            _ => {}
        }
    }
}

fn fold_expr(expr: &mut Expr, targets: &HashMap<u64, u64>) {
    // The slot itself is pointer-sized. A narrower read of the same address is
    // reading part of a pointer, which is not the value this fold knows.
    if let Expr::Deref { addr, size } = expr {
        if matches!(**addr, Expr::Addr(_) | Expr::Named { .. }) && matches!(size, 4 | 8) {
            let slot = match addr.as_ref() {
                Expr::Addr(address) => Some(*address),
                Expr::Named { va, .. } => Some(*va),
                _ => None,
            };
            if let Some(target) = slot.and_then(|slot| targets.get(&slot)).copied() {
                *expr = Expr::Addr(target);
                return;
            }
        }
    }
    match expr {
        Expr::Deref { addr, .. } => fold_expr(addr, targets),
        Expr::Un { src, .. } => fold_expr(src, targets),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => fold_expr(expr, targets),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            fold_expr(lhs, targets);
            fold_expr(rhs, targets);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            fold_expr(cond, targets);
            fold_expr(if_true, targets);
            fold_expr(if_false, targets);
        }
        Expr::WideArithmetic { args, .. } => {
            for argument in args.iter_mut() {
                fold_expr(argument, targets);
            }
        }
        Expr::FunctionTableEntry { index, .. } => fold_expr(index, targets),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::VReg;

    fn function(body: Vec<Stmt>) -> Function {
        Function {
            name: "probe".into(),
            entry_va: 0x1000,
            body,
        }
    }

    #[test]
    fn a_pointer_load_through_a_resolved_slot_becomes_its_target() {
        // `vis_public_bias`: slot 0x3fe8 is GLOB_DAT against a symbol this
        // image defines at 0x4028, so `*(long *)0x3fe8` IS 0x4028.
        let targets = HashMap::from([(0x3fe8u64, 0x4028u64)]);
        let mut f = function(vec![Stmt::Assign {
            dst: VReg::phys("rax"),
            src: Expr::Deref {
                addr: Box::new(Expr::Addr(0x3fe8)),
                size: 8,
            },
        }]);

        fold_got_pointer_loads(&mut f, &targets);

        assert_eq!(
            f.body,
            vec![Stmt::Assign {
                dst: VReg::phys("rax"),
                src: Expr::Addr(0x4028),
            }]
        );
    }

    #[test]
    fn the_outer_read_of_the_global_survives_the_fold() {
        let targets = HashMap::from([(0x3fe8u64, 0x4028u64)]);
        let mut f = function(vec![Stmt::Assign {
            dst: VReg::phys("eax"),
            src: Expr::Deref {
                addr: Box::new(Expr::Deref {
                    addr: Box::new(Expr::Addr(0x3fe8)),
                    size: 8,
                }),
                size: 4,
            },
        }]);

        fold_got_pointer_loads(&mut f, &targets);

        assert_eq!(
            f.body,
            vec![Stmt::Assign {
                dst: VReg::phys("eax"),
                src: Expr::Deref {
                    addr: Box::new(Expr::Addr(0x4028)),
                    size: 4,
                },
            }]
        );
    }

    #[test]
    fn an_unrelated_address_is_untouched() {
        let targets = HashMap::from([(0x3fe8u64, 0x4028u64)]);
        let original = Stmt::Assign {
            dst: VReg::phys("rax"),
            src: Expr::Deref {
                addr: Box::new(Expr::Addr(0x3ff0)),
                size: 8,
            },
        };
        let mut f = function(vec![original.clone()]);

        fold_got_pointer_loads(&mut f, &targets);

        assert_eq!(f.body, vec![original]);
    }

    #[test]
    fn a_sub_pointer_read_of_the_slot_is_not_folded() {
        // One byte of a relocated pointer is not the pointer, and this fold
        // has nothing to say about it.
        let targets = HashMap::from([(0x3fe8u64, 0x4028u64)]);
        let original = Stmt::Assign {
            dst: VReg::phys("al"),
            src: Expr::Deref {
                addr: Box::new(Expr::Addr(0x3fe8)),
                size: 1,
            },
        };
        let mut f = function(vec![original.clone()]);

        fold_got_pointer_loads(&mut f, &targets);

        assert_eq!(f.body, vec![original]);
    }
}
