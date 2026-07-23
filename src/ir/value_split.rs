//! Split an argument register's post-spill scratch reuse into a distinct local.
//!
//! At `-O0` a function spills each parameter to its frame slot in the prologue
//! (`store [rbp-8], rdi`), and thereafter reads the parameter back from the
//! stack — the raw argument register is dead *as a parameter* and gets reused as
//! a scratch integer. Because naming and typing key on the physical register,
//! every use of that register is named `argN` and given one type, so a pointer
//! parameter reused as a scratch int produces `arg2 = <int>` (an int↔pointer
//! assignment) that modern C rejects, tanking the recompile (byte_match).
//!
//! This pass exploits the spill invariant: once an argument register has been
//! stored to its frame slot, every later occurrence of that register is scratch,
//! not the parameter. So it renames those post-spill occurrences to a fresh
//! `scr_<reg>` name — which is in no argument table, so the naming pass folds it
//! into an ordinary `varN` local with a plain scalar type. The parameter itself
//! (the single pre-spill read that feeds the spill store) keeps the register
//! name and its recovered pointer type. Result: `arg2 = ret` becomes
//! `varK = ret`, with no int↔pointer conflict.
//!
//! Gated on "the register was actually spilled", so register-resident parameters
//! (typical of `-O2`) are left completely untouched — this pass cannot change
//! argument arity (type_match) or statement shape (GED); it only renames a
//! scratch value that was already destined to be a `varN`.

use std::collections::{HashMap, HashSet};

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::types::VReg;

/// The argument-register sub-name groups for `cc`, one inner slice per ABI
/// argument slot (mirrors `naming::arg_slot_tables`).
fn arg_slot_tables(cc: CallConv) -> &'static [&'static [&'static str]] {
    match cc {
        CallConv::SysVAmd64 => &[
            &["rdi", "edi", "di", "dil"],
            &["rsi", "esi", "si", "sil"],
            &["rdx", "edx", "dx", "dl"],
            &["rcx", "ecx", "cx", "cl"],
            &["r8", "r8d", "r8w", "r8b"],
            &["r9", "r9d", "r9w", "r9b"],
        ],
        CallConv::Win64 => &[
            &["rcx", "ecx", "cx", "cl"],
            &["rdx", "edx", "dx", "dl"],
            &["r8", "r8d", "r8w", "r8b"],
            &["r9", "r9d", "r9w", "r9b"],
        ],
        CallConv::Aarch64 => &[
            &["x0", "w0"],
            &["x1", "w1"],
            &["x2", "w2"],
            &["x3", "w3"],
            &["x4", "w4"],
            &["x5", "w5"],
            &["x6", "w6"],
            &["x7", "w7"],
        ],
        CallConv::Arm => &[&["r0"], &["r1"], &["r2"], &["r3"]],
    }
}

struct Splitter {
    /// register sub-name -> argument slot index
    slot_of: HashMap<&'static str, usize>,
    /// slots whose spill store has already been seen (register now scratch)
    spilled: HashSet<usize>,
}

/// Rename an argument register's scratch reuse after it has been spilled.
pub fn split_spilled_arg_reuse(f: &mut Function, cc: CallConv) {
    let mut slot_of = HashMap::new();
    for (i, names) in arg_slot_tables(cc).iter().enumerate() {
        for n in *names {
            slot_of.insert(*n, i);
        }
    }
    let mut sp = Splitter {
        slot_of,
        spilled: HashSet::new(),
    };
    sp.walk_body(&mut f.body);
}

impl Splitter {
    /// Slot index of a register name, if it is an argument register.
    fn slot(&self, name: &str) -> Option<usize> {
        self.slot_of.get(name).copied()
    }

    /// Rename a register occurrence to its scratch alias when its slot has
    /// already been spilled.
    fn rename_reg(&self, v: &mut VReg) {
        if let VReg::Phys(n) = v {
            if let Some(slot) = self.slot(n) {
                if self.spilled.contains(&slot) {
                    *n = format!("scr_{}", n);
                }
            }
        }
    }

    fn rename_expr(&self, e: &mut Expr) {
        match e {
            Expr::Reg(v) => self.rename_reg(v),
            Expr::Const(_)
            | Expr::Addr(_)
            | Expr::Named { .. }
            | Expr::StringLit { .. }
            | Expr::Unknown(_) => {}
            Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
                if let Some(v) = base {
                    self.rename_reg(v);
                }
                if let Some(v) = index {
                    self.rename_reg(v);
                }
            }
            Expr::Deref { addr, .. } => self.rename_expr(addr),
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                self.rename_expr(lhs);
                self.rename_expr(rhs);
            }
            Expr::Un { src, .. } => self.rename_expr(src),
        }
    }

    /// Is `s` the spill store of an argument register that hasn't been spilled
    /// yet — `store <promoted-local> = <argreg>`? Returns the slot to mark.
    fn spill_slot(&self, s: &Stmt) -> Option<usize> {
        if let Stmt::Store {
            addr: Expr::Reg(VReg::Phys(dst)),
            src: Expr::Reg(VReg::Phys(srcname)),
        } = s
        {
            if is_promoted_local(dst) {
                if let Some(slot) = self.slot(srcname) {
                    if !self.spilled.contains(&slot) {
                        return Some(slot);
                    }
                }
            }
        }
        None
    }

    fn walk_body(&mut self, body: &mut [Stmt]) {
        for s in body.iter_mut() {
            // Detect the spill BEFORE renaming this statement, so the parameter
            // read that feeds it is preserved; mark the slot spilled AFTER, so
            // only *subsequent* occurrences are renamed.
            let spill = self.spill_slot(s);

            // Rename the statement's own (non-nested) register occurrences.
            match s {
                Stmt::Assign { dst, src } => {
                    self.rename_reg(dst);
                    self.rename_expr(src);
                }
                Stmt::Store { addr, src } => {
                    self.rename_expr(addr);
                    // For the spill store itself, keep the parameter register.
                    if spill.is_none() {
                        self.rename_expr(src);
                    }
                }
                Stmt::Call { target, args } => {
                    self.rename_expr(target);
                    for a in args.iter_mut() {
                        self.rename_expr(a);
                    }
                }
                Stmt::Return { value } => {
                    if let Some(e) = value {
                        self.rename_expr(e);
                    }
                }
                Stmt::Push { value } => self.rename_expr(value),
                Stmt::Pop { target } => self.rename_reg(target),
                Stmt::If { cond, .. } | Stmt::While { cond, .. } => self.rename_expr(cond),
                Stmt::Switch { discriminant, .. } => self.rename_expr(discriminant),
                Stmt::Goto { .. } | Stmt::Label(_) | Stmt::Nop | Stmt::Unknown(_) | Stmt::Comment(_) => {}
            }

            if let Some(slot) = spill {
                self.spilled.insert(slot);
            }

            // Recurse into nested bodies (they follow in program order).
            match s {
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    self.walk_body(then_body);
                    if let Some(eb) = else_body {
                        self.walk_body(eb);
                    }
                }
                Stmt::While { body, .. } => self.walk_body(body),
                Stmt::Switch { cases, default, .. } => {
                    for (_, b) in cases.iter_mut() {
                        self.walk_body(b);
                    }
                    if let Some(b) = default {
                        self.walk_body(b);
                    }
                }
                _ => {}
            }
        }
    }
}

fn is_promoted_local(name: &str) -> bool {
    name.starts_with("local_") || name.starts_with("stack_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Function, Stmt};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }

    #[test]
    fn spilled_arg_reuse_is_renamed_param_kept() {
        // store local_18 = rdx   (spill the pointer param)
        // rdx = eax              (reuse rdx as scratch -> must become scr_rdx)
        // rcx = rdx              (read scratch -> scr_rdx)
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(reg("local_18")),
                    src: Expr::Reg(reg("rdx")),
                },
                Stmt::Assign {
                    dst: reg("rdx"),
                    src: Expr::Reg(reg("eax")),
                },
                Stmt::Assign {
                    dst: reg("rcx"),
                    src: Expr::Reg(reg("rdx")),
                },
            ],
        };
        split_spilled_arg_reuse(&mut f, CallConv::SysVAmd64);
        // The spill keeps the parameter register.
        assert_eq!(
            f.body[0],
            Stmt::Store {
                addr: Expr::Reg(reg("local_18")),
                src: Expr::Reg(reg("rdx"))
            }
        );
        // The reuse def and its later read are renamed to the scratch alias.
        assert_eq!(
            f.body[1],
            Stmt::Assign {
                dst: reg("scr_rdx"),
                src: Expr::Reg(reg("eax"))
            }
        );
        assert_eq!(
            f.body[2],
            Stmt::Assign {
                dst: reg("rcx"),
                src: Expr::Reg(reg("scr_rdx"))
            }
        );
    }

    #[test]
    fn unspilled_arg_register_is_untouched() {
        // No spill store: rax = rdi ; return rax — rdi stays the parameter.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Reg(reg("rdi")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rax"))),
                },
            ],
        };
        split_spilled_arg_reuse(&mut f, CallConv::SysVAmd64);
        assert_eq!(
            f.body[0],
            Stmt::Assign {
                dst: reg("rax"),
                src: Expr::Reg(reg("rdi"))
            },
            "an unspilled arg register must not be split"
        );
    }
}
