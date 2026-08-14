//! Split reused argument-register storage into distinct source values.
//!
//! At `-O0` a function spills each parameter to its frame slot in the prologue
//! (`store [rbp-8], rdi`), and thereafter reads the parameter back from the
//! stack — the raw argument register is dead *as a parameter* and gets reused as
//! a scratch integer. Because naming and typing key on the physical register,
//! every use of that register is named `argN` and given one type, so a pointer
//! parameter reused as a scratch int produces `arg2 = <int>` (an int↔pointer
//! assignment) that modern C rejects, tanking the recompile (byte_match).
//!
//! Two independent facts can prove that a later definition starts a new value:
//!
//! * after an argument has been stored to its frame slot, a later definition of
//!   that register is post-spill scratch storage; and
//! * on ABIs where argument slot zero aliases the return register (AAPCS32/64),
//!   a definition of that storage is a result/scratch value, not a redefinition
//!   of the entry parameter.
//!
//! Reads before the definition retain the incoming identity. Proven later
//! occurrences get a fresh `scr_<reg>` name, which the naming pass folds into an
//! ordinary `varN`. State is tracked independently through structured branches;
//! a definition in one arm cannot rename a live-in read in its sibling arm.

use std::collections::{HashMap, HashSet};

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::expression_width::can_carry_bits_above;
use crate::ir::types::{is_promoted_local_name as is_promoted_local, VReg};

/// Whether an assignment proves that a live-in register's storage is reused at
/// a wider width inside the function.
///
/// This is the missing dual-role witness for shapes such as AArch64 `UMULL`:
/// the parameter and final result can both be 32-bit while an intermediate
/// 64-bit product destructively occupies x0. Unknown expression widths remain
/// conservative and do not trigger a split.
pub(crate) fn definition_exceeds_live_in_width(
    function: &Function,
    register: &VReg,
    live_in_width: u8,
) -> bool {
    fn body_has_wider_definition(body: &[Stmt], register: &VReg, live_in_width: u8) -> bool {
        body.iter().any(|statement| match statement {
            Stmt::Assign { dst, src } => {
                dst == register && can_carry_bits_above(src, live_in_width)
            }
            Stmt::Call {
                dst: Some(destination),
                call_spec: Some(call_spec),
                ..
            } if destination == register => matches!(
                crate::ir::call_contracts::call_return_hint(
                    &call_spec.call_prototype.return_type
                ),
                Some(crate::ir::types_recover::TypeHint::Int { width, .. })
                    if width > live_in_width
            ),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                body_has_wider_definition(then_body, register, live_in_width)
                    || else_body.as_deref().is_some_and(|body| {
                        body_has_wider_definition(body, register, live_in_width)
                    })
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                body_has_wider_definition(body, register, live_in_width)
            }
            Stmt::For {
                init, step, body, ..
            } => {
                body_has_wider_definition(std::slice::from_ref(init), register, live_in_width)
                    || body_has_wider_definition(
                        std::slice::from_ref(step),
                        register,
                        live_in_width,
                    )
                    || body_has_wider_definition(body, register, live_in_width)
            }
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter()
                    .any(|(_, body)| body_has_wider_definition(body, register, live_in_width))
                    || default.as_deref().is_some_and(|body| {
                        body_has_wider_definition(body, register, live_in_width)
                    })
            }
            Stmt::TryCatch { try_body, catches } => {
                body_has_wider_definition(try_body, register, live_in_width)
                    || catches.iter().any(|catch| {
                        body_has_wider_definition(&catch.body, register, live_in_width)
                    })
            }
            _ => false,
        })
    }

    body_has_wider_definition(&function.body, register, live_in_width)
}

/// Decide whether arg0/output storage has a proven second lifetime even when
/// the entry parameter was never spilled.
pub(crate) fn should_split_unspilled_dual_role(
    function: &Function,
    cc: CallConv,
    prototype: Option<&crate::ir::types_recover::RecoveredPrototype>,
) -> bool {
    let Some(prototype) = prototype else {
        return false;
    };
    use crate::ir::types_recover::TypeHint;

    if prototype.output_kind() != crate::ir::types_recover::RecoveredOutputKind::Direct {
        return false;
    }
    let Some(parameter) = prototype.parameter(0) else {
        return false;
    };
    let Some(result) = prototype.result() else {
        return false;
    };
    let parameter_uses_output_storage = match &parameter.value.base {
        VReg::Phys(name) => crate::ir::abi::is_return_register(cc, name),
        _ => false,
    };
    let Some(TypeHint::Int {
        width: parameter_width,
        ..
    }) = parameter.hint
    else {
        return false;
    };
    let result_width_differs = matches!(
        result.hint,
        Some(TypeHint::Int { width, .. }) if width != parameter_width
    );
    let body_has_wider_definition =
        definition_exceeds_live_in_width(function, &parameter.value.base, parameter_width);
    parameter_uses_output_storage
        && !result.values.is_empty()
        && (result_width_differs || body_has_wider_definition)
}

struct Splitter {
    /// register sub-name -> argument slot index
    slot_of: HashMap<&'static str, usize>,
    /// Slots where a definition is a new value even without a prior spill.
    split_on_definition: HashSet<usize>,
}

#[derive(Clone, Default)]
struct SplitState {
    /// slots whose spill store has already been seen
    spilled: HashSet<usize>,
    /// slots whose first proven definition has started a scratch lifetime
    scratch: HashSet<usize>,
}

/// Rename later values that reuse an ABI argument's physical storage.
pub fn split_argument_storage_reuse(
    f: &mut Function,
    cc: CallConv,
    split_unspilled_dual_role: bool,
) {
    let mut slot_of = HashMap::new();
    let argument_slots = crate::ir::abi::argument_slots(cc);
    for (i, names) in argument_slots.iter().enumerate() {
        for n in *names {
            slot_of.insert(*n, i);
        }
    }
    let return_aliases = crate::ir::abi::return_registers(cc);
    let split_on_definition = if split_unspilled_dual_role {
        argument_slots
            .iter()
            .enumerate()
            .filter_map(|(slot, names)| {
                names
                    .iter()
                    .any(|name| return_aliases.contains(name))
                    .then_some(slot)
            })
            .collect()
    } else {
        HashSet::new()
    };
    let splitter = Splitter {
        slot_of,
        split_on_definition,
    };
    splitter.walk_body(&mut f.body, &mut SplitState::default());
}

impl Splitter {
    /// Slot index of a register name, if it is an argument register.
    fn slot(&self, name: &str) -> Option<usize> {
        self.slot_of.get(name).copied()
    }

    /// Rename a register occurrence to its scratch alias when its slot has
    /// already been spilled.
    fn rename_reg(&self, v: &mut VReg, state: &SplitState) {
        if let VReg::Phys(n) = v {
            if let Some(slot) = self.slot(n) {
                if state.scratch.contains(&slot) {
                    *n = format!("scr_{}", n);
                }
            }
        }
    }

    fn rename_expr(&self, e: &mut Expr, state: &SplitState) {
        match e {
            Expr::Reg(v) => self.rename_reg(v, state),
            Expr::StackAddr { object, .. } => self.rename_reg(object, state),
            Expr::Const(_)
            | Expr::FloatConst { .. }
            | Expr::Addr(_)
            | Expr::Named { .. }
            | Expr::StringLit { .. }
            | Expr::Unknown(_) => {}
            Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
                if let Some(v) = base {
                    self.rename_reg(v, state);
                }
                if let Some(v) = index {
                    self.rename_reg(v, state);
                }
            }
            Expr::Deref { addr, .. } => self.rename_expr(addr, state),
            Expr::Call { target, args, .. } => {
                self.rename_expr(target, state);
                for argument in args {
                    self.rename_expr(argument, state);
                }
            }
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                self.rename_expr(lhs, state);
                self.rename_expr(rhs, state);
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                self.rename_expr(cond, state);
                self.rename_expr(if_true, state);
                self.rename_expr(if_false, state);
            }
            Expr::Un { src, .. } => self.rename_expr(src, state),
            Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
                self.rename_expr(expr, state)
            }
            Expr::FunctionTableEntry { index, .. } => self.rename_expr(index, state),
            Expr::WideArithmetic { args, .. } => {
                for argument in args {
                    self.rename_expr(argument, state);
                }
            }
        }
    }

    /// Is `s` the spill store of an argument register that hasn't been spilled
    /// yet — `store <promoted-local> = <argreg>`? Returns the slot to mark.
    fn spill_slot(&self, s: &Stmt, state: &SplitState) -> Option<usize> {
        if let Stmt::Store {
            addr: Expr::Reg(VReg::Phys(dst)),
            src: Expr::Reg(VReg::Phys(srcname)),
            ..
        } = s
        {
            if is_promoted_local(dst) {
                if let Some(slot) = self.slot(srcname) {
                    if !state.scratch.contains(&slot) {
                        return Some(slot);
                    }
                }
            }
        }
        None
    }

    /// A write to an already-spilled argument register starts its scratch value.
    /// A consumed call result is a definition too: on AArch64 the call-owned
    /// destination is the same physical `x0` slot as the caller's arg0.
    fn scratch_definition_slot(&self, s: &Stmt, state: &SplitState) -> Option<usize> {
        let name = match s {
            Stmt::Assign {
                dst: VReg::Phys(name),
                ..
            }
            | Stmt::Call {
                dst: Some(VReg::Phys(name)),
                ..
            } => name,
            _ => return None,
        };
        let slot = self.slot(name)?;
        (state.spilled.contains(&slot) || self.split_on_definition.contains(&slot)).then_some(slot)
    }

    fn rename_as_scratch(v: &mut VReg) {
        if let VReg::Phys(name) = v {
            *name = format!("scr_{name}");
        }
    }

    fn definite_intersection(states: &[SplitState]) -> SplitState {
        let Some(first) = states.first() else {
            return SplitState::default();
        };
        let spilled = first
            .spilled
            .iter()
            .copied()
            .filter(|slot| states[1..].iter().all(|state| state.spilled.contains(slot)))
            .collect::<HashSet<_>>();
        let scratch_candidates = states
            .iter()
            .flat_map(|state| state.scratch.iter().copied())
            .collect::<HashSet<_>>();
        let scratch = scratch_candidates
            .into_iter()
            .filter(|slot| {
                states.iter().all(|state| state.scratch.contains(slot))
                    // A definitely spilled parameter is dead in its register;
                    // any later definition begins post-spill storage. Preserve
                    // the historical monotone fact across unstructured gotos,
                    // whose target may live inside a sibling AST arm.
                    || (spilled.contains(slot)
                        && states.iter().any(|state| state.scratch.contains(slot)))
            })
            .collect();
        SplitState { spilled, scratch }
    }

    fn walk_body(&self, body: &mut [Stmt], state: &mut SplitState) {
        for s in body.iter_mut() {
            self.walk_stmt(s, state);
        }
    }

    fn walk_stmt(&self, s: &mut Stmt, state: &mut SplitState) {
        match s {
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                self.rename_expr(cond, state);
                let entry = state.clone();
                let mut then_state = entry.clone();
                self.walk_body(then_body, &mut then_state);
                let mut else_state = entry;
                if let Some(else_body) = else_body {
                    self.walk_body(else_body, &mut else_state);
                }
                *state = Self::definite_intersection(&[then_state, else_state]);
            }
            Stmt::While { cond, body } => {
                self.rename_expr(cond, state);
                let entry = state.clone();
                let mut body_state = entry.clone();
                self.walk_body(body, &mut body_state);
                *state = Self::definite_intersection(&[entry, body_state]);
            }
            Stmt::DoWhile { body, cond } => {
                self.walk_body(body, state);
                self.rename_expr(cond, state);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                self.walk_stmt(init, state);
                self.rename_expr(cond, state);
                let entry = state.clone();
                let mut body_state = entry.clone();
                self.walk_body(body, &mut body_state);
                self.walk_stmt(step, &mut body_state);
                *state = Self::definite_intersection(&[entry, body_state]);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                self.rename_expr(discriminant, state);
                let entry = state.clone();
                let mut exits = Vec::with_capacity(cases.len() + 1);
                for (_, body) in cases {
                    let mut case_state = entry.clone();
                    self.walk_body(body, &mut case_state);
                    exits.push(case_state);
                }
                if let Some(default) = default {
                    let mut default_state = entry;
                    self.walk_body(default, &mut default_state);
                    exits.push(default_state);
                } else {
                    exits.push(entry);
                }
                *state = Self::definite_intersection(&exits);
            }
            Stmt::TryCatch { try_body, catches } => {
                let entry = state.clone();
                let mut exits = Vec::with_capacity(catches.len() + 1);
                let mut try_state = entry.clone();
                self.walk_body(try_body, &mut try_state);
                exits.push(try_state);
                for catch in catches {
                    let mut catch_state = entry.clone();
                    self.walk_body(&mut catch.body, &mut catch_state);
                    exits.push(catch_state);
                }
                *state = Self::definite_intersection(&exits);
            }
            _ => {
                // Detect the spill BEFORE renaming this statement, so the parameter
                // read that feeds it is preserved; mark the slot spilled AFTER, so
                // a later definition can begin the scratch lifetime.
                let spill = self.spill_slot(s, state);
                let scratch_definition = self.scratch_definition_slot(s, state);

                match s {
                    Stmt::Assign { dst, src } => {
                        self.rename_expr(src, state);
                        if scratch_definition.is_some() {
                            Self::rename_as_scratch(dst);
                        } else {
                            self.rename_reg(dst, state);
                        }
                    }
                    Stmt::Store { addr, src, .. } => {
                        self.rename_expr(addr, state);
                        // For the spill store itself, keep the parameter register.
                        if spill.is_none() {
                            self.rename_expr(src, state);
                        }
                    }
                    Stmt::Call {
                        target, args, dst, ..
                    } => {
                        self.rename_expr(target, state);
                        for a in args.iter_mut() {
                            self.rename_expr(a, state);
                        }
                        if let Some(dst) = dst {
                            if scratch_definition.is_some() {
                                Self::rename_as_scratch(dst);
                            } else {
                                self.rename_reg(dst, state);
                            }
                        }
                    }
                    Stmt::Return { value } => {
                        if let Some(e) = value {
                            self.rename_expr(e, state);
                        }
                    }
                    Stmt::Throw { value } | Stmt::Push { value } => self.rename_expr(value, state),
                    Stmt::Pop { target } => self.rename_reg(target, state),
                    Stmt::IndirectGoto { target } => self.rename_expr(target, state),
                    Stmt::Goto { .. }
                    | Stmt::Label(_)
                    | Stmt::Break
                    | Stmt::Nop
                    | Stmt::Unknown(_)
                    | Stmt::Comment(_) => {}
                    Stmt::If { .. }
                    | Stmt::While { .. }
                    | Stmt::DoWhile { .. }
                    | Stmt::For { .. }
                    | Stmt::Switch { .. }
                    | Stmt::TryCatch { .. } => unreachable!("structured statements handled above"),
                }

                if let Some(slot) = spill {
                    state.spilled.insert(slot);
                }
                if let Some(slot) = scratch_definition {
                    state.scratch.insert(slot);
                }
            }
        }
    }
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
                    size: 8,
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
        split_argument_storage_reuse(&mut f, CallConv::SysVAmd64, false);
        // The spill keeps the parameter register.
        assert_eq!(
            f.body[0],
            Stmt::Store {
                addr: Expr::Reg(reg("local_18")),
                src: Expr::Reg(reg("rdx")),
                size: 8,
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
    fn repeated_parameter_spills_remain_the_same_live_in_until_a_definition() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(reg("stack_0")),
                    src: Expr::Reg(reg("rdi")),
                    size: 8,
                },
                Stmt::Store {
                    addr: Expr::Reg(reg("stack_1")),
                    src: Expr::Reg(reg("rdi")),
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Reg(reg("rdi")),
                },
            ],
        };

        split_argument_storage_reuse(&mut f, CallConv::SysVAmd64, false);

        assert_eq!(
            f.body[1],
            Stmt::Store {
                addr: Expr::Reg(reg("stack_1")),
                src: Expr::Reg(reg("rdi")),
                size: 8,
            }
        );
        assert_eq!(
            f.body[2],
            Stmt::Assign {
                dst: reg("rax"),
                src: Expr::Reg(reg("rdi")),
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
        split_argument_storage_reuse(&mut f, CallConv::SysVAmd64, false);
        assert_eq!(
            f.body[0],
            Stmt::Assign {
                dst: reg("rax"),
                src: Expr::Reg(reg("rdi"))
            },
            "an unspilled arg register must not be split"
        );
    }

    #[test]
    fn direct_arm_output_survives_the_arg0_scratch_split() {
        // ARM32 r0 carries both arg0 on entry and the direct result on exit.
        // Once arg0 is spilled, value splitting must rename the later r0 value
        // and the semantic return together; otherwise the result becomes an
        // unreferenced scratch and DecBench C falls back to `return 0`.
        let mut f = Function {
            name: "console_getc".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(reg("local_14")),
                    src: Expr::Reg(reg("r0")),
                    size: 4,
                },
                Stmt::Assign {
                    dst: reg("r3#1"),
                    src: Expr::Reg(reg("local_9")),
                },
                Stmt::Assign {
                    dst: reg("r0"),
                    src: Expr::Reg(reg("r3#1")),
                },
                Stmt::Return { value: None },
            ],
        };

        crate::ir::direct_output::materialize_direct_output(&mut f);
        split_argument_storage_reuse(&mut f, CallConv::Arm, false);

        assert_eq!(
            f.body.last(),
            Some(&Stmt::Return {
                value: Some(Expr::Reg(reg("scr_r0"))),
            }),
            "the same post-spill role split must reach the direct return"
        );
    }

    #[test]
    fn call_result_survives_the_arg0_scratch_split() {
        // AArch64 x0 is both the incoming arg0 and every integer call result.
        // An earlier return-value assignment can start the post-spill scratch
        // lifetime on one structured path before a later path calls a helper.
        // The call definition and its consumer must retain one identity.
        let mut f = Function {
            name: "hash_lookup".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(reg("stack_2")),
                    src: Expr::Reg(reg("x0")),
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("x0"),
                    src: Expr::Const(-1),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "hash_slot".into(),
                    },
                    args: vec![Expr::Const(17), Expr::Const(8)],
                    dst: Some(reg("x0")),
                    call_spec: None,
                },
                Stmt::Store {
                    addr: Expr::Reg(reg("stack_6")),
                    src: Expr::Reg(reg("x0")),
                    size: 4,
                },
            ],
        };

        split_argument_storage_reuse(&mut f, CallConv::Aarch64, false);

        let Stmt::Call { dst, .. } = &f.body[2] else {
            panic!("expected helper call")
        };
        assert_eq!(dst, &Some(reg("scr_x0")));
        assert_eq!(
            f.body[3],
            Stmt::Store {
                addr: Expr::Reg(reg("stack_6")),
                src: Expr::Reg(reg("scr_x0")),
                size: 4,
            },
            "the spilled consumer must read the exact call-result role"
        );
    }

    /// AAPCS64 uses x0 for both the 32-bit entry parameter and the 64-bit
    /// result.  An optimized accumulator can therefore overwrite x0 without
    /// ever spilling arg0.  The result lifetime must not inherit arg0's name
    /// and type merely because both values occupied the same register.
    #[test]
    fn unspilled_aarch64_arg0_reuse_is_split_from_the_wide_result() {
        let mut f = Function {
            name: "factorial_while".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("t0"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::And,
                        lhs: Box::new(Expr::Reg(reg("x0"))),
                        rhs: Box::new(Expr::Const(14)),
                    },
                },
                Stmt::Assign {
                    dst: reg("x1#1"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::And,
                        lhs: Box::new(Expr::Reg(reg("x0"))),
                        rhs: Box::new(Expr::Const(15)),
                    },
                },
                Stmt::Assign {
                    dst: reg("x0#1"),
                    src: Expr::Const(1),
                },
                Stmt::DoWhile {
                    body: vec![
                        Stmt::Assign {
                            dst: reg("x0"),
                            src: Expr::Bin {
                                op: crate::ir::types::BinOp::Mul,
                                lhs: Box::new(Expr::Reg(reg("x0#1"))),
                                rhs: Box::new(Expr::Reg(reg("x1#1"))),
                            },
                        },
                        Stmt::Assign {
                            dst: reg("x0#1"),
                            src: Expr::Reg(reg("x0")),
                        },
                    ],
                    cond: Expr::Const(1),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("x0"))),
                },
            ],
        };

        split_argument_storage_reuse(&mut f, CallConv::Aarch64, true);

        assert_eq!(
            f.body[0],
            Stmt::Assign {
                dst: reg("t0"),
                src: Expr::Bin {
                    op: crate::ir::types::BinOp::And,
                    lhs: Box::new(Expr::Reg(reg("x0"))),
                    rhs: Box::new(Expr::Const(14)),
                },
            },
            "entry reads must retain the parameter identity"
        );
        let Stmt::DoWhile { body, .. } = &f.body[3] else {
            panic!("expected accumulator loop: {:#?}", f.body)
        };
        let Stmt::Assign { dst, .. } = &body[0] else {
            panic!("expected accumulator definition")
        };
        assert_eq!(dst, &reg("scr_x0"));
        assert_eq!(
            body[1],
            Stmt::Assign {
                dst: reg("x0#1"),
                src: Expr::Reg(reg("scr_x0")),
            }
        );
        assert_eq!(
            f.body[4],
            Stmt::Return {
                value: Some(Expr::Reg(reg("scr_x0"))),
            }
        );
    }

    /// `mul_widen(uint32_t, uint32_t)` has a 32-bit final result but computes a
    /// genuine 64-bit product in x0 first. Comparing only parameter and result
    /// prototype widths therefore misses the destructive dual-role lifetime.
    #[test]
    fn wider_intermediate_definition_is_evidence_for_an_unspilled_role_split() {
        let f = Function {
            name: "mul_widen".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("x0"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Mul,
                        lhs: Box::new(Expr::Cast {
                            signed: false,
                            width: 8,
                            expr: Box::new(Expr::Cast {
                                signed: false,
                                width: 4,
                                expr: Box::new(Expr::Reg(reg("x0"))),
                            }),
                        }),
                        rhs: Box::new(Expr::Cast {
                            signed: false,
                            width: 8,
                            expr: Box::new(Expr::Cast {
                                signed: false,
                                width: 4,
                                expr: Box::new(Expr::Reg(reg("x1"))),
                            }),
                        }),
                    },
                },
                Stmt::Assign {
                    dst: reg("x1#1"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Shr,
                        lhs: Box::new(Expr::Reg(reg("x0"))),
                        rhs: Box::new(Expr::Const(32)),
                    },
                },
            ],
        };

        assert!(definition_exceeds_live_in_width(&f, &reg("x0"), 4));

        let wide_call_prototype = crate::ir::call_contracts::CallPrototype {
            return_type: "unsigned long".into(),
            parameter_types: vec!["unsigned int".into(), "unsigned int".into()],
            variadic: false,
            authority: crate::ir::call_contracts::CallPrototypeAuthority::Recovered,
        };
        let wide_call_result = Function {
            name: "call_fold_wide_result".into(),
            entry_va: 0,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "widen_mul".into(),
                },
                args: vec![Expr::Reg(reg("x0")), Expr::Reg(reg("x1"))],
                dst: Some(reg("x0")),
                call_spec: Some(crate::ir::call_contracts::CallSiteSpec {
                    callee_prototype: Some(wide_call_prototype.clone()),
                    call_prototype: wide_call_prototype,
                }),
            }],
        };
        assert!(
            definition_exceeds_live_in_width(&wide_call_result, &reg("x0"), 4),
            "a recovered 64-bit call contract is an explicit wide-definition witness"
        );

        let w_register_canonicalization = Function {
            name: "word_identity".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("x0"),
                src: Expr::Cast {
                    signed: false,
                    width: 8,
                    expr: Box::new(Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Reg(reg("x0#2"))),
                    }),
                },
            }],
        };
        assert!(
            !definition_exceeds_live_in_width(&w_register_canonicalization, &reg("x0"), 4),
            "zero-extension into the architectural X register carries no significant high bits"
        );

        let wide_select = Function {
            name: "clamped_wide_state".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("x0"),
                src: Expr::Select {
                    cond: Box::new(Expr::Cmp {
                        op: crate::ir::types::CmpOp::Sle,
                        lhs: Box::new(Expr::Reg(reg("x0#4"))),
                        rhs: Box::new(Expr::Reg(reg("x6#1"))),
                    }),
                    if_true: Box::new(Expr::Reg(reg("x0#4"))),
                    if_false: Box::new(Expr::Reg(reg("x6#1"))),
                    width: 8,
                },
            }],
        };
        assert!(
            definition_exceeds_live_in_width(&wide_select, &reg("x0"), 4),
            "a proven 64-bit select can carry significant state above the parameter width"
        );

        let ordinary = Function {
            name: "increment".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("x0"),
                src: Expr::Bin {
                    op: crate::ir::types::BinOp::Add,
                    lhs: Box::new(Expr::Reg(reg("x0"))),
                    rhs: Box::new(Expr::Const(1)),
                },
            }],
        };
        assert!(
            !definition_exceeds_live_in_width(&ordinary, &reg("x0"), 4),
            "an untyped same-width parameter update is not proof of a new role"
        );
    }

    /// A definition on one structured path must not rename a live-in read on
    /// its sibling path.  The split tracks reaching state, not source order.
    #[test]
    fn dual_role_split_keeps_sibling_branch_live_in_reads() {
        let mut f = Function {
            name: "conditional_result".into(),
            entry_va: 0,
            body: vec![Stmt::If {
                cond: Expr::Reg(reg("x1")),
                then_body: vec![
                    Stmt::Assign {
                        dst: reg("x0"),
                        src: Expr::Const(7),
                    },
                    Stmt::Return {
                        value: Some(Expr::Reg(reg("x0"))),
                    },
                ],
                else_body: Some(vec![Stmt::Return {
                    value: Some(Expr::Reg(reg("x0"))),
                }]),
            }],
        };

        split_argument_storage_reuse(&mut f, CallConv::Aarch64, true);

        let Stmt::If {
            then_body,
            else_body: Some(else_body),
            ..
        } = &f.body[0]
        else {
            panic!("expected conditional result: {:#?}", f.body)
        };
        assert_eq!(
            then_body[1],
            Stmt::Return {
                value: Some(Expr::Reg(reg("scr_x0"))),
            }
        );
        assert_eq!(
            else_body[0],
            Stmt::Return {
                value: Some(Expr::Reg(reg("x0"))),
            },
            "the sibling path still reads the entry value"
        );
    }

    /// Once a parameter was definitely spilled, a branch-local definition is
    /// post-spill storage on every later path.  A goto may enter the defining
    /// tail from a sibling arm, so requiring structured-arm intersection would
    /// lose the scratch identity at the common return.
    #[test]
    fn post_spill_branch_definition_reaches_an_unstructured_common_return() {
        let mut f = Function {
            name: "nested_switch".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(reg("stack_0")),
                    src: Expr::Reg(reg("x0")),
                    size: 4,
                },
                Stmt::If {
                    cond: Expr::Reg(reg("x1")),
                    then_body: vec![Stmt::Assign {
                        dst: reg("x0"),
                        src: Expr::Const(6000),
                    }],
                    else_body: Some(vec![Stmt::Goto { target: 0x1040 }]),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("x0"))),
                },
            ],
        };

        split_argument_storage_reuse(&mut f, CallConv::Aarch64, false);

        assert_eq!(
            f.body[2],
            Stmt::Return {
                value: Some(Expr::Reg(reg("scr_x0"))),
            }
        );
    }
}
