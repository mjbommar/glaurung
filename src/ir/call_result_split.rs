//! Give consumed ABI call results distinct source-level identities.
//!
//! Machine ABIs deliberately reuse one output register for every scalar call.
//! That storage reuse must not survive into the source AST: two adjacent calls
//! can have unrelated prototypes, and merging their destinations under one
//! role lets the later narrow result truncate the earlier wide one.  This pass
//! versions each attributed call destination, rewrites only uses reached by
//! that exact definition, and intersects the reaching identity at structured
//! joins.
//!
//! Every split call also gets a compatibility copy back to its architectural
//! output register.  Proven uses are rewritten to the fresh value and make the
//! copy dead.  Uses the structured walk cannot prove (notably loop-carried and
//! label-crossing values) retain the old register spelling and therefore keep
//! the pre-pass semantics instead of becoming undefined.

use std::collections::HashMap;

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::types::{BinOp, VReg};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct FlowState {
    /// ABI output storage -> exact call-result value reaching this point.
    results: HashMap<String, VReg>,
    reachable: bool,
}

impl FlowState {
    fn entry() -> Self {
        Self {
            results: HashMap::new(),
            reachable: true,
        }
    }

    fn without_results(&self) -> Self {
        Self {
            results: HashMap::new(),
            reachable: self.reachable,
        }
    }
}

struct Splitter {
    cc: CallConv,
    next_result: usize,
}

/// Version each consumed ABI call result and its proven reaching uses.
pub fn split_call_result_lifetimes(function: &mut Function, cc: CallConv) {
    let mut splitter = Splitter { cc, next_result: 0 };
    splitter.walk_body(&mut function.body, &mut FlowState::entry());
}

impl Splitter {
    /// One logical storage key for all width views of an ABI output register.
    fn result_storage(&self, register: &VReg) -> Option<String> {
        let VReg::Phys(name) = register else {
            return None;
        };
        if crate::ir::abi::wide_integer_return_part(self.cc, name) == Some(1) {
            return Some("wide_integer_result_high".to_string());
        }
        if !crate::ir::abi::is_return_register(self.cc, name) {
            return None;
        }
        let base = crate::ir::abi::ssa_base(name);
        Some(match self.cc {
            CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Cdecl32 => "rax".to_string(),
            CallConv::Aarch64 => "x0".to_string(),
            // AAPCS hard-float has disjoint integer and FP result banks.  Keep
            // their identities distinct; every call still invalidates all of
            // them before installing its attributed destination below.
            CallConv::Arm | CallConv::ArmHardFloat => base.to_string(),
        })
    }

    fn fresh_result(&mut self, original: &VReg) -> VReg {
        let base = match original {
            VReg::Phys(name) => crate::ir::abi::ssa_base(name),
            VReg::Temp(_) | VReg::Flag(_) | VReg::FlagValue { .. } => "ret",
        };
        let result = VReg::phys(format!("{base}#call_lifetime_{}", self.next_result));
        self.next_result += 1;
        result
    }

    fn fresh_high_result(&self, high_register: &str) -> VReg {
        let index = self.next_result.saturating_sub(1);
        VReg::phys(format!("{high_register}#call_lifetime_high_{index}"))
    }

    fn wide_result_pair(
        &self,
        call_spec: Option<&crate::ir::call_contracts::CallSiteSpec>,
    ) -> Option<(&'static str, &'static str)> {
        let width = crate::ir::call_contracts::integer_c_type_width(
            &call_spec?.call_prototype.return_type,
            crate::ir::abi::machine_word_bytes(self.cc),
        )?;
        crate::ir::abi::wide_integer_return_pair(self.cc, width)
    }

    fn rewrite_reg(&self, register: &mut VReg, state: &FlowState) {
        if !state.reachable {
            return;
        }
        let Some(storage) = self.result_storage(register) else {
            return;
        };
        if let Some(result) = state.results.get(&storage) {
            *register = result.clone();
        }
    }

    fn rewrite_expr(&self, expression: &mut Expr, state: &FlowState) {
        match expression {
            Expr::Reg(register) => self.rewrite_reg(register, state),
            Expr::StackAddr { object, .. } => self.rewrite_reg(object, state),
            Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
                if let Some(base) = base {
                    self.rewrite_reg(base, state);
                }
                if let Some(index) = index {
                    self.rewrite_reg(index, state);
                }
            }
            Expr::Deref { addr, .. } => self.rewrite_expr(addr, state),
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                self.rewrite_expr(lhs, state);
                self.rewrite_expr(rhs, state);
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                self.rewrite_expr(cond, state);
                self.rewrite_expr(if_true, state);
                self.rewrite_expr(if_false, state);
            }
            Expr::Un { src, .. } => self.rewrite_expr(src, state),
            Expr::Cast { expr, .. } => self.rewrite_expr(expr, state),
            Expr::FunctionTableEntry { index, .. } => self.rewrite_expr(index, state),
            Expr::WideArithmetic { args, .. } => {
                for argument in args {
                    self.rewrite_expr(argument, state);
                }
            }
            Expr::Const(_)
            | Expr::FloatConst { .. }
            | Expr::Addr(_)
            | Expr::Named { .. }
            | Expr::StringLit { .. }
            | Expr::Unknown(_) => {}
        }
    }

    fn kill_definition(&self, destination: &VReg, state: &mut FlowState) {
        if let Some(storage) = self.result_storage(destination) {
            state.results.remove(&storage);
        }
    }

    fn intersect(states: &[FlowState]) -> FlowState {
        let reachable = states
            .iter()
            .filter(|state| state.reachable)
            .collect::<Vec<_>>();
        let Some(first) = reachable.first() else {
            return FlowState::default();
        };
        let mut results = first.results.clone();
        results.retain(|storage, value| {
            reachable
                .iter()
                .skip(1)
                .all(|state| state.results.get(storage) == Some(value))
        });
        FlowState {
            results,
            reachable: true,
        }
    }

    fn body_contains_break(body: &[Stmt]) -> bool {
        body.iter().any(|statement| match statement {
            Stmt::Break => true,
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                Self::body_contains_break(then_body)
                    || else_body.as_deref().is_some_and(Self::body_contains_break)
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                Self::body_contains_break(body)
            }
            Stmt::For { body, .. } => Self::body_contains_break(body),
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter()
                    .any(|(_, body)| Self::body_contains_break(body))
                    || default.as_deref().is_some_and(Self::body_contains_break)
            }
            Stmt::TryCatch { try_body, catches } => {
                Self::body_contains_break(try_body)
                    || catches
                        .iter()
                        .any(|catch| Self::body_contains_break(&catch.body))
            }
            _ => false,
        })
    }

    /// Transform a vector body, inserting compatibility copies after calls.
    fn walk_body(&mut self, body: &mut Vec<Stmt>, state: &mut FlowState) {
        let mut output = Vec::with_capacity(body.len());
        for mut statement in std::mem::take(body) {
            let compatibility = self.walk_stmt(&mut statement, state);
            output.push(statement);
            output.extend(compatibility);
        }
        *body = output;
    }

    /// Transform a statement. Calls return a compatibility copy for their
    /// enclosing vector body to insert immediately after the call.
    fn walk_stmt(&mut self, statement: &mut Stmt, state: &mut FlowState) -> Vec<Stmt> {
        match statement {
            Stmt::Assign { dst, src } => {
                self.rewrite_expr(src, state);
                self.kill_definition(dst, state);
            }
            Stmt::Store { addr, src, .. } => {
                self.rewrite_expr(addr, state);
                self.rewrite_expr(src, state);
            }
            Stmt::Call {
                target,
                args,
                dst,
                call_spec,
            } => {
                self.rewrite_expr(target, state);
                for argument in args {
                    self.rewrite_expr(argument, state);
                }
                // Every call clobbers every ABI result bank, regardless of
                // whether source-level consumption attributed a destination.
                state.results.clear();
                let Some(original) = dst.clone() else {
                    return Vec::new();
                };
                let Some(storage) = self.result_storage(&original) else {
                    return Vec::new();
                };
                let wide_pair = self.wide_result_pair(call_spec.as_ref());
                let fresh = self.fresh_result(&original);
                *dst = Some(fresh.clone());
                if state.reachable {
                    state.results.insert(storage, fresh.clone());
                }
                let mut compatibility = Vec::with_capacity(if wide_pair.is_some() { 2 } else { 1 });
                if let Some((_, high_register)) = wide_pair.filter(|(low, _)| {
                    crate::ir::abi::ssa_base(match &original {
                        VReg::Phys(name) => name,
                        _ => "",
                    }) == *low
                }) {
                    let high = self.fresh_high_result(high_register);
                    if state.reachable {
                        let high_storage = self
                            .result_storage(&VReg::phys(high_register))
                            .expect("a wide return pair must expose its high storage");
                        state.results.insert(high_storage, high.clone());
                    }
                    compatibility.push(Stmt::Assign {
                        dst: high,
                        src: Expr::Cast {
                            signed: false,
                            width: crate::ir::abi::machine_word_bytes(self.cc),
                            expr: Box::new(Expr::Bin {
                                op: BinOp::Shr,
                                lhs: Box::new(Expr::Reg(fresh.clone())),
                                rhs: Box::new(Expr::Const(
                                    i64::from(crate::ir::abi::machine_word_bytes(self.cc)) * 8,
                                )),
                            }),
                        },
                    });
                }
                compatibility.push(Stmt::Assign {
                    dst: original,
                    src: Expr::Reg(fresh),
                });
                return compatibility;
            }
            Stmt::Return { value } => {
                if let Some(value) = value {
                    self.rewrite_expr(value, state);
                }
                state.reachable = false;
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                self.rewrite_expr(cond, state);
                let entry = state.clone();
                let mut then_state = entry.clone();
                self.walk_body(then_body, &mut then_state);
                let mut else_state = entry;
                if let Some(else_body) = else_body {
                    self.walk_body(else_body, &mut else_state);
                }
                *state = Self::intersect(&[then_state, else_state]);
            }
            Stmt::While { cond, body } => {
                let entry = state.clone();
                let original_body = body.clone();
                let mut candidate_body = original_body.clone();
                let mut candidate_state = entry.clone();
                self.walk_body(&mut candidate_body, &mut candidate_state);
                let preserves_entry = !Self::body_contains_break(&original_body)
                    && (!candidate_state.reachable || candidate_state.results == entry.results);
                if preserves_entry {
                    self.rewrite_expr(cond, &entry);
                    *body = candidate_body;
                    *state = entry;
                } else {
                    let mut inner_state = entry.without_results();
                    *body = original_body;
                    self.walk_body(body, &mut inner_state);
                    state.results.clear();
                }
            }
            Stmt::DoWhile { body, cond } => {
                let entry = state.clone();
                let original_body = body.clone();
                let mut candidate_body = original_body.clone();
                let mut candidate_state = entry.clone();
                self.walk_body(&mut candidate_body, &mut candidate_state);
                let preserves_entry = !Self::body_contains_break(&original_body)
                    && (!candidate_state.reachable || candidate_state.results == entry.results);
                if preserves_entry {
                    self.rewrite_expr(cond, &candidate_state);
                    *body = candidate_body;
                    *state = candidate_state;
                } else {
                    let mut inner_state = entry.without_results();
                    *body = original_body;
                    self.walk_body(body, &mut inner_state);
                    self.rewrite_expr(cond, &inner_state);
                    state.results.clear();
                    state.reachable &= inner_state.reachable;
                }
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                // A Box<Stmt> cannot host the compatibility copy required for
                // a direct call. Leave such rare init/step calls unsplit.
                self.walk_embedded_stmt(init, state);
                let mut loop_state = state.without_results();
                self.rewrite_expr(cond, &loop_state);
                self.walk_body(body, &mut loop_state);
                self.walk_embedded_stmt(step, &mut loop_state);
                state.results.clear();
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                self.rewrite_expr(discriminant, state);
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
                *state = Self::intersect(&exits);
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
                *state = Self::intersect(&exits);
            }
            Stmt::Push { value } | Stmt::Throw { value } => {
                self.rewrite_expr(value, state);
                if matches!(statement, Stmt::Throw { .. }) {
                    state.reachable = false;
                }
            }
            Stmt::Pop { target } => self.kill_definition(target, state),
            Stmt::IndirectGoto { target } => {
                self.rewrite_expr(target, state);
                state.results.clear();
                state.reachable = false;
            }
            Stmt::Goto { .. } => {
                state.results.clear();
                state.reachable = false;
            }
            Stmt::Label(_) => {
                // A label can have predecessors outside the structured walk.
                state.results.clear();
                state.reachable = true;
            }
            Stmt::Break | Stmt::Nop | Stmt::Unknown(_) | Stmt::Comment(_) => {}
        }
        Vec::new()
    }

    fn walk_embedded_stmt(&mut self, statement: &mut Stmt, state: &mut FlowState) {
        if let Stmt::Call { target, args, .. } = statement {
            self.rewrite_expr(target, state);
            for argument in args {
                self.rewrite_expr(argument, state);
            }
            state.results.clear();
            return;
        }
        debug_assert!(self.walk_stmt(statement, state).is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::call_contracts::{CallPrototype, CallPrototypeAuthority, CallSiteSpec};

    fn reg(name: &str) -> VReg {
        VReg::phys(name)
    }

    fn call(name: &str) -> Stmt {
        Stmt::Call {
            target: Expr::Named {
                va: 0,
                name: name.to_string(),
            },
            args: Vec::new(),
            dst: Some(reg("x0")),
            call_spec: None,
        }
    }

    fn wide_call(name: &str, cc: CallConv) -> Stmt {
        let prototype = CallPrototype {
            return_type: "unsigned long long".to_string(),
            parameter_types: Vec::new(),
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        Stmt::Call {
            target: Expr::Named {
                va: 0,
                name: name.to_string(),
            },
            args: Vec::new(),
            dst: Some(reg(crate::ir::abi::return_register(cc))),
            call_spec: Some(CallSiteSpec {
                callee_prototype: Some(prototype.clone()),
                call_prototype: prototype,
            }),
        }
    }

    fn store(slot: &str) -> Stmt {
        Stmt::Store {
            addr: Expr::Reg(reg(slot)),
            src: Expr::Reg(reg("x0")),
            size: 4,
        }
    }

    #[test]
    fn sequential_call_results_get_distinct_reaching_identities() {
        let mut function = Function {
            name: "decode_header".to_string(),
            entry_va: 0,
            body: vec![
                call("validate_header"),
                store("stack_validator"),
                call("read_be16"),
                store("stack_first"),
                call("read_be16"),
                store("stack_second"),
            ],
        };

        split_call_result_lifetimes(&mut function, CallConv::Aarch64);

        let call_results = function
            .body
            .iter()
            .filter_map(|statement| match statement {
                Stmt::Call { dst: Some(dst), .. } => Some(dst.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let stored_results = function
            .body
            .iter()
            .filter_map(|statement| match statement {
                Stmt::Store {
                    src: Expr::Reg(src),
                    ..
                } => Some(src.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(call_results.len(), 3);
        assert_eq!(stored_results, call_results);
        assert_ne!(call_results[0], call_results[1]);
        assert_ne!(call_results[1], call_results[2]);
    }

    #[test]
    fn an_overwrite_stops_the_call_result_from_reaching_a_later_read() {
        let mut function = Function {
            name: "overwrite".to_string(),
            entry_va: 0,
            body: vec![
                call("producer"),
                Stmt::Assign {
                    dst: reg("x0"),
                    src: Expr::Const(7),
                },
                store("stack_after_overwrite"),
            ],
        };

        split_call_result_lifetimes(&mut function, CallConv::Aarch64);

        assert!(function.body.iter().any(|statement| matches!(
            statement,
            Stmt::Store {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "x0"
        )));
    }

    #[test]
    fn ilp32_wide_call_joins_low_and_high_abi_registers_into_one_scalar() {
        for (cc, low, high) in [
            (CallConv::Arm, "r0", "r1"),
            (CallConv::Cdecl32, "rax", "rdx"),
        ] {
            let mut function = Function {
                name: "fold_wide".to_string(),
                entry_va: 0,
                body: vec![
                    wide_call("widen_mul", cc),
                    Stmt::Store {
                        addr: Expr::Reg(reg("low_slot")),
                        src: Expr::Reg(reg(low)),
                        size: 4,
                    },
                    Stmt::Store {
                        addr: Expr::Reg(reg("high_slot")),
                        src: Expr::Reg(reg(high)),
                        size: 4,
                    },
                ],
            };

            split_call_result_lifetimes(&mut function, cc);

            let call_result = function.body.iter().find_map(|statement| match statement {
                Stmt::Call { dst: Some(dst), .. } => Some(dst.clone()),
                _ => None,
            });
            let Some(call_result) = call_result else {
                panic!("wide call lost its scalar destination: {function:#?}");
            };
            let stored = function
                .body
                .iter()
                .filter_map(|statement| match statement {
                    Stmt::Store {
                        src: Expr::Reg(src),
                        ..
                    } => Some(src.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(stored.first(), Some(&call_result), "{function:#?}");
            let high_result = stored.get(1).expect("missing high-half consumer");
            assert_ne!(
                high_result,
                &reg(high),
                "stale pre-call high half: {function:#?}"
            );
            assert!(
                function.body.iter().any(|statement| matches!(
                    statement,
                    Stmt::Assign {
                        dst,
                        src: Expr::Cast {
                            signed: false,
                            width: 4,
                            expr,
                        },
                    } if dst == high_result && matches!(
                        expr.as_ref(),
                        Expr::Bin {
                            op: crate::ir::types::BinOp::Shr,
                            lhs,
                            rhs,
                        } if lhs.as_ref() == &Expr::Reg(call_result.clone())
                            && rhs.as_ref() == &Expr::Const(32)
                    )
                )),
                "wide call did not define its high ABI part from the scalar result: {function:#?}"
            );
        }
    }

    #[test]
    fn a_shared_result_identity_survives_a_structured_join() {
        let mut function = Function {
            name: "branch".to_string(),
            entry_va: 0,
            body: vec![
                call("producer"),
                Stmt::If {
                    cond: Expr::Const(1),
                    then_body: vec![store("stack_then")],
                    else_body: Some(vec![store("stack_else")]),
                },
                store("stack_join"),
            ],
        };

        split_call_result_lifetimes(&mut function, CallConv::Aarch64);

        let result = function.body.iter().find_map(|statement| match statement {
            Stmt::Call { dst: Some(dst), .. } => Some(dst.clone()),
            _ => None,
        });
        let Some(result) = result else {
            panic!("call result was not versioned: {function:#?}");
        };
        let mut stores = Vec::new();
        fn collect(body: &[Stmt], stores: &mut Vec<VReg>) {
            for statement in body {
                match statement {
                    Stmt::Store {
                        src: Expr::Reg(src),
                        ..
                    } => stores.push(src.clone()),
                    Stmt::If {
                        then_body,
                        else_body,
                        ..
                    } => {
                        collect(then_body, stores);
                        if let Some(else_body) = else_body {
                            collect(else_body, stores);
                        }
                    }
                    _ => {}
                }
            }
        }
        collect(&function.body, &mut stores);
        assert_eq!(stores, vec![result.clone(), result.clone(), result]);
    }

    #[test]
    fn an_ambiguous_loop_keeps_the_compatibility_storage() {
        let mut function = Function {
            name: "loop".to_string(),
            entry_va: 0,
            body: vec![
                call("before_loop"),
                Stmt::While {
                    cond: Expr::Reg(reg("x0")),
                    body: vec![store("stack_before_call"), call("inside_loop")],
                },
                store("stack_after_loop"),
            ],
        };

        split_call_result_lifetimes(&mut function, CallConv::Aarch64);

        let Stmt::While { cond, .. } = &function.body[2] else {
            panic!("compatibility copy must immediately follow the call: {function:#?}");
        };
        assert_eq!(cond, &Expr::Reg(reg("x0")));
        assert!(matches!(
            function.body.last(),
            Some(Stmt::Store {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            }) if name == "x0"
        ));
    }
}
