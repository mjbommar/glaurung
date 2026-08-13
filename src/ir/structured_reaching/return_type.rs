//! Conservative return-definition facts over structured AST values.
//!
//! LLIR SSA is the primary value identity. Some late source-level transforms,
//! however, deliberately coalesce those identities into one rendered role.
//! This private side-car answers one narrow question at that boundary without
//! reverting to flow-insensitive "every assignment in the function" scans.
//! Unsupported unstructured control flow fails closed. It deliberately lives
//! under `structured_reaching`; it is not the future CFG/MIR definition service.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::VReg;
use crate::ir::types_recover::{TypeHint, TypeMap};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DefinitionClass {
    Unreachable,
    Undefined,
    Integer(u8),
    NonInteger,
    Conflicting,
}

impl DefinitionClass {
    fn join(self, other: Self) -> Self {
        match (self, other) {
            (DefinitionClass::Unreachable, reachable)
            | (reachable, DefinitionClass::Unreachable) => reachable,
            (DefinitionClass::Integer(left), DefinitionClass::Integer(right)) => {
                DefinitionClass::Integer(left.max(right))
            }
            (left, right) if left == right => left,
            _ => DefinitionClass::Conflicting,
        }
    }
}

#[derive(Debug)]
struct QueryState {
    current: DefinitionClass,
    returns: Vec<DefinitionClass>,
    supported: bool,
}

/// Result of the structured return-definition query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReturnedIntegerFact {
    /// Every definition reaching every observed return is an integer.
    Proven(u8),
    /// Structured control flow was understood, but a non-integer, conflicting,
    /// or missing definition can reach a return.
    Refuted,
    /// An unstructured transfer prevents the query from proving predecessor
    /// sets. This is absence of proof, not evidence for a pointer.
    Unsupported,
}

/// Return the widest proven integer definition of `target` reaching a direct
/// return of that role.
///
/// Earlier killed definitions do not participate. Joins, zero-iteration loops,
/// and missing definitions are conservative and return [`ReturnedIntegerFact::Refuted`].
/// Any goto or indirect transfer returns [`ReturnedIntegerFact::Unsupported`]
/// because structured traversal cannot prove its predecessor set.
pub(crate) fn returned_role_integer_fact(
    function: &Function,
    target: &str,
    types: &TypeMap,
) -> ReturnedIntegerFact {
    let mut state = QueryState {
        current: DefinitionClass::Undefined,
        returns: Vec::new(),
        supported: true,
    };
    state.current = analyze_body(&function.body, target, types, &mut state);
    if !state.supported {
        return ReturnedIntegerFact::Unsupported;
    }
    if state.returns.is_empty() {
        return ReturnedIntegerFact::Refuted;
    }
    match state
        .returns
        .into_iter()
        .try_fold(0, |width, class| match class {
            DefinitionClass::Integer(value_width) => Some(width.max(value_width)),
            DefinitionClass::Unreachable
            | DefinitionClass::Undefined
            | DefinitionClass::NonInteger
            | DefinitionClass::Conflicting => None,
        }) {
        Some(width) => ReturnedIntegerFact::Proven(width),
        None => ReturnedIntegerFact::Refuted,
    }
}

fn analyze_body(
    body: &[Stmt],
    target: &str,
    types: &TypeMap,
    query: &mut QueryState,
) -> DefinitionClass {
    let mut current = query.current;
    for statement in body {
        query.current = current;
        current = analyze_statement(statement, target, types, query);
    }
    current
}

fn analyze_statement(
    statement: &Stmt,
    target: &str,
    types: &TypeMap,
    query: &mut QueryState,
) -> DefinitionClass {
    let incoming = query.current;
    if incoming == DefinitionClass::Unreachable {
        return incoming;
    }
    match statement {
        Stmt::Assign {
            dst: VReg::Phys(name),
            src,
        } if name == target => expression_integer_width(src, types)
            .map(DefinitionClass::Integer)
            .unwrap_or(DefinitionClass::NonInteger),
        Stmt::Call {
            target: Expr::Named { name, .. },
            ..
        } if crate::analysis::call_semantics::is_known_noreturn_symbol(name) => {
            DefinitionClass::Unreachable
        }
        Stmt::Call { dst, .. }
            if target == "ret" || matches!(dst, Some(VReg::Phys(name)) if name == target) =>
        {
            // Calls define the ABI return role even when a later pass records
            // no source-level destination because the result appears unused.
            DefinitionClass::NonInteger
        }
        Stmt::Pop {
            target: VReg::Phys(name),
        } if name == target => DefinitionClass::NonInteger,
        Stmt::Return {
            value: Some(Expr::Reg(VReg::Phys(name))),
        } if name == target => {
            query.returns.push(incoming);
            DefinitionClass::Unreachable
        }
        Stmt::Return { .. } => DefinitionClass::Unreachable,
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            query.current = incoming;
            let then_state = analyze_body(then_body, target, types, query);
            query.current = incoming;
            let else_state = else_body
                .as_deref()
                .map_or(incoming, |body| analyze_body(body, target, types, query));
            then_state.join(else_state)
        }
        Stmt::While { body, .. } => {
            loop_fixed_point(incoming, |head| {
                query.current = head;
                analyze_body(body, target, types, query)
            })
            .0
        }
        Stmt::DoWhile { body, .. } => {
            loop_fixed_point(incoming, |head| {
                query.current = head;
                analyze_body(body, target, types, query)
            })
            .1
        }
        Stmt::For {
            init, step, body, ..
        } => {
            query.current = incoming;
            let initialized = analyze_statement(init, target, types, query);
            loop_fixed_point(initialized, |head| {
                query.current = head;
                let body_state = analyze_body(body, target, types, query);
                query.current = body_state;
                analyze_statement(step, target, types, query)
            })
            .0
        }
        Stmt::Switch { cases, default, .. } => {
            let mut joined = default.as_deref().map_or(incoming, |body| {
                query.current = incoming;
                analyze_body(body, target, types, query)
            });
            for (_, body) in cases {
                query.current = incoming;
                joined = joined.join(analyze_body(body, target, types, query));
            }
            joined
        }
        // Abrupt transfers need explicit normal/exceptional/break exit states.
        // This narrow structured side-car does not model those edges; treating
        // them as lexical fallthrough can prove a stale definition reaches a
        // return. Leave them to the conservative caller fallback instead.
        Stmt::TryCatch { .. }
        | Stmt::Throw { .. }
        | Stmt::Break
        | Stmt::Goto { .. }
        | Stmt::IndirectGoto { .. } => {
            query.supported = false;
            DefinitionClass::Conflicting
        }
        _ => incoming,
    }
}

/// Close a structured loop over its back edge. The state space is a finite
/// join-semilattice, so this monotone iteration reaches a fixed point without
/// an arbitrary pass limit. The returned pair is `(loop_head, body_exit)`:
/// head-tested loops may exit from the former, while `do` loops execute the
/// body at least once and therefore exit from the latter.
fn loop_fixed_point(
    entry: DefinitionClass,
    mut transfer: impl FnMut(DefinitionClass) -> DefinitionClass,
) -> (DefinitionClass, DefinitionClass) {
    let mut head = entry;
    loop {
        let body_exit = transfer(head);
        let next_head = entry.join(body_exit);
        if next_head == head {
            return (head, body_exit);
        }
        head = next_head;
    }
}

fn expression_integer_width(expression: &Expr, types: &TypeMap) -> Option<u8> {
    match expression {
        Expr::Const(value) => Some(if i32::try_from(*value).is_ok() { 4 } else { 8 }),
        Expr::NumericConvert { to, .. } => Some(to.width()),
        Expr::Cast { width, .. }
        | Expr::Select { width, .. }
        | Expr::WideArithmetic { width, .. } => match expression {
            Expr::Select {
                if_true, if_false, ..
            } => {
                expression_integer_width(if_true, types)?;
                expression_integer_width(if_false, types)?;
                Some(*width)
            }
            _ => Some(*width),
        },
        Expr::Cmp { .. } => Some(4),
        Expr::Reg(VReg::Phys(name)) => match types.get(&VReg::phys(name)) {
            Some(TypeHint::Int { width, .. }) => Some(width),
            Some(TypeHint::BoolLike) => Some(4),
            _ => None,
        },
        Expr::Bin { lhs, rhs, .. } => {
            Some(expression_integer_width(lhs, types)?.max(expression_integer_width(rhs, types)?))
        }
        Expr::Un { src, .. } => expression_integer_width(src, types),
        Expr::Call { result_width, .. } => *result_width,
        Expr::Unknown(_)
        | Expr::FloatConst { .. }
        | Expr::Reg(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Deref { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. }
        | Expr::FunctionTableEntry { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function(body: Vec<Stmt>) -> Function {
        Function {
            name: "return_query".to_string(),
            entry_va: 0x1000,
            body,
        }
    }

    fn returned_target() -> Stmt {
        Stmt::Return {
            value: Some(Expr::Reg(VReg::phys("ret"))),
        }
    }

    #[test]
    fn killed_pointer_definition_does_not_poison_integer_return() {
        let body = vec![
            Stmt::Assign {
                dst: VReg::phys("ret"),
                src: Expr::Named {
                    va: 0x28,
                    name: "__stack_chk_guard".to_string(),
                },
            },
            Stmt::Assign {
                dst: VReg::phys("ret"),
                src: Expr::Const(-1),
            },
            returned_target(),
        ];

        assert_eq!(
            returned_role_integer_fact(&function(body), "ret", &TypeMap::default()),
            ReturnedIntegerFact::Proven(4)
        );
    }

    #[test]
    fn branch_with_pointer_reaching_return_fails_closed() {
        let body = vec![
            Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Const(1),
                }],
                else_body: Some(vec![Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Addr(0x4000),
                }]),
            },
            returned_target(),
        ];

        assert_eq!(
            returned_role_integer_fact(&function(body), "ret", &TypeMap::default()),
            ReturnedIntegerFact::Refuted
        );
    }

    #[test]
    fn zero_iteration_loop_with_undefined_entry_fails_closed() {
        let body = vec![
            Stmt::While {
                cond: Expr::Const(1),
                body: vec![Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Const(1),
                }],
            },
            returned_target(),
        ];

        assert_eq!(
            returned_role_integer_fact(&function(body), "ret", &TypeMap::default()),
            ReturnedIntegerFact::Refuted
        );
    }

    #[test]
    fn float_and_pointer_select_definitions_are_not_integer_proofs() {
        for source in [
            Expr::FloatConst {
                bits: 1.0_f64.to_bits(),
                width: 8,
            },
            Expr::Select {
                cond: Box::new(Expr::Const(1)),
                if_true: Box::new(Expr::Addr(0x4000)),
                if_false: Box::new(Expr::Addr(0x5000)),
                width: 8,
            },
        ] {
            let body = vec![
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: source,
                },
                returned_target(),
            ];
            assert_eq!(
                returned_role_integer_fact(&function(body), "ret", &TypeMap::default()),
                ReturnedIntegerFact::Refuted
            );
        }
    }

    #[test]
    fn unstructured_transfer_fails_closed() {
        let body = vec![
            Stmt::Assign {
                dst: VReg::phys("ret"),
                src: Expr::Const(1),
            },
            Stmt::Goto { target: 0x2000 },
            returned_target(),
        ];

        assert_eq!(
            returned_role_integer_fact(&function(body), "ret", &TypeMap::default()),
            ReturnedIntegerFact::Unsupported
        );
    }

    #[test]
    fn abrupt_exception_flow_cannot_prove_the_stale_try_entry_definition() {
        let body = vec![
            Stmt::Assign {
                dst: VReg::phys("ret"),
                src: Expr::Const(1),
            },
            Stmt::TryCatch {
                try_body: vec![
                    Stmt::Assign {
                        dst: VReg::phys("ret"),
                        src: Expr::Addr(0x4000),
                    },
                    Stmt::Throw {
                        value: Expr::Const(7),
                    },
                ],
                catches: vec![crate::ir::ast::CatchClause {
                    type_name: "exception".to_string(),
                    binding: VReg::phys("caught"),
                    body: vec![returned_target()],
                }],
            },
        ];

        assert_eq!(
            returned_role_integer_fact(&function(body), "ret", &TypeMap::default()),
            ReturnedIntegerFact::Unsupported
        );
    }

    #[test]
    fn implicit_call_and_pop_writes_kill_a_stale_integer_definition() {
        for write in [
            Stmt::Call {
                target: Expr::Addr(0x5000),
                args: Vec::new(),
                dst: None,
                call_spec: None,
            },
            Stmt::Pop {
                target: VReg::phys("ret"),
            },
        ] {
            let body = vec![
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Const(1),
                },
                write,
                returned_target(),
            ];

            assert_eq!(
                returned_role_integer_fact(&function(body), "ret", &TypeMap::default()),
                ReturnedIntegerFact::Refuted
            );
        }
    }

    #[test]
    fn known_noreturn_call_does_not_create_a_false_join_exit() {
        let body = vec![
            Stmt::Assign {
                dst: VReg::phys("ret"),
                src: Expr::Const(1),
            },
            Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![Stmt::Call {
                    target: Expr::Named {
                        va: 0x5000,
                        name: "__stack_chk_fail".to_string(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                }],
                else_body: Some(Vec::new()),
            },
            returned_target(),
        ];

        assert_eq!(
            returned_role_integer_fact(&function(body), "ret", &TypeMap::default()),
            ReturnedIntegerFact::Proven(4)
        );
    }

    #[test]
    fn statements_after_a_terminal_return_cannot_supply_a_definition() {
        let body = vec![
            Stmt::Return { value: None },
            Stmt::Assign {
                dst: VReg::phys("ret"),
                src: Expr::Const(1),
            },
            returned_target(),
        ];

        assert_eq!(
            returned_role_integer_fact(&function(body), "ret", &TypeMap::default()),
            ReturnedIntegerFact::Refuted
        );
    }
}
