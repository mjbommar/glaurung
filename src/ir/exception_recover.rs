//! Recover source-level C++ exception constructs from typed Itanium metadata.
//!
//! The CFG owns LSDA-only landing pads and SSA sees the exceptional edge before
//! this pass runs.  This module performs the final, deliberately narrow lift:
//! an LSDA catch whose typeinfo relocation proves `int`, together with the
//! canonical `__cxa_begin_catch`/`__cxa_end_catch` body, becomes a typed AST
//! `try`/`catch`.  ABI allocation/store/throw sequences become `Stmt::Throw`.

use crate::analysis::exception::{CatchType, ExceptionAction, ExceptionCallSite};
use crate::ir::ast::{CatchClause, Expr, Function, Stmt};
use crate::ir::types::VReg;

/// Preserve landing-pad identity through generic label cleanup without making
/// exception constructs visible to passes that run before final preparation.
pub fn mark_landing_pads(function: &mut Function, sites: &[ExceptionCallSite]) {
    for site in sites {
        let Some(index) = function
            .body
            .iter()
            .position(|stmt| matches!(stmt, Stmt::Label(va) if *va == site.landing_pad))
        else {
            continue;
        };
        function.body.insert(
            index,
            Stmt::Comment(format!("__glaurung_eh_landing_{:x}", site.landing_pad)),
        );
    }
}

/// Recover one top-level typed handler when every structural witness agrees.
pub fn recover_typed_handlers(function: &mut Function, sites: &[ExceptionCallSite]) {
    let Some(site) = sites.iter().find(|site| {
        site.action == ExceptionAction::Catch
            && site.catch_type == Some(CatchType::Int)
            && function.body.iter().any(|stmt| {
                matches!(stmt, Stmt::Label(va) if *va == site.landing_pad)
                    || matches!(stmt, Stmt::Comment(text) if text == &format!(
                        "__glaurung_eh_landing_{:x}",
                        site.landing_pad
                    ))
            })
    }) else {
        return;
    };
    let marker = format!("__glaurung_eh_landing_{:x}", site.landing_pad);
    let Some(landing_index) = function.body.iter().position(|stmt| {
        matches!(stmt, Stmt::Label(va) if *va == site.landing_pad)
            || matches!(stmt, Stmt::Comment(text) if text == &marker)
    }) else {
        return;
    };
    let normal = &function.body[..landing_index];
    let handler = &function.body[landing_index + 1..];
    let Some((return_index, return_value)) =
        normal
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, stmt)| match stmt {
                Stmt::Return { value: Some(value) } => Some((index, value.clone())),
                _ => None,
            })
    else {
        return;
    };
    let Some(begin_index) = handler.iter().position(is_begin_catch) else {
        return;
    };
    let Some(end_index) = handler
        .iter()
        .enumerate()
        .skip(begin_index + 1)
        .find_map(|(index, stmt)| is_end_catch(stmt).then_some(index))
    else {
        return;
    };
    let Some(catch_pointer) = call_destination(&handler[begin_index]) else {
        return;
    };

    let binding = VReg::phys("exception_0");
    let mut catch_body = handler[begin_index + 1..end_index].to_vec();
    let tail_end = handler[end_index + 1..]
        .iter()
        .position(is_unwind_boundary)
        .map_or(handler.len(), |offset| end_index + 1 + offset);
    // A compiler-generated handler commonly assigns the return register and
    // jumps into the normal epilogue.  That exact target label is the boundary:
    // copying from the normal return-register definition would overwrite the
    // handler's value before returning it.
    let shared_epilogue_start =
        handler[end_index + 1..tail_end]
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Goto { target } => normal
                    .iter()
                    .position(|candidate| matches!(candidate, Stmt::Label(va) if va == target)),
                _ => None,
            });
    let return_suffix_start = shared_epilogue_start.unwrap_or_else(|| match &return_value {
        Expr::Reg(return_reg) => normal[..return_index]
            .iter()
            .rposition(
                |statement| matches!(statement, Stmt::Assign { dst, .. } if dst == return_reg),
            )
            .unwrap_or(return_index),
        _ => return_index,
    });
    let return_suffix: Vec<Stmt> = normal[return_suffix_start..=return_index]
        .iter()
        .filter(|stmt| !matches!(stmt, Stmt::Label(_) | Stmt::Goto { .. }))
        .cloned()
        .collect();
    catch_body.extend(
        handler[end_index + 1..tail_end]
            .iter()
            .filter(|stmt| !matches!(stmt, Stmt::Label(_) | Stmt::Goto { .. }))
            .cloned(),
    );
    replace_caught_value(&mut catch_body, &catch_pointer, &binding);
    catch_body.extend(return_suffix);

    function.body = vec![Stmt::TryCatch {
        try_body: normal.to_vec(),
        catches: vec![CatchClause {
            type_name: "int".to_string(),
            binding,
            body: catch_body,
        }],
    }];
    if std::env::var_os("GLAURUNG_DUMP_PASSES").is_some() {
        eprintln!(
            "\n===== after recover_typed_handlers =====\n{}",
            crate::ir::ast::render(function)
        );
    }
}

/// Recover exact Itanium integer throws anywhere in an AST.
pub fn recover_throws(function: &mut Function) {
    recover_throws_in(&mut function.body);
}

/// Retain an `_ZTIi` proof while ordinary preparation folds the ABI sequence.
pub fn mark_int_throws(function: &mut Function) {
    mark_int_throws_in(&mut function.body);
}

const INT_THROW_MARKER: &str = "__glaurung_throw_int";

fn mark_int_throws_in(body: &mut Vec<Stmt>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                mark_int_throws_in(then_body);
                if let Some(else_body) = else_body {
                    mark_int_throws_in(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => mark_int_throws_in(body),
            Stmt::For { body, .. } => mark_int_throws_in(body),
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    mark_int_throws_in(body);
                }
                if let Some(body) = default {
                    mark_int_throws_in(body);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                mark_int_throws_in(try_body);
                for catch in catches {
                    mark_int_throws_in(&mut catch.body);
                }
            }
            _ => {}
        }
    }
    let Some(allocate) = body.iter().position(is_allocate_exception) else {
        return;
    };
    let Some(throw) = body
        .iter()
        .enumerate()
        .skip(allocate + 1)
        .find_map(|(index, stmt)| is_throw_call(stmt).then_some(index))
    else {
        return;
    };
    if body[allocate..=throw]
        .iter()
        .any(statement_mentions_typeinfo_int)
        && !matches!(body.get(allocate.wrapping_sub(1)), Some(Stmt::Comment(text)) if text == INT_THROW_MARKER)
    {
        body.insert(allocate, Stmt::Comment(INT_THROW_MARKER.to_string()));
    }
}

fn recover_throws_in(body: &mut Vec<Stmt>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                recover_throws_in(then_body);
                if let Some(else_body) = else_body {
                    recover_throws_in(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => recover_throws_in(body),
            Stmt::For { body, .. } => recover_throws_in(body),
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    recover_throws_in(body);
                }
                if let Some(body) = default {
                    recover_throws_in(body);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                recover_throws_in(try_body);
                for catch in catches {
                    recover_throws_in(&mut catch.body);
                }
            }
            _ => {}
        }
    }

    let Some(allocate) = body.iter().position(is_allocate_exception) else {
        return;
    };
    let Some(throw) = body
        .iter()
        .enumerate()
        .skip(allocate + 1)
        .find_map(|(index, stmt)| is_throw_call(stmt).then_some(index))
    else {
        return;
    };
    let marker = allocate
        .checked_sub(1)
        .filter(|index| matches!(&body[*index], Stmt::Comment(text) if text == INT_THROW_MARKER));
    if marker.is_none()
        && !body[allocate..=throw]
            .iter()
            .any(|stmt| statement_mentions_typeinfo_int(stmt))
    {
        return;
    }
    let Some(value) = body[allocate..throw].iter().find_map(|stmt| match stmt {
        Stmt::Store { src, size: 4, .. } => Some(src.clone()),
        _ => None,
    }) else {
        return;
    };
    body.splice(
        marker.unwrap_or(allocate)..=throw,
        [Stmt::Throw {
            value: Expr::Cast {
                signed: true,
                width: 4,
                expr: Box::new(value),
            },
        }],
    );
}

fn call_name(statement: &Stmt) -> Option<&str> {
    let Stmt::Call { target, .. } = statement else {
        return None;
    };
    match target {
        Expr::Named { name, .. } | Expr::Unknown(name) => Some(name),
        _ => None,
    }
}

fn call_destination(statement: &Stmt) -> Option<VReg> {
    let Stmt::Call { dst, .. } = statement else {
        return None;
    };
    dst.clone()
}

fn is_begin_catch(statement: &Stmt) -> bool {
    call_name(statement).is_some_and(|name| name.starts_with("__cxa_begin_catch"))
}

fn is_end_catch(statement: &Stmt) -> bool {
    call_name(statement).is_some_and(|name| name.starts_with("__cxa_end_catch"))
}

fn is_allocate_exception(statement: &Stmt) -> bool {
    call_name(statement).is_some_and(|name| name.starts_with("__cxa_allocate_exception"))
}

fn is_throw_call(statement: &Stmt) -> bool {
    call_name(statement).is_some_and(|name| name.starts_with("__cxa_throw"))
}

fn is_unwind_boundary(statement: &Stmt) -> bool {
    matches!(statement, Stmt::Label(_))
        || call_name(statement).is_some_and(|name| name.starts_with("_Unwind_Resume"))
}

fn statement_mentions_typeinfo_int(statement: &Stmt) -> bool {
    fn expression_mentions(expr: &Expr) -> bool {
        match expr {
            Expr::Named { name, .. } | Expr::Unknown(name) => name.starts_with("_ZTIi"),
            Expr::Deref { addr, .. }
            | Expr::Un { src: addr, .. }
            | Expr::Cast { expr: addr, .. } => expression_mentions(addr),
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                expression_mentions(lhs) || expression_mentions(rhs)
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                expression_mentions(cond)
                    || expression_mentions(if_true)
                    || expression_mentions(if_false)
            }
            _ => false,
        }
    }
    match statement {
        Stmt::Assign { src, .. } => expression_mentions(src),
        Stmt::Store { addr, src, .. } => expression_mentions(addr) || expression_mentions(src),
        Stmt::Call { target, args, .. } => {
            expression_mentions(target) || args.iter().any(expression_mentions)
        }
        _ => false,
    }
}

fn replace_caught_value(body: &mut [Stmt], pointer: &VReg, binding: &VReg) {
    let mut aliases = std::collections::HashSet::from([pointer.clone()]);
    loop {
        let before = aliases.len();
        for statement in body.iter() {
            if let Stmt::Assign {
                dst,
                src: Expr::Reg(source),
            } = statement
            {
                if aliases.contains(source) {
                    aliases.insert(dst.clone());
                }
            }
        }
        if aliases.len() == before {
            break;
        }
    }

    fn rewrite(expr: &mut Expr, aliases: &std::collections::HashSet<VReg>, binding: &VReg) {
        let is_catch_deref = matches!(expr, Expr::Deref { addr, size: 4 }
            if matches!(addr.as_ref(), Expr::Reg(reg) if aliases.contains(reg))
                || matches!(addr.as_ref(), Expr::Lea {
                    base: Some(reg),
                    index: None,
                    disp: 0,
                    segment: None,
                    ..
                } if aliases.contains(reg)));
        if is_catch_deref {
            *expr = Expr::Reg(binding.clone());
            return;
        }
        match expr {
            Expr::Deref { addr, .. }
            | Expr::Un { src: addr, .. }
            | Expr::Cast { expr: addr, .. } => rewrite(addr, aliases, binding),
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                rewrite(lhs, aliases, binding);
                rewrite(rhs, aliases, binding);
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                rewrite(cond, aliases, binding);
                rewrite(if_true, aliases, binding);
                rewrite(if_false, aliases, binding);
            }
            _ => {}
        }
    }
    for statement in body {
        match statement {
            Stmt::Assign { src, .. } => rewrite(src, &aliases, binding),
            Stmt::Store { addr, src, .. } => {
                rewrite(addr, &aliases, binding);
                rewrite(src, &aliases, binding);
            }
            Stmt::Call { target, args, .. } => {
                rewrite(target, &aliases, binding);
                for arg in args {
                    rewrite(arg, &aliases, binding);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{recover_throws, recover_typed_handlers};
    use crate::analysis::exception::{CatchType, ExceptionAction, ExceptionCallSite};
    use crate::ir::ast::{Expr, Function, Stmt};
    use crate::ir::types::VReg;

    fn abi_call(name: &str, dst: Option<VReg>) -> Stmt {
        Stmt::Call {
            target: Expr::Named {
                va: 0,
                name: name.to_string(),
            },
            args: Vec::new(),
            dst,
            call_spec: None,
        }
    }

    #[test]
    fn lsda_int_handler_becomes_typed_try_catch() {
        let pointer = VReg::phys("caught_ptr");
        let mut function = Function {
            name: "f".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Const(7),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("ret"))),
                },
                Stmt::Label(0x1030),
                abi_call("__cxa_begin_catch@plt", Some(pointer.clone())),
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Reg(pointer)),
                        size: 4,
                    },
                },
                abi_call("__cxa_end_catch@plt", None),
                Stmt::Goto { target: 0x1010 },
            ],
        };
        let sites = [ExceptionCallSite {
            function_start: 0x1000,
            protected_start: 0x1004,
            protected_end: 0x1010,
            landing_pad: 0x1030,
            action: ExceptionAction::Catch,
            catch_type: Some(CatchType::Int),
            type_info_location: Some(0x4000),
        }];

        recover_typed_handlers(&mut function, &sites);

        let Stmt::TryCatch { catches, .. } = &function.body[0] else {
            panic!("expected typed try/catch")
        };
        assert_eq!(catches[0].type_name, "int");
        assert!(matches!(
            &catches[0].body[0],
            Stmt::Assign { src: Expr::Reg(name), .. } if name == &VReg::phys("exception_0")
        ));
        assert!(matches!(catches[0].body.last(), Some(Stmt::Return { .. })));
    }

    #[test]
    fn typed_handler_reuses_epilogue_without_overwriting_its_return_value() {
        let pointer = VReg::phys("caught_ptr");
        let return_reg = VReg::phys("ret");
        let mut function = Function {
            name: "f".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: return_reg.clone(),
                    src: Expr::Const(7),
                },
                Stmt::Label(0x1010),
                Stmt::Return {
                    value: Some(Expr::Reg(return_reg.clone())),
                },
                Stmt::Label(0x1030),
                abi_call("__cxa_begin_catch@plt", Some(pointer.clone())),
                Stmt::Assign {
                    dst: return_reg,
                    src: Expr::Deref {
                        addr: Box::new(Expr::Reg(pointer)),
                        size: 4,
                    },
                },
                abi_call("__cxa_end_catch@plt", None),
                Stmt::Goto { target: 0x1010 },
            ],
        };
        let sites = [ExceptionCallSite {
            function_start: 0x1000,
            protected_start: 0x1004,
            protected_end: 0x1010,
            landing_pad: 0x1030,
            action: ExceptionAction::Catch,
            catch_type: Some(CatchType::Int),
            type_info_location: Some(0x4000),
        }];

        recover_typed_handlers(&mut function, &sites);

        let Stmt::TryCatch { catches, .. } = &function.body[0] else {
            panic!("expected typed try/catch")
        };
        assert!(matches!(catches[0].body.last(), Some(Stmt::Return { .. })));
        assert!(
            !catches[0]
                .body
                .iter()
                .any(|stmt| matches!(stmt, Stmt::Label(0x1010))),
            "a copied shared epilogue must not duplicate a function-scoped C label"
        );
        assert!(
            !catches[0].body.iter().any(|stmt| matches!(
                stmt,
                Stmt::Assign {
                    src: Expr::Const(7),
                    ..
                }
            )),
            "the normal-path value definition must not overwrite the catch result: {:#?}",
            catches[0].body
        );
    }

    #[test]
    fn typed_handler_tracks_a_direct_copy_of_the_begin_catch_pointer() {
        let pointer = VReg::phys("caught_ptr");
        let alias = VReg::phys("caught_alias");
        let mut function = Function {
            name: "f".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Return {
                    value: Some(Expr::Const(7)),
                },
                Stmt::Label(0x1030),
                abi_call("__cxa_begin_catch@plt", Some(pointer.clone())),
                Stmt::Assign {
                    dst: alias.clone(),
                    src: Expr::Reg(pointer),
                },
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Reg(alias)),
                        size: 4,
                    },
                },
                abi_call("__cxa_end_catch@plt", None),
            ],
        };
        let sites = [ExceptionCallSite {
            function_start: 0x1000,
            protected_start: 0x1004,
            protected_end: 0x1010,
            landing_pad: 0x1030,
            action: ExceptionAction::Catch,
            catch_type: Some(CatchType::Int),
            type_info_location: Some(0x4000),
        }];

        recover_typed_handlers(&mut function, &sites);

        let Stmt::TryCatch { catches, .. } = &function.body[0] else {
            panic!("expected typed try/catch")
        };
        assert!(catches[0].body.iter().any(|stmt| {
            matches!(stmt, Stmt::Assign { src: Expr::Reg(reg), .. }
                if reg == &VReg::phys("exception_0"))
        }));
    }

    #[test]
    fn split_chunk_lsda_int_handler_becomes_typed_try_catch() {
        let pointer = VReg::phys("caught_ptr");
        let mut function = Function {
            name: "f".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Return {
                    value: Some(Expr::Const(7)),
                },
                Stmt::Label(0x0930),
                abi_call("__cxa_begin_catch@plt", Some(pointer.clone())),
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Reg(pointer)),
                        size: 4,
                    },
                },
                abi_call("__cxa_end_catch@plt", None),
            ],
        };
        let sites = [ExceptionCallSite {
            function_start: 0x0900,
            protected_start: 0x0910,
            protected_end: 0x0920,
            landing_pad: 0x0930,
            action: ExceptionAction::Catch,
            catch_type: Some(CatchType::Int),
            type_info_location: Some(0x4000),
        }];

        recover_typed_handlers(&mut function, &sites);

        assert!(
            matches!(function.body.as_slice(), [Stmt::TryCatch { .. }]),
            "a typed LSDA rooted at an owned cold chunk belongs to the outer function: {:#?}",
            function.body
        );
    }

    #[test]
    fn exact_int_abi_sequence_becomes_throw() {
        let mut function = Function {
            name: "f".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![
                    abi_call("__cxa_allocate_exception@plt", Some(VReg::phys("object"))),
                    Stmt::Store {
                        addr: Expr::Reg(VReg::phys("object")),
                        src: Expr::Reg(VReg::phys("arg0")),
                        size: 4,
                    },
                    Stmt::Assign {
                        dst: VReg::phys("type"),
                        src: Expr::Named {
                            va: 0,
                            name: "_ZTIi".to_string(),
                        },
                    },
                    abi_call("__cxa_throw@plt", None),
                ],
                else_body: None,
            }],
        };

        recover_throws(&mut function);

        let Stmt::If { then_body, .. } = &function.body[0] else {
            panic!("expected if")
        };
        assert_eq!(
            then_body,
            &[Stmt::Throw {
                value: Expr::Cast {
                    signed: true,
                    width: 4,
                    expr: Box::new(Expr::Reg(VReg::phys("arg0"))),
                }
            }]
        );
    }
}
