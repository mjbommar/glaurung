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
    fold_restored_catch_return(&mut catch_body);

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

/// ARM EHABI epilogues may save the computed catch result in the promoted
/// `stack_top` slot, call `__cxa_end_catch`, then restore r0 with a `Pop`.
/// A standalone C rebuild has no machine stack behind that pop, so carry the
/// exact saved expression into the return before the ABI scaffolding is erased.
fn fold_restored_catch_return(body: &mut Vec<Stmt>) {
    let Some((store_index, saved)) =
        body.iter()
            .enumerate()
            .rev()
            .find_map(|(index, stmt)| match stmt {
                Stmt::Store {
                    addr: Expr::Reg(VReg::Phys(name)),
                    src,
                    ..
                } if name == "stack_top" => Some((index, src.clone())),
                _ => None,
            })
    else {
        return;
    };
    let Some((pop_index, target)) =
        body.iter()
            .enumerate()
            .skip(store_index + 1)
            .find_map(|(index, stmt)| match stmt {
                Stmt::Pop { target } => Some((index, target.clone())),
                _ => None,
            })
    else {
        return;
    };
    if !matches!(
        body.get(pop_index + 1),
        Some(Stmt::Return {
            value: Some(Expr::Reg(register))
        }) if register == &target
    ) {
        return;
    }
    body.splice(
        pop_index..=pop_index + 1,
        [Stmt::Return { value: Some(saved) }],
    );
}

/// Recover exact Itanium integer throws anywhere in an AST.
pub fn recover_throws(function: &mut Function) {
    recover_throws_in(&mut function.body);
}

/// Retain an `_ZTIi` proof while ordinary preparation folds the ABI sequence.
pub fn mark_int_throws(function: &mut Function) {
    mark_int_throws_in(&mut function.body, None, &std::collections::HashMap::new());
}

/// Retain an exact integer-RTTI proof reached through an ELF GOT slot.
///
/// AArch64 materialises `_ZTIi` as `adrp page; ldr [page + offset]`.  Ordinary
/// name resolution runs before copy propagation has joined those instructions,
/// while source-level preparation later deletes the now-dead RTTI load.  Track
/// only local constant address definitions here and consult the relocation-
/// backed address map before that proof disappears.
pub fn mark_int_throws_with_address_map(
    function: &mut Function,
    address_names: &std::collections::HashMap<u64, String>,
) {
    mark_int_throws_in(
        &mut function.body,
        Some(address_names),
        &std::collections::HashMap::new(),
    );
}

const INT_THROW_MARKER: &str = "__glaurung_throw_int";

fn mark_int_throws_in(
    body: &mut Vec<Stmt>,
    address_names: Option<&std::collections::HashMap<u64, String>>,
    inherited_addresses: &std::collections::HashMap<VReg, u64>,
) {
    let mut addresses = inherited_addresses.clone();
    for statement in body.iter_mut() {
        match statement {
            Stmt::Assign { dst, src } => {
                if let Some(address) = known_exception_address(src, &addresses) {
                    addresses.insert(dst.clone(), address);
                } else {
                    addresses.remove(dst);
                }
            }
            Stmt::Store {
                addr: Expr::Reg(dst),
                src,
                ..
            } if promoted_exception_local(dst) => {
                if let Some(address) = known_exception_address(src, &addresses) {
                    addresses.insert(dst.clone(), address);
                } else {
                    addresses.remove(dst);
                }
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                mark_int_throws_in(then_body, address_names, &addresses);
                if let Some(else_body) = else_body {
                    mark_int_throws_in(else_body, address_names, &addresses);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                mark_int_throws_in(body, address_names, &addresses)
            }
            Stmt::For { body, .. } => mark_int_throws_in(body, address_names, &addresses),
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    mark_int_throws_in(body, address_names, &addresses);
                }
                if let Some(body) = default {
                    mark_int_throws_in(body, address_names, &addresses);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                mark_int_throws_in(try_body, address_names, &addresses);
                for catch in catches {
                    mark_int_throws_in(&mut catch.body, address_names, &addresses);
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
    if (body[allocate..=throw]
        .iter()
        .any(statement_mentions_typeinfo_int)
        || address_names.is_some_and(|names| {
            statements_reference_named_address(
                &body[..=throw],
                allocate,
                inherited_addresses,
                names,
                "_ZTIi",
            )
        }))
        && !matches!(body.get(allocate.wrapping_sub(1)), Some(Stmt::Comment(text)) if text == INT_THROW_MARKER)
    {
        body.insert(allocate, Stmt::Comment(INT_THROW_MARKER.to_string()));
    }
}

fn known_exception_address(
    expression: &Expr,
    definitions: &std::collections::HashMap<VReg, u64>,
) -> Option<u64> {
    use crate::ir::types::BinOp;

    match expression {
        Expr::Addr(value) => Some(*value),
        Expr::Const(value) => u64::try_from(*value).ok(),
        Expr::Reg(register) => definitions.get(register).copied(),
        Expr::Cast { expr, .. } => known_exception_address(expr, definitions),
        Expr::Bin { op, lhs, rhs } => {
            let lhs = known_exception_address(lhs, definitions)?;
            let rhs = known_exception_address(rhs, definitions)?;
            match op {
                BinOp::Add => lhs.checked_add(rhs),
                BinOp::Sub => lhs.checked_sub(rhs),
                _ => None,
            }
        }
        Expr::Lea {
            base,
            index,
            scale,
            disp,
            segment: None,
            ..
        } => {
            let base = base
                .as_ref()
                .and_then(|register| definitions.get(register).copied())
                .unwrap_or(0);
            let indexed = match index {
                Some(register) => definitions
                    .get(register)
                    .copied()?
                    // ARM adapters use scale zero for an unshifted register
                    // offset; in address arithmetic that means a factor of
                    // one, not that the index vanishes.
                    .checked_mul(u64::from((*scale).max(1)))?,
                None => 0,
            };
            let address = base.checked_add(indexed)?;
            if *disp >= 0 {
                address.checked_add(*disp as u64)
            } else {
                address.checked_sub(disp.unsigned_abs())
            }
        }
        _ => None,
    }
}

fn promoted_exception_local(register: &VReg) -> bool {
    matches!(register, VReg::Phys(name) if name.starts_with("local_") || name.starts_with("stack_"))
}

fn statements_reference_named_address(
    statements: &[Stmt],
    proof_start: usize,
    inherited_addresses: &std::collections::HashMap<VReg, u64>,
    address_names: &std::collections::HashMap<u64, String>,
    expected_name: &str,
) -> bool {
    fn expression_references(
        expression: &Expr,
        definitions: &std::collections::HashMap<VReg, u64>,
        address_names: &std::collections::HashMap<u64, String>,
        expected_name: &str,
    ) -> bool {
        let address = match expression {
            Expr::Deref { addr, .. } => known_exception_address(addr, definitions),
            Expr::Addr(_) | Expr::Const(_) | Expr::Reg(_) | Expr::Bin { .. } | Expr::Lea { .. } => {
                known_exception_address(expression, definitions)
            }
            _ => None,
        };
        address
            .and_then(|address| address_names.get(&address))
            .is_some_and(|name| name.starts_with(expected_name))
    }

    let mut definitions = inherited_addresses.clone();
    for (index, statement) in statements.iter().enumerate() {
        match statement {
            Stmt::Assign { dst, src } => {
                if index >= proof_start
                    && expression_references(src, &definitions, address_names, expected_name)
                {
                    return true;
                }
                if let Some(address) = known_exception_address(src, &definitions) {
                    definitions.insert(dst.clone(), address);
                } else {
                    definitions.remove(dst);
                }
            }
            Stmt::Store {
                addr: Expr::Reg(dst),
                src,
                ..
            } if promoted_exception_local(dst) => {
                if index >= proof_start
                    && expression_references(src, &definitions, address_names, expected_name)
                {
                    return true;
                }
                if let Some(address) = known_exception_address(src, &definitions) {
                    definitions.insert(dst.clone(), address);
                } else {
                    definitions.remove(dst);
                }
            }
            Stmt::Store { addr, src, .. } => {
                if index >= proof_start
                    && (expression_references(addr, &definitions, address_names, expected_name)
                        || expression_references(src, &definitions, address_names, expected_name))
                {
                    return true;
                }
            }
            Stmt::Call { target, args, .. } => {
                if index >= proof_start
                    && (expression_references(target, &definitions, address_names, expected_name)
                        || args.iter().any(|argument| {
                            expression_references(
                                argument,
                                &definitions,
                                address_names,
                                expected_name,
                            )
                        }))
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
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
    let Some(value) = resolved_throw_value(body, allocate, throw) else {
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

/// Resolve the exception-object store through the pure SSA and promoted-stack
/// copies that feed it before removing the Itanium runtime sequence.
///
/// Keeping the final temporary is not sufficient: that temporary is defined
/// between `__cxa_allocate_exception` and `__cxa_throw`, and the whole interval
/// is replaced by `Throw`.  The replacement must therefore carry an expression
/// rooted outside the removed interval (normally the source parameter).
fn resolved_throw_value(body: &[Stmt], allocate: usize, throw: usize) -> Option<Expr> {
    fn promoted_local(register: &VReg) -> bool {
        matches!(register, VReg::Phys(name) if name.starts_with("local_") || name.starts_with("stack_"))
    }

    fn resolve(expression: &Expr, definitions: &std::collections::HashMap<VReg, Expr>) -> Expr {
        fn inner(
            expression: &Expr,
            definitions: &std::collections::HashMap<VReg, Expr>,
            visiting: &mut std::collections::HashSet<VReg>,
        ) -> Expr {
            match expression {
                Expr::Reg(register) if visiting.insert(register.clone()) => {
                    let resolved = definitions.get(register).map_or_else(
                        || expression.clone(),
                        |definition| inner(definition, definitions, visiting),
                    );
                    visiting.remove(register);
                    resolved
                }
                Expr::Cast {
                    signed,
                    width,
                    expr,
                } => Expr::Cast {
                    signed: *signed,
                    width: *width,
                    expr: Box::new(inner(expr, definitions, visiting)),
                },
                _ => expression.clone(),
            }
        }
        inner(
            expression,
            definitions,
            &mut std::collections::HashSet::new(),
        )
    }

    let mut definitions = std::collections::HashMap::new();
    for (index, statement) in body.iter().enumerate().take(throw) {
        match statement {
            Stmt::Assign { dst, src } => {
                definitions.insert(dst.clone(), src.clone());
            }
            Stmt::Store {
                addr: Expr::Reg(dst),
                src,
                ..
            } if promoted_local(dst) => {
                definitions.insert(dst.clone(), src.clone());
            }
            Stmt::Store { src, size: 4, .. } if index >= allocate => {
                return Some(resolve(src, &definitions));
            }
            _ => {}
        }
    }
    None
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
    use super::{mark_int_throws_with_address_map, recover_throws, recover_typed_handlers};
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
    fn arm_ehabi_handler_returns_the_value_saved_across_end_catch() {
        let pointer = VReg::phys("caught_ptr");
        let result = VReg::phys("catch_result");
        let restored = VReg::phys("scr_r0");
        let mut function = Function {
            name: "f".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Return {
                    value: Some(Expr::Const(7)),
                },
                Stmt::Label(0x1030),
                abi_call("__cxa_begin_catch@plt", Some(pointer)),
                Stmt::Assign {
                    dst: result.clone(),
                    src: Expr::Const(9001),
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("stack_top")),
                    src: Expr::Reg(result.clone()),
                    size: 4,
                },
                abi_call("__cxa_end_catch@plt", None),
                Stmt::Pop {
                    target: restored.clone(),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(restored)),
                },
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
        assert!(catches[0].body.iter().any(|statement| matches!(
            statement,
            Stmt::Return {
                value: Some(Expr::Reg(register))
            } if register == &result
        )));
        assert!(!catches[0]
            .body
            .iter()
            .any(|statement| matches!(statement, Stmt::Pop { .. })));
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

    #[test]
    fn aarch64_got_typeinfo_sequence_retains_the_int_throw_proof() {
        let page = VReg::phys("typeinfo_page");
        let offset = VReg::phys("typeinfo_offset");
        let spill = VReg::phys("stack_2");
        let reloaded = VReg::phys("reloaded");
        let widened = VReg::phys("widened");
        let mut function = Function {
            name: "f".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: page.clone(),
                    src: Expr::Const(0x1f000),
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("local_c")),
                    src: Expr::Reg(page.clone()),
                    size: 8,
                },
                Stmt::If {
                    cond: Expr::Const(1),
                    then_body: vec![
                        Stmt::Store {
                            addr: Expr::Reg(spill.clone()),
                            src: Expr::Reg(VReg::phys("arg0")),
                            size: 4,
                        },
                        abi_call("__cxa_allocate_exception@plt", Some(VReg::phys("object"))),
                        Stmt::Assign {
                            dst: reloaded.clone(),
                            src: Expr::Reg(spill),
                        },
                        Stmt::Assign {
                            dst: widened.clone(),
                            src: Expr::Cast {
                                signed: false,
                                width: 8,
                                expr: Box::new(Expr::Reg(reloaded)),
                            },
                        },
                        Stmt::Store {
                            addr: Expr::Reg(VReg::phys("object")),
                            src: Expr::Reg(widened),
                            size: 4,
                        },
                        Stmt::Assign {
                            dst: offset.clone(),
                            src: Expr::Const(0xf98),
                        },
                        Stmt::Assign {
                            dst: VReg::phys("typeinfo"),
                            src: Expr::Deref {
                                addr: Box::new(Expr::Lea {
                                    base: Some(VReg::phys("local_c")),
                                    index: Some(offset),
                                    // ARM represents an unshifted index with zero.
                                    scale: 0,
                                    disp: 0,
                                    segment: None,
                                }),
                                size: 8,
                            },
                        },
                        abi_call("__cxa_throw@plt", None),
                    ],
                    else_body: None,
                },
            ],
        };
        let names = std::collections::HashMap::from([(0x1ff98, "_ZTIi".to_string())]);

        mark_int_throws_with_address_map(&mut function, &names);
        recover_throws(&mut function);
        let prepared = crate::ir::ast::prepare_for_decbench(&function);

        let Some(Stmt::If { then_body, .. }) = prepared
            .body
            .iter()
            .find(|statement| matches!(statement, Stmt::If { .. }))
        else {
            panic!("expected if")
        };
        assert!(
            matches!(
                then_body.last(),
                Some(Stmt::Throw {
                    value: Expr::Cast { expr, .. }
                }) if matches!(expr.as_ref(), Expr::Cast { expr, .. }
                    if expr.as_ref() == &Expr::Reg(VReg::phys("arg0")))
            ),
            "the throw value must survive removal of its SSA chain: {then_body:#?}"
        );
    }
}
