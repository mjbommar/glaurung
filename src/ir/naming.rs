//! Role-based register renaming for the decompiled AST.
//!
//! After the earlier passes (lower → reconstruct → DCE → name-resolve →
//! call-arg → strings-fold) the body of a function still talks in raw
//! machine-register names (`%rax`, `%rdi`, `%x0`). That is faithful but not
//! legible — a human reader has to remember the calling convention to
//! understand which register means "argument 0" and which means "return
//! value". This pass rewrites those physical registers to role-based
//! names within the scope of a single function:
//!
//! * Return-value register → `ret`
//! * Argument-passing register N -> `argN` (rdi/rcx/x0 -> `arg0`,
//!   rsi/rdx/x1 -> `arg1`, ...)
//! * Stack-frame registers (`rsp`, `ebp`, `sp`, `x29`, …) keep their names —
//!   renaming them to `stack` would lose information.
//! * Any other GPR that still appears after earlier folding gets a stable
//!   `varN` alias assigned in first-appearance order.
//!
//! The rename is purely cosmetic — it does not alter the semantics of the
//! AST. `Expr::Reg(VReg::Phys("rdi"))` becomes `Expr::Reg(VReg::Phys("arg0"))`,
//! which the printer then shows as `%arg0`.

use std::collections::HashMap;

use crate::ir::ast::parse_arg_index;
use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::types::VReg;

const STACK_KEEPERS: &[&str] = &[
    "rsp", "esp", "sp", "rbp", "ebp", "bp", "x29", "w29", "fp", "x30", "w30", "lr",
];

/// The register spellings that may carry this convention's result.
///
/// Delegated rather than restated: this was a verbatim second copy of
/// [`crate::ir::abi::return_registers`], and the copies drifted the moment the
/// x86-64 SSE result register was added to one of them — the recovered value
/// landed in an anonymous `varN` and every float-returning function returned
/// zero. Two copies of a fact are two chances to disagree with a third thing.
fn return_reg_aliases(cc: CallConv) -> &'static [&'static str] {
    crate::ir::abi::return_registers(cc)
}

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
        CallConv::Cdecl32 => &[],
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
        CallConv::Arm | CallConv::ArmHardFloat => &[&["r0"], &["r1"], &["r2"], &["r3"]],
    }
}

/// Rename registers in `f` according to the given calling convention.
pub fn apply_role_names(f: &mut Function, cc: CallConv) {
    // Default: recover the live-in parameter slots from the AST body.
    let param_slots = live_in_arg_slots(&f.body, cc);
    apply_role_names_with_params(f, cc, &param_slots);
}

/// As [`apply_role_names`], but with an authoritative live-in parameter-slot set
/// supplied by the caller. The AST-based [`live_in_arg_slots`] is fooled at -O2,
/// where an argument-slot register is reused as scratch through a sub-register
/// `lea` (`lea -0x2(%rsi),%ecx`) and mis-read as a live-in parameter; a set
/// computed on the LLIR (see `value_number::live_in_arg_slots_llir`) is reliable
/// there. Using it prevents a scratch `rdx`/`rcx` from becoming a spurious `argN`
/// and inflating the recovered arity.
pub fn apply_role_names_with_params(
    f: &mut Function,
    cc: CallConv,
    param_slots: &std::collections::HashSet<usize>,
) {
    apply_role_names_with_parameter_roles(f, cc, param_slots, &HashMap::new());
}

/// Apply role names with exact prototype-owned storage bindings in addition to
/// the convention's ordinary integer slot table. This is required for ABIs
/// whose argument storage classes are disjoint (for example ARM hard-float
/// `s0` versus core-register `r0`) and deliberately does not merge those names
/// in the global ABI table.
pub fn apply_role_names_with_parameter_roles(
    f: &mut Function,
    cc: CallConv,
    param_slots: &std::collections::HashSet<usize>,
    parameter_roles: &HashMap<String, usize>,
) -> HashMap<String, String> {
    // Build the role map: raw name → friendly name. We build it up-front so
    // that every substitution is consistent across the function.
    let mut role: HashMap<String, String> = HashMap::new();
    // On AArch64 x0 serves as both arg0 and return value. We prefer `arg0`
    // because in a called function it's more often referenced as the input
    // than as the output slot.
    for (slot_idx, names) in arg_slot_tables(cc).iter().enumerate() {
        if !param_slots.contains(&slot_idx) {
            continue;
        }
        for name in *names {
            role.entry(name.to_string())
                .or_insert_with(|| format!("arg{}", slot_idx));
        }
    }
    for (name, slot) in parameter_roles {
        // Prototype recovery owns the exact source-role binding. In a mixed
        // AAPCS signature r1 may be source arg2 because s0 is source arg1, so
        // the ordinary core-register slot table must not win here.
        role.insert(name.clone(), format!("arg{slot}"));
    }
    // Explicit LLIR returns preserve their exact SSA identity through AST
    // lowering. Project a directly returned *machine result-storage* carrier
    // onto the source-level output role just as we do for an unversioned ABI
    // register below. A returned source local is a value, not evidence that its
    // storage has the ABI output role. Registers nested inside a cast or
    // arithmetic expression are likewise merely inputs to the result.
    // Parameter bindings keep priority for identity functions such as AArch64
    // `return x0`.
    let mut direct_return_carriers = Vec::new();
    collect_direct_return_carriers(&f.body, &mut direct_return_carriers);
    for name in direct_return_carriers {
        if crate::ir::abi::is_return_register(cc, &name) {
            role.entry(name).or_insert_with(|| "ret".to_string());
        }
    }
    // A materialised SSE-pair result has already captured `xmm0:xmm1` into a
    // synthetic object. Those registers and the integer aliases (`eax`, etc.)
    // are now ordinary scratch storage. Renaming every ABI-capable carrier to
    // one `ret` identity corrupts cross-bank computations: GCC's fixture 197
    // computes `eax = seed*2`, clears `xmm0`, then converts EAX into XMM0; the
    // cosmetic collision turned that conversion source into the clear's zero.
    // The exact object name is produced only by the proven SsePair materializer,
    // so scalar/unmaterialised returns retain the longstanding role mapping.
    let materialized_sse_pair = collect_first_appearance_phys(&f.body)
        .iter()
        .any(|name| crate::ir::abi::ssa_base(name) == "sse_pair_return_object");
    if !materialized_sse_pair {
        for name in return_reg_aliases(cc) {
            // `ret` only wins if no arg-slot already claimed the name (x0 case
            // above keeps `arg0`).
            role.entry(name.to_string())
                .or_insert_with(|| "ret".to_string());
        }
    }

    // Assign stable `varN` aliases for other physical registers in order of
    // first appearance. We walk the body in reading order.
    let mut counter = 0usize;
    let mut assign_var = |name: &str, role: &mut HashMap<String, String>| {
        if STACK_KEEPERS.contains(&name) {
            return;
        }
        // Names already allocated by the stack-slot promotion pass
        // (`stack_0`, `local_0`, `stack_top`) are meaningful — don't
        // rewrite them to generic varN.
        if name.starts_with("stack_") || name.starts_with("local_") {
            return;
        }
        // Nor an `argN` the promotion pass recovered for a STACK-passed parameter
        // (`[rbp+16]` upward on SysV). Renaming it to `varN` would turn the
        // function's own seventh argument into an undefined scratch local — the
        // signature would still grow (arity comes from the highest `argN`), so the
        // parameter would be declared and then never read.
        if parse_arg_index(name).is_some() {
            return;
        }
        if role.contains_key(name) {
            return;
        }
        let n = counter;
        counter += 1;
        role.insert(name.to_string(), format!("var{}", n));
    };
    for name in collect_first_appearance_phys(&f.body) {
        assign_var(&name, &mut role);
    }

    rewrite_body(&mut f.body, &role);
    role
}

/// Replace internal promoted-local identities with validated source names at
/// the final presentation boundary.
///
/// Stack promotion and all semantic passes intentionally keep the `local_N`
/// identity because that spelling carries storage-class and frame-offset
/// meaning throughout the IR. Applying debug names only after those passes
/// avoids turning a scalar assignment into a pointer store merely because its
/// source identifier no longer begins with `local_`.
pub fn apply_authoritative_local_names(f: &mut Function, source_names: &HashMap<String, String>) {
    rewrite_body(&mut f.body, source_names);
}

/// Give the two strongest source-level loop roles conventional names when no
/// debug name survived.
///
/// This deliberately recognizes only a promoted local initialized to zero and
/// used as the induction variable of an already-recovered `for`, plus a second
/// zero-initialized promoted local updated by `self + value` in that loop. The
/// structure pass has already proved the loop; this pass changes identities
/// only, and declines when `i` or `sum` is already in use.
pub fn apply_canonical_loop_local_names(f: &mut Function) -> HashMap<String, String> {
    fn is_reg(expr: &Expr, name: &str) -> bool {
        match expr {
            Expr::Reg(VReg::Phys(candidate)) => candidate == name,
            Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => is_reg(expr, name),
            _ => false,
        }
    }

    fn local_assignment(statement: &Stmt) -> Option<(&str, &Expr)> {
        match statement {
            Stmt::Assign {
                dst: VReg::Phys(name),
                src,
            }
            | Stmt::Store {
                addr: Expr::Reg(VReg::Phys(name)),
                src,
                ..
            } if crate::ir::types::is_promoted_local_name(name) => Some((name, src)),
            _ => None,
        }
    }

    fn unit_increment(statement: &Stmt, name: &str) -> bool {
        let Some((dst, Expr::Bin { op, lhs, rhs })) = local_assignment(statement) else {
            return false;
        };
        dst == name
            && *op == crate::ir::types::BinOp::Add
            && ((is_reg(lhs, name) && matches!(rhs.as_ref(), Expr::Const(1)))
                || (is_reg(rhs, name) && matches!(lhs.as_ref(), Expr::Const(1))))
    }

    fn has_additive_update(body: &[Stmt], name: &str) -> bool {
        body.iter().any(|statement| match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                has_additive_update(then_body, name)
                    || else_body
                        .as_deref()
                        .is_some_and(|body| has_additive_update(body, name))
            }
            _ => local_assignment(statement).is_some_and(|(dst, src)| {
                matches!(src, Expr::Bin { op: crate::ir::types::BinOp::Add, lhs, rhs }
                    if dst == name && (is_reg(lhs, name) || is_reg(rhs, name)))
            }),
        })
    }

    let used = collect_first_appearance_phys(&f.body)
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    let mut roles = HashMap::new();
    for (loop_index, statement) in f.body.iter().enumerate() {
        let Stmt::For {
            init, step, body, ..
        } = statement
        else {
            continue;
        };
        let Some((induction, Expr::Const(0))) = local_assignment(init.as_ref()) else {
            continue;
        };
        if !used.contains("i")
            && !roles.values().any(|name| name == "i")
            && unit_increment(step, induction)
        {
            roles.insert(induction.to_string(), "i".to_string());
        }

        if used.contains("sum") || roles.values().any(|name| name == "sum") {
            continue;
        }
        if let Some(accumulator) = f.body[..loop_index].iter().rev().find_map(|candidate| {
            let (name, Expr::Const(0)) = local_assignment(candidate)? else {
                return None;
            };
            (name != induction && has_additive_update(body, name)).then_some(name.to_string())
        }) {
            roles.insert(accumulator, "sum".to_string());
        }
        break;
    }
    rewrite_body(&mut f.body, &roles);
    roles
}

/// Whether a debug-provided local name can safely enter the generated C namespace.
///
/// Source names that collide with C keywords, ABI roles, or identities reserved
/// by earlier decompiler passes are rejected instead of being sanitized into a
/// potentially different variable. Callers remain responsible for enforcing
/// uniqueness within the function.
pub(crate) fn valid_authoritative_local_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && !matches!(
            name,
            "auto"
                | "break"
                | "case"
                | "char"
                | "const"
                | "continue"
                | "default"
                | "do"
                | "double"
                | "else"
                | "enum"
                | "extern"
                | "float"
                | "for"
                | "goto"
                | "if"
                | "inline"
                | "int"
                | "long"
                | "register"
                | "restrict"
                | "return"
                | "short"
                | "signed"
                | "sizeof"
                | "static"
                | "struct"
                | "switch"
                | "typedef"
                | "union"
                | "unsigned"
                | "void"
                | "volatile"
                | "while"
                | "_Bool"
                | "_Complex"
                | "_Imaginary"
                | "ret"
                | "lr"
                | "rbp"
                | "ebp"
                | "rsp"
                | "esp"
                | "sp"
                | "fp"
        )
        && parse_arg_index(name).is_none()
        && !name
            .strip_prefix("var")
            .or_else(|| name.strip_prefix('t'))
            .is_some_and(|suffix| {
                !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit())
            })
        && !name.starts_with("local_")
        && !name.starts_with("stack_")
}

fn collect_direct_return_carriers(body: &[Stmt], out: &mut Vec<String>) {
    for statement in body {
        match statement {
            Stmt::Return {
                value: Some(Expr::Reg(VReg::Phys(name))),
            } => out.push(name.clone()),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_direct_return_carriers(then_body, out);
                if let Some(else_body) = else_body {
                    collect_direct_return_carriers(else_body, out);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                collect_direct_return_carriers(body, out);
            }
            Stmt::For { body, .. } => collect_direct_return_carriers(body, out),
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    collect_direct_return_carriers(case_body, out);
                }
                if let Some(default_body) = default {
                    collect_direct_return_carriers(default_body, out);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                collect_direct_return_carriers(try_body, out);
                for catch in catches {
                    collect_direct_return_carriers(&catch.body, out);
                }
            }
            _ => {}
        }
    }
}

/// Slot indices (into [`arg_slot_tables`]) that behave like genuine live-in
/// parameters: some alias of the slot is **read before** any alias is
/// **written**, scanning the body in linear (approximate execution) order.
///
/// A register written before its first read is scratch reuse of that ABI slot,
/// not an incoming argument, so its slot is excluded — this is what stops
/// scratch uses of `rcx`/`rdx`/... from inflating the recovered function arity.
/// The prologue of an `-O0` function spills each real parameter first thing
/// (`mov [rbp-x], edi`), i.e. reads it, so real parameters are reliably
/// classified as live-in by this first-touch scan.
fn live_in_arg_slots(body: &[Stmt], cc: CallConv) -> std::collections::HashSet<usize> {
    let mut slot_of: HashMap<&str, usize> = HashMap::new();
    for (i, names) in arg_slot_tables(cc).iter().enumerate() {
        for n in *names {
            slot_of.insert(n, i);
        }
    }
    // slot -> is_param (true = first touch was a read). First touch wins.
    let mut decided: HashMap<usize, bool> = HashMap::new();
    for s in body {
        walk_stmt_rw(s, &mut |name, is_write| {
            if let Some(&slot) = slot_of.get(name) {
                decided.entry(slot).or_insert(!is_write);
            }
        });
    }
    decided
        .into_iter()
        .filter_map(|(slot, is_param)| is_param.then_some(slot))
        .collect()
}

/// Walk a statement emitting `(register_name, is_write)` events in execution
/// order: the reads of a statement are reported before its write. Memory stores
/// write memory, not a register, so their operands are all reads.
fn walk_stmt_rw(s: &Stmt, cb: &mut impl FnMut(&str, bool)) {
    match s {
        Stmt::Assign { dst, src } => {
            walk_expr_phys(src, &mut |n| cb(n, false));
            if let VReg::Phys(n) = dst {
                cb(n, true);
            }
        }
        Stmt::Store { addr, src, .. } => {
            walk_expr_phys(addr, &mut |n| cb(n, false));
            walk_expr_phys(src, &mut |n| cb(n, false));
        }
        Stmt::Call {
            target, args, dst, ..
        } => {
            walk_expr_phys(target, &mut |n| cb(n, false));
            for a in args {
                walk_expr_phys(a, &mut |n| cb(n, false));
            }
            // A call WRITES its return register: reporting otherwise would let the
            // live-in scan mistake a clobbered return register for a parameter.
            if let Some(VReg::Phys(n)) = dst {
                cb(n.as_str(), true);
            }
        }
        Stmt::Return { value } => {
            if let Some(e) = value {
                walk_expr_phys(e, &mut |n| cb(n, false));
            }
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            walk_expr_phys(cond, &mut |n| cb(n, false));
            for s in then_body {
                walk_stmt_rw(s, cb);
            }
            if let Some(eb) = else_body {
                for s in eb {
                    walk_stmt_rw(s, cb);
                }
            }
        }
        Stmt::While { cond, body } => {
            walk_expr_phys(cond, &mut |n| cb(n, false));
            for s in body {
                walk_stmt_rw(s, cb);
            }
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            walk_stmt_rw(init, cb);
            walk_expr_phys(cond, &mut |n| cb(n, false));
            for s in body {
                walk_stmt_rw(s, cb);
            }
            walk_stmt_rw(step, cb);
        }
        Stmt::DoWhile { body, cond } => {
            for s in body {
                walk_stmt_rw(s, cb);
            }
            walk_expr_phys(cond, &mut |n| cb(n, false));
        }
        Stmt::Push { value } => walk_expr_phys(value, &mut |n| cb(n, false)),
        Stmt::Pop { target } => {
            if let VReg::Phys(n) = target {
                cb(n, true);
            }
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            walk_expr_phys(discriminant, &mut |n| cb(n, false));
            for (_, body) in cases {
                for s in body {
                    walk_stmt_rw(s, cb);
                }
            }
            if let Some(b) = default {
                for s in b {
                    walk_stmt_rw(s, cb);
                }
            }
        }
        Stmt::IndirectGoto { target } => walk_expr_phys(target, &mut |n| cb(n, false)),
        Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Continue
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_)
        | Stmt::Throw { .. }
        | Stmt::TryCatch { .. } => {}
    }
}

fn collect_first_appearance_phys(body: &[Stmt]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for s in body {
        walk_stmt_phys(s, &mut |name| {
            if seen.insert(name.to_string()) {
                out.push(name.to_string());
            }
        });
    }
    out
}

fn walk_stmt_phys(s: &Stmt, cb: &mut impl FnMut(&str)) {
    match s {
        Stmt::IndirectGoto { target } => walk_expr_phys(target, cb),
        Stmt::Assign { dst, src } => {
            if let VReg::Phys(n) = dst {
                cb(n);
            }
            walk_expr_phys(src, cb);
        }
        Stmt::Store { addr, src, .. } => {
            walk_expr_phys(addr, cb);
            walk_expr_phys(src, cb);
        }
        Stmt::Call {
            target, args, dst, ..
        } => {
            walk_expr_phys(target, cb);
            for a in args {
                walk_expr_phys(a, cb);
            }
            if let Some(VReg::Phys(n)) = dst {
                cb(n.as_str());
            }
        }
        Stmt::Return { value } => {
            if let Some(e) = value {
                walk_expr_phys(e, cb);
            }
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            walk_expr_phys(cond, cb);
            for s in then_body {
                walk_stmt_phys(s, cb);
            }
            if let Some(eb) = else_body {
                for s in eb {
                    walk_stmt_phys(s, cb);
                }
            }
        }
        Stmt::While { cond, body } => {
            walk_expr_phys(cond, cb);
            for s in body {
                walk_stmt_phys(s, cb);
            }
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            walk_stmt_phys(init, cb);
            walk_expr_phys(cond, cb);
            for s in body {
                walk_stmt_phys(s, cb);
            }
            walk_stmt_phys(step, cb);
        }
        Stmt::DoWhile { body, cond } => {
            for s in body {
                walk_stmt_phys(s, cb);
            }
            walk_expr_phys(cond, cb);
        }
        Stmt::Push { value } => walk_expr_phys(value, cb),
        Stmt::Pop { target } => {
            if let VReg::Phys(n) = target {
                cb(n);
            }
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            walk_expr_phys(discriminant, cb);
            for (_, body) in cases {
                for s in body {
                    walk_stmt_phys(s, cb);
                }
            }
            if let Some(b) = default {
                for s in b {
                    walk_stmt_phys(s, cb);
                }
            }
        }
        Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Continue
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_)
        | Stmt::Throw { .. }
        | Stmt::TryCatch { .. } => {}
    }
}

fn walk_expr_phys(e: &Expr, cb: &mut impl FnMut(&str)) {
    match e {
        Expr::Reg(VReg::Phys(n)) => cb(n),
        Expr::StackAddr {
            object: VReg::Phys(n),
            ..
        } => cb(n),
        Expr::Reg(_)
        | Expr::StackAddr { .. }
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            if let Some(VReg::Phys(n)) = base {
                cb(n);
            }
            if let Some(VReg::Phys(n)) = index {
                cb(n);
            }
        }
        Expr::Deref { addr, .. } => walk_expr_phys(addr, cb),
        Expr::Call { target, args, .. } => {
            walk_expr_phys(target, cb);
            for argument in args {
                walk_expr_phys(argument, cb);
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            walk_expr_phys(lhs, cb);
            walk_expr_phys(rhs, cb);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            walk_expr_phys(cond, cb);
            walk_expr_phys(if_true, cb);
            walk_expr_phys(if_false, cb);
        }
        Expr::Un { src, .. } => walk_expr_phys(src, cb),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => walk_expr_phys(expr, cb),
        Expr::FunctionTableEntry { index, .. } => walk_expr_phys(index, cb),
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                walk_expr_phys(argument, cb);
            }
        }
    }
}

fn rename_vreg(v: &mut VReg, role: &HashMap<String, String>) {
    if let VReg::Phys(n) = v {
        if let Some(alias) = role.get(n) {
            *n = alias.clone();
        }
    }
}

fn rewrite_expr(e: &mut Expr, role: &HashMap<String, String>) {
    match e {
        Expr::Reg(v) => rename_vreg(v, role),
        Expr::StackAddr { object, .. } => rename_vreg(object, role),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            if let Some(v) = base {
                rename_vreg(v, role);
            }
            if let Some(v) = index {
                rename_vreg(v, role);
            }
        }
        Expr::Deref { addr, .. } => rewrite_expr(addr, role),
        Expr::Call { target, args, .. } => {
            rewrite_expr(target, role);
            for argument in args {
                rewrite_expr(argument, role);
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            rewrite_expr(lhs, role);
            rewrite_expr(rhs, role);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            rewrite_expr(cond, role);
            rewrite_expr(if_true, role);
            rewrite_expr(if_false, role);
        }
        Expr::Un { src, .. } => rewrite_expr(src, role),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => rewrite_expr(expr, role),
        Expr::FunctionTableEntry { index, .. } => rewrite_expr(index, role),
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                rewrite_expr(argument, role);
            }
        }
    }
}

fn rewrite_body(body: &mut [Stmt], role: &HashMap<String, String>) {
    for s in body.iter_mut() {
        match s {
            Stmt::IndirectGoto { target } => rewrite_expr(target, role),
            Stmt::Assign { dst, src } => {
                rename_vreg(dst, role);
                rewrite_expr(src, role);
            }
            Stmt::Store { addr, src, .. } => {
                rewrite_expr(addr, role);
                rewrite_expr(src, role);
            }
            Stmt::Call {
                target, args, dst, ..
            } => {
                rewrite_expr(target, role);
                for a in args {
                    rewrite_expr(a, role);
                }
                // The call's destination is the same register every reader of the
                // return value uses; leaving it raw would sever that connection.
                if let Some(VReg::Phys(n)) = dst {
                    if let Some(new) = role.get(n.as_str()) {
                        *n = new.clone();
                    }
                }
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    rewrite_expr(e, role);
                }
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                rewrite_expr(cond, role);
                rewrite_body(then_body, role);
                if let Some(eb) = else_body {
                    rewrite_body(eb, role);
                }
            }
            Stmt::While { cond, body } => {
                rewrite_expr(cond, role);
                rewrite_body(body, role);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                rewrite_body(std::slice::from_mut(init.as_mut()), role);
                rewrite_expr(cond, role);
                rewrite_body(body, role);
                rewrite_body(std::slice::from_mut(step.as_mut()), role);
            }
            Stmt::DoWhile { body, cond } => {
                rewrite_body(body, role);
                rewrite_expr(cond, role);
            }
            Stmt::Push { value } => rewrite_expr(value, role),
            Stmt::Pop { target } => rename_vreg(target, role),
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                rewrite_expr(discriminant, role);
                for (_, body) in cases.iter_mut() {
                    rewrite_body(body, role);
                }
                if let Some(b) = default {
                    rewrite_body(b, role);
                }
            }
            Stmt::Goto { .. }
            | Stmt::Label(_)
            | Stmt::Break
            | Stmt::Continue
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. }
            | Stmt::TryCatch { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{render, Function, Stmt};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }

    #[test]
    fn sysv_rdi_becomes_arg0_and_rax_becomes_ret() {
        // rdi is READ (a genuine live-in parameter) before rax is set as the
        // return value.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0x1000,
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
        apply_role_names(&mut f, CallConv::SysVAmd64);
        let text = render(&f);
        assert!(text.contains("%ret = %arg0;"), "got: {}", text);
        assert!(text.contains("return %ret;"), "got: {}", text);
        assert!(!text.contains("%rdi"));
        assert!(!text.contains("%rax"));
    }

    #[test]
    fn exact_ssa_return_carrier_keeps_the_output_role() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0x1010,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax#7"),
                    src: Expr::Const(42),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rax#7"))),
                },
            ],
        };

        apply_role_names(&mut f, CallConv::SysVAmd64);

        assert_eq!(
            f.body,
            vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Const(42),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("ret"))),
                },
            ]
        );
    }

    #[test]
    fn materialized_sse_pair_keeps_integer_and_sse_scratch_identities_distinct() {
        let object = reg("sse_pair_return_object");
        let mut f = Function {
            name: "f".into(),
            entry_va: 0x1020,
            body: vec![
                Stmt::Assign {
                    dst: reg("eax"),
                    src: Expr::Const(2),
                },
                Stmt::Assign {
                    dst: reg("xmm0"),
                    src: Expr::Const(0),
                },
                Stmt::Assign {
                    dst: reg("xmm1"),
                    src: Expr::Reg(reg("eax")),
                },
                Stmt::Return {
                    value: Some(Expr::Deref {
                        addr: Box::new(Expr::StackAddr { object, size: 12 }),
                        size: 8,
                    }),
                },
            ],
        };
        apply_role_names(&mut f, CallConv::SysVAmd64);
        let Stmt::Assign { dst: integer, .. } = &f.body[0] else {
            unreachable!()
        };
        let Stmt::Assign { dst: sse, .. } = &f.body[1] else {
            unreachable!()
        };
        let Stmt::Assign {
            src: Expr::Reg(converted_source),
            ..
        } = &f.body[2]
        else {
            unreachable!()
        };
        assert_ne!(
            integer, sse,
            "cross-bank scratches must not collapse to ret"
        );
        assert_eq!(
            converted_source, integer,
            "the conversion must still read EAX's value"
        );
    }

    #[test]
    fn ordinary_scalar_return_still_gets_ret_role_without_materialized_object() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0x1030,
            body: vec![
                Stmt::Assign {
                    dst: reg("xmm0"),
                    src: Expr::Const(1),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("xmm0"))),
                },
            ],
        };
        apply_role_names(&mut f, CallConv::SysVAmd64);
        assert!(matches!(&f.body[0], Stmt::Assign { dst, .. } if dst == &reg("ret")));
    }

    #[test]
    fn returned_source_local_does_not_become_machine_output_storage() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0x1010,
            body: vec![Stmt::Return {
                value: Some(Expr::Reg(reg("local_18"))),
            }],
        };

        apply_role_names(&mut f, CallConv::SysVAmd64);

        assert_eq!(
            f.body,
            vec![Stmt::Return {
                value: Some(Expr::Reg(reg("local_18"))),
            }]
        );
    }

    #[test]
    fn scratch_arg_register_written_first_is_not_a_param() {
        // rcx (SysV 4th arg slot) is written before any read -> it is scratch,
        // not `arg3`; it must become a `varN` local so the recovered arity is
        // not inflated. rdi *is* read first, so it is the sole parameter.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0x2000,
            body: vec![
                Stmt::Assign {
                    dst: reg("rcx"),
                    src: Expr::Const(32),
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("rdi"))),
                        rhs: Box::new(Expr::Reg(reg("rcx"))),
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rax"))),
                },
            ],
        };
        apply_role_names(&mut f, CallConv::SysVAmd64);
        let text = render(&f);
        assert!(text.contains("%arg0"), "rdi should be arg0: {}", text);
        assert!(
            !text.contains("arg3") && !text.contains("arg1") && !text.contains("arg2"),
            "scratch rcx must not become an arg slot: {}",
            text
        );
        assert!(
            !text.contains("%rcx"),
            "rcx should be aliased away: {}",
            text
        );
    }

    #[test]
    fn stack_registers_keep_their_names() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rsp"),
                src: Expr::Bin {
                    op: crate::ir::types::BinOp::Sub,
                    lhs: Box::new(Expr::Reg(reg("rsp"))),
                    rhs: Box::new(Expr::Const(8)),
                },
            }],
        };
        apply_role_names(&mut f, CallConv::SysVAmd64);
        let text = render(&f);
        assert!(text.contains("%rsp"), "got: {}", text);
    }

    #[test]
    fn unclaimed_gprs_get_stable_varn_aliases() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("r12"),
                    src: Expr::Const(1),
                },
                Stmt::Assign {
                    dst: reg("r13"),
                    src: Expr::Reg(reg("r12")),
                },
            ],
        };
        apply_role_names(&mut f, CallConv::SysVAmd64);
        let text = render(&f);
        assert!(text.contains("%var0 = 1;"), "got: {}", text);
        assert!(text.contains("%var1 = %var0;"), "got: {}", text);
    }

    #[test]
    fn authoritative_local_name_is_applied_only_at_the_presentation_boundary() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("local_c"),
                src: Expr::Const(1),
            }],
        };

        apply_authoritative_local_names(
            &mut f,
            &HashMap::from([("local_c".to_string(), "reg32".to_string())]),
        );

        assert_eq!(
            f.body[0],
            Stmt::Assign {
                dst: reg("reg32"),
                src: Expr::Const(1)
            }
        );
    }

    #[test]
    fn authoritative_local_names_reject_c_and_decompiler_namespaces() {
        for valid in ["i", "result", "_source_value", "reg32"] {
            assert!(valid_authoritative_local_name(valid), "rejected {valid}");
        }
        for invalid in [
            "",
            "two words",
            "3d",
            "return",
            "arg2",
            "var4",
            "t17",
            "local_c",
            "stack_0",
            "ret",
            "sp",
        ] {
            assert!(
                !valid_authoritative_local_name(invalid),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn aarch64_x0_stays_arg0() {
        // x0 is read (live-in parameter); on AArch64 arg0 wins over the
        // ret-alias for the shared x0 register.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Return {
                value: Some(Expr::Reg(reg("x0"))),
            }],
        };
        apply_role_names(&mut f, CallConv::Aarch64);
        let text = render(&f);
        assert!(text.contains("return %arg0;"), "got: {}", text);
    }

    #[test]
    fn aarch64_exact_result_does_not_steal_the_live_in_arg0_role() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("x0#2"),
                    src: Expr::Reg(reg("x0")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("x0#2"))),
                },
            ],
        };

        apply_role_names(&mut f, CallConv::Aarch64);

        assert_eq!(
            f.body,
            vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Reg(reg("arg0")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("ret"))),
                },
            ]
        );
    }

    #[test]
    fn exact_mixed_arm_roles_override_core_register_slot_numbers() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("r3"),
                    src: Expr::Reg(reg("r1")),
                },
                Stmt::Assign {
                    dst: reg("s1"),
                    src: Expr::Reg(reg("s0")),
                },
            ],
        };
        let roles = HashMap::from([
            ("r0".to_string(), 0),
            ("s0".to_string(), 1),
            ("r1".to_string(), 2),
        ]);
        apply_role_names_with_parameter_roles(
            &mut f,
            CallConv::Arm,
            &std::collections::HashSet::from([0, 1]),
            &roles,
        );

        assert_eq!(
            f.body,
            vec![
                Stmt::Assign {
                    dst: reg("var0"),
                    src: Expr::Reg(reg("arg2")),
                },
                Stmt::Assign {
                    dst: reg("var1"),
                    src: Expr::Reg(reg("arg1")),
                },
            ]
        );
    }

    #[test]
    fn call_arg_expression_is_also_renamed() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0,
                    name: "puts".into(),
                },
                args: vec![Expr::Reg(reg("rdi"))],
                dst: None,
                call_spec: None,
            }],
        };
        apply_role_names(&mut f, CallConv::SysVAmd64);
        let text = render(&f);
        assert!(text.contains("call puts(%arg0);"), "got: {}", text);
    }

    #[test]
    fn canonical_loop_names_identify_induction_and_additive_accumulator() {
        let mut f = Function {
            name: "main".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(reg("stack_4")),
                    src: Expr::Const(0),
                    size: 4,
                },
                Stmt::For {
                    init: Box::new(Stmt::Store {
                        addr: Expr::Reg(reg("stack_5")),
                        src: Expr::Const(0),
                        size: 4,
                    }),
                    cond: Expr::Cmp {
                        op: crate::ir::types::CmpOp::Slt,
                        lhs: Box::new(Expr::Reg(reg("stack_5"))),
                        rhs: Box::new(Expr::Reg(reg("arg0"))),
                    },
                    step: Box::new(Stmt::Store {
                        addr: Expr::Reg(reg("stack_5")),
                        src: Expr::Bin {
                            op: crate::ir::types::BinOp::Add,
                            lhs: Box::new(Expr::Reg(reg("stack_5"))),
                            rhs: Box::new(Expr::Const(1)),
                        },
                        size: 4,
                    }),
                    body: vec![Stmt::Store {
                        addr: Expr::Reg(reg("stack_4")),
                        src: Expr::Bin {
                            op: crate::ir::types::BinOp::Add,
                            lhs: Box::new(Expr::Reg(reg("stack_4"))),
                            rhs: Box::new(Expr::Call {
                                target: Box::new(Expr::Named {
                                    va: 0,
                                    name: "strlen".into(),
                                }),
                                args: vec![],
                                call_spec: None,
                                result_width: Some(8),
                            }),
                        },
                        size: 4,
                    }],
                },
            ],
        };

        apply_canonical_loop_local_names(&mut f);
        let text = render(&f);
        assert!(text.contains("%sum = 0"), "{text}");
        assert!(text.contains("for (%i = 0;"), "{text}");
        assert!(text.contains("%sum = (%sum + strlen())"), "{text}");
    }

    #[test]
    fn win64_rcx_becomes_arg0_and_rdi_becomes_var() {
        // rcx (Win64 arg0) is read first -> arg0; rdi is not a Win64 arg slot
        // and is written -> a var local.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Reg(reg("rcx")),
                },
                Stmt::Assign {
                    dst: reg("rdi"),
                    src: Expr::Const(2),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rax"))),
                },
            ],
        };
        apply_role_names(&mut f, CallConv::Win64);
        let text = render(&f);
        assert!(text.contains("%ret = %arg0;"), "got: {}", text);
        assert!(text.contains("%var0 = 2;"), "got: {}", text);
        assert!(text.contains("return %ret;"), "got: {}", text);
    }
}
