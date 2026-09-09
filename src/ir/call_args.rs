//! Reconstruct call arguments by folding the immediately-preceding
//! argument-register assignments into each `Stmt::Call`.
//!
//! The pass is intentionally conservative: it only folds an assignment when
//!
//! 1. the assignment's destination is a calling-convention argument
//!    register (x86-64 SysV: rdi/rsi/rdx/rcx/r8/r9; Windows x64:
//!    rcx/rdx/r8/r9; AArch64: x0..x7), and
//! 2. that register is not read between the assignment and the call, and
//! 3. no intervening statement has a side effect we can't reason about
//!    (calls are treated as a barrier to keep the transformation
//!    semantically safe).
//!
//! If a later slot was explicitly set but an earlier slot was never written
//! since the previous call boundary, the pass fills that earlier slot from
//! the function's incoming argument register. This covers common forwarding
//! shapes such as Win64 `rdx = 256; call strnlen`, where `rcx` still carries
//! the function's incoming first parameter.
//!
//! A 32-bit sub-register write (e.g. `%esi = 0`) also counts as writing the
//! corresponding 64-bit arg register because on x86-64 the upper 32 bits of
//! every GPR are zeroed by a 32-bit write.
//!
//! SysV integer arguments beyond the six-register prefix are recovered from
//! exact lowered `push` pairs or a contiguous preallocated outgoing area only
//! when the matching post-call cleanup balances the complete allocation. This
//! prevents callee-save pushes or local frame storage from becoming invented
//! call arguments.
//!
//! After running, `call foo` becomes `call foo(arg0, arg1, …)` with args
//! populated in calling-convention order.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::{BinOp, VReg};

mod aapcs;
mod captured_defs;
mod cdecl32;
mod enclosing_slots;
mod fold_one_call;
mod return_attribution;
mod slot_marking;
mod tail_calls;

use aapcs::{
    aapcs_core_register_arity, aapcs_integer_stack_suffix,
    fold_one_arm_hard_float_call_with_identities, known_arm_core_register_arity,
    known_arm_hard_float_layout, outgoing_aapcs_stack_area_with_identities,
};
use captured_defs::{
    is_stable_frame_arg_definition_with_identities, resolve_captured_definition,
    resolve_captured_definition_in, substitute_exact_reg,
};
use cdecl32::fold_one_cdecl32_call;
use enclosing_slots::EnclosingSlots;
use fold_one_call::fold_one_call;
use return_attribution::{attribute_call_results, attribute_call_results_with_identities};
use slot_marking::{
    mark_arg_reads_in_expr_with_identities, mark_arg_reads_in_stmt_with_identities,
    mark_arg_writes_in_stmt_with_identities, mark_slot_write_with_identities,
};
pub use tail_calls::{
    recover_proven_vtable_tail_calls, recover_resolved_direct_tail_calls,
    recover_resolved_tail_calls,
};
pub(crate) use tail_calls::{
    recover_proven_vtable_tail_calls_with_identities,
    recover_resolved_direct_tail_calls_with_identities,
    recover_resolved_tail_calls_with_identities,
};

/// Compatibility export while ABI consumers migrate to `crate::target`.
pub use crate::target::abi::CallConv;

/// Argument slots come from [`crate::ir::abi`], which owns them. They were
/// previously written out here AND in `value_number`, and the copies drifted in a
/// way no test could see: this one matched names literally while the other had
/// already renamed registers to `canon#version`, so `rdi#3` matched nothing and
/// every call on that path silently lost all of its arguments.
fn arg_slots(arch: CallConv) -> &'static [&'static [&'static str]] {
    crate::ir::abi::argument_slots(arch)
}

/// The calling-convention slot a register name denotes, if any.
///
/// The name may be SSA-VERSIONED. The decbench pipeline value-numbers the LLIR
/// before lowering (`value_number` renames a register to `canon#version`), so an
/// argument arrives here as `rdi#3`. Matching the slot table against the literal
/// string found nothing and every call on that path silently lost all of its
/// arguments — `signed_step(x)` rendered as `signed_step()`. The register-style
/// path does not value-number, which is exactly why the same function showed its
/// arguments there and hid the bug.
fn slot_of(arch: CallConv, name: &str) -> Option<usize> {
    crate::ir::abi::argument_slot_of(arch, name)
}

pub(super) fn ssa_base(name: &str) -> &str {
    crate::ir::abi::ssa_base(name)
}

/// Could `layout` be a real parameter allocation under `arch`?
///
/// Every convention modelled here allocates integer/pointer parameters from
/// [`slot_of`]'s table in ascending order beginning at slot zero, so the
/// argument-slot registers of a genuine callee layout are that table's
/// contiguous prefix, in order. Registers drawn from a separate bank (AAPCS-VFP
/// `s0`…`s15`, which is the whole reason recovered layouts exist) are not part
/// of that order and are skipped rather than judged.
///
/// This exists because a layout is evidence imported from ANOTHER function, and
/// the caller trusts it ahead of the call site's own instructions.
/// `recover_direct_callee_layouts` derives one by lifting the callee — and an
/// ARM32 PLT stub is not a function: discovery does not stop at
/// `ldr pc,[ip,#n]!`, so the body it lifts runs through the following stubs and
/// into misdecoded bytes whose reads of r2/r3 become the "parameters". Every
/// imported callee of `strip_iconv_arm-v7` was recovered as `[r2, r3]`, and
/// those two undefined live-in registers were installed verbatim on ten distinct
/// calls — leaving no call-site value for string folding to see, so that binary
/// recovered no string literals at all.
///
/// Rejecting the layout is not a guess about the callee. It only withdraws
/// unusable outside evidence, returning the call to the local backward scan over
/// the argument setup the caller actually executed.
///
/// Applied to every convention rather than only to AAPCS: the allocation order
/// it checks is a property of all of them, and measuring the unscoped form moved
/// no cell of the fixture matrix and no `arch_roundtrip` lane.
fn layout_matches_abi_allocation_order(arch: CallConv, layout: &[VReg]) -> bool {
    let mut expected_slot = 0usize;
    for register in layout {
        let VReg::Phys(name) = register else {
            continue;
        };
        let Some(slot) = slot_of(arch, name) else {
            continue;
        };
        if slot != expected_slot {
            return false;
        }
        expected_slot += 1;
    }
    true
}

/// Architectural registers whose value is a stack-coordinate phase, not an
/// ordinary substitutable scalar.
///
/// An unversioned `sp = sp - N` definition describes when a coordinate is
/// observed. Inlining it into a later call argument and then running stack
/// promotion applies the current delta a second time. Frame pointers have the
/// dual hazard: replacing their establishment value with the current stack
/// pointer changes meaning after any later allocation. Keeping these
/// definitions statement-rooted is conservative and preserves the coordinate
/// oracle's ownership of frame rebasing.
fn is_frame_coordinate_storage(
    arch: CallConv,
    register: &VReg,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> bool {
    let name = match identities {
        Some(identities) => {
            let Some(identity) = identities.exact(register) else {
                return false;
            };
            let VReg::Phys(base) = &identity.base else {
                return false;
            };
            base.as_str()
        }
        None => {
            let VReg::Phys(name) = register else {
                return false;
            };
            ssa_base(name)
        }
    };
    match arch {
        CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Cdecl32 => {
            matches!(name, "rsp" | "esp" | "rbp" | "ebp")
        }
        CallConv::Aarch64 => matches!(name, "sp" | "x29" | "fp"),
        CallConv::Arm | CallConv::ArmHardFloat => {
            matches!(name, "sp" | "r7" | "r11" | "fp")
        }
    }
}

/// An expression naming the function's INCOMING value in `slot`, as that value is
/// actually spelled in `body`.
///
/// The bare canonical name is wrong on a value-numbered body. The decbench
/// pipeline renames registers to `canon#version`, so injecting `rdi` referenced a
/// register the body never defines — it survived naming as a scratch `varN` and
/// produced `__stack_chk_fail(var24)`, an argument reading nothing, in a callee
/// that takes no arguments at all.
///
/// The incoming value is the LOWEST version of the slot's register present in the
/// body: later versions are definitions made inside the function. When the slot's
/// register does not appear at all there is no incoming value to name and no
/// argument is invented.
fn incoming_arg_expr_with_identities(
    arch: CallConv,
    slot: usize,
    body: &[Stmt],
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> Option<Expr> {
    let names = arg_slots(arch).get(slot)?;
    if let Some(identities) = identities {
        let mut live_in = None;
        walk_body_reg_names(body, &mut |name| {
            if live_in.is_some() {
                return;
            }
            let register = VReg::phys(name);
            let Some(identity) = identities.exact(&register) else {
                return;
            };
            let VReg::Phys(base) = &identity.base else {
                return;
            };
            if identity.version == 0 && names.contains(&base.as_str()) {
                live_in = Some(Expr::Reg(register));
            }
        });
        return live_in;
    }
    // Is this body value-numbered at all? On the un-numbered path the incoming
    // register is implicit — it legitimately appears nowhere — and the bare
    // canonical name is the right reference, as it always was.
    let mut versioned_anywhere = false;
    let mut bare_live_in: Option<String> = None;
    let mut best: Option<(u32, String)> = None;
    let mut visit = |n: &str| {
        let Some((_, v)) = n.split_once('#') else {
            if names.contains(&n) && bare_live_in.is_none() {
                bare_live_in = Some(n.to_string());
            }
            return;
        };
        versioned_anywhere = true;
        if !names.contains(&ssa_base(n)) {
            return;
        }
        if let Ok(v) = v.parse::<u32>() {
            if best.as_ref().is_none_or(|(bv, _)| v < *bv) {
                best = Some((v, n.to_string()));
            }
        }
    };
    walk_body_reg_names(body, &mut visit);
    if !versioned_anywhere {
        return names
            .first()
            .map(|n| Expr::Reg(VReg::Phys((*n).to_string())));
    }
    // `value_number` deliberately leaves version zero bare. If this exact slot
    // has a bare use, it is therefore the live-in value and is safe to backfill.
    // The caller additionally requires `param_slots` to classify this slot as a
    // real read-before-write parameter, preventing the old cpp_virtual_dispatch
    // failure where a scratch register invented an undefined call argument.
    if let Some(name) = bare_live_in {
        return Some(Expr::Reg(VReg::Phys(name)));
    }
    // VALUE-NUMBERED with no bare version-zero witness: decline. Guessing the
    // lowest numbered definition is not a live-in proof.
    let _ = best;
    None
}

/// Call `f` with every register name mentioned anywhere in `body`.
fn walk_body_reg_names(body: &[Stmt], f: &mut impl FnMut(&str)) {
    fn expr(e: &Expr, f: &mut impl FnMut(&str)) {
        match e {
            Expr::Origin { expr: inner, .. } => expr(inner, f),
            Expr::Reg(VReg::Phys(n)) => f(n),
            Expr::Reg(_) => {}
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                expr(lhs, f);
                expr(rhs, f);
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                expr(cond, f);
                expr(if_true, f);
                expr(if_false, f);
            }
            Expr::Un { src, .. } => expr(src, f),
            Expr::Cast { expr: inner, .. } | Expr::NumericConvert { expr: inner, .. } => {
                expr(inner, f);
            }
            Expr::Deref { addr, .. } => expr(addr, f),
            Expr::Call { target, args, .. } => {
                expr(target, f);
                for argument in args {
                    expr(argument, f);
                }
            }
            Expr::FunctionTableEntry { index, .. } => expr(index, f),
            Expr::WideArithmetic { args, .. } => {
                for argument in args {
                    expr(argument, f);
                }
            }
            Expr::StackAddr { object, .. } => {
                if let VReg::Phys(name) = object {
                    f(name);
                }
            }
            Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
                for register in [base, index].into_iter().flatten() {
                    if let VReg::Phys(name) = register {
                        f(name);
                    }
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
    for s in body {
        match s.semantic() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::Assign { dst, src } => {
                if let VReg::Phys(n) = dst {
                    f(n);
                }
                expr(src, f);
            }
            Stmt::Store { addr, src, .. } => {
                expr(addr, f);
                expr(src, f);
            }
            Stmt::Call {
                target, args, dst, ..
            } => {
                expr(target, f);
                for a in args {
                    expr(a, f);
                }
                if let Some(VReg::Phys(n)) = dst {
                    f(n);
                }
            }
            Stmt::Return { value: Some(e) } => expr(e, f),
            Stmt::Return { value: None } => {}
            Stmt::Throw { value } | Stmt::IndirectGoto { target: value } | Stmt::Push { value } => {
                expr(value, f)
            }
            Stmt::TryCatch { try_body, catches } => {
                walk_body_reg_names(try_body, f);
                for catch in catches {
                    if let VReg::Phys(name) = &catch.binding {
                        f(name);
                    }
                    walk_body_reg_names(&catch.body, f);
                }
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                expr(cond, f);
                walk_body_reg_names(then_body, f);
                if let Some(b) = else_body {
                    walk_body_reg_names(b, f);
                }
            }
            Stmt::While { cond, body } => {
                expr(cond, f);
                walk_body_reg_names(body, f);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                walk_body_reg_names(std::slice::from_ref(init.as_ref()), f);
                expr(cond, f);
                walk_body_reg_names(body, f);
                walk_body_reg_names(std::slice::from_ref(step.as_ref()), f);
            }
            Stmt::DoWhile { body, cond } => {
                walk_body_reg_names(body, f);
                expr(cond, f);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                expr(discriminant, f);
                for (_, b) in cases {
                    walk_body_reg_names(b, f);
                }
                if let Some(b) = default {
                    walk_body_reg_names(b, f);
                }
            }
            Stmt::Pop {
                target: VReg::Phys(name),
            } => f(name),
            Stmt::Pop { .. }
            | Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::Continue
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_) => {}
        }
    }
}

/// Run argument reconstruction on `f` using the given calling convention.
pub fn reconstruct_args(f: &mut Function, arch: CallConv) {
    reconstruct_args_with_params(f, arch, &std::collections::HashSet::new())
}

/// As [`reconstruct_args`], but told which argument slots hold THIS function's
/// own incoming parameters (`value_number::live_in_arg_slots_llir`).
///
/// The backfill below invents an argument from the incoming register when an
/// earlier slot was never written. That is only sound when the register actually
/// carries a parameter. Without the set it fired on `__stack_chk_fail` — a void
/// callee — and produced `__stack_chk_fail(var24)` reading a value nothing ever
/// defines, which the definition verifier duly reported.
pub fn reconstruct_args_with_params(
    f: &mut Function,
    arch: CallConv,
    param_slots: &std::collections::HashSet<usize>,
) {
    let mut effective_param_slots = param_slots.clone();
    reconstruct_args_with_params_and_callee_layouts(
        f,
        arch,
        &mut effective_param_slots,
        &std::collections::HashMap::new(),
    );
}

/// Reconstruct call arguments while honoring exact direct-callee storage.
///
/// AAPCS-VFP allocates core and floating-point parameters from independent
/// banks. Their source order is therefore not derivable from the caller's
/// register names alone. A recovered callee prototype supplies that missing
/// order as one physical storage register per source parameter.
pub fn reconstruct_args_with_params_and_callee_layouts(
    f: &mut Function,
    arch: CallConv,
    param_slots: &mut std::collections::HashSet<usize>,
    callee_layouts: &std::collections::HashMap<u64, Vec<VReg>>,
) {
    reconstruct_args_with_layouts(
        f,
        arch,
        param_slots,
        callee_layouts,
        &std::collections::HashMap::new(),
    );
}

/// As [`reconstruct_args_with_params_and_callee_layouts`], but also told the
/// recovered parameter storage of every entry of the relocation-proven
/// function-pointer tables this function calls through.
///
/// A call through such a table has no single callee to ask for a parameter
/// layout, which is why the direct-call recovery does not generalise to it. It
/// does have a proven, finite, complete SET of callees, and the registers the
/// machine call may read is the union over that set. See
/// [`table_call_may_use_layout`].
pub fn reconstruct_args_with_layouts(
    f: &mut Function,
    arch: CallConv,
    param_slots: &mut std::collections::HashSet<usize>,
    callee_layouts: &std::collections::HashMap<u64, Vec<VReg>>,
    table_entry_layouts: &std::collections::HashMap<u64, Vec<VReg>>,
) {
    reconstruct_args_with_layouts_and_strings(
        f,
        arch,
        param_slots,
        callee_layouts,
        table_entry_layouts,
        &std::collections::HashMap::new(),
    );
}

/// As [`reconstruct_args_with_layouts`], with literal string evidence available
/// to prove the arity of recognized variadic format consumers.
pub fn reconstruct_args_with_layouts_and_strings(
    f: &mut Function,
    arch: CallConv,
    param_slots: &mut std::collections::HashSet<usize>,
    callee_layouts: &std::collections::HashMap<u64, Vec<VReg>>,
    table_entry_layouts: &std::collections::HashMap<u64, Vec<VReg>>,
    string_pool: &std::collections::HashMap<u64, String>,
) {
    reconstruct_args_with_layouts_prototypes_and_strings(
        f,
        arch,
        param_slots,
        callee_layouts,
        table_entry_layouts,
        None,
        string_pool,
    );
}

/// As [`reconstruct_args_with_layouts_and_strings`], with recovered direct-
/// callee prototypes available for multi-register forwarding proofs.
pub fn reconstruct_args_with_layouts_prototypes_and_strings(
    f: &mut Function,
    arch: CallConv,
    param_slots: &mut std::collections::HashSet<usize>,
    callee_layouts: &std::collections::HashMap<u64, Vec<VReg>>,
    table_entry_layouts: &std::collections::HashMap<u64, Vec<VReg>>,
    direct_prototypes: Option<
        &std::collections::HashMap<u64, crate::ir::call_contracts::CallPrototype>,
    >,
    string_pool: &std::collections::HashMap<u64, String>,
) {
    reconstruct_args_with_layouts_prototypes_strings_and_optional_identities(
        f,
        arch,
        param_slots,
        callee_layouts,
        table_entry_layouts,
        direct_prototypes,
        string_pool,
        None,
    );
}

/// Production form of [`reconstruct_args_with_layouts_prototypes_and_strings`]
/// that resolves incoming values through exact SSA identities.
pub fn reconstruct_args_with_layouts_prototypes_strings_and_identities(
    f: &mut Function,
    arch: CallConv,
    param_slots: &mut std::collections::HashSet<usize>,
    callee_layouts: &std::collections::HashMap<u64, Vec<VReg>>,
    table_entry_layouts: &std::collections::HashMap<u64, Vec<VReg>>,
    direct_prototypes: Option<
        &std::collections::HashMap<u64, crate::ir::call_contracts::CallPrototype>,
    >,
    string_pool: &std::collections::HashMap<u64, String>,
    identities: &crate::ir::value_number::ValueIdentities,
) {
    reconstruct_args_with_layouts_prototypes_strings_and_optional_identities(
        f,
        arch,
        param_slots,
        callee_layouts,
        table_entry_layouts,
        direct_prototypes,
        string_pool,
        Some(identities),
    );
}

fn reconstruct_args_with_layouts_prototypes_strings_and_optional_identities(
    f: &mut Function,
    arch: CallConv,
    param_slots: &mut std::collections::HashSet<usize>,
    callee_layouts: &std::collections::HashMap<u64, Vec<VReg>>,
    table_entry_layouts: &std::collections::HashMap<u64, Vec<VReg>>,
    direct_prototypes: Option<
        &std::collections::HashMap<u64, crate::ir::call_contracts::CallPrototype>,
    >,
    string_pool: &std::collections::HashMap<u64, String>,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) {
    // The spelling this function uses for each live-in argument register is a
    // WHOLE-FUNCTION fact. Answering it from the statement list that happens to
    // contain the call makes an untouched incoming parameter invisible to every
    // call nested in a branch arm — see `EnclosingSlots`.
    let function_live_ins = (0..arg_slots(arch).len())
        .map(|slot| incoming_arg_expr_with_identities(arch, slot, &f.body, identities))
        .collect::<Vec<_>>();
    fold_body(
        &mut f.body,
        arch,
        param_slots,
        CalleeLayouts {
            direct: callee_layouts,
            table_entry: table_entry_layouts,
            direct_prototypes,
        },
        &function_live_ins,
        string_pool,
        identities,
    );
    match identities {
        Some(identities) => attribute_call_results_with_identities(&mut f.body, arch, identities),
        None => attribute_call_results(&mut f.body, arch),
    }
}

/// The register a callee leaves its return value in.
fn return_reg(arch: CallConv) -> &'static str {
    crate::ir::abi::return_register(arch)
}

/// The ABI argument slots whose FUNCTION-ENTRY value still occupies their
/// argument register at every point in the function.
///
/// The backward scan fails closed at `Stmt::Label`, because a label is a join
/// and a predecessor it cannot see may arrive with a different value. That is
/// the right default and it is why a `-O2` diamond whose arms were structured
/// as labelled goto targets rendered `se189_bump()` for a callee declared
/// `(int *, int)`: the arm's own `esi` setup WAS recovered, and then discarded
/// with the missing slot zero, because ABI arguments are a contiguous prefix.
///
/// This is the cheapest whole-function proof that makes such a slot answerable
/// without a real reaching-definition service. Both conditions are required:
///
/// 1. no statement anywhere writes the slot — so no assignment can have changed
///    it on any path, labelled or not; and
/// 2. every call in the function runs straight into a `Return` — so no call's
///    caller-clobber of the argument registers can precede any other call.
///
/// Together they mean the architectural register still holds what the caller
/// put there, whatever path was taken. Anything less exact than this leaves the
/// slot blocked, which is the existing behavior.
///
/// This is deliberately NOT the general answer. Reaching definitions across
/// arbitrary joins belong to the verified MIR query surface; this proof only
/// removes the cases where there is provably nothing to reason about.
fn entry_constant_slots(
    body: &[Stmt],
    arch: CallConv,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> Vec<bool> {
    let slots = arg_slots(arch).len();
    if !every_call_returns_immediately(body) {
        return vec![false; slots];
    }
    let mut written = vec![false; slots];
    for statement in body {
        mark_slot_writes_everywhere(statement, arch, &mut written, identities);
    }
    written.into_iter().map(|write| !write).collect()
}

/// Does every `Stmt::Call` in `body` run straight into a `Return`?
///
/// "Straight into" means the statements after it in its own list reach a
/// `Return` without another call, a label, or any explicit transfer — so
/// nothing else in the function can execute after it, and in particular no
/// other call site is reachable from it.
fn every_call_returns_immediately(body: &[Stmt]) -> bool {
    fn nested_bodies(statement: &Stmt) -> Vec<&[Stmt]> {
        match statement.semantic() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => std::iter::once(then_body.as_slice())
                .chain(else_body.as_deref().map(|body: &[Stmt]| body))
                .collect(),
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                vec![body.as_slice()]
            }
            Stmt::Switch { cases, default, .. } => cases
                .iter()
                .map(|(_, case)| case.as_slice())
                .chain(default.as_deref().map(|body: &[Stmt]| body))
                .collect(),
            Stmt::TryCatch { try_body, catches } => std::iter::once(try_body.as_slice())
                .chain(catches.iter().map(|catch| catch.body.as_slice()))
                .collect(),
            _ => Vec::new(),
        }
    }
    for (index, statement) in body.iter().enumerate() {
        if matches!(statement.semantic(), Stmt::Call { .. }) {
            let mut returns = false;
            for following in &body[index + 1..] {
                match following.semantic() {
                    Stmt::Origin { .. } => {
                        unreachable!("semantic statement cannot be an origin wrapper")
                    }
                    Stmt::Return { .. } => {
                        returns = true;
                        break;
                    }
                    Stmt::Call { .. }
                    | Stmt::Label(_)
                    | Stmt::Goto { .. }
                    | Stmt::IndirectGoto { .. }
                    | Stmt::Break
                    | Stmt::Throw { .. } => break,
                    // A nested body after the call can reach anything.
                    other if !nested_bodies(other).is_empty() => break,
                    _ => {}
                }
            }
            if !returns {
                return false;
            }
        }
        if !nested_bodies(statement)
            .into_iter()
            .all(every_call_returns_immediately)
        {
            return false;
        }
    }
    true
}

/// Note every argument-slot write in `statement`, at any nesting depth.
///
/// Unlike `mark_arg_writes_in_stmt` this deliberately ignores control flow: the
/// question is whether the slot is written ANYWHERE, so branch arms that cannot
/// fall through still count.
fn mark_slot_writes_everywhere(
    statement: &Stmt,
    arch: CallConv,
    written: &mut [bool],
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) {
    match statement.semantic() {
        Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
        Stmt::Assign { dst, .. } | Stmt::Pop { target: dst } => {
            mark_slot_write_with_identities(dst, arch, written, identities)
        }
        Stmt::Call { dst: Some(dst), .. } => {
            mark_slot_write_with_identities(dst, arch, written, identities)
        }
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            for nested in then_body.iter().chain(else_body.iter().flatten()) {
                mark_slot_writes_everywhere(nested, arch, written, identities);
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            for nested in body {
                mark_slot_writes_everywhere(nested, arch, written, identities);
            }
        }
        Stmt::For {
            init, step, body, ..
        } => {
            mark_slot_writes_everywhere(init, arch, written, identities);
            mark_slot_writes_everywhere(step, arch, written, identities);
            for nested in body {
                mark_slot_writes_everywhere(nested, arch, written, identities);
            }
        }
        Stmt::Switch { cases, default, .. } => {
            for nested in cases
                .iter()
                .flat_map(|(_, case)| case)
                .chain(default.iter().flatten())
            {
                mark_slot_writes_everywhere(nested, arch, written, identities);
            }
        }
        Stmt::TryCatch { try_body, catches } => {
            for nested in try_body
                .iter()
                .chain(catches.iter().flat_map(|catch| &catch.body))
            {
                mark_slot_writes_everywhere(nested, arch, written, identities);
            }
        }
        _ => {}
    }
}

/// The callee storage facts argument reconstruction may consult.
///
/// `direct` is keyed by a direct call target VA. `table_entry` is keyed by the
/// VA of an entry of a relocation-proven function-pointer table, and is
/// deliberately a SEPARATE map: a table entry is not a direct call target of
/// this caller, so nothing that resolves a direct target can accidentally read
/// it, and populating it cannot change any existing recovery.
#[derive(Clone, Copy)]
pub struct CalleeLayouts<'facts> {
    direct: &'facts std::collections::HashMap<u64, Vec<VReg>>,
    table_entry: &'facts std::collections::HashMap<u64, Vec<VReg>>,
    direct_prototypes:
        Option<&'facts std::collections::HashMap<u64, crate::ir::call_contracts::CallPrototype>>,
}

fn fold_body(
    body: &mut Vec<Stmt>,
    arch: CallConv,
    param_slots: &mut std::collections::HashSet<usize>,
    callee_layouts: CalleeLayouts<'_>,
    function_live_ins: &[Option<Expr>],
    string_pool: &std::collections::HashMap<u64, String>,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) {
    let entry_constant = entry_constant_slots(body, arch, identities);
    let entry = EnclosingSlots::entry(arch, function_live_ins, entry_constant);
    fold_body_with_context(
        body,
        arch,
        param_slots,
        callee_layouts,
        &entry,
        string_pool,
        identities,
    );
}

fn fold_body_with_context(
    body: &mut Vec<Stmt>,
    arch: CallConv,
    param_slots: &mut std::collections::HashSet<usize>,
    callee_layouts: CalleeLayouts<'_>,
    enclosing: &EnclosingSlots,
    string_pool: &std::collections::HashMap<u64, String>,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) {
    // Recurse into nested bodies first so we don't miss calls inside arms.
    // `running` is the enclosing clobber mask at each position, accumulated in
    // one forward walk rather than rescanned per statement. `reaching` is the
    // matching per-slot definition, accumulated by the same walk.
    let mut running = enclosing.blocked.clone();
    let storage_slots = arg_slots(arch).len() + crate::ir::abi::sse_argument_registers(arch).len();
    running.resize(storage_slots, false);
    let mut reaching = enclosing.reaching.clone();
    reaching.resize(storage_slots, None);
    for index in 0..body.len() {
        let (prefix, suffix) = body.split_at_mut(index);
        let s = &mut suffix[0];
        let nested = enclosing.with_blocked(running.clone(), reaching.clone());
        match s.semantic_mut() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_body_with_context(
                    then_body,
                    arch,
                    param_slots,
                    callee_layouts,
                    &nested,
                    string_pool,
                    identities,
                );
                if let Some(eb) = else_body {
                    fold_body_with_context(
                        eb,
                        arch,
                        param_slots,
                        callee_layouts,
                        &nested,
                        string_pool,
                        identities,
                    );
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                // A loop's own carried inputs are `loop_carried_arg_inputs`'
                // business; only the path INTO the loop is inherited here.
                let loop_inputs =
                    loop_carried_arg_inputs(prefix, body, arch, &enclosing.overrides, identities);
                let nested = enclosing
                    .with_blocked(
                        running.clone(),
                        loop_body_reaching(&reaching, body, arch, identities),
                    )
                    .with_overrides(loop_inputs);
                fold_body_with_context(
                    body,
                    arch,
                    param_slots,
                    callee_layouts,
                    &nested,
                    string_pool,
                    identities,
                )
            }
            Stmt::For { body, .. } => {
                let nested = enclosing.with_blocked(
                    running.clone(),
                    loop_body_reaching(&reaching, body, arch, identities),
                );
                fold_body_with_context(
                    body,
                    arch,
                    param_slots,
                    callee_layouts,
                    &nested,
                    string_pool,
                    identities,
                )
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    fold_body_with_context(
                        case,
                        arch,
                        param_slots,
                        callee_layouts,
                        &nested,
                        string_pool,
                        identities,
                    );
                }
                if let Some(default) = default {
                    fold_body_with_context(
                        default,
                        arch,
                        param_slots,
                        callee_layouts,
                        &nested,
                        string_pool,
                        identities,
                    );
                }
            }
            _ => {}
        }
        EnclosingSlots::advance(&mut running, &suffix[0], arch, identities);
        EnclosingSlots::advance_reaching(&mut reaching, &suffix[0], arch, identities);
    }

    // Find calls and walk backward from each to collect args.
    let mut call_positions: Vec<usize> = body
        .iter()
        .enumerate()
        .filter_map(|(i, s)| {
            if matches!(s.semantic(), Stmt::Call { .. }) {
                Some(i)
            } else {
                None
            }
        })
        .collect();

    // Process right-to-left so earlier indices stay stable as we remove
    // preceding arg assignments for a later call first.
    call_positions.reverse();
    for call_idx in call_positions {
        fold_one_call(
            body,
            call_idx,
            arch,
            param_slots,
            callee_layouts,
            enclosing,
            string_pool,
            identities,
        );
    }
}

/// The reaching definitions of the path into a loop that survive INSIDE it.
///
/// A definition made before the loop still reaches every point of the body only
/// when the body itself never writes that slot: otherwise the back edge carries
/// a different value round and the pre-loop name is stale. `mark_slot_writes_everywhere`
/// ignores control flow deliberately, so a write on any path at any depth
/// clears the slot.
fn loop_body_reaching(
    incoming: &[Option<Expr>],
    loop_body: &[Stmt],
    arch: CallConv,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> Vec<Option<Expr>> {
    let mut written = vec![false; incoming.len()];
    for statement in loop_body {
        mark_slot_writes_everywhere(statement, arch, &mut written, identities);
    }
    incoming
        .iter()
        .zip(written)
        .map(|(reaching, written)| if written { None } else { reaching.clone() })
        .collect()
}

/// Recover the value entering an ABI slot at the top of a structured loop.
///
/// SSA destruction leaves an explicit initialization before the loop and a
/// definition of the same value-numbered name at the back edge (`rdi#1 = rdi`
/// ... `rdi#1 = next`). A call before that definition consumes `rdi#1`, not the
/// function-entry `rdi`. Phi-copy coalescing can fold `next` into an arbitrary
/// computed expression, so the update is not required to remain a register
/// copy. Requiring the exact initialized SSA destination and a preceding call
/// keeps this narrower than generic phi reconstruction.
fn loop_carried_arg_inputs(
    prefix: &[Stmt],
    loop_body: &[Stmt],
    arch: CallConv,
    inherited: &[Option<Expr>],
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> Vec<Option<Expr>> {
    let mut inputs = inherited.to_vec();
    inputs.resize(arg_slots(arch).len(), None);
    for (update_index, statement) in loop_body.iter().enumerate() {
        let Stmt::Assign { dst, .. } = statement.semantic() else {
            continue;
        };
        let Some((slot, versioned, initialized)) = (match identities {
            Some(identities) => identities.exact(dst).and_then(|identity| {
                let storage = identity.canonical_physical_base()?;
                let slot = slot_of(arch, storage)?;
                let initialized = prefix.iter().rev().any(|candidate| {
                    matches!(
                        candidate.semantic(),
                        Stmt::Assign { dst: prior, .. }
                            if identities.exact(prior) == Some(identity)
                    )
                });
                Some((slot, identity.version > 0, initialized))
            }),
            None => {
                let VReg::Phys(name) = dst else {
                    continue;
                };
                slot_of(arch, name).map(|slot| {
                    let initialized = prefix.iter().rev().any(|candidate| {
                        matches!(
                            candidate.semantic(),
                            Stmt::Assign { dst: VReg::Phys(prior), .. } if prior == name
                        )
                    });
                    (slot, name.contains('#'), initialized)
                })
            }
        }) else {
            continue;
        };
        if !versioned
            || !loop_body[..update_index]
                .iter()
                .any(|candidate| matches!(candidate.semantic(), Stmt::Call { .. }))
            || !initialized
        {
            continue;
        }
        inputs[slot] = Some(Expr::Reg(dst.clone()));
    }
    inputs
}

fn direct_call_target_va(statement: &Stmt) -> Option<u64> {
    match statement.semantic() {
        Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
        Stmt::Call { target, .. } => match target.semantic() {
            Expr::Named { va, .. } | Expr::Addr(va) => Some(*va),
            _ => None,
        },
        _ => None,
    }
}

/// The entry VAs of the relocation-proven function-pointer table this call
/// dispatches through, if it dispatches through one.
///
/// `function_tables::resolve_function_table_entries` has already replaced the
/// pointer-sized load with an [`Expr::FunctionTableEntry`] carrying the complete
/// target list, and it only does so when a real defined data symbol has an exact
/// relocation for EVERY slot resolving to an exact defined function symbol. The
/// completeness of that list is what makes a union over it sound; a partially
/// recovered table would not be a proof about the call at all.
fn table_call_target_vas(statement: &Stmt) -> Option<Vec<u64>> {
    fn entry_targets(expression: &Expr) -> Option<Vec<u64>> {
        match expression.semantic() {
            Expr::FunctionTableEntry { targets, .. } => {
                Some(targets.iter().map(|target| target.va).collect())
            }
            // The lowered target may be wrapped in a width cast or a pointer
            // conversion; neither changes which entry is selected.
            Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => entry_targets(expr),
            _ => None,
        }
    }
    match statement.semantic() {
        Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
        Stmt::Call { target, .. } => entry_targets(target),
        _ => None,
    }
}

/// The ABI argument registers a call through a proven function-pointer table
/// MAY read: the union over every entry's recovered parameter storage.
///
/// This is the whole reason the direct-call recovery does not generalise. A
/// direct call has one callee, so its recovered layout is an exact read set. An
/// indirect call has no callee to ask — but a call through a proven table has a
/// complete set of them, and the machine may transfer to any one. Passing the
/// registers of the widest entry is therefore the safe direction: an entry that
/// reads fewer of them is unaffected by the extra ones being live, while
/// passing fewer than some entry reads deletes an argument that entry consumes,
/// which is a silent wrong-code bug of exactly the kind
/// `docs/history/design/campaigns/table-dispatch-arguments-2026-08-12.md` records.
///
/// It fails closed on everything it cannot prove:
///
/// * an entry whose parameter storage was not recovered leaves the union
///   unknown — one unanalysed entry could read anything;
/// * the layouts must nest: each must be a prefix of the widest one under the
///   convention's own allocation order. Two entries that disagree about which
///   register holds parameter *n* have no common reading, and inventing one
///   would name storage some entry never reads; and
/// * the union must itself be a valid ABI allocation prefix.
fn table_call_may_use_layout(
    statement: &Stmt,
    arch: CallConv,
    table_entry_layouts: &std::collections::HashMap<u64, Vec<VReg>>,
) -> Option<Vec<VReg>> {
    let targets = table_call_target_vas(statement)?;
    if targets.is_empty() {
        return None;
    }
    let layouts = targets
        .iter()
        .map(|target| table_entry_layouts.get(target))
        .collect::<Option<Vec<_>>>()?;
    let widest = layouts.iter().copied().max_by_key(|layout| layout.len())?;
    if widest.is_empty() || !layout_matches_abi_allocation_order(arch, widest) {
        return None;
    }
    layouts
        .iter()
        .all(|layout| widest.starts_with(layout))
        .then(|| widest.clone())
}

/// Apply a proven table call's may-use set as the call's arguments.
///
/// Two ways to reach the values, in decreasing order of locality:
///
/// 1. the adjacent setup assignments, folded by `fold_one_recovered_layout_call`
///    exactly as for a locked direct callee; or
/// 2. the proven reaching definition of each slot, which is what an optimized
///    dispatcher needs — `-O2` shuffles the caller's own incoming registers into
///    place before a bounds check and calls from inside the guarded arm, so the
///    setup is in an enclosing scope and there is nothing adjacent to fold.
///
/// It is all-or-nothing. ABI arguments are a contiguous prefix, so a partially
/// proven union would silently drop the slots it could not name. Declining
/// leaves the ordinary backward scan's result untouched, which is the previous
/// behavior.
fn fold_one_table_call(
    body: &mut Vec<Stmt>,
    call_idx: usize,
    arch: CallConv,
    layout: &[VReg],
    param_slots: &std::collections::HashSet<usize>,
    enclosing: &EnclosingSlots,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> bool {
    if fold_one_recovered_layout_call(body, call_idx, layout, identities) {
        return true;
    }
    let mut blocked_here = vec![false; arg_slots(arch).len()];
    for statement in &body[..call_idx] {
        mark_arg_writes_in_stmt_with_identities(statement, arch, &mut blocked_here, identities);
    }
    let Some(arguments) = layout
        .iter()
        .map(|storage| {
            let VReg::Phys(name) = storage else {
                return None;
            };
            let slot = crate::ir::abi::argument_slot_of(arch, name)?;
            enclosing.reaching_value(slot, &blocked_here, param_slots)
        })
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    if let Stmt::Call { args, .. } = body[call_idx].semantic_mut() {
        *args = arguments;
        return true;
    }
    false
}

/// Fold a call setup according to a recovered callee's source-ordered storage.
///
/// This deliberately accepts only an adjacent, side-effect-free assignment
/// window. Moving a load-valued argument across a store or another call would
/// change its value, so less obvious shapes remain explicit until the AST owns
/// a full reaching-definition query.
fn fold_one_recovered_layout_call(
    body: &mut Vec<Stmt>,
    call_idx: usize,
    layout: &[VReg],
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> bool {
    if layout.is_empty() {
        return false;
    }
    let mut found: Vec<Option<(usize, Expr, VReg)>> = vec![None; layout.len()];
    let mut index = call_idx;
    while index > 0 && found.iter().any(Option::is_none) {
        index -= 1;
        match body[index].semantic() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::Assign { dst, src } => {
                let Some(slot) = layout.iter().position(|storage| {
                    let VReg::Phys(storage) = storage else {
                        return false;
                    };
                    register_is_storage(dst, ssa_base(storage), identities)
                }) else {
                    continue;
                };
                if found[slot].is_none() {
                    let mut argument = src.clone();
                    if let Some(origins) = body[index].origins() {
                        argument.merge_origins(origins);
                    }
                    found[slot] = Some((index, argument, dst.clone()));
                }
            }
            Stmt::Nop | Stmt::Comment(_) => {}
            _ => break,
        }
    }
    if found.iter().any(Option::is_none) {
        return false;
    }
    if found
        .iter()
        .flatten()
        .any(|(_, expression, _)| !is_pure_arg_normalisation(expression))
    {
        return false;
    }
    if !resolve_recovered_layout_sources(body, call_idx, &mut found, identities) {
        return false;
    }

    // Removing a setup assignment must not leave another captured expression
    // referring to that exact definition. Decline instead of inventing a
    // substitution across register banks.
    let removed: Vec<VReg> = found
        .iter()
        .flatten()
        .map(|(_, _, destination)| destination.clone())
        .collect();
    if found.iter().flatten().any(|(_, expression, _)| {
        removed
            .iter()
            .any(|destination| reads_reg_in_expr(expression, destination))
    }) {
        return false;
    }

    // Nor may it read a value-numbered register that is rewritten between the
    // setup and the call — see `versioned_operand_is_reassigned`. Declining here
    // falls back to the general backward scan, which keeps the setup in place
    // and names the argument register at the call.
    if found.iter().flatten().any(|(index, expression, _)| {
        versioned_operand_is_reassigned(expression, body, *index, call_idx, identities)
    }) {
        return false;
    }

    let arguments: Vec<Expr> = found
        .iter()
        .flatten()
        .map(|(_, expression, _)| expression.clone())
        .collect();
    if let Stmt::Call { args, .. } = body[call_idx].semantic_mut() {
        *args = arguments;
    } else {
        return false;
    }
    let mut used: Vec<usize> = found.iter().flatten().map(|(index, _, _)| *index).collect();
    let consumed_origins = used
        .iter()
        .filter_map(|index| body[*index].origins())
        .cloned()
        .reduce(|left, right| left.union(&right));
    if let Some(origins) = consumed_origins.as_ref() {
        body[call_idx].merge_origins(origins);
    }
    used.sort_unstable_by(|left, right| right.cmp(left));
    for index in used {
        body.remove(index);
    }
    true
}

/// Follow pure straight-line definitions feeding a recovered layout setup.
///
/// The layout scan stops once every ABI storage location has a nearest setup,
/// but those setup expressions can still name compiler-generated spill locals.
/// The ordinary argument fold already follows these exact definition edges;
/// doing the same here prevents a stronger callee-layout proof from degrading
/// `callee(arg0)` into `local = arg0; callee(local)`. A call, control boundary,
/// memory effect, impure definition, or intervening rewrite declines the
/// specialized fold and leaves the established general path in charge.
fn resolve_recovered_layout_sources(
    body: &[Stmt],
    call_idx: usize,
    found: &mut [Option<(usize, Expr, VReg)>],
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> bool {
    let Some(first_setup) = found.iter().flatten().map(|(index, _, _)| *index).min() else {
        return true;
    };
    for index in (0..first_setup).rev() {
        match body[index].semantic() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::Assign { dst, src } => {
                let promoted = identities.map_or_else(
                    || crate::ir::types::is_promoted_local_reg(dst),
                    |identities| identities.is_promoted_stack_object(dst),
                );
                if !promoted {
                    continue;
                }
                let feeds = found
                    .iter()
                    .flatten()
                    .any(|(_, argument, _)| reads_reg_in_expr(argument, dst));
                if !feeds {
                    continue;
                }
                if !is_pure_arg_normalisation(src)
                    || versioned_operand_is_reassigned(src, body, index, call_idx, identities)
                {
                    return false;
                }
                let definition_origins = body[index].origins().cloned();
                for (_, argument, _) in found.iter_mut().flatten() {
                    if substitute_exact_reg(argument, dst, src) {
                        if let Some(origins) = definition_origins.as_ref() {
                            argument.merge_origins(origins);
                        }
                    }
                }
            }
            Stmt::Nop | Stmt::Comment(_) => {}
            _ => break,
        }
    }
    true
}

/// Fold a recovered layout whose arguments mix adjacent setup assignments with
/// untouched caller parameters already occupying their ABI slots.
fn fold_one_recovered_layout_call_with_live_ins(
    body: &mut Vec<Stmt>,
    call_idx: usize,
    arch: CallConv,
    layout: &[VReg],
    param_slots: &std::collections::HashSet<usize>,
    enclosing: &EnclosingSlots,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> bool {
    if layout.is_empty() {
        return false;
    }
    let mut found: Vec<Option<(usize, Expr, VReg)>> = vec![None; layout.len()];
    let mut index = call_idx;
    while index > 0 {
        index -= 1;
        match body[index].semantic() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::Assign { dst, src } => {
                let Some(slot) = layout.iter().position(|storage| {
                    let VReg::Phys(storage) = storage else {
                        return false;
                    };
                    register_is_storage(dst, ssa_base(storage), identities)
                }) else {
                    continue;
                };
                if found[slot].is_none() {
                    let mut argument = src.clone();
                    if let Some(origins) = body[index].origins() {
                        argument.merge_origins(origins);
                    }
                    found[slot] = Some((index, argument, dst.clone()));
                }
            }
            Stmt::Nop | Stmt::Comment(_) => {}
            _ => break,
        }
    }
    if found.iter().all(Option::is_none) || found.iter().all(Option::is_some) {
        return false;
    }

    let storage_slots = arg_slots(arch).len() + crate::ir::abi::sse_argument_registers(arch).len();
    let mut blocked_storage = vec![false; storage_slots];
    for statement in &body[..call_idx] {
        mark_arg_writes_in_stmt_with_identities(statement, arch, &mut blocked_storage, identities);
        match statement.semantic() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::Assign { dst, .. } => {
                let sse_slot = match identities {
                    Some(identities) => identities.exact(dst).and_then(|identity| {
                        let name = identity.canonical_physical_base()?;
                        crate::ir::abi::sse_argument_slot_of(arch, name)
                    }),
                    None => {
                        let VReg::Phys(name) = dst else {
                            continue;
                        };
                        crate::ir::abi::sse_argument_slot_of(arch, name)
                    }
                };
                if let Some(slot) = sse_slot {
                    blocked_storage[arg_slots(arch).len() + slot] = true;
                }
            }
            Stmt::Call { .. } => blocked_storage.fill(true),
            _ => {}
        }
    }
    let mut arguments = Vec::with_capacity(layout.len());
    for (layout_index, storage) in layout.iter().enumerate() {
        if let Some((_, expression, _)) = &found[layout_index] {
            arguments.push(expression.clone());
            continue;
        }
        let VReg::Phys(name) = storage else {
            return false;
        };
        if let Some(value) = enclosing.reaching_storage_value(arch, name, &blocked_storage) {
            arguments.push(value);
            continue;
        }
        let Some(slot) = crate::ir::abi::argument_slot_of(arch, name) else {
            return false;
        };
        if !param_slots.contains(&slot)
            || blocked_storage[slot]
            || !enclosing.entry_value_reaches(slot)
        {
            return false;
        }
        arguments.push(
            enclosing
                .overrides
                .get(slot)
                .and_then(Clone::clone)
                .unwrap_or_else(|| Expr::Reg(storage.clone())),
        );
    }

    let removed: Vec<VReg> = found
        .iter()
        .flatten()
        .map(|(_, _, destination)| destination.clone())
        .collect();
    if found.iter().flatten().any(|(_, expression, _)| {
        removed
            .iter()
            .any(|destination| reads_reg_in_expr(expression, destination))
    }) || found.iter().flatten().any(|(index, expression, _)| {
        versioned_operand_is_reassigned(expression, body, *index, call_idx, identities)
    }) {
        return false;
    }

    if let Stmt::Call { args, .. } = body[call_idx].semantic_mut() {
        *args = arguments;
    } else {
        return false;
    }
    let mut used: Vec<usize> = found.iter().flatten().map(|(index, _, _)| *index).collect();
    let consumed_origins = used
        .iter()
        .filter_map(|index| body[*index].origins())
        .cloned()
        .reduce(|left, right| left.union(&right));
    if let Some(origins) = consumed_origins.as_ref() {
        body[call_idx].merge_origins(origins);
    }
    used.sort_unstable_by(|left, right| right.cmp(left));
    for index in used {
        body.remove(index);
    }
    true
}

fn is_pure_arg_normalisation(expr: &Expr) -> bool {
    match expr {
        Expr::Origin { expr, .. } => is_pure_arg_normalisation(expr),
        Expr::Deref { .. }
        | Expr::Call { .. }
        | Expr::FunctionTableEntry { .. }
        | Expr::Unknown(_) => false,
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            is_pure_arg_normalisation(lhs) && is_pure_arg_normalisation(rhs)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            is_pure_arg_normalisation(cond)
                && is_pure_arg_normalisation(if_true)
                && is_pure_arg_normalisation(if_false)
        }
        Expr::Un { src, .. } => is_pure_arg_normalisation(src),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
            is_pure_arg_normalisation(expr)
        }
        Expr::WideArithmetic { op, args, .. } => {
            matches!(
                op,
                crate::ir::ast::WideArithmetic::UnsignedMulHigh
                    | crate::ir::ast::WideArithmetic::SignedMulHigh
            ) && args.iter().all(is_pure_arg_normalisation)
        }
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => true,
    }
}

/// Width of `esp/rsp = esp/rsp - N`, if this is exactly a stack allocation.
#[cfg(test)]
pub(super) fn stack_pointer_sub_width(stmt: &Stmt) -> Option<i64> {
    stack_pointer_sub_width_with_identities(stmt, None)
}

pub(super) fn stack_pointer_sub_width_with_identities(
    stmt: &Stmt,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> Option<i64> {
    let Stmt::Assign { dst, src } = stmt.semantic() else {
        return None;
    };
    let Expr::Bin {
        op: BinOp::Sub,
        lhs,
        rhs,
    } = src.semantic()
    else {
        return None;
    };
    let stack = if register_is_storage(dst, "rsp", identities) {
        "rsp"
    } else if register_is_storage(dst, "esp", identities) {
        "esp"
    } else {
        return None;
    };
    if !matches!(lhs.semantic(), Expr::Reg(src) if register_is_storage(src, stack, identities)) {
        return None;
    }
    match rhs.semantic() {
        Expr::Const(width) if *width > 0 => Some(*width),
        _ => None,
    }
}

/// One exact SysV `push value` after lowering to stack arithmetic.
#[cfg(test)]
pub(super) fn outgoing_sysv_stack_push(body: &[Stmt], store_index: usize) -> Option<(&Expr, i64)> {
    outgoing_sysv_stack_push_with_identities(body, store_index, None)
}

pub(super) fn outgoing_sysv_stack_push_with_identities<'body>(
    body: &'body [Stmt],
    store_index: usize,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> Option<(&'body Expr, i64)> {
    if store_index == 0 {
        return None;
    }
    let Stmt::Store { addr, src, size: 8 } = body[store_index].semantic() else {
        return None;
    };
    let Expr::Lea {
        base: Some(base),
        index: None,
        disp: 0,
        ..
    } = addr.semantic()
    else {
        return None;
    };
    if !register_is_storage(base, "rsp", identities)
        || stack_pointer_sub_width_with_identities(&body[store_index - 1], identities) != Some(8)
    {
        return None;
    }
    Some((src, 8))
}

/// A contiguous preallocated SysV outgoing area immediately before a call.
///
/// Clang commonly reserves its whole frame once, then writes argument six to
/// `[rsp]` and argument seven to `[rsp+8]`. Integer values may be written as
/// four bytes into those eight-byte ABI slots. Requiring an uninterrupted,
/// zero-based slot layout distinguishes that call area from ordinary frame
/// locals and preserves ABI argument order independent of store order.
fn outgoing_sysv_stack_area(
    body: &[Stmt],
    call_index: usize,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> Option<(Vec<Expr>, Vec<usize>)> {
    let mut by_offset = std::collections::BTreeMap::new();
    let mut cursor = call_index;
    while cursor > 0 {
        let index = cursor - 1;
        match body[index].semantic() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::Store { addr, src, size } => {
                let Expr::Lea {
                    base: Some(base),
                    index: None,
                    disp,
                    ..
                } = addr.semantic()
                else {
                    break;
                };
                if !register_is_storage(base, "rsp", identities)
                    || *disp < 0
                    || *disp % 8 != 0
                    || !matches!(*size, 4 | 8)
                {
                    break;
                }
                // A `[rsp]` store paired with the immediately preceding
                // `rsp -= 8` is the push-form handled by the balanced-cleanup
                // path, not a preallocated outgoing area.
                if outgoing_sysv_stack_push_with_identities(body, index, identities).is_some() {
                    return None;
                }
                let mut value = src.clone();
                if let Some(origins) = body[index].origins() {
                    value.merge_origins(origins);
                }
                if by_offset.insert(*disp, (index, value)).is_some() {
                    return None;
                }
            }
            Stmt::Comment(_) | Stmt::Nop => {}
            _ => break,
        }
        cursor = index;
    }
    if by_offset.is_empty() {
        return None;
    }
    let mut args = Vec::new();
    let mut indices = Vec::new();
    for (slot, (offset, (index, value))) in by_offset.into_iter().enumerate() {
        if offset != i64::try_from(slot).ok()?.saturating_mul(8) {
            return None;
        }
        args.push(value);
        indices.push(index);
    }
    Some((args, indices))
}

/// Width of `rsp = rsp + N`, if this is exactly caller stack cleanup.
fn stack_pointer_add_width(
    stmt: &Stmt,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> Option<i64> {
    let Stmt::Assign { dst, src } = stmt.semantic() else {
        return None;
    };
    let Expr::Bin {
        op: BinOp::Add,
        lhs,
        rhs,
    } = src.semantic()
    else {
        return None;
    };
    if !register_is_storage(dst, "rsp", identities)
        || !matches!(lhs.semantic(), Expr::Reg(src) if register_is_storage(src, "rsp", identities))
    {
        return None;
    }
    match rhs.semantic() {
        Expr::Const(width) if *width > 0 => Some(*width),
        _ => None,
    }
}

/// Prove an exact post-call cleanup, including lowered `pop` pairs.
///
/// GCC may consume outgoing slots as `tmp = [rsp]; rsp += 8` instead of one
/// `rsp += N`. The caller supplies the exact byte count implied by the pushes,
/// so this stops as soon as that amount is balanced and never consumes the
/// following callee-save pop.
#[cfg(test)]
pub(super) fn outgoing_stack_cleanup(
    body: &[Stmt],
    call_index: usize,
    expected_bytes: i64,
) -> Option<Vec<usize>> {
    outgoing_stack_cleanup_with_identities(body, call_index, expected_bytes, None)
}

pub(super) fn outgoing_stack_cleanup_with_identities(
    body: &[Stmt],
    call_index: usize,
    expected_bytes: i64,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> Option<Vec<usize>> {
    if expected_bytes <= 0 {
        return None;
    }
    let mut cursor = call_index + 1;
    let mut cleaned = 0i64;
    let mut used = Vec::new();
    while cursor < body.len() {
        if cleaned == expected_bytes {
            return Some(used);
        }
        if let Some(width) = lowered_stack_pop_width(body, cursor, identities) {
            if cleaned.saturating_add(width) > expected_bytes {
                return None;
            }
            used.extend([cursor, cursor + 1]);
            cleaned += width;
            cursor += 2;
            continue;
        }
        if let Some(width) = stack_pointer_add_width(&body[cursor], identities) {
            if cleaned.saturating_add(width) != expected_bytes {
                return None;
            }
            used.push(cursor);
            cleaned += width;
            cursor += 1;
            continue;
        }
        match body[cursor].semantic() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::Assign { dst, .. } if register_is_storage(dst, "rsp", identities) => return None,
            Stmt::Assign { .. } | Stmt::Comment(_) | Stmt::Nop if cleaned == 0 => {
                cursor += 1;
            }
            _ => return None,
        }
    }
    (cleaned == expected_bytes).then_some(used)
}

fn lowered_stack_pop_width(
    body: &[Stmt],
    load_index: usize,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> Option<i64> {
    let Stmt::Assign { dst, src } = body.get(load_index)?.semantic() else {
        return None;
    };
    let Expr::Deref { addr, size } = src.semantic() else {
        return None;
    };
    let Expr::Lea {
        base: Some(base),
        index: None,
        disp: 0,
        ..
    } = addr.semantic()
    else {
        return None;
    };
    let width = i64::from(*size);
    (!register_is_storage(dst, "rsp", identities)
        && register_is_storage(base, "rsp", identities)
        && stack_pointer_add_width(body.get(load_index + 1)?, identities) == Some(width))
    .then_some(width)
}

pub(super) fn register_is_storage(
    register: &VReg,
    expected: &str,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> bool {
    match identities {
        Some(identities) => {
            let Some(candidates) = identities.candidates(register) else {
                return false;
            };
            !candidates.is_empty()
                && candidates
                    .iter()
                    .all(|identity| matches!(&identity.base, VReg::Phys(base) if base == expected))
        }
        None => matches!(register, VReg::Phys(name) if ssa_base(name) == expected),
    }
}

/// The ABI argument slot represented by one exact value identity.
///
/// A coalesced value is accepted only when every candidate denotes the same
/// slot. The spelling-based branch exists solely for compatibility callers
/// that do not carry the production identity sidecar.
pub(super) fn register_argument_slot(
    arch: CallConv,
    register: &VReg,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> Option<usize> {
    match identities {
        Some(identities) => {
            let candidates = identities.candidates(register)?;
            let mut slots = candidates.iter().map(|identity| {
                identity
                    .canonical_physical_base()
                    .and_then(|name| crate::ir::abi::argument_slot_of(arch, name))
            });
            let slot = slots.next()??;
            slots
                .all(|candidate| candidate == Some(slot))
                .then_some(slot)
        }
        None => match register {
            VReg::Phys(name) => crate::ir::abi::argument_slot_of(arch, name),
            _ => None,
        },
    }
}

/// Whether every exact candidate for `register` is ABI result storage.
pub(super) fn register_is_return_storage(
    arch: CallConv,
    register: &VReg,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> bool {
    match identities {
        Some(identities) => identities.candidates(register).is_some_and(|candidates| {
            !candidates.is_empty()
                && candidates.iter().all(|identity| {
                    identity
                        .canonical_physical_base()
                        .is_some_and(|name| crate::ir::abi::is_return_register(arch, name))
                })
        }),
        None => {
            matches!(register, VReg::Phys(name) if crate::ir::abi::is_return_register(arch, name))
        }
    }
}

/// Whether every exact candidate is the version-zero ABI result carrier.
pub(super) fn register_is_entry_return_storage(
    arch: CallConv,
    register: &VReg,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> bool {
    match identities {
        Some(identities) => identities.candidates(register).is_some_and(|candidates| {
            !candidates.is_empty()
                && candidates.iter().all(|identity| {
                    identity.version == 0
                        && identity
                            .canonical_physical_base()
                            .is_some_and(|name| crate::ir::abi::is_return_register(arch, name))
                })
        }),
        None => {
            matches!(register, VReg::Phys(name) if crate::ir::abi::is_return_register(arch, name) && !name.contains('#'))
        }
    }
}

/// A captured argument slot that must keep its defining statement: the value is
/// referenced by name at the call instead of being spliced into it.
const KEEP_ARG_SETUP: usize = usize::MAX;

/// Does any **value-numbered** register that `expr` reads get reassigned in
/// `body[from + 1 .. to]`?
///
/// Folding an argument setup into its call moves the whole expression forward
/// over everything in between, which is sound exactly when nothing it reads
/// changes there. For a `reg#version` name that used to be true by
/// construction — one static definition per value — so the backward scan
/// deliberately treats versioned scratch as statement-rooted and never repairs
/// it. `value_number::coalesce_phi_copies` ends that: a coalesced phi web is one
/// name with a definition per incoming edge, and a loop body routinely reads the
/// carried value, computes the next one, and writes it back before the call:
///
/// ```text
/// rdi#2 = (unsigned)rbx#1;      // the argument: this iteration's cursor
/// rbx#3 = rbx#1 + 1;
/// rbx#1 = (unsigned)rbx#3;      // the merged name now holds the NEXT cursor
/// call wrap_byte;               // ... and folding rdi#2 here reads it
/// ```
///
/// Measured on `11_call_shapes:gcc:O2:call_accumulate_bytes`, which accumulated
/// `wrap_byte(seed + i + 1)` instead of `wrap_byte(seed + i)`.
fn versioned_operand_is_reassigned(
    expr: &Expr,
    body: &[Stmt],
    from: usize,
    to: usize,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> bool {
    fn writes(
        statement: &Stmt,
        out: &mut Vec<VReg>,
        identities: Option<&crate::ir::value_number::ValueIdentities>,
    ) {
        let mut record = |register: &VReg| {
            if has_numbered_identity(register, identities) {
                out.push(register.clone());
            }
        };
        match statement.semantic() {
            Stmt::Origin { .. } => unreachable!("semantic statement cannot be an origin wrapper"),
            Stmt::Assign { dst, .. } | Stmt::Pop { target: dst } => record(dst),
            Stmt::Call { dst: Some(dst), .. } => record(dst),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                for s in then_body.iter().chain(else_body.iter().flatten()) {
                    writes(s, out, identities);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                for s in body {
                    writes(s, out, identities);
                }
            }
            Stmt::For {
                init, step, body, ..
            } => {
                writes(init, out, identities);
                writes(step, out, identities);
                for s in body {
                    writes(s, out, identities);
                }
            }
            Stmt::Switch { cases, default, .. } => {
                for s in cases
                    .iter()
                    .flat_map(|(_, b)| b)
                    .chain(default.iter().flatten())
                {
                    writes(s, out, identities);
                }
            }
            _ => {}
        }
    }
    let mut reassigned = Vec::new();
    for statement in &body[(from + 1).min(to)..to] {
        writes(statement, &mut reassigned, identities);
    }
    reassigned.iter().any(|register| {
        identities.map_or_else(
            || reads_reg_in_expr(expr, register),
            |identities| expr_reads_identity_candidate(expr, register, identities),
        )
    })
}

pub(super) fn has_numbered_identity(
    register: &VReg,
    identities: Option<&crate::ir::value_number::ValueIdentities>,
) -> bool {
    match identities {
        Some(identities) => identities
            .candidates(register)
            .is_some_and(|values| values.iter().any(|value| value.version > 0)),
        None => matches!(register, VReg::Phys(name) if name.contains('#')),
    }
}

fn expr_reads_identity_candidate(
    expression: &Expr,
    target: &VReg,
    identities: &crate::ir::value_number::ValueIdentities,
) -> bool {
    let Some(targets) = identities.candidates(target) else {
        return false;
    };
    let mut reads_same_value = |register: &VReg| {
        identities
            .candidates(register)
            .is_some_and(|reads| reads.iter().any(|value| targets.contains(value)))
    };
    any_reg_in_expr(expression, &mut reads_same_value)
}

fn any_reg_in_expr(expression: &Expr, visit: &mut impl FnMut(&VReg) -> bool) -> bool {
    match expression {
        Expr::Origin { expr, .. } => any_reg_in_expr(expr, visit),
        Expr::Reg(register) => visit(register),
        Expr::StackAddr { object, .. } => visit(object),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            base.as_ref().is_some_and(&mut *visit) || index.as_ref().is_some_and(&mut *visit)
        }
        Expr::Deref { addr, .. } => any_reg_in_expr(addr, visit),
        Expr::Call {
            target: call_target,
            args,
            ..
        } => {
            any_reg_in_expr(call_target, visit)
                || args.iter().any(|argument| any_reg_in_expr(argument, visit))
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            any_reg_in_expr(lhs, visit) || any_reg_in_expr(rhs, visit)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            any_reg_in_expr(cond, visit)
                || any_reg_in_expr(if_true, visit)
                || any_reg_in_expr(if_false, visit)
        }
        Expr::Un { src, .. } => any_reg_in_expr(src, visit),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => any_reg_in_expr(expr, visit),
        Expr::FunctionTableEntry { index, .. } => any_reg_in_expr(index, visit),
        Expr::WideArithmetic { args, .. } => {
            args.iter().any(|argument| any_reg_in_expr(argument, visit))
        }
    }
}

fn reads_reg_in_expr(e: &Expr, target: &VReg) -> bool {
    any_reg_in_expr(e, &mut |register| register == target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Function, OriginSet, Stmt};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }

    #[test]
    fn opaque_argument_reassignment_is_detected_by_value_identity() {
        let read = reg("opaque_read");
        let written = reg("opaque_write");
        let value = crate::ir::ssa::SsaValue {
            base: reg("rbx"),
            version: 3,
        };
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(read.clone(), value.clone());
        identities.record(written.clone(), value);
        let body = vec![
            Stmt::Comment("setup".into()),
            Stmt::Assign {
                dst: written,
                src: Expr::Const(2),
            },
            Stmt::Comment("call".into()),
        ];

        assert!(versioned_operand_is_reassigned(
            &Expr::Reg(read),
            &body,
            0,
            2,
            Some(&identities),
        ));
    }

    #[test]
    fn distinct_argument_identities_do_not_create_a_false_reassignment() {
        let read = reg("opaque_read");
        let written = reg("opaque_write");
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            read.clone(),
            crate::ir::ssa::SsaValue {
                base: reg("rbx"),
                version: 3,
            },
        );
        identities.record(
            written.clone(),
            crate::ir::ssa::SsaValue {
                base: reg("rbx"),
                version: 4,
            },
        );
        let body = vec![
            Stmt::Comment("setup".into()),
            Stmt::Assign {
                dst: written,
                src: Expr::Const(2),
            },
            Stmt::Comment("call".into()),
        ];

        assert!(!versioned_operand_is_reassigned(
            &Expr::Reg(read),
            &body,
            0,
            2,
            Some(&identities),
        ));
    }

    #[test]
    fn captured_scratch_numbering_comes_from_identity_not_spelling() {
        let opaque = reg("opaque_scratch");
        let misleading = reg("rax#99");
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            opaque.clone(),
            crate::ir::ssa::SsaValue {
                base: reg("rax"),
                version: 3,
            },
        );
        identities.record(
            misleading.clone(),
            crate::ir::ssa::SsaValue {
                base: reg("rdi"),
                version: 0,
            },
        );

        assert!(has_numbered_identity(&opaque, Some(&identities)));
        assert!(!has_numbered_identity(&misleading, Some(&identities)));
        assert!(has_numbered_identity(&misleading, None));
    }

    #[test]
    fn a_layout_that_skips_leading_slots_is_not_a_parameter_layout() {
        // AAPCS allocates core parameters r0, r1, r2, r3 in order, so `[r2, r3]`
        // cannot be any callee's first two parameters. It is what
        // `recover_direct_callee_layouts` produced for EVERY imported function of
        // `strip_iconv_arm-v7`: discovery does not stop at an ARM32 PLT stub's
        // `ldr pc,[ip,#n]!`, so the "callee" it lifts runs through the following
        // stubs into misdecoded bytes that read r2/r3.
        assert!(!layout_matches_abi_allocation_order(
            CallConv::Arm,
            &[reg("r2"), reg("r3")]
        ));
        // An AAPCS-VFP layout allocates from two independent banks; the core
        // registers inside it are still ordered from r0.
        assert!(layout_matches_abi_allocation_order(
            CallConv::ArmHardFloat,
            &[reg("r0"), reg("s0"), reg("r1")]
        ));
        assert!(!layout_matches_abi_allocation_order(
            CallConv::ArmHardFloat,
            &[reg("r1"), reg("s0"), reg("r0")]
        ));
        // The same order property holds for SysV's slot table.
        assert!(layout_matches_abi_allocation_order(
            CallConv::SysVAmd64,
            &[reg("rdi"), reg("rsi")]
        ));
        assert!(!layout_matches_abi_allocation_order(
            CallConv::SysVAmd64,
            &[reg("rdx"), reg("rcx")]
        ));
    }

    /// The rejection must reach the CALL, not just the predicate.
    ///
    /// [`a_layout_that_skips_leading_slots_is_not_a_parameter_layout`] pins the
    /// predicate; nothing pinned that `fold_one_call` actually consults it. With
    /// `[r2, r3]` trusted, the fold installed those two bare live-in registers as
    /// the argument list and returned before ever looking at the real r0/r1/r2
    /// setup — so ten distinct callees in `strip_iconv_arm-v7`'s `sub_6fc` all
    /// received the same two undefined locals, and no call-site value survived
    /// for string folding to see.
    #[test]
    fn an_impossible_callee_layout_does_not_displace_the_call_site_setup() {
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0x1000,
            body: vec![
                assign("r0", 11),
                assign("r1", 22),
                assign("r2", 33),
                call_to("getopt@plt"),
            ],
        };
        let layouts = std::collections::HashMap::from([(0x2000, vec![reg("r2"), reg("r3")])]);
        let mut parameter_slots = Default::default();

        reconstruct_args_with_params_and_callee_layouts(
            &mut f,
            CallConv::ArmHardFloat,
            &mut parameter_slots,
            &layouts,
        );

        let Stmt::Call { args, .. } = &f.body[0] else {
            panic!("setup did not fold into the call: {:#?}", f.body);
        };
        assert_eq!(
            args,
            &[Expr::Const(11), Expr::Const(22), Expr::Const(33)],
            "the call site's own argument setup is the evidence, not a layout \
             that no calling convention could have allocated"
        );
    }

    fn assign(dst: &str, value: i64) -> Stmt {
        Stmt::Assign {
            dst: reg(dst),
            src: Expr::Const(value),
        }
    }

    #[test]
    fn origin_wrapped_argument_setup_folds_into_origin_wrapped_call() {
        let first_owner = OriginSet::one(0x1000);
        let second_owner = OriginSet::one(0x1004);
        let call_owner = OriginSet::one(0x1008);
        let mut function = Function {
            name: "wrapped_caller".into(),
            entry_va: 0x1000,
            body: vec![
                assign("rdi", 11).with_origins(first_owner.clone()),
                assign("rsi", 22).with_origins(second_owner.clone()),
                call_to("callee").with_origins(call_owner.clone()),
            ],
        };

        reconstruct_args(&mut function, CallConv::SysVAmd64);

        assert_eq!(function.body.len(), 1);
        let Stmt::Call { args, .. } = function.body[0].semantic() else {
            panic!("expected folded call: {:#?}", function.body)
        };
        assert_eq!(args.len(), 2);
        assert!(matches!(args[0].semantic(), Expr::Const(11)));
        assert!(matches!(args[1].semantic(), Expr::Const(22)));
        assert_eq!(args[0].origins(), Some(&first_owner));
        assert_eq!(args[1].origins(), Some(&second_owner));
        assert_eq!(
            function.body[0]
                .origins()
                .expect("folded call retains setup and call origins")
                .addresses(),
            &[0x1000, 0x1004, 0x1008]
        );
    }

    #[test]
    fn transitive_argument_definition_origins_reach_the_folded_argument() {
        let source_owner = OriginSet::one(0x1010);
        let setup_owner = OriginSet::one(0x1014);
        let mut function = Function {
            name: "transitive_argument_origin".into(),
            entry_va: 0x1010,
            body: vec![
                Stmt::Assign {
                    dst: reg("var0"),
                    src: Expr::Const(17),
                }
                .with_origins(source_owner.clone()),
                Stmt::Assign {
                    dst: reg("rdi"),
                    src: Expr::Reg(reg("var0")),
                }
                .with_origins(setup_owner.clone()),
                call_to("callee").with_origins(OriginSet::one(0x1018)),
            ],
        };

        reconstruct_args(&mut function, CallConv::SysVAmd64);

        let call = function
            .body
            .iter()
            .find(|statement| matches!(statement.semantic(), Stmt::Call { .. }))
            .expect("folded call survives");
        let Stmt::Call { args, .. } = call.semantic() else {
            unreachable!()
        };
        assert_eq!(args.len(), 1);
        let (value, origins) = args[0].clone().into_semantic_with_origins();
        assert!(matches!(value, Expr::Const(17)));
        assert_eq!(origins, Some(source_owner.union(&setup_owner)));
    }

    /// An argument setup may only be folded into its call when nothing it reads
    /// changes in between. A coalesced phi web is one name with several
    /// definitions, so a loop that reads the carried value, computes the next
    /// one and writes it back before the call breaks that condition — and the
    /// hoist silently passed the NEXT iteration's value.
    #[test]
    fn an_argument_setup_is_not_hoisted_across_a_rewrite_of_what_it_reads() {
        let carried_then_call = || {
            vec![
                Stmt::Assign {
                    dst: reg("rdi#2"),
                    src: Expr::Reg(reg("rbx#1")),
                },
                Stmt::Assign {
                    dst: reg("rbx#3"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("rbx#1"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                },
                // The merged name now holds the NEXT cursor.
                Stmt::Assign {
                    dst: reg("rbx#1"),
                    src: Expr::Reg(reg("rbx#3")),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1090,
                        name: "wrap_byte".to_string(),
                    },
                    args: vec![],
                    dst: None,
                    call_spec: None,
                },
            ]
        };
        let mut f = Function {
            name: "caller".to_string(),
            entry_va: 0x1000,
            body: carried_then_call(),
        };
        let mut slots = std::collections::HashSet::new();
        reconstruct_args_with_params_and_callee_layouts(
            &mut f,
            CallConv::SysVAmd64,
            &mut slots,
            &Default::default(),
        );
        let call = f.body.last().expect("the call must survive");
        let Stmt::Call { args, .. } = call else {
            panic!("expected a call, got {call:?}");
        };
        assert_eq!(
            args,
            &vec![Expr::Reg(reg("rdi#2"))],
            "the argument must stay named, not be replaced by an expression \
             reading a register rewritten after it: {:#?}",
            f.body
        );
        assert!(
            f.body.iter().any(|s| matches!(
                s,
                Stmt::Assign { dst, src: Expr::Reg(source) }
                    if dst == &reg("rdi#2") && source == &reg("rbx#1")
            )),
            "and its defining statement must stay where it is: {:#?}",
            f.body
        );

        // Without the intervening rewrite the setup still folds into the call —
        // this rule must not turn every argument into a named temporary.
        let mut foldable = carried_then_call();
        foldable.remove(2);
        let mut f = Function {
            name: "caller".to_string(),
            entry_va: 0x1000,
            body: foldable,
        };
        let mut slots = std::collections::HashSet::new();
        reconstruct_args_with_params_and_callee_layouts(
            &mut f,
            CallConv::SysVAmd64,
            &mut slots,
            &Default::default(),
        );
        let Some(Stmt::Call { args, .. }) = f.body.last() else {
            panic!("expected a call: {:#?}", f.body);
        };
        assert_eq!(
            args,
            &vec![Expr::Reg(reg("rbx#1"))],
            "an unobstructed setup must still be spliced into the call: {:#?}",
            f.body
        );
    }

    #[test]
    fn an_origin_wrapped_argument_setup_is_not_hoisted_across_a_wrapped_rewrite() {
        let mut function = Function {
            name: "recursive".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: reg("rdi#10"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("r12#9"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                }
                .with_origins(crate::ir::ast::OriginSet::one(0x1000)),
                Stmt::Assign {
                    dst: reg("r12#9"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("r12#9"))),
                        rhs: Box::new(Expr::Const(2)),
                    },
                }
                .with_origins(crate::ir::ast::OriginSet::one(0x1004)),
                call_to("recursive").with_origins(crate::ir::ast::OriginSet::one(0x1008)),
            ],
        };

        reconstruct_args(&mut function, CallConv::SysVAmd64);

        assert_eq!(function.body.len(), 3);
        assert!(matches!(
            function.body[2].semantic(),
            Stmt::Call { args, .. } if args == &[Expr::Reg(reg("rdi#10"))]
        ));
    }

    #[test]
    fn reconstructs_arguments_inside_switch_cases_and_default() {
        let call = || Stmt::Call {
            target: Expr::Named {
                va: 0x4000,
                name: "callee".into(),
            },
            args: Vec::new(),
            dst: None,
            call_spec: None,
        };
        let arm = |left, right| vec![assign("rdi#1", left), assign("rsi#1", right), call()];
        let mut function = Function {
            name: "dispatch".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Switch {
                discriminant: Expr::Reg(reg("rax")),
                cases: vec![(Some(0), arm(10, 20))],
                default: Some(arm(30, 40)),
            }],
        };

        reconstruct_args(&mut function, CallConv::SysVAmd64);

        let Stmt::Switch { cases, default, .. } = &function.body[0] else {
            panic!("expected switch, got {:#?}", function.body);
        };
        let call_args = |body: &[Stmt]| match body.last() {
            Some(Stmt::Call { args, .. }) => args.clone(),
            other => panic!("expected arm call, got {other:#?}"),
        };
        assert_eq!(
            call_args(&cases[0].1),
            vec![Expr::Const(10), Expr::Const(20)]
        );
        assert_eq!(
            call_args(default.as_deref().expect("default arm")),
            vec![Expr::Const(30), Expr::Const(40)]
        );
    }

    #[test]
    fn folds_first_arg_before_direct_call() {
        // %rdi = 0x13d0 ; call main
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 0x13d0),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "main".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 1, "assign not absorbed: {:?}", f.body);
        if let Stmt::Call { args, .. } = &f.body[0] {
            assert_eq!(args.len(), 1);
            assert_eq!(args[0], Expr::Const(0x13d0));
        } else {
            panic!("expected Call, got {:?}", f.body[0]);
        }
    }

    #[test]
    fn folds_multiple_args_in_conventional_order() {
        // %rdi = 1 ; %rsi = 2 ; %rdx = 3 ; call foo
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 1),
                assign("rsi", 2),
                assign("rdx", 3),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 1);
        if let Stmt::Call { args, .. } = &f.body[0] {
            assert_eq!(args.len(), 3);
            assert_eq!(args[0], Expr::Const(1));
            assert_eq!(args[1], Expr::Const(2));
            assert_eq!(args[2], Expr::Const(3));
        }
    }

    #[test]
    fn call_argument_scan_stops_at_a_labelled_control_flow_edge() {
        let mut f = Function {
            name: "stack_check_join".into(),
            entry_va: 0,
            body: vec![
                assign("rdi#1", 1),
                assign("rsi#1", 2),
                Stmt::Goto { target: 0x1204 },
                Stmt::Label(0x125a),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1050,
                        name: "__stack_chk_fail".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        assert!(
            matches!(&f.body[0], Stmt::Assign { dst, .. } if dst == &reg("rdi#1")),
            "an assignment on the goto predecessor was consumed: {f:#?}"
        );
        assert!(
            matches!(&f.body[1], Stmt::Assign { dst, .. } if dst == &reg("rsi#1")),
            "an assignment on the goto predecessor was consumed: {f:#?}"
        );
        assert!(matches!(
            f.body.last(),
            Some(Stmt::Call { args, .. }) if args.is_empty()
        ));
    }

    /// A branch arm that always transfers control away is not on the path into
    /// the statement after it, so the argument registers it clobbers cannot
    /// reach a following call.
    ///
    /// This is the shape `gcc -O2` gives `189_effectful_select:se189_select_call`:
    /// one call per arm of a diamond, the taken arm returning directly, and the
    /// fall-through call reusing the untouched incoming `rdi`. Treating the
    /// returning arm's `esi`/`rdi` clobbers as reaching the second call blocked
    /// its slot-zero backfill, and because ABI arguments are a contiguous
    /// prefix the recovered `esi` argument was dropped with it — emitting
    /// `se189_bump()` for a callee declared `(int *, int)`, which then
    /// incremented whatever the argument register happened to hold.
    #[test]
    fn a_returning_branch_arm_does_not_clobber_the_next_calls_incoming_arguments() {
        let arm_call = |setup: &str| {
            vec![
                Stmt::Assign {
                    dst: reg("esi"),
                    src: Expr::Reg(reg(setup)),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1050,
                        name: "se189_bump".into(),
                    },
                    args: Vec::new(),
                    dst: Some(reg("rax")),
                    call_spec: None,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rax"))),
                },
            ]
        };
        let mut f = Function {
            name: "se189_select_call".into(),
            entry_va: 0x1140,
            body: vec![
                Stmt::Assign {
                    dst: reg("rbx"),
                    src: Expr::Reg(reg("rdi")),
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: crate::ir::types::CmpOp::Ne,
                        lhs: Box::new(Expr::Reg(reg("esi"))),
                        rhs: Box::new(Expr::Const(0)),
                    },
                    then_body: arm_call("edx"),
                    else_body: None,
                },
                Stmt::Assign {
                    dst: reg("esi"),
                    src: Expr::Reg(reg("ecx")),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1050,
                        name: "se189_bump".into(),
                    },
                    args: Vec::new(),
                    dst: Some(reg("rax")),
                    call_spec: None,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rax"))),
                },
            ],
        };

        reconstruct_args_with_params(&mut f, CallConv::SysVAmd64, &[0, 1].into_iter().collect());

        let Stmt::If { then_body, .. } = &f.body[1] else {
            panic!("the branch was rewritten: {f:#?}");
        };
        assert!(
            matches!(&then_body[0], Stmt::Call { args, .. } if args.len() == 2),
            "the returning arm's own call lost its arguments: {f:#?}"
        );
        let fallthrough = f
            .body
            .iter()
            .skip(2)
            .find_map(|statement| match statement {
                Stmt::Call { args, .. } => Some(args.clone()),
                _ => None,
            })
            .expect("the fall-through call disappeared");
        assert_eq!(
            fallthrough,
            vec![Expr::Reg(reg("rdi")), Expr::Reg(reg("ecx"))],
            "the fall-through call did not recover its reaching arguments: {f:#?}"
        );
    }

    /// The value-numbered shape of the same defect, which is what the DecBench
    /// render path actually sees.
    ///
    /// `value_number` leaves the live-in version bare (`rdi`) and versions every
    /// later definition (`rsi#2`). Inside a branch arm the untouched `rdi` has no
    /// mention at all, so the arm-local `incoming_arg_expr` declined, slot zero
    /// stayed empty, and the ABI contiguous-prefix rule then discarded the `rsi`
    /// argument the same scan HAD recovered — `se189_bump()` for a callee
    /// declared `(int *, int)`.
    ///
    /// The negative control is the second arm: an enclosing write to `rdi` on
    /// the path in must still refuse the backfill.
    #[test]
    fn a_call_in_a_branch_arm_recovers_the_functions_own_live_in_parameter() {
        let arm = |setup: &str| {
            vec![
                Stmt::Assign {
                    dst: reg(setup),
                    src: Expr::Reg(reg("rdx")),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1050,
                        name: "se189_bump".into(),
                    },
                    args: Vec::new(),
                    dst: Some(reg("rax#2")),
                    call_spec: None,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rax#2"))),
                },
            ]
        };
        let function = |prefix: Vec<Stmt>| Function {
            name: "se189_select_call".into(),
            entry_va: 0x1140,
            body: [
                prefix,
                vec![
                    Stmt::Store {
                        addr: Expr::Reg(reg("rdi")),
                        src: Expr::Const(0),
                        size: 4,
                    },
                    Stmt::If {
                        cond: Expr::Cmp {
                            op: crate::ir::types::CmpOp::Ne,
                            lhs: Box::new(Expr::Reg(reg("rsi"))),
                            rhs: Box::new(Expr::Const(0)),
                        },
                        then_body: arm("rsi#2"),
                        else_body: None,
                    },
                    Stmt::Return { value: None },
                ],
            ]
            .concat(),
        };
        let arm_args = |f: &Function| match &f.body[f.body.len() - 2] {
            Stmt::If { then_body, .. } => then_body
                .iter()
                .find_map(|statement| match statement {
                    Stmt::Call { args, .. } => Some(args.clone()),
                    _ => None,
                })
                .expect("the arm's call disappeared"),
            other => panic!("the branch was rewritten: {other:#?}"),
        };

        let mut recovered = function(vec![Stmt::Assign {
            dst: reg("rbx#1"),
            src: Expr::Reg(reg("rdi")),
        }]);
        reconstruct_args_with_params(
            &mut recovered,
            CallConv::SysVAmd64,
            &[0, 1].into_iter().collect(),
        );
        assert_eq!(
            arm_args(&recovered),
            vec![Expr::Reg(reg("rdi")), Expr::Reg(reg("rdx"))],
            "the branch arm did not recover the live-in first parameter: {recovered:#?}"
        );

        // Negative control: the enclosing scope overwrote slot zero, so the
        // function-entry value no longer reaches the nested call.
        let mut clobbered = function(vec![Stmt::Assign {
            dst: reg("rdi"),
            src: Expr::Const(7),
        }]);
        reconstruct_args_with_params(
            &mut clobbered,
            CallConv::SysVAmd64,
            &[0, 1].into_iter().collect(),
        );
        assert!(
            arm_args(&clobbered).is_empty(),
            "a clobbered slot zero was still backfilled from function entry: {clobbered:#?}"
        );
    }

    #[test]
    fn exact_sse_layout_uses_enclosing_whole_register_definitions() {
        let mut function = Function {
            name: "complex_helper_caller".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: reg("xmm1#1"),
                    src: Expr::Reg(reg("ai_value")),
                },
                Stmt::Assign {
                    dst: reg("xmm1_d1#1"),
                    src: Expr::Reg(reg("xmm1#1")),
                },
                Stmt::Assign {
                    dst: reg("xmm2#1"),
                    src: Expr::Reg(reg("br_value")),
                },
                Stmt::Assign {
                    dst: reg("xmm3#1"),
                    src: Expr::Reg(reg("bi_value")),
                },
                Stmt::If {
                    cond: Expr::Reg(reg("needs_helper")),
                    then_body: vec![
                        Stmt::Assign {
                            dst: reg("xmm0#2"),
                            src: Expr::Reg(reg("ar_value")),
                        },
                        call_to("__muldc3"),
                    ],
                    else_body: None,
                },
            ],
        };
        let layouts = std::collections::HashMap::from([(
            0x2000,
            ["xmm0", "xmm1", "xmm2", "xmm3"].map(reg).to_vec(),
        )]);
        reconstruct_args_with_params_and_callee_layouts(
            &mut function,
            CallConv::SysVAmd64,
            &mut Default::default(),
            &layouts,
        );
        let Stmt::If { then_body, .. } = &function.body[4] else {
            panic!("branch disappeared: {function:#?}")
        };
        let Stmt::Call { args, .. } = &then_body[0] else {
            panic!("setup did not fold: {then_body:#?}")
        };
        assert_eq!(
            args,
            &[
                Expr::Reg(reg("ar_value")),
                Expr::Reg(reg("xmm1#1")),
                Expr::Reg(reg("xmm2#1")),
                Expr::Reg(reg("xmm3#1")),
            ]
        );
    }

    /// `gcc -O2` structures a nested diamond as labelled goto targets, so the
    /// call sits directly after a `Stmt::Label` join and the backward scan stops
    /// dead. `189_effectful_select:gcc:O2:se189_nested_select` is that shape.
    ///
    /// A whole-function proof answers slot zero anyway when nothing writes it
    /// and every call runs straight into a return, so no call's ABI clobber can
    /// precede another. The controls check both halves of that proof.
    #[test]
    fn a_labelled_call_uses_a_slot_the_whole_function_never_redefines() {
        // `extra` lands on the OTHER predecessor of the join, which is exactly
        // where the local backward scan cannot see it.
        let labelled = |extra: Vec<Stmt>| {
            let mut body = vec![Stmt::Store {
                addr: Expr::Reg(reg("rdi")),
                src: Expr::Const(0),
                size: 4,
            }];
            body.extend(extra);
            body.extend([
                Stmt::Goto { target: 0x1220 },
                Stmt::Label(0x1220),
                Stmt::Assign {
                    dst: reg("rsi#4"),
                    src: Expr::Reg(reg("r8d")),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1050,
                        name: "se189_bump".into(),
                    },
                    args: Vec::new(),
                    dst: Some(reg("rax#1")),
                    call_spec: None,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rax#1"))),
                },
            ]);
            Function {
                name: "se189_nested_select".into(),
                entry_va: 0x11d0,
                body,
            }
        };
        let call_args = |f: &Function| {
            f.body
                .iter()
                .find_map(|statement| match statement {
                    Stmt::Call { args, .. } => Some(args.clone()),
                    _ => None,
                })
                .expect("the call disappeared")
        };

        let mut recovered = labelled(Vec::new());
        reconstruct_args_with_params(
            &mut recovered,
            CallConv::SysVAmd64,
            &[0, 1].into_iter().collect(),
        );
        assert_eq!(
            call_args(&recovered),
            vec![Expr::Reg(reg("rdi")), Expr::Reg(reg("r8d"))],
            "a never-redefined slot zero was not recovered across the join: {recovered:#?}"
        );

        // Control one: something in the function writes the slot, so no path
        // argument can be made from the register name.
        let mut written = labelled(vec![Stmt::Assign {
            dst: reg("rdi#1"),
            src: Expr::Const(3),
        }]);
        reconstruct_args_with_params(
            &mut written,
            CallConv::SysVAmd64,
            &[0, 1].into_iter().collect(),
        );
        assert!(
            call_args(&written).is_empty(),
            "a redefined slot zero was recovered across the join: {written:#?}"
        );

        // Control two: another call exists that does NOT run straight into a
        // return, so its ABI clobber may precede this one.
        let mut clobbered = labelled(vec![Stmt::Call {
            target: Expr::Named {
                va: 0x1060,
                name: "other".into(),
            },
            args: Vec::new(),
            dst: None,
            call_spec: None,
        }]);
        reconstruct_args_with_params(
            &mut clobbered,
            CallConv::SysVAmd64,
            &[0, 1].into_iter().collect(),
        );
        assert!(
            call_args(&clobbered).is_empty(),
            "a slot a preceding call clobbers was recovered: {clobbered:#?}"
        );
    }

    #[test]
    fn consumed_prior_call_result_gets_a_distinct_value_before_scratch_reuse() {
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "producer".into(),
                    },
                    args: Vec::new(),
                    dst: Some(reg("rax")),
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: reg("rdi"),
                    src: Expr::Reg(reg("rax")),
                },
                assign("rax", 99),
                assign("rsi", 2),
                call_to("consumer"),
            ],
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        let producer_result = f.body.iter().find_map(|statement| match statement {
            Stmt::Call {
                target: Expr::Named { name, .. },
                dst: Some(result),
                ..
            } if name == "producer" => Some(result.clone()),
            _ => None,
        });
        let consumer_first = f.body.iter().find_map(|statement| match statement {
            Stmt::Call {
                target: Expr::Named { name, .. },
                args,
                ..
            } if name == "consumer" => args.first().cloned(),
            _ => None,
        });
        let Some(result) = producer_result else {
            panic!("producer result was not attributed: {f:#?}");
        };
        assert_ne!(
            result,
            reg("rax"),
            "the result needs its own value identity"
        );
        assert_eq!(consumer_first, Some(Expr::Reg(result)));
    }

    #[test]
    fn preceding_call_result_uses_exact_identity_not_display_spelling() {
        let caller = |result: &str| Function {
            name: "caller".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "producer".into(),
                    },
                    args: Vec::new(),
                    dst: Some(reg(result)),
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: reg("rdi"),
                    src: Expr::Reg(reg(result)),
                },
                call_to("consumer"),
            ],
        };
        let run = |mut function: Function,
                   identities: &crate::ir::value_number::ValueIdentities| {
            reconstruct_args_with_layouts_prototypes_strings_and_identities(
                &mut function,
                CallConv::SysVAmd64,
                &mut Default::default(),
                &Default::default(),
                &Default::default(),
                None,
                &Default::default(),
                identities,
            );
            function
        };
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            reg("opaque_result"),
            crate::ir::ssa::SsaValue {
                base: reg("rax"),
                version: 1,
            },
        );
        identities.record(
            reg("rax#looks_like_result"),
            crate::ir::ssa::SsaValue {
                base: reg("rdi"),
                version: 0,
            },
        );
        identities.record(
            reg("opaque_entry_result"),
            crate::ir::ssa::SsaValue {
                base: reg("rax"),
                version: 0,
            },
        );
        identities.record(
            reg("rdi"),
            crate::ir::ssa::SsaValue {
                base: reg("rdi"),
                version: 2,
            },
        );

        let exact = run(caller("opaque_result"), &identities);
        assert!(
            exact.body.iter().any(|statement| matches!(
                statement.semantic(),
                Stmt::Call { target: Expr::Named { name, .. }, args, .. }
                    if name == "consumer" && args == &[Expr::Reg(reg("opaque_result"))]
            )),
            "exact result was not preserved: {exact:#?}"
        );

        let misleading = run(caller("rax#looks_like_result"), &identities);
        assert!(misleading.body.iter().any(|statement| matches!(
            statement.semantic(),
            Stmt::Call { target: Expr::Named { name, .. }, args, .. }
                if name == "consumer" && args == &[Expr::Reg(reg("rax#looks_like_result"))]
        )));
        assert!(matches!(
            misleading.body.first().map(Stmt::semantic),
            Some(Stmt::Call { dst: Some(result), .. }) if result == &reg("rax#looks_like_result")
        ));

        let entry = run(caller("opaque_entry_result"), &identities);
        let producer_result = entry
            .body
            .iter()
            .find_map(|statement| match statement.semantic() {
                Stmt::Call {
                    target: Expr::Named { name, .. },
                    dst: Some(result),
                    ..
                } if name == "producer" => Some(result.clone()),
                _ => None,
            });
        let consumer_argument =
            entry
                .body
                .iter()
                .find_map(|statement| match statement.semantic() {
                    Stmt::Call {
                        target: Expr::Named { name, .. },
                        args,
                        ..
                    } if name == "consumer" => args.first().cloned(),
                    _ => None,
                });
        let result = producer_result.expect("producer result must remain explicit");
        assert_ne!(result, reg("opaque_entry_result"));
        assert_eq!(consumer_argument, Some(Expr::Reg(result)));
    }

    #[test]
    fn pushed_arguments_keep_the_prior_call_result_distinct_from_rax_setup() {
        let adjust_rsp = |op, width| Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(width)),
            },
        };
        let push_rax = || Stmt::Store {
            addr: Expr::Lea {
                base: Some(reg("rsp")),
                index: None,
                scale: 1,
                disp: 0,
                segment: None,
            },
            src: Expr::Reg(reg("rax")),
            size: 8,
        };
        let pop_pair = |dst| {
            [
                Stmt::Assign {
                    dst: reg(dst),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Lea {
                            base: Some(reg("rsp")),
                            index: None,
                            scale: 1,
                            disp: 0,
                            segment: None,
                        }),
                        size: 8,
                    },
                },
                adjust_rsp(BinOp::Add, 8),
            ]
        };
        let from = |name, addend| Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::Reg(reg(name))),
            rhs: Box::new(Expr::Const(addend)),
        };
        let mut body = vec![
            call_to("producer"),
            Stmt::Assign {
                dst: reg("rcx"),
                src: Expr::Const(3),
            },
            assign("r9", 5),
            assign("rsi", 1),
            Stmt::Assign {
                dst: reg("rdi#1"),
                src: Expr::Reg(reg("rax")),
            },
            Stmt::Assign {
                dst: reg("rdx"),
                src: from("rax", 1),
            },
            assign("rax", 7),
            adjust_rsp(BinOp::Sub, 8),
            push_rax(),
            Stmt::Assign {
                dst: reg("rax"),
                src: from("rdi#1", 5),
            },
            Stmt::Assign {
                dst: reg("r8"),
                src: from("rdi#1", 3),
            },
            adjust_rsp(BinOp::Sub, 8),
            push_rax(),
            call_to("consumer"),
        ];
        body.extend(pop_pair("rdx"));
        body.extend(pop_pair("rcx"));
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body,
        };
        let mut slots = [1].into_iter().collect();

        reconstruct_args_with_params_and_callee_layouts(
            &mut f,
            CallConv::SysVAmd64,
            &mut slots,
            &Default::default(),
        );

        let result = f.body.iter().find_map(|statement| match statement {
            Stmt::Call {
                target: Expr::Named { name, .. },
                dst: Some(result),
                ..
            } if name == "producer" => Some(result.clone()),
            _ => None,
        });
        let consumer_args = f.body.iter().find_map(|statement| match statement {
            Stmt::Call {
                target: Expr::Named { name, .. },
                args,
                ..
            } if name == "consumer" => Some(args),
            _ => None,
        });
        let Some(result) = result else {
            panic!("producer result was not attributed: {f:#?}");
        };
        let args = consumer_args.expect("consumer call must survive");
        assert_eq!(args.len(), 8, "stack suffix did not fold: {f:#?}");
        assert!(args
            .iter()
            .any(|argument| reads_reg_in_expr(argument, &result)));
        assert!(slots.contains(&0), "implicit parameter was not fed back");
    }

    #[test]
    fn first_value_producing_call_forwards_an_untouched_leading_parameter() {
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rbp#1"),
                    src: Expr::Reg(reg("rsi#1")),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "signed_step".into(),
                    }
                    .with_origins(OriginSet::one(0x1010)),
                    args: Vec::new(),
                    dst: Some(reg("rax")),
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: reg("rbx"),
                    src: Expr::Reg(reg("rax")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rbx"))),
                },
            ],
        };

        reconstruct_args_with_params(&mut f, CallConv::SysVAmd64, &[0, 1].into_iter().collect());

        let args = f.body.iter().find_map(|statement| match statement {
            Stmt::Call { target, args, .. }
                if matches!(target.semantic(), Expr::Named { name, .. } if name == "signed_step") =>
            {
                Some(args)
            }
            _ => None,
        });
        assert_eq!(args, Some(&vec![Expr::Reg(reg("rdi"))]));
    }

    /// The AAPCS shape of the test above, as
    /// `arm-linux-gnueabihf-gcc -O2 -mthumb` emits
    /// `11_call_shapes:call_result_drives_branch`: the incoming parameter is
    /// already in `r0`, so the call has no argument setup at all and used to
    /// render as `signed_step()`.
    #[test]
    fn an_aapcs_zero_setup_call_forwards_the_incoming_first_parameter() {
        let mut f = Function {
            name: "call_result_drives_branch".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("sp")),
                        index: None,
                        scale: 1,
                        disp: 0,
                        segment: None,
                    },
                    src: Expr::Reg(reg("lr")),
                    size: 4,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "signed_step".into(),
                    }
                    .with_origins(OriginSet::one(0x1014)),
                    args: Vec::new(),
                    dst: Some(reg("rax")),
                    call_spec: None,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("r0"))),
                },
            ],
        };

        reconstruct_args_with_params(&mut f, CallConv::ArmHardFloat, &[0].into_iter().collect());

        let args = f.body.iter().find_map(|statement| match statement {
            Stmt::Call { target, args, .. }
                if matches!(target.semantic(), Expr::Named { name, .. } if name == "signed_step") =>
            {
                Some(args)
            }
            _ => None,
        });
        assert_eq!(args, Some(&vec![Expr::Reg(reg("r0"))]));
    }

    #[test]
    fn call_inside_loop_uses_the_loop_carried_argument_value() {
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rdi#1"),
                    src: Expr::Reg(reg("rdi")),
                },
                Stmt::DoWhile {
                    body: vec![
                        call_to("signed_step"),
                        Stmt::Assign {
                            dst: reg("rdi#2"),
                            src: Expr::Reg(reg("rax")),
                        },
                        Stmt::Assign {
                            dst: reg("rdi#1"),
                            src: Expr::Reg(reg("rdi#2")),
                        },
                    ],
                    cond: Expr::Const(1),
                },
            ],
        };

        let layouts = std::collections::HashMap::from([(0x2000, vec![reg("rdi")])]);
        reconstruct_args_with_params_and_callee_layouts(
            &mut f,
            CallConv::SysVAmd64,
            &mut [0].into_iter().collect(),
            &layouts,
        );

        let Stmt::DoWhile { body, .. } = &f.body[1] else {
            panic!("expected loop: {f:#?}");
        };
        let args = body.iter().find_map(|statement| match statement {
            Stmt::Call {
                target: Expr::Named { name, .. },
                args,
                ..
            } if name == "signed_step" => Some(args),
            _ => None,
        });
        assert_eq!(args, Some(&vec![Expr::Reg(reg("rdi#1"))]));
    }

    #[test]
    fn loop_carried_input_uses_exact_identity_not_display_spelling() {
        let loop_with = |name: &str| {
            vec![
                call_to("signed_step"),
                Stmt::Assign {
                    dst: reg(name),
                    src: Expr::Reg(reg("rax")),
                },
            ]
        };
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            reg("opaque_init"),
            crate::ir::ssa::SsaValue {
                base: reg("rdi"),
                version: 1,
            },
        );
        identities.record(
            reg("opaque_loop"),
            crate::ir::ssa::SsaValue {
                base: reg("rdi"),
                version: 1,
            },
        );
        identities.record(
            reg("rdi#1"),
            crate::ir::ssa::SsaValue {
                base: reg("rax"),
                version: 1,
            },
        );

        let exact = loop_carried_arg_inputs(
            &[Stmt::Assign {
                dst: reg("opaque_init"),
                src: Expr::Reg(reg("rdi")),
            }],
            &loop_with("opaque_loop"),
            CallConv::SysVAmd64,
            &[None],
            Some(&identities),
        );
        assert_eq!(exact[0], Some(Expr::Reg(reg("opaque_loop"))));
        assert!(exact[1..].iter().all(Option::is_none));

        let misleading = loop_carried_arg_inputs(
            &[Stmt::Assign {
                dst: reg("rdi#1"),
                src: Expr::Reg(reg("rdi")),
            }],
            &loop_with("rdi#1"),
            CallConv::SysVAmd64,
            &[None],
            Some(&identities),
        );
        assert!(misleading.iter().all(Option::is_none));
    }

    /// AArch64 reuses x0 for both the first argument and the return value. GCC
    /// therefore emits no setup instruction for a loop-carried `callee(x0)`:
    /// the phi value is already in the right storage when `bl` executes.
    #[test]
    fn aarch64_call_inside_loop_uses_the_loop_carried_x0_value() {
        let mut f = Function {
            name: "call_chain_in_loop".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("x0#1"),
                    src: Expr::Reg(reg("x0")),
                },
                Stmt::DoWhile {
                    body: vec![
                        call_to("signed_step"),
                        Stmt::Assign {
                            dst: reg("x0#3"),
                            src: Expr::Bin {
                                op: BinOp::Add,
                                lhs: Box::new(Expr::Reg(reg("x0"))),
                                rhs: Box::new(Expr::Reg(reg("x19#2"))),
                            },
                        },
                        Stmt::Assign {
                            dst: reg("x0#1"),
                            src: Expr::Reg(reg("x0#3")),
                        },
                    ],
                    cond: Expr::Const(1),
                },
            ],
        };

        reconstruct_args_with_params(&mut f, CallConv::Aarch64, &[0, 1].into_iter().collect());

        let Stmt::DoWhile { body, .. } = &f.body[1] else {
            panic!("expected loop: {f:#?}");
        };
        let args = body.iter().find_map(|statement| match statement {
            Stmt::Call {
                target: Expr::Named { name, .. },
                args,
                ..
            } if name == "signed_step" => Some(args),
            _ => None,
        });
        assert_eq!(args, Some(&vec![Expr::Reg(reg("x0#1"))]));
    }

    #[test]
    fn call_inside_loop_uses_a_coalesced_computed_loop_value() {
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rdi#1"),
                    src: Expr::Reg(reg("rdi")),
                },
                Stmt::DoWhile {
                    body: vec![
                        call_to("signed_step"),
                        // Phi-copy coalescing gives the update and loop input
                        // one name. The update need not remain a copy: normal
                        // reconstruction folds the call result and induction
                        // term into the assignment directly.
                        Stmt::Assign {
                            dst: reg("rdi#1"),
                            src: Expr::Bin {
                                op: BinOp::Add,
                                lhs: Box::new(Expr::Reg(reg("rax#2"))),
                                rhs: Box::new(Expr::Reg(reg("rbx#2"))),
                            },
                        },
                    ],
                    cond: Expr::Const(1),
                },
            ],
        };

        reconstruct_args_with_params(&mut f, CallConv::SysVAmd64, &[0].into_iter().collect());

        let Stmt::DoWhile { body, .. } = &f.body[1] else {
            panic!("expected loop: {f:#?}");
        };
        let args = body.iter().find_map(|statement| match statement {
            Stmt::Call {
                target: Expr::Named { name, .. },
                args,
                ..
            } if name == "signed_step" => Some(args),
            _ => None,
        });
        assert_eq!(args, Some(&vec![Expr::Reg(reg("rdi#1"))]));
    }

    #[test]
    fn loop_back_edge_without_an_initializer_does_not_invent_an_input() {
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![Stmt::DoWhile {
                body: vec![
                    call_to("signed_step"),
                    Stmt::Assign {
                        dst: reg("rdi#1"),
                        src: Expr::Reg(reg("rdi#2")),
                    },
                ],
                cond: Expr::Const(1),
            }],
        };

        reconstruct_args_with_params(&mut f, CallConv::SysVAmd64, &[0].into_iter().collect());

        let Stmt::DoWhile { body, .. } = &f.body[0] else {
            panic!("expected loop: {f:#?}");
        };
        let args = body.iter().find_map(|statement| match statement {
            Stmt::Call { args, .. } => Some(args),
            _ => None,
        });
        assert_eq!(args, Some(&vec![Expr::Reg(reg("rdi"))]));
    }

    #[test]
    fn cdecl32_folds_contiguous_outgoing_stack_stores() {
        let stack_store = |disp, value| Stmt::Store {
            addr: Expr::Lea {
                base: Some(reg("esp")),
                index: None,
                scale: 1,
                disp,
                segment: None,
            },
            src: Expr::Const(value),
            size: 4,
        };
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                stack_store(8, 30),
                stack_store(4, 20),
                stack_store(0, 10),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "callee".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        reconstruct_args(&mut f, CallConv::Cdecl32);

        assert_eq!(
            f.body.len(),
            1,
            "stack setup was not absorbed: {:#?}",
            f.body
        );
        assert!(matches!(
            &f.body[0],
            Stmt::Call { args, .. }
                if args == &vec![Expr::Const(10), Expr::Const(20), Expr::Const(30)]
        ));
    }

    #[test]
    fn cdecl32_folds_attributed_stack_stores_into_the_call_owner() {
        let stack_store = |disp, value, va| {
            Stmt::Store {
                addr: Expr::Lea {
                    base: Some(reg("esp")),
                    index: None,
                    scale: 1,
                    disp,
                    segment: None,
                }
                .with_origins(OriginSet::one(va - 8)),
                src: Expr::Const(value).with_origins(OriginSet::one(va - 4)),
                size: 4,
            }
            .with_origins(crate::ir::ast::OriginSet::one(va))
        };
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                stack_store(4, 20, 0x1010),
                stack_store(0, 10, 0x1014),
                call_to("callee").with_origins(crate::ir::ast::OriginSet::one(0x1018)),
            ],
        };

        reconstruct_args(&mut f, CallConv::Cdecl32);

        assert_eq!(f.body.len(), 1, "attributed setup was not folded: {f:#?}");
        let Stmt::Call { args, .. } = f.body[0].semantic() else {
            panic!("folded statement is not a call: {f:#?}")
        };
        assert_eq!(args.len(), 2);
        assert!(matches!(args[0].semantic(), Expr::Const(10)));
        assert!(matches!(args[1].semantic(), Expr::Const(20)));
        assert_eq!(
            args[0].origins(),
            Some(&OriginSet::from_addresses([0x1010, 0x1014]))
        );
        assert_eq!(
            args[1].origins(),
            Some(&OriginSet::from_addresses([0x100c, 0x1010]))
        );
        assert_eq!(
            f.body[0].origins().expect("folded call owner").addresses(),
            &[0x1010, 0x1014, 0x1018]
        );
    }

    #[test]
    fn sysv_resolves_reused_scratch_registers_in_captured_arguments() {
        let from_rax = |addend| Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::Reg(reg("rax"))),
            rhs: Box::new(Expr::Const(addend)),
        };
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 0),
                assign("rsi", 1),
                assign("rdx", 2),
                assign("rax", 10),
                Stmt::Assign {
                    dst: reg("rcx"),
                    src: from_rax(3),
                },
                assign("rax", 20),
                Stmt::Assign {
                    dst: reg("r8"),
                    src: from_rax(4),
                },
                assign("rax", 30),
                Stmt::Assign {
                    dst: reg("r9"),
                    src: from_rax(5),
                },
                call_to("callee"),
            ],
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        let Stmt::Call { args, .. } = f.body.last().expect("call must survive") else {
            panic!("expected call: {f:#?}");
        };
        assert_eq!(
            args,
            &vec![
                Expr::Const(0),
                Expr::Const(1),
                Expr::Const(2),
                Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Const(10)),
                    rhs: Box::new(Expr::Const(3)),
                },
                Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Const(20)),
                    rhs: Box::new(Expr::Const(4)),
                },
                Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Const(30)),
                    rhs: Box::new(Expr::Const(5)),
                },
            ]
        );
    }

    #[test]
    fn sysv_resolves_distinct_stable_frame_loads_from_one_scratch_register() {
        let frame_load = |disp| Expr::Deref {
            addr: Box::new(Expr::Lea {
                base: Some(reg("rbp")),
                index: None,
                scale: 1,
                disp,
                segment: None,
            }),
            size: 4,
        };
        let from_rax = |addend| Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::Reg(reg("rax"))),
            rhs: Box::new(Expr::Const(addend)),
        };
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 0),
                assign("rsi", 1),
                assign("rdx", 2),
                Stmt::Assign {
                    dst: reg("rax"),
                    src: frame_load(-8),
                },
                Stmt::Assign {
                    dst: reg("rcx"),
                    src: from_rax(3),
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: frame_load(-16),
                },
                Stmt::Assign {
                    dst: reg("r8"),
                    src: from_rax(4),
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: frame_load(-24),
                },
                Stmt::Assign {
                    dst: reg("r9"),
                    src: from_rax(5),
                },
                call_to("callee"),
            ],
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        let Stmt::Call { args, .. } = f.body.last().expect("call must survive") else {
            panic!("expected call: {f:#?}");
        };
        for (slot, (disp, addend)) in [(3, (-8, 3)), (4, (-16, 4)), (5, (-24, 5))] {
            assert!(
                matches!(
                    &args[slot],
                    Expr::Bin { lhs, rhs, .. }
                        if matches!(lhs.as_ref(), Expr::Deref { addr, size: 4 }
                            if matches!(addr.as_ref(), Expr::Lea { disp: actual, .. } if *actual == disp))
                            && rhs.as_ref() == &Expr::Const(addend)
                ),
                "slot {slot} did not retain its own frame snapshot: {args:#?}"
            );
        }
    }

    #[test]
    fn sysv_keeps_frame_load_statement_when_an_aliasing_store_intervenes() {
        let frame_addr = || Expr::Lea {
            base: Some(reg("rbp")),
            index: None,
            scale: 1,
            disp: -8,
            segment: None,
        };
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 0),
                assign("rsi", 1),
                assign("rdx", 2),
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Deref {
                        addr: Box::new(frame_addr()),
                        size: 4,
                    },
                },
                Stmt::Store {
                    addr: frame_addr(),
                    src: Expr::Const(99),
                    size: 4,
                },
                Stmt::Assign {
                    dst: reg("rcx"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("rax"))),
                        rhs: Box::new(Expr::Const(3)),
                    },
                },
                assign("r8", 4),
                assign("r9", 5),
                call_to("callee"),
            ],
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        assert!(f.body.iter().any(|statement| matches!(
            statement,
            Stmt::Assign {
                dst: VReg::Phys(name),
                src: Expr::Deref { .. },
            } if name == "rax"
        )));
        let Stmt::Call { args, .. } = f.body.last().expect("call must survive") else {
            panic!("expected call: {f:#?}");
        };
        assert!(matches!(
            &args[3],
            Expr::Bin { lhs, .. }
                if lhs.as_ref() == &Expr::Reg(reg("rax"))
        ));
    }

    #[test]
    fn sysv_origin_wrapped_aliasing_store_blocks_frame_load_substitution() {
        let frame_addr = || Expr::Lea {
            base: Some(reg("rbp")),
            index: None,
            scale: 1,
            disp: -8,
            segment: None,
        };
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 0),
                assign("rsi", 1),
                assign("rdx", 2),
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Deref {
                        addr: Box::new(frame_addr()),
                        size: 4,
                    },
                },
                Stmt::Store {
                    addr: frame_addr(),
                    src: Expr::Const(99),
                    size: 4,
                }
                .with_origins(OriginSet::one(0x1010)),
                Stmt::Assign {
                    dst: reg("rcx"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("rax"))),
                        rhs: Box::new(Expr::Const(3)),
                    },
                },
                assign("r8", 4),
                assign("r9", 5),
                call_to("callee"),
            ],
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        assert!(f.body.iter().any(|statement| matches!(
            statement.semantic(),
            Stmt::Assign {
                dst: VReg::Phys(name),
                src: Expr::Deref { .. },
            } if name == "rax"
        )));
        let Stmt::Call { args, .. } = f.body.last().expect("call must survive").semantic() else {
            panic!("expected call: {f:#?}");
        };
        assert!(matches!(
            &args[3],
            Expr::Bin { lhs, .. } if lhs.as_ref() == &Expr::Reg(reg("rax"))
        ));
    }

    #[test]
    fn sysv_does_not_cross_an_opaque_scratch_definition() {
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 0),
                assign("rsi", 1),
                assign("rdx", 2),
                assign("rax", 99),
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Reg(reg("rbx"))),
                        size: 4,
                    },
                },
                Stmt::Assign {
                    dst: reg("rcx"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("rax"))),
                        rhs: Box::new(Expr::Const(3)),
                    },
                },
                assign("r8", 4),
                assign("r9", 5),
                call_to("callee"),
            ],
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        let Stmt::Call { args, .. } = f.body.last().expect("call must survive") else {
            panic!("expected call: {f:#?}");
        };
        assert!(matches!(
            &args[3],
            Expr::Bin { lhs, .. }
                if lhs.as_ref() == &Expr::Reg(reg("rax"))
        ));
        assert!(f.body.iter().any(|statement| matches!(
            statement,
            Stmt::Assign {
                dst: VReg::Phys(name),
                src: Expr::Deref { .. },
            } if name == "rax"
        )));
    }

    #[test]
    fn sysv_folds_contiguous_preallocated_outgoing_stack_arguments() {
        let stack_store = |disp, value, owner| {
            Stmt::Store {
                addr: Expr::Lea {
                    base: Some(reg("rsp")),
                    index: None,
                    scale: 1,
                    disp,
                    segment: None,
                },
                src: Expr::Const(value),
                size: 4,
            }
            .with_origins(owner)
        };
        let seventh_owner = OriginSet::one(0x1020);
        let eighth_owner = OriginSet::one(0x1024);
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 0),
                assign("rsi", 1),
                assign("rdx", 2),
                assign("rcx", 3),
                assign("r8", 4),
                assign("r9", 5),
                stack_store(0, 6, seventh_owner.clone()),
                stack_store(8, 7, eighth_owner.clone()),
                call_to("callee"),
            ],
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        let [call] = f.body.as_slice() else {
            panic!("preallocated outgoing area was not absorbed: {f:#?}")
        };
        let Stmt::Call { args, .. } = call.semantic() else {
            panic!("expected folded call: {f:#?}")
        };
        assert_eq!(args.len(), 8);
        assert!(
            args.iter()
                .enumerate()
                .all(|(index, arg)| matches!(arg.semantic(), Expr::Const(value) if *value == index as i64)),
            "wrong argument values: {args:#?}"
        );
        assert_eq!(args[6].origins(), Some(&seventh_owner));
        assert_eq!(args[7].origins(), Some(&eighth_owner));
    }

    #[test]
    fn sysv_rejects_nonzero_based_preallocated_stack_stores() {
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 0),
                assign("rsi", 1),
                assign("rdx", 2),
                assign("rcx", 3),
                assign("r8", 4),
                assign("r9", 5),
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rsp")),
                        index: None,
                        scale: 1,
                        disp: 8,
                        segment: None,
                    },
                    src: Expr::Const(7),
                    size: 8,
                },
                call_to("callee"),
            ],
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        assert!(f.body.iter().any(|statement| matches!(
            statement,
            Stmt::Store {
                addr: Expr::Lea { disp: 8, .. },
                ..
            }
        )));
        let Stmt::Call { args, .. } = f.body.last().expect("call must survive") else {
            panic!("expected call: {f:#?}");
        };
        assert_eq!(args, &(0..6).map(Expr::Const).collect::<Vec<_>>());
    }

    #[test]
    fn sysv_folds_stack_arguments_after_the_six_register_arguments() {
        let push_pair = |value| {
            [
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(8)),
                    },
                },
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rsp")),
                        index: None,
                        scale: 1,
                        disp: 0,
                        segment: None,
                    },
                    src: Expr::Const(value),
                    size: 8,
                },
            ]
        };
        let mut body = vec![
            assign("rsi", 1),
            assign("rdx", 2),
            assign("rcx", 3),
            assign("r9", 5),
        ];
        // SysV places stack arguments right-to-left. Walking backward from the
        // call therefore encounters arg6 first and arg7 second.
        body.extend(push_pair(7));
        body.extend(push_pair(6));
        // GCC may finish register setup after pushing the stack suffix.
        body.push(assign("r8", 4));
        body.push(assign("rdi", 0));
        body.push(call_to("callee"));
        body.push(Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(16)),
            },
        });
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body,
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        assert_eq!(
            f.body.len(),
            1,
            "all outgoing setup must be absorbed: {f:#?}"
        );
        assert!(matches!(
            f.body.as_slice(),
            [Stmt::Call { args, .. }]
                if args == &(0..8).map(Expr::Const).collect::<Vec<_>>()
        ));
    }

    #[test]
    fn sysv_balanced_stack_argument_keeps_only_its_value_store_owner() {
        let allocation_owner = OriginSet::one(0x1100);
        let value_owner = OriginSet::one(0x1104);
        let call_owner = OriginSet::one(0x1108);
        let cleanup_owner = OriginSet::one(0x110c);
        let mut body = vec![
            assign("rdi", 0),
            assign("rsi", 1),
            assign("rdx", 2),
            assign("rcx", 3),
            assign("r8", 4),
            assign("r9", 5),
            Stmt::Assign {
                dst: reg("rsp"),
                src: Expr::Bin {
                    op: BinOp::Sub,
                    lhs: Box::new(Expr::Reg(reg("rsp"))),
                    rhs: Box::new(Expr::Const(8)),
                },
            }
            .with_origins(allocation_owner.clone()),
            Stmt::Store {
                addr: Expr::Lea {
                    base: Some(reg("rsp")),
                    index: None,
                    scale: 1,
                    disp: 0,
                    segment: None,
                },
                src: Expr::Const(6),
                size: 8,
            }
            .with_origins(value_owner.clone()),
            call_to("callee").with_origins(call_owner.clone()),
            Stmt::Assign {
                dst: reg("rsp"),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(reg("rsp"))),
                    rhs: Box::new(Expr::Const(8)),
                },
            }
            .with_origins(cleanup_owner.clone()),
        ];
        let mut function = Function {
            name: "stack_argument_origin".into(),
            entry_va: 0x1100,
            body: std::mem::take(&mut body),
        };

        reconstruct_args(&mut function, CallConv::SysVAmd64);

        assert_eq!(function.body.len(), 1, "setup did not fold: {function:#?}");
        let Stmt::Call { args, .. } = function.body[0].semantic() else {
            panic!("expected folded call: {function:#?}")
        };
        assert_eq!(args.len(), 7);
        assert!(matches!(args[6].semantic(), Expr::Const(6)));
        assert_eq!(args[6].origins(), Some(&value_owner));
        assert_eq!(
            function.body[0].origins(),
            Some(
                &allocation_owner
                    .union(&value_owner)
                    .union(&call_owner)
                    .union(&cleanup_owner)
            )
        );
    }

    #[test]
    fn sysv_balances_stack_arguments_consumed_by_lowered_pop_pairs() {
        let push_pair = |value| {
            [
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(8)),
                    },
                },
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rsp")),
                        index: None,
                        scale: 1,
                        disp: 0,
                        segment: None,
                    },
                    src: Expr::Const(value),
                    size: 8,
                },
            ]
        };
        let pop_pair = |dst| {
            [
                Stmt::Assign {
                    dst: reg(dst),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Lea {
                            base: Some(reg("rsp")),
                            index: None,
                            scale: 1,
                            disp: 0,
                            segment: None,
                        }),
                        size: 8,
                    },
                },
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(8)),
                    },
                },
            ]
        };
        let mut body = vec![
            assign("rdi", 0),
            assign("rsi", 1),
            assign("rdx", 2),
            assign("rcx", 3),
            assign("r8", 4),
            assign("r9", 5),
        ];
        body.extend(push_pair(7));
        body.extend(push_pair(6));
        body.push(call_to("callee"));
        body.extend(pop_pair("rdx"));
        body.extend(pop_pair("rcx"));
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body,
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        assert!(
            matches!(
                f.body.as_slice(),
                [Stmt::Call { args, .. }]
                    if args == &(0..8).map(Expr::Const).collect::<Vec<_>>()
            ),
            "lowered pop cleanup was not absorbed: {f:#?}"
        );
    }

    #[test]
    fn sysv_does_not_consume_stack_saves_without_matching_call_cleanup() {
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(8)),
                    },
                },
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rsp")),
                        index: None,
                        scale: 1,
                        disp: 0,
                        segment: None,
                    },
                    src: Expr::Reg(reg("rbx")),
                    size: 8,
                },
                assign("rdi", 0),
                assign("rsi", 1),
                assign("rdx", 2),
                assign("rcx", 3),
                assign("r8", 4),
                assign("r9", 5),
                call_to("callee"),
            ],
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        assert!(f.body.iter().any(|statement| matches!(
            statement,
            Stmt::Store {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "rbx"
        )));
        let Stmt::Call { args, .. } = f.body.last().expect("call must survive") else {
            panic!("expected call: {f:#?}");
        };
        assert_eq!(args, &(0..6).map(Expr::Const).collect::<Vec<_>>());
    }

    #[test]
    fn sysv_absorbs_one_alignment_word_with_an_odd_stack_suffix() {
        let stack_sub = || Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op: BinOp::Sub,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(8)),
            },
        };
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 0),
                assign("rsi", 1),
                assign("rdx", 2),
                assign("rcx", 3),
                assign("r8", 4),
                assign("r9", 5),
                stack_sub(),
                stack_sub(),
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rsp")),
                        index: None,
                        scale: 1,
                        disp: 0,
                        segment: None,
                    },
                    src: Expr::Const(6),
                    size: 8,
                },
                call_to("callee"),
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(16)),
                    },
                },
            ],
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        assert!(matches!(
            f.body.as_slice(),
            [Stmt::Call { args, .. }]
                if args == &(0..7).map(Expr::Const).collect::<Vec<_>>()
        ));
    }

    #[test]
    fn sysv_stack_area_uses_exact_identity_not_display_spelling() {
        let stack_sub = |name| Stmt::Assign {
            dst: reg(name),
            src: Expr::Bin {
                op: BinOp::Sub,
                lhs: Box::new(Expr::Reg(reg(name)).with_origins(OriginSet::one(0x1000))),
                rhs: Box::new(Expr::Const(8).with_origins(OriginSet::one(0x1004))),
            }
            .with_origins(OriginSet::one(0x1008)),
        };
        let stack_store = |name| Stmt::Store {
            addr: Expr::Lea {
                base: Some(reg(name)),
                index: None,
                scale: 1,
                disp: 0,
                segment: None,
            }
            .with_origins(OriginSet::one(0x100c)),
            src: Expr::Const(7),
            size: 8,
        };
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            reg("opaque_sp"),
            crate::ir::ssa::SsaValue {
                base: reg("rsp"),
                version: 3,
            },
        );
        identities.record(
            reg("rsp#3"),
            crate::ir::ssa::SsaValue {
                base: reg("rax"),
                version: 3,
            },
        );

        assert_eq!(
            stack_pointer_sub_width_with_identities(&stack_sub("opaque_sp"), Some(&identities),),
            Some(8)
        );
        assert_eq!(
            stack_pointer_sub_width_with_identities(&stack_sub("rsp#3"), Some(&identities)),
            None
        );
        assert!(outgoing_sysv_stack_push_with_identities(
            &[stack_sub("opaque_sp"), stack_store("opaque_sp")],
            1,
            Some(&identities),
        )
        .is_some());
        assert!(outgoing_sysv_stack_push_with_identities(
            &[stack_sub("rsp#3"), stack_store("rsp#3")],
            1,
            Some(&identities),
        )
        .is_none());
    }

    #[test]
    fn cdecl32_folds_right_to_left_push_lowering() {
        let push_pair = |value| {
            [
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(4)),
                    },
                },
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rsp")),
                        index: None,
                        scale: 1,
                        disp: 0,
                        segment: None,
                    },
                    src: Expr::Const(value),
                    size: 4,
                },
            ]
        };
        let mut body = Vec::new();
        body.extend(push_pair(30));
        body.extend(push_pair(20));
        body.extend(push_pair(10));
        body.push(Stmt::Call {
            target: Expr::Named {
                va: 0,
                name: "callee".into(),
            },
            args: Vec::new(),
            dst: None,
            call_spec: None,
        });
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body,
        };

        reconstruct_args(&mut f, CallConv::Cdecl32);

        // Six statements collapse to the call plus ONE stack adjustment holding
        // the twelve bytes the folded pushes moved `esp` by — see
        // `rebase_esp_after_removed_pushes` for why the net delta has to survive.
        assert_eq!(
            f.body.len(),
            2,
            "push setup was not absorbed: {:#?}",
            f.body
        );
        assert_eq!(stack_pointer_sub_width(&f.body[0]), Some(12));
        assert!(matches!(
            &f.body[1],
            Stmt::Call { args, .. }
                if args == &vec![Expr::Const(10), Expr::Const(20), Expr::Const(30)]
        ));
    }

    #[test]
    fn cdecl32_attributed_pushes_preserve_call_and_adjustment_owners() {
        let push_pair = |value, adjustment_va, store_va| {
            [
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(4)),
                    },
                }
                .with_origins(crate::ir::ast::OriginSet::one(adjustment_va)),
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rsp")),
                        index: None,
                        scale: 1,
                        disp: 0,
                        segment: None,
                    },
                    src: Expr::Const(value),
                    size: 4,
                }
                .with_origins(crate::ir::ast::OriginSet::one(store_va)),
            ]
        };
        let mut body = Vec::new();
        body.extend(push_pair(20, 0x1020, 0x1022));
        body.extend(push_pair(10, 0x1024, 0x1026));
        body.push(call_to("callee").with_origins(crate::ir::ast::OriginSet::one(0x1028)));
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body,
        };

        reconstruct_args(&mut f, CallConv::Cdecl32);

        assert_eq!(f.body.len(), 2, "attributed pushes were not folded: {f:#?}");
        assert_eq!(stack_pointer_sub_width(&f.body[0]), Some(8));
        assert_eq!(
            f.body[0]
                .origins()
                .expect("net stack adjustment owner")
                .addresses(),
            &[0x1020, 0x1024]
        );
        let Stmt::Call { args, .. } = f.body[1].semantic() else {
            panic!("folded statement is not a call: {f:#?}")
        };
        assert_eq!(args.len(), 2);
        assert!(matches!(args[0].semantic(), Expr::Const(10)));
        assert!(matches!(args[1].semantic(), Expr::Const(20)));
        assert_eq!(args[0].origins(), Some(&OriginSet::one(0x1026)));
        assert_eq!(args[1].origins(), Some(&OriginSet::one(0x1022)));
        assert_eq!(
            f.body[1].origins().expect("folded call owner").addresses(),
            &[0x1020, 0x1022, 0x1024, 0x1026, 0x1028]
        );
    }

    #[test]
    fn origin_wrapped_sysv_push_and_cleanup_are_recognized() {
        let adjust = |op, va| {
            Stmt::Assign {
                dst: reg("rsp"),
                src: Expr::Bin {
                    op,
                    lhs: Box::new(Expr::Reg(reg("rsp")).with_origins(OriginSet::one(va + 1))),
                    rhs: Box::new(Expr::Const(8).with_origins(OriginSet::one(va + 2))),
                }
                .with_origins(OriginSet::one(va + 3)),
            }
            .with_origins(crate::ir::ast::OriginSet::one(va))
        };
        let body = vec![
            adjust(BinOp::Sub, 0x1000),
            Stmt::Store {
                addr: Expr::Lea {
                    base: Some(reg("rsp")),
                    index: None,
                    scale: 1,
                    disp: 0,
                    segment: None,
                }
                .with_origins(OriginSet::one(0x1005)),
                src: Expr::Const(7),
                size: 8,
            }
            .with_origins(crate::ir::ast::OriginSet::one(0x1004)),
            call_to("callee").with_origins(crate::ir::ast::OriginSet::one(0x1008)),
            Stmt::Assign {
                dst: reg("scratch"),
                src: Expr::Deref {
                    addr: Box::new(
                        Expr::Lea {
                            base: Some(reg("rsp")),
                            index: None,
                            scale: 1,
                            disp: 0,
                            segment: None,
                        }
                        .with_origins(OriginSet::one(0x100d)),
                    ),
                    size: 8,
                }
                .with_origins(OriginSet::one(0x100e)),
            }
            .with_origins(crate::ir::ast::OriginSet::one(0x100c)),
            adjust(BinOp::Add, 0x1010),
        ];

        assert_eq!(
            outgoing_sysv_stack_push(&body, 1),
            Some((&Expr::Const(7), 8))
        );
        assert_eq!(outgoing_stack_cleanup(&body, 2, 8), Some(vec![3, 4]));
    }

    /// Six identical `push 0x2c(%esp)` instructions forward six DIFFERENT
    /// arguments: `esp` drops four bytes between each. Folding the pushes deletes
    /// those decrements, so each surviving load has to be rebased or the call
    /// gets six copies of one argument — which is exactly what
    /// `06_calling_conventions:i386:O2:forward_sum6` recovered.
    #[test]
    fn cdecl32_push_through_esp_rebases_each_load() {
        let load_and_push = |temp: u32| {
            [
                Stmt::Assign {
                    dst: VReg::Temp(temp),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Lea {
                            base: Some(reg("rsp")),
                            index: None,
                            scale: 1,
                            disp: 0x2c,
                            segment: None,
                        }),
                        size: 4,
                    },
                },
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(4)),
                    },
                },
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rsp")),
                        index: None,
                        scale: 1,
                        disp: 0,
                        segment: None,
                    },
                    src: Expr::Reg(VReg::Temp(temp)),
                    size: 4,
                },
            ]
        };
        let mut body = Vec::new();
        for temp in 0..3u32 {
            body.extend(load_and_push(temp));
        }
        body.push(Stmt::Call {
            target: Expr::Named {
                va: 0,
                name: "callee".into(),
            },
            args: Vec::new(),
            dst: None,
            call_spec: None,
        });
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body,
        };

        reconstruct_args(&mut f, CallConv::Cdecl32);

        let displacements: Vec<i64> = f
            .body
            .iter()
            .filter_map(|statement| match statement {
                Stmt::Assign {
                    src: Expr::Deref { addr, .. },
                    ..
                } => match addr.as_ref() {
                    Expr::Lea { disp, .. } => Some(*disp),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert_eq!(
            displacements,
            vec![0x2c, 0x28, 0x24],
            "the surviving loads were not rebased onto the folded `esp`: {:#?}",
            f.body
        );
    }

    /// 32-bit PIC copies the materialised GOT base into `ebx` right before the
    /// call. That single statement used to end the backward scan, so
    /// `06_calling_conventions:i386:O0:forward_sum6` recovered as a
    /// ZERO-argument call. The caller's own `add $N,%esp` cleanup is what makes
    /// stepping over it safe.
    #[test]
    fn cdecl32_steps_over_the_pic_got_copy_before_a_call() {
        let push_pair = |value| {
            [
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(4)),
                    },
                },
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rsp")),
                        index: None,
                        scale: 1,
                        disp: 0,
                        segment: None,
                    },
                    src: Expr::Const(value),
                    size: 4,
                },
            ]
        };
        let mut body = Vec::new();
        body.extend(push_pair(20));
        body.extend(push_pair(10));
        body.push(Stmt::Assign {
            dst: reg("ebx"),
            src: Expr::Reg(reg("eax")),
        });
        body.push(Stmt::Call {
            target: Expr::Named {
                va: 0,
                name: "callee".into(),
            },
            args: Vec::new(),
            dst: None,
            call_spec: None,
        });
        body.push(Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(reg("rsp")).with_origins(OriginSet::one(0x1040))),
                rhs: Box::new(Expr::Const(8).with_origins(OriginSet::one(0x1044))),
            }
            .with_origins(OriginSet::one(0x1048)),
        });
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body,
        };

        reconstruct_args(&mut f, CallConv::Cdecl32);

        assert!(
            f.body.iter().any(|statement| matches!(
                statement,
                Stmt::Call { args, .. }
                    if args == &vec![Expr::Const(10), Expr::Const(20)]
            )),
            "the GOT copy stopped argument recovery: {:#?}",
            f.body
        );
    }

    /// Without the caller-side cleanup there is no proof the preceding stack
    /// traffic belongs to this call, so the gap must NOT be stepped over — this
    /// is the callee-saved-prologue shape the scan has always refused.
    #[test]
    fn cdecl32_does_not_step_over_a_gap_without_a_proven_cleanup() {
        let push_pair = |value| {
            [
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(4)),
                    },
                },
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rsp")),
                        index: None,
                        scale: 1,
                        disp: 0,
                        segment: None,
                    },
                    src: Expr::Const(value),
                    size: 4,
                },
            ]
        };
        let mut body = Vec::new();
        body.extend(push_pair(20));
        body.extend(push_pair(10));
        body.push(Stmt::Assign {
            dst: reg("ebx"),
            src: Expr::Reg(reg("eax")),
        });
        body.push(Stmt::Call {
            target: Expr::Named {
                va: 0,
                name: "callee".into(),
            },
            args: Vec::new(),
            dst: None,
            call_spec: None,
        });
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body,
        };

        reconstruct_args(&mut f, CallConv::Cdecl32);

        assert!(
            f.body.iter().any(|statement| matches!(
                statement, Stmt::Call { args, .. } if args.is_empty()
            )),
            "arguments were invented across an unproven gap: {:#?}",
            f.body
        );
    }

    #[test]
    fn cdecl32_does_not_absorb_frame_prologue_as_an_argument() {
        let stack_sub = || Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op: BinOp::Sub,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(4)),
            },
        };
        let stack_store = |value| Stmt::Store {
            addr: Expr::Lea {
                base: Some(reg("rsp")),
                index: None,
                scale: 1,
                disp: 0,
                segment: None,
            },
            src: Expr::Const(value),
            size: 4,
        };
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                stack_sub(),
                stack_store(99),
                Stmt::Assign {
                    dst: reg("rbp"),
                    src: Expr::Reg(reg("rsp")),
                },
                stack_sub(),
                stack_store(20),
                stack_sub(),
                stack_store(10),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "callee".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        reconstruct_args(&mut f, CallConv::Cdecl32);

        assert!(matches!(
            f.body.last(),
            Some(Stmt::Call { args, .. })
                if args == &vec![Expr::Const(10), Expr::Const(20)]
        ));
        assert!(f.body.iter().any(|stmt| matches!(
            stmt,
            Stmt::Assign { dst: VReg::Phys(name), .. } if name == "rbp"
        )));
    }

    #[test]
    fn cdecl32_does_not_scan_past_parameter_loads_into_callee_saved_prologue() {
        let stack_sub = || Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op: BinOp::Sub,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(4)),
            },
        };
        let stack_store = |name| Stmt::Store {
            addr: Expr::Lea {
                base: Some(reg("rsp")),
                index: None,
                scale: 1,
                disp: 0,
                segment: None,
            },
            src: Expr::Reg(reg(name)),
            size: 4,
        };
        let load = |dst, disp| Stmt::Assign {
            dst: reg(dst),
            src: Expr::Deref {
                addr: Box::new(Expr::Lea {
                    base: Some(reg("rsp")),
                    index: None,
                    scale: 1,
                    disp,
                    segment: None,
                }),
                size: 4,
            },
        };
        let mut f = Function {
            name: "rand_str".into(),
            entry_va: 0,
            body: vec![
                stack_sub(),
                stack_store("rdi"),
                stack_sub(),
                stack_store("rsi"),
                stack_sub(),
                stack_store("rbx"),
                load("rsi#1", 20),
                load("rbx#1", 16),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "GetTickCount".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        reconstruct_args(&mut f, CallConv::Cdecl32);

        assert_eq!(
            f.body.len(),
            9,
            "callee-save prologue was removed: {:#?}",
            f.body
        );
        assert!(matches!(
            f.body.last(),
            Some(Stmt::Call { args, .. }) if args.is_empty()
        ));
    }

    #[test]
    fn stops_at_first_gap_in_arg_sequence() {
        // %rdi = 1 ; %rdx = 3 ; call foo  — only rdi folds (rsi is missing).
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 1),
                assign("rdx", 3),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        // rdx assign must stay; rdi is folded.
        assert_eq!(f.body.len(), 2, "unexpected shape: {:?}", f.body);
        assert!(matches!(&f.body[0], Stmt::Assign { dst, .. } if dst == &reg("rdx")));
        if let Stmt::Call { args, .. } = &f.body[1] {
            assert_eq!(args.len(), 1);
            assert_eq!(args[0], Expr::Const(1));
        }
    }

    #[test]
    fn fold_does_not_cross_intervening_call() {
        // %rdi = 1 ; call other ; call foo  — rdi must not fold into `foo`
        // because `other` clobbers it (we conservatively treat any call
        // between def and use as a barrier).
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 1),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "other".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        // `other` still has its rdi fold (legitimate); `foo` gets none.
        if let Stmt::Call { args, .. } = &f.body[f.body.len() - 1] {
            assert!(args.is_empty(), "foo() shouldn't have args: {:?}", f.body);
        }
    }

    #[test]
    fn sub_register_write_counts_as_arg_write() {
        // %edi = 0x2a ; call foo — %edi writes rdi's slot on x86-64.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("edi"),
                    src: Expr::Const(42),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        if let Stmt::Call { args, .. } = &f.body[0] {
            assert_eq!(args.len(), 1);
            assert_eq!(args[0], Expr::Const(42));
        }
    }

    #[test]
    fn argument_slot_liveness_uses_exact_identity_not_display_spelling() {
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            reg("opaque_arg"),
            crate::ir::ssa::SsaValue {
                base: reg("rsi"),
                version: 2,
            },
        );
        identities.record(
            reg("rdi#2"),
            crate::ir::ssa::SsaValue {
                base: reg("rax"),
                version: 2,
            },
        );
        identities.record(
            reg("ambiguous_arg"),
            crate::ir::ssa::SsaValue {
                base: reg("rdi"),
                version: 1,
            },
        );
        identities.record(
            reg("multi_non_arg"),
            crate::ir::ssa::SsaValue {
                base: reg("rsp"),
                version: 1,
            },
        );
        identities.record(
            reg("multi_non_arg"),
            crate::ir::ssa::SsaValue {
                base: reg("rsp"),
                version: 2,
            },
        );
        identities.record(
            reg("ambiguous_arg"),
            crate::ir::ssa::SsaValue {
                base: reg("rsi"),
                version: 1,
            },
        );

        let mut reads = vec![false; 6];
        mark_arg_reads_in_expr_with_identities(
            &Expr::Reg(reg("opaque_arg")),
            CallConv::SysVAmd64,
            &mut reads,
            Some(&identities),
        );
        mark_arg_reads_in_expr_with_identities(
            &Expr::Reg(reg("rdi#2")),
            CallConv::SysVAmd64,
            &mut reads,
            Some(&identities),
        );
        assert_eq!(reads, vec![false, true, false, false, false, false]);

        let mut writes = vec![false; 6];
        mark_slot_write_with_identities(
            &reg("opaque_arg"),
            CallConv::SysVAmd64,
            &mut writes,
            Some(&identities),
        );
        mark_slot_write_with_identities(
            &reg("rdi#2"),
            CallConv::SysVAmd64,
            &mut writes,
            Some(&identities),
        );
        assert_eq!(writes, vec![false, true, false, false, false, false]);

        let mut ambiguous = vec![false; 6];
        mark_slot_write_with_identities(
            &reg("ambiguous_arg"),
            CallConv::SysVAmd64,
            &mut ambiguous,
            Some(&identities),
        );
        assert!(ambiguous.into_iter().all(|blocked| blocked));

        let mut synthesized_local = vec![false; 6];
        mark_slot_write_with_identities(
            &reg("source_local"),
            CallConv::SysVAmd64,
            &mut synthesized_local,
            Some(&identities),
        );
        assert!(synthesized_local.into_iter().all(|blocked| !blocked));
        let mut multi_non_arg = vec![false; 6];
        mark_slot_write_with_identities(
            &reg("multi_non_arg"),
            CallConv::SysVAmd64,
            &mut multi_non_arg,
            Some(&identities),
        );
        assert!(multi_non_arg.into_iter().all(|blocked| !blocked));
    }

    #[test]
    fn aarch64_folds_x0_argument() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("x0"),
                    src: Expr::Const(7),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "puts".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::Aarch64);
        assert_eq!(f.body.len(), 1);
        if let Stmt::Call { args, .. } = &f.body[0] {
            assert_eq!(args[0], Expr::Const(7));
        }
    }

    #[test]
    fn win64_folds_rcx_rdx_r8_r9_in_windows_order() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rcx", 1),
                assign("rdx", 2),
                assign("r8", 3),
                assign("r9", 4),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::Win64);
        assert_eq!(f.body.len(), 1);
        if let Stmt::Call { args, .. } = &f.body[0] {
            assert_eq!(
                args,
                &vec![
                    Expr::Const(1),
                    Expr::Const(2),
                    Expr::Const(3),
                    Expr::Const(4)
                ]
            );
        } else {
            panic!("expected Call, got {:?}", f.body[0]);
        }
    }

    #[test]
    fn win64_does_not_treat_rdi_as_first_argument() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 1),
                assign("rcx", 2),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::Win64);
        assert!(matches!(&f.body[0], Stmt::Assign { dst, .. } if dst == &reg("rdi")));
        if let Stmt::Call { args, .. } = &f.body[1] {
            assert_eq!(args, &vec![Expr::Const(2)]);
        } else {
            panic!("expected Call, got {:?}", f.body[1]);
        }
    }

    #[test]
    fn win64_folds_args_across_unrelated_stores() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rcx"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("rax"))),
                        rhs: Box::new(Expr::Const(40)),
                    },
                },
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rax")),
                        index: None,
                        scale: 1,
                        disp: 0x14,
                        segment: None,
                    },
                    src: Expr::Reg(reg("rbx")),
                    size: 8,
                },
                assign("r8", 3),
                assign("rdx", 256),
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rax")),
                        index: None,
                        scale: 1,
                        disp: 0x18,
                        segment: None,
                    },
                    src: Expr::Reg(reg("r11")),
                    size: 8,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "strcpy_s".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::Win64);

        assert_eq!(f.body.len(), 3, "only unrelated stores and call remain");
        assert!(matches!(f.body[0], Stmt::Store { .. }));
        assert!(matches!(f.body[1], Stmt::Store { .. }));
        if let Stmt::Call { args, .. } = &f.body[2] {
            assert_eq!(args.len(), 3);
            assert_eq!(
                args[0],
                Expr::Bin {
                    op: crate::ir::types::BinOp::Add,
                    lhs: Box::new(Expr::Reg(reg("rax"))),
                    rhs: Box::new(Expr::Const(40)),
                }
            );
            assert_eq!(args[1], Expr::Const(256));
            assert_eq!(args[2], Expr::Const(3));
        } else {
            panic!("expected Call, got {:?}", f.body[2]);
        }
    }

    #[test]
    fn win64_fills_leading_incoming_arg_when_later_slot_is_set() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rdx", 256),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "strnlen".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        // The premise of the backfill is that `rcx` still carries the function's
        // OWN incoming first parameter, so slot 0 must be declared as such.
        reconstruct_args_with_params(&mut f, CallConv::Win64, &[0].into_iter().collect());

        assert_eq!(f.body.len(), 1);
        if let Stmt::Call { args, .. } = &f.body[0] {
            assert_eq!(args, &vec![Expr::Reg(reg("rcx")), Expr::Const(256)]);
        } else {
            panic!("expected Call, got {:?}", f.body[0]);
        }
    }

    /// The same shape in a function that has NO first parameter must not invent
    /// one. This is how `__stack_chk_fail`, which takes nothing, acquired
    /// `__stack_chk_fail(var24)` — an argument reading a register nothing defines.
    #[test]
    fn no_incoming_argument_is_invented_when_the_slot_is_not_a_parameter() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rdx", 256),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "strnlen".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        reconstruct_args_with_params(&mut f, CallConv::Win64, &Default::default());
        let args = f
            .body
            .iter()
            .find_map(|s| match s {
                Stmt::Call { args, .. } => Some(args.clone()),
                _ => None,
            })
            .expect("the call must survive");
        assert!(
            !args.iter().any(|a| *a == Expr::Reg(reg("rcx"))),
            "invented an incoming argument for a slot that is not a parameter: {args:?}"
        );
    }

    #[test]
    fn win64_does_not_fill_internal_argument_gap() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rcx", 1),
                assign("r8", 3),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::Win64);

        assert!(matches!(&f.body[0], Stmt::Assign { dst, .. } if dst == &reg("r8")));
        if let Stmt::Call { args, .. } = &f.body[1] {
            assert_eq!(args, &vec![Expr::Const(1)]);
        } else {
            panic!("expected Call, got {:?}", f.body[1]);
        }
    }

    #[test]
    fn win64_does_not_fold_arg_read_by_intervening_store() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rcx", 1),
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rcx")),
                        index: None,
                        scale: 1,
                        disp: 0,
                        segment: None,
                    },
                    src: Expr::Const(99),
                    size: 8,
                },
                assign("rdx", 2),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::Win64);

        assert!(matches!(&f.body[0], Stmt::Assign { dst, .. } if dst == &reg("rcx")));
        assert!(matches!(&f.body[2], Stmt::Assign { dst, .. } if dst == &reg("rdx")));
        if let Stmt::Call { args, .. } = &f.body[3] {
            assert!(args.is_empty(), "call args should not fold: {:?}", f.body);
        } else {
            panic!("expected Call, got {:?}", f.body[3]);
        }
    }

    #[test]
    fn read_of_arg_reg_between_def_and_call_blocks_fold() {
        // %rdi = 1 ; %rsi = rdi + 2 ; call foo — rdi is read between the
        // assignment and the call, so folding it would move its value out
        // of sequence. Leave rdi's assign alone; rsi still folds.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 1),
                Stmt::Assign {
                    dst: reg("rsi"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("rdi"))),
                        rhs: Box::new(Expr::Const(2)),
                    },
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        // Since rdi can't fold, the slot-0 is empty, so nothing folds at all
        // (args are contiguous prefix).
        assert!(matches!(&f.body[0], Stmt::Assign { dst, .. } if dst == &reg("rdi")));
    }

    fn call_to(name: &str) -> Stmt {
        call_at(0x2000, name)
    }

    fn call_at(va: u64, name: &str) -> Stmt {
        Stmt::Call {
            target: Expr::Named {
                va,
                name: name.into(),
            },
            args: vec![],
            dst: None,
            call_spec: None,
        }
    }

    fn recovered_prototype(
        return_type: &str,
        parameter_types: &[&str],
    ) -> crate::ir::call_contracts::CallPrototype {
        crate::ir::call_contracts::CallPrototype {
            return_type: return_type.into(),
            parameter_types: parameter_types
                .iter()
                .map(|value| (*value).into())
                .collect(),
            variadic: false,
            authority: crate::ir::call_contracts::CallPrototypeAuthority::Recovered,
        }
    }

    #[test]
    fn sysv_sse_pair_result_forwards_into_a_proven_pair_parameter_tail_call() {
        let mut function = Function {
            name: "pair_roundtrip".into(),
            entry_va: 0x1000,
            body: vec![
                call_at(0x2000, "make_pair"),
                Stmt::Assign {
                    dst: reg("eax#1"),
                    src: Expr::Const(3),
                },
                call_at(0x3000, "consume_pair"),
            ],
        };
        let layouts = std::collections::HashMap::from([
            (0x2000, vec![reg("rdi")]),
            (0x3000, vec![reg("xmm0"), reg("xmm1")]),
        ]);
        let prototypes = std::collections::HashMap::from([
            (
                0x2000,
                recovered_prototype("struct __glaurung_sse_pair", &["int"]),
            ),
            (0x3000, recovered_prototype("int", &["double", "double"])),
        ]);
        let mut parameters = [0].into_iter().collect();

        reconstruct_args_with_layouts_prototypes_and_strings(
            &mut function,
            CallConv::SysVAmd64,
            &mut parameters,
            &layouts,
            &std::collections::HashMap::new(),
            Some(&prototypes),
            &std::collections::HashMap::new(),
        );

        let args = function
            .body
            .iter()
            .filter_map(|statement| match statement {
                Stmt::Call {
                    target: Expr::Named { va: 0x3000, .. },
                    args,
                    ..
                } => Some(args),
                _ => None,
            })
            .next()
            .expect("consumer call");
        assert_eq!(args, &[Expr::Reg(reg("xmm0")), Expr::Reg(reg("xmm1"))]);
    }

    #[test]
    fn origin_wrapped_sysv_sse_pair_result_still_forwards() {
        let mut function = Function {
            name: "pair_roundtrip".into(),
            entry_va: 0x1000,
            body: vec![
                call_at(0x2000, "make_pair").with_origins(OriginSet::one(0x1000)),
                call_at(0x3000, "consume_pair"),
            ],
        };
        let layouts = std::collections::HashMap::from([
            (0x2000, vec![reg("rdi")]),
            (0x3000, vec![reg("xmm0"), reg("xmm1")]),
        ]);
        let prototypes = std::collections::HashMap::from([
            (
                0x2000,
                recovered_prototype("struct __glaurung_sse_pair", &["int"]),
            ),
            (0x3000, recovered_prototype("int", &["double", "double"])),
        ]);

        reconstruct_args_with_layouts_prototypes_and_strings(
            &mut function,
            CallConv::SysVAmd64,
            &mut [0].into_iter().collect(),
            &layouts,
            &std::collections::HashMap::new(),
            Some(&prototypes),
            &std::collections::HashMap::new(),
        );

        let args = function
            .body
            .iter()
            .find_map(|statement| match statement.semantic() {
                Stmt::Call {
                    target: Expr::Named { va: 0x3000, .. },
                    args,
                    ..
                } => Some(args),
                _ => None,
            })
            .expect("consumer call");
        assert_eq!(args, &[Expr::Reg(reg("xmm0")), Expr::Reg(reg("xmm1"))]);
    }

    #[test]
    fn sysv_sse_pair_forwarding_refuses_an_intervening_high_bank_write() {
        let mut function = Function {
            name: "clobbered_pair".into(),
            entry_va: 0x1000,
            body: vec![
                call_at(0x2000, "make_pair"),
                Stmt::Assign {
                    dst: reg("xmm1"),
                    src: Expr::Const(0),
                },
                call_at(0x3000, "consume_pair"),
            ],
        };
        let layouts = std::collections::HashMap::from([
            (0x2000, vec![reg("rdi")]),
            (0x3000, vec![reg("xmm0"), reg("xmm1")]),
        ]);
        let prototypes = std::collections::HashMap::from([
            (
                0x2000,
                recovered_prototype("struct __glaurung_sse_pair", &["int"]),
            ),
            (0x3000, recovered_prototype("int", &["double", "double"])),
        ]);
        let mut parameters = [0].into_iter().collect();

        reconstruct_args_with_layouts_prototypes_and_strings(
            &mut function,
            CallConv::SysVAmd64,
            &mut parameters,
            &layouts,
            &std::collections::HashMap::new(),
            Some(&prototypes),
            &std::collections::HashMap::new(),
        );

        let args = function
            .body
            .iter()
            .find_map(|statement| match statement {
                Stmt::Call {
                    target: Expr::Named { va: 0x3000, .. },
                    args,
                    ..
                } => Some(args),
                _ => None,
            })
            .expect("consumer call");
        assert!(args.is_empty(), "clobbered pair was forwarded: {args:?}");
    }

    #[test]
    fn sysv_sse_pair_clobber_uses_exact_identity_not_display_spelling() {
        let layouts = std::collections::HashMap::from([
            (0x2000, vec![reg("rdi")]),
            (0x3000, vec![reg("xmm0"), reg("xmm1")]),
        ]);
        let prototypes = std::collections::HashMap::from([
            (
                0x2000,
                recovered_prototype("struct __glaurung_sse_pair", &["int"]),
            ),
            (0x3000, recovered_prototype("int", &["double", "double"])),
        ]);
        let run = |destination: &str, identities: &crate::ir::value_number::ValueIdentities| {
            let mut function = Function {
                name: "pair".into(),
                entry_va: 0x1000,
                body: vec![
                    call_at(0x2000, "make_pair"),
                    Stmt::Assign {
                        dst: reg(destination),
                        src: Expr::Const(0),
                    },
                    call_at(0x3000, "consume_pair"),
                ],
            };
            reconstruct_args_with_layouts_prototypes_strings_and_identities(
                &mut function,
                CallConv::SysVAmd64,
                &mut [0].into_iter().collect(),
                &layouts,
                &Default::default(),
                Some(&prototypes),
                &Default::default(),
                identities,
            );
            function
                .body
                .into_iter()
                .find_map(|statement| match statement {
                    Stmt::Call {
                        target: Expr::Named { va: 0x3000, .. },
                        args,
                        ..
                    } => Some(args),
                    _ => None,
                })
        };
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            reg("opaque_high"),
            crate::ir::ssa::SsaValue {
                base: reg("xmm1"),
                version: 2,
            },
        );
        identities.record(
            reg("xmm1#looks_high"),
            crate::ir::ssa::SsaValue {
                base: reg("rax"),
                version: 2,
            },
        );
        identities.record(
            reg("malformed_identity_base"),
            crate::ir::ssa::SsaValue {
                base: reg("xmm1#not_canonical"),
                version: 2,
            },
        );

        assert_eq!(run("opaque_high", &identities), Some(Vec::new()));
        assert_eq!(
            run("xmm1#looks_high", &identities),
            Some(vec![Expr::Reg(reg("xmm0")), Expr::Reg(reg("xmm1"))])
        );
        assert_eq!(
            run("malformed_identity_base", &identities),
            Some(vec![Expr::Reg(reg("xmm0")), Expr::Reg(reg("xmm1"))])
        );
    }

    #[test]
    fn arm_hard_float_call_folds_vfp_arguments_and_consumed_result() {
        let mut f = Function {
            name: "hard_float_caller".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: reg("s1#1"),
                    src: Expr::FloatConst {
                        bits: 2.0f32.to_bits() as u64,
                        width: 4,
                    },
                },
                Stmt::Assign {
                    dst: reg("s0"),
                    src: Expr::FloatConst {
                        bits: 1.0f32.to_bits() as u64,
                        width: 4,
                    },
                },
                call_to("float_pair"),
                Stmt::Assign {
                    dst: reg("s14#1"),
                    src: Expr::Reg(reg("s0#1")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("s14#1"))),
                },
            ],
        };

        reconstruct_args(&mut f, CallConv::ArmHardFloat);

        let Stmt::Call { args, dst, .. } = &f.body[0] else {
            panic!("VFP setup did not fold into the call: {:#?}", f.body);
        };
        assert_eq!(args.len(), 2, "VFP argument prefix: {:#?}", f.body);
        assert_eq!(
            args,
            &[
                Expr::FloatConst {
                    bits: 1.0f32.to_bits() as u64,
                    width: 4,
                },
                Expr::FloatConst {
                    bits: 2.0f32.to_bits() as u64,
                    width: 4,
                },
            ]
        );
        assert_eq!(dst, &Some(reg("s0")));
    }

    #[test]
    fn named_unary_float_contract_ignores_unrelated_vfp_scratch_storage() {
        let mut f = Function {
            name: "hard_float_math_caller".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: reg("s15#1"),
                    src: Expr::Reg(reg("s0#1")),
                },
                Stmt::Assign {
                    dst: reg("s0#2"),
                    src: Expr::Reg(reg("s15#1")),
                },
                call_to("asinf"),
                Stmt::Assign {
                    dst: reg("s14#1"),
                    src: Expr::Reg(reg("s0#3")),
                },
            ],
        };

        reconstruct_args(&mut f, CallConv::ArmHardFloat);

        let call = f
            .body
            .iter()
            .find_map(|statement| match statement {
                Stmt::Call { args, dst, .. } => Some((args, dst)),
                _ => None,
            })
            .expect("math call remains in the body");
        assert_eq!(call.0, &[Expr::Reg(reg("s15#1"))]);
        assert_eq!(call.1, &Some(reg("s0")));
    }

    #[test]
    fn recovered_callee_layout_interleaves_arm_core_and_vfp_arguments() {
        let target_owner = OriginSet::one(0x1010);
        let mut f = Function {
            name: "mixed_hard_float_caller".into(),
            entry_va: 0x1000,
            body: vec![
                assign("r1#1", 22),
                Stmt::Assign {
                    dst: reg("s0#1"),
                    src: Expr::FloatConst {
                        bits: 2.5f32.to_bits() as u64,
                        width: 4,
                    },
                },
                assign("r0", 7),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "mixed_float".into(),
                    }
                    .with_origins(target_owner.clone()),
                    args: vec![],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: reg("s14#1"),
                    src: Expr::Reg(reg("s0#2")),
                },
            ],
        };
        let layouts =
            std::collections::HashMap::from([(0x2000, vec![reg("r0"), reg("s0"), reg("r1")])]);
        let mut parameter_slots = Default::default();

        reconstruct_args_with_params_and_callee_layouts(
            &mut f,
            CallConv::ArmHardFloat,
            &mut parameter_slots,
            &layouts,
        );

        let Stmt::Call {
            target, args, dst, ..
        } = &f.body[0]
        else {
            panic!("mixed setup did not fold into the call: {:#?}", f.body);
        };
        assert_eq!(
            args,
            &[
                Expr::Const(7),
                Expr::FloatConst {
                    bits: 2.5f32.to_bits() as u64,
                    width: 4,
                },
                Expr::Const(22),
            ]
        );
        assert_eq!(dst, &Some(reg("s0")));
        assert_eq!(target.origins(), Some(&target_owner));
    }

    #[test]
    fn attributed_recovered_layout_setup_folds_and_joins_the_call_owner() {
        let setup0 = crate::ir::ast::OriginSet::one(0x1010);
        let setup1 = crate::ir::ast::OriginSet::one(0x1014);
        let call_owner = crate::ir::ast::OriginSet::one(0x1018);
        let mut body = vec![
            assign("rdi#1", 7).with_origins(setup0.clone()),
            assign("rsi#1", 11).with_origins(setup1.clone()),
            call_to("mixed_float").with_origins(call_owner),
        ];

        assert!(fold_one_recovered_layout_call(
            &mut body,
            2,
            &[reg("rdi"), reg("rsi")],
            None,
        ));

        assert_eq!(body.len(), 1);
        let Stmt::Call { args, .. } = body[0].semantic() else {
            panic!("folded statement is not a call: {body:#?}")
        };
        assert_eq!(args.len(), 2);
        assert!(matches!(args[0].semantic(), Expr::Const(7)));
        assert!(matches!(args[1].semantic(), Expr::Const(11)));
        assert_eq!(args[0].origins(), Some(&setup0));
        assert_eq!(args[1].origins(), Some(&setup1));
        assert_eq!(
            body[0].origins().expect("folded call owner").addresses(),
            &[0x1010, 0x1014, 0x1018]
        );
    }

    #[test]
    fn recovered_layout_setup_uses_exact_identity_not_display_spelling() {
        let setup = |destination: &str| vec![assign(destination, 7), call_to("callee")];
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            reg("opaque_argument"),
            crate::ir::ssa::SsaValue {
                base: reg("rdi"),
                version: 1,
            },
        );
        identities.record(
            reg("rdi#looks_versioned"),
            crate::ir::ssa::SsaValue {
                base: reg("rax"),
                version: 1,
            },
        );

        let mut exact = setup("opaque_argument");
        assert!(fold_one_recovered_layout_call(
            &mut exact,
            1,
            &[reg("rdi")],
            Some(&identities),
        ));
        assert!(matches!(
            exact.as_slice(),
            [Stmt::Call { args, .. }] if args == &[Expr::Const(7)]
        ));

        let mut misleading = setup("rdi#looks_versioned");
        assert!(!fold_one_recovered_layout_call(
            &mut misleading,
            1,
            &[reg("rdi")],
            Some(&identities),
        ));
        assert!(matches!(
            misleading.as_slice(),
            [Stmt::Assign { .. }, Stmt::Call { args, .. }] if args.is_empty()
        ));
    }

    #[test]
    fn attributed_recovered_layout_follows_a_pure_spill_definition() {
        let mut body = vec![
            Stmt::Assign {
                dst: reg("local_c"),
                src: Expr::Reg(reg("arg0")),
            }
            .with_origins(crate::ir::ast::OriginSet::one(0x1010)),
            Stmt::Assign {
                dst: reg("rdi#1"),
                src: Expr::Reg(reg("local_c")),
            }
            .with_origins(crate::ir::ast::OriginSet::one(0x1014)),
            call_to("callee").with_origins(crate::ir::ast::OriginSet::one(0x1018)),
        ];

        assert!(fold_one_recovered_layout_call(
            &mut body,
            2,
            &[reg("rdi")],
            None,
        ));

        assert_eq!(body.len(), 2, "only the ABI setup is consumed");
        let Stmt::Call { args, .. } = body[1].semantic() else {
            panic!("folded statement is not a call: {body:#?}")
        };
        assert_eq!(args.len(), 1);
        assert!(matches!(args[0].semantic(), Expr::Reg(value) if value == &reg("arg0")));
        assert_eq!(
            args[0]
                .origins()
                .expect("argument expression owner")
                .addresses(),
            &[0x1010, 0x1014]
        );
        assert_eq!(
            body[1].origins().expect("folded call owner").addresses(),
            &[0x1014, 0x1018]
        );
    }

    #[test]
    fn recovered_layout_follows_opaque_promoted_spill_identity() {
        let object_name = "frame_object".to_string();
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.attach_promoted_stack_objects([&object_name]);
        identities.record(
            reg("opaque_argument"),
            crate::ir::ssa::SsaValue {
                base: reg("rdi"),
                version: 1,
            },
        );
        let mut body = vec![
            Stmt::Assign {
                dst: reg(&object_name),
                src: Expr::Reg(reg("arg0")),
            },
            Stmt::Assign {
                dst: reg("opaque_argument"),
                src: Expr::Reg(reg(&object_name)),
            },
            call_to("callee"),
        ];

        assert!(fold_one_recovered_layout_call(
            &mut body,
            2,
            &[reg("rdi")],
            Some(&identities),
        ));

        assert_eq!(body.len(), 2, "only the ABI setup is consumed");
        assert!(matches!(
            &body[1],
            Stmt::Call { args, .. } if args == &[Expr::Reg(reg("arg0"))]
        ));
    }

    #[test]
    fn attributed_recovered_layout_leaves_frame_loads_for_the_general_fold() {
        let frame_load = Expr::Deref {
            addr: Box::new(Expr::Lea {
                segment: None,
                base: Some(reg("r7#1")),
                index: None,
                scale: 1,
                disp: 4,
            }),
            size: 4,
        };
        let mut body = vec![
            Stmt::Assign {
                dst: reg("s0#1"),
                src: frame_load,
            }
            .with_origins(crate::ir::ast::OriginSet::one(0x1014)),
            call_to("callee").with_origins(crate::ir::ast::OriginSet::one(0x1018)),
        ];

        assert!(!fold_one_recovered_layout_call(
            &mut body,
            1,
            &[reg("s0")],
            None,
        ));
        assert_eq!(body.len(), 2, "the general fold must retain the load root");
        assert!(matches!(body[1].semantic(), Stmt::Call { args, .. } if args.is_empty()));
    }

    #[test]
    fn attributed_mixed_layout_setup_folds_with_a_proven_live_in() {
        let mut body = vec![
            assign("rdi#1", 7).with_origins(crate::ir::ast::OriginSet::one(0x1020)),
            call_to("mixed_float").with_origins(crate::ir::ast::OriginSet::one(0x1024)),
        ];
        let live_ins = vec![Some(Expr::Reg(reg("rdi"))), Some(Expr::Reg(reg("rsi")))];
        let enclosing = EnclosingSlots::entry(
            CallConv::SysVAmd64,
            &live_ins,
            vec![true; arg_slots(CallConv::SysVAmd64).len()],
        );

        assert!(fold_one_recovered_layout_call_with_live_ins(
            &mut body,
            1,
            CallConv::SysVAmd64,
            &[reg("rdi"), reg("rsi")],
            &[0, 1].into_iter().collect(),
            &enclosing,
            None,
        ));

        assert_eq!(body.len(), 1);
        let Stmt::Call { args, .. } = body[0].semantic() else {
            panic!("folded statement is not a call: {body:#?}")
        };
        assert_eq!(args.len(), 2);
        assert!(matches!(args[0].semantic(), Expr::Const(7)));
        assert_eq!(args[0].origins(), Some(&OriginSet::one(0x1020)));
        assert_eq!(args[1], Expr::Reg(reg("rsi")));
        assert_eq!(
            body[0].origins().expect("folded call owner").addresses(),
            &[0x1020, 0x1024]
        );
    }

    #[test]
    fn recovered_callee_layout_keeps_current_register_without_adjacent_setup() {
        let mut f = Function {
            name: "tail_caller".into(),
            entry_va: 0x1000,
            body: vec![call_to("mixed_float")],
        };
        let layouts = std::collections::HashMap::from([(0x2000, vec![reg("r0")])]);
        let mut parameter_slots = [0].into_iter().collect();

        reconstruct_args_with_params_and_callee_layouts(
            &mut f,
            CallConv::Arm,
            &mut parameter_slots,
            &layouts,
        );

        let Stmt::Call { args, .. } = &f.body[0] else {
            panic!("call disappeared: {:#?}", f.body);
        };
        assert_eq!(args, &[Expr::Reg(reg("r0"))]);
    }

    #[test]
    fn recovered_callee_layout_keeps_all_untouched_aarch64_live_in_parameters() {
        let mut function = Function {
            name: "wide_multiply_caller".into(),
            entry_va: 0x1000,
            body: vec![call_to("widen_mul")],
        };
        let layouts = std::collections::HashMap::from([(0x2000, vec![reg("x0"), reg("x1")])]);
        let mut parameter_slots = [0, 1].into_iter().collect();

        reconstruct_args_with_params_and_callee_layouts(
            &mut function,
            CallConv::Aarch64,
            &mut parameter_slots,
            &layouts,
        );

        let Stmt::Call { args, .. } = &function.body[0] else {
            panic!("call disappeared: {:#?}", function.body);
        };
        assert_eq!(
            args,
            &[Expr::Reg(reg("x0")), Expr::Reg(reg("x1"))],
            "the locked callee layout must retain every proven caller live-in"
        );
    }

    #[test]
    fn recovered_callee_layout_combines_hidden_result_setup_with_live_in_argument() {
        let mut function = Function {
            name: "aggregate_return_caller".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: reg("rdi#1"),
                    src: Expr::Reg(reg("rsp")),
                },
                call_to("make_big"),
            ],
        };
        let layouts = std::collections::HashMap::from([(0x2000, vec![reg("rdi"), reg("rsi")])]);
        let mut parameter_slots = [0, 1].into_iter().collect();

        reconstruct_args_with_params_and_callee_layouts(
            &mut function,
            CallConv::SysVAmd64,
            &mut parameter_slots,
            &layouts,
        );

        assert_eq!(function.body.len(), 1, "the hidden-pointer setup must fold");
        let Stmt::Call { args, .. } = &function.body[0] else {
            panic!("call disappeared: {:#?}", function.body);
        };
        assert_eq!(
            args,
            &[Expr::Reg(reg("rsp")), Expr::Reg(reg("rsi"))],
            "the declared argument remains in the caller's untouched second slot"
        );
    }

    #[test]
    fn recovered_callee_layout_does_not_reuse_live_ins_after_a_call_clobber() {
        let mut function = Function {
            name: "two_calls".into(),
            entry_va: 0x1000,
            body: vec![call_to("first"), call_to("second")],
        };
        let layouts = std::collections::HashMap::from([(0x2000, vec![reg("x0"), reg("x1")])]);
        let mut parameter_slots = [0, 1].into_iter().collect();

        reconstruct_args_with_params_and_callee_layouts(
            &mut function,
            CallConv::Aarch64,
            &mut parameter_slots,
            &layouts,
        );

        let calls: Vec<_> = function
            .body
            .iter()
            .filter_map(|statement| match statement {
                Stmt::Call { args, .. } => Some(args),
                _ => None,
            })
            .collect();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], &[Expr::Reg(reg("x0")), Expr::Reg(reg("x1"))]);
        assert!(
            calls[1].is_empty(),
            "a prior call clobbers both live-ins, so the fallback must fail closed"
        );
    }

    /// The exact core/stack setup emitted by ARM GCC for an eight-integer call.
    /// Older r2/r3 definitions feed stack slots while the nearest definitions
    /// feed the ordinary core-register prefix.
    #[test]
    fn recovered_aapcs_layout_folds_reused_core_registers_and_stack_suffix() {
        let stack_store = |disp, source, va| {
            Stmt::Store {
                addr: if disp == 0 {
                    Expr::Reg(reg("sp"))
                } else {
                    Expr::Lea {
                        base: Some(reg("sp")),
                        index: None,
                        scale: 1,
                        disp,
                        segment: None,
                    }
                },
                src: Expr::Reg(reg(source)),
                size: 4,
            }
            .with_origins(OriginSet::one(va))
        };
        let mut f = Function {
            name: "call_into_spill_shape".into(),
            entry_va: 0x1000,
            body: vec![
                assign("r3#1", 7),
                assign("r2#1", 8),
                assign("ip#1", 6),
                stack_store(8, "r3#1", 0x120c),
                stack_store(12, "r2#1", 0x1210),
                assign("r3#2", 5),
                assign("r2#2", 3),
                stack_store(0, "r3#2", 0x121c),
                stack_store(4, "ip#1", 0x1220),
                assign("r3#3", 4),
                Stmt::Assign {
                    dst: reg("flag_input#1"),
                    src: Expr::Reg(reg("r3#3")),
                },
                assign("r1#1", 2),
                assign("r0#1", 1),
                call_to("spill_combine"),
            ],
        };
        // Locked stack parameters use source-role placeholders because they do
        // not have an entry register SSA value.
        let layouts = std::collections::HashMap::from([(
            0x2000,
            vec![
                reg("r0"),
                reg("r1"),
                reg("r2"),
                reg("r3"),
                reg("arg4"),
                reg("arg5"),
                reg("arg6"),
                reg("arg7"),
            ],
        )]);
        let mut parameter_slots = Default::default();

        reconstruct_args_with_params_and_callee_layouts(
            &mut f,
            CallConv::ArmHardFloat,
            &mut parameter_slots,
            &layouts,
        );

        let call = f
            .body
            .iter()
            .find(|statement| matches!(statement.semantic(), Stmt::Call { .. }))
            .expect("call must survive");
        let Stmt::Call { args, .. } = call.semantic() else {
            unreachable!()
        };
        assert_eq!(
            args.iter().map(Expr::semantic).cloned().collect::<Vec<_>>(),
            vec![
                Expr::Const(1),
                Expr::Const(2),
                Expr::Const(3),
                Expr::Reg(reg("r3#3")),
                Expr::Const(5),
                Expr::Reg(reg("ip#1")),
                Expr::Const(7),
                Expr::Const(8),
            ],
            "AAPCS stack setup was not composed with the core-register prefix: {:#?}",
            f.body
        );
        assert_eq!(args[4].origins(), Some(&OriginSet::one(0x121c)));
        assert_eq!(args[5].origins(), Some(&OriginSet::one(0x1220)));
        assert_eq!(args[6].origins(), Some(&OriginSet::one(0x120c)));
        assert_eq!(args[7].origins(), Some(&OriginSet::one(0x1210)));
        assert!(
            f.body.iter().any(|statement| matches!(
                statement,
                Stmt::Assign { dst, src: Expr::Const(6) } if dst == &reg("ip#1")
            )),
            "versioned stack-argument definitions remain statement-rooted"
        );
        assert!(
            f.body.iter().any(|statement| matches!(
                statement,
                Stmt::Assign { dst, src: Expr::Const(4) } if dst == &reg("r3#3")
            )),
            "an argument definition read by intervening bookkeeping must remain in place"
        );
        assert!(
            f.body
                .iter()
                .all(|statement| !matches!(statement, Stmt::Store { .. })),
            "consumed outgoing stores must not survive as frame locals: {:#?}",
            f.body
        );
    }

    #[test]
    fn aapcs_stack_call_uses_the_immediately_prior_call_result_as_slot_zero() {
        let stack_store = |disp, value| Stmt::Store {
            addr: if disp == 0 {
                Expr::Reg(reg("sp"))
            } else {
                Expr::Lea {
                    base: Some(reg("sp")),
                    index: None,
                    scale: 1,
                    disp,
                    segment: None,
                }
            },
            src: Expr::Const(value),
            size: 4,
        };
        let mut producer = call_to("signed_step");
        if let Stmt::Call {
            target: Expr::Named { va, .. },
            ..
        } = &mut producer
        {
            *va = 0x1000;
        }
        let mut f = Function {
            name: "call_result_into_spill".into(),
            entry_va: 0x800,
            body: vec![
                producer,
                Stmt::Assign {
                    dst: reg("result_copy#1"),
                    src: Expr::Reg(reg("r0")),
                },
                stack_store(0, 5),
                stack_store(4, 6),
                stack_store(8, 7),
                stack_store(12, 8),
                assign("r3#1", 4),
                assign("r2#1", 3),
                assign("r1#1", 2),
                call_to("spill_combine"),
            ],
        };
        let layouts = std::collections::HashMap::from([(
            0x2000,
            vec![
                reg("r0"),
                reg("r1"),
                reg("r2"),
                reg("r3"),
                reg("arg4"),
                reg("arg5"),
                reg("arg6"),
                reg("arg7"),
            ],
        )]);
        let mut parameter_slots = [0].into_iter().collect();

        reconstruct_args_with_params_and_callee_layouts(
            &mut f,
            CallConv::ArmHardFloat,
            &mut parameter_slots,
            &layouts,
        );

        let calls: Vec<_> = f
            .body
            .iter()
            .filter_map(|statement| match statement {
                Stmt::Call { args, dst, .. } => Some((args, dst)),
                _ => None,
            })
            .collect();
        assert_eq!(calls.len(), 2, "both calls must survive: {:#?}", f.body);
        let result = calls[0]
            .1
            .as_ref()
            .expect("the consumed producer result needs an exact value");
        assert_eq!(
            calls[1].0,
            &vec![
                Expr::Reg(result.clone()),
                Expr::Const(2),
                Expr::Const(3),
                Expr::Const(4),
                Expr::Const(5),
                Expr::Const(6),
                Expr::Const(7),
                Expr::Const(8),
            ],
            "slot zero must be the reaching call result, not the function's incoming r0"
        );
        assert!(
            f.body.iter().any(|statement| matches!(
                statement,
                Stmt::Assign { dst, src: Expr::Reg(source) }
                    if dst == &reg("result_copy#1") && source == result
            )),
            "transitive setup computations must read the exact producer result: {:#?}",
            f.body
        );
    }

    /// AArch64 has eight core argument registers, so an optimized call can use
    /// the preceding call result directly as x0 while populating only x1-x7.
    /// The contiguous ABI prefix proves x0 is the first consumer argument; it
    /// must not be backfilled from this function's stale incoming x0.
    #[test]
    fn aarch64_register_call_uses_the_immediately_prior_call_result_as_slot_zero() {
        let mut producer = call_to("signed_step");
        if let Stmt::Call {
            target: Expr::Named { va, .. },
            ..
        } = &mut producer
        {
            *va = 0x1000;
        }
        let from_x0 = |addend| Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::Reg(reg("x0"))),
            rhs: Box::new(Expr::Const(addend)),
        };
        let from_x1 = |addend| Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::Reg(reg("x1#2"))),
            rhs: Box::new(Expr::Const(addend)),
        };
        let widen = |source: &str| Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Reg(reg(source))),
        };
        let mut f = Function {
            name: "call_into_spill".into(),
            entry_va: 0x800,
            body: vec![
                producer,
                Stmt::Assign {
                    dst: reg("x1#1"),
                    src: Expr::Reg(reg("saved_arg1")),
                },
                Stmt::Assign {
                    dst: reg("x1#2"),
                    src: widen("x1#1"),
                },
                Stmt::Assign {
                    dst: reg("x6#1"),
                    src: from_x0(5),
                },
                Stmt::Assign {
                    dst: reg("x6#2"),
                    src: widen("x6#1"),
                },
                Stmt::Assign {
                    dst: reg("x4#1"),
                    src: from_x0(3),
                },
                Stmt::Assign {
                    dst: reg("x4#2"),
                    src: widen("x4#1"),
                },
                Stmt::Assign {
                    dst: reg("x2#1"),
                    src: from_x0(1),
                },
                Stmt::Assign {
                    dst: reg("x2#2"),
                    src: widen("x2#1"),
                },
                Stmt::Assign {
                    dst: reg("x7#1"),
                    src: from_x1(6),
                },
                Stmt::Assign {
                    dst: reg("x7#2"),
                    src: widen("x7#1"),
                },
                Stmt::Assign {
                    dst: reg("x5#1"),
                    src: from_x1(4),
                },
                Stmt::Assign {
                    dst: reg("x5#2"),
                    src: widen("x5#1"),
                },
                Stmt::Assign {
                    dst: reg("x3#1"),
                    src: from_x1(2),
                },
                Stmt::Assign {
                    dst: reg("x3#2"),
                    src: widen("x3#1"),
                },
                call_to("spill_combine"),
            ],
        };

        reconstruct_args_with_params(&mut f, CallConv::Aarch64, &[0, 1].into_iter().collect());

        let calls: Vec<_> = f
            .body
            .iter()
            .filter_map(|statement| match statement {
                Stmt::Call { args, dst, .. } => Some((args, dst)),
                _ => None,
            })
            .collect();
        assert_eq!(calls.len(), 2, "both calls must survive: {:#?}", f.body);
        let result = calls[0]
            .1
            .as_ref()
            .expect("the consumed producer result needs an exact value");
        assert_ne!(
            result,
            &reg("x0"),
            "the result needs its own value identity"
        );
        assert_eq!(
            calls[1].0.len(),
            8,
            "slot zero must be the reaching call result: {:#?}",
            f.body
        );
        assert_eq!(calls[1].0[0], Expr::Reg(result.clone()));
        assert_eq!(calls[1].0[1], Expr::Reg(reg("x1#2")));
        assert!(
            calls[1]
                .0
                .iter()
                .skip(1)
                .all(|argument| { !reads_reg_in_expr(argument, &reg("x0")) }),
            "derived arguments must not read the stale architectural x0: {:#?}",
            f.body
        );
    }

    fn dst_of(s: &Stmt) -> &Option<VReg> {
        match s {
            Stmt::Call { dst, .. } => dst,
            other => panic!("expected a call, got {other:?}"),
        }
    }

    #[test]
    fn a_consumed_call_result_records_where_it_lands() {
        // A call PRODUCES a value. Until the AST could say so, the emitted C dropped
        // it: `fib` called itself and then used the ARGUMENT where the returned value
        // belonged.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                call_to("g"),
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("rax"))),
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        assert_eq!(*dst_of(&f.body[0]), Some(VReg::phys("rax")));
    }

    #[test]
    fn an_origin_wrapped_consumed_call_result_is_attributed_in_place() {
        let call_owner = OriginSet::one(0x1000);
        let return_owner = OriginSet::one(0x1004);
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                call_to("g").with_origins(call_owner.clone()),
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("rax"))),
                }
                .with_origins(return_owner),
            ],
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        assert_eq!(f.body[0].origins(), Some(&call_owner));
        match f.body[0].semantic() {
            Stmt::Call { dst, .. } => assert_eq!(*dst, Some(VReg::phys("rax"))),
            other => panic!("expected a call, got {other:?}"),
        }
    }

    #[test]
    fn origin_wrappers_do_not_hide_register_names_from_call_recovery() {
        let body = vec![Stmt::Return {
            value: Some(Expr::Reg(reg("rdi")).with_origins(OriginSet::one(0x1004))),
        }
        .with_origins(OriginSet::one(0x1000))];
        let mut names = Vec::new();

        walk_body_reg_names(&body, &mut |name| names.push(name.to_string()));

        assert_eq!(names, vec!["rdi"]);
    }

    #[test]
    fn origin_wrappers_do_not_hide_enclosing_reaching_definitions() {
        let mut reaching = vec![None; arg_slots(CallConv::SysVAmd64).len()];
        let definition = Stmt::Assign {
            dst: reg("rdi#1"),
            src: Expr::Const(7),
        }
        .with_origins(OriginSet::one(0x1000));

        EnclosingSlots::advance_reaching(&mut reaching, &definition, CallConv::SysVAmd64, None);

        let value = reaching[0].as_ref().expect("reaching definition");
        assert!(matches!(value.semantic(), Expr::Reg(reg) if reg == &VReg::phys("rdi#1")));
        assert_eq!(value.origins(), Some(&OriginSet::one(0x1000)));
    }

    #[test]
    fn enclosing_reaching_state_does_not_reparse_an_identity_base() {
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            reg("opaque_argument"),
            crate::ir::ssa::SsaValue {
                base: reg("rdi"),
                version: 1,
            },
        );
        identities.record(
            reg("malformed_identity_base"),
            crate::ir::ssa::SsaValue {
                base: reg("rdi#not_canonical"),
                version: 1,
            },
        );
        let definition = |dst| Stmt::Assign {
            dst: reg(dst),
            src: Expr::Const(7),
        };

        let mut exact = vec![None; arg_slots(CallConv::SysVAmd64).len()];
        EnclosingSlots::advance_reaching(
            &mut exact,
            &definition("opaque_argument"),
            CallConv::SysVAmd64,
            Some(&identities),
        );
        assert_eq!(exact[0], Some(Expr::Reg(reg("opaque_argument"))));

        let mut malformed = vec![None; arg_slots(CallConv::SysVAmd64).len()];
        EnclosingSlots::advance_reaching(
            &mut malformed,
            &definition("malformed_identity_base"),
            CallConv::SysVAmd64,
            Some(&identities),
        );
        assert!(malformed.iter().all(Option::is_none));
    }

    #[test]
    fn a_result_nobody_reads_is_not_an_assignment() {
        // The ABI clobbers the return register on EVERY call — that belongs in the
        // value model. Printing `ret = puts(..)` claims something else: that the
        // source took the result. Here the register is overwritten before any read.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                call_to("puts"),
                Stmt::Assign {
                    dst: VReg::phys("rax"),
                    src: Expr::Const(0),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("rax"))),
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        assert_eq!(*dst_of(&f.body[0]), None);
    }

    #[test]
    fn a_later_call_clobbers_the_register_so_the_earlier_result_is_unread() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                call_to("first"),
                call_to("second"),
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("rax"))),
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        assert_eq!(*dst_of(&f.body[0]), None, "first result is never read");
        assert_eq!(
            *dst_of(&f.body[1]),
            Some(VReg::phys("rax")),
            "second result is returned"
        );
    }

    #[test]
    fn a_conditional_reader_counts_as_consuming_the_result() {
        // The scan errs toward attaching the destination: a spurious assignment is
        // dead code, a missing one makes the reader take a stale value.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                call_to("g"),
                Stmt::If {
                    cond: Expr::Reg(VReg::phys("rdi")),
                    then_body: vec![Stmt::Return {
                        value: Some(Expr::Reg(VReg::phys("rax"))),
                    }],
                    else_body: None,
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        assert_eq!(*dst_of(&f.body[0]), Some(VReg::phys("rax")));
    }

    #[test]
    fn a_call_at_the_end_of_a_block_is_treated_as_consumed() {
        // Control continues where this walk cannot see.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![call_to("g")],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        assert_eq!(*dst_of(&f.body[0]), Some(VReg::phys("rax")));
    }

    #[test]
    fn the_result_register_follows_the_abi() {
        for (cc, reg_name) in [
            (CallConv::SysVAmd64, "rax"),
            (CallConv::Win64, "rax"),
            (CallConv::Aarch64, "x0"),
            (CallConv::Arm, "r0"),
        ] {
            let mut f = Function {
                name: "f".into(),
                entry_va: 0,
                body: vec![Stmt::Call {
                    target: Expr::Addr(0x2000),
                    args: vec![],
                    dst: None,
                    call_spec: None,
                }],
            };
            // A call at the end of a block counts as consumed, so this exercises the
            // ABI's choice of register rather than the liveness scan.
            reconstruct_args(&mut f, cc);
            match &f.body[0] {
                Stmt::Call { dst, .. } => assert_eq!(*dst, Some(VReg::phys(reg_name)), "{cc:?}"),
                other => panic!("expected a call, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_call_inside_a_branch_is_attributed_too() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::If {
                cond: Expr::Reg(VReg::phys("rdi")),
                then_body: vec![Stmt::Call {
                    target: Expr::Addr(0x2000),
                    args: vec![],
                    dst: None,
                    call_spec: None,
                }],
                else_body: None,
            }],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        match &f.body[0] {
            Stmt::If { then_body, .. } => match &then_body[0] {
                Stmt::Call { dst, .. } => assert_eq!(*dst, Some(VReg::phys("rax"))),
                other => panic!("expected a call, got {other:?}"),
            },
            other => panic!("expected an if, got {other:?}"),
        }
    }

    /// The decbench pipeline value-numbers the LLIR before lowering, so an
    /// argument register arrives as `rdi#3`, not `rdi`. Matching the slot table
    /// against the literal name found NOTHING, and every call on that path lost
    /// all of its arguments: `signed_step(x)` rendered as `signed_step()`.
    ///
    /// The register-style path does not value-number, which is why the same
    /// function showed the argument there and hid the bug.
    #[test]
    fn an_ssa_versioned_argument_register_still_names_its_slot() {
        assert_eq!(slot_of(CallConv::SysVAmd64, "rdi"), Some(0));
        assert_eq!(slot_of(CallConv::SysVAmd64, "rdi#3"), Some(0));
        assert_eq!(slot_of(CallConv::SysVAmd64, "esi#12"), Some(1));
        assert_eq!(slot_of(CallConv::Aarch64, "x2#1"), Some(2));
        // A non-argument register is still not an argument register.
        assert_eq!(slot_of(CallConv::SysVAmd64, "rbx#2"), None);
    }

    #[test]
    fn incoming_argument_uses_exact_identity_not_display_spelling() {
        let body = vec![Stmt::Return {
            value: Some(Expr::Reg(VReg::phys("opaque_incoming"))),
        }];
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            VReg::phys("opaque_incoming"),
            crate::ir::ssa::SsaValue {
                base: VReg::phys("rdi"),
                version: 0,
            },
        );
        identities.record(
            VReg::phys("rdi#0"),
            crate::ir::ssa::SsaValue {
                base: VReg::phys("rax"),
                version: 0,
            },
        );

        assert_eq!(
            incoming_arg_expr_with_identities(CallConv::SysVAmd64, 0, &body, Some(&identities),),
            Some(Expr::Reg(VReg::phys("opaque_incoming")))
        );
        assert_eq!(
            incoming_arg_expr_with_identities(
                CallConv::SysVAmd64,
                0,
                &[Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("rdi#0"))),
                }],
                Some(&identities),
            ),
            None
        );
    }

    #[test]
    fn frame_coordinate_uses_exact_identity_not_display_spelling() {
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            VReg::phys("opaque_stack"),
            crate::ir::ssa::SsaValue {
                base: VReg::phys("rsp"),
                version: 4,
            },
        );
        identities.record(
            VReg::phys("rsp#4"),
            crate::ir::ssa::SsaValue {
                base: VReg::phys("rax"),
                version: 4,
            },
        );

        assert!(is_frame_coordinate_storage(
            CallConv::SysVAmd64,
            &VReg::phys("opaque_stack"),
            Some(&identities),
        ));
        assert!(!is_frame_coordinate_storage(
            CallConv::SysVAmd64,
            &VReg::phys("rsp#4"),
            Some(&identities),
        ));
    }

    #[test]
    fn argument_slot_uses_exact_identity_not_display_spelling() {
        let caller = |destination: &str| Function {
            name: "caller".into(),
            entry_va: 0x1000,
            body: vec![assign(destination, 17), call_to("callee")],
        };
        let run = |mut function: Function,
                   identities: &crate::ir::value_number::ValueIdentities| {
            reconstruct_args_with_layouts_prototypes_strings_and_identities(
                &mut function,
                CallConv::SysVAmd64,
                &mut Default::default(),
                &Default::default(),
                &Default::default(),
                None,
                &Default::default(),
                identities,
            );
            function
        };

        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            reg("opaque_argument"),
            crate::ir::ssa::SsaValue {
                base: reg("rdi"),
                version: 2,
            },
        );
        identities.record(
            reg("rdi#looks_versioned"),
            crate::ir::ssa::SsaValue {
                base: reg("rax"),
                version: 2,
            },
        );

        let exact = run(caller("opaque_argument"), &identities);
        assert!(matches!(
            exact.body.as_slice(),
            [Stmt::Call { args, .. }] if args == &[Expr::Const(17)]
        ));

        let misleading = run(caller("rdi#looks_versioned"), &identities);
        assert!(matches!(
            misleading.body.as_slice(),
            [Stmt::Assign { .. }, Stmt::Call { args, .. }] if args.is_empty()
        ));
    }

    #[test]
    fn storage_match_does_not_reparse_an_authoritative_identity_base() {
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            reg("opaque_argument"),
            crate::ir::ssa::SsaValue {
                base: reg("rdi#not_canonical"),
                version: 2,
            },
        );

        assert!(!register_is_storage(
            &reg("opaque_argument"),
            "rdi",
            Some(&identities),
        ));
    }

    #[test]
    fn stable_frame_load_uses_exact_identity_not_display_spelling() {
        let frame_load = |base| {
            Expr::Deref {
                addr: Box::new(
                    Expr::Lea {
                        base: Some(VReg::phys(base)),
                        index: None,
                        scale: 1,
                        disp: -8,
                        segment: None,
                    }
                    .with_origins(OriginSet::one(0x1000)),
                ),
                size: 4,
            }
            .with_origins(OriginSet::one(0x1004))
        };
        let mut identities = crate::ir::value_number::ValueIdentities::default();
        identities.record(
            VReg::phys("opaque_frame"),
            crate::ir::ssa::SsaValue {
                base: VReg::phys("rbp"),
                version: 3,
            },
        );
        identities.record(
            VReg::phys("rbp#3"),
            crate::ir::ssa::SsaValue {
                base: VReg::phys("rax"),
                version: 3,
            },
        );
        identities.record(
            VReg::phys("opaque_reframe"),
            crate::ir::ssa::SsaValue {
                base: VReg::phys("rbp"),
                version: 4,
            },
        );

        let body = vec![assign("rax", 1), call_to("callee")];

        assert!(is_stable_frame_arg_definition_with_identities(
            &frame_load("opaque_frame"),
            &body,
            0,
            0,
            Some(&identities),
        ));
        assert!(!is_stable_frame_arg_definition_with_identities(
            &frame_load("rbp#3"),
            &body,
            0,
            0,
            Some(&identities),
        ));

        let fake_frame_write = vec![assign("rax", 1), assign("rbp#3", 2), call_to("callee")];
        assert!(is_stable_frame_arg_definition_with_identities(
            &frame_load("opaque_frame"),
            &fake_frame_write,
            0,
            2,
            Some(&identities),
        ));
        let real_frame_write = vec![
            assign("rax", 1),
            assign("opaque_reframe", 2),
            call_to("callee"),
        ];
        assert!(!is_stable_frame_arg_definition_with_identities(
            &frame_load("opaque_frame"),
            &real_frame_write,
            0,
            2,
            Some(&identities),
        ));
    }

    /// End to end over the pass: a value-numbered argument write folds into the
    /// call just as an unversioned one does.
    #[test]
    fn a_value_numbered_argument_write_folds_into_the_call() {
        let mut f = Function {
            name: "caller".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("rdi#4"),
                    src: Expr::Const(7),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "callee".to_string(),
                    },
                    args: vec![],
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        let args = f
            .body
            .iter()
            .find_map(|s| match s {
                Stmt::Call { args, .. } => Some(args.clone()),
                _ => None,
            })
            .expect("the call must survive");
        assert_eq!(args, vec![Expr::Const(7)], "body was:\n{:#?}", f.body);
    }

    /// A later value in one argument register must not hide setup for a higher
    /// slot that happened before an older SSA value of that same register.
    ///
    /// GCC emits this exact SysV variadic-call shape for
    /// `fprintf(stream, fmt, global, name, incoming_int)`: `rdx#1` feeds
    /// `r8#1`, then `rdx#2` and `rdx#3` are reused for the fourth and third
    /// arguments. The backward scan used to stop at `rdx#2` because slot 2 was
    /// already filled by `rdx#3`, so it never reached `r8#1` and silently
    /// truncated the call to four arguments.
    #[test]
    fn value_numbered_scan_follows_captured_argument_def_use_chains() {
        let mut f = Function {
            name: "variadic_caller".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: reg("rdx#1"),
                    src: Expr::Reg(reg("rdi")),
                },
                Stmt::Assign {
                    dst: reg("r8#1"),
                    src: Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: Box::new(Expr::Reg(reg("rdx#1"))),
                    },
                },
                Stmt::Assign {
                    dst: reg("rdx#2"),
                    src: Expr::Addr(0x5040),
                },
                Stmt::Assign {
                    dst: reg("rcx#1"),
                    src: Expr::Reg(reg("rdx#2")),
                },
                Stmt::Assign {
                    dst: reg("rdx#3"),
                    src: Expr::Addr(0x6000),
                },
                Stmt::Assign {
                    dst: reg("rsi#1"),
                    src: Expr::Addr(0x30a0),
                },
                Stmt::Assign {
                    dst: reg("rdi#1"),
                    src: Expr::Reg(reg("rax#1")),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x11d0,
                        name: "fprintf".to_string(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        let args = f
            .body
            .iter()
            .find_map(|statement| match statement {
                Stmt::Call { args, .. } => Some(args),
                _ => None,
            })
            .expect("the call must survive");
        assert_eq!(
            args,
            &[
                Expr::Reg(reg("rax#1")),
                Expr::Addr(0x30a0),
                Expr::Addr(0x6000),
                Expr::Addr(0x5040),
                Expr::Cast {
                    signed: false,
                    width: 8,
                    expr: Box::new(Expr::Reg(reg("rdi"))),
                },
            ],
            "body was:\n{:#?}",
            f.body
        );
    }

    /// A fully understood literal format proves that the third SysV slot is
    /// consumed even when an inlined body reads its reaching definition before
    /// the call. Keep that definition rooted and name its exact SSA value at
    /// the call rather than silently truncating the variadic argument list.
    #[test]
    fn literal_printf_format_keeps_an_interveningly_read_argument() {
        let mut f = Function {
            name: "inlined_printf_caller".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: reg("rdi#1"),
                    src: Expr::Const(2),
                },
                Stmt::Assign {
                    dst: reg("rsi#1"),
                    src: Expr::Addr(0x3000),
                },
                Stmt::Assign {
                    dst: reg("rdx#1"),
                    src: Expr::Const(42),
                },
                Stmt::Store {
                    addr: Expr::Addr(0x4000),
                    src: Expr::Reg(reg("rdx#1")),
                    size: 4,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "__printf_chk".to_string(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        let strings = std::collections::HashMap::from([(0x3000, "called %d times\n".to_string())]);

        reconstruct_args_with_layouts_and_strings(
            &mut f,
            CallConv::SysVAmd64,
            &mut Default::default(),
            &Default::default(),
            &Default::default(),
            &strings,
        );

        let args = f
            .body
            .iter()
            .find_map(|statement| match statement {
                Stmt::Call { args, .. } => Some(args),
                _ => None,
            })
            .expect("the call must survive");
        assert_eq!(
            args,
            &[Expr::Const(2), Expr::Addr(0x3000), Expr::Reg(reg("rdx#1")),],
            "body was:\n{:#?}",
            f.body
        );
        assert!(f.body.iter().any(|statement| matches!(
            statement,
            Stmt::Assign { dst, .. } if dst == &reg("rdx#1")
        )));
    }

    #[test]
    fn origin_wrapped_printf_call_keeps_format_proven_argument() {
        let mut f = Function {
            name: "printf_caller".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: reg("rdi#1"),
                    src: Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: Box::new(Expr::Addr(0x3000).with_origins(OriginSet::one(0x1000))),
                    }
                    .with_origins(OriginSet::one(0x1004)),
                },
                Stmt::Assign {
                    dst: reg("rsi#1"),
                    src: Expr::Const(42),
                },
                Stmt::Store {
                    addr: Expr::Addr(0x4000),
                    src: Expr::Reg(reg("rsi#1")),
                    size: 4,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "printf".to_string(),
                    }
                    .with_origins(OriginSet::one(0x100c)),
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                }
                .with_origins(OriginSet::one(0x1010)),
            ],
        };
        let strings = std::collections::HashMap::from([(0x3000, "%d\n".to_string())]);

        reconstruct_args_with_layouts_and_strings(
            &mut f,
            CallConv::SysVAmd64,
            &mut Default::default(),
            &Default::default(),
            &Default::default(),
            &strings,
        );

        let args = f
            .body
            .iter()
            .find_map(|statement| match statement.semantic() {
                Stmt::Call { args, .. } => Some(args),
                _ => None,
            })
            .expect("the call must survive");
        assert_eq!(args.len(), 2, "body was:\n{:#?}", f.body);
        assert!(matches!(
            args[0].semantic(),
            Expr::Cast { expr, .. } if matches!(expr.semantic(), Expr::Addr(0x3000))
        ));
        assert_eq!(args[1].semantic(), &Expr::Reg(reg("rsi#1")));
    }

    /// Unsupported format constructs must not relax the read barrier. This is
    /// the fail-closed control for the positive proof above: `%*d` consumes a
    /// dynamic width, which the shared parser deliberately declines.
    #[test]
    fn unsupported_printf_format_does_not_invent_an_argument() {
        let mut f = Function {
            name: "unsupported_printf_caller".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: reg("rdi#1"),
                    src: Expr::Addr(0x3000),
                },
                Stmt::Assign {
                    dst: reg("rsi#1"),
                    src: Expr::Const(42),
                },
                Stmt::Store {
                    addr: Expr::Addr(0x4000),
                    src: Expr::Reg(reg("rsi#1")),
                    size: 4,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "printf".to_string(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        let strings = std::collections::HashMap::from([(0x3000, "value %*d\n".to_string())]);

        reconstruct_args_with_layouts_and_strings(
            &mut f,
            CallConv::SysVAmd64,
            &mut Default::default(),
            &Default::default(),
            &Default::default(),
            &strings,
        );

        let args = f
            .body
            .iter()
            .find_map(|statement| match statement {
                Stmt::Call { args, .. } => Some(args),
                _ => None,
            })
            .expect("the call must survive");
        assert_eq!(args, &[Expr::Addr(0x3000)], "body was:\n{:#?}", f.body);
    }

    /// A different SSA version is not, by itself, permission to keep scanning.
    /// Optimised code frequently reuses argument registers between unrelated
    /// calls; treating every older version as independent made a one-argument
    /// `xmalloc(32)` consume stale values left in rsi and rdx.
    #[test]
    fn value_numbered_scan_stops_at_an_unrelated_older_slot_definition() {
        let mut f = Function {
            name: "one_argument_caller".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: reg("rsi#1"),
                    src: Expr::Const(2),
                },
                Stmt::Assign {
                    dst: reg("rdx#1"),
                    src: Expr::Const(3),
                },
                Stmt::Assign {
                    dst: reg("rdi#1"),
                    src: Expr::Const(99),
                },
                Stmt::Assign {
                    dst: reg("rdi#2"),
                    src: Expr::Const(32),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "xmalloc".to_string(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        let args = f
            .body
            .iter()
            .find_map(|statement| match statement {
                Stmt::Call { args, .. } => Some(args),
                _ => None,
            })
            .expect("the call must survive");
        assert_eq!(args, &[Expr::Const(32)], "body was:\n{:#?}", f.body);
    }

    #[test]
    fn value_numbered_tail_call_backfills_a_proven_bare_live_in_prefix() {
        let mut f = Function {
            name: "tail_wrapper".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rdi")),
                        index: None,
                        scale: 0,
                        disp: 0x100,
                        segment: None,
                    },
                    src: Expr::Const(0),
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("rsi#1"),
                    src: Expr::Const(24),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x5000,
                        name: "sub_5000".to_string(),
                    },
                    args: vec![],
                    dst: Some(reg("rax")),
                    call_spec: None,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rax"))),
                },
            ],
        };

        reconstruct_args_with_params(&mut f, CallConv::SysVAmd64, &[0].into_iter().collect());

        let args = f
            .body
            .iter()
            .find_map(|statement| match statement {
                Stmt::Call { args, .. } => Some(args),
                _ => None,
            })
            .expect("tail call must survive");
        assert_eq!(
            args,
            &vec![Expr::Reg(reg("rdi")), Expr::Const(24)],
            "body was:\n{:#?}",
            f.body
        );
    }

    #[test]
    fn value_numbered_call_does_not_backfill_across_a_prior_call_clobber() {
        let mut f = Function {
            name: "ordinary_caller".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rdi")),
                        index: None,
                        scale: 0,
                        disp: 0x100,
                        segment: None,
                    },
                    src: Expr::Const(0),
                    size: 8,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x4000,
                        name: "sub_4000".to_string(),
                    },
                    args: vec![],
                    dst: Some(reg("rax")),
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: reg("rsi#1"),
                    src: Expr::Const(24),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x5000,
                        name: "sub_5000".to_string(),
                    },
                    args: vec![],
                    dst: Some(reg("rax")),
                    call_spec: None,
                },
            ],
        };

        reconstruct_args_with_params(&mut f, CallConv::SysVAmd64, &[0].into_iter().collect());

        let args = f
            .body
            .iter()
            .find_map(|statement| match statement {
                Stmt::Call {
                    target: Expr::Named { name, .. },
                    args,
                    ..
                } if name == "sub_5000" => Some(args),
                _ => None,
            })
            .expect("later call must survive");
        assert!(
            args.is_empty(),
            "a later call must not inherit an entry value clobbered by a prior call: {:#?}",
            f.body
        );
    }

    #[test]
    fn value_numbered_nonterminal_call_backfills_a_proven_untouched_live_in_prefix() {
        let mut f = Function {
            name: "ordinary_caller".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rdi")),
                        index: None,
                        scale: 0,
                        disp: 0x100,
                        segment: None,
                    },
                    src: Expr::Const(0),
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("rsi#1"),
                    src: Expr::Const(24),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x5000,
                        name: "sub_5000".to_string(),
                    },
                    args: vec![],
                    dst: Some(reg("rax")),
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: reg("rbx#1"),
                    src: Expr::Const(1),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rax"))),
                },
            ],
        };

        reconstruct_args_with_params(&mut f, CallConv::SysVAmd64, &[0].into_iter().collect());

        let args = f
            .body
            .iter()
            .find_map(|statement| match statement {
                Stmt::Call { args, .. } => Some(args),
                _ => None,
            })
            .expect("call must survive");
        assert_eq!(
            args,
            &vec![Expr::Reg(reg("rdi")), Expr::Const(24)],
            "the proven live-in remains the machine value in rdi: {:#?}",
            f.body
        );
    }

    #[test]
    fn nonterminal_call_does_not_backfill_across_a_nested_call_clobber() {
        let mut f = Function {
            name: "branching_caller".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rdi")),
                        index: None,
                        scale: 0,
                        disp: 0x100,
                        segment: None,
                    },
                    src: Expr::Const(0),
                    size: 8,
                },
                Stmt::If {
                    cond: Expr::Const(1),
                    then_body: vec![Stmt::Call {
                        target: Expr::Named {
                            va: 0x4000,
                            name: "may_clobber_rdi".to_string(),
                        },
                        args: vec![],
                        dst: None,
                        call_spec: None,
                    }],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: reg("rsi#1"),
                    src: Expr::Const(24),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x5000,
                        name: "sub_5000".to_string(),
                    },
                    args: vec![],
                    dst: Some(reg("rax")),
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: reg("rbx#1"),
                    src: Expr::Const(1),
                },
            ],
        };

        reconstruct_args_with_params(&mut f, CallConv::SysVAmd64, &[0].into_iter().collect());

        let args = f
            .body
            .iter()
            .find_map(|statement| match statement {
                Stmt::Call {
                    target: Expr::Named { name, .. },
                    args,
                    ..
                } if name == "sub_5000" => Some(args),
                _ => None,
            })
            .expect("call must survive");
        assert!(
            args.is_empty(),
            "a nested call may clobber the incoming ABI register: {:#?}",
            f.body
        );
    }

    #[test]
    fn ssa_normalisation_chain_of_one_argument_does_not_hide_earlier_slots() {
        // Clang -O0 commonly zeroes edx and then emits the architectural
        // zero-extension as a second SSA definition immediately before a call.
        // Treating that as an unrelated second write stopped the entire backward
        // scan and lost this, arg1, and arg3 as well as the zero argument.
        let mut f = Function {
            name: "clang_ctor_call".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: reg("rsi#1"),
                    src: Expr::Reg(reg("rsi#0")),
                },
                Stmt::Assign {
                    dst: reg("rcx#1"),
                    src: Expr::Reg(reg("rcx#0")),
                },
                Stmt::Assign {
                    dst: reg("rdi#1"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rbp"))),
                        rhs: Box::new(Expr::Const(32)),
                    },
                },
                Stmt::Assign {
                    dst: reg("rdx#1"),
                    src: Expr::Const(0),
                },
                Stmt::Assign {
                    dst: reg("rdx#2"),
                    src: Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: Box::new(Expr::Reg(reg("rdx#1"))),
                    },
                },
                call_to("ctor"),
            ],
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        let Stmt::Call { args, .. } = f.body.last().expect("call must survive") else {
            panic!("expected call: {:#?}", f.body);
        };
        assert_eq!(
            args.len(),
            4,
            "all contiguous ABI slots must survive: {f:#?}"
        );
        assert_eq!(
            args[2],
            Expr::Cast {
                signed: false,
                width: 8,
                expr: Box::new(Expr::Const(0)),
            }
        );
    }

    #[test]
    fn nonsubstitutable_address_dependency_stays_statement_rooted() {
        // ARM address formation can reuse one ABI slot through two SSA
        // definitions. The later argument expression reads the older value as
        // a LEA component, but substituting an arithmetic expression into that
        // VReg-only component is intentionally unsupported. That is not an
        // invariant failure: keep the older definition and let the call
        // argument continue to reference it.
        let older = Stmt::Assign {
            dst: reg("r0#1"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(reg("r4#1"))),
                rhs: Box::new(Expr::Const(4)),
            },
        };
        let mut f = Function {
            name: "arm_address_arg".to_string(),
            entry_va: 0x1000,
            body: vec![
                older.clone(),
                Stmt::Assign {
                    dst: reg("r0#2"),
                    src: Expr::Lea {
                        base: Some(reg("r0#1")),
                        index: None,
                        scale: 1,
                        disp: 0,
                        segment: None,
                    },
                },
                call_to("callee"),
            ],
        };

        reconstruct_args(&mut f, CallConv::Arm);

        assert_eq!(f.body.first(), Some(&older));
        let Stmt::Call { args, .. } = f.body.last().expect("call must survive") else {
            panic!("expected call: {:#?}", f.body)
        };
        assert_eq!(
            args,
            &[Expr::Lea {
                base: Some(reg("r0#1")),
                index: None,
                scale: 1,
                disp: 0,
                segment: None,
            }]
        );
    }

    #[test]
    fn attributed_register_definition_substitutes_into_address_with_its_owner() {
        let old = reg("r0#1");
        let new = reg("r4#2");
        let owner = OriginSet::one(0x1010);
        let mut address = Expr::Lea {
            base: Some(old.clone()),
            index: None,
            scale: 1,
            disp: 4,
            segment: None,
        };
        let replacement = Expr::Reg(new.clone()).with_origins(owner.clone());

        assert!(substitute_exact_reg(&mut address, &old, &replacement));
        assert!(matches!(
            address.semantic(),
            Expr::Lea { base: Some(base), .. } if base == &new
        ));
        assert_eq!(address.origins(), Some(&owner));
    }

    #[test]
    fn rsp_relative_argument_load_stays_before_tail_epilogue() {
        // GCC saves an incoming value in its local frame, reloads it into the
        // fourth SysV argument register, restores rsp, and only then performs
        // a tail call. Moving the load expression into the call changes its
        // coordinate phase: [rsp+8] before the restore is entry_rsp-16, while
        // [rsp+8] afterwards is the incoming seventh-argument slot.
        let adjust_rsp = |op| Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(24)),
            },
        };
        let local_address = || Expr::Lea {
            base: Some(reg("rsp")),
            index: None,
            scale: 1,
            disp: 8,
            segment: None,
        };
        let saved_load = Stmt::Assign {
            dst: reg("rcx#1"),
            src: Expr::Deref {
                addr: Box::new(local_address()),
                size: 8,
            }
            .with_origins(OriginSet::one(0x1010)),
        };
        let mut f = Function {
            name: "format_wrapper".to_string(),
            entry_va: 0x1000,
            body: vec![
                adjust_rsp(BinOp::Sub),
                Stmt::Store {
                    addr: local_address(),
                    src: Expr::Reg(reg("rsi")),
                    size: 8,
                },
                saved_load.clone(),
                assign("rdx#1", 3),
                assign("rsi#1", 0),
                assign("rdi#1", 0),
                adjust_rsp(BinOp::Add),
                call_to("error"),
            ],
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        assert!(
            f.body.contains(&saved_load),
            "the phase-sensitive load must remain before the rsp restore: {f:#?}"
        );
        let Stmt::Call { args, .. } = f.body.last().expect("call must survive") else {
            panic!("expected call: {f:#?}")
        };
        assert_eq!(args.get(3), Some(&Expr::Reg(reg("rcx#1"))), "{f:#?}");

        crate::ir::stack_locals::promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));
        let rendered = crate::ir::ast::render(&f);
        assert!(!rendered.contains("arg6"), "{rendered}");
    }

    #[test]
    fn fixed_arm_library_contract_crosses_shadowed_argument_setup() {
        // GCC 15 emits two consecutive `mov r1, #0` instructions before the
        // A32 rb_validate memset. The nearest definition is the call input;
        // the older one is shadowed machine state, not a boundary that can
        // erase the already-proven r0-r2 fixed-arity call.
        let destination = Expr::Lea {
            base: Some(reg("sp")),
            index: None,
            scale: 1,
            disp: 12,
            segment: None,
        };
        for convention in [CallConv::Arm, CallConv::ArmHardFloat] {
            let mut function = Function {
                name: "a32_memset_caller".into(),
                entry_va: 0x1000,
                body: vec![
                    assign("r2#1", 64),
                    Stmt::Assign {
                        dst: reg("r0#1"),
                        src: destination.clone(),
                    },
                    assign("r1#1", 0),
                    assign("r1#2", 0),
                    call_to("memset@plt"),
                ],
            };

            reconstruct_args(&mut function, convention);

            let Stmt::Call { args, .. } = function.body.last().expect("memset call must survive")
            else {
                panic!("expected memset call: {:#?}", function.body);
            };
            assert_eq!(
                args,
                &[destination.clone(), Expr::Const(0), Expr::Const(64)],
                "{convention:?}"
            );
        }
    }

    #[test]
    fn fixed_arm_library_contract_excludes_scratch_registers_after_setup() {
        // Thumb rb_validate writes r3 for stack-canary bookkeeping after the
        // complete r0-r2 memset setup. Treating every observed ABI register as
        // a possible argument invents slot three, then an older r3 definition
        // aborts the backward scan and loses the real call entirely.
        let destination = Expr::Lea {
            base: Some(reg("sp")),
            index: None,
            scale: 1,
            disp: 4,
            segment: None,
        };
        let canary = Expr::Deref {
            addr: Box::new(Expr::Reg(reg("r8#1"))),
            size: 4,
        };
        for convention in [CallConv::Arm, CallConv::ArmHardFloat] {
            let mut function = Function {
                name: "thumb_memset_caller".into(),
                entry_va: 0x1000,
                body: vec![
                    assign("r2#1", 64),
                    Stmt::Assign {
                        dst: reg("r0#1"),
                        src: destination.clone(),
                    },
                    assign("r1#1", 0),
                    Stmt::Assign {
                        dst: reg("r3#1"),
                        src: canary.clone(),
                    },
                    Stmt::Store {
                        addr: Expr::Lea {
                            base: Some(reg("sp")),
                            index: None,
                            scale: 1,
                            disp: 324,
                            segment: None,
                        },
                        src: Expr::Reg(reg("r3#1")),
                        size: 4,
                    },
                    assign("r3#2", 0),
                    call_to("memset@plt"),
                ],
            };

            reconstruct_args(&mut function, convention);

            let Stmt::Call { args, .. } = function.body.last().expect("memset call must survive")
            else {
                panic!("expected memset call: {:#?}", function.body);
            };
            assert_eq!(
                args,
                &[destination.clone(), Expr::Const(0), Expr::Const(64)],
                "{convention:?}"
            );
        }
    }

    #[test]
    fn arm_call_argument_keeps_its_current_stack_coordinate() {
        // The r0 definition is relative to the current SP after both frame
        // allocations. Inlining the two older unversioned SP definitions into
        // the call argument changes its coordinate phase; stack promotion then
        // applies the current delta again and addresses entry_sp-740 instead of
        // the real entry_sp-364 object.
        let current_stack_destination = Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::Reg(reg("sp"))),
            rhs: Box::new(Expr::Const(12)),
        };
        let stack_adjust = |amount| Stmt::Assign {
            dst: reg("sp"),
            src: Expr::Bin {
                op: BinOp::Sub,
                lhs: Box::new(Expr::Reg(reg("sp"))),
                rhs: Box::new(Expr::Const(amount)),
            },
        };
        let mut function = Function {
            name: "a32_memset_stack_coordinate".into(),
            entry_va: 0x1000,
            body: vec![
                stack_adjust(36),
                stack_adjust(340),
                assign("r2#1", 64),
                Stmt::Assign {
                    dst: reg("r0#1"),
                    src: current_stack_destination.clone(),
                },
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("sp")),
                        index: None,
                        scale: 1,
                        disp: 332,
                        segment: None,
                    },
                    src: Expr::Reg(reg("r8#1")),
                    size: 4,
                },
                assign("r1#1", 0),
                call_to("memset@plt"),
            ],
        };

        reconstruct_args(&mut function, CallConv::ArmHardFloat);

        let Stmt::Call { args, .. } = function.body.last().expect("memset call must survive")
        else {
            panic!("expected memset call: {:#?}", function.body);
        };
        assert_eq!(
            args,
            &[current_stack_destination, Expr::Const(0), Expr::Const(64)]
        );
    }

    /// On a VALUE-NUMBERED body the incoming value has a version, and only a
    /// version the body mentions may be referenced. Injecting the bare `rdi` gave
    /// `__stack_chk_fail(var24)` — an argument reading a register nothing defines,
    /// in a callee that takes none.
    #[test]
    fn no_bare_register_is_injected_into_a_value_numbered_body() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rdx#7", 256),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "strnlen".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        reconstruct_args_with_params(&mut f, CallConv::Win64, &[0].into_iter().collect());
        let args = f
            .body
            .iter()
            .find_map(|s| match s {
                Stmt::Call { args, .. } => Some(args.clone()),
                _ => None,
            })
            .expect("the call must survive");
        assert!(
            !args
                .iter()
                .any(|a| matches!(a, Expr::Reg(VReg::Phys(n)) if n == "rcx")),
            "injected an unversioned register into a value-numbered body: {args:?}"
        );
    }

    /// A value-numbered body declines the backfill entirely: the live-in version is
    /// not knowable here, and guessing produced an argument that read nothing.
    #[test]
    fn a_value_numbered_body_declines_the_incoming_backfill() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("scratch"),
                    src: Expr::Reg(reg("rcx#1")),
                },
                assign("rdx#7", 256),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "strnlen".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        reconstruct_args_with_params(&mut f, CallConv::Win64, &[0].into_iter().collect());
        let args = f
            .body
            .iter()
            .find_map(|s| match s {
                Stmt::Call { args, .. } => Some(args.clone()),
                _ => None,
            })
            .expect("the call must survive");
        assert!(
            !args
                .iter()
                .any(|a| matches!(a, Expr::Reg(VReg::Phys(n)) if ssa_base(n) == "rcx")),
            "the backfill must not fire on a value-numbered body: {args:?}"
        );
    }

    // --- proven function-pointer-table may-uses ------------------------------

    /// The five entries of `95_function_pointer_table`'s `OPERATIONS`, all with
    /// the same two-integer layout, and one caller-side deviation per test.
    fn table_call(entry_vas: &[u64]) -> Stmt {
        Stmt::Call {
            target: Expr::FunctionTableEntry {
                table_va: 0x3e60,
                table_name: "OPERATIONS".into(),
                pointer_size: 8,
                index: Box::new(Expr::Reg(reg("rax#1"))),
                targets: entry_vas
                    .iter()
                    .map(|va| crate::ir::ast::FunctionTableTarget {
                        va: *va,
                        name: format!("op_{va:x}"),
                    })
                    .collect(),
            },
            args: vec![],
            dst: None,
            call_spec: None,
        }
    }

    fn layouts(entries: &[(u64, &[&str])]) -> std::collections::HashMap<u64, Vec<VReg>> {
        entries
            .iter()
            .map(|(va, storage)| (*va, storage.iter().map(|name| reg(name)).collect()))
            .collect()
    }

    /// The exact `dispatch_operation:gcc:O2` shape: the incoming arguments are
    /// shuffled into place BEFORE the bounds check, and the call happens inside
    /// the guarded arm. Nothing adjacent to the call sets anything up, so the
    /// answer has to come from the enclosing scope's reaching definitions.
    fn guarded_table_dispatch(entry_vas: &[u64]) -> Function {
        Function {
            name: "dispatch_operation".into(),
            entry_va: 0x1150,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax#1"),
                    src: Expr::Reg(reg("rdi")),
                },
                Stmt::Assign {
                    dst: reg("rdi#1"),
                    src: Expr::Reg(reg("rsi")),
                },
                Stmt::Assign {
                    dst: reg("rsi#1"),
                    src: Expr::Reg(reg("rdx")),
                },
                Stmt::If {
                    cond: Expr::Reg(reg("t0")),
                    then_body: vec![
                        table_call(entry_vas),
                        Stmt::Return {
                            value: Some(Expr::Reg(reg("rax"))),
                        },
                    ],
                    else_body: None,
                },
                Stmt::Return {
                    value: Some(Expr::Const(-1)),
                },
            ],
        }
    }

    fn recovered_table_args(f: &Function) -> Vec<Expr> {
        fn find(body: &[Stmt]) -> Option<Vec<Expr>> {
            for statement in body {
                match statement.semantic() {
                    Stmt::Call { target, args, .. }
                        if matches!(target.semantic(), Expr::FunctionTableEntry { .. }) =>
                    {
                        return Some(args.clone())
                    }
                    Stmt::If {
                        then_body,
                        else_body,
                        ..
                    } => {
                        if let Some(found) =
                            find(then_body).or_else(|| else_body.as_deref().and_then(find))
                        {
                            return Some(found);
                        }
                    }
                    Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                        if let Some(found) = find(body) {
                            return Some(found);
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        find(&f.body).expect("the table call must survive")
    }

    fn reconstruct_with_table(
        f: &mut Function,
        table_entry_layouts: &std::collections::HashMap<u64, Vec<VReg>>,
    ) {
        reconstruct_args_with_layouts(
            f,
            CallConv::SysVAmd64,
            &mut [0usize, 1, 2].into_iter().collect(),
            &std::collections::HashMap::new(),
            table_entry_layouts,
        );
    }

    /// A call through a proven table has no callee to ask for a layout, which is
    /// why the direct-call recovery does not generalise to it. It does have a
    /// complete callee SET, and every member here reads `rdi`/`rsi` — so the
    /// call reads the values those registers hold at the call, which are the
    /// enclosing scope's `rdi#1` and `rsi#1`, NOT this function's own `arg0`.
    #[test]
    fn a_proven_table_call_reads_the_enclosing_reaching_definitions() {
        let mut f = guarded_table_dispatch(&[0x1100, 0x1110]);
        let Stmt::If { then_body, .. } = &mut f.body[3] else {
            unreachable!()
        };
        let mut attributed_call = std::mem::replace(&mut then_body[0], Stmt::Nop);
        let Stmt::Call { target, .. } = attributed_call.semantic_mut() else {
            unreachable!()
        };
        let semantic_target = std::mem::replace(target, Expr::Unknown("moved".into()));
        *target = semantic_target.with_origins(OriginSet::one(0x1160));
        then_body[0] = attributed_call.with_origins(OriginSet::one(0x1167));
        let first_owner = OriginSet::one(0x1154);
        let second_owner = OriginSet::one(0x1158);
        for (index, owner) in [(1, first_owner.clone()), (2, second_owner.clone())] {
            let statement = std::mem::replace(&mut f.body[index], Stmt::Nop);
            f.body[index] = statement.with_origins(owner);
        }
        reconstruct_with_table(
            &mut f,
            &layouts(&[(0x1100, &["rdi", "rsi"]), (0x1110, &["rdi", "rsi"])]),
        );
        let args = recovered_table_args(&f);
        assert_eq!(args.len(), 2);
        assert!(matches!(args[0].semantic(), Expr::Reg(value) if value == &reg("rdi#1")));
        assert!(matches!(args[1].semantic(), Expr::Reg(value) if value == &reg("rsi#1")));
        assert_eq!(args[0].origins(), Some(&first_owner));
        assert_eq!(args[1].origins(), Some(&second_owner));
    }

    /// The may-use direction. One entry reads two registers and the other reads
    /// one; the machine may transfer to either, so the union is the WIDER set.
    /// Taking the narrower one would delete the setup of a register an entry
    /// really reads, which is the silent wrong-code direction.
    #[test]
    fn the_table_may_use_set_is_the_widest_entry_not_the_narrowest() {
        let mut f = guarded_table_dispatch(&[0x1100, 0x1110]);
        reconstruct_with_table(
            &mut f,
            &layouts(&[(0x1100, &["rdi"]), (0x1110, &["rdi", "rsi"])]),
        );
        assert_eq!(
            recovered_table_args(&f),
            vec![Expr::Reg(reg("rdi#1")), Expr::Reg(reg("rsi#1"))],
        );
    }

    /// NEGATIVE CONTROL. One unanalysed entry could read anything, so the union
    /// over the set is unknown and the call keeps whatever the ordinary backward
    /// scan found — here, nothing.
    #[test]
    fn a_table_entry_with_no_recovered_layout_leaves_the_call_alone() {
        let mut f = guarded_table_dispatch(&[0x1100, 0x1110]);
        reconstruct_with_table(&mut f, &layouts(&[(0x1100, &["rdi", "rsi"])]));
        assert!(
            recovered_table_args(&f).is_empty(),
            "an incomplete callee set is not a proof about the call"
        );
    }

    /// NEGATIVE CONTROL. Two entries that disagree about which register holds a
    /// parameter have no common reading. Passing `rdi, rsi` would name storage
    /// the second entry never reads as its first parameter.
    #[test]
    fn disagreeing_table_entry_layouts_are_not_unioned() {
        let mut f = guarded_table_dispatch(&[0x1100, 0x1110]);
        reconstruct_with_table(
            &mut f,
            &layouts(&[(0x1100, &["rdi", "rsi"]), (0x1110, &["rsi"])]),
        );
        assert!(recovered_table_args(&f).is_empty());
    }

    /// NEGATIVE CONTROL, and the exact bug that got the 2026-08-12 table-layout
    /// patch reverted: an UNVERSIONED architectural name is one storage with many
    /// definitions. Naming `rdi` at the call would render as this function's own
    /// `arg0` while the register actually holds the shuffled second parameter.
    #[test]
    fn an_unversioned_enclosing_definition_is_never_named_at_a_table_call() {
        let mut f = guarded_table_dispatch(&[0x1100, 0x1110]);
        for statement in &mut f.body {
            if let Stmt::Assign { dst, .. } = statement {
                if let VReg::Phys(name) = dst {
                    *name = ssa_base(name).to_string();
                }
            }
        }
        reconstruct_with_table(
            &mut f,
            &layouts(&[(0x1100, &["rdi", "rsi"]), (0x1110, &["rdi", "rsi"])]),
        );
        assert!(recovered_table_args(&f).is_empty());
    }

    /// NEGATIVE CONTROL. Every ABI argument register is caller-clobbered, so an
    /// intervening call destroys the reaching definition even though the
    /// statement that produced it is still visible above it.
    #[test]
    fn a_call_between_the_setup_and_a_table_call_clobbers_the_slot() {
        let mut f = guarded_table_dispatch(&[0x1100, 0x1110]);
        f.body.insert(3, call_to("side_effect"));
        reconstruct_with_table(
            &mut f,
            &layouts(&[(0x1100, &["rdi", "rsi"]), (0x1110, &["rdi", "rsi"])]),
        );
        assert!(recovered_table_args(&f).is_empty());
    }

    /// A dispatch loop whose accumulator lives in an argument register. The
    /// back edge writes the SAME value-numbered name the pre-loop initializer
    /// wrote, so that name is exactly what reaches the call on every iteration —
    /// this is `loop_carried_arg_inputs`' existing proof, and the may-use path
    /// must defer to it rather than to the stale pre-loop definition.
    fn table_dispatch_loop(update: &str) -> Function {
        Function {
            name: "fold_operations".into(),
            entry_va: 0x1120,
            body: vec![
                Stmt::Assign {
                    dst: reg("rdi#1"),
                    src: Expr::Reg(reg("rsi")),
                },
                Stmt::Assign {
                    dst: reg("rsi#1"),
                    src: Expr::Reg(reg("rdx")),
                },
                Stmt::While {
                    cond: Expr::Reg(reg("t0")),
                    body: vec![
                        table_call(&[0x1100, 0x1110]),
                        Stmt::Assign {
                            dst: reg(update),
                            src: Expr::Reg(reg("rax")),
                        },
                    ],
                },
                Stmt::Return { value: None },
            ],
        }
    }

    #[test]
    fn a_table_call_in_a_loop_reads_the_loop_carried_definition() {
        let mut f = table_dispatch_loop("rsi#1");
        reconstruct_with_table(
            &mut f,
            &layouts(&[(0x1100, &["rdi", "rsi"]), (0x1110, &["rdi", "rsi"])]),
        );
        assert_eq!(
            recovered_table_args(&f),
            vec![Expr::Reg(reg("rdi#1")), Expr::Reg(reg("rsi#1"))],
        );
    }

    /// NEGATIVE CONTROL. Same loop, but the back edge writes a DIFFERENT name.
    /// Nothing then proves what the second iteration finds in `rsi`, so the
    /// pre-loop definition is stale and the whole argument list is refused
    /// rather than half of it being invented.
    #[test]
    fn a_loop_that_rewrites_the_slot_under_a_new_name_declines() {
        let mut f = table_dispatch_loop("rsi#2");
        reconstruct_with_table(
            &mut f,
            &layouts(&[(0x1100, &["rdi", "rsi"]), (0x1110, &["rdi", "rsi"])]),
        );
        assert!(
            recovered_table_args(&f).is_empty(),
            "the loop rewrites the slot and nothing proves the carried value"
        );
    }

    /// NEGATIVE CONTROL. An indirect call that is NOT through a proven table has
    /// no callee set at all, so nothing here fires and the ordinary recovery is
    /// untouched.
    #[test]
    fn an_indirect_call_that_is_not_a_proven_table_gains_nothing() {
        let mut f = guarded_table_dispatch(&[0x1100, 0x1110]);
        if let Some(Stmt::If { then_body, .. }) = f.body.get_mut(3) {
            then_body[0] = Stmt::Call {
                target: Expr::Reg(reg("rax#2")),
                args: vec![],
                dst: None,
                call_spec: None,
            };
        }
        reconstruct_with_table(
            &mut f,
            &layouts(&[(0x1100, &["rdi", "rsi"]), (0x1110, &["rdi", "rsi"])]),
        );
        let args = f
            .body
            .iter()
            .find_map(|statement| match statement {
                Stmt::If { then_body, .. } => match &then_body[0] {
                    Stmt::Call { args, .. } => Some(args.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("the call must survive");
        assert!(args.is_empty());
    }
}
