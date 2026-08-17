//! The DecBench type maps: the `(declaration, expression-width)` `TypeMap` pair
//! the DecBench C renderer consumes, and the projections that build it.
//!
//! Type recovery produces facts keyed by machine STORAGE (`rdi`, `edi`, a frame
//! offset). The renderer needs them keyed by the AST's ROLE names (`arg0`,
//! `ret`, `local_8`). Everything in this module is that projection, plus the
//! refinements that sharpen it: promoted slot sizes, exact definition widths,
//! DWARF source types, per-value SSA evidence, and the float-copy fixed point.
//!
//! Two entry points cross back into the parent: [`decbench_type_maps`] for
//! `style="decbench"`, and [`remap_type_map`] for the plain `types=True`
//! render. Nothing here touches the AST, the LLIR, or PyO3.

use super::dwarf_contracts::dwarf_return_hint_with_env;
use crate::ir::abi::machine_word_bytes;

/// Fold recovered stack-slot sizes into a (already-remapped) TypeMap as
/// width-typed integers keyed by the promoted local name (`local_0`,
/// `stack_1`, …). `upsert_public` keeps any more-specific classification
/// (e.g. a pointer), so this only supplies a committed width where nothing
/// else typed the slot.
fn merge_slot_sizes(
    tm: &mut crate::ir::types_recover::TypeMap,
    sizes: &std::collections::HashMap<String, u8>,
    cc: crate::ir::call_args::CallConv,
) {
    let word = machine_word_bytes(cc);
    for (name, &size) in sizes {
        if size == 0 {
            continue;
        }
        // A machine-word-sized frame slot is a spill slot, and on a 32-bit
        // target a spilled POINTER lands in one exactly as often as a spilled
        // `int` does — `-O0` spills every parameter. Declaring it `int` there
        // truncated the pointer once the recovered C was rebuilt at the host
        // pointer width. A genuinely narrower slot still states its own width on
        // every target. Same rule as `merge_exact_definition_widths`, and gated
        // by the same predicate — see `word_width_implies_int`.
        if size >= word && !word_width_implies_int(cc) {
            continue;
        }
        tm.upsert_public(
            crate::ir::types::VReg::Phys(name.clone()),
            crate::ir::types_recover::TypeHint::Int {
                signed: true,
                width: size,
            },
        );
    }
}

/// Rebuild a TypeMap whose keys match the post-rename AST. We walk the
/// original physical-register TypeMap and, for each entry, look up the
/// alias the naming pass would have produced. Any remaining entries keep
/// their original names so the printer still has a chance to annotate.
pub(super) fn remap_type_map(
    tm: &crate::ir::types_recover::TypeMap,
    _f: &crate::ir::ast::Function,
    cc: crate::ir::call_args::CallConv,
    param_slots: &std::collections::HashSet<usize>,
) -> crate::ir::types_recover::TypeMap {
    remap_type_map_impl(tm, cc, param_slots, true, None, false)
}

fn remap_type_map_impl(
    tm: &crate::ir::types_recover::TypeMap,
    cc: crate::ir::call_args::CallConv,
    param_slots: &std::collections::HashSet<usize>,
    include_parameters: bool,
    exact_roles: Option<&std::collections::HashMap<String, String>>,
    exact_integer_roles: bool,
) -> crate::ir::types_recover::TypeMap {
    // Reconstruct the alias table the naming pass used for arg/ret slots;
    // `varN` aliases are assigned by first-appearance order and we can't
    // trivially recover them here, so those keys survive untouched.
    let mut alias: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let arg_slots: &[&[&str]] = match cc {
        crate::ir::call_args::CallConv::SysVAmd64 => &[
            &["rdi", "edi", "di", "dil"],
            &["rsi", "esi", "si", "sil"],
            &["rdx", "edx", "dx", "dl"],
            &["rcx", "ecx", "cx", "cl"],
            &["r8", "r8d", "r8w", "r8b"],
            &["r9", "r9d", "r9w", "r9b"],
        ],
        crate::ir::call_args::CallConv::Win64 => &[
            &["rcx", "ecx", "cx", "cl"],
            &["rdx", "edx", "dx", "dl"],
            &["r8", "r8d", "r8w", "r8b"],
            &["r9", "r9d", "r9w", "r9b"],
        ],
        crate::ir::call_args::CallConv::Cdecl32 => &[],
        crate::ir::call_args::CallConv::Aarch64 => &[
            &["x0", "w0"],
            &["x1", "w1"],
            &["x2", "w2"],
            &["x3", "w3"],
            &["x4", "w4"],
            &["x5", "w5"],
            &["x6", "w6"],
            &["x7", "w7"],
        ],
        crate::ir::call_args::CallConv::Arm | crate::ir::call_args::CallConv::ArmHardFloat => {
            &[&["r0"], &["r1"], &["r2"], &["r3"]]
        }
    };
    for (slot, names) in arg_slots.iter().enumerate() {
        // Only alias a slot's registers to `argN` when it is a genuine live-in
        // parameter. An argument-slot register reused as scratch (common at -O2,
        // e.g. `rdx`/`rcx`) must not become a spurious `argN` and inflate the
        // recovered arity/typing.
        if !include_parameters || !param_slots.contains(&slot) {
            continue;
        }
        for n in *names {
            alias
                .entry(n.to_string())
                .or_insert_with(|| format!("arg{}", slot));
        }
    }
    let ret_aliases: &[&str] = match cc {
        crate::ir::call_args::CallConv::SysVAmd64 | crate::ir::call_args::CallConv::Win64 => {
            &["rax", "eax", "ax", "al"]
        }
        crate::ir::call_args::CallConv::Cdecl32 => &["rax", "eax", "ax", "al"],
        crate::ir::call_args::CallConv::Aarch64 => &["x0", "w0"],
        crate::ir::call_args::CallConv::Arm | crate::ir::call_args::CallConv::ArmHardFloat => {
            &["r0", "s0", "d0"]
        }
    };
    for n in ret_aliases {
        alias
            .entry(n.to_string())
            .or_insert_with(|| "ret".to_string());
    }
    let mut out = crate::ir::types_recover::TypeMap::default();
    for (reg, hint) in tm.iter() {
        match reg {
            crate::ir::types::VReg::Phys(n) => {
                if matches!(hint, crate::ir::types_recover::TypeHint::Float { .. }) {
                    // Raw type recovery sees the architectural VFP register
                    // (`s15`), while value numbering deliberately splits its
                    // definitions (`s15#1`, `s15#2`, ...). Every such exact
                    // role carries the same scalar storage class; projecting
                    // only an exact bare-name match leaves merged values as
                    // `long` and silently truncates float arithmetic in C.
                    let mut projected = false;
                    if let Some(roles) = exact_roles {
                        for (storage, role) in roles {
                            if crate::ir::abi::ssa_base(storage) == n
                                && (include_parameters
                                    || crate::ir::ast::parse_arg_index(role).is_none())
                            {
                                out.upsert_public(
                                    crate::ir::types::VReg::Phys(role.clone()),
                                    *hint,
                                );
                                projected = true;
                            }
                        }
                    }
                    if projected {
                        continue;
                    }
                }
                // Exact first-appearance aliases are needed only for semantic
                // float storage: unlike broad scalar guesses, a typed VFP
                // intrinsic proves every operand's source class. Keeping this
                // projection narrow avoids letting flow-insensitive register
                // hints perturb unrelated call prototypes.
                let exact = (exact_integer_roles
                    || matches!(
                        hint,
                        crate::ir::types_recover::TypeHint::Float { .. }
                            | crate::ir::types_recover::TypeHint::Pointer { .. }
                    ))
                .then(|| exact_roles.and_then(|roles| roles.get(n)))
                .flatten()
                .filter(|role| {
                    include_parameters || crate::ir::ast::parse_arg_index(role).is_none()
                })
                .cloned();
                let new_name = exact
                    .or_else(|| alias.get(n).cloned())
                    .unwrap_or_else(|| n.clone());
                out.upsert_public(crate::ir::types::VReg::Phys(new_name), *hint);
            }
            _ => out.upsert_public(reg.clone(), *hint),
        }
    }
    out
}

fn float_expression_width(
    expression: &crate::ir::ast::Expr,
    types: &crate::ir::types_recover::TypeMap,
) -> Option<u8> {
    use crate::ir::ast::Expr;
    use crate::ir::types_recover::TypeHint;

    match expression {
        Expr::Reg(register) => match types.get(register) {
            Some(TypeHint::Float { width }) => Some(width),
            _ => None,
        },
        Expr::FloatConst { width, .. } => Some(*width),
        Expr::Un { src, .. } => float_expression_width(src, types),
        Expr::Bin { lhs, rhs, .. } => {
            float_expression_width(lhs, types).or_else(|| float_expression_width(rhs, types))
        }
        Expr::Select {
            if_true, if_false, ..
        } => float_expression_width(if_true, types)
            .or_else(|| float_expression_width(if_false, types)),
        _ => None,
    }
}

/// Carry semantic float facts through the source-level copies introduced by
/// stack promotion and SSA-merge lowering.
///
/// The raw LLIR map proves that `s0`/`s15` carry floats, but a promoted stack
/// slot is named only later (`local_c`). Treating its four-byte extent as an
/// integer changes a numeric float copy into a C conversion. This small fixed
/// point preserves the already-proven class without guessing from width alone.
///
/// The loop terminates because progress is measured by what the map ACTUALLY
/// holds afterwards, never by whether the proposed hint was adopted.
/// `TypeMap::refine_from_value` is a lattice join with the right to decline —
/// it is a no-op on a locked register, and `(Float{8}, Float{4})` falls through
/// to its conservative arm — so "the destination does not equal the hint I want"
/// is a condition a re-run cannot clear. Reporting that as progress spun
/// `172_float_double_widths:gcc:O2:accumulate_wide` forever (a `double`
/// accumulator fed by a `float` term is exactly the declined join), and because
/// the spin is inside one pass, no `timeout_ms` between passes could cap it.
fn refine_float_copy_types(
    body: &[crate::ir::ast::Stmt],
    types: &mut crate::ir::types_recover::TypeMap,
) {
    use crate::ir::ast::{Expr, Stmt};
    use crate::ir::types::{VReg, VReg::Phys};
    use crate::ir::types_recover::TypeHint;

    fn refine(
        destination: &VReg,
        source: &Expr,
        types: &mut crate::ir::types_recover::TypeMap,
        changed: &mut bool,
    ) {
        let Some(width) = float_expression_width(source, types) else {
            return;
        };
        let hint = TypeHint::Float { width };
        let before = types.get(destination);
        if before == Some(hint) {
            return;
        }
        types.refine_from_value(destination.clone(), hint);
        if types.get(destination) != before {
            *changed = true;
        }
    }

    fn visit(body: &[Stmt], types: &mut crate::ir::types_recover::TypeMap, changed: &mut bool) {
        for statement in body {
            match statement {
                Stmt::Assign { dst, src } => refine(dst, src, types, changed),
                Stmt::Store {
                    addr: Expr::Reg(destination @ Phys(name)),
                    src,
                    ..
                } if name.starts_with("local_") || name.starts_with("stack_") => {
                    refine(destination, src, types, changed);
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    visit(then_body, types, changed);
                    if let Some(else_body) = else_body {
                        visit(else_body, types, changed);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                    visit(body, types, changed)
                }
                Stmt::For {
                    init, step, body, ..
                } => {
                    visit(std::slice::from_ref(init.as_ref()), types, changed);
                    visit(body, types, changed);
                    visit(std::slice::from_ref(step.as_ref()), types, changed);
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        visit(case_body, types, changed);
                    }
                    if let Some(default) = default {
                        visit(default, types, changed);
                    }
                }
                _ => {}
            }
        }
    }

    // Every reported round strictly changes at least one entry, and the join
    // only ever moves a register from "no fact"/integer-ish to float, so the
    // number of rounds is bounded by the number of float-typed destinations.
    // The cap is a backstop against a future non-monotone edit to the lattice:
    // it fails loudly in debug builds rather than hanging a release gate.
    const MAX_ROUNDS: usize = 512;
    let mut rounds = 0;
    loop {
        let mut changed = false;
        visit(body, types, &mut changed);
        rounds += 1;
        if !changed {
            break;
        }
        if rounds >= MAX_ROUNDS {
            debug_assert!(
                false,
                "refine_float_copy_types did not reach a fixed point in {MAX_ROUNDS} rounds"
            );
            break;
        }
    }
}

/// Build the `(declaration, width)` type-map pair the DecBench renderer needs.
///
/// Machine-width facts come from the PRE-canonicalisation LLIR (`lf_raw`), the only
/// place each operand's true machine width survives (`edi`=4; canonicalisation folds
/// it into `rdi`). That width is what the declaration should state — DWARF's
/// `dispatch(int,int,int)`, not a blanket `long` — and what the logical-shift cast
/// needs. Parameter facts are projected from the pre-lowering `RecoveredPrototype`,
/// which retains exact SSA live-in identity. Only non-parameter roles are remapped
/// from storage names; both maps are then augmented with promoted-slot sizes.
/// Whether a MACHINE-WORD-sized definition or frame slot should be read as
/// evidence that the value is an `int` of that width.
///
/// True on the 64-bit conventions, where writing `edi` instead of `rdi` is a
/// narrowing the compiler chose and is *the* -O0 type-recovery signal.
///
/// False on cdecl32, where four bytes is the whole register and the same fact is
/// equally consistent with `int`, `long` and a pointer. Recording it as `int`
/// truncated every pointer that flowed through a machine register or a spill
/// slot once the recovered C was rebuilt at the host pointer width, which was
/// 50 of i386's 110 execution failures.
///
/// Deliberately still TRUE for the 32-bit ARM conventions. They have the same
/// ambiguity but not the same balance: the ARM32 lifter has no sub-register
/// spellings, so its machine registers are already declared `long` and this rule
/// would only change FRAME SLOTS. Measured on `tools/arch_roundtrip.py`, doing
/// that costs armv7 two functions and gains none —
/// `03_loop_shapes:O0:dowhile_recompute` (`t >>= 8` on a `long` no longer wraps
/// at 32 bits, so the loop runs eight times instead of four) and
/// `11_call_shapes:O0:call_result_drives_branch` (a 32-bit call result widened
/// to `long` acquires the callee's undefined high half, inverting a sign test).
/// Both are the cost side of the same trade i386 wins on.
///
/// The durable fix for both is to propagate POINTER types through copies rather
/// than inferring a type from storage width at all; until that exists, this
/// records exactly where the trade has been measured to pay.
fn word_width_implies_int(cc: crate::ir::call_args::CallConv) -> bool {
    !matches!(cc, crate::ir::call_args::CallConv::Cdecl32)
}

fn merge_exact_definition_widths(
    tm: &mut crate::ir::types_recover::TypeMap,
    definition_widths: &std::collections::HashMap<crate::ir::types::VReg, u8>,
    role_names: &std::collections::HashMap<String, String>,
    cc: crate::ir::call_args::CallConv,
) {
    let word = machine_word_bytes(cc);
    // Collect first, apply second. `role_names` is many-to-one: several machine
    // storages name one rendered role, and `ret` in particular collects every
    // return carrier the naming pass found — an integer `rax#3` and an SSE
    // `xmm0` alike. `TypeMap::refine_from_value` is last-write-wins on integer
    // width, so writing straight out of a `HashMap` walk let iteration order
    // pick the declared width.
    //
    // That is not a per-process defect. `RandomState::new` bumps a per-thread
    // counter for every map it builds, so two maps built at different moments in
    // ONE process hash differently; the winner therefore changed from one
    // `decompile_at` call to the next inside a single interpreter. Measured on
    // the 30 `-rustc-` objects in `tests/decompiler_fixtures/build`, three
    // same-process passes over 5595 functions at `style="decbench"` left 13
    // functions with more than one rendered text, every one of them a return
    // type flipping between `long`, `unsigned long` and `unsigned int` in both
    // directions. Same failure mode, same symptom and same fix shape as
    // `ir::stack_locals`, whose bare `collect()` alternated `char` and `long`.
    //
    // Conflicts are resolved by withholding rather than by picking a winner: a
    // census over those 11 190 merge calls found 506 (4.5%) with a role whose
    // storages disagree, and `ret` is the ONLY role that ever disagrees
    // (`(8,16)` 384, `(4,8)` 84, `(4,16)` 22, `(2,8)` 16). When the projection
    // is not injective and its sources disagree there is no "exact definition
    // width" for that role to state, and `ret` has two stronger, value-keyed
    // sources on either side of this call — `RecoveredPrototype::result_type_map`
    // above and the explicit `recovered_width.max(proven_width)` union in
    // `ast::refine_decbench_abi_widths_with_value_widths` below. Same rule as
    // `stack_locals`'s `ambiguous_coordinates`.
    let mut by_role: std::collections::BTreeMap<&str, Option<u8>> =
        std::collections::BTreeMap::new();
    for (storage, &exact_width) in definition_widths {
        // A full-width machine-register definition on a 32-bit target is not a
        // narrowing and therefore not evidence of an `int`. Recording it as one
        // declares every machine word `int`, and the DecBench C is rebuilt at the
        // HOST pointer width — so a recovered `var = p; var = var + 4;` chain
        // truncated the pointer to 32 bits and faulted, and an assignment from
        // such an `int` into a `long` role acquired a `(unsigned long)(unsigned
        // int)` conversion that did the same. Narrower definitions (a byte or a
        // halfword) remain genuine narrowing evidence on every target. Gated by
        // `word_width_implies_int`, which records where the trade measures out.
        if exact_width >= word && !word_width_implies_int(cc) {
            continue;
        }
        let crate::ir::types::VReg::Phys(storage_name) = storage else {
            continue;
        };
        let Some(role_name) = role_names.get(storage_name) else {
            continue;
        };
        // A later use of an ABI argument register is a new value, not new
        // evidence about the function's entry parameter.  In particular,
        // `mov esi, 1` before a recursive call must not narrow an entry `%rsi`
        // that was spilled, reloaded, and compared as a 64-bit parameter.
        // Parameter widths come from `RecoveredPrototype`'s exact SSA live-in;
        // this legacy storage-name projection is only valid for non-parameter
        // roles whose definition identity the naming pass retained.
        if crate::ir::ast::parse_arg_index(role_name).is_some() {
            continue;
        }
        by_role
            .entry(role_name.as_str())
            .and_modify(|agreed| {
                if *agreed != Some(exact_width) {
                    *agreed = None;
                }
            })
            .or_insert(Some(exact_width));
    }
    for (role_name, agreed_width) in by_role {
        // Two storages disagreed about this role's width; the projection states
        // nothing rather than whichever one the hash happened to order last.
        let Some(exact_width) = agreed_width else {
            continue;
        };
        let role = crate::ir::types::VReg::phys(role_name);
        // An exact SSA value used as an address is stronger than its register
        // storage width. On 32-bit ARM both facts are four bytes, but projecting
        // the latter as `int` truncates the former when DecBench recompiles the
        // recovered C on a 64-bit host (`var = p; *(var + 4)`).
        if matches!(
            tm.get(&role),
            Some(
                crate::ir::types_recover::TypeHint::Pointer { .. }
                    | crate::ir::types_recover::TypeHint::CodePointer
            )
        ) {
            continue;
        }
        let signed = match tm.get(&role) {
            Some(crate::ir::types_recover::TypeHint::Int { signed, .. }) => signed,
            // The definition map proves storage width, not source-language
            // signedness. Preserve richer evidence when present and otherwise
            // keep the renderer's conservative signed-integer default.
            _ => true,
        };
        tm.refine_from_value(
            role,
            crate::ir::types_recover::TypeHint::Int {
                signed,
                width: exact_width,
            },
        );
    }
}

pub(super) fn decbench_type_maps(
    f: &crate::ir::ast::Function,
    lf_raw: &crate::ir::types::LlirFunction,
    lf_numbered: &crate::ir::types::LlirFunction,
    prototype: &crate::ir::types_recover::RecoveredPrototype,
    cc: crate::ir::call_args::CallConv,
    param_slots: &std::collections::HashSet<usize>,
    slot_sizes: &std::collections::HashMap<String, u8>,
    source_types: &std::collections::HashMap<String, String>,
    source_names: &std::collections::HashMap<String, String>,
    dwarf_type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
    role_names: &std::collections::HashMap<String, String>,
    definition_widths: &std::collections::HashMap<crate::ir::types::VReg, u8>,
) -> (
    crate::ir::types_recover::TypeMap,
    crate::ir::types_recover::TypeMap,
    std::collections::HashMap<String, u8>,
) {
    use crate::ir::types_recover::recover_types_for;
    let raw = recover_types_for(lf_raw, cc);
    let numbered = remap_type_map_impl(
        &recover_types_for(lf_numbered, cc),
        cc,
        param_slots,
        false,
        Some(role_names),
        true,
    );
    let mut decl = remap_type_map_impl(&raw, cc, param_slots, false, Some(role_names), false);
    let live_ins = prototype.parameter_type_map();
    let result = prototype.result_type_map();
    if let Some(hint) = result.get(&crate::ir::types::VReg::phys("ret")) {
        if prototype.output_is_locked() {
            decl.apply_locked_fact(crate::ir::types::VReg::phys("ret"), hint);
        } else {
            decl.refine_from_value(crate::ir::types::VReg::phys("ret"), hint);
        }
    }
    // Only entry values with the qualified spill/reload/dereference proof are
    // allowed to refine a rendered role. The complete version-zero map remains
    // available to analysis, but prototype recovery is not yet a fixed point
    // with function boundaries and direct-callee types.
    for parameter in prototype.parameters() {
        let role = crate::ir::types::VReg::Phys(format!("arg{}", parameter.slot));
        let hint = live_ins.get(&role).or_else(|| {
            prototype.parameter_arity_is_locked().then_some(
                crate::ir::types_recover::TypeHint::Int {
                    signed: true,
                    width: crate::ir::abi::machine_word_bytes(cc),
                },
            )
        });
        if let Some(hint) = hint {
            if prototype.parameter_is_locked(parameter.slot) {
                decl.apply_locked_fact(role, hint);
            } else {
                decl.refine_from_value(role, hint);
            }
        }
    }
    merge_slot_sizes(&mut decl, slot_sizes, cc);
    apply_stack_source_types(&mut decl, source_types, source_names, cc, dwarf_type_env);
    merge_exact_definition_widths(&mut decl, definition_widths, role_names, cc);
    crate::ir::call_contracts::refine_call_result_types(f, &mut decl);
    refine_float_copy_types(&f.body, &mut decl);
    for (role, hint) in numbered.iter() {
        refine_numbered_declaration(&mut decl, role, hint);
    }
    let mut width = remap_type_map_impl(&raw, cc, param_slots, false, Some(role_names), false);
    if let Some(hint) = result.get(&crate::ir::types::VReg::phys("ret")) {
        if prototype.output_is_locked() {
            width.apply_locked_fact(crate::ir::types::VReg::phys("ret"), hint);
        } else {
            width.refine_from_value(crate::ir::types::VReg::phys("ret"), hint);
        }
    }
    for parameter in prototype.parameters() {
        let role = crate::ir::types::VReg::Phys(format!("arg{}", parameter.slot));
        let hint = live_ins.get(&role).or_else(|| {
            prototype.parameter_arity_is_locked().then_some(
                crate::ir::types_recover::TypeHint::Int {
                    signed: true,
                    width: crate::ir::abi::machine_word_bytes(cc),
                },
            )
        });
        if let Some(hint) = hint {
            if prototype.parameter_is_locked(parameter.slot) {
                width.apply_locked_fact(role, hint);
            } else {
                width.refine_from_value(role, hint);
            }
        }
    }
    merge_slot_sizes(&mut width, slot_sizes, cc);
    apply_stack_source_types(&mut width, source_types, source_names, cc, dwarf_type_env);
    merge_exact_definition_widths(&mut width, definition_widths, role_names, cc);
    crate::ir::call_contracts::refine_call_result_types(f, &mut width);
    refine_float_copy_types(&f.body, &mut width);
    for (role, hint) in numbered.iter() {
        match hint {
            crate::ir::types_recover::TypeHint::Pointer { pointee_width } => {
                width.refine_from_value(
                    role.clone(),
                    crate::ir::types_recover::TypeHint::Pointer {
                        pointee_width: *pointee_width,
                    },
                );
            }
            crate::ir::types_recover::TypeHint::Int {
                signed,
                width: exact_width,
            } if matches!(
                width.get(role),
                Some(crate::ir::types_recover::TypeHint::Int { .. })
            ) =>
            {
                // This companion map governs expression casts, not storage
                // declarations. Per-value SSA evidence therefore owns both
                // width and signedness: raw-register recovery routinely sees a
                // zero-extended move before the same value's signed wide use.
                width.force_int_width(role.clone(), *exact_width);
                width.force_int_signedness(role.clone(), *signed);
            }
            _ => {}
        }
    }
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!("\n===== exact role names =====\n{role_names:#?}");
        eprintln!("\n===== numbered value types =====\n{numbered:#?}");
        eprintln!("\n===== recovered declaration types =====\n{decl:#?}");
        eprintln!("\n===== recovered expression-width types =====\n{width:#?}");
    }
    let exact_value_widths = integer_widths_by_role(&width);
    (decl, width, exact_value_widths)
}

fn apply_stack_source_types(
    types: &mut crate::ir::types_recover::TypeMap,
    source_types: &std::collections::HashMap<String, String>,
    source_names: &std::collections::HashMap<String, String>,
    cc: crate::ir::call_args::CallConv,
    dwarf_type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
) {
    for (internal_name, c_type) in source_types {
        let Some(hint) = dwarf_return_hint_with_env(c_type, cc, dwarf_type_env) else {
            continue;
        };
        types.apply_locked_fact(crate::ir::types::VReg::phys(internal_name), hint);
        if let Some(source_name) = source_names.get(internal_name) {
            types.apply_locked_fact(crate::ir::types::VReg::phys(source_name), hint);
        }
    }
}

/// Extract scalar widths from the final per-value expression map.
///
/// This map has already combined raw operation evidence with exact numbered
/// identities. It intentionally excludes pointers and floats: declaration-kind
/// recovery owns those, while this companion only answers integer expression
/// width after prepared AST copies have hidden the original storage spelling.
fn integer_widths_by_role(
    widths: &crate::ir::types_recover::TypeMap,
) -> std::collections::HashMap<String, u8> {
    widths
        .iter()
        .filter_map(|(role, hint)| match (role, hint) {
            (
                crate::ir::types::VReg::Phys(role),
                crate::ir::types_recover::TypeHint::Int { width, .. },
            ) => Some((role.clone(), *width)),
            _ => None,
        })
        .collect()
}

/// Apply per-value SSA evidence without discarding a previously proven pointer.
fn refine_numbered_declaration(
    decl: &mut crate::ir::types_recover::TypeMap,
    role: &crate::ir::types::VReg,
    hint: &crate::ir::types_recover::TypeHint,
) {
    match hint {
        crate::ir::types_recover::TypeHint::Pointer { pointee_width } => {
            decl.refine_from_value(
                role.clone(),
                crate::ir::types_recover::TypeHint::Pointer {
                    pointee_width: *pointee_width,
                },
            );
        }
        // Register width alone does not prove a source integer declaration.
        // This is especially important when a 32-bit pointer is transported
        // through a full-width GPR and the recovered C is rebuilt on a 64-bit
        // host. Prepared-AST definition widths refine genuine wide scalars
        // later, with enough context to distinguish those cases.
        crate::ir::types_recover::TypeHint::Int { .. } => {}
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{
        integer_widths_by_role, merge_exact_definition_widths, refine_float_copy_types,
        refine_numbered_declaration,
    };
    use crate::ir::ast::{Expr, Stmt};
    use crate::ir::call_args::CallConv;
    use crate::ir::types::VReg;
    use crate::ir::types_recover::{TypeHint, TypeMap};
    use std::collections::HashMap;

    #[test]
    fn float_copy_refinement_terminates_when_the_join_declines_the_hint() {
        // `double total = ...; total += (double)step;` with a `float` term:
        // the destination already holds `Float{8}` and the source proposes
        // `Float{4}`, which `refine_from_value` is entitled to decline. The
        // fixed point must observe that the map did not move, not that its
        // proposal was not adopted — the latter never becomes false, which is
        // how `172_float_double_widths:gcc:O2:accumulate_wide` hung forever.
        let accumulator = VReg::phys("local_8");
        let mut types = TypeMap::default();
        types.upsert_public(accumulator.clone(), TypeHint::Float { width: 8 });
        let body = vec![Stmt::Assign {
            dst: accumulator.clone(),
            src: Expr::FloatConst { bits: 0, width: 4 },
        }];

        refine_float_copy_types(&body, &mut types);

        assert_eq!(types.get(&accumulator), Some(TypeHint::Float { width: 8 }));
    }

    #[test]
    fn float_copy_refinement_still_propagates_onto_an_untyped_slot() {
        let slot = VReg::phys("local_c");
        let source = VReg::phys("s0");
        let mut types = TypeMap::default();
        types.upsert_public(source.clone(), TypeHint::Float { width: 4 });
        let body = vec![Stmt::Assign {
            dst: slot.clone(),
            src: Expr::Reg(source),
        }];

        refine_float_copy_types(&body, &mut types);

        assert_eq!(types.get(&slot), Some(TypeHint::Float { width: 4 }));
    }

    #[test]
    fn semantic_value_widths_exclude_non_integer_kinds() {
        let mut widths = TypeMap::default();
        widths.upsert_public(
            VReg::phys("var0"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );
        widths.upsert_public(VReg::phys("var1"), TypeHint::Pointer { pointee_width: 8 });

        assert_eq!(
            integer_widths_by_role(&widths),
            HashMap::from([("var0".to_string(), 4)])
        );
    }

    #[test]
    fn later_subregister_definition_does_not_narrow_a_parameter_prototype() {
        let argument = VReg::phys("arg1");
        let mut types = TypeMap::default();
        types.upsert_public(
            argument.clone(),
            TypeHint::Int {
                signed: true,
                width: 8,
            },
        );
        let definition_widths = HashMap::from([(VReg::phys("esi"), 4)]);
        let role_names = HashMap::from([("esi".to_string(), "arg1".to_string())]);

        merge_exact_definition_widths(
            &mut types,
            &definition_widths,
            &role_names,
            CallConv::SysVAmd64,
        );

        assert_eq!(
            types.get(&argument),
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            })
        );
    }

    /// Two machine storages, one rendered role, disagreeing widths: the role
    /// must come out the same every time.
    ///
    /// `role_names` is many-to-one, and `ret` is where it actually collides:
    /// the naming pass maps every return carrier onto that one role, so an
    /// integer `rax#3` (8 bytes) and an SSE `xmm0` (16) both land on it. This
    /// loop used to write straight into the `TypeMap` out of a `HashMap` walk,
    /// and `refine_from_value` is last-write-wins on width, so whichever
    /// storage the hash ordered last chose the declared return type.
    ///
    /// The reproduction was not across processes. `RandomState::new` bumps a
    /// per-thread counter per map, so two maps built at different points in one
    /// process iterate differently: 16 repeated
    /// `decompile_at(169_rust_slices_bounds-rustc-O2.so, 0x70a0,
    /// style="decbench")` calls in a single interpreter returned both `long
    /// rust_slice_get_range(...)` and `unsigned long rust_slice_get_range(...)`.
    /// 64 iterations here because a 50/50 flip needs repeats to be caught.
    #[test]
    fn colliding_storages_for_one_role_state_no_width_instead_of_racing() {
        let ret = VReg::phys("ret");
        for _ in 0..64 {
            let mut types = TypeMap::default();
            types.upsert_public(
                ret.clone(),
                TypeHint::Int {
                    signed: false,
                    width: 4,
                },
            );
            let definition_widths =
                HashMap::from([(VReg::phys("rax#3"), 8), (VReg::phys("xmm0"), 16)]);
            let role_names = HashMap::from([
                ("rax#3".to_string(), "ret".to_string()),
                ("xmm0".to_string(), "ret".to_string()),
            ]);

            merge_exact_definition_widths(
                &mut types,
                &definition_widths,
                &role_names,
                CallConv::SysVAmd64,
            );

            assert_eq!(
                types.get(&ret),
                Some(TypeHint::Int {
                    signed: false,
                    width: 4,
                }),
                "an ambiguous storage->role projection must state no width, \
                 not whichever storage the hash ordered last"
            );
        }
    }

    /// Agreement is not ambiguity: several storages that all say the same
    /// width still refine the role.
    #[test]
    fn agreeing_storages_for_one_role_still_refine_it() {
        let ret = VReg::phys("ret");
        let mut types = TypeMap::default();
        types.upsert_public(
            ret.clone(),
            TypeHint::Int {
                signed: true,
                width: 8,
            },
        );
        let definition_widths = HashMap::from([(VReg::phys("eax#1"), 4), (VReg::phys("eax#7"), 4)]);
        let role_names = HashMap::from([
            ("eax#1".to_string(), "ret".to_string()),
            ("eax#7".to_string(), "ret".to_string()),
        ]);

        merge_exact_definition_widths(
            &mut types,
            &definition_widths,
            &role_names,
            CallConv::SysVAmd64,
        );

        assert_eq!(
            types.get(&ret),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            })
        );
    }

    /// On x86-64 a 32-bit definition is a deliberate narrowing (`edi`, not
    /// `rdi`) and remains the -O0 type-recovery signal.
    #[test]
    fn a_narrowing_definition_still_types_a_local_on_a_sixty_four_bit_target() {
        let role = VReg::phys("var0");
        let mut types = TypeMap::default();
        let definition_widths = HashMap::from([(VReg::phys("eax#1"), 4)]);
        let role_names = HashMap::from([("eax#1".to_string(), "var0".to_string())]);

        merge_exact_definition_widths(
            &mut types,
            &definition_widths,
            &role_names,
            CallConv::SysVAmd64,
        );

        assert_eq!(
            types.get(&role),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            })
        );
    }

    #[test]
    fn a_storage_width_does_not_overwrite_an_exact_pointer_role() {
        let role = VReg::phys("var0");
        let mut types = TypeMap::default();
        types.upsert_public(role.clone(), TypeHint::Pointer { pointee_width: 4 });
        let definition_widths = HashMap::from([(VReg::phys("r3#2"), 4)]);
        let role_names = HashMap::from([("r3#2".to_string(), "var0".to_string())]);

        merge_exact_definition_widths(
            &mut types,
            &definition_widths,
            &role_names,
            CallConv::ArmHardFloat,
        );

        assert_eq!(
            types.get(&role),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
    }

    #[test]
    fn numbered_integer_evidence_does_not_overwrite_a_proven_pointer() {
        let role = VReg::phys("var0");
        let mut types = TypeMap::default();
        types.refine_from_value(role.clone(), TypeHint::Pointer { pointee_width: 4 });

        refine_numbered_declaration(
            &mut types,
            &role,
            &TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        assert_eq!(
            types.get(&role),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
    }

    #[test]
    fn numbered_register_width_does_not_retype_a_prepared_scalar_declaration() {
        let role = VReg::phys("var0");
        let mut types = TypeMap::default();
        types.refine_from_value(
            role.clone(),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        refine_numbered_declaration(
            &mut types,
            &role,
            &TypeHint::Int {
                signed: true,
                width: 8,
            },
        );

        assert_eq!(
            types.get(&role),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            })
        );
    }

    /// The same 4-byte definition on i386 is the WHOLE register — there is no
    /// wider spelling the compiler declined to use — so it proves nothing, and
    /// declaring the role `int` truncates any pointer that flows through it once
    /// the recovered C is rebuilt at the host pointer width.
    #[test]
    fn a_full_width_definition_is_not_int_evidence_on_a_thirty_two_bit_target() {
        let role = VReg::phys("var0");
        let mut types = TypeMap::default();
        let definition_widths = HashMap::from([(VReg::phys("eax#1"), 4)]);
        let role_names = HashMap::from([("eax#1".to_string(), "var0".to_string())]);

        merge_exact_definition_widths(
            &mut types,
            &definition_widths,
            &role_names,
            CallConv::Cdecl32,
        );

        assert_eq!(types.get(&role), None);
    }

    /// A byte-wide definition is a narrowing on every target, 32-bit included.
    #[test]
    fn a_sub_word_definition_is_still_evidence_on_a_thirty_two_bit_target() {
        let role = VReg::phys("var0");
        let mut types = TypeMap::default();
        let definition_widths = HashMap::from([(VReg::phys("al#1"), 1)]);
        let role_names = HashMap::from([("al#1".to_string(), "var0".to_string())]);

        merge_exact_definition_widths(
            &mut types,
            &definition_widths,
            &role_names,
            CallConv::Cdecl32,
        );

        assert_eq!(
            types.get(&role),
            Some(TypeHint::Int {
                signed: true,
                width: 1,
            })
        );
    }

    /// A four-byte frame slot on x86-64 is a genuine 32-bit local and keeps
    /// stating its width; the same slot on i386 is a machine word that a
    /// spilled pointer occupies just as readily.
    #[test]
    fn word_sized_frame_slots_only_declare_int_where_the_word_is_wider() {
        let slot = VReg::phys("local_c");
        let sizes = HashMap::from([("local_c".to_string(), 4u8)]);

        let mut sixty_four = TypeMap::default();
        super::merge_slot_sizes(&mut sixty_four, &sizes, CallConv::SysVAmd64);
        assert_eq!(
            sixty_four.get(&slot),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            })
        );

        let mut thirty_two = TypeMap::default();
        super::merge_slot_sizes(&mut thirty_two, &sizes, CallConv::Cdecl32);
        assert_eq!(thirty_two.get(&slot), None);

        // A byte-wide slot is narrower than the word on both.
        let narrow = HashMap::from([("local_1".to_string(), 1u8)]);
        let mut narrow_map = TypeMap::default();
        super::merge_slot_sizes(&mut narrow_map, &narrow, CallConv::Cdecl32);
        assert_eq!(
            narrow_map.get(&VReg::phys("local_1")),
            Some(TypeHint::Int {
                signed: true,
                width: 1,
            })
        );
    }

    #[test]
    fn machine_word_is_four_bytes_on_every_thirty_two_bit_convention() {
        assert_eq!(crate::ir::abi::machine_word_bytes(CallConv::Cdecl32), 4);
        assert_eq!(crate::ir::abi::machine_word_bytes(CallConv::Arm), 4);
        assert_eq!(
            crate::ir::abi::machine_word_bytes(CallConv::ArmHardFloat),
            4
        );
        assert_eq!(crate::ir::abi::machine_word_bytes(CallConv::SysVAmd64), 8);
        assert_eq!(crate::ir::abi::machine_word_bytes(CallConv::Win64), 8);
        assert_eq!(crate::ir::abi::machine_word_bytes(CallConv::Aarch64), 8);
    }

    /// The ambiguity rule is applied where it has been MEASURED to pay, and only
    /// there. See `word_width_implies_int` for the armv7 evidence.
    #[test]
    fn word_width_stops_implying_int_only_on_cdecl32() {
        assert!(!super::word_width_implies_int(CallConv::Cdecl32));
        assert!(super::word_width_implies_int(CallConv::Arm));
        assert!(super::word_width_implies_int(CallConv::ArmHardFloat));
        assert!(super::word_width_implies_int(CallConv::SysVAmd64));
        assert!(super::word_width_implies_int(CallConv::Win64));
        assert!(super::word_width_implies_int(CallConv::Aarch64));
    }
}
