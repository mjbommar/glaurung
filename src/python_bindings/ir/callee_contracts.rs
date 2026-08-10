//! Demand-driven interprocedural call-layout and prototype recovery.
//!
//! This module owns the bounded callee/grandcallee analysis used by every
//! Python decompilation entry point. Keeping the definition-site contract logic
//! here prevents the already-large binding orchestrator from becoming another
//! analysis owner.

use super::{
    annotate_calls_in, calling_convention_pointer_width, inline_soft_helper_calls_in,
    recover_decbench_prototype, DwarfPrototypeContract,
};

#[derive(Debug, Default)]
pub(super) struct DirectCalleeFacts {
    pub(super) layouts: std::collections::HashMap<u64, Vec<crate::ir::types::VReg>>,
    pub(super) prototypes: std::collections::HashMap<u64, crate::ir::call_contracts::CallPrototype>,
}

fn imported_symbol_base(name: &str) -> &str {
    name.strip_suffix("@plt")
        .or_else(|| name.strip_suffix(".plt"))
        .unwrap_or(name)
}

fn defined_text_symbol_address(
    image: &crate::program::image::ProgramImage,
    name: &str,
) -> Option<u64> {
    image.defined_text_symbol_address(name)
}

/// Fixed Itanium C++ runtime layouts whose imported PLT stubs have no body from
/// which parameter liveness can be recovered.
///
/// In particular, `__cxa_throw(object, typeinfo, destructor)` must retain all
/// three setup registers. Without this layout x1/x2 are dead before final
/// exception recovery, `_ZTIi` disappears, and the ABI call cannot become a
/// source-level `throw int`.
fn itanium_runtime_layout(
    name: &str,
    cc: crate::ir::call_args::CallConv,
) -> Option<Vec<crate::ir::types::VReg>> {
    let clean = imported_symbol_base(name);
    let arity = match clean {
        "__cxa_allocate_exception" | "__cxa_begin_catch" => 1,
        "__cxa_throw" => 3,
        "__cxa_end_catch" => 0,
        _ => return None,
    };
    if cc == crate::ir::call_args::CallConv::Cdecl32 {
        // cdecl arguments are reconstructed from stack pushes, not registers.
        return None;
    }
    Some(
        crate::ir::abi::argument_slots(cc)
            .iter()
            .take(arity)
            .map(|slot| crate::ir::types::VReg::phys(slot[0]))
            .collect(),
    )
}

pub(super) fn recovered_call_prototype(
    prototype: &crate::ir::types_recover::RecoveredPrototype,
    cc: crate::ir::call_args::CallConv,
) -> crate::ir::call_contracts::CallPrototype {
    use crate::ir::call_contracts::{CallPrototype, CallPrototypeAuthority};
    use crate::ir::types::VReg;
    use crate::ir::types_recover::RecoveredOutputKind;

    fn storage_fallback(register: &VReg) -> &'static str {
        match register {
            VReg::Phys(name) if name.starts_with('s') => "float",
            VReg::Phys(name) if name.starts_with('d') => "double",
            _ => "long",
        }
    }

    let parameter_types = prototype
        .parameters()
        .iter()
        .map(|parameter| {
            parameter
                .hint
                .map(|hint| {
                    crate::ir::types_recover::c_type_for_hint_with_pointer_width(
                        hint,
                        calling_convention_pointer_width(cc),
                    )
                })
                .unwrap_or_else(|| storage_fallback(&parameter.value.base))
                .to_string()
        })
        .collect();
    let return_type = match prototype.output_kind() {
        RecoveredOutputKind::Void => "void",
        RecoveredOutputKind::Direct => prototype
            .result()
            .and_then(|result| result.hint)
            .map(|hint| {
                crate::ir::types_recover::c_type_for_hint_with_pointer_width(
                    hint,
                    calling_convention_pointer_width(cc),
                )
            })
            .or_else(|| {
                prototype
                    .result()
                    .and_then(|result| result.values.first())
                    .map(|value| storage_fallback(&value.base))
            })
            .unwrap_or("long"),
        RecoveredOutputKind::Unknown | RecoveredOutputKind::HiddenReturn => "long",
    };
    CallPrototype {
        return_type: return_type.to_string(),
        parameter_types,
        variadic: false,
        authority: CallPrototypeAuthority::Recovered,
    }
}

/// Whether a direct callee's empty recovered argument layout is authoritative.
///
/// Machine-code liveness can miss parameters, so an empty inferred layout is
/// normally not safe to impose on a caller. A DWARF `DW_AT_prototyped` function
/// with no formal parameters is different: it proves a genuine `f(void)`
/// declaration, and its return contract must not be discarded merely because
/// there are no argument registers to record.
fn retain_empty_direct_callee_layout(declared: Option<&DwarfPrototypeContract>) -> bool {
    declared.is_some_and(|contract| contract.prototyped && contract.parameter_types.is_empty())
}

/// Fixed general-purpose parameter count encoded by a SysV `va_list` prologue.
///
/// A variadic callee saves every *unnamed* argument register in an eight-byte
/// register-save-area suffix and initializes adjacent `gp_offset`/`fp_offset`
/// fields.  Ordinary parameter spills are not enough to classify a function as
/// variadic; requiring both the complete suffix and the ABI header constants
/// keeps this fail-closed.  The named prefix may be propagated to callers, but
/// the saved suffix is optional call data rather than fixed signature evidence.
fn sysv_variadic_fixed_gp_count(
    function: &crate::ir::types::LlirFunction,
    cc: crate::ir::call_args::CallConv,
) -> Option<usize> {
    use crate::ir::types::{Op, VReg, Value};

    if cc != crate::ir::call_args::CallConv::SysVAmd64 {
        return None;
    }

    fn frame_base(address: &crate::ir::types::MemOp) -> Option<&str> {
        let Some(VReg::Phys(base)) = address.base.as_ref() else {
            return None;
        };
        let base = crate::ir::abi::ssa_base(base);
        matches!(base, "rsp" | "rbp").then_some(base)
    }

    let mut constants = std::collections::HashMap::<(String, i64), i64>::new();
    let mut spills = std::collections::HashMap::<(String, usize), i64>::new();
    for instruction in function.blocks.iter().flat_map(|block| &block.instrs) {
        let Op::Store { addr, src } = &instruction.op else {
            continue;
        };
        if addr.index.is_some() || addr.segment.is_some() {
            continue;
        }
        let Some(base) = frame_base(addr) else {
            continue;
        };
        match src {
            Value::Const(value) if addr.size == 4 => {
                constants.insert((base.to_string(), addr.disp), *value);
            }
            Value::Reg(VReg::Phys(register)) if addr.size == 8 => {
                let Some(slot) = crate::ir::abi::argument_slot_of(cc, register) else {
                    continue;
                };
                spills.insert((base.to_string(), slot), addr.disp);
            }
            _ => {}
        }
    }

    for ((base, displacement), gp_offset) in &constants {
        if *gp_offset <= 0 || *gp_offset >= 48 || gp_offset % 8 != 0 {
            continue;
        }
        if constants.get(&(base.clone(), displacement + 4)) != Some(&48) {
            continue;
        }
        let fixed = usize::try_from(gp_offset / 8).ok()?;
        let Some(suffix) = (fixed..6)
            .map(|slot| spills.get(&(base.clone(), slot)).copied())
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        if suffix.len() < 2
            || suffix
                .windows(2)
                .any(|pair| pair[1].checked_sub(pair[0]) != Some(8))
        {
            continue;
        }
        return Some(fixed);
    }
    None
}

/// Attach recovered positive argument evidence to convention-wide call effects.
///
/// The ABI-wide `args` set remains intact for safe liveness and DCE.  The
/// recovered layout is intentionally only a proven subset: body inference can
/// miss inputs, so it must not claim an exact contract and narrow machine
/// effects.  Signature and type recovery consume `proven_args` as positive
/// evidence without treating the remaining may-uses as source parameters.
pub(super) fn apply_recovered_direct_callee_effects(
    function: &mut crate::ir::types::LlirFunction,
    cc: crate::ir::call_args::CallConv,
    facts: &DirectCalleeFacts,
) {
    for block in &mut function.blocks {
        for instruction in &mut block.instrs {
            let crate::ir::types::Op::Call {
                target: crate::ir::types::CallTarget::Direct(target),
                effects,
            } = &mut instruction.op
            else {
                continue;
            };
            let Some(layout) = facts.layouts.get(target) else {
                continue;
            };
            let mut recovered = effects
                .clone()
                .unwrap_or_else(|| crate::ir::abi::call_effects(cc));
            recovered.proven_args = layout.clone();
            if facts
                .prototypes
                .get(target)
                .is_some_and(|prototype| prototype.return_type == "void")
            {
                recovered.result_is_source_value = false;
            }
            *effects = Some(recovered);
        }
    }
}

/// Project recovered callee parameter types back through untouched SSA live-ins.
///
/// The callee layout identifies the proven machine storage for each parameter.
/// Looking that storage up in the call's existing ABI may-use list avoids
/// rewriting caller-side machine effects merely to transport a type fact.
pub(super) fn refine_passthrough_parameter_hints(
    prototype: &mut crate::ir::types_recover::RecoveredPrototype,
    function: &crate::ir::types::LlirFunction,
    ssa: &crate::ir::ssa::SsaInfo,
    facts: &DirectCalleeFacts,
) {
    use crate::ir::types::{CallTarget, Op};
    use crate::ir::use_def::InstrAddr;

    fn copy_origin(
        function: &crate::ir::types::LlirFunction,
        ssa: &crate::ir::ssa::SsaInfo,
        definitions: &std::collections::HashMap<
            crate::ir::ssa::SsaValue,
            (InstrAddr, &crate::ir::types::Op),
        >,
        mut value: crate::ir::ssa::SsaValue,
    ) -> Option<crate::ir::ssa::SsaValue> {
        for _ in 0..=definitions.len() {
            if value.version == 0 {
                return Some(value);
            }
            let definition = definitions.get(&value)?;
            // A conversion produces a different source value. Projecting a
            // pointer contract through `zext`, for example, turns an integer
            // address parameter into `char *` even though only the converted
            // call operand has pointer semantics. Only identity copies retain
            // the definition-site type contract.
            if !matches!(definition.1, Op::Assign { .. }) {
                return None;
            }
            value = ssa.use_value(function, definition.0, 0)?;
        }
        None
    }

    let definitions = function
        .blocks
        .iter()
        .enumerate()
        .flat_map(|(block_idx, block)| {
            block
                .instrs
                .iter()
                .enumerate()
                .filter_map(move |(instr_idx, instruction)| {
                    let address = InstrAddr {
                        block_idx,
                        instr_idx,
                    };
                    ssa.def_value(function, address)
                        .map(|value| (value, (address, &instruction.op)))
                })
        })
        .collect::<std::collections::HashMap<_, _>>();

    for (block_idx, block) in function.blocks.iter().enumerate() {
        for (instr_idx, instruction) in block.instrs.iter().enumerate() {
            let Op::Call {
                target: CallTarget::Direct(target),
                effects: Some(effects),
            } = &instruction.op
            else {
                continue;
            };
            let Some(callee) = facts.prototypes.get(target) else {
                continue;
            };
            let Some(layout) = facts.layouts.get(target) else {
                continue;
            };
            let address = InstrAddr {
                block_idx,
                instr_idx,
            };
            for (index, c_type) in callee.parameter_types.iter().enumerate() {
                let Some(storage) = layout.get(index) else {
                    continue;
                };
                let Some(use_index) = effects.args.iter().position(|arg| arg == storage) else {
                    continue;
                };
                let Some(value) = ssa
                    .use_value(function, address, use_index)
                    .and_then(|value| copy_origin(function, ssa, &definitions, value))
                else {
                    continue;
                };
                let Some(hint) = crate::ir::call_contracts::call_return_hint(c_type) else {
                    continue;
                };
                prototype.refine_parameter_hint_for_value(&value, hint);
            }
        }
    }
}

fn direct_callee_body_va(
    image: &crate::program::image::ProgramImage,
    functions: &[crate::core::function::Function],
    callee_va: u64,
    address_names: &std::collections::HashMap<u64, String>,
) -> u64 {
    let body_va = address_names
        .get(&callee_va)
        .map(|name| imported_symbol_base(name))
        .and_then(|name| {
            defined_text_symbol_address(image, name).or_else(|| {
                functions
                    .iter()
                    .find(|function| {
                        let entry = function.entry_point.value;
                        function.name == name
                            || [entry, entry | 1].into_iter().any(|address| {
                                address_names
                                    .get(&address)
                                    .is_some_and(|resolved| imported_symbol_base(resolved) == name)
                            })
                    })
                    .map(|function| function.entry_point.value)
            })
        })
        .unwrap_or(callee_va);
    image.normalize_function_entry(body_va)
}

/// Recover one direct callee, optionally using one proven grandcallee layer.
///
/// One layer is enough to recover the common optimized wrapper shape without
/// recursively walking a whole program or looping on mutually recursive
/// functions. The outer cache still ensures repeated requested callees are
/// analyzed once per batch/session.
fn recover_direct_callee_definition(
    image: &crate::program::image::ProgramImage,
    functions: &[crate::core::function::Function],
    callee_va: u64,
    arch: crate::core::binary::Arch,
    cc: crate::ir::call_args::CallConv,
    arm_vfp_args: bool,
    budgets: &crate::analysis::cfg::Budgets,
    dwarf_outputs: Option<&std::collections::HashMap<u64, DwarfPrototypeContract>>,
    type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
    address_names: &std::collections::HashMap<u64, String>,
    include_grandcallees: bool,
) -> Option<(
    Vec<crate::ir::types::VReg>,
    crate::ir::call_contracts::CallPrototype,
    String,
)> {
    use crate::ir::lift_function::lift_function_from_image;
    use crate::ir::ssa::compute_ssa;

    let body_va = direct_callee_body_va(image, functions, callee_va, address_names);
    let targeted;
    let callee = match functions
        .iter()
        .find(|function| function.entry_point.value == body_va)
    {
        Some(callee) => callee,
        None => {
            targeted = crate::analysis::cfg::discover_function_image_at(image, budgets, body_va)?;
            &targeted
        }
    };
    let mut lifted = lift_function_from_image(image, callee, arch)?;
    inline_soft_helper_calls_in(&mut lifted, address_names);
    annotate_calls_in(&mut lifted, cc, address_names);

    let mut nested = DirectCalleeFacts::default();
    if include_grandcallees {
        let catalog_facts = lifted
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter_map(|instruction| {
                let crate::ir::types::Op::Call {
                    target: crate::ir::types::CallTarget::Direct(target),
                    effects: Some(effects),
                } = &instruction.op
                else {
                    return None;
                };
                if !effects.args_are_exact {
                    return None;
                }
                let prototype = address_names
                    .get(target)
                    .and_then(|name| crate::ir::call_contracts::lookup(name))
                    .and_then(|contract| contract.standalone_prototype())?;
                Some((*target, (effects.args.clone(), prototype)))
            })
            .collect::<std::collections::HashMap<_, _>>();
        let targets = lifted
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter_map(|instruction| match instruction.op {
                crate::ir::types::Op::Call {
                    target: crate::ir::types::CallTarget::Direct(target),
                    ..
                } if image.normalize_function_entry(target) != body_va => Some(target),
                _ => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        for target in targets {
            if let Some((layout, prototype)) = catalog_facts.get(&target) {
                nested.layouts.insert(target, layout.clone());
                nested.prototypes.insert(target, prototype.clone());
                continue;
            }
            let Some((layout, prototype, _)) = recover_direct_callee_definition(
                image,
                functions,
                target,
                arch,
                cc,
                arm_vfp_args,
                budgets,
                dwarf_outputs,
                type_env,
                address_names,
                false,
            ) else {
                continue;
            };
            nested.layouts.insert(target, layout);
            nested.prototypes.insert(target, prototype);
        }
        apply_recovered_direct_callee_effects(&mut lifted, cc, &nested);
    }

    let ssa = compute_ssa(&lifted);
    let parameter_slots = crate::ir::value_number::live_in_arg_slots_llir(&lifted, cc);
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!(
            "callee body 0x{body_va:x}: nested layouts {:?}, parameter slots {:?}",
            nested.layouts, parameter_slots
        );
    }
    let mut prototype = recover_decbench_prototype(
        &lifted,
        &ssa,
        cc,
        &parameter_slots,
        arm_vfp_args,
        dwarf_outputs.and_then(|outputs| outputs.get(&body_va)),
        type_env,
    );
    refine_passthrough_parameter_hints(&mut prototype, &lifted, &ssa, &nested);
    let mut layout = prototype
        .parameters()
        .iter()
        .map(|parameter| parameter.value.base.clone())
        .collect::<Vec<_>>();
    let mut call_prototype = recovered_call_prototype(&prototype, cc);
    let fixed_prefix = crate::ir::abi::fixed_parameter_prefix_len(cc, &layout);
    layout.truncate(fixed_prefix);
    call_prototype.parameter_types.truncate(fixed_prefix);
    if let Some(fixed) = sysv_variadic_fixed_gp_count(&lifted, cc) {
        layout.truncate(fixed);
        call_prototype.parameter_types.truncate(fixed);
        call_prototype.variadic = true;
    }
    let declared = dwarf_outputs.and_then(|outputs| outputs.get(&body_va));
    (!layout.is_empty() || retain_empty_direct_callee_layout(declared))
        .then(|| (layout, call_prototype, callee.name.clone()))
}

/// Recover the source-ordered physical parameter storage and prototype of direct callees.
///
/// This is intentionally demand-driven and cached. AAPCS-VFP callsites need
/// cross-function prototype evidence to interleave core and VFP registers; the
/// other conventions need the same callee-local evidence for parameter types
/// that a forwarding caller cannot prove itself. Lifting every discovered
/// function up front would double the dominant cost of large-binary
/// decompilation, so only callees of the function currently being rendered are
/// analyzed and repeated callees in batch modes reuse the result.
pub(super) fn recover_direct_callee_layouts(
    image: &crate::program::image::ProgramImage,
    functions: &[crate::core::function::Function],
    caller: &crate::ir::types::LlirFunction,
    arch: crate::core::binary::Arch,
    cc: crate::ir::call_args::CallConv,
    arm_vfp_args: bool,
    budgets: &crate::analysis::cfg::Budgets,
    dwarf_outputs: Option<&std::collections::HashMap<u64, DwarfPrototypeContract>>,
    type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
    address_names: &mut std::collections::HashMap<u64, String>,
    cache: &mut std::collections::HashMap<
        u64,
        Option<(
            Vec<crate::ir::types::VReg>,
            crate::ir::call_contracts::CallPrototype,
            String,
        )>,
    >,
) -> DirectCalleeFacts {
    let mut facts = DirectCalleeFacts::default();
    let callees: std::collections::BTreeSet<u64> = caller
        .blocks
        .iter()
        .flat_map(|block| block.instrs.iter())
        .filter_map(|instruction| match instruction.op {
            crate::ir::types::Op::Call {
                target: crate::ir::types::CallTarget::Direct(address),
                ..
            } => Some(address),
            _ => None,
        })
        .collect();
    let dump = std::env::var("GLAURUNG_DUMP_PASSES").is_ok();
    if dump {
        eprintln!("\n===== direct callee candidates =====\n{callees:#x?}");
    }
    for callee_va in callees {
        if let Some(layout) = address_names
            .get(&callee_va)
            .and_then(|name| itanium_runtime_layout(name, cc))
        {
            facts.layouts.insert(callee_va, layout);
            continue;
        }
        // PIC code commonly calls a local exported definition through its PLT
        // entry. Keep facts keyed by the machine target while analyzing the
        // real definition, and let one nested contract recover optimized
        // pass-through arguments in that definition.
        let body_va = direct_callee_body_va(image, functions, callee_va, address_names);
        if dump {
            eprintln!(
                "callee 0x{callee_va:x} {:?} -> body 0x{body_va:x}",
                address_names.get(&callee_va)
            );
        }
        if !cache.contains_key(&callee_va) {
            let recovered = recover_direct_callee_definition(
                image,
                functions,
                callee_va,
                arch,
                cc,
                arm_vfp_args,
                budgets,
                dwarf_outputs,
                type_env,
                address_names,
                true,
            );
            cache.insert(callee_va, recovered);
        }
        let recovered = cache.get(&callee_va).cloned().flatten();
        if let Some((layout, prototype, name)) = recovered {
            if dump {
                eprintln!("callee 0x{callee_va:x}: recovered layout {layout:?}");
            }
            match address_names.entry(callee_va) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(name);
                }
                std::collections::hash_map::Entry::Occupied(mut entry)
                    if entry.get().starts_with("sub_") && !name.starts_with("sub_") =>
                {
                    entry.insert(name);
                }
                std::collections::hash_map::Entry::Occupied(_) => {}
            }
            facts.layouts.insert(callee_va, layout);
            facts.prototypes.insert(callee_va, prototype);
        } else if dump {
            eprintln!("callee 0x{callee_va:x}: no recovered layout");
        }
    }
    facts
}
