//! The shared LLIR/AST stage pipeline every decompilation entry point runs.
//!
//! One copy of the pass list, one copy of the LLIR preparation, so the four
//! Python entry points cannot drift into different value models.

use pyo3::prelude::*;

use super::callee_contracts::DirectCalleeFacts;
use super::dwarf_contracts::{dwarf_source_register_lifetimes, DwarfPrototypeContract};
use super::{lock_parameter_slots_from_prototype, recover_decbench_prototype};

/// Replace calls to the compiler's division runtime helpers with the arithmetic
/// they perform (see [`crate::ir::soft_helpers`]).
///
/// Must run on the raw LLIR — before `abi::annotate_calls` and before SSA —
/// because the expansion is written in terms of the architectural argument
/// registers. Shared by every decompile entry point for the same reason
/// `run_ast_passes` is: a pass wired into one of the four and not the others is
/// a pass that silently does nothing in three of them.
pub(super) fn inline_soft_helper_calls_in(
    lf: &mut crate::ir::types::LlirFunction,
    addr_map: &std::collections::HashMap<u64, String>,
) {
    crate::ir::soft_helpers::inline_soft_helper_calls(&mut lf.blocks, |va| {
        addr_map.get(&va).cloned()
    });
}

/// Attach convention-wide call effects, then narrow resolved library calls.
///
/// This must precede SSA and prototype recovery. Keeping the two layers in one
/// helper prevents an entry point from observing the ABI's conservative
/// six/eight-register approximation after another already applied the exact
/// program-level symbol contract.
pub(super) fn annotate_calls_in(
    function: &mut crate::ir::types::LlirFunction,
    cc: crate::ir::call_args::CallConv,
    address_names: &std::collections::HashMap<u64, String>,
) {
    crate::ir::abi::annotate_calls(function, cc);
    crate::ir::call_contracts::apply_known_llir_call_contracts(function, cc, address_names);
}

/// Constant-data facts for one image, with relocation-fixed storage interpreted
/// rather than read.
///
/// Read-only storage the loader fixes up holds references, not data: a
/// `static const char *const` table lands in `.data.rel.ro`, and reading its
/// bytes as integers yields an image address that the rebuilt unit does not
/// map. The canonical reference resolver is asked what each pointer-width slot
/// means before any pass can see those bytes at all. See
/// [`crate::program::references`].
pub(super) fn readonly_data_for(
    session: &crate::program::session::ProgramSession,
    image: &crate::program::image::ProgramImage,
    str_pool: &std::collections::HashMap<u64, String>,
) -> crate::ir::readonly_fold::ReadonlyData {
    let mut readonly_data = crate::ir::readonly_fold::collect_readonly_data_from_image(image);
    let symbols = session.symbol_store();
    readonly_data.resolve_relocated_slots(
        image,
        &crate::program::references::ReferenceResolver::new(image, &symbols, str_pool),
    );
    readonly_data
}

/// THE AST pass pipeline. Every public decompile entry point runs exactly this.
///
/// It used to be copy-pasted into four functions — `decompile_at`, `decompile_range_at`,
/// `decompile_all`, `decompile_many` — with tests keeping the copies aligned by
/// convention and nothing enforcing it. That is not hypothetical drift: a loop-hoist
/// retry added during this work landed in one copy and silently did nothing in the other
/// three, which is exactly how a "fix" gets measured as ineffective.
///
/// Returns the recovered stack-slot sizes, which callers thread into type recovery.
///
/// (The sibling of this rule for the LLIR stage is `inline_soft_helper_calls_in`,
/// just above.)
///
/// The pass-by-pass AST dump (`GLAURUNG_DUMP_PASSES=1`) is read here, so EVERY entry
/// point gets identical diagnostics rather than only the one that happened to carry the
/// macro. Debugging `--all` used to produce no dump at all.
pub(super) fn run_ast_passes(
    f: &mut crate::ir::ast::Function,
    profiler: &mut crate::decompile::profile::FunctionProfiler,
    cfg_health: crate::ir::health::CfgHealth,
    cc: crate::ir::call_args::CallConv,
    nested_machine_frame_cleanup: bool,
    prototype: Option<&crate::ir::types_recover::RecoveredPrototype>,
    param_slots: &mut std::collections::HashSet<usize>,
    locked_parameter_count: Option<usize>,
    callee_facts: &DirectCalleeFacts,
    addr_map: &std::collections::HashMap<u64, String>,
    str_pool: &std::collections::HashMap<u64, String>,
    function_tables: &[crate::ir::function_tables::FunctionPointerTable],
    stack_object_hints: &[crate::ir::stack_locals::StackObjectHint],
    got_targets: &std::collections::HashMap<u64, u64>,
) -> (
    crate::ir::stack_locals::StackLocalFacts,
    std::collections::HashMap<String, String>,
) {
    let dump = std::env::var("GLAURUNG_DUMP_PASSES").is_ok();
    let output_kind = prototype.map_or(
        crate::ir::types_recover::RecoveredOutputKind::Unknown,
        crate::ir::types_recover::RecoveredPrototype::output_kind,
    );
    // A recovered variadic callee layout names only its fixed prefix. Passing
    // that prefix to the fixed-layout folder would truncate genuine optional
    // arguments already set up at this call site. Let the ordinary backward
    // call scan recover the actual argument count; the prototype applied in
    // the next pass preserves the fixed types and variadic tail.
    let reconstruction_layouts = callee_facts
        .layouts
        .iter()
        .filter(|(target, _)| {
            !callee_facts
                .prototypes
                .get(target)
                .is_some_and(|prototype| prototype.variadic)
        })
        .map(|(target, layout)| (*target, layout.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    let parameter_roles = prototype
        .map(crate::ir::types_recover::RecoveredPrototype::parameter_role_map)
        .unwrap_or_default();
    if dump {
        eprintln!(
            "\n===== parameter evidence =====\nslots={param_slots:?}\nroles={parameter_roles:?}"
        );
        eprintln!("\n===== stack object hints =====\n{stack_object_hints:#?}");
    }
    macro_rules! pass {
        ($n:expr, $operation:expr) => {{
            let result = profiler.measure($n, || $operation);
            crate::ir::health::trace_pass($n, f, cfg_health);
            if dump {
                eprintln!("\n===== after {} =====\n{}", $n, crate::ir::ast::render(f));
            }
            result
        }};
    }
    crate::ir::health::trace_pass("ast_pipeline_entry", f, cfg_health);
    // Packed XMM moves use four scalar lane operations so arithmetic remains
    // analyzable.  Rejoin an untouched four-lane load/store pair before copy
    // propagation erases the common 16-byte transport identity.
    pass!(
        "recover_wide_copies",
        crate::ir::vector_copy::recover_wide_copies(f)
    );
    pass!("reconstruct", crate::ir::expr_reconstruct::reconstruct(f));
    pass!("fold_constants", crate::ir::const_fold::fold_constants(f));
    pass!(
        "fold_boolean_masks",
        crate::ir::select_fold::fold_boolean_masks(f)
    );
    // Per-definition first: it removes writes an unread overwrite supersedes, which the
    // per-name pass below cannot see (flags are un-versioned, so one read keeps every
    // write of that name alive).
    pass!("prune_dead_flags", {
        crate::ir::dce::prune_overwritten_flags(f);
        crate::ir::dce::prune_dead_flags(f);
    });
    // A direct jump into a PLT stub lowers to that stub's terminal GOT
    // dereference. Resolve the slot before argument reconstruction, then recover
    // only symbol-backed terminal jumps as tail calls so the ordinary call pass
    // can see their argument-register setup and returned value.
    // Before names are resolved, so a slot that `elf_got_map` also names is
    // replaced by the address it holds rather than by a symbol standing on a
    // linkage word. See `ir::got_fold`.
    pass!("fold_got_pointer_loads", {
        crate::ir::got_fold::fold_got_pointer_loads(f, got_targets);
    });
    pass!("recover_resolved_tail_calls", {
        crate::ir::name_resolve::resolve_names(f, addr_map);
        crate::ir::function_tables::resolve_function_table_entries(f, function_tables);
        crate::ir::call_args::recover_resolved_direct_tail_calls(f, cc, addr_map);
        crate::ir::call_args::recover_resolved_tail_calls(f, cc);
    });
    pass!("reconstruct_args", {
        crate::ir::call_args::reconstruct_args_with_layouts(
            f,
            cc,
            param_slots,
            &reconstruction_layouts,
            &callee_facts.table_entry_layouts,
        );
    });
    // ABI liveness supplies candidate call inputs/outputs; an authoritative
    // library prototype wins when one is known. This mirrors Ghidra's locked
    // FuncProto and angr's callee-prototype priority rather than asking the C
    // renderer to paper over a semantically impossible AST result.
    pass!("apply_known_call_contracts", {
        crate::ir::call_contracts::apply_recovered_callee_prototypes(f, &callee_facts.prototypes);
        crate::ir::call_contracts::apply_known_call_contracts(f);
    });
    pass!(
        "split_call_result_lifetimes",
        crate::ir::call_result_split::split_call_result_lifetimes(f, cc)
    );
    pass!("canary+strings", {
        crate::ir::strings_fold::fold_string_literals(f, str_pool);
        crate::ir::canary::recognise_canary(f);
    });
    // Stack-slot promotion runs before register renaming so the aliases (`stack_0`,
    // `local_0`, ...) it allocates cannot collide with the role names (`arg0`, `ret`,
    // `varN`) the naming pass introduces.
    // AAPCS64's `x8` result buffer is not described by DWARF at `-O2` -- it is a
    // compiler temporary with no source name -- so the ABI has to declare it.
    // Without this the twenty-byte buffer of `agr198_five_roundtrip` promotes as
    // five unrelated four-byte slots and the call has no single destination.
    // Empty on every other convention and on every AArch64 function with no
    // indirect-return call, so the hint list is unchanged where it does not
    // apply.
    let indirect_result_hints =
        crate::ir::aapcs64_indirect_result::indirect_result_buffer_hints(f, cc);
    let stack_object_hints = if indirect_result_hints.is_empty() {
        stack_object_hints.to_vec()
    } else {
        let mut combined = stack_object_hints.to_vec();
        combined.extend(indirect_result_hints);
        combined
    };
    let stack_facts = pass!(
        "promote_stack_locals",
        crate::ir::stack_locals::promote_stack_locals_with_facts(
            f,
            Some(cc),
            locked_parameter_count,
            &stack_object_hints,
        )
    );
    // Now that the buffer is a named object, make it the destination of the
    // call that fills it. Before promotion its address is still `sp + k`
    // arithmetic, which no renderer can take the address of.
    pass!(
        "bind_indirect_result_buffers",
        crate::ir::aapcs64_indirect_result::bind_indirect_result_buffers(f, cc)
    );
    // Frame-relative storage is source-level state; the push/mov/sub sequence
    // that establishes its machine frame is not.  Recognise the machine prologue
    // here, while stack promotion has made the storage identities explicit but
    // before dead-store elimination removes the now-unused `rbp = rsp` witness.
    // A second call after the remaining passes still handles epilogues exposed
    // by stack-op rematerialisation.
    pass!("recognise_machine_frame", {
        recognise_machine_frame(f, cc);
        if nested_machine_frame_cleanup {
            crate::ir::dead_stores::prune_callee_saved_spills_nested(f, cc);
        }
    });
    // Project a prototype-proven result while the raw ABI output register is
    // still present. ARM32/AArch64 reuse arg0's register for the result; the
    // following spill-role split must rename both its final definition and the
    // return use together, rather than orphaning the result as scratch.
    pass!("materialize_direct_output", {
        if output_kind == crate::ir::types_recover::RecoveredOutputKind::Direct {
            crate::ir::direct_output::materialize_prototype_output(f, cc, prototype);
            // The result register now carries the LOW eightbyte of a proven
            // two-register aggregate result. State the whole contract here,
            // while the high half's definition is still present: dead-store
            // elimination runs a few passes below and has nothing to keep it
            // alive until a `return` reads it.
            crate::ir::callee_return_pair::compose_pair_returns(f, cc, prototype);
        }
    });
    // Reconstructed expressions now carry their explicit machine width. Make
    // the dual-role decision here rather than at pipeline entry, where a wide
    // result may still be hidden behind widthless temporaries.
    let split_unspilled_dual_role =
        crate::ir::value_split::should_split_unspilled_dual_role(f, cc, prototype);
    if dump {
        eprintln!(
            "\n===== value-role evidence =====\n\
             split_unspilled_dual_role={split_unspilled_dual_role}"
        );
    }
    pass!(
        "split_argument_storage_reuse",
        crate::ir::value_split::split_argument_storage_reuse(f, cc, split_unspilled_dual_role)
    );
    let role_names = pass!(
        "apply_role_names",
        crate::ir::naming::apply_role_names_with_parameter_roles(
            f,
            cc,
            param_slots,
            &parameter_roles,
        )
    );
    // Dead-store elimination runs *after* naming so it sees the aliased return register
    // (`ret` / `arg0`) rather than the raw physical one; that removes the common pre-call
    // `%ret = 0` idiom entirely.
    pass!("eliminate_dead_stores", {
        crate::ir::canary::collapse_canary_save(f);
        if matches!(cc, crate::ir::call_args::CallConv::Aarch64) {
            crate::ir::arm64_prologue::recognise_arm64_prologue(f);
        }
        crate::ir::dead_stores::eliminate_dead_stores(f, cc);
    });
    pass!("stack_idiom+label_prune", {
        crate::ir::stack_idiom::rematerialise_stack_ops(f);
        crate::ir::label_prune::prune_unreferenced_labels(f);
    });
    (stack_facts, role_names)
}

/// Collapse architecture-specific machine frames after stack-slot promotion.
///
/// The pass is repeated after the common AST pipeline because stack-idiom
/// rematerialisation may expose a second canonical spelling. Each recogniser
/// is idempotent and fail-closed when the frame is not exactly balanced.
pub(super) fn recognise_machine_frame(
    f: &mut crate::ir::ast::Function,
    cc: crate::ir::call_args::CallConv,
) {
    match cc {
        crate::ir::call_args::CallConv::SysVAmd64 | crate::ir::call_args::CallConv::Win64 => {
            crate::ir::x86_prologue::recognise_x86_prologue(f);
        }
        crate::ir::call_args::CallConv::Arm | crate::ir::call_args::CallConv::ArmHardFloat => {
            crate::ir::arm32_prologue::recognise_arm32_frame(f);
        }
        _ => {}
    }
    // Whatever the per-architecture recogniser could not attribute to a frame
    // pattern, the callee-saved spills themselves are still machine bookkeeping.
    // This runs for every convention, including AArch64, which has no dedicated
    // recogniser in this match.
    crate::ir::dead_stores::prune_callee_saved_spills(f, cc);
}

pub(super) fn target_calling_convention(
    image: &crate::program::image::ProgramImage,
) -> PyResult<crate::ir::call_args::CallConv> {
    let target = image.target();
    let arch = target.architecture();
    if !crate::ir::lift_function::supports_arch(arch) {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "LLIR decompiler does not support target {arch:?}"
        )));
    }
    let cc = target.calling_convention().ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "target {arch:?} has no supported calling convention"
        ))
    })?;
    Ok(cc)
}

/// Normalize proof-dead partial-register lanes before any consumer leaves SSA.
///
/// Exception edges participate in both SSA computations: the first supplies
/// reaching values to the bit-demand oracle and the second describes the
/// normalized LLIR consumed by region recovery and value numbering.  Keeping
/// this sequence in one helper prevents the four Python decompilation entry
/// points from drifting into different value models.
fn normalize_definedness_and_compute_ssa(
    function: &mut crate::ir::types::LlirFunction,
    exception_sites: &[crate::analysis::exception::ExceptionCallSite],
    cc: crate::ir::call_args::CallConv,
) -> crate::ir::ssa::SsaInfo {
    let graph = crate::analysis::exception::with_exceptional_successors(function, exception_sites);
    let initial_ssa = crate::ir::ssa::compute_ssa(&graph);
    let oracle = crate::ir::definedness::BitDemandOracle::analyze(&graph, &initial_ssa, cc);
    if crate::ir::definedness::erase_unobserved_masked_inputs(function, &initial_ssa, &oracle) == 0
    {
        return initial_ssa;
    }
    let normalized_graph =
        crate::analysis::exception::with_exceptional_successors(function, exception_sites);
    crate::ir::ssa::compute_ssa(&normalized_graph)
}

/// One shared LLIR preparation pipeline for every decompilation entry point.
///
/// Prototype recovery needs initial SSA and parameter evidence. A proven direct
/// output then upgrades operand-free machine returns to explicit LLIR uses, so
/// SSA and the definedness oracle must run once more before value numbering and
/// structuring. Keeping that feedback edge here prevents `--all`, `--vas`, and
/// address/range decompilation from observing different return identities.
pub(super) struct PreparedLlir {
    pub(super) region: crate::ir::structure::Region,
    pub(super) shadow_v2_region: Option<crate::ir::structure::Region>,
    pub(super) cfg_health: crate::ir::health::CfgHealth,
    pub(super) numbered: crate::ir::types::LlirFunction,
    pub(super) definition_widths: std::collections::HashMap<crate::ir::types::VReg, u8>,
    pub(super) parameter_slots: std::collections::HashSet<usize>,
    pub(super) prototype: Option<crate::ir::types_recover::RecoveredPrototype>,
}

impl PreparedLlir {
    pub(super) fn select_shadow_v2(
        &mut self,
        requested: bool,
        typed_pipeline: bool,
    ) -> Result<(), &'static str> {
        if !requested {
            return Ok(());
        }
        if !typed_pipeline {
            return Err("shadow_v2 requires style='decbench'");
        }
        self.region = self
            .shadow_v2_region
            .take()
            .ok_or("verified structure v2 region unavailable")?;
        Ok(())
    }

    /// Verified typed MIR for this function, built on demand.
    ///
    /// Available for EVERY decompilation rather than only when
    /// `GLAURUNG_DUMP_PASSES` is set. It used to be computed inside the debug
    /// dump, printed and dropped, so the roadmap's "migrate a production
    /// consumer to verified MIR evidence" had nothing to migrate onto, and the
    /// analysis a consumer would trust existed only in debug runs — correctness
    /// must not depend on an environment variable.
    ///
    /// Computed here rather than stored on the struct because nothing consumes
    /// it yet: building it eagerly measured +13% on a whole-binary decompile
    /// (0.53 s -> 0.60 s on 09_memory_effects-clang-O2) for an artifact no
    /// caller reads. A consumer calls this when it needs the evidence.
    ///
    /// The `Err` is returned verbatim: an unavailable analysis must present as
    /// a typed reason, never as "no objects found".
    #[allow(dead_code)]
    pub(super) fn mir(
        &self,
        image: &crate::program::image::ProgramImage,
    ) -> Result<crate::ir::mir::MirFunction, Vec<String>> {
        crate::ir::mir::lower_verified_with_image(&self.numbered, image)
    }
}

pub(super) fn requested_function_limit(func_vas: &[u64], max_functions: usize) -> usize {
    if max_functions == 0 {
        func_vas
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>()
            .len()
            .max(1)
    } else {
        max_functions
    }
}

pub(super) fn prepare_llir_for_lowering(
    function: &mut crate::ir::types::LlirFunction,
    image: &crate::program::image::ProgramImage,
    exception_sites: &[crate::analysis::exception::ExceptionCallSite],
    cc: crate::ir::call_args::CallConv,
    recover_semantic_prototype: bool,
    arm_vfp_args: bool,
    declared: Option<&DwarfPrototypeContract>,
    program_fact: Option<&crate::program::environment::FunctionPrototypeFact>,
    type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
) -> PreparedLlir {
    prepare_llir_for_lowering_with_shadow(
        function,
        image,
        exception_sites,
        cc,
        recover_semantic_prototype,
        arm_vfp_args,
        declared,
        program_fact,
        type_env,
        false,
    )
}

pub(super) fn prepare_llir_for_lowering_with_shadow(
    function: &mut crate::ir::types::LlirFunction,
    image: &crate::program::image::ProgramImage,
    exception_sites: &[crate::analysis::exception::ExceptionCallSite],
    cc: crate::ir::call_args::CallConv,
    recover_semantic_prototype: bool,
    arm_vfp_args: bool,
    declared: Option<&DwarfPrototypeContract>,
    program_fact: Option<&crate::program::environment::FunctionPrototypeFact>,
    type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
    prepare_shadow_v2: bool,
) -> PreparedLlir {
    let mut ssa = normalize_definedness_and_compute_ssa(function, exception_sites, cc);
    let provisional_slots = if recover_semantic_prototype {
        crate::ir::value_number::value_number_with_parameter_slots(function, &ssa, cc).2
    } else {
        crate::ir::value_number::live_in_arg_slots_llir(function, cc)
    };
    let prototype = recover_semantic_prototype.then(|| {
        let mut prototype = recover_decbench_prototype(
            function,
            &ssa,
            cc,
            &provisional_slots,
            arm_vfp_args,
            declared,
            type_env,
        );
        // Debug declarations remain the strongest source.  A registration API
        // supplies the missing contract only when local/debug recovery did not
        // already lock one, which keeps conflicting evidence fail-closed.
        if let Some(fact) = program_fact {
            if !prototype.parameter_arity_is_locked() {
                if fact.parameter_arity_is_exact {
                    prototype.apply_locked_parameters(cc, &fact.parameter_hints);
                } else {
                    prototype.apply_parameter_hints(&fact.parameter_hints);
                }
            }
            if !prototype.output_is_locked() {
                if let Some(output_kind) = fact.output_kind {
                    prototype.apply_locked_output(output_kind, None);
                }
            }
        }
        prototype
    });
    if prototype.as_ref().is_some_and(|prototype| {
        crate::ir::types_recover::materialize_return_values(function, cc, prototype) != 0
    }) {
        ssa = normalize_definedness_and_compute_ssa(function, exception_sites, cc);
    }
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!("\n===== prototype-resolved LLIR =====");
        for block in &function.blocks {
            eprintln!("block 0x{:x} -> {:?}", block.start_va, block.succs);
            for instruction in &block.instrs {
                eprintln!("  0x{:x}: {}", instruction.va, instruction.op);
            }
        }
    }
    // What a relocation proves about each computed transfer. The image's slot
    // index is recovered once and shared, so this costs a def-use walk per
    // function and no extra object parse. It reaches only the terminal census;
    // no region decision depends on it.
    let indirect_destinations = crate::ir::indirect_targets::resolve_indirect_jumps(
        function,
        &ssa,
        &image.relocated_symbol_slots(),
    );
    let (region, cfg_health) = crate::ir::structure::recover_verified_with_health_and_destinations(
        function,
        &ssa,
        &indirect_destinations,
    );
    let shadow_v2_region = prepare_shadow_v2
        .then(|| {
            let report = crate::ir::structure_v2::observe(function, &ssa);
            crate::ir::structure_v2::render::adapt_tree(report.tree.as_ref()?)
        })
        .flatten();
    let (numbered, definition_widths, mut parameter_slots) = if recover_semantic_prototype {
        let source_lifetimes = dwarf_source_register_lifetimes(declared, cc);
        crate::ir::value_number::value_number_with_parameter_slots_and_lifetimes(
            function,
            &ssa,
            cc,
            &source_lifetimes,
        )
    } else {
        (
            function.clone(),
            std::collections::HashMap::new(),
            crate::ir::value_number::live_in_arg_slots_llir(function, cc),
        )
    };
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!("\n===== prepared numbered LLIR =====");
        for block in &numbered.blocks {
            eprintln!("block 0x{:x} -> {:?}", block.start_va, block.succs);
            for instruction in &block.instrs {
                eprintln!("  0x{:x}: {}", instruction.va, instruction.op);
            }
        }
        match &crate::ir::mir::lower_verified_with_image(&numbered, image) {
            Ok(mir) => {
                eprintln!(
                    "\n===== verified typed MIR memory values =====\n{:#?}",
                    mir.memory_values()
                );
                eprintln!(
                    "\n===== typed MIR memory objects =====\n{:#?}",
                    mir.objects()
                );
            }
            Err(error) => {
                eprintln!("\n===== invalid typed MIR memory analysis =====\n{error:#?}");
            }
        }
    }
    lock_parameter_slots_from_prototype(prototype.as_ref(), &mut parameter_slots);
    PreparedLlir {
        region,
        shadow_v2_region,
        cfg_health,
        numbered,
        definition_widths,
        parameter_slots,
        prototype,
    }
}
