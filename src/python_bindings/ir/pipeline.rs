//! The shared LLIR/AST stage pipeline every decompilation entry point runs.
//!
//! One copy of the pass list, one copy of the LLIR preparation, so the four
//! Python entry points cannot drift into different value models.

use pyo3::prelude::*;

use super::callee_contracts::{
    prepare_direct_callee_facts, refine_passthrough_parameter_hints, DirectCalleeFacts,
    RecoveredDirectCallee,
};
use super::dwarf_contracts::{dwarf_source_register_lifetimes, DwarfPrototypeContract};
use super::{lock_parameter_slots_from_prototype, recover_decbench_prototype_with_inferred};

/// Explicit work limits for one decompilation request.
///
/// This is deliberately owned by the pipeline rather than by a Python entry
/// point.  Adapters may expose different defaults, but once constructed the
/// request has one budget identity and one conversion to discovery limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub(super) struct DiscoveryBudget {
    /// Maximum number of function records admitted to the program discovery.
    pub(super) max_functions: usize,
    /// Optional wall-clock bound for the complete program discovery.
    pub(super) total_timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub(super) struct CfgBudget {
    /// Maximum basic blocks admitted to one function CFG.
    pub(super) max_blocks: usize,
    /// Maximum decoded instructions admitted to one function CFG.
    pub(super) max_instructions: usize,
    /// Wall-clock bound for one function CFG.
    pub(super) timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub(super) struct CalleeBudget {
    /// Additional direct-callee bodies a callee analysis may enter.
    pub(super) max_depth: u8,
}

impl Default for CalleeBudget {
    fn default() -> Self {
        Self { max_depth: 1 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub(super) struct TypeBudget {
    /// Maximum rounds in the render-time type refinement fixed point.
    pub(super) max_refinement_rounds: usize,
}

impl Default for TypeBudget {
    fn default() -> Self {
        Self {
            max_refinement_rounds: 512,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub(super) struct SizeBudget {
    /// Maximum byte window synthesized by the explicit-range fallback.
    pub(super) max_range_bytes: u64,
    /// Maximum function artifacts projected by a batch adapter.
    pub(super) max_output_functions: usize,
}

impl SizeBudget {
    pub(super) fn from_instruction_and_output_limits(
        max_instructions: usize,
        max_output_functions: usize,
    ) -> Self {
        Self {
            max_range_bytes: (max_instructions as u64).saturating_mul(16).max(1),
            max_output_functions,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub(super) struct AnalysisBudget {
    pub(super) discovery: DiscoveryBudget,
    pub(super) cfg: CfgBudget,
    pub(super) callee: CalleeBudget,
    pub(super) types: TypeBudget,
    pub(super) size: SizeBudget,
}

impl AnalysisBudget {
    pub(super) fn discovery(self) -> crate::analysis::cfg::Budgets {
        crate::analysis::cfg::Budgets {
            max_functions: self.discovery.max_functions,
            max_blocks: self.cfg.max_blocks,
            max_instructions: self.cfg.max_instructions,
            timeout_ms: self.cfg.timeout_ms,
            total_timeout_ms: self.discovery.total_timeout_ms,
        }
    }
}

/// One authoritative discovery result paired with the exact limits that
/// produced it. Keeping these together prevents later context builders from
/// accidentally querying the session with a different budget identity.
pub(super) struct ProgramDiscovery {
    pub(super) budgets: crate::analysis::cfg::Budgets,
    pub(super) functions: std::sync::Arc<[crate::core::function::Function]>,
}

pub(super) fn discover_program(
    py: Python<'_>,
    session: &crate::program::session::ProgramSession,
    analysis_budget: AnalysisBudget,
    requested_vas: &[u64],
) -> ProgramDiscovery {
    let budgets = analysis_budget.discovery();
    let functions = py.detach(|| session.discover_functions(&budgets, requested_vas));
    ProgramDiscovery { budgets, functions }
}

/// Rendering and analyst overlays attached to one pipeline request.
#[derive(Debug, Clone, Copy)]
pub(super) struct RenderOptions<'a> {
    pub(super) types: bool,
    pub(super) style: &'a str,
    pub(super) shadow_v2: bool,
    pub(super) pdb_cache: &'a str,
    pub(super) analyst_names: Option<&'a std::collections::HashMap<u64, String>>,
    pub(super) analyst_locals: Option<&'a std::collections::HashMap<i64, (String, String)>>,
    pub(super) analyst_prototype: Option<&'a super::AnalystPrototype>,
}

/// The common input to the single-function pipeline.
#[derive(Debug, Clone, Copy)]
pub(super) struct DecompileRequest<'a> {
    pub(super) va: u64,
    pub(super) analysis_budget: AnalysisBudget,
    pub(super) render_options: RenderOptions<'a>,
}

/// Increment whenever the enabled pass set or its semantic order changes.
pub(super) const PIPELINE_PASS_VERSION: u32 = 1;

/// Stable identity of the semantic pipeline configuration for one result.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(super) struct PipelineFingerprint {
    pub(super) schema: &'static str,
    pub(super) pass_version: u32,
    pub(super) analysis_budget: AnalysisBudget,
    pub(super) style: String,
    pub(super) types: bool,
    pub(super) debug_contracts: bool,
    pub(super) analyst_overlay: bool,
    pub(super) shadow_v2: bool,
}

impl PipelineFingerprint {
    pub(super) fn canonical(&self) -> String {
        serde_json::to_string(self).expect("pipeline fingerprint is serializable")
    }
}

impl DecompileRequest<'_> {
    pub(super) fn fingerprint(&self) -> PipelineFingerprint {
        PipelineFingerprint {
            schema: "glaurung.decompile-pipeline/v1",
            pass_version: PIPELINE_PASS_VERSION,
            analysis_budget: self.analysis_budget,
            style: self.render_options.style.to_string(),
            types: self.render_options.types,
            shadow_v2: self.render_options.shadow_v2,
            debug_contracts: !self.render_options.pdb_cache.is_empty()
                || (self.render_options.style == "decbench" && self.render_options.types),
            analyst_overlay: self.render_options.analyst_names.is_some()
                || self.render_options.analyst_locals.is_some()
                || self.render_options.analyst_prototype.is_some(),
        }
    }
}

/// Whether discovery proved the entire CFG requested for this result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DecompileCompleteness {
    pub(super) complete: bool,
    pub(super) fired_budgets: Vec<&'static str>,
}

impl DecompileCompleteness {
    pub(super) fn from_function(function: &crate::core::function::Function) -> Self {
        let fired_budgets = function.cfg_incomplete_budgets();
        Self {
            complete: fired_budgets.is_empty(),
            fired_budgets,
        }
    }
}

/// Pipeline-owned output; Python adapters may project the pseudocode for the
/// legacy string API without discarding the facts internally.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Legacy Python adapters project text until structured-result migration lands.
pub(super) struct DecompileResult {
    pub(super) pseudocode: String,
    pub(super) line_mappings: Vec<(usize, crate::ir::ast::OriginSet)>,
    pub(super) health: crate::ir::health::AstHealth,
    pub(super) completeness: DecompileCompleteness,
    pub(super) provenance: Vec<&'static str>,
    pub(super) pipeline_fingerprint: PipelineFingerprint,
}

impl DecompileResult {
    pub(super) fn from_rendered(
        pseudocode: String,
        function: &crate::ir::ast::Function,
        cfg_health: crate::ir::health::CfgHealth,
        discovered: &crate::core::function::Function,
        provenance: Vec<&'static str>,
        line_mappings: Vec<(usize, crate::ir::ast::OriginSet)>,
        pipeline_fingerprint: PipelineFingerprint,
    ) -> Self {
        Self {
            pseudocode,
            line_mappings,
            health: crate::ir::health::measure_with_cfg(function, cfg_health),
            completeness: DecompileCompleteness::from_function(discovered),
            provenance,
            pipeline_fingerprint,
        }
    }
}

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

/// Immutable, image-wide facts shared by every function rendered from one
/// decompilation request.
///
/// These used to be assembled independently by each Python adapter.  Keeping
/// their construction here makes the ownership explicit and, for batch
/// requests, guarantees that the string/data reconciliation and relocation
/// interpretation happen exactly once for the entire image.
pub(super) struct ProgramRenderContext {
    pub(super) data_symbols: crate::ir::data_symbols::DataSymbols,
    pub(super) string_pool: std::collections::HashMap<u64, String>,
    pub(super) readonly_data: crate::ir::readonly_fold::ReadonlyData,
    pub(super) function_tables: Vec<crate::ir::function_tables::FunctionPointerTable>,
    pub(super) got_targets: std::collections::HashMap<u64, u64>,
}

/// Binary-truth names and data symbols for one discovered program view.
///
/// Analyst names are intentionally excluded: callee and environment recovery
/// must consume the names present in the binary, then apply presentation
/// overlays after every name-keyed semantic query has completed.
pub(super) struct ProgramNameContext {
    pub(super) address_names: std::collections::HashMap<u64, String>,
    pub(super) data_symbols: crate::ir::data_symbols::DataSymbols,
}

pub(super) fn prepare_program_name_context(
    image: &crate::program::image::ProgramImage,
    binary_path: &str,
    pdb_cache: Option<&std::path::Path>,
    functions: &[crate::core::function::Function],
) -> ProgramNameContext {
    // The combined collector intentionally owns the only object parse here:
    // GOT, code-name, and data-symbol extraction must reuse the parsed image.
    let (mut address_names, data_symbols) =
        crate::ir::name_resolve::collect_address_map_with_pdb_cache_and_data_symbols(
            image.bytes(),
            binary_path,
            pdb_cache,
        );
    crate::ir::name_resolve::add_discovered_function_names(&mut address_names, functions);
    crate::ir::name_resolve::add_flirt_referenced_function_names(
        image,
        &mut address_names,
        functions,
    );
    crate::ir::name_resolve::add_referenced_function_names(&mut address_names, functions);
    ProgramNameContext {
        address_names,
        data_symbols,
    }
}

pub(super) fn prepare_program_render_context(
    session: &crate::program::session::ProgramSession,
    image: &crate::program::image::ProgramImage,
    data_symbols: crate::ir::data_symbols::DataSymbols,
) -> ProgramRenderContext {
    let mut string_pool = crate::ir::strings_fold::collect_string_pool_from_image(image);
    data_symbols.remove_truncated_character_arrays(&mut string_pool);
    let readonly_data = readonly_data_for(session, image, &string_pool);
    let function_tables =
        crate::ir::function_tables::collect_function_pointer_tables(&image.bytes());
    let got_targets = crate::analysis::elf_got::elf_got_target_map(&image.bytes())
        .into_iter()
        .collect();
    ProgramRenderContext {
        data_symbols,
        string_pool,
        readonly_data,
        function_tables,
        got_targets,
    }
}

/// Debug declarations and layouts prepared once for a program request.
///
/// `DwarfTypeEnv` deliberately remains a borrowed view constructed by the
/// caller after this owned context is in place; making this struct
/// self-referential would obscure, rather than clarify, the lifetime boundary.
pub(super) struct ProgramDebugContext {
    pub(super) output_contracts:
        Option<std::collections::HashMap<u64, super::dwarf_contracts::DwarfPrototypeContract>>,
    pub(super) pdb_contract_vas: std::collections::HashSet<u64>,
    pub(super) types: Option<Vec<crate::debug::dwarf::DwarfType>>,
}

pub(super) fn prepare_program_debug_context(
    session: &crate::program::session::ProgramSession,
    image: &crate::program::image::ProgramImage,
    binary_path: &str,
    pdb_cache: &str,
    enabled: bool,
) -> ProgramDebugContext {
    if !enabled {
        return ProgramDebugContext {
            output_contracts: None,
            pdb_contract_vas: std::collections::HashSet::new(),
            types: None,
        };
    }
    let (output_contracts, pdb_contract_vas, pdb_types) =
        super::dwarf_contracts::debug_output_contracts(image, binary_path, pdb_cache);
    let mut types = session.debug_types().to_vec();
    types.extend(pdb_types);
    ProgramDebugContext {
        output_contracts: Some(output_contracts),
        pdb_contract_vas,
        types: Some(types),
    }
}

/// Canonical semantic order for the AST pipeline.
///
/// A pass may be omitted when its typed precondition is absent (for example,
/// wide-parameter materialization without a recovered prototype), but a pass
/// may not be unknown, repeated, or run behind a later pass.
const AST_PASS_ORDER: &[&str] = &[
    "recover_wide_copies",
    "reconstruct",
    "fold_constants",
    "fold_boolean_masks",
    "prune_dead_flags",
    "fold_got_pointer_loads",
    "recover_resolved_tail_calls",
    "reconstruct_args",
    "apply_known_call_contracts",
    "split_call_result_lifetimes",
    "canary+strings",
    "promote_stack_locals",
    "bind_indirect_result_buffers",
    "recognise_machine_frame",
    "materialize_direct_output",
    "split_argument_storage_reuse",
    "materialize_32bit_wide_parameters",
    "apply_role_names",
    "eliminate_dead_stores",
    "stack_idiom+label_prune",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AstPassOrderError {
    Unknown {
        pass: &'static str,
    },
    OutOfOrder {
        pass: &'static str,
        previous: &'static str,
    },
}

impl std::fmt::Display for AstPassOrderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown { pass } => write!(formatter, "unknown AST pipeline pass {pass}"),
            Self::OutOfOrder { pass, previous } => write!(
                formatter,
                "AST pipeline pass {pass} cannot run after {previous}"
            ),
        }
    }
}

#[derive(Debug, Default)]
struct AstPassOrder {
    previous: Option<(usize, &'static str)>,
}

impl AstPassOrder {
    fn check(&mut self, pass: &'static str) -> Result<(), AstPassOrderError> {
        let Some(index) = AST_PASS_ORDER
            .iter()
            .position(|candidate| *candidate == pass)
        else {
            return Err(AstPassOrderError::Unknown { pass });
        };
        if let Some((previous_index, previous)) = self.previous {
            if index <= previous_index {
                return Err(AstPassOrderError::OutOfOrder { pass, previous });
            }
        }
        self.previous = Some((index, pass));
        Ok(())
    }
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
/// Fold the pre-naming AST using explicit register and stack parameter roles.
fn fold_early_constants(
    function: &mut crate::ir::ast::Function,
    value_identities: &crate::ir::value_number::ValueIdentities,
    parameter_slots: &std::collections::HashSet<usize>,
) -> bool {
    let parameter_identities = value_identities.with_parameter_slots(parameter_slots);
    crate::ir::const_fold::fold_constants_with_identities(function, &parameter_identities)
}

pub(super) fn run_ast_passes(
    f: &mut crate::ir::ast::Function,
    profiler: &mut crate::decompile::profile::FunctionProfiler,
    cfg_health: crate::ir::health::CfgHealth,
    cc: crate::ir::call_args::CallConv,
    endianness: crate::core::binary::Endianness,
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
    value_identities: &mut crate::ir::value_number::ValueIdentities,
) -> Result<
    (
        crate::ir::stack_locals::StackLocalFacts,
        std::collections::HashMap<String, String>,
    ),
    AstPassOrderError,
> {
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
    let mut pass_order = AstPassOrder::default();
    macro_rules! pass {
        ($n:expr, $operation:expr) => {{
            pass_order.check($n)?;
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
        crate::ir::vector_copy::recover_wide_copies_with_identities(f, value_identities)
    );
    pass!("reconstruct", crate::ir::expr_reconstruct::reconstruct(f));
    pass!(
        "fold_constants",
        fold_early_constants(f, value_identities, param_slots)
    );
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
        crate::ir::call_args::recover_proven_vtable_tail_calls(f, cc, &callee_facts.prototypes);
    });
    pass!("reconstruct_args", {
        crate::ir::call_args::reconstruct_args_with_layouts_prototypes_strings_and_identities(
            f,
            cc,
            param_slots,
            &reconstruction_layouts,
            &callee_facts.table_entry_layouts,
            Some(&callee_facts.prototypes),
            str_pool,
            value_identities,
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
    // Indirect result buffers are not reliably described by DWARF at `-O2` --
    // they are compiler temporaries with no source name -- so the ABI has to
    // declare them. This covers AAPCS64's separate `x8` and SysV's hidden first
    // argument; without the latter, a bare `rsp` call argument renders as an
    // uninitialised scalar rather than the address of the promoted buffer.
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
        crate::ir::stack_locals::promote_stack_locals_with_facts_and_identities(
            f,
            Some(cc),
            locked_parameter_count,
            &stack_object_hints,
            value_identities,
        )
    );
    value_identities.attach_machine_saved_slots(&stack_facts.machine_saved_slots);
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
        recognise_machine_frame(f, cc, value_identities);
        if nested_machine_frame_cleanup {
            crate::ir::dead_stores::prune_callee_saved_spills_nested_with_identities(
                f,
                cc,
                value_identities,
            );
        }
    });
    // Project a prototype-proven result while the raw ABI output register is
    // still present. ARM32/AArch64 reuse arg0's register for the result; the
    // following spill-role split must rename both its final definition and the
    // return use together, rather than orphaning the result as scratch.
    pass!("materialize_direct_output", {
        if output_kind == crate::ir::types_recover::RecoveredOutputKind::Direct {
            // Preserve every bank before generic direct-output projection
            // chooses one and folds its final assignment into the return.
            // After that fold the expression no longer identifies whether it
            // came from RAX or XMM0; GCC and Clang choose opposite banks for
            // the same mixed aggregate.
            crate::ir::callee_return_bank::materialize_register_split_returns(f, cc, prototype);
            crate::ir::callee_return_bank::materialize_register_sse_pair_returns(f, cc, prototype);
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
    if let Some(prototype) = prototype {
        pass!(
            "materialize_32bit_wide_parameters",
            crate::ir::wide_parameters::materialize_32bit_wide_parameters(
                f,
                prototype,
                &stack_facts,
                endianness,
            )
        );
    }
    let role_names = pass!(
        "apply_role_names",
        crate::ir::naming::apply_role_names_with_parameter_roles_and_stack_parameters(
            f,
            cc,
            param_slots,
            &parameter_roles,
            &stack_facts.parameter_slots,
        )
    );
    let named_value_identities =
        value_identities.with_role_aliases_and_parameter_slots(&role_names, param_slots);
    // Dead-store elimination runs *after* naming so it sees the aliased return register
    // (`ret` / `arg0`) rather than the raw physical one; that removes the common pre-call
    // `%ret = 0` idiom entirely.
    pass!("eliminate_dead_stores", {
        crate::ir::canary::collapse_canary_save(f);
        if matches!(cc, crate::ir::call_args::CallConv::Aarch64) {
            crate::ir::arm64_prologue::recognise_arm64_prologue(f);
        }
        crate::ir::dead_stores::eliminate_dead_stores_with_identities(
            f,
            cc,
            &named_value_identities,
        );
    });
    pass!("stack_idiom+label_prune", {
        crate::ir::stack_idiom::rematerialise_stack_ops(f);
        crate::ir::label_prune::prune_unreferenced_labels(f);
    });
    Ok((stack_facts, role_names))
}

/// Collapse architecture-specific machine frames after stack-slot promotion.
///
/// The pass is repeated after the common AST pipeline because stack-idiom
/// rematerialisation may expose a second canonical spelling. Each recogniser
/// is idempotent and fail-closed when the frame is not exactly balanced.
pub(super) fn recognise_machine_frame(
    f: &mut crate::ir::ast::Function,
    cc: crate::ir::call_args::CallConv,
    value_identities: &crate::ir::value_number::ValueIdentities,
) {
    match cc {
        crate::ir::call_args::CallConv::SysVAmd64 | crate::ir::call_args::CallConv::Win64 => {
            crate::ir::x86_prologue::recognise_x86_prologue_with_identities(f, value_identities);
        }
        crate::ir::call_args::CallConv::Cdecl32 => {
            crate::ir::x86_prologue::recognise_cdecl32_call_alignment(f);
        }
        crate::ir::call_args::CallConv::Arm | crate::ir::call_args::CallConv::ArmHardFloat => {
            crate::ir::arm32_prologue::recognise_arm32_frame_with_identities(f, value_identities);
        }
        crate::ir::call_args::CallConv::Aarch64 => {
            crate::ir::arm64_prologue::recognise_arm64_prologue(f);
        }
    }
    if matches!(
        cc,
        crate::ir::call_args::CallConv::SysVAmd64
            | crate::ir::call_args::CallConv::Win64
            | crate::ir::call_args::CallConv::Cdecl32
    ) {
        crate::ir::x86_prologue::drop_implicit_main_runtime_call(f);
    }
    // Whatever the per-architecture recogniser could not attribute to a frame
    // pattern, the callee-saved spills themselves are still machine bookkeeping.
    // This runs for every convention. It also removes any independently proven
    // dead spill that an architecture recogniser deliberately left alone.
    crate::ir::dead_stores::prune_callee_saved_spills_with_identities(f, cc, value_identities);
}

/// Apply the presentation-boundary semantic facts every renderer consumes.
///
/// This remains part of the pipeline rather than an adapter concern: rendering
/// an AST before debug locals, exception semantics, machine-frame cleanup, or
/// field facts have landed is a different decompilation result.
#[allow(clippy::too_many_arguments)]
pub(super) fn finalize_prepared_ast(
    mut prepared: PreparedAst,
    analyst_locals: Option<&std::collections::HashMap<i64, (String, String)>>,
    debug_contract: Option<&super::dwarf_contracts::DwarfPrototypeContract>,
    arch: crate::core::binary::Arch,
    cc: crate::ir::call_args::CallConv,
    dwarf_type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
    style: &str,
    exception_sites: &[crate::analysis::exception::ExceptionCallSite],
    address_names: &std::collections::HashMap<u64, String>,
    field_map: Option<&crate::ir::pdb_fields::PdbFieldMap>,
) -> PreparedAst {
    if let Some(locals) = analyst_locals {
        crate::ir::stack_locals::apply_analyst_locals(&mut prepared.stack_facts, locals);
    }
    super::dwarf_contracts::merge_dwarf_register_local_facts(
        &mut prepared.stack_facts,
        debug_contract,
        &prepared.numbered,
        &prepared.role_names,
        &prepared.value_identities,
        &prepared.parameter_slots,
        arch,
        cc,
        dwarf_type_env,
    );
    if style == "decbench" {
        crate::ir::exception_recover::recover_typed_handlers(
            &mut prepared.function,
            exception_sites,
        );
        crate::ir::exception_recover::mark_int_throws_with_address_map(
            &mut prepared.function,
            address_names,
        );
        crate::ir::exception_recover::recover_throws(&mut prepared.function);
    }
    recognise_machine_frame(&mut prepared.function, cc, &prepared.ast_value_identities);
    if let Some(field_map) = field_map {
        crate::ir::pdb_fields::annotate_function_fields(&mut prepared.function, field_map);
    }
    prepared
}

/// Program and request facts needed to render one finalized AST.
///
/// Keeping these facts in one typed object prevents the four Python adapters
/// from independently choosing declaration authority, type projections, or
/// incompleteness behavior. Adapter-specific Python containers remain outside
/// this boundary.
pub(super) struct FunctionRenderContext<'a> {
    pub(super) raw: &'a crate::ir::types::LlirFunction,
    pub(super) discovered: &'a crate::core::function::Function,
    pub(super) budgets: &'a crate::analysis::cfg::Budgets,
    pub(super) type_budget: TypeBudget,
    pub(super) function_va: u64,
    pub(super) render_options: RenderOptions<'a>,
    pub(super) debug_contract: Option<&'a DwarfPrototypeContract>,
    pub(super) debug_types: &'a [crate::debug::dwarf::DwarfType],
    pub(super) debug_type_env: Option<&'a crate::ir::dwarf_type_env::DwarfTypeEnv<'a>>,
    pub(super) debug_source: crate::program::environment::DeclarationSource,
    pub(super) exception_sites: &'a [crate::analysis::exception::ExceptionCallSite],
    pub(super) readonly_data: &'a crate::ir::readonly_fold::ReadonlyData,
    pub(super) string_pool: &'a std::collections::HashMap<u64, String>,
    pub(super) address_names: &'a std::collections::HashMap<u64, String>,
    pub(super) symbol_env: &'a crate::ir::symbol_env::SymbolEnv,
    pub(super) data_symbols: &'a crate::ir::data_symbols::DataSymbols,
    pub(super) calling_convention: crate::ir::call_args::CallConv,
    pub(super) pdb_outer_name: Option<&'a str>,
}

pub(super) struct RenderedAst {
    pub(super) text: String,
    pub(super) provenance: Vec<&'static str>,
    pub(super) line_mappings: Vec<(usize, crate::ir::ast::OriginSet)>,
}

pub(super) struct FunctionPipelineContext<'a> {
    pub(super) image: &'a crate::program::image::ProgramImage,
    pub(super) functions: &'a [crate::core::function::Function],
    pub(super) discovered: &'a crate::core::function::Function,
    pub(super) budgets: &'a crate::analysis::cfg::Budgets,
    pub(super) callee_budget: CalleeBudget,
    pub(super) type_budget: TypeBudget,
    pub(super) pipeline_fingerprint: PipelineFingerprint,
    pub(super) render_options: RenderOptions<'a>,
    pub(super) debug_outputs: Option<&'a std::collections::HashMap<u64, DwarfPrototypeContract>>,
    pub(super) debug_types: &'a [crate::debug::dwarf::DwarfType],
    pub(super) debug_type_env: Option<&'a crate::ir::dwarf_type_env::DwarfTypeEnv<'a>>,
    pub(super) debug_source: crate::program::environment::DeclarationSource,
    pub(super) program_fact: Option<&'a crate::program::environment::FunctionPrototypeFact>,
    pub(super) exception_sites: &'a [crate::analysis::exception::ExceptionCallSite],
    pub(super) address_names: &'a mut std::collections::HashMap<u64, String>,
    pub(super) function_tables: &'a [crate::ir::function_tables::FunctionPointerTable],
    pub(super) got_targets: &'a std::collections::HashMap<u64, u64>,
    pub(super) string_pool: &'a std::collections::HashMap<u64, String>,
    pub(super) readonly_data: &'a crate::ir::readonly_fold::ReadonlyData,
    pub(super) data_symbols: &'a crate::ir::data_symbols::DataSymbols,
    pub(super) field_map: Option<&'a crate::ir::pdb_fields::PdbFieldMap>,
    pub(super) call_graph: Option<&'a crate::program::call_graph::ProgramCallGraph>,
    pub(super) callee_cache: &'a mut std::collections::HashMap<u64, Option<RecoveredDirectCallee>>,
    pub(super) calling_convention: crate::ir::call_args::CallConv,
    pub(super) arm_vfp_args: bool,
    pub(super) prefer_debug_function_name: bool,
    pub(super) pdb_outer_name: Option<&'a str>,
}

pub(super) struct PipelineFunctionOutput {
    pub(super) raw: crate::ir::types::LlirFunction,
    pub(super) prepared: PreparedAst,
    pub(super) rendered: RenderedAst,
}

/// Coarse semantic stages of the per-function pipeline.
///
/// These are deliberately not inferred from which values happen to exist.
/// A new orchestration step must state the stage it consumes and produces, so
/// moving it across a semantic boundary fails immediately in tests and in the
/// production transaction instead of silently changing only one entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PipelineStage {
    Start,
    Lifted,
    CalleeFactsPrepared,
    LlirPrepared,
    AstPrepared,
    Finalized,
    Rendered,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PipelineStageError {
    operation: &'static str,
    expected: PipelineStage,
    actual: PipelineStage,
}

impl std::fmt::Display for PipelineStageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "pipeline operation {} requires {:?}, found {:?}",
            self.operation, self.expected, self.actual
        )
    }
}

#[derive(Debug, Clone)]
struct PipelineStageTracker {
    current: PipelineStage,
    operations: Vec<&'static str>,
}

impl PipelineStageTracker {
    fn new() -> Self {
        Self {
            current: PipelineStage::Start,
            operations: Vec::new(),
        }
    }

    fn advance(
        &mut self,
        operation: &'static str,
        expected: PipelineStage,
        next: PipelineStage,
    ) -> Result<(), PipelineStageError> {
        if self.current != expected {
            return Err(PipelineStageError {
                operation,
                expected,
                actual: self.current,
            });
        }
        self.current = next;
        self.operations.push(operation);
        Ok(())
    }

    fn operations(&self) -> &[&'static str] {
        &self.operations
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FunctionPipelineError {
    Lift(String),
    Shadow(&'static str),
    Stage(PipelineStageError),
    PassOrder(AstPassOrderError),
}

impl std::fmt::Display for FunctionPipelineError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lift(reason) => formatter.write_str(reason),
            Self::Shadow(reason) => formatter.write_str(reason),
            Self::Stage(reason) => reason.fmt(formatter),
            Self::PassOrder(reason) => reason.fmt(formatter),
        }
    }
}

impl From<PipelineStageError> for FunctionPipelineError {
    fn from(error: PipelineStageError) -> Self {
        Self::Stage(error)
    }
}

impl From<AstPassOrderError> for FunctionPipelineError {
    fn from(error: AstPassOrderError) -> Self {
        Self::PassOrder(error)
    }
}

/// Execute the complete semantic pipeline for one discovered function.
pub(super) fn decompile_function(
    context: FunctionPipelineContext<'_>,
) -> Result<PipelineFunctionOutput, FunctionPipelineError> {
    let mut stages = PipelineStageTracker::new();
    let FunctionPipelineContext {
        image,
        functions,
        discovered,
        budgets,
        callee_budget,
        type_budget,
        pipeline_fingerprint,
        render_options,
        debug_outputs,
        debug_types,
        debug_type_env,
        debug_source,
        program_fact,
        exception_sites,
        address_names,
        function_tables,
        got_targets,
        string_pool,
        readonly_data,
        data_symbols,
        field_map,
        call_graph,
        callee_cache,
        calling_convention: cc,
        arm_vfp_args,
        prefer_debug_function_name,
        pdb_outer_name,
    } = context;
    let function_va = discovered.entry_point.value;
    let mut raw = crate::ir::lift_function::lift_function_from_image(image, discovered)
        .map_err(|error| FunctionPipelineError::Lift(error.to_string()))?;
    stages.advance("lift", PipelineStage::Start, PipelineStage::Lifted)?;
    let mut callee_facts = prepare_direct_callee_facts(
        image,
        functions,
        &mut raw,
        cc,
        arm_vfp_args,
        budgets,
        callee_budget.max_depth,
        debug_outputs,
        debug_type_env,
        address_names,
        function_tables,
        call_graph,
        callee_cache,
    );
    stages.advance(
        "prepare_direct_callee_facts",
        PipelineStage::Lifted,
        PipelineStage::CalleeFactsPrepared,
    )?;
    if let Some(names) = render_options.analyst_names {
        let renames = crate::ir::name_resolve::apply_analyst_names(address_names, names);
        if !renames.is_empty() {
            callee_facts.env.rename_display(&renames);
        }
    }
    let debug_contract = debug_outputs.and_then(|outputs| outputs.get(&function_va));
    let typed_pipeline =
        render_options.style == "decbench" && (render_options.types || render_options.shadow_v2);
    let mut prepared_llir = prepare_llir_for_lowering_with_shadow(
        &mut raw,
        image,
        exception_sites,
        cc,
        typed_pipeline,
        arm_vfp_args,
        debug_contract,
        program_fact,
        debug_type_env,
        render_options.shadow_v2,
    );
    stages.advance(
        "prepare_llir_for_lowering_with_shadow",
        PipelineStage::CalleeFactsPrepared,
        PipelineStage::LlirPrepared,
    )?;
    prepared_llir
        .select_shadow_v2(render_options.shadow_v2, render_options.style == "decbench")
        .map_err(FunctionPipelineError::Shadow)?;
    let function_name = if prefer_debug_function_name {
        debug_contract
            .and_then(|contract| contract.function_name.as_ref())
            .cloned()
            .unwrap_or_else(|| discovered.name.clone())
    } else {
        crate::ir::name_resolve::resolve_outer_function_name_with_analyst(
            &discovered.name,
            function_va,
            address_names,
            render_options.analyst_names,
        )
    };
    let stack_object_hints = super::dwarf_contracts::dwarf_stack_object_hints(debug_contract, cc);
    let prepared = lower_and_run_ast_passes(
        prepared_llir,
        &raw,
        function_name,
        function_va,
        exception_sites,
        cc,
        image.endianness(),
        render_options.shadow_v2,
        &callee_facts,
        address_names,
        string_pool,
        function_tables,
        &stack_object_hints,
        got_targets,
    )?;
    stages.advance(
        "lower_and_run_ast_passes",
        PipelineStage::LlirPrepared,
        PipelineStage::AstPrepared,
    )?;
    let mut prepared = finalize_prepared_ast(
        prepared,
        render_options.analyst_locals,
        debug_contract,
        image.target().architecture(),
        cc,
        debug_type_env,
        render_options.style,
        exception_sites,
        address_names,
        field_map,
    );
    stages.advance(
        "finalize_prepared_ast",
        PipelineStage::AstPrepared,
        PipelineStage::Finalized,
    )?;
    let rendered = render_prepared_ast(
        &mut prepared,
        FunctionRenderContext {
            raw: &raw,
            discovered,
            budgets,
            type_budget,
            function_va,
            render_options,
            debug_contract,
            debug_types,
            debug_type_env,
            debug_source,
            exception_sites,
            readonly_data,
            string_pool,
            address_names,
            symbol_env: &callee_facts.env,
            data_symbols,
            calling_convention: cc,
            pdb_outer_name,
        },
    );
    stages.advance(
        "render_prepared_ast",
        PipelineStage::Finalized,
        PipelineStage::Rendered,
    )?;
    prepared
        .profiler
        .record_pipeline_stages(stages.operations(), || pipeline_fingerprint.canonical());
    Ok(PipelineFunctionOutput {
        raw,
        prepared,
        rendered,
    })
}

/// Render one already-finalized AST through the single shared style policy.
pub(super) fn render_prepared_ast(
    prepared: &mut PreparedAst,
    context: FunctionRenderContext<'_>,
) -> RenderedAst {
    let FunctionRenderContext {
        raw,
        discovered,
        budgets,
        type_budget,
        function_va,
        render_options,
        debug_contract,
        debug_types,
        debug_type_env,
        debug_source,
        exception_sites,
        readonly_data,
        string_pool,
        address_names,
        symbol_env,
        data_symbols,
        calling_convention: cc,
        pdb_outer_name,
    } = context;
    let mut provenance = vec![crate::program::environment::DeclarationSource::Inferred.label()];
    if render_options.analyst_names.is_some()
        || render_options.analyst_locals.is_some()
        || render_options.analyst_prototype.is_some()
    {
        provenance.push(crate::program::environment::DeclarationSource::Analyst.label());
    }

    let text = if render_options.style == "decbench" {
        let maps = render_options.types.then(|| {
            super::type_maps::decbench_type_maps(
                &prepared.function,
                raw,
                &prepared.numbered,
                prepared
                    .prototype
                    .as_ref()
                    .expect("typed DecBench prototype"),
                cc,
                &prepared.parameter_slots,
                &prepared.stack_facts.sizes,
                &prepared.stack_facts.source_types,
                &prepared.stack_facts.source_names,
                debug_type_env,
                &prepared.role_names,
                &prepared.value_identities,
                &prepared.definition_widths,
                type_budget.max_refinement_rounds,
            )
        });
        let (decl, width, exact_value_widths) = match &maps {
            Some((decl, width, exact)) => (Some(decl), Some(width), Some(exact)),
            None => (None, None, None),
        };
        let debug_render = debug_contract.and_then(super::dwarf_contracts::dwarf_render_prototype);
        let analyst_render = render_options.analyst_prototype.map(|prototype| {
            crate::ir::call_contracts::CallPrototype::from_analyst(
                &prototype.return_type,
                &prototype.parameter_types,
                prototype.variadic,
            )
        });
        let (declared_source, declared_render) = match (analyst_render, debug_render) {
            (Some(analyst), Some(debug)) => {
                crate::program::environment::DeclarationSource::strongest(
                    (
                        crate::program::environment::DeclarationSource::Analyst,
                        Some(analyst),
                    ),
                    (debug_source, Some(debug)),
                )
            }
            (Some(analyst), None) => (
                crate::program::environment::DeclarationSource::Analyst,
                Some(analyst),
            ),
            (None, debug) => (debug_source, debug),
        };
        if declared_render.is_some() && !provenance.contains(&declared_source.label()) {
            provenance.push(declared_source.label());
        }
        let declared_parameter_names =
            if declared_source == crate::program::environment::DeclarationSource::Analyst {
                render_options
                    .analyst_prototype
                    .map(|prototype| prototype.parameter_names.as_slice())
            } else {
                debug_contract.map(|contract| contract.parameter_names.as_slice())
            };
        if render_options.analyst_prototype.is_some() {
            super::record_prototype_conflict_with_candidate(
                &prepared.function.name,
                function_va,
                crate::program::environment::DeclarationSource::Analyst.label(),
                declared_render.as_ref(),
                crate::program::environment::DeclarationSource::Dwarf.label(),
                debug_contract
                    .and_then(super::dwarf_contracts::dwarf_render_prototype)
                    .as_ref(),
            );
        }
        super::record_recovered_prototype_conflict(
            &prepared.function.name,
            function_va,
            declared_source.label(),
            declared_render.as_ref(),
            prepared.inferred_prototype.as_ref(),
            cc,
        );
        super::decbench_render::decbench_text(
            &prepared.function,
            &prepared.ast_value_identities,
            &mut prepared.profiler,
            prepared.cfg_health,
            exception_sites,
            decl,
            width,
            exact_value_widths,
            readonly_data,
            string_pool,
            prepared.prototype.as_ref(),
            declared_render.as_ref(),
            declared_parameter_names,
            debug_types,
            &prepared.stack_facts.source_types,
            &prepared.stack_facts.source_names,
            &prepared.stack_facts.sizes,
            debug_contract.map_or(&[], |contract| contract.static_locals.as_slice()),
            cc,
            address_names,
            symbol_env,
            data_symbols,
        )
    } else if render_options.style == "c" {
        let body = prepared
            .profiler
            .measure("render_c", || crate::ir::ast::render_c(&prepared.function));
        match pdb_outer_name {
            Some(name) => format!("// PDB: {name}\n{body}"),
            None => body,
        }
    } else if render_options.types {
        let recovered = crate::ir::types_recover::recover_types_for_with_identities(
            &prepared.numbered,
            cc,
            &prepared.value_identities,
        );
        let renamed = super::type_maps::remap_type_map_with_roles(
            &recovered,
            cc,
            &prepared.parameter_slots,
            &prepared.role_names,
            &prepared.value_identities,
        );
        prepared.profiler.measure("render_with_types", || {
            crate::ir::ast::render_with_types(&prepared.function, &renamed)
        })
    } else {
        prepared
            .profiler
            .measure("render", || crate::ir::ast::render(&prepared.function))
    };
    let mut line_mappings = if render_options.style == "decbench" {
        crate::ir::ast::take_decbench_line_mappings()
    } else {
        Vec::new()
    };
    let text = match crate::analysis::completeness::cfg_incompleteness_note(discovered, budgets) {
        Some(note) => {
            for (line_number, _) in &mut line_mappings {
                *line_number += 1;
            }
            format!("{note}\n{text}")
        }
        None => text,
    };
    RenderedAst {
        text,
        provenance,
        line_mappings,
    }
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
struct SsaTrackedLlir<'a> {
    function: &'a mut crate::ir::types::LlirFunction,
    ssa: crate::ir::ssa::VersionedSsa,
}

impl<'a> SsaTrackedLlir<'a> {
    fn new(
        function: &'a mut crate::ir::types::LlirFunction,
        ssa: crate::ir::ssa::VersionedSsa,
    ) -> Self {
        Self { function, ssa }
    }

    fn function(&self) -> &crate::ir::types::LlirFunction {
        self.function
    }

    fn ensure(&mut self, analyzed: &crate::ir::types::LlirFunction) -> &crate::ir::ssa::SsaInfo {
        self.ssa.ensure(analyzed)
    }

    fn apply_mutation<R>(
        &mut self,
        change: crate::ir::ssa::Invalidate,
        mutation: impl FnOnce(&mut crate::ir::types::LlirFunction) -> (R, bool),
    ) -> R {
        self.ssa.apply_mutation(self.function, change, mutation)
    }
}

fn normalize_definedness_with_ssa(
    tracked: &mut SsaTrackedLlir<'_>,
    exception_sites: &[crate::analysis::exception::ExceptionCallSite],
    cc: crate::ir::call_args::CallConv,
) {
    let graph = crate::analysis::exception::with_exceptional_successors(
        tracked.function(),
        exception_sites,
    );
    let current_ssa = tracked.ensure(&graph).clone();
    let oracle = crate::ir::definedness::BitDemandOracle::analyze(&graph, &current_ssa, cc);
    let erased = tracked.apply_mutation(crate::ir::ssa::Invalidate::Uses, |function| {
        let count =
            crate::ir::definedness::erase_unobserved_masked_inputs(function, &current_ssa, &oracle);
        (count, count != 0)
    });
    if erased != 0 {
        let normalized_graph = crate::analysis::exception::with_exceptional_successors(
            tracked.function(),
            exception_sites,
        );
        tracked.ensure(&normalized_graph);
    }
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
    pub(super) value_identities: crate::ir::value_number::ValueIdentities,
    pub(super) definition_widths: std::collections::HashMap<crate::ir::types::VReg, u8>,
    pub(super) parameter_slots: std::collections::HashSet<usize>,
    /// Machine-only recovery before DWARF locks are applied, retained solely
    /// for declaration-conflict provenance.
    pub(super) inferred_prototype: Option<crate::ir::types_recover::RecoveredPrototype>,
    pub(super) prototype: Option<crate::ir::types_recover::RecoveredPrototype>,
}

/// Output of the common LLIR-to-AST portion of one decompilation.
///
/// Rendering remains an adapter concern for now, but no public entry point may
/// independently refine the prototype, lower the selected region, or run the
/// AST pass list. Keeping the supporting facts beside the AST prevents a
/// renderer from accidentally pairing it with a different numbered function.
pub(super) struct PreparedAst {
    pub(super) function: crate::ir::ast::Function,
    pub(super) profiler: crate::decompile::profile::FunctionProfiler,
    pub(super) cfg_health: crate::ir::health::CfgHealth,
    pub(super) numbered: crate::ir::types::LlirFunction,
    /// Opaque SSA identities keyed by values retained across AST lowering.
    pub(super) value_identities: crate::ir::value_number::ValueIdentities,
    /// The same identities projected through the exact AST role-name map.
    /// Separate storage preserves the original keys used by type recovery.
    pub(super) ast_value_identities: crate::ir::value_number::ValueIdentities,
    pub(super) definition_widths: std::collections::HashMap<crate::ir::types::VReg, u8>,
    pub(super) parameter_slots: std::collections::HashSet<usize>,
    pub(super) inferred_prototype: Option<crate::ir::types_recover::RecoveredPrototype>,
    pub(super) prototype: Option<crate::ir::types_recover::RecoveredPrototype>,
    pub(super) stack_facts: crate::ir::stack_locals::StackLocalFacts,
    pub(super) role_names: std::collections::HashMap<String, String>,
}

/// Lower one prepared LLIR function and run the one authoritative AST pipeline.
#[allow(clippy::too_many_arguments)]
pub(super) fn lower_and_run_ast_passes(
    prepared: PreparedLlir,
    raw: &crate::ir::types::LlirFunction,
    function_name: String,
    function_va: u64,
    exception_sites: &[crate::analysis::exception::ExceptionCallSite],
    cc: crate::ir::call_args::CallConv,
    endianness: crate::core::binary::Endianness,
    nested_machine_frame_cleanup: bool,
    callee_facts: &DirectCalleeFacts,
    address_names: &std::collections::HashMap<u64, String>,
    string_pool: &std::collections::HashMap<u64, String>,
    function_tables: &[crate::ir::function_tables::FunctionPointerTable],
    stack_object_hints: &[crate::ir::stack_locals::StackObjectHint],
    got_targets: &std::collections::HashMap<u64, u64>,
) -> Result<PreparedAst, AstPassOrderError> {
    let PreparedLlir {
        region,
        cfg_health,
        numbered,
        mut value_identities,
        definition_widths,
        parameter_slots: mut param_slots,
        inferred_prototype,
        mut prototype,
        ..
    } = prepared;
    if let Some(prototype) = prototype.as_mut() {
        let exact_ssa = crate::ir::ssa::compute_ssa(raw);
        refine_passthrough_parameter_hints(prototype, raw, &exact_ssa, callee_facts);
    }
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!("\n===== recovered prototype =====\n{prototype:#?}");
    }

    let mut profiler =
        crate::decompile::profile::FunctionProfiler::from_env(&function_name, function_va);
    let mut function = profiler.measure("lower", || {
        crate::ir::ast::lower(&numbered, &region, function_name)
    });
    crate::ir::exception_recover::mark_landing_pads(&mut function, exception_sites);
    crate::ir::health::trace_pass("lower", &function, cfg_health);
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!(
            "\n===== after lower =====\n{}",
            crate::ir::ast::render(&function)
        );
    }
    let (stack_facts, role_names) = run_ast_passes(
        &mut function,
        &mut profiler,
        cfg_health,
        cc,
        endianness,
        nested_machine_frame_cleanup,
        prototype.as_ref(),
        &mut param_slots,
        super::locked_parameter_count(prototype.as_ref()),
        callee_facts,
        address_names,
        string_pool,
        function_tables,
        stack_object_hints,
        got_targets,
        &mut value_identities,
    )?;
    let ast_value_identities =
        value_identities.with_role_aliases_and_parameter_slots(&role_names, &param_slots);

    Ok(PreparedAst {
        function,
        profiler,
        cfg_health,
        numbered,
        value_identities,
        ast_value_identities,
        definition_widths,
        parameter_slots: param_slots,
        inferred_prototype,
        prototype,
        stack_facts,
        role_names,
    })
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
    let initial_graph =
        crate::analysis::exception::with_exceptional_successors(function, exception_sites);
    let ssa_state = crate::ir::ssa::VersionedSsa::compute(&initial_graph, *image.target());
    let mut tracked = SsaTrackedLlir::new(function, ssa_state);
    normalize_definedness_with_ssa(&mut tracked, exception_sites, cc);
    let current_graph = crate::analysis::exception::with_exceptional_successors(
        tracked.function(),
        exception_sites,
    );
    let ssa = tracked.ensure(&current_graph).clone();
    let provisional_slots = if recover_semantic_prototype {
        crate::ir::value_number::value_number_with_parameter_slots(tracked.function(), &ssa, cc).2
    } else {
        crate::ir::value_number::live_in_arg_slots_llir(tracked.function(), cc)
    };
    let mut inferred_prototype = None;
    let prototype = recover_semantic_prototype.then(|| {
        let (mut prototype, inferred) = recover_decbench_prototype_with_inferred(
            tracked.function(),
            &ssa,
            cc,
            &provisional_slots,
            arm_vfp_args,
            declared,
            type_env,
        );
        if declared.is_some() {
            inferred_prototype = Some(inferred);
        }
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
    let materialized_returns = prototype.as_ref().map_or(0, |prototype| {
        tracked.apply_mutation(crate::ir::ssa::Invalidate::Uses, |function| {
            let count =
                crate::ir::types_recover::materialize_return_values(function, cc, prototype);
            (count, count != 0)
        })
    });
    if materialized_returns != 0 {
        normalize_definedness_with_ssa(&mut tracked, exception_sites, cc);
    }
    let current_graph = crate::analysis::exception::with_exceptional_successors(
        tracked.function(),
        exception_sites,
    );
    let ssa = tracked.ensure(&current_graph).clone();
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!("\n===== prototype-resolved LLIR =====");
        for block in &tracked.function().blocks {
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
        tracked.function(),
        &ssa,
        &image.relocated_symbol_slots(),
    );
    let (region, cfg_health) = crate::ir::structure::recover_verified_with_health_and_destinations(
        tracked.function(),
        &ssa,
        &indirect_destinations,
    );
    let shadow_v2_region = prepare_shadow_v2
        .then(|| {
            let report = crate::ir::structure_v2::observe(tracked.function(), &ssa);
            crate::ir::structure_v2::render::adapt_tree(tracked.function(), report.tree.as_ref()?)
        })
        .flatten();
    let (numbered, definition_widths, mut parameter_slots, value_identities) =
        if recover_semantic_prototype {
            let source_lifetimes = dwarf_source_register_lifetimes(declared, cc);
            crate::ir::value_number::value_number_with_parameter_slots_lifetimes_and_identities(
                tracked.function(),
                &ssa,
                cc,
                &source_lifetimes,
            )
        } else {
            (
                tracked.function().clone(),
                std::collections::HashMap::new(),
                crate::ir::value_number::live_in_arg_slots_llir(tracked.function(), cc),
                crate::ir::value_number::ValueIdentities::default(),
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
        value_identities,
        definition_widths,
        parameter_slots,
        inferred_prototype,
        prototype,
    }
}

#[cfg(test)]
mod request_tests {
    use super::{
        fold_early_constants, AnalysisBudget, AstPassOrder, AstPassOrderError, CalleeBudget,
        CfgBudget, DecompileCompleteness, DecompileRequest, DiscoveryBudget, PipelineStage,
        PipelineStageTracker, RenderOptions, SizeBudget, TypeBudget,
    };

    #[test]
    fn early_constant_fold_uses_typed_stack_parameter_roles() {
        use crate::ir::ast::{Expr, Function, Stmt};
        use crate::ir::types::VReg;

        let load = |name: &str| Expr::Deref {
            addr: Box::new(Expr::StackAddr {
                object: VReg::phys(name),
                size: 4,
            }),
            size: 4,
        };
        let mut function = Function {
            name: "typed_early_fold".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("owned"),
                    src: load("arg0"),
                },
                Stmt::Assign {
                    dst: VReg::phys("unowned"),
                    src: load("arg99"),
                },
            ],
        };

        assert!(fold_early_constants(
            &mut function,
            &crate::ir::value_number::ValueIdentities::default(),
            &std::collections::HashSet::from([0]),
        ));
        assert!(matches!(
            &function.body[0],
            Stmt::Assign { src: Expr::Reg(value), .. } if value == &VReg::phys("arg0")
        ));
        assert!(matches!(
            &function.body[1],
            Stmt::Assign {
                src: Expr::Deref { .. },
                ..
            }
        ));
    }

    #[test]
    fn ast_pass_order_allows_omissions_but_rejects_duplicates_and_reordering() {
        let mut passes = AstPassOrder::default();
        passes.check("recover_wide_copies").unwrap();
        passes.check("fold_constants").unwrap();
        passes.check("apply_role_names").unwrap();

        assert_eq!(
            passes.check("fold_constants"),
            Err(AstPassOrderError::OutOfOrder {
                pass: "fold_constants",
                previous: "apply_role_names",
            })
        );
    }

    #[test]
    fn ast_pass_order_rejects_an_unregistered_pass() {
        let mut passes = AstPassOrder::default();
        assert_eq!(
            passes.check("surprise_cleanup"),
            Err(AstPassOrderError::Unknown {
                pass: "surprise_cleanup",
            })
        );
    }

    #[test]
    fn invalid_pipeline_stage_order_fails_with_the_required_precondition() {
        let mut stages = PipelineStageTracker::new();
        stages
            .advance("lift", PipelineStage::Start, PipelineStage::Lifted)
            .unwrap();

        let error = stages
            .advance(
                "render_prepared_ast",
                PipelineStage::Finalized,
                PipelineStage::Rendered,
            )
            .unwrap_err();

        assert_eq!(error.operation, "render_prepared_ast");
        assert_eq!(error.expected, PipelineStage::Finalized);
        assert_eq!(error.actual, PipelineStage::Lifted);
        assert_eq!(stages.current, PipelineStage::Lifted);
    }

    #[test]
    fn pipeline_budget_preserves_every_discovery_limit() {
        let request = AnalysisBudget {
            discovery: DiscoveryBudget {
                max_functions: 17,
                total_timeout_ms: 41,
            },
            cfg: CfgBudget {
                max_blocks: 29,
                max_instructions: 31,
                timeout_ms: 37,
            },
            callee: CalleeBudget { max_depth: 3 },
            types: TypeBudget {
                max_refinement_rounds: 43,
            },
            size: SizeBudget {
                max_range_bytes: 47,
                max_output_functions: 53,
            },
        };

        let discovery = request.discovery();

        assert_eq!(discovery.max_functions, 17);
        assert_eq!(discovery.max_blocks, 29);
        assert_eq!(discovery.max_instructions, 31);
        assert_eq!(discovery.timeout_ms, 37);
        assert_eq!(discovery.total_timeout_ms, 41);
    }

    #[test]
    fn fingerprint_changes_with_budget_and_carries_the_pass_version() {
        let options = RenderOptions {
            types: true,
            style: "decbench",
            shadow_v2: false,
            pdb_cache: "",
            analyst_names: None,
            analyst_locals: None,
            analyst_prototype: None,
        };
        let first = DecompileRequest {
            va: 0x1000,
            analysis_budget: AnalysisBudget {
                discovery: DiscoveryBudget {
                    max_functions: 1,
                    total_timeout_ms: 0,
                },
                cfg: CfgBudget {
                    max_blocks: 256,
                    max_instructions: 10_000,
                    timeout_ms: 500,
                },
                callee: CalleeBudget::default(),
                types: TypeBudget::default(),
                size: SizeBudget::from_instruction_and_output_limits(10_000, 1),
            },
            render_options: options,
        };
        let mut second = first;
        second.analysis_budget.cfg.max_blocks += 1;

        let first = first.fingerprint();
        let second = second.fingerprint();
        assert_eq!(first.schema, "glaurung.decompile-pipeline/v1");
        assert_eq!(first.pass_version, super::PIPELINE_PASS_VERSION);
        assert_ne!(first, second);

        let mut third_request = DecompileRequest {
            va: 0x1000,
            analysis_budget: first.analysis_budget,
            render_options: options,
        };
        third_request.analysis_budget.callee.max_depth += 1;
        assert_ne!(first, third_request.fingerprint());
        let mut fourth_request = third_request;
        fourth_request.analysis_budget.types.max_refinement_rounds += 1;
        assert_ne!(third_request.fingerprint(), fourth_request.fingerprint());
        let mut fifth_request = fourth_request;
        fifth_request.analysis_budget.size.max_output_functions += 1;
        assert_ne!(fourth_request.fingerprint(), fifth_request.fingerprint());
        assert_eq!(first.canonical(), first.canonical());
        assert_ne!(first.canonical(), second.canonical());
    }

    #[test]
    fn completeness_names_the_exact_budget_that_fired() {
        use crate::core::address::{Address, AddressKind};
        use crate::core::function::{Function, FunctionFlags, FunctionKind};

        let entry = Address::new(AddressKind::VA, 0x1000, 64, None, None).unwrap();
        let mut function = Function::new("f".into(), entry, FunctionKind::Normal).unwrap();
        assert_eq!(
            DecompileCompleteness::from_function(&function),
            DecompileCompleteness {
                complete: true,
                fired_budgets: Vec::new(),
            }
        );

        function.add_flag(FunctionFlags::CFG_BLOCK_LIMIT);
        assert_eq!(
            DecompileCompleteness::from_function(&function),
            DecompileCompleteness {
                complete: false,
                fired_budgets: vec!["max_blocks"],
            }
        );
    }
}
