//! Python bindings for the LLIR (low-level IR) lifting pipeline.
//!
//! The IR is still young and likely to evolve, so rather than freeze a
//! PyO3 class per variant we expose a *dict-based* representation. Every
//! LLIR op becomes a small `dict` with a stable `kind` field plus kind-specific
//! payload fields. Python callers can pattern-match on `op["kind"]`.
//!
//! Stable shape (subject to additive changes):
//!
//! ```text
//! {
//!     "va": int,
//!     "kind": "assign" | "ite" | "bin" | "un" | "cmp"
//!           | "load" | "store" | "jump" | "cond_jump" | "call"
//!           | "return" | "nop" | "unknown",
//!     # additional kind-specific fields — see encode_op below.
//! }
//! ```
//!
//! `VReg`s are encoded as strings: physical registers as their raw name
//! (`"rax"`, `"x0"`), temporaries as `"%tN"`, and flags as `"%zf"`, `"%cf"`, …
//! This matches the Rust `Display` impl so the Python output round-trips
//! through tests.

mod callee_contracts;
mod decbench_render;
mod dwarf_contracts;
mod lift;
mod pipeline;
mod session;
mod type_maps;

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyList};

// `select_renderable_dwarf_local_facts` has no production caller in this module
// -- its only consumer here is the `mod tests` below, so the import is gated the
// same way `dwarf_return_hint` already is, rather than being dead in the shipped
// build.
#[cfg(test)]
use decbench_render::select_renderable_dwarf_local_facts;

#[cfg(test)]
use dwarf_contracts::dwarf_return_hint;
// `calling_convention_pointer_width` has no caller in this module: the sibling
// `callee_contracts` reaches it through `super::`, which is how it was already
// wired before the split.
use dwarf_contracts::{
    calling_convention_pointer_width, dwarf_render_prototype, dwarf_return_hint_with_env,
    DwarfPrototypeContract,
};

use lift::{lift_bytes_py, lift_window_at_py};

use pipeline::{
    decompile_function, discover_program, prepare_program_debug_context,
    prepare_program_name_context, prepare_program_render_context, target_calling_convention,
    AnalysisBudget, DecompileRequest, DecompileResult, FunctionPipelineContext,
    ProgramDebugContext, ProgramDiscovery, ProgramNameContext, ProgramRenderContext, RenderOptions,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AnalystPrototype {
    return_type: String,
    parameter_types: Vec<String>,
    variadic: bool,
    parameter_names: Vec<Option<String>>,
}

fn extract_analyst_prototype(
    value: Option<&Bound<'_, PyAny>>,
) -> PyResult<Option<AnalystPrototype>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if let Ok((return_type, parameter_types, variadic, parameter_names)) =
        value.extract::<(String, Vec<String>, bool, Vec<Option<String>>)>()
    {
        if parameter_names.len() != parameter_types.len() {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "analyst prototype has {} parameter types but {} parameter names",
                parameter_types.len(),
                parameter_names.len()
            )));
        }
        return Ok(Some(AnalystPrototype {
            return_type,
            parameter_types,
            variadic,
            parameter_names,
        }));
    }
    let (return_type, parameter_types, variadic) =
        value.extract::<(String, Vec<String>, bool)>()?;
    let parameter_names = vec![None; parameter_types.len()];
    Ok(Some(AnalystPrototype {
        return_type,
        parameter_types,
        variadic,
        parameter_names,
    }))
}

fn load_program_image(path: &str) -> PyResult<crate::program::image::ProgramImage> {
    use crate::program::image::{ProgramImage, ProgramImageError};

    ProgramImage::from_path(std::path::Path::new(path)).map_err(|error| match error {
        ProgramImageError::Io(error) => {
            pyo3::exceptions::PyIOError::new_err(format!("read error: {error}"))
        }
        ProgramImageError::Parse(error) => {
            pyo3::exceptions::PyValueError::new_err(format!("image parse failed: {error}"))
        }
    })
}

pub(super) fn load_program_session(
    path: &str,
) -> PyResult<crate::program::session::ProgramSession> {
    use crate::program::image::ProgramImageError;
    use crate::program::session::ProgramSession;

    ProgramSession::from_path(std::path::Path::new(path)).map_err(|error| match error {
        ProgramImageError::Io(error) => {
            pyo3::exceptions::PyIOError::new_err(format!("read error: {error}"))
        }
        ProgramImageError::Parse(error) => {
            pyo3::exceptions::PyValueError::new_err(format!("image parse failed: {error}"))
        }
    })
}

/// Run the full decompiler pipeline on the function whose entry is `func_va`
/// in `path`, returning the rendered pseudocode.
///
/// Pipeline: cfg discovery → per-function LLIR lift → SSA → structural
/// analysis → AST lowering → expression reconstruction. When `types=True`
/// (the default), the first-cut type-recovery pass runs and the output
/// carries `(u64*)`, `(bool)`, etc. annotations on classified registers.
/// When `style="c"`, the C-like renderer is used instead (strips `%`
/// prefixes and type annotations).
#[pyfunction]
#[pyo3(name = "decompile_at")]
#[pyo3(signature = (path, func_va, max_blocks=4096usize, max_instructions=200_000usize, timeout_ms=5000u64, types=true, style="", pdb_cache="", max_functions=1usize, analyst_names=None, analyst_locals=None, analyst_prototype=None))]
fn decompile_at_py(
    py: Python<'_>,
    path: String,
    func_va: u64,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    types: bool,
    style: &str,
    pdb_cache: &str,
    max_functions: usize,
    analyst_names: Option<std::collections::HashMap<u64, String>>,
    analyst_locals: Option<std::collections::HashMap<i64, (String, String)>>,
    analyst_prototype: Option<&Bound<'_, PyAny>>,
) -> PyResult<String> {
    let analyst_prototype = extract_analyst_prototype(analyst_prototype)?;
    let session = load_program_session(&path)?;
    decompile_at_session(
        py,
        &session,
        &path,
        DecompileRequest {
            va: func_va,
            analysis_budget: AnalysisBudget {
                discovery: pipeline::DiscoveryBudget {
                    max_functions,
                    total_timeout_ms: 0,
                },
                cfg: pipeline::CfgBudget {
                    max_blocks,
                    max_instructions,
                    timeout_ms,
                },
                callee: pipeline::CalleeBudget::default(),
                types: pipeline::TypeBudget::default(),
                size: pipeline::SizeBudget::from_instruction_and_output_limits(
                    max_instructions,
                    max_functions,
                ),
            },
            render_options: RenderOptions {
                types,
                style,
                shadow_v2: false,
                pdb_cache,
                analyst_names: analyst_names.as_ref(),
                analyst_locals: analyst_locals.as_ref(),
                analyst_prototype: analyst_prototype.as_ref(),
            },
        },
    )
    .map(|result| result.pseudocode)
}

fn decompile_at_session(
    py: Python<'_>,
    session: &crate::program::session::ProgramSession,
    path: &str,
    request: DecompileRequest<'_>,
) -> PyResult<DecompileResult> {
    let _run_profile = crate::decompile::profile::RunProfiler::from_env("decompile_at");

    let pipeline_fingerprint = request.fingerprint();
    let DecompileRequest {
        va: func_va,
        analysis_budget,
        render_options,
    } = request;
    let RenderOptions {
        types,
        style,
        shadow_v2: _,
        pdb_cache,
        analyst_names,
        analyst_locals,
        analyst_prototype,
    } = render_options;

    let image = session.image().clone();
    // An ARM32 Thumb symbol's value carries the Thumb bit; the entry it denotes
    // is one lower. Anything resolving a callee through `.symtab` hands us that
    // value verbatim, and decoding one byte in recovers a body with no
    // parameters at all. See `arm32_mode::normalise_entry`.
    let func_va = image.normalize_function_entry(func_va);
    let exception_sites = image.exception_call_sites();
    let ProgramDebugContext {
        output_contracts: dwarf_outputs,
        pdb_contract_vas,
        types: dwarf_types,
    } = prepare_program_debug_context(
        session,
        &image,
        path,
        pdb_cache,
        style == "decbench" && types,
    );
    let dwarf_type_env = dwarf_types
        .as_deref()
        .map(crate::ir::dwarf_type_env::DwarfTypeEnv::new);
    let ProgramDiscovery {
        budgets,
        functions: funcs,
    } = discover_program(py, session, analysis_budget, &[func_va]);
    let func = funcs
        .iter()
        .find(|f| f.entry_point.value == func_va)
        .cloned()
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "no function at entry VA 0x{:x}",
                func_va
            ))
        })?;
    let cc = target_calling_convention(&image)?;
    let arm_vfp_args = image.arm_hard_float();
    // Build the address map first so we can apply a PDB public-symbol name
    // to the *outer* function header before lowering. The map already
    // includes PDB symbols when a cache is configured, plus exports / IAT
    // names that beat the CFG-pass heuristic on stripped Windows binaries.
    // It is also what tells `soft_helpers` which call targets are libgcc
    // division helpers, and that has to happen while the IR is still physical.
    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    let ProgramNameContext {
        address_names: mut addr_map,
        data_symbols,
    } = prepare_program_name_context(&image, path, pdb_cache, &funcs);
    let ProgramRenderContext {
        data_symbols,
        string_pool: str_pool,
        readonly_data,
        function_tables,
        got_targets,
    } = prepare_program_render_context(session, &image, data_symbols);
    // The analyst overlay is DELIBERATELY not applied here. Everything between
    // this point and `recover_direct_callee_layouts` resolves callees BY NAME
    // against what the binary calls them -- `session.environment`,
    // `annotate_calls_in`, and the callee layout recovery itself. Renaming
    // `validate` to `parse_packet_hdr` before those run means they look up a
    // name no symbol source knows, find nothing, and downgrade a recovered
    // `int validate(char *, int)` to `long f(void)` at every call site. The
    // rename is a presentation decision, so it is applied after the analysis
    // that depends on binary truth -- see below.
    let program_environment = (style == "decbench" && types)
        .then(|| session.environment(&budgets, cc, &addr_map, &[func_va]));
    // Identity-keyed call structure for this exact discovery. `call_graph_for`
    // builds from `funcs` (already fetched above) instead of re-querying
    // `discover_functions`, so this one logical query registers exactly one
    // discovery-cache hit-or-miss rather than two. The SCC condensation lets
    // nested callee analysis decline to spend a layer inside a call cycle.
    let callee_call_graph = py.detach(|| session.call_graph_for(&budgets, &[func_va], &funcs));
    let mut callee_layout_cache = std::collections::HashMap::new();
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    // Emit a `// PDB: <name>` provenance comment in C-style output when the
    // outer function name came from a PDB public symbol -- a hint that this
    // name is Microsoft-authoritative (and not LLM-proposed / FLIRT / CFG-
    // heuristic). The PDB name is the function's `f.name` after the
    // outer-name resolution above; we only emit when a PDB cache was
    // configured AND the cache map actually answered for this VA.
    let pdb_outer_name = pdb_cache
        .and_then(|cache_dir| {
            crate::ir::name_resolve::collect_pdb_public_symbol_map(&path, cache_dir)
                .get(&func_va)
                .cloned()
        })
        .filter(|name| !name.is_empty() && !name.starts_with("sub_"));
    let output = decompile_function(FunctionPipelineContext {
        image: &image,
        functions: &funcs,
        discovered: &func,
        budgets: &budgets,
        callee_budget: analysis_budget.callee,
        type_budget: analysis_budget.types,
        render_options: RenderOptions {
            types,
            style,
            shadow_v2: false,
            pdb_cache: pdb_cache.and_then(|path| path.to_str()).unwrap_or(""),
            analyst_names,
            analyst_locals,
            analyst_prototype,
        },
        debug_outputs: dwarf_outputs.as_ref(),
        debug_types: dwarf_types.as_deref().unwrap_or(&[]),
        debug_type_env: dwarf_type_env.as_ref(),
        debug_source: if pdb_contract_vas.contains(&func_va) {
            crate::program::environment::DeclarationSource::Pdb
        } else {
            crate::program::environment::DeclarationSource::Dwarf
        },
        exception_sites: &exception_sites,
        program_fact: program_environment
            .as_deref()
            .and_then(|environment| environment.prototype_for(func_va)),
        address_names: &mut addr_map,
        function_tables: &function_tables,
        got_targets: &got_targets,
        string_pool: &str_pool,
        readonly_data: &readonly_data,
        data_symbols: &data_symbols,
        field_map: field_map.as_ref(),
        call_graph: Some(callee_call_graph.as_ref()),
        callee_cache: &mut callee_layout_cache,
        calling_convention: cc,
        arm_vfp_args,
        prefer_debug_function_name: false,
        pdb_outer_name: pdb_outer_name.as_deref(),
    })
    .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
    Ok(DecompileResult::from_rendered(
        output.rendered.text,
        &output.prepared.function,
        output.prepared.cfg_health,
        &func,
        output.rendered.provenance,
        pipeline_fingerprint,
    ))
}

#[pyfunction]
#[pyo3(name = "decompile_range_at")]
#[pyo3(signature = (path, func_va, range_start, range_end, max_blocks=256usize, max_instructions=10_000usize, timeout_ms=500u64, types=true, style="", pdb_cache="", max_functions=1usize))]
fn decompile_range_at_py(
    py: Python<'_>,
    path: String,
    func_va: u64,
    range_start: u64,
    range_end: u64,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    types: bool,
    style: &str,
    pdb_cache: &str,
    max_functions: usize,
) -> PyResult<String> {
    let _run_profile = crate::decompile::profile::RunProfiler::from_env("decompile_range_at");
    use crate::core::address::{Address, AddressKind};
    use crate::core::address_range::AddressRange;
    use crate::core::basic_block::BasicBlock;
    use crate::core::function::{Function, FunctionKind};

    if range_end <= range_start {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "range_end must be greater than range_start",
        ));
    }
    if func_va < range_start || func_va >= range_end {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "func_va must lie inside [range_start, range_end)",
        ));
    }
    if max_blocks == 0 || max_instructions == 0 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "max_blocks and max_instructions must be non-zero",
        ));
    }
    let request = DecompileRequest {
        va: func_va,
        analysis_budget: AnalysisBudget {
            discovery: pipeline::DiscoveryBudget {
                max_functions,
                total_timeout_ms: 0,
            },
            cfg: pipeline::CfgBudget {
                max_blocks,
                max_instructions,
                timeout_ms,
            },
            callee: pipeline::CalleeBudget::default(),
            types: pipeline::TypeBudget::default(),
            size: pipeline::SizeBudget::from_instruction_and_output_limits(
                max_instructions,
                max_functions,
            ),
        },
        render_options: RenderOptions {
            types,
            style,
            shadow_v2: false,
            pdb_cache,
            analyst_names: None,
            analyst_locals: None,
            analyst_prototype: None,
        },
    };
    let pipeline_fingerprint = request.fingerprint();
    let DecompileRequest {
        va: func_va,
        analysis_budget,
        render_options,
    } = request;
    let RenderOptions {
        types,
        style,
        shadow_v2: _,
        pdb_cache,
        analyst_names: _,
        analyst_locals: _,
        analyst_prototype: _,
    } = render_options;

    let image = load_program_image(&path)?;
    let session = crate::program::session::ProgramSession::from_image(image);
    let image = session.image().clone();
    let exception_sites = image.exception_call_sites();
    let ProgramDebugContext {
        output_contracts: dwarf_outputs,
        pdb_contract_vas,
        types: dwarf_types,
    } = prepare_program_debug_context(
        &session,
        &image,
        &path,
        pdb_cache,
        style == "decbench" && types,
    );
    let dwarf_type_env = dwarf_types
        .as_deref()
        .map(crate::ir::dwarf_type_env::DwarfTypeEnv::new);
    let cc = target_calling_convention(&image)?;
    let arm_vfp_args = image.arm_hard_float();
    let bits = image.target().address_bits().ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("target address width is unknown")
    })?;
    let max_bytes = analysis_budget.size.max_range_bytes;
    let capped_end = range_end.min(range_start.saturating_add(max_bytes));
    let entry = Address::new(AddressKind::VA, func_va, bits, None, None)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let block_start = Address::new(AddressKind::VA, range_start, bits, None, None)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let block_end = Address::new(AddressKind::VA, capped_end, bits, None, None)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let range = AddressRange::new(block_start.clone(), capped_end - range_start, None)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    // Prefer the ordinary CFG for a discovered function when every recovered
    // block lies inside the caller's explicit range. This makes range and
    // address requests consume the same control-flow facts without weakening
    // the range API's ability to lift an otherwise undiscovered byte window.
    let ProgramDiscovery {
        budgets,
        functions: discovered,
    } = discover_program(py, &session, analysis_budget, &[func_va]);
    let discovered_function = discovered
        .iter()
        .find(|candidate| {
            candidate.entry_point.value == func_va
                && !candidate.basic_blocks.is_empty()
                && candidate.basic_blocks.iter().all(|block| {
                    block.start_address.value >= range_start
                        && block.end_address.value <= capped_end
                })
        })
        .cloned();
    let func = if let Some(function) = discovered_function {
        function
    } else {
        let mut function = Function::new(format!("sub_{:x}", func_va), entry, FunctionKind::Normal)
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
        function.range = Some(range.clone());
        function.size = Some(range.size);
        function.chunks.push(range);
        function.basic_blocks.push(BasicBlock::new(
            format!("bb_{:x}", range_start),
            block_start,
            block_end,
            1,
            Some(Vec::new()),
            Some(Vec::new()),
        ));
        function
    };

    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    let ProgramNameContext {
        address_names: mut addr_map,
        data_symbols,
    } = prepare_program_name_context(&image, &path, pdb_cache, &discovered);
    let ProgramRenderContext {
        data_symbols,
        string_pool: str_pool,
        readonly_data,
        function_tables,
        got_targets,
    } = prepare_program_render_context(&session, &image, data_symbols);
    let program_environment = (style == "decbench" && types)
        .then(|| session.environment(&budgets, cc, &addr_map, &[func_va]));
    let callee_call_graph = session.call_graph_for(&budgets, &[func_va], &discovered);
    let mut callee_layout_cache = std::collections::HashMap::new();
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    let output = decompile_function(FunctionPipelineContext {
        image: &image,
        functions: &discovered,
        discovered: &func,
        budgets: &budgets,
        callee_budget: analysis_budget.callee,
        type_budget: analysis_budget.types,
        render_options: RenderOptions {
            types,
            style,
            shadow_v2: false,
            pdb_cache: pdb_cache.and_then(|path| path.to_str()).unwrap_or(""),
            analyst_names: None,
            analyst_locals: None,
            analyst_prototype: None,
        },
        debug_outputs: dwarf_outputs.as_ref(),
        debug_types: dwarf_types.as_deref().unwrap_or(&[]),
        debug_type_env: dwarf_type_env.as_ref(),
        debug_source: if pdb_contract_vas.contains(&func_va) {
            crate::program::environment::DeclarationSource::Pdb
        } else {
            crate::program::environment::DeclarationSource::Dwarf
        },
        exception_sites: &exception_sites,
        program_fact: program_environment
            .as_deref()
            .and_then(|environment| environment.prototype_for(func_va)),
        address_names: &mut addr_map,
        function_tables: &function_tables,
        got_targets: &got_targets,
        string_pool: &str_pool,
        readonly_data: &readonly_data,
        data_symbols: &data_symbols,
        field_map: field_map.as_ref(),
        call_graph: Some(callee_call_graph.as_ref()),
        callee_cache: &mut callee_layout_cache,
        calling_convention: cc,
        arm_vfp_args,
        prefer_debug_function_name: true,
        pdb_outer_name: None,
    })
    .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
    Ok(DecompileResult::from_rendered(
        output.rendered.text,
        &output.prepared.function,
        output.prepared.cfg_health,
        &func,
        output.rendered.provenance,
        pipeline_fingerprint,
    )
    .pseudocode)
}

/// Recover machine-code prototype facts, then apply a stronger declared output
/// contract when one exists. Stripped binaries pass `None` and retain the
/// existing Ghidra/Kuna-style only-use inference unchanged.
fn recover_decbench_prototype(
    lf_raw: &crate::ir::types::LlirFunction,
    ssa: &crate::ir::ssa::SsaInfo,
    cc: crate::ir::call_args::CallConv,
    param_slots: &std::collections::HashSet<usize>,
    arm_vfp_args: bool,
    declared: Option<&DwarfPrototypeContract>,
    type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
) -> crate::ir::types_recover::RecoveredPrototype {
    recover_decbench_prototype_with_inferred(
        lf_raw,
        ssa,
        cc,
        param_slots,
        arm_vfp_args,
        declared,
        type_env,
    )
    .0
}

/// Whether source DWARF and machine evidence prove a hidden result pointer from
/// a non-C language ABI.
///
/// The platform C classifier is deliberately not the oracle here: Rust's
/// internal ABI may return an aggregate indirectly even where C would use a
/// register pair. All independent facts must agree before the declared source
/// signature is translated into that machine boundary.
fn non_c_abi_hidden_result_evidence(
    cc: crate::ir::call_args::CallConv,
    inferred_output: crate::ir::types_recover::RecoveredOutputKind,
    inferred_parameter_count: usize,
    leading_parameter_is_pointer: bool,
    declared_parameter_count: usize,
    declared_result_is_non_scalar: bool,
) -> bool {
    crate::ir::abi::indirect_result_register(cc).is_none()
        && !crate::ir::abi::argument_slots(cc).is_empty()
        && inferred_output == crate::ir::types_recover::RecoveredOutputKind::Void
        && inferred_parameter_count == declared_parameter_count.saturating_add(1)
        && leading_parameter_is_pointer
        && declared_result_is_non_scalar
}

/// Return the selected prototype and the untouched machine-recovered candidate.
///
/// Keeping both from one recovery avoids paying for (and risking divergence
/// between) two whole type-recovery walks merely to report provenance.
fn recover_decbench_prototype_with_inferred(
    lf_raw: &crate::ir::types::LlirFunction,
    ssa: &crate::ir::ssa::SsaInfo,
    cc: crate::ir::call_args::CallConv,
    param_slots: &std::collections::HashSet<usize>,
    arm_vfp_args: bool,
    declared: Option<&DwarfPrototypeContract>,
    type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
) -> (
    crate::ir::types_recover::RecoveredPrototype,
    crate::ir::types_recover::RecoveredPrototype,
) {
    use crate::debug::dwarf::{DwarfParameterType, DwarfReturnType};
    use crate::ir::types_recover::RecoveredOutputKind;

    let inferred = crate::ir::types_recover::recover_prototype_with_arm_vfp_args(
        lf_raw,
        ssa,
        cc,
        param_slots,
        arm_vfp_args,
    );
    let mut prototype = inferred.clone();
    let mut non_c_hidden_result = false;
    if let Some(declared) = declared {
        // A MEMORY-class result is not in a register at all: the CALLER
        // allocates the object and passes its address in the first INTEGER
        // argument register, so every declared parameter arrives one register
        // further right than its source position says. Without the shift the
        // declaration's first formal is locked onto the hidden pointer's
        // register and the real first argument is left with no storage at all
        // — measured on 2026-08-18, `struct agr198_five agr198_make_five(int32_t
        // seed)` recovered as `f(int)` with `seed` reading an undefined value
        // and callers narrowing a 64-bit stack address through `(int)`.
        //
        // The pointer is spelled as a parameter rather than modelled as a
        // separate output because on System V it IS an ordinary argument slot.
        // AAPCS64's equivalent uses `x8`, which is not in the argument bank and
        // therefore cannot be reached this way; that convention has
        // `ReturnClass::IndirectBuffer` and `aapcs64_indirect_result` instead,
        // and `declared_return_class` never answers `Memory` for it.
        let hidden_return_pointer = matches!(
            &declared.return_type,
            DwarfReturnType::Type(c_type)
                if crate::ir::return_class::declared_return_class(c_type, cc, type_env)
                    == Some(crate::ir::abi::ReturnClass::Memory)
        );
        let declared_result_is_non_scalar = matches!(
            &declared.return_type,
            DwarfReturnType::Type(c_type)
                if dwarf_return_hint_with_env(c_type, cc, type_env).is_none()
        );
        let leading_parameter_is_pointer = inferred
            .parameters()
            .first()
            .and_then(|parameter| parameter.hint)
            .is_some_and(|hint| matches!(hint, crate::ir::types_recover::TypeHint::Pointer { .. }));
        non_c_hidden_result = non_c_abi_hidden_result_evidence(
            cc,
            inferred.output_kind(),
            inferred.parameters().len(),
            leading_parameter_is_pointer,
            declared.parameter_types.len(),
            declared_result_is_non_scalar,
        );
        let hidden_return_width = if hidden_return_pointer {
            match &declared.return_type {
                DwarfReturnType::Type(c_type) => type_env
                    .and_then(|env| env.aggregate_layout(c_type))
                    .and_then(|layout| u8::try_from(layout.byte_size).ok())
                    .filter(|width| *width != 0),
                _ => None,
            }
        } else {
            None
        };
        let hidden_return_hint = (hidden_return_pointer || non_c_hidden_result).then_some(Some(
            crate::ir::types_recover::TypeHint::Pointer {
                // One byte remains the conservative unknown-pointee spelling;
                // a declared aggregate carries its exact buffer extent through
                // the recovered prototype for call-site object promotion.
                pointee_width: hidden_return_width.unwrap_or(1),
            },
        ));
        let parameter_hints = hidden_return_hint
            .into_iter()
            .chain(declared.parameter_types.iter().flat_map(|parameter| {
                let DwarfParameterType::Type(c_type) = parameter else {
                    return vec![None];
                };
                // A by-value all-SSE aggregate is ONE source parameter in TWO
                // SSE argument registers, and the register contract of
                // `f(struct {double x; double y;})` is that of `f(double,
                // double)` exactly: each eightbyte takes the next register of
                // the SSE bank. Spelling it as its eightbytes is what the
                // return side could not do — a C function returns one value —
                // and it needs no synthesised tag at all. The second hint
                // carries the OCCUPANCY, so a twelve-byte `{float,float,float}`
                // declares its high eightbyte `float` and moves four bytes
                // rather than eight.
                if let Some(high_bytes) =
                    crate::ir::return_class::declared_sse_pair_parameter_high_bytes(
                        c_type, cc, type_env,
                    )
                {
                    return vec![
                        Some(crate::ir::types_recover::TypeHint::Float { width: 8 }),
                        Some(crate::ir::types_recover::TypeHint::Float { width: high_bytes }),
                    ];
                }
                // The same argument one bank over. A by-value aggregate of two
                // INTEGER eightbytes is ONE source parameter in TWO general
                // registers, and `f(struct {uint32_t q[4];})` has the register
                // contract of `f(unsigned long, unsigned long)` exactly. Unlike
                // the SSE case this one had no model at all: a sixteen-byte
                // aggregate has no scalar type hint, so the storage projection
                // declined and the declaration collapsed to a single `long`
                // parameter with the second eightbyte read from nothing. The
                // second hint carries the OCCUPANCY, so a twelve-byte
                // `{int32_t a,b,c;}` declares four bytes and not eight.
                if let Some(high_bytes) =
                    crate::ir::return_class::declared_integer_pair_parameter_high_bytes(
                        c_type, cc, type_env,
                    )
                {
                    return vec![
                        Some(crate::ir::types_recover::TypeHint::Int {
                            signed: false,
                            width: 8,
                        }),
                        Some(crate::ir::types_recover::TypeHint::Int {
                            signed: false,
                            width: high_bytes,
                        }),
                    ];
                }
                vec![dwarf_return_hint_with_env(c_type, cc, type_env)]
            }))
            .collect::<Vec<_>>();
        prototype.apply_locked_parameters(cc, &parameter_hints);
    }
    if non_c_hidden_result {
        // Render the boundary the machine actually implements. The source
        // aggregate remains available as metadata, but forcing its C ABI here
        // would make the generated caller and callee disagree about both arity
        // and result storage.
        prototype.apply_locked_output(RecoveredOutputKind::Void, None);
    } else {
        match declared.map(|contract| &contract.return_type) {
            Some(DwarfReturnType::Void) => {
                prototype.apply_locked_output(RecoveredOutputKind::Void, None);
            }
            Some(DwarfReturnType::Type(c_type)) => {
                // A declared BY-VALUE aggregate is not a scalar in the result
                // register, and locking it as one is how a 16-byte struct became
                // `extern long f(int)` with its `rdx` half read but never defined.
                // Take the ABI storage contract from the declared shape first; only
                // a `Single` class is a scalar direct output.
                let class = crate::ir::return_class::declared_return_class(c_type, cc, type_env);
                if let Some(class) = class {
                    prototype.apply_return_class(class);
                }
                let hint = dwarf_return_hint_with_env(c_type, cc, type_env);
                match class {
                    // The result exists, but it is the caller's buffer rather than a
                    // value in a register. This is the only construction site of
                    // `HiddenReturn`, which the type system has known about since it
                    // was declared and no code could produce.
                    Some(crate::ir::abi::ReturnClass::Memory) => {
                        prototype.apply_locked_output(RecoveredOutputKind::HiddenReturn, hint);
                    }
                    // Every other class — including an unclassifiable shape, which
                    // is every scalar — keeps the direct scalar output it has always
                    // had. Where the class is `IntegerPair`, the call-boundary
                    // spelling widens in `recovered_call_prototype`; nothing else
                    // about this function's own recovery changes.
                    _ => {
                        prototype.apply_locked_output(RecoveredOutputKind::Direct, hint);
                    }
                }
            }
            Some(DwarfReturnType::Unknown) | None => {}
        }
    }
    (prototype, inferred)
}

fn lock_parameter_slots_from_prototype(
    prototype: Option<&crate::ir::types_recover::RecoveredPrototype>,
    param_slots: &mut std::collections::HashSet<usize>,
) {
    let Some(prototype) = prototype.filter(|prototype| prototype.parameter_arity_is_locked())
    else {
        return;
    };
    param_slots.clear();
    param_slots.extend(
        prototype
            .parameters()
            .iter()
            .map(|parameter| parameter.slot),
    );
}

fn locked_parameter_count(
    prototype: Option<&crate::ir::types_recover::RecoveredPrototype>,
) -> Option<usize> {
    prototype
        .filter(|prototype| prototype.parameter_arity_is_locked())
        .map(|prototype| prototype.parameters().len())
}

fn record_recovered_prototype_conflict(
    function: &str,
    entry_va: u64,
    source: &str,
    declared: Option<&crate::ir::call_contracts::CallPrototype>,
    inferred: Option<&crate::ir::types_recover::RecoveredPrototype>,
    cc: crate::ir::call_args::CallConv,
) {
    let (Some(declared), Some(inferred)) = (declared, inferred) else {
        return;
    };
    let inferred = callee_contracts::recovered_call_prototype(inferred, cc);
    record_prototype_conflict_with_candidate(
        function,
        entry_va,
        source,
        Some(declared),
        crate::program::environment::DeclarationSource::Inferred.label(),
        Some(&inferred),
    );
}

fn record_prototype_conflict_with_candidate(
    function: &str,
    entry_va: u64,
    authoritative_source: &str,
    authoritative: Option<&crate::ir::call_contracts::CallPrototype>,
    candidate_source: &str,
    candidate: Option<&crate::ir::call_contracts::CallPrototype>,
) {
    let (Some(authoritative), Some(candidate)) = (authoritative, candidate) else {
        return;
    };
    crate::ir::health::record_prototype_conflict(
        function,
        entry_va,
        authoritative_source,
        authoritative,
        candidate_source,
        candidate,
    );
}

/// Decompile the first `limit` discovered functions. Returns a list of
/// `(func_name, entry_va, pseudocode)` triples.
///
/// `limit` bounds returned artifacts independently from `max_functions`, which
/// bounds program discovery. Their defaults match so `--all` emits every
/// discovered function unless the caller requests a smaller output window.
#[pyfunction]
#[pyo3(name = "decompile_all")]
#[pyo3(signature = (path, limit=30_000usize, max_blocks=4096usize, max_instructions=200_000usize, timeout_ms=10_000u64, pdb_cache="", style="", analyst_names=None, max_functions=30_000usize))]
fn decompile_all_py(
    py: Python<'_>,
    path: String,
    limit: usize,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    pdb_cache: &str,
    style: &str,
    analyst_names: Option<std::collections::HashMap<u64, String>>,
    max_functions: usize,
) -> PyResult<PyObject> {
    let _run_profile = crate::decompile::profile::RunProfiler::from_env("decompile_all");

    let analysis_budget = AnalysisBudget {
        discovery: pipeline::DiscoveryBudget {
            max_functions: max_functions.max(1),
            total_timeout_ms: 0,
        },
        cfg: pipeline::CfgBudget {
            max_blocks,
            max_instructions,
            timeout_ms,
        },
        callee: pipeline::CalleeBudget::default(),
        types: pipeline::TypeBudget::default(),
        size: pipeline::SizeBudget::from_instruction_and_output_limits(max_instructions, limit),
    };
    let render_options = RenderOptions {
        types: style == "decbench",
        style,
        shadow_v2: false,
        pdb_cache,
        analyst_names: analyst_names.as_ref(),
        analyst_locals: None,
        analyst_prototype: None,
    };

    let image = load_program_image(&path)?;
    let session = crate::program::session::ProgramSession::from_image(image);
    let image = session.image().clone();
    let exception_sites = image.exception_call_sites();
    let ProgramDebugContext {
        output_contracts: dwarf_outputs,
        pdb_contract_vas,
        types: dwarf_types,
    } = prepare_program_debug_context(&session, &image, &path, pdb_cache, style == "decbench");
    let dwarf_type_env = dwarf_types
        .as_deref()
        .map(crate::ir::dwarf_type_env::DwarfTypeEnv::new);
    let ProgramDiscovery {
        budgets,
        functions: funcs,
    } = discover_program(py, &session, analysis_budget, &[]);
    let cc = target_calling_convention(&image)?;
    let arm_vfp_args = image.arm_hard_float();
    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    let ProgramNameContext {
        address_names: mut addr_map,
        data_symbols,
    } = prepare_program_name_context(&image, &path, pdb_cache, &funcs);
    // The analyst overlay is DELIBERATELY not applied here. Everything between
    // this point and `recover_direct_callee_layouts` resolves callees BY NAME
    // against what the binary calls them -- `session.environment`,
    // `annotate_calls_in`, and the callee layout recovery itself. Renaming
    // `validate` to `parse_packet_hdr` before those run means they look up a
    // name no symbol source knows, find nothing, and downgrade a recovered
    // `int validate(char *, int)` to `long f(void)` at every call site. The
    // rename is a presentation decision, so it is applied after the analysis
    // that depends on binary truth -- see below.
    let ProgramRenderContext {
        data_symbols,
        string_pool: str_pool,
        readonly_data,
        function_tables,
        got_targets,
    } = prepare_program_render_context(&session, &image, data_symbols);
    let environment_targets = funcs
        .iter()
        .take(analysis_budget.size.max_output_functions)
        .map(|function| function.entry_point.value)
        .collect::<Vec<_>>();
    let program_environment = (style == "decbench")
        .then(|| session.environment(&budgets, cc, &addr_map, &environment_targets));
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    // Identity-keyed call structure for this exact discovery. `call_graph_for`
    // builds from `funcs` (already fetched above) instead of re-querying
    // `discover_functions`, so this one logical query registers exactly one
    // discovery-cache hit-or-miss rather than two. The SCC condensation lets
    // nested callee analysis decline to spend a layer inside a call cycle.
    let callee_call_graph = py.detach(|| session.call_graph_for(&budgets, &[], &funcs));
    let mut callee_layout_cache = std::collections::HashMap::new();
    let list = PyList::empty(py);
    for func in funcs.iter().take(analysis_budget.size.max_output_functions) {
        // The GIL is held across the per-function lifting work (the loop builds
        // a `PyList` as it goes), so CPython never re-enters its eval loop and
        // never notices a signal. This is the supported way to stay
        // interruptible without releasing: it raises `KeyboardInterrupt` here.
        py.check_signals()?;
        let request = DecompileRequest {
            va: func.entry_point.value,
            analysis_budget,
            render_options,
        };
        let pipeline_fingerprint = request.fingerprint();
        let Ok(output) = decompile_function(FunctionPipelineContext {
            image: &image,
            functions: &funcs,
            discovered: func,
            budgets: &budgets,
            callee_budget: analysis_budget.callee,
            type_budget: analysis_budget.types,
            render_options,
            debug_outputs: dwarf_outputs.as_ref(),
            debug_types: dwarf_types.as_deref().unwrap_or(&[]),
            debug_type_env: dwarf_type_env.as_ref(),
            debug_source: if pdb_contract_vas.contains(&func.entry_point.value) {
                crate::program::environment::DeclarationSource::Pdb
            } else {
                crate::program::environment::DeclarationSource::Dwarf
            },
            exception_sites: &exception_sites,
            program_fact: program_environment
                .as_deref()
                .and_then(|environment| environment.prototype_for(func.entry_point.value)),
            address_names: &mut addr_map,
            function_tables: &function_tables,
            got_targets: &got_targets,
            string_pool: &str_pool,
            readonly_data: &readonly_data,
            data_symbols: &data_symbols,
            field_map: field_map.as_ref(),
            call_graph: Some(callee_call_graph.as_ref()),
            callee_cache: &mut callee_layout_cache,
            calling_convention: cc,
            arm_vfp_args,
            prefer_debug_function_name: false,
            pdb_outer_name: None,
        }) else {
            continue;
        };
        let outer_name = output.prepared.function.name.clone();
        let result = DecompileResult::from_rendered(
            output.rendered.text,
            &output.prepared.function,
            output.prepared.cfg_health,
            func,
            output.rendered.provenance,
            pipeline_fingerprint,
        );
        let variables = crate::ir::recovered_variables::recovered_variables_from_llir(
            &result.pseudocode,
            output.prepared.prototype.as_ref(),
            &output.prepared.stack_facts,
            calling_convention_pointer_width(cc),
            &output.raw,
        );
        list.append((
            outer_name,
            func.entry_point.value,
            result.pseudocode,
            func.size,
            variables_to_py(py, &variables)?,
        ))?;
    }
    Ok(list.into())
}

#[pyfunction]
#[pyo3(name = "decompile_many")]
#[pyo3(signature = (path, func_vas, max_blocks=4096usize, max_instructions=200_000usize, timeout_ms=5000u64, types=true, style="", shadow_v2=false, pdb_cache="", max_functions=0usize, analyst_names=None))]
#[allow(clippy::too_many_arguments)]
fn decompile_many_py(
    py: Python<'_>,
    path: String,
    func_vas: Vec<u64>,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    types: bool,
    style: &str,
    shadow_v2: bool,
    pdb_cache: &str,
    max_functions: usize,
    analyst_names: Option<std::collections::HashMap<u64, String>>,
) -> PyResult<PyObject> {
    let _run_profile = crate::decompile::profile::RunProfiler::from_env("decompile_many");
    if shadow_v2 && style != "decbench" {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "shadow_v2 requires style='decbench'",
        ));
    }
    // Decompile an arbitrary SUBSET of functions in a SINGLE analysis pass.
    //
    // `decompile_at` re-runs `analyze_functions_bytes` (and the PDB/addr-map
    // build) on every call, so decompiling N scattered functions in a large
    // binary (e.g. the 18 MB mpengine.dll, ~30k functions) costs N full
    // analyses. This amortises that fixed cost across the whole requested set:
    // analyse once, then run the same per-function pipeline as `decompile_at`
    // for each requested VA. Returns a list of (name, va, c_or_ir_text) for
    // every requested VA that resolves to a known function.
    use std::collections::HashSet;

    let image = load_program_image(&path)?;
    let session = crate::program::session::ProgramSession::from_image(image);
    let image = session.image().clone();
    // See `decompile_at`: an ARM32 Thumb `.symtab` value carries the Thumb bit.
    let func_vas: Vec<u64> = func_vas
        .into_iter()
        .map(|va| image.normalize_function_entry(va))
        .collect();
    let exception_sites = image.exception_call_sites();
    let ProgramDebugContext {
        output_contracts: dwarf_outputs,
        pdb_contract_vas,
        types: dwarf_types,
    } = prepare_program_debug_context(&session, &image, &path, pdb_cache, style == "decbench");
    let dwarf_type_env = dwarf_types
        .as_deref()
        .map(crate::ir::dwarf_type_env::DwarfTypeEnv::new);
    // Zero is the public address-scoped default: process exactly the unique
    // requested entries. Direct-callee prototype evidence is recovered lazily
    // by `recover_direct_callee_layouts`, so unrelated automatic seeds never
    // need to consume this worklist merely to render one call accurately.
    let requested_function_limit = pipeline::requested_function_limit(&func_vas, max_functions);
    let analysis_budget = AnalysisBudget {
        discovery: pipeline::DiscoveryBudget {
            max_functions: requested_function_limit,
            total_timeout_ms: 0,
        },
        cfg: pipeline::CfgBudget {
            max_blocks,
            max_instructions,
            timeout_ms,
        },
        callee: pipeline::CalleeBudget::default(),
        types: pipeline::TypeBudget::default(),
        size: pipeline::SizeBudget::from_instruction_and_output_limits(
            max_instructions,
            requested_function_limit,
        ),
    };
    let render_options = RenderOptions {
        types,
        style,
        shadow_v2,
        pdb_cache,
        analyst_names: analyst_names.as_ref(),
        analyst_locals: None,
        analyst_prototype: None,
    };
    // --- one-time analysis + name/field/string maps -----------------------
    let ProgramDiscovery {
        budgets,
        functions: funcs,
    } = discover_program(py, &session, analysis_budget, &func_vas);
    let cc = target_calling_convention(&image)?;
    let arm_vfp_args = image.arm_hard_float();
    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    let ProgramNameContext {
        address_names: mut addr_map,
        data_symbols,
    } = prepare_program_name_context(&image, &path, pdb_cache, &funcs);
    // The analyst overlay is DELIBERATELY not applied here. Everything between
    // this point and `recover_direct_callee_layouts` resolves callees BY NAME
    // against what the binary calls them -- `session.environment`,
    // `annotate_calls_in`, and the callee layout recovery itself. Renaming
    // `validate` to `parse_packet_hdr` before those run means they look up a
    // name no symbol source knows, find nothing, and downgrade a recovered
    // `int validate(char *, int)` to `long f(void)` at every call site. The
    // rename is a presentation decision, so it is applied after the analysis
    // that depends on binary truth -- see below.
    let ProgramRenderContext {
        data_symbols,
        string_pool: str_pool,
        readonly_data,
        function_tables,
        got_targets,
    } = prepare_program_render_context(&session, &image, data_symbols);
    let program_environment = (style == "decbench" && types)
        .then(|| session.environment(&budgets, cc, &addr_map, &func_vas));
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    // Identity-keyed call structure for this exact discovery. `call_graph_for`
    // builds from `funcs` (already fetched above) instead of re-querying
    // `discover_functions`, so this one logical query registers exactly one
    // discovery-cache hit-or-miss rather than two. The SCC condensation lets
    // nested callee analysis decline to spend a layer inside a call cycle.
    let callee_call_graph = py.detach(|| session.call_graph_for(&budgets, &func_vas, &funcs));
    let mut callee_layout_cache = std::collections::HashMap::new();
    // PDB-only public-symbol map for the `// PDB:` provenance comment; built
    // once, empty for non-PE inputs (so it never fires on ELF/Mach-O).
    let pdb_public_map = pdb_cache
        .map(|cache_dir| crate::ir::name_resolve::collect_pdb_public_symbol_map(&path, cache_dir))
        .unwrap_or_default();

    let wanted: HashSet<u64> = func_vas.iter().copied().collect();
    let list = PyList::empty(py);

    // The rendering loop deliberately has NO wall clock, and `timeout_ms`
    // stays what `Budgets` documents: the per-function CFG-walk budget.
    //
    // A clock here was tried and measured. `tools/diff_decompile.decompiled_many_c`
    // calls this with no `timeout_ms`, so it takes the 5 s default; under CPU
    // load the budget expired mid-set and the unrendered functions came back as
    // an explanatory stub. That stub is a correct report and a wrong ANSWER:
    // the harness compiled it, found no definition, and reported
    // `151_wide_branch_ladder:clang:O0:big151_flat_cascade` as
    // `undefined symbol: big151_flat_cascade` — a semantic failure verdict
    // manufactured by how busy the machine was. Same build, same seed: passes
    // idle, fails under sixteen spinners.
    //
    // Exceeding a wall clock is not evidence that a decompilation is wrong, and
    // a pass that fails to terminate is a correctness bug to fix in that pass,
    // not something a clock between passes could have caught anyway — the spin
    // that motivated this was inside `refine_float_copy_types`, where no
    // between-pass check could reach it. See its fixed-point proof.
    let mut output_count = 0usize;
    for func in funcs.iter() {
        // See `decompile_all_py`: keeps a long multi-function decompile
        // interruptible while the GIL is held for the `PyList` it is building.
        py.check_signals()?;
        let func_va = func.entry_point.value;
        if !wanted.contains(&func_va) {
            continue;
        }
        if output_count >= analysis_budget.size.max_output_functions {
            break;
        }
        let request = DecompileRequest {
            va: func_va,
            analysis_budget,
            render_options,
        };
        let pipeline_fingerprint = request.fingerprint();
        let pdb_outer_name = pdb_public_map
            .get(&func_va)
            .filter(|name| !name.is_empty() && !name.starts_with("sub_"))
            .cloned();
        let Ok(output) = decompile_function(FunctionPipelineContext {
            image: &image,
            functions: &funcs,
            discovered: func,
            budgets: &budgets,
            callee_budget: analysis_budget.callee,
            type_budget: analysis_budget.types,
            render_options: RenderOptions {
                types,
                style,
                shadow_v2,
                pdb_cache: pdb_cache.and_then(|path| path.to_str()).unwrap_or(""),
                analyst_names: analyst_names.as_ref(),
                analyst_locals: None,
                analyst_prototype: None,
            },
            debug_outputs: dwarf_outputs.as_ref(),
            debug_types: dwarf_types.as_deref().unwrap_or(&[]),
            debug_type_env: dwarf_type_env.as_ref(),
            debug_source: if pdb_contract_vas.contains(&func_va) {
                crate::program::environment::DeclarationSource::Pdb
            } else {
                crate::program::environment::DeclarationSource::Dwarf
            },
            exception_sites: &exception_sites,
            program_fact: program_environment
                .as_deref()
                .and_then(|environment| environment.prototype_for(func_va)),
            address_names: &mut addr_map,
            function_tables: &function_tables,
            got_targets: &got_targets,
            string_pool: &str_pool,
            readonly_data: &readonly_data,
            data_symbols: &data_symbols,
            field_map: field_map.as_ref(),
            call_graph: Some(callee_call_graph.as_ref()),
            callee_cache: &mut callee_layout_cache,
            calling_convention: cc,
            arm_vfp_args,
            prefer_debug_function_name: false,
            pdb_outer_name: pdb_outer_name.as_deref(),
        }) else {
            continue;
        };
        let name = output.prepared.function.name.clone();
        // The structured inventory a consumer needs to match our locals without
        // re-parsing the C. Computed from the prototype and the stack-promotion
        // facts already in scope, and filtered to names the render actually
        // emitted -- see `ir::recovered_variables`.
        let result = DecompileResult::from_rendered(
            output.rendered.text,
            &output.prepared.function,
            output.prepared.cfg_health,
            func,
            output.rendered.provenance,
            pipeline_fingerprint,
        );
        let variables = crate::ir::recovered_variables::recovered_variables_from_llir(
            &result.pseudocode,
            output.prepared.prototype.as_ref(),
            &output.prepared.stack_facts,
            calling_convention_pointer_width(cc),
            &output.raw,
        );
        list.append((
            name,
            func_va,
            result.pseudocode,
            func.size,
            variables_to_py(py, &variables)?,
        ))?;
        output_count += 1;
    }
    Ok(list.into())
}

/// One `RecoveredVariable` per dict, in the shape a consumer reads.
///
/// `arg_index` and `stack_offset` are `None` rather than absent when they do not
/// apply, so a reader never has to distinguish "this key is missing" from "this
/// variable has no offset" -- the second is a real, load-bearing answer (see the
/// withheld-coordinate rule in `ir::recovered_variables`).
fn variables_to_py(
    py: Python<'_>,
    variables: &[crate::ir::recovered_variables::RecoveredVariable],
) -> PyResult<PyObject> {
    use pyo3::types::{PyDict, PyList};
    let list = PyList::empty(py);
    for variable in variables {
        let item = PyDict::new(py);
        item.set_item("name", &variable.name)?;
        item.set_item("type", &variable.ctype)?;
        item.set_item("kind", variable.kind)?;
        item.set_item("arg_index", variable.arg_index)?;
        item.set_item("stack_offset", variable.stack_offset)?;
        item.set_item("size", variable.size)?;
        // Always present, empty when unclaimed. A consumer that filters on
        // truthiness gets the right answer; one that checks for the key does
        // not have to special-case a producer that never emits it.
        item.set_item("addresses", variable.addresses.clone())?;
        list.append(item)?;
    }
    Ok(list.into())
}

/// Drain and return the definition-before-use verdicts recorded since the last call.
///
/// The dictionary carries `verified_functions`, `unverified_functions`,
/// `undefined_uses`, `dropped_verdicts`, and `unverified` — a list of
/// `{"function", "entry_va", "undefined_uses", "violations": [{"name", "kind"}]}`
/// ordered by entry address.
///
/// A non-empty `unverified` list means the recovered C for those functions reads a
/// value the machine never produced. Draining rather than peeking is deliberate:
/// the caller that asks is the caller that reports, and the next question should
/// be about the next run.
#[pyfunction]
#[pyo3(name = "take_render_verification")]
fn take_render_verification_py(py: Python<'_>) -> PyResult<Py<pyo3::PyAny>> {
    use pyo3::types::{PyDict, PyList};

    let report = crate::ir::health::take_render_verification();
    let out = PyDict::new(py);
    out.set_item("verified_functions", report.verified_functions)?;
    out.set_item("unverified_functions", report.unverified_functions)?;
    out.set_item("undefined_uses", report.undefined_uses)?;
    out.set_item("dropped_verdicts", report.dropped_verdicts)?;
    out.set_item("prototype_conflict_count", report.prototype_conflict_count)?;
    let unverified = PyList::empty(py);
    for verdict in &report.unverified {
        let entry = PyDict::new(py);
        entry.set_item("function", &verdict.function)?;
        entry.set_item("entry_va", &verdict.entry_va)?;
        entry.set_item("undefined_uses", verdict.undefined_uses)?;
        let violations = PyList::empty(py);
        for violation in &verdict.violations {
            let item = PyDict::new(py);
            item.set_item("name", &violation.name)?;
            item.set_item("kind", violation.kind)?;
            violations.append(item)?;
        }
        entry.set_item("violations", violations)?;
        unverified.append(entry)?;
    }
    out.set_item("unverified", unverified)?;
    let conflicts = PyList::empty(py);
    for conflict in &report.prototype_conflicts {
        let entry = PyDict::new(py);
        entry.set_item("function", &conflict.function)?;
        entry.set_item("entry_va", &conflict.entry_va)?;
        entry.set_item("authoritative_source", &conflict.authoritative_source)?;
        entry.set_item("candidate_source", &conflict.candidate_source)?;
        let prototype_dict = |prototype: &crate::ir::health::PrototypeShape| -> PyResult<_> {
            let item = PyDict::new(py);
            item.set_item("return_type", &prototype.return_type)?;
            item.set_item("parameter_types", &prototype.parameter_types)?;
            item.set_item("variadic", prototype.variadic)?;
            Ok(item)
        };
        entry.set_item("authoritative", prototype_dict(&conflict.authoritative)?)?;
        entry.set_item("candidate", prototype_dict(&conflict.candidate)?)?;
        entry.set_item("disagreements", &conflict.disagreements)?;
        conflicts.append(entry)?;
    }
    out.set_item("prototype_conflicts", conflicts)?;
    Ok(out.into())
}

/// Register LLIR-related Python bindings under the `ir` submodule.
pub fn register_ir_bindings(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let ir_mod = pyo3::types::PyModule::new(py, "ir")?;
    ir_mod.add_class::<session::PyDecompilerSession>()?;
    ir_mod.add_function(wrap_pyfunction!(lift_bytes_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(lift_window_at_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(decompile_at_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(decompile_range_at_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(decompile_all_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(decompile_many_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(take_render_verification_py, &ir_mod)?)?;
    m.add_submodule(&ir_mod)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    /// Verified typed MIR must be built for every decompilation, not only when
    /// `GLAURUNG_DUMP_PASSES` happens to be set.
    ///
    /// It was previously computed inside the debug-dump block, printed, and
    /// dropped. That left the roadmap's "migrate a production consumer to
    /// verified MIR evidence" with nothing to migrate onto, and made the
    /// artifact's health visible only to a human reading stderr. It also broke
    /// the rule that correctness must not depend on an environment variable —
    /// the analysis a consumer would trust existed only in debug runs.
    ///
    /// The env var is explicitly cleared here so the test cannot pass by
    /// inheriting a debug-enabled environment.
    #[test]
    fn verified_mir_is_prepared_without_the_debug_environment_variable() {
        let directory = tempfile::tempdir().expect("temporary fixture directory");
        let source = directory.path().join("mir_available.c");
        let executable = directory.path().join("mir_available");
        std::fs::write(
            &source,
            "__attribute__((noinline)) int mir_target(int *values, int count) {\n\
                 int total = 0;\n\
                 for (int index = 0; index < count; ++index) {\n\
                     total += values[index];\n\
                 }\n\
                 return total;\n\
             }\n\
             int main(void) { int v[4] = {1,2,3,4}; return mir_target(v, 4); }\n",
        )
        .expect("write real fixture");
        let built = std::process::Command::new("cc")
            .args(["-g", "-O0", "-o"])
            .arg(&executable)
            .arg(&source)
            .output()
            .expect("host C compiler is available");
        assert!(
            built.status.success(),
            "compile fixture: {}",
            String::from_utf8_lossy(&built.stderr)
        );

        let session = crate::program::session::ProgramSession::from_path(&executable)
            .expect("fixture is a real object");
        let image = session.image();
        let entry = image
            .defined_text_symbol_address("mir_target")
            .expect("fixture target symbol");

        // SAFETY: single-threaded test; the variable is only read by the dump
        // block this test exists to prove is not required.
        unsafe { std::env::remove_var("GLAURUNG_DUMP_PASSES") };

        let discovered = session.discover_functions(
            &crate::analysis::cfg::Budgets {
                max_functions: 1,
                max_blocks: 256,
                max_instructions: 16_384,
                timeout_ms: 10_000,
                total_timeout_ms: 0,
            },
            &[entry],
        );
        let target = discovered
            .iter()
            .find(|candidate| candidate.entry_point.value == entry)
            .expect("the fixture function is discovered");
        let mut function = crate::ir::lift_function::lift_function_from_image(image, target)
            .expect("the fixture function lifts");
        let prepared = super::pipeline::prepare_llir_for_lowering_with_shadow(
            &mut function,
            image,
            &[],
            CallConv::SysVAmd64,
            true,
            false,
            None,
            None,
            None,
            false,
        );

        let mir = prepared
            .mir(image)
            .expect("verified MIR must be available without GLAURUNG_DUMP_PASSES");
        assert!(
            !mir.values().is_empty(),
            "a real counted loop must produce MIR values"
        );
    }

    #[test]
    fn production_preparation_exposes_the_verified_clang_wide_switch_region() {
        let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/decompiler_fixtures/build/154_wide_switch-clang-O2.so");
        if !binary.is_file() {
            crate::testing::missing_fixture("154_wide_switch-clang-O2.so");
            return;
        }
        let session = crate::program::session::ProgramSession::from_path(&binary)
            .expect("checked-in wide-switch fixture parses");
        let image = session.image();
        let entry = image
            .defined_text_symbol_address("wide154_dense_effects")
            .expect("fixture exports wide154_dense_effects");
        let discovered = session.discover_functions(
            &crate::analysis::cfg::Budgets {
                max_functions: 1,
                max_blocks: 1024,
                max_instructions: 4096,
                timeout_ms: 5000,
                total_timeout_ms: 0,
            },
            &[entry],
        );
        let target = discovered
            .iter()
            .find(|candidate| candidate.entry_point.value == entry)
            .expect("wide effect switch is discovered");
        let mut function = crate::ir::lift_function::lift_function_from_image(image, target)
            .expect("wide effect switch lifts");
        let prepared = super::pipeline::prepare_llir_for_lowering_with_shadow(
            &mut function,
            image,
            &[],
            CallConv::SysVAmd64,
            true,
            false,
            None,
            None,
            None,
            true,
        );

        let region = prepared
            .shadow_v2_region
            .as_ref()
            .expect("production-prepared LLIR must retain a verified v2 region");
        let ast = crate::ir::ast::lower(
            &prepared.numbered,
            region,
            "wide154_dense_effects".to_string(),
        );
        let text = crate::ir::ast::render_c(&ast);
        assert!(text.contains("switch ("), "{text}");
        assert!(text.contains("case 0:"), "{text}");
        assert!(text.contains("case 255:"), "{text}");
        assert!(!text.contains("unrecovered indirect jump"), "{text}");
    }

    use super::dwarf_contracts::{dwarf_stack_object_hints, merge_dwarf_register_local_facts};
    use super::{
        dwarf_return_hint, dwarf_return_hint_with_env, select_renderable_dwarf_local_facts,
        DwarfPrototypeContract,
    };
    use crate::debug::dwarf::{DwarfReturnType, DwarfStackBase, DwarfStackObject};
    use crate::ir::call_args::CallConv;
    use crate::ir::types::VReg;
    use crate::ir::types_recover::{TypeHint, TypeMap};
    use std::collections::HashMap;

    #[test]
    fn rust_style_hidden_result_requires_the_full_machine_contradiction() {
        use crate::ir::types_recover::RecoveredOutputKind;

        let classify = |cc, output, inferred, pointer, declared, aggregate| {
            super::non_c_abi_hidden_result_evidence(
                cc, output, inferred, pointer, declared, aggregate,
            )
        };
        assert!(classify(
            CallConv::SysVAmd64,
            RecoveredOutputKind::Void,
            4,
            true,
            3,
            true,
        ));
        assert!(!classify(
            CallConv::SysVAmd64,
            RecoveredOutputKind::Direct,
            4,
            true,
            3,
            true,
        ));
        assert!(!classify(
            CallConv::SysVAmd64,
            RecoveredOutputKind::Void,
            3,
            true,
            3,
            true,
        ));
        assert!(!classify(
            CallConv::SysVAmd64,
            RecoveredOutputKind::Void,
            4,
            false,
            3,
            true,
        ));
        assert!(!classify(
            CallConv::Aarch64,
            RecoveredOutputKind::Void,
            4,
            true,
            3,
            true,
        ));
    }

    #[test]
    fn source_local_rename_requires_a_renderable_authoritative_type() {
        use crate::debug::dwarf::{DwarfType, DwarfTypeKind};

        let dwarf_types = [DwarfType {
            kind: DwarfTypeKind::Typedef,
            name: "COLUMN".to_string(),
            byte_size: 0,
            fields: Vec::new(),
            variants: Vec::new(),
            typedef_target: Some("struct column".to_string()),
            source_file: Some("locals.c".to_string()),
        }];
        let local_types = HashMap::from([
            ("local_4".to_string(), "uch".to_string()),
            ("local_8".to_string(), "unsigned int".to_string()),
            ("local_10".to_string(), "COLUMN *".to_string()),
        ]);
        let local_names = HashMap::from([
            ("local_4".to_string(), "byte".to_string()),
            ("local_8".to_string(), "count".to_string()),
            ("local_10".to_string(), "column".to_string()),
        ]);

        let (selected_types, selected_names) =
            select_renderable_dwarf_local_facts(&local_types, &local_names, &dwarf_types);

        assert!(!selected_types.contains_key("local_4"));
        assert!(!selected_names.contains_key("local_4"));
        assert_eq!(
            selected_names.get("local_8").map(String::as_str),
            Some("count")
        );
        assert_eq!(
            selected_names.get("local_10").map(String::as_str),
            Some("column")
        );
    }

    #[test]
    fn dwarf_long_return_width_follows_the_platform_data_model() {
        assert_eq!(
            dwarf_return_hint("long", CallConv::SysVAmd64),
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            })
        );
        assert_eq!(
            dwarf_return_hint("long", CallConv::Win64),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            })
        );
        assert_eq!(
            dwarf_return_hint("unsigned long long", CallConv::Win64),
            Some(TypeHint::Int {
                signed: false,
                width: 8,
            })
        );
    }

    #[test]
    fn dwarf_named_pointer_return_is_locked_as_a_pointer() {
        assert_eq!(
            dwarf_return_hint("struct node *", CallConv::SysVAmd64),
            Some(TypeHint::Pointer { pointee_width: 1 })
        );
        assert_eq!(
            dwarf_return_hint("const unsigned int *", CallConv::SysVAmd64),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
    }

    #[test]
    fn dwarf_fixed_width_integer_aliases_keep_their_exact_widths() {
        assert_eq!(
            dwarf_return_hint("uint32_t", CallConv::SysVAmd64),
            Some(TypeHint::Int {
                signed: false,
                width: 4,
            })
        );
        assert_eq!(
            dwarf_return_hint("const int32_t *", CallConv::SysVAmd64),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
        assert_eq!(
            dwarf_return_hint("int64_t", CallConv::Win64),
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            })
        );
    }

    #[test]
    fn dwarf_enum_typedef_keeps_its_measured_scalar_abi() {
        use crate::debug::dwarf::{DwarfEnumVariant, DwarfType, DwarfTypeKind};
        use crate::ir::dwarf_type_env::DwarfTypeEnv;

        let types = vec![
            DwarfType {
                kind: DwarfTypeKind::Typedef,
                name: "Status".to_string(),
                byte_size: 0,
                fields: Vec::new(),
                variants: Vec::new(),
                typedef_target: Some("enum Status_".to_string()),
                source_file: None,
            },
            DwarfType {
                kind: DwarfTypeKind::Enum,
                name: "Status_".to_string(),
                byte_size: 4,
                fields: Vec::new(),
                variants: vec![DwarfEnumVariant {
                    name: "ERROR".to_string(),
                    value: -1,
                }],
                typedef_target: None,
                source_file: None,
            },
        ];
        let env = DwarfTypeEnv::new(&types);

        assert_eq!(
            dwarf_return_hint_with_env("Status", CallConv::SysVAmd64, Some(&env)),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            })
        );
    }

    #[test]
    fn dwarf_arm_frame_registers_map_to_stack_object_hints() {
        let contract = DwarfPrototypeContract {
            function_name: None,
            prototyped: true,
            variadic: false,
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
            static_locals: Vec::new(),
            register_locals: Vec::new(),
            stack_objects: vec![
                DwarfStackObject {
                    base: DwarfStackBase::Register(11),
                    offset: -24,
                    byte_size: 16,
                    aggregate: true,
                    source_name: None,
                    c_type: None,
                },
                DwarfStackObject {
                    base: DwarfStackBase::Register(7),
                    offset: -8,
                    byte_size: 8,
                    aggregate: true,
                    source_name: None,
                    c_type: None,
                },
            ],
        };

        let hints = dwarf_stack_object_hints(Some(&contract), CallConv::Arm);

        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].base, "fp");
        assert_eq!(hints[0].disp, -24);
        assert_eq!(hints[0].size, 16);
        assert_eq!(hints[1].base, "fp");
        assert_eq!(hints[1].disp, -8);
        assert_eq!(hints[1].size, 8);
    }

    #[test]
    fn dwarf_aarch64_cfa_maps_to_the_entry_stack_coordinate() {
        let contract = DwarfPrototypeContract {
            function_name: None,
            prototyped: true,
            variadic: false,
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
            static_locals: Vec::new(),
            register_locals: Vec::new(),
            stack_objects: vec![DwarfStackObject {
                base: DwarfStackBase::CallFrameCfa,
                offset: -40,
                byte_size: 16,
                aggregate: true,
                source_name: None,
                c_type: None,
            }],
        };

        let hints = dwarf_stack_object_hints(Some(&contract), CallConv::Aarch64);

        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].base, "entry_sp");
        assert_eq!(hints[0].disp, -40);
        assert_eq!(hints[0].size, 16);
    }

    #[test]
    fn dwarf_arm_cfa_maps_to_the_entry_stack_coordinate() {
        let contract = DwarfPrototypeContract {
            function_name: None,
            prototyped: true,
            variadic: false,
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
            static_locals: Vec::new(),
            register_locals: Vec::new(),
            stack_objects: vec![DwarfStackObject {
                base: DwarfStackBase::CallFrameCfa,
                offset: -24,
                byte_size: 8,
                aggregate: true,
                source_name: None,
                c_type: None,
            }],
        };

        for cc in [CallConv::Arm, CallConv::ArmHardFloat] {
            let hints = dwarf_stack_object_hints(Some(&contract), cc);

            assert_eq!(hints.len(), 1);
            assert_eq!(hints[0].base, "entry_sp");
            assert_eq!(hints[0].disp, -24);
            assert_eq!(hints[0].size, 8);
        }
    }

    #[test]
    fn dwarf_scalar_stack_objects_retain_their_authoritative_coordinate() {
        let contract = DwarfPrototypeContract {
            function_name: None,
            prototyped: true,
            variadic: false,
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
            static_locals: Vec::new(),
            register_locals: Vec::new(),
            stack_objects: vec![DwarfStackObject {
                base: DwarfStackBase::CallFrameCfa,
                offset: -12,
                byte_size: 4,
                aggregate: false,
                source_name: Some("reg32".to_string()),
                c_type: Some("int".to_string()),
            }],
        };

        let hints = dwarf_stack_object_hints(Some(&contract), CallConv::Arm);

        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].base, "entry_sp");
        assert_eq!(hints[0].disp, -12);
        assert_eq!(hints[0].size, 4);
        assert!(!hints[0].aggregate);
        assert_eq!(hints[0].source_name.as_deref(), Some("reg32"));
        assert_eq!(hints[0].c_type.as_deref(), Some("int"));
    }

    #[test]
    fn cdecl32_dwarf_frame_register_joins_the_canonical_x86_identity() {
        let contract = DwarfPrototypeContract {
            function_name: None,
            prototyped: true,
            variadic: false,
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
            static_locals: Vec::new(),
            register_locals: Vec::new(),
            stack_objects: vec![DwarfStackObject {
                base: DwarfStackBase::Register(5),
                offset: -32,
                byte_size: 4,
                aggregate: false,
                source_name: Some("sum".to_string()),
                c_type: Some("int".to_string()),
            }],
        };

        let hints = dwarf_stack_object_hints(Some(&contract), CallConv::Cdecl32);

        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].base, "rbp");
        assert_eq!(hints[0].disp, -32);
        assert_eq!(hints[0].source_name.as_deref(), Some("sum"));
    }

    #[test]
    fn dwarf_register_range_selects_the_numbered_value_role() {
        use crate::core::binary::Arch;
        use crate::debug::dwarf::{DwarfRegisterLocal, DwarfRegisterLocation};
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

        let contract = DwarfPrototypeContract {
            function_name: None,
            prototyped: true,
            variadic: false,
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
            static_locals: Vec::new(),
            stack_objects: Vec::new(),
            register_locals: vec![DwarfRegisterLocal {
                source_name: "i".to_string(),
                c_type: "unsigned int".to_string(),
                locations: vec![DwarfRegisterLocation {
                    start: 0x105,
                    end: 0x110,
                    register: 4,
                }],
            }],
        };
        let numbered = LlirFunction {
            entry_va: 0x100,
            blocks: vec![LlirBlock {
                start_va: 0x100,
                end_va: 0x110,
                instrs: vec![LlirInstr {
                    va: 0x108,
                    op: Op::Assign {
                        dst: VReg::phys("r0#1"),
                        src: Value::Reg(VReg::phys("r4#1")),
                    },
                }],
                succs: Vec::new(),
            }],
        };
        let mut facts = crate::ir::stack_locals::StackLocalFacts::default();

        merge_dwarf_register_local_facts(
            &mut facts,
            Some(&contract),
            &numbered,
            &std::collections::HashMap::from([("r4#1".to_string(), "var1".to_string())]),
            Arch::ARM,
            crate::ir::call_args::CallConv::Arm,
            None,
        );

        assert_eq!(
            facts.source_names.get("var1").map(String::as_str),
            Some("i")
        );
        assert_eq!(
            facts.source_types.get("var1").map(String::as_str),
            Some("unsigned int")
        );
    }

    #[test]
    fn dwarf_register_family_with_reused_role_becomes_declaration_only() {
        use crate::core::binary::Arch;
        use crate::debug::dwarf::{DwarfRegisterLocal, DwarfRegisterLocation};
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

        let contract = DwarfPrototypeContract {
            function_name: None,
            prototyped: true,
            variadic: false,
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
            static_locals: Vec::new(),
            stack_objects: Vec::new(),
            register_locals: vec![DwarfRegisterLocal {
                source_name: "i".to_string(),
                c_type: "int".to_string(),
                locations: vec![DwarfRegisterLocation {
                    start: 0x100,
                    end: 0x110,
                    register: 0,
                }],
            }],
        };
        let numbered = LlirFunction {
            entry_va: 0x80,
            blocks: vec![LlirBlock {
                start_va: 0x80,
                end_va: 0x110,
                instrs: vec![
                    LlirInstr {
                        va: 0x90,
                        op: Op::Assign {
                            dst: VReg::phys("rcx#1"),
                            src: Value::Reg(VReg::phys("rax#1")),
                        },
                    },
                    LlirInstr {
                        va: 0x104,
                        op: Op::Assign {
                            dst: VReg::phys("rcx#3"),
                            src: Value::Reg(VReg::phys("rax#1")),
                        },
                    },
                    LlirInstr {
                        va: 0x108,
                        op: Op::Assign {
                            dst: VReg::phys("rcx#2"),
                            src: Value::Reg(VReg::phys("rax#2")),
                        },
                    },
                ],
                succs: Vec::new(),
            }],
        };
        let roles = std::collections::HashMap::from([
            ("rax#1".to_string(), "ret".to_string()),
            ("rax#2".to_string(), "var4".to_string()),
        ]);
        let mut facts = crate::ir::stack_locals::StackLocalFacts::default();

        merge_dwarf_register_local_facts(
            &mut facts,
            Some(&contract),
            &numbered,
            &roles,
            Arch::X86_64,
            crate::ir::call_args::CallConv::SysVAmd64,
            None,
        );

        assert!(facts.source_names.is_empty());
        assert_eq!(facts.source_types.get("i").map(String::as_str), Some("int"));
    }

    /// One machine value serving two source locals of different widths must be
    /// declared at the WIDER one. gcc `-O2` does exactly this for
    /// `dp190_mul_both_halves`: `product` (uint64_t) and `low` (uint32_t) both
    /// live in `rsi` over the same range because `low` is `product`'s
    /// truncation. Binding the narrow claimant makes `product >> 32`
    /// identically zero, so the high half of the widening multiply is lost.
    /// Declaration order is not evidence, and the loser here is deliberately
    /// listed FIRST so the test fails against first-claimant-wins.
    #[test]
    fn dwarf_register_widest_claimant_owns_a_shared_recovered_value() {
        use crate::core::binary::Arch;
        use crate::debug::dwarf::{DwarfRegisterLocal, DwarfRegisterLocation};
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

        let at_rsi = |name: &str, c_type: &str| DwarfRegisterLocal {
            source_name: name.to_string(),
            c_type: c_type.to_string(),
            locations: vec![DwarfRegisterLocation {
                start: 0x100,
                end: 0x110,
                register: 4,
            }],
        };
        let contract = DwarfPrototypeContract {
            function_name: None,
            prototyped: true,
            variadic: false,
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
            static_locals: Vec::new(),
            stack_objects: Vec::new(),
            register_locals: vec![at_rsi("low", "uint32_t"), at_rsi("product", "uint64_t")],
        };
        let numbered = LlirFunction {
            entry_va: 0x100,
            blocks: vec![LlirBlock {
                start_va: 0x100,
                end_va: 0x110,
                instrs: vec![LlirInstr {
                    va: 0x104,
                    op: Op::Assign {
                        dst: VReg::phys("rax#1"),
                        src: Value::Reg(VReg::phys("rsi#1")),
                    },
                }],
                succs: Vec::new(),
            }],
        };
        let roles = std::collections::HashMap::from([("rsi#1".to_string(), "var2".to_string())]);
        let mut facts = crate::ir::stack_locals::StackLocalFacts::default();

        merge_dwarf_register_local_facts(
            &mut facts,
            Some(&contract),
            &numbered,
            &roles,
            Arch::X86_64,
            crate::ir::call_args::CallConv::SysVAmd64,
            None,
        );

        assert_eq!(
            facts.source_names.get("var2").map(String::as_str),
            Some("product")
        );
        assert_eq!(
            facts.source_types.get("var2").map(String::as_str),
            Some("uint64_t")
        );
    }

    /// Equal widths carry no preference, so the established order still decides
    /// and the rule above must not fire.
    #[test]
    fn dwarf_register_equal_width_claimants_keep_the_established_order() {
        use crate::core::binary::Arch;
        use crate::debug::dwarf::{DwarfRegisterLocal, DwarfRegisterLocation};
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

        let at_rsi = |name: &str| DwarfRegisterLocal {
            source_name: name.to_string(),
            c_type: "uint32_t".to_string(),
            locations: vec![DwarfRegisterLocation {
                start: 0x100,
                end: 0x110,
                register: 4,
            }],
        };
        let contract = DwarfPrototypeContract {
            function_name: None,
            prototyped: true,
            variadic: false,
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
            static_locals: Vec::new(),
            stack_objects: Vec::new(),
            register_locals: vec![at_rsi("first"), at_rsi("second")],
        };
        let numbered = LlirFunction {
            entry_va: 0x100,
            blocks: vec![LlirBlock {
                start_va: 0x100,
                end_va: 0x110,
                instrs: vec![LlirInstr {
                    va: 0x104,
                    op: Op::Assign {
                        dst: VReg::phys("rax#1"),
                        src: Value::Reg(VReg::phys("rsi#1")),
                    },
                }],
                succs: Vec::new(),
            }],
        };
        let roles = std::collections::HashMap::from([("rsi#1".to_string(), "var2".to_string())]);
        let mut facts = crate::ir::stack_locals::StackLocalFacts::default();

        merge_dwarf_register_local_facts(
            &mut facts,
            Some(&contract),
            &numbered,
            &roles,
            Arch::X86_64,
            crate::ir::call_args::CallConv::SysVAmd64,
            None,
        );

        assert_eq!(
            facts.source_names.get("var2").map(String::as_str),
            Some("first")
        );
    }

    #[test]
    fn dwarf_register_unique_winner_survives_a_reused_sibling_role() {
        use crate::core::binary::Arch;
        use crate::debug::dwarf::{DwarfRegisterLocal, DwarfRegisterLocation};
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

        let contract = DwarfPrototypeContract {
            function_name: None,
            prototyped: true,
            variadic: false,
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
            static_locals: Vec::new(),
            stack_objects: Vec::new(),
            register_locals: vec![DwarfRegisterLocal {
                source_name: "i".to_string(),
                c_type: "int".to_string(),
                locations: vec![DwarfRegisterLocation {
                    start: 0x100,
                    end: 0x110,
                    register: 0,
                }],
            }],
        };
        let numbered = LlirFunction {
            entry_va: 0x80,
            blocks: vec![LlirBlock {
                start_va: 0x80,
                end_va: 0x110,
                instrs: vec![
                    LlirInstr {
                        va: 0x90,
                        op: Op::Assign {
                            dst: VReg::phys("rcx#1"),
                            src: Value::Reg(VReg::phys("rax#1")),
                        },
                    },
                    LlirInstr {
                        va: 0x104,
                        op: Op::Assign {
                            dst: VReg::phys("rcx#2"),
                            src: Value::Reg(VReg::phys("rax#1")),
                        },
                    },
                    LlirInstr {
                        va: 0x108,
                        op: Op::Bin {
                            dst: VReg::phys("rcx#3"),
                            op: crate::ir::types::BinOp::Add,
                            lhs: Value::Reg(VReg::phys("rax#2")),
                            rhs: Value::Reg(VReg::phys("rax#2")),
                        },
                    },
                    LlirInstr {
                        va: 0x10c,
                        op: Op::Assign {
                            dst: VReg::phys("rcx#4"),
                            src: Value::Reg(VReg::phys("rax#2")),
                        },
                    },
                ],
                succs: Vec::new(),
            }],
        };
        let roles = std::collections::HashMap::from([
            ("rax#1".to_string(), "ret".to_string()),
            ("rax#2".to_string(), "var4".to_string()),
        ]);
        let mut facts = crate::ir::stack_locals::StackLocalFacts::default();

        merge_dwarf_register_local_facts(
            &mut facts,
            Some(&contract),
            &numbered,
            &roles,
            Arch::X86_64,
            crate::ir::call_args::CallConv::SysVAmd64,
            None,
        );

        assert_eq!(
            facts.source_names.get("var4").map(String::as_str),
            Some("i")
        );
        assert_eq!(
            facts.source_types.get("var4").map(String::as_str),
            Some("int")
        );
    }

    #[test]
    fn dwarf_register_name_rejects_a_role_used_outside_the_source_lifetime() {
        use crate::core::binary::Arch;
        use crate::debug::dwarf::{DwarfRegisterLocal, DwarfRegisterLocation};
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

        let contract = DwarfPrototypeContract {
            function_name: None,
            prototyped: true,
            variadic: false,
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
            static_locals: Vec::new(),
            stack_objects: Vec::new(),
            register_locals: vec![DwarfRegisterLocal {
                source_name: "result".to_string(),
                c_type: "struct sensor *".to_string(),
                locations: vec![DwarfRegisterLocation {
                    start: 0x105,
                    end: 0x110,
                    register: 4,
                }],
            }],
        };
        let numbered = LlirFunction {
            entry_va: 0x80,
            blocks: vec![LlirBlock {
                start_va: 0x80,
                end_va: 0x110,
                instrs: vec![
                    LlirInstr {
                        va: 0x90,
                        op: Op::Assign {
                            dst: VReg::phys("r0#1"),
                            src: Value::Reg(VReg::phys("r4#1")),
                        },
                    },
                    LlirInstr {
                        va: 0x108,
                        op: Op::Assign {
                            dst: VReg::phys("r1#1"),
                            src: Value::Reg(VReg::phys("r4#1")),
                        },
                    },
                ],
                succs: Vec::new(),
            }],
        };
        let mut facts = crate::ir::stack_locals::StackLocalFacts::default();

        merge_dwarf_register_local_facts(
            &mut facts,
            Some(&contract),
            &numbered,
            &std::collections::HashMap::from([("r4#1".to_string(), "var1".to_string())]),
            Arch::ARM,
            crate::ir::call_args::CallConv::Arm,
            None,
        );

        assert!(facts.source_names.is_empty());
        assert!(facts.source_types.is_empty());
    }

    #[test]
    fn dwarf_register_name_rejects_an_unsafe_source_identifier() {
        use crate::core::binary::Arch;
        use crate::debug::dwarf::{DwarfRegisterLocal, DwarfRegisterLocation};
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

        let contract = DwarfPrototypeContract {
            function_name: None,
            prototyped: true,
            variadic: false,
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
            static_locals: Vec::new(),
            stack_objects: Vec::new(),
            register_locals: vec![DwarfRegisterLocal {
                source_name: "return".to_string(),
                c_type: "int".to_string(),
                locations: vec![DwarfRegisterLocation {
                    start: 0x100,
                    end: 0x110,
                    register: 4,
                }],
            }],
        };
        let numbered = LlirFunction {
            entry_va: 0x100,
            blocks: vec![LlirBlock {
                start_va: 0x100,
                end_va: 0x110,
                instrs: vec![LlirInstr {
                    va: 0x108,
                    op: Op::Assign {
                        dst: VReg::phys("r0#1"),
                        src: Value::Reg(VReg::phys("r4#1")),
                    },
                }],
                succs: Vec::new(),
            }],
        };
        let mut facts = crate::ir::stack_locals::StackLocalFacts::default();

        merge_dwarf_register_local_facts(
            &mut facts,
            Some(&contract),
            &numbered,
            &std::collections::HashMap::from([("r4#1".to_string(), "var1".to_string())]),
            Arch::ARM,
            crate::ir::call_args::CallConv::Arm,
            None,
        );

        assert!(facts.source_names.is_empty());
        assert!(facts.source_types.is_empty());
    }
}
