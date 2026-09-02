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

use callee_contracts::{
    apply_recovered_direct_callee_effects, recover_direct_callee_layouts,
    refine_passthrough_parameter_hints, DirectCalleeFacts,
};

use decbench_render::decbench_text;
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
    calling_convention_pointer_width, dwarf_output_contracts, dwarf_render_prototype,
    dwarf_return_hint_with_env, dwarf_stack_object_hints, merge_dwarf_register_local_facts,
    DwarfPrototypeContract,
};

use lift::{lift_bytes_py, lift_window_at_py};

use pipeline::{
    annotate_calls_in, inline_soft_helper_calls_in, prepare_llir_for_lowering, readonly_data_for,
    recognise_machine_frame, run_ast_passes, target_calling_convention, PreparedLlir,
};

use type_maps::{decbench_type_maps, remap_type_map};

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
        func_va,
        max_blocks,
        max_instructions,
        timeout_ms,
        types,
        style,
        pdb_cache,
        max_functions,
        analyst_names.as_ref(),
        analyst_locals.as_ref(),
        analyst_prototype.as_ref(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn decompile_at_session(
    py: Python<'_>,
    session: &crate::program::session::ProgramSession,
    path: &str,
    func_va: u64,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    types: bool,
    style: &str,
    pdb_cache: &str,
    max_functions: usize,
    analyst_names: Option<&std::collections::HashMap<u64, String>>,
    analyst_locals: Option<&std::collections::HashMap<i64, (String, String)>>,
    analyst_prototype: Option<&AnalystPrototype>,
) -> PyResult<String> {
    let _run_profile = crate::decompile::profile::RunProfiler::from_env("decompile_at");
    use crate::analysis::cfg::Budgets;
    use crate::ir::ast::{lower, render, render_with_types};
    use crate::ir::lift_function::lift_function_from_image;
    use crate::ir::types_recover::recover_types_for;

    let image = session.image().clone();
    let data = image.bytes();
    // An ARM32 Thumb symbol's value carries the Thumb bit; the entry it denotes
    // is one lower. Anything resolving a callee through `.symtab` hands us that
    // value verbatim, and decoding one byte in recovers a body with no
    // parameters at all. See `arm32_mode::normalise_entry`.
    let func_va = image.normalize_function_entry(func_va);
    let exception_sites = image.exception_call_sites();
    let dwarf_outputs = (style == "decbench" && types).then(|| dwarf_output_contracts(&image));
    let dwarf_types = (style == "decbench" && types).then(|| session.debug_types());
    let dwarf_type_env = dwarf_types
        .as_deref()
        .map(crate::ir::dwarf_type_env::DwarfTypeEnv::new);
    let budgets = Budgets {
        max_functions,
        max_blocks,
        max_instructions,
        timeout_ms,
        total_timeout_ms: 0,
    };
    // Whole-binary function discovery: seconds to minutes on a large image, and
    // the reason `Ctrl-C` used to do nothing until it finished. `data` is an
    // owned `Vec<u8>` and `Budgets` is `Copy`; no `Bound`/`Py` reference crosses
    // the closure boundary. See `python_bindings::analysis`.
    let funcs = py.detach(|| session.discover_functions(&budgets, &[func_va]));
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
    let arch = image.target().architecture();
    let arm_vfp_args = image.arm_hard_float();
    // Build the address map first so we can apply a PDB public-symbol name
    // to the *outer* function header before lowering. The map already
    // includes PDB symbols when a cache is configured, plus exports / IAT
    // names that beat the CFG-pass heuristic on stripped Windows binaries.
    // It is also what tells `soft_helpers` which call targets are libgcc
    // division helpers, and that has to happen while the IR is still physical.
    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    // ONE parse of the image yields both the call-target names and the
    // named static storage. Two parses tripped the object-parse ceiling.
    let (mut addr_map, data_symbols) =
        crate::ir::name_resolve::collect_address_map_with_pdb_cache_and_data_symbols(
            &data, &path, pdb_cache,
        );
    crate::ir::name_resolve::add_discovered_function_names(&mut addr_map, &funcs);
    crate::ir::name_resolve::add_referenced_function_names(&mut addr_map, &funcs);
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
    // The reason is the analyst-visible one. This used to blame the
    // architecture unconditionally, so an x86-64 function whose blocks were all
    // attributed to a neighbour reported "LLIR lifter does not support this
    // architecture" about a lifter that supports it perfectly well.
    let lf_raw = lift_function_from_image(&image, &func)
        .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
    // The ABI's call effects, recorded on the calls themselves, BEFORE SSA — so a
    // call participates in def/use like any other instruction instead of every later
    // pass having to special-case it (see `ir::abi`).
    let mut lf_raw = lf_raw;
    inline_soft_helper_calls_in(&mut lf_raw, &addr_map);
    annotate_calls_in(&mut lf_raw, cc, &addr_map);
    // Recovered here rather than with the other AST-pass inputs below: a call
    // through one of these tables needs its entries' parameter storage, and
    // that is the same demand-driven callee analysis.
    let function_tables = crate::ir::function_tables::collect_function_pointer_tables(&data);
    // Identity-keyed call structure for this exact discovery. `call_graph_for`
    // builds from `funcs` (already fetched above) instead of re-querying
    // `discover_functions`, so this one logical query registers exactly one
    // discovery-cache hit-or-miss rather than two. The SCC condensation lets
    // nested callee analysis decline to spend a layer inside a call cycle.
    let callee_call_graph = py.detach(|| session.call_graph_for(&budgets, &[func_va], &funcs));
    let mut callee_layout_cache = std::collections::HashMap::new();
    let mut callee_facts = recover_direct_callee_layouts(
        &image,
        &funcs,
        &lf_raw,
        cc,
        arm_vfp_args,
        &budgets,
        dwarf_outputs.as_ref(),
        dwarf_type_env.as_ref(),
        &mut addr_map,
        &function_tables,
        Some(callee_call_graph.as_ref()),
        &mut callee_layout_cache,
    );
    apply_recovered_direct_callee_effects(&mut lf_raw, cc, &callee_facts);
    // The analyst overlay, applied now that every name-keyed analysis above has
    // run against what the binary calls things. It rewrites the address map --
    // which `resolve_names` turns into `Expr::Named` -- so one overlay renames
    // the definition AND every call site, and it rekeys the recovered symbol
    // environment so the callee keeps the prototype recovered under its old
    // name. See `apply_analyst_names` and `SymbolEnv::rename_display`.
    if let Some(names) = analyst_names {
        {
            let renames = crate::ir::name_resolve::apply_analyst_names(&mut addr_map, names);
            if !renames.is_empty() {
                {
                    callee_facts.env.rename_display(&renames);
                }
            }
        }
    }
    // `value_number` canonicalises sub-registers to their 64-bit parent (`edi`
    // -> `rdi`) so def/use versions line up for value correctness. But the
    // register sub-name width (`edi`=4) is *the* -O0 type-recovery signal, and
    // canonicalisation erases it. So type recovery runs on `lf_raw` (widths
    // intact) while everything downstream uses the canonicalised `lf`; the
    // remap merges the raw `edi`/`rdi` keys into one `argN` slot, keeping the
    // narrower width.
    // Live-in argument slots (authoritative parameter set) for the type-map
    // remap, so scratch reuse of an arg register never becomes a spurious `argN`.
    // Recover the semantic prototype while SSA value IDs are still available.
    // It survives the AST pipeline as an immutable companion object; naming is
    // now only a final projection (`value -> argN`), never a type-analysis key.
    let prepared_llir = prepare_llir_for_lowering(
        &mut lf_raw,
        &image,
        &exception_sites,
        cc,
        style == "decbench" && types,
        arm_vfp_args,
        dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va)),
        program_environment
            .as_deref()
            .and_then(|environment| environment.prototype_for(func_va)),
        dwarf_type_env.as_ref(),
    );
    let PreparedLlir {
        region,
        cfg_health,
        numbered: lf,
        definition_widths,
        parameter_slots: mut param_slots,
        inferred_prototype,
        mut prototype,
        ..
    } = prepared_llir;
    if let Some(prototype) = prototype.as_mut() {
        let exact_ssa = crate::ir::ssa::compute_ssa(&lf_raw);
        refine_passthrough_parameter_hints(prototype, &lf_raw, &exact_ssa, &callee_facts);
    }
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!("\n===== recovered prototype =====\n{prototype:#?}");
    }
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    let outer_name =
        resolve_outer_function_name_with_analyst(&func.name, func_va, &addr_map, analyst_names);
    let mut profiler = crate::decompile::profile::FunctionProfiler::from_env(&outer_name, func_va);
    let mut f = profiler.measure("lower", || lower(&lf, &region, outer_name));
    crate::ir::exception_recover::mark_landing_pads(&mut f, &exception_sites);
    // Pass-by-pass AST dump for debugging the decbench lowering pipeline. Set
    // GLAURUNG_DUMP_PASSES=1 to print the rendered body after each pass to stderr
    // (bisect which pass corrupts a function). No-op otherwise.
    let dump_passes = std::env::var("GLAURUNG_DUMP_PASSES").is_ok();
    macro_rules! dp {
        ($n:expr) => {
            crate::ir::health::trace_pass($n, &f, cfg_health);
            if dump_passes {
                eprintln!("\n===== after {} =====\n{}", $n, crate::ir::ast::render(&f));
            }
        };
    }
    dp!("lower");
    let str_pool = crate::ir::strings_fold::collect_string_pool_from_image(&image);
    let readonly_data = readonly_data_for(&session, &image, &str_pool);
    // Slot -> the in-image address the loader stores there, so a `-fPIC` read
    // of a locally-defined global folds to that global instead of dereferencing
    // an unrelocated linkage word. See `ir::got_fold`.
    let got_targets: std::collections::HashMap<u64, u64> =
        crate::analysis::elf_got::elf_got_target_map(&data)
            .into_iter()
            .collect();
    let stack_object_hints = dwarf_stack_object_hints(
        dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va)),
        cc,
    );
    let (mut stack_facts, role_names) = run_ast_passes(
        &mut f,
        &mut profiler,
        cfg_health,
        cc,
        false,
        prototype.as_ref(),
        &mut param_slots,
        locked_parameter_count(prototype.as_ref()),
        &callee_facts,
        &addr_map,
        &str_pool,
        &function_tables,
        &stack_object_hints,
        &got_targets,
    );
    // The analyst's own names and types for frame slots, joined by frame
    // offset and applied through the SAME mechanism debug names use --
    // `source_names` / `source_types`, consumed by
    // `naming::apply_authoritative_local_names` at the presentation boundary.
    // Riding that path rather than building a second one means a rename cannot
    // turn a scalar assignment into a pointer store, and an analyst who names a
    // variable `int` gets the same rejection a bad DWARF name gets.
    if let Some(locals) = analyst_locals {
        crate::ir::stack_locals::apply_analyst_locals(&mut stack_facts, locals);
    }
    merge_dwarf_register_local_facts(
        &mut stack_facts,
        dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va)),
        &lf,
        &role_names,
        arch,
        cc,
        dwarf_type_env.as_ref(),
    );
    if style == "decbench" {
        crate::ir::exception_recover::recover_typed_handlers(&mut f, &exception_sites);
        crate::ir::exception_recover::mark_int_throws_with_address_map(&mut f, &addr_map);
        crate::ir::exception_recover::recover_throws(&mut f);
    }
    recognise_machine_frame(&mut f, cc);
    if let Some(field_map) = &field_map {
        crate::ir::pdb_fields::annotate_function_fields(&mut f, field_map);
    }
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
    // Design Rule 8: a proof that did not complete becomes an explicit unknown
    // in the output, not a silent omission. `func` carries whichever discovery
    // budget stopped ITS OWN walk, so this can only ever fire for the function
    // being rendered. See `analysis::completeness`.
    let incompleteness_note =
        crate::analysis::completeness::cfg_incompleteness_note(&func, &budgets);
    let text = if style == "decbench" {
        // DecBench wants concrete C types. Reuse the recovered TypeMap when it
        // was computed, else recover on demand, then remap raw-reg keys to the
        // AST's role names (`arg0`, `ret`, ...) before rendering.
        let maps = types.then(|| {
            decbench_type_maps(
                &f,
                &lf_raw,
                &lf,
                prototype.as_ref().expect("typed DecBench prototype"),
                cc,
                &param_slots,
                &stack_facts.sizes,
                &stack_facts.source_types,
                &stack_facts.source_names,
                dwarf_type_env.as_ref(),
                &role_names,
                &definition_widths,
            )
        });
        let (decl, width, exact_value_widths) = match &maps {
            Some((d, w, exact)) => (Some(d), Some(w), Some(exact)),
            None => (None, None, None),
        };
        // The analyst's prototype outranks the compiler's, for the same reason
        // their rename outranks the symbol table: it is a decision ABOUT the
        // recovered facts rather than another one of them. It lands in the slot
        // DWARF already uses -- `declared_prototype` overrides the recovered
        // prototype for rendering and drives both the return type and the
        // parameter c_types (`ast::declaration_plan`) -- so there is no second
        // mechanism and the two cannot disagree.
        // Analyst first, then DWARF -- see `CallPrototype::from_analyst`.
        let dwarf_render_contract = dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va));
        let declared_render = analyst_prototype
            .map(|prototype| {
                crate::ir::call_contracts::CallPrototype::from_analyst(
                    &prototype.return_type,
                    &prototype.parameter_types,
                    prototype.variadic,
                )
            })
            .or_else(|| dwarf_render_contract.and_then(dwarf_render_prototype));
        let declared_parameter_names = analyst_prototype
            .map(|prototype| prototype.parameter_names.as_slice())
            .or_else(|| dwarf_render_contract.map(|contract| contract.parameter_names.as_slice()));
        if analyst_prototype.is_some() {
            record_prototype_conflict_with_candidate(
                &f.name,
                func_va,
                "analyst",
                declared_render.as_ref(),
                "dwarf",
                dwarf_render_contract
                    .and_then(dwarf_render_prototype)
                    .as_ref(),
            );
        }
        record_recovered_prototype_conflict(
            &f.name,
            func_va,
            if analyst_prototype.is_some() {
                "analyst"
            } else {
                "dwarf"
            },
            declared_render.as_ref(),
            inferred_prototype.as_ref(),
            cc,
        );
        decbench_text(
            &f,
            &mut profiler,
            cfg_health,
            &exception_sites,
            decl,
            width,
            exact_value_widths,
            &readonly_data,
            prototype.as_ref(),
            declared_render.as_ref(),
            declared_parameter_names,
            dwarf_types.as_deref().unwrap_or(&[]),
            &stack_facts.source_types,
            &stack_facts.source_names,
            cc,
            &addr_map,
            &callee_facts.env,
            &data_symbols,
        )
    } else if style == "c" {
        let body = profiler.measure("render_c", || crate::ir::ast::render_c(&f));
        match pdb_outer_name {
            Some(name) => format!("// PDB: {}\n{}", name, body),
            None => body,
        }
    } else if types {
        // Plain-with-types style. Non-decbench paths skip `value_number`, so the
        // raw LLIR is the canonical one; remap the TypeMap keys from raw physical
        // regs into the role-based names the AST now uses.
        let renamed = remap_type_map(&recover_types_for(&lf_raw, cc), &f, cc, &param_slots);
        profiler.measure("render_with_types", || render_with_types(&f, &renamed))
    } else {
        profiler.measure("render", || render(&f))
    };
    Ok(match incompleteness_note {
        Some(note) => format!("{note}\n{text}"),
        None => text,
    })
}

#[pyfunction]
#[pyo3(name = "decompile_range_at")]
#[pyo3(signature = (path, func_va, range_start, range_end, max_blocks=256usize, max_instructions=10_000usize, timeout_ms=500u64, types=true, style="", pdb_cache=""))]
fn decompile_range_at_py(
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
) -> PyResult<String> {
    let _run_profile = crate::decompile::profile::RunProfiler::from_env("decompile_range_at");
    use crate::core::address::{Address, AddressKind};
    use crate::core::address_range::AddressRange;
    use crate::core::basic_block::BasicBlock;
    use crate::core::function::{Function, FunctionKind};
    use crate::ir::ast::{lower, render, render_with_types};
    use crate::ir::lift_function::lift_function_from_image;
    use crate::ir::types_recover::recover_types_for;

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
    let _ = timeout_ms;

    let image = load_program_image(&path)?;
    let session = crate::program::session::ProgramSession::from_image(image);
    let image = session.image().clone();
    let data = image.bytes();
    let exception_sites = image.exception_call_sites();
    let dwarf_outputs = (style == "decbench" && types).then(|| dwarf_output_contracts(&image));
    let dwarf_types = (style == "decbench" && types).then(|| session.debug_types());
    let dwarf_type_env = dwarf_types
        .as_deref()
        .map(crate::ir::dwarf_type_env::DwarfTypeEnv::new);
    let cc = target_calling_convention(&image)?;
    let arch = image.target().architecture();
    let arm_vfp_args = image.arm_hard_float();
    let bits = image.target().address_bits().ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("target address width is unknown")
    })?;
    let max_bytes = (max_instructions as u64).saturating_mul(16).max(1);
    let capped_end = range_end.min(range_start.saturating_add(max_bytes));
    let entry = Address::new(AddressKind::VA, func_va, bits, None, None)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let block_start = Address::new(AddressKind::VA, range_start, bits, None, None)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let block_end = Address::new(AddressKind::VA, capped_end, bits, None, None)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let range = AddressRange::new(block_start.clone(), capped_end - range_start, None)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let mut func = Function::new(format!("sub_{:x}", func_va), entry, FunctionKind::Normal)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    func.range = Some(range.clone());
    func.size = Some(range.size);
    func.chunks.push(range);
    func.basic_blocks.push(BasicBlock::new(
        format!("bb_{:x}", range_start),
        block_start,
        block_end,
        1,
        Some(Vec::new()),
        Some(Vec::new()),
    ));

    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    // ONE parse of the image yields both the call-target names and the
    // named static storage. Two parses tripped the object-parse ceiling.
    let (addr_map, data_symbols) =
        crate::ir::name_resolve::collect_address_map_with_pdb_cache_and_data_symbols(
            &data, &path, pdb_cache,
        );
    let budgets = crate::analysis::cfg::Budgets {
        max_functions: 1,
        max_blocks,
        max_instructions,
        timeout_ms,
        total_timeout_ms: 0,
    };
    let program_environment = (style == "decbench" && types)
        .then(|| session.environment(&budgets, cc, &addr_map, &[func_va]));
    // The reason is the analyst-visible one. This used to blame the
    // architecture unconditionally, so an x86-64 function whose blocks were all
    // attributed to a neighbour reported "LLIR lifter does not support this
    // architecture" about a lifter that supports it perfectly well.
    let lf_raw = lift_function_from_image(&image, &func)
        .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
    // The ABI's call effects, recorded on the calls themselves, BEFORE SSA — so a
    // call participates in def/use like any other instruction instead of every later
    // pass having to special-case it (see `ir::abi`).
    let mut lf_raw = lf_raw;
    inline_soft_helper_calls_in(&mut lf_raw, &addr_map);
    annotate_calls_in(&mut lf_raw, cc, &addr_map);
    // `value_number` canonicalises sub-registers to their 64-bit parent (`edi`
    // -> `rdi`) so def/use versions line up for value correctness. But the
    // register sub-name width (`edi`=4) is *the* -O0 type-recovery signal, and
    // canonicalisation erases it. So type recovery runs on `lf_raw` (widths
    // intact) while everything downstream uses the canonicalised `lf`; the
    // remap merges the raw `edi`/`rdi` keys into one `argN` slot, keeping the
    // narrower width.
    let prepared_llir = prepare_llir_for_lowering(
        &mut lf_raw,
        &image,
        &exception_sites,
        cc,
        style == "decbench" && types,
        arm_vfp_args,
        dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va)),
        program_environment
            .as_deref()
            .and_then(|environment| environment.prototype_for(func_va)),
        dwarf_type_env.as_ref(),
    );
    let PreparedLlir {
        region,
        cfg_health,
        numbered: lf,
        definition_widths,
        parameter_slots: mut param_slots,
        inferred_prototype,
        prototype,
        ..
    } = prepared_llir;
    let declared_function_name = dwarf_outputs
        .as_ref()
        .and_then(|outputs| outputs.get(&func_va))
        .and_then(|contract| contract.function_name.as_ref())
        .cloned()
        .unwrap_or_else(|| func.name.clone());
    let mut profiler =
        crate::decompile::profile::FunctionProfiler::from_env(&declared_function_name, func_va);
    let mut f = profiler.measure("lower", || lower(&lf, &region, declared_function_name));
    crate::ir::exception_recover::mark_landing_pads(&mut f, &exception_sites);
    // An explicit byte range has no discovered callee Function objects from
    // which to recover cross-function storage layouts.
    let callee_facts = DirectCalleeFacts::default();
    // Inputs the shared pipeline needs. These were interleaved BETWEEN passes here, which
    // is why the four copies could not simply be diffed against each other — the pass
    // list and the local setup were braided together. None of them touch `f`, so
    // hoisting them is order-preserving.
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    let str_pool = crate::ir::strings_fold::collect_string_pool_from_image(&image);
    let readonly_data = readonly_data_for(&session, &image, &str_pool);
    let function_tables = crate::ir::function_tables::collect_function_pointer_tables(&data);
    // Slot -> the in-image address the loader stores there, so a `-fPIC` read
    // of a locally-defined global folds to that global instead of dereferencing
    // an unrelocated linkage word. See `ir::got_fold`.
    let got_targets: std::collections::HashMap<u64, u64> =
        crate::analysis::elf_got::elf_got_target_map(&data)
            .into_iter()
            .collect();
    let stack_object_hints = dwarf_stack_object_hints(
        dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va)),
        cc,
    );
    let (mut stack_facts, role_names) = run_ast_passes(
        &mut f,
        &mut profiler,
        cfg_health,
        cc,
        false,
        prototype.as_ref(),
        &mut param_slots,
        locked_parameter_count(prototype.as_ref()),
        &callee_facts,
        &addr_map,
        &str_pool,
        &function_tables,
        &stack_object_hints,
        &got_targets,
    );
    merge_dwarf_register_local_facts(
        &mut stack_facts,
        dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va)),
        &lf,
        &role_names,
        arch,
        cc,
        dwarf_type_env.as_ref(),
    );
    if style == "decbench" {
        crate::ir::exception_recover::recover_typed_handlers(&mut f, &exception_sites);
        crate::ir::exception_recover::mark_int_throws_with_address_map(&mut f, &addr_map);
        crate::ir::exception_recover::recover_throws(&mut f);
    }
    recognise_machine_frame(&mut f, cc);
    if let Some(field_map) = &field_map {
        crate::ir::pdb_fields::annotate_function_fields(&mut f, field_map);
    }
    Ok(if style == "decbench" {
        let maps = types.then(|| {
            decbench_type_maps(
                &f,
                &lf_raw,
                &lf,
                prototype.as_ref().expect("typed DecBench prototype"),
                cc,
                &param_slots,
                &stack_facts.sizes,
                &stack_facts.source_types,
                &stack_facts.source_names,
                dwarf_type_env.as_ref(),
                &role_names,
                &definition_widths,
            )
        });
        let (decl, width, exact_value_widths) = match &maps {
            Some((d, w, exact)) => (Some(d), Some(w), Some(exact)),
            None => (None, None, None),
        };
        let dwarf_render_contract = dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va));
        let declared_render = dwarf_render_contract.and_then(dwarf_render_prototype);
        record_recovered_prototype_conflict(
            &f.name,
            func_va,
            "dwarf",
            declared_render.as_ref(),
            inferred_prototype.as_ref(),
            cc,
        );
        decbench_text(
            &f,
            &mut profiler,
            cfg_health,
            &exception_sites,
            decl,
            width,
            exact_value_widths,
            &readonly_data,
            prototype.as_ref(),
            declared_render.as_ref(),
            dwarf_render_contract.map(|contract| contract.parameter_names.as_slice()),
            dwarf_types.as_deref().unwrap_or(&[]),
            &stack_facts.source_types,
            &stack_facts.source_names,
            cc,
            &addr_map,
            &callee_facts.env,
            &data_symbols,
        )
    } else if style == "c" {
        profiler.measure("render_c", || crate::ir::ast::render_c(&f))
    } else if types {
        let renamed = remap_type_map(&recover_types_for(&lf_raw, cc), &f, cc, &param_slots);
        profiler.measure("render_with_types", || render_with_types(&f, &renamed))
    } else {
        profiler.measure("render", || render(&f))
    })
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
        let hidden_return_hint =
            hidden_return_pointer.then_some(Some(crate::ir::types_recover::TypeHint::Pointer {
                pointee_width: 1,
            }));
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
        "inferred",
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
/// Default `limit=30000` matches the function-discovery cap so the
/// `--all` flag really does emit every function unless the user
/// explicitly opts back into a smaller window.
#[pyfunction]
#[pyo3(name = "decompile_all")]
#[pyo3(signature = (path, limit=30_000usize, max_blocks=4096usize, max_instructions=200_000usize, timeout_ms=10_000u64, pdb_cache="", style="", analyst_names=None))]
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
) -> PyResult<PyObject> {
    let _run_profile = crate::decompile::profile::RunProfiler::from_env("decompile_all");
    use crate::analysis::cfg::Budgets;
    use crate::ir::ast::{lower, render};
    use crate::ir::lift_function::lift_function_from_image;

    let image = load_program_image(&path)?;
    let session = crate::program::session::ProgramSession::from_image(image);
    let image = session.image().clone();
    let data = image.bytes();
    let exception_sites = image.exception_call_sites();
    let dwarf_outputs = (style == "decbench").then(|| dwarf_output_contracts(&image));
    let dwarf_types = (style == "decbench").then(|| session.debug_types());
    let dwarf_type_env = dwarf_types
        .as_deref()
        .map(crate::ir::dwarf_type_env::DwarfTypeEnv::new);
    let budgets = Budgets {
        max_functions: limit.max(1),
        max_blocks,
        max_instructions,
        timeout_ms,
        total_timeout_ms: 0,
    };
    // Whole-binary function discovery: seconds to minutes on a large image, and
    // the reason `Ctrl-C` used to do nothing until it finished. `data` is an
    // owned `Vec<u8>` and `Budgets` is `Copy`; no `Bound`/`Py` reference crosses
    // the closure boundary. See `python_bindings::analysis`.
    let funcs = py.detach(|| session.discover_functions(&budgets, &[]));
    let cc = target_calling_convention(&image)?;
    let arch = image.target().architecture();
    let arm_vfp_args = image.arm_hard_float();
    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    // ONE parse of the image yields both the call-target names and the
    // named static storage. Two parses tripped the object-parse ceiling.
    let (mut addr_map, data_symbols) =
        crate::ir::name_resolve::collect_address_map_with_pdb_cache_and_data_symbols(
            &data, &path, pdb_cache,
        );
    crate::ir::name_resolve::add_discovered_function_names(&mut addr_map, &funcs);
    crate::ir::name_resolve::add_referenced_function_names(&mut addr_map, &funcs);
    // The analyst overlay is DELIBERATELY not applied here. Everything between
    // this point and `recover_direct_callee_layouts` resolves callees BY NAME
    // against what the binary calls them -- `session.environment`,
    // `annotate_calls_in`, and the callee layout recovery itself. Renaming
    // `validate` to `parse_packet_hdr` before those run means they look up a
    // name no symbol source knows, find nothing, and downgrade a recovered
    // `int validate(char *, int)` to `long f(void)` at every call site. The
    // rename is a presentation decision, so it is applied after the analysis
    // that depends on binary truth -- see below.
    let environment_targets = funcs
        .iter()
        .take(limit)
        .map(|function| function.entry_point.value)
        .collect::<Vec<_>>();
    let program_environment = (style == "decbench")
        .then(|| session.environment(&budgets, cc, &addr_map, &environment_targets));
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    let str_pool = crate::ir::strings_fold::collect_string_pool_from_image(&image);
    let readonly_data = readonly_data_for(&session, &image, &str_pool);
    let function_tables = crate::ir::function_tables::collect_function_pointer_tables(&data);
    // Slot -> the in-image address the loader stores there, so a `-fPIC` read
    // of a locally-defined global folds to that global instead of dereferencing
    // an unrelocated linkage word. See `ir::got_fold`.
    let got_targets: std::collections::HashMap<u64, u64> =
        crate::analysis::elf_got::elf_got_target_map(&data)
            .into_iter()
            .collect();
    // Identity-keyed call structure for this exact discovery. `call_graph_for`
    // builds from `funcs` (already fetched above) instead of re-querying
    // `discover_functions`, so this one logical query registers exactly one
    // discovery-cache hit-or-miss rather than two. The SCC condensation lets
    // nested callee analysis decline to spend a layer inside a call cycle.
    let callee_call_graph = py.detach(|| session.call_graph_for(&budgets, &[], &funcs));
    let mut callee_layout_cache = std::collections::HashMap::new();
    let list = PyList::empty(py);
    for func in funcs.iter().take(limit) {
        // The GIL is held across the per-function lifting work (the loop builds
        // a `PyList` as it goes), so CPython never re-enters its eval loop and
        // never notices a signal. This is the supported way to stay
        // interruptible without releasing: it raises `KeyboardInterrupt` here.
        py.check_signals()?;
        let Ok(lf_raw) = lift_function_from_image(&image, func) else {
            continue;
        };
        // See `ir::abi`: the ABI's call effects go on the calls before SSA.
        let mut lf_raw = lf_raw;
        inline_soft_helper_calls_in(&mut lf_raw, &addr_map);
        annotate_calls_in(&mut lf_raw, cc, &addr_map);
        let mut callee_facts = recover_direct_callee_layouts(
            &image,
            &funcs,
            &lf_raw,
            cc,
            arm_vfp_args,
            &budgets,
            dwarf_outputs.as_ref(),
            dwarf_type_env.as_ref(),
            &mut addr_map,
            &function_tables,
            Some(callee_call_graph.as_ref()),
            &mut callee_layout_cache,
        );
        apply_recovered_direct_callee_effects(&mut lf_raw, cc, &callee_facts);
        // The analyst overlay, applied now that every name-keyed analysis above has
        // run against what the binary calls things. It rewrites the address map --
        // which `resolve_names` turns into `Expr::Named` -- so one overlay renames
        // the definition AND every call site, and it rekeys the recovered symbol
        // environment so the callee keeps the prototype recovered under its old
        // name. See `apply_analyst_names` and `SymbolEnv::rename_display`.
        if let Some(names) = analyst_names.as_ref() {
            {
                let renames = crate::ir::name_resolve::apply_analyst_names(&mut addr_map, names);
                if !renames.is_empty() {
                    {
                        callee_facts.env.rename_display(&renames);
                    }
                }
            }
        }
        // Recover types on the pre-canonicalisation LLIR (sub-register widths
        // intact); see the note in `decompile_at`.
        let prepared_llir = prepare_llir_for_lowering(
            &mut lf_raw,
            &image,
            &exception_sites,
            cc,
            style == "decbench",
            arm_vfp_args,
            dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func.entry_point.value)),
            program_environment
                .as_deref()
                .and_then(|environment| environment.prototype_for(func.entry_point.value)),
            dwarf_type_env.as_ref(),
        );
        let PreparedLlir {
            region,
            cfg_health,
            numbered: lf,
            definition_widths,
            parameter_slots: mut param_slots,
            inferred_prototype,
            mut prototype,
            ..
        } = prepared_llir;
        if let Some(prototype) = prototype.as_mut() {
            let exact_ssa = crate::ir::ssa::compute_ssa(&lf_raw);
            refine_passthrough_parameter_hints(prototype, &lf_raw, &exact_ssa, &callee_facts);
        }
        let outer_name = resolve_outer_function_name_with_analyst(
            &func.name,
            func.entry_point.value,
            &addr_map,
            analyst_names.as_ref(),
        );
        let mut profiler = crate::decompile::profile::FunctionProfiler::from_env(
            &outer_name,
            func.entry_point.value,
        );
        let mut f = profiler.measure("lower", || lower(&lf, &region, outer_name.clone()));
        crate::ir::exception_recover::mark_landing_pads(&mut f, &exception_sites);
        // One pass list, shared with every other entry point — see `run_ast_passes`.
        // This site used to run dead-flag pruning before constant folding and never
        // pruned unreferenced labels, so `--all` produced different output from `--vas`
        // for the same function, and the fixture gate's structural lane measured a
        // different pipeline from its execution lane. It cannot drift again.
        let stack_object_hints = dwarf_stack_object_hints(
            dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func.entry_point.value)),
            cc,
        );
        let (mut stack_facts, role_names) = run_ast_passes(
            &mut f,
            &mut profiler,
            cfg_health,
            cc,
            false,
            prototype.as_ref(),
            &mut param_slots,
            locked_parameter_count(prototype.as_ref()),
            &callee_facts,
            &addr_map,
            &str_pool,
            &function_tables,
            &stack_object_hints,
            &got_targets,
        );
        merge_dwarf_register_local_facts(
            &mut stack_facts,
            dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func.entry_point.value)),
            &lf,
            &role_names,
            arch,
            cc,
            dwarf_type_env.as_ref(),
        );
        if style == "decbench" {
            crate::ir::exception_recover::recover_typed_handlers(&mut f, &exception_sites);
            crate::ir::exception_recover::mark_int_throws_with_address_map(&mut f, &addr_map);
            crate::ir::exception_recover::recover_throws(&mut f);
        }
        recognise_machine_frame(&mut f, cc);
        if let Some(field_map) = &field_map {
            crate::ir::pdb_fields::annotate_function_fields(&mut f, field_map);
        }
        let text = if style == "decbench" {
            let (decl, width, exact_value_widths) = decbench_type_maps(
                &f,
                &lf_raw,
                &lf,
                prototype.as_ref().expect("DecBench prototype"),
                cc,
                &param_slots,
                &stack_facts.sizes,
                &stack_facts.source_types,
                &stack_facts.source_names,
                dwarf_type_env.as_ref(),
                &role_names,
                &definition_widths,
            );
            let dwarf_render_contract = dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func.entry_point.value));
            let declared_render = dwarf_render_contract.and_then(dwarf_render_prototype);
            record_recovered_prototype_conflict(
                &f.name,
                func.entry_point.value,
                "dwarf",
                declared_render.as_ref(),
                inferred_prototype.as_ref(),
                cc,
            );
            decbench_text(
                &f,
                &mut profiler,
                cfg_health,
                &exception_sites,
                Some(&decl),
                Some(&width),
                Some(&exact_value_widths),
                &readonly_data,
                prototype.as_ref(),
                declared_render.as_ref(),
                dwarf_render_contract.map(|contract| contract.parameter_names.as_slice()),
                dwarf_types.as_deref().unwrap_or(&[]),
                &stack_facts.source_types,
                &stack_facts.source_names,
                cc,
                &addr_map,
                &callee_facts.env,
                &data_symbols,
            )
        } else {
            profiler.measure("render", || render(&f))
        };
        let variables = crate::ir::recovered_variables::recovered_variables_from_llir(
            &text,
            prototype.as_ref(),
            &stack_facts,
            calling_convention_pointer_width(cc),
            &lf_raw,
        );
        list.append((
            outer_name,
            func.entry_point.value,
            text,
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
    // Decompile an arbitrary SUBSET of functions in a SINGLE analysis pass.
    //
    // `decompile_at` re-runs `analyze_functions_bytes` (and the PDB/addr-map
    // build) on every call, so decompiling N scattered functions in a large
    // binary (e.g. the 18 MB mpengine.dll, ~30k functions) costs N full
    // analyses. This amortises that fixed cost across the whole requested set:
    // analyse once, then run the same per-function pipeline as `decompile_at`
    // for each requested VA. Returns a list of (name, va, c_or_ir_text) for
    // every requested VA that resolves to a known function.
    use crate::analysis::cfg::Budgets;
    use crate::ir::ast::{lower, render, render_with_types};
    use crate::ir::lift_function::lift_function_from_image;
    use crate::ir::types_recover::recover_types_for;
    use std::collections::HashSet;

    let image = load_program_image(&path)?;
    let session = crate::program::session::ProgramSession::from_image(image);
    let image = session.image().clone();
    let data = image.bytes();
    // See `decompile_at`: an ARM32 Thumb `.symtab` value carries the Thumb bit.
    let func_vas: Vec<u64> = func_vas
        .into_iter()
        .map(|va| image.normalize_function_entry(va))
        .collect();
    let exception_sites = image.exception_call_sites();
    let dwarf_outputs = (style == "decbench").then(|| dwarf_output_contracts(&image));
    let dwarf_types = (style == "decbench").then(|| session.debug_types());
    let dwarf_type_env = dwarf_types
        .as_deref()
        .map(crate::ir::dwarf_type_env::DwarfTypeEnv::new);
    // Zero is the public address-scoped default: process exactly the unique
    // requested entries. Direct-callee prototype evidence is recovered lazily
    // by `recover_direct_callee_layouts`, so unrelated automatic seeds never
    // need to consume this worklist merely to render one call accurately.
    let requested_function_limit = pipeline::requested_function_limit(&func_vas, max_functions);
    let budgets = Budgets {
        max_functions: requested_function_limit,
        max_blocks,
        max_instructions,
        timeout_ms,
        total_timeout_ms: 0,
    };
    // --- one-time analysis + name/field/string maps -----------------------
    // Whole-binary function discovery: seconds to minutes on a large image, and
    // the reason `Ctrl-C` used to do nothing until it finished. `data` is an
    // owned `Vec<u8>` and `Budgets` is `Copy`; no `Bound`/`Py` reference crosses
    // the closure boundary. See `python_bindings::analysis`.
    let funcs = py.detach(|| session.discover_functions(&budgets, &func_vas));
    let cc = target_calling_convention(&image)?;
    let arch = image.target().architecture();
    let arm_vfp_args = image.arm_hard_float();
    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    // ONE parse of the image yields both the call-target names and the
    // named static storage. Two parses tripped the object-parse ceiling.
    let (mut addr_map, data_symbols) =
        crate::ir::name_resolve::collect_address_map_with_pdb_cache_and_data_symbols(
            &data, &path, pdb_cache,
        );
    crate::ir::name_resolve::add_discovered_function_names(&mut addr_map, &funcs);
    crate::ir::name_resolve::add_referenced_function_names(&mut addr_map, &funcs);
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
        .then(|| session.environment(&budgets, cc, &addr_map, &func_vas));
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    let str_pool = crate::ir::strings_fold::collect_string_pool_from_image(&image);
    let readonly_data = readonly_data_for(&session, &image, &str_pool);
    let function_tables = crate::ir::function_tables::collect_function_pointer_tables(&data);
    // Slot -> the in-image address the loader stores there, so a `-fPIC` read
    // of a locally-defined global folds to that global instead of dereferencing
    // an unrelocated linkage word. See `ir::got_fold`.
    let got_targets: std::collections::HashMap<u64, u64> =
        crate::analysis::elf_got::elf_got_target_map(&data)
            .into_iter()
            .collect();
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
    for func in funcs.iter() {
        // See `decompile_all_py`: keeps a long multi-function decompile
        // interruptible while the GIL is held for the `PyList` it is building.
        py.check_signals()?;
        let func_va = func.entry_point.value;
        if !wanted.contains(&func_va) {
            continue;
        }
        let Ok(lf_raw) = lift_function_from_image(&image, func) else {
            continue;
        };
        // See `ir::abi`: the ABI's call effects go on the calls before SSA.
        let mut lf_raw = lf_raw;
        inline_soft_helper_calls_in(&mut lf_raw, &addr_map);
        annotate_calls_in(&mut lf_raw, cc, &addr_map);
        let mut callee_facts = recover_direct_callee_layouts(
            &image,
            &funcs,
            &lf_raw,
            cc,
            arm_vfp_args,
            &budgets,
            dwarf_outputs.as_ref(),
            dwarf_type_env.as_ref(),
            &mut addr_map,
            &function_tables,
            Some(callee_call_graph.as_ref()),
            &mut callee_layout_cache,
        );
        apply_recovered_direct_callee_effects(&mut lf_raw, cc, &callee_facts);
        // The analyst overlay, applied now that every name-keyed analysis above has
        // run against what the binary calls things. It rewrites the address map --
        // which `resolve_names` turns into `Expr::Named` -- so one overlay renames
        // the definition AND every call site, and it rekeys the recovered symbol
        // environment so the callee keeps the prototype recovered under its old
        // name. See `apply_analyst_names` and `SymbolEnv::rename_display`.
        if let Some(names) = analyst_names.as_ref() {
            {
                let renames = crate::ir::name_resolve::apply_analyst_names(&mut addr_map, names);
                if !renames.is_empty() {
                    {
                        callee_facts.env.rename_display(&renames);
                    }
                }
            }
        }
        // Recover types on the pre-canonicalisation LLIR (sub-register widths
        // intact); see the note in `decompile_at`.
        let mut prepared_llir = pipeline::prepare_llir_for_lowering_with_shadow(
            &mut lf_raw,
            &image,
            &exception_sites,
            cc,
            style == "decbench",
            arm_vfp_args,
            dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func_va)),
            program_environment
                .as_deref()
                .and_then(|environment| environment.prototype_for(func_va)),
            dwarf_type_env.as_ref(),
            shadow_v2,
        );
        prepared_llir
            .select_shadow_v2(shadow_v2, style == "decbench")
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
        let PreparedLlir {
            region,
            cfg_health,
            numbered: lf,
            definition_widths,
            parameter_slots: mut param_slots,
            inferred_prototype,
            mut prototype,
            ..
        } = prepared_llir;
        if let Some(prototype) = prototype.as_mut() {
            let exact_ssa = crate::ir::ssa::compute_ssa(&lf_raw);
            refine_passthrough_parameter_hints(prototype, &lf_raw, &exact_ssa, &callee_facts);
        }
        let outer_name = resolve_outer_function_name_with_analyst(
            &func.name,
            func_va,
            &addr_map,
            analyst_names.as_ref(),
        );
        let mut profiler =
            crate::decompile::profile::FunctionProfiler::from_env(&outer_name, func_va);
        let mut f = profiler.measure("lower", || lower(&lf, &region, outer_name));
        crate::ir::exception_recover::mark_landing_pads(&mut f, &exception_sites);
        // One pass list, shared with every other entry point — see `run_ast_passes`.
        // This site used to run dead-flag pruning before constant folding and never
        // pruned unreferenced labels, so `--all` produced different output from `--vas`
        // for the same function, and the fixture gate's structural lane measured a
        // different pipeline from its execution lane. It cannot drift again.
        // Type recovery runs on the pre-canonicalisation LLIR and does not touch `f`,
        // so it is hoisted above the shared pipeline rather than braided into it.
        let tm = if types {
            Some(recover_types_for(&lf_raw, cc))
        } else {
            None
        };
        let stack_object_hints = dwarf_stack_object_hints(
            dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func_va)),
            cc,
        );
        let (mut stack_facts, role_names) = run_ast_passes(
            &mut f,
            &mut profiler,
            cfg_health,
            cc,
            shadow_v2,
            prototype.as_ref(),
            &mut param_slots,
            locked_parameter_count(prototype.as_ref()),
            &callee_facts,
            &addr_map,
            &str_pool,
            &function_tables,
            &stack_object_hints,
            &got_targets,
        );
        merge_dwarf_register_local_facts(
            &mut stack_facts,
            dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func_va)),
            &lf,
            &role_names,
            arch,
            cc,
            dwarf_type_env.as_ref(),
        );
        if style == "decbench" {
            crate::ir::exception_recover::recover_typed_handlers(&mut f, &exception_sites);
            crate::ir::exception_recover::mark_int_throws_with_address_map(&mut f, &addr_map);
            crate::ir::exception_recover::recover_throws(&mut f);
        }
        recognise_machine_frame(&mut f, cc);
        if let Some(field_map) = &field_map {
            crate::ir::pdb_fields::annotate_function_fields(&mut f, field_map);
        }
        let pdb_outer_name = pdb_public_map
            .get(&func_va)
            .filter(|name| !name.is_empty() && !name.starts_with("sub_"))
            .cloned();
        let text = if style == "decbench" {
            let (decl, width, exact_value_widths) = decbench_type_maps(
                &f,
                &lf_raw,
                &lf,
                prototype.as_ref().expect("DecBench prototype"),
                cc,
                &param_slots,
                &stack_facts.sizes,
                &stack_facts.source_types,
                &stack_facts.source_names,
                dwarf_type_env.as_ref(),
                &role_names,
                &definition_widths,
            );
            let dwarf_render_contract = dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func_va));
            let declared_render = dwarf_render_contract.and_then(dwarf_render_prototype);
            record_recovered_prototype_conflict(
                &f.name,
                func_va,
                "dwarf",
                declared_render.as_ref(),
                inferred_prototype.as_ref(),
                cc,
            );
            decbench_text(
                &f,
                &mut profiler,
                cfg_health,
                &exception_sites,
                Some(&decl),
                Some(&width),
                Some(&exact_value_widths),
                &readonly_data,
                prototype.as_ref(),
                declared_render.as_ref(),
                dwarf_render_contract.map(|contract| contract.parameter_names.as_slice()),
                dwarf_types.as_deref().unwrap_or(&[]),
                &stack_facts.source_types,
                &stack_facts.source_names,
                cc,
                &addr_map,
                &callee_facts.env,
                &data_symbols,
            )
        } else if style == "c" {
            let body = profiler.measure("render_c", || crate::ir::ast::render_c(&f));
            match pdb_outer_name {
                Some(name) => format!("// PDB: {}\n{}", name, body),
                None => body,
            }
        } else {
            match tm {
                Some(tm) => {
                    let renamed = remap_type_map(&tm, &f, cc, &param_slots);
                    profiler.measure("render_with_types", || render_with_types(&f, &renamed))
                }
                None => profiler.measure("render", || render(&f)),
            }
        };
        // Per function, from that function's own walk: in a set where one entry
        // hit a budget and the next did not, only the first is marked. See
        // `analysis::completeness`.
        let text = match crate::analysis::completeness::cfg_incompleteness_note(func, &budgets) {
            Some(note) => format!("{note}\n{text}"),
            None => text,
        };
        let name = resolve_outer_function_name_with_analyst(
            &func.name,
            func_va,
            &addr_map,
            analyst_names.as_ref(),
        );
        // The structured inventory a consumer needs to match our locals without
        // re-parsing the C. Computed from the prototype and the stack-promotion
        // facts already in scope, and filtered to names the render actually
        // emitted -- see `ir::recovered_variables`.
        let variables = crate::ir::recovered_variables::recovered_variables_from_llir(
            &text,
            prototype.as_ref(),
            &stack_facts,
            calling_convention_pointer_width(cc),
            &lf_raw,
        );
        list.append((
            name,
            func_va,
            text,
            func.size,
            variables_to_py(py, &variables)?,
        ))?;
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

use crate::ir::name_resolve::resolve_outer_function_name_with_analyst;

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
        let prepared = super::prepare_llir_for_lowering(
            &mut function,
            image,
            &[],
            CallConv::SysVAmd64,
            true,
            false,
            None,
            None,
            None,
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

    use super::{
        dwarf_return_hint, dwarf_return_hint_with_env, dwarf_stack_object_hints,
        merge_dwarf_register_local_facts, select_renderable_dwarf_local_facts,
        DwarfPrototypeContract,
    };
    use crate::debug::dwarf::{DwarfReturnType, DwarfStackBase, DwarfStackObject};
    use crate::ir::call_args::CallConv;
    use crate::ir::types::VReg;
    use crate::ir::types_recover::{TypeHint, TypeMap};
    use std::collections::HashMap;

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
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
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
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
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
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
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
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
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
    fn dwarf_register_range_selects_the_numbered_value_role() {
        use crate::core::binary::Arch;
        use crate::debug::dwarf::{DwarfRegisterLocal, DwarfRegisterLocation};
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

        let contract = DwarfPrototypeContract {
            function_name: None,
            prototyped: true,
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
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
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
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
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
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
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
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
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
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
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
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
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            return_type: DwarfReturnType::Void,
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
