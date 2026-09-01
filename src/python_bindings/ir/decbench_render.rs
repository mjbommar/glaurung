//! Preparing, verifying and rendering one function as DecBench C.

use super::callee_contracts::recovered_call_prototype;
use super::dwarf_contracts::calling_convention_pointer_width;
use super::pipeline::recognise_machine_frame;
use crate::ir::abi::machine_word_bytes;

/// Prepare, verify, and render one function as DecBench C.
///
/// The three stages are deliberately separate and in this order:
///
/// 1. [`crate::ir::ast::prepare_for_decbench`] performs the semantic AST
///    transformation (bare-return ABI register, parameter-spill coalescing,
///    copy-chain folding and source-level loop-form recovery) that used to happen
///    inside the renderer;
/// 2. [`crate::ir::guarded_switch::collapse_range_guards_with_types`] uses the
///    recovered integer widths to prove compiler range-check wrappers around
///    switches redundant when an untyped proof was deliberately insufficient;
/// 3. [`crate::ir::verify_defs::verify_before_render`] verifies the result — the
///    AST that is about to be printed, which is what makes the check trustworthy;
/// 4. the renderer formats it, and nothing else.
///
/// The verdict leaves the boundary through three channels, deliberately ranked by
/// how much they cost the consumer:
///
/// * ALWAYS: [`crate::ir::health::record_render_verification`] records it, so
///   `take_render_verification` can report an honest count for the run. The CLI
///   turns a non-empty report into one stderr line. Nothing about the emitted C
///   changes, which is why this channel can be unconditional.
/// * `GLAURUNG_PASS_HEALTH`: the same count appears as `undefined_uses` on the
///   `ready_to_render` event, beside the CFG fidelity counters.
/// * `GLAURUNG_VERIFY_DEFS`: each violation is spliced in as a
///   `// glaurung-verify:` comment line. Opt-in because the decbench render is an
///   artifact other tools parse and score.
///
/// Reporting rather than erroring is deliberate: a violation means the
/// decompilation of THAT function is untrustworthy, not that the analyst's whole
/// run should fail, and suppressing the body would destroy the only evidence of
/// what went wrong.
///
/// The type maps are computed by the caller from the UNPREPARED function, whose
/// names the recovered `TypeMap` keys were remapped against.
pub(super) fn select_renderable_dwarf_local_facts(
    local_types: &std::collections::HashMap<String, String>,
    local_names: &std::collections::HashMap<String, String>,
    dwarf_types: &[crate::debug::dwarf::DwarfType],
) -> (
    std::collections::HashMap<String, String>,
    std::collections::HashMap<String, String>,
) {
    let type_env = crate::ir::dwarf_type_env::DwarfTypeEnv::new(dwarf_types);
    let selected_types = local_types
        .iter()
        .filter(|(_name, c_type)| {
            crate::ir::ast::dwarf_prototype_type_is_renderable(c_type, false, &type_env)
        })
        .map(|(name, c_type)| (name.clone(), c_type.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    // A NAME WITHOUT A RENDERABLE TYPE IS NOT SAFE TO APPLY, and this pairing is
    // the guard. It reads like tidiness and is not. Measured 2026-08-28 on a
    // stripped `-O0` build, renaming the surviving local at `rbp-0xc` with no
    // type attached turned
    //
    //     int local_c;   local_c = 0;   ... return (unsigned int)(local_c);
    //
    // into
    //
    //     long running_total;   *(int *)(running_total) = 0;
    //
    // -- a pointer store synthesised from a scalar assignment, because the
    // local lost its recovered width along with its `local_` identity. With a
    // type supplied the same rename renders correctly. So an analyst rename of
    // a local is applied only alongside a type, which is a real constraint on
    // the feature rather than a bug in this filter; `apply_analyst_locals`
    // enforces the same rule at the other end so the pair never separates.
    let selected_names = local_names
        .iter()
        .filter(|(internal_name, _source_name)| selected_types.contains_key(*internal_name))
        .map(|(internal_name, source_name)| (internal_name.clone(), source_name.clone()))
        .collect();
    (selected_types, selected_names)
}

pub(super) fn decbench_text(
    f: &crate::ir::ast::Function,
    profiler: &mut crate::decompile::profile::FunctionProfiler,
    cfg_health: crate::ir::health::CfgHealth,
    exception_sites: &[crate::analysis::exception::ExceptionCallSite],
    decl: Option<&crate::ir::types_recover::TypeMap>,
    width: Option<&crate::ir::types_recover::TypeMap>,
    exact_value_widths: Option<&std::collections::HashMap<String, u8>>,
    readonly_data: &crate::ir::readonly_fold::ReadonlyData,
    recovered_prototype: Option<&crate::ir::types_recover::RecoveredPrototype>,
    declared_prototype: Option<&crate::ir::call_contracts::CallPrototype>,
    dwarf_types: &[crate::debug::dwarf::DwarfType],
    dwarf_local_types: &std::collections::HashMap<String, String>,
    dwarf_local_names: &std::collections::HashMap<String, String>,
    cc: crate::ir::call_args::CallConv,
    addr_map: &std::collections::HashMap<u64, String>,
    symbol_env: &crate::ir::symbol_env::SymbolEnv,
    data_symbols: &crate::ir::data_symbols::DataSymbols,
) -> String {
    // Install the program-level callee records for this render, and clear them
    // when it ends. The renderer used to do the clearing, which made it the
    // owner of a thread-local it never installed: a formatting projection was
    // mutating caller state on the way out. Install and release now happen in
    // the same function, so the renderer's only remaining relationship with the
    // environment is to read it.
    crate::ir::symbol_env::install(symbol_env.clone());
    // Same install/release discipline as the callee environment above: the
    // renderer reads these names and never owns them.
    crate::ir::ast::install_dec_global_names(data_symbols.clone());
    let text = decbench_text_with_installed_environment(
        f,
        profiler,
        cfg_health,
        exception_sites,
        decl,
        width,
        exact_value_widths,
        readonly_data,
        recovered_prototype,
        declared_prototype,
        dwarf_types,
        dwarf_local_types,
        dwarf_local_names,
        cc,
        addr_map,
    );
    crate::ir::symbol_env::clear();
    crate::ir::ast::clear_dec_global_names();
    text
}

/// The prepare/verify/render body of [`decbench_text`], with the program-level
/// callee environment already installed by its caller.
#[allow(clippy::too_many_arguments)]
fn decbench_text_with_installed_environment(
    f: &crate::ir::ast::Function,
    profiler: &mut crate::decompile::profile::FunctionProfiler,
    cfg_health: crate::ir::health::CfgHealth,
    exception_sites: &[crate::analysis::exception::ExceptionCallSite],
    decl: Option<&crate::ir::types_recover::TypeMap>,
    width: Option<&crate::ir::types_recover::TypeMap>,
    exact_value_widths: Option<&std::collections::HashMap<String, u8>>,
    readonly_data: &crate::ir::readonly_fold::ReadonlyData,
    recovered_prototype: Option<&crate::ir::types_recover::RecoveredPrototype>,
    declared_prototype: Option<&crate::ir::call_contracts::CallPrototype>,
    dwarf_types: &[crate::debug::dwarf::DwarfType],
    dwarf_local_types: &std::collections::HashMap<String, String>,
    dwarf_local_names: &std::collections::HashMap<String, String>,
    cc: crate::ir::call_args::CallConv,
    addr_map: &std::collections::HashMap<u64, String>,
) -> String {
    let output_kind = recovered_prototype.map_or(
        crate::ir::types_recover::RecoveredOutputKind::Unknown,
        crate::ir::types_recover::RecoveredPrototype::output_kind,
    );
    let (dwarf_local_types, dwarf_local_names) =
        select_renderable_dwarf_local_facts(dwarf_local_types, dwarf_local_names, dwarf_types);
    let protected_locals = dwarf_local_names
        .keys()
        .cloned()
        .collect::<std::collections::HashSet<_>>();
    let mut prepared = profiler.measure("prepare_for_decbench", || {
        let mut prepared = crate::ir::ast::prepare_for_decbench_with_output_and_protected_locals(
            f,
            output_kind,
            &protected_locals,
            calling_convention_pointer_width(cc),
        );
        // Preparation deletes proof-dead caller-saved register zeroing from
        // hardened GCC epilogues.  Only at this point can the x86 frame owner
        // see the adjacent balanced x87 scrub and stack teardown as one exact
        // machine-only suffix.  Run the idempotent recogniser at this semantic
        // boundary, then repeat the narrow joined-return fold it may unblock.
        // The renderer below remains formatting-only.
        recognise_machine_frame(&mut prepared, cc);
        crate::ir::ast::fold_exhaustive_if_returns(&mut prepared);
        crate::ir::ast::remove_redundant_return_constant_assignments(&mut prepared.body);
        // Preparation is also where a PC-relative address arithmetic sequence
        // finally becomes an absolute address. On AArch64 the stack guard is reached
        // through its GOT slot (`adrp`/`ldr`/`ldr`), so at the earlier
        // `resolve_names` the slot was still `%x0 + 0xfd8` and no name could attach;
        // only now is it the constant an `R_AARCH64_GLOB_DAT` relocation names.
        // Re-resolve, then let the canary pass recognise it — without this the
        // guard renders as a portable zero-filled object that the recovered C
        // dereferences, and every `-fstack-protector` function takes SIGSEGV.
        //
        // Folding first is what makes the address a single constant: preparation is
        // where the `adrp` page and the `add` of the low 12 bits finally meet in one
        // expression, and until they are folded there is no VA for `resolve_names`
        // to look up and no address for the renderer to back with a portable object.
        // `read_counter` emitted `*(int *)(0x20000 + 28)` — a dereference of a raw
        // original-image address, which is a wild pointer once recompiled.
        crate::ir::const_fold::fold_constants(&mut prepared);
        crate::ir::name_resolve::resolve_names(&mut prepared, addr_map);
        crate::ir::canary::recognise_canary(&mut prepared);
        // Source-level preparation folds GCC's multi-statement reload/sub/flag
        // sequence into a direct comparison of the promoted canary slot. Re-run
        // the idempotent canary pass here so the earlier collapsed save cannot
        // leave that now-recognisable check reading an uninitialised C local.
        crate::ir::canary::collapse_canary_save(&mut prepared);
        prepared
    });
    // From here to the verification boundary every semantic step is a NAMED pass.
    //
    // Naming is not cosmetic. `run_ast_passes` has always announced each of its
    // passes; this tail did not, so seventeen AST-mutating transforms ran between
    // `prepare_for_decbench` and `ready_to_render` with no boundary between them.
    // The consequence is concrete: `tools/pass_health_report.py` attributes the
    // FIRST pass at which a counter moves, so a newly introduced undefined read
    // anywhere in this tail was reported against `ready_to_render` — the boundary
    // that observes the damage rather than the pass that caused it. With the
    // passes named, the same report blames the transform.
    //
    // `pass!` is for a transform that rewrites the AST: it is profiled, dumped
    // under `GLAURUNG_DUMP_PASSES`, and health-traced. `refine!` is for a
    // transform that only sharpens a `TypeMap` — the AST is unchanged, so a health
    // event would repeat the previous one, and only the timing is worth recording.
    macro_rules! pass {
        ($name:expr, $operation:expr) => {{
            let result = profiler.measure($name, || $operation);
            if std::env::var_os("GLAURUNG_DUMP_PASSES").is_some() {
                eprintln!(
                    "\n===== after {} =====\n{}",
                    $name,
                    crate::ir::ast::render(&prepared)
                );
            }
            crate::ir::health::trace_pass($name, &prepared, cfg_health);
            result
        }};
    }
    macro_rules! refine {
        ($name:expr, $operation:expr) => {
            profiler.measure($name, || $operation)
        };
    }

    if std::env::var_os("GLAURUNG_DUMP_PASSES").is_some() {
        eprintln!(
            "\n===== after prepare_for_decbench =====\n{}",
            crate::ir::ast::render(&prepared)
        );
    }
    crate::ir::health::trace_pass("prepare_for_decbench", &prepared, cfg_health);
    // Preparation exposes the actual expression dataflow (notably parameter
    // spill coalescing and folded returns), so only now can high-half uses and
    // wide return definitions safely override a misleading narrow sub-register
    // type hint.
    let mut refined_decl = decl.cloned();
    let mut refined_width = width.cloned();
    if let Some(tm) = refined_decl.as_mut() {
        refine!("refine_decbench_abi_widths", {
            crate::ir::ast::refine_decbench_abi_widths_with_value_widths(
                &prepared,
                tm,
                exact_value_widths,
            );
            crate::ir::high_variables::refine_pointer_high_variables(&prepared, tm);
        });
    }
    if let Some(tm) = refined_decl.as_mut() {
        pass!(
            "coalesce_loop_entry_copies",
            crate::ir::latch_predicate::coalesce_loop_entry_copies(
                &mut prepared,
                &protected_locals,
                tm,
            )
        );
        pass!(
            "coalesce_source_loop_updates",
            crate::ir::latch_predicate::coalesce_source_loop_updates(
                &mut prepared,
                &protected_locals,
                tm,
                exact_value_widths,
            )
        );
    }
    if let Some(tm) = refined_width.as_mut() {
        refine!(
            "refine_decbench_abi_widths_for_width_map",
            crate::ir::ast::refine_decbench_abi_widths_with_value_widths(
                &prepared,
                tm,
                exact_value_widths,
            )
        );
    }
    if let Some(tm) = refined_decl.as_ref() {
        pass!(
            "propagate_adjacent_typed_promoted_values",
            crate::ir::copy_prop::propagate_adjacent_typed_promoted_values(&mut prepared, tm)
        );
        pass!(
            "fold_typed_declared_views",
            crate::ir::const_fold::fold_typed_declared_views(&mut prepared, tm)
        );
        pass!(
            "fold_consumed_extensions",
            crate::ir::typed_simplify::fold_consumed_extensions(&mut prepared, tm)
        );
        pass!(
            "fold_typed_comparison_extensions",
            crate::ir::const_fold::fold_typed_comparison_extensions(&mut prepared, tm)
        );
        pass!(
            "fold_constants_after_typed_folds",
            crate::ir::const_fold::fold_constants(&mut prepared)
        );
    }
    pass!("fold_guarded_readonly_lookups", {
        crate::ir::readonly_fold::fold_guarded_readonly_lookups(&mut prepared, readonly_data);
        // Read-only folding can turn an image load into a literal after the main
        // expression pipeline has already run. Re-propagate and fold immediately so
        // consumers such as packed byte-table permutations see the literal index
        // rather than rendering a dynamic 16-way lookup for a compiler-emitted mask.
        crate::ir::copy_prop::propagate_copies(&mut prepared);
        crate::ir::const_fold::fold_constants(&mut prepared);
    });
    if let Some(tm) = refined_decl.as_ref() {
        pass!(
            "collapse_range_guards_with_types",
            crate::ir::guarded_switch::collapse_range_guards_with_types(&mut prepared, tm)
        );
    }
    // A typed range proof may have synthesized an exhaustive switch default,
    // exposing the same exact switch-result join as the untyped preparation
    // path. Fold it before verification and rendering as well.
    pass!(
        "fold_exhaustive_switch_returns",
        crate::ir::ast::fold_exhaustive_switch_returns(&mut prepared)
    );
    if let Some(tm) = refined_decl.as_ref() {
        pass!(
            "fold_typed_return_abi_extensions",
            crate::ir::ast::fold_typed_return_abi_extensions(&mut prepared, tm)
        );
        // Declarations are recovered at true machine width, so a value read in a
        // wider context needs the extension the hardware performed made explicit.
        // Runs before verification and rendering; it changes no definition, use,
        // or value identity.
        pass!(
            "insert_widening_casts_for_machine_width",
            crate::ir::widen::insert_widening_casts_for_machine_width(
                &mut prepared,
                tm,
                machine_word_bytes(cc),
            )
        );
    }
    let decl = refined_decl.as_ref();
    let width = refined_width.as_ref();
    // Call specifications belong to concrete AST calls, not to renderer-local
    // symbol guesses. Refresh them after every expression/type refinement so
    // string folding, promoted objects, and pointer facts are represented on
    // the exact call boundary the verifier and C renderer consume.
    pass!(
        "refine_call_site_specs",
        crate::ir::call_contracts::refine_call_site_specs(&mut prepared, decl)
    );
    let mut dwarf_pointer_types = pass!(
        "annotate_function_fields",
        crate::ir::dwarf_fields::annotate_function_fields(
            &mut prepared,
            declared_prototype,
            dwarf_types,
            calling_convention_pointer_width(cc),
        )
    );
    for (internal_name, source_name) in &dwarf_local_names {
        let internal = crate::ir::types::VReg::phys(internal_name);
        if let Some(pointer_type) = dwarf_pointer_types.remove(&internal) {
            dwarf_pointer_types.insert(crate::ir::types::VReg::phys(source_name), pointer_type);
        }
    }
    pass!(
        "apply_authoritative_local_names",
        crate::ir::naming::apply_authoritative_local_names(&mut prepared, &dwarf_local_names)
    );
    let rendered_local_types = dwarf_local_types
        .iter()
        .map(|(internal_name, c_type)| {
            (
                dwarf_local_names
                    .get(internal_name)
                    .unwrap_or(internal_name)
                    .clone(),
                c_type.clone(),
            )
        })
        .collect::<std::collections::HashMap<_, _>>();
    pass!(
        "recover_typed_handlers",
        crate::ir::exception_recover::recover_typed_handlers(&mut prepared, exception_sites)
    );
    pass!(
        "recover_throws",
        crate::ir::exception_recover::recover_throws(&mut prepared)
    );
    pass!(
        "prune_unobserved_promoted_object_stores",
        crate::ir::dead_stores::prune_unobserved_promoted_object_stores(&mut prepared)
    );
    // A result the ABI splits across two register BANKS becomes the whole-object
    // load its declared class requires. Deliberately the LAST semantic pass:
    // the object's members must survive store pruning above (they are what the
    // second bank's bytes are), and the rewrite reads a body nothing further
    // will rewrite. See `crate::ir::callee_return_bank`.
    if output_kind == crate::ir::types_recover::RecoveredOutputKind::Direct {
        pass!(
            "compose_bank_returns",
            crate::ir::callee_return_bank::compose_bank_returns(
                &mut prepared,
                cc,
                recovered_prototype
            )
        );
    }
    crate::ir::health::trace_pass("ready_to_render", &prepared, cfg_health);
    // THE pre-render verification boundary. Every semantic transform is behind us
    // and the renderer below is formatting-only, so this AST is exactly what is
    // printed. The verdict is RECORDED, not merely computed: an undefined read
    // means the emitted C reads a value the machine never produced, and a proof
    // that fails into a dropped `Vec` is a wrong-code bug nobody can count.
    let verification = profiler.measure("verify_before_render", || {
        crate::ir::verify_defs::verify_before_render(&prepared)
    });
    crate::ir::health::record_render_verification(&verification);
    let violations = verification.violations;
    let recovered_render_prototype = if declared_prototype.is_none() {
        recovered_prototype.and_then(|prototype| {
            let mut machine_prototype = recovered_call_prototype(prototype, cc);
            machine_prototype.return_type =
                if output_kind == crate::ir::types_recover::RecoveredOutputKind::Void {
                    "void"
                } else {
                    crate::ir::ast::infer_return_ctype(&prepared.body, decl)
                }
                .to_string();
            if let Some(types) = decl {
                for (slot, c_type) in machine_prototype.parameter_types.iter_mut().enumerate() {
                    if let Some(hint) =
                        types.get(&crate::ir::types::VReg::phys(format!("arg{slot}")))
                    {
                        *c_type = crate::ir::types_recover::c_type_for_hint_with_pointer_width(
                            hint,
                            calling_convention_pointer_width(cc),
                        )
                        .to_string();
                    }
                }
            }
            let refined = crate::ir::call_contracts::refine_opaque_parameter_types_from_calls(
                &prepared,
                &machine_prototype,
            );
            (refined != machine_prototype).then_some(refined)
        })
    } else {
        None
    };
    let render_prototype = declared_prototype.or(recovered_render_prototype.as_ref());
    // A function whose OWN result is a proven two-register INTEGER aggregate
    // cannot be declared at one machine word: `struct bv195_quad` is not a
    // renderable source spelling, so the signature fell back to `unsigned long`
    // and the second eightbyte — members `c` and `d`, computed correctly into
    // `rdx` — was returned by nothing. The double-word integer type has exactly
    // that storage contract, and it is the SAME spelling `recovered_call_prototype`
    // already gives every CALLER of this function, so both sides of the boundary
    // agree by construction.
    //
    // Gated on the PREPARED body, not on the class alone: the rewrite is all or
    // nothing and may decline (a `return` with no proven reaching high half),
    // and a later transform could yet have rewritten a composed return. The
    // declaration and the value are one decision, so both read the same AST.
    let pair_render_prototype = recovered_prototype
        .filter(|prototype| {
            prototype.return_class() == crate::ir::abi::ReturnClass::IntegerPair
                && output_kind == crate::ir::types_recover::RecoveredOutputKind::Direct
                && crate::ir::callee_return_pair::returns_are_pair_composed(&prepared.body, cc)
        })
        .and_then(|_| crate::ir::callee_return_pair::pair_return_c_type(cc))
        .map(|return_type| {
            let mut prototype = render_prototype.cloned().unwrap_or_else(|| {
                crate::ir::call_contracts::CallPrototype {
                    return_type: String::new(),
                    parameter_types: Vec::new(),
                    variadic: false,
                    authority: crate::ir::call_contracts::CallPrototypeAuthority::Recovered,
                }
            });
            prototype.return_type = return_type.to_string();
            prototype
        });
    // The one-eightbyte sibling of the case above, and the reason it needs
    // saying at all: an aggregate small enough to fit ONE result register was
    // left to the ordinary path, and the ordinary path takes the return type
    // from the returned EXPRESSION. `struct hfa197_tagged { float; int32_t; }`
    // is eight bytes whose low half holds a `float`, so the inferred type was
    // `float` and the declaration returned it in `xmm0` — where System V's
    // class merge puts the whole object in `rax`. The class is what decides the
    // bank, so the class is what declares it.
    //
    // Read from the DECLARED type, never from machine evidence: only DWARF can
    // say that a result register holds an aggregate rather than a scalar, which
    // is the same rule `declared_return_class` states for every other class.
    let single_render_prototype = (output_kind
        == crate::ir::types_recover::RecoveredOutputKind::Direct)
        .then(|| crate::ir::dwarf_type_env::DwarfTypeEnv::new(dwarf_types))
        .and_then(|type_env| {
            let declared = declared_prototype?;
            let return_type = crate::ir::return_class::single_class_aggregate_return_c_type(
                &declared.return_type,
                cc,
                Some(&type_env),
            )?;
            let mut prototype = declared.clone();
            prototype.return_type = return_type.to_string();
            Some(prototype)
        });
    // The three classes one bank further out than `pair_render_prototype`'s.
    // `xmm0:xmm1`, `rax`+`xmm0` and an AAPCS64 HFA have no builtin C spelling,
    // so the declaration is a synthesised tag — the SAME tag
    // `recovered_call_prototype` already gives every caller of this function,
    // which is what makes the two sides of the boundary agree.
    //
    // Gated on the PREPARED body for the same reason the pair is: the rewrite
    // is all or nothing and declines whenever the result does not demonstrably
    // live in one frame object, and a signature that outran it would declare a
    // sixteen-byte result over a body handing back eight.
    let bank_render_prototype = (output_kind
        == crate::ir::types_recover::RecoveredOutputKind::Direct)
        .then(|| {
            crate::ir::callee_return_bank::bank_return_c_type(
                &prepared.body,
                cc,
                recovered_prototype,
            )
        })
        .flatten()
        .map(|return_type| {
            let mut prototype = render_prototype.cloned().unwrap_or_else(|| {
                crate::ir::call_contracts::CallPrototype {
                    return_type: String::new(),
                    parameter_types: Vec::new(),
                    variadic: false,
                    authority: crate::ir::call_contracts::CallPrototypeAuthority::Recovered,
                }
            });
            prototype.return_type = return_type.to_string();
            prototype
        });
    let render_prototype = pair_render_prototype
        .as_ref()
        .or(bank_render_prototype.as_ref())
        .or(single_render_prototype.as_ref())
        .or(render_prototype);
    let body = profiler.measure("render_decbench", || {
        crate::ir::ast::render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types(
            &prepared,
            decl,
            width,
            output_kind,
            render_prototype,
            dwarf_types,
            calling_convention_pointer_width(cc),
            &dwarf_pointer_types,
            &rendered_local_types,
        )
    });
    if violations.is_empty() {
        return body;
    }
    tracing::debug!(
        function = %prepared.name,
        count = violations.len(),
        "def-before-use verification found violations"
    );
    // The comments are INSTRUMENTATION, not decompiler output, so they are opt-in.
    // Emitted unconditionally they end up in whatever consumes this render — including
    // the artifact submitted to an external benchmark, where each one is a note
    // announcing our own bug inside the C we are asking someone to score. The fixture
    // gate's structural lane opts in (see `structural.decompile_all`) so its ratchet
    // still sees every violation.
    if std::env::var_os("GLAURUNG_VERIFY_DEFS").is_none() {
        return body;
    }
    crate::ir::verify_defs::splice_verify_comments(&body, &violations)
}
