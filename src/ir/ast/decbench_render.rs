//! The DecBench parseable-C front door: the six `render_decbench*` entry points.
//!
//! These are the public boundary of the C renderer. The contract they hold --
//! the emitted translation-unit fragment *parses* -- and the reasons for each
//! synthesised construct are stated in the `-- DecBench parseable-C renderer --`
//! notes in the parent module, immediately above the identifier-collection and
//! type-spelling helpers these functions consume.
//!
//! The five short entry points are pure argument defaulting; all of the work is
//! in [`render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types`],
//! which installs the render-scoped thread-locals and the
//! [`DeclarationPlan`](super::DeclarationPlan), emits the file-scope and
//! block-scope declarations, and then delegates every statement to
//! [`write_stmt_dec`](super::write_stmt_dec) in `dec_render`. The DWARF-derived
//! type predicates it consults live in the sibling
//! [`dwarf_render_types`](super::dwarf_render_types) module.

use std::fmt::Write;

use crate::ir::call_contracts::{CallPrototype, CallPrototypeAuthority};
use crate::ir::types::VReg;
use crate::ir::types_recover::TypeMap;

use super::dwarf_render_types::{
    collision_safe_local_aggregate_type, dwarf_prototype_type_is_renderable,
    renderable_dwarf_structs, source_prototype_forward_declarations,
    source_type_with_complete_struct_alias,
};
use super::{
    callee_display_name, collect_idents_stmt, dec_global_name, dec_global_object_bytes, dec_plan,
    insert_local, parse_arg_index, recover_named_call_prototypes, sanitize_c_ident, write_stmt_dec,
    DecIdents, DeclarationInputs, DeclarationPlan, Function, LocalDeclaration, DEC_GLOBAL_ADDRS,
    DEC_NAMED_CALL_PROTOTYPES, DEC_PLAN, DEC_POINTER_WIDTH, DEC_RENDERABLE_STRUCTS,
    DEC_SOURCE_LOCALS, DEC_STRUCT_PTR_TYPES, DEC_WIDE_LOCALS,
};

/// Render `f` as parseable C for the DecBench harness (and any consumer that
/// needs valid C rather than the register-level `render_c` view). See the
/// module-level notes above this function for the contract and rationale.
///
/// Untyped entry point (blanket `long`) — used by unit tests and any consumer
/// that has no recovered types.
/// Untyped DecBench rendering of an already-prepared function (see
/// [`prepare_for_decbench`]). Formatting only.
pub fn render_decbench(f: &Function) -> String {
    render_decbench_typed(f, None, None)
}

/// Render `f` as parseable C for DecBench, typing the return value and
/// arguments from `tm` (a TypeMap already remapped to the AST's role names —
/// `arg0`, `ret`, …). Locals stay `long` for now (their TypeMap keys do not
/// survive register renaming; a later pass will type stack slots by size).
/// Render an already-prepared function as DecBench C. FORMATTING ONLY: this must
/// not change definitions, uses, control flow, or value identities — run
/// [`prepare_for_decbench`] first (the pipeline does).
pub fn render_decbench_typed(
    f: &Function,
    tm: Option<&TypeMap>,
    width_tm: Option<&TypeMap>,
) -> String {
    render_decbench_typed_with_output(
        f,
        tm,
        width_tm,
        crate::ir::types_recover::RecoveredOutputKind::Unknown,
    )
}

/// Typed DecBench renderer with an explicit recovered output contract.
pub fn render_decbench_typed_with_output(
    f: &Function,
    tm: Option<&TypeMap>,
    width_tm: Option<&TypeMap>,
    output_kind: crate::ir::types_recover::RecoveredOutputKind,
) -> String {
    render_decbench_typed_with_output_and_prototype(f, tm, width_tm, output_kind, None)
}

/// Typed DecBench renderer with an optional authoritative source prototype.
///
/// Machine-code inference remains responsible for the body and storage model.
/// When DWARF supplies an exactly arity-compatible scalar/pointer prototype,
/// retain its named C types at the function boundary. By-value aggregates are
/// deliberately rejected until their multi-eightbyte ABI reconstruction is
/// represented in the middle IR.
pub fn render_decbench_typed_with_output_and_prototype(
    f: &Function,
    tm: Option<&TypeMap>,
    width_tm: Option<&TypeMap>,
    output_kind: crate::ir::types_recover::RecoveredOutputKind,
    declared_prototype: Option<&CallPrototype>,
) -> String {
    render_decbench_typed_with_output_and_prototype_and_dwarf_types(
        f,
        tm,
        width_tm,
        output_kind,
        declared_prototype,
        &[],
        8,
        &std::collections::HashMap::new(),
    )
}

/// Typed DecBench renderer with optional authoritative source aggregates.
pub fn render_decbench_typed_with_output_and_prototype_and_dwarf_types(
    f: &Function,
    tm: Option<&TypeMap>,
    width_tm: Option<&TypeMap>,
    output_kind: crate::ir::types_recover::RecoveredOutputKind,
    declared_prototype: Option<&CallPrototype>,
    dwarf_types: &[crate::debug::dwarf::DwarfType],
    pointer_width: u8,
    dwarf_pointer_types: &std::collections::HashMap<VReg, String>,
) -> String {
    render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types(
        f,
        tm,
        width_tm,
        output_kind,
        declared_prototype,
        dwarf_types,
        pointer_width,
        dwarf_pointer_types,
        &std::collections::HashMap::new(),
    )
}

/// Typed DecBench renderer with exact source spellings for promoted locals.
pub fn render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types(
    f: &Function,
    tm: Option<&TypeMap>,
    width_tm: Option<&TypeMap>,
    output_kind: crate::ir::types_recover::RecoveredOutputKind,
    declared_prototype: Option<&CallPrototype>,
    dwarf_types: &[crate::debug::dwarf::DwarfType],
    pointer_width: u8,
    dwarf_pointer_types: &std::collections::HashMap<VReg, String>,
    dwarf_local_types: &std::collections::HashMap<String, String>,
) -> String {
    let source_locals = dwarf_local_types
        .keys()
        .cloned()
        .collect::<std::collections::HashSet<String>>();
    DEC_SOURCE_LOCALS.with(|locals| *locals.borrow_mut() = source_locals.clone());
    DEC_POINTER_WIDTH.with(|width| width.set(pointer_width));
    let dwarf_type_env = crate::ir::dwarf_type_env::DwarfTypeEnv::new(dwarf_types);
    let mut ids = DecIdents::default();
    for s in &f.body {
        collect_idents_stmt(s, &mut ids);
    }
    // A debug local can be optimized into a constant or a different induction
    // variable and therefore have no surviving AST use. Its authoritative
    // source declaration is still useful and safe to emit; unlike an invented
    // value, an unused C local changes neither control flow nor dataflow.
    let mut declaration_only_locals = dwarf_local_types
        .keys()
        .filter(|name| crate::ir::naming::valid_authoritative_local_name(name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    declaration_only_locals.sort();
    for local in declaration_only_locals {
        insert_local(&mut ids, local);
    }
    DEC_GLOBAL_ADDRS
        .with(|addresses| *addresses.borrow_mut() = ids.global_addresses.keys().copied().collect());
    DEC_WIDE_LOCALS.with(|locals| *locals.borrow_mut() = ids.wide_locals.iter().cloned().collect());

    let name = sanitize_c_ident(&f.name);
    // Signature arity: the highest `argN` referenced in the body, *or* recovered
    // in the type map — whichever is larger. Types are recovered from the full
    // pre-structuring IR, so an argument whose only uses were dropped by dead-code
    // elimination (e.g. a `switch` whose cases were lost to `goto`s) still has a
    // type-map entry and must still appear in the signature (an ABI/prototype
    // property, not a "still referenced after DCE" one).
    let mut arg_count = ids.max_arg.map(|m| m + 1).unwrap_or(0);
    if let Some(tm) = tm {
        for (v, _) in tm.iter() {
            if let VReg::Phys(n) = v {
                if let Some(idx) = parse_arg_index(n) {
                    arg_count = arg_count.max(idx + 1);
                }
            }
        }
    }
    let declared_prototype = declared_prototype.filter(|prototype| {
        prototype.parameter_types.len() == arg_count
            && dwarf_prototype_type_is_renderable(&prototype.return_type, true, &dwarf_type_env)
            && ((output_kind == crate::ir::types_recover::RecoveredOutputKind::Void
                && prototype.return_type == "void")
                || (output_kind != crate::ir::types_recover::RecoveredOutputKind::Void
                    && prototype.return_type != "void"))
    });
    let all_declared_parameters_renderable = declared_prototype.is_some_and(|prototype| {
        prototype
            .parameter_types
            .iter()
            .all(|c_type| dwarf_prototype_type_is_renderable(c_type, false, &dwarf_type_env))
    });

    let aggregate_layouts = renderable_dwarf_structs(
        declared_prototype,
        dwarf_types,
        &dwarf_type_env,
        pointer_width,
    );
    let complete_structs = aggregate_layouts
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    // Complete layouts already emit `typedef struct T T;`. Give an explicit
    // opaque `struct T *`/`union T *` source contract the same standalone alias
    // so parameter spelling does not depend on whether every field layout was
    // safely renderable.
    let mut source_type_aliases = complete_structs.clone();
    if let Some(prototype) = declared_prototype {
        source_type_aliases.extend(
            std::iter::once(&prototype.return_type)
                .chain(&prototype.parameter_types)
                .filter_map(|c_type| dwarf_type_env.aggregate_pointer(c_type))
                .map(|pointer| pointer.source_name.to_string()),
        );
    }
    source_type_aliases.extend(
        dwarf_local_types
            .values()
            .filter_map(|c_type| dwarf_type_env.aggregate_pointer(c_type))
            .map(|pointer| pointer.source_name.to_string()),
    );
    // Callee declarations come from the program-level environment, and a record
    // may spell an aggregate this function never otherwise mentions. Those tags
    // are forward-declared (see the emission below) rather than defined: an
    // incomplete type is all a pointer parameter needs, so the declaration
    // never depends on recovering the aggregate's layout.
    //
    // The alias rewrite that turns `struct X *` into the typedef spelling is
    // deliberately NOT applied to these declarations. `typedef struct X X;`
    // makes the two spellings one type wherever both are visible, so the
    // defining function's `X *` and a caller's `struct X *` already agree —
    // and the tag spelling needs only a forward declaration, while the typedef
    // spelling would need the definition.
    let named_call_declarations = recover_named_call_prototypes(&f.body, &name);
    let callee_tag_declarations = named_call_declarations
        .keys()
        .filter_map(|callee| crate::ir::symbol_env::lookup(callee))
        .flat_map(|record| record.required_structs)
        .collect::<std::collections::BTreeSet<_>>();
    DEC_RENDERABLE_STRUCTS.with(|selected| *selected.borrow_mut() = complete_structs.clone());
    let struct_pointer_types = {
        let mut exact = std::collections::HashMap::new();
        for (register, type_name) in dwarf_pointer_types {
            if !complete_structs.contains(type_name) {
                continue;
            }
            if let VReg::Phys(name) = register {
                let c_type = format!("{type_name} *");
                exact.insert(name.clone(), c_type.clone());
                exact.insert(sanitize_c_ident(name), c_type);
            }
        }
        for (name, c_type) in dwarf_local_types {
            if dwarf_type_env.aggregate_pointer(c_type).is_none()
                || !dwarf_prototype_type_is_renderable(c_type, false, &dwarf_type_env)
            {
                continue;
            }
            let c_type = collision_safe_local_aggregate_type(name, c_type, &dwarf_type_env)
                .unwrap_or_else(|| {
                    source_type_with_complete_struct_alias(c_type, &source_type_aliases)
                });
            exact.insert(name.clone(), c_type.clone());
            exact.insert(sanitize_c_ident(name), c_type);
        }
        exact
    };
    DEC_STRUCT_PTR_TYPES.with(|selected| *selected.borrow_mut() = struct_pointer_types.clone());

    let mut out = String::new();
    // Provenance as a C comment (valid, and the harness maps by address anyway).
    let _ = writeln!(out, "// glaurung: {} @ 0x{:x}", f.name, f.entry_va);
    let mut source_declarations = std::collections::BTreeSet::new();
    if let Some(prototype) = declared_prototype {
        source_declarations.extend(source_prototype_forward_declarations(
            prototype,
            &complete_structs,
            &dwarf_type_env,
        ));
    }
    for (local_name, c_type) in dwarf_local_types {
        if let Some(pointer) = dwarf_type_env.aggregate_pointer(c_type) {
            if !complete_structs.contains(pointer.source_name) {
                if collision_safe_local_aggregate_type(local_name, c_type, &dwarf_type_env)
                    .is_some()
                {
                    let keyword = match pointer.kind {
                        crate::debug::dwarf::DwarfTypeKind::Struct => "struct",
                        crate::debug::dwarf::DwarfTypeKind::Union => "union",
                        crate::debug::dwarf::DwarfTypeKind::Enum
                        | crate::debug::dwarf::DwarfTypeKind::Typedef => {
                            unreachable!("aggregate pointers resolve only to struct or union")
                        }
                    };
                    source_declarations.insert(format!("{keyword} {};", pointer.tag_name));
                } else {
                    source_declarations.insert(dwarf_type_env.forward_declaration(pointer));
                }
            }
        } else if let Some(declaration) = dwarf_type_env.typedef_declaration(c_type) {
            source_declarations.insert(declaration);
        }
    }
    for declaration in source_declarations {
        let _ = writeln!(out, "{declaration}");
    }
    // Tags named by the callee declarations below, at FILE scope.
    //
    // Not inside the body, which is where they were first emitted: a tag
    // declared at block scope is a *new, distinct* type scoped to that block
    // (C11 6.2.1p4). Two functions each declaring `struct varbuf;` in their own
    // bodies therefore got two incompatible `struct varbuf`s, and every
    // `extern void varbuf_end_str(struct varbuf *);` conflicted with every
    // other — with gcc printing `have 'void(struct varbuf *)'` against a
    // `previous declaration ... with type 'void(struct varbuf *)'`, identical
    // text, 46 times for that one symbol. At file scope there is one tag and
    // the declarations agree.
    //
    // DecBench's per-function split discards this line along with the struct
    // definitions already emitted here; the sliced fragment then declares the
    // tag in parameter-list scope, which warns but compiles.
    for declaration in &callee_tag_declarations {
        let _ = writeln!(out, "{declaration}");
    }
    for (name, layout) in &aggregate_layouts {
        let guard = format!("GLAURUNG_STRUCT_{name}_DEFINED");
        let _ = writeln!(out, "#ifndef {guard}");
        let _ = writeln!(out, "#define {guard}");
        let _ = writeln!(out, "typedef struct {name} {name};");
        let _ = writeln!(out, "struct {name} {{");
        for field in &layout.fields {
            let _ = writeln!(out, "    {} {};", field.c_type, field.name);
        }
        out.push_str("};\n");
        out.push_str("#endif\n");
    }
    // A direct load/store whose image VA survived readonly-data folding refers
    // to writable static storage. The original VA is meaningless after this C
    // fragment is linked into a new shared object, so give it a portable,
    // zero-initialized identity. Repeated tentative declarations of the same
    // internal-linkage object in a combined helper/root translation unit denote
    // one object, preserving sharing between decompiled sibling functions.
    // The attribute leads the declaration deliberately. DecBench's recompile
    // harness runs `fixup::sanitize_tokens` over every unit before compiling it,
    // and its `_ARRAY_RET` rule — which exists to repair array-return-type
    // declarations — is anchored at the start of a line and matches
    // `<type> <name>[N] <ident>(`. The trailing-attribute spelling hits it:
    //
    //     static unsigned char g[16] __attribute__((aligned(16)));
    //  -> static unsigned char g *__attribute__((aligned(16)));   // syntax error
    //
    // Valid C in, uncompilable C out, and the diagnostic points at our line, so
    // it reads as our defect. Leading the attribute is byte-identical through
    // the sanitizer and identical to the compiler. Verified directly against
    // `decbench.metrics.fixup.sanitize_tokens`.
    //
    // The indented, function-local spelling below is safe: `_ARRAY_RET` is
    // `^`-anchored, so leading whitespace already prevents the match.
    //
    // THIS DEFINITION IS NOT OPTIONAL, AND IT IS NOT A `byte_match` LEVER.
    // Both claims have been made, on the strength of a real GCC behaviour seen
    // through a harness that is not DecBench's. Measured 2026-08-04 on the
    // frozen 250-function holdout; do not re-litigate without redoing this:
    //
    //   * DecBench never compiles this line. `evalkit ingest` slices the
    //     submitted unit with `decompilers.dockerized.split_c_functions`, which
    //     starts each snippet at the `_FUNC_DEF_RE` SIGNATURE line. Census over
    //     the whole holdout: 88 of 250 submitted functions reference a
    //     `glaurung_global_*`; 88 of those 88 snippets carry the in-body
    //     `extern` below; 0 of 250 carry this file-scope definition.
    //   * A/B over the holdout, definitions emitted vs. suppressed, same build:
    //     227/250 compile and byte_match 0.2005 over 250 BOTH ways — 0 of 250
    //     functions changed by a single ULP. The lever does not exist here.
    //   * Suppressing them costs the execution differential 4 of 656
    //     `tools/fixture_harness.py` cases (656 -> 652): `tools/diff_decompile.py`
    //     builds the WHOLE emitted unit into a shared object and `dlopen`s it,
    //     and supplies no definition of its own. This line is that definition.
    //
    // The real GCC behaviour behind the false lever: in a whole translation
    // unit an uninitialised `static` array is provably zero, so -O2 folds every
    // guard that reads it. Measured on 25 holdout functions, 20 compile SMALLER
    // as a whole TU than as the DecBench snippet (`sub_53d0` 3 vs 130
    // instructions). That collapse is real — and it is confined to whole-TU
    // consumers (`tools/recompile_fidelity.py`, `diff_decompile`), which is
    // exactly why a whole-TU proxy reports a large win for deleting these and
    // the scored metric reports none.
    for address in ids.global_addresses.keys() {
        let _ = writeln!(
            out,
            "static unsigned char {}[16] __attribute__((aligned(16)));",
            dec_global_name(*address)
        );
    }

    // EVERY declaration this render makes is decided here, once, before the
    // signature or a single local is printed. The printer below reads the plan
    // and cannot add to it: a declaration is a decision, and emitting one is
    // formatting.
    let plan = DeclarationPlan::compute(DeclarationInputs {
        ids: &ids,
        body: &f.body,
        tm,
        width_tm,
        output_kind,
        declared_prototype,
        arg_count,
        source_type_aliases: &source_type_aliases,
        dwarf_type_env: &dwarf_type_env,
        struct_pointer_types: &struct_pointer_types,
        source_locals: &source_locals,
    });
    let return_type = plan.return_ctype().to_string();
    DEC_PLAN.with(|installed| *installed.borrow_mut() = std::rc::Rc::new(plan));
    // GCC 15 can ICE in its final RTL pass at `-O2` on exceptionally large,
    // goto-heavy generated functions even after the C front end accepts them.
    // Keep the source semantics and all producer flags, but lower only that
    // function's optimization level. The 2,000-statement threshold is above
    // every other function in the current 250-function blinded DecBench slice
    // (next-largest rendered body: 1,670 lines) and therefore cannot silently
    // perturb ordinary output.
    if ids.statement_count >= 2_000 {
        out.push_str("__attribute__((optimize(\"O1\"))) ");
    }
    // A recovered frame slot renders as `unsigned char name[N]`, and GCC's
    // `-fstack-protector-strong` — on by default in every mainstream distro
    // toolchain — protects any function containing an array. So a function that
    // had NO canary in the original acquires a guard load, a guard compare and
    // a failure branch purely because we spelled a spill as an array.
    //
    // Measured on the ARM fixture corpus, that injection alone costs 0.0346 of
    // recompilation fidelity (0.6260 -> 0.6606, 51 functions better, none
    // worse): on `sum_arg1` the rebuild goes from 11 instructions to 39.
    //
    // Suppress it ONLY where the original demonstrably had no protector, which
    // is exactly the absence of a `__stack_chk_fail` call in the recovered
    // body. Where the original DID have one, we say nothing and let the rebuild
    // add its own — that matches the code being compared against.
    //
    // Spelled as a BARE attribute, not a `__has_attribute` macro dance.
    //
    // The guarded form cost 43 holdout functions their compile. DecBench does
    // not compile the unit we emit: `split_c_functions`
    // (`decbench/decompilers/dockerized.py:156`) cuts each snippet starting at
    // the `_FUNC_DEF_RE` match — the SIGNATURE line — and discards everything
    // above it. The `#define`s were emitted correctly and thrown away, leaving
    // a bare `GLAURUNG_NO_SSP` token in front of the return type:
    //
    //     /tmp/x.c:4:16: error: expected ';' before 'void'
    //         GLAURUNG_NO_SSP void rcc_periph_clock_enable(int arg0) {
    //
    // The general rule this violated: ANY per-function preamble above the
    // signature is invisible to scoring. Everything a function needs must sit
    // at or below its signature line.
    //
    // The macro was unnecessary anyway — all four holdout toolchains accept the
    // attribute directly (probed: gcc 15.2, arm-none-eabi-gcc 14.2,
    // i686/x86_64-w64-mingw32-gcc 13).
    if !ids.stack_objects.is_empty() && !ids.calls_stack_check {
        out.push_str("__attribute__((no_stack_protector)) ");
    }
    out.push_str(&return_type);
    out.push(' ');
    out.push_str(&name);
    out.push('(');
    let parameter_types = dec_plan(|plan| plan.parameters().to_vec());
    if parameter_types.is_empty() {
        out.push_str("void");
    } else {
        for (i, aty) in parameter_types.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            let _ = write!(out, "{} arg{}", aty, i);
        }
    }
    out.push_str(") {\n");

    // The current definition is also a callee declaration for recursive calls.
    // Put it in the selected-prototype table with external symbols, but do not
    // print a redundant block-scope declaration. An incompatible recursive
    // call can now own its pointer type without weakening this definition.
    let mut selected_call_prototypes = named_call_declarations.clone();
    selected_call_prototypes.insert(
        name.clone(),
        CallPrototype {
            return_type: return_type.clone(),
            parameter_types,
            variadic: false,
            authority: if all_declared_parameters_renderable {
                CallPrototypeAuthority::Authoritative
            } else {
                CallPrototypeAuthority::Recovered
            },
        },
    );
    DEC_NAMED_CALL_PROTOTYPES.with(|selected| {
        *selected.borrow_mut() = selected_call_prototypes;
    });

    if ids.has_unknown_value {
        out.push_str("    extern long __unknown(long, ...);\n");
    }

    // A callee whose result the ABI splits across the integer and SSE banks —
    // or across the two SSE registers — is declared with a synthesised tag,
    // because no builtin C type has that storage contract. Define the tag above
    // the declarations that name it, for the same reason
    // `SymbolRecord::required_structs` is emitted here: a sliced one-function
    // fragment must declare everything it names, and nothing above the
    // signature line survives that slice.
    for definition in named_call_declarations
        .values()
        .filter_map(|prototype| {
            crate::ir::abi::synthesised_return_definition(&prototype.return_type)
        })
        .collect::<std::collections::BTreeSet<_>>()
    {
        let _ = writeln!(out, "    {definition}");
    }

    // A resolved named call is still a typed call site. Keep the selected
    // authoritative-or-recovered contract inside the function so the standalone
    // fragment is valid C11/C23 without hiding the function definition behind a
    // translation-unit prelude. The prototype object retains its authority even
    // though both sources share one deterministic declaration table here.
    for (callee, prototype) in &named_call_declarations {
        out.push_str("    extern ");
        // Non-returning-ness is a property of the callee, so it belongs to the
        // callee's record. The symbol catalog remains the fallback for callees
        // the environment never reached.
        if crate::ir::symbol_env::lookup(callee).map_or_else(
            || crate::analysis::call_semantics::is_known_noreturn_symbol(callee),
            |record| record.noreturn,
        ) {
            out.push_str("__attribute__((noreturn)) ");
        }
        let _ = write!(out, "{} {}(", prototype.return_type, callee);
        if prototype.parameter_types.is_empty() {
            out.push_str("void");
        } else {
            for (index, parameter_type) in prototype.parameter_types.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                out.push_str(parameter_type);
            }
            if prototype.variadic {
                out.push_str(", ...");
            }
        }
        out.push_str(");\n");
    }

    // The portable objects above are file-scope definitions, which keeps the
    // sharing between decompiled sibling functions that the original static
    // storage had. Consumers that score ONE function definition sliced out of
    // the translation unit never see them, so restate each one here: a
    // block-scope `extern` of an identifier whose file-scope `static` is
    // visible denotes that same internal-linkage object (C11 6.2.2p4), and the
    // sliced fragment declares everything it names.
    for (address, required) in &ids.global_addresses {
        let _ = writeln!(
            out,
            "    extern unsigned char {}[{}];",
            dec_global_name(*address),
            dec_global_object_bytes(*required)
        );
    }

    // A relocation-proven table is source-level data, not a raw image address
    // and not a set of guessed direct calls. Materialise it as a function-local
    // static object so standalone C preserves pointer-table indexing and storage
    // lifetime. Exact local target declarations also let the differential
    // harness include their real decompilations before compiling this fragment.
    let mut table_target_names = std::collections::BTreeSet::new();
    for (_, targets) in ids.function_tables.values() {
        for target in targets {
            let displayed = sanitize_c_ident(callee_display_name(&target.name));
            if displayed != name && !named_call_declarations.contains_key(&displayed) {
                table_target_names.insert(displayed);
            }
        }
    }
    for target in &table_target_names {
        let _ = writeln!(out, "    extern void {}(void);", target);
    }
    for (table_name, targets) in ids.function_tables.values() {
        let table_name = sanitize_c_ident(table_name);
        let _ = writeln!(
            out,
            "    static void (*{}[{}])(void) = {{",
            table_name,
            targets.len()
        );
        for target in targets {
            let target = sanitize_c_ident(callee_display_name(&target.name));
            let _ = writeln!(out, "        (void (*)(void)){},", target);
        }
        out.push_str("    };\n");
    }

    // Emit the body-local declarations the plan selected, in its order.
    dec_plan(|plan| {
        for (local, declaration) in plan.locals() {
            match declaration {
                LocalDeclaration::StackObject { bytes } => {
                    let _ = writeln!(out, "    unsigned char {}[{}];", local, bytes);
                }
                LocalDeclaration::WideVector => {
                    let _ = writeln!(
                        out,
                        "    unsigned char {}[16] __attribute__((aligned(16)));",
                        local
                    );
                }
                LocalDeclaration::Scalar { c_type } => {
                    let _ = writeln!(out, "    {} {};", c_type, local);
                }
            }
        }
    });

    // Body.
    for s in &f.body {
        write_stmt_dec(s, &mut out, 1);
    }

    // Any `goto` target that was never emitted as a label would make the unit
    // fail to compile ("label used but not defined"); pin each missing one with
    // a trailing null-statement label so the parse still closes cleanly.
    for target in ids.gotos.difference(&ids.labels) {
        let _ = writeln!(out, "    L_{:x}: ;", target);
    }

    out.push_str("}\n");
    DEC_NAMED_CALL_PROTOTYPES.with(|selected| selected.borrow_mut().clear());
    DEC_RENDERABLE_STRUCTS.with(|selected| selected.borrow_mut().clear());
    DEC_STRUCT_PTR_TYPES.with(|selected| selected.borrow_mut().clear());
    DEC_SOURCE_LOCALS.with(|locals| locals.borrow_mut().clear());
    DEC_GLOBAL_ADDRS.with(|addresses| addresses.borrow_mut().clear());
    DEC_WIDE_LOCALS.with(|locals| locals.borrow_mut().clear());
    DEC_POINTER_WIDTH.with(|width| width.set(8));
    // The program-level callee environment is NOT cleared here. It is installed
    // by the caller that owns the render (`python_bindings::ir::decbench_text`)
    // and released by that same caller, so this projection only reads it.
    out
}
