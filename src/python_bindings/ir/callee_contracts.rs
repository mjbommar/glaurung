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
    /// Program-level records keyed by the identifier emitted for each callee.
    pub(super) env: crate::ir::symbol_env::SymbolEnv,
    /// Recovered parameter storage for the entries of the relocation-proven
    /// function-pointer tables this caller references.
    ///
    /// Kept apart from `layouts` on purpose. `layouts` is keyed by a DIRECT call
    /// target and is consulted by call-effect annotation, prototype application,
    /// and direct argument folding; a table entry is none of those things for
    /// this caller, and merging the two would make an entry's contract reachable
    /// from code that proved only a direct target. See
    /// `call_args::table_call_may_use_layout` for the one consumer.
    pub(super) table_entry_layouts: std::collections::HashMap<u64, Vec<crate::ir::types::VReg>>,
}

type RecoveredDirectCallee = (
    Vec<crate::ir::types::VReg>,
    crate::ir::call_contracts::CallPrototype,
    String,
    bool,
);

fn apply_proven_integer_pair_boundary(
    prototype: &mut crate::ir::call_contracts::CallPrototype,
    caller: &crate::ir::types::LlirFunction,
    target: u64,
    cc: crate::ir::call_args::CallConv,
    callee_defines_pair: bool,
) {
    if callee_defines_pair
        && prototype.authority == crate::ir::call_contracts::CallPrototypeAuthority::Recovered
        && crate::ir::interprocedural_return::caller_observes_integer_pair(caller, target, cc)
    {
        prototype.return_type = wide_integer_return_c_type(cc).to_string();
    }
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

/// Fixed compiler-runtime layouts whose imported helpers have no source body
/// from which parameter liveness or source order can be recovered.
fn compiler_runtime_layout(
    name: &str,
    cc: crate::ir::call_args::CallConv,
) -> Option<Vec<crate::ir::types::VReg>> {
    if cc != crate::ir::call_args::CallConv::SysVAmd64 {
        return None;
    }
    match imported_symbol_base(name) {
        "__mulsc3" | "__muldc3" => Some(
            ["xmm0", "xmm1", "xmm2", "xmm3"]
                .map(crate::ir::types::VReg::phys)
                .to_vec(),
        ),
        _ => None,
    }
}

/// Choose the strongest callee-owned record available for `name`.
fn callee_record(
    name: &str,
    recovered: &crate::ir::call_contracts::CallPrototype,
    noreturn: bool,
) -> crate::ir::symbol_env::SymbolRecord {
    use crate::ir::symbol_env::{RecordSource, SymbolRecord};

    crate::ir::call_contracts::lookup(name)
        .and_then(|contract| contract.standalone_prototype())
        .map(|prototype| SymbolRecord::new(prototype, RecordSource::Catalog, noreturn))
        .unwrap_or_else(|| SymbolRecord::new(recovered.clone(), RecordSource::CalleeBody, noreturn))
}

/// The C spelling of an integer occupying exactly two general-purpose result
/// registers.
///
/// Unsigned deliberately: the halves are storage, not a signed quantity, and a
/// signed double-word would make the high-half extraction an arithmetic shift.
fn wide_integer_return_c_type(cc: crate::ir::call_args::CallConv) -> &'static str {
    match crate::ir::abi::machine_word_bytes(cc) {
        8 => "unsigned __int128",
        _ => "unsigned long long",
    }
}

/// Merge source declaration facts that are also exact call-boundary facts.
///
/// Scalar and void return spellings describe their ABI storage directly, so
/// they outrank a body-only guess such as `void`. Aggregate spellings do not:
/// their fields may occupy multiple banks or a hidden buffer, and the recovered
/// prototype deliberately carries the representation type selected from that
/// class instead. Parameter types are safe only when source and storage arity
/// already agree.
fn refine_call_boundary_from_declared(
    call: &mut crate::ir::call_contracts::CallPrototype,
    declared: &crate::ir::call_contracts::CallPrototype,
    storage_arity: usize,
    source_uses_platform_c_abi: bool,
) {
    let mut selected_return_authority = false;
    // A source spelling crosses this machine boundary only when it denotes a
    // scalar/pointer storage class the call model understands. Rust aliases
    // such as `u32` are not C tokens, and a source aggregate such as
    // `NonZeroU32` may use a language ABI whose one-register carrier is not a
    // C by-value struct parameter. In both cases the recovered carrier is the
    // honest executable contract; the source declaration remains in metadata.
    let declared_machine_parameter_types = declared
        .parameter_types
        .iter()
        .map(|c_type| crate::ir::call_contracts::standalone_c_type(c_type))
        .collect::<Option<Vec<_>>>();
    if declared.parameter_types.len() == storage_arity {
        if let Some(parameter_types) = declared_machine_parameter_types {
            call.parameter_types = parameter_types;
            call.variadic = declared.variadic;
        } else if source_uses_platform_c_abi {
            // C and C++ declarations describe this platform's actual ABI, so
            // a representable by-value aggregate remains authoritative. The
            // Rust/Go path never enters this branch: its source aggregate can
            // have a different carrier despite equal source/storage arity.
            call.parameter_types = declared.parameter_types.clone();
            call.variadic = declared.variadic;
        }
    }
    if declared.return_type.trim().eq_ignore_ascii_case("void")
        || crate::ir::call_contracts::call_return_hint(&declared.return_type).is_some()
    {
        if let Some(return_type) =
            crate::ir::call_contracts::standalone_c_type(&declared.return_type)
        {
            call.return_type = return_type;
            selected_return_authority = true;
        }
    }
    // `CallPrototypeAuthority` currently describes the returned value in every
    // consumer that guards type/representation refinement. Copying only
    // parameter spellings must not lock an unrelated body-recovered result.
    if selected_return_authority {
        call.authority = declared.authority;
    }
}

fn source_uses_platform_c_abi(image: &crate::program::image::ProgramImage, body_va: u64) -> bool {
    image
        .dwarf_functions()
        .iter()
        .find(|function| function.entry_va == body_va)
        .and_then(|function| function.language.as_deref())
        .map_or(true, |language| matches!(language, "C" | "C++"))
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

    let mut parameter_types: Vec<String> = prototype
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
    if prototype.return_class() == crate::ir::abi::ReturnClass::Memory {
        if let Some(crate::ir::types_recover::TypeHint::Pointer { pointee_width }) = prototype
            .parameters()
            .first()
            .and_then(|parameter| parameter.hint)
        {
            if pointee_width > 1 {
                parameter_types[0] = format!("char (*)[{pointee_width}]");
            }
        }
    }
    let scalar_return_type = || {
        prototype
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
            .unwrap_or("long")
    };
    let return_type = match prototype.output_kind() {
        RecoveredOutputKind::Void => "void",
        // The MEMORY class returns the caller's buffer address in the ordinary
        // result register, so its call-boundary spelling is the recovered
        // scalar one. The CLASS is what a consumer needs; the spelling is
        // already right.
        RecoveredOutputKind::Direct | RecoveredOutputKind::HiddenReturn => scalar_return_type(),
        RecoveredOutputKind::Unknown => "long",
    };
    // A proven two-register INTEGER result cannot be spelled by any scalar C
    // type of one machine word, and spelling it as one is what left the `rdx`
    // half of every 16-byte aggregate read but never defined. The double-word
    // integer type has EXACTLY this ABI contract — INTEGER, INTEGER, hence
    // `rax:rdx` — so declaring it makes the call site's storage correct without
    // reconstructing the source aggregate's fields.
    let return_type = match prototype.return_class() {
        crate::ir::abi::ReturnClass::IntegerPair
            if crate::ir::abi::wide_integer_return_pair(
                cc,
                crate::ir::abi::wide_integer_return_width(cc),
            )
            .is_some() =>
        {
            wide_integer_return_c_type(cc)
        }
        // The same argument one bank further out. A result split across the
        // INTEGER and SSE banks has no builtin spelling at all, so naming
        // either bank alone discards the other eightbyte — visible as the SSE
        // half of a `{int; double;}` return being punned out of `rax`. The
        // synthesised tag has exactly this ABI contract by construction.
        // System V only: Win64 returns every over-wide aggregate through a
        // hidden pointer and AAPCS has its own HFA rules, so neither can
        // inherit this spelling.
        crate::ir::abi::ReturnClass::SplitBanks { integer_first }
            if cc == crate::ir::call_args::CallConv::SysVAmd64 =>
        {
            crate::ir::abi::split_bank_return_tag(integer_first)
        }
        // And the neighbouring class: an all-floating-point aggregate comes
        // back in `xmm0:xmm1`, TWO SSE registers holding ONE value. `double`
        // names `xmm0` alone, so declaring it discards the second eightbyte
        // entirely — visible as the second and third members of a
        // `{float,float,float}` return being read from variables nothing ever
        // defined. The tag also carries the second eightbyte's OCCUPANCY, so a
        // twelve-byte result does not read four bytes the callee never stored.
        // System V only, for the same reason as above.
        crate::ir::abi::ReturnClass::SsePair { high_bytes }
            if cc == crate::ir::call_args::CallConv::SysVAmd64
                && crate::ir::abi::sse_pair_return_tag(high_bytes).is_some() =>
        {
            crate::ir::abi::sse_pair_return_tag(high_bytes).unwrap_or(return_type)
        }
        _ => return_type,
    };
    // The two AAPCS64 classes, which need a SPELLING and not just a width.
    //
    // An HFA is one value in up to four SIMD registers; naming its member type
    // declares `s0` alone and discards the rest, which is the same defect the
    // SSE pair had one bank over. The indirect class is not in registers at
    // all: only a declaration of an object LARGER than sixteen bytes makes a C
    // compiler emit the `x8` setup, because `x8` is not an argument slot and no
    // argument list can reach it.
    let return_type = match prototype.return_class() {
        crate::ir::abi::ReturnClass::HomogeneousFloat {
            member_bytes,
            members,
        } if cc == crate::ir::call_args::CallConv::Aarch64 => {
            crate::ir::abi::hfa_return_tag(member_bytes, members)
                .map_or_else(|| return_type.to_string(), str::to_string)
        }
        crate::ir::abi::ReturnClass::IndirectBuffer { bytes }
            if cc == crate::ir::call_args::CallConv::Aarch64 =>
        {
            crate::ir::abi::indirect_return_tag(bytes).unwrap_or_else(|| return_type.to_string())
        }
        _ => return_type.to_string(),
    };
    CallPrototype {
        return_type,
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

/// How many nested callee layers below the requested callee may be analyzed.
///
/// This is the ONLY termination guarantee for the nested walk, and it must stay
/// so. The session's SCC condensation below is an under-approximation — an
/// unresolved indirect call contributes no edge — so "not in a cycle" is not
/// proof that recursion ends. The counter decrements unconditionally on every
/// nested layer, which bounds the walk whether or not the graph saw the cycle.
///
/// This replaced an `include_grandcallees: bool` that conflated two concerns:
/// how deep to go, and how not to loop. They are now separate — the counter
/// bounds depth, the SCC guard declines cycles.
///
/// **1 because 2 was measured and changes nothing.** Raising it to 2 was tried
/// on 2026-08-15: 1457 decompiled functions over 300 objects in
/// `tests/decompiler_fixtures/build/` produced byte-identical C for every one,
/// and `dectest @o0` + `@o2` (728 lanes) reported no verdict change. The 29% of
/// the corpus whose call chains run deeper than one nested layer do not, in
/// fact, need the extra layer to render correctly. Raise this only with a
/// fixture that demonstrably regresses at 1.
const NESTED_CALLEE_DEPTH: u8 = 1;

/// Recover one direct callee, using up to `remaining_depth` nested layers.
///
/// The layers recover the common optimized wrapper shape without recursively
/// walking a whole program. `call_graph`, when present, is used only to DECLINE
/// spending a layer on a callee inside the analyzed function's own strongly
/// connected component: re-entering a cycle re-derives facts from a
/// partially-analyzed body and cannot converge in a bounded walk. It never
/// authorizes recursion that the depth counter would not already allow.
/// The outer cache still ensures repeated requested callees are analyzed once
/// per batch/session.
fn recover_direct_callee_definition(
    image: &crate::program::image::ProgramImage,
    functions: &[crate::core::function::Function],
    callee_va: u64,
    cc: crate::ir::call_args::CallConv,
    arm_vfp_args: bool,
    budgets: &crate::analysis::cfg::Budgets,
    dwarf_outputs: Option<&std::collections::HashMap<u64, DwarfPrototypeContract>>,
    type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
    address_names: &std::collections::HashMap<u64, String>,
    call_graph: Option<&crate::program::call_graph::ProgramCallGraph>,
    remaining_depth: u8,
) -> Option<RecoveredDirectCallee> {
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
    let mut lifted = lift_function_from_image(image, callee).ok()?;
    inline_soft_helper_calls_in(&mut lifted, address_names);
    annotate_calls_in(&mut lifted, cc, address_names);

    let mut nested = DirectCalleeFacts::default();
    if remaining_depth > 0 {
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
            // Spend a layer only outside this function's own cycle. Inside one,
            // the nested body calls back into a function that is itself only
            // partially analyzed, so the extra layer yields facts derived from
            // an unconverged state rather than more information.
            let target_id = crate::program::call_graph::FunctionId::new(image, target);
            let body_id = crate::program::call_graph::FunctionId::new(image, body_va);
            let nested_depth = match call_graph {
                Some(graph) if graph.shares_component(body_id, target_id) => 0,
                _ => remaining_depth.saturating_sub(1),
            };
            let Some((layout, mut prototype, _, callee_defines_pair)) =
                recover_direct_callee_definition(
                    image,
                    functions,
                    target,
                    cc,
                    arm_vfp_args,
                    budgets,
                    dwarf_outputs,
                    type_env,
                    address_names,
                    call_graph,
                    nested_depth,
                )
            else {
                continue;
            };
            apply_proven_integer_pair_boundary(
                &mut prototype,
                &lifted,
                target,
                cc,
                callee_defines_pair,
            );
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
    if let Some(authoritative) = declared.and_then(super::dwarf_render_prototype) {
        // One source aggregate occupying one ABI slot is representable at the
        // existing call-site boundary: the renderer can bitcast that slot to
        // the complete source object. Multi-slot aggregates still need an
        // explicit grouping model, so retain the recovered machine prototype
        // unless source and storage arity agree exactly.
        refine_call_boundary_from_declared(
            &mut call_prototype,
            &authoritative,
            layout.len(),
            source_uses_platform_c_abi(image, body_va),
        );
    }
    let callee_defines_pair =
        crate::ir::interprocedural_return::callee_defines_integer_pair_on_every_return(&lifted, cc);
    (!layout.is_empty() || retain_empty_direct_callee_layout(declared)).then(|| {
        (
            layout,
            call_prototype,
            callee.name.clone(),
            callee_defines_pair,
        )
    })
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
    cc: crate::ir::call_args::CallConv,
    arm_vfp_args: bool,
    budgets: &crate::analysis::cfg::Budgets,
    dwarf_outputs: Option<&std::collections::HashMap<u64, DwarfPrototypeContract>>,
    type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
    address_names: &mut std::collections::HashMap<u64, String>,
    function_tables: &[crate::ir::function_tables::FunctionPointerTable],
    call_graph: Option<&crate::program::call_graph::ProgramCallGraph>,
    cache: &mut std::collections::HashMap<u64, Option<RecoveredDirectCallee>>,
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
        if let Some((name, layout, prototype)) = address_names.get(&callee_va).and_then(|name| {
            let layout = compiler_runtime_layout(name, cc)?;
            let prototype = crate::ir::call_contracts::lookup(name)?.standalone_prototype()?;
            Some((name.clone(), layout, prototype))
        }) {
            let key = crate::ir::ast::sanitize_c_ident(crate::ir::ast::callee_display_name(&name));
            facts.layouts.insert(callee_va, layout);
            facts.prototypes.insert(callee_va, prototype.clone());
            facts.env.insert(
                key,
                crate::ir::symbol_env::SymbolRecord::new(
                    prototype,
                    crate::ir::symbol_env::RecordSource::Catalog,
                    false,
                ),
            );
            continue;
        }
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
                cc,
                arm_vfp_args,
                budgets,
                dwarf_outputs,
                type_env,
                address_names,
                call_graph,
                NESTED_CALLEE_DEPTH,
            );
            cache.insert(callee_va, recovered);
        }
        let recovered = cache.get(&callee_va).cloned().flatten();
        if let Some((layout, mut prototype, name, callee_defines_pair)) = recovered {
            apply_proven_integer_pair_boundary(
                &mut prototype,
                caller,
                callee_va,
                cc,
                callee_defines_pair,
            );
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
            let layout_len = layout.len();
            facts.layouts.insert(callee_va, layout);
            let mut call_prototype = prototype.clone();
            if let Some(display) = address_names.get(&callee_va) {
                let key =
                    crate::ir::ast::sanitize_c_ident(crate::ir::ast::callee_display_name(display));
                let noreturn = crate::analysis::call_semantics::is_known_noreturn_symbol(&key);
                facts
                    .env
                    .insert(key.clone(), callee_record(&key, &prototype, noreturn));
                if let Some(declared) = dwarf_outputs
                    .and_then(|outputs| outputs.get(&body_va))
                    .and_then(super::dwarf_render_prototype)
                {
                    if let Some(record) = crate::ir::symbol_env::dwarf_record(&declared, noreturn) {
                        facts.env.insert(key.clone(), record);
                    }
                }
                // The call-site renderer receives the same DWARF type
                // environment and can therefore emit complete aggregate
                // definitions plus an explicit representation bridge. Keep
                // the authoritative prototype even when it names such a tag.
                if let Some(declared) = dwarf_outputs
                    .and_then(|outputs| outputs.get(&body_va))
                    .and_then(super::dwarf_render_prototype)
                {
                    refine_call_boundary_from_declared(
                        &mut call_prototype,
                        &declared,
                        layout_len,
                        source_uses_platform_c_abi(image, body_va),
                    );
                } else if let Some(record) = facts.env.get(&key) {
                    if record.prototype.parameter_types.len() == layout_len {
                        call_prototype.parameter_types = record.prototype.parameter_types.clone();
                        call_prototype.variadic = record.prototype.variadic;
                        call_prototype.authority = record.prototype.authority;
                    }
                }
            }
            facts.prototypes.insert(callee_va, call_prototype);
        } else if dump {
            eprintln!("callee 0x{callee_va:x}: no recovered layout");
        }
    }
    recover_table_entry_layouts(
        &mut facts,
        image,
        functions,
        caller,
        cc,
        arm_vfp_args,
        budgets,
        dwarf_outputs,
        type_env,
        address_names,
        function_tables,
        call_graph,
        cache,
        dump,
    );
    facts
}

/// Recover the parameter storage of every entry of every relocation-proven
/// function-pointer table this caller references.
///
/// A call through such a table has no single callee to ask for a contract —
/// that is exactly why the direct-call recovery does not generalise to it — but
/// it does have a complete, proven set of them.
/// `call_args::table_call_may_use_layout` unions that set into the ABI registers
/// the call MAY read, so the setup is recovered as real arguments before any
/// dead-store or dead-copy pass can observe it as unread.
///
/// Nothing here writes `facts.layouts`, `facts.prototypes`, or `facts.env`: an
/// entry is not a direct call target of this caller, and every existing consumer
/// of those maps is keyed by one. The declarations and types this caller emits
/// are therefore unchanged.
///
/// Cost is bounded by `tables_referenced_by` plus the shared `cache`, which is
/// the same demand-driven discipline the direct path already uses.
#[allow(clippy::too_many_arguments)]
fn recover_table_entry_layouts(
    facts: &mut DirectCalleeFacts,
    image: &crate::program::image::ProgramImage,
    functions: &[crate::core::function::Function],
    caller: &crate::ir::types::LlirFunction,
    cc: crate::ir::call_args::CallConv,
    arm_vfp_args: bool,
    budgets: &crate::analysis::cfg::Budgets,
    dwarf_outputs: Option<&std::collections::HashMap<u64, DwarfPrototypeContract>>,
    type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
    address_names: &mut std::collections::HashMap<u64, String>,
    function_tables: &[crate::ir::function_tables::FunctionPointerTable],
    call_graph: Option<&crate::program::call_graph::ProgramCallGraph>,
    cache: &mut std::collections::HashMap<u64, Option<RecoveredDirectCallee>>,
    dump: bool,
) {
    let referenced = crate::ir::function_tables::tables_referenced_by(caller, function_tables);
    if dump && !referenced.is_empty() {
        eprintln!(
            "\n===== referenced function-pointer tables =====\n{:#x?}",
            referenced
                .iter()
                .map(|table| (table.va, table.name.as_str()))
                .collect::<Vec<_>>()
        );
    }
    let entries: std::collections::BTreeSet<u64> = referenced
        .iter()
        .flat_map(|table| table.targets.iter().map(|target| target.va))
        .collect();
    for entry_va in entries {
        if !cache.contains_key(&entry_va) {
            let recovered = recover_direct_callee_definition(
                image,
                functions,
                entry_va,
                cc,
                arm_vfp_args,
                budgets,
                dwarf_outputs,
                type_env,
                address_names,
                call_graph,
                NESTED_CALLEE_DEPTH,
            );
            cache.insert(entry_va, recovered);
        }
        if let Some((layout, _, _, _)) = cache.get(&entry_va).cloned().flatten() {
            if dump {
                eprintln!("table entry 0x{entry_va:x}: recovered layout {layout:?}");
            }
            facts.table_entry_layouts.insert(entry_va, layout);
        } else if dump {
            eprintln!("table entry 0x{entry_va:x}: no recovered layout");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ir::call_contracts::{CallPrototype, CallPrototypeAuthority};

    #[test]
    fn declared_scalar_return_repairs_a_body_only_void_guess() {
        let mut boundary = CallPrototype {
            return_type: "void".into(),
            parameter_types: vec!["long".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        let declared = CallPrototype {
            return_type: "int".into(),
            parameter_types: vec!["int".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };

        super::refine_call_boundary_from_declared(&mut boundary, &declared, 1, true);

        assert_eq!(boundary.return_type, "int");
        assert_eq!(boundary.parameter_types, ["int"]);
        assert_eq!(boundary.authority, CallPrototypeAuthority::Authoritative);
    }

    #[test]
    fn declared_aggregate_return_keeps_its_machine_carrier() {
        let mut boundary = CallPrototype {
            return_type: "unsigned __int128".into(),
            parameter_types: vec!["long".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        let declared = CallPrototype {
            return_type: "struct quad".into(),
            parameter_types: vec!["int".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };

        super::refine_call_boundary_from_declared(&mut boundary, &declared, 1, true);

        assert_eq!(boundary.return_type, "unsigned __int128");
        assert_eq!(boundary.parameter_types, ["int"]);
        assert_eq!(boundary.authority, CallPrototypeAuthority::Recovered);
    }

    #[test]
    fn non_c_scalar_alias_does_not_escape_into_generated_c() {
        let mut boundary = CallPrototype {
            return_type: "long".into(),
            parameter_types: vec!["unsigned int".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        let declared = CallPrototype {
            return_type: "u32".into(),
            parameter_types: vec!["u32".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };

        super::refine_call_boundary_from_declared(&mut boundary, &declared, 1, false);

        assert_eq!(boundary.parameter_types, ["unsigned int"]);
    }

    #[test]
    fn language_aggregate_parameter_keeps_its_machine_carrier() {
        let mut boundary = CallPrototype {
            return_type: "unsigned int".into(),
            parameter_types: vec!["unsigned int".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        let declared = CallPrototype {
            return_type: "u32".into(),
            parameter_types: vec!["struct NonZeroU32".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };

        super::refine_call_boundary_from_declared(&mut boundary, &declared, 1, false);

        assert_eq!(boundary.parameter_types, ["unsigned int"]);
    }

    #[test]
    fn c_aggregate_parameter_keeps_its_source_abi_spelling() {
        let mut boundary = CallPrototype {
            return_type: "unsigned int".into(),
            parameter_types: vec!["unsigned int".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        let declared = CallPrototype {
            return_type: "unsigned int".into(),
            parameter_types: vec!["struct Pair".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };

        super::refine_call_boundary_from_declared(&mut boundary, &declared, 1, true);

        assert_eq!(boundary.parameter_types, ["struct Pair"]);
    }

    #[test]
    fn non_c_pointer_alias_is_normalized_to_standalone_c() {
        let mut boundary = CallPrototype {
            return_type: "long".into(),
            parameter_types: vec!["long".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        let declared = CallPrototype {
            return_type: "i32 *".into(),
            parameter_types: vec!["i32 *".into()],
            variadic: false,
            authority: CallPrototypeAuthority::Authoritative,
        };

        super::refine_call_boundary_from_declared(&mut boundary, &declared, 1, false);

        assert_eq!(boundary.return_type, "void *");
        assert_eq!(boundary.parameter_types, ["void *"]);
    }
}
