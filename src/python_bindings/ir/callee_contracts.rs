//! Demand-driven interprocedural call-layout and prototype recovery.
//!
//! This module owns the bounded callee/grandcallee analysis used by every
//! Python decompilation entry point. Keeping the definition-site contract logic
//! here prevents the already-large binding orchestrator from becoming another
//! analysis owner.

use super::pipeline::{annotate_calls_in, inline_soft_helper_calls_in};
use super::{calling_convention_pointer_width, recover_decbench_prototype, DwarfPrototypeContract};

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

pub(super) type RecoveredDirectCallee = (
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

/// Prepare one caller for SSA and return all proven direct-callee facts.
///
/// The order is semantic: compiler helpers expand while argument registers are
/// still architectural, ABI and known-call effects attach before SSA, callee
/// bodies refine those conservative effects, and only then may the caller enter
/// prototype recovery. Every public decompilation entry point must cross this
/// boundary instead of hand-repeating that sequence.
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_direct_callee_facts(
    image: &crate::program::image::ProgramImage,
    functions: &[crate::core::function::Function],
    caller: &mut crate::ir::types::LlirFunction,
    cc: crate::ir::call_args::CallConv,
    arm_vfp_args: bool,
    budgets: &crate::analysis::cfg::Budgets,
    max_nested_depth: u8,
    dwarf_outputs: Option<&std::collections::HashMap<u64, DwarfPrototypeContract>>,
    type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
    address_names: &mut std::collections::HashMap<u64, String>,
    function_tables: &[crate::ir::function_tables::FunctionPointerTable],
    call_graph: Option<&crate::program::call_graph::ProgramCallGraph>,
    cache: &mut std::collections::HashMap<u64, Option<RecoveredDirectCallee>>,
) -> DirectCalleeFacts {
    inline_soft_helper_calls_in(caller, address_names);
    annotate_calls_in(caller, cc, address_names);
    let facts = recover_direct_callee_layouts(
        image,
        functions,
        caller,
        cc,
        arm_vfp_args,
        budgets,
        max_nested_depth,
        dwarf_outputs,
        type_env,
        address_names,
        function_tables,
        call_graph,
        cache,
    );
    apply_recovered_direct_callee_effects(caller, cc, &facts);
    apply_recovered_table_call_effects(caller, cc, &facts, function_tables);
    facts
}

/// Attach exact machine inputs to indirect calls whose target is proven to be
/// an entry loaded from one complete relocation-backed function table.
///
/// This runs on flat LLIR, before SSA and before dead-store elimination.  The
/// later AST-only table recognizer is too late for loops that have not yet been
/// structured: without these uses, their argument setup can be deleted before
/// `reconstruct_args` sees the call.
fn apply_recovered_table_call_effects(
    function: &mut crate::ir::types::LlirFunction,
    cc: crate::ir::call_args::CallConv,
    facts: &DirectCalleeFacts,
    tables: &[crate::ir::function_tables::FunctionPointerTable],
) {
    use crate::ir::types::{CallTarget, MemOp, Op, VReg, Value};
    use std::collections::HashMap;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TableValue {
        Address(u64),
        Entry(u64),
    }

    fn offset(address: u64, displacement: i64) -> Option<u64> {
        if displacement >= 0 {
            address.checked_add(displacement as u64)
        } else {
            address.checked_sub(displacement.unsigned_abs())
        }
    }

    fn exact_address(value: &Value, state: &HashMap<VReg, TableValue>) -> Option<u64> {
        match value {
            Value::Addr(address) => Some(*address),
            Value::Const(address) => u64::try_from(*address).ok(),
            Value::Reg(source) => match state.get(source) {
                Some(TableValue::Address(address)) => Some(*address),
                Some(TableValue::Entry(_)) | None => None,
            },
        }
    }

    fn assigned_value(value: &Value, state: &HashMap<VReg, TableValue>) -> Option<TableValue> {
        match value {
            Value::Reg(source) => state.get(source).copied(),
            Value::Addr(_) | Value::Const(_) => {
                exact_address(value, state).map(TableValue::Address)
            }
        }
    }

    fn register_address(register: &VReg, state: &HashMap<VReg, TableValue>) -> Option<u64> {
        match state.get(register) {
            Some(TableValue::Address(address)) => Some(*address),
            Some(TableValue::Entry(_)) | None => None,
        }
    }

    fn derived_address(
        op: crate::ir::types::BinOp,
        lhs: &Value,
        rhs: &Value,
        state: &HashMap<VReg, TableValue>,
    ) -> Option<u64> {
        use crate::ir::types::BinOp;
        match (op, lhs, rhs) {
            (BinOp::Add, Value::Reg(base), Value::Const(displacement))
            | (BinOp::Add, Value::Const(displacement), Value::Reg(base)) => {
                register_address(base, state).and_then(|address| offset(address, *displacement))
            }
            (BinOp::Sub, Value::Reg(base), Value::Const(displacement)) => {
                register_address(base, state)
                    .and_then(|address| offset(address, displacement.saturating_neg()))
            }
            _ => None,
        }
    }

    fn loaded_table(
        address: u64,
        indexed: bool,
        scale: u8,
        size: u8,
        tables: &[crate::ir::function_tables::FunctionPointerTable],
    ) -> Option<u64> {
        tables.iter().find_map(|table| {
            if size != table.pointer_size {
                return None;
            }
            if indexed {
                return (scale == table.pointer_size && address == table.va).then_some(table.va);
            }
            let displacement = address.checked_sub(table.va)?;
            (displacement % u64::from(table.pointer_size) == 0
                && displacement / u64::from(table.pointer_size) < table.targets.len() as u64)
                .then_some(table.va)
        })
    }

    fn loaded_value(
        address: &MemOp,
        state: &HashMap<VReg, TableValue>,
        tables: &[crate::ir::function_tables::FunctionPointerTable],
    ) -> Option<TableValue> {
        if address.segment.is_some() {
            return None;
        }
        let base = address.base.as_ref()?;
        let base_address = register_address(base, state)?;
        let effective_address = offset(base_address, address.disp)?;
        loaded_table(
            effective_address,
            address.index.is_some(),
            address.scale,
            address.size,
            tables,
        )
        .map(TableValue::Entry)
    }

    fn merge(states: impl Iterator<Item = HashMap<VReg, TableValue>>) -> HashMap<VReg, TableValue> {
        let mut states = states.peekable();
        let Some(mut joined) = states.next() else {
            return HashMap::new();
        };
        for state in states {
            joined.retain(|register, value| state.get(register) == Some(value));
        }
        joined
    }

    let tables_by_va = tables
        .iter()
        .map(|table| (table.va, table))
        .collect::<HashMap<_, _>>();
    let is_caller_saved = |register: &VReg| match register {
        VReg::Phys(name) => {
            crate::ir::abi::caller_saved_registers(cc).contains(&crate::ir::abi::ssa_base(name))
        }
        VReg::Temp(_) | VReg::Flag(_) | VReg::FlagValue { .. } => true,
    };
    if tables_by_va.is_empty() || function.blocks.is_empty() {
        return;
    }
    let block_by_va = function
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start_va, index))
        .collect::<HashMap<_, _>>();
    let entry_index = block_by_va.get(&function.entry_va).copied().unwrap_or(0);
    let mut predecessors = vec![Vec::new(); function.blocks.len()];
    for (index, block) in function.blocks.iter().enumerate() {
        for successor in &block.succs {
            if let Some(&successor_index) = block_by_va.get(successor) {
                predecessors[successor_index].push(index);
            }
        }
    }

    // `None` means that predecessor has not contributed yet.  This permits a
    // preheader fact to enter a loop on the first iteration; when the backedge
    // arrives, the ordinary agreement join can only retain or remove it.
    let mut outputs: Vec<Option<HashMap<VReg, TableValue>>> = vec![None; function.blocks.len()];
    let mut changed = true;
    while changed {
        changed = false;
        for block_index in 0..function.blocks.len() {
            let incoming = if block_index == entry_index {
                HashMap::new()
            } else {
                merge(
                    predecessors[block_index]
                        .iter()
                        .filter_map(|&predecessor| outputs[predecessor].clone()),
                )
            };
            if block_index != entry_index
                && !predecessors[block_index].is_empty()
                && predecessors[block_index]
                    .iter()
                    .all(|&predecessor| outputs[predecessor].is_none())
            {
                continue;
            }
            let mut state = incoming;
            for instruction in &function.blocks[block_index].instrs {
                let definition = crate::ir::use_def::def_ref(&instruction.op).cloned();
                let derived = match &instruction.op {
                    Op::Assign { src, .. } => assigned_value(src, &state),
                    Op::Bin { op, lhs, rhs, .. } => {
                        derived_address(*op, lhs, rhs, &state).map(TableValue::Address)
                    }
                    Op::Load { addr, .. } => loaded_value(addr, &state, tables),
                    _ => None,
                };
                if let Some(definition) = definition.as_ref() {
                    state.remove(definition);
                }
                match &instruction.op {
                    Op::Assign { dst, .. } | Op::Bin { dst, .. } | Op::Load { dst, .. } => {
                        if let Some(value) = derived {
                            state.insert(dst.clone(), value);
                        }
                    }
                    Op::Call { .. } => state.retain(|register, _| !is_caller_saved(register)),
                    _ => {}
                }
            }
            if outputs[block_index].as_ref() != Some(&state) {
                outputs[block_index] = Some(state);
                changed = true;
            }
        }
    }

    for block_index in 0..function.blocks.len() {
        let mut state = if block_index == entry_index {
            HashMap::new()
        } else {
            merge(
                predecessors[block_index]
                    .iter()
                    .filter_map(|&predecessor| outputs[predecessor].clone()),
            )
        };
        for instruction in &mut function.blocks[block_index].instrs {
            let definition = crate::ir::use_def::def_ref(&instruction.op).cloned();
            let derived = match &instruction.op {
                Op::Assign { src, .. } => assigned_value(src, &state),
                Op::Bin { op, lhs, rhs, .. } => {
                    derived_address(*op, lhs, rhs, &state).map(TableValue::Address)
                }
                Op::Load { addr, .. } => loaded_value(addr, &state, tables),
                _ => None,
            };
            if let Some(definition) = definition.as_ref() {
                state.remove(definition);
            }
            match &mut instruction.op {
                Op::Assign { dst, .. } | Op::Bin { dst, .. } | Op::Load { dst, .. } => {
                    if let Some(value) = derived {
                        state.insert(dst.clone(), value);
                    }
                }
                Op::Call {
                    target: CallTarget::Indirect(Value::Reg(target)),
                    effects,
                } => {
                    let Some(TableValue::Entry(table_va)) = state.get(target).copied() else {
                        continue;
                    };
                    let Some(table) = tables_by_va.get(&table_va) else {
                        continue;
                    };
                    let targets = table
                        .targets
                        .iter()
                        .map(|target| target.va)
                        .collect::<Vec<_>>();
                    let Some(layout) = crate::ir::call_args::table_target_may_use_layout(
                        &targets,
                        cc,
                        &facts.table_entry_layouts,
                    ) else {
                        continue;
                    };
                    let mut recovered = effects
                        .clone()
                        .unwrap_or_else(|| crate::ir::abi::call_effects(cc));
                    recovered.args = layout.clone();
                    recovered.proven_args = layout;
                    recovered.args_are_exact = true;
                    *effects = Some(recovered);
                    state.retain(|register, _| !is_caller_saved(register));
                }
                Op::Call { .. } => state.retain(|register, _| !is_caller_saved(register)),
                _ => {}
            }
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
        fn exact_reaching_spill_source(
            function: &crate::ir::types::LlirFunction,
            ssa: &crate::ir::ssa::SsaInfo,
            load_at: InstrAddr,
            load_addr: &crate::ir::types::MemOp,
        ) -> Option<crate::ir::ssa::SsaValue> {
            use crate::ir::types::{Op, Value};

            // This is a stack-home proof, not general memory forwarding. An
            // indexed or segmented address could denote an array/global/TLS
            // object and needs the real memory model instead.
            if load_addr.base.is_none() || load_addr.index.is_some() || load_addr.segment.is_some()
            {
                return None;
            }
            let block = function.blocks.get(load_at.block_idx)?;
            for store_idx in (0..load_at.instr_idx).rev() {
                let instruction = block.instrs.get(store_idx)?;
                match &instruction.op {
                    Op::Store { addr, src } if addr == load_addr => {
                        if !matches!(src, Value::Reg(_)) {
                            return None;
                        }
                        let store_at = InstrAddr {
                            block_idx: load_at.block_idx,
                            instr_idx: store_idx,
                        };
                        let load_base = ssa.use_value(function, load_at, 0)?;
                        let store_base = ssa.use_value(function, store_at, 0)?;
                        if load_base != store_base
                            || !load_base.canonical_physical_base().is_some_and(|base| {
                                matches!(
                                    base,
                                    "rsp"
                                        | "esp"
                                        | "rbp"
                                        | "ebp"
                                        | "sp"
                                        | "x29"
                                        | "w29"
                                        | "r7"
                                        | "r11"
                                        | "fp"
                                )
                            })
                        {
                            return None;
                        }
                        let source_use =
                            usize::from(addr.base.is_some()) + usize::from(addr.index.is_some());
                        return ssa.use_value(function, store_at, source_use);
                    }
                    // Memory is not in SSA. Any intervening writer makes this
                    // load/store relation ambiguous, even when its spelling
                    // appears to use a different address.
                    Op::Store { .. }
                    | Op::CondStore { .. }
                    | Op::Call { .. }
                    | Op::Intrinsic { .. }
                    | Op::Unknown { .. } => return None,
                    _ => {}
                }
            }
            None
        }

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
            value = match definition.1 {
                Op::Assign { .. } => ssa.use_value(function, definition.0, 0)?,
                Op::Load { addr, .. } => {
                    exact_reaching_spill_source(function, ssa, definition.0, addr)?
                }
                _ => return None,
            };
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
    max_nested_depth: u8,
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
                max_nested_depth,
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
        max_nested_depth,
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
    max_nested_depth: u8,
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
                max_nested_depth,
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

    fn table(targets: &[u64]) -> crate::ir::function_tables::FunctionPointerTable {
        crate::ir::function_tables::FunctionPointerTable {
            va: 0x3e60,
            name: "OPERATIONS".into(),
            pointer_size: 8,
            targets: targets
                .iter()
                .enumerate()
                .map(|(index, va)| crate::ir::ast::FunctionTableTarget {
                    va: *va,
                    name: format!("operation_{index}"),
                })
                .collect(),
        }
    }

    fn flat_loop_table_call() -> crate::ir::types::LlirFunction {
        use crate::ir::types::{
            CallTarget, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value,
        };
        let instruction = |va, op| LlirInstr { va, op };
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                LlirBlock {
                    start_va: 0x1000,
                    end_va: 0x1008,
                    instrs: vec![instruction(
                        0x1000,
                        Op::Assign {
                            dst: VReg::phys("r13"),
                            src: Value::Addr(0x3e60),
                        },
                    )],
                    succs: vec![0x1100],
                },
                LlirBlock {
                    start_va: 0x1100,
                    end_va: 0x1110,
                    instrs: vec![
                        instruction(
                            0x1104,
                            Op::Load {
                                dst: VReg::Temp(0),
                                addr: MemOp::plain(
                                    Some(VReg::phys("r13")),
                                    Some(VReg::phys("rcx")),
                                    8,
                                    0,
                                    8,
                                ),
                            },
                        ),
                        instruction(
                            0x1108,
                            Op::Call {
                                target: CallTarget::Indirect(Value::Reg(VReg::Temp(0))),
                                effects: None,
                            },
                        ),
                    ],
                    succs: vec![0x1100, 0x1200],
                },
                LlirBlock {
                    start_va: 0x1200,
                    end_va: 0x1204,
                    instrs: vec![instruction(0x1200, Op::Return)],
                    succs: vec![],
                },
            ],
        }
    }

    #[test]
    fn flat_loop_table_call_gets_exact_pre_ssa_arguments() {
        use crate::ir::types::{CallTarget, Op, VReg, Value};
        let mut function = flat_loop_table_call();
        let mut facts = super::DirectCalleeFacts::default();
        for target in [0x2000, 0x2100] {
            facts
                .table_entry_layouts
                .insert(target, vec![VReg::phys("rdi"), VReg::phys("rsi")]);
        }

        super::apply_recovered_table_call_effects(
            &mut function,
            crate::ir::call_args::CallConv::SysVAmd64,
            &facts,
            &[table(&[0x2000, 0x2100])],
        );

        let Op::Call {
            target: CallTarget::Indirect(Value::Reg(target)),
            effects: Some(effects),
        } = &function.blocks[1].instrs[1].op
        else {
            panic!("expected annotated indirect call")
        };
        assert_eq!(target, &VReg::Temp(0));
        assert_eq!(effects.args, [VReg::phys("rdi"), VReg::phys("rsi")]);
        assert_eq!(effects.proven_args, effects.args);
        assert!(effects.args_are_exact);
    }

    #[test]
    fn affine_page_table_call_gets_exact_pre_ssa_arguments() {
        use crate::ir::types::{CallTarget, LlirInstr, Op, VReg, Value};

        let mut function = flat_loop_table_call();
        function.blocks[0].end_va = 0x100c;
        function.blocks[0].instrs = vec![
            LlirInstr {
                va: 0x1000,
                op: Op::Assign {
                    dst: VReg::phys("r13"),
                    src: Value::Addr(0x3000),
                },
            },
            LlirInstr {
                va: 0x1004,
                op: Op::Bin {
                    dst: VReg::phys("r13"),
                    op: crate::ir::types::BinOp::Add,
                    lhs: Value::Reg(VReg::phys("r13")),
                    rhs: Value::Const(0xe60),
                },
            },
        ];
        let Op::Load { dst, .. } = &mut function.blocks[1].instrs[0].op else {
            panic!("expected indexed table load")
        };
        *dst = VReg::phys("r13");
        function.blocks[1].succs = vec![0x1200];
        let Op::Call { target, .. } = &mut function.blocks[1].instrs[1].op else {
            panic!("expected indirect call")
        };
        *target = CallTarget::Indirect(Value::Reg(VReg::phys("r13")));
        let mut facts = super::DirectCalleeFacts::default();
        for target in [0x2000, 0x2100] {
            facts
                .table_entry_layouts
                .insert(target, vec![VReg::phys("x0"), VReg::phys("x1")]);
        }

        super::apply_recovered_table_call_effects(
            &mut function,
            crate::ir::call_args::CallConv::Aarch64,
            &facts,
            &[table(&[0x2000, 0x2100])],
        );

        let Op::Call {
            target: CallTarget::Indirect(Value::Reg(target)),
            effects: Some(effects),
        } = &function.blocks[1].instrs[1].op
        else {
            panic!("expected annotated indirect call")
        };
        assert_eq!(target, &VReg::phys("r13"));
        assert_eq!(effects.args, [VReg::phys("x0"), VReg::phys("x1")]);
        assert_eq!(effects.proven_args, effects.args);
        assert!(effects.args_are_exact);
    }

    #[test]
    fn copied_affine_table_entry_keeps_exact_pre_ssa_arguments() {
        use crate::ir::types::{CallTarget, LlirInstr, Op, VReg, Value};

        let mut function = flat_loop_table_call();
        function.blocks[0].instrs = vec![
            LlirInstr {
                va: 0x1000,
                op: Op::Assign {
                    dst: VReg::phys("r13"),
                    src: Value::Addr(0x3000),
                },
            },
            LlirInstr {
                va: 0x1004,
                op: Op::Bin {
                    dst: VReg::phys("r13"),
                    op: crate::ir::types::BinOp::Add,
                    lhs: Value::Reg(VReg::phys("r13")),
                    rhs: Value::Const(0xe60),
                },
            },
        ];
        function.blocks[1].instrs.insert(
            1,
            LlirInstr {
                va: 0x1106,
                op: Op::Assign {
                    dst: VReg::Temp(1),
                    src: Value::Reg(VReg::Temp(0)),
                },
            },
        );
        let Op::Call { target, .. } = &mut function.blocks[1].instrs[2].op else {
            panic!("expected indirect call")
        };
        *target = CallTarget::Indirect(Value::Reg(VReg::Temp(1)));
        let mut facts = super::DirectCalleeFacts::default();
        for target in [0x2000, 0x2100] {
            facts
                .table_entry_layouts
                .insert(target, vec![VReg::phys("x0")]);
        }

        super::apply_recovered_table_call_effects(
            &mut function,
            crate::ir::call_args::CallConv::Aarch64,
            &facts,
            &[table(&[0x2000, 0x2100])],
        );

        let Op::Call {
            target: CallTarget::Indirect(Value::Reg(target)),
            effects: Some(effects),
        } = &function.blocks[1].instrs[2].op
        else {
            panic!("expected annotated copied indirect call")
        };
        assert_eq!(target, &VReg::Temp(1));
        assert_eq!(effects.proven_args, [VReg::phys("x0")]);
        assert!(effects.args_are_exact);
    }

    #[test]
    fn unknown_page_arithmetic_does_not_narrow_table_call() {
        use crate::ir::types::{LlirInstr, Op, VReg, Value};

        let mut function = flat_loop_table_call();
        function.blocks[0].instrs.push(LlirInstr {
            va: 0x1004,
            op: Op::Bin {
                dst: VReg::phys("r13"),
                op: crate::ir::types::BinOp::Mul,
                lhs: Value::Reg(VReg::phys("r13")),
                rhs: Value::Const(1),
            },
        });
        let mut facts = super::DirectCalleeFacts::default();
        for target in [0x2000, 0x2100] {
            facts
                .table_entry_layouts
                .insert(target, vec![VReg::phys("rdi")]);
        }

        super::apply_recovered_table_call_effects(
            &mut function,
            crate::ir::call_args::CallConv::SysVAmd64,
            &facts,
            &[table(&[0x2000, 0x2100])],
        );

        let Op::Call { effects, .. } = &function.blocks[1].instrs[1].op else {
            panic!("expected indirect call")
        };
        assert!(effects.is_none());
    }

    #[test]
    fn incomplete_table_contract_does_not_narrow_indirect_call() {
        let mut function = flat_loop_table_call();
        let mut facts = super::DirectCalleeFacts::default();
        facts
            .table_entry_layouts
            .insert(0x2000, vec![crate::ir::types::VReg::phys("rdi")]);

        super::apply_recovered_table_call_effects(
            &mut function,
            crate::ir::call_args::CallConv::SysVAmd64,
            &facts,
            &[table(&[0x2000, 0x2100])],
        );

        let crate::ir::types::Op::Call { effects, .. } = &function.blocks[1].instrs[1].op else {
            panic!("expected indirect call")
        };
        assert!(effects.is_none());
    }

    #[test]
    fn conflicting_predecessor_table_provenance_is_rejected() {
        use crate::ir::types::{LlirBlock, LlirInstr, Op, VReg, Value};
        let mut function = flat_loop_table_call();
        function.blocks[0].succs = vec![0x1080, 0x1090];
        function.blocks.insert(
            1,
            LlirBlock {
                start_va: 0x1080,
                end_va: 0x1084,
                instrs: vec![],
                succs: vec![0x1100],
            },
        );
        function.blocks.insert(
            2,
            LlirBlock {
                start_va: 0x1090,
                end_va: 0x1094,
                instrs: vec![LlirInstr {
                    va: 0x1090,
                    op: Op::Assign {
                        dst: VReg::phys("r13"),
                        src: Value::Const(0),
                    },
                }],
                succs: vec![0x1100],
            },
        );
        let mut facts = super::DirectCalleeFacts::default();
        for target in [0x2000, 0x2100] {
            facts
                .table_entry_layouts
                .insert(target, vec![VReg::phys("rdi")]);
        }

        super::apply_recovered_table_call_effects(
            &mut function,
            crate::ir::call_args::CallConv::SysVAmd64,
            &facts,
            &[table(&[0x2000, 0x2100])],
        );

        let Op::Call { effects, .. } = &function.blocks[3].instrs[1].op else {
            panic!("expected indirect call")
        };
        assert!(effects.is_none());
    }

    fn passthrough_caller(
        spill: crate::ir::types::MemOp,
        load: crate::ir::types::MemOp,
        between: Vec<crate::ir::types::Op>,
    ) -> crate::ir::types::LlirFunction {
        use crate::ir::types::{CallEffects, CallTarget, LlirBlock, LlirInstr, Op, VReg, Value};

        let mut ops = vec![Op::Store {
            addr: spill,
            src: Value::Reg(VReg::phys("rdi")),
        }];
        ops.extend(between);
        ops.extend([
            Op::Load {
                dst: VReg::phys("rax"),
                addr: load,
            },
            Op::Assign {
                dst: VReg::phys("rdi"),
                src: Value::Reg(VReg::phys("rax")),
            },
            Op::Call {
                target: CallTarget::Direct(0x2000),
                effects: Some(CallEffects {
                    args: vec![VReg::phys("rdi")],
                    proven_args: vec![VReg::phys("rdi")],
                    args_are_exact: true,
                    ..Default::default()
                }),
            },
            Op::Return,
        ]);
        crate::ir::types::LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1014,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(index, op)| LlirInstr {
                        va: 0x1000 + index as u64 * 4,
                        op,
                    })
                    .collect(),
                succs: Vec::new(),
            }],
        }
    }

    fn stack_slot(disp: i64) -> crate::ir::types::MemOp {
        crate::ir::types::MemOp {
            base: Some(crate::ir::types::VReg::phys("rbp")),
            disp,
            size: 8,
            ..Default::default()
        }
    }

    fn refine_spilled_passthrough(
        function: &crate::ir::types::LlirFunction,
    ) -> crate::ir::types_recover::RecoveredPrototype {
        use crate::ir::call_args::CallConv;

        let ssa = crate::ir::ssa::compute_ssa(function);
        let mut prototype = crate::ir::types_recover::recover_prototype(
            function,
            &ssa,
            CallConv::SysVAmd64,
            &std::collections::HashSet::from([0]),
        );
        let mut facts = super::DirectCalleeFacts::default();
        facts
            .layouts
            .insert(0x2000, vec![crate::ir::types::VReg::phys("rdi")]);
        facts.prototypes.insert(
            0x2000,
            CallPrototype {
                return_type: "int".into(),
                parameter_types: vec!["int *".into()],
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            },
        );
        super::refine_passthrough_parameter_hints(&mut prototype, function, &ssa, &facts);
        prototype
    }

    #[test]
    fn exact_same_block_spill_reload_refines_passthrough_parameter() {
        let slot = stack_slot(-8);
        let prototype =
            refine_spilled_passthrough(&passthrough_caller(slot.clone(), slot, Vec::new()));

        assert_eq!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(crate::ir::types_recover::TypeHint::Pointer { pointee_width: 4 })
        );
    }

    #[test]
    fn intervening_memory_writer_blocks_spill_passthrough_refinement() {
        use crate::ir::types::{Op, Value};

        let slot = stack_slot(-8);
        let prototype = refine_spilled_passthrough(&passthrough_caller(
            slot.clone(),
            slot,
            vec![Op::Store {
                addr: stack_slot(-16),
                src: Value::Const(0),
            }],
        ));

        assert!(!matches!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(crate::ir::types_recover::TypeHint::Pointer { .. })
        ));
    }

    #[test]
    fn redefined_address_base_blocks_spill_passthrough_refinement() {
        use crate::ir::types::{Op, VReg, Value};

        let slot = stack_slot(-8);
        let prototype = refine_spilled_passthrough(&passthrough_caller(
            slot.clone(),
            slot,
            vec![Op::Assign {
                dst: VReg::phys("rbp"),
                src: Value::Const(0),
            }],
        ));

        assert!(!matches!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(crate::ir::types_recover::TypeHint::Pointer { .. })
        ));
    }

    #[test]
    fn different_spill_slot_blocks_passthrough_refinement() {
        let prototype = refine_spilled_passthrough(&passthrough_caller(
            stack_slot(-8),
            stack_slot(-16),
            Vec::new(),
        ));

        assert!(!matches!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(crate::ir::types_recover::TypeHint::Pointer { .. })
        ));
    }

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
