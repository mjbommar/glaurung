/// Index authoritative DWARF prototype contracts once per binary analysis.
///
/// Batch decompilation must not reparse debug sections for every function.
/// The CFG analyser already consumes DWARF for boundaries and names; this
/// compact companion map carries parameter and output facts to typed recovery.
#[derive(Debug, Clone)]
pub(super) struct DwarfPrototypeContract {
    pub(super) function_name: Option<String>,
    /// Whether the producer marked this as a complete function prototype.
    /// This distinguishes `f(void)` from an old-style `f()` when both have no
    /// formal-parameter DIEs.
    pub(super) prototyped: bool,
    pub(super) parameter_types: Vec<crate::debug::dwarf::DwarfParameterType>,
    pub(super) parameter_names: Vec<Option<String>>,
    pub(super) return_type: crate::debug::dwarf::DwarfReturnType,
    pub(super) stack_objects: Vec<crate::debug::dwarf::DwarfStackObject>,
    pub(super) register_locals: Vec<crate::debug::dwarf::DwarfRegisterLocal>,
    pub(super) static_locals: Vec<crate::debug::dwarf::DwarfStaticLocal>,
}

pub(super) fn dwarf_output_contracts(
    image: &crate::program::image::ProgramImage,
) -> std::collections::HashMap<u64, DwarfPrototypeContract> {
    image
        .dwarf_functions()
        .iter()
        .filter_map(|function| {
            let entry_va = if function.chunks.is_empty() {
                // A name-only declaration is safe to render as C only when it
                // came from a C-family compilation unit. Rust/Go declarations
                // describe a different source ABI and routinely share local
                // monomorphized names; treating them as C contracts changed
                // LLIR parameter materialization and regressed definedness.
                if !matches!(function.language.as_deref(), Some("C" | "C++")) {
                    return None;
                }
                function
                    .name
                    .as_deref()
                    .and_then(|name| image.unique_defined_text_symbol_address(name))?
            } else {
                function.entry_va
            };
            Some((
                entry_va,
                DwarfPrototypeContract {
                    function_name: function.name.clone(),
                    prototyped: function.prototyped,
                    parameter_types: function.parameter_types.clone(),
                    parameter_names: function.parameter_names.clone(),
                    return_type: function.return_type.clone(),
                    stack_objects: function.stack_objects.clone(),
                    register_locals: function.register_locals.clone(),
                    static_locals: function.static_locals.clone(),
                },
            ))
        })
        .collect()
}

/// Index authoritative PDB module-procedure declarations by PE virtual address.
///
/// Unlike public symbols, `S_GPROC32`/`S_LPROC32` records carry both the code
/// address and the TPI index of the complete function type. Cache misses and
/// malformed optional debug data remain best-effort and yield no contracts.
pub(super) fn pdb_output_contracts(
    pe_path: &str,
    cache_dir: &std::path::Path,
) -> std::collections::HashMap<u64, DwarfPrototypeContract> {
    use crate::debug::dwarf::{DwarfParameterType, DwarfReturnType};

    let Ok(Some(source)) = crate::symbols::pdb::PdbIngestor::from_pe_cache(pe_path, cache_dir)
    else {
        return std::collections::HashMap::new();
    };
    let Ok(declarations) = source.function_declarations() else {
        return std::collections::HashMap::new();
    };

    declarations
        .into_iter()
        .filter_map(|declaration| {
            let va = declaration.va?;
            let return_type = match declaration.prototype.return_type_name.as_deref() {
                Some("void") => DwarfReturnType::Void,
                Some(c_type) => DwarfReturnType::Type(c_type.to_string()),
                None => DwarfReturnType::Unknown,
            };
            let parameter_types = declaration
                .prototype
                .argument_type_names
                .into_iter()
                .map(|c_type| match c_type {
                    Some(c_type) => DwarfParameterType::Type(c_type),
                    None => DwarfParameterType::Unknown,
                })
                .collect::<Vec<_>>();
            let parameter_names = vec![None; parameter_types.len()];
            Some((
                va,
                DwarfPrototypeContract {
                    function_name: Some(declaration.name),
                    prototyped: true,
                    parameter_types,
                    parameter_names,
                    return_type,
                    stack_objects: Vec::new(),
                    register_locals: Vec::new(),
                    static_locals: Vec::new(),
                },
            ))
        })
        .collect()
}

/// Merge compiler declarations with deterministic authority ordering.
/// DWARF wins if a binary unusually carries both formats at the same address.
pub(super) fn debug_output_contracts(
    image: &crate::program::image::ProgramImage,
    binary_path: &str,
    pdb_cache: &str,
) -> (
    std::collections::HashMap<u64, DwarfPrototypeContract>,
    std::collections::HashSet<u64>,
    Vec<crate::debug::dwarf::DwarfType>,
) {
    use crate::program::environment::DeclarationSource;

    let dwarf_contracts = dwarf_output_contracts(image);
    let mut contracts = dwarf_contracts.clone();
    let mut pdb_addresses = std::collections::HashSet::new();
    let mut pdb_types = Vec::new();
    if let Some(cache_dir) = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache)) {
        let pdb_contracts = pdb_output_contracts(binary_path, cache_dir);
        pdb_types = pdb_type_layouts(binary_path, cache_dir, pdb_contracts.values());
        for (va, pdb_contract) in pdb_contracts {
            let selected = match dwarf_contracts.get(&va).cloned() {
                Some(dwarf_contract) => DeclarationSource::strongest(
                    (DeclarationSource::Pdb, pdb_contract),
                    (DeclarationSource::Dwarf, dwarf_contract),
                ),
                None => (DeclarationSource::Pdb, pdb_contract),
            };
            if selected.0 == DeclarationSource::Pdb {
                pdb_addresses.insert(va);
            }
            contracts.insert(va, selected.1);
        }
    }
    (contracts, pdb_addresses, pdb_types)
}

fn pdb_type_layouts<'a>(
    binary_path: &str,
    cache_dir: &std::path::Path,
    contracts: impl Iterator<Item = &'a DwarfPrototypeContract>,
) -> Vec<crate::debug::dwarf::DwarfType> {
    use crate::debug::dwarf::{DwarfField, DwarfParameterType, DwarfReturnType, DwarfType};

    let mut names = std::collections::BTreeMap::new();
    for contract in contracts {
        if let DwarfReturnType::Type(c_type) = &contract.return_type {
            if let Some((name, kind)) = tagged_pdb_type_name(c_type) {
                names.insert(name, kind);
            }
        }
        for parameter in &contract.parameter_types {
            if let DwarfParameterType::Type(c_type) = parameter {
                if let Some((name, kind)) = tagged_pdb_type_name(c_type) {
                    names.insert(name, kind);
                }
            }
        }
    }
    let Ok(Some(source)) = crate::symbols::pdb::PdbIngestor::from_pe_cache(binary_path, cache_dir)
    else {
        return Vec::new();
    };

    let requested = names
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let Ok(layouts) = source.find_struct_layouts(&requested) else {
        return Vec::new();
    };
    layouts
        .into_iter()
        .filter_map(|layout| {
            let kind = *names.get(&layout.name)?;
            Some(DwarfType {
                kind,
                name: layout.name,
                byte_size: layout.byte_size,
                fields: layout
                    .fields
                    .into_iter()
                    .filter_map(|field| {
                        Some(DwarfField {
                            offset: field.byte_offset,
                            name: field.name,
                            c_type: field.type_name?,
                            size: 0,
                        })
                    })
                    .collect(),
                variants: Vec::new(),
                typedef_target: None,
                source_file: None,
            })
        })
        .collect()
}

fn tagged_pdb_type_name(c_type: &str) -> Option<(String, crate::debug::dwarf::DwarfTypeKind)> {
    use crate::debug::dwarf::DwarfTypeKind;

    let normalized = c_type.split_whitespace().collect::<Vec<_>>().join(" ");
    let base = normalized.trim_end_matches('*').trim();
    let mut words = base.split_whitespace();
    let kind = match words.next()? {
        "struct" | "class" => DwarfTypeKind::Struct,
        "union" => DwarfTypeKind::Union,
        "enum" => DwarfTypeKind::Enum,
        _ => return None,
    };
    let name = words.next()?;
    (words.next().is_none()).then(|| (name.to_string(), kind))
}

pub(super) fn dwarf_stack_object_hints(
    contract: Option<&DwarfPrototypeContract>,
    cc: crate::ir::call_args::CallConv,
) -> Vec<crate::ir::stack_locals::StackObjectHint> {
    use crate::debug::dwarf::DwarfStackBase;
    use crate::ir::call_args::CallConv;

    let Some(contract) = contract else {
        return Vec::new();
    };
    contract
        .stack_objects
        .iter()
        .filter_map(|object| {
            // `cfa_relative` records which of these arms produced the base, not
            // just where it landed. The x86 CFA arms name a frame-pointer
            // coordinate the body only forms when it establishes one; the stack
            // pass rebases those onto the entry stack pointer when it does not,
            // and must be able to tell them from a hint DWARF genuinely rooted
            // at `rbp`/`ebp`.
            let (base, adjustment, cfa_relative) = match (cc, object.base) {
                (CallConv::SysVAmd64 | CallConv::Win64, DwarfStackBase::Register(6)) => {
                    ("rbp", 0, false)
                }
                (CallConv::SysVAmd64 | CallConv::Win64, DwarfStackBase::CallFrameCfa) => {
                    ("rbp", 16, true)
                }
                // The decoder canonicalizes 32-bit x86 register operands into
                // their parent identities (`ebp` -> `rbp`). Keep DWARF in that
                // same coordinate space or an exact `DW_OP_breg5 - N` local
                // seeds an unused `ebp` slot beside the real `rbp` access.
                (CallConv::Cdecl32, DwarfStackBase::Register(5)) => ("rbp", 0, false),
                (CallConv::Cdecl32, DwarfStackBase::CallFrameCfa) => ("rbp", 8, true),
                (CallConv::Aarch64, DwarfStackBase::Register(29)) => ("x29", 0, false),
                // DWARF register 31 is SP in AArch64 location expressions.
                // Clang O0 uses direct `DW_OP_breg31 + offset` locations for
                // scalar locals even while DW_AT_frame_base names x29.
                (CallConv::Aarch64, DwarfStackBase::Register(31)) => ("sp", 0, false),
                // DW_OP_fbreg is relative to the call-frame address, which is
                // the architectural entry SP. The stack-local pass retains
                // this coordinate for proven aggregates and reconciles it with
                // the current-SP delta without globally rebasing AArch64's
                // ordinary own-frame slots.
                (CallConv::Aarch64, DwarfStackBase::CallFrameCfa) => ("entry_sp", 0, true),
                (CallConv::Arm | CallConv::ArmHardFloat, DwarfStackBase::Register(11 | 7)) => {
                    ("fp", 0, false)
                }
                (CallConv::Arm | CallConv::ArmHardFloat, DwarfStackBase::CallFrameCfa) => {
                    ("entry_sp", 0, true)
                }
                _ => return None,
            };
            Some(crate::ir::stack_locals::StackObjectHint {
                base: base.to_string(),
                disp: object.offset.checked_add(adjustment)?,
                size: object.byte_size,
                aggregate: object.aggregate,
                source_name: object.source_name.clone(),
                c_type: object.c_type.clone(),
                cfa_relative,
            })
        })
        .collect()
}

/// Which recovered value, if any, a DWARF register local names.
enum RegisterLocalRole {
    /// No numbered value uses the register anywhere in the recorded ranges.
    Unbound,
    /// Several distinct values tie for the strongest evidence.
    Ambiguous,
    /// Exactly one numbered role carries the local.
    Bound(String),
}

/// Score every numbered value that uses the local's register inside its live
/// ranges and keep the single strongest, if there is one.
fn resolve_register_local_role(
    local: &crate::debug::dwarf::DwarfRegisterLocal,
    numbered: &crate::ir::types::LlirFunction,
    role_names: &std::collections::HashMap<String, String>,
    arch: crate::core::binary::Arch,
) -> RegisterLocalRole {
    let mut counts = std::collections::HashMap::<String, usize>::new();
    for location in &local.locations {
        let Some(machine_register) = dwarf_machine_register(arch, location.register) else {
            continue;
        };
        for instruction in numbered
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter(|instruction| instruction.va >= location.start && instruction.va < location.end)
        {
            // A range ending at an epilogue can overlap the instruction
            // that restores the same callee-saved register. That restore
            // is a definition of machine state, not a use of the source
            // local. Requiring an in-range use rejects that false tie
            // while retaining the value that actually feeds the body.
            let (_definition, registers) = crate::ir::use_def::def_uses(&instruction.op);
            let mut seen_roles = std::collections::HashSet::new();
            for register in registers {
                let crate::ir::types::VReg::Phys(raw_name) = register else {
                    continue;
                };
                if crate::ir::abi::ssa_base(&raw_name) != machine_register {
                    continue;
                }
                let Some(role) = role_names.get(&raw_name) else {
                    continue;
                };
                if seen_roles.insert(role.clone()) {
                    *counts.entry(role.clone()).or_default() += 1;
                }
            }
        }
    }
    let Some(maximum) = counts.values().copied().max() else {
        if std::env::var_os("GLAURUNG_DUMP_PASSES").is_some() {
            eprintln!("DWARF register local {:?}: no numbered role", local);
        }
        return RegisterLocalRole::Unbound;
    };
    if std::env::var_os("GLAURUNG_DUMP_PASSES").is_some() {
        eprintln!("DWARF register local {:?}: role counts {counts:?}", local);
    }
    let mut winners = counts
        .into_iter()
        .filter_map(|(role, count)| (count == maximum).then_some(role));
    let Some(role) = winners.next() else {
        return RegisterLocalRole::Unbound;
    };
    if winners.next().is_some() {
        // Equal evidence cannot select one machine value as the source
        // identity.
        return RegisterLocalRole::Ambiguous;
    }
    RegisterLocalRole::Bound(role)
}

/// The declared width of a scalar integer C type, when it is one.
///
/// Pointers and floats deliberately answer `None`: they do not participate in
/// the narrow/wide role contest below, and leaving them unresolved keeps the
/// established first-claimant behaviour for shapes this rule does not cover.
fn scalar_int_width(
    c_type: &str,
    cc: crate::ir::call_args::CallConv,
    type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
) -> Option<u8> {
    match dwarf_return_hint_with_env(c_type, cc, type_env) {
        Some(crate::ir::types_recover::TypeHint::Int { width, .. }) => Some(width),
        _ => None,
    }
}

/// Pick the claimant that must own a recovered value when several source
/// locals resolve to the same one.
///
/// An optimiser can serve two source variables of DIFFERENT widths from one
/// machine value whenever the narrow one is the wide one's truncation:
/// `product = (uint64_t)a * b; low = (uint32_t)product` leaves a single 64-bit
/// register live as both, and DWARF then records both locals at that register
/// over the same range. Only the widest claimant can be declared without
/// losing bits — the narrow reads of the same value already carry their own
/// truncating casts, while a narrow DECLARATION discards the high half before
/// any use can see it. Order of appearance is no evidence at all, so the
/// previous first-claimant-wins rule decided this on nothing.
///
/// Only a UNIQUE strict maximum overrides the existing order; a tie at the top
/// or unresolvable spellings leave the choice exactly where it was.
fn widest_claimant_per_role(
    locals: &[crate::debug::dwarf::DwarfRegisterLocal],
    roles: &[RegisterLocalRole],
    cc: crate::ir::call_args::CallConv,
    type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
) -> std::collections::HashMap<String, usize> {
    let mut claimants = std::collections::HashMap::<&str, Vec<usize>>::new();
    for (index, role) in roles.iter().enumerate() {
        if let RegisterLocalRole::Bound(role) = role {
            claimants.entry(role.as_str()).or_default().push(index);
        }
    }
    let mut preferred = std::collections::HashMap::new();
    for (role, indices) in claimants {
        if indices.len() < 2 {
            continue;
        }
        let widths = indices
            .iter()
            .map(|&index| scalar_int_width(&locals[index].c_type, cc, type_env))
            .collect::<Vec<_>>();
        let Some(widest) = widths.iter().flatten().copied().max() else {
            continue;
        };
        let mut at_widest = indices
            .iter()
            .zip(&widths)
            .filter(|(_, width)| **width == Some(widest));
        let Some((&winner, _)) = at_widest.next() else {
            continue;
        };
        if at_widest.next().is_some() {
            continue;
        }
        preferred.insert(role.to_string(), winner);
    }
    preferred
}

pub(super) fn merge_dwarf_register_local_facts(
    facts: &mut crate::ir::stack_locals::StackLocalFacts,
    contract: Option<&DwarfPrototypeContract>,
    numbered: &crate::ir::types::LlirFunction,
    role_names: &std::collections::HashMap<String, String>,
    arch: crate::core::binary::Arch,
    cc: crate::ir::call_args::CallConv,
    type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
) {
    let Some(contract) = contract else {
        return;
    };
    let roles = contract
        .register_locals
        .iter()
        .map(|local| {
            if local.locations.is_empty() {
                RegisterLocalRole::Unbound
            } else {
                resolve_register_local_role(local, numbered, role_names, arch)
            }
        })
        .collect::<Vec<_>>();
    let preferred = widest_claimant_per_role(&contract.register_locals, &roles, cc, type_env);

    for (index, local) in contract.register_locals.iter().enumerate() {
        let role = match &roles[index] {
            // Keep the authoritative declaration without rewriting either
            // candidate's dataflow.
            RegisterLocalRole::Unbound | RegisterLocalRole::Ambiguous => {
                record_declaration_only(facts, local);
                continue;
            }
            RegisterLocalRole::Bound(role) => role.clone(),
        };
        if preferred
            .get(role.as_str())
            .is_some_and(|winner| *winner != index)
        {
            // A wider source local owns this recovered value.
            continue;
        }
        if !crate::ir::naming::valid_authoritative_local_name(&local.source_name)
            || crate::ir::ast::parse_arg_index(&role).is_some()
            || facts.source_names.contains_key(&role)
            || facts.source_types.contains_key(&role)
            || facts
                .source_names
                .values()
                .any(|name| name == &local.source_name)
            || (local.c_type.contains('*')
                && register_role_has_out_of_range_use(local, &role, numbered, role_names, arch))
        {
            continue;
        }
        facts
            .source_names
            .insert(role.clone(), local.source_name.clone());
        facts.source_types.insert(role, local.c_type.clone());
    }
}

fn record_declaration_only(
    facts: &mut crate::ir::stack_locals::StackLocalFacts,
    local: &crate::debug::dwarf::DwarfRegisterLocal,
) {
    if crate::ir::naming::valid_authoritative_local_name(&local.source_name)
        && !facts
            .source_names
            .values()
            .any(|name| name == &local.source_name)
    {
        facts
            .source_types
            .entry(local.source_name.clone())
            .or_insert_with(|| local.c_type.clone());
    }
}

fn register_role_has_out_of_range_use(
    local: &crate::debug::dwarf::DwarfRegisterLocal,
    role: &str,
    numbered: &crate::ir::types::LlirFunction,
    role_names: &std::collections::HashMap<String, String>,
    arch: crate::core::binary::Arch,
) -> bool {
    let predecessor_tolerance = match arch {
        crate::core::binary::Arch::ARM | crate::core::binary::Arch::AArch64 => 4,
        crate::core::binary::Arch::X86 | crate::core::binary::Arch::X86_64 => 15,
        _ => 0,
    };
    numbered
        .blocks
        .iter()
        .flat_map(|block| &block.instrs)
        .any(|instruction| {
            let (_definition, uses) = crate::ir::use_def::def_uses(&instruction.op);
            uses.into_iter().any(|register| {
                let crate::ir::types::VReg::Phys(raw_name) = register else {
                    return false;
                };
                if role_names.get(&raw_name).map(String::as_str) != Some(role) {
                    return false;
                }
                let machine_register = crate::ir::abi::ssa_base(&raw_name);
                let relevant_locations = local.locations.iter().filter(|location| {
                    dwarf_machine_register(arch, location.register) == Some(machine_register)
                });
                !relevant_locations.into_iter().any(|location| {
                    (instruction.va >= location.start && instruction.va < location.end)
                        || instruction
                            .va
                            .checked_add(predecessor_tolerance)
                            .is_some_and(|end| end >= location.start && end < location.end)
                })
            })
        })
}

pub(super) fn dwarf_machine_register(
    arch: crate::core::binary::Arch,
    register: u16,
) -> Option<&'static str> {
    use crate::core::binary::Arch;
    const ARM: [&str; 16] = [
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp",
        "lr", "pc",
    ];
    const X86: [&str; 8] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
    const X86_64: [&str; 16] = [
        "rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15",
    ];
    match arch {
        Arch::ARM => ARM.get(usize::from(register)).copied(),
        Arch::X86 => X86.get(usize::from(register)).copied(),
        Arch::X86_64 => X86_64.get(usize::from(register)).copied(),
        Arch::AArch64 if register <= 30 => Some(match register {
            0 => "x0",
            1 => "x1",
            2 => "x2",
            3 => "x3",
            4 => "x4",
            5 => "x5",
            6 => "x6",
            7 => "x7",
            8 => "x8",
            9 => "x9",
            10 => "x10",
            11 => "x11",
            12 => "x12",
            13 => "x13",
            14 => "x14",
            15 => "x15",
            16 => "x16",
            17 => "x17",
            18 => "x18",
            19 => "x19",
            20 => "x20",
            21 => "x21",
            22 => "x22",
            23 => "x23",
            24 => "x24",
            25 => "x25",
            26 => "x26",
            27 => "x27",
            28 => "x28",
            29 => "x29",
            30 => "x30",
            _ => return None,
        }),
        _ => None,
    }
}

pub(super) fn dwarf_source_register_lifetimes(
    contract: Option<&DwarfPrototypeContract>,
    cc: crate::ir::call_args::CallConv,
) -> Vec<crate::ir::value_number::SourceRegisterLifetime> {
    use crate::core::binary::Arch;
    use crate::ir::call_args::CallConv;

    let Some(contract) = contract else {
        return Vec::new();
    };
    let arch = match cc {
        CallConv::Arm | CallConv::ArmHardFloat => Arch::ARM,
        CallConv::Aarch64 => Arch::AArch64,
        CallConv::Cdecl32 => Arch::X86,
        CallConv::SysVAmd64 | CallConv::Win64 => Arch::X86_64,
    };
    contract
        .register_locals
        .iter()
        .flat_map(|local| {
            let mut by_register = std::collections::BTreeMap::<String, Vec<(u64, u64)>>::new();
            for location in &local.locations {
                let Some(register) = dwarf_machine_register(arch, location.register) else {
                    continue;
                };
                by_register
                    .entry(register.to_string())
                    .or_default()
                    .push((location.start, location.end));
            }
            by_register.into_iter().map(|(register, ranges)| {
                crate::ir::value_number::SourceRegisterLifetime { register, ranges }
            })
        })
        .collect()
}

pub(super) fn calling_convention_pointer_width(cc: crate::ir::call_args::CallConv) -> u8 {
    use crate::ir::call_args::CallConv;
    match cc {
        CallConv::Cdecl32 | CallConv::Arm | CallConv::ArmHardFloat => 4,
        CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Aarch64 => 8,
    }
}

/// Translate only DWARF scalar spellings that the current renderer can express
/// exactly. An unrepresentable declared type still locks the output as non-void;
/// it simply leaves machine-code recovery responsible for the concrete C type.
#[cfg(test)]
pub(super) fn dwarf_return_hint(
    c_type: &str,
    cc: crate::ir::call_args::CallConv,
) -> Option<crate::ir::types_recover::TypeHint> {
    dwarf_return_hint_with_env(c_type, cc, None)
}

pub(super) fn dwarf_return_hint_with_env(
    c_type: &str,
    cc: crate::ir::call_args::CallConv,
    type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
) -> Option<crate::ir::types_recover::TypeHint> {
    use crate::ir::types_recover::TypeHint;

    let normalized = c_type
        .split_whitespace()
        .filter(|word| !matches!(*word, "const" | "volatile" | "restrict"))
        .collect::<Vec<_>>()
        .join(" ");
    let c_long_width = match cc {
        crate::ir::call_args::CallConv::SysVAmd64 | crate::ir::call_args::CallConv::Aarch64 => 8,
        crate::ir::call_args::CallConv::Win64
        | crate::ir::call_args::CallConv::Cdecl32
        | crate::ir::call_args::CallConv::Arm
        | crate::ir::call_args::CallConv::ArmHardFloat => 4,
    };
    if let Some(pointee) = normalized.strip_suffix('*').map(str::trim) {
        let pointee_width = match dwarf_return_hint_with_env(pointee, cc, type_env) {
            Some(TypeHint::Int { width, .. } | TypeHint::Float { width }) => width,
            Some(TypeHint::BoolLike) => 1,
            Some(TypeHint::Pointer { .. } | TypeHint::CodePointer) => c_long_width,
            None => 1,
        };
        return Some(TypeHint::Pointer { pointee_width });
    }
    let scalar = type_env
        .and_then(|env| env.scalar_spelling(&normalized))
        .unwrap_or(normalized);
    match scalar.as_str() {
        "_Bool" | "bool" => Some(TypeHint::BoolLike),
        "char" | "signed char" | "int8_t" => Some(TypeHint::Int {
            signed: true,
            width: 1,
        }),
        "unsigned char" | "uint8_t" => Some(TypeHint::Int {
            signed: false,
            width: 1,
        }),
        "short" | "short int" | "signed short" | "signed short int" | "int16_t" => {
            Some(TypeHint::Int {
                signed: true,
                width: 2,
            })
        }
        "unsigned short" | "unsigned short int" | "uint16_t" => Some(TypeHint::Int {
            signed: false,
            width: 2,
        }),
        "int" | "signed" | "signed int" | "int32_t" => Some(TypeHint::Int {
            signed: true,
            width: 4,
        }),
        "unsigned" | "unsigned int" | "uint32_t" => Some(TypeHint::Int {
            signed: false,
            width: 4,
        }),
        "long" | "long int" | "signed long" | "signed long int" => Some(TypeHint::Int {
            signed: true,
            width: c_long_width,
        }),
        "unsigned long" | "unsigned long int" | "long unsigned" | "long unsigned int" => {
            Some(TypeHint::Int {
                signed: false,
                width: c_long_width,
            })
        }
        "long long" | "long long int" | "signed long long" | "signed long long int" | "int64_t" => {
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            })
        }
        "unsigned long long"
        | "unsigned long long int"
        | "long long unsigned"
        | "long long unsigned int"
        | "uint64_t" => Some(TypeHint::Int {
            signed: false,
            width: 8,
        }),
        "float" => Some(TypeHint::Float { width: 4 }),
        "double" => Some(TypeHint::Float { width: 8 }),
        _ => None,
    }
}

/// Translate source-language scalar aliases into self-contained C spellings.
///
/// Rust DWARF retains names such as `i32` and `u32` even for an exported
/// `extern "C"` function. Those names prove exact storage widths but are not C
/// tokens. Keep this translation at the debug-to-render boundary so the
/// generic C catalog normalizer does not accidentally reinterpret language
/// pointers or aggregates.
fn standalone_dwarf_type(source_type: &str) -> String {
    let source_type = source_type.trim();
    let normalized = source_type.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut unqualified = normalized.as_str();
    while let Some(rest) = ["const ", "volatile ", "restrict "]
        .into_iter()
        .find_map(|qualifier| unqualified.strip_prefix(qualifier))
    {
        unqualified = rest;
    }
    // `standalone_c_type` is also used for inferred library catalogs, where
    // degrading an unknown aggregate pointee to `void *` is appropriately
    // conservative.  A DWARF/PDB spelling is an authoritative declaration,
    // however: retain its nominal tag and let the renderer's type environment
    // prove whether it can emit the declaration and any recovered layout.
    if unqualified.starts_with("struct ") || unqualified.starts_with("union ") {
        return normalized;
    }
    let rust_scalar = match source_type {
        "u8" => Some("unsigned char"),
        "i8" => Some("signed char"),
        "u16" => Some("unsigned short"),
        "i16" => Some("short"),
        "u32" => Some("unsigned int"),
        "i32" => Some("int"),
        "u64" => Some("unsigned long long"),
        "i64" => Some("long long"),
        "usize" => Some("__SIZE_TYPE__"),
        "isize" => Some("__PTRDIFF_TYPE__"),
        "u128" => Some("unsigned __int128"),
        "i128" => Some("__int128"),
        _ => None,
    };
    rust_scalar.map(str::to_string).unwrap_or_else(|| {
        crate::ir::call_contracts::standalone_c_type(source_type)
            .unwrap_or_else(|| source_type.to_string())
    })
}

pub(super) fn dwarf_render_prototype(
    declared: &DwarfPrototypeContract,
) -> Option<crate::ir::call_contracts::CallPrototype> {
    use crate::debug::dwarf::{DwarfParameterType, DwarfReturnType};
    use crate::ir::call_contracts::{CallPrototype, CallPrototypeAuthority};

    let return_type = match &declared.return_type {
        DwarfReturnType::Void => "void".to_string(),
        DwarfReturnType::Type(c_type) => standalone_dwarf_type(c_type),
        DwarfReturnType::Unknown => return None,
    };
    let parameter_types = declared
        .parameter_types
        .iter()
        .map(|parameter| match parameter {
            DwarfParameterType::Type(c_type) => Some(standalone_dwarf_type(c_type)),
            DwarfParameterType::Unknown => None,
        })
        .collect::<Option<Vec<_>>>()?;
    Some(CallPrototype {
        return_type,
        parameter_types,
        variadic: false,
        authority: CallPrototypeAuthority::Authoritative,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn rust_fixed_width_scalars_have_standalone_c_spellings() {
        assert_eq!(super::standalone_dwarf_type("i32"), "int");
        assert_eq!(super::standalone_dwarf_type("u32"), "unsigned int");
        assert_eq!(super::standalone_dwarf_type("isize"), "__PTRDIFF_TYPE__");
        assert_eq!(super::standalone_dwarf_type("usize"), "__SIZE_TYPE__");
        assert_eq!(super::standalone_dwarf_type("struct Pair"), "struct Pair");
    }

    #[test]
    fn authoritative_tagged_pointers_keep_their_nominal_type() {
        assert_eq!(
            super::standalone_dwarf_type("struct Record *"),
            "struct Record *"
        );
        assert_eq!(
            super::standalone_dwarf_type("const union Payload *"),
            "const union Payload *"
        );
    }
}
