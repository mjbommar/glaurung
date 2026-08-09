/// Index authoritative DWARF prototype contracts once per binary analysis.
///
/// Batch decompilation must not reparse debug sections for every function.
/// The CFG analyser already consumes DWARF for boundaries and names; this
/// compact companion map carries parameter and output facts to typed recovery.
#[derive(Debug, Clone)]
pub(super) struct DwarfPrototypeContract {
    /// Whether the producer marked this as a complete function prototype.
    /// This distinguishes `f(void)` from an old-style `f()` when both have no
    /// formal-parameter DIEs.
    pub(super) prototyped: bool,
    pub(super) parameter_types: Vec<crate::debug::dwarf::DwarfParameterType>,
    pub(super) return_type: crate::debug::dwarf::DwarfReturnType,
    pub(super) stack_objects: Vec<crate::debug::dwarf::DwarfStackObject>,
    pub(super) register_locals: Vec<crate::debug::dwarf::DwarfRegisterLocal>,
}

pub(super) fn dwarf_output_contracts(
    data: &[u8],
) -> std::collections::HashMap<u64, DwarfPrototypeContract> {
    crate::debug::dwarf::extract_dwarf_functions(data)
        .into_iter()
        .map(|function| {
            (
                function.entry_va,
                DwarfPrototypeContract {
                    prototyped: function.prototyped,
                    parameter_types: function.parameter_types,
                    return_type: function.return_type,
                    stack_objects: function.stack_objects,
                    register_locals: function.register_locals,
                },
            )
        })
        .collect()
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
            let (base, adjustment) = match (cc, object.base) {
                (CallConv::SysVAmd64 | CallConv::Win64, DwarfStackBase::Register(6)) => ("rbp", 0),
                (CallConv::SysVAmd64 | CallConv::Win64, DwarfStackBase::CallFrameCfa) => {
                    ("rbp", 16)
                }
                (CallConv::Cdecl32, DwarfStackBase::Register(5)) => ("ebp", 0),
                (CallConv::Cdecl32, DwarfStackBase::CallFrameCfa) => ("ebp", 8),
                (CallConv::Aarch64, DwarfStackBase::Register(29)) => ("x29", 0),
                // DW_OP_fbreg is relative to the call-frame address, which is
                // the architectural entry SP. The stack-local pass retains
                // this coordinate for proven aggregates and reconciles it with
                // the current-SP delta without globally rebasing AArch64's
                // ordinary own-frame slots.
                (CallConv::Aarch64, DwarfStackBase::CallFrameCfa) => ("entry_sp", 0),
                (CallConv::Arm | CallConv::ArmHardFloat, DwarfStackBase::Register(11 | 7)) => {
                    ("fp", 0)
                }
                (CallConv::Arm | CallConv::ArmHardFloat, DwarfStackBase::CallFrameCfa) => {
                    ("entry_sp", 0)
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
            })
        })
        .collect()
}

pub(super) fn merge_dwarf_register_local_facts(
    facts: &mut crate::ir::stack_locals::StackLocalFacts,
    contract: Option<&DwarfPrototypeContract>,
    numbered: &crate::ir::types::LlirFunction,
    role_names: &std::collections::HashMap<String, String>,
    arch: crate::core::binary::Arch,
) {
    let Some(contract) = contract else {
        return;
    };
    for local in &contract.register_locals {
        if local.locations.is_empty() {
            record_declaration_only(facts, local);
            continue;
        }
        let mut counts = std::collections::HashMap::<String, usize>::new();
        for location in &local.locations {
            let Some(machine_register) = dwarf_machine_register(arch, location.register) else {
                continue;
            };
            for instruction in numbered
                .blocks
                .iter()
                .flat_map(|block| &block.instrs)
                .filter(|instruction| {
                    instruction.va >= location.start && instruction.va < location.end
                })
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
            record_declaration_only(facts, local);
            continue;
        };
        if std::env::var_os("GLAURUNG_DUMP_PASSES").is_some() {
            eprintln!("DWARF register local {:?}: role counts {counts:?}", local);
        }
        let mut winners = counts
            .into_iter()
            .filter_map(|(role, count)| (count == maximum).then_some(role));
        let Some(role) = winners.next() else {
            continue;
        };
        if winners.next().is_some() {
            // Equal evidence cannot select one machine value as the source
            // identity. Keep the authoritative declaration without rewriting
            // either candidate's dataflow.
            record_declaration_only(facts, local);
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

pub(super) fn dwarf_render_prototype(
    declared: &DwarfPrototypeContract,
) -> Option<crate::ir::call_contracts::CallPrototype> {
    use crate::debug::dwarf::{DwarfParameterType, DwarfReturnType};
    use crate::ir::call_contracts::{CallPrototype, CallPrototypeAuthority};

    let return_type = match &declared.return_type {
        DwarfReturnType::Void => "void".to_string(),
        DwarfReturnType::Type(c_type) => c_type.clone(),
        DwarfReturnType::Unknown => return None,
    };
    let parameter_types = declared
        .parameter_types
        .iter()
        .map(|parameter| match parameter {
            DwarfParameterType::Type(c_type) => Some(c_type.clone()),
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
