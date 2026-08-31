//! Interprocedural format-wrapper contracts for the program environment.
//!
//! A wrapper such as `try_help(format, operand)` can erase `operand`'s type
//! from its own machine body by forwarding it through a variadic API.  When all
//! direct callers provide literal formats, those formats are authoritative
//! type evidence. Dynamic, unsupported, and contradictory formats fail closed.

use std::collections::{BTreeSet, HashMap};

use crate::analysis::cfg::{discover_function_image_at, Budgets};
use crate::ir::call_args::CallConv;
use crate::ir::lift_function::lift_function_from_image;
use crate::ir::types::{CallTarget, LlirFunction, Op, VReg, Value};
use crate::ir::types_recover::TypeHint;
use crate::program::image::ProgramImage;

use super::environment::{
    clean_import_name, direct_call_sites, input_states_for_image, transfer_instruction,
    AbstractValue, CallSemantics,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct FormatForwarding {
    format_parameter: usize,
    conversion_parameters: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FormatConsumer {
    format_argument: usize,
    variadic_start: Option<usize>,
}

fn known_call_semantics(address_names: &HashMap<u64, String>) -> HashMap<u64, CallSemantics> {
    address_names
        .iter()
        .filter_map(|(address, name)| match clean_import_name(name) {
            "gettext" => Some((
                *address,
                CallSemantics::MessageIdentity { argument_index: 0 },
            )),
            "dcgettext" => Some((
                *address,
                CallSemantics::MessageIdentity { argument_index: 1 },
            )),
            _ => None,
        })
        .collect()
}

fn format_consumer(name: &str) -> Option<FormatConsumer> {
    let consumer = match name {
        "printf" => FormatConsumer {
            format_argument: 0,
            variadic_start: Some(1),
        },
        "fprintf" => FormatConsumer {
            format_argument: 1,
            variadic_start: Some(2),
        },
        "__printf_chk" => FormatConsumer {
            format_argument: 1,
            variadic_start: Some(2),
        },
        "__fprintf_chk" => FormatConsumer {
            format_argument: 2,
            variadic_start: Some(3),
        },
        "error" => FormatConsumer {
            format_argument: 2,
            variadic_start: Some(3),
        },
        "vprintf" => FormatConsumer {
            format_argument: 0,
            variadic_start: None,
        },
        "vfprintf" => FormatConsumer {
            format_argument: 1,
            variadic_start: None,
        },
        "__vfprintf_chk" => FormatConsumer {
            format_argument: 2,
            variadic_start: None,
        },
        _ => return None,
    };
    Some(consumer)
}

fn format_consumers(address_names: &HashMap<u64, String>) -> HashMap<u64, FormatConsumer> {
    address_names
        .iter()
        .filter_map(|(address, name)| {
            format_consumer(clean_import_name(name)).map(|consumer| (*address, consumer))
        })
        .collect()
}

/// The views of `address_names` this module actually consults, built once.
///
/// `known_call_semantics` and `format_consumers` each walk the WHOLE address
/// -name map and allocate a fresh `HashMap`, and both are derived purely from
/// `address_names`, which does not change while a binary is being analysed.
/// They were being rebuilt inside `recover_format_parameter_hints`, which
/// `recover_program_environment` calls once per requested function -- and that
/// function calls two helpers which each rebuild both, so a binary paid up to
/// FOUR full map walks and four map constructions per function. On
/// `/usr/bin/bash` (2,954 functions) that is roughly 11,800 walks of a map
/// whose contents never move.
///
/// perf attributed 5.2% of a release decompile to the two `fold_impl`
/// specializations alone, before counting the allocator and hashing work the
/// rebuilt maps drive -- and the allocator is 26% of that profile.
pub(super) struct FormatIndex {
    semantics: HashMap<u64, CallSemantics>,
    consumers: HashMap<u64, FormatConsumer>,
    has_consumer: bool,
}

impl FormatIndex {
    /// Build every derived view in one pass over `address_names`.
    pub(super) fn build(address_names: &HashMap<u64, String>) -> Self {
        let consumers = format_consumers(address_names);
        Self {
            semantics: known_call_semantics(address_names),
            has_consumer: !consumers.is_empty(),
            consumers,
        }
    }

    /// Whether any address names a format consumer.
    ///
    /// `format_consumers` keeps exactly the addresses whose cleaned name
    /// resolves to a `FormatConsumer`, so emptiness is the same predicate the
    /// former `has_format_consumer` scan computed.
    pub(super) fn has_consumer(&self) -> bool {
        self.has_consumer
    }
}

fn parameter_index(value: Option<&AbstractValue>) -> Option<usize> {
    match value {
        Some(AbstractValue::Parameter(index)) => Some(*index),
        _ => None,
    }
}

fn format_parameter_index(value: Option<&AbstractValue>) -> Option<usize> {
    match value {
        Some(AbstractValue::Parameter(index) | AbstractValue::FormatParameter(index)) => {
            Some(*index)
        }
        _ => None,
    }
}

fn recover_format_forwarding(
    function: &LlirFunction,
    image: &ProgramImage,
    cc: CallConv,
    index: &FormatIndex,
) -> Option<FormatForwarding> {
    let semantics = &index.semantics;
    let consumers = &index.consumers;
    if consumers.is_empty() {
        return None;
    }
    let inputs = input_states_for_image(function, cc, image, &semantics, true);
    let argument_registers = crate::ir::abi::argument_registers(cc);
    let mut found: Option<FormatForwarding> = None;
    for (block_index, block) in function.blocks.iter().enumerate() {
        let mut state = inputs[block_index].clone();
        for instruction in &block.instrs {
            if let Op::Call {
                target: CallTarget::Direct(target),
                ..
            } = instruction.op
            {
                if let Some(consumer) = consumers.get(&target) {
                    if let Some(variadic_start) = consumer.variadic_start {
                        let format_register = *argument_registers.get(consumer.format_argument)?;
                        if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
                            eprintln!("format sink 0x{:x}: {state:#x?}", instruction.va);
                        }
                        if let Some(format_parameter) =
                            format_parameter_index(state.registers.get(format_register))
                        {
                            let conversion_parameters = argument_registers
                                .iter()
                                .skip(variadic_start)
                                .take_while(|register| {
                                    state.written_registers.contains(**register)
                                        && parameter_index(state.registers.get(**register))
                                            .is_some()
                                })
                                .filter_map(|register| {
                                    parameter_index(state.registers.get(*register))
                                })
                                .collect::<Vec<_>>();
                            if !conversion_parameters.is_empty() {
                                let candidate = FormatForwarding {
                                    format_parameter,
                                    conversion_parameters,
                                };
                                if found
                                    .as_ref()
                                    .is_some_and(|existing| existing != &candidate)
                                {
                                    return None;
                                }
                                found = Some(candidate);
                            }
                        }
                    }
                }
            }
            transfer_instruction(&instruction.op, &mut state, image, cc, &semantics);
        }
    }
    found
}

fn has_sysv_variadic_register_save(function: &LlirFunction, fixed: usize) -> bool {
    if fixed != 1 {
        return false;
    }
    let registers = ["rsi", "rdx", "rcx", "r8", "r9"];
    let first_call = function
        .blocks
        .iter()
        .flat_map(|block| &block.instrs)
        .filter(|instruction| matches!(instruction.op, Op::Call { .. }))
        .map(|instruction| instruction.va)
        .min()
        .unwrap_or(u64::MAX);
    let mut offsets = HashMap::new();
    for instruction in function
        .blocks
        .iter()
        .flat_map(|block| &block.instrs)
        .filter(|instruction| instruction.va < first_call)
    {
        let Op::Store {
            addr,
            src: Value::Reg(VReg::Phys(source)),
        } = &instruction.op
        else {
            continue;
        };
        if addr.size != 8
            || addr.index.is_some()
            || addr.base.as_ref() != Some(&VReg::phys("rsp"))
            || !registers.contains(&source.as_str())
        {
            continue;
        }
        offsets.entry(source.as_str()).or_insert(addr.disp);
    }
    let Some(first_offset) = offsets.get(registers[0]).copied() else {
        return false;
    };
    registers.iter().enumerate().all(|(index, register)| {
        offsets.get(register).copied() == Some(first_offset + (index as i64 * 8))
    })
}

fn recover_local_format_sink(
    function: &LlirFunction,
    image: &ProgramImage,
    cc: CallConv,
    index: &FormatIndex,
) -> Option<usize> {
    let consumers = &index.consumers;
    if consumers.is_empty() {
        return None;
    }
    let semantics = &index.semantics;
    let inputs = input_states_for_image(function, cc, image, &semantics, true);
    let argument_registers = crate::ir::abi::argument_registers(cc);
    let mut found = None;
    for (block_index, block) in function.blocks.iter().enumerate() {
        let mut state = inputs[block_index].clone();
        for instruction in &block.instrs {
            if let Op::Call {
                target: CallTarget::Direct(target),
                ..
            } = instruction.op
            {
                if let Some(consumer) = consumers.get(&target) {
                    let format_register = *argument_registers.get(consumer.format_argument)?;
                    if let Some(parameter) =
                        format_parameter_index(state.registers.get(format_register))
                    {
                        if found.is_some_and(|existing| existing != parameter) {
                            return None;
                        }
                        found = Some(parameter);
                    }
                }
            }
            transfer_instruction(&instruction.op, &mut state, image, cc, &semantics);
        }
    }
    let parameter = found?;
    (cc == CallConv::SysVAmd64
        && has_sysv_variadic_register_save(function, parameter.saturating_add(1)))
    .then_some(parameter)
}

fn parse_printf_hints(format: &str, pointer_width: u8) -> Option<Vec<TypeHint>> {
    let bytes = format.as_bytes();
    let mut hints = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor] != b'%' {
            cursor += 1;
            continue;
        }
        cursor += 1;
        if bytes.get(cursor) == Some(&b'%') {
            cursor += 1;
            continue;
        }
        while bytes
            .get(cursor)
            .is_some_and(|byte| b"-+ #0'".contains(byte))
        {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b'*') {
            return None;
        }
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b'$') {
            return None;
        }
        if bytes.get(cursor) == Some(&b'.') {
            cursor += 1;
            if bytes.get(cursor) == Some(&b'*') {
                return None;
            }
            while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                cursor += 1;
            }
        }
        let length_start = cursor;
        while bytes
            .get(cursor)
            .is_some_and(|byte| b"hljztL".contains(byte))
        {
            cursor += 1;
        }
        let length = std::str::from_utf8(&bytes[length_start..cursor]).ok()?;
        let conversion = char::from(*bytes.get(cursor)?);
        cursor += 1;
        let integer_width = match length {
            "hh" => 1,
            "h" => 2,
            "l" | "z" | "t" => pointer_width,
            "ll" | "j" => 8,
            "" => 4,
            _ => return None,
        };
        let hint = match conversion {
            's' if length.is_empty() => TypeHint::Pointer { pointee_width: 1 },
            'c' if length.is_empty() => TypeHint::Int {
                signed: true,
                width: 4,
            },
            'd' | 'i' => TypeHint::Int {
                signed: true,
                width: integer_width,
            },
            'o' | 'u' | 'x' | 'X' => TypeHint::Int {
                signed: false,
                width: integer_width,
            },
            'p' if length.is_empty() => TypeHint::Pointer { pointee_width: 0 },
            'f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A' if length.is_empty() || length == "l" => {
                TypeHint::Float { width: 8 }
            }
            _ => return None,
        };
        hints.push(hint);
    }
    Some(hints)
}

fn merge_observed_hint(current: Option<TypeHint>, incoming: TypeHint) -> Option<TypeHint> {
    match current {
        None => Some(incoming),
        Some(existing) if existing == incoming => Some(existing),
        Some(TypeHint::Pointer {
            pointee_width: left,
        }) if matches!(incoming, TypeHint::Pointer { pointee_width: right } if left == 0 || right == 0) =>
        {
            let TypeHint::Pointer {
                pointee_width: right,
            } = incoming
            else {
                unreachable!()
            };
            Some(TypeHint::Pointer {
                pointee_width: left.max(right),
            })
        }
        Some(_) => None,
    }
}

fn apply_literal_format(
    value: Option<&AbstractValue>,
    string_pool: &HashMap<u64, String>,
    forwarding: &FormatForwarding,
    pointer_width: u8,
    hints: &mut [Option<TypeHint>],
) -> Option<bool> {
    let Some(conversions) = literal_format_hints(value, string_pool, pointer_width)? else {
        return Some(false);
    };
    if conversions.len() > forwarding.conversion_parameters.len() {
        return None;
    }
    let typed = !conversions.is_empty();
    for (parameter, incoming) in forwarding.conversion_parameters.iter().zip(conversions) {
        hints[*parameter] = Some(merge_observed_hint(hints[*parameter], incoming)?);
    }
    Some(typed)
}

fn literal_format_hints(
    value: Option<&AbstractValue>,
    string_pool: &HashMap<u64, String>,
    pointer_width: u8,
) -> Option<Option<Vec<TypeHint>>> {
    let address = match value {
        Some(AbstractValue::Scalar(0)) => return Some(None),
        Some(AbstractValue::Data(address)) => *address,
        Some(AbstractValue::Scalar(address)) if *address > 0 => u64::try_from(*address).ok()?,
        _ => return None,
    };
    Some(Some(parse_printf_hints(
        string_pool.get(&address)?,
        pointer_width,
    )?))
}

fn recover_direct_literal_parameter_hints(
    function: &LlirFunction,
    image: &ProgramImage,
    budgets: &Budgets,
    cc: CallConv,
    index: &FormatIndex,
) -> Option<Vec<Option<TypeHint>>> {
    let targeted_budgets = Budgets {
        max_functions: 1,
        ..*budgets
    };
    let mut sinks = index
        .consumers
        .iter()
        .map(|(k, v)| (*k, *v))
        .into_iter()
        .filter_map(|(target, consumer)| {
            consumer
                .variadic_start
                .map(|_| (target, consumer.format_argument))
        })
        .collect::<HashMap<_, _>>();
    let direct_targets = function
        .blocks
        .iter()
        .flat_map(|block| &block.instrs)
        .filter_map(|instruction| match instruction.op {
            Op::Call {
                target: CallTarget::Direct(target),
                ..
            } => Some(target),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    for target in direct_targets {
        if sinks.contains_key(&target) {
            continue;
        }
        let Some(callee) = discover_function_image_at(image, &targeted_budgets, target) else {
            continue;
        };
        let Ok(lifted) = lift_function_from_image(image, &callee) else {
            continue;
        };
        if let Some(format_parameter) = recover_local_format_sink(&lifted, image, cc, index) {
            sinks.insert(target, format_parameter);
        }
    }
    if sinks.is_empty() {
        return None;
    }

    let parameter_slots = crate::ir::value_number::live_in_arg_slots_llir(function, cc);
    let arity = parameter_slots.iter().copied().max()?.saturating_add(1);
    let mut hints = vec![None; arity];
    let semantics = &index.semantics;
    let inputs = input_states_for_image(function, cc, image, &semantics, true);
    let argument_registers = crate::ir::abi::argument_registers(cc);
    let string_pool = crate::ir::strings_fold::collect_string_pool_from_image(image);
    let pointer_width = crate::ir::abi::machine_word_bytes(cc);
    let mut saw_typed_parameter = false;
    let mut saw_sink_call = false;
    for (block_index, block) in function.blocks.iter().enumerate() {
        let mut state = inputs[block_index].clone();
        for instruction in &block.instrs {
            if let Op::Call {
                target: CallTarget::Direct(target),
                ..
            } = instruction.op
            {
                if let Some(format_argument) = sinks.get(&target).copied() {
                    saw_sink_call = true;
                    let format_register = *argument_registers.get(format_argument)?;
                    let conversions = literal_format_hints(
                        state.registers.get(format_register),
                        &string_pool,
                        pointer_width,
                    )?;
                    if let Some(conversions) = conversions {
                        for (offset, incoming) in conversions.into_iter().enumerate() {
                            let register = argument_registers
                                .get(format_argument.saturating_add(1).saturating_add(offset))?;
                            let parameter = parameter_index(state.registers.get(*register));
                            let Some(parameter) = parameter else {
                                continue;
                            };
                            if !parameter_slots.contains(&parameter) || parameter >= hints.len() {
                                return None;
                            }
                            hints[parameter] =
                                Some(merge_observed_hint(hints[parameter], incoming)?);
                            saw_typed_parameter = true;
                        }
                    }
                }
            }
            transfer_instruction(&instruction.op, &mut state, image, cc, &semantics);
        }
    }
    (saw_sink_call && saw_typed_parameter).then_some(hints)
}

pub(super) fn recover_format_parameter_hints(
    image: &ProgramImage,
    budgets: &Budgets,
    cc: CallConv,
    index: &FormatIndex,
    fdes: &[crate::analysis::exception::EhFrameFunction],
    target: u64,
) -> Option<Vec<Option<TypeHint>>> {
    if !index.has_consumer() {
        return None;
    }
    let targeted_budgets = Budgets {
        max_functions: 1,
        ..*budgets
    };
    let target_function = discover_function_image_at(image, &targeted_budgets, target)?;
    let target_lifted = lift_function_from_image(image, &target_function).ok()?;
    let direct = recover_direct_literal_parameter_hints(&target_lifted, image, budgets, cc, index);
    let Some(forwarding) = recover_format_forwarding(&target_lifted, image, cc, index) else {
        return direct;
    };
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!("format forwarding 0x{target:x}: {forwarding:?}");
    }
    let sites = direct_call_sites(image, &HashMap::from([(target, "format-wrapper")]));
    if sites.is_empty() {
        return None;
    }
    let owner_entries = sites
        .iter()
        .filter_map(|(site, _)| {
            fdes.iter()
                .find(|function| function.start <= *site && *site < function.end)
                .map(|function| function.start)
        })
        .collect::<BTreeSet<_>>();
    let string_pool = crate::ir::strings_fold::collect_string_pool_from_image(image);
    let semantics = HashMap::new();
    let mut hints = vec![
        None;
        forwarding
            .conversion_parameters
            .iter()
            .copied()
            .chain(std::iter::once(forwarding.format_parameter))
            .max()?
            .saturating_add(1)
    ];
    let mut saw_typed_format = false;
    let mut saw_verified_call = false;
    for owner in owner_entries {
        let Some(function) = discover_function_image_at(image, &targeted_budgets, owner) else {
            continue;
        };
        let Ok(lifted) = lift_function_from_image(image, &function) else {
            continue;
        };
        let inputs = input_states_for_image(&lifted, cc, image, &semantics, false);
        for (block_index, block) in lifted.blocks.iter().enumerate() {
            let mut state = inputs[block_index].clone();
            for instruction in &block.instrs {
                if matches!(
                    instruction.op,
                    Op::Call {
                        target: CallTarget::Direct(call_target),
                        ..
                    } if call_target == target
                ) {
                    saw_verified_call = true;
                    let format_register =
                        crate::ir::abi::argument_registers(cc).get(forwarding.format_parameter)?;
                    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
                        eprintln!("format caller 0x{:x}: {state:#x?}", instruction.va);
                    }
                    saw_typed_format |= apply_literal_format(
                        state.registers.get(*format_register),
                        &string_pool,
                        &forwarding,
                        crate::ir::abi::machine_word_bytes(cc),
                        &mut hints,
                    )?;
                }
                transfer_instruction(&instruction.op, &mut state, image, cc, &semantics);
            }
        }
    }
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!(
            "format result 0x{target:x}: verified={saw_verified_call} typed={saw_typed_format} hints={hints:?}"
        );
    }
    let forwarded = (saw_verified_call && saw_typed_format).then_some(hints);
    merge_hint_vectors(direct, forwarded)
}

fn merge_hint_vectors(
    left: Option<Vec<Option<TypeHint>>>,
    right: Option<Vec<Option<TypeHint>>>,
) -> Option<Vec<Option<TypeHint>>> {
    match (left, right) {
        (None, None) => None,
        (Some(hints), None) | (None, Some(hints)) => Some(hints),
        (Some(mut left), Some(right)) => {
            left.resize(left.len().max(right.len()), None);
            for (index, incoming) in right.into_iter().enumerate() {
                let Some(incoming) = incoming else {
                    continue;
                };
                left[index] = Some(merge_observed_hint(left[index], incoming)?);
            }
            Some(left)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_printf_hints;
    use crate::ir::types_recover::TypeHint;

    #[test]
    fn printf_parser_is_typed_and_fail_closed() {
        assert_eq!(
            parse_printf_hints("name '%s': %ld%%", 8),
            Some(vec![
                TypeHint::Pointer { pointee_width: 1 },
                TypeHint::Int {
                    signed: true,
                    width: 8,
                },
            ])
        );
        assert_eq!(parse_printf_hints("%2$s", 8), None);
        assert_eq!(parse_printf_hints("%*s", 8), None);
        assert_eq!(parse_printf_hints("%ls", 8), None);
        assert_eq!(parse_printf_hints("%hf", 8), None);
        assert_eq!(
            parse_printf_hints("%jd", 4),
            Some(vec![TypeHint::Int {
                signed: true,
                width: 8,
            }])
        );
    }
}
