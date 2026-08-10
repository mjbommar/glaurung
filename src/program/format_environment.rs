//! Interprocedural format-wrapper contracts for the program environment.
//!
//! A wrapper such as `try_help(format, operand)` can erase `operand`'s type
//! from its own machine body by forwarding it through a variadic API.  When all
//! direct callers provide literal formats, those formats are authoritative
//! type evidence. Dynamic, unsupported, and contradictory formats fail closed.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::analysis::cfg::{discover_function_image_at, Budgets};
use crate::ir::call_args::CallConv;
use crate::ir::lift_function::lift_function_from_image;
use crate::ir::types::{CallTarget, LlirFunction, Op};
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

fn named_targets(address_names: &HashMap<u64, String>, wanted: &str) -> HashSet<u64> {
    address_names
        .iter()
        .filter_map(|(address, name)| (clean_import_name(name) == wanted).then_some(*address))
        .collect()
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
    address_names: &HashMap<u64, String>,
) -> Option<FormatForwarding> {
    let semantics = known_call_semantics(address_names);
    let error_targets = named_targets(address_names, "error");
    if error_targets.is_empty() {
        return None;
    }
    let inputs = input_states_for_image(function, cc, image, &semantics, true);
    let argument_registers = crate::ir::abi::argument_registers(cc);
    let format_register = *argument_registers.get(2)?;
    let mut found: Option<FormatForwarding> = None;
    for (block_index, block) in function.blocks.iter().enumerate() {
        let mut state = inputs[block_index].clone();
        for instruction in &block.instrs {
            if let Op::Call {
                target: CallTarget::Direct(target),
                ..
            } = instruction.op
            {
                if error_targets.contains(&target) {
                    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
                        eprintln!("format sink 0x{:x}: {state:#x?}", instruction.va);
                    }
                    if let Some(format_parameter) =
                        format_parameter_index(state.registers.get(format_register))
                    {
                        let conversion_parameters = argument_registers
                            .iter()
                            .skip(3)
                            .take_while(|register| {
                                state.written_registers.contains(**register)
                                    && parameter_index(state.registers.get(**register)).is_some()
                            })
                            .filter_map(|register| parameter_index(state.registers.get(*register)))
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
            transfer_instruction(&instruction.op, &mut state, image, cc, &semantics);
        }
    }
    found
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
    let address = match value {
        Some(AbstractValue::Scalar(0)) => return Some(false),
        Some(AbstractValue::Data(address)) => *address,
        Some(AbstractValue::Scalar(address)) if *address > 0 => u64::try_from(*address).ok()?,
        _ => return None,
    };
    let conversions = parse_printf_hints(string_pool.get(&address)?, pointer_width)?;
    if conversions.len() > forwarding.conversion_parameters.len() {
        return None;
    }
    let typed = !conversions.is_empty();
    for (parameter, incoming) in forwarding.conversion_parameters.iter().zip(conversions) {
        hints[*parameter] = Some(merge_observed_hint(hints[*parameter], incoming)?);
    }
    Some(typed)
}

pub(super) fn recover_format_parameter_hints(
    image: &ProgramImage,
    budgets: &Budgets,
    cc: CallConv,
    address_names: &HashMap<u64, String>,
    fdes: &[crate::analysis::exception::EhFrameFunction],
    target: u64,
) -> Option<Vec<Option<TypeHint>>> {
    if named_targets(address_names, "error").is_empty() {
        return None;
    }
    let targeted_budgets = Budgets {
        max_functions: 1,
        ..*budgets
    };
    let target_function = discover_function_image_at(image, &targeted_budgets, target)?;
    let target_lifted = lift_function_from_image(image, &target_function, image.arch())?;
    let forwarding = recover_format_forwarding(&target_lifted, image, cc, address_names)?;
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
        let Some(lifted) = lift_function_from_image(image, &function, image.arch()) else {
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
    (saw_verified_call && saw_typed_format).then_some(hints)
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
