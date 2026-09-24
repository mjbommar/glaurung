//! Relations from observed runtime writes to authoritative DWARF stack objects.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::capsule::{PageContent, ProcessCapsule, RuntimeObjectKind};
use super::correlation::StaticValueExpression;
use super::correlation::{
    resolve_runtime_address, resolve_static_code, resolve_static_function, AddressResolution,
    FunctionResolution, StaticCodeResolution,
};
use super::crash::Evidence;
use super::event_correlation::{correlate_input_events, OperationOccurrence};
use super::instruction_trace::analyze_instruction_trace;
use super::memory::RuntimeMemoryView;
use crate::debug::dwarf::{extract_dwarf_types, DwarfStackBase, DwarfTypeKind};
use crate::program::image::ProgramImage;

pub const STACK_WRITE_REPORT_SCHEMA: &str = "glaurung-runtime-stack-write-report-v1";
const X86_64_DWARF_RBP: u16 = 6;
const MAX_FRAME_SCAN_BYTES: u64 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFrameIdentity {
    pub function_entry: u64,
    pub function_name: Option<String>,
    pub frame_pointer: u64,
    pub call_frame_cfa: u64,
    pub evidence_record_address: u64,
    pub return_address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealizedStackObject {
    pub source_name: Option<String>,
    pub c_type: Option<String>,
    pub static_base: String,
    pub static_offset: i64,
    pub runtime_start: u64,
    pub byte_len: u64,
    pub aggregate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealizedField {
    pub name: String,
    pub c_type: String,
    pub object_offset: u64,
    pub runtime_start: u64,
    pub byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackWriteBounds {
    pub write_start: u64,
    pub write_byte_len: u64,
    pub object_bytes_exceeded: u64,
    pub field_bytes_exceeded: u64,
    pub classification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackFieldChangedInterval {
    pub field_offset_start: u64,
    pub field_offset_end: u64,
    pub before_hex: String,
    pub after_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackFieldChange {
    pub field: RealizedField,
    pub before_hex: String,
    pub after_hex: String,
    pub changed_intervals: Vec<StackFieldChangedInterval>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackInputFieldEffect {
    pub input_source_id: String,
    pub source_offset_start: u64,
    pub source_offset_end: u64,
    pub runtime_start: u64,
    pub runtime_end: u64,
    pub object_offset_start: u64,
    pub object_offset_end: u64,
    pub field: RealizedField,
    pub field_offset_start: u64,
    pub field_offset_end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackObjectChangedInterval {
    pub object_offset_start: u64,
    pub object_offset_end: u64,
    pub before_hex: String,
    pub after_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackObjectChange {
    pub object: RealizedStackObject,
    pub before_hex: String,
    pub after_hex: String,
    pub changed_intervals: Vec<StackObjectChangedInterval>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackAddressDerivation {
    pub base_field: RealizedField,
    pub element_index: u64,
    pub element_byte_len: u64,
    pub effective_address: u64,
    pub field_bytes_exceeded: u64,
    pub classification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackWriteRelation {
    pub process_id: String,
    pub sequence: u64,
    pub event_kind: String,
    pub registers: Evidence<BTreeMap<String, u64>>,
    pub operation_occurrence: Evidence<OperationOccurrence>,
    pub frame: Evidence<RuntimeFrameIdentity>,
    pub object: Evidence<RealizedStackObject>,
    pub field: Evidence<RealizedField>,
    pub bounds: Evidence<StackWriteBounds>,
    pub address_derivation: Evidence<StackAddressDerivation>,
    pub object_change: Evidence<StackObjectChange>,
    pub field_changes: Evidence<Vec<StackFieldChange>>,
    pub input_field_effects: Evidence<Vec<StackInputFieldEffect>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackWriteReport {
    pub schema: String,
    pub capture_id: String,
    pub image_sha256: String,
    pub relations: Vec<StackWriteRelation>,
    pub integer_conversion_writes: Vec<IntegerConversionWriteRelation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegerConversionWriteRelation {
    pub process_id: String,
    pub source_sequence: u64,
    pub conversion_sequence: u64,
    pub write_sequence: u64,
    pub source_object: RealizedStackObject,
    pub converted_object: RealizedStackObject,
    pub source_value: u64,
    pub converted_value: u64,
    pub source_bits: u16,
    pub converted_bits: u16,
    pub conversion_operation: OperationOccurrence,
    pub write_operation: OperationOccurrence,
    pub write_field: RealizedField,
    pub write_bounds: StackWriteBounds,
    pub classification: String,
}

/// Relate selected input writes to DWARF objects without mutating either model.
pub fn analyze_stack_writes(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
) -> StackWriteReport {
    let image_sha256 = hex::encode(Sha256::digest(image.bytes()));
    let input_relations = correlate_input_events(capsule, image).relations;
    let mut relations = capsule
        .events
        .iter()
        .filter(|event| {
            matches!(
                event.kind.as_str(),
                "descriptor_read" | "descriptor_stdin_read" | "file_read"
            ) && event.fields.contains_key("destination_address")
        })
        .map(|event| {
            let operation_occurrence = input_relations
                .iter()
                .find(|relation| {
                    relation.process_id == event.process_id && relation.sequence == event.sequence
                })
                .map(|relation| relation.operation_occurrence.clone())
                .unwrap_or_else(|| Evidence::Unknown {
                    reason: "runtime write has no matching input operation occurrence".to_string(),
                });
            let destination = event
                .fields
                .get("destination_address")
                .and_then(|value| value.parse::<u64>().ok());
            let byte_len = event
                .fields
                .get("read_byte_len")
                .and_then(|value| value.parse::<u64>().ok());
            let (frame, object, field, bounds) = match (destination, byte_len) {
                (Some(destination), Some(byte_len)) => relate_one_write(
                    capsule,
                    payloads,
                    image,
                    &event.process_id,
                    destination,
                    byte_len,
                ),
                _ => unknown_tuple("input event has malformed destination or byte length"),
            };
            let field_changes =
                compare_field_snapshots(capsule, payloads, image, &event.process_id, &object);
            let object_change =
                compare_object_snapshots(capsule, payloads, &event.process_id, &object);
            let input_field_effects =
                relate_input_field_effects(&operation_occurrence, &object, &field_changes);
            StackWriteRelation {
                process_id: event.process_id.clone(),
                sequence: event.sequence,
                event_kind: event.kind.clone(),
                registers: Evidence::Unknown {
                    reason: "input event has no pre-instruction register snapshot".to_string(),
                },
                operation_occurrence,
                frame,
                object,
                field,
                bounds,
                address_derivation: Evidence::Unknown {
                    reason: "input-event write has no static address expression".to_string(),
                },
                object_change,
                field_changes,
                input_field_effects,
            }
        })
        .collect::<Vec<_>>();
    let instruction_report = analyze_instruction_trace(capsule, payloads, image);
    for trace_relation in instruction_report.relations {
        let Evidence::Observed { value: changes, .. } = &trace_relation.changes else {
            continue;
        };
        for change in changes {
            let byte_len = change.end - change.start;
            let (frame, object, field, bounds) = relate_one_write(
                capsule,
                payloads,
                image,
                &trace_relation.process_id,
                change.start,
                byte_len,
            );
            let field_changes = compare_field_snapshots(
                capsule,
                payloads,
                image,
                &trace_relation.process_id,
                &object,
            );
            let object_change =
                compare_object_snapshots(capsule, payloads, &trace_relation.process_id, &object);
            let address_derivation = derive_stack_address(
                capsule,
                payloads,
                image,
                &trace_relation.process_id,
                &trace_relation.registers,
                &trace_relation.operation_occurrence,
                &object,
            );
            relations.push(StackWriteRelation {
                process_id: trace_relation.process_id.clone(),
                sequence: trace_relation.sequence,
                event_kind: "instruction_step".to_string(),
                registers: trace_relation.registers.clone(),
                operation_occurrence: trace_relation.operation_occurrence.clone(),
                frame,
                object,
                field,
                bounds,
                address_derivation,
                object_change,
                field_changes,
                input_field_effects: Evidence::Unknown {
                    reason: "instruction-step write has no introduced input source".to_string(),
                },
            });
        }
    }
    for call_relation in instruction_report.call_relations {
        let Evidence::Inferred {
            value: occurrence, ..
        } = &call_relation.operation_occurrence
        else {
            continue;
        };
        let memory_effect = occurrence.effects.iter().find(|effect| {
            effect.kind == "memory_write" && effect.address.is_some() && effect.byte_len.is_some()
        });
        let destination = memory_effect.and_then(|effect| effect.address);
        let byte_len = memory_effect.and_then(|effect| effect.byte_len);
        let (frame, object, field, bounds) = match (destination, byte_len) {
            (Some(destination), Some(byte_len)) => relate_one_write(
                capsule,
                payloads,
                image,
                &call_relation.process_id,
                destination,
                byte_len,
            ),
            _ => unknown_tuple("call occurrence has malformed destination or byte length"),
        };
        let field_changes =
            compare_field_snapshots(capsule, payloads, image, &call_relation.process_id, &object);
        let object_change =
            compare_object_snapshots(capsule, payloads, &call_relation.process_id, &object);
        relations.push(StackWriteRelation {
            process_id: call_relation.process_id,
            sequence: call_relation.sequence,
            event_kind: "semantic_call".to_string(),
            registers: call_relation.registers,
            operation_occurrence: call_relation.operation_occurrence,
            frame,
            object,
            field,
            bounds,
            address_derivation: Evidence::Unknown {
                reason: "call effect has no scalar LLIR address expression".to_string(),
            },
            object_change,
            field_changes,
            input_field_effects: Evidence::Unknown {
                reason: "semantic call has no introduced input source".to_string(),
            },
        });
    }
    let integer_conversion_writes = derive_integer_conversion_writes(&relations);
    StackWriteReport {
        schema: STACK_WRITE_REPORT_SCHEMA.to_string(),
        capture_id: capsule.identity.capture_id.clone(),
        image_sha256,
        relations,
        integer_conversion_writes,
    }
}

fn derive_integer_conversion_writes(
    relations: &[StackWriteRelation],
) -> Vec<IntegerConversionWriteRelation> {
    let mut derived = Vec::new();
    for conversion in relations {
        let (
            Evidence::Inferred {
                value: converted_object,
                ..
            },
            Evidence::Inferred {
                value: conversion_operation,
                ..
            },
            Evidence::Inferred {
                value: converted_change,
                ..
            },
            Evidence::Observed {
                value: conversion_registers,
                ..
            },
        ) = (
            &conversion.object,
            &conversion.operation_occurrence,
            &conversion.object_change,
            &conversion.registers,
        )
        else {
            continue;
        };
        let Some(expression) = &conversion_operation.static_operation.stored_value else {
            continue;
        };
        let Some((source_address, source_bits, converted_bits)) =
            integer_reduction_from_frame_load(expression)
        else {
            continue;
        };
        if converted_bits != converted_object.byte_len.saturating_mul(8) as u16
            || converted_bits >= source_bits
        {
            continue;
        }
        let Some(expected_runtime_start) =
            evaluate_register_expression(&source_address, conversion_registers)
        else {
            continue;
        };
        let sources = relations
            .iter()
            .filter(|candidate| {
                candidate.process_id == conversion.process_id
                    && candidate.sequence < conversion.sequence
                    && matches!(
                        &candidate.object,
                        Evidence::Inferred { value, .. }
                            if value.runtime_start == expected_runtime_start
                                && value.byte_len.saturating_mul(8) as u16 == source_bits
                    )
            })
            .collect::<Vec<_>>();
        let [source] = sources.as_slice() else {
            continue;
        };
        let (
            Evidence::Inferred {
                value: source_object,
                ..
            },
            Evidence::Inferred {
                value: source_change,
                ..
            },
        ) = (&source.object, &source.object_change)
        else {
            continue;
        };
        let (Some(source_value), Some(converted_value)) = (
            little_endian_hex_value(&source_change.after_hex),
            little_endian_hex_value(&converted_change.after_hex),
        ) else {
            continue;
        };
        if truncate_to_bits(source_value, converted_bits) != Some(converted_value) {
            continue;
        }
        let writes = relations
            .iter()
            .filter(|candidate| {
                candidate.process_id == conversion.process_id
                    && candidate.sequence > conversion.sequence
                    && candidate.event_kind == "semantic_call"
                    && matches!(
                        &candidate.operation_occurrence,
                        Evidence::Inferred { value, .. }
                            if matches!(
                                &value.static_operation.call_target,
                                Some(super::correlation::StaticCallTarget::Direct {
                                    symbol: Some(symbol),
                                    ..
                                }) if symbol == "memset"
                            )
                    )
            })
            .collect::<Vec<_>>();
        let [write] = writes.as_slice() else {
            continue;
        };
        let (
            Evidence::Inferred {
                value: write_operation,
                ..
            },
            Evidence::Inferred {
                value: write_field, ..
            },
            Evidence::Inferred {
                value: write_bounds,
                ..
            },
        ) = (&write.operation_occurrence, &write.field, &write.bounds)
        else {
            continue;
        };
        derived.push(IntegerConversionWriteRelation {
            process_id: conversion.process_id.clone(),
            source_sequence: source.sequence,
            conversion_sequence: conversion.sequence,
            write_sequence: write.sequence,
            source_object: source_object.clone(),
            converted_object: converted_object.clone(),
            source_value,
            converted_value,
            source_bits,
            converted_bits,
            conversion_operation: conversion_operation.clone(),
            write_operation: write_operation.clone(),
            write_field: write_field.clone(),
            write_bounds: write_bounds.clone(),
            classification: if write_bounds.field_bytes_exceeded == 0 {
                "narrowing_precedes_bounded_write"
            } else {
                "narrowing_precedes_field_overflow"
            }
            .to_string(),
        });
    }
    derived
}

fn integer_reduction_from_frame_load(
    expression: &StaticValueExpression,
) -> Option<(StaticValueExpression, u16, u16)> {
    match expression {
        StaticValueExpression::BitwiseAnd { left, right } => {
            let (load, mask) = match (&**left, &**right) {
                (
                    load @ StaticValueExpression::Load { .. },
                    StaticValueExpression::Constant { value },
                )
                | (
                    StaticValueExpression::Constant { value },
                    load @ StaticValueExpression::Load { .. },
                ) => (load, u64::try_from(*value).ok()?),
                _ => return None,
            };
            let converted_bits = u16::try_from(mask.count_ones()).ok()?;
            if mask != truncate_mask(converted_bits)? {
                return None;
            }
            frame_load_width(load)
                .map(|(offset, source_bits)| (offset, source_bits, converted_bits))
        }
        StaticValueExpression::Truncate {
            value,
            from_bits,
            to_bits,
        } => {
            let (offset, loaded_bits) = frame_load_width(value)?;
            (*from_bits == loaded_bits).then_some((offset, *from_bits, *to_bits))
        }
        StaticValueExpression::Extract {
            value,
            high_bit,
            low_bit,
        } if *low_bit == 0 => {
            let (offset, source_bits) = frame_load_width(value)?;
            Some((offset, source_bits, *high_bit))
        }
        _ => None,
    }
}

fn frame_load_width(expression: &StaticValueExpression) -> Option<(StaticValueExpression, u16)> {
    let StaticValueExpression::Load { address, byte_len } = expression else {
        return None;
    };
    Some(((**address).clone(), u16::from(*byte_len) * 8))
}

fn evaluate_register_expression(
    expression: &StaticValueExpression,
    registers: &BTreeMap<String, u64>,
) -> Option<u64> {
    match expression {
        StaticValueExpression::Register { name } => registers.get(name).copied(),
        StaticValueExpression::Constant { value } => Some(*value as u64),
        StaticValueExpression::Address { value } => Some(*value),
        StaticValueExpression::Add { left, right } => Some(
            evaluate_register_expression(left, registers)?
                .wrapping_add(evaluate_register_expression(right, registers)?),
        ),
        StaticValueExpression::Subtract { left, right } => Some(
            evaluate_register_expression(left, registers)?
                .wrapping_sub(evaluate_register_expression(right, registers)?),
        ),
        StaticValueExpression::Multiply { left, right } => Some(
            evaluate_register_expression(left, registers)?
                .wrapping_mul(evaluate_register_expression(right, registers)?),
        ),
        _ => None,
    }
}

fn little_endian_hex_value(value: &str) -> Option<u64> {
    let bytes = hex::decode(value).ok()?;
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let mut padded = [0_u8; 8];
    padded[..bytes.len()].copy_from_slice(&bytes);
    Some(u64::from_le_bytes(padded))
}

fn truncate_mask(bits: u16) -> Option<u64> {
    match bits {
        0 => None,
        64 => Some(u64::MAX),
        1..=63 => Some((1_u64 << bits) - 1),
        _ => None,
    }
}

fn truncate_to_bits(value: u64, bits: u16) -> Option<u64> {
    Some(value & truncate_mask(bits)?)
}

fn derive_stack_address(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    process_id: &str,
    registers: &Evidence<BTreeMap<String, u64>>,
    occurrence: &Evidence<OperationOccurrence>,
    object: &Evidence<RealizedStackObject>,
) -> Evidence<StackAddressDerivation> {
    let Evidence::Observed {
        value: registers, ..
    } = registers
    else {
        return Evidence::Unknown {
            reason: "address derivation requires pre-instruction registers".to_string(),
        };
    };
    let Evidence::Inferred {
        value: occurrence, ..
    } = occurrence
    else {
        return Evidence::Unknown {
            reason: "address derivation requires one operation occurrence".to_string(),
        };
    };
    let Evidence::Inferred { value: object, .. } = object else {
        return Evidence::Unknown {
            reason: "address derivation requires one realized stack object".to_string(),
        };
    };
    let Some(access) = &occurrence.static_operation.memory_access else {
        return Evidence::Unknown {
            reason: "LLIR store has no memory-access width".to_string(),
        };
    };
    let Ok(memory) = RuntimeMemoryView::new(capsule, payloads, process_id) else {
        return Evidence::Unknown {
            reason: "address derivation has no runtime memory view".to_string(),
        };
    };
    let Some(effective_address) = evaluate_memory_access(access, registers) else {
        return Evidence::Unknown {
            reason: "LLIR memory operand cannot be evaluated from captured registers".to_string(),
        };
    };
    let type_name = object.c_type.as_deref().and_then(|value| {
        value
            .strip_prefix("struct ")
            .or_else(|| value.strip_prefix("union "))
    });
    let Some(type_name) = type_name else {
        return Evidence::Unknown {
            reason: "realized stack object has no aggregate type".to_string(),
        };
    };
    let layouts = extract_dwarf_types(image.bytes())
        .into_iter()
        .filter(|layout| layout.name == type_name)
        .collect::<Vec<_>>();
    let [layout] = layouts.as_slice() else {
        return Evidence::Unknown {
            reason: "DWARF aggregate layout is absent or ambiguous".to_string(),
        };
    };
    let mut expression_values = Vec::new();
    if let Some(expression) = &occurrence.static_operation.address_expression {
        collect_expression_values(expression, registers, &memory, &mut expression_values);
    }
    if access.index_register.is_some() {
        let base = access
            .base_register
            .as_ref()
            .and_then(|name| registers.get(name).copied())
            .unwrap_or(0)
            .wrapping_add_signed(access.displacement);
        expression_values.push(base);
    }
    let candidates = layout
        .fields
        .iter()
        .filter(|field| field.c_type.contains('['))
        .filter_map(|field| {
            let runtime_start = object.runtime_start.checked_add(field.offset)?;
            expression_values
                .contains(&runtime_start)
                .then_some(RealizedField {
                    name: field.name.clone(),
                    c_type: field.c_type.clone(),
                    object_offset: field.offset,
                    runtime_start,
                    byte_len: field.size,
                })
        })
        .collect::<Vec<_>>();
    let [base_field] = candidates.as_slice() else {
        return Evidence::Unknown {
            reason: "static address expression does not identify one DWARF array field".to_string(),
        };
    };
    let element_byte_len = u64::from(access.byte_len);
    let Some(byte_offset) = effective_address.checked_sub(base_field.runtime_start) else {
        return Evidence::Unknown {
            reason: "effective address precedes the derived base field".to_string(),
        };
    };
    if element_byte_len == 0 || byte_offset % element_byte_len != 0 {
        return Evidence::Unknown {
            reason: "address offset is not aligned to the LLIR access width".to_string(),
        };
    }
    let write_end = byte_offset.saturating_add(element_byte_len);
    let field_bytes_exceeded = write_end.saturating_sub(base_field.byte_len);
    Evidence::Inferred {
        value: StackAddressDerivation {
            base_field: base_field.clone(),
            element_index: byte_offset / element_byte_len,
            element_byte_len,
            effective_address,
            field_bytes_exceeded,
            classification: if field_bytes_exceeded == 0 {
                "within_field"
            } else {
                "crosses_field_boundary"
            }
            .to_string(),
        },
        source: "bounded LLIR backward slice evaluated with observed registers and sparse memory, then joined to DWARF layout".to_string(),
    }
}

fn evaluate_memory_access(
    access: &super::correlation::StaticMemoryAccess,
    registers: &BTreeMap<String, u64>,
) -> Option<u64> {
    if access.segment.is_some() {
        return None;
    }
    let base = match &access.base_register {
        Some(name) => *registers.get(name)?,
        None => 0,
    };
    let index = match &access.index_register {
        Some(name) => *registers.get(name)?,
        None => 0,
    };
    Some(
        base.wrapping_add(index.wrapping_mul(u64::from(access.scale)))
            .wrapping_add_signed(access.displacement),
    )
}

fn evaluate_static_expression(
    expression: &StaticValueExpression,
    registers: &BTreeMap<String, u64>,
    memory: &RuntimeMemoryView<'_>,
) -> Result<u64, ()> {
    match expression {
        StaticValueExpression::Register { name } => registers.get(name).copied().ok_or(()),
        StaticValueExpression::Constant { value } => Ok(*value as u64),
        StaticValueExpression::Address { value } => Ok(*value),
        StaticValueExpression::Add { left, right } => {
            Ok(evaluate_static_expression(left, registers, memory)?
                .wrapping_add(evaluate_static_expression(right, registers, memory)?))
        }
        StaticValueExpression::Subtract { left, right } => {
            Ok(evaluate_static_expression(left, registers, memory)?
                .wrapping_sub(evaluate_static_expression(right, registers, memory)?))
        }
        StaticValueExpression::Multiply { left, right } => {
            Ok(evaluate_static_expression(left, registers, memory)?
                .wrapping_mul(evaluate_static_expression(right, registers, memory)?))
        }
        StaticValueExpression::BitwiseAnd { left, right } => {
            Ok(evaluate_static_expression(left, registers, memory)?
                & evaluate_static_expression(right, registers, memory)?)
        }
        StaticValueExpression::BitwiseOr { left, right } => {
            Ok(evaluate_static_expression(left, registers, memory)?
                | evaluate_static_expression(right, registers, memory)?)
        }
        StaticValueExpression::BitwiseXor { left, right } => {
            Ok(evaluate_static_expression(left, registers, memory)?
                ^ evaluate_static_expression(right, registers, memory)?)
        }
        StaticValueExpression::Truncate { value, to_bits, .. } => {
            let value = evaluate_static_expression(value, registers, memory)?;
            if *to_bits >= 64 {
                Ok(value)
            } else {
                Ok(value & ((1_u64 << to_bits) - 1))
            }
        }
        StaticValueExpression::ZeroExtend {
            value, from_bits, ..
        } => {
            let value = evaluate_static_expression(value, registers, memory)?;
            if *from_bits >= 64 {
                Ok(value)
            } else {
                Ok(value & ((1_u64 << from_bits) - 1))
            }
        }
        StaticValueExpression::SignExtend {
            value, from_bits, ..
        } => {
            let value = evaluate_static_expression(value, registers, memory)?;
            if *from_bits == 0 || *from_bits > 64 {
                return Err(());
            }
            let shift = 64 - u32::from(*from_bits);
            Ok(((value << shift) as i64 >> shift) as u64)
        }
        StaticValueExpression::Extract {
            value,
            high_bit,
            low_bit,
        } => {
            let value = evaluate_static_expression(value, registers, memory)?;
            let width = high_bit.checked_sub(*low_bit).ok_or(())?;
            let shifted = value.checked_shr(u32::from(*low_bit)).unwrap_or(0);
            if width >= 64 {
                Ok(shifted)
            } else {
                Ok(shifted & ((1_u64 << width) - 1))
            }
        }
        StaticValueExpression::Load { address, byte_len } => {
            let address = evaluate_static_expression(address, registers, memory)?;
            let bytes = memory
                .read_runtime_bytes(address, usize::from(*byte_len))
                .map_err(|_| ())?;
            if bytes.is_empty() || bytes.len() > 8 {
                return Err(());
            }
            let mut value = [0u8; 8];
            value[..bytes.len()].copy_from_slice(&bytes);
            Ok(u64::from_le_bytes(value))
        }
        StaticValueExpression::Compare { .. } | StaticValueExpression::CallResult { .. } => Err(()),
    }
}

fn collect_expression_values(
    expression: &StaticValueExpression,
    registers: &BTreeMap<String, u64>,
    memory: &RuntimeMemoryView<'_>,
    values: &mut Vec<u64>,
) {
    if let Ok(value) = evaluate_static_expression(expression, registers, memory) {
        values.push(value);
    }
    match expression {
        StaticValueExpression::Add { left, right }
        | StaticValueExpression::Subtract { left, right }
        | StaticValueExpression::Multiply { left, right }
        | StaticValueExpression::BitwiseAnd { left, right } => {
            collect_expression_values(left, registers, memory, values);
            collect_expression_values(right, registers, memory, values);
        }
        StaticValueExpression::Truncate { value, .. }
        | StaticValueExpression::Extract { value, .. }
        | StaticValueExpression::ZeroExtend { value, .. }
        | StaticValueExpression::SignExtend { value, .. } => {
            collect_expression_values(value, registers, memory, values);
        }
        StaticValueExpression::Load { address, .. } => {
            collect_expression_values(address, registers, memory, values);
        }
        _ => {}
    }
}

fn compare_object_snapshots(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    process_id: &str,
    object: &Evidence<RealizedStackObject>,
) -> Evidence<StackObjectChange> {
    let Evidence::Inferred { value: object, .. } = object else {
        return Evidence::Unknown {
            reason: "stack object must resolve before it can be compared".to_string(),
        };
    };
    let Some(mapping_object) = capsule.runtime_objects.iter().find(|candidate| {
        candidate.process_id == process_id
            && candidate.kind == RuntimeObjectKind::Mapping
            && candidate.start <= object.runtime_start
            && object
                .runtime_start
                .checked_add(object.byte_len)
                .zip(candidate.start.checked_add(candidate.byte_len))
                .is_some_and(|(object_end, mapping_end)| object_end <= mapping_end)
    }) else {
        return Evidence::Unknown {
            reason: "realized stack object has no containing captured mapping object".to_string(),
        };
    };
    let mut snapshots = capsule
        .object_snapshots
        .iter()
        .filter(|snapshot| snapshot.object_id == mapping_object.id)
        .collect::<Vec<_>>();
    snapshots.sort_by_key(|snapshot| {
        (
            snapshot.point.thread_id.clone(),
            snapshot.point.sequence,
            snapshot.id.clone(),
        )
    });
    let [before, after] = snapshots.as_slice() else {
        return Evidence::Unknown {
            reason: "object comparison requires exactly two ordered mapping snapshots".to_string(),
        };
    };
    if before.object_offset != after.object_offset || before.byte_len != after.byte_len {
        return Evidence::Unknown {
            reason: "before and after mapping snapshots cover different intervals".to_string(),
        };
    }
    let load = |snapshot: &super::capsule::ObjectSnapshotRecord| -> Result<&[u8], String> {
        let PageContent::Captured { payload } = &snapshot.content else {
            return Err("mapping snapshot payload was omitted".to_string());
        };
        let bytes = payloads
            .get(&payload.id)
            .ok_or_else(|| format!("mapping snapshot payload {} is unavailable", payload.id))?;
        if bytes.len() as u64 != payload.byte_len
            || payload.byte_len != snapshot.byte_len
            || hex::encode(Sha256::digest(bytes)) != payload.sha256
        {
            return Err(format!(
                "mapping snapshot payload {} disagrees with its identity",
                payload.id
            ));
        }
        Ok(bytes)
    };
    let (before_bytes, after_bytes) = match (load(before), load(after)) {
        (Ok(before_bytes), Ok(after_bytes)) => (before_bytes, after_bytes),
        (Err(reason), _) | (_, Err(reason)) => return Evidence::Unknown { reason },
    };
    let Some(snapshot_start) = mapping_object.start.checked_add(before.object_offset) else {
        return Evidence::Unknown {
            reason: "mapping snapshot runtime range overflowed".to_string(),
        };
    };
    let Some(snapshot_end) = snapshot_start.checked_add(before.byte_len) else {
        return Evidence::Unknown {
            reason: "mapping snapshot runtime range overflowed".to_string(),
        };
    };
    let Some(object_end) = object.runtime_start.checked_add(object.byte_len) else {
        return Evidence::Unknown {
            reason: "realized stack object range overflowed".to_string(),
        };
    };
    if object.runtime_start < snapshot_start || object_end > snapshot_end {
        return Evidence::Unknown {
            reason: "realized stack object is outside captured snapshots".to_string(),
        };
    }
    let start = usize::try_from(object.runtime_start - snapshot_start)
        .expect("validated snapshot object offset");
    let end = start + usize::try_from(object.byte_len).expect("validated stack object size");
    let before_object = &before_bytes[start..end];
    let after_object = &after_bytes[start..end];
    let mut intervals = Vec::new();
    let mut cursor = 0usize;
    while cursor < before_object.len() {
        if before_object[cursor] == after_object[cursor] {
            cursor += 1;
            continue;
        }
        let interval_start = cursor;
        while cursor < before_object.len() && before_object[cursor] != after_object[cursor] {
            cursor += 1;
        }
        intervals.push(StackObjectChangedInterval {
            object_offset_start: interval_start as u64,
            object_offset_end: cursor as u64,
            before_hex: hex::encode(&before_object[interval_start..cursor]),
            after_hex: hex::encode(&after_object[interval_start..cursor]),
        });
    }
    Evidence::Inferred {
        value: StackObjectChange {
            object: object.clone(),
            before_hex: hex::encode(before_object),
            after_hex: hex::encode(after_object),
            changed_intervals: intervals,
        },
        source: "hash-verified same-execution snapshots joined to one realized DWARF stack object"
            .to_string(),
    }
}

fn compare_field_snapshots(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    process_id: &str,
    object: &Evidence<RealizedStackObject>,
) -> Evidence<Vec<StackFieldChange>> {
    let Evidence::Inferred { value: object, .. } = object else {
        return Evidence::Unknown {
            reason: "stack object must resolve before fields can be compared".to_string(),
        };
    };
    let Some(mapping_object) = capsule.runtime_objects.iter().find(|candidate| {
        candidate.process_id == process_id
            && candidate.kind == RuntimeObjectKind::Mapping
            && candidate.start <= object.runtime_start
            && object
                .runtime_start
                .checked_add(object.byte_len)
                .is_some_and(|end| end <= candidate.start + candidate.byte_len)
    }) else {
        return Evidence::Unknown {
            reason: "realized stack object has no containing captured mapping object".to_string(),
        };
    };
    let mut snapshots = capsule
        .object_snapshots
        .iter()
        .filter(|snapshot| snapshot.object_id == mapping_object.id)
        .collect::<Vec<_>>();
    snapshots.sort_by_key(|snapshot| {
        (
            snapshot.point.thread_id.clone(),
            snapshot.point.sequence,
            snapshot.id.clone(),
        )
    });
    let [before, after] = snapshots.as_slice() else {
        return Evidence::Unknown {
            reason: "field comparison requires exactly two ordered mapping snapshots".to_string(),
        };
    };
    if before.object_offset != after.object_offset || before.byte_len != after.byte_len {
        return Evidence::Unknown {
            reason: "before and after mapping snapshots cover different intervals".to_string(),
        };
    }
    let load = |snapshot: &super::capsule::ObjectSnapshotRecord| -> Result<&[u8], String> {
        let PageContent::Captured { payload } = &snapshot.content else {
            return Err("mapping snapshot payload was omitted".to_string());
        };
        let bytes = payloads
            .get(&payload.id)
            .ok_or_else(|| format!("mapping snapshot payload {} is unavailable", payload.id))?;
        if bytes.len() as u64 != payload.byte_len
            || payload.byte_len != snapshot.byte_len
            || hex::encode(Sha256::digest(bytes)) != payload.sha256
        {
            return Err(format!(
                "mapping snapshot payload {} disagrees with its identity",
                payload.id
            ));
        }
        Ok(bytes)
    };
    let (before_bytes, after_bytes) = match (load(before), load(after)) {
        (Ok(before_bytes), Ok(after_bytes)) => (before_bytes, after_bytes),
        (Err(reason), _) | (_, Err(reason)) => return Evidence::Unknown { reason },
    };
    let Some(snapshot_start) = mapping_object.start.checked_add(before.object_offset) else {
        return Evidence::Unknown {
            reason: "mapping snapshot runtime range overflowed".to_string(),
        };
    };
    let snapshot_end = snapshot_start + before.byte_len;
    let Some(type_name) = object
        .c_type
        .as_deref()
        .and_then(|value| value.strip_prefix("struct "))
    else {
        return Evidence::Unknown {
            reason: "DWARF stack object has no concrete struct type".to_string(),
        };
    };
    let layouts = extract_dwarf_types(image.bytes())
        .into_iter()
        .filter(|layout| layout.kind == DwarfTypeKind::Struct && layout.name == type_name)
        .collect::<Vec<_>>();
    let [layout] = layouts.as_slice() else {
        return Evidence::Unknown {
            reason: "DWARF struct layout is absent or ambiguous".to_string(),
        };
    };
    let mut changes = Vec::new();
    for field in &layout.fields {
        let field_start = object.runtime_start + field.offset;
        let field_end = field_start.saturating_add(field.size);
        if field.size == 0 || field_start < snapshot_start || field_end > snapshot_end {
            continue;
        }
        let start = usize::try_from(field_start - snapshot_start).expect("bounded snapshot offset");
        let end = start + usize::try_from(field.size).expect("bounded field size");
        let before_field = &before_bytes[start..end];
        let after_field = &after_bytes[start..end];
        let mut intervals = Vec::new();
        let mut cursor = 0usize;
        while cursor < before_field.len() {
            if before_field[cursor] == after_field[cursor] {
                cursor += 1;
                continue;
            }
            let interval_start = cursor;
            while cursor < before_field.len() && before_field[cursor] != after_field[cursor] {
                cursor += 1;
            }
            intervals.push(StackFieldChangedInterval {
                field_offset_start: interval_start as u64,
                field_offset_end: cursor as u64,
                before_hex: hex::encode(&before_field[interval_start..cursor]),
                after_hex: hex::encode(&after_field[interval_start..cursor]),
            });
        }
        changes.push(StackFieldChange {
            field: RealizedField {
                name: field.name.clone(),
                c_type: field.c_type.clone(),
                object_offset: field.offset,
                runtime_start: field_start,
                byte_len: field.size,
            },
            before_hex: hex::encode(before_field),
            after_hex: hex::encode(after_field),
            changed_intervals: intervals,
        });
    }
    Evidence::Inferred {
        value: changes,
        source: "hash-verified same-execution snapshots joined to realized DWARF fields"
            .to_string(),
    }
}

fn relate_input_field_effects(
    occurrence: &Evidence<OperationOccurrence>,
    object: &Evidence<RealizedStackObject>,
    field_changes: &Evidence<Vec<StackFieldChange>>,
) -> Evidence<Vec<StackInputFieldEffect>> {
    let Evidence::Inferred {
        value: occurrence, ..
    } = occurrence
    else {
        return Evidence::Unknown {
            reason: "input field effects require an exact operation occurrence".to_string(),
        };
    };
    let candidates = occurrence
        .effects
        .iter()
        .filter(|effect| {
            effect.input_source_id.is_some()
                && effect.address.is_some()
                && effect.byte_len.is_some_and(|byte_len| byte_len != 0)
        })
        .collect::<Vec<_>>();
    let [effect] = candidates.as_slice() else {
        return Evidence::Unknown {
            reason: "input field effects require exactly one bounded input memory effect"
                .to_string(),
        };
    };
    let input_source_id = effect
        .input_source_id
        .as_ref()
        .expect("filtered input source");
    let matching_sources = occurrence
        .introduced_input_sources
        .iter()
        .filter(|source| source.id == *input_source_id)
        .collect::<Vec<_>>();
    let [source] = matching_sources.as_slice() else {
        return Evidence::Unknown {
            reason: "input memory effect has no unique introduced source identity".to_string(),
        };
    };
    let effect_start = effect.address.expect("filtered effect address");
    let effect_len = effect.byte_len.expect("filtered effect length");
    if source.byte_len != effect_len {
        return Evidence::Unknown {
            reason: "introduced input extent disagrees with the memory effect".to_string(),
        };
    }
    let Some(effect_end) = effect_start.checked_add(effect_len) else {
        return Evidence::Unknown {
            reason: "input memory effect range overflowed".to_string(),
        };
    };
    let Evidence::Inferred { value: object, .. } = object else {
        return Evidence::Unknown {
            reason: "input field effects require one realized stack object".to_string(),
        };
    };
    let Some(object_end) = object.runtime_start.checked_add(object.byte_len) else {
        return Evidence::Unknown {
            reason: "realized stack object range overflowed".to_string(),
        };
    };
    if effect_start < object.runtime_start || effect_end > object_end {
        return Evidence::Unknown {
            reason: "input memory effect is not contained in the realized stack object".to_string(),
        };
    }
    let Evidence::Inferred { value: changes, .. } = field_changes else {
        return Evidence::Unknown {
            reason: "input field effects require realized DWARF fields".to_string(),
        };
    };
    let mut relations = Vec::new();
    for change in changes {
        let field = &change.field;
        let Some(field_end) = field.runtime_start.checked_add(field.byte_len) else {
            return Evidence::Unknown {
                reason: "realized stack field range overflowed".to_string(),
            };
        };
        let overlap_start = effect_start.max(field.runtime_start);
        let overlap_end = effect_end.min(field_end);
        if overlap_start >= overlap_end {
            continue;
        }
        relations.push(StackInputFieldEffect {
            input_source_id: input_source_id.clone(),
            source_offset_start: overlap_start - effect_start,
            source_offset_end: overlap_end - effect_start,
            runtime_start: overlap_start,
            runtime_end: overlap_end,
            object_offset_start: overlap_start - object.runtime_start,
            object_offset_end: overlap_end - object.runtime_start,
            field: field.clone(),
            field_offset_start: overlap_start - field.runtime_start,
            field_offset_end: overlap_end - field.runtime_start,
        });
    }
    if relations.is_empty()
        || relations
            .iter()
            .map(|relation| relation.source_offset_end - relation.source_offset_start)
            .sum::<u64>()
            != effect_len
    {
        return Evidence::Unknown {
            reason: "realized fields do not exactly cover the input memory effect".to_string(),
        };
    }
    Evidence::Inferred {
        value: relations,
        source: "introduced input source and LLIR call effect joined to realized DWARF fields"
            .to_string(),
    }
}

type RelationEvidence = (
    Evidence<RuntimeFrameIdentity>,
    Evidence<RealizedStackObject>,
    Evidence<RealizedField>,
    Evidence<StackWriteBounds>,
);

fn unknown_tuple(reason: &str) -> RelationEvidence {
    (
        Evidence::Unknown {
            reason: reason.to_string(),
        },
        Evidence::Unknown {
            reason: reason.to_string(),
        },
        Evidence::Unknown {
            reason: reason.to_string(),
        },
        Evidence::Unknown {
            reason: reason.to_string(),
        },
    )
}

/// One `[saved rbp][return address]` record pushed by a callee of `main`.
struct MainFrameRecord {
    function_entry: u64,
    function_name: Option<String>,
    frame_pointer: u64,
    record_address: u64,
    return_address: u64,
}

/// Validate the 16 bytes at `cursor` as a frame record pushed by a callee of
/// `main`, or return `None`.
///
/// A value merely resolving into `main` is not a return address: glibc's
/// start-up frame holds `main`'s own entry address as a function pointer, and
/// an adjacent stack pointer makes that slot look like a frame record. A
/// return address is only accepted when the exact-image instruction ending at
/// it is a `call` inside `main`. The record must also lie wholly below the
/// frame it names, since a callee's record is pushed beneath its caller's.
#[allow(clippy::too_many_arguments)]
fn main_callee_frame_record(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    process_id: &str,
    memory: &RuntimeMemoryView,
    return_sites: &mut BTreeMap<u64, Option<(u64, Option<String>)>>,
    cursor: u64,
    stack_end: u64,
) -> Option<MainFrameRecord> {
    let record = memory.read_runtime_bytes(cursor, 16).ok()?;
    let next_rbp = u64::from_le_bytes(record[0..8].try_into().ok()?);
    let return_address = u64::from_le_bytes(record[8..16].try_into().ok()?);
    if next_rbp < cursor.checked_add(16)?
        || next_rbp & 7 != 0
        || next_rbp.saturating_add(16) > stack_end
    {
        return None;
    }
    let site = match return_sites.get(&return_address) {
        Some(site) => site.clone(),
        None => {
            let site = main_return_site(capsule, payloads, image, process_id, return_address);
            return_sites.insert(return_address, site.clone());
            site
        }
    };
    let (function_entry, function_name) = site?;
    memory.read_runtime_bytes(next_rbp, 16).ok()?;
    Some(MainFrameRecord {
        function_entry,
        function_name,
        frame_pointer: next_rbp,
        record_address: cursor,
        return_address,
    })
}

/// Return `main`'s entry and name when `return_address` immediately follows
/// an exact-image `call` instruction inside `main`.
fn main_return_site(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    process_id: &str,
    return_address: u64,
) -> Option<(u64, Option<String>)> {
    let AddressResolution::Exact { address } =
        resolve_runtime_address(capsule, payloads, image, process_id, return_address)
    else {
        return None;
    };
    // A return address is never a function entry: `Exact` means the value is
    // `main` itself (a function pointer), not a return into it.
    let FunctionResolution::Interior {
        entry_va,
        name,
        end_va,
    } = address.function
    else {
        return None;
    };
    if name.as_deref() != Some("main") {
        return None;
    }
    let static_return_va = address.static_va;
    let call_byte = static_return_va.checked_sub(1)?;
    let function = resolve_static_function(image, call_byte);
    if !matches!(
        &function,
        FunctionResolution::Exact { entry_va: owner, .. }
            | FunctionResolution::Interior { entry_va: owner, .. }
            if *owner == entry_va
    ) {
        return None;
    }
    let StaticCodeResolution::Resolved {
        instruction_va,
        instruction_end,
        mnemonic,
        ..
    } = resolve_static_code(image, call_byte, &function)
    else {
        return None;
    };
    (instruction_va >= entry_va
        && instruction_end == static_return_va
        && static_return_va <= end_va
        && mnemonic.starts_with("call"))
    .then_some((entry_va, name))
}

fn relate_one_write(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    process_id: &str,
    destination: u64,
    byte_len: u64,
) -> RelationEvidence {
    if capsule.executable.sha256 != hex::encode(Sha256::digest(image.bytes())) {
        return unknown_tuple("capsule executable identity disagrees with static image");
    }
    let Some(thread) = capsule
        .threads
        .iter()
        .find(|thread| thread.process_id == process_id)
    else {
        return unknown_tuple("runtime write has no checkpoint thread evidence");
    };
    let registers = thread
        .registers
        .iter()
        .filter_map(|register| {
            u64::from_str_radix(&register.value_hex, 16)
                .ok()
                .map(|value| (register.provider_name.as_str(), value))
        })
        .collect::<BTreeMap<_, _>>();
    let Some(&rsp) = registers.get("rsp") else {
        return unknown_tuple("checkpoint thread has no observed stack pointer");
    };
    let Ok(memory) = RuntimeMemoryView::new(capsule, payloads, process_id) else {
        return unknown_tuple("checkpoint runtime memory view is unavailable");
    };
    let Some(stack_end) = capsule
        .mappings
        .iter()
        .find(|mapping| {
            mapping.process_id == process_id && mapping.start <= rsp && rsp < mapping.end
        })
        .map(|mapping| mapping.end)
    else {
        return unknown_tuple("checkpoint stack pointer has no unique mapping");
    };
    let scan_end = stack_end.min(rsp.saturating_add(MAX_FRAME_SCAN_BYTES));
    let mut return_sites = BTreeMap::new();
    let mut frame_records = Vec::new();
    let mut cursor = rsp.saturating_add(7) & !7;
    while cursor.saturating_add(16) <= scan_end {
        if let Some(record) = main_callee_frame_record(
            capsule,
            payloads,
            image,
            process_id,
            &memory,
            &mut return_sites,
            cursor,
            stack_end,
        ) {
            frame_records.push(record);
        }
        cursor = cursor.saturating_add(8);
    }
    // Every call main makes pushes main's frame pointer beside a return site in
    // main, so stale records left by earlier callees name the same frame as the
    // live one. The frame is identified when every validated record agrees on
    // it; a disagreement is a second frame (or forged evidence) and fails closed.
    let frames = frame_records
        .iter()
        .map(|record| (record.function_entry, record.frame_pointer))
        .collect::<BTreeSet<_>>();
    if frames.len() != 1 {
        return unknown_tuple("checkpoint stack does not identify one unique main frame");
    }
    // The live record sits directly below main's frame; stale copies can only
    // survive in deeper (lower) callee frames.
    let Some(live) = frame_records
        .into_iter()
        .max_by_key(|record| record.record_address)
    else {
        return unknown_tuple("checkpoint stack does not identify one unique main frame");
    };
    let MainFrameRecord {
        function_entry,
        function_name,
        frame_pointer,
        record_address,
        return_address,
    } = live;
    let Some(call_frame_cfa) = frame_pointer.checked_add(16) else {
        return unknown_tuple("main call-frame address overflowed");
    };
    let frame_value = RuntimeFrameIdentity {
        function_entry,
        function_name,
        frame_pointer,
        call_frame_cfa,
        evidence_record_address: record_address,
        return_address,
    };
    let frame = Evidence::Inferred {
        value: frame_value.clone(),
        source: "bounded x86-64 frame record whose return follows an exact-image call in main"
            .to_string(),
    };

    let dwarf_functions = image.dwarf_functions();
    let Some(function) = dwarf_functions
        .iter()
        .find(|function| function.entry_va == function_entry)
    else {
        return (
            frame,
            Evidence::Unknown {
                reason: "resolved main function has no DWARF stack-object contract".to_string(),
            },
            Evidence::Unknown {
                reason: "stack object is unavailable".to_string(),
            },
            Evidence::Unknown {
                reason: "stack object bounds are unavailable".to_string(),
            },
        );
    };
    let mut objects = function
        .stack_objects
        .iter()
        .filter_map(|object| {
            let (base, static_base) = match object.base {
                DwarfStackBase::Register(X86_64_DWARF_RBP) => {
                    (frame_pointer, "dwarf_register_6_rbp")
                }
                DwarfStackBase::CallFrameCfa => (call_frame_cfa, "dwarf_call_frame_cfa"),
                DwarfStackBase::Register(_) => return None,
            };
            let start = base.checked_add_signed(object.offset)?;
            let end = start.checked_add(u64::from(object.byte_size))?;
            (start <= destination && destination < end).then(|| RealizedStackObject {
                source_name: object.source_name.clone(),
                c_type: object.c_type.clone(),
                static_base: static_base.to_string(),
                static_offset: object.offset,
                runtime_start: start,
                byte_len: u64::from(object.byte_size),
                aggregate: object.aggregate,
            })
        })
        .collect::<Vec<_>>();
    objects.sort_by_key(|object| (object.runtime_start, object.byte_len));
    objects.dedup();
    let [object_value] = objects.as_slice() else {
        return (
            frame,
            Evidence::Unknown {
                reason: "runtime destination does not identify one DWARF stack object".to_string(),
            },
            Evidence::Unknown {
                reason: "stack-object field is unavailable".to_string(),
            },
            Evidence::Unknown {
                reason: "stack-object bounds are unavailable".to_string(),
            },
        );
    };
    let object_value = object_value.clone();
    let object = Evidence::Inferred {
        value: object_value.clone(),
        source: "runtime main frame joined to authoritative DWARF stack-object location"
            .to_string(),
    };
    let type_name = object_value
        .c_type
        .as_deref()
        .and_then(|value| value.strip_prefix("struct "));
    let Some(type_name) = type_name else {
        return (
            frame,
            object,
            Evidence::Unknown {
                reason: "DWARF stack object has no concrete struct type".to_string(),
            },
            Evidence::Unknown {
                reason: "field bounds are unavailable".to_string(),
            },
        );
    };
    let layouts = extract_dwarf_types(image.bytes())
        .into_iter()
        .filter(|layout| layout.kind == DwarfTypeKind::Struct && layout.name == type_name)
        .collect::<Vec<_>>();
    let [layout] = layouts.as_slice() else {
        return (
            frame,
            object,
            Evidence::Unknown {
                reason: "DWARF struct layout is absent or ambiguous".to_string(),
            },
            Evidence::Unknown {
                reason: "field bounds are unavailable".to_string(),
            },
        );
    };
    let destination_offset = destination - object_value.runtime_start;
    let fields = layout
        .fields
        .iter()
        .filter(|field| {
            field.offset <= destination_offset
                && destination_offset < field.offset.saturating_add(field.size)
        })
        .collect::<Vec<_>>();
    let [field_contract] = fields.as_slice() else {
        return (
            frame,
            object,
            Evidence::Unknown {
                reason: "runtime destination does not identify one DWARF field".to_string(),
            },
            Evidence::Unknown {
                reason: "field bounds are unavailable".to_string(),
            },
        );
    };
    let field_value = RealizedField {
        name: field_contract.name.clone(),
        c_type: field_contract.c_type.clone(),
        object_offset: field_contract.offset,
        runtime_start: object_value.runtime_start + field_contract.offset,
        byte_len: field_contract.size,
    };
    let field = Evidence::Inferred {
        value: field_value.clone(),
        source: "realized DWARF object joined to its authoritative field layout".to_string(),
    };
    let Some(write_end) = destination.checked_add(byte_len) else {
        return (
            frame,
            object,
            field,
            Evidence::Unknown {
                reason: "runtime write range overflowed".to_string(),
            },
        );
    };
    let object_end = object_value.runtime_start + object_value.byte_len;
    let field_end = field_value.runtime_start + field_value.byte_len;
    let object_bytes_exceeded = write_end.saturating_sub(object_end);
    let field_bytes_exceeded = write_end.saturating_sub(field_end);
    let classification = if field_bytes_exceeded != 0 {
        "crosses_field_boundary"
    } else {
        "within_field"
    };
    let bounds = Evidence::Inferred {
        value: StackWriteBounds {
            write_start: destination,
            write_byte_len: byte_len,
            object_bytes_exceeded,
            field_bytes_exceeded,
            classification: classification.to_string(),
        },
        source: "observed write interval compared with realized DWARF object and field bounds"
            .to_string(),
    };
    (frame, object, field, bounds)
}
