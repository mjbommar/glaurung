//! Object-relative byte changes from time-scoped runtime snapshots.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::capsule::{ObjectSnapshotRecord, PageContent, ProcessCapsule, RuntimeObjectKind};
use super::correlation::{
    resolve_static_code, resolve_static_function, FunctionResolution, StaticCodeResolution,
    StaticValueExpression,
};
use super::crash::Evidence;
use super::event_correlation::{operation_occurrence, OperationEffect, OperationOccurrence};
use crate::core::binary::Arch;
use crate::debug::dwarf::DwarfStackBase;
use crate::program::image::ProgramImage;

pub const OBJECT_CHANGE_REPORT_SCHEMA: &str = "glaurung-runtime-object-change-report-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedInterval {
    pub object_offset_start: u64,
    pub object_offset_end: u64,
    pub before_hex: String,
    pub after_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectChange {
    pub object_id: String,
    pub kind: RuntimeObjectKind,
    pub runtime_start: u64,
    pub object_byte_len: u64,
    pub creation_callsite: Evidence<StaticCallsite>,
    pub creation_occurrence: Evidence<OperationOccurrence>,
    pub before_snapshot_id: Evidence<String>,
    pub after_snapshot_id: Evidence<String>,
    pub changed_intervals: Evidence<Vec<ChangedInterval>>,
    pub responsible_write: Evidence<WriteAttribution>,
    pub static_callsite: Evidence<StaticCallsite>,
    pub operation_occurrence: Evidence<OperationOccurrence>,
    pub write_observations: Vec<ObjectWriteObservation>,
    pub allocation_prefix_write: Evidence<AllocationPrefixWriteRelation>,
    pub allocation_prefix_transition: Evidence<AllocationPrefixTransition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationPrefixWriteRelation {
    pub runtime_object_id: String,
    pub source_name: String,
    pub c_type: String,
    pub static_base: String,
    pub static_offset: i64,
    pub allocation_argument_position: usize,
    pub allocation_abi_register: String,
    pub logical_prefix_byte_len: u64,
    pub reserved_tail_byte_len: u64,
    pub allocation_byte_len: u64,
    pub write_byte_len: u64,
    pub prefix_bytes_exceeded: u64,
    pub classification: String,
    pub allocation_occurrence: OperationOccurrence,
    pub write_occurrence: OperationOccurrence,
    pub source_pointer: SourcePointerRelation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationPrefixTransition {
    pub runtime_object_id: String,
    pub write_sequence: u64,
    pub before_snapshot_id: String,
    pub after_snapshot_id: String,
    pub logical_prefix_byte_len: u64,
    pub reserved_tail_byte_len: u64,
    pub prefix_changed_intervals: Vec<ChangedInterval>,
    pub tail_changed_intervals: Vec<ChangedInterval>,
    pub tail_before_hex: String,
    pub tail_after_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectWriteObservation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub address: u64,
    pub byte_len: u64,
    pub object_offset: Evidence<u64>,
    pub lifetime: ObjectWriteLifetime,
    pub after_hex: Evidence<String>,
    pub static_callsite: Evidence<StaticCallsite>,
    pub operation_occurrence: Evidence<OperationOccurrence>,
    pub source_pointer: Evidence<SourcePointerRelation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectWriteLifetime {
    BeforeLifetime,
    Live,
    Ended,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourcePointerRelation {
    pub runtime_object_id: String,
    pub static_variable: crate::ir::function_ir::StaticVariable,
    pub static_type: crate::ir::function_ir::StaticType,
    pub semantic_binding: crate::ir::function_ir::SemanticValueVariableBinding,
    pub source_name: String,
    pub c_type: String,
    pub function_entry: u64,
    pub static_base: String,
    pub static_offset: i64,
    pub argument_position: usize,
    pub abi_register: String,
    pub relation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WriteAttribution {
    Event {
        process_id: String,
        thread_id: Option<String>,
        sequence: u64,
        address: u64,
        byte_len: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticCallsite {
    pub runtime_return_va: u64,
    pub static_instruction_va: u64,
    pub function: FunctionResolution,
    pub code: StaticCodeResolution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectChangeReport {
    pub schema: String,
    pub capture_id: String,
    pub objects: Vec<ObjectChange>,
}

pub fn analyze_object_changes(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
) -> ObjectChangeReport {
    let mut objects = Vec::new();
    for object in &capsule.runtime_objects {
        let mut snapshots: Vec<_> = capsule
            .object_snapshots
            .iter()
            .filter(|snapshot| snapshot.object_id == object.id)
            .collect();
        snapshots.sort_by_key(|snapshot| {
            (
                snapshot.point.thread_id.clone(),
                snapshot.point.sequence,
                snapshot.id.clone(),
            )
        });
        let pair = snapshots
            .first()
            .zip(snapshots.last())
            .filter(|_| snapshots.len() >= 2)
            .map(|(before, after)| (*before, *after));
        let (before_snapshot_id, after_snapshot_id, changed_intervals) = pair.map_or_else(
            || {
                let reason = format!(
                    "runtime object has {} snapshot(s); at least two are required",
                    snapshots.len()
                );
                (
                    Evidence::Unknown {
                        reason: reason.clone(),
                    },
                    Evidence::Unknown {
                        reason: reason.clone(),
                    },
                    Evidence::Unknown { reason },
                )
            },
            |(before, after)| {
                let source = "ordered object snapshot records".to_string();
                let before_id = Evidence::Observed {
                    value: before.id.clone(),
                    source: source.clone(),
                };
                let after_id = Evidence::Observed {
                    value: after.id.clone(),
                    source: source.clone(),
                };
                let changes = compare_snapshots(before, after, payloads).map_or_else(
                    |reason| Evidence::Unknown { reason },
                    |value| Evidence::Observed {
                        value,
                        source: "hash-verified object snapshot payloads".to_string(),
                    },
                );
                (before_id, after_id, changes)
            },
        );
        let responsible_write = attribute_write(capsule, object, pair, &changed_intervals);
        let creation_callsite = resolve_allocation_callsite(capsule, image, object);
        let creation_occurrence =
            make_allocation_operation_occurrence(capsule, object, &creation_callsite);
        let static_callsite = resolve_write_callsite(capsule, image, &responsible_write);
        let operation_occurrence = make_write_operation_occurrence(
            capsule,
            &responsible_write,
            &static_callsite,
            &object.id,
        );
        let write_observations = collect_write_observations(capsule, payloads, image, object);
        let allocation_prefix_write = relate_allocation_prefix_write(
            image,
            object,
            &creation_occurrence,
            &write_observations,
        );
        let allocation_prefix_transition = relate_allocation_prefix_transition(
            capsule,
            payloads,
            object,
            &allocation_prefix_write,
        );
        objects.push(ObjectChange {
            object_id: object.id.clone(),
            kind: object.kind,
            runtime_start: object.start,
            object_byte_len: object.byte_len,
            creation_callsite,
            creation_occurrence,
            before_snapshot_id,
            after_snapshot_id,
            changed_intervals,
            responsible_write,
            static_callsite,
            operation_occurrence,
            write_observations,
            allocation_prefix_write,
            allocation_prefix_transition,
        });
    }
    ObjectChangeReport {
        schema: OBJECT_CHANGE_REPORT_SCHEMA.to_string(),
        capture_id: capsule.identity.capture_id.clone(),
        objects,
    }
}

fn relate_allocation_prefix_transition(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    object: &super::capsule::RuntimeObjectRecord,
    relation: &Evidence<AllocationPrefixWriteRelation>,
) -> Evidence<AllocationPrefixTransition> {
    let Evidence::Inferred {
        value: relation, ..
    } = relation
    else {
        return Evidence::Unknown {
            reason: "allocation-prefix transition requires the prefix-write relation".to_string(),
        };
    };
    let sequence = relation.write_occurrence.event_sequence;
    let mut before = capsule
        .object_snapshots
        .iter()
        .filter(|snapshot| {
            snapshot.process_id == object.process_id
                && snapshot.object_id == object.id
                && snapshot.point.thread_id == relation.write_occurrence.thread_id
                && snapshot.point.sequence < sequence
        })
        .max_by_key(|snapshot| snapshot.point.sequence);
    let mut after = capsule
        .object_snapshots
        .iter()
        .filter(|snapshot| {
            snapshot.process_id == object.process_id
                && snapshot.object_id == object.id
                && snapshot.point.thread_id == relation.write_occurrence.thread_id
                && snapshot.point.sequence > sequence
        })
        .min_by_key(|snapshot| snapshot.point.sequence);
    let (Some(before), Some(after)) = (before.take(), after.take()) else {
        return Evidence::Unknown {
            reason: "write occurrence is not bracketed by object snapshots".to_string(),
        };
    };
    if before.object_offset != 0
        || after.object_offset != 0
        || before.byte_len != object.byte_len
        || after.byte_len != object.byte_len
    {
        return Evidence::Unknown {
            reason: "write-bracketing snapshots do not cover the full runtime object".to_string(),
        };
    }
    let before_bytes = match snapshot_bytes(before, payloads) {
        Ok(bytes) => bytes,
        Err(reason) => return Evidence::Unknown { reason },
    };
    let after_bytes = match snapshot_bytes(after, payloads) {
        Ok(bytes) => bytes,
        Err(reason) => return Evidence::Unknown { reason },
    };
    let Ok(prefix_end) = usize::try_from(relation.logical_prefix_byte_len) else {
        return Evidence::Unknown {
            reason: "logical allocation prefix does not fit the host index space".to_string(),
        };
    };
    if prefix_end > before_bytes.len() || before_bytes.len() != after_bytes.len() {
        return Evidence::Unknown {
            reason: "logical allocation prefix exceeds captured object bytes".to_string(),
        };
    }
    Evidence::Inferred {
        value: AllocationPrefixTransition {
            runtime_object_id: object.id.clone(),
            write_sequence: sequence,
            before_snapshot_id: before.id.clone(),
            after_snapshot_id: after.id.clone(),
            logical_prefix_byte_len: relation.logical_prefix_byte_len,
            reserved_tail_byte_len: relation.reserved_tail_byte_len,
            prefix_changed_intervals: changed_intervals_for_range(
                before_bytes,
                after_bytes,
                0,
                prefix_end,
            ),
            tail_changed_intervals: changed_intervals_for_range(
                before_bytes,
                after_bytes,
                prefix_end,
                before_bytes.len(),
            ),
            tail_before_hex: hex::encode(&before_bytes[prefix_end..]),
            tail_after_hex: hex::encode(&after_bytes[prefix_end..]),
        },
        source: "hash-verified object snapshots immediately bracketing one exact write occurrence"
            .to_string(),
    }
}

fn changed_intervals_for_range(
    before: &[u8],
    after: &[u8],
    start: usize,
    end: usize,
) -> Vec<ChangedInterval> {
    let mut changed = Vec::new();
    let mut index = start;
    while index < end {
        if before[index] == after[index] {
            index += 1;
            continue;
        }
        let interval_start = index;
        while index < end && before[index] != after[index] {
            index += 1;
        }
        changed.push(ChangedInterval {
            object_offset_start: interval_start as u64,
            object_offset_end: index as u64,
            before_hex: hex::encode(&before[interval_start..index]),
            after_hex: hex::encode(&after[interval_start..index]),
        });
    }
    changed
}

fn allocation_event<'a>(
    capsule: &'a ProcessCapsule,
    object: &super::capsule::RuntimeObjectRecord,
) -> Result<&'a super::capsule::EventRecord, String> {
    let candidates = capsule
        .events
        .iter()
        .filter(|event| {
            event.process_id == object.process_id
                && event.kind == "allocation"
                && event.fields.get("object_id").map(String::as_str) == Some(object.id.as_str())
        })
        .collect::<Vec<_>>();
    let [event] = candidates.as_slice() else {
        return Err(format!(
            "expected one allocation event for runtime object, found {}",
            candidates.len()
        ));
    };
    Ok(event)
}

pub(super) fn resolve_allocation_callsite(
    capsule: &ProcessCapsule,
    image: &ProgramImage,
    object: &super::capsule::RuntimeObjectRecord,
) -> Evidence<StaticCallsite> {
    let event = match allocation_event(capsule, object) {
        Ok(event) => event,
        Err(reason) => return Evidence::Unknown { reason },
    };
    resolve_interposed_event_callsite(capsule, image, event, "allocation")
}

pub(super) fn make_allocation_operation_occurrence(
    capsule: &ProcessCapsule,
    object: &super::capsule::RuntimeObjectRecord,
    callsite: &Evidence<StaticCallsite>,
) -> Evidence<OperationOccurrence> {
    let event = match allocation_event(capsule, object) {
        Ok(event) => event,
        Err(reason) => return Evidence::Unknown { reason },
    };
    let Evidence::Inferred {
        value: callsite, ..
    } = callsite
    else {
        return Evidence::Unknown {
            reason: "allocation occurrence requires an exact static callsite".to_string(),
        };
    };
    let StaticCodeResolution::Resolved {
        operations: super::correlation::OperationResolution::Resolved { operations },
        ..
    } = &callsite.code
    else {
        return Evidence::Unknown {
            reason: "allocation callsite has no resolved LLIR operation".to_string(),
        };
    };
    let calls = operations
        .iter()
        .filter(|operation| {
            operation.kind == "call"
                && matches!(
                    &operation.call_target,
                    Some(super::correlation::StaticCallTarget::Direct {
                        symbol: Some(symbol),
                        ..
                    }) if symbol == "calloc"
                )
        })
        .collect::<Vec<_>>();
    let [operation] = calls.as_slice() else {
        return Evidence::Unknown {
            reason: "allocation instruction does not identify exactly one calloc operation"
                .to_string(),
        };
    };
    let observed = |field: &str| {
        event.fields.get(field).map(|value| Evidence::Observed {
            value: value.clone(),
            source: "provider-neutral calloc event".to_string(),
        })
    };
    let (Some(count), Some(element_size)) =
        (observed("calloc_count"), observed("calloc_element_size"))
    else {
        return Evidence::Unknown {
            reason: "allocation event has no valid calloc arguments".to_string(),
        };
    };
    operation_occurrence(
        capsule,
        &event.process_id,
        event.thread_id.as_deref(),
        event.sequence,
        operation,
        BTreeMap::from([
            ("count".to_string(), count),
            ("element_size".to_string(), element_size),
        ]),
        Vec::new(),
        Evidence::Unknown {
            reason: "pointer-valued calloc result is represented by the allocation effect"
                .to_string(),
        },
        vec![OperationEffect {
            kind: "memory_allocate".to_string(),
            resource_id: None,
            runtime_object_id: Some(object.id.clone()),
            errno: None,
            address: Some(object.start),
            byte_len: Some(object.byte_len),
            input_source_id: None,
        }],
        "observed calloc arguments and object joined to one exact static LLIR call operation",
    )
}

fn relate_allocation_prefix_write(
    image: &ProgramImage,
    object: &super::capsule::RuntimeObjectRecord,
    creation: &Evidence<OperationOccurrence>,
    writes: &[ObjectWriteObservation],
) -> Evidence<AllocationPrefixWriteRelation> {
    let Evidence::Inferred {
        value: allocation_occurrence,
        ..
    } = creation
    else {
        return Evidence::Unknown {
            reason: "allocation-prefix relation requires one allocation occurrence".to_string(),
        };
    };
    let count = observed_occurrence_input(allocation_occurrence, "count");
    let allocation_byte_len = observed_occurrence_input(allocation_occurrence, "element_size");
    if count != Some(1) || allocation_byte_len != Some(object.byte_len) {
        return Evidence::Unknown {
            reason: "allocation-prefix relation requires calloc(1, object_byte_len)".to_string(),
        };
    }
    let arguments = allocation_occurrence
        .static_operation
        .call_register_inputs
        .iter()
        .filter(|argument| argument.position == 1 && argument.abi_register == "rsi")
        .collect::<Vec<_>>();
    let [argument] = arguments.as_slice() else {
        return Evidence::Unknown {
            reason: "calloc call does not identify one SysV element-size input".to_string(),
        };
    };
    let Some((load, reserved_tail_byte_len)) = additive_frame_load(&argument.expression) else {
        return Evidence::Unknown {
            reason: "calloc element size is not one frame load plus a constant tail".to_string(),
        };
    };
    let Some(logical_prefix_byte_len) = object.byte_len.checked_sub(reserved_tail_byte_len) else {
        return Evidence::Unknown {
            reason: "calloc reserved tail exceeds the observed allocation".to_string(),
        };
    };
    let Some((register, static_offset, byte_len)) = loaded_frame_slot(load) else {
        return Evidence::Unknown {
            reason: "calloc prefix term is not one bounded frame-slot load".to_string(),
        };
    };
    let functions = image.dwarf_functions();
    let Some(function) = functions.iter().find(|function| {
        function.entry_va == allocation_occurrence.static_operation.function_entry
    }) else {
        return Evidence::Unknown {
            reason: "calloc function has no DWARF local-variable contract".to_string(),
        };
    };
    let candidates = function
        .stack_objects
        .iter()
        .filter_map(|candidate| {
            let candidate_offset = match candidate.base {
                DwarfStackBase::Register(candidate_register) if candidate_register == register => {
                    candidate.offset
                }
                DwarfStackBase::CallFrameCfa if register == 6 => {
                    candidate.offset.checked_add(16)?
                }
                _ => return None,
            };
            let source_name = candidate.source_name.as_ref()?;
            let c_type = candidate.c_type.as_ref()?;
            (candidate_offset == static_offset && u16::from(byte_len) == candidate.byte_size)
                .then_some((candidate, source_name, c_type))
        })
        .collect::<Vec<_>>();
    let [(candidate, source_name, c_type)] = candidates.as_slice() else {
        return Evidence::Unknown {
            reason: "calloc prefix load does not identify one DWARF scalar local".to_string(),
        };
    };
    let matching_writes = writes
        .iter()
        .filter_map(|write| {
            let Evidence::Inferred {
                value: write_occurrence,
                ..
            } = &write.operation_occurrence
            else {
                return None;
            };
            let Evidence::Inferred {
                value: source_pointer,
                ..
            } = &write.source_pointer
            else {
                return None;
            };
            (write.address == object.start
                && write.lifetime == ObjectWriteLifetime::Live
                && write_occurrence
                    .effects
                    .iter()
                    .any(|effect| effect.runtime_object_id.as_deref() == Some(object.id.as_str())))
            .then_some((write, write_occurrence, source_pointer))
        })
        .collect::<Vec<_>>();
    let [(write, write_occurrence, source_pointer)] = matching_writes.as_slice() else {
        return Evidence::Unknown {
            reason: "allocation prefix has no unique live write through its source pointer"
                .to_string(),
        };
    };
    let prefix_bytes_exceeded = write.byte_len.saturating_sub(logical_prefix_byte_len);
    Evidence::Inferred {
        value: AllocationPrefixWriteRelation {
            runtime_object_id: object.id.clone(),
            source_name: (*source_name).clone(),
            c_type: (*c_type).clone(),
            static_base: match candidate.base {
                DwarfStackBase::Register(value) => format!("dwarf_register_{value}"),
                DwarfStackBase::CallFrameCfa => "dwarf_call_frame_cfa".to_string(),
            },
            static_offset: candidate.offset,
            allocation_argument_position: argument.position,
            allocation_abi_register: argument.abi_register.clone(),
            logical_prefix_byte_len,
            reserved_tail_byte_len,
            allocation_byte_len: object.byte_len,
            write_byte_len: write.byte_len,
            prefix_bytes_exceeded,
            classification: if prefix_bytes_exceeded == 0 {
                "within_allocation_prefix"
            } else {
                "crosses_allocation_prefix_within_object"
            }
            .to_string(),
            allocation_occurrence: allocation_occurrence.clone(),
            write_occurrence: (*write_occurrence).clone(),
            source_pointer: (*source_pointer).clone(),
        },
        source: "observed calloc and memset occurrences joined through bounded LLIR argument slices, one DWARF scalar extent, and one runtime object".to_string(),
    }
}

fn observed_occurrence_input(occurrence: &OperationOccurrence, name: &str) -> Option<u64> {
    match occurrence.inputs.get(name)? {
        Evidence::Observed { value, .. } => value.parse().ok(),
        _ => None,
    }
}

fn additive_frame_load(
    expression: &StaticValueExpression,
) -> Option<(&StaticValueExpression, u64)> {
    let (load, constant) = match expression {
        StaticValueExpression::Add { left, right } => match (&**left, &**right) {
            (
                load @ StaticValueExpression::Load { .. },
                StaticValueExpression::Constant { value },
            )
            | (
                StaticValueExpression::Constant { value },
                load @ StaticValueExpression::Load { .. },
            ) => (load, *value),
            _ => return None,
        },
        _ => return None,
    };
    Some((load, u64::try_from(constant).ok()?))
}

fn collect_write_observations(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    object: &super::capsule::RuntimeObjectRecord,
) -> Vec<ObjectWriteObservation> {
    capsule
        .events
        .iter()
        .filter(|event| {
            event.process_id == object.process_id
                && event.kind == "memory_write"
                && event.fields.get("object_id").map(String::as_str) == Some(object.id.as_str())
        })
        .filter_map(|event| {
            let address = event.address?;
            let byte_len = event.fields.get("byte_len")?.parse::<u64>().ok()?;
            let object_offset = address.checked_sub(object.start).map_or_else(
                || Evidence::Unknown {
                    reason: "write address precedes runtime object".to_string(),
                },
                |offset| {
                    if offset
                        .checked_add(byte_len)
                        .is_some_and(|end| end <= object.byte_len)
                    {
                        Evidence::Inferred {
                            value: offset,
                            source: "observed write range compared with runtime object extent"
                                .to_string(),
                        }
                    } else {
                        Evidence::Unknown {
                            reason: "write range exceeds runtime object".to_string(),
                        }
                    }
                },
            );
            let lifetime = if event.sequence < object.created_at.sequence {
                ObjectWriteLifetime::BeforeLifetime
            } else if object
                .ended_at
                .as_ref()
                .is_some_and(|ended| event.sequence >= ended.sequence)
            {
                ObjectWriteLifetime::Ended
            } else {
                ObjectWriteLifetime::Live
            };
            let after_hex = observed_write_bytes(event, payloads);
            let attribution = Evidence::Observed {
                value: WriteAttribution::Event {
                    process_id: event.process_id.clone(),
                    thread_id: event.thread_id.clone(),
                    sequence: event.sequence,
                    address,
                    byte_len,
                },
                source: "provider-neutral bounded memory_write event".to_string(),
            };
            let static_callsite = resolve_write_callsite(capsule, image, &attribution);
            let operation_occurrence = make_write_operation_occurrence(
                capsule,
                &attribution,
                &static_callsite,
                &object.id,
            );
            let source_pointer = relate_source_pointer(image, object, &operation_occurrence);
            Some(ObjectWriteObservation {
                process_id: event.process_id.clone(),
                thread_id: event.thread_id.clone(),
                sequence: event.sequence,
                address,
                byte_len,
                object_offset,
                lifetime,
                after_hex,
                static_callsite,
                operation_occurrence,
                source_pointer,
            })
        })
        .collect()
}

fn relate_source_pointer(
    image: &ProgramImage,
    object: &super::capsule::RuntimeObjectRecord,
    occurrence: &Evidence<OperationOccurrence>,
) -> Evidence<SourcePointerRelation> {
    let Evidence::Inferred {
        value: occurrence, ..
    } = occurrence
    else {
        return Evidence::Unknown {
            reason: "source pointer requires an exact operation occurrence".to_string(),
        };
    };
    let destination = occurrence
        .inputs
        .get("destination_address")
        .and_then(|evidence| match evidence {
            Evidence::Observed { value, .. } => value.parse::<u64>().ok(),
            _ => None,
        });
    if destination != Some(object.start) {
        return Evidence::Unknown {
            reason: "observed call destination is not the runtime object start".to_string(),
        };
    }
    if !matches!(
        &occurrence.static_operation.call_target,
        Some(super::correlation::StaticCallTarget::Direct {
            symbol: Some(symbol),
            ..
        }) if symbol == "memset"
    ) {
        return Evidence::Unknown {
            reason: "source pointer relation requires the exact memset contract".to_string(),
        };
    }
    let arguments = occurrence
        .static_operation
        .call_register_inputs
        .iter()
        .filter(|argument| argument.position == 0 && argument.abi_register == "rdi")
        .collect::<Vec<_>>();
    let [argument] = arguments.as_slice() else {
        return Evidence::Unknown {
            reason: "static call does not identify one SysV destination register input".to_string(),
        };
    };
    let Some((register, static_offset, byte_len)) = loaded_frame_slot(&argument.expression) else {
        return Evidence::Unknown {
            reason: "static destination argument is not one bounded frame-slot load".to_string(),
        };
    };
    let functions = image.dwarf_functions();
    let Some(function) = functions
        .iter()
        .find(|function| function.entry_va == occurrence.static_operation.function_entry)
    else {
        return Evidence::Unknown {
            reason: "call function has no DWARF local-variable contract".to_string(),
        };
    };
    let candidates = function
        .stack_objects
        .iter()
        .filter_map(|candidate| {
            let candidate_offset = match candidate.base {
                DwarfStackBase::Register(candidate_register) if candidate_register == register => {
                    candidate.offset
                }
                DwarfStackBase::CallFrameCfa if register == 6 => {
                    candidate.offset.checked_add(16)?
                }
                _ => return None,
            };
            let source_name = candidate.source_name.as_ref()?;
            let c_type = candidate.c_type.as_ref()?;
            (candidate_offset == static_offset
                && u16::from(byte_len) == candidate.byte_size
                && c_type.contains('*'))
            .then_some((candidate, source_name, c_type))
        })
        .collect::<Vec<_>>();
    let [(candidate, source_name, c_type)] = candidates.as_slice() else {
        return Evidence::Unknown {
            reason: "static destination load does not identify one DWARF pointer local".to_string(),
        };
    };
    let (Some(declaration_offset), Some(type_offset)) = (
        candidate.declaration_debug_info_offset,
        candidate.type_debug_info_offset,
    ) else {
        return Evidence::Unknown {
            reason: "DWARF pointer local has no stable declaration or type identity".to_string(),
        };
    };
    let static_type = crate::ir::function_ir::dwarf_static_type(
        &occurrence.static_operation.image_sha256,
        type_offset,
        c_type,
    );
    let static_variable = crate::ir::function_ir::dwarf_static_variable(
        &occurrence.static_operation.image_sha256,
        &occurrence.static_operation.function_id,
        declaration_offset,
        source_name,
        &static_type.id,
    );
    let semantic_binding = crate::ir::function_ir::semantic_value_variable_binding(
        &argument.value_id,
        &static_variable.id,
        "reads_pointer_value_from",
    );
    Evidence::Inferred {
        value: SourcePointerRelation {
            runtime_object_id: object.id.clone(),
            static_variable,
            static_type,
            semantic_binding,
            source_name: (*source_name).clone(),
            c_type: (*c_type).clone(),
            function_entry: function.entry_va,
            static_base: match candidate.base {
                DwarfStackBase::Register(value) => format!("dwarf_register_{value}"),
                DwarfStackBase::CallFrameCfa => "dwarf_call_frame_cfa".to_string(),
            },
            static_offset: candidate.offset,
            argument_position: argument.position,
            abi_register: argument.abi_register.clone(),
            relation: "points_to_runtime_object_start".to_string(),
        },
        source: "observed destination joined to a bounded static call-argument slice and one DWARF pointer local".to_string(),
    }
}

fn loaded_frame_slot(expression: &StaticValueExpression) -> Option<(u16, i64, u8)> {
    let StaticValueExpression::Load { address, byte_len } = expression else {
        return None;
    };
    let (register, offset) = frame_address(address)?;
    Some((register, offset, *byte_len))
}

fn frame_address(expression: &StaticValueExpression) -> Option<(u16, i64)> {
    match expression {
        StaticValueExpression::Register { name } if name == "rbp" => Some((6, 0)),
        StaticValueExpression::Add { left, right } => match (&**left, &**right) {
            (address, StaticValueExpression::Constant { value })
            | (StaticValueExpression::Constant { value }, address) => {
                let (register, offset) = frame_address(address)?;
                Some((register, offset.checked_add(*value)?))
            }
            _ => None,
        },
        StaticValueExpression::Subtract { left, right } => {
            let StaticValueExpression::Constant { value } = &**right else {
                return None;
            };
            let (register, offset) = frame_address(left)?;
            Some((register, offset.checked_sub(*value)?))
        }
        _ => None,
    }
}

fn observed_write_bytes(
    event: &super::capsule::EventRecord,
    payloads: &BTreeMap<String, Vec<u8>>,
) -> Evidence<String> {
    let Some(payload_id) = event.fields.get("write_bytes_payload_id") else {
        return Evidence::Unknown {
            reason: "write event has no captured result bytes".to_string(),
        };
    };
    let Some(expected_sha256) = event.fields.get("write_bytes_sha256") else {
        return Evidence::Unknown {
            reason: "write-byte payload hash is absent".to_string(),
        };
    };
    let Some(expected_len) = event
        .fields
        .get("write_bytes_byte_len")
        .and_then(|value| value.parse::<usize>().ok())
    else {
        return Evidence::Unknown {
            reason: "write-byte payload length is absent or malformed".to_string(),
        };
    };
    let Some(bytes) = payloads.get(payload_id) else {
        return Evidence::Unknown {
            reason: format!("write-byte payload {payload_id} is unavailable"),
        };
    };
    if bytes.len() != expected_len || hex::encode(Sha256::digest(bytes)) != *expected_sha256 {
        return Evidence::Unknown {
            reason: "write-byte payload disagrees with its identity".to_string(),
        };
    }
    Evidence::Observed {
        value: hex::encode(bytes),
        source: "hash-verified bounded post-write bytes".to_string(),
    }
}

fn make_write_operation_occurrence(
    capsule: &ProcessCapsule,
    attribution: &Evidence<WriteAttribution>,
    callsite: &Evidence<StaticCallsite>,
    object_id: &str,
) -> Evidence<OperationOccurrence> {
    let Evidence::Observed {
        value:
            WriteAttribution::Event {
                process_id,
                thread_id,
                sequence,
                address,
                byte_len,
            },
        ..
    } = attribution
    else {
        return Evidence::Unknown {
            reason: "memory-write occurrence requires one observed write event".to_string(),
        };
    };
    let Evidence::Inferred {
        value: callsite, ..
    } = callsite
    else {
        return Evidence::Unknown {
            reason: "memory-write occurrence requires an exact static callsite".to_string(),
        };
    };
    let StaticCodeResolution::Resolved {
        operations: super::correlation::OperationResolution::Resolved { operations },
        ..
    } = &callsite.code
    else {
        return Evidence::Unknown {
            reason: "memory-write callsite has no resolved LLIR operation".to_string(),
        };
    };
    let call_operations = operations
        .iter()
        .filter(|operation| operation.kind == "call")
        .collect::<Vec<_>>();
    let [static_operation] = call_operations.as_slice() else {
        return Evidence::Unknown {
            reason: "memory-write instruction does not identify exactly one LLIR call operation"
                .to_string(),
        };
    };
    let observed = |value: String| Evidence::Observed {
        value,
        source: "provider-neutral bounded memory_write event".to_string(),
    };
    operation_occurrence(
        capsule,
        process_id,
        thread_id.as_deref(),
        *sequence,
        static_operation,
        BTreeMap::from([
            (
                "destination_address".to_string(),
                observed(address.to_string()),
            ),
            ("write_byte_len".to_string(), observed(byte_len.to_string())),
        ]),
        Vec::new(),
        Evidence::Unknown {
            reason: "memory-write provider did not capture the call return value".to_string(),
        },
        vec![OperationEffect {
            kind: "memory_write".to_string(),
            resource_id: None,
            runtime_object_id: Some(object_id.to_string()),
            errno: None,
            address: Some(*address),
            byte_len: Some(*byte_len),
            input_source_id: None,
        }],
        "observed object write joined to one exact static LLIR call operation",
    )
}

fn resolve_write_callsite(
    capsule: &ProcessCapsule,
    image: &ProgramImage,
    attribution: &Evidence<WriteAttribution>,
) -> Evidence<StaticCallsite> {
    let Evidence::Observed {
        value:
            WriteAttribution::Event {
                process_id,
                thread_id,
                sequence,
                ..
            },
        ..
    } = attribution
    else {
        return Evidence::Unknown {
            reason: "no unique observed write event exists".to_string(),
        };
    };
    let Some(event) = capsule.events.iter().find(|event| {
        event.process_id == *process_id
            && event.thread_id == *thread_id
            && event.sequence == *sequence
    }) else {
        return Evidence::Unknown {
            reason: "write event identity is missing from the capsule".to_string(),
        };
    };
    resolve_interposed_event_callsite(capsule, image, event, "write")
}

fn resolve_interposed_event_callsite(
    capsule: &ProcessCapsule,
    image: &ProgramImage,
    event: &super::capsule::EventRecord,
    role: &str,
) -> Evidence<StaticCallsite> {
    let Some(return_va) = event
        .fields
        .get("caller_return_va")
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return Evidence::Unknown {
            reason: format!("{role} event has no valid caller return address"),
        };
    };
    if event.fields.get("caller_main_module").map(String::as_str) != Some("true") {
        return Evidence::Unknown {
            reason: format!("{role} caller was not observed inside the launched main module"),
        };
    }
    let Some(module_base) = event
        .fields
        .get("caller_module_base")
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return Evidence::Unknown {
            reason: format!("{role} event has no valid main-module load bias"),
        };
    };
    let image_sha256 = hex::encode(Sha256::digest(image.bytes()));
    if image_sha256 != capsule.executable.sha256 {
        return Evidence::Unknown {
            reason: "capsule executable identity disagrees with static image".to_string(),
        };
    }
    if image.arch() != Arch::X86_64 || capsule.target.os_abi != "linux" {
        return Evidence::Unknown {
            reason: "caller resolution currently requires Linux x86-64".to_string(),
        };
    }
    let Some(static_return_va) = static_va_from_load_bias(return_va, module_base) else {
        return Evidence::Unknown {
            reason: "caller module-relative address overflowed".to_string(),
        };
    };
    let Some(call_va) = static_return_va.checked_sub(5) else {
        return Evidence::Unknown {
            reason: "caller return address cannot contain an x86-64 direct call".to_string(),
        };
    };
    let function = resolve_static_function(image, call_va);
    let code = resolve_static_code(image, call_va, &function);
    let StaticCodeResolution::Resolved {
        instruction_va,
        instruction_end,
        mnemonic,
        ..
    } = &code
    else {
        return Evidence::Unknown {
            reason: "caller return address did not resolve to static code".to_string(),
        };
    };
    if *instruction_va != call_va
        || *instruction_end != static_return_va
        || !mnemonic.starts_with("call")
    {
        return Evidence::Unknown {
            reason: "caller return address is not immediately after an exact direct call"
                .to_string(),
        };
    }
    Evidence::Inferred {
        value: StaticCallsite {
            runtime_return_va: return_va,
            static_instruction_va: call_va,
            function,
            code,
        },
        source: "observed main-module load bias and interposed-call return address in exact ProgramImage".to_string(),
    }
}

/// Translate a runtime address using the ELF loader's observed `dlpi_addr`.
///
/// `dlpi_addr` is the load bias added to ELF virtual addresses. It is zero for
/// the ordinary ET_EXEC case and non-zero for a relocated PIE image, so the
/// same subtraction is correct for both without consulting or guessing an
/// image base.
fn static_va_from_load_bias(runtime_va: u64, load_bias: u64) -> Option<u64> {
    runtime_va.checked_sub(load_bias)
}

fn attribute_write(
    capsule: &ProcessCapsule,
    object: &super::capsule::RuntimeObjectRecord,
    pair: Option<(&ObjectSnapshotRecord, &ObjectSnapshotRecord)>,
    changes: &Evidence<Vec<ChangedInterval>>,
) -> Evidence<WriteAttribution> {
    let Some((before, after)) = pair else {
        return Evidence::Unknown {
            reason: "no ordered before/after snapshot pair was captured".to_string(),
        };
    };
    let Evidence::Observed {
        value: intervals, ..
    } = changes
    else {
        return Evidence::Unknown {
            reason: "changed intervals are unavailable".to_string(),
        };
    };
    if intervals.is_empty() {
        return Evidence::Unknown {
            reason: "object bytes did not change".to_string(),
        };
    }
    let candidates: Vec<_> = capsule
        .events
        .iter()
        .filter_map(|event| {
            if event.process_id != object.process_id
                || event.thread_id != before.point.thread_id
                || event.sequence <= before.point.sequence
                || event.sequence >= after.point.sequence
                || event.kind != "memory_write"
                || event.fields.get("object_id").map(String::as_str) != Some(object.id.as_str())
            {
                return None;
            }
            let address = event.address?;
            let byte_len = event.fields.get("byte_len")?.parse::<u64>().ok()?;
            let end = address.checked_add(byte_len)?;
            let covers_all = intervals.iter().all(|interval| {
                let start = object.start.checked_add(interval.object_offset_start);
                let interval_end = object.start.checked_add(interval.object_offset_end);
                start.is_some_and(|start| address <= start)
                    && interval_end.is_some_and(|interval_end| interval_end <= end)
            });
            covers_all.then_some((event, address, byte_len))
        })
        .collect();
    if candidates.len() != 1 {
        return Evidence::Unknown {
            reason: format!(
                "expected one bounded write event covering every changed byte, found {}",
                candidates.len()
            ),
        };
    }
    let (event, address, byte_len) = candidates[0];
    Evidence::Observed {
        value: WriteAttribution::Event {
            process_id: event.process_id.clone(),
            thread_id: event.thread_id.clone(),
            sequence: event.sequence,
            address,
            byte_len,
        },
        source: "provider-neutral bounded memory_write event".to_string(),
    }
}

fn compare_snapshots(
    before: &ObjectSnapshotRecord,
    after: &ObjectSnapshotRecord,
    payloads: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<ChangedInterval>, String> {
    if before.point.thread_id != after.point.thread_id
        || before.point.sequence >= after.point.sequence
    {
        return Err("object snapshots do not establish one ordered event stream".to_string());
    }
    if before.object_offset != after.object_offset || before.byte_len != after.byte_len {
        return Err("object snapshots do not cover the same object interval".to_string());
    }
    let before_bytes = snapshot_bytes(before, payloads)?;
    let after_bytes = snapshot_bytes(after, payloads)?;
    let mut changed = Vec::new();
    let mut index = 0usize;
    while index < before_bytes.len() {
        if before_bytes[index] == after_bytes[index] {
            index += 1;
            continue;
        }
        let start = index;
        while index < before_bytes.len() && before_bytes[index] != after_bytes[index] {
            index += 1;
        }
        changed.push(ChangedInterval {
            object_offset_start: before.object_offset + start as u64,
            object_offset_end: before.object_offset + index as u64,
            before_hex: hex::encode(&before_bytes[start..index]),
            after_hex: hex::encode(&after_bytes[start..index]),
        });
    }
    Ok(changed)
}

fn snapshot_bytes<'a>(
    snapshot: &ObjectSnapshotRecord,
    payloads: &'a BTreeMap<String, Vec<u8>>,
) -> Result<&'a [u8], String> {
    let PageContent::Captured { payload } = &snapshot.content else {
        return Err(format!(
            "object snapshot {} bytes were omitted",
            snapshot.id
        ));
    };
    let bytes = payloads
        .get(&payload.id)
        .ok_or_else(|| format!("object snapshot {} payload is missing", snapshot.id))?;
    if bytes.len() as u64 != payload.byte_len
        || hex::encode(Sha256::digest(bytes)) != payload.sha256
    {
        return Err(format!(
            "object snapshot {} payload identity disagrees",
            snapshot.id
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::static_va_from_load_bias;

    #[test]
    fn observed_elf_load_bias_normalizes_exec_and_pie_addresses() {
        assert_eq!(static_va_from_load_bias(0x401234, 0), Some(0x401234));
        assert_eq!(
            static_va_from_load_bias(0x7f00_0000_1234, 0x7f00_0000_0000),
            Some(0x1234)
        );
        assert_eq!(static_va_from_load_bias(0x1000, 0x2000), None);
    }
}
