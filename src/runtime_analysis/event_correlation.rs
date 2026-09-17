//! Typed relations from observed OS events to immutable static semantics.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::behavior::{analyze_descriptor_behavior, analyze_file_behavior};
use super::capsule::ProcessCapsule;
use super::correlation::{
    resolve_static_code, resolve_static_function, FunctionResolution, OperationResolution,
    StaticCodeResolution, StaticOperation,
};
use super::crash::Evidence;
use super::input::{input_provenance, InputSourceIdentity};
use crate::core::binary::Arch;
use crate::program::image::ProgramImage;

pub const IOCTL_EVENT_RELATION_REPORT_SCHEMA: &str = "glaurung-runtime-ioctl-event-relation-v1";
pub const INPUT_EVENT_RELATION_REPORT_SCHEMA: &str = "glaurung-runtime-input-event-relation-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticEventCallsite {
    pub observed_return_module_offset: u64,
    pub static_return_va: u64,
    pub static_instruction_va: u64,
    pub function: FunctionResolution,
    pub code: StaticCodeResolution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoctlEventRelation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub resource_id: String,
    pub request: u64,
    pub static_callsite: Evidence<StaticEventCallsite>,
    pub operation_occurrence: Evidence<OperationOccurrence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationEffect {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_object_id: Option<String>,
    pub errno: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_len: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_source_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationOccurrence {
    pub id: String,
    pub capture_id: String,
    pub process_id: String,
    pub thread_id: Option<String>,
    pub event_sequence: u64,
    pub static_operation: StaticOperation,
    pub code_origin: String,
    pub inputs: BTreeMap<String, Evidence<String>>,
    pub introduced_input_sources: Vec<InputSourceIdentity>,
    pub output: Evidence<i64>,
    pub effects: Vec<OperationEffect>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn operation_occurrence(
    capsule: &ProcessCapsule,
    process_id: &str,
    thread_id: Option<&str>,
    sequence: u64,
    static_operation: &StaticOperation,
    inputs: BTreeMap<String, Evidence<String>>,
    introduced_input_sources: Vec<InputSourceIdentity>,
    output: Evidence<i64>,
    effects: Vec<OperationEffect>,
    source: &str,
) -> Evidence<OperationOccurrence> {
    let expected_static_id = crate::ir::function_ir::operation_id(
        &static_operation.image_sha256,
        static_operation.function_entry,
        &static_operation.lift_profile,
        static_operation.block_start,
        static_operation.operation_index,
        &static_operation.kind,
    );
    let expected_function_id = crate::ir::function_ir::function_id(
        &static_operation.image_sha256,
        &static_operation.lift_profile,
        static_operation.function_entry,
    );
    let expected_block_id =
        crate::ir::function_ir::block_id(&expected_function_id, static_operation.block_start);
    if static_operation.id != expected_static_id
        || static_operation.function_id != expected_function_id
        || static_operation.block_id != expected_block_id
    {
        return Evidence::Unknown {
            reason: "operation occurrence static operation identity is not canonical".to_string(),
        };
    }
    let expected_address_expression_id = static_operation.address_expression.as_ref().map(|_| {
        crate::ir::function_ir::expression_id(
            &static_operation.id,
            crate::ir::function_ir::OperationExpressionRole::MemoryAddress,
        )
    });
    let expected_stored_value_expression_id = static_operation.stored_value.as_ref().map(|_| {
        crate::ir::function_ir::expression_id(
            &static_operation.id,
            crate::ir::function_ir::OperationExpressionRole::StoredValue,
        )
    });
    let expected_condition_expression_id =
        static_operation.condition_expression.as_ref().map(|_| {
            crate::ir::function_ir::expression_id(
                &static_operation.id,
                crate::ir::function_ir::OperationExpressionRole::Condition,
            )
        });
    let expected_defined_value_expression_id = static_operation.defined_value.as_ref().map(|_| {
        crate::ir::function_ir::expression_id(
            &static_operation.id,
            crate::ir::function_ir::OperationExpressionRole::DefinedValue,
        )
    });
    let expected_call_target_expression_id = match &static_operation.call_target {
        Some(super::correlation::StaticCallTarget::Indirect {
            expression: Some(_),
        }) => Some(crate::ir::function_ir::expression_id(
            &static_operation.id,
            crate::ir::function_ir::OperationExpressionRole::CallTarget,
        )),
        _ => None,
    };
    let expected_call_target_value_id = static_operation.call_target.as_ref().map(|_| {
        crate::ir::function_ir::value_id(
            &static_operation.id,
            crate::ir::function_ir::OperationValueRole::CallTarget,
        )
    });
    if static_operation.address_expression_id != expected_address_expression_id
        || static_operation.stored_value_expression_id != expected_stored_value_expression_id
        || static_operation.condition_expression_id != expected_condition_expression_id
        || static_operation.defined_value_expression_id != expected_defined_value_expression_id
        || static_operation.call_target_expression_id != expected_call_target_expression_id
        || static_operation.call_register_inputs.iter().any(|input| {
            input.expression_id
                != crate::ir::function_ir::expression_id(
                    &static_operation.id,
                    crate::ir::function_ir::OperationExpressionRole::CallInput(input.position),
                )
        })
    {
        return Evidence::Unknown {
            reason: "operation occurrence static expression identity is not canonical".to_string(),
        };
    }
    if static_operation.call_target_value_id != expected_call_target_value_id
        || static_operation.call_register_inputs.iter().any(|input| {
            input.value_id
                != crate::ir::function_ir::value_id(
                    &static_operation.id,
                    crate::ir::function_ir::OperationValueRole::CallInput(input.position),
                )
        })
    {
        return Evidence::Unknown {
            reason: "operation occurrence static semantic value identity is not canonical"
                .to_string(),
        };
    }
    let mut expected_expression_nodes = Vec::new();
    for (id, expression) in [
        (
            &expected_address_expression_id,
            &static_operation.address_expression,
        ),
        (
            &expected_stored_value_expression_id,
            &static_operation.stored_value,
        ),
        (
            &expected_condition_expression_id,
            &static_operation.condition_expression,
        ),
        (
            &expected_defined_value_expression_id,
            &static_operation.defined_value,
        ),
    ] {
        if let Some((id, expression)) = id.as_ref().zip(expression.as_ref()) {
            expected_expression_nodes
                .extend(super::correlation::static_expression_nodes(id, expression));
        }
    }
    if let Some((id, expression)) = expected_call_target_expression_id.as_ref().zip(
        static_operation
            .call_target
            .as_ref()
            .and_then(|target| match target {
                super::correlation::StaticCallTarget::Indirect { expression } => {
                    expression.as_ref()
                }
                super::correlation::StaticCallTarget::Direct { .. } => None,
            }),
    ) {
        expected_expression_nodes
            .extend(super::correlation::static_expression_nodes(id, expression));
    }
    for input in &static_operation.call_register_inputs {
        expected_expression_nodes.extend(super::correlation::static_expression_nodes(
            &input.expression_id,
            &input.expression,
        ));
    }
    if static_operation.expression_nodes != expected_expression_nodes {
        return Evidence::Unknown {
            reason: "operation occurrence static expression graph is not canonical".to_string(),
        };
    }
    let expected_semantic_values = super::correlation::static_semantic_values(
        &static_operation.id,
        expected_address_expression_id.as_deref(),
        expected_stored_value_expression_id.as_deref(),
        expected_condition_expression_id.as_deref(),
        expected_defined_value_expression_id.as_deref(),
        static_operation.call_target.as_ref(),
        expected_call_target_expression_id.as_deref(),
        &static_operation.call_register_inputs,
    );
    if static_operation.semantic_values != expected_semantic_values {
        return Evidence::Unknown {
            reason: "operation occurrence static semantic values are not canonical".to_string(),
        };
    }
    if !capsule
        .processes
        .iter()
        .any(|process| process.id == process_id)
    {
        return Evidence::Unknown {
            reason: "operation occurrence process is absent from the capsule".to_string(),
        };
    }
    if thread_id.is_some_and(|thread_id| {
        !capsule
            .threads
            .iter()
            .any(|thread| thread.id == thread_id && thread.process_id == process_id)
    }) {
        return Evidence::Unknown {
            reason: "operation occurrence thread is absent or belongs to another process"
                .to_string(),
        };
    }
    if !capsule.events.iter().any(|event| {
        event.process_id == process_id
            && event.thread_id.as_deref() == thread_id
            && event.sequence == sequence
    }) {
        return Evidence::Unknown {
            reason: "operation occurrence has no matching capsule event identity".to_string(),
        };
    }
    if static_operation.image_sha256 != capsule.executable.sha256 {
        return Evidence::Unknown {
            reason: "operation occurrence static operation belongs to another image".to_string(),
        };
    }
    if effects
        .iter()
        .any(|effect| effect.resource_id.is_some() && effect.runtime_object_id.is_some())
    {
        return Evidence::Unknown {
            reason: "an operation effect cannot identify both an OS resource and a runtime object"
                .to_string(),
        };
    }
    if effects.iter().any(|effect| {
        effect.runtime_object_id.as_ref().is_some_and(|object_id| {
            !capsule
                .runtime_objects
                .iter()
                .any(|object| object.id == *object_id && object.process_id == process_id)
        })
    }) {
        return Evidence::Unknown {
            reason: "operation effect runtime object is absent or belongs to another process"
                .to_string(),
        };
    }
    let mut digest = Sha256::new();
    for component in [
        capsule.identity.capture_id.as_str(),
        process_id,
        thread_id.unwrap_or(""),
        &sequence.to_string(),
        &static_operation.id,
    ] {
        digest.update(component.as_bytes());
        digest.update([0]);
    }
    Evidence::Inferred {
        value: OperationOccurrence {
            id: format!("operation-occurrence-{}", hex::encode(digest.finalize())),
            capture_id: capsule.identity.capture_id.clone(),
            process_id: process_id.to_string(),
            thread_id: thread_id.map(str::to_string),
            event_sequence: sequence,
            static_operation: static_operation.clone(),
            code_origin: format!(
                "static_image:{}@0x{:x}",
                static_operation.image_sha256, static_operation.machine_va
            ),
            inputs,
            introduced_input_sources,
            output,
            effects,
        },
        source: source.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputEventRelation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub event_kind: String,
    pub resource_id: String,
    pub input_source: Evidence<InputSourceIdentity>,
    pub static_callsite: Evidence<StaticEventCallsite>,
    pub operation_occurrence: Evidence<OperationOccurrence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputEventRelationReport {
    pub schema: String,
    pub capture_id: String,
    pub image_sha256: String,
    pub relations: Vec<InputEventRelation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoctlEventRelationReport {
    pub schema: String,
    pub capture_id: String,
    pub image_sha256: String,
    pub relations: Vec<IoctlEventRelation>,
}

/// Correlate observed IOCTL events to exact static call instructions.
pub fn correlate_ioctl_events(
    capsule: &ProcessCapsule,
    image: &ProgramImage,
) -> IoctlEventRelationReport {
    let image_sha256 = hex::encode(Sha256::digest(image.bytes()));
    let behavior = analyze_file_behavior(capsule);
    let relations = behavior
        .ioctls
        .into_iter()
        .map(|ioctl| {
            let static_callsite = correlate_ioctl_callsite(
                capsule,
                image,
                &image_sha256,
                ioctl.user_return_module_offset,
                ioctl.user_frame_artifact_sha256.as_deref(),
            );
            let operation_occurrence = make_operation_occurrence(
                capsule,
                &ioctl.process_id,
                ioctl.thread_id.as_deref(),
                ioctl.sequence,
                &ioctl.resource_id,
                ioctl.descriptor,
                ioctl.request,
                &ioctl.scalar_argument,
                &ioctl.result,
                ioctl.errno.as_deref(),
                &static_callsite,
            );
            IoctlEventRelation {
                process_id: ioctl.process_id,
                thread_id: ioctl.thread_id,
                sequence: ioctl.sequence,
                resource_id: ioctl.resource_id,
                request: ioctl.request,
                static_callsite,
                operation_occurrence,
            }
        })
        .collect();
    IoctlEventRelationReport {
        schema: IOCTL_EVENT_RELATION_REPORT_SCHEMA.to_string(),
        capture_id: capsule.identity.capture_id.clone(),
        image_sha256,
        relations,
    }
}

#[allow(clippy::too_many_arguments)]
fn make_operation_occurrence(
    capsule: &ProcessCapsule,
    process_id: &str,
    thread_id: Option<&str>,
    sequence: u64,
    resource_id: &str,
    descriptor: u64,
    request: u64,
    scalar_argument: &str,
    output: &Evidence<i64>,
    errno: Option<&str>,
    callsite: &Evidence<StaticEventCallsite>,
) -> Evidence<OperationOccurrence> {
    let Evidence::Inferred {
        value: callsite, ..
    } = callsite
    else {
        return Evidence::Unknown {
            reason: "IOCTL operation occurrence requires an exact static callsite".to_string(),
        };
    };
    let StaticCodeResolution::Resolved {
        operations: OperationResolution::Resolved { operations },
        ..
    } = &callsite.code
    else {
        return Evidence::Unknown {
            reason: "IOCTL callsite has no resolved LLIR operation".to_string(),
        };
    };
    let call_operations: Vec<_> = operations
        .iter()
        .filter(|operation| operation.kind == "call")
        .collect();
    let [static_operation] = call_operations.as_slice() else {
        return Evidence::Unknown {
            reason: "IOCTL machine instruction does not identify exactly one LLIR call operation"
                .to_string(),
        };
    };
    let observed = |value: String| Evidence::Observed {
        value,
        source: "normalized file_ioctl event".to_string(),
    };
    operation_occurrence(
        capsule,
        process_id,
        thread_id,
        sequence,
        static_operation,
        BTreeMap::from([
            ("descriptor".to_string(), observed(descriptor.to_string())),
            ("request".to_string(), observed(format!("0x{request:08x}"))),
            (
                "scalar_argument".to_string(),
                observed(scalar_argument.to_string()),
            ),
        ]),
        Vec::new(),
        output.clone(),
        vec![OperationEffect {
            kind: "file_ioctl".to_string(),
            resource_id: Some(resource_id.to_string()),
            runtime_object_id: None,
            errno: errno.map(str::to_string),
            address: None,
            byte_len: None,
            input_source_id: None,
        }],
        "observed IOCTL values and effect joined to one exact static LLIR call operation",
    )
}

/// Correlate selected bytes entering the process to the exact LLIR call
/// occurrence that returned them. This does not claim downstream propagation.
pub fn correlate_input_events(
    capsule: &ProcessCapsule,
    image: &ProgramImage,
) -> InputEventRelationReport {
    let image_sha256 = hex::encode(Sha256::digest(image.bytes()));
    let sources = input_provenance(capsule)
        .sources
        .into_iter()
        .map(|source| (source.name.clone(), source))
        .collect::<BTreeMap<_, _>>();
    let file_reads = analyze_file_behavior(capsule)
        .reads
        .into_iter()
        .map(|read| {
            (
                read.process_id,
                read.thread_id,
                read.sequence,
                "file_read".to_string(),
                read.resource_id,
                read.descriptor,
                read.requested_byte_len,
                read.outcome,
                read.input_source_name,
                read.destination_address,
                read.user_return_module_offset,
                read.user_frame_artifact_sha256,
            )
        });
    let descriptor_reads = analyze_descriptor_behavior(capsule)
        .transfers
        .into_iter()
        .filter(|transfer| {
            matches!(transfer.operation.as_str(), "read" | "recv") && transfer.endpoint != "stdin"
        })
        .map(|transfer| {
            (
                transfer.process_id,
                transfer.thread_id,
                transfer.sequence,
                format!("descriptor_{}", transfer.operation),
                transfer.resource_id,
                transfer.descriptor,
                transfer.requested_byte_len,
                transfer.outcome,
                transfer.input_source_name,
                transfer.destination_address,
                transfer.user_return_module_offset,
                transfer.user_frame_artifact_sha256,
            )
        });
    let stdin_reads = capsule
        .events
        .iter()
        .filter(|event| event.kind == "descriptor_stdin_read")
        .filter_map(|event| {
            let descriptor = event.fields.get("descriptor")?.parse().ok()?;
            let requested_byte_len = event.fields.get("requested_byte_len")?.parse().ok()?;
            let output = match event.fields.get("result").map(String::as_str) {
                Some("success") => Evidence::Observed {
                    value: event.fields.get("read_byte_len")?.parse().ok()?,
                    source: "normalized successful stdin read result".to_string(),
                },
                Some("failure") => Evidence::Unknown {
                    reason: format!(
                        "stdin read failed: {}",
                        event
                            .fields
                            .get("errno")
                            .map_or("unknown errno", String::as_str)
                    ),
                },
                _ => return None,
            };
            Some((
                event.process_id.clone(),
                event.thread_id.clone(),
                event.sequence,
                event.kind.clone(),
                event.fields.get("resource_id")?.clone(),
                descriptor,
                requested_byte_len,
                output,
                event.fields.get("input_source_name").cloned(),
                event
                    .fields
                    .get("destination_address")
                    .and_then(|value| value.parse().ok()),
                event
                    .fields
                    .get("user_return_module_offset")
                    .and_then(|value| value.parse().ok()),
                event.fields.get("user_frame_artifact_sha256").cloned(),
            ))
        });
    let relations = file_reads
        .chain(descriptor_reads)
        .chain(stdin_reads)
        .map(
            |(
                process_id,
                thread_id,
                sequence,
                event_kind,
                resource_id,
                descriptor,
                requested_byte_len,
                output,
                source_name,
                destination_address,
                return_offset,
                frame_sha256,
            )| {
                let input_source = source_name
                    .as_ref()
                    .and_then(|name| sources.get(name))
                    .cloned()
                    .map_or_else(
                        || Evidence::Unknown {
                            reason: "input event has no matching capsule input source".to_string(),
                        },
                        |value| Evidence::Observed {
                            value,
                            source:
                                "capsule input provenance linked by normalized event source name"
                                    .to_string(),
                        },
                    );
                let static_callsite = correlate_event_callsite(
                    capsule,
                    image,
                    &image_sha256,
                    return_offset,
                    frame_sha256.as_deref(),
                    "input event",
                );
                let operation_occurrence = make_input_operation_occurrence(
                    capsule,
                    &process_id,
                    thread_id.as_deref(),
                    sequence,
                    &event_kind,
                    &resource_id,
                    descriptor,
                    requested_byte_len,
                    destination_address,
                    &output,
                    &input_source,
                    &static_callsite,
                );
                InputEventRelation {
                    process_id,
                    thread_id,
                    sequence,
                    event_kind,
                    resource_id,
                    input_source,
                    static_callsite,
                    operation_occurrence,
                }
            },
        )
        .collect();
    InputEventRelationReport {
        schema: INPUT_EVENT_RELATION_REPORT_SCHEMA.to_string(),
        capture_id: capsule.identity.capture_id.clone(),
        image_sha256,
        relations,
    }
}

#[allow(clippy::too_many_arguments)]
fn make_input_operation_occurrence(
    capsule: &ProcessCapsule,
    process_id: &str,
    thread_id: Option<&str>,
    sequence: u64,
    event_kind: &str,
    resource_id: &str,
    descriptor: u64,
    requested_byte_len: u64,
    destination_address: Option<u64>,
    output: &Evidence<u64>,
    input_source: &Evidence<InputSourceIdentity>,
    callsite: &Evidence<StaticEventCallsite>,
) -> Evidence<OperationOccurrence> {
    let Evidence::Inferred {
        value: callsite, ..
    } = callsite
    else {
        return Evidence::Unknown {
            reason: "input operation occurrence requires an exact static callsite".to_string(),
        };
    };
    let Some(static_operation) = exact_call_operation(&callsite.code) else {
        return Evidence::Unknown {
            reason:
                "input event machine instruction does not identify exactly one LLIR call operation"
                    .to_string(),
        };
    };
    let Evidence::Observed { value: source, .. } = input_source else {
        return Evidence::Unknown {
            reason: "input operation occurrence requires an exact input source".to_string(),
        };
    };
    let output = match output {
        Evidence::Observed { value, source } => i64::try_from(*value).map_or_else(
            |_| Evidence::Unknown {
                reason: "input event result exceeds signed occurrence range".to_string(),
            },
            |value| Evidence::Observed {
                value,
                source: source.clone(),
            },
        ),
        Evidence::Inferred { value, source } => i64::try_from(*value).map_or_else(
            |_| Evidence::Unknown {
                reason: "input event result exceeds signed occurrence range".to_string(),
            },
            |value| Evidence::Inferred {
                value,
                source: source.clone(),
            },
        ),
        Evidence::Unknown { reason } => Evidence::Unknown {
            reason: reason.clone(),
        },
    };
    let observed = |value: String| Evidence::Observed {
        value,
        source: format!("normalized {event_kind} event"),
    };
    operation_occurrence(
        capsule,
        process_id,
        thread_id,
        sequence,
        static_operation,
        BTreeMap::from([
            ("descriptor".to_string(), observed(descriptor.to_string())),
            (
                "requested_byte_len".to_string(),
                observed(requested_byte_len.to_string()),
            ),
        ]),
        vec![source.clone()],
        output,
        vec![OperationEffect {
            kind: event_kind.to_string(),
            resource_id: Some(resource_id.to_string()),
            runtime_object_id: None,
            errno: None,
            address: destination_address,
            byte_len: destination_address.map(|_| source.byte_len),
            input_source_id: destination_address.map(|_| source.id.clone()),
        }],
        "observed input source and result joined to one exact static LLIR call operation",
    )
}

fn exact_call_operation(code: &StaticCodeResolution) -> Option<&StaticOperation> {
    let StaticCodeResolution::Resolved {
        operations: OperationResolution::Resolved { operations },
        ..
    } = code
    else {
        return None;
    };
    let calls = operations
        .iter()
        .filter(|operation| operation.kind == "call")
        .collect::<Vec<_>>();
    let [operation] = calls.as_slice() else {
        return None;
    };
    Some(*operation)
}

fn correlate_ioctl_callsite(
    capsule: &ProcessCapsule,
    image: &ProgramImage,
    image_sha256: &str,
    return_offset: Option<u64>,
    frame_artifact_sha256: Option<&str>,
) -> Evidence<StaticEventCallsite> {
    correlate_event_callsite(
        capsule,
        image,
        image_sha256,
        return_offset,
        frame_artifact_sha256,
        "IOCTL",
    )
}

fn correlate_event_callsite(
    capsule: &ProcessCapsule,
    image: &ProgramImage,
    image_sha256: &str,
    return_offset: Option<u64>,
    frame_artifact_sha256: Option<&str>,
    label: &str,
) -> Evidence<StaticEventCallsite> {
    if image_sha256 != capsule.executable.sha256 {
        return Evidence::Unknown {
            reason: "capsule executable identity disagrees with static image".to_string(),
        };
    }
    if frame_artifact_sha256 != Some(image_sha256) {
        return Evidence::Unknown {
            reason: format!("{label} user frame is not bound to the exact static image"),
        };
    }
    if image.arch() != Arch::X86_64 || capsule.target.os_abi != "linux" {
        return Evidence::Unknown {
            reason: format!("{label} callsite correlation currently requires Linux x86-64"),
        };
    }
    let Some(return_offset) = return_offset else {
        return Evidence::Unknown {
            reason: format!("{label} event has no main-module return offset"),
        };
    };
    let Some(static_return_va) = image
        .image_base()
        .and_then(|image_base| image_base.checked_add(return_offset))
    else {
        return Evidence::Unknown {
            reason: format!(
                "{label} module-relative return offset did not map into the static image"
            ),
        };
    };
    let Some(call_va) = static_return_va.checked_sub(5) else {
        return Evidence::Unknown {
            reason: format!("{label} return offset cannot contain an x86-64 direct call"),
        };
    };
    let function = resolve_static_function(image, call_va);
    let code = resolve_static_code(image, call_va, &function);
    let StaticCodeResolution::Resolved {
        instruction_va,
        instruction_end,
        mnemonic,
        operations,
        ..
    } = &code
    else {
        return Evidence::Unknown {
            reason: format!("{label} return offset did not resolve to static code"),
        };
    };
    let has_call_operation = matches!(
        operations,
        super::correlation::OperationResolution::Resolved { operations }
            if operations.iter().any(|operation| operation.kind == "call")
    );
    if *instruction_va != call_va
        || *instruction_end != static_return_va
        || !mnemonic.starts_with("call")
        || !has_call_operation
    {
        return Evidence::Unknown {
            reason: format!(
                "{label} return offset is not immediately after an exact LLIR call operation"
            ),
        };
    }
    Evidence::Inferred {
        value: StaticEventCallsite {
            observed_return_module_offset: return_offset,
            static_return_va,
            static_instruction_va: call_va,
            function,
            code,
        },
        source: "observed exact-image user frame joined to immutable ProgramImage and LLIR"
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_analysis::capsule::{
        EventPosition, EventRecord, RuntimeObjectKind, RuntimeObjectRecord,
    };
    use crate::runtime_analysis::correlation::{
        tests::{capsule, hello_image},
        StaticCallTarget, StaticValueExpression,
    };

    fn static_operation(image_sha256: String, kind: &str) -> StaticOperation {
        let id =
            crate::ir::function_ir::operation_id(&image_sha256, 0x1000, "test", 0x1000, 3, kind);
        let function_id = crate::ir::function_ir::function_id(&image_sha256, "test", 0x1000);
        let block_id = crate::ir::function_ir::block_id(&function_id, 0x1000);
        StaticOperation {
            id,
            function_id,
            block_id,
            image_sha256,
            function_entry: 0x1000,
            machine_va: 0x1010,
            machine_operation_ordinal: 0,
            lift_profile: "test".to_string(),
            block_start: 0x1000,
            operation_index: 3,
            kind: kind.to_string(),
            memory_access: None,
            address_expression: None,
            address_expression_id: None,
            stored_value: None,
            stored_value_expression_id: None,
            expression_nodes: Vec::new(),
            semantic_values: Vec::new(),
            stored_value_register: None,
            call_target: None,
            call_target_expression_id: None,
            call_target_value_id: None,
            call_register_inputs: Vec::new(),
            control_target: None,
            condition_expression: None,
            condition_expression_id: None,
            condition_call_results: Vec::new(),
            defined_register: None,
            defined_value: None,
            defined_value_expression_id: None,
            used_registers: Vec::new(),
            value_selection: None,
        }
    }

    #[test]
    fn occurrence_identity_includes_operation_kind_and_rejects_cross_domain_targets() {
        let image = hello_image();
        let mut capsule = capsule(&image);
        capsule.events.push(EventRecord {
            process_id: "process-main".to_string(),
            thread_id: None,
            sequence: 1,
            kind: "memory_write".to_string(),
            address: Some(0x8000),
            fields: BTreeMap::new(),
        });
        capsule.events.push(EventRecord {
            process_id: "process-main".to_string(),
            thread_id: None,
            sequence: 2,
            kind: "memory_write".to_string(),
            address: Some(0x8000),
            fields: BTreeMap::new(),
        });
        capsule.runtime_objects.push(RuntimeObjectRecord {
            id: "object-1".to_string(),
            process_id: "process-main".to_string(),
            mapping_id: None,
            kind: RuntimeObjectKind::Heap,
            start: 0x8000,
            byte_len: 8,
            created_at: EventPosition {
                thread_id: None,
                sequence: 1,
            },
            ended_at: None,
        });
        let effect = OperationEffect {
            kind: "memory_write".to_string(),
            resource_id: None,
            runtime_object_id: Some("object-1".to_string()),
            errno: None,
            address: Some(0x8000),
            byte_len: Some(1),
            input_source_id: None,
        };
        let make = |sequence: u64, kind: &str, effect: OperationEffect| {
            operation_occurrence(
                &capsule,
                "process-main",
                None,
                sequence,
                &static_operation(capsule.executable.sha256.clone(), kind),
                BTreeMap::new(),
                Vec::new(),
                Evidence::Unknown {
                    reason: "not captured".to_string(),
                },
                vec![effect.clone()],
                "test",
            )
        };
        let Evidence::Inferred { value: call, .. } = make(1, "call", effect.clone()) else {
            panic!("valid occurrence must resolve");
        };
        let Evidence::Inferred {
            value: repeated_call,
            ..
        } = make(2, "call", effect.clone())
        else {
            panic!("repeated valid occurrence must resolve");
        };
        assert_eq!(call.static_operation.id, repeated_call.static_operation.id);
        assert_ne!(call.id, repeated_call.id);

        let Evidence::Inferred { value: store, .. } = make(1, "store", effect.clone()) else {
            panic!("valid occurrence must resolve");
        };
        assert_ne!(call.id, store.id);
        assert_ne!(call.static_operation.id, store.static_operation.id);

        let mut forged = static_operation(capsule.executable.sha256.clone(), "call");
        forged.id = "static-operation-forged".to_string();
        assert_eq!(
            operation_occurrence(
                &capsule,
                "process-main",
                None,
                1,
                &forged,
                BTreeMap::new(),
                Vec::new(),
                Evidence::Unknown {
                    reason: "not captured".to_string(),
                },
                vec![effect.clone()],
                "test",
            ),
            Evidence::Unknown {
                reason: "operation occurrence static operation identity is not canonical"
                    .to_string(),
            }
        );

        let mut expression_operation = static_operation(capsule.executable.sha256.clone(), "store");
        expression_operation.address_expression = Some(StaticValueExpression::Register {
            name: "rax".to_string(),
        });
        expression_operation.address_expression_id = Some(crate::ir::function_ir::expression_id(
            &expression_operation.id,
            crate::ir::function_ir::OperationExpressionRole::MemoryAddress,
        ));
        expression_operation.expression_nodes = super::super::correlation::static_expression_nodes(
            expression_operation
                .address_expression_id
                .as_deref()
                .unwrap(),
            expression_operation.address_expression.as_ref().unwrap(),
        );
        expression_operation.semantic_values = super::super::correlation::static_semantic_values(
            &expression_operation.id,
            expression_operation.address_expression_id.as_deref(),
            None,
            None,
            None,
            None,
            None,
            &[],
        );
        assert!(matches!(
            operation_occurrence(
                &capsule,
                "process-main",
                None,
                1,
                &expression_operation,
                BTreeMap::new(),
                Vec::new(),
                Evidence::Unknown {
                    reason: "not captured".to_string(),
                },
                vec![effect.clone()],
                "test",
            ),
            Evidence::Inferred { .. }
        ));
        let mut forged_graph = expression_operation.clone();
        forged_graph.expression_nodes[0].kind = "constant".to_string();
        assert_eq!(
            operation_occurrence(
                &capsule,
                "process-main",
                None,
                1,
                &forged_graph,
                BTreeMap::new(),
                Vec::new(),
                Evidence::Unknown {
                    reason: "not captured".to_string(),
                },
                vec![effect.clone()],
                "test",
            ),
            Evidence::Unknown {
                reason: "operation occurrence static expression graph is not canonical".to_string(),
            }
        );
        let mut forged_value = expression_operation.clone();
        forged_value.semantic_values[0].role = "runtime_value".to_string();
        assert_eq!(
            operation_occurrence(
                &capsule,
                "process-main",
                None,
                1,
                &forged_value,
                BTreeMap::new(),
                Vec::new(),
                Evidence::Unknown {
                    reason: "not captured".to_string(),
                },
                vec![effect.clone()],
                "test",
            ),
            Evidence::Unknown {
                reason: "operation occurrence static semantic values are not canonical".to_string(),
            }
        );
        expression_operation.address_expression_id = Some("static-expression-forged".to_string());
        assert_eq!(
            operation_occurrence(
                &capsule,
                "process-main",
                None,
                1,
                &expression_operation,
                BTreeMap::new(),
                Vec::new(),
                Evidence::Unknown {
                    reason: "not captured".to_string(),
                },
                vec![effect.clone()],
                "test",
            ),
            Evidence::Unknown {
                reason: "operation occurrence static expression identity is not canonical"
                    .to_string(),
            }
        );

        let mut call_operation = static_operation(capsule.executable.sha256.clone(), "call");
        call_operation.call_target = Some(StaticCallTarget::Direct {
            address: 0x2000,
            symbol: Some("sink".to_string()),
        });
        call_operation.call_target_value_id = Some(crate::ir::function_ir::value_id(
            &call_operation.id,
            crate::ir::function_ir::OperationValueRole::CallTarget,
        ));
        call_operation.semantic_values = super::super::correlation::static_semantic_values(
            &call_operation.id,
            None,
            None,
            None,
            None,
            call_operation.call_target.as_ref(),
            None,
            &[],
        );
        assert!(matches!(
            operation_occurrence(
                &capsule,
                "process-main",
                None,
                1,
                &call_operation,
                BTreeMap::new(),
                Vec::new(),
                Evidence::Unknown {
                    reason: "not captured".to_string(),
                },
                vec![effect.clone()],
                "test",
            ),
            Evidence::Inferred { .. }
        ));
        call_operation.call_target_value_id = Some("static-value-forged".to_string());
        assert!(matches!(
            operation_occurrence(
                &capsule,
                "process-main",
                None,
                1,
                &call_operation,
                BTreeMap::new(),
                Vec::new(),
                Evidence::Unknown {
                    reason: "not captured".to_string(),
                },
                vec![effect.clone()],
                "test",
            ),
            Evidence::Unknown { reason }
                if reason
                    == "operation occurrence static semantic value identity is not canonical"
        ));

        let mut invalid = effect;
        invalid.resource_id = Some("resource-1".to_string());
        assert_eq!(
            make(1, "call", invalid),
            Evidence::Unknown {
                reason:
                    "an operation effect cannot identify both an OS resource and a runtime object"
                        .to_string(),
            }
        );
    }
}
