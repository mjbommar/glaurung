//! Evidence-bearing runtime-address correlation into one immutable static image.

use std::collections::{BTreeMap, BTreeSet};

use object::{Object, ObjectKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::capsule::{
    ArtifactIdentity, CapsuleLimits, MappingBacking, OmissionReason, PageContent, Permissions,
    ProcessCapsule,
};
use crate::analysis::cfg::{discover_function_image_at, Budgets};
use crate::core::address::{Address, AddressKind};
use crate::core::disassembler::{Architecture, Disassembler};
use crate::disasm::registry;
use crate::ir::lift_function::lift_function_from_image;
use crate::ir::types::{BinOp, CallTarget, LlirInstr, MemOp, Op, VReg, Value};
use crate::program::image::ProgramImage;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeAddress {
    pub capture_id: String,
    pub process_id: String,
    pub mapping_id: String,
    pub module_id: Option<String>,
    pub raw_va: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeModule {
    pub capture_id: String,
    pub process_id: String,
    pub module_id: String,
    pub artifact: ArtifactIdentity,
    pub mapping_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeMapping {
    pub capture_id: String,
    pub process_id: String,
    pub mapping_id: String,
    pub start: u64,
    pub end: u64,
    pub permissions: Permissions,
    pub backing: MappingBacking,
    pub module_id: Option<String>,
    pub file_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeIdentityGraph {
    pub capture_id: String,
    pub process_id: String,
    pub modules: Vec<RuntimeModule>,
    pub mappings: Vec<RuntimeMapping>,
}

/// Project one capsule process into explicit runtime identities.
///
/// These records are correlation endpoints. They neither own process state nor
/// mutate the static [`ProgramImage`].
pub fn runtime_identity_graph(
    capsule: &ProcessCapsule,
    process_id: &str,
) -> Result<RuntimeIdentityGraph, String> {
    capsule.validate(CapsuleLimits::default())?;
    if !capsule
        .processes
        .iter()
        .any(|process| process.id == process_id)
    {
        return Err(format!("capsule has no process {process_id}"));
    }
    let capture_id = capsule.identity.capture_id.clone();
    let mut modules: Vec<_> = capsule
        .modules
        .iter()
        .filter(|module| module.process_id == process_id)
        .map(|module| RuntimeModule {
            capture_id: capture_id.clone(),
            process_id: process_id.to_string(),
            module_id: module.id.clone(),
            artifact: module.artifact.clone(),
            mapping_ids: module.mapping_ids.clone(),
        })
        .collect();
    modules.sort_by(|left, right| left.module_id.cmp(&right.module_id));
    let mut mappings: Vec<_> = capsule
        .mappings
        .iter()
        .filter(|mapping| mapping.process_id == process_id)
        .map(|mapping| RuntimeMapping {
            capture_id: capture_id.clone(),
            process_id: process_id.to_string(),
            mapping_id: mapping.id.clone(),
            start: mapping.start,
            end: mapping.end,
            permissions: mapping.permissions,
            backing: mapping.backing.clone(),
            module_id: mapping.module_id.clone(),
            file_offset: mapping.file_offset,
        })
        .collect();
    mappings.sort_by(|left, right| left.mapping_id.cmp(&right.mapping_id));
    Ok(RuntimeIdentityGraph {
        capture_id,
        process_id: process_id.to_string(),
        modules,
        mappings,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedRuntimeAddress {
    pub runtime: RuntimeAddress,
    pub image_sha256: String,
    pub runtime_file_offset: u64,
    pub static_va: u64,
    pub module_relative: u64,
    pub byte_status: RuntimeByteStatus,
    pub function: FunctionResolution,
    pub code: StaticCodeResolution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum FunctionResolution {
    Exact {
        entry_va: u64,
        end_va: u64,
        name: Option<String>,
    },
    Interior {
        entry_va: u64,
        end_va: u64,
        name: Option<String>,
    },
    Ambiguous {
        entries: Vec<u64>,
    },
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum StaticCodeResolution {
    Resolved {
        block_start: u64,
        block_end: u64,
        instruction_va: u64,
        instruction_end: u64,
        instruction_relation: InstructionRelation,
        mnemonic: String,
        operations: OperationResolution,
    },
    Ambiguous {
        block_starts: Vec<u64>,
    },
    Incomplete {
        reason: String,
        budgets: Vec<String>,
    },
    Missing {
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionRelation {
    Exact,
    Interior,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum OperationResolution {
    Resolved { operations: Vec<StaticOperation> },
    NoOperations { reason: String },
    Unavailable { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticOperation {
    /// Stable identity of this operation in one immutable lifted-function
    /// generation. Runtime occurrence identity is deliberately separate.
    pub id: String,
    pub function_id: String,
    pub block_id: String,
    pub image_sha256: String,
    pub function_entry: u64,
    pub machine_va: u64,
    pub machine_operation_ordinal: usize,
    pub lift_profile: String,
    pub block_start: u64,
    pub operation_index: usize,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_access: Option<StaticMemoryAccess>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_expression: Option<StaticValueExpression>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_expression_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_value: Option<StaticValueExpression>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_value_expression_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expression_nodes: Vec<StaticExpressionNode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub semantic_values: Vec<StaticSemanticValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_value_register: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_target: Option<StaticCallTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_target_expression_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_target_value_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_register_inputs: Vec<StaticCallRegisterInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_target: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition_expression: Option<StaticValueExpression>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition_expression_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub condition_call_results: Vec<StaticCallResultOrigin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defined_register: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defined_value: Option<StaticValueExpression>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defined_value_expression_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub used_registers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_selection: Option<StaticValueSelection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticCallResultOrigin {
    pub machine_va: u64,
    pub register: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticValueSelection {
    pub output_register: String,
    pub when_true: StaticValueExpression,
    pub when_false: StaticValueExpression,
}

/// One statically sliced candidate ABI register input at an LLIR call.
///
/// Presence does not claim that the callee consumes this position. A resolved
/// prototype or semantic call contract must establish arity and meaning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticCallRegisterInput {
    pub position: usize,
    pub abi_register: String,
    pub expression: StaticValueExpression,
    pub expression_id: String,
    pub value_id: String,
}

/// Static LLIR call-target semantics, without any occurrence values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StaticCallTarget {
    Direct {
        address: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        symbol: Option<String>,
    },
    Indirect {
        expression: Option<StaticValueExpression>,
    },
}

/// Static LLIR effective-address semantics, without any runtime values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticMemoryAccess {
    pub base_register: Option<String>,
    pub index_register: Option<String>,
    pub scale: u8,
    pub displacement: i64,
    pub byte_len: u8,
    pub segment: Option<String>,
}

/// A bounded static backward slice for a memory address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StaticValueExpression {
    Register {
        name: String,
    },
    Constant {
        value: i64,
    },
    Address {
        value: u64,
    },
    Add {
        left: Box<StaticValueExpression>,
        right: Box<StaticValueExpression>,
    },
    Subtract {
        left: Box<StaticValueExpression>,
        right: Box<StaticValueExpression>,
    },
    Multiply {
        left: Box<StaticValueExpression>,
        right: Box<StaticValueExpression>,
    },
    BitwiseAnd {
        left: Box<StaticValueExpression>,
        right: Box<StaticValueExpression>,
    },
    BitwiseOr {
        left: Box<StaticValueExpression>,
        right: Box<StaticValueExpression>,
    },
    BitwiseXor {
        left: Box<StaticValueExpression>,
        right: Box<StaticValueExpression>,
    },
    Truncate {
        value: Box<StaticValueExpression>,
        from_bits: u16,
        to_bits: u16,
    },
    ZeroExtend {
        value: Box<StaticValueExpression>,
        from_bits: u16,
        to_bits: u16,
    },
    SignExtend {
        value: Box<StaticValueExpression>,
        from_bits: u16,
        to_bits: u16,
    },
    Extract {
        value: Box<StaticValueExpression>,
        high_bit: u16,
        low_bit: u16,
    },
    Compare {
        comparison: String,
        left: Box<StaticValueExpression>,
        right: Box<StaticValueExpression>,
    },
    CallResult {
        machine_va: u64,
        register: String,
    },
    Load {
        address: Box<StaticValueExpression>,
        byte_len: u8,
    },
}

/// One stable node in a recovered static expression tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticExpressionNode {
    pub id: String,
    pub root_id: String,
    pub parent_id: Option<String>,
    /// Typed child path from the root. Empty means the root itself.
    pub path: String,
    pub kind: String,
}

/// One immutable semantic operand in the static operation graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticSemanticValue {
    pub id: String,
    pub operation_id: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression_root_id: Option<String>,
}

pub(super) fn static_semantic_values(
    operation_id: &str,
    address_expression_id: Option<&str>,
    stored_value_expression_id: Option<&str>,
    condition_expression_id: Option<&str>,
    defined_value_expression_id: Option<&str>,
    call_target: Option<&StaticCallTarget>,
    call_target_expression_id: Option<&str>,
    call_register_inputs: &[StaticCallRegisterInput],
) -> Vec<StaticSemanticValue> {
    use crate::ir::function_ir::OperationValueRole;

    [
        (OperationValueRole::MemoryAddress, address_expression_id),
        (OperationValueRole::StoredValue, stored_value_expression_id),
        (OperationValueRole::Condition, condition_expression_id),
        (
            OperationValueRole::DefinedValue,
            defined_value_expression_id,
        ),
    ]
    .into_iter()
    .filter_map(|(role, expression_root_id)| {
        expression_root_id.map(|expression_root_id| StaticSemanticValue {
            id: crate::ir::function_ir::value_id(operation_id, role),
            operation_id: operation_id.to_string(),
            role: role.name(),
            expression_root_id: Some(expression_root_id.to_string()),
        })
    })
    .chain(call_target.map(|_| StaticSemanticValue {
        id: crate::ir::function_ir::value_id(operation_id, OperationValueRole::CallTarget),
        operation_id: operation_id.to_string(),
        role: OperationValueRole::CallTarget.name(),
        expression_root_id: call_target_expression_id.map(str::to_string),
    }))
    .chain(
        call_register_inputs
            .iter()
            .map(|input| StaticSemanticValue {
                id: input.value_id.clone(),
                operation_id: operation_id.to_string(),
                role: OperationValueRole::CallInput(input.position).name(),
                expression_root_id: Some(input.expression_id.clone()),
            }),
    )
    .collect()
}

pub(super) fn static_expression_nodes(
    root_id: &str,
    expression: &StaticValueExpression,
) -> Vec<StaticExpressionNode> {
    fn visit(
        root_id: &str,
        path: &str,
        parent_id: Option<String>,
        expression: &StaticValueExpression,
        nodes: &mut Vec<StaticExpressionNode>,
    ) {
        let id = crate::ir::function_ir::expression_node_id(root_id, path);
        let kind = match expression {
            StaticValueExpression::Register { .. } => "register",
            StaticValueExpression::Constant { .. } => "constant",
            StaticValueExpression::Address { .. } => "address",
            StaticValueExpression::Add { .. } => "add",
            StaticValueExpression::Subtract { .. } => "subtract",
            StaticValueExpression::Multiply { .. } => "multiply",
            StaticValueExpression::BitwiseAnd { .. } => "bitwise_and",
            StaticValueExpression::BitwiseOr { .. } => "bitwise_or",
            StaticValueExpression::BitwiseXor { .. } => "bitwise_xor",
            StaticValueExpression::Truncate { .. } => "truncate",
            StaticValueExpression::ZeroExtend { .. } => "zero_extend",
            StaticValueExpression::SignExtend { .. } => "sign_extend",
            StaticValueExpression::Extract { .. } => "extract",
            StaticValueExpression::Compare { .. } => "compare",
            StaticValueExpression::CallResult { .. } => "call_result",
            StaticValueExpression::Load { .. } => "load",
        };
        nodes.push(StaticExpressionNode {
            id: id.clone(),
            root_id: root_id.to_string(),
            parent_id,
            path: path.to_string(),
            kind: kind.to_string(),
        });
        let child_path = |name: &str| {
            if path.is_empty() {
                name.to_string()
            } else {
                format!("{path}/{name}")
            }
        };
        match expression {
            StaticValueExpression::Add { left, right }
            | StaticValueExpression::Subtract { left, right }
            | StaticValueExpression::Multiply { left, right }
            | StaticValueExpression::BitwiseAnd { left, right }
            | StaticValueExpression::BitwiseOr { left, right }
            | StaticValueExpression::BitwiseXor { left, right }
            | StaticValueExpression::Compare { left, right, .. } => {
                visit(root_id, &child_path("left"), Some(id.clone()), left, nodes);
                visit(root_id, &child_path("right"), Some(id), right, nodes);
            }
            StaticValueExpression::Truncate { value, .. }
            | StaticValueExpression::ZeroExtend { value, .. }
            | StaticValueExpression::SignExtend { value, .. }
            | StaticValueExpression::Extract { value, .. } => {
                visit(root_id, &child_path("value"), Some(id), value, nodes);
            }
            StaticValueExpression::Load { address, .. } => {
                visit(root_id, &child_path("address"), Some(id), address, nodes);
            }
            StaticValueExpression::Register { .. }
            | StaticValueExpression::Constant { .. }
            | StaticValueExpression::Address { .. }
            | StaticValueExpression::CallResult { .. } => {}
        }
    }

    let mut nodes = Vec::new();
    visit(root_id, "", None, expression, &mut nodes);
    nodes
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RuntimeByteStatus {
    CapturedMatchesStatic {
        payload_id: String,
    },
    CapturedDiffersFromStatic {
        payload_id: String,
        runtime_byte: u8,
        static_byte: u8,
    },
    CapturedPayloadUnavailable {
        payload_id: String,
    },
    CapturedPayloadInvalid {
        payload_id: String,
        reason: String,
    },
    Omitted {
        reason: OmissionReason,
        detail: String,
    },
    FileBackedNotCaptured,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePageClassification {
    pub capture_id: String,
    pub process_id: String,
    pub mapping_id: String,
    pub start: u64,
    pub byte_len: u64,
    pub availability: RuntimePageAvailability,
    pub kind: RuntimePageKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RuntimePageAvailability {
    Captured {
        payload_id: String,
    },
    Omitted {
        reason: OmissionReason,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuntimePageKind {
    FileBackedUnchanged {
        image_sha256: String,
        file_offset: u64,
    },
    FileBackedModified {
        image_sha256: String,
        file_offset: u64,
        changed_byte_count: u64,
        first_changed_offset: u64,
    },
    Anonymous,
    Unknown {
        reason: String,
    },
}

/// Classify captured runtime ranges without using paths or mutating static bytes.
pub fn classify_runtime_pages(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    process_id: &str,
) -> Result<Vec<RuntimePageClassification>, String> {
    capsule.validate(CapsuleLimits::default())?;
    if !capsule
        .processes
        .iter()
        .any(|process| process.id == process_id)
    {
        return Err(format!("capsule has no process {process_id}"));
    }
    let image_sha256 = hex::encode(Sha256::digest(image.bytes()));
    let mut classifications = Vec::new();
    for page in capsule
        .pages
        .iter()
        .filter(|page| page.process_id == process_id)
    {
        let mapping = capsule
            .mappings
            .iter()
            .find(|mapping| mapping.id == page.mapping_id)
            .expect("validated capsule page mapping exists");
        let availability = match &page.content {
            PageContent::Captured { payload } => RuntimePageAvailability::Captured {
                payload_id: payload.id.clone(),
            },
            PageContent::Omitted { reason, detail } => RuntimePageAvailability::Omitted {
                reason: *reason,
                detail: detail.clone(),
            },
        };
        let kind = match &mapping.backing {
            MappingBacking::Anonymous => RuntimePageKind::Anonymous,
            MappingBacking::Special { name } => RuntimePageKind::Unknown {
                reason: format!("special mapping {name} has no portable backing identity"),
            },
            MappingBacking::Unknown { reason } => RuntimePageKind::Unknown {
                reason: format!("mapping backing is unknown: {reason}"),
            },
            MappingBacking::File {
                artifact_sha256, ..
            } => classify_file_backed_page(
                page,
                mapping,
                payloads,
                image,
                &image_sha256,
                artifact_sha256,
            ),
        };
        classifications.push(RuntimePageClassification {
            capture_id: capsule.identity.capture_id.clone(),
            process_id: process_id.to_string(),
            mapping_id: page.mapping_id.clone(),
            start: page.start,
            byte_len: page.byte_len,
            availability,
            kind,
        });
    }
    classifications.sort_by_key(|page| (page.start, page.mapping_id.clone()));
    Ok(classifications)
}

fn classify_file_backed_page(
    page: &super::capsule::PageRecord,
    mapping: &super::capsule::MappingRecord,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    image_sha256: &str,
    artifact_sha256: &str,
) -> RuntimePageKind {
    if artifact_sha256 != image_sha256 {
        return RuntimePageKind::Unknown {
            reason: "file-backed page belongs to a different static artifact".to_string(),
        };
    }
    let Some(mapping_file_offset) = mapping.file_offset else {
        return RuntimePageKind::Unknown {
            reason: "file-backed mapping has no file offset".to_string(),
        };
    };
    let Some(file_offset) = mapping_file_offset.checked_add(page.start - mapping.start) else {
        return RuntimePageKind::Unknown {
            reason: "page file offset overflowed".to_string(),
        };
    };
    let PageContent::Captured { payload } = &page.content else {
        return RuntimePageKind::Unknown {
            reason: "file-backed page bytes were omitted".to_string(),
        };
    };
    let Some(runtime_bytes) = payloads.get(&payload.id) else {
        return RuntimePageKind::Unknown {
            reason: "captured page payload is unavailable".to_string(),
        };
    };
    if runtime_bytes.len() as u64 != payload.byte_len
        || hex::encode(Sha256::digest(runtime_bytes)) != payload.sha256
    {
        return RuntimePageKind::Unknown {
            reason: "captured page payload length or SHA-256 disagrees".to_string(),
        };
    }
    let Some(start) = usize::try_from(file_offset).ok() else {
        return RuntimePageKind::Unknown {
            reason: "page file offset is outside host index range".to_string(),
        };
    };
    let Some(end) = start.checked_add(runtime_bytes.len()) else {
        return RuntimePageKind::Unknown {
            reason: "page static range overflowed".to_string(),
        };
    };
    let Some(static_bytes) = image.bytes().get(start..end) else {
        return RuntimePageKind::Unknown {
            reason: "page range is not present in the supplied static artifact".to_string(),
        };
    };
    let mut differences = runtime_bytes
        .iter()
        .zip(static_bytes)
        .enumerate()
        .filter(|(_, (runtime, static_byte))| runtime != static_byte);
    let Some((first, _)) = differences.next() else {
        return RuntimePageKind::FileBackedUnchanged {
            image_sha256: image_sha256.to_string(),
            file_offset,
        };
    };
    let changed_byte_count = 1 + differences.count() as u64;
    RuntimePageKind::FileBackedModified {
        image_sha256: image_sha256.to_string(),
        file_offset,
        changed_byte_count,
        first_changed_offset: first as u64,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum AddressResolution {
    Exact {
        address: ResolvedRuntimeAddress,
    },
    Missing {
        reason: String,
    },
    Ambiguous {
        mapping_ids: Vec<String>,
    },
    WrongImage {
        capsule_sha256: String,
        image_sha256: String,
        reason: String,
    },
    InvalidCapsule {
        reason: String,
    },
}

/// Resolve one process VA without treating a path, basename, or load bias as identity.
pub fn resolve_runtime_address(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    process_id: &str,
    raw_va: u64,
) -> AddressResolution {
    if let Err(reason) = capsule.validate(CapsuleLimits::default()) {
        return AddressResolution::InvalidCapsule { reason };
    }
    let mut candidates: Vec<_> = capsule
        .mappings
        .iter()
        .filter(|mapping| {
            mapping.process_id == process_id && mapping.start <= raw_va && raw_va < mapping.end
        })
        .collect();
    candidates.sort_by(|left, right| left.id.cmp(&right.id));
    if candidates.is_empty() {
        return AddressResolution::Missing {
            reason: "runtime address is not contained by a process mapping".to_string(),
        };
    }
    if candidates.len() != 1 {
        return AddressResolution::Ambiguous {
            mapping_ids: candidates
                .into_iter()
                .map(|mapping| mapping.id.clone())
                .collect(),
        };
    }
    let mapping = candidates[0];
    let Some(module_id) = mapping.module_id.as_deref() else {
        return AddressResolution::Missing {
            reason: "runtime mapping has no proven module instance".to_string(),
        };
    };
    let Some(module) = capsule.modules.iter().find(|module| module.id == module_id) else {
        return AddressResolution::InvalidCapsule {
            reason: format!("mapping references absent module {module_id}"),
        };
    };
    let MappingBacking::File {
        artifact_sha256, ..
    } = &mapping.backing
    else {
        return AddressResolution::Missing {
            reason: "runtime mapping is not proven file-backed".to_string(),
        };
    };
    if artifact_sha256 != &module.artifact.sha256 {
        return AddressResolution::InvalidCapsule {
            reason: "mapping and module artifact identities disagree".to_string(),
        };
    }

    let image_sha256 = hex::encode(Sha256::digest(image.bytes()));
    if module.artifact.sha256 != image_sha256 {
        return AddressResolution::WrongImage {
            capsule_sha256: module.artifact.sha256.clone(),
            image_sha256,
            reason: "content identity disagrees".to_string(),
        };
    }
    if let Some(expected_build_id) = &module.artifact.build_id {
        match static_build_id(image.bytes()) {
            Ok(Some(actual)) if &actual == expected_build_id => {}
            Ok(actual) => {
                return AddressResolution::WrongImage {
                    capsule_sha256: module.artifact.sha256.clone(),
                    image_sha256,
                    reason: format!(
                        "build ID disagrees: capsule={expected_build_id}, image={actual:?}"
                    ),
                };
            }
            Err(reason) => {
                return AddressResolution::WrongImage {
                    capsule_sha256: module.artifact.sha256.clone(),
                    image_sha256,
                    reason,
                };
            }
        }
    }

    let Some(mapping_file_offset) = mapping.file_offset else {
        return AddressResolution::Missing {
            reason: "file-backed mapping has no file offset".to_string(),
        };
    };
    let Some(runtime_file_offset) = mapping_file_offset.checked_add(raw_va - mapping.start) else {
        return AddressResolution::Missing {
            reason: "runtime file-offset calculation overflowed".to_string(),
        };
    };
    let Some(static_va) = image.file_offset_to_va(runtime_file_offset) else {
        return AddressResolution::Missing {
            reason: "runtime file offset has no unambiguous static VA".to_string(),
        };
    };
    let Some(image_base) = image.image_base() else {
        return AddressResolution::Missing {
            reason: "static image has no mapped base".to_string(),
        };
    };
    let Some(module_relative) = static_va.checked_sub(image_base) else {
        return AddressResolution::Missing {
            reason: "static VA precedes the image base".to_string(),
        };
    };
    let byte_status = runtime_byte_status(
        capsule,
        payloads,
        image,
        process_id,
        &mapping.id,
        raw_va,
        runtime_file_offset,
    );
    let function = resolve_static_function(image, static_va);
    let code = match &byte_status {
        RuntimeByteStatus::CapturedDiffersFromStatic { .. } => StaticCodeResolution::Missing {
            reason: "captured instruction byte differs from the static image; stale file semantics withheld"
                .to_string(),
        },
        RuntimeByteStatus::CapturedPayloadInvalid { .. }
        | RuntimeByteStatus::CapturedPayloadUnavailable { .. } => StaticCodeResolution::Missing {
            reason: "captured instruction-byte evidence is unavailable or invalid; static semantics withheld"
                .to_string(),
        },
        RuntimeByteStatus::CapturedMatchesStatic { .. }
        | RuntimeByteStatus::Omitted { .. }
        | RuntimeByteStatus::FileBackedNotCaptured => {
            resolve_static_code(image, static_va, &function)
        }
    };
    AddressResolution::Exact {
        address: ResolvedRuntimeAddress {
            runtime: RuntimeAddress {
                capture_id: capsule.identity.capture_id.clone(),
                process_id: process_id.to_string(),
                mapping_id: mapping.id.clone(),
                module_id: Some(module_id.to_string()),
                raw_va,
            },
            image_sha256,
            runtime_file_offset,
            static_va,
            module_relative,
            byte_status,
            function,
            code,
        },
    }
}

pub(crate) fn resolve_static_code(
    image: &ProgramImage,
    static_va: u64,
    function_resolution: &FunctionResolution,
) -> StaticCodeResolution {
    let entry_va = match function_resolution {
        FunctionResolution::Exact { entry_va, .. }
        | FunctionResolution::Interior { entry_va, .. } => *entry_va,
        FunctionResolution::Ambiguous { .. } => {
            return StaticCodeResolution::Missing {
                reason: "static function ownership is ambiguous".to_string(),
            };
        }
        FunctionResolution::Missing => {
            return StaticCodeResolution::Missing {
                reason: "static function ownership is missing".to_string(),
            };
        }
    };
    let Some(function) = discover_function_image_at(image, &Budgets::default(), entry_va) else {
        return StaticCodeResolution::Missing {
            reason: "targeted CFG discovery did not recover the owning function".to_string(),
        };
    };
    let mut blocks: Vec<_> = function
        .basic_blocks
        .iter()
        .filter(|block| {
            block.start_address.value <= static_va && static_va < block.end_address.value
        })
        .collect();
    blocks.sort_by_key(|block| block.start_address.value);
    if blocks.len() > 1 {
        return StaticCodeResolution::Ambiguous {
            block_starts: blocks
                .iter()
                .map(|block| block.start_address.value)
                .collect(),
        };
    }
    let Some(block) = blocks.first() else {
        if function.cfg_is_incomplete() {
            return StaticCodeResolution::Incomplete {
                reason: "targeted CFG stopped before resolving the static PC".to_string(),
                budgets: function
                    .cfg_incomplete_budgets()
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            };
        }
        return StaticCodeResolution::Missing {
            reason: "static PC is not contained by a discovered basic block".to_string(),
        };
    };

    let arch = Architecture::from(image.arch());
    let Some(backend) = registry::for_arch(arch, image.endianness()) else {
        return StaticCodeResolution::Missing {
            reason: "no disassembler backend exists for the static image target".to_string(),
        };
    };
    let bits = arch.address_bits();
    let mut instruction_va = block.start_address.value;
    while instruction_va < block.end_address.value {
        let Some(offset) = image.va_to_code_file_offset(instruction_va) else {
            break;
        };
        let Ok(address) = Address::new(AddressKind::VA, instruction_va, bits, None, None) else {
            break;
        };
        let Ok(instruction) = backend.disassemble_instruction(&address, &image.bytes()[offset..])
        else {
            break;
        };
        let Some(instruction_end) = instruction_va.checked_add(u64::from(instruction.length))
        else {
            break;
        };
        if instruction_va <= static_va && static_va < instruction_end {
            let operations = resolve_static_operations(image, &function, instruction_va);
            return StaticCodeResolution::Resolved {
                block_start: block.start_address.value,
                block_end: block.end_address.value,
                instruction_va,
                instruction_end,
                instruction_relation: if instruction_va == static_va {
                    InstructionRelation::Exact
                } else {
                    InstructionRelation::Interior
                },
                mnemonic: instruction.mnemonic,
                operations,
            };
        }
        if instruction.length == 0 {
            break;
        }
        instruction_va = instruction_end;
    }
    StaticCodeResolution::Missing {
        reason: "static PC is not covered by a decodable instruction".to_string(),
    }
}

fn resolve_static_operations(
    image: &ProgramImage,
    function: &crate::core::function::Function,
    instruction_va: u64,
) -> OperationResolution {
    let lifted = match lift_function_from_image(image, function) {
        Ok(lifted) => lifted,
        Err(error) => {
            return OperationResolution::Unavailable {
                reason: error.to_string(),
            };
        }
    };
    let operations: Vec<_> = lifted
        .blocks
        .iter()
        .flat_map(|block| {
            block
                .instrs
                .iter()
                .enumerate()
                .filter(move |(_, instruction)| instruction.va == instruction_va)
                .enumerate()
                .map(
                    move |(machine_operation_ordinal, (operation_index, instruction))| {
                        let image_sha256 = hex::encode(Sha256::digest(image.bytes()));
                        let lift_profile = "glaurung-raw-llir-v1";
                        let kind = op_kind(&instruction.op);
                        let function_id = crate::ir::function_ir::function_id(
                            &image_sha256,
                            lift_profile,
                            function.entry_point.value,
                        );
                        let block_id =
                            crate::ir::function_ir::block_id(&function_id, block.start_va);
                        let operation_id = crate::ir::function_ir::operation_id(
                            &image_sha256,
                            function.entry_point.value,
                            lift_profile,
                            block.start_va,
                            operation_index,
                            kind,
                        );
                        let address_expression =
                            address_expression(&block.instrs, operation_index, &instruction.op);
                        let stored_value = stored_value_expression(
                            &block.instrs,
                            operation_index,
                            &instruction.op,
                        );
                        let condition_expression = condition_expression(
                            image,
                            &block.instrs,
                            operation_index,
                            &instruction.op,
                        );
                        let defined_value = defined_value_expression(
                            &block.instrs,
                            operation_index,
                            &instruction.op,
                        );
                        let call_target =
                            call_target(image, &block.instrs, operation_index, &instruction.op);
                        let call_target_expression_id = match &call_target {
                            Some(StaticCallTarget::Indirect {
                                expression: Some(_),
                            }) => Some(crate::ir::function_ir::expression_id(
                                &operation_id,
                                crate::ir::function_ir::OperationExpressionRole::CallTarget,
                            )),
                            _ => None,
                        };
                        let call_target_value_id = call_target.as_ref().map(|_| {
                            crate::ir::function_ir::value_id(
                                &operation_id,
                                crate::ir::function_ir::OperationValueRole::CallTarget,
                            )
                        });
                        let mut call_register_inputs = call_register_inputs(
                            image,
                            &block.instrs,
                            operation_index,
                            &instruction.op,
                        );
                        for input in &mut call_register_inputs {
                            input.expression_id = crate::ir::function_ir::expression_id(
                                &operation_id,
                                crate::ir::function_ir::OperationExpressionRole::CallInput(
                                    input.position,
                                ),
                            );
                            input.value_id = crate::ir::function_ir::value_id(
                                &operation_id,
                                crate::ir::function_ir::OperationValueRole::CallInput(
                                    input.position,
                                ),
                            );
                        }
                        let address_expression_id = address_expression.as_ref().map(|_| {
                            crate::ir::function_ir::expression_id(
                                &operation_id,
                                crate::ir::function_ir::OperationExpressionRole::MemoryAddress,
                            )
                        });
                        let stored_value_expression_id = stored_value.as_ref().map(|_| {
                            crate::ir::function_ir::expression_id(
                                &operation_id,
                                crate::ir::function_ir::OperationExpressionRole::StoredValue,
                            )
                        });
                        let condition_expression_id = condition_expression.as_ref().map(|_| {
                            crate::ir::function_ir::expression_id(
                                &operation_id,
                                crate::ir::function_ir::OperationExpressionRole::Condition,
                            )
                        });
                        let defined_value_expression_id = defined_value.as_ref().map(|_| {
                            crate::ir::function_ir::expression_id(
                                &operation_id,
                                crate::ir::function_ir::OperationExpressionRole::DefinedValue,
                            )
                        });
                        let mut expression_nodes = Vec::new();
                        for (id, expression) in [
                            (&address_expression_id, &address_expression),
                            (&stored_value_expression_id, &stored_value),
                            (&condition_expression_id, &condition_expression),
                            (&defined_value_expression_id, &defined_value),
                        ] {
                            if let Some((id, expression)) = id.as_ref().zip(expression.as_ref()) {
                                expression_nodes.extend(static_expression_nodes(id, expression));
                            }
                        }
                        if let Some((id, expression)) =
                            call_target_expression_id
                                .as_ref()
                                .zip(call_target.as_ref().and_then(|target| match target {
                                    StaticCallTarget::Indirect { expression } => {
                                        expression.as_ref()
                                    }
                                    StaticCallTarget::Direct { .. } => None,
                                }))
                        {
                            expression_nodes.extend(static_expression_nodes(id, expression));
                        }
                        for input in &call_register_inputs {
                            expression_nodes.extend(static_expression_nodes(
                                &input.expression_id,
                                &input.expression,
                            ));
                        }
                        let semantic_values = static_semantic_values(
                            &operation_id,
                            address_expression_id.as_deref(),
                            stored_value_expression_id.as_deref(),
                            condition_expression_id.as_deref(),
                            defined_value_expression_id.as_deref(),
                            call_target.as_ref(),
                            call_target_expression_id.as_deref(),
                            &call_register_inputs,
                        );
                        StaticOperation {
                            address_expression_id,
                            stored_value_expression_id,
                            condition_expression_id,
                            defined_value_expression_id,
                            call_target_expression_id,
                            call_target_value_id,
                            expression_nodes,
                            semantic_values,
                            id: operation_id,
                            function_id,
                            block_id,
                            image_sha256,
                            function_entry: function.entry_point.value,
                            machine_va: instruction_va,
                            machine_operation_ordinal,
                            lift_profile: lift_profile.to_string(),
                            block_start: block.start_va,
                            operation_index,
                            kind: kind.to_string(),
                            memory_access: memory_access(&instruction.op),
                            address_expression,
                            stored_value,
                            stored_value_register: stored_value_register(&instruction.op),
                            call_target,
                            call_register_inputs,
                            control_target: control_target(&instruction.op),
                            condition_expression,
                            condition_call_results: condition_call_results(
                                image,
                                &block.instrs,
                                operation_index,
                                &instruction.op,
                            ),
                            defined_register: crate::ir::use_def::def_ref(&instruction.op)
                                .map(register_name),
                            defined_value,
                            used_registers: crate::ir::use_def::def_uses(&instruction.op)
                                .1
                                .into_iter()
                                .map(|register| register_name(&register))
                                .collect(),
                            value_selection: value_selection(
                                &block.instrs,
                                operation_index,
                                &instruction.op,
                            ),
                        }
                    },
                )
        })
        .collect();
    if operations.is_empty() {
        OperationResolution::NoOperations {
            reason: "the decoded machine instruction emitted no LLIR operations".to_string(),
        }
    } else {
        OperationResolution::Resolved { operations }
    }
}

fn value_selection(
    instructions: &[LlirInstr],
    operation_index: usize,
    op: &Op,
) -> Option<StaticValueSelection> {
    let Op::Ite { dst, t, e, .. } = op else {
        return None;
    };
    Some(StaticValueSelection {
        output_register: register_name(dst),
        when_true: selection_value(instructions, operation_index, t)?,
        when_false: selection_value(instructions, operation_index, e)?,
    })
}

fn selection_value(
    instructions: &[LlirInstr],
    operation_index: usize,
    value: &Value,
) -> Option<StaticValueExpression> {
    if let Some(expression) = slice_value(instructions, operation_index, value, 0) {
        return Some(expression);
    }
    let Value::Reg(VReg::Phys(register)) = value else {
        return None;
    };
    if !matches!(register.as_str(), "eax" | "rax") {
        return None;
    }
    instructions[..operation_index]
        .iter()
        .rev()
        .find(|instruction| matches!(instruction.op, Op::Call { .. }))
        .map(|instruction| StaticValueExpression::CallResult {
            machine_va: instruction.va,
            register: "rax".to_string(),
        })
}

fn condition_call_results(
    image: &ProgramImage,
    instructions: &[LlirInstr],
    operation_index: usize,
    op: &Op,
) -> Vec<StaticCallResultOrigin> {
    let condition = match op {
        Op::CondJump { cond, .. }
        | Op::CondReturn { cond, .. }
        | Op::CondReturnValue { cond, .. }
        | Op::Ite { cond, .. } => cond,
        _ => return Vec::new(),
    };
    if image.target().calling_convention() != Some(crate::target::CallConv::SysVAmd64) {
        return Vec::new();
    }
    instructions[..operation_index]
        .iter()
        .enumerate()
        .filter(|(_, instruction)| matches!(instruction.op, Op::Call { .. }))
        .filter_map(|(call_index, call)| {
            let mut tainted = BTreeSet::from([VReg::phys("rax"), VReg::phys("eax")]);
            for instruction in &instructions[call_index + 1..operation_index] {
                if matches!(instruction.op, Op::Call { .. }) {
                    tainted.remove(&VReg::phys("rax"));
                    tainted.remove(&VReg::phys("eax"));
                }
                let (definition, uses) = crate::ir::use_def::def_uses(&instruction.op);
                let derived = uses.iter().any(|value| tainted.contains(value));
                if let Some(definition) = definition {
                    tainted.remove(&definition);
                    if derived {
                        tainted.insert(definition);
                    }
                }
            }
            tainted.contains(condition).then(|| StaticCallResultOrigin {
                machine_va: call.va,
                register: "rax".to_string(),
            })
        })
        .collect()
}

fn control_target(op: &Op) -> Option<u64> {
    match op {
        Op::Jump { target } | Op::CondJump { target, .. } => Some(*target),
        _ => None,
    }
}

fn condition_expression(
    image: &ProgramImage,
    instructions: &[LlirInstr],
    operation_index: usize,
    op: &Op,
) -> Option<StaticValueExpression> {
    let condition = match op {
        Op::CondJump { cond, .. }
        | Op::CondReturn { cond, .. }
        | Op::CondReturnValue { cond, .. } => cond,
        _ => return None,
    };
    let expression = slice_register(instructions, operation_index, condition, 0)?;
    bind_abi_call_result(image, instructions, operation_index, expression)
}

fn bind_abi_call_result(
    image: &ProgramImage,
    instructions: &[LlirInstr],
    before: usize,
    expression: StaticValueExpression,
) -> Option<StaticValueExpression> {
    if image.target().calling_convention() != Some(crate::target::CallConv::SysVAmd64)
        || !expression_uses_register(&expression, &["eax", "rax"])
    {
        return Some(expression);
    }
    let mut call = None;
    for instruction in instructions[..before].iter().rev() {
        if explicitly_defines_abi_result(&instruction.op) {
            return Some(expression);
        }
        if matches!(instruction.op, Op::Call { .. }) {
            call = Some(instruction.va);
            break;
        }
    }
    let machine_va = call?;
    Some(replace_abi_result(expression, machine_va))
}

fn explicitly_defines_abi_result(op: &Op) -> bool {
    crate::ir::use_def::def_ref(op).is_some_and(
        |register| matches!(register, VReg::Phys(name) if matches!(name.as_str(), "eax" | "rax")),
    )
}

fn expression_uses_register(expression: &StaticValueExpression, names: &[&str]) -> bool {
    match expression {
        StaticValueExpression::Register { name } => names.contains(&name.as_str()),
        StaticValueExpression::Add { left, right }
        | StaticValueExpression::Subtract { left, right }
        | StaticValueExpression::Multiply { left, right }
        | StaticValueExpression::BitwiseAnd { left, right }
        | StaticValueExpression::BitwiseOr { left, right }
        | StaticValueExpression::BitwiseXor { left, right }
        | StaticValueExpression::Compare { left, right, .. } => {
            expression_uses_register(left, names) || expression_uses_register(right, names)
        }
        StaticValueExpression::Truncate { value, .. }
        | StaticValueExpression::ZeroExtend { value, .. }
        | StaticValueExpression::SignExtend { value, .. }
        | StaticValueExpression::Extract { value, .. }
        | StaticValueExpression::Load { address: value, .. } => {
            expression_uses_register(value, names)
        }
        _ => false,
    }
}

fn replace_abi_result(expression: StaticValueExpression, machine_va: u64) -> StaticValueExpression {
    match expression {
        StaticValueExpression::Register { name } if matches!(name.as_str(), "eax" | "rax") => {
            StaticValueExpression::CallResult {
                machine_va,
                register: "rax".to_string(),
            }
        }
        StaticValueExpression::Add { left, right } => StaticValueExpression::Add {
            left: Box::new(replace_abi_result(*left, machine_va)),
            right: Box::new(replace_abi_result(*right, machine_va)),
        },
        StaticValueExpression::Subtract { left, right } => StaticValueExpression::Subtract {
            left: Box::new(replace_abi_result(*left, machine_va)),
            right: Box::new(replace_abi_result(*right, machine_va)),
        },
        StaticValueExpression::Multiply { left, right } => StaticValueExpression::Multiply {
            left: Box::new(replace_abi_result(*left, machine_va)),
            right: Box::new(replace_abi_result(*right, machine_va)),
        },
        StaticValueExpression::BitwiseAnd { left, right } => StaticValueExpression::BitwiseAnd {
            left: Box::new(replace_abi_result(*left, machine_va)),
            right: Box::new(replace_abi_result(*right, machine_va)),
        },
        StaticValueExpression::BitwiseOr { left, right } => StaticValueExpression::BitwiseOr {
            left: Box::new(replace_abi_result(*left, machine_va)),
            right: Box::new(replace_abi_result(*right, machine_va)),
        },
        StaticValueExpression::BitwiseXor { left, right } => StaticValueExpression::BitwiseXor {
            left: Box::new(replace_abi_result(*left, machine_va)),
            right: Box::new(replace_abi_result(*right, machine_va)),
        },
        StaticValueExpression::Compare {
            comparison,
            left,
            right,
        } => StaticValueExpression::Compare {
            comparison,
            left: Box::new(replace_abi_result(*left, machine_va)),
            right: Box::new(replace_abi_result(*right, machine_va)),
        },
        StaticValueExpression::Truncate {
            value,
            from_bits,
            to_bits,
        } => StaticValueExpression::Truncate {
            value: Box::new(replace_abi_result(*value, machine_va)),
            from_bits,
            to_bits,
        },
        StaticValueExpression::ZeroExtend {
            value,
            from_bits,
            to_bits,
        } => StaticValueExpression::ZeroExtend {
            value: Box::new(replace_abi_result(*value, machine_va)),
            from_bits,
            to_bits,
        },
        StaticValueExpression::SignExtend {
            value,
            from_bits,
            to_bits,
        } => StaticValueExpression::SignExtend {
            value: Box::new(replace_abi_result(*value, machine_va)),
            from_bits,
            to_bits,
        },
        StaticValueExpression::Extract {
            value,
            high_bit,
            low_bit,
        } => StaticValueExpression::Extract {
            value: Box::new(replace_abi_result(*value, machine_va)),
            high_bit,
            low_bit,
        },
        StaticValueExpression::Load { address, byte_len } => StaticValueExpression::Load {
            address: Box::new(replace_abi_result(*address, machine_va)),
            byte_len,
        },
        other => other,
    }
}

fn call_register_inputs(
    image: &ProgramImage,
    instructions: &[LlirInstr],
    operation_index: usize,
    op: &Op,
) -> Vec<StaticCallRegisterInput> {
    if !matches!(op, Op::Call { .. })
        || image.target().calling_convention() != Some(crate::target::CallConv::SysVAmd64)
    {
        return Vec::new();
    }
    ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        .into_iter()
        .enumerate()
        .filter_map(|(position, register)| {
            slice_register(instructions, operation_index, &VReg::phys(register), 0).map(
                |expression| StaticCallRegisterInput {
                    position,
                    abi_register: register.to_string(),
                    expression,
                    expression_id: String::new(),
                    value_id: String::new(),
                },
            )
        })
        .collect()
}

fn call_target(
    image: &ProgramImage,
    instructions: &[LlirInstr],
    operation_index: usize,
    op: &Op,
) -> Option<StaticCallTarget> {
    let Op::Call { target, .. } = op else {
        return None;
    };
    Some(match target {
        CallTarget::Direct(address) => StaticCallTarget::Direct {
            address: *address,
            symbol: image.imported_call_targets().get(address).cloned(),
        },
        CallTarget::Indirect(value) => StaticCallTarget::Indirect {
            expression: slice_value(instructions, operation_index, value, 0),
        },
    })
}

fn stored_value_expression(
    instructions: &[LlirInstr],
    operation_index: usize,
    op: &Op,
) -> Option<StaticValueExpression> {
    let Op::Store { src, .. } = op else {
        return None;
    };
    slice_value(instructions, operation_index, src, 0)
}

fn defined_value_expression(
    instructions: &[LlirInstr],
    operation_index: usize,
    op: &Op,
) -> Option<StaticValueExpression> {
    let register = crate::ir::use_def::def_ref(op)?;
    slice_register(instructions, operation_index + 1, &register, 0)
}

fn stored_value_register(op: &Op) -> Option<String> {
    let Op::Store {
        src: Value::Reg(register),
        ..
    } = op
    else {
        return None;
    };
    Some(register_name(register))
}

fn address_expression(
    instructions: &[LlirInstr],
    operation_index: usize,
    op: &Op,
) -> Option<StaticValueExpression> {
    let address = match op {
        Op::Load { addr, .. } | Op::Store { addr, .. } => addr,
        _ => return None,
    };
    slice_memory_address(instructions, operation_index, address, 0)
}

fn slice_memory_address(
    instructions: &[LlirInstr],
    before: usize,
    address: &MemOp,
    depth: usize,
) -> Option<StaticValueExpression> {
    if depth >= 32 || address.segment.is_some() {
        return None;
    }
    let mut expression = match &address.base {
        Some(VReg::Phys(name)) if matches!(name.as_str(), "rbp" | "rsp") => {
            StaticValueExpression::Register { name: name.clone() }
        }
        Some(register) => slice_register(instructions, before, register, depth + 1)?,
        None => StaticValueExpression::Constant { value: 0 },
    };
    if let Some(index) = &address.index {
        let mut index = slice_register(instructions, before, index, depth + 1)?;
        let scale = address.scale.max(1);
        if scale != 1 {
            index = StaticValueExpression::Multiply {
                left: Box::new(index),
                right: Box::new(StaticValueExpression::Constant {
                    value: i64::from(scale),
                }),
            };
        }
        expression = StaticValueExpression::Add {
            left: Box::new(expression),
            right: Box::new(index),
        };
    }
    if address.disp != 0 {
        expression = StaticValueExpression::Add {
            left: Box::new(expression),
            right: Box::new(StaticValueExpression::Constant {
                value: address.disp,
            }),
        };
    }
    Some(expression)
}

fn slice_register(
    instructions: &[LlirInstr],
    before: usize,
    register: &VReg,
    depth: usize,
) -> Option<StaticValueExpression> {
    if depth >= 32 {
        return None;
    }
    for (index, instruction) in instructions[..before].iter().enumerate().rev() {
        match &instruction.op {
            Op::Assign { dst, src } if same_register_storage(dst, register) => {
                return slice_value(instructions, index, src, depth + 1);
            }
            Op::Bin {
                dst,
                op: BinOp::Add,
                lhs,
                rhs,
            } if same_register_storage(dst, register) => {
                return Some(StaticValueExpression::Add {
                    left: Box::new(slice_value(instructions, index, lhs, depth + 1)?),
                    right: Box::new(slice_value(instructions, index, rhs, depth + 1)?),
                });
            }
            Op::Bin {
                dst,
                op: BinOp::Sub,
                lhs,
                rhs,
            } if same_register_storage(dst, register) => {
                return Some(StaticValueExpression::Subtract {
                    left: Box::new(slice_value(instructions, index, lhs, depth + 1)?),
                    right: Box::new(slice_value(instructions, index, rhs, depth + 1)?),
                });
            }
            Op::Bin {
                dst,
                op: BinOp::Mul,
                lhs,
                rhs,
            } if same_register_storage(dst, register) => {
                return Some(StaticValueExpression::Multiply {
                    left: Box::new(slice_value(instructions, index, lhs, depth + 1)?),
                    right: Box::new(slice_value(instructions, index, rhs, depth + 1)?),
                });
            }
            Op::Bin {
                dst,
                op: BinOp::And,
                lhs,
                rhs,
            } if same_register_storage(dst, register) => {
                return Some(StaticValueExpression::BitwiseAnd {
                    left: Box::new(slice_value(instructions, index, lhs, depth + 1)?),
                    right: Box::new(slice_value(instructions, index, rhs, depth + 1)?),
                });
            }
            Op::Bin {
                dst,
                op: BinOp::Or,
                lhs,
                rhs,
            } if same_register_storage(dst, register) => {
                return Some(StaticValueExpression::BitwiseOr {
                    left: Box::new(slice_value(instructions, index, lhs, depth + 1)?),
                    right: Box::new(slice_value(instructions, index, rhs, depth + 1)?),
                });
            }
            Op::Bin {
                dst,
                op: BinOp::Xor,
                lhs,
                rhs,
            } if same_register_storage(dst, register) => {
                return Some(StaticValueExpression::BitwiseXor {
                    left: Box::new(slice_value(instructions, index, lhs, depth + 1)?),
                    right: Box::new(slice_value(instructions, index, rhs, depth + 1)?),
                });
            }
            Op::Load { dst, addr } if same_register_storage(dst, register) => {
                return Some(StaticValueExpression::Load {
                    address: Box::new(slice_memory_address(instructions, index, addr, depth + 1)?),
                    byte_len: addr.size,
                });
            }
            Op::Trunc { dst, src, from, to } if same_register_storage(dst, register) => {
                return Some(StaticValueExpression::Truncate {
                    value: Box::new(slice_value(instructions, index, src, depth + 1)?),
                    from_bits: from.bits(),
                    to_bits: to.bits(),
                });
            }
            Op::ZExt { dst, src, from, to } if same_register_storage(dst, register) => {
                return Some(StaticValueExpression::ZeroExtend {
                    value: Box::new(slice_value(instructions, index, src, depth + 1)?),
                    from_bits: from.bits(),
                    to_bits: to.bits(),
                });
            }
            Op::SExt { dst, src, from, to } if same_register_storage(dst, register) => {
                return Some(StaticValueExpression::SignExtend {
                    value: Box::new(slice_value(instructions, index, src, depth + 1)?),
                    from_bits: from.bits(),
                    to_bits: to.bits(),
                });
            }
            Op::Extract { dst, src, hi, lo } if same_register_storage(dst, register) => {
                return Some(StaticValueExpression::Extract {
                    value: Box::new(slice_value(instructions, index, src, depth + 1)?),
                    high_bit: *hi,
                    low_bit: *lo,
                });
            }
            Op::Cmp { dst, op, lhs, rhs } if same_register_storage(dst, register) => {
                return Some(StaticValueExpression::Compare {
                    comparison: comparison_name(*op).to_string(),
                    left: Box::new(slice_value(instructions, index, lhs, depth + 1)?),
                    right: Box::new(slice_value(instructions, index, rhs, depth + 1)?),
                });
            }
            Op::Call {
                effects: Some(effects),
                ..
            } if effects
                .result
                .as_ref()
                .is_some_and(|result| same_register_storage(result, register)) =>
            {
                return Some(StaticValueExpression::CallResult {
                    machine_va: instruction.va,
                    register: register_name(register),
                });
            }
            Op::Call { effects: None, .. } if matches!(register, VReg::Phys(name) if matches!(name.as_str(), "eax" | "rax")) =>
            {
                return None;
            }
            _ if op_defines(&instruction.op, register) => return None,
            _ => {}
        }
    }
    Some(StaticValueExpression::Register {
        name: register_name(register),
    })
}

fn same_register_storage(left: &VReg, right: &VReg) -> bool {
    match (left, right) {
        (VReg::Phys(left), VReg::Phys(right)) => {
            let left = crate::ir::regview::parent_of(crate::ir::regview::Arch::X86_64, left)
                .unwrap_or(left);
            let right = crate::ir::regview::parent_of(crate::ir::regview::Arch::X86_64, right)
                .unwrap_or(right);
            left == right
        }
        _ => left == right,
    }
}

fn comparison_name(op: crate::ir::types::CmpOp) -> &'static str {
    use crate::ir::types::CmpOp;
    match op {
        CmpOp::Eq => "eq",
        CmpOp::Ne => "ne",
        CmpOp::Ult => "ult",
        CmpOp::Ule => "ule",
        CmpOp::Slt => "slt",
        CmpOp::Sle => "sle",
    }
}

fn op_defines(op: &Op, register: &VReg) -> bool {
    match op {
        Op::Assign { dst, .. }
        | Op::Undef { dst, .. }
        | Op::Bin { dst, .. }
        | Op::Un { dst, .. }
        | Op::Cmp { dst, .. }
        | Op::Load { dst, .. }
        | Op::CondLoad { dst, .. }
        | Op::ZExt { dst, .. }
        | Op::SExt { dst, .. }
        | Op::Trunc { dst, .. }
        | Op::Extract { dst, .. }
        | Op::Concat { dst, .. }
        | Op::Ite { dst, .. } => same_register_storage(dst, register),
        Op::Call {
            effects: Some(effects),
            ..
        } => effects
            .result
            .as_ref()
            .is_some_and(|result| same_register_storage(result, register)),
        Op::Intrinsic { outs, .. } => outs.iter().any(|(output, _)| output == register),
        _ => false,
    }
}

fn slice_value(
    instructions: &[LlirInstr],
    before: usize,
    value: &Value,
    depth: usize,
) -> Option<StaticValueExpression> {
    match value {
        Value::Reg(register) => slice_register(instructions, before, register, depth + 1),
        Value::Const(value) => Some(StaticValueExpression::Constant { value: *value }),
        Value::Addr(value) => Some(StaticValueExpression::Address { value: *value }),
    }
}

fn memory_access(op: &Op) -> Option<StaticMemoryAccess> {
    let address = match op {
        Op::Load { addr, .. } | Op::Store { addr, .. } => addr,
        _ => return None,
    };
    Some(StaticMemoryAccess {
        base_register: address.base.as_ref().map(register_name),
        index_register: address.index.as_ref().map(register_name),
        scale: address.scale.max(1),
        displacement: address.disp,
        byte_len: address.size,
        segment: address.segment.clone(),
    })
}

fn register_name(register: &crate::ir::VReg) -> String {
    match register {
        crate::ir::VReg::Phys(name) => name.clone(),
        _ => register.to_string(),
    }
}

fn op_kind(op: &Op) -> &'static str {
    match op {
        Op::Assign { .. } => "assign",
        Op::Undef { .. } => "undef",
        Op::Bin { .. } => "bin",
        Op::Un { .. } => "un",
        Op::Cmp { .. } => "cmp",
        Op::Load { .. } => "load",
        Op::CondLoad { .. } => "cond_load",
        Op::Store { .. } => "store",
        Op::CondStore { .. } => "cond_store",
        Op::Jump { .. } => "jump",
        Op::IndirectJump { .. } => "indirect_jump",
        Op::CondJump { .. } => "cond_jump",
        Op::CondReturn { .. } => "cond_return",
        Op::CondReturnValue { .. } => "cond_return_value",
        Op::Call { .. } => "call",
        Op::ReturnValue { .. } => "return_value",
        Op::Return => "return",
        Op::Nop => "nop",
        Op::ZExt { .. } => "zext",
        Op::SExt { .. } => "sext",
        Op::Trunc { .. } => "trunc",
        Op::Extract { .. } => "extract",
        Op::Concat { .. } => "concat",
        Op::Ite { .. } => "ite",
        Op::Intrinsic { .. } => "intrinsic",
        Op::Unknown { .. } => "unknown",
    }
}

pub(crate) fn resolve_static_function(image: &ProgramImage, static_va: u64) -> FunctionResolution {
    let mut candidates: Vec<_> = image
        .eh_frame_functions()
        .iter()
        .filter(|function| function.start <= static_va && static_va < function.end)
        .collect();
    candidates.sort_by_key(|function| (function.start, function.end));
    candidates.dedup_by_key(|function| (function.start, function.end));
    if candidates.len() > 1 {
        return FunctionResolution::Ambiguous {
            entries: candidates.iter().map(|function| function.start).collect(),
        };
    }
    let Some(function) = candidates.first() else {
        return FunctionResolution::Missing;
    };
    let name = image
        .defined_symbol_name_at(function.start)
        .map(str::to_string);
    if static_va == function.start {
        FunctionResolution::Exact {
            entry_va: function.start,
            end_va: function.end,
            name,
        }
    } else {
        FunctionResolution::Interior {
            entry_va: function.start,
            end_va: function.end,
            name,
        }
    }
}

fn runtime_byte_status(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    process_id: &str,
    mapping_id: &str,
    raw_va: u64,
    file_offset: u64,
) -> RuntimeByteStatus {
    let page = capsule.pages.iter().find(|page| {
        page.process_id == process_id
            && page.mapping_id == mapping_id
            && page.start <= raw_va
            && raw_va < page.start + page.byte_len
    });
    let Some(page) = page else {
        return RuntimeByteStatus::FileBackedNotCaptured;
    };
    match &page.content {
        PageContent::Omitted { reason, detail } => RuntimeByteStatus::Omitted {
            reason: *reason,
            detail: detail.clone(),
        },
        PageContent::Captured { payload } => {
            let Some(bytes) = payloads.get(&payload.id) else {
                return RuntimeByteStatus::CapturedPayloadUnavailable {
                    payload_id: payload.id.clone(),
                };
            };
            if bytes.len() as u64 != payload.byte_len
                || hex::encode(Sha256::digest(bytes)) != payload.sha256
            {
                return RuntimeByteStatus::CapturedPayloadInvalid {
                    payload_id: payload.id.clone(),
                    reason: "payload length or SHA-256 disagrees with capsule".to_string(),
                };
            }
            let page_offset = usize::try_from(raw_va - page.start).ok();
            let static_offset = usize::try_from(file_offset).ok();
            match (
                page_offset
                    .and_then(|offset| bytes.get(offset))
                    .map(|byte| *byte),
                static_offset
                    .and_then(|offset| image.bytes().get(offset))
                    .map(|byte| *byte),
            ) {
                (Some(runtime_byte), Some(static_byte)) if runtime_byte == static_byte => {
                    RuntimeByteStatus::CapturedMatchesStatic {
                        payload_id: payload.id.clone(),
                    }
                }
                (Some(runtime_byte), Some(static_byte)) => {
                    RuntimeByteStatus::CapturedDiffersFromStatic {
                        payload_id: payload.id.clone(),
                        runtime_byte,
                        static_byte,
                    }
                }
                _ => RuntimeByteStatus::CapturedPayloadUnavailable {
                    payload_id: payload.id.clone(),
                },
            }
        }
    }
}

fn static_build_id(bytes: &[u8]) -> Result<Option<String>, String> {
    let file = object::File::parse(bytes)
        .map_err(|error| format!("parse exact static image for build ID: {error}"))?;
    if file.kind() == ObjectKind::Unknown {
        return Err("static image has unknown object kind".to_string());
    }
    file.build_id()
        .map(|value| value.map(hex::encode))
        .map_err(|error| format!("read static image build ID: {error}"))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::core::binary::{Arch, Endianness};
    use crate::ir::types::CmpOp;
    use crate::runtime_analysis::capsule::{
        AcquisitionMode, ArtifactIdentity, CaptureIdentity, CaptureProvenance, MappingRecord,
        ModuleInstance, OmissionReason, PageRecord, PayloadReference, Permissions, ProcessRecord,
        RuntimeTarget, Sensitivity, TerminalState, SCHEMA, VERSION,
    };

    #[test]
    fn stack_memory_slice_keeps_occurrence_time_frame_register() {
        let instructions = vec![LlirInstr {
            va: 0x1000,
            op: Op::Assign {
                dst: VReg::phys("rbp"),
                src: Value::Reg(VReg::phys("rsp")),
            },
        }];
        let address = MemOp::plain(Some(VReg::phys("rbp")), None, 1, -40, 8);
        assert_eq!(
            slice_memory_address(&instructions, instructions.len(), &address, 0),
            Some(StaticValueExpression::Add {
                left: Box::new(StaticValueExpression::Register {
                    name: "rbp".to_string(),
                }),
                right: Box::new(StaticValueExpression::Constant { value: -40 }),
            })
        );
    }

    #[test]
    fn value_slice_follows_x86_parent_across_eax_definition() {
        let byte = VReg::Temp(0);
        let instructions = vec![
            LlirInstr {
                va: 0x1000,
                op: Op::Load {
                    dst: byte.clone(),
                    addr: MemOp::plain(Some(VReg::phys("rax")), None, 1, 0, 1),
                },
            },
            LlirInstr {
                va: 0x1000,
                op: Op::ZExt {
                    dst: VReg::phys("eax"),
                    src: Value::Reg(byte),
                    from: crate::ir::types::Width::W8,
                    to: crate::ir::types::Width::W32,
                },
            },
            LlirInstr {
                va: 0x1003,
                op: Op::Store {
                    addr: MemOp::plain(Some(VReg::phys("rbp")), None, 1, -1, 1),
                    src: Value::Reg(VReg::phys("rax")),
                },
            },
        ];
        assert_eq!(
            stored_value_expression(&instructions, 2, &instructions[2].op),
            Some(StaticValueExpression::ZeroExtend {
                value: Box::new(StaticValueExpression::Load {
                    address: Box::new(StaticValueExpression::Register {
                        name: "rax".to_string(),
                    }),
                    byte_len: 1,
                }),
                from_bits: 8,
                to_bits: 32,
            })
        );
    }

    #[test]
    fn condition_call_result_origin_uses_abi_and_fails_closed_on_clobber() {
        let image = hello_image();
        let temporary = VReg::Temp(1);
        let condition = VReg::Temp(2);
        let mut instructions = vec![
            LlirInstr {
                va: 0x1000,
                op: Op::Call {
                    target: CallTarget::Direct(0x2000),
                    effects: None,
                },
            },
            LlirInstr {
                va: 0x1005,
                op: Op::Bin {
                    dst: temporary.clone(),
                    op: BinOp::And,
                    lhs: Value::Reg(VReg::phys("eax")),
                    rhs: Value::Reg(VReg::phys("eax")),
                },
            },
            LlirInstr {
                va: 0x1007,
                op: Op::Cmp {
                    dst: condition.clone(),
                    op: CmpOp::Eq,
                    lhs: Value::Reg(temporary),
                    rhs: Value::Const(0),
                },
            },
            LlirInstr {
                va: 0x1009,
                op: Op::CondJump {
                    cond: condition,
                    target: 0x1010,
                    inverted: false,
                },
            },
        ];
        assert_eq!(
            condition_call_results(&image, &instructions, 3, &instructions[3].op,),
            vec![StaticCallResultOrigin {
                machine_va: 0x1000,
                register: "rax".to_string(),
            }]
        );

        instructions.insert(
            1,
            LlirInstr {
                va: 0x1005,
                op: Op::Assign {
                    dst: VReg::phys("eax"),
                    src: Value::Const(7),
                },
            },
        );
        assert!(condition_call_results(&image, &instructions, 4, &instructions[4].op,).is_empty());
    }

    pub(crate) fn hello_image() -> ProgramImage {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0");
        ProgramImage::from_path(&path).expect("parse real ELF")
    }

    pub(crate) fn capsule(image: &ProgramImage) -> ProcessCapsule {
        let hash = hex::encode(Sha256::digest(image.bytes()));
        let artifact = ArtifactIdentity {
            sha256: hash.clone(),
            byte_len: image.bytes().len() as u64,
            build_id: None,
            display_path: Some("/exact/hello".to_string()),
        };
        ProcessCapsule {
            schema: SCHEMA.to_string(),
            version: VERSION,
            identity: CaptureIdentity {
                capture_id: "capture-test".to_string(),
                acquisition: AcquisitionMode::Core,
                host_os: "linux".to_string(),
                kernel: "test".to_string(),
                captured_at: "unknown".to_string(),
            },
            required_features: Vec::new(),
            target: RuntimeTarget {
                architecture: Arch::X86_64,
                endianness: Endianness::Little,
                address_bits: 64,
                os_abi: "linux".to_string(),
            },
            executable: artifact.clone(),
            processes: vec![ProcessRecord {
                id: "process-main".to_string(),
                os_pid: 1,
                parent_id: None,
                terminal: Some(TerminalState::Running),
            }],
            modules: vec![ModuleInstance {
                id: "module-main".to_string(),
                process_id: "process-main".to_string(),
                artifact: artifact.clone(),
                load_bias: Some(0x7000_0000),
                mapping_ids: vec!["mapping-main".to_string()],
            }],
            mappings: vec![MappingRecord {
                id: "mapping-main".to_string(),
                process_id: "process-main".to_string(),
                start: 0x7000_0000,
                end: 0x7000_0000 + image.bytes().len() as u64,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: true,
                    private: true,
                },
                backing: MappingBacking::File {
                    artifact_sha256: hash,
                    deleted: false,
                },
                module_id: Some("module-main".to_string()),
                file_offset: Some(0),
            }],
            threads: Vec::new(),
            pages: Vec::new(),
            runtime_objects: Vec::new(),
            object_snapshots: Vec::new(),
            outputs: Vec::new(),
            descriptors: Vec::new(),
            events: Vec::new(),
            provenance: CaptureProvenance {
                producer: "correlation-test".to_string(),
                producer_version: "1".to_string(),
                command: Vec::new(),
                input_artifacts: vec![artifact],
                input_bytes: Vec::new(),
                warnings: Vec::new(),
            },
            completeness: Vec::new(),
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn exact_identity_and_file_offset_resolve_without_aslr_guessing() {
        let image = hello_image();
        let capsule = capsule(&image);
        let resolution = resolve_runtime_address(
            &capsule,
            &BTreeMap::new(),
            &image,
            "process-main",
            0x7000_2549,
        );
        let AddressResolution::Exact { address } = resolution else {
            panic!("expected exact resolution, got {resolution:?}");
        };
        assert_eq!(address.runtime_file_offset, 0x2549);
        assert_eq!(address.static_va, 0x2549);
        assert_eq!(address.module_relative, 0x2549);
        assert!(matches!(
            address.function,
            FunctionResolution::Exact {
                entry_va: 0x2549,
                ..
            }
        ));
        assert!(matches!(
            address.code,
            StaticCodeResolution::Resolved {
                instruction_relation: InstructionRelation::Exact,
                operations: OperationResolution::Resolved { .. },
                ..
            }
        ));
        assert_eq!(
            address.byte_status,
            RuntimeByteStatus::FileBackedNotCaptured
        );
        assert_eq!(address.runtime.module_id.as_deref(), Some("module-main"));
    }

    #[test]
    fn runtime_identity_graph_keeps_unowned_mappings_runtime_specific() {
        let image = hello_image();
        let mut capsule = capsule(&image);
        capsule.mappings.push(MappingRecord {
            id: "mapping-anonymous".to_string(),
            process_id: "process-main".to_string(),
            start: 0x7100_0000,
            end: 0x7100_1000,
            permissions: Permissions {
                read: true,
                write: true,
                execute: false,
                private: true,
            },
            backing: MappingBacking::Anonymous,
            module_id: None,
            file_offset: None,
        });
        let graph = runtime_identity_graph(&capsule, "process-main").expect("identity graph");
        assert_eq!(graph.capture_id, "capture-test");
        assert_eq!(graph.modules.len(), 1);
        assert_eq!(graph.mappings.len(), 2);
        let anonymous = graph
            .mappings
            .iter()
            .find(|mapping| mapping.mapping_id == "mapping-anonymous")
            .expect("anonymous mapping projection");
        assert_eq!(anonymous.module_id, None);
        assert_eq!(anonymous.backing, MappingBacking::Anonymous);
        assert!(runtime_identity_graph(&capsule, "missing-process").is_err());
    }

    #[test]
    fn runtime_pages_distinguish_unchanged_modified_anonymous_and_unknown() {
        let image = hello_image();
        let mut capsule = capsule(&image);
        let static_bytes = image.bytes()[..16].to_vec();
        let main_payload = "page-main".to_string();
        capsule.pages.push(PageRecord {
            process_id: "process-main".to_string(),
            mapping_id: "mapping-main".to_string(),
            start: 0x7000_0000,
            byte_len: 16,
            content: PageContent::Captured {
                payload: PayloadReference {
                    id: main_payload.clone(),
                    sha256: hex::encode(Sha256::digest(&static_bytes)),
                    byte_len: 16,
                    sensitivity: Sensitivity::Sensitive,
                },
            },
        });
        capsule.mappings.push(MappingRecord {
            id: "mapping-anonymous".to_string(),
            process_id: "process-main".to_string(),
            start: 0x7100_0000,
            end: 0x7100_1000,
            permissions: Permissions::default(),
            backing: MappingBacking::Anonymous,
            module_id: None,
            file_offset: None,
        });
        capsule.pages.push(PageRecord {
            process_id: "process-main".to_string(),
            mapping_id: "mapping-anonymous".to_string(),
            start: 0x7100_0000,
            byte_len: 16,
            content: PageContent::Omitted {
                reason: OmissionReason::NotRequested,
                detail: "test omission".to_string(),
            },
        });
        capsule.mappings.push(MappingRecord {
            id: "mapping-unknown".to_string(),
            process_id: "process-main".to_string(),
            start: 0x7200_0000,
            end: 0x7200_1000,
            permissions: Permissions::default(),
            backing: MappingBacking::Unknown {
                reason: "identity unavailable".to_string(),
            },
            module_id: None,
            file_offset: None,
        });
        capsule.pages.push(PageRecord {
            process_id: "process-main".to_string(),
            mapping_id: "mapping-unknown".to_string(),
            start: 0x7200_0000,
            byte_len: 16,
            content: PageContent::Omitted {
                reason: OmissionReason::ProviderUnsupported,
                detail: "test omission".to_string(),
            },
        });
        let mut payloads = BTreeMap::from([(main_payload.clone(), static_bytes.clone())]);
        let classified = classify_runtime_pages(&capsule, &payloads, &image, "process-main")
            .expect("classify pages");
        assert!(matches!(
            classified[0].kind,
            RuntimePageKind::FileBackedUnchanged { file_offset: 0, .. }
        ));
        assert_eq!(classified[1].kind, RuntimePageKind::Anonymous);
        assert!(matches!(
            classified[2].kind,
            RuntimePageKind::Unknown { .. }
        ));

        let mut modified = static_bytes;
        modified[5] ^= 0xff;
        payloads.insert(main_payload, modified.clone());
        if let PageContent::Captured { payload } = &mut capsule.pages[0].content {
            payload.sha256 = hex::encode(Sha256::digest(&modified));
        }
        let classified = classify_runtime_pages(&capsule, &payloads, &image, "process-main")
            .expect("classify modified page");
        assert!(matches!(
            classified[0].kind,
            RuntimePageKind::FileBackedModified {
                changed_byte_count: 1,
                first_changed_offset: 5,
                ..
            }
        ));
    }

    #[test]
    fn same_basename_wrong_image_and_overlapping_mappings_fail_closed() {
        let image = hello_image();
        let mut wrong = capsule(&image);
        assert_eq!(
            wrong.modules[0].artifact.display_path.as_deref(),
            Some("/exact/hello")
        );
        wrong.modules[0].artifact.sha256 = "f".repeat(64);
        wrong.mappings[0].backing = MappingBacking::File {
            artifact_sha256: "f".repeat(64),
            deleted: false,
        };
        assert!(matches!(
            resolve_runtime_address(
                &wrong,
                &BTreeMap::new(),
                &image,
                "process-main",
                0x7000_2549
            ),
            AddressResolution::WrongImage { .. }
        ));

        let mut ambiguous = capsule(&image);
        let mut second = ambiguous.mappings[0].clone();
        second.id = "mapping-alias".to_string();
        ambiguous.modules[0].mapping_ids.push(second.id.clone());
        ambiguous.mappings.push(second);
        let AddressResolution::Ambiguous { mapping_ids } = resolve_runtime_address(
            &ambiguous,
            &BTreeMap::new(),
            &image,
            "process-main",
            0x7000_2549,
        ) else {
            panic!("overlapping mappings must be ambiguous");
        };
        assert_eq!(mapping_ids, ["mapping-alias", "mapping-main"]);
    }

    #[test]
    fn duplicate_disjoint_loads_keep_instance_identity_and_share_static_va() {
        let image = hello_image();
        let mut duplicate = capsule(&image);
        let mut second_mapping = duplicate.mappings[0].clone();
        second_mapping.id = "mapping-second-load".to_string();
        second_mapping.start = 0x7100_0000;
        second_mapping.end = second_mapping.start + image.bytes().len() as u64;
        second_mapping.module_id = Some("module-second-load".to_string());
        let mut second_module = duplicate.modules[0].clone();
        second_module.id = "module-second-load".to_string();
        second_module.load_bias = Some(second_mapping.start);
        second_module.mapping_ids = vec![second_mapping.id.clone()];
        duplicate.modules.push(second_module);
        duplicate.mappings.push(second_mapping);
        duplicate
            .validate(CapsuleLimits::default())
            .expect("two disjoint instances of one artifact are valid");

        let AddressResolution::Exact { address: first } = resolve_runtime_address(
            &duplicate,
            &BTreeMap::new(),
            &image,
            "process-main",
            0x7000_2549,
        ) else {
            panic!("first module instance must resolve");
        };
        let AddressResolution::Exact { address: second } = resolve_runtime_address(
            &duplicate,
            &BTreeMap::new(),
            &image,
            "process-main",
            0x7100_2549,
        ) else {
            panic!("second module instance must resolve");
        };
        assert_eq!(first.static_va, second.static_va);
        assert_eq!(first.runtime.module_id.as_deref(), Some("module-main"));
        assert_eq!(
            second.runtime.module_id.as_deref(),
            Some("module-second-load")
        );
        assert_eq!(first.runtime.mapping_id, "mapping-main");
        assert_eq!(second.runtime.mapping_id, "mapping-second-load");
        assert_ne!(first.runtime.raw_va, second.runtime.raw_va);
    }

    #[test]
    fn missing_and_omitted_code_pages_never_claim_runtime_bytes() {
        let image = hello_image();
        let mut capsule = capsule(&image);
        let raw_va = 0x7000_2549;
        let AddressResolution::Exact { address } =
            resolve_runtime_address(&capsule, &BTreeMap::new(), &image, "process-main", raw_va)
        else {
            panic!("address identity does not require captured page bytes");
        };
        assert_eq!(
            address.byte_status,
            RuntimeByteStatus::FileBackedNotCaptured
        );

        capsule.pages.push(PageRecord {
            process_id: "process-main".to_string(),
            mapping_id: "mapping-main".to_string(),
            start: raw_va,
            byte_len: 1,
            content: PageContent::Omitted {
                reason: OmissionReason::ProviderUnsupported,
                detail: "core omitted clean executable page".to_string(),
            },
        });
        let AddressResolution::Exact { address } =
            resolve_runtime_address(&capsule, &BTreeMap::new(), &image, "process-main", raw_va)
        else {
            panic!("explicit page omission retains address identity");
        };
        assert_eq!(
            address.byte_status,
            RuntimeByteStatus::Omitted {
                reason: OmissionReason::ProviderUnsupported,
                detail: "core omitted clean executable page".to_string(),
            }
        );
    }

    #[test]
    fn captured_code_byte_is_compared_without_mutating_the_static_image() {
        let image = hello_image();
        let mut capsule = capsule(&image);
        let raw_va = 0x7000_2549;
        let static_byte = image.bytes()[0x2549];
        let payload_id = "page-code".to_string();
        capsule.pages.push(PageRecord {
            process_id: "process-main".to_string(),
            mapping_id: "mapping-main".to_string(),
            start: raw_va,
            byte_len: 1,
            content: PageContent::Captured {
                payload: PayloadReference {
                    id: payload_id.clone(),
                    sha256: hex::encode(Sha256::digest([static_byte])),
                    byte_len: 1,
                    sensitivity: Sensitivity::Sensitive,
                },
            },
        });
        let mut payloads = BTreeMap::from([(payload_id.clone(), vec![static_byte])]);
        let AddressResolution::Exact { address } =
            resolve_runtime_address(&capsule, &payloads, &image, "process-main", raw_va)
        else {
            panic!("matching captured byte must resolve");
        };
        assert_eq!(
            address.byte_status,
            RuntimeByteStatus::CapturedMatchesStatic {
                payload_id: payload_id.clone()
            }
        );

        let modified = static_byte ^ 0xff;
        payloads.insert(payload_id.clone(), vec![modified]);
        let AddressResolution::Exact { address } =
            resolve_runtime_address(&capsule, &payloads, &image, "process-main", raw_va)
        else {
            panic!("invalid payload must retain address relation");
        };
        assert!(matches!(
            address.byte_status,
            RuntimeByteStatus::CapturedPayloadInvalid { .. }
        ));
        assert!(matches!(
            address.code,
            StaticCodeResolution::Missing { ref reason }
                if reason.contains("unavailable or invalid")
        ));
        if let PageContent::Captured { payload } = &mut capsule.pages[0].content {
            payload.sha256 = hex::encode(Sha256::digest([modified]));
        }
        let AddressResolution::Exact { address } =
            resolve_runtime_address(&capsule, &payloads, &image, "process-main", raw_va)
        else {
            panic!("modified captured byte still resolves with contrary evidence");
        };
        assert_eq!(
            address.byte_status,
            RuntimeByteStatus::CapturedDiffersFromStatic {
                payload_id,
                runtime_byte: modified,
                static_byte,
            }
        );
        assert!(matches!(
            address.code,
            StaticCodeResolution::Missing { ref reason }
                if reason.contains("stale file semantics withheld")
        ));
        assert_eq!(image.bytes()[0x2549], static_byte);
    }
}
