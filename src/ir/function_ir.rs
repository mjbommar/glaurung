//! Stable identities for the shared function-semantic graph.
//!
//! This is the deliberately small nucleus of the planned `FunctionIR`.  It
//! belongs to static analysis: runtime captures may refer to these identities,
//! but execution, process, thread, time, and concrete values must never enter
//! their derivation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn identity(prefix: &str, domain: &[u8], components: &[String]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    for component in components {
        digest.update(component.as_bytes());
        digest.update([0]);
    }
    format!("{prefix}-{}", hex::encode(digest.finalize()))
}

/// Canonical identity of one function in an immutable analysis generation.
pub fn function_id(image_sha256: &str, lift_profile: &str, function_entry: u64) -> String {
    identity(
        "static-function",
        b"glaurung-static-function-v1",
        &[
            image_sha256.to_string(),
            lift_profile.to_string(),
            format!("{function_entry:016x}"),
        ],
    )
}

/// Canonical identity of one LLIR block under its static function.
pub fn block_id(function_id: &str, block_start: u64) -> String {
    identity(
        "static-block",
        b"glaurung-static-block-v1",
        &[function_id.to_string(), format!("{block_start:016x}")],
    )
}

/// Canonical identity of one source variable declaration proved by DWARF.
///
/// The DIE offset is image-relative debug provenance, not a runtime address or
/// a rendered variable name. Optimized location ranges may therefore change
/// without changing the declaration identity.
pub fn dwarf_variable_id(image_sha256: &str, declaration_debug_info_offset: u64) -> String {
    identity(
        "static-variable",
        b"glaurung-static-dwarf-variable-v1",
        &[
            image_sha256.to_string(),
            format!("{declaration_debug_info_offset:016x}"),
        ],
    )
}

/// Canonical identity of one type DIE in an immutable image.
pub fn dwarf_type_id(image_sha256: &str, type_debug_info_offset: u64) -> String {
    identity(
        "static-type",
        b"glaurung-static-dwarf-type-v1",
        &[
            image_sha256.to_string(),
            format!("{type_debug_info_offset:016x}"),
        ],
    )
}

/// One immutable source-variable node in the function semantic graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticVariable {
    pub id: String,
    pub function_id: String,
    pub image_sha256: String,
    pub source_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_id: Option<String>,
    pub origin: StaticVariableOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StaticVariableOrigin {
    Dwarf {
        declaration_debug_info_offset: u64,
    },
    AbiArgument {
        position: usize,
        recovery_profile: String,
    },
    FrameStorage {
        base: String,
        displacement: i64,
        recovery_profile: String,
    },
}

/// Structural shape of a recovered type. Presentation spelling is deliberately
/// absent: two renderers may spell the same shape differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RecoveredTypeShape {
    Integer {
        signed: bool,
        width: u8,
    },
    Float {
        width: u8,
    },
    DataPointer {
        pointee_width: u8,
        pointer_width: u8,
    },
    BoolLike,
    CodePointer {
        pointer_width: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StaticTypeOrigin {
    Dwarf {
        type_debug_info_offset: u64,
    },
    Recovered {
        shape: RecoveredTypeShape,
        recovery_profile: String,
    },
}

/// One immutable type node in the shared semantic graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticType {
    pub id: String,
    pub image_sha256: String,
    /// Presentation spelling retained as an attribute, never as identity.
    pub c_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_debug_info_offset: Option<u64>,
    pub origin: StaticTypeOrigin,
}

/// A static graph edge from one operation value to a source variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticValueVariableBinding {
    pub id: String,
    pub semantic_value_id: String,
    pub variable_id: String,
    pub relation: String,
}

pub fn dwarf_static_type(
    image_sha256: &str,
    type_debug_info_offset: u64,
    c_type: &str,
) -> StaticType {
    StaticType {
        id: dwarf_type_id(image_sha256, type_debug_info_offset),
        image_sha256: image_sha256.to_string(),
        c_type: c_type.to_string(),
        type_debug_info_offset: Some(type_debug_info_offset),
        origin: StaticTypeOrigin::Dwarf {
            type_debug_info_offset,
        },
    }
}

pub fn recovered_static_type(
    image_sha256: &str,
    shape: RecoveredTypeShape,
    c_type: &str,
    recovery_profile: &str,
) -> StaticType {
    let shape_key = match shape {
        RecoveredTypeShape::Integer { signed, width } => format!("integer:{signed}:{width}"),
        RecoveredTypeShape::Float { width } => format!("float:{width}"),
        RecoveredTypeShape::DataPointer {
            pointee_width,
            pointer_width,
        } => format!("data-pointer:{pointer_width}:{pointee_width}"),
        RecoveredTypeShape::BoolLike => "bool-like".to_string(),
        RecoveredTypeShape::CodePointer { pointer_width } => {
            format!("code-pointer:{pointer_width}")
        }
    };
    StaticType {
        id: identity(
            "static-type",
            b"glaurung-static-recovered-type-v1",
            &[
                image_sha256.to_string(),
                recovery_profile.to_string(),
                shape_key,
            ],
        ),
        image_sha256: image_sha256.to_string(),
        c_type: c_type.to_string(),
        type_debug_info_offset: None,
        origin: StaticTypeOrigin::Recovered {
            shape,
            recovery_profile: recovery_profile.to_string(),
        },
    }
}

pub fn dwarf_static_variable(
    image_sha256: &str,
    function_id: &str,
    declaration_debug_info_offset: u64,
    source_name: &str,
    type_id: &str,
) -> StaticVariable {
    StaticVariable {
        id: dwarf_variable_id(image_sha256, declaration_debug_info_offset),
        function_id: function_id.to_string(),
        image_sha256: image_sha256.to_string(),
        source_name: source_name.to_string(),
        type_id: Some(type_id.to_string()),
        origin: StaticVariableOrigin::Dwarf {
            declaration_debug_info_offset,
        },
    }
}

/// Mint a recovered high-variable node from storage evidence, never spelling.
pub fn recovered_static_variable(
    image_sha256: &str,
    function_id: &str,
    source_name: &str,
    type_id: Option<&str>,
    origin: StaticVariableOrigin,
) -> StaticVariable {
    let origin_key = match &origin {
        StaticVariableOrigin::Dwarf {
            declaration_debug_info_offset,
        } => format!("dwarf:{declaration_debug_info_offset:016x}"),
        StaticVariableOrigin::AbiArgument {
            position,
            recovery_profile,
        } => format!("abi-argument:{recovery_profile}:{position}"),
        StaticVariableOrigin::FrameStorage {
            base,
            displacement,
            recovery_profile,
        } => format!("frame-storage:{recovery_profile}:{base}:{displacement}"),
    };
    StaticVariable {
        id: identity(
            "static-variable",
            b"glaurung-static-recovered-variable-v1",
            &[function_id.to_string(), origin_key],
        ),
        function_id: function_id.to_string(),
        image_sha256: image_sha256.to_string(),
        source_name: source_name.to_string(),
        type_id: type_id.map(str::to_string),
        origin,
    }
}

pub fn semantic_value_variable_binding(
    semantic_value_id: &str,
    variable_id: &str,
    relation: &str,
) -> SemanticValueVariableBinding {
    SemanticValueVariableBinding {
        id: identity(
            "static-value-variable-binding",
            b"glaurung-static-value-variable-binding-v1",
            &[
                semantic_value_id.to_string(),
                variable_id.to_string(),
                relation.to_string(),
            ],
        ),
        semantic_value_id: semantic_value_id.to_string(),
        variable_id: variable_id.to_string(),
        relation: relation.to_string(),
    }
}

/// A semantic expression owned by one static operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationExpressionRole {
    MemoryAddress,
    StoredValue,
    Condition,
    DefinedValue,
    CallTarget,
    CallInput(usize),
}

/// A semantic operand value owned by one static operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationValueRole {
    MemoryAddress,
    StoredValue,
    Condition,
    DefinedValue,
    CallTarget,
    CallInput(usize),
}

impl OperationValueRole {
    pub fn name(self) -> String {
        match self {
            Self::MemoryAddress => "memory_address".to_string(),
            Self::StoredValue => "stored_value".to_string(),
            Self::Condition => "condition".to_string(),
            Self::DefinedValue => "defined_value".to_string(),
            Self::CallTarget => "call_target".to_string(),
            Self::CallInput(position) => format!("call_input_{position}"),
        }
    }
}

/// Canonical identity of one semantic operand value under an operation.
pub fn value_id(operation_id: &str, role: OperationValueRole) -> String {
    identity(
        "static-value",
        b"glaurung-static-value-v1",
        &[operation_id.to_string(), role.name()],
    )
}

impl OperationExpressionRole {
    fn name(self) -> String {
        match self {
            Self::MemoryAddress => "memory_address".to_string(),
            Self::StoredValue => "stored_value".to_string(),
            Self::Condition => "condition".to_string(),
            Self::DefinedValue => "defined_value".to_string(),
            Self::CallTarget => "call_target".to_string(),
            Self::CallInput(position) => format!("call_input_{position}"),
        }
    }
}

/// Canonical identity of a root semantic expression under one operation.
///
/// Nested expression-node paths will extend this namespace; this first form
/// intentionally identifies roots only and must not be presented as token
/// identity.
pub fn expression_id(operation_id: &str, role: OperationExpressionRole) -> String {
    identity(
        "static-expression",
        b"glaurung-static-expression-v1",
        &[operation_id.to_string(), role.name()],
    )
}

/// Canonical identity of a nested expression node under a semantic root.
/// `path` is a typed child path such as `left/address`, never a display token.
pub fn expression_node_id(root_id: &str, path: &str) -> String {
    if path.is_empty() {
        return root_id.to_string();
    }
    identity(
        "static-expression-node",
        b"glaurung-static-expression-node-v1",
        &[root_id.to_string(), path.to_string()],
    )
}

/// Canonical identity of one operation in an immutable function-IR generation.
///
/// The operation kind is a fail-closed schema guard. If a new lifter changes
/// the meaning at an otherwise identical coordinate, it cannot silently reuse
/// the old identity; the lift profile must also change when generation rules
/// change incompatibly.
pub fn operation_id(
    image_sha256: &str,
    function_entry: u64,
    lift_profile: &str,
    block_start: u64,
    operation_index: usize,
    kind: &str,
) -> String {
    let function_id = function_id(image_sha256, lift_profile, function_entry);
    let block_id = block_id(&function_id, block_start);
    identity(
        "static-operation",
        b"glaurung-static-operation-v1",
        &[block_id, operation_index.to_string(), kind.to_string()],
    )
}

#[cfg(test)]
mod tests {
    use super::{
        block_id, dwarf_static_type, dwarf_static_variable, dwarf_type_id, dwarf_variable_id,
        expression_id, expression_node_id, function_id, operation_id, recovered_static_type,
        recovered_static_variable, semantic_value_variable_binding, value_id,
        OperationExpressionRole, OperationValueRole, RecoveredTypeShape, StaticTypeOrigin,
        StaticVariableOrigin,
    };

    #[test]
    fn operation_identity_is_deterministic_and_generation_scoped() {
        let make = |profile: &str, index: usize, kind: &str| {
            operation_id(&"ab".repeat(32), 0x401000, profile, 0x401020, index, kind)
        };
        assert_eq!(make("raw-v1", 3, "store"), make("raw-v1", 3, "store"));
        assert_ne!(make("raw-v1", 3, "store"), make("raw-v2", 3, "store"));
        assert_ne!(make("raw-v1", 3, "store"), make("raw-v1", 4, "store"));
        assert_ne!(make("raw-v1", 3, "store"), make("raw-v1", 3, "load"));
        let function = function_id(&"ab".repeat(32), "raw-v1", 0x401000);
        let block = block_id(&function, 0x401020);
        assert!(function.starts_with("static-function-"));
        assert!(block.starts_with("static-block-"));
        let operation = make("raw-v1", 3, "store");
        let address = expression_id(&operation, OperationExpressionRole::MemoryAddress);
        let value = expression_id(&operation, OperationExpressionRole::StoredValue);
        assert!(address.starts_with("static-expression-"));
        assert_ne!(address, value);
        assert_eq!(expression_node_id(&address, ""), address);
        assert_ne!(
            expression_node_id(&address, "left"),
            expression_node_id(&address, "right")
        );
        assert!(dwarf_variable_id(&"ab".repeat(32), 0x44).starts_with("static-variable-"));
        assert!(dwarf_type_id(&"ab".repeat(32), 0x55).starts_with("static-type-"));
        assert_ne!(
            dwarf_variable_id(&"ab".repeat(32), 0x44),
            dwarf_variable_id(&"ab".repeat(32), 0x45)
        );
        let static_type = dwarf_static_type(&"ab".repeat(32), 0x55, "int *");
        let static_variable = dwarf_static_variable(
            &"ab".repeat(32),
            &function,
            0x44,
            "pointer",
            &static_type.id,
        );
        let binding = semantic_value_variable_binding(
            &value_id(&operation, OperationValueRole::MemoryAddress),
            &static_variable.id,
            "reads_pointer_value_from",
        );
        assert_eq!(
            static_variable.type_id.as_deref(),
            Some(static_type.id.as_str())
        );
        assert_eq!(binding.variable_id, static_variable.id);
        assert!(binding.id.starts_with("static-value-variable-binding-"));
        let argument = recovered_static_variable(
            &"ab".repeat(32),
            &function,
            "renamed_argument",
            None,
            StaticVariableOrigin::AbiArgument {
                position: 0,
                recovery_profile: "high-variable-v1".to_string(),
            },
        );
        let same_storage_different_name = recovered_static_variable(
            &"ab".repeat(32),
            &function,
            "arg0",
            None,
            StaticVariableOrigin::AbiArgument {
                position: 0,
                recovery_profile: "high-variable-v1".to_string(),
            },
        );
        assert_eq!(argument.id, same_storage_different_name.id);
        let recovered_type = recovered_static_type(
            &"ab".repeat(32),
            RecoveredTypeShape::Integer {
                signed: true,
                width: 4,
            },
            "int",
            "glaurung-recovered-type-v1",
        );
        let same_shape_different_spelling = recovered_static_type(
            &"ab".repeat(32),
            RecoveredTypeShape::Integer {
                signed: true,
                width: 4,
            },
            "signed int",
            "glaurung-recovered-type-v1",
        );
        assert_eq!(recovered_type.id, same_shape_different_spelling.id);
        assert_ne!(recovered_type.c_type, same_shape_different_spelling.c_type);
        assert!(matches!(
            recovered_type.origin,
            StaticTypeOrigin::Recovered { .. }
        ));
        assert_ne!(
            value_id(&operation, OperationValueRole::MemoryAddress),
            value_id(&operation, OperationValueRole::StoredValue)
        );
        assert_ne!(
            value_id(&operation, OperationValueRole::CallInput(0)),
            value_id(&operation, OperationValueRole::CallInput(1))
        );
    }
}
