//! Cross-checks for MIR memory-object and access-path identities.

use crate::ir::memory_objects::{AccessRole, AccessSource, MemoryStateIdentity, ObjectIdentity};

use super::model::MirFunction;

pub(super) fn verify_objects(function: &MirFunction, errors: &mut Vec<String>) {
    for (index, access) in function.memory_accesses.iter().enumerate() {
        let Some(object_id) = access.object else {
            continue;
        };
        let Some(object) = function.object_model.object(object_id) else {
            errors.push(format!(
                "memory access {index} has invalid object {}",
                object_id.0
            ));
            continue;
        };
        if !object
            .accesses
            .iter()
            .any(|path| path.mir_access == Some(access.id))
        {
            errors.push(format!(
                "memory access {index} is orphaned from object {}",
                object.id.0
            ));
        }
    }

    for (index, object) in function.objects().iter().enumerate() {
        if object.id.0 != index {
            errors.push(format!(
                "object id {} does not match arena index {index}",
                object.id.0
            ));
        }
        if function
            .object_model
            .object_for_identity(&object.identity)
            .is_none_or(|indexed| indexed.id != object.id)
        {
            errors.push(format!("object {index} identity index is inconsistent"));
        }
        verify_access_paths(function, index, object, errors);
    }
}

fn verify_access_paths(
    function: &MirFunction,
    object_index: usize,
    object: &crate::ir::memory_objects::MemoryObject,
    errors: &mut Vec<String>,
) {
    for path in &object.accesses {
        if path.object != object.id {
            errors.push(format!(
                "object {object_index} has an access ownership mismatch"
            ));
        }
        if let ObjectIdentity::MirValue(value) = path.cursor {
            if value.0 >= function.values.len() {
                errors.push(format!(
                    "object {object_index} access has invalid cursor value {}",
                    value.0
                ));
            } else if function
                .object_model
                .object_for_identity(&path.cursor)
                .is_none_or(|indexed| indexed.id != object.id)
            {
                errors.push(format!(
                    "object {object_index} cursor value {} is not indexed to its owner",
                    value.0
                ));
            }
        }
        verify_mir_access(function, object_index, object.id, path, errors);
    }
}

fn verify_mir_access(
    function: &MirFunction,
    object_index: usize,
    object_id: crate::ir::memory_objects::ObjectId,
    path: &crate::ir::memory_objects::AccessPath,
    errors: &mut Vec<String>,
) {
    let Some(access_id) = path.mir_access else {
        errors.push(format!("object {object_index} has a non-MIR access path"));
        return;
    };
    let Some(access) = function.memory_accesses.get(access_id.0) else {
        errors.push(format!(
            "object {object_index} has invalid memory access {}",
            access_id.0
        ));
        return;
    };
    if access.object != Some(object_id) {
        errors.push(format!(
            "object {object_index} access {} has an inconsistent backreference",
            access_id.0
        ));
    }
    if path.memory_region != Some(access.region) {
        errors.push(format!(
            "object {object_index} access {} has a memory region mismatch",
            access_id.0
        ));
    }
    let expected_state = match path.role {
        AccessRole::Read => Some(MemoryStateIdentity::Mir(access.input)),
        AccessRole::Write => access.output.map(MemoryStateIdentity::Mir),
    };
    if path.memory_state != expected_state {
        errors.push(format!(
            "object {object_index} access {} has a memory state mismatch",
            access_id.0
        ));
    }
    if path.source != AccessSource::MirInstruction(access.instruction) {
        errors.push(format!(
            "object {object_index} access {} has an instruction mismatch",
            access_id.0
        ));
    }
}
