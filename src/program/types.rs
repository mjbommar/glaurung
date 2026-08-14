//! Interned, provenance-bearing program type environment.

use std::collections::{BTreeMap, BTreeSet};

use crate::core::DataType;

mod dwarf;
mod import;
mod verify;

/// Stable arena identity for one program type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeId(pub usize);

/// Authority order for selecting among conflicting type facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TypeAuthority {
    Inference,
    Binary,
    Debug,
    Analyst,
}

/// Provenance attached to one type fact.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeEvidence {
    pub authority: TypeAuthority,
    pub source: String,
    pub format_source: Option<String>,
}

impl TypeEvidence {
    pub fn new(authority: TypeAuthority, source: impl Into<String>) -> Self {
        Self {
            authority,
            source: source.into(),
            format_source: None,
        }
    }

    fn for_data_type(&self, data_type: &DataType) -> Self {
        let mut evidence = self.clone();
        evidence.format_source = data_type.source.clone();
        evidence
    }
}

/// A field whose referenced type has been resolved into this store.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeField {
    pub name: String,
    pub type_id: TypeId,
    pub offset: u64,
}

/// An enum member retained independently of language spelling.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeEnumMember {
    pub name: String,
    pub value: i64,
}

/// Recursive, language-neutral type shape.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TypeShape {
    Primitive {
        name: String,
        size: u64,
        alignment: Option<u64>,
    },
    Pointer {
        pointee: TypeId,
        size: u64,
        alignment: Option<u64>,
        attributes: Vec<String>,
    },
    Array {
        element: TypeId,
        count: u64,
        size: u64,
        alignment: Option<u64>,
    },
    Struct {
        fields: Vec<TypeField>,
        size: u64,
        alignment: Option<u64>,
    },
    Union {
        fields: Vec<TypeField>,
        size: u64,
        alignment: Option<u64>,
    },
    Enum {
        underlying: TypeId,
        members: Vec<TypeEnumMember>,
        size: u64,
        alignment: Option<u64>,
    },
    Function {
        result: Option<TypeId>,
        parameters: Vec<TypeId>,
        variadic: bool,
    },
    Typedef {
        target: TypeId,
    },
}

impl TypeShape {
    fn referenced_types(&self) -> Vec<TypeId> {
        match self {
            Self::Primitive { .. } => Vec::new(),
            Self::Pointer { pointee, .. } => vec![*pointee],
            Self::Array { element, .. } => vec![*element],
            Self::Struct { fields, .. } | Self::Union { fields, .. } => {
                fields.iter().map(|field| field.type_id).collect()
            }
            Self::Enum { underlying, .. } => vec![*underlying],
            Self::Function {
                result, parameters, ..
            } => result
                .iter()
                .copied()
                .chain(parameters.iter().copied())
                .collect(),
            Self::Typedef { target } => vec![*target],
        }
    }
}

/// A retained failure or disagreement; conflicts never silently mutate the
/// selected fact.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TypeConflict {
    InvalidDefinition,
    MissingReference(String),
    IncompatibleDefinition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TypeFact {
    shape: TypeShape,
    evidence: Vec<TypeEvidence>,
}

impl TypeFact {
    fn new(shape: TypeShape, evidence: TypeEvidence) -> Self {
        Self {
            shape,
            evidence: vec![evidence],
        }
    }

    fn authority(&self) -> TypeAuthority {
        self.evidence
            .iter()
            .map(|evidence| evidence.authority)
            .max()
            .unwrap_or(TypeAuthority::Inference)
    }

    fn add_evidence(&mut self, evidence: TypeEvidence) {
        if !self.evidence.contains(&evidence) {
            self.evidence.push(evidence);
            self.evidence.sort();
        }
    }
}

/// One selected type plus alternatives and explicit conflicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeRecord {
    pub id: TypeId,
    external_ids: BTreeSet<String>,
    names: BTreeSet<String>,
    selected: Option<TypeFact>,
    alternatives: Vec<TypeFact>,
    conflicts: BTreeSet<TypeConflict>,
}

impl TypeRecord {
    pub fn selected_shape(&self) -> Option<&TypeShape> {
        self.selected.as_ref().map(|fact| &fact.shape)
    }

    pub fn evidence(&self) -> &[TypeEvidence] {
        self.selected
            .as_ref()
            .map(|fact| fact.evidence.as_slice())
            .unwrap_or_default()
    }

    pub fn alternatives(&self) -> impl ExactSizeIterator<Item = &TypeShape> {
        self.alternatives.iter().map(|fact| &fact.shape)
    }

    pub fn conflicts(&self) -> &BTreeSet<TypeConflict> {
        &self.conflicts
    }
}

/// Result of one deterministic import batch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TypeImportReport {
    pub imported: BTreeMap<String, TypeId>,
    pub conflicts: Vec<(TypeId, TypeConflict)>,
}

/// Function-qualified identity of one stable MIR memory object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectTypeKey {
    pub function_entry: u64,
    pub object: crate::ir::mir::ObjectId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObjectTypeFact {
    type_id: TypeId,
    evidence: Vec<TypeEvidence>,
}

impl ObjectTypeFact {
    fn new(type_id: TypeId, evidence: TypeEvidence) -> Self {
        Self {
            type_id,
            evidence: vec![evidence],
        }
    }

    fn authority(&self) -> TypeAuthority {
        self.evidence
            .iter()
            .map(|evidence| evidence.authority)
            .max()
            .unwrap_or(TypeAuthority::Inference)
    }

    fn add_evidence(&mut self, evidence: TypeEvidence) {
        if !self.evidence.contains(&evidence) {
            self.evidence.push(evidence);
            self.evidence.sort();
        }
    }
}

/// Selected type for a MIR object plus retained conflicting alternatives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectTypeRecord {
    selected: ObjectTypeFact,
    alternatives: Vec<ObjectTypeFact>,
}

impl ObjectTypeRecord {
    pub fn selected(&self) -> TypeId {
        self.selected.type_id
    }

    pub fn evidence(&self) -> &[TypeEvidence] {
        &self.selected.evidence
    }

    pub fn alternatives(&self) -> impl ExactSizeIterator<Item = TypeId> + '_ {
        self.alternatives.iter().map(|fact| fact.type_id)
    }
}

/// Failure to attach a type to a stable object identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TypeBindingError {
    #[error("unknown type identity")]
    UnknownType,
    #[error("type identity has no valid selected definition")]
    UnresolvedType,
}

/// Fail-closed rejection of an anonymous inferred shape.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TypeStoreError {
    #[error("type shape references unknown type {0:?}")]
    UnknownReference(TypeId),
    #[error("type shape references unresolved type {0:?}")]
    UnresolvedReference(TypeId),
    #[error("invalid inferred type shape: {0}")]
    InvalidShape(&'static str),
}

/// Program-owned recursive type arena. Nominal external declarations reserve
/// identities before resolution; anonymous inferred shapes are interned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TypeStore {
    records: Vec<TypeRecord>,
    by_external: BTreeMap<String, TypeId>,
    anonymous_by_shape: BTreeMap<TypeShape, TypeId>,
    object_types: BTreeMap<ObjectTypeKey, ObjectTypeRecord>,
    revision: u64,
}

fn unique_nonempty_names<'a>(mut names: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    names.all(|name| !name.trim().is_empty() && seen.insert(name))
}

fn fields_are_valid(fields: &[TypeField], size: u64, union: bool) -> bool {
    size != 0
        && unique_nonempty_names(fields.iter().map(|field| field.name.as_str()))
        && fields
            .iter()
            .all(|field| field.offset < size && (!union || field.offset == 0))
}

impl TypeStore {
    pub fn records(&self) -> &[TypeRecord] {
        &self.records
    }

    pub fn get(&self, id: TypeId) -> Option<&TypeRecord> {
        self.records.get(id.0)
    }

    pub fn resolve_external(&self, external_id: &str) -> Option<TypeId> {
        self.by_external.get(external_id).copied()
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn object_type(&self, key: ObjectTypeKey) -> Option<&ObjectTypeRecord> {
        self.object_types.get(&key)
    }

    pub fn bind_object_type(
        &mut self,
        key: ObjectTypeKey,
        type_id: TypeId,
        evidence: TypeEvidence,
    ) -> Result<(), TypeBindingError> {
        let Some(type_record) = self.records.get(type_id.0) else {
            return Err(TypeBindingError::UnknownType);
        };
        if type_record.selected.is_none() {
            return Err(TypeBindingError::UnresolvedType);
        }
        let Some(binding) = self.object_types.get_mut(&key) else {
            self.object_types.insert(
                key,
                ObjectTypeRecord {
                    selected: ObjectTypeFact::new(type_id, evidence),
                    alternatives: Vec::new(),
                },
            );
            self.revision = self.revision.saturating_add(1);
            return Ok(());
        };
        if binding.selected.type_id == type_id {
            let before = binding.selected.evidence.len();
            binding.selected.add_evidence(evidence);
            if binding.selected.evidence.len() != before {
                self.revision = self.revision.saturating_add(1);
            }
            return Ok(());
        }
        if let Some(alternative) = binding
            .alternatives
            .iter_mut()
            .find(|alternative| alternative.type_id == type_id)
        {
            let before = alternative.evidence.len();
            alternative.add_evidence(evidence);
            if alternative.evidence.len() != before {
                self.revision = self.revision.saturating_add(1);
            }
            return Ok(());
        }
        let candidate = ObjectTypeFact::new(type_id, evidence);
        if candidate.authority() > binding.selected.authority() {
            let old = std::mem::replace(&mut binding.selected, candidate);
            binding.alternatives.push(old);
        } else {
            binding.alternatives.push(candidate);
        }
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    pub fn intern_anonymous(
        &mut self,
        shape: TypeShape,
        evidence: TypeEvidence,
    ) -> Result<TypeId, TypeStoreError> {
        self.validate_anonymous_shape(&shape)?;
        if let Some(id) = self.anonymous_by_shape.get(&shape).copied() {
            if let Some(selected) = self.records[id.0].selected.as_mut() {
                let before = selected.evidence.len();
                selected.add_evidence(evidence);
                if selected.evidence.len() != before {
                    self.revision = self.revision.saturating_add(1);
                }
            }
            return Ok(id);
        }
        let id = TypeId(self.records.len());
        self.records.push(TypeRecord {
            id,
            external_ids: BTreeSet::new(),
            names: BTreeSet::new(),
            selected: Some(TypeFact::new(shape.clone(), evidence)),
            alternatives: Vec::new(),
            conflicts: BTreeSet::new(),
        });
        self.anonymous_by_shape.insert(shape, id);
        self.revision = self.revision.saturating_add(1);
        Ok(id)
    }

    fn validate_anonymous_shape(&self, shape: &TypeShape) -> Result<(), TypeStoreError> {
        for reference in shape.referenced_types() {
            let Some(record) = self.records.get(reference.0) else {
                return Err(TypeStoreError::UnknownReference(reference));
            };
            if record.selected.is_none() {
                return Err(TypeStoreError::UnresolvedReference(reference));
            }
        }
        let valid_alignment = |alignment: Option<u64>| {
            alignment.is_none_or(|alignment| alignment != 0 && alignment.is_power_of_two())
        };
        match shape {
            TypeShape::Primitive {
                name,
                size,
                alignment,
            } if !name.trim().is_empty()
                && matches!(size, 1 | 2 | 4 | 8 | 16)
                && valid_alignment(*alignment) => {}
            TypeShape::Pointer {
                size, alignment, ..
            } if *size != 0 && *size <= 16 && valid_alignment(*alignment) => {}
            TypeShape::Array {
                count,
                size,
                alignment,
                ..
            } if *count != 0 && *size != 0 && valid_alignment(*alignment) => {}
            TypeShape::Struct {
                fields,
                size,
                alignment,
            } if fields_are_valid(fields, *size, false) && valid_alignment(*alignment) => {}
            TypeShape::Union {
                fields,
                size,
                alignment,
            } if fields_are_valid(fields, *size, true) && valid_alignment(*alignment) => {}
            TypeShape::Enum {
                members,
                size,
                alignment,
                ..
            } if *size != 0
                && valid_alignment(*alignment)
                && unique_nonempty_names(members.iter().map(|member| member.name.as_str())) => {}
            TypeShape::Function { .. } | TypeShape::Typedef { .. } => {}
            _ => {
                return Err(TypeStoreError::InvalidShape(
                    "shape invariants are not satisfied",
                ))
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "types_tests.rs"]
mod tests;
