//! Deterministic `core::DataType` import and conflict selection.

use std::collections::BTreeSet;

use crate::core::{DataType, DataTypeKind, TypeData};

use super::{
    TypeConflict, TypeEnumMember, TypeEvidence, TypeFact, TypeField, TypeId, TypeImportReport,
    TypeRecord, TypeShape, TypeStore,
};

impl TypeStore {
    pub fn import_data_types(
        &mut self,
        data_types: &[DataType],
        evidence: TypeEvidence,
    ) -> TypeImportReport {
        let mut ordered = data_types.iter().collect::<Vec<_>>();
        ordered.sort_by(|left, right| left.id.cmp(&right.id).then(left.name.cmp(&right.name)));
        let mut report = TypeImportReport::default();

        for data_type in &ordered {
            if data_type.id.trim().is_empty() {
                continue;
            }
            let id = if let Some(id) = self.by_external.get(&data_type.id).copied() {
                id
            } else {
                let id = TypeId(self.records.len());
                self.records.push(TypeRecord {
                    id,
                    external_ids: BTreeSet::from([data_type.id.clone()]),
                    names: BTreeSet::new(),
                    selected: None,
                    alternatives: Vec::new(),
                    conflicts: BTreeSet::new(),
                });
                self.by_external.insert(data_type.id.clone(), id);
                self.revision = self.revision.saturating_add(1);
                id
            };
            report.imported.insert(data_type.id.clone(), id);
        }

        for data_type in ordered {
            let Some(id) = self.by_external.get(&data_type.id).copied() else {
                continue;
            };
            self.records[id.0].names.insert(data_type.name.clone());
            if !data_type.is_valid() {
                self.record_conflict(id, TypeConflict::InvalidDefinition, &mut report);
                continue;
            }
            let shape = match self.convert(data_type) {
                Ok(shape) => shape,
                Err(conflict) => {
                    self.record_conflict(id, conflict, &mut report);
                    continue;
                }
            };
            self.merge_fact(id, shape, evidence.for_data_type(data_type), &mut report);
        }
        report
    }

    fn convert(&self, data_type: &DataType) -> Result<TypeShape, TypeConflict> {
        let resolve = |external: &str| {
            self.by_external
                .get(external)
                .copied()
                .ok_or_else(|| TypeConflict::MissingReference(external.to_string()))
        };
        match (&data_type.kind, &data_type.type_data) {
            (DataTypeKind::Primitive, TypeData::Primitive {}) => Ok(TypeShape::Primitive {
                name: data_type.name.clone(),
                size: data_type.size,
                alignment: data_type.alignment,
            }),
            (
                DataTypeKind::Pointer,
                TypeData::Pointer {
                    base_type_id,
                    attributes,
                },
            ) => {
                let mut attributes = attributes.clone();
                attributes.sort();
                attributes.dedup();
                Ok(TypeShape::Pointer {
                    pointee: resolve(base_type_id)?,
                    size: data_type.size,
                    alignment: data_type.alignment,
                    attributes,
                })
            }
            (
                DataTypeKind::Array,
                TypeData::Array {
                    base_type_id,
                    count,
                },
            ) => Ok(TypeShape::Array {
                element: resolve(base_type_id)?,
                count: *count,
                size: data_type.size,
                alignment: data_type.alignment,
            }),
            (DataTypeKind::Struct, TypeData::Struct { fields }) => Ok(TypeShape::Struct {
                fields: self.convert_fields(fields)?,
                size: data_type.size,
                alignment: data_type.alignment,
            }),
            (DataTypeKind::Union, TypeData::Union { fields }) => Ok(TypeShape::Union {
                fields: self.convert_fields(fields)?,
                size: data_type.size,
                alignment: data_type.alignment,
            }),
            (
                DataTypeKind::Enum,
                TypeData::Enum {
                    underlying_type_id,
                    members,
                },
            ) => Ok(TypeShape::Enum {
                underlying: resolve(underlying_type_id)?,
                members: members
                    .iter()
                    .map(|member| TypeEnumMember {
                        name: member.name.clone(),
                        value: member.value,
                    })
                    .collect(),
                size: data_type.size,
                alignment: data_type.alignment,
            }),
            (
                DataTypeKind::Function,
                TypeData::Function {
                    return_type_id,
                    parameter_type_ids,
                    variadic,
                },
            ) => Ok(TypeShape::Function {
                result: return_type_id.as_deref().map(resolve).transpose()?,
                parameters: parameter_type_ids
                    .iter()
                    .map(|parameter| resolve(parameter))
                    .collect::<Result<_, _>>()?,
                variadic: *variadic,
            }),
            (DataTypeKind::Typedef, TypeData::Typedef { base_type_id }) => Ok(TypeShape::Typedef {
                target: resolve(base_type_id)?,
            }),
            _ => Err(TypeConflict::InvalidDefinition),
        }
    }

    fn convert_fields(
        &self,
        fields: &[crate::core::Field],
    ) -> Result<Vec<TypeField>, TypeConflict> {
        fields
            .iter()
            .map(|field| {
                Ok(TypeField {
                    name: field.name.clone(),
                    type_id: self
                        .by_external
                        .get(&field.type_id)
                        .copied()
                        .ok_or_else(|| TypeConflict::MissingReference(field.type_id.clone()))?,
                    offset: field.offset,
                })
            })
            .collect()
    }

    fn merge_fact(
        &mut self,
        id: TypeId,
        shape: TypeShape,
        evidence: TypeEvidence,
        report: &mut TypeImportReport,
    ) {
        let record = &mut self.records[id.0];
        let Some(selected) = record.selected.as_mut() else {
            record.selected = Some(TypeFact::new(shape, evidence));
            self.revision = self.revision.saturating_add(1);
            return;
        };
        if selected.shape == shape {
            let before = selected.evidence.len();
            selected.add_evidence(evidence);
            if selected.evidence.len() != before {
                self.revision = self.revision.saturating_add(1);
            }
            return;
        }

        let conflict = TypeConflict::IncompatibleDefinition;
        record.conflicts.insert(conflict.clone());
        report.conflicts.push((id, conflict));
        let candidate = TypeFact::new(shape, evidence);
        if candidate.authority() > selected.authority() {
            let old = std::mem::replace(selected, candidate);
            record.alternatives.push(old);
        } else {
            record.alternatives.push(candidate);
        }
        self.revision = self.revision.saturating_add(1);
    }

    fn record_conflict(
        &mut self,
        id: TypeId,
        conflict: TypeConflict,
        report: &mut TypeImportReport,
    ) {
        self.records[id.0].conflicts.insert(conflict.clone());
        report.conflicts.push((id, conflict));
        self.revision = self.revision.saturating_add(1);
    }
}
