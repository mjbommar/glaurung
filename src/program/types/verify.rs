//! Independent structural verification for the program type environment.

use super::{TypeRecord, TypeStore};

impl TypeStore {
    pub fn verify(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for (index, record) in self.records.iter().enumerate() {
            if record.id.0 != index {
                errors.push(format!(
                    "type id {} does not match arena index {index}",
                    record.id.0
                ));
            }
            if record.selected.is_none() && record.conflicts.is_empty() {
                errors.push(format!("type {index} is unresolved without a conflict"));
            }
            for fact in record.selected.iter().chain(record.alternatives.iter()) {
                for reference in fact.shape.referenced_types() {
                    if self
                        .records
                        .get(reference.0)
                        .is_none_or(|record| record.selected.is_none())
                    {
                        errors.push(format!(
                            "type {index} has invalid or unresolved reference {}",
                            reference.0
                        ));
                    }
                }
            }
            for external in &record.external_ids {
                if self.by_external.get(external) != Some(&record.id) {
                    errors.push(format!("type {index} external identity is inconsistent"));
                }
            }
        }
        for (shape, id) in &self.anonymous_by_shape {
            if self.records.get(id.0).and_then(TypeRecord::selected_shape) != Some(shape) {
                errors.push(format!(
                    "anonymous type {} is not interned consistently",
                    id.0
                ));
            }
        }
        for (key, binding) in &self.object_types {
            for fact in std::iter::once(&binding.selected).chain(binding.alternatives.iter()) {
                if self
                    .records
                    .get(fact.type_id.0)
                    .is_none_or(|record| record.selected.is_none())
                {
                    errors.push(format!(
                        "object {} at 0x{:x} has invalid type {}",
                        key.object.0, key.function_entry, fact.type_id.0
                    ));
                }
            }
        }
        errors
    }
}
