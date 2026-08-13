//! Fixed-point definedness queries over verified MIR.

use super::model::{Definition, MirFunction, UseId, ValueId};

pub struct DefinitionOracle {
    all_paths_defined: Vec<bool>,
    use_values: Vec<usize>,
    definitions: Vec<Definition>,
    uses_by_value: Vec<Vec<UseId>>,
}

impl DefinitionOracle {
    pub fn new(function: &MirFunction) -> Self {
        let mut defined = function
            .values()
            .iter()
            .map(|value| {
                matches!(
                    value.definition,
                    Definition::Input
                        | Definition::InstructionOutput { .. }
                        | Definition::Phi { .. }
                        | Definition::UnknownEffect { .. }
                )
            })
            .collect::<Vec<_>>();
        let mut changed = true;
        while changed {
            changed = false;
            for value in function.values() {
                let next = match &value.definition {
                    Definition::InstructionOutput { instruction, .. } => function.instructions()
                        [instruction.0]
                        .uses
                        .iter()
                        .all(|use_| defined[function.use_(*use_).value.0]),
                    Definition::Phi { incoming, .. } => {
                        !incoming.is_empty()
                            && incoming.iter().all(|(_, incoming)| defined[incoming.0])
                    }
                    _ => continue,
                };
                if !next && defined[value.id.0] {
                    defined[value.id.0] = false;
                    changed = true;
                }
            }
        }
        let mut uses_by_value = vec![Vec::new(); function.values().len()];
        for use_ in function.uses() {
            if let Some(uses) = uses_by_value.get_mut(use_.value.0) {
                uses.push(use_.id);
            }
        }
        Self {
            all_paths_defined: defined,
            use_values: function.uses().iter().map(|use_| use_.value.0).collect(),
            definitions: function
                .values()
                .iter()
                .map(|value| value.definition.clone())
                .collect(),
            uses_by_value,
        }
    }

    pub fn all_paths_defined(&self, use_: UseId) -> bool {
        self.use_values
            .get(use_.0)
            .and_then(|value| self.all_paths_defined.get(*value))
            .copied()
            .unwrap_or(false)
    }

    pub fn value_is_all_paths_defined(&self, value: ValueId) -> bool {
        self.all_paths_defined
            .get(value.0)
            .copied()
            .unwrap_or(false)
    }

    pub fn definition(&self, value: ValueId) -> Option<&Definition> {
        self.definitions.get(value.0)
    }

    pub fn uses(&self, value: ValueId) -> &[UseId] {
        self.uses_by_value
            .get(value.0)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
}
