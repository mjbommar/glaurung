//! Independent structural verification for the program symbol environment.

use super::{SymbolDefinition, SymbolFact, SymbolRecord, SymbolStore};

fn defines(record: &SymbolRecord, address: u64) -> bool {
    record
        .selected
        .iter()
        .chain(record.alternatives.iter())
        .any(|fact| {
            matches!(fact.definition, SymbolDefinition::Defined { address: at, .. } if at == address)
        })
}

fn extent(record: &SymbolRecord, address: u64, end: u64) -> bool {
    record
        .selected
        .iter()
        .chain(record.alternatives.iter())
        .any(|fact| match fact.definition {
            SymbolDefinition::Defined {
                address: at,
                size: Some(size),
            } => at == address && at.checked_add(size) == Some(end),
            _ => false,
        })
}

impl SymbolStore {
    /// Recompute every index and invariant from the arena alone.
    pub fn verify(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for (index, record) in self.records.iter().enumerate() {
            if record.id.0 != index {
                errors.push(format!(
                    "symbol id {} does not match arena index {index}",
                    record.id.0
                ));
            }
            if record.selected.is_none() && record.conflicts.is_empty() {
                errors.push(format!("symbol {index} is unresolved without a conflict"));
            }
            if !record.alternatives.is_empty() && record.conflicts.is_empty() {
                errors.push(format!(
                    "symbol {index} retains alternatives without an explicit conflict"
                ));
            }
            if self.by_linkage.get(&record.linkage) != Some(&record.id) {
                errors.push(format!("symbol {index} linkage identity is inconsistent"));
            }
            if !record.has_exact_name(&record.linkage) {
                errors.push(format!("symbol {index} does not carry its linkage name"));
            }
            for name in &record.names {
                if !self
                    .by_name
                    .get(&name.text)
                    .is_some_and(|symbols| symbols.contains(&record.id))
                {
                    errors.push(format!("symbol {index} name {} is not indexed", name.text));
                }
            }
            for fact in record.selected.iter().chain(record.alternatives.iter()) {
                if fact.evidence().is_empty() {
                    errors.push(format!("symbol {index} has a fact without provenance"));
                }
            }
            let facts = record
                .selected
                .iter()
                .chain(record.alternatives.iter())
                .collect::<Vec<_>>();
            for (position, fact) in facts.iter().enumerate() {
                if facts[position + 1..]
                    .iter()
                    .any(|other| SymbolFact::describes_same(fact, other))
                {
                    errors.push(format!("symbol {index} retains a duplicated fact"));
                }
            }
        }

        for (text, symbols) in &self.by_name {
            for id in symbols {
                match self.records.get(id.0) {
                    Some(record) if record.names.iter().any(|name| &name.text == text) => {}
                    _ => errors.push(format!("name index entry {text} is inconsistent")),
                }
            }
        }
        for (address, symbols) in &self.by_address {
            for id in symbols {
                if !self.records.get(id.0).is_some_and(|r| defines(r, *address)) {
                    errors.push(format!("address index entry {address:#x} is inconsistent"));
                }
            }
        }
        for window in self.ranges.windows(2) {
            if window[0] > window[1] {
                errors.push("the range index is not sorted".to_string());
            }
        }
        for (start, end, id) in &self.ranges {
            if !self
                .records
                .get(id.0)
                .is_some_and(|r| extent(r, *start, *end))
            {
                errors.push(format!("range entry {start:#x}..{end:#x} is inconsistent"));
            }
            if end.saturating_sub(*start) > self.max_extent {
                errors.push(format!(
                    "range entry {start:#x}..{end:#x} exceeds the indexed extent"
                ));
            }
        }
        for (index, reference) in self.references.iter().enumerate() {
            if self.records.get(reference.symbol.0).is_none() {
                errors.push(format!("reference {index} names an unknown symbol"));
            }
            if !self
                .references_by_site
                .get(&reference.site)
                .is_some_and(|indices| indices.contains(&index))
            {
                errors.push(format!("reference {index} is not indexed by site"));
            }
            if !self
                .references_by_symbol
                .get(&reference.symbol)
                .is_some_and(|indices| indices.contains(&index))
            {
                errors.push(format!("reference {index} is not indexed by symbol"));
            }
        }
        errors
    }
}
