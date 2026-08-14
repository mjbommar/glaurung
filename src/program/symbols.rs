//! Interned, provenance-bearing program symbol environment.
//!
//! Identity is the exact linkage spelling recorded by the program: one name is
//! one stable [`SymbolId`] for the life of the store. A name is not a unique
//! program identity: two translation units may legally define distinct local
//! symbols with the same spelling, so disagreeing definitions are retained as
//! alternatives beside an explicit conflict instead of letting the last
//! observation win.
//!
//! Everything here is exact: names, bindings, definition states, modules,
//! versions, and relocation sites are read verbatim from a program table.
//! Inferred or resembling knowledge is representable (`SymbolAuthority`,
//! [`NameMatch`]) but is never produced by this store's importers.

use std::collections::{BTreeMap, BTreeSet};

mod object_import;
mod verify;

/// Stable arena identity for one program symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SymbolId(pub usize);

/// Authority order for selecting among conflicting symbol facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SymbolAuthority {
    Inference,
    Binary,
    Debug,
    Analyst,
}

/// The exact program record one symbol fact was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SymbolSource {
    ObjectSymbolTable,
    DynamicSymbolTable,
    ImportTable,
    ExportTable,
    /// A relocation applied by the static linker or held in a section table.
    StaticRelocation,
    /// A relocation applied by the runtime loader.
    DynamicRelocation,
    Debug,
    Analyst,
    Inference,
}

/// Provenance attached to one symbol fact or reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SymbolEvidence {
    pub authority: SymbolAuthority,
    pub source: SymbolSource,
    /// Defining module (shared object, DLL, or import library) when the format
    /// states one.
    pub module: Option<String>,
    /// Symbol version when the format states one.
    pub version: Option<String>,
}

impl SymbolEvidence {
    pub fn new(authority: SymbolAuthority, source: SymbolSource) -> Self {
        Self {
            authority,
            source,
            module: None,
            version: None,
        }
    }

    pub fn with_module(mut self, module: impl Into<String>) -> Self {
        self.module = Some(module.into());
        self
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }
}

/// Demangling scheme that produced a name spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DemangleScheme {
    Itanium,
    Rust,
    Msvc,
}

/// How a name spelling was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NameForm {
    /// The exact linkage spelling stored in the program.
    Linkage,
    /// A demangled projection of the linkage spelling.
    Demangled(DemangleScheme),
}

/// Whether a name was read verbatim from the program or catalog, or merely
/// resembles one. A resemblance is evidence, never proof, and never answers an
/// exact query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NameMatch {
    Exact,
    Resemblance,
}

/// One name spelling attached to a symbol identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SymbolName {
    pub text: String,
    pub form: NameForm,
    pub match_kind: NameMatch,
}

/// What a symbol denotes, as declared by the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SymbolKind {
    Function,
    Data,
    Section,
    File,
    Label,
    Tls,
    Unknown,
}

/// Linkage binding declared by the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SymbolBinding {
    Local,
    Global,
    Weak,
    Unknown,
}

/// Where a symbol lives, if anywhere, in this image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SymbolDefinition {
    /// Defined in this image at an exact address; `size` is present only when
    /// the format states it.
    Defined { address: u64, size: Option<u64> },
    /// Referenced here and defined elsewhere.
    Undefined,
    /// An absolute value that is not an address in this image.
    Absolute { value: u64 },
    /// A tentative definition to be merged by the linker.
    Common { size: u64 },
    /// The format declares a symbol whose location it does not state.
    Unknown,
}

/// One coherent claim about a symbol plus the provenance that supports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolFact {
    pub kind: SymbolKind,
    pub binding: SymbolBinding,
    pub definition: SymbolDefinition,
    evidence: Vec<SymbolEvidence>,
}

impl SymbolFact {
    pub fn new(
        kind: SymbolKind,
        binding: SymbolBinding,
        definition: SymbolDefinition,
        evidence: SymbolEvidence,
    ) -> Self {
        Self {
            kind,
            binding,
            definition,
            evidence: vec![evidence],
        }
    }

    /// Every retained observation supporting this claim.
    pub fn evidence(&self) -> &[SymbolEvidence] {
        &self.evidence
    }

    fn authority(&self) -> SymbolAuthority {
        self.evidence
            .iter()
            .map(|evidence| evidence.authority)
            .max()
            .unwrap_or(SymbolAuthority::Inference)
    }

    fn describes_same(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.binding == other.binding
            && self.definition == other.definition
    }

    fn add_evidence(&mut self, evidence: SymbolEvidence) -> bool {
        if self.evidence.contains(&evidence) {
            return false;
        }
        self.evidence.push(evidence);
        true
    }
}

/// A retained disagreement. Conflicts never silently mutate a selected fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SymbolConflict {
    /// Two exact records disagree about kind, binding, or definition.
    IncompatibleDefinition,
}

/// A monotone reason this store is known to be partial. Later imports may add
/// reasons; nothing removes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SymbolIncompleteness {
    /// The image carries no object symbol table; local and static names are gone.
    NoObjectSymbolTable,
    /// The image carries no dynamic symbol table.
    NoDynamicSymbolTable,
    /// At least one defined symbol states no size, so containing-range queries
    /// cannot cover it.
    MissingSymbolSizes,
    /// Addresses in a relocatable object are section-relative, not virtual.
    SectionRelativeAddresses,
    /// At least one relocation names a target this import could not resolve to
    /// a symbol identity.
    UnresolvedRelocationTargets,
    /// A declared format table could not be read.
    UnreadableTable(&'static str),
    /// The image itself could not be parsed.
    UnreadableImage,
}

/// One symbol identity: names, the selected fact, retained alternatives, and
/// explicit conflicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolRecord {
    pub id: SymbolId,
    linkage: String,
    names: BTreeSet<SymbolName>,
    selected: Option<SymbolFact>,
    alternatives: Vec<SymbolFact>,
    conflicts: BTreeSet<SymbolConflict>,
}

impl SymbolRecord {
    /// The exact linkage spelling that identifies this symbol.
    pub fn linkage_name(&self) -> &str {
        &self.linkage
    }

    /// Every name spelling attached to this identity, with its provenance.
    pub fn names(&self) -> impl ExactSizeIterator<Item = &SymbolName> {
        self.names.iter()
    }

    /// The currently selected fact, or `None` when nothing has been observed.
    pub fn selected(&self) -> Option<&SymbolFact> {
        self.selected.as_ref()
    }

    /// Provenance supporting the selected fact.
    pub fn evidence(&self) -> &[SymbolEvidence] {
        self.selected
            .as_ref()
            .map(|fact| fact.evidence.as_slice())
            .unwrap_or_default()
    }

    /// Retained conflicting facts, never discarded by selection.
    pub fn alternatives(&self) -> impl ExactSizeIterator<Item = &SymbolFact> {
        self.alternatives.iter()
    }

    pub fn conflicts(&self) -> &BTreeSet<SymbolConflict> {
        &self.conflicts
    }

    fn has_exact_name(&self, text: &str) -> bool {
        self.names
            .iter()
            .any(|name| name.text == text && name.match_kind == NameMatch::Exact)
    }
}

/// How a relocated place uses the symbol's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReferenceKind {
    /// The place holds the symbol value plus an addend.
    Absolute,
    /// The place holds a displacement from the place itself.
    ProgramCounterRelative,
    /// The place holds an offset into a global offset table.
    GotOffset,
    /// The place holds an offset from the image base.
    ImageRelative,
    /// The place holds an offset from a section.
    SectionRelative,
    /// The generic model does not classify this relocation; `format_type`
    /// retains the exact declared type.
    Unclassified,
}

/// One exact, relocation-backed use of a symbol at a program address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolReference {
    /// Address of the relocated storage, or its section-relative offset when
    /// the store declares [`SymbolIncompleteness::SectionRelativeAddresses`].
    pub site: u64,
    pub symbol: SymbolId,
    pub addend: i64,
    /// The addend is stored in the place rather than the relocation record.
    pub implicit_addend: bool,
    /// Exact width of the place when the format states it.
    pub width_bits: Option<u8>,
    pub kind: ReferenceKind,
    /// Format-specific relocation type, retained verbatim.
    pub format_type: Option<u32>,
    pub evidence: SymbolEvidence,
}

/// Result of a contextual address query. A query that cannot prove an answer
/// says so rather than returning a nearest guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressSymbol {
    /// One or more symbols start exactly at the queried address.
    Exact {
        symbols: Vec<SymbolId>,
    },
    /// The address lies inside one range shared by these aliases.
    Containing {
        symbols: Vec<SymbolId>,
        offset: u64,
    },
    Unknown(AddressUnknown),
}

/// Why an address query produced no proved answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressUnknown {
    /// No retained definition covers the address.
    NoSymbolEvidence,
    /// Several ranges with different starts cover the address; selecting one
    /// would be a guess.
    AmbiguousRanges(Vec<SymbolId>),
}

/// Fail-closed rejection of an unusable symbol operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SymbolStoreError {
    #[error("a symbol must have a non-empty linkage name")]
    EmptyName,
    #[error("unknown symbol identity {0:?}")]
    UnknownSymbol(SymbolId),
}

/// Program-owned symbol arena with contextual address, name, and reference
/// indices.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SymbolStore {
    records: Vec<SymbolRecord>,
    by_linkage: BTreeMap<String, SymbolId>,
    by_name: BTreeMap<String, Vec<SymbolId>>,
    by_address: BTreeMap<u64, Vec<SymbolId>>,
    /// Sorted by start address; one entry per retained sized definition.
    ranges: Vec<(u64, u64, SymbolId)>,
    max_extent: u64,
    references: Vec<SymbolReference>,
    references_by_site: BTreeMap<u64, Vec<usize>>,
    references_by_symbol: BTreeMap<SymbolId, Vec<usize>>,
    incompleteness: BTreeSet<SymbolIncompleteness>,
    revision: u64,
}

impl SymbolStore {
    pub fn records(&self) -> &[SymbolRecord] {
        &self.records
    }

    pub fn get(&self, id: SymbolId) -> Option<&SymbolRecord> {
        self.records.get(id.0)
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Every declared reason this store is partial.
    pub fn incompleteness(&self) -> &BTreeSet<SymbolIncompleteness> {
        &self.incompleteness
    }

    /// Whether every consulted source was read in full.
    pub fn is_complete(&self) -> bool {
        self.incompleteness.is_empty()
    }

    /// Declare a partial view of the program. Reasons only accumulate.
    pub fn note_incomplete(&mut self, reason: SymbolIncompleteness) {
        if self.incompleteness.insert(reason) {
            self.revision = self.revision.saturating_add(1);
        }
    }

    /// Resolve the identity of an exact linkage spelling.
    pub fn symbol_by_linkage(&self, linkage: &str) -> Option<SymbolId> {
        self.by_linkage.get(linkage).copied()
    }

    /// Every identity carrying `text` under any name form or match kind.
    pub fn symbols_named(&self, text: &str) -> &[SymbolId] {
        self.by_name
            .get(text)
            .map_or(&[][..], |symbols| symbols.as_slice())
    }

    /// Every identity for which `text` was read verbatim rather than guessed.
    pub fn exact_symbols_named(&self, text: &str) -> Vec<SymbolId> {
        self.symbols_named(text)
            .iter()
            .copied()
            .filter(|id| {
                self.records
                    .get(id.0)
                    .is_some_and(|record| record.has_exact_name(text))
            })
            .collect()
    }

    /// Contextually resolve a program address to symbol identities.
    pub fn resolve_address(&self, address: u64) -> AddressSymbol {
        if let Some(symbols) = self.by_address.get(&address) {
            return AddressSymbol::Exact {
                symbols: symbols.clone(),
            };
        }
        let end = self
            .ranges
            .partition_point(|(start, _, _)| *start <= address);
        let lower = address.saturating_sub(self.max_extent);
        let mut candidates = Vec::new();
        for (start, range_end, id) in self.ranges[..end].iter().rev() {
            if *start < lower {
                break;
            }
            if address < *range_end {
                candidates.push((*start, *id));
            }
        }
        if candidates.is_empty() {
            return AddressSymbol::Unknown(AddressUnknown::NoSymbolEvidence);
        }
        candidates.sort_unstable();
        candidates.dedup();
        let first_start = candidates[0].0;
        let mut symbols = candidates.iter().map(|(_, id)| *id).collect::<Vec<_>>();
        symbols.sort_unstable();
        symbols.dedup();
        if candidates.iter().any(|(start, _)| *start != first_start) {
            return AddressSymbol::Unknown(AddressUnknown::AmbiguousRanges(symbols));
        }
        AddressSymbol::Containing {
            symbols,
            offset: address - first_start,
        }
    }

    /// Every indexed relocation-backed reference.
    pub fn references(&self) -> &[SymbolReference] {
        &self.references
    }

    /// References whose relocated place is exactly `site`.
    pub fn references_at(&self, site: u64) -> impl Iterator<Item = &SymbolReference> {
        self.references_by_site
            .get(&site)
            .into_iter()
            .flatten()
            .filter_map(|index| self.references.get(*index))
    }

    /// References naming one symbol identity.
    pub fn references_to(&self, symbol: SymbolId) -> impl Iterator<Item = &SymbolReference> {
        self.references_by_symbol
            .get(&symbol)
            .into_iter()
            .flatten()
            .filter_map(|index| self.references.get(*index))
    }

    /// Observe one exact fact about a linkage name, creating its identity when
    /// first seen and retaining any disagreement.
    pub fn declare(
        &mut self,
        linkage: &str,
        fact: SymbolFact,
    ) -> Result<SymbolId, SymbolStoreError> {
        if linkage.trim().is_empty() {
            return Err(SymbolStoreError::EmptyName);
        }
        let id = match self.by_linkage.get(linkage).copied() {
            Some(id) => id,
            None => {
                let id = SymbolId(self.records.len());
                self.records.push(SymbolRecord {
                    id,
                    linkage: linkage.to_string(),
                    names: BTreeSet::new(),
                    selected: None,
                    alternatives: Vec::new(),
                    conflicts: BTreeSet::new(),
                });
                self.by_linkage.insert(linkage.to_string(), id);
                self.revision = self.revision.saturating_add(1);
                self.add_name(
                    id,
                    SymbolName {
                        text: linkage.to_string(),
                        form: NameForm::Linkage,
                        match_kind: NameMatch::Exact,
                    },
                );
                id
            }
        };
        self.merge_fact(id, fact);
        Ok(id)
    }

    /// Add provenance to an identity that already exists. Attestation never
    /// invents a symbol.
    pub fn attest(&mut self, linkage: &str, evidence: SymbolEvidence) -> Option<SymbolId> {
        let id = self.by_linkage.get(linkage).copied()?;
        let selected = self.records[id.0].selected.as_mut()?;
        if selected.add_evidence(evidence) {
            self.revision = self.revision.saturating_add(1);
        }
        Some(id)
    }

    /// Attach a name spelling to an identity.
    pub fn add_name(&mut self, id: SymbolId, name: SymbolName) {
        let Some(record) = self.records.get_mut(id.0) else {
            return;
        };
        let text = name.text.clone();
        if !record.names.insert(name) {
            return;
        }
        let entry = self.by_name.entry(text).or_default();
        if !entry.contains(&id) {
            entry.push(id);
            entry.sort_unstable();
        }
        self.revision = self.revision.saturating_add(1);
    }

    /// Index one exact reference site.
    pub fn add_reference(&mut self, reference: SymbolReference) -> Result<(), SymbolStoreError> {
        if reference.symbol.0 >= self.records.len() {
            return Err(SymbolStoreError::UnknownSymbol(reference.symbol));
        }
        if self.references.contains(&reference) {
            return Ok(());
        }
        let index = self.references.len();
        self.references_by_site
            .entry(reference.site)
            .or_default()
            .push(index);
        self.references_by_symbol
            .entry(reference.symbol)
            .or_default()
            .push(index);
        self.references.push(reference);
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    fn merge_fact(&mut self, id: SymbolId, fact: SymbolFact) {
        let definition = fact.definition;
        let record = &mut self.records[id.0];
        let changed = if record.selected.is_none() {
            record.selected = Some(fact);
            true
        } else if record
            .selected
            .as_ref()
            .is_some_and(|selected| selected.describes_same(&fact))
        {
            let selected = record.selected.as_mut().expect("checked above");
            add_all_evidence(selected, fact)
        } else if let Some(alternative) = record
            .alternatives
            .iter_mut()
            .find(|alternative| alternative.describes_same(&fact))
        {
            add_all_evidence(alternative, fact)
        } else {
            record
                .conflicts
                .insert(SymbolConflict::IncompatibleDefinition);
            let selected_authority = record
                .selected
                .as_ref()
                .map_or(SymbolAuthority::Inference, SymbolFact::authority);
            if fact.authority() > selected_authority {
                let displaced = record.selected.replace(fact).expect("checked above");
                record.alternatives.push(displaced);
            } else {
                record.alternatives.push(fact);
            }
            true
        };
        if changed {
            self.revision = self.revision.saturating_add(1);
        }
        self.index_definition(id, definition);
    }

    fn index_definition(&mut self, id: SymbolId, definition: SymbolDefinition) {
        let SymbolDefinition::Defined { address, size } = definition else {
            return;
        };
        let starts = self.by_address.entry(address).or_default();
        if !starts.contains(&id) {
            starts.push(id);
            starts.sort_unstable();
        }
        let Some(size) = size.filter(|size| *size != 0) else {
            self.note_incomplete(SymbolIncompleteness::MissingSymbolSizes);
            return;
        };
        let Some(end) = address.checked_add(size) else {
            self.note_incomplete(SymbolIncompleteness::MissingSymbolSizes);
            return;
        };
        let entry = (address, end, id);
        let position = self.ranges.partition_point(|range| *range < entry);
        if self.ranges.get(position) == Some(&entry) {
            return;
        }
        self.ranges.insert(position, entry);
        self.max_extent = self.max_extent.max(size);
    }
}

/// Merge every observation from `fact` into `target`, reporting whether any was
/// new. Every evidence item is considered; this never short-circuits.
fn add_all_evidence(target: &mut SymbolFact, fact: SymbolFact) -> bool {
    let mut changed = false;
    for evidence in fact.evidence {
        changed |= target.add_evidence(evidence);
    }
    changed
}

/// Project one linkage spelling to its demangled alias, when a scheme claims it.
pub fn demangled_name(linkage: &str) -> Option<SymbolName> {
    if !(linkage.starts_with("_Z")
        || linkage.starts_with("__Z")
        || linkage.starts_with("_R")
        || linkage.starts_with('?'))
    {
        return None;
    }
    let result = crate::demangle::demangle_one(linkage)?;
    if result.demangled == linkage {
        return None;
    }
    let scheme = match result.flavor {
        crate::demangle::SymbolFlavor::Rust => DemangleScheme::Rust,
        crate::demangle::SymbolFlavor::Itanium => DemangleScheme::Itanium,
        crate::demangle::SymbolFlavor::Msvc => DemangleScheme::Msvc,
        crate::demangle::SymbolFlavor::Unknown => return None,
    };
    Some(SymbolName {
        text: result.demangled,
        form: NameForm::Demangled(scheme),
        match_kind: NameMatch::Exact,
    })
}

#[cfg(test)]
#[path = "symbols_tests.rs"]
mod tests;
