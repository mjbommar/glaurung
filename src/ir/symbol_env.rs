//! Program-level symbol and type environment.
//!
//! Every other type-recovery structure in this crate is scoped to one function:
//! [`crate::ir::types_recover::TypeMap`] describes one body's values, and the
//! call-site specification in [`crate::ir::call_contracts`] describes one call
//! boundary. Neither can answer "what *is* this callee", so until now each
//! caller re-derived a prototype for the same symbol from whatever its own
//! argument setup happened to look like. Measured on dpkg (816 rendered
//! functions, 746 distinct declared callee names, 3,609 declaration sites),
//! that produced up to seven mutually contradictory declarations of one symbol
//! and left 1,720 of the 2,399 declaration sites for callees defined in the
//! same unit disagreeing with those callees' own definitions.
//!
//! This module owns the missing middle: **one record per callee**, keyed by the
//! identifier the renderer prints, consulted by every caller and by the
//! renderer itself. The library catalogs in [`crate::ir::call_contracts`] and
//! [`crate::ir::winapi_prototypes`] become seed data for this environment
//! rather than a parallel special case.
//!
//! # Order independence
//!
//! Functions are decompiled one at a time and in an order that depends on the
//! caller's request, so a record whose value depended on *which* caller was
//! rendered first would reintroduce exactly the disagreement this exists to
//! remove. Every source admitted here is therefore a property of the **callee**
//! alone — its DWARF declaration, its catalog contract, or the recovery run
//! over its own body — and [`SymbolEnv::insert`] is an idempotent,
//! commutative join over a total priority order. Rendering the same binary with
//! any subset of its functions, in any order, yields the same record.

use std::collections::BTreeMap;

use crate::ir::call_contracts::{CallPrototype, CallPrototypeAuthority};

/// Where a record's prototype came from, strongest first.
///
/// Distinct from [`CallPrototypeAuthority`], which only separates "declared" from
/// "inferred". The environment must additionally break ties *within* declared
/// facts: a binary's own DWARF is a stronger statement about its own function
/// than a generic library catalog entry that merely matched by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecordSource {
    /// Inferred from the call sites of one caller. Weakest; present only for
    /// symbols with no body in this image and no catalog entry.
    CallSite,
    /// Recovered from the callee's own machine code.
    CalleeBody,
    /// A curated library contract matched by symbol name.
    Catalog,
    /// The image's own debug information for this exact function.
    Dwarf,
}

/// One authoritative record for one callee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolRecord {
    /// The single declaration every caller prints and every call site is
    /// reconciled against.
    pub prototype: CallPrototype,
    /// Whether control never returns from this callee.
    pub noreturn: bool,
    /// Provenance, used only to break ties in [`SymbolEnv::insert`].
    pub source: RecordSource,
    /// Forward declarations (`struct pkginfo;`) a function must emit **inside
    /// its own body**, above this declaration, for the tags `prototype` names.
    ///
    /// An incomplete type is all a pointer parameter needs, so this never
    /// requires the aggregate's layout — and unlike a file-scope definition it
    /// survives DecBench's per-function split, which discards everything above
    /// the signature line. In a whole translation unit the defining function's
    /// `typedef struct pkginfo pkginfo;` makes `pkginfo *` and `struct pkginfo *`
    /// the same type, so the declaration and the definition still agree.
    pub required_structs: Vec<String>,
}

impl SymbolRecord {
    /// A record for a prototype that names no aggregate types.
    pub fn new(prototype: CallPrototype, source: RecordSource, noreturn: bool) -> Self {
        Self {
            prototype,
            noreturn,
            source,
            required_structs: Vec::new(),
        }
    }
}

/// The program-level environment: one [`SymbolRecord`] per callee identifier.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SymbolEnv {
    records: BTreeMap<String, SymbolRecord>,
}

impl SymbolEnv {
    /// An environment with no records. Every lookup misses, so consumers fall
    /// back to their pre-existing per-function inference unchanged.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether any callee has a record.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Number of callees with a record.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// The record for `name`, which must already be the identifier the renderer
    /// prints (`@plt` stripped, sanitized).
    pub fn get(&self, name: &str) -> Option<&SymbolRecord> {
        self.records.get(name)
    }

    /// Iterate every `(name, record)` pair in identifier order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &SymbolRecord)> {
        self.records.iter()
    }

    /// Admit `record` for `name`, keeping the stronger of the two.
    ///
    /// A strictly stronger source wins. Two records of *equal* source can still
    /// differ — one display name can be reached through both a PLT stub and the
    /// real body it forwards to — and "keep the incumbent" would then resolve to
    /// whichever caller was rendered first, which is the exact
    /// order-dependence this type exists to remove. The tie is therefore broken
    /// on the declaration's own text: the lexicographically smaller
    /// `(return_type, parameter_types, variadic)` wins. That choice carries no
    /// meaning, only stability, which is the property callers actually need.
    pub fn insert(&mut self, name: impl Into<String>, record: SymbolRecord) {
        let name = name.into();
        let replace = match self.records.get(&name) {
            None => true,
            Some(existing) if existing.source != record.source => existing.source < record.source,
            Some(existing) => Self::tie_break_key(&record) < Self::tie_break_key(existing),
        };
        if replace {
            self.records.insert(name, record);
        }
    }

    fn tie_break_key(record: &SymbolRecord) -> (&str, &[String], bool) {
        (
            record.prototype.return_type.as_str(),
            record.prototype.parameter_types.as_slice(),
            record.prototype.variadic,
        )
    }

    /// Merge every record of `other` under the same priority rule.
    pub fn merge(&mut self, other: &SymbolEnv) {
        for (name, record) in &other.records {
            self.insert(name.clone(), record.clone());
        }
    }
}

thread_local! {
    /// The environment installed for the render currently in progress.
    ///
    /// The DecBench renderer already threads its per-render selections through
    /// thread-locals (`DEC_NAMED_CALL_PROTOTYPES` and friends in
    /// [`crate::ir::ast`]); this is the program-scoped owner those per-render
    /// tables are now projections of. Renders are single-threaded.
    static ACTIVE: std::cell::RefCell<SymbolEnv> = std::cell::RefCell::new(SymbolEnv::new());
}

/// Install `env` for the render about to run, replacing any previous one.
pub fn install(env: SymbolEnv) {
    ACTIVE.with(|active| *active.borrow_mut() = env);
}

/// Drop the installed environment. Subsequent lookups miss.
pub fn clear() {
    ACTIVE.with(|active| *active.borrow_mut() = SymbolEnv::new());
}

/// The installed record for `name`, if any.
pub fn lookup(name: &str) -> Option<SymbolRecord> {
    ACTIVE.with(|active| active.borrow().get(name).cloned())
}

/// Whether any record is installed.
pub fn is_installed() -> bool {
    ACTIVE.with(|active| !active.borrow().is_empty())
}

/// Admit a DWARF-declared prototype as a record, reporting the tag forward
/// declarations printing it will require.
///
/// A type is admissible only when the declaration can print it **verbatim**,
/// because the defining function prints the DWARF spelling and the two must be
/// the same type. That is a stricter test than
/// [`crate::ir::call_contracts::standalone_c_type`] returning `Some`: that
/// function is a *rewriter*, and it maps every `struct T *` to `void *`. Taking
/// its `Some` as "this type is fine" would have admitted `struct opaque *` and
/// then declared it as an incompatible `void *` — a completeness trap of
/// exactly the kind that turns into a silent `false` rather than an error.
///
/// A pointer to an explicitly tagged aggregate is admissible without any layout
/// knowledge, because `struct pkginfo;` above the declaration is enough to make
/// `struct pkginfo *` a complete pointer type. A pointer to a *typedef* name is
/// not: no forward declaration introduces a typedef, so those are withheld.
///
/// Returns `None` when any type is neither self-contained verbatim nor a
/// forward-declarable tag pointer, because a declaration naming a type that is
/// not in scope fails to compile rather than merely under-describing the callee.
pub fn dwarf_record(prototype: &CallPrototype, noreturn: bool) -> Option<SymbolRecord> {
    let mut required: Vec<String> = Vec::new();
    let mut check = |c_type: &str| -> bool {
        // Verbatim-spellable FIRST. `forward_declarable_tag` would otherwise
        // never be reached for ordinary pointers, but the reverse order is the
        // trap: a candidate extractor that answers `Some("char")` for
        // `const char *` as readily as `Some("pkginfo")` for `struct pkginfo *`
        // makes every pointer parameter claim a struct dependency.
        if crate::ir::call_contracts::standalone_c_type(c_type)
            .is_some_and(|spelling| spelling == c_type.trim())
        {
            return true;
        }
        match forward_declarable_tag(c_type) {
            Some(declaration) => {
                if !required.iter().any(|existing| *existing == declaration) {
                    required.push(declaration);
                }
                true
            }
            None => false,
        }
    };
    if !check(&prototype.return_type) {
        return None;
    }
    if !prototype.parameter_types.iter().all(|t| check(t)) {
        return None;
    }
    Some(SymbolRecord {
        prototype: CallPrototype {
            authority: CallPrototypeAuthority::Authoritative,
            ..prototype.clone()
        },
        noreturn,
        source: RecordSource::Dwarf,
        required_structs: required,
    })
}

/// The forward declaration that completes a pointer-to-tagged-aggregate type.
///
/// `const struct pkginfo *` yields `struct pkginfo;`. A typedef spelling such as
/// `pkginfo *` yields `None`: a tag declaration does not introduce a typedef
/// name, so nothing this function could emit would put that spelling in scope.
pub fn forward_declarable_tag(c_type: &str) -> Option<String> {
    let pointee = c_type.trim().strip_suffix('*')?.trim();
    if pointee.ends_with('*') || pointee.contains('(') || pointee.contains('[') {
        return None;
    }
    let mut base = pointee;
    loop {
        let stripped = base
            .strip_prefix("const ")
            .or_else(|| base.strip_prefix("volatile "));
        match stripped {
            Some(rest) => base = rest.trim(),
            None => break,
        }
    }
    let (keyword, tag) = base
        .strip_prefix("struct ")
        .map(|tag| ("struct", tag))
        .or_else(|| base.strip_prefix("union ").map(|tag| ("union", tag)))?;
    let tag = tag.trim();
    let is_identifier = !tag.is_empty()
        && tag
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && tag
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric());
    is_identifier.then(|| format!("{keyword} {tag};"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prototype(return_type: &str, parameters: &[&str]) -> CallPrototype {
        CallPrototype {
            return_type: return_type.to_string(),
            parameter_types: parameters.iter().map(|t| t.to_string()).collect(),
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        }
    }

    #[test]
    fn a_stronger_source_replaces_a_weaker_record() {
        let mut env = SymbolEnv::new();
        env.insert(
            "f",
            SymbolRecord::new(prototype("long", &["long"]), RecordSource::CallSite, false),
        );
        env.insert(
            "f",
            SymbolRecord::new(
                prototype("int", &["const char *"]),
                RecordSource::Dwarf,
                false,
            ),
        );
        assert_eq!(env.get("f").unwrap().prototype.return_type, "int");
    }

    #[test]
    fn a_weaker_source_never_replaces_a_stronger_record() {
        let mut env = SymbolEnv::new();
        env.insert(
            "f",
            SymbolRecord::new(prototype("int", &[]), RecordSource::Catalog, false),
        );
        env.insert(
            "f",
            SymbolRecord::new(
                prototype("long", &["long"]),
                RecordSource::CalleeBody,
                false,
            ),
        );
        assert_eq!(env.get("f").unwrap().prototype.return_type, "int");
    }

    /// The order-independence the module docs promise: two equally-sourced
    /// observations must not resolve to whichever arrived last, or the record
    /// for one symbol would depend on which caller was rendered first.
    #[test]
    fn equal_sources_are_order_independent() {
        let a = SymbolRecord::new(
            prototype("long", &["long"]),
            RecordSource::CalleeBody,
            false,
        );
        let b = SymbolRecord::new(
            prototype("int", &["char *"]),
            RecordSource::CalleeBody,
            false,
        );
        let mut forward = SymbolEnv::new();
        forward.insert("f", a.clone());
        forward.insert("f", b.clone());
        let mut backward = SymbolEnv::new();
        backward.insert("f", b);
        backward.insert("f", a);
        assert_eq!(forward.get("f"), backward.get("f"));
    }

    #[test]
    fn merge_respects_the_same_priority_order() {
        let mut strong = SymbolEnv::new();
        strong.insert(
            "f",
            SymbolRecord::new(prototype("int", &[]), RecordSource::Dwarf, false),
        );
        let mut weak = SymbolEnv::new();
        weak.insert(
            "f",
            SymbolRecord::new(prototype("long", &[]), RecordSource::CalleeBody, false),
        );
        weak.merge(&strong);
        assert_eq!(weak.get("f").unwrap().source, RecordSource::Dwarf);
        strong.merge(&weak);
        assert_eq!(strong.get("f").unwrap().source, RecordSource::Dwarf);
    }

    #[test]
    fn a_forward_declaration_is_offered_only_for_explicit_tags() {
        assert_eq!(
            forward_declarable_tag("struct pkginfo *").as_deref(),
            Some("struct pkginfo;")
        );
        assert_eq!(
            forward_declarable_tag("const struct pkginfo *").as_deref(),
            Some("struct pkginfo;")
        );
        assert_eq!(
            forward_declarable_tag("union value *").as_deref(),
            Some("union value;")
        );
        // A tag declaration does not introduce a typedef name, so a typedef
        // spelling has no forward declaration that would put it in scope.
        assert_eq!(forward_declarable_tag("dpkg_version *"), None);
        assert_eq!(forward_declarable_tag("char **"), None);
        assert_eq!(forward_declarable_tag("int"), None);
        assert_eq!(forward_declarable_tag("struct s (*)(void) *"), None);
    }

    #[test]
    fn a_dwarf_record_withholds_itself_when_a_type_cannot_be_spelled() {
        assert!(dwarf_record(&prototype("int", &["nomenclature *"]), false).is_none());
    }

    /// An ordinary pointer parameter is spellable on its own and must not be
    /// reported as depending on a tag named after its pointee.
    #[test]
    fn a_dwarf_record_claims_no_tag_for_ordinary_pointers() {
        let record = dwarf_record(
            &prototype("void", &["int", "const char *", "void *", "char **"]),
            false,
        )
        .expect("ordinary pointers are self-contained");
        assert!(record.required_structs.is_empty());
    }

    #[test]
    fn a_dwarf_record_reports_the_tags_it_depends_on() {
        let record = dwarf_record(
            &prototype("int", &["const struct pkginfo *", "const char *"]),
            false,
        )
        .expect("a tagged aggregate pointer is admissible");
        assert_eq!(record.required_structs, vec!["struct pkginfo;".to_string()]);
        assert_eq!(record.source, RecordSource::Dwarf);
        assert_eq!(
            record.prototype.authority,
            CallPrototypeAuthority::Authoritative
        );
    }

    #[test]
    fn an_installed_environment_is_visible_to_lookup_and_clears() {
        install({
            let mut env = SymbolEnv::new();
            env.insert(
                "f",
                SymbolRecord::new(prototype("void", &[]), RecordSource::CalleeBody, true),
            );
            env
        });
        let record = lookup("f").expect("installed record");
        assert!(record.noreturn);
        clear();
        assert!(lookup("f").is_none());
        assert!(!is_installed());
    }
}
