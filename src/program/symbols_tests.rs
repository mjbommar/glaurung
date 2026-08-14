use super::*;

fn binary(source: SymbolSource) -> SymbolEvidence {
    SymbolEvidence::new(SymbolAuthority::Binary, source)
}

fn function(definition: SymbolDefinition, evidence: SymbolEvidence) -> SymbolFact {
    SymbolFact::new(
        SymbolKind::Function,
        SymbolBinding::Global,
        definition,
        evidence,
    )
}

fn defined(address: u64, size: u64) -> SymbolDefinition {
    SymbolDefinition::Defined {
        address,
        size: Some(size),
    }
}

#[test]
fn one_linkage_name_keeps_one_stable_identity_and_accumulates_evidence() {
    let mut store = SymbolStore::default();

    let first = store
        .declare(
            "shared",
            function(defined(0x1000, 16), binary(SymbolSource::ObjectSymbolTable)),
        )
        .expect("named symbol");
    let second = store
        .declare(
            "shared",
            function(
                defined(0x1000, 16),
                binary(SymbolSource::DynamicSymbolTable),
            ),
        )
        .expect("named symbol");

    assert_eq!(first, second, "one linkage name is one stable identity");
    let record = store.get(first).expect("record");
    assert!(
        record.conflicts().is_empty(),
        "agreeing facts do not conflict"
    );
    let sources = record
        .evidence()
        .iter()
        .map(|evidence| evidence.source)
        .collect::<Vec<_>>();
    assert_eq!(
        sources,
        vec![
            SymbolSource::ObjectSymbolTable,
            SymbolSource::DynamicSymbolTable
        ],
        "every observing table is retained as provenance"
    );
    assert!(store.verify().is_empty());
}

#[test]
fn disagreeing_definitions_are_retained_and_authority_only_reorders_them() {
    let mut store = SymbolStore::default();

    let id = store
        .declare(
            "helper",
            function(defined(0x1000, 16), binary(SymbolSource::ObjectSymbolTable)),
        )
        .expect("named symbol");
    let _ = store
        .declare(
            "helper",
            function(defined(0x2000, 22), binary(SymbolSource::ObjectSymbolTable)),
        )
        .expect("named symbol");

    let record = store.get(id).expect("record");
    assert!(
        record
            .conflicts()
            .contains(&SymbolConflict::IncompatibleDefinition),
        "two definitions of one name are an explicit conflict"
    );
    assert_eq!(
        record.selected().map(|fact| fact.definition),
        Some(defined(0x1000, 16)),
        "equal authority never displaces the first observation"
    );
    assert_eq!(
        record
            .alternatives()
            .map(|fact| fact.definition)
            .collect::<Vec<_>>(),
        vec![defined(0x2000, 22)]
    );

    let _ = store
        .declare(
            "helper",
            SymbolFact::new(
                SymbolKind::Function,
                SymbolBinding::Global,
                defined(0x3000, 8),
                SymbolEvidence::new(SymbolAuthority::Analyst, SymbolSource::Analyst),
            ),
        )
        .expect("named symbol");

    let record = store.get(id).expect("record");
    assert_eq!(
        record.selected().map(|fact| fact.definition),
        Some(defined(0x3000, 8)),
        "higher authority is selected"
    );
    let mut retained = record
        .alternatives()
        .map(|fact| fact.definition)
        .collect::<Vec<_>>();
    retained.sort_by_key(|definition| match definition {
        SymbolDefinition::Defined { address, .. } => *address,
        _ => 0,
    });
    assert_eq!(
        retained,
        vec![defined(0x1000, 16), defined(0x2000, 22)],
        "selection never destroys a conflicting observation"
    );

    for address in [0x1000, 0x2000, 0x3000] {
        assert!(
            matches!(store.resolve_address(address), AddressSymbol::Exact { ref symbols } if symbols == &[id]),
            "every retained definition stays addressable at {address:#x}"
        );
    }
    assert!(store.verify().is_empty());
}

#[test]
fn incompleteness_only_grows() {
    let mut store = SymbolStore::default();
    assert!(store.is_complete());

    store.note_incomplete(SymbolIncompleteness::NoObjectSymbolTable);
    store.note_incomplete(SymbolIncompleteness::NoObjectSymbolTable);
    store.note_incomplete(SymbolIncompleteness::MissingSymbolSizes);
    let _ = store
        .declare(
            "later",
            function(defined(0x40, 4), binary(SymbolSource::ObjectSymbolTable)),
        )
        .expect("named symbol");

    assert!(!store.is_complete());
    assert_eq!(
        store.incompleteness().iter().copied().collect::<Vec<_>>(),
        vec![
            SymbolIncompleteness::NoObjectSymbolTable,
            SymbolIncompleteness::MissingSymbolSizes
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>(),
        "later facts never erase an incompleteness reason"
    );
}

#[test]
fn resembling_names_are_retained_but_never_answer_an_exact_query() {
    let mut store = SymbolStore::default();
    let id = store
        .declare(
            "sub_1000",
            function(defined(0x1000, 16), binary(SymbolSource::ObjectSymbolTable)),
        )
        .expect("named symbol");
    store.add_name(
        id,
        SymbolName {
            text: "memcpy".to_string(),
            form: NameForm::Linkage,
            match_kind: NameMatch::Resemblance,
        },
    );

    assert_eq!(store.symbols_named("memcpy"), &[id]);
    assert!(
        store.exact_symbols_named("memcpy").is_empty(),
        "a resemblance is not an exact catalog match"
    );
    assert_eq!(store.exact_symbols_named("sub_1000"), vec![id]);
    assert!(store.verify().is_empty());
}

#[test]
fn demangled_aliases_carry_their_scheme_and_answer_name_queries() {
    let mut store = SymbolStore::default();
    let id = store
        .declare(
            "_ZN8glaurung3addEii",
            function(defined(0x1000, 16), binary(SymbolSource::ObjectSymbolTable)),
        )
        .expect("named symbol");
    let alias = demangled_name("_ZN8glaurung3addEii").expect("itanium demangling");
    assert_eq!(alias.form, NameForm::Demangled(DemangleScheme::Itanium));
    assert_eq!(alias.match_kind, NameMatch::Exact);
    store.add_name(id, alias.clone());

    assert_eq!(store.symbols_named(&alias.text), &[id]);
    assert_eq!(
        store.symbol_by_linkage("_ZN8glaurung3addEii"),
        Some(id),
        "the linkage spelling stays the identity"
    );
    assert!(store.verify().is_empty());
}

#[test]
fn address_queries_refuse_to_guess_between_unrelated_ranges() {
    let mut store = SymbolStore::default();
    let outer = store
        .declare(
            "outer",
            function(
                defined(0x1000, 0x40),
                binary(SymbolSource::ObjectSymbolTable),
            ),
        )
        .expect("named symbol");
    let inner = store
        .declare(
            "inner",
            function(
                defined(0x1010, 0x10),
                binary(SymbolSource::ObjectSymbolTable),
            ),
        )
        .expect("named symbol");
    let alias = store
        .declare(
            "outer_alias",
            function(
                defined(0x1000, 0x40),
                binary(SymbolSource::ObjectSymbolTable),
            ),
        )
        .expect("named symbol");

    assert!(
        matches!(store.resolve_address(0x1014), AddressSymbol::Unknown(AddressUnknown::AmbiguousRanges(ref ids)) if ids.contains(&outer) && ids.contains(&inner)),
        "overlapping ranges from different starts are an explicit unknown, got {:?}",
        store.resolve_address(0x1014)
    );
    assert!(
        matches!(store.resolve_address(0x1004), AddressSymbol::Containing { ref symbols, offset: 4 } if symbols == &[outer, alias]),
        "aliases at one start resolve together, got {:?}",
        store.resolve_address(0x1004)
    );
    assert!(matches!(
        store.resolve_address(0x9000),
        AddressSymbol::Unknown(AddressUnknown::NoSymbolEvidence)
    ));
    assert!(store.verify().is_empty());
}

#[test]
fn references_bind_exact_sites_to_stable_symbol_identities() {
    let mut store = SymbolStore::default();
    let target = store
        .declare(
            "printf",
            SymbolFact::new(
                SymbolKind::Function,
                SymbolBinding::Global,
                SymbolDefinition::Undefined,
                binary(SymbolSource::DynamicSymbolTable),
            ),
        )
        .expect("named symbol");
    let reference = SymbolReference {
        site: 0x3fd0,
        symbol: target,
        addend: 0,
        implicit_addend: false,
        width_bits: Some(64),
        kind: ReferenceKind::Absolute,
        format_type: Some(7),
        evidence: binary(SymbolSource::DynamicRelocation),
    };
    store
        .add_reference(reference.clone())
        .expect("known symbol");

    assert_eq!(
        store.references_at(0x3fd0).collect::<Vec<_>>(),
        vec![&reference]
    );
    assert_eq!(
        store.references_to(target).collect::<Vec<_>>(),
        vec![&reference]
    );
    assert!(store.references_at(0x4000).next().is_none());
    assert_eq!(
        store.add_reference(SymbolReference {
            symbol: SymbolId(99),
            ..reference
        }),
        Err(SymbolStoreError::UnknownSymbol(SymbolId(99))),
        "a reference to an unknown identity is rejected, not invented"
    );
    assert!(store.verify().is_empty());
}

#[test]
fn an_unnamed_symbol_is_rejected() {
    let mut store = SymbolStore::default();
    assert_eq!(
        store.declare(
            "   ",
            function(defined(0x10, 4), binary(SymbolSource::ObjectSymbolTable))
        ),
        Err(SymbolStoreError::EmptyName)
    );
    assert!(store.records().is_empty());
    assert!(store.verify().is_empty());
}

#[test]
fn attestation_adds_provenance_only_to_a_known_identity() {
    let mut store = SymbolStore::default();
    let id = store
        .declare(
            "printf",
            SymbolFact::new(
                SymbolKind::Function,
                SymbolBinding::Global,
                SymbolDefinition::Undefined,
                binary(SymbolSource::DynamicSymbolTable),
            ),
        )
        .expect("named symbol");

    let attested = store.attest(
        "printf",
        SymbolEvidence::new(SymbolAuthority::Binary, SymbolSource::ImportTable)
            .with_module("libc.so.6"),
    );
    assert_eq!(attested, Some(id));
    assert!(store
        .attest("absent", binary(SymbolSource::ImportTable))
        .is_none());
    assert_eq!(
        store.records().len(),
        1,
        "attestation never invents a record"
    );

    let record = store.get(id).expect("record");
    assert!(record.evidence().iter().any(|evidence| {
        evidence.source == SymbolSource::ImportTable
            && evidence.module.as_deref() == Some("libc.so.6")
    }));
    assert!(store.verify().is_empty());
}
