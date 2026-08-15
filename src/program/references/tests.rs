//! Resolver tests.
//!
//! Every image here is a real checked-in binary. The negative controls are the
//! point of the file: a value that lands in a mapped range and is consumed by
//! arithmetic must survive interpretation as a number.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::*;
use crate::program::session::ProgramSession;

fn sample() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2")
}

fn session() -> ProgramSession {
    ProgramSession::from_path(&sample()).expect("index the checked-in ELF")
}

/// A VA the image maps, so "mapped" is a fact rather than an assumption.
fn a_mapped_address(image: &ProgramImage) -> u64 {
    image
        .sections()
        .find(|section| section.name() == ".rodata" && !section.data().is_empty())
        .map(|section| section.address())
        .expect("the sample has a non-empty .rodata")
}

#[test]
fn a_mapped_value_consumed_by_arithmetic_stays_a_number() {
    let session = session();
    let symbols = session.symbol_store();
    let resolver = ReferenceResolver::without_strings(session.image(), &symbols);
    let mapped = a_mapped_address(session.image());
    assert!(
        session.image().memory_kind_at(mapped).is_some(),
        "the control is only meaningful if {mapped:#x} really is mapped"
    );

    let interpretation = resolver.interpret(&ReferenceRequest::new(
        ReferenceSite::operand(0x1000, 1, 64),
        mapped,
        OperandRole::ScalarArithmetic,
    ));

    assert!(
        interpretation.is_numeric(),
        "a mapped value under arithmetic resolved to {:?}",
        interpretation.kind()
    );
    // The mapped-region reading is not destroyed, only refused.
    assert!(
        interpretation
            .alternatives()
            .any(|candidate| candidate.source == EvidenceSource::MappedRegion),
        "the refused reading must be retained as an alternative"
    );
    assert_eq!(
        interpretation.bits(),
        mapped,
        "the bits are never rewritten"
    );
    assert_eq!(interpretation.width_bits(), 64);
}

#[test]
fn the_same_bits_at_an_address_role_resolve_to_an_address() {
    let session = session();
    let symbols = session.symbol_store();
    let resolver = ReferenceResolver::without_strings(session.image(), &symbols);
    let mapped = a_mapped_address(session.image());

    let interpretation = resolver.interpret(&ReferenceRequest::new(
        ReferenceSite::operand(0x1000, 1, 64),
        mapped,
        OperandRole::AddressComputation,
    ));

    assert!(
        !interpretation.is_numeric(),
        "an address-role operand over mapped storage stayed numeric"
    );
    assert_eq!(interpretation.kind().address(), Some(mapped));
}

#[test]
fn an_unmapped_value_used_as_a_pointer_is_an_explicit_unknown() {
    let session = session();
    let symbols = session.symbol_store();
    let resolver = ReferenceResolver::without_strings(session.image(), &symbols);
    let unmapped = 0xdead_0000_0000_0000u64;
    assert!(session.image().memory_kind_at(unmapped).is_none());

    let interpretation = resolver.interpret(&ReferenceRequest::new(
        ReferenceSite::operand(0x1000, 0, 64),
        unmapped,
        OperandRole::MemoryAccess,
    ));

    assert_eq!(
        *interpretation.kind(),
        InterpretationKind::Unknown(UnresolvedReason::UnmappedReference),
        "a failed proof must be an explicit unknown, not a fallback"
    );
}

#[test]
fn an_unclassified_role_refuses_mapped_region_evidence_alone() {
    let session = session();
    let symbols = session.symbol_store();
    let resolver = ReferenceResolver::without_strings(session.image(), &symbols);
    let mapped = a_mapped_address(session.image());

    let interpretation = resolver.interpret(&ReferenceRequest::new(
        ReferenceSite::operand(0x1000, 0, 64),
        mapped,
        OperandRole::Unclassified,
    ));

    assert!(
        interpretation.is_numeric(),
        "mapped-range membership alone promoted an unclassified operand to {:?}",
        interpretation.kind()
    );
}

#[test]
fn a_caller_may_not_supply_a_tier_the_resolver_owns() {
    let session = session();
    let symbols = session.symbol_store();
    let resolver = ReferenceResolver::without_strings(session.image(), &symbols);

    let forged = ReferenceRequest::new(
        ReferenceSite::operand(0x1000, 0, 64),
        0x4242_4242,
        OperandRole::ScalarArithmetic,
    )
    .with(InterpretationEvidence::new(
        EvidenceSource::Relocation,
        InterpretationKind::Address { va: 0x4242_4242 },
        Confidence::Proved,
        "a claim the caller cannot hold",
    ));

    let interpretation = resolver.interpret(&forged);

    assert!(
        interpretation.is_numeric(),
        "supplied relocation-tier evidence was trusted"
    );
    assert!(
        interpretation
            .evidence()
            .iter()
            .all(|candidate| candidate.source != EvidenceSource::Relocation),
        "the forged tier must be dropped, not merely outranked"
    );
}

#[test]
fn supplied_call_constraints_are_admitted_for_a_pointer_argument() {
    let session = session();
    let symbols = session.symbol_store();
    let resolver = ReferenceResolver::without_strings(session.image(), &symbols);
    let mapped = a_mapped_address(session.image());

    let request = ReferenceRequest::new(
        ReferenceSite::operand(0x1000, 0, 64),
        mapped,
        OperandRole::PointerArgument,
    )
    .with(InterpretationEvidence::new(
        EvidenceSource::CallOrTypeConstraint,
        InterpretationKind::Address { va: mapped },
        Confidence::Likely,
        "the callee's contract declares this parameter a pointer",
    ));

    let interpretation = resolver.interpret(&request);
    assert_eq!(interpretation.kind().address(), Some(mapped));
    // Mapped-region evidence outranks a call constraint, so the constraint is
    // an alternative here — retained, not deleted.
    assert!(interpretation
        .evidence()
        .iter()
        .any(|candidate| candidate.source == EvidenceSource::CallOrTypeConstraint));
}

#[test]
fn equal_rank_disagreement_resolves_to_conflict_rather_than_a_pick() {
    let session = session();
    let symbols = session.symbol_store();
    let resolver = ReferenceResolver::without_strings(session.image(), &symbols);
    let mapped = a_mapped_address(session.image());

    let request = ReferenceRequest::new(
        ReferenceSite::operand(0x1000, 0, 64),
        mapped,
        OperandRole::MemoryAccess,
    )
    .with(InterpretationEvidence::new(
        EvidenceSource::XrefConsistency,
        InterpretationKind::CodeAddress { va: mapped },
        Confidence::Likely,
        "one use site reads this as code",
    ))
    .with(InterpretationEvidence::new(
        EvidenceSource::XrefConsistency,
        InterpretationKind::Address { va: mapped + 1 },
        Confidence::Likely,
        "another use site reads this as a different datum",
    ));

    let interpretation = resolver.interpret(&request);

    assert!(interpretation
        .conflicts()
        .contains(&EvidenceSource::XrefConsistency));
    // The stronger mapped-region reading is still available and still wins;
    // the conflict is recorded at its own tier rather than poisoning the site.
    assert_eq!(interpretation.kind().address(), Some(mapped));
    assert_eq!(interpretation.evidence().len(), 3);
}

#[test]
fn a_conflict_at_the_only_available_tier_is_an_explicit_unknown() {
    let session = session();
    let symbols = session.symbol_store();
    let resolver = ReferenceResolver::without_strings(session.image(), &symbols);
    let unmapped = 0xdead_0000_0000_0000u64;

    let request = ReferenceRequest::new(
        ReferenceSite::operand(0x1000, 0, 64),
        unmapped,
        OperandRole::MemoryAccess,
    )
    .with(InterpretationEvidence::new(
        EvidenceSource::MirProvenance,
        InterpretationKind::Address { va: 0x10 },
        Confidence::Likely,
        "one definition",
    ))
    .with(InterpretationEvidence::new(
        EvidenceSource::MirProvenance,
        InterpretationKind::Address { va: 0x20 },
        Confidence::Likely,
        "a different definition",
    ));

    let interpretation = resolver.interpret(&request);

    assert_eq!(
        *interpretation.kind(),
        InterpretationKind::Unknown(UnresolvedReason::ConflictingEvidence)
    );
    assert_eq!(interpretation.alternatives().count(), 2);
}

#[test]
fn a_string_address_resolves_to_its_exact_bytes() {
    let session = session();
    let symbols = session.symbol_store();
    let strings = crate::ir::strings_fold::collect_string_pool_from_image(session.image());
    assert!(!strings.is_empty(), "the sample has recoverable strings");
    let (&va, text) = strings.iter().next().expect("one string");
    let expected = text.clone();

    let resolver = ReferenceResolver::new(session.image(), &symbols, &strings);
    let interpretation = resolver.interpret(&ReferenceRequest::new(
        ReferenceSite::operand(0x1000, 0, 64),
        va,
        OperandRole::PointerArgument,
    ));

    assert_eq!(
        *interpretation.kind(),
        InterpretationKind::StringLiteral { va, text: expected }
    );
}

#[test]
fn the_same_string_address_in_arithmetic_is_still_a_number() {
    let session = session();
    let symbols = session.symbol_store();
    let strings = crate::ir::strings_fold::collect_string_pool_from_image(session.image());
    let (&va, _) = strings.iter().next().expect("one string");

    let resolver = ReferenceResolver::new(session.image(), &symbols, &strings);
    let interpretation = resolver.interpret(&ReferenceRequest::new(
        ReferenceSite::operand(0x1000, 0, 64),
        va,
        OperandRole::ScalarArithmetic,
    ));

    assert!(
        interpretation.is_numeric(),
        "a string address under arithmetic became {:?}",
        interpretation.kind()
    );
}

#[test]
fn the_sample_image_has_relocated_places_and_they_are_reported_as_such() {
    let session = session();
    let symbols = session.symbol_store();
    let resolver = ReferenceResolver::without_strings(session.image(), &symbols);

    assert!(
        resolver.relocated_place_count() > 0,
        "a dynamically linked ELF must have relocated places"
    );
    let (&site, _) = resolver
        .relocated
        .iter()
        .next()
        .expect("at least one relocated place");
    assert!(resolver.place_is_relocated(site, 64));
    // A place one pointer before the first relocation is not covered by it.
    assert!(!resolver.place_is_relocated(site.saturating_sub(64), 8));
}

#[test]
fn reading_a_word_honours_the_image_byte_order_and_bounds() {
    let session = session();
    let symbols = session.symbol_store();
    let resolver = ReferenceResolver::without_strings(session.image(), &symbols);
    let rodata = a_mapped_address(session.image());

    let byte = resolver.read_word(rodata, 8).expect("a mapped byte");
    assert!(byte <= u64::from(u8::MAX));
    assert_eq!(
        resolver.read_word(rodata, 24),
        None,
        "a width the machine has no place for is refused"
    );
    assert_eq!(resolver.read_word(0xdead_0000_0000_0000, 64), None);
}

#[test]
fn interpreting_stored_words_reads_through_the_image() {
    let session = session();
    let symbols = session.symbol_store();
    let strings: HashMap<u64, String> =
        crate::ir::strings_fold::collect_string_pool_from_image(session.image());
    let resolver = ReferenceResolver::new(session.image(), &symbols, &strings);
    let rodata = a_mapped_address(session.image());

    let interpretation = resolver
        .interpret_storage(rodata, 32, OperandRole::ScalarArithmetic)
        .expect("mapped storage");
    assert_eq!(interpretation.site(), ReferenceSite::storage(rodata, 32));
    assert!(interpretation.is_numeric());
    assert_eq!(
        resolver.interpret_storage(0xdead_0000_0000_0000, 64, OperandRole::MemoryAccess),
        None
    );
}

#[test]
fn readonly_storage_is_distinguished_from_writable_storage() {
    let session = session();
    let symbols = session.symbol_store();
    let resolver = ReferenceResolver::without_strings(session.image(), &symbols);
    assert!(resolver.is_readonly(a_mapped_address(session.image())));
    assert!(!resolver.is_readonly(0xdead_0000_0000_0000));
}

#[test]
fn evidence_is_ordered_exactly_as_the_resolution_order_requires() {
    assert!(EvidenceSource::Relocation < EvidenceSource::DecodedOperand);
    assert!(EvidenceSource::DecodedOperand < EvidenceSource::MappedRegion);
    assert!(EvidenceSource::MappedRegion < EvidenceSource::MirProvenance);
    assert!(EvidenceSource::MirProvenance < EvidenceSource::CallOrTypeConstraint);
    assert!(EvidenceSource::CallOrTypeConstraint < EvidenceSource::XrefConsistency);
    assert!(EvidenceSource::XrefConsistency < EvidenceSource::Heuristic);
}

#[test]
fn only_a_relocation_may_promote_a_value_that_arithmetic_consumes() {
    for source in [
        EvidenceSource::DecodedOperand,
        EvidenceSource::MappedRegion,
        EvidenceSource::MirProvenance,
        EvidenceSource::CallOrTypeConstraint,
        EvidenceSource::XrefConsistency,
        EvidenceSource::Heuristic,
    ] {
        assert!(
            !OperandRole::ScalarArithmetic.admits(source),
            "{source:?} was admitted under arithmetic"
        );
    }
    assert!(OperandRole::ScalarArithmetic.admits(EvidenceSource::Relocation));
    for role in [
        OperandRole::AddressComputation,
        OperandRole::BranchTarget,
        OperandRole::MemoryAccess,
        OperandRole::PointerArgument,
    ] {
        assert!(role.admits(EvidenceSource::Heuristic), "{role:?}");
    }
}
