//! Use-site interpretation of constant operands and stored machine words.
//!
//! The same machine bits may validly mean different things at different use
//! sites: an integer, a relocation, an address, a string, a function, a symbol
//! plus addend, an enum member, a field offset. Nothing in this module ever
//! rewrites the bits. A [`ReferenceInterpretation`] records the exact bits, the
//! exact width, where they were read, how the operand is consumed, and every
//! piece of evidence that bears on what they mean — with one selected reading
//! and the rest retained as alternatives.
//!
//! # Why the bits are not enough
//!
//! A symbolizer that promotes every constant landing in a mapped range to an
//! address produces plausible, wrong C. Measured on a checked-in probe: a
//! `static const char *const NAMES[4]` table folded on mapped-region evidence
//! alone yields `(i == 0) ? 0x402008 : ...`, which is a number that used to be
//! an address and is neither in the rebuilt unit. The reading that is correct —
//! `(i == 0) ? "alpha" : ...` — is only available to something that knows the
//! slot is a *reference*, not a datum.
//!
//! # Evidence order
//!
//! [`EvidenceSource`] is ordered exactly as the roadmap requires, strongest
//! first:
//!
//! 1. [`EvidenceSource::Relocation`] — relocation and loader semantics.
//! 2. [`EvidenceSource::DecodedOperand`] — decoded operand role and PC
//!    calculation.
//! 3. [`EvidenceSource::MappedRegion`] — what the image maps at the value.
//! 4. [`EvidenceSource::MirProvenance`] — where the value came from in MIR.
//! 5. [`EvidenceSource::CallOrTypeConstraint`] — a parameter or field type.
//! 6. [`EvidenceSource::XrefConsistency`] — agreement with other use sites.
//! 7. [`EvidenceSource::Heuristic`] — everything conservative and unproved.
//!
//! This resolver *owns* tiers 1-3, because the program image and the
//! [`SymbolStore`] are exactly the facts needed to establish them. It does not
//! own tiers 4-7: MIR provenance, call and type constraints, and cross-use
//! agreement live in stages that this module cannot see. Those are supplied by
//! the caller through [`ReferenceRequest::supplied`], and the resolver refuses,
//! fail-closed, any supplied evidence claiming a tier it could have proved
//! itself — a caller cannot smuggle a guess in wearing a relocation's clothes.
//!
//! # Selection
//!
//! Ordering alone does not decide. Two rules constrain it:
//!
//! * **Role admission** ([`OperandRole::admits`]). A value consumed by integer
//!   arithmetic stays an integer unless a *relocation* says otherwise. Mapped
//!   region membership and heuristics cannot promote it, no matter how
//!   address-shaped it looks. This is the negative control the roadmap asks
//!   for, expressed as policy rather than as a pass-ordering accident.
//! * **A failed proof is an explicit unknown.** When the role says a value must
//!   be a reference and nothing establishes one, or when two claims of equal
//!   rank disagree, selection is [`InterpretationKind::Unknown`] with a stated
//!   reason. It never falls through to the most convenient answer.
//!
//! Losing evidence is never discarded: [`ReferenceInterpretation::alternatives`]
//! returns it, and [`ReferenceInterpretation::conflicts`] reports whether the
//! disagreement was between equals.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use object::{Object, ObjectSection, RelocationTarget};

use crate::program::image::{ImageMemoryKind, ProgramImage};
use crate::program::symbols::{
    AddressSymbol, SymbolDefinition, SymbolId, SymbolKind, SymbolRecord, SymbolStore,
};

/// Where one interpreted value was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReferenceOrigin {
    /// Decoded from an operand of the instruction at `va`.
    ///
    /// `operand` is the zero-based operand index within that instruction, so
    /// two constants in one instruction are distinct sites.
    Instruction { va: u64, operand: u8 },
    /// Read out of image storage at `va` — a table slot, a literal-pool entry,
    /// a vtable word. There is no source instruction; the place itself is the
    /// site.
    Storage { va: u64 },
}

impl ReferenceOrigin {
    /// The instruction this value was decoded from, when there is one.
    pub fn instruction_va(self) -> Option<u64> {
        match self {
            Self::Instruction { va, .. } => Some(va),
            Self::Storage { .. } => None,
        }
    }

    /// The address that identifies this site.
    pub fn va(self) -> u64 {
        match self {
            Self::Instruction { va, .. } | Self::Storage { va } => va,
        }
    }
}

/// One use site: where the value came from and how wide it exactly is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReferenceSite {
    pub origin: ReferenceOrigin,
    /// Exact width of the place in bits. Not the register it lands in, and not
    /// the architecture's pointer width: the width of the storage the bits were
    /// read from.
    pub width_bits: u8,
}

impl ReferenceSite {
    /// A value decoded from one operand of one instruction.
    pub fn operand(instruction_va: u64, operand: u8, width_bits: u8) -> Self {
        Self {
            origin: ReferenceOrigin::Instruction {
                va: instruction_va,
                operand,
            },
            width_bits,
        }
    }

    /// A machine word read out of image storage.
    pub fn storage(va: u64, width_bits: u8) -> Self {
        Self {
            origin: ReferenceOrigin::Storage { va },
            width_bits,
        }
    }
}

/// How the value is consumed at its use site.
///
/// This is the question "is this operand being used as a reference?", which is
/// separate from "could these bits be an address?". Answering only the second
/// is what turns arithmetic into fiction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OperandRole {
    /// The decoder proved an address computation: a PC-relative `lea`, an
    /// `adrp`/`add` pair, an absolute memory displacement.
    AddressComputation,
    /// A call or branch destination.
    BranchTarget,
    /// The address of a load or store of the stated width.
    MemoryAccess,
    /// An argument at a call whose contract declares this parameter a pointer.
    PointerArgument,
    /// The value is consumed by integer arithmetic, a shift, a mask, or a
    /// comparison against another integer.
    ScalarArithmetic,
    /// Nothing at the site says how the value is used.
    Unclassified,
}

impl OperandRole {
    /// Whether evidence of this strength may promote a value in this role from
    /// an integer to a reference.
    ///
    /// Relocations are proof and are admitted everywhere: a relocated place
    /// *is* a reference no matter what the surrounding code does with it.
    /// Everything weaker needs the role to already say "reference". A value
    /// consumed by arithmetic admits nothing below a relocation, which is what
    /// keeps a mapped numeric numeric.
    pub fn admits(self, source: EvidenceSource) -> bool {
        if source == EvidenceSource::Relocation {
            return true;
        }
        match self {
            Self::AddressComputation
            | Self::BranchTarget
            | Self::MemoryAccess
            | Self::PointerArgument => true,
            // The decoder's own tag is the only thing that may speak for a site
            // whose role nothing else described; mapped-range membership and
            // heuristics may not.
            Self::Unclassified => source == EvidenceSource::DecodedOperand,
            Self::ScalarArithmetic => false,
        }
    }
}

/// Ranked evidence classes, strongest first. The ordinal is the roadmap's
/// resolution order and `Ord` follows it, so `min()` is "the strongest claim".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EvidenceSource {
    /// A relocation or loader rule fixes this place's runtime value.
    Relocation,
    /// The instruction encoding states an address computation or a
    /// program-counter calculation.
    DecodedOperand,
    /// The image maps the value, and the mapping states its permissions.
    MappedRegion,
    /// Typed MIR says where the value came from.
    MirProvenance,
    /// A call contract or a recovered type constrains the operand.
    CallOrTypeConstraint,
    /// Other use sites of the same value agree on a reading.
    XrefConsistency,
    /// A conservative shape or range heuristic, proving nothing.
    Heuristic,
}

impl EvidenceSource {
    /// Tiers this resolver establishes from the image and the symbol store. A
    /// caller may not supply these; it has not read what the resolver reads.
    fn is_resolver_owned(self) -> bool {
        matches!(
            self,
            Self::Relocation | Self::DecodedOperand | Self::MappedRegion
        )
    }
}

/// How strongly one piece of evidence holds, independent of its tier. A
/// relocation is proof; a printable run in `.rodata` is at best likely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Confidence {
    Possible,
    Likely,
    Proved,
}

/// A contextual reading of the bits at one use site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterpretationKind {
    /// A number. The default reading, and the only safe one under arithmetic.
    Integer,
    /// An address in this image with no symbol attached.
    Address { va: u64 },
    /// A defined symbol plus a byte addend. `va` is the in-image address the
    /// reference denotes, present only when this image defines the symbol; an
    /// import resolves to an address no value in this file predicts.
    SymbolAddend {
        symbol: SymbolId,
        addend: i64,
        va: Option<u64>,
    },
    /// An address inside executable storage.
    CodeAddress { va: u64 },
    /// The address of a NUL-terminated string, with its exact recovered bytes.
    StringLiteral { va: u64, text: String },
    /// No reading is proved. Carries why.
    Unknown(UnresolvedReason),
}

impl InterpretationKind {
    /// Whether this reading says the bits are a plain number.
    pub fn is_numeric(&self) -> bool {
        matches!(self, Self::Integer)
    }

    /// The image address this reading denotes, when it denotes one.
    pub fn address(&self) -> Option<u64> {
        match self {
            Self::Address { va } | Self::CodeAddress { va } | Self::StringLiteral { va, .. } => {
                Some(*va)
            }
            Self::SymbolAddend { va, .. } => *va,
            Self::Integer | Self::Unknown(_) => None,
        }
    }
}

/// Why no reading was proved. An explicit unknown, never a silent fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UnresolvedReason {
    /// Nothing bearing on this site was found at all.
    NoEvidence,
    /// The role says the value is used as a reference, but the image maps
    /// nothing at it.
    UnmappedReference,
    /// Two claims of equal rank disagree; selecting one would be a guess.
    ConflictingEvidence,
    /// A relocation fixes this place's runtime value and this resolver could
    /// not compute it. The stored bytes are not the answer.
    UnresolvedRelocation,
    /// The image itself is only partly readable at this site.
    ImageIncomplete,
}

/// One claim about a use site, with the tier and provenance that support it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterpretationEvidence {
    pub source: EvidenceSource,
    pub kind: InterpretationKind,
    pub confidence: Confidence,
    /// Why this evidence exists, in the vocabulary of the thing that produced
    /// it. Retained so a rejected reading can still be explained.
    pub note: &'static str,
}

impl InterpretationEvidence {
    pub fn new(
        source: EvidenceSource,
        kind: InterpretationKind,
        confidence: Confidence,
        note: &'static str,
    ) -> Self {
        Self {
            source,
            kind,
            confidence,
            note,
        }
    }
}

/// Everything known about the bits at one use site.
///
/// Construction never destroys evidence. [`Self::selected`] is a policy
/// decision over the retained set; [`Self::alternatives`] is the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceInterpretation {
    site: ReferenceSite,
    bits: u64,
    role: OperandRole,
    evidence: Vec<InterpretationEvidence>,
    selected: usize,
    conflicts: BTreeSet<EvidenceSource>,
}

impl ReferenceInterpretation {
    /// The site these bits were read at.
    pub fn site(&self) -> ReferenceSite {
        self.site
    }

    /// The exact machine bits, zero-extended from the site's width. Never
    /// rewritten by interpretation.
    pub fn bits(&self) -> u64 {
        self.bits
    }

    /// Exact width of the place in bits.
    pub fn width_bits(&self) -> u8 {
        self.site.width_bits
    }

    /// How the value is consumed at this site.
    pub fn role(&self) -> OperandRole {
        self.role
    }

    /// The reading selected by the ordering and the role admission rule.
    pub fn selected(&self) -> &InterpretationEvidence {
        &self.evidence[self.selected]
    }

    /// The selected reading's kind.
    pub fn kind(&self) -> &InterpretationKind {
        &self.selected().kind
    }

    /// Whether the selected reading says the bits are a plain number.
    pub fn is_numeric(&self) -> bool {
        self.kind().is_numeric()
    }

    /// Every retained claim, selected and rejected alike, strongest tier first.
    pub fn evidence(&self) -> &[InterpretationEvidence] {
        &self.evidence
    }

    /// Every claim that was not selected. Retained per design rule 3: selection
    /// policy never destroys conflicts.
    pub fn alternatives(&self) -> impl Iterator<Item = &InterpretationEvidence> {
        self.evidence
            .iter()
            .enumerate()
            .filter(move |(index, _)| *index != self.selected)
            .map(|(_, evidence)| evidence)
    }

    /// Tiers at which two retained claims disagreed.
    pub fn conflicts(&self) -> &BTreeSet<EvidenceSource> {
        &self.conflicts
    }

    /// Build one interpretation from a complete evidence set.
    ///
    /// The set is sorted by tier, disagreements between equals are recorded,
    /// and the first admissible non-integer reading wins. An empty set, or one
    /// whose only readings the role refuses, resolves to a number when the role
    /// permits a number and to an explicit unknown when it does not.
    fn resolve(
        site: ReferenceSite,
        bits: u64,
        role: OperandRole,
        mut evidence: Vec<InterpretationEvidence>,
    ) -> Self {
        evidence.sort_by(|left, right| {
            left.source
                .cmp(&right.source)
                .then(right.confidence.cmp(&left.confidence))
        });

        let mut conflicts = BTreeSet::new();
        for window in evidence.windows(2) {
            let (left, right) = (&window[0], &window[1]);
            if left.source == right.source && left.kind != right.kind {
                conflicts.insert(left.source);
            }
        }

        let admissible = evidence.iter().position(|candidate| {
            !candidate.kind.is_numeric()
                && !matches!(candidate.kind, InterpretationKind::Unknown(_))
                && role.admits(candidate.source)
                && !conflicts.contains(&candidate.source)
        });

        if let Some(selected) = admissible {
            return Self {
                site,
                bits,
                role,
                evidence,
                selected,
                conflicts,
            };
        }

        // Nothing was admitted. Say why, in the site's own terms.
        let fallback = if !conflicts.is_empty() {
            InterpretationKind::Unknown(UnresolvedReason::ConflictingEvidence)
        } else if let Some(reason) = evidence.iter().find_map(|candidate| match candidate.kind {
            InterpretationKind::Unknown(reason) => Some(reason),
            _ => None,
        }) {
            InterpretationKind::Unknown(reason)
        } else if matches!(
            role,
            OperandRole::BranchTarget | OperandRole::MemoryAccess | OperandRole::PointerArgument
        ) && !evidence
            .iter()
            .any(|candidate| !candidate.kind.is_numeric())
        {
            // The role states the operand is a reference and nothing in the
            // image backs one. Rule 8: an explicit unknown, not a guess.
            InterpretationKind::Unknown(UnresolvedReason::UnmappedReference)
        } else {
            InterpretationKind::Integer
        };

        let note = match fallback {
            InterpretationKind::Integer => "no admissible reference reading for this role",
            _ => "no reading proved at this site",
        };
        evidence.push(InterpretationEvidence::new(
            EvidenceSource::DecodedOperand,
            fallback,
            Confidence::Possible,
            note,
        ));
        let selected = evidence.len() - 1;
        Self {
            site,
            bits,
            role,
            evidence,
            selected,
            conflicts,
        }
    }
}

/// One question for the resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceRequest {
    pub site: ReferenceSite,
    /// The exact bits at the site, zero-extended.
    pub bits: u64,
    pub role: OperandRole,
    /// Evidence the caller holds that the image and the symbol store cannot
    /// supply: MIR provenance, call and type constraints, cross-use agreement,
    /// and conservative heuristics. Anything claiming a resolver-owned tier is
    /// rejected rather than trusted.
    pub supplied: Vec<InterpretationEvidence>,
}

impl ReferenceRequest {
    /// A request carrying no caller evidence.
    pub fn new(site: ReferenceSite, bits: u64, role: OperandRole) -> Self {
        Self {
            site,
            bits,
            role,
            supplied: Vec::new(),
        }
    }

    /// Attach one piece of caller-owned evidence.
    pub fn with(mut self, evidence: InterpretationEvidence) -> Self {
        self.supplied.push(evidence);
        self
    }
}

/// What a relocation fixes at one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelocatedPlace {
    /// The loader stores this exact in-image address.
    Absolute { va: u64 },
    /// A relocation covers the place and this index could not compute its
    /// runtime value. The stored bytes are not the answer.
    Unresolved,
}

/// Resolves use-site interpretations from the program image, its relocations,
/// and the canonical symbol store.
///
/// One resolver serves a whole image. Building it reads the object's relocation
/// tables once; every query after that is index lookups.
#[derive(Debug)]
pub struct ReferenceResolver<'a> {
    image: &'a ProgramImage,
    symbols: &'a SymbolStore,
    /// Places whose runtime value a relocation fixes, keyed by place address.
    relocated: BTreeMap<u64, RelocatedPlace>,
    /// VA to exact C-string bytes, for the string reading.
    strings: &'a HashMap<u64, String>,
}

/// Strings are not the resolver's to discover; a caller that has no index
/// passes this.
static NO_STRINGS: std::sync::LazyLock<HashMap<u64, String>> =
    std::sync::LazyLock::new(HashMap::new);

impl<'a> ReferenceResolver<'a> {
    /// Index one image's relocations and bind the symbol and string evidence.
    pub fn new(
        image: &'a ProgramImage,
        symbols: &'a SymbolStore,
        strings: &'a HashMap<u64, String>,
    ) -> Self {
        Self {
            relocated: index_relocated_places(image),
            image,
            symbols,
            strings,
        }
    }

    /// A resolver with no string index, for callers that only ask about
    /// addresses and numbers.
    pub fn without_strings(image: &'a ProgramImage, symbols: &'a SymbolStore) -> Self {
        Self::new(image, symbols, &NO_STRINGS)
    }

    /// Number of places whose runtime value a relocation fixes.
    pub fn relocated_place_count(&self) -> usize {
        self.relocated.len()
    }

    /// Whether a relocation covers the `width_bits`-wide place at `va`.
    ///
    /// Reading the image bytes at such a place gives the link-time contents,
    /// which the loader is entitled to overwrite. Callers that fold stored data
    /// into constants must not fold these.
    pub fn place_is_relocated(&self, va: u64, width_bits: u8) -> bool {
        self.relocation_at(va, width_bits).is_some()
            || self.symbols.references_at(va).next().is_some()
    }

    fn relocation_at(&self, va: u64, width_bits: u8) -> Option<RelocatedPlace> {
        let end = va.checked_add(u64::from(width_bits.div_ceil(8)))?;
        self.relocated
            .range(va..end)
            .next()
            .map(|(_, place)| *place)
    }

    /// Interpret the bits at one use site.
    pub fn interpret(&self, request: &ReferenceRequest) -> ReferenceInterpretation {
        let mut evidence = Vec::new();

        // Tier 1: relocation and loader semantics. A symbol-backed relocation
        // is already indexed with its provenance by the symbol store, and it is
        // the better record; the local index speaks only for the places the
        // store cannot represent, which is exactly the symbol-less
        // `R_*_RELATIVE` class that fills a `const` pointer table.
        let mut symbol_backed = false;
        for reference in self.symbols.references_at(request.site.origin.va()) {
            symbol_backed = true;
            evidence.push(InterpretationEvidence::new(
                EvidenceSource::Relocation,
                InterpretationKind::SymbolAddend {
                    symbol: reference.symbol,
                    addend: reference.addend,
                    va: self
                        .symbol_address(reference.symbol)
                        .map(|address| address.saturating_add_signed(reference.addend)),
                },
                Confidence::Proved,
                "a symbol-backed relocation applies to this place",
            ));
        }
        if !symbol_backed {
            if let Some(place) =
                self.relocation_at(request.site.origin.va(), request.site.width_bits)
            {
                match place {
                    RelocatedPlace::Absolute { va } => {
                        evidence.push(InterpretationEvidence::new(
                            EvidenceSource::Relocation,
                            self.describe_address(va),
                            Confidence::Proved,
                            "a relocation fixes this place's runtime value",
                        ));
                    }
                    RelocatedPlace::Unresolved => {
                        evidence.push(InterpretationEvidence::new(
                            EvidenceSource::Relocation,
                            InterpretationKind::Unknown(UnresolvedReason::UnresolvedRelocation),
                            Confidence::Proved,
                            "a relocation covers this place and its target is not in this image",
                        ));
                    }
                }
            }
        }

        // Tier 2: decoded operand role and program-counter calculation.
        if matches!(
            request.role,
            OperandRole::AddressComputation | OperandRole::BranchTarget
        ) {
            evidence.push(InterpretationEvidence::new(
                EvidenceSource::DecodedOperand,
                self.describe_address(request.bits),
                Confidence::Likely,
                "the instruction encoding states an address computation",
            ));
        }

        // Tier 3: what the image maps at the value.
        if self.image.memory_kind_at(request.bits).is_some() {
            evidence.push(InterpretationEvidence::new(
                EvidenceSource::MappedRegion,
                self.describe_address(request.bits),
                Confidence::Possible,
                "the image maps storage at this value",
            ));
        }

        // Tiers 4-7 belong to stages this resolver cannot see. Take them only
        // from the caller, and only for tiers the caller could actually hold.
        for supplied in &request.supplied {
            if supplied.source.is_resolver_owned() {
                continue;
            }
            evidence.push(supplied.clone());
        }

        ReferenceInterpretation::resolve(request.site, request.bits, request.role, evidence)
    }

    /// Interpret the machine word stored at `place`, reading it from the image.
    ///
    /// Returns `None` when the image does not map `width_bits` at `place`.
    pub fn interpret_storage(
        &self,
        place: u64,
        width_bits: u8,
        role: OperandRole,
    ) -> Option<ReferenceInterpretation> {
        let bits = self.read_word(place, width_bits)?;
        Some(self.interpret(&ReferenceRequest::new(
            ReferenceSite::storage(place, width_bits),
            bits,
            role,
        )))
    }

    /// The exact zero-extended machine word at `place`, honouring the image's
    /// byte order.
    pub fn read_word(&self, place: u64, width_bits: u8) -> Option<u64> {
        if !matches!(width_bits, 8 | 16 | 32 | 64) {
            return None;
        }
        let width = usize::from(width_bits / 8);
        let offset = self.image.va_to_file_offset(place)?;
        let slice = self.image.bytes().get(offset..offset.checked_add(width)?)?;
        let mut buffer = [0u8; 8];
        if self.image.endianness() == crate::core::binary::Endianness::Little {
            buffer[..width].copy_from_slice(slice);
            Some(u64::from_le_bytes(buffer))
        } else {
            buffer[8 - width..].copy_from_slice(slice);
            Some(u64::from_be_bytes(buffer))
        }
    }

    /// The strongest reading of one in-image address, from the image and the
    /// symbol store alone.
    fn describe_address(&self, va: u64) -> InterpretationKind {
        if self.image.memory_kind_at(va).is_none() {
            return InterpretationKind::Unknown(UnresolvedReason::UnmappedReference);
        }
        if let Some(text) = self.strings.get(&va) {
            return InterpretationKind::StringLiteral {
                va,
                text: text.clone(),
            };
        }
        if let Some(symbol) = self.exact_symbol_at(va) {
            return InterpretationKind::SymbolAddend {
                symbol,
                addend: 0,
                va: Some(va),
            };
        }
        if self
            .image
            .executable_ranges()
            .any(|range| range.contains(&va))
        {
            return InterpretationKind::CodeAddress { va };
        }
        InterpretationKind::Address { va }
    }

    /// The single defined function or data symbol starting exactly at `va`.
    /// Aliases and ambiguity resolve to no symbol rather than to an arbitrary
    /// pick — [`SymbolStore::resolve_address`] already refuses to guess, and
    /// this keeps that refusal.
    fn exact_symbol_at(&self, va: u64) -> Option<SymbolId> {
        let AddressSymbol::Exact { symbols } = self.symbols.resolve_address(va) else {
            return None;
        };
        let mut named = symbols.into_iter().filter(|id| {
            self.symbols
                .get(*id)
                .and_then(SymbolRecord::selected)
                .is_some_and(|fact| {
                    matches!(fact.kind, SymbolKind::Function | SymbolKind::Data)
                        && matches!(fact.definition, SymbolDefinition::Defined { .. })
                })
        });
        let first = named.next()?;
        named.next().is_none().then_some(first)
    }

    /// The address this image defines `symbol` at, when it defines one.
    fn symbol_address(&self, symbol: SymbolId) -> Option<u64> {
        match self.symbols.get(symbol)?.selected()?.definition {
            SymbolDefinition::Defined { address, .. } => Some(address),
            _ => None,
        }
    }

    /// Whether the image maps `va` as storage the program may not write.
    pub fn is_readonly(&self, va: u64) -> bool {
        self.image.memory_kind_at(va) == Some(ImageMemoryKind::ReadOnly)
    }
}

/// Read every relocation in `image` and record what each fixes.
///
/// Symbol-backed relocations are already indexed by [`SymbolStore`]; this index
/// exists for the ones that are not — `R_*_RELATIVE` and friends carry no
/// symbol at all, and they are exactly what fills a `const` pointer table.
fn index_relocated_places(image: &ProgramImage) -> BTreeMap<u64, RelocatedPlace> {
    let mut places = BTreeMap::new();
    let Ok(object) = crate::decompile::profile::parse_object(image.bytes()) else {
        return places;
    };
    let mut record = |site: u64, relocation: &object::Relocation| {
        let place = match relocation.target() {
            RelocationTarget::Absolute => {
                // The loader stores `base + addend`. In a non-relocatable image
                // the addend is already the final virtual address.
                match u64::try_from(relocation.addend()) {
                    Ok(va) if image.memory_kind_at(va).is_some() => RelocatedPlace::Absolute { va },
                    _ => RelocatedPlace::Unresolved,
                }
            }
            RelocationTarget::Symbol(_) | RelocationTarget::Section(_) => {
                RelocatedPlace::Unresolved
            }
            _ => RelocatedPlace::Unresolved,
        };
        places.insert(site, place);
    };
    if let Some(dynamic) = object.dynamic_relocations() {
        for (site, relocation) in dynamic {
            record(site, &relocation);
        }
    }
    for section in object.sections() {
        for (site, relocation) in section.relocations() {
            record(site, &relocation);
        }
    }
    places
}

#[cfg(test)]
mod tests;
