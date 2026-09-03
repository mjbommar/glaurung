//! FLIRT-style signature matching (#158).
//!
//! Loads a JSON signature library produced by
//! `python -m glaurung.tools.build_flirt_library` and uses it to rename
//! `sub_*` functions in stripped binaries during the analysis pass.
//!
//! # v2: masks, a CRC, and referenced names
//!
//! v1 was exact byte equality on a fixed-length prologue read from *linked*
//! sample binaries. That cannot work, and the reason is structural rather than
//! statistical: a linked image has no relocation table, so every `call rel32`
//! and every RIP-relative `lea` in the window is an absolute the linker chose,
//! and it changes on the next link. `tests/flirt_signature_matching.rs`
//! measures the damage on the one real archive in the tree.
//!
//! v2 keeps the same file and the same entry point and adds the three fields
//! that make a signature survive relinking, in FLIRT's own order:
//!
//! 1. **A variant-byte mask.** [`FlirtSignatureEntry::mask_hex`] marks each
//!    pattern byte fixed (`ff`) or variant (`00`). Derived from the relocation
//!    table of the `.o` inside a `.a` -- see [`archive`]. **Absent means all
//!    bytes fixed**, so every v1 library keeps its exact-match behaviour.
//! 2. **A CRC16 over the bytes after the pattern, up to the first variant
//!    byte.** [`crc16`] is IDA's exact variant. This is what stops a masked
//!    32-byte pattern from degenerating into a prefix match.
//! 3. **Referenced names as a second-level disambiguator.** When pattern and
//!    CRC leave more than one candidate, FLIRT asks what the *callees* are
//!    named. [`FlirtLibrary::match_at_with_refs`] does the same, and returns
//!    [`FlirtMatch::Ambiguous`] rather than guessing when it still cannot tell.
//!
//! # Why "no name" beats "a name"
//!
//! A FLIRT hit writes a name under `set_by=flirt`, which
//! `python/glaurung/llm/kb/provenance.py` ranks at 50 -- above `auto`, above
//! `propagated`. A false positive here does not degrade an answer, it
//! outranks the correct one. Every ambiguity in this module therefore resolves
//! to silence.
//!
//! # Evidence and the membership gate
//!
//! [`FlirtLibrary::match_at_with_evidence`] and
//! [`match_functions_with_evidence`] are the KB-facing counterparts of
//! [`FlirtLibrary::match_at`] and [`apply_flirt_overrides`]: same matcher,
//! same escalation order, but the return value names *which* level resolved
//! the match (`"flirt-L1"` pattern only, `"flirt-L2"` the CRC was needed,
//! `"flirt-L4"` a referenced name broke a tie -- L3, the tail-byte
//! discriminator, is schema-reserved and not implemented by this matcher) so
//! `python/glaurung/llm/kb/siglib.py` can write an auditable `function_match`
//! row rather than a bare rename. See
//! `docs/history/program-measures-2026-09-02/03-schema.sql` section 8 and
//! `docs/reference/function-signature-libraries.md`.
//!
//! [`FlirtLibrary::masked_pattern_identities`] is the identity string this
//! module contributes to `crate::identity::gate`: the masked pattern, hex
//! encoded with every variant byte forced to `0x00`, mirroring the ambiguity
//! key `python/glaurung/tools/build_flirt_library.py::_masked_pattern`
//! already uses to decide which signatures collide.

pub mod archive;
pub mod crc16;
pub mod gsig;

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::core::function::Function;

pub use crc16::crc16;

/// A name referenced from inside a signature's function body.
///
/// FLIRT records these as `^offset name` in a `.pat` line. They are the
/// second-level disambiguator: two library functions can share 32 masked bytes
/// and a CRC and still call different things.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlirtReference {
    /// Byte offset from the function's entry at which the reference occurs.
    pub offset: u32,
    /// The symbol name the reference resolves to in the library.
    pub name: String,
}

/// The `crate::identity::gate` / `identity_filter.scheme` and
/// `siglib_function.scheme` value for [`FlirtLibrary::masked_pattern_identities`].
///
/// Not a `function_identity` scheme: a masked pattern is not an equality key
/// (two different functions routinely share one until the CRC and references
/// disambiguate them), so it has no business in that table. It exists only as
/// gate/provenance input -- "is this masked pattern used by any known
/// signature at all" -- which tolerates the collision a gate's false-positive
/// rate already tolerates.
pub const MASKED_PATTERN_SCHEME: &str = "flirt-masked-pattern-v1";

/// How a signature library is keyed.
///
/// A corpus spanning gcc and clang across `-O0` to `-O3` is not one library;
/// it is N libraries sharing a name. No exact or masked scheme crosses an
/// optimisation level, so the variant is part of the identity rather than
/// metadata. Cross-variant matching is the CFR rung's job, not this one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlirtLibraryKey {
    /// Library name, e.g. `mathlib`.
    pub name: String,
    /// Library version, e.g. `1.0.0`.
    pub version: String,
    /// Compiler and flags, e.g. `gcc-O2`.
    pub variant: String,
    /// Architecture tag, e.g. `x86_64`.
    pub arch: String,
}

impl FlirtLibraryKey {
    /// The canonical `name/version/variant/arch` string used in provenance.
    pub fn as_provenance(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.name, self.version, self.variant, self.arch
        )
    }
}

/// One signature, as it appears on disk.
///
/// Every field added after v1 is `#[serde(default)]`, and every default is the
/// v1 behaviour: no mask (all bytes fixed), no CRC, no references.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlirtSignatureEntry {
    /// The function name a match assigns.
    pub name: String,
    /// The pattern bytes, hex-encoded.
    pub prologue_hex: String,
    /// Where the signature came from. Free text, for provenance only.
    #[serde(default)]
    pub source_binary: String,
    /// Per-byte variance mask, hex-encoded, the same byte length as
    /// `prologue_hex`: `ff` = the byte is fixed, `00` = the byte varies.
    /// Absent means every byte is fixed, which is exactly v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mask_hex: Option<String>,
    /// FLIRT CRC16 over the `crc_len` bytes that follow the pattern.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crc16: Option<u16>,
    /// How many bytes after the pattern the CRC covers. `0` means no CRC.
    #[serde(default)]
    pub crc_len: u16,
    /// The function's total length in bytes, when the builder knew it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_len: Option<u32>,
    /// Names referenced from the function body, for disambiguation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<FlirtReference>,
}

/// The on-disk library file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlirtLibraryFile {
    /// `"1"` for the exact-match format, `"2"` once masks are present.
    pub schema_version: String,
    /// Architecture tag.
    pub arch: String,
    /// Pattern length in bytes; every entry's pattern is exactly this long.
    pub prologue_len: usize,
    /// The signatures.
    pub entries: Vec<FlirtSignatureEntry>,
    /// Hex-prefix -> indices into `entries`. Built by the Python tool;
    /// we don't strictly need it (we rebuild the runtime index ourselves)
    /// but we keep the field so deserialization is symmetric.
    #[serde(default)]
    pub index: HashMap<String, Vec<usize>>,
    /// `(name, version, variant, arch)` provenance for the whole file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library: Option<FlirtLibraryKey>,
    /// Builder statistics; opaque here.
    #[serde(default)]
    pub stats: serde_json::Value,
}

/// One signature, compiled for matching.
#[derive(Debug, Clone)]
pub struct FlirtSignature {
    /// The function name a match assigns.
    pub name: String,
    /// Pattern bytes. Variant positions hold whatever the builder saw and are
    /// never compared, so they carry no information and must not be read as
    /// library content.
    pub pattern: Vec<u8>,
    /// `true` at every position that must compare equal.
    pub fixed: Vec<bool>,
    /// Expected CRC over the `crc_len` bytes after the pattern.
    pub crc: Option<u16>,
    /// Length the CRC covers.
    pub crc_len: usize,
    /// Total function length, when known.
    pub function_len: Option<u32>,
    /// Names referenced from the body.
    pub refs: Vec<FlirtReference>,
}

impl FlirtSignature {
    /// Does `data` (read from the candidate function's entry) match the
    /// pattern and, if one is recorded, the CRC?
    pub fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.pattern.len() {
            return false;
        }
        for (i, (&want, &is_fixed)) in self.pattern.iter().zip(self.fixed.iter()).enumerate() {
            if is_fixed && data[i] != want {
                return false;
            }
        }
        match (self.crc, self.crc_len) {
            (Some(expected), len) if len > 0 => {
                let start = self.pattern.len();
                let Some(range) = data.get(start..start + len) else {
                    // The candidate is shorter than the CRC range. FLIRT
                    // treats an unverifiable CRC as a non-match rather than a
                    // free pass; so do we.
                    return false;
                };
                crc16(range) == expected
            }
            _ => true,
        }
    }

    /// The number of leading pattern bytes that are fixed.
    ///
    /// Zero means the signature cannot be bucketed by its first byte and has
    /// to be scanned; in practice a prologue always starts fixed.
    pub fn leading_fixed(&self) -> usize {
        self.fixed.iter().take_while(|f| **f).count()
    }

    /// The [`MASKED_PATTERN_SCHEME`] identity string: the pattern with every
    /// variant byte forced to `0x00`, hex encoded. Two signatures that are
    /// indistinguishable to [`Self::matches`] -- same fixed bytes, same
    /// mask -- produce the same string here regardless of what their variant
    /// bytes happened to record, which is exactly the equivalence
    /// `python/glaurung/tools/build_flirt_library.py::_masked_pattern`
    /// already uses to decide which signatures collide.
    pub fn masked_pattern_hex(&self) -> String {
        let masked: Vec<u8> = self
            .pattern
            .iter()
            .zip(self.fixed.iter())
            .map(|(&byte, &is_fixed)| if is_fixed { byte } else { 0 })
            .collect();
        hex::encode(masked)
    }
}

/// The outcome of a lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlirtMatch<'a> {
    /// Nothing matched.
    None,
    /// Exactly one name survived every filter.
    Unique(&'a str),
    /// Several names survived. **Never** collapse this to a name: see the
    /// module docs on `set_by=flirt` outranking correct answers.
    Ambiguous(Vec<&'a str>),
}

impl FlirtMatch<'_> {
    /// The name, when and only when the match is unambiguous.
    pub fn unique(&self) -> Option<&str> {
        match self {
            Self::Unique(name) => Some(name),
            _ => None,
        }
    }
}

/// In-memory matcher.
pub struct FlirtLibrary {
    /// Architecture tag from the file.
    pub arch: String,
    /// Pattern length in bytes.
    pub prologue_len: usize,
    /// Provenance key, when the file carried one.
    pub library: Option<FlirtLibraryKey>,
    signatures: Vec<FlirtSignature>,
    /// First pattern byte -> signature indices, for signatures whose first
    /// byte is fixed.
    by_first_byte: HashMap<u8, Vec<usize>>,
    /// Signatures whose first byte is variant and so must always be tried.
    always_try: Vec<usize>,
}

impl FlirtLibrary {
    /// Compile an on-disk library.
    ///
    /// Entries whose pattern is not `prologue_len` bytes, or whose mask length
    /// disagrees with the pattern, are dropped: a signature we cannot compare
    /// correctly is worse than a missing one.
    pub fn from_file(file: FlirtLibraryFile) -> Self {
        let mut signatures: Vec<FlirtSignature> = Vec::new();
        for e in &file.entries {
            let Ok(pattern) = hex_to_bytes(&e.prologue_hex) else {
                continue;
            };
            if pattern.len() != file.prologue_len {
                continue;
            }
            let fixed = match &e.mask_hex {
                None => vec![true; pattern.len()],
                Some(hex) => {
                    let Ok(mask) = hex_to_bytes(hex) else {
                        continue;
                    };
                    if mask.len() != pattern.len() {
                        continue;
                    }
                    mask.iter().map(|b| *b != 0).collect()
                }
            };
            signatures.push(FlirtSignature {
                name: e.name.clone(),
                pattern,
                fixed,
                crc: e.crc16,
                crc_len: usize::from(e.crc_len),
                function_len: e.function_len,
                refs: e.refs.clone(),
            });
        }

        Self::from_parts(file.arch, file.prologue_len, file.library, signatures)
    }

    /// Build the runtime index over already-compiled signatures.
    ///
    /// Shared by [`Self::from_file`] and [`Self::from_gsig_bytes`] so the two
    /// load paths cannot drift into bucketing candidates differently — which
    /// would show up as a format-dependent match rate, the worst possible
    /// shape for that bug.
    fn from_parts(
        arch: String,
        prologue_len: usize,
        library: Option<FlirtLibraryKey>,
        signatures: Vec<FlirtSignature>,
    ) -> Self {
        let mut by_first_byte: HashMap<u8, Vec<usize>> = HashMap::new();
        let mut always_try: Vec<usize> = Vec::new();
        for (i, sig) in signatures.iter().enumerate() {
            if sig.fixed.first().copied().unwrap_or(false) {
                by_first_byte.entry(sig.pattern[0]).or_default().push(i);
            } else {
                always_try.push(i);
            }
        }

        Self {
            arch,
            prologue_len,
            library,
            signatures,
            by_first_byte,
            always_try,
        }
    }

    /// Parse and compile a library from JSON.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        let f: FlirtLibraryFile = serde_json::from_str(s)?;
        Ok(Self::from_file(f))
    }

    /// Compile a library from `gsig/1` bytes.
    ///
    /// Goes straight from the container's arena to the matcher's signatures:
    /// no hex, no JSON, no `FlirtLibraryFile` in between. The same drop rule
    /// as [`Self::from_file`] applies — an entry whose pattern is not
    /// `prologue_len` bytes is skipped, because a signature we cannot compare
    /// correctly is worse than a missing one.
    pub fn from_gsig_bytes(data: &[u8]) -> Result<Self, gsig::GsigError> {
        Self::from_gsig_library(&gsig::GsigLibrary::parse(data)?)
    }

    /// Compile a library from a `.gsig` on disk, `mmap`ing it to read.
    pub fn from_gsig(path: &std::path::Path) -> Result<Self, gsig::GsigError> {
        Self::from_gsig_library(&gsig::GsigLibrary::open(path)?)
    }

    fn from_gsig_library(loaded: &gsig::GsigLibrary) -> Result<Self, gsig::GsigError> {
        let prologue_len = loaded.prologue_len();
        let mut signatures = Vec::with_capacity(loaded.records().len());
        for record in loaded.records() {
            let pattern = loaded.pattern(record);
            if pattern.len() != prologue_len {
                continue;
            }
            signatures.push(FlirtSignature {
                name: loaded.string(record.name)?.to_string(),
                pattern: pattern.to_vec(),
                fixed: loaded.fixed(record),
                crc: record.crc16,
                crc_len: usize::from(record.crc_len),
                function_len: record.function_len,
                refs: loaded.refs(record)?,
            });
        }
        Ok(Self::from_parts(
            loaded.arch().to_string(),
            prologue_len,
            loaded.library().cloned(),
            signatures,
        ))
    }

    /// Load a library from disk, dispatching on its first four bytes.
    ///
    /// `gsig/1` files begin with [`gsig::MAGIC`]; a JSON library begins with
    /// `{` or whitespace. That is the whole dispatch, and it is why the
    /// container's magic has to sit at byte 0 rather than inside a Zstandard
    /// skippable frame.
    pub fn from_path(path: &std::path::Path) -> Result<Self, LoadError> {
        let mut magic = [0u8; 4];
        {
            use std::io::Read;
            let mut file = std::fs::File::open(path)?;
            // A file shorter than four bytes is not a library of either kind;
            // let the JSON parser produce the error, which names the file.
            let _ = file.read(&mut magic)?;
        }
        if gsig::is_gsig(&magic) {
            return Ok(Self::from_gsig(path)?);
        }
        let text = std::fs::read_to_string(path)?;
        Ok(Self::from_json(&text)?)
    }

    /// Match `data`, read from a candidate function's entry.
    ///
    /// `data` may be longer than [`Self::prologue_len`] -- and must be, for a
    /// signature that records a CRC.
    pub fn match_at(&self, data: &[u8]) -> FlirtMatch<'_> {
        self.resolve_with_evidence(self.candidates(data), None).0
    }

    /// Match bytes while also using an exact discovered function length.
    ///
    /// Linker relocation can erase every distinguishing byte in the initial
    /// pattern and prevent a CRC, while the linked function boundary still
    /// preserves the archive symbol's exact size. Unknown recorded lengths do
    /// not participate; a known disagreement eliminates that candidate.
    pub fn match_at_with_length(&self, data: &[u8], function_len: u64) -> FlirtMatch<'_> {
        let candidates = self
            .candidates(data)
            .into_iter()
            .filter(|index| {
                self.signatures[*index]
                    .function_len
                    .is_none_or(|expected| u64::from(expected) == function_len)
            })
            .collect();
        self.resolve_with_evidence(candidates, None).0
    }

    /// Match `data`, using `resolver` to break ties.
    ///
    /// `resolver(offset)` answers "what is the name of the thing this function
    /// references `offset` bytes in?" -- normally by decoding the call at that
    /// offset and looking the target up in the symbol or PLT table. Returning
    /// `None` means "unknown", which never eliminates a candidate; returning a
    /// name that disagrees with a candidate's recorded reference does.
    ///
    /// Candidates are then ranked by how many of their references were
    /// positively confirmed, and the best score wins only if it is both
    /// non-zero and held by exactly one candidate.
    pub fn match_at_with_refs(
        &self,
        data: &[u8],
        resolver: &dyn Fn(u32) -> Option<String>,
    ) -> FlirtMatch<'_> {
        self.resolve_with_evidence(self.candidates(data), Some(resolver))
            .0
    }

    /// [`Self::match_at`] / [`Self::match_at_with_refs`], but also naming
    /// *which* escalation level resolved a [`FlirtMatch::Unique`] verdict --
    /// what a `function_match.evidence` column needs and what `match_at`
    /// alone cannot report. `resolver` is optional so a caller with no
    /// reference resolver wired up yet still gets L1/L2 evidence rather than
    /// no evidence at all.
    ///
    /// The level is only meaningful for [`FlirtMatch::Unique`]: `None`
    /// carries no level by definition, and `Ambiguous` is the schema's
    /// `ambiguous = 1` case -- "no name beats a wrong name" means an
    /// ambiguous verdict never gets a level attributed to it either, because
    /// no level actually resolved it.
    ///
    /// | Returned level | What ran |
    /// |---|---|
    /// | `"flirt-L1"` | Masked pattern compare only; no signature in the surviving set records a CRC. |
    /// | `"flirt-L2"` | At least one surviving signature's CRC was checked (`crc_len > 0`) before the pattern-only survivors collapsed to one name. |
    /// | `"flirt-L4"` | Pattern and CRC left more than one name; `resolver` broke the tie. |
    ///
    /// L3 (FLIRT's single tail-byte discriminator) is schema-reserved
    /// (`siglib_flirt.tail_offset`/`tail_byte`) but not implemented by this
    /// matcher -- see `docs/reference/function-signature-libraries.md` --
    /// and so never appears here.
    pub fn match_at_with_evidence(
        &self,
        data: &[u8],
        resolver: Option<&dyn Fn(u32) -> Option<String>>,
    ) -> (FlirtMatch<'_>, Option<&'static str>) {
        self.resolve_with_evidence(self.candidates(data), resolver)
    }

    /// v1 entry point: exact-length prologue in, name out, `None` on any
    /// ambiguity. Kept because it is what `apply_flirt_overrides` and every
    /// existing caller use.
    pub fn match_prologue(&self, prologue: &[u8]) -> Option<&str> {
        if prologue.len() < self.prologue_len {
            return None;
        }
        match self.match_at(prologue) {
            FlirtMatch::Unique(name) => Some(name),
            _ => None,
        }
    }

    /// How many signatures compiled successfully.
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// How many bytes past a candidate's entry the matcher wants to read.
    ///
    /// The pattern plus the largest CRC range the format can record. Callers
    /// read this much where they can and less at the end of a section; a
    /// signature whose CRC range runs off the end simply does not match. It is
    /// derived from *this* library's pattern length rather than being a
    /// constant, because a library with a 64-byte pattern would otherwise be
    /// handed too few bytes and every CRC in it would fail.
    pub fn match_window(&self) -> usize {
        self.prologue_len + MAX_CRC_LEN
    }

    /// Read-only access to the compiled signatures, for tooling and tests.
    pub fn signatures(&self) -> &[FlirtSignature] {
        &self.signatures
    }

    /// The [`MASKED_PATTERN_SCHEME`] identity string of every compiled
    /// signature: the pattern with each variant byte forced to `0x00`, hex
    /// encoded. This is what a `crate::identity::gate::IdentityGate` is built
    /// over for this library, and what `siglib_function.identity` stores
    /// under that scheme -- see
    /// `docs/history/program-measures-2026-09-02/03-schema.sql` section 7.
    ///
    /// Not deduplicated: a caller building a gate feeds this straight to
    /// `IdentityGate::build`, which dedupes internally, and a caller counting
    /// per-signature provenance rows wants one entry per signature, collision
    /// or not.
    pub fn masked_pattern_identities(&self) -> Vec<String> {
        self.signatures
            .iter()
            .map(FlirtSignature::masked_pattern_hex)
            .collect()
    }

    /// Every signature whose pattern and CRC accept `data`.
    fn candidates(&self, data: &[u8]) -> Vec<usize> {
        let mut out: Vec<usize> = Vec::new();
        if data.len() < self.prologue_len {
            return out;
        }
        let bucket = self.by_first_byte.get(&data[0]);
        for &i in bucket.into_iter().flatten().chain(self.always_try.iter()) {
            if self.signatures[i].matches(data) {
                out.push(i);
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Turn surviving candidates into a verdict, collapsing candidates that
    /// merely agree on the name, and name which escalation level resolved a
    /// [`FlirtMatch::Unique`] verdict. See [`Self::match_at_with_evidence`]
    /// for what each returned level means.
    fn resolve_with_evidence(
        &self,
        candidates: Vec<usize>,
        resolver: Option<&dyn Fn(u32) -> Option<String>>,
    ) -> (FlirtMatch<'_>, Option<&'static str>) {
        if candidates.is_empty() {
            return (FlirtMatch::None, None);
        }
        let mut surviving = candidates;
        // Evidence is read off the candidate set BEFORE reference resolution
        // runs: if the pattern (plus CRC, where recorded) already left only
        // one name, references were never consulted and must not be credited
        // with the resolution.
        let mut level = if surviving.iter().any(|&i| self.signatures[i].crc_len > 0) {
            "flirt-L2"
        } else {
            "flirt-L1"
        };
        if surviving.len() > 1 {
            if let Some(resolve) = resolver {
                let refined = self.rank_by_references(&surviving, resolve);
                if !refined.is_empty() {
                    level = "flirt-L4";
                }
                surviving = refined;
            }
        }
        let mut names: Vec<&str> = surviving
            .iter()
            .map(|i| self.signatures[*i].name.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        match names.len() {
            0 => (FlirtMatch::None, None),
            1 => (FlirtMatch::Unique(names[0]), Some(level)),
            _ => (FlirtMatch::Ambiguous(names), None),
        }
    }

    /// Keep the candidates whose references the target binary confirms.
    fn rank_by_references(
        &self,
        candidates: &[usize],
        resolve: &dyn Fn(u32) -> Option<String>,
    ) -> Vec<usize> {
        let mut best = 0usize;
        let mut scored: Vec<(usize, usize)> = Vec::with_capacity(candidates.len());
        for &i in candidates {
            let sig = &self.signatures[i];
            let mut confirmed = 0usize;
            let mut contradicted = false;
            for r in &sig.refs {
                match resolve(r.offset) {
                    Some(found) if found == r.name => confirmed += 1,
                    Some(_) => {
                        contradicted = true;
                        break;
                    }
                    None => {}
                }
            }
            if contradicted {
                continue;
            }
            best = best.max(confirmed);
            scored.push((i, confirmed));
        }
        if scored.is_empty() {
            return Vec::new();
        }
        scored
            .into_iter()
            .filter(|(_, score)| *score == best)
            .map(|(i, _)| i)
            .collect()
    }
}

/// Why [`FlirtLibrary::from_path`] could not load a library.
///
/// One error type over both formats, because a caller that has just been
/// handed a path does not yet know which one it is holding — and the useful
/// thing to report is "this file is not a signature library", not "it is not
/// the format I guessed".
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The file could not be opened or read.
    #[error("cannot read signature library: {0}")]
    Io(#[from] std::io::Error),
    /// It began with `{` but did not parse as a JSON library.
    #[error("signature library is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// It began with `GSIG` but did not parse as a `gsig/1` container.
    #[error("{0}")]
    Gsig(#[from] gsig::GsigError),
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, &'static str> {
    if s.len() % 2 != 0 {
        return Err("odd hex length");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "bad hex")?;
        out.push(byte);
    }
    Ok(out)
}

/// The largest CRC range FLIRT can record, since it stores the length in one
/// byte.
pub const MAX_CRC_LEN: usize = 255;

/// Look up the default library file. Search order:
///   1. `GLAURUNG_FLIRT_LIB` env var (single file, either format).
///   2. `data/sigs/glaurung-base.x86_64.flirt.gsig` relative to the cwd.
///   3. `data/sigs/glaurung-base.x86_64.flirt.json` relative to the cwd.
///
/// The container is preferred where both exist: it is the same content and
/// loads without parsing a megabyte of text. Returns `None` if no library is
/// reachable — that's fine, the matcher pass becomes a no-op when no library
/// is available.
pub fn default_library_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("GLAURUNG_FLIRT_LIB") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    let cwd = std::env::current_dir().ok()?;
    for name in [
        "data/sigs/glaurung-base.x86_64.flirt.gsig",
        "data/sigs/glaurung-base.x86_64.flirt.json",
    ] {
        let candidate = cwd.join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Try to load the default FLIRT library, in whichever format it is on disk.
/// Returns `None` silently if no library is available; analysis falls back to
/// whatever DWARF and symbol-table renaming already accomplished.
pub fn load_default_library() -> Option<FlirtLibrary> {
    FlirtLibrary::from_path(&default_library_path()?).ok()
}

/// Build a (vm_start, vm_size, file_offset) → (vm_start, vm_size, file_offset)
/// projection for the binary, used to map VA ↔ file offset.
fn build_va_map(data: &[u8]) -> Vec<(u64, u64, u64)> {
    use object::{Object, ObjectSection, ObjectSegment};
    let obj = match crate::decompile::profile::parse_object(data) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let mut maps: Vec<(u64, u64, u64)> = Vec::new();
    let mut have_segments = false;
    for seg in obj.segments() {
        let (faddr, fsize) = seg.file_range();
        if fsize == 0 {
            continue;
        }
        let vaddr = seg.address();
        let vsize = seg.size();
        if vsize == 0 {
            continue;
        }
        maps.push((vaddr, vsize, faddr));
        have_segments = true;
    }
    if !have_segments {
        for sec in obj.sections() {
            let vaddr = sec.address();
            let vsize = sec.size();
            if vsize == 0 {
                continue;
            }
            if let Some((faddr, _flen)) = sec.file_range() {
                maps.push((vaddr, vsize, faddr));
            }
        }
    }
    maps
}

fn va_to_file_off(maps: &[(u64, u64, u64)], va: u64) -> Option<usize> {
    for (vaddr, vsize, faddr) in maps {
        if va >= *vaddr && va < vaddr + vsize {
            let delta = va - vaddr;
            return Some((faddr + delta) as usize);
        }
    }
    None
}

/// Scan executable regions for prologue matches against `lib`, returning
/// `(va, name)` pairs for every byte offset where a known signature
/// matches. This is what gives FLIRT real teeth on stripped binaries:
/// the symbol table is gone, so seed discovery from FLIRT hits.
///
/// Skips matches that would land inside a known existing Function chunk
/// to avoid duplicate seeding.
pub fn discover_flirt_seeds(
    data: &[u8],
    existing: &[Function],
    lib: &FlirtLibrary,
) -> Vec<(u64, String)> {
    use object::{Object, ObjectSection, SectionKind};

    let obj = match crate::decompile::profile::parse_object(data) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let known_starts: std::collections::HashSet<u64> =
        existing.iter().map(|f| f.entry_point.value).collect();

    let mut seeds: Vec<(u64, String)> = Vec::new();
    let mut seen_vas: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut seen_names: std::collections::HashSet<String> = std::collections::HashSet::new();

    for sec in obj.sections() {
        if !matches!(
            sec.kind(),
            SectionKind::Text | SectionKind::OtherString | SectionKind::Other
        ) && sec.kind() != SectionKind::Text
        {
            // Restrict scanning to executable code sections.
            continue;
        }
        let (faddr, fsize) = match sec.file_range() {
            Some(t) => t,
            None => continue,
        };
        if fsize == 0 {
            continue;
        }
        let start = faddr as usize;
        let end = std::cmp::min(data.len(), (faddr + fsize) as usize);
        if end <= start || end - start < lib.prologue_len {
            continue;
        }
        let vbase = sec.address();

        // Slide a window byte by byte. Could be sped up with a 4-byte
        // prefix index, but on small text sections this is already
        // sub-millisecond; keep v1 simple.
        let mut off = start;
        while off + lib.prologue_len <= end {
            let window_end = std::cmp::min(end, off + lib.match_window());
            if let Some(name) = lib.match_at(&data[off..window_end]).unique() {
                let va = vbase + (off as u64 - faddr);
                if !known_starts.contains(&va) && !seen_vas.contains(&va) {
                    // Don't seed the same name twice — typically means
                    // the matcher hit on inlined boilerplate. Prefer the
                    // first match (lower VA).
                    if !seen_names.contains(name) {
                        seen_vas.insert(va);
                        seen_names.insert(name.to_string());
                        seeds.push((va, name.to_string()));
                    }
                }
            }
            off += 1;
        }
    }
    seeds
}

/// Rename every `sub_*` function whose entry-VA window matches a signature in
/// `lib`. Reads bytes from `data` via the binary's section table (`object`
/// crate). Returns the number of renames applied.
///
/// An ambiguous match renames nothing: `set_by=flirt` outranks `auto`, so a
/// coin flip here is strictly worse than leaving the placeholder in place.
pub fn apply_flirt_overrides(data: &[u8], functions: &mut [Function], lib: &FlirtLibrary) -> usize {
    let maps = build_va_map(data);
    let mut renamed = 0usize;
    for f in functions.iter_mut() {
        // Only rename placeholder sub_* names; never overwrite a name we
        // already trust (DWARF, symbol table, manual).
        if !f.name.starts_with("sub_") {
            continue;
        }
        let foff = match va_to_file_off(&maps, f.entry_point.value) {
            Some(o) => o,
            None => continue,
        };
        if foff.saturating_add(lib.prologue_len) > data.len() {
            continue;
        }
        let end = std::cmp::min(data.len(), foff.saturating_add(lib.match_window()));
        if let Some(name) = lib.match_at(&data[foff..end]).unique() {
            f.name = name.to_string();
            renamed += 1;
        }
    }
    renamed
}

/// Match signatures only at concrete referenced function addresses.
///
/// Single-function decompilation intentionally bounds CFG discovery, but its
/// direct callees still have exact entry addresses. Looking up those few VAs
/// preserves static-library names without repeating the whole-section FLIRT
/// scan or spending the discovery function budget on library bodies.
pub fn names_at_vas(
    data: &[u8],
    vas: impl IntoIterator<Item = u64>,
    lib: &FlirtLibrary,
) -> Vec<(u64, String)> {
    let maps = build_va_map(data);
    let mut names = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for va in vas {
        if va == 0 || !seen.insert(va) {
            continue;
        }
        let Some(offset) = va_to_file_off(&maps, va) else {
            continue;
        };
        if offset.saturating_add(lib.prologue_len) > data.len() {
            continue;
        }
        let end = data.len().min(offset.saturating_add(lib.match_window()));
        if let Some(name) = lib.match_at(&data[offset..end]).unique() {
            names.push((va, name.to_string()));
        }
    }
    names
}

/// Match concrete function entries with their discovered byte lengths.
pub fn names_at_vas_with_lengths(
    data: &[u8],
    vas: impl IntoIterator<Item = (u64, Option<u64>)>,
    lib: &FlirtLibrary,
) -> Vec<(u64, String)> {
    let maps = build_va_map(data);
    let mut names = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (va, function_len) in vas {
        if va == 0 || !seen.insert(va) {
            continue;
        }
        let Some(offset) = va_to_file_off(&maps, va) else {
            continue;
        };
        if offset.saturating_add(lib.prologue_len) > data.len() {
            continue;
        }
        let end = data.len().min(offset.saturating_add(lib.match_window()));
        let verdict = function_len.map_or_else(
            || lib.match_at(&data[offset..end]),
            |length| lib.match_at_with_length(&data[offset..end], length),
        );
        if let Some(name) = verdict.unique() {
            names.push((va, name.to_string()));
        }
    }
    names
}

/// One function's FLIRT match, evidence-carrying and independent of whatever
/// name (if any) the binary's own symbol table already gives it.
///
/// This is deliberately a different question from [`apply_flirt_overrides`]'s
/// "should this function be renamed": that pass only ever touches `sub_*`
/// placeholders, because renaming an already-named function is not this
/// module's job. A `function_match` audit row is -- every candidate FLIRT can
/// resolve or rule out, named or not, is evidence worth recording, which is
/// exactly what lets `tests/flirt_signature_matching.rs`-style fixtures with
/// intact symbol tables prove the matcher against ground truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlirtEntryMatch {
    /// The function's entry VA.
    pub entry_va: u64,
    /// One name if [`Self::ambiguous`] is `false`; every surviving candidate
    /// name, sorted, if it is `true`. Always non-empty -- a function with no
    /// surviving candidate at all is simply absent from the result list.
    pub names: Vec<String>,
    /// `true` when more than one name survived every filter. Per the module
    /// docs, no name is ever picked in that case: [`Self::evidence`] is
    /// `None` and a caller must not apply any of [`Self::names`].
    pub ambiguous: bool,
    /// Which escalation level resolved the match. `Some` if and only if
    /// `ambiguous` is `false`.
    pub evidence: Option<&'static str>,
}

/// Match every function in `functions` against `lib`, evidence-carrying.
///
/// Unlike [`apply_flirt_overrides`] this does not mutate `functions` and does
/// not skip functions that already carry a real name: it is the read side
/// `python/glaurung/llm/kb/siglib.py` drives to populate `function_match`
/// rows, and an audit trail is not supposed to have a smaller domain than the
/// rename pass it backs.
pub fn match_functions_with_evidence(
    data: &[u8],
    functions: &[Function],
    lib: &FlirtLibrary,
) -> Vec<FlirtEntryMatch> {
    let maps = build_va_map(data);
    let mut out = Vec::new();
    for f in functions {
        let Some(foff) = va_to_file_off(&maps, f.entry_point.value) else {
            continue;
        };
        if foff.saturating_add(lib.prologue_len) > data.len() {
            continue;
        }
        let end = std::cmp::min(data.len(), foff.saturating_add(lib.match_window()));
        let (verdict, evidence) = lib.match_at_with_evidence(&data[foff..end], None);
        match verdict {
            FlirtMatch::None => continue,
            FlirtMatch::Unique(name) => out.push(FlirtEntryMatch {
                entry_va: f.entry_point.value,
                names: vec![name.to_string()],
                ambiguous: false,
                evidence,
            }),
            FlirtMatch::Ambiguous(names) => out.push(FlirtEntryMatch {
                entry_va: f.entry_point.value,
                names: names.into_iter().map(str::to_string).collect(),
                ambiguous: true,
                evidence: None,
            }),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _tiny_library() -> FlirtLibrary {
        let json = r#"{
          "schema_version": "1",
          "arch": "x86_64",
          "prologue_len": 8,
          "entries": [
            {"name": "expected_name", "prologue_hex": "554889e54883ec10", "source_binary": "test"}
          ],
          "index": {}
        }"#;
        FlirtLibrary::from_json(json).unwrap()
    }

    #[test]
    fn matches_known_prologue() {
        let lib = _tiny_library();
        assert_eq!(lib.signature_count(), 1);
        let proto = &[0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10];
        assert_eq!(lib.match_prologue(proto), Some("expected_name"));
    }

    #[test]
    fn rejects_wrong_length() {
        let lib = _tiny_library();
        let too_short = &[0x55, 0x48, 0x89, 0xe5];
        assert_eq!(lib.match_prologue(too_short), None);
    }

    #[test]
    fn rejects_non_matching_prologue() {
        let lib = _tiny_library();
        let other = &[0xff; 8];
        assert_eq!(lib.match_prologue(other), None);
    }

    #[test]
    fn from_json_round_trip() {
        let lib = _tiny_library();
        assert_eq!(lib.arch, "x86_64");
        assert_eq!(lib.prologue_len, 8);
    }

    /// A v1 file has no `mask_hex`, and must keep behaving as exact equality.
    #[test]
    fn an_absent_mask_means_every_byte_is_fixed() {
        let lib = _tiny_library();
        assert!(lib.signatures()[0].fixed.iter().all(|f| *f));
        let one_byte_off = &[0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x11];
        assert_eq!(lib.match_prologue(one_byte_off), None);
    }

    fn masked_library() -> FlirtLibrary {
        // Bytes 4..8 are variant: a `call rel32` the linker will rewrite.
        let json = r#"{
          "schema_version": "2",
          "arch": "x86_64",
          "prologue_len": 8,
          "entries": [
            {"name": "masked_fn", "prologue_hex": "554889e5e8000000",
             "mask_hex": "ffffffffff000000", "source_binary": "test"}
          ],
          "index": {}
        }"#;
        FlirtLibrary::from_json(json).unwrap()
    }

    /// The load-bearing property, in miniature: two link layouts differ only
    /// in the masked bytes and both match.
    #[test]
    fn a_masked_signature_matches_both_link_layouts() {
        let lib = masked_library();
        let layout_a = &[0x55, 0x48, 0x89, 0xe5, 0xe8, 0x40, 0x00, 0x00];
        let layout_b = &[0x55, 0x48, 0x89, 0xe5, 0xe8, 0x91, 0x2c, 0x01];
        assert_eq!(lib.match_prologue(layout_a), Some("masked_fn"));
        assert_eq!(lib.match_prologue(layout_b), Some("masked_fn"));
    }

    /// A mask must not become a wildcard for the fixed half.
    #[test]
    fn a_masked_signature_still_rejects_a_changed_fixed_byte() {
        let lib = masked_library();
        let different = &[0x53, 0x48, 0x89, 0xe5, 0xe8, 0x40, 0x00, 0x00];
        assert_eq!(lib.match_prologue(different), None);
    }

    fn crc_library() -> FlirtLibrary {
        // Pattern: 4 bytes. CRC over the next 4 bytes.
        let tail = [0xaau8, 0xbb, 0xcc, 0xdd];
        let expected = crc16(&tail);
        let file = FlirtLibraryFile {
            schema_version: "2".to_string(),
            arch: "x86_64".to_string(),
            prologue_len: 4,
            entries: vec![FlirtSignatureEntry {
                name: "crc_fn".to_string(),
                prologue_hex: "554889e5".to_string(),
                crc16: Some(expected),
                crc_len: 4,
                ..Default::default()
            }],
            index: Default::default(),
            library: None,
            stats: serde_json::Value::Null,
        };
        let json = serde_json::to_string(&file).unwrap();
        FlirtLibrary::from_json(&json).unwrap()
    }

    /// The CRC is what stops a short pattern from being a prefix match.
    #[test]
    fn the_crc_separates_two_functions_that_share_a_pattern() {
        let lib = crc_library();
        let right = [0x55u8, 0x48, 0x89, 0xe5, 0xaa, 0xbb, 0xcc, 0xdd];
        let wrong = [0x55u8, 0x48, 0x89, 0xe5, 0xaa, 0xbb, 0xcc, 0xde];
        assert_eq!(lib.match_at(&right), FlirtMatch::Unique("crc_fn"));
        assert_eq!(lib.match_at(&wrong), FlirtMatch::None);
    }

    /// A candidate whose CRC range runs off the end of the readable bytes is
    /// unverifiable, and unverifiable is not a match.
    #[test]
    fn a_truncated_crc_range_is_not_a_match() {
        let lib = crc_library();
        let truncated = [0x55u8, 0x48, 0x89, 0xe5, 0xaa, 0xbb];
        assert_eq!(lib.match_at(&truncated), FlirtMatch::None);
    }

    fn ambiguous_library() -> FlirtLibrary {
        let json = r#"{
          "schema_version": "2",
          "arch": "x86_64",
          "prologue_len": 4,
          "entries": [
            {"name": "alpha", "prologue_hex": "554889e5",
             "refs": [{"offset": 16, "name": "helper_a"}], "source_binary": "t"},
            {"name": "beta", "prologue_hex": "554889e5",
             "refs": [{"offset": 16, "name": "helper_b"}], "source_binary": "t"}
          ],
          "index": {}
        }"#;
        FlirtLibrary::from_json(json).unwrap()
    }

    #[test]
    fn exact_function_length_breaks_an_otherwise_unresolvable_tie() {
        let json = r#"{
          "schema_version": "2",
          "arch": "aarch64",
          "prologue_len": 4,
          "entries": [
            {"name": "puts", "prologue_hex": "3f2303d5", "function_len": 628},
            {"name": "other", "prologue_hex": "3f2303d5", "function_len": 664}
          ],
          "index": {}
        }"#;
        let lib = FlirtLibrary::from_json(json).unwrap();
        let prologue = 0xd503233fu32.to_le_bytes();
        assert!(matches!(lib.match_at(&prologue), FlirtMatch::Ambiguous(_)));
        assert_eq!(
            lib.match_at_with_length(&prologue, 628),
            FlirtMatch::Unique("puts")
        );
        assert_eq!(lib.match_at_with_length(&prologue, 640), FlirtMatch::None);
    }

    /// Two signatures sharing a pattern report ambiguity rather than a name.
    #[test]
    fn an_ambiguous_pattern_names_nothing_without_a_resolver() {
        let lib = ambiguous_library();
        let data = [0x55u8, 0x48, 0x89, 0xe5];
        assert_eq!(
            lib.match_at(&data),
            FlirtMatch::Ambiguous(vec!["alpha", "beta"])
        );
        assert_eq!(lib.match_prologue(&data), None);
    }

    /// A confirmed referenced name is the second-level disambiguator.
    #[test]
    fn a_referenced_name_breaks_the_tie() {
        let lib = ambiguous_library();
        let data = [0x55u8, 0x48, 0x89, 0xe5];
        let resolver = |off: u32| (off == 16).then(|| "helper_b".to_string());
        assert_eq!(
            lib.match_at_with_refs(&data, &resolver),
            FlirtMatch::Unique("beta")
        );
    }

    /// An unresolvable reference must not manufacture a decision.
    #[test]
    fn an_unresolvable_reference_leaves_the_tie_intact() {
        let lib = ambiguous_library();
        let data = [0x55u8, 0x48, 0x89, 0xe5];
        let resolver = |_off: u32| None;
        assert_eq!(
            lib.match_at_with_refs(&data, &resolver),
            FlirtMatch::Ambiguous(vec!["alpha", "beta"])
        );
    }

    /// A reference that resolves to something neither candidate expects
    /// eliminates both, rather than picking the least-bad one.
    #[test]
    fn a_contradicted_reference_eliminates_the_candidate() {
        let lib = ambiguous_library();
        let data = [0x55u8, 0x48, 0x89, 0xe5];
        let resolver = |_off: u32| Some("something_else".to_string());
        assert_eq!(lib.match_at_with_refs(&data, &resolver), FlirtMatch::None);
    }

    /// Two entries with the same NAME are not an ambiguity; the answer is the
    /// name either way.
    #[test]
    fn duplicate_names_collapse_rather_than_conflict() {
        let json = r#"{
          "schema_version": "2", "arch": "x86_64", "prologue_len": 4,
          "entries": [
            {"name": "same", "prologue_hex": "554889e5", "source_binary": "a"},
            {"name": "same", "prologue_hex": "554889e5", "source_binary": "b"}
          ], "index": {}
        }"#;
        let lib = FlirtLibrary::from_json(json).unwrap();
        assert_eq!(lib.match_prologue(&[0x55, 0x48, 0x89, 0xe5]), Some("same"));
    }

    /// A mask whose length disagrees with the pattern is a corrupt entry, and
    /// a corrupt entry is dropped rather than compared half-way.
    #[test]
    fn a_mask_of_the_wrong_length_drops_the_entry() {
        let json = r#"{
          "schema_version": "2", "arch": "x86_64", "prologue_len": 4,
          "entries": [
            {"name": "bad", "prologue_hex": "554889e5", "mask_hex": "ffff"}
          ], "index": {}
        }"#;
        let lib = FlirtLibrary::from_json(json).unwrap();
        assert_eq!(lib.signature_count(), 0);
    }

    #[test]
    fn a_library_key_renders_as_provenance() {
        let key = FlirtLibraryKey {
            name: "mathlib".into(),
            version: "1.0.0".into(),
            variant: "gcc-O2".into(),
            arch: "x86_64".into(),
        };
        assert_eq!(key.as_provenance(), "mathlib/1.0.0/gcc-O2/x86_64");
    }

    // -----------------------------------------------------------------
    // Evidence and the masked-pattern gate identity
    // -----------------------------------------------------------------

    /// A pattern-only match (no CRC recorded) is attributed to L1.
    #[test]
    fn evidence_is_flirt_l1_for_a_pattern_only_match() {
        let lib = _tiny_library();
        let proto = &[0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10];
        let (verdict, evidence) = lib.match_at_with_evidence(proto, None);
        assert_eq!(verdict, FlirtMatch::Unique("expected_name"));
        assert_eq!(evidence, Some("flirt-L1"));
    }

    /// A match that needed the CRC to be verified is attributed to L2, even
    /// though the pattern alone already left exactly one candidate: the CRC
    /// ran and was part of what made the verdict trustworthy.
    #[test]
    fn evidence_is_flirt_l2_when_a_crc_was_recorded() {
        let lib = crc_library();
        let right = [0x55u8, 0x48, 0x89, 0xe5, 0xaa, 0xbb, 0xcc, 0xdd];
        let (verdict, evidence) = lib.match_at_with_evidence(&right, None);
        assert_eq!(verdict, FlirtMatch::Unique("crc_fn"));
        assert_eq!(evidence, Some("flirt-L2"));
    }

    /// A tie the pattern and CRC could not break, resolved only once a
    /// referenced name confirms one candidate, is attributed to L4.
    #[test]
    fn evidence_is_flirt_l4_when_a_reference_breaks_the_tie() {
        let lib = ambiguous_library();
        let data = [0x55u8, 0x48, 0x89, 0xe5];
        let resolver = |off: u32| (off == 16).then(|| "helper_b".to_string());
        let (verdict, evidence) = lib.match_at_with_evidence(&data, Some(&resolver));
        assert_eq!(verdict, FlirtMatch::Unique("beta"));
        assert_eq!(evidence, Some("flirt-L4"));
    }

    /// "No name beats a wrong name": an ambiguous verdict never carries a
    /// level, because no level actually resolved it.
    #[test]
    fn an_ambiguous_verdict_carries_no_evidence() {
        let lib = ambiguous_library();
        let data = [0x55u8, 0x48, 0x89, 0xe5];
        let (verdict, evidence) = lib.match_at_with_evidence(&data, None);
        assert!(matches!(verdict, FlirtMatch::Ambiguous(_)));
        assert_eq!(evidence, None);
    }

    /// `match_at`/`match_at_with_refs` must keep behaving exactly as before:
    /// the evidence-carrying entry point is additive, not a replacement that
    /// silently changed what the old ones return.
    #[test]
    fn match_at_is_unchanged_by_the_evidence_refactor() {
        let lib = ambiguous_library();
        let data = [0x55u8, 0x48, 0x89, 0xe5];
        assert_eq!(
            lib.match_at(&data),
            FlirtMatch::Ambiguous(vec!["alpha", "beta"])
        );
        let resolver = |off: u32| (off == 16).then(|| "helper_b".to_string());
        assert_eq!(
            lib.match_at_with_refs(&data, &resolver),
            FlirtMatch::Unique("beta")
        );
    }

    /// A masked signature's identity string zeroes exactly the variant bytes,
    /// so it is the same string for every link layout that varies only in
    /// those bytes -- what makes it usable as `identity_filter`/
    /// `siglib_function` input in the first place.
    #[test]
    fn masked_pattern_identity_zeroes_the_variant_bytes() {
        let lib = masked_library();
        let ids = lib.masked_pattern_identities();
        assert_eq!(ids.len(), 1);
        // Pattern is `554889e5e8000000`, mask fixes the first 5 bytes:
        // the last 3 bytes must read back as zero.
        assert_eq!(ids[0], "554889e5e8000000");
    }

    /// Two signatures whose fixed bytes and mask agree are the same masked
    /// identity even though their recorded variant bytes differ -- the
    /// equivalence `build_flirt_library.py::_masked_pattern` already uses to
    /// decide which signatures collide.
    #[test]
    fn masked_pattern_identity_collapses_across_differing_variant_bytes() {
        let json = r#"{
          "schema_version": "2", "arch": "x86_64", "prologue_len": 8,
          "entries": [
            {"name": "one", "prologue_hex": "554889e5e8000000",
             "mask_hex": "ffffffffff000000", "source_binary": "a"},
            {"name": "one", "prologue_hex": "554889e5e8912c01",
             "mask_hex": "ffffffffff000000", "source_binary": "b"}
          ], "index": {}
        }"#;
        let lib = FlirtLibrary::from_json(json).unwrap();
        let ids = lib.masked_pattern_identities();
        assert_eq!(ids[0], ids[1]);
    }
}
