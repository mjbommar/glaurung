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
//! # Loading
//!
//! [`library_for`] is the only way a path becomes a matcher, and it parses at
//! most once per `(path, mtime, size)` per process. Everything else --
//! [`load_default_library`], the Python binding -- goes through it, so a
//! second `analyze()` in one process re-uses the first one's parse instead of
//! re-reading megabytes of JSON. [`default_library_paths`] is the resolution
//! order (`GLAURUNG_FLIRT_LIB`, `GLAURUNG_SIG_DIR`, `~/.cache/glaurung/sigs/`,
//! the packaged `data/sigs/`), and [`set_packaged_sig_dir`] is how the
//! installed location gets told to Rust at all.
//!
//! # The builder's duplicate key is this file's business
//!
//! [`FlirtLibraryFile::matcher_key_collisions`] states the invariant a
//! *builder* has to satisfy, from the matcher's side: no two entries may agree
//! on everything [`FlirtSignature::matches`] compares. A builder keying on
//! more than that (a function length, say) leaves entries no input can ever
//! separate, and they collapse to a permanent [`FlirtMatch::Ambiguous`]. The
//! representation for names that genuinely cannot be separated by pattern and
//! CRC is [`FlirtSignatureEntry::alternatives`] -- one leaf, several names,
//! the way FLIRT's own tree holds several modules on a leaf.
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
    /// Further names sharing this entry's [matcher key](FlirtLibraryFile::matcher_key_collisions).
    ///
    /// FLIRT's tree keeps *several* modules on one leaf and separates them
    /// below the pattern; so does this. An entry with a non-empty
    /// `alternatives` is a leaf the pattern and the CRC cannot resolve, and
    /// [`FlirtLibrary::from_file`] compiles it into one [`FlirtSignature`]
    /// per name so a later level -- an exact function length, a referenced
    /// name -- still has something to choose between. Empty is the ordinary
    /// case and is exactly the v2 file this field was added to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternatives: Vec<FlirtAlternative>,
}

/// One further name on a signature leaf, with the discriminators that are
/// its own.
///
/// The pattern, mask, CRC and CRC length belong to the enclosing
/// [`FlirtSignatureEntry`] -- by construction, since sharing them is what put
/// this name here. Only the fields the matcher can still tell apart on live
/// here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlirtAlternative {
    /// The function name this alternative assigns.
    pub name: String,
    /// The function's total length in bytes, when the builder knew it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_len: Option<u32>,
    /// Names referenced from this alternative's body.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<FlirtReference>,
    /// Where this alternative came from. Free text, for provenance only.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_binary: String,
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

/// Everything [`FlirtSignature::matches`] actually compares, as a value.
///
/// The masked pattern (variant bytes forced to `0x00`), the mask itself, and
/// the CRC with its length. Two entries agreeing on all four accept exactly
/// the same bytes: no input can reach one and not the other, and no amount of
/// pattern or CRC work will ever separate them. Anything else an entry
/// records -- `function_len`, `refs`, `source_binary` -- is invisible at this
/// level and must not be part of a builder's duplicate key. See
/// [`FlirtLibraryFile::matcher_key_collisions`].
pub type MatcherKey = (String, String, Option<u16>, u16);

impl FlirtLibraryFile {
    /// The [`MatcherKey`] of one entry, or `None` if its hex does not decode.
    fn entry_matcher_key(&self, entry: &FlirtSignatureEntry) -> Option<MatcherKey> {
        let pattern = hex_to_bytes(&entry.prologue_hex).ok()?;
        let mask = match &entry.mask_hex {
            None => vec![0xffu8; pattern.len()],
            Some(hex) => {
                let bytes = hex_to_bytes(hex).ok()?;
                if bytes.len() != pattern.len() {
                    return None;
                }
                bytes
            }
        };
        let masked: Vec<u8> = pattern
            .iter()
            .zip(mask.iter())
            .map(|(&byte, &m)| if m != 0 { byte } else { 0 })
            .collect();
        // Normalise the mask to one bit per byte so `ff`/`01` -- both "fixed"
        // to `from_file` -- cannot read as two different keys.
        let normalized: Vec<u8> = mask.iter().map(|m| u8::from(*m != 0)).collect();
        Some((
            hex::encode(masked),
            hex::encode(normalized),
            entry.crc16,
            entry.crc_len,
        ))
    }

    /// Groups of entry indices that [`FlirtLibrary::match_at`] cannot tell
    /// apart, largest first within each group's own order.
    ///
    /// **This should always be empty.** A builder's duplicate key has to be
    /// exactly what the matcher compares: key on *more* than the matcher and
    /// several entries survive that no input can ever separate, so every one
    /// of them becomes a candidate together and the verdict is a permanent
    /// [`FlirtMatch::Ambiguous`] -- a name the library paid for and can never
    /// deliver. Measured on a seven-library set built from this box's own
    /// `libc.a`, `libm`, `libstdc++`, `libcrypto`, `libssl`, `libz` and the
    /// Rust sysroot: 276 such groups covering 594 of 15,538 entries, because
    /// `build_flirt_library.py` keyed on `function_len` as well. Those names
    /// now share one entry as [`FlirtSignatureEntry::alternatives`], where a
    /// later level can still choose between them.
    ///
    /// Entries whose hex does not decode are skipped; [`FlirtLibrary::from_file`]
    /// drops them too.
    pub fn matcher_key_collisions(&self) -> Vec<Vec<usize>> {
        let mut by_key: HashMap<MatcherKey, Vec<usize>> = HashMap::new();
        for (i, entry) in self.entries.iter().enumerate() {
            let Some(key) = self.entry_matcher_key(entry) else {
                continue;
            };
            by_key.entry(key).or_default().push(i);
        }
        let mut groups: Vec<Vec<usize>> = by_key
            .into_values()
            .filter(|indices| indices.len() > 1)
            .collect();
        groups.sort_unstable();
        groups
    }
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
    ///
    /// An entry carrying [`FlirtSignatureEntry::alternatives`] compiles to one
    /// [`FlirtSignature`] per name, all sharing the entry's pattern, mask and
    /// CRC. That is the shape the rest of this module already handles: they
    /// arrive together as candidates, `match_at` reports them
    /// [`FlirtMatch::Ambiguous`], and a length or a referenced name can still
    /// pick one.
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
                pattern: pattern.clone(),
                fixed: fixed.clone(),
                crc: e.crc16,
                crc_len: usize::from(e.crc_len),
                function_len: e.function_len,
                refs: e.refs.clone(),
            });
            for alt in &e.alternatives {
                signatures.push(FlirtSignature {
                    name: alt.name.clone(),
                    pattern: pattern.clone(),
                    fixed: fixed.clone(),
                    crc: e.crc16,
                    crc_len: usize::from(e.crc_len),
                    function_len: alt.function_len,
                    refs: alt.refs.clone(),
                });
            }
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
        // A `gsig/1` container can hold either identity scheme, and a
        // `GLAURUNG_SIG_DIR` holding a published set holds both. A WARP GUID
        // library has no patterns and no `prologue_len`, so compiling one as
        // a masked-pattern matcher yields an empty library with
        // `prologue_len == 0` -- and [`library_for_paths`] takes its window
        // length from the *first* file it loads, so one WARP blob sorting
        // first would silently skip every real FLIRT library behind it.
        // Refuse here instead; the caller skips the file and keeps the rest.
        if loaded.scheme() != gsig::Scheme::FlirtMaskedPatternV1 {
            return Err(gsig::GsigError::WrongScheme {
                want: MASKED_PATTERN_SCHEME,
                got: loaded.scheme().as_str(),
            });
        }
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
    ///
    /// **A contradiction alone never crowns a winner.** Eliminating every
    /// candidate but one and then naming that one looks like sound
    /// elimination and is not, because a library records *one* spelling of an
    /// aliased symbol and the binary may legitimately show another: glibc's
    /// `pthread_mutex_lock` and `__pthread_mutex_lock` are one address, and
    /// the builder keeps the public spelling. Measured on four `gcc -O2
    /// -static` binaries against a seven-library set, allowing it named
    /// `__dlsym` and `__dlvsym` as each other -- and `dlsym`/`dlvsym` with
    /// them -- 16 wrong names, every one of them a pair whose two variants
    /// call the same helpers at offsets four bytes apart. So the winning
    /// score has to be non-zero: at least one reference must have been
    /// *positively* confirmed. With every candidate contradicted there is
    /// nothing left to name and the verdict is `None`, which is unchanged.
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
            // Every candidate was refuted: there is nothing here to name.
            return Vec::new();
        }
        if best == 0 {
            // Some candidates were refuted, none confirmed. See the note above
            // on aliases: leave the tie exactly as it was rather than let
            // elimination decide it.
            return candidates.to_vec();
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

/// Where the packaged `data/sigs/` directory is, once something has been able
/// to say. See [`set_packaged_sig_dir`].
static PACKAGED_SIG_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Record where the *installed* `data/sigs/` lives.
///
/// A wheel's signature libraries sit beside the Python package, and pure Rust
/// has no way to find that: the process is `python`, not us, so
/// `current_exe()` points at the interpreter and a cwd-relative `data/sigs`
/// only works when the cwd happens to be a checkout. `data/types/*.json` has
/// the same problem and solves it the same way -- `include_str!` where the
/// bundle is small enough to compile in (`src/ir/call_contracts.rs`), and a
/// path derived from `__file__` where it is not
/// (`python/glaurung/llm/kb/type_db.py::_stdlib_bundle_dir`). A signature
/// corpus is far too large to compile in, so `src/python_bindings/flirt.rs`
/// derives this from the extension module's own `__file__` at registration
/// time and calls this once.
///
/// Ignored after the first call: the answer is a property of the
/// installation, not of a request.
pub fn set_packaged_sig_dir(dir: PathBuf) {
    let _ = PACKAGED_SIG_DIR.set(dir);
}

/// The packaged `data/sigs/`, if [`set_packaged_sig_dir`] named one that
/// exists.
pub fn packaged_sig_dir() -> Option<&'static std::path::Path> {
    PACKAGED_SIG_DIR
        .get()
        .map(PathBuf::as_path)
        .filter(|p| p.is_dir())
}

/// Every `*.flirt.json` or `*.gsig` in `dir`, sorted, so the merge order is a
/// property of the directory rather than of the filesystem's readdir order.
///
/// Both extensions are recognized here, not just under `data/sigs/`: a
/// `GLAURUNG_SIG_DIR` pointed at a harvest or build output can hold either
/// format, or both side by side while a migration is in progress.
fn flirt_files_in(dir: &std::path::Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file() && {
                let name = p.to_string_lossy();
                name.ends_with(".flirt.json") || name.ends_with(".gsig")
            }
        })
        .collect();
    out.sort();
    out
}

/// Every file in `dir` except `catalog.json`, sorted.
///
/// The signature-distribution client (`python/glaurung/sigs/`) writes the
/// content-addressed cache at `~/.cache/glaurung/sigs/` as sha256-named blobs
/// plus a `catalog.json` index mapping library keys to those names. This
/// loader does not yet consult the catalog to pick a subset -- it loads every
/// blob in the directory and skips the index file by name, which is
/// acceptable while the cache holds one or a handful of published sets. A
/// catalog-aware selection (e.g. by architecture) can replace this once the
/// cache holds enough sets that loading all of them stops being free.
fn cache_files_in(dir: &std::path::Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.file_name().and_then(|n| n.to_str()) != Some("catalog.json"))
        .collect();
    out.sort();
    out
}

/// The library files to load, in resolution order. The **first rung that
/// yields anything wins**; rungs are not merged with each other.
///
/// 1. `GLAURUNG_FLIRT_LIB` -- one explicit file, either format. An override
///    is an override: naming a file must not silently pull in a directory's
///    worth of others.
/// 2. `GLAURUNG_SIG_DIR` -- every `*.flirt.json` and `*.gsig` in that
///    directory, merged (see [`flirt_files_in`]).
/// 3. `~/.cache/glaurung/sigs/` -- the client download cache, read by
///    [`cache_files_in`]: every file in the directory except `catalog.json`.
/// 4. The packaged `data/sigs/` ([`set_packaged_sig_dir`]), else `data/sigs/`
///    relative to the cwd, which is what a checkout has and what every
///    existing caller relied on.
///
/// Whichever rung wins, [`library_for_paths`] dispatches each resolved file
/// on its own magic, so a rung mixing both formats loads correctly.
///
/// Empty means no library is reachable, which is fine: the matcher pass
/// becomes a no-op.
pub fn default_library_paths() -> Vec<PathBuf> {
    resolve_library_paths(
        std::env::var("GLAURUNG_FLIRT_LIB").ok().as_deref(),
        std::env::var("GLAURUNG_SIG_DIR").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
        packaged_sig_dir(),
        std::env::current_dir().ok().as_deref(),
    )
}

/// [`default_library_paths`] with the environment passed in, so the order can
/// be tested without mutating a process-global that other tests are reading
/// concurrently.
fn resolve_library_paths(
    flirt_lib: Option<&str>,
    sig_dir: Option<&str>,
    home: Option<&str>,
    packaged: Option<&std::path::Path>,
    cwd: Option<&std::path::Path>,
) -> Vec<PathBuf> {
    if let Some(p) = flirt_lib {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return vec![pb];
        }
    }
    // Each rung pairs a candidate directory with how it is read: `sig_dir`,
    // `packaged` and the cwd's `data/sigs` are our own directories, so we know
    // their naming convention and can filter by extension. The cache root is
    // written by the signature-distribution client
    // (`python/glaurung/sigs/`) as sha256-named blobs plus a `catalog.json`
    // index -- see [`cache_files_in`].
    let rungs: [(Option<PathBuf>, fn(&std::path::Path) -> Vec<PathBuf>); 4] = [
        (sig_dir.map(PathBuf::from), flirt_files_in),
        (
            home.map(|h| PathBuf::from(h).join(".cache/glaurung/sigs")),
            cache_files_in,
        ),
        (packaged.map(std::path::Path::to_path_buf), flirt_files_in),
        (cwd.map(|c| c.join("data/sigs")), flirt_files_in),
    ];
    for (dir, list_fn) in rungs {
        let Some(dir) = dir else { continue };
        let found = list_fn(&dir);
        if !found.is_empty() {
            return found;
        }
    }
    Vec::new()
}

/// The first path [`default_library_paths`] resolves to, kept for callers that
/// want to name the library in provenance rather than load it.
pub fn default_library_path() -> Option<PathBuf> {
    default_library_paths().into_iter().next()
}

/// What identifies a file well enough to reuse a parse of it: the path, the
/// modification time in nanoseconds since the epoch, and the length.
type FileStamp = (PathBuf, u128, u64);

fn file_stamp(path: &std::path::Path) -> Option<FileStamp> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some((path.to_path_buf(), mtime, meta.len()))
}

#[allow(clippy::type_complexity)]
static LIBRARY_CACHE: std::sync::OnceLock<
    std::sync::RwLock<HashMap<Vec<FileStamp>, std::sync::Arc<FlirtLibrary>>>,
> = std::sync::OnceLock::new();

fn library_cache(
) -> &'static std::sync::RwLock<HashMap<Vec<FileStamp>, std::sync::Arc<FlirtLibrary>>> {
    LIBRARY_CACHE.get_or_init(|| std::sync::RwLock::new(HashMap::new()))
}

/// Why a signature library could not be loaded.
#[derive(Debug)]
pub enum LibraryLoadError {
    /// The file could not be read.
    Io(std::io::Error),
    /// The file was read but is not a valid JSON signature library.
    Parse(serde_json::Error),
    /// The file began with the `gsig/1` magic but did not parse as one.
    Gsig(gsig::GsigError),
}

impl std::fmt::Display for LibraryLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Parse(e) => write!(f, "{e}"),
            Self::Gsig(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LibraryLoadError {}

impl From<LoadError> for LibraryLoadError {
    fn from(e: LoadError) -> Self {
        match e {
            LoadError::Io(e) => Self::Io(e),
            LoadError::Json(e) => Self::Parse(e),
            LoadError::Gsig(e) => Self::Gsig(e),
        }
    }
}

/// **The one entry point for turning a path into a matcher.** Parses at most
/// once per `(path, mtime, size)` per process and hands every later caller the
/// same `Arc`.
///
/// The cost this removes is not hypothetical: `load_default_library` used to
/// re-read and re-parse the JSON on *every* `analyze()`, and a seven-library
/// set built from this box's own archives is 15,538 signatures over 19 MB of
/// JSON. The key includes mtime and length so a rebuilt library is picked up
/// without a restart -- a tool that rebuilds and immediately re-analyses is
/// the normal way this code is used -- while a re-analysis of an unchanged
/// file costs a hash lookup.
///
/// This is also the seam the `gsig/1` reader plugs into: a caller says
/// "library at this path" and gets an `Arc<FlirtLibrary>`, and dispatching on
/// the file's magic happens here rather than in the analysis pass. Nothing
/// outside this function needs to learn a second format.
pub fn library_for(
    path: &std::path::Path,
) -> Result<std::sync::Arc<FlirtLibrary>, LibraryLoadError> {
    library_for_paths(std::slice::from_ref(&path.to_path_buf()))
}

/// [`library_for`] over several files, merged into one matcher.
///
/// Each file is loaded through [`FlirtLibrary::from_path`], which dispatches
/// on its own magic -- so a JSON library and a `gsig/1` container can sit in
/// the same rung and both load correctly. Merging is concatenation of the
/// already-compiled signatures: a signature carries its own pattern, mask and
/// CRC, so two libraries have nothing to reconcile. Files whose
/// `prologue_len` disagrees with the first are **skipped**, because the
/// matcher indexes and compares one window length -- silently comparing 32
/// bytes of a 64-byte signature would be a false-positive generator.
pub fn library_for_paths(
    paths: &[PathBuf],
) -> Result<std::sync::Arc<FlirtLibrary>, LibraryLoadError> {
    let stamps: Vec<FileStamp> = paths
        .iter()
        .map(|p| {
            file_stamp(p).unwrap_or_else(|| (p.clone(), 0, u64::MAX)) // uncacheable-but-keyed
        })
        .collect();
    if let Some(hit) = library_cache()
        .read()
        .ok()
        .and_then(|guard| guard.get(&stamps).cloned())
    {
        return Ok(hit);
    }

    let mut merged_arch: Option<String> = None;
    let mut merged_prologue_len: Option<usize> = None;
    let mut merged_key: Option<FlirtLibraryKey> = None;
    let mut merged_signatures: Vec<FlirtSignature> = Vec::new();
    let mut first_error: Option<LibraryLoadError> = None;
    let mut loaded_any = false;
    for path in paths {
        let lib = match FlirtLibrary::from_path(path) {
            Ok(l) => l,
            Err(e) => {
                first_error.get_or_insert(LibraryLoadError::from(e));
                continue;
            }
        };
        match merged_prologue_len {
            None => {
                merged_arch = Some(lib.arch);
                merged_prologue_len = Some(lib.prologue_len);
                merged_key = lib.library;
                merged_signatures = lib.signatures;
                loaded_any = true;
            }
            Some(expected) if expected == lib.prologue_len => {
                merged_signatures.extend(lib.signatures);
                loaded_any = true;
            }
            Some(_) => {
                // Disagrees with the first file's window length; skip it
                // rather than corrupt the index.
            }
        }
    }
    if !loaded_any {
        return Err(first_error.unwrap_or_else(|| {
            LibraryLoadError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no signature library files given",
            ))
        }));
    }
    // A merged set has no single provenance key; drop it rather than claim
    // the first file's.
    let library = std::sync::Arc::new(FlirtLibrary::from_parts(
        merged_arch.unwrap_or_default(),
        merged_prologue_len.unwrap_or_default(),
        if paths.len() > 1 { None } else { merged_key },
        merged_signatures,
    ));
    if let Ok(mut guard) = library_cache().write() {
        guard.insert(stamps, std::sync::Arc::clone(&library));
    }
    Ok(library)
}

/// Try to load the default FLIRT library, in whichever format it is on disk.
/// Returns `None` silently if no library is available; analysis falls back to
/// whatever DWARF and symbol-table renaming already accomplished.
///
/// Loads through [`library_for_paths`], so the second `analyze()` in a
/// process re-uses the first one's parse, and a rung that resolves to more
/// than one file (mixed JSON/`gsig`) is merged into one matcher.
pub fn load_default_library() -> Option<std::sync::Arc<FlirtLibrary>> {
    let paths = default_library_paths();
    if paths.is_empty() {
        return None;
    }
    library_for_paths(&paths).ok()
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

/// Where one binary's functions reference other code, in the coordinates a
/// signature's [`FlirtReference::offset`] uses.
///
/// A signature records a reference at the **relocation's** offset from the
/// function entry -- the offset of the field the linker rewrites, not of the
/// instruction that contains it (`archive.rs`, "References"). A linked image
/// has no relocation table, so the analysis pass has to reconstruct that
/// offset from the call site it already found. For a `call rel32` at
/// instruction offset `k` the field is at `k + 1`; a `jcc rel32` puts it at
/// `k + 2`; on ARM the whole instruction word is the field and it is at `k`.
/// [`Self::from_call_sites`] reads the opcode and files each target under the
/// one offset that opcode implies, falling back to the instruction offset
/// where it cannot place a field.
///
/// Two different targets claiming one offset is recorded as a conflict and
/// answers "unknown" rather than picking: a wrong answer here does not merely
/// fail to break a tie, it *eliminates the correct candidate* and can leave
/// the wrong one standing alone.
#[derive(Debug, Clone, Default)]
pub struct FlirtReferenceSites {
    /// `entry VA -> (offset from entry -> target VA)`. A `None` target is an
    /// offset two call sites disagreed about.
    by_function: HashMap<u64, HashMap<u32, Option<u64>>>,
}

impl FlirtReferenceSites {
    /// Build from `(caller entry VA, call-site VA, target VA)` triples --
    /// exactly the call xrefs the discovery pass already collected.
    pub fn from_call_sites(data: &[u8], sites: impl IntoIterator<Item = (u64, u64, u64)>) -> Self {
        Self::from_call_sites_with_map(data, &build_va_map(data), sites)
    }

    /// [`Self::from_call_sites`] over a VA map the caller already has.
    ///
    /// Building one costs an object parse, and
    /// `program::session_tests::discovery_parse_count_does_not_scale_with_the_number_of_functions`
    /// counts those: a whole-binary discovery is not allowed to pay for the
    /// same parse twice, so the rename pass builds the map once and both it
    /// and this share it.
    fn from_call_sites_with_map(
        data: &[u8],
        maps: &[(u64, u64, u64)],
        sites: impl IntoIterator<Item = (u64, u64, u64)>,
    ) -> Self {
        let mut by_function: HashMap<u64, HashMap<u32, Option<u64>>> = HashMap::new();
        for (entry_va, site_va, target_va) in sites {
            if target_va == 0 || site_va < entry_va {
                continue;
            }
            let Ok(raw_offset) = u32::try_from(site_va - entry_va) else {
                continue;
            };
            // Exactly ONE offset per call site. Filing a target under both the
            // instruction offset and the field offset looks like belt and
            // braces and is not: the spare registration answers a *different*
            // signature reference that happens to sit at that offset, and a
            // wrong answer does not merely fail to break a tie -- it can
            // eliminate the correct candidate. The opcode says where the field
            // is; where it does not, the instruction *is* the field.
            let offset = va_to_file_off(maps, site_va)
                .and_then(|off| relocated_field_offset(data, off))
                .map_or(raw_offset, |delta| raw_offset.saturating_add(delta));
            by_function
                .entry(entry_va)
                .or_default()
                .entry(offset)
                .and_modify(|existing| {
                    if *existing != Some(target_va) {
                        *existing = None;
                    }
                })
                .or_insert(Some(target_va));
        }
        Self { by_function }
    }

    /// The VA a reference `offset` bytes into `entry_va`'s body points at, if
    /// exactly one call site claims that offset.
    pub fn target(&self, entry_va: u64, offset: u32) -> Option<u64> {
        *self.by_function.get(&entry_va)?.get(&offset)?
    }

    /// How many functions have at least one recorded reference site.
    pub fn function_count(&self) -> usize {
        self.by_function.len()
    }
}

/// How far into the instruction at `off` the field a relocation would have
/// covered begins, for the direct branches a call xref can name.
///
/// `None` when the opcode is not one we can place a field in; the caller then
/// files the target under the raw instruction offset only, which is the right
/// answer on the fixed-width architectures where the instruction *is* the
/// field.
fn relocated_field_offset(data: &[u8], off: usize) -> Option<u32> {
    let mut i = off;
    // Legacy prefixes and REX, so `rex.w call` and a branch hint land the same
    // as the bare form.
    let mut skipped = 0u32;
    while let Some(&byte) = data.get(i) {
        let is_prefix = matches!(
            byte,
            0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3 | 0x2e | 0x3e | 0x26 | 0x36 | 0x64 | 0x65
        ) || (0x40..=0x4f).contains(&byte);
        if !is_prefix || skipped >= 4 {
            break;
        }
        i += 1;
        skipped += 1;
    }
    match data.get(i)? {
        // call rel32 / jmp rel32
        0xe8 | 0xe9 => Some(skipped + 1),
        // 0f 8x: jcc rel32
        0x0f if matches!(data.get(i + 1), Some(0x80..=0x8f)) => Some(skipped + 2),
        // ff /2, ff /4 with a RIP-relative modrm: the displacement follows the
        // opcode and the modrm byte.
        0xff if matches!(data.get(i + 1), Some(0x15 | 0x25)) => Some(skipped + 2),
        _ => None,
    }
}

/// Rename every `sub_*` function whose entry-VA window matches a signature in
/// `lib`. Reads bytes from `data` via the binary's section table (`object`
/// crate). Returns the number of renames applied.
///
/// An ambiguous match renames nothing: `set_by=flirt` outranks `auto`, so a
/// coin flip here is strictly worse than leaving the placeholder in place.
pub fn apply_flirt_overrides(data: &[u8], functions: &mut [Function], lib: &FlirtLibrary) -> usize {
    apply_flirt_overrides_with_refs(data, functions, lib, std::iter::empty(), &HashMap::new())
}

/// [`apply_flirt_overrides`] with FLIRT's referenced-name level wired in.
///
/// 17.6 percent of the signatures a real archive yields record **no CRC at
/// all** (`crc_len == 0`, measured over 15,534 signatures from this box's
/// libc, libm, libstdc++, libcrypto, libssl, libz and Rust sysroot), plus a
/// further 8 percent with a range of one to three bytes. Those are the leaves
/// FLIRT expects the caller-name discriminator to finish, and until this
/// function existed the pass called the bare `match_at` and every such tie
/// stayed a tie.
///
/// **Multi-pass, as FLIRT is.** Naming one function makes it usable as
/// evidence for its callers and callees, so the loop repeats until a pass
/// renames nothing (bounded by `MAX_REFERENCE_PASSES`, since each pass can
/// only ever add names and the set of `sub_*` functions is finite).
///
/// `call_sites` is `(caller entry VA, call-site VA, target VA)`, exactly the
/// call xrefs the discovery pass already collected; it is turned into a
/// [`FlirtReferenceSites`] here so the VA map is built once and shared.
/// `extra_names` supplies names for VAs that are not discovered functions --
/// PLT stubs and import thunks, whose names a dynamically linked binary's
/// references depend on. The discovery pass passes an empty map today: the
/// only available source (`analysis::elf_plt::elf_plt_map`) parses the whole
/// object a second time, and that pass's object-parse count is itself an
/// asserted gate.
pub fn apply_flirt_overrides_with_refs(
    data: &[u8],
    functions: &mut [Function],
    lib: &FlirtLibrary,
    call_sites: impl IntoIterator<Item = (u64, u64, u64)>,
    extra_names: &HashMap<u64, String>,
) -> usize {
    let maps = build_va_map(data);
    let sites = FlirtReferenceSites::from_call_sites_with_map(data, &maps, call_sites);
    let mut name_by_va: HashMap<u64, String> = extra_names.clone();
    for f in functions.iter() {
        if !f.name.starts_with("sub_") {
            name_by_va.insert(f.entry_point.value, f.name.clone());
        }
    }

    let mut renamed = 0usize;
    for _pass in 0..MAX_REFERENCE_PASSES {
        let mut this_pass = 0usize;
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
            let entry_va = f.entry_point.value;
            let resolve = |offset: u32| -> Option<String> {
                let target = sites.target(entry_va, offset)?;
                name_by_va.get(&target).cloned()
            };
            let verdict = lib.match_at_with_refs(&data[foff..end], &resolve);
            if let Some(name) = verdict.unique() {
                let name = name.to_string();
                name_by_va.insert(entry_va, name.clone());
                f.name = name;
                this_pass += 1;
            }
        }
        renamed += this_pass;
        if this_pass == 0 {
            break;
        }
    }
    renamed
}

/// How many times [`apply_flirt_overrides_with_refs`] re-runs after a pass
/// that named something.
///
/// Reference resolution is monotone -- a pass only ever adds names -- so the
/// loop terminates on its own; this only bounds the cost of a long chain of
/// one-new-name-per-pass. Four is enough for the two-hop cases that actually
/// occur (a wrapper named by its callee, then the wrapper's own caller) and
/// keeps the worst case at four scans of the `sub_*` set.
const MAX_REFERENCE_PASSES: usize = 4;

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

    /// Eliminating all but one candidate, with nothing confirmed, does not
    /// name that one.
    ///
    /// This is the aliasing case: a library keeps one spelling of an aliased
    /// symbol (`pthread_mutex_lock`, not `__pthread_mutex_lock`), so a
    /// resolver reporting the other spelling contradicts a signature that is
    /// in fact correct. Letting that contradiction alone decide named
    /// `__dlsym` and `__dlvsym` as each other on four static binaries.
    #[test]
    fn a_contradiction_with_nothing_confirmed_does_not_decide() {
        let lib = ambiguous_library();
        let data = [0x55u8, 0x48, 0x89, 0xe5];
        // `alpha` expects `helper_a` at 16 and is contradicted; `beta` expects
        // `helper_b` at 16 -- also contradicted here, so both go...
        let both = |off: u32| (off == 16).then(|| "helper_c".to_string());
        assert_eq!(lib.match_at_with_refs(&data, &both), FlirtMatch::None);

        // ...but with `alpha` contradicted and `beta` merely unconfirmed, the
        // tie stands. `beta` has no positive evidence of its own.
        let one_sided = |off: u32| (off == 16).then(|| "helper_a_v2".to_string());
        let lib2 = FlirtLibrary::from_json(
            r#"{"schema_version":"2","arch":"x86_64","prologue_len":4,"entries":[
                 {"name":"alpha","prologue_hex":"554889e5",
                  "refs":[{"offset":16,"name":"helper_a"}]},
                 {"name":"beta","prologue_hex":"554889e5",
                  "refs":[{"offset":32,"name":"helper_b"}]}
               ],"index":{}}"#,
        )
        .unwrap();
        assert_eq!(
            lib2.match_at_with_refs(&data, &one_sided),
            FlirtMatch::Ambiguous(vec!["alpha", "beta"])
        );
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

    // -- the matcher's own duplicate key -------------------------------------

    /// Two entries agreeing on everything `matches` compares, differing only
    /// in a `function_len` it never reads. This is the shape the builder
    /// produced 276 times over a seven-library set.
    const COLLIDING_FILE: &str = r#"{
      "schema_version": "2", "arch": "x86_64", "prologue_len": 4,
      "entries": [
        {"name": "_IO_seekoff", "prologue_hex": "f30f1efa",
         "crc16": 7706, "crc_len": 1, "function_len": 646},
        {"name": "_IO_seekpos", "prologue_hex": "f30f1efa",
         "crc16": 7706, "crc_len": 1, "function_len": 492}
      ], "index": {}
    }"#;

    #[test]
    fn a_builder_key_wider_than_the_matcher_leaves_a_collision() {
        let file: FlirtLibraryFile = serde_json::from_str(COLLIDING_FILE).unwrap();
        let groups = file.matcher_key_collisions();
        assert_eq!(groups, vec![vec![0, 1]]);
    }

    #[test]
    fn an_absent_mask_and_an_all_ff_mask_are_one_key() {
        // `from_file` treats both as "every byte fixed", so the collision
        // check has to as well, or it under-reports.
        let json = r#"{
          "schema_version": "2", "arch": "x86_64", "prologue_len": 4,
          "entries": [
            {"name": "a", "prologue_hex": "f30f1efa"},
            {"name": "b", "prologue_hex": "f30f1efa", "mask_hex": "ffffffff"}
          ], "index": {}
        }"#;
        let file: FlirtLibraryFile = serde_json::from_str(json).unwrap();
        assert_eq!(file.matcher_key_collisions(), vec![vec![0, 1]]);
    }

    #[test]
    fn alternatives_are_one_entry_with_no_collision_and_two_candidates() {
        let json = r#"{
          "schema_version": "2", "arch": "x86_64", "prologue_len": 4,
          "entries": [
            {"name": "_IO_seekoff", "prologue_hex": "f30f1efa",
             "crc16": null, "crc_len": 0, "function_len": 646,
             "alternatives": [{"name": "_IO_seekpos", "function_len": 492}]}
          ], "index": {}
        }"#;
        let file: FlirtLibraryFile = serde_json::from_str(json).unwrap();
        assert!(file.matcher_key_collisions().is_empty());

        let lib = FlirtLibrary::from_file(file);
        assert_eq!(lib.signature_count(), 2);
        // Indistinguishable to `match_at`, which is the honest answer.
        assert_eq!(
            lib.match_at(&[0xf3, 0x0f, 0x1e, 0xfa]),
            FlirtMatch::Ambiguous(vec!["_IO_seekoff", "_IO_seekpos"])
        );
        // ...and still separable by the level that can tell them apart.
        assert_eq!(
            lib.match_at_with_length(&[0xf3, 0x0f, 0x1e, 0xfa], 492),
            FlirtMatch::Unique("_IO_seekpos")
        );
    }

    #[test]
    fn the_shipped_library_has_no_matcher_key_collisions() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("data/sigs/glaurung-base.x86_64.flirt.json");
        let file: FlirtLibraryFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let groups = file.matcher_key_collisions();
        let named: Vec<Vec<&str>> = groups
            .iter()
            .map(|g| g.iter().map(|i| file.entries[*i].name.as_str()).collect())
            .collect();
        assert!(
            named.is_empty(),
            "{path:?} holds indistinguishable entries: {named:?}"
        );
    }

    // -- reference sites -----------------------------------------------------

    #[test]
    fn a_call_rel32_puts_its_field_one_byte_in() {
        // e8 <rel32>: the relocation covers bytes 1..5.
        assert_eq!(relocated_field_offset(&[0xe8, 0, 0, 0, 0], 0), Some(1));
        // 48 e8 ...: a REX prefix shifts it.
        assert_eq!(
            relocated_field_offset(&[0x48, 0xe8, 0, 0, 0, 0], 0),
            Some(2)
        );
        // 0f 84 <rel32>: jcc.
        assert_eq!(
            relocated_field_offset(&[0x0f, 0x84, 0, 0, 0, 0], 0),
            Some(2)
        );
        // ff 15 <disp32>: an indirect call through a RIP-relative slot.
        assert_eq!(
            relocated_field_offset(&[0xff, 0x15, 0, 0, 0, 0], 0),
            Some(2)
        );
        // A fixed-width instruction word is its own field; the caller then
        // uses the raw offset.
        assert_eq!(relocated_field_offset(&[0x94, 0x00, 0x00, 0x00], 0), None);
    }

    #[test]
    fn two_targets_at_one_offset_answer_unknown() {
        // No object to read bytes from, so only the raw offsets are filed --
        // which is enough to exercise the conflict rule.
        let sites = FlirtReferenceSites::from_call_sites(
            &[],
            [(0x1000, 0x1010, 0x2000), (0x1000, 0x1010, 0x3000)],
        );
        assert_eq!(sites.target(0x1000, 0x10), None);
        assert_eq!(sites.function_count(), 1);
    }

    #[test]
    fn a_call_site_is_filed_under_its_offset_from_the_entry() {
        let sites = FlirtReferenceSites::from_call_sites(&[], [(0x1000, 0x1014, 0x2000)]);
        assert_eq!(sites.target(0x1000, 0x14), Some(0x2000));
        assert_eq!(sites.target(0x1000, 0x15), None);
        assert_eq!(sites.target(0x2000, 0x14), None);
    }

    // -- the wired-in resolver -----------------------------------------------

    /// A `Function` placeholder at `va`, with no body, for the rename pass.
    fn placeholder(va: u64) -> Function {
        use crate::core::address::{Address, AddressKind};
        use crate::core::function::FunctionKind;
        Function::new(
            format!("sub_{va:x}"),
            Address::new(AddressKind::VA, va, 64, None, None).unwrap(),
            FunctionKind::Normal,
        )
        .unwrap()
    }

    /// A name that exists only in `extra_names` -- a PLT stub, an import thunk
    /// -- still breaks a tie. Nothing else in the pass would know it.
    #[test]
    fn a_name_from_the_import_map_breaks_a_tie() {
        // A 4-byte ELF-less blob is enough: `build_va_map` returns nothing for
        // it, so no function resolves to a file offset and no rename can
        // happen. Use the reference machinery directly instead.
        let lib = ambiguous_library();
        let sites = FlirtReferenceSites::from_call_sites(&[], [(0x1000, 0x1010, 0x2000)]);
        let mut names: HashMap<u64, String> = HashMap::new();
        names.insert(0x2000, "helper_b".to_string());
        let resolve =
            |offset: u32| -> Option<String> { names.get(&sites.target(0x1000, offset)?).cloned() };
        // The site is at offset 0x10 = 16, which is where both signatures
        // record their reference.
        let data = [0x55u8, 0x48, 0x89, 0xe5];
        assert_eq!(
            lib.match_at_with_refs(&data, &resolve),
            FlirtMatch::Unique("beta")
        );
    }

    /// The rename pass leaves an established name alone and only ever fills a
    /// `sub_*` placeholder.
    #[test]
    fn the_rename_pass_never_overwrites_an_established_name() {
        let lib = _tiny_library();
        let mut functions = vec![placeholder(0x1000)];
        functions[0].name = "my_own_name".to_string();
        // No object to map VAs through, so nothing can be renamed anyway; the
        // point is that an established name is skipped before any of that.
        let renamed = apply_flirt_overrides(&[], &mut functions, &lib);
        assert_eq!(renamed, 0);
        assert_eq!(functions[0].name, "my_own_name");
    }

    // -- resolution order ----------------------------------------------------

    fn touch(dir: &std::path::Path, name: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, "{}").unwrap();
        p
    }

    #[test]
    fn resolution_order_prefers_the_explicit_file_then_the_dir_then_the_cache() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().to_path_buf();
        let explicit = touch(&root.join("explicit"), "one.flirt.json");
        let sig_dir = root.join("sigdir");
        let a = touch(&sig_dir, "a.flirt.json");
        let b = touch(&sig_dir, "b.flirt.json");
        touch(&sig_dir, "notes.txt");
        let home = root.join("home");
        let cached = touch(&home.join(".cache/glaurung/sigs"), "cached.flirt.json");
        let cwd = root.join("checkout");
        let shipped = touch(&cwd.join("data/sigs"), "base.flirt.json");

        let sig_dir_s = sig_dir.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();
        let explicit_s = explicit.to_string_lossy().into_owned();

        // 1. the explicit file wins outright, and pulls in nothing else.
        assert_eq!(
            resolve_library_paths(
                Some(&explicit_s),
                Some(&sig_dir_s),
                Some(&home_s),
                None,
                Some(&cwd)
            ),
            vec![explicit.clone()]
        );
        // 2. the directory, sorted, and only its `*.flirt.json`.
        assert_eq!(
            resolve_library_paths(None, Some(&sig_dir_s), Some(&home_s), None, Some(&cwd)),
            vec![a, b]
        );
        // 3. the download cache.
        assert_eq!(
            resolve_library_paths(None, None, Some(&home_s), None, Some(&cwd)),
            vec![cached]
        );
        // 4. the packaged directory, then the cwd-relative checkout.
        let packaged = root.join("packaged");
        let installed = touch(&packaged, "installed.flirt.json");
        assert_eq!(
            resolve_library_paths(None, None, None, Some(&packaged), Some(&cwd)),
            vec![installed]
        );
        assert_eq!(
            resolve_library_paths(None, None, None, None, Some(&cwd)),
            vec![shipped]
        );
        // An unreachable rung is skipped rather than ending the search.
        assert_eq!(
            resolve_library_paths(
                Some("/nonexistent/lib.flirt.json"),
                Some("/nonexistent/dir"),
                None,
                None,
                Some(&cwd)
            ),
            vec![root.join("checkout/data/sigs/base.flirt.json")]
        );
    }

    // -- the load cache ------------------------------------------------------

    #[test]
    fn one_path_is_parsed_once_per_process() {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("lib.flirt.json");
        std::fs::write(
            &path,
            r#"{"schema_version":"2","arch":"x86_64","prologue_len":4,
                "entries":[{"name":"a","prologue_hex":"f30f1efa"}],"index":{}}"#,
        )
        .unwrap();

        let first = library_for(&path).unwrap();
        let second = library_for(&path).unwrap();
        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "the second load re-parsed the file"
        );

        // A rewrite with new content invalidates the entry: a tool that
        // rebuilds a library and immediately re-analyses must not match
        // against the old one.
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(
            &path,
            r#"{"schema_version":"2","arch":"x86_64","prologue_len":4,
                "entries":[{"name":"a","prologue_hex":"f30f1efa"},
                           {"name":"b","prologue_hex":"554889e5"}],"index":{}}"#,
        )
        .unwrap();
        let third = library_for(&path).unwrap();
        assert!(!std::sync::Arc::ptr_eq(&first, &third));
        assert_eq!(third.signature_count(), 2);
    }

    #[test]
    fn merging_skips_a_library_with_a_different_pattern_length() {
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path();
        let four = dir.join("four.flirt.json");
        let also_four = dir.join("also-four.flirt.json");
        let eight = dir.join("eight.flirt.json");
        std::fs::write(
            &four,
            r#"{"schema_version":"2","arch":"x86_64","prologue_len":4,
                "entries":[{"name":"a","prologue_hex":"f30f1efa"}],"index":{}}"#,
        )
        .unwrap();
        std::fs::write(
            &also_four,
            r#"{"schema_version":"2","arch":"x86_64","prologue_len":4,
                "entries":[{"name":"b","prologue_hex":"554889e5"}],"index":{}}"#,
        )
        .unwrap();
        std::fs::write(
            &eight,
            r#"{"schema_version":"2","arch":"x86_64","prologue_len":8,
                "entries":[{"name":"c","prologue_hex":"f30f1efa554889e5"}],"index":{}}"#,
        )
        .unwrap();
        let merged = library_for_paths(&[four, also_four, eight]).unwrap();
        assert_eq!(merged.prologue_len, 4);
        assert_eq!(merged.signature_count(), 2);
    }

    /// A published set holds both identity schemes, and `GLAURUNG_SIG_DIR`
    /// hands the FLIRT loader every `*.gsig` in it. A WARP GUID library has
    /// no patterns, so it compiles to an empty matcher with `prologue_len`
    /// zero -- and the merge takes its window length from the *first* file it
    /// loads. Sorted by name, `a-guids.gsig` comes first, so before
    /// `from_gsig_library` checked the scheme this test's FLIRT library was
    /// silently skipped and the matcher was empty.
    #[test]
    fn merging_skips_a_warp_blob_and_still_loads_the_flirt_libraries() {
        use crate::flirt::gsig::{
            warp_library_to_gsig, WarpEntry, WarpLibraryFile, WarpLibraryKey, WriteOptions,
        };
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path();
        let guids = dir.join("a-guids.gsig");
        let patterns = dir.join("z-patterns.flirt.json");
        let warp = WarpLibraryFile {
            schema_version: "1".to_string(),
            scheme: crate::identity::warp::SCHEME.to_string(),
            library: WarpLibraryKey {
                name: "afd.sys".to_string(),
                version: "10.0.19041.1766".to_string(),
                variant: "msvc-14.20-b27412".to_string(),
                arch: "x86_64".to_string(),
                platform: Some("windows".to_string()),
            },
            sources: serde_json::Value::Null,
            stats: serde_json::Value::Null,
            entries: vec![WarpEntry {
                guid: "00062565-9d18-555b-835c-b886e4f81697".to_string(),
                name: "AfdEnqueueTPacketsIrp".to_string(),
                base_name: "AfdEnqueueTPacketsIrp".to_string(),
                block_count: 9,
                byte_len: 197,
                occurrences: 1,
                ambiguous: false,
                constraints: Vec::new(),
            }],
        };
        std::fs::write(
            &guids,
            warp_library_to_gsig(&warp, &WriteOptions::default()).unwrap(),
        )
        .unwrap();
        std::fs::write(
            &patterns,
            r#"{"schema_version":"2","arch":"x86_64","prologue_len":4,
                "entries":[{"name":"a","prologue_hex":"f30f1efa"}],"index":{}}"#,
        )
        .unwrap();
        let merged = library_for_paths(&[guids.clone(), patterns]).unwrap();
        assert_eq!(merged.prologue_len, 4);
        assert_eq!(merged.signature_count(), 1);

        // And on its own it is an error, not an empty library that would
        // report "no signatures matched" forever.
        assert!(library_for_paths(&[guids]).is_err());
    }
}
