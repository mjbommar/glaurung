//! The WARP function-GUID library, and its lossless mapping onto `gsig/1`.
//!
//! [`super::Scheme::FlirtMaskedPatternV1`] and
//! [`super::Scheme::WarpFunctionGuidV1`] share the container and almost
//! nothing else. A masked pattern is a *filter*: bytes, a mask, a CRC over a
//! bounded window, and referenced names to disambiguate what survives. A WARP
//! GUID is an *equality key*: 16 bytes that either match or do not. So the
//! two schemes fill different sections, and a reader has to look at
//! [`super::GsigHeader::scheme`] before it interprets anything.
//!
//! What a GUID library still needs to carry, beyond the key itself, is what
//! the knowledge base files in a `siglib_function` row -- the name, the base
//! name, the block count the GUID was computed over, the function's byte
//! length, whether the producer judged the GUID ambiguous, and the WARP
//! constraints that are the only way to break that ambiguity. Those live in
//! [`super::ChunkKind::GuidRecords`] and
//! [`super::ChunkKind::Constraints`], parallel to the Guids section and in
//! the same order.
//!
//! Two shapes are deliberately *not* new sections:
//!
//! * The library's `(name, version, variant, arch)` key reuses
//!   [`super::wire::WireMeta::library`], because it is the same key a FLIRT
//!   library carries and a publisher's manifest is keyed on it.
//! * `platform`, `sources` and `stats` are folded into the meta record's
//!   `stats_json` envelope. Adding a field to `WireMeta` would change the
//!   `postcard` encoding of *every* library including every FLIRT one, and
//!   the golden test that pins those bytes exists precisely to stop that.

use serde::{Deserialize, Serialize};

use super::reader::GsigLibrary;
use super::writer::{write_warp_library, WriteOptions};
use super::{GsigError, Scheme};

/// The `(name, version, variant, arch)` key plus the platform a WARP library
/// was derived on.
///
/// `platform` is the one field with no counterpart in
/// [`crate::flirt::FlirtLibraryKey`]: a masked pattern is identified by its
/// triplet, while a Windows PE's GUIDs are the same GUIDs whatever host
/// derived them, so the platform is provenance rather than identity. The KB's
/// `siglib` row records it, so it has to survive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarpLibraryKey {
    /// The module the library was derived from, e.g. `afd.sys`.
    pub name: String,
    /// The module's own version string.
    pub version: String,
    /// The toolchain variant, e.g. `msvc-14.20-b27412`.
    pub variant: String,
    /// The architecture the GUIDs are valid for.
    pub arch: String,
    /// The operating system, e.g. `windows`. Absent in an older file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

/// One WARP constraint: a related function's GUID, how it is related, and
/// where.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarpConstraintEntry {
    /// The constraint GUID.
    pub guid: String,
    /// `callee`, `caller`, `adjacent`, ...
    pub kind: String,
    /// Byte offset within the function, when the kind has one. **`null` is
    /// not zero**: a callee at offset 0 is a different fact from a caller
    /// with no offset at all, which is why this is an `Option` all the way
    /// down to the wire sentinel.
    #[serde(default)]
    pub offset: Option<i64>,
}

/// One function, identified by an exact GUID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarpEntry {
    /// The function GUID, canonical lowercase hyphenated form.
    pub guid: String,
    /// The function's name as the producer resolved it.
    pub name: String,
    /// The de-suffixed or demangled name. Stored rather than derived: the
    /// producer's rule for it is not reproducible from `name` alone.
    pub base_name: String,
    /// Basic blocks the GUID was computed over.
    pub block_count: u32,
    /// The function's length in bytes.
    pub byte_len: u64,
    /// How many times the producer saw this `(guid, name)` pair.
    pub occurrences: u32,
    /// Whether the GUID names more than one function in this library.
    pub ambiguous: bool,
    /// Constraints, in the producer's order.
    #[serde(default)]
    pub constraints: Vec<WarpConstraintEntry>,
}

/// A `*.warp.json` library, as `glaurung.tools.build_warp_library` writes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WarpLibraryFile {
    /// The JSON schema version, e.g. `"1"`.
    pub schema_version: String,
    /// Must be [`crate::identity::warp::SCHEME`].
    pub scheme: String,
    /// The library key.
    pub library: WarpLibraryKey,
    /// Free-form per-input provenance. Carried verbatim.
    #[serde(default)]
    pub sources: serde_json::Value,
    /// Free-form producer statistics. Carried verbatim.
    #[serde(default)]
    pub stats: serde_json::Value,
    /// The entries, in the producer's order.
    pub entries: Vec<WarpEntry>,
}

/// The non-entry envelope, as it is stored in the meta record's `stats_json`.
///
/// Its field names are fixed because they are on disk in every published WARP
/// blob; `serde_json`'s map is a `BTreeMap`, so the text is canonical and the
/// container stays a pure function of its input.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct WarpEnvelope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub sources: serde_json::Value,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub stats: serde_json::Value,
}

/// Parse a canonical UUID string to the `u128` the container stores.
pub(super) fn guid_to_u128(text: &str) -> Result<u128, GsigError> {
    uuid::Uuid::parse_str(text)
        .map(|u| u.as_u128())
        .map_err(|e| GsigError::Encode(format!("guid {text:?} is not a UUID: {e}")))
}

/// The canonical lowercase hyphenated spelling of a stored GUID.
pub(super) fn guid_to_string(value: u128) -> String {
    uuid::Uuid::from_u128(value).to_string()
}

/// Serialize a WARP JSON library to `gsig/1` bytes.
///
/// Entries keep the producer's order. Determinism is "a pure function of the
/// input", and the input's order is part of the input -- the same rule the
/// masked-pattern writer follows, and what lets a content-addressed
/// distribution name the blob by its hash.
pub fn warp_library_to_gsig(
    file: &WarpLibraryFile,
    options: &WriteOptions,
) -> Result<Vec<u8>, GsigError> {
    write_warp_library(file, options)
}

/// Rebuild the WARP JSON library a `.gsig` was written from.
///
/// # Errors
///
/// [`GsigError::WrongScheme`] if the container is not a
/// [`Scheme::WarpFunctionGuidV1`] file. Reading a masked-pattern library as a
/// GUID library would produce an empty, plausible-looking result, which is
/// the worst possible failure for a signature corpus.
pub fn warp_library_from_gsig(library: &GsigLibrary) -> Result<WarpLibraryFile, GsigError> {
    if library.scheme() != Scheme::WarpFunctionGuidV1 {
        return Err(GsigError::WrongScheme {
            want: Scheme::WarpFunctionGuidV1.as_str(),
            got: library.scheme().as_str(),
        });
    }
    let envelope = library.warp_envelope()?;
    let key = library.library().ok_or(GsigError::MissingSection(
        "meta.library (a WARP library must carry its key)",
    ))?;
    let mut entries = Vec::with_capacity(library.guid_records().len());
    for record in library.guid_records() {
        let mut constraints = Vec::with_capacity(record.constraints.len());
        for constraint in &record.constraints {
            constraints.push(WarpConstraintEntry {
                guid: guid_to_string(constraint.guid),
                kind: library.string(constraint.kind)?.to_string(),
                offset: constraint.offset,
            });
        }
        entries.push(WarpEntry {
            guid: guid_to_string(record.guid),
            name: library.string(record.name)?.to_string(),
            base_name: library.string(record.base_name)?.to_string(),
            block_count: record.block_count,
            byte_len: record.byte_len,
            occurrences: record.occurrences,
            ambiguous: record.ambiguous,
            constraints,
        });
    }
    Ok(WarpLibraryFile {
        schema_version: library.schema_version().to_string(),
        scheme: Scheme::WarpFunctionGuidV1.as_str().to_string(),
        library: WarpLibraryKey {
            name: key.name.clone(),
            version: key.version.clone(),
            variant: key.variant.clone(),
            arch: key.arch.clone(),
            platform: envelope.platform,
        },
        sources: envelope.sources,
        stats: envelope.stats,
        entries,
    })
}

#[cfg(test)]
pub(crate) fn sample_warp_library() -> WarpLibraryFile {
    WarpLibraryFile {
        schema_version: "1".to_string(),
        scheme: Scheme::WarpFunctionGuidV1.as_str().to_string(),
        library: WarpLibraryKey {
            name: "afd.sys".to_string(),
            version: "10.0.19041.1766".to_string(),
            variant: "msvc-14.20-b27412".to_string(),
            arch: "x86_64".to_string(),
            platform: Some("windows".to_string()),
        },
        sources: serde_json::json!([{"path": "/corpus/afd.sys", "functions": 1175}]),
        stats: serde_json::json!({"entries": 3, "guids_unique": 2}),
        entries: vec![
            WarpEntry {
                guid: "00062565-9d18-555b-835c-b886e4f81697".to_string(),
                name: "AfdEnqueueTPacketsIrp".to_string(),
                base_name: "AfdEnqueueTPacketsIrp".to_string(),
                block_count: 9,
                byte_len: 197,
                occurrences: 1,
                ambiguous: false,
                constraints: Vec::new(),
            },
            // Same GUID, two names: the ambiguity a `siglib_function` row
            // keeps deliberately, plus the constraints that could break it.
            WarpEntry {
                guid: "e6fa87c0-e14d-537a-8cca-5e7e5137be42".to_string(),
                name: "AfdTliGetTdiHandles".to_string(),
                base_name: "AfdTliGetTdiHandles".to_string(),
                block_count: 1,
                byte_len: 24,
                occurrences: 1,
                ambiguous: true,
                constraints: vec![
                    WarpConstraintEntry {
                        guid: "0e8af237-b832-5ff0-8810-775c54171f14".to_string(),
                        kind: "callee".to_string(),
                        offset: Some(0),
                    },
                    WarpConstraintEntry {
                        guid: "890825ad-f093-5365-bd4b-06f77b38d29d".to_string(),
                        kind: "caller".to_string(),
                        offset: None,
                    },
                ],
            },
            WarpEntry {
                guid: "e6fa87c0-e14d-537a-8cca-5e7e5137be42".to_string(),
                name: "AfdTliGetTdiHandlesAlias".to_string(),
                base_name: "AfdTliGetTdiHandlesAlias".to_string(),
                block_count: 1,
                byte_len: 24,
                occurrences: 2,
                ambiguous: true,
                constraints: Vec::new(),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_round_trips(file: &WarpLibraryFile) {
        let bytes = warp_library_to_gsig(file, &WriteOptions::default()).unwrap();
        let loaded = GsigLibrary::parse(&bytes).unwrap();
        assert_eq!(loaded.scheme(), Scheme::WarpFunctionGuidV1);
        let back = warp_library_from_gsig(&loaded).unwrap();
        assert_eq!(
            serde_json::to_value(file).unwrap(),
            serde_json::to_value(&back).unwrap()
        );
        assert_eq!(
            bytes,
            warp_library_to_gsig(&back, &WriteOptions::default()).unwrap()
        );
    }

    #[test]
    fn a_warp_library_round_trips_with_every_field_intact() {
        assert_round_trips(&sample_warp_library());
    }

    /// Constraints belong to the record that declared them, in order, however
    /// unevenly they are distributed -- the corpus has them on 39,175 of
    /// 368,870 entries and on none of the rest.
    #[test]
    fn constraints_stay_with_the_record_that_claimed_them() {
        let file = sample_warp_library();
        let bytes = warp_library_to_gsig(&file, &WriteOptions::default()).unwrap();
        let loaded = GsigLibrary::parse(&bytes).unwrap();
        let records = loaded.guid_records();
        assert_eq!(records.len(), 3);
        assert!(records[0].constraints.is_empty());
        assert_eq!(records[1].constraints.len(), 2);
        assert_eq!(records[1].constraints[0].offset, Some(0));
        assert_eq!(records[1].constraints[1].offset, None);
        assert!(records[2].constraints.is_empty());
    }

    /// The GUID index still answers lookups, and an ambiguous GUID still
    /// reports both names -- the property `match_warp_library` depends on.
    #[test]
    fn an_ambiguous_guid_reports_every_name() {
        let file = sample_warp_library();
        let bytes = warp_library_to_gsig(&file, &WriteOptions::default()).unwrap();
        let loaded = GsigLibrary::parse(&bytes).unwrap();
        let ambiguous = guid_to_u128("e6fa87c0-e14d-537a-8cca-5e7e5137be42").unwrap();
        let mut names = loaded.guid_names(ambiguous);
        names.sort_unstable();
        assert_eq!(
            names,
            vec!["AfdTliGetTdiHandles", "AfdTliGetTdiHandlesAlias"]
        );
        let unique = guid_to_u128("00062565-9d18-555b-835c-b886e4f81697").unwrap();
        assert_eq!(loaded.lookup_guid(unique), Some("AfdEnqueueTPacketsIrp"));
    }

    /// A library with no entries is a legitimate harvest outcome and must not
    /// become a parse error at the other end.
    #[test]
    fn an_empty_warp_library_round_trips() {
        let mut file = sample_warp_library();
        file.entries.clear();
        file.sources = serde_json::Value::Null;
        file.stats = serde_json::Value::Null;
        file.library.platform = None;
        assert_round_trips(&file);
    }

    /// Reading a masked-pattern container through the WARP path must fail
    /// loudly. It would otherwise return a well-formed library with zero
    /// entries, which is indistinguishable from a genuinely empty harvest.
    #[test]
    fn a_flirt_container_is_refused_by_the_warp_reader() {
        let bytes = super::super::library_file_to_gsig(
            &crate::flirt::gsig::sample_library_file(),
            &WriteOptions::default(),
        )
        .unwrap();
        let loaded = GsigLibrary::parse(&bytes).unwrap();
        assert!(matches!(
            warp_library_from_gsig(&loaded),
            Err(GsigError::WrongScheme { .. })
        ));
    }
}
