//! Lossless conversion between the JSON library and `gsig/1`.
//!
//! JSON stays the import/export format: it is what a harvester writes, what a
//! reviewer diffs, and what every existing tool reads. `gsig/1` is what a
//! corpus *ships* in. The two must therefore be exactly interconvertible, and
//! `tests/flirt_gsig_roundtrip.rs` holds that to the whole harvested set —
//! JSON to gsig to JSON, byte-identical after canonical sorting.

use super::reader::GsigLibrary;
use super::writer::{write, WriteOptions};
use super::GsigError;
use crate::flirt::{FlirtLibraryFile, FlirtSignatureEntry};

/// Serialize a JSON-shaped library to `gsig/1` bytes.
pub fn library_file_to_gsig(
    file: &FlirtLibraryFile,
    options: &WriteOptions,
) -> Result<Vec<u8>, GsigError> {
    write(file, options)
}

/// Rebuild the JSON-shaped library a `.gsig` was written from.
///
/// Entries come back in the writer's sort order — `(name, pattern, ...)` —
/// which is the order the Python builder already emits, so a round trip
/// through this function is a no-op on any library the builder produced.
pub fn library_file_from_gsig(library: &GsigLibrary) -> Result<FlirtLibraryFile, GsigError> {
    let mut entries = Vec::with_capacity(library.records().len());
    for record in library.records() {
        let fixed = library.fixed(record);
        let mask_hex = if record.mask_off == u32::MAX {
            None
        } else {
            Some(hex::encode(
                fixed
                    .iter()
                    .map(|f| if *f { 0xffu8 } else { 0x00 })
                    .collect::<Vec<u8>>(),
            ))
        };
        entries.push(FlirtSignatureEntry {
            name: library.string(record.name)?.to_string(),
            prologue_hex: hex::encode(library.pattern(record)),
            source_binary: library.string(record.source)?.to_string(),
            mask_hex,
            crc16: record.crc16,
            crc_len: record.crc_len,
            function_len: record.function_len,
            refs: library.refs(record)?,
        });
    }
    Ok(FlirtLibraryFile {
        schema_version: library.schema_version().to_string(),
        arch: library.arch().to_string(),
        prologue_len: library.prologue_len(),
        entries,
        index: library.index()?,
        library: library.library().cloned(),
        stats: library.stats().clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_round_trips(file: &FlirtLibraryFile) {
        let bytes = library_file_to_gsig(file, &WriteOptions::default()).unwrap();
        let loaded = GsigLibrary::parse(&bytes).unwrap();
        let back = library_file_from_gsig(&loaded).unwrap();
        assert_eq!(
            serde_json::to_value(file).unwrap(),
            serde_json::to_value(&back).unwrap()
        );
        // ...and the second pass through the container is byte-identical,
        // which is the property a content-addressed distribution needs.
        assert_eq!(
            bytes,
            library_file_to_gsig(&back, &WriteOptions::default()).unwrap()
        );
    }

    #[test]
    fn a_masked_v2_library_round_trips() {
        assert_round_trips(&crate::flirt::gsig::sample_library_file());
    }

    /// A v1 file has no masks, no CRC, no references and no library key. All
    /// four absences must survive: an entry that gained a `"mask_hex": null`
    /// or a `"library"` block would no longer be the file it started as.
    #[test]
    fn a_v1_library_round_trips_with_every_absence_intact() {
        let file = FlirtLibraryFile {
            schema_version: "1".to_string(),
            arch: "x86_64".to_string(),
            prologue_len: 8,
            entries: vec![FlirtSignatureEntry {
                name: "expected_name".to_string(),
                prologue_hex: "554889e54883ec10".to_string(),
                source_binary: "test".to_string(),
                mask_hex: None,
                crc16: None,
                crc_len: 0,
                function_len: None,
                refs: Vec::new(),
            }],
            index: [("554889e5".to_string(), vec![0usize])]
                .into_iter()
                .collect(),
            library: None,
            stats: serde_json::Value::Null,
        };
        assert_round_trips(&file);
        let bytes = library_file_to_gsig(&file, &WriteOptions::default()).unwrap();
        let loaded = GsigLibrary::parse(&bytes).unwrap();
        assert!(loaded.library().is_none());
        assert!(loaded.stats().is_null());
    }

    #[test]
    fn an_empty_library_round_trips() {
        let file = FlirtLibraryFile {
            schema_version: "2".to_string(),
            arch: "aarch64".to_string(),
            prologue_len: 32,
            entries: Vec::new(),
            index: Default::default(),
            library: None,
            stats: serde_json::json!({}),
        };
        assert_round_trips(&file);
    }

    /// The one field with no natural home in a columnar layout is the free
    /// text `source_binary`. It is interned like every other string, so a
    /// library whose 2,690 entries all name one archive pays for that path
    /// once.
    #[test]
    fn a_repeated_source_binary_is_interned_once() {
        let mut file = crate::flirt::gsig::sample_library_file();
        for i in 0..64 {
            let mut entry = file.entries[1].clone();
            entry.name = format!("fn_{i:03}");
            entry.prologue_hex = format!("554889e5488{i:05x}");
            entry.refs = Vec::new();
            file.entries.push(entry);
        }
        file.index.clear();
        let bytes = library_file_to_gsig(&file, &WriteOptions::default()).unwrap();
        let loaded = GsigLibrary::parse(&bytes).unwrap();
        // 66 entries, one shared source string: names + source + refs + meta
        // strings, not 66 copies of "libsample.a".
        assert!(loaded.header().n_strings < 80, "{:?}", loaded.header());
        assert_round_trips(&file);
    }
}
