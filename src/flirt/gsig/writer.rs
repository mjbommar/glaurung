//! The `gsig/1` writer.
//!
//! Everything here exists to make one property true: **the bytes are a pure
//! function of the input.** Records are sorted, the string table is sorted and
//! deduplicated, the chunk size and codec are fixed, and no timestamp, path or
//! hash-map iteration order reaches the file. `tests/flirt_gsig_golden.rs`
//! holds that property to a committed SHA-256.

use std::collections::HashMap;

use super::codec::Encoder;
use super::wire::{
    pack_bitmap, IndexKind, StringTableBuilder, WireIndexBucket, WireMeta, WireRecord,
    FLAG_HAS_CRC16, FLAG_HAS_FUNCTION_LEN, FLAG_HAS_MASK, NO_STRING,
};
use super::{
    Arch, ChunkEntry, ChunkKind, GsigError, GsigHeader, Scheme, CHUNK_ENTRY_LEN, CHUNK_SIZE,
    FORMAT_VERSION, HEADER_LEN, READER_VERSION,
};
use crate::flirt::{FlirtLibraryFile, FlirtSignatureEntry};

/// Knobs the writer exposes. The defaults are what a shipped library uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteOptions {
    /// How chunks are compressed. See [`Encoder`].
    pub encoder: Encoder,
    /// Uncompressed bytes per chunk. [`CHUNK_SIZE`] unless a measurement says
    /// otherwise; smaller means finer seeking and worse ratio.
    pub chunk_size: usize,
    /// Zstandard dictionary id to record. `0` (none) until the distribution
    /// lane trains one — the reader refuses anything else, which is the
    /// correct behaviour for a dictionary it cannot obtain.
    pub dict_id: u32,
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            encoder: Encoder::default(),
            chunk_size: CHUNK_SIZE,
            dict_id: 0,
        }
    }
}

/// One entry, decoded out of its hex and ready to lay out.
struct Prepared<'a> {
    entry: &'a FlirtSignatureEntry,
    pattern: Vec<u8>,
    /// `None` when the entry had no `mask_hex` — i.e. every byte is fixed.
    fixed: Option<Vec<bool>>,
    /// Where this entry sat in the caller's `entries`, so the JSON `index`
    /// can be remapped if the sort moved it.
    original: usize,
}

impl Prepared<'_> {
    /// The sort key: `(name, pattern)`, exactly what the design calls for and
    /// exactly what the Python builder already emits.
    ///
    /// It is deliberately **not** a total order, and the sort is stable. Two
    /// entries can share a name and a pattern and differ only in their CRC and
    /// provenance -- MinGW's `libmsvcrt` has 24 called `_stub` -- and those
    /// keep the order the caller gave them. Extending the key to break such
    /// ties would reorder them against the JSON file they came from, and
    /// "JSON to gsig to JSON is byte-identical" would stop holding for 35 of
    /// the 419 harvested libraries. Determinism here means "a pure function of
    /// the input", and the input's order is part of the input.
    fn sort_key(&self) -> (&str, &[u8]) {
        (&self.entry.name, &self.pattern)
    }

    /// Is this entry filed in the derivable prefix index? See
    /// [`IndexKind::Derived`].
    fn indexable(&self) -> bool {
        self.pattern.len() >= 4
            && self
                .fixed
                .as_ref()
                .is_none_or(|f| f.iter().take(4).all(|b| *b))
    }
}

fn hex_to_bytes(s: &str, what: &'static str) -> Result<Vec<u8>, GsigError> {
    hex::decode(s).map_err(|e| GsigError::Encode(format!("{what} {s:?} is not hex: {e}")))
}

/// Decode every entry's hex, refusing anything the container cannot represent
/// faithfully.
///
/// The JSON matcher *drops* an entry whose mask length disagrees with its
/// pattern. A converter must not: silently losing signatures during a format
/// change is exactly the kind of thing that shows up months later as "the new
/// format is worse". Say so and stop.
fn prepare<'a>(file: &'a FlirtLibraryFile) -> Result<Vec<Prepared<'a>>, GsigError> {
    let mut out = Vec::with_capacity(file.entries.len());
    for (original, entry) in file.entries.iter().enumerate() {
        let pattern = hex_to_bytes(&entry.prologue_hex, "prologue_hex")?;
        let fixed = match &entry.mask_hex {
            None => None,
            Some(mask_hex) => {
                let mask = hex_to_bytes(mask_hex, "mask_hex")?;
                if mask.len() != pattern.len() {
                    return Err(GsigError::Encode(format!(
                        "entry {:?} has a {}-byte mask over a {}-byte pattern",
                        entry.name,
                        mask.len(),
                        pattern.len()
                    )));
                }
                Some(mask.iter().map(|b| *b != 0).collect())
            }
        };
        if pattern.len() > usize::from(u16::MAX) {
            return Err(GsigError::TooLarge("pattern bytes", pattern.len()));
        }
        out.push(Prepared {
            entry,
            pattern,
            fixed,
            original,
        });
    }
    Ok(out)
}

/// The prefix index [`IndexKind::Derived`] describes, over `prepared` in its
/// final order.
fn derive_index(prepared: &[Prepared<'_>]) -> HashMap<String, Vec<usize>> {
    let mut index: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, p) in prepared.iter().enumerate() {
        if p.indexable() {
            index
                .entry(hex::encode(&p.pattern[..4]))
                .or_default()
                .push(i);
        }
    }
    index
}

/// The caller's `index`, with every entry number moved to where the sort put
/// it. Returns `None` if it names an entry that does not exist.
fn remap_index(
    index: &HashMap<String, Vec<usize>>,
    old_to_new: &[usize],
) -> Option<HashMap<String, Vec<usize>>> {
    let mut out: HashMap<String, Vec<usize>> = HashMap::with_capacity(index.len());
    for (key, entries) in index {
        let mut moved: Vec<usize> = entries
            .iter()
            .map(|old| old_to_new.get(*old).copied())
            .collect::<Option<Vec<usize>>>()?;
        moved.sort_unstable();
        out.insert(key.clone(), moved);
    }
    Some(out)
}

/// One logical section, before chunking.
#[derive(Default)]
struct Sections {
    meta: Vec<u8>,
    strings: Vec<u8>,
    signatures: Vec<u8>,
    patterns: Vec<u8>,
    masks: Vec<u8>,
    refs: Vec<u8>,
    guids: Vec<u8>,
    index: Vec<u8>,
}

impl Sections {
    fn get(&self, kind: ChunkKind) -> &[u8] {
        match kind {
            ChunkKind::Meta => &self.meta,
            ChunkKind::Strings => &self.strings,
            ChunkKind::Signatures => &self.signatures,
            ChunkKind::Patterns => &self.patterns,
            ChunkKind::Masks => &self.masks,
            ChunkKind::Refs => &self.refs,
            ChunkKind::Guids => &self.guids,
            ChunkKind::Index => &self.index,
        }
    }
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, GsigError> {
    postcard::to_stdvec(value).map_err(|e| GsigError::Encode(e.to_string()))
}

fn append<T: serde::Serialize>(buf: Vec<u8>, value: &T) -> Result<Vec<u8>, GsigError> {
    postcard::to_extend(value, buf).map_err(|e| GsigError::Encode(e.to_string()))
}

/// Serialize a signature library to `gsig/1` bytes.
///
/// Deterministic: two calls with the same `file` and `options` produce
/// identical bytes, and shuffling `file.entries` does not change them as long
/// as no two entries share a `(name, pattern)` -- the sort is stable, so
/// entries that do share one keep the caller's order. See
/// [`Prepared::sort_key`] for why that is the right trade.
pub fn write(file: &FlirtLibraryFile, options: &WriteOptions) -> Result<Vec<u8>, GsigError> {
    let mut prepared = prepare(file)?;
    prepared.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    let mut old_to_new = vec![0usize; prepared.len()];
    for (new, p) in prepared.iter().enumerate() {
        old_to_new[p.original] = new;
    }

    // ---- strings -------------------------------------------------------
    let stats_json = if file.stats.is_null() {
        String::new()
    } else {
        serde_json::to_string(&file.stats).map_err(|e| GsigError::Encode(e.to_string()))?
    };
    let mut table = StringTableBuilder::default();
    table.add(&file.schema_version);
    table.add(&file.arch);
    table.add(&stats_json);
    if let Some(key) = &file.library {
        for s in [&key.name, &key.version, &key.variant, &key.arch] {
            table.add(s);
        }
    }
    for p in &prepared {
        table.add(&p.entry.name);
        table.add(&p.entry.source_binary);
        for r in &p.entry.refs {
            table.add(&r.name);
        }
    }

    // The index is derived data. Store it only when the derivation does not
    // reproduce it -- which, over all 419 harvested libraries, never happened.
    let derived = derive_index(&prepared);
    let remapped = remap_index(&file.index, &old_to_new);
    let index_kind = match &remapped {
        Some(actual) if *actual == derived => IndexKind::Derived,
        _ => IndexKind::Explicit,
    };
    let explicit: Vec<(String, Vec<usize>)> = if index_kind == IndexKind::Explicit {
        let mut buckets: Vec<(String, Vec<usize>)> = remapped
            .unwrap_or_else(|| file.index.clone())
            .into_iter()
            .collect();
        buckets.sort_by(|a, b| a.0.cmp(&b.0));
        for (key, _) in &buckets {
            table.add(key);
        }
        buckets
    } else {
        Vec::new()
    };

    let (strings, string_id) = table.finish();
    let id_of = |s: &str| -> u32 { string_id.get(s).copied().unwrap_or(NO_STRING) };

    // ---- sections ------------------------------------------------------
    let mut sections = Sections {
        strings: encode(&strings)?,
        ..Default::default()
    };

    for p in &prepared {
        let mut flags = 0u8;
        if let Some(fixed) = &p.fixed {
            flags |= FLAG_HAS_MASK;
            sections.masks.extend_from_slice(&pack_bitmap(fixed));
        }
        if p.entry.crc16.is_some() {
            flags |= FLAG_HAS_CRC16;
        }
        if p.entry.function_len.is_some() {
            flags |= FLAG_HAS_FUNCTION_LEN;
        }
        sections.patterns.extend_from_slice(&p.pattern);
        for r in &p.entry.refs {
            sections.refs.extend_from_slice(&r.offset.to_le_bytes());
            sections
                .refs
                .extend_from_slice(&id_of(&r.name).to_le_bytes());
        }
        let record = WireRecord {
            name: id_of(&p.entry.name),
            source: id_of(&p.entry.source_binary),
            pattern_len: p.pattern.len() as u16,
            flags,
            crc16: p.entry.crc16.unwrap_or(0),
            crc_len: p.entry.crc_len,
            function_len: p.entry.function_len.unwrap_or(0),
            n_refs: u32::try_from(p.entry.refs.len())
                .map_err(|_| GsigError::TooLarge("references", p.entry.refs.len()))?,
        };
        sections.signatures = append(std::mem::take(&mut sections.signatures), &record)?;
    }

    if index_kind == IndexKind::Explicit {
        let buckets: Vec<WireIndexBucket> = explicit
            .into_iter()
            .map(|(key, entries)| WireIndexBucket {
                key: id_of(&key),
                entries: entries.into_iter().map(|e| e as u32).collect(),
            })
            .collect();
        sections.index = encode(&buckets)?;
    }

    let library = file.library.as_ref().map_or([NO_STRING; 4], |k| {
        [
            id_of(&k.name),
            id_of(&k.version),
            id_of(&k.variant),
            id_of(&k.arch),
        ]
    });
    sections.meta = encode(&WireMeta {
        schema_version: id_of(&file.schema_version),
        arch: id_of(&file.arch),
        prologue_len: u32::try_from(file.prologue_len)
            .map_err(|_| GsigError::TooLarge("prologue bytes", file.prologue_len))?,
        library,
        stats_json: id_of(&stats_json),
        index_kind: index_kind as u8,
    })?;

    let header = GsigHeader {
        format_version: FORMAT_VERSION,
        reader_min: READER_VERSION,
        arch: Arch::from_name(&file.arch),
        scheme: Scheme::FlirtMaskedPatternV1,
        n_signatures: u32::try_from(prepared.len())
            .map_err(|_| GsigError::TooLarge("signatures", prepared.len()))?,
        n_strings: u32::try_from(strings.len())
            .map_err(|_| GsigError::TooLarge("strings", strings.len()))?,
        dict_id: options.dict_id,
        chunk_count: 0,
        header_len: HEADER_LEN as u32,
    };
    assemble(header, &sections, options)
}

/// Serialize an exact-match GUID library — [`Scheme::WarpFunctionGuidV1`] and
/// anything else whose identity is a plain `u128` equality key.
///
/// The same container, a different index: no patterns, no masks, no CRCs, just
/// the Guids section, written **sorted by GUID** so the reader can binary
/// search it in place instead of building a hash map.
pub fn write_guid_library(
    arch: &str,
    entries: &[(u128, String)],
    options: &WriteOptions,
) -> Result<Vec<u8>, GsigError> {
    let mut sorted: Vec<(u128, &str)> = entries.iter().map(|(g, n)| (*g, n.as_str())).collect();
    sorted.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    sorted.dedup();

    let mut table = StringTableBuilder::default();
    table.add("");
    table.add(arch);
    for (_, name) in &sorted {
        table.add(name);
    }
    let (strings, string_id) = table.finish();
    let id_of = |s: &str| -> u32 { string_id.get(s).copied().unwrap_or(NO_STRING) };

    let mut guids = Vec::with_capacity(sorted.len() * 20);
    for (guid, name) in &sorted {
        guids.extend_from_slice(&guid.to_le_bytes());
        guids.extend_from_slice(&id_of(name).to_le_bytes());
    }

    let meta = encode(&WireMeta {
        schema_version: id_of(""),
        arch: id_of(arch),
        prologue_len: 0,
        library: [NO_STRING; 4],
        stats_json: id_of(""),
        index_kind: IndexKind::Derived as u8,
    })?;
    let sections = Sections {
        meta,
        strings: encode(&strings)?,
        guids,
        ..Default::default()
    };
    let header = GsigHeader {
        format_version: FORMAT_VERSION,
        reader_min: READER_VERSION,
        arch: Arch::from_name(arch),
        scheme: Scheme::WarpFunctionGuidV1,
        n_signatures: 0,
        n_strings: u32::try_from(strings.len())
            .map_err(|_| GsigError::TooLarge("strings", strings.len()))?,
        dict_id: options.dict_id,
        chunk_count: 0,
        header_len: HEADER_LEN as u32,
    };
    assemble(header, &sections, options)
}

/// Chunk, compress and lay out. Sections are emitted in [`ChunkKind::ALL`]
/// order; an empty section emits no chunks at all, so a file with no
/// references carries no Refs entry rather than a zero-length one.
fn assemble(
    mut header: GsigHeader,
    sections: &Sections,
    options: &WriteOptions,
) -> Result<Vec<u8>, GsigError> {
    let chunk_size = options.chunk_size.max(1);
    let mut payloads: Vec<(u8, u8, Vec<u8>, u32)> = Vec::new();
    for kind in ChunkKind::ALL {
        let data = sections.get(kind);
        for piece in data.chunks(chunk_size) {
            let stored = options.encoder.compress(piece);
            payloads.push((
                kind as u8,
                options.encoder.compression() as u8,
                stored,
                piece.len() as u32,
            ));
        }
    }

    header.chunk_count =
        u32::try_from(payloads.len()).map_err(|_| GsigError::TooLarge("chunks", payloads.len()))?;

    let table_len = payloads.len() * CHUNK_ENTRY_LEN;
    let mut offset = (HEADER_LEN + table_len) as u64;
    let mut table = Vec::with_capacity(table_len);
    for (kind, compression, stored, uncompressed) in &payloads {
        let entry = ChunkEntry {
            kind: *kind,
            compression: *compression,
            compressed_size: u32::try_from(stored.len())
                .map_err(|_| GsigError::TooLarge("chunk bytes", stored.len()))?,
            uncompressed_size: *uncompressed,
            file_offset: offset,
        };
        table.extend_from_slice(&entry.to_bytes());
        offset += stored.len() as u64;
    }

    let mut out = Vec::with_capacity(offset as usize);
    out.extend_from_slice(&header.to_bytes());
    out.extend_from_slice(&table);
    for (_, _, stored, _) in &payloads {
        out.extend_from_slice(stored);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flirt::gsig::sample_library_file as sample_file;

    #[test]
    fn a_written_file_starts_with_the_magic_and_a_parseable_header() {
        let bytes = write(&sample_file(), &WriteOptions::default()).unwrap();
        assert_eq!(&bytes[0..4], b"GSIG");
        let header = GsigHeader::parse(&bytes).unwrap();
        assert_eq!(header.format_version, FORMAT_VERSION);
        assert_eq!(header.n_signatures, 2);
        assert_eq!(header.arch, Arch::X86_64);
        assert_eq!(header.scheme, Scheme::FlirtMaskedPatternV1);
        assert!(header.chunk_count >= 5);
    }

    #[test]
    fn two_writes_of_one_input_are_byte_identical() {
        let file = sample_file();
        let a = write(&file, &WriteOptions::default()).unwrap();
        let b = write(&file, &WriteOptions::default()).unwrap();
        assert_eq!(a, b);
    }

    /// Distinct `(name, pattern)` keys sort to the same place whatever order
    /// a harvester emitted them in, so the blob is the same blob.
    #[test]
    fn entry_order_does_not_change_the_bytes_when_keys_are_distinct() {
        let file = sample_file();
        let mut shuffled = file.clone();
        shuffled.entries.reverse();
        shuffled.index.insert("554889e5".to_string(), vec![0, 1]);
        assert_eq!(
            write(&file, &WriteOptions::default()).unwrap(),
            write(&shuffled, &WriteOptions::default()).unwrap()
        );
    }

    /// ...and entries that *share* a key keep the caller's order, which is
    /// what makes the JSON round trip exact for the 35 harvested libraries
    /// that contain such duplicates. See [`Prepared::sort_key`].
    #[test]
    fn entries_sharing_a_key_keep_the_callers_order() {
        let mut file = sample_file();
        let mut twin = file.entries[0].clone();
        twin.crc16 = Some(0x0001);
        twin.source_binary = "other.o".to_string();
        file.entries.insert(1, twin);
        file.index.insert("554889e5".to_string(), vec![0, 1, 2]);

        let bytes = write(&file, &WriteOptions::default()).unwrap();
        let mut swapped = file.clone();
        swapped.entries.swap(0, 1);
        assert_ne!(bytes, write(&swapped, &WriteOptions::default()).unwrap());
        assert_eq!(bytes, write(&file, &WriteOptions::default()).unwrap());
    }

    #[test]
    fn the_chunk_table_offsets_tile_the_file_without_gaps() {
        let bytes = write(&sample_file(), &WriteOptions::default()).unwrap();
        let header = GsigHeader::parse(&bytes).unwrap();
        let mut expected = HEADER_LEN as u64 + u64::from(header.chunk_count) * 24;
        for i in 0..header.chunk_count as usize {
            let at = header.header_len as usize + i * CHUNK_ENTRY_LEN;
            let entry = ChunkEntry::parse(&bytes[at..]).unwrap();
            assert_eq!(entry.file_offset, expected, "chunk {i}");
            expected += u64::from(entry.compressed_size);
        }
        assert_eq!(expected as usize, bytes.len());
    }

    #[test]
    fn a_mask_the_matcher_would_drop_is_refused_not_silently_lost() {
        let mut file = sample_file();
        file.entries[0].mask_hex = Some("ffff".to_string());
        let err = write(&file, &WriteOptions::default()).unwrap_err();
        assert!(
            format!("{err}").contains("2-byte mask over a 8-byte pattern"),
            "{err}"
        );
    }

    /// The prefix index is derived data; the writer must recognise that and
    /// store nothing.
    #[test]
    fn a_derivable_index_costs_no_chunk() {
        let bytes = write(&sample_file(), &WriteOptions::default()).unwrap();
        let header = GsigHeader::parse(&bytes).unwrap();
        for i in 0..header.chunk_count as usize {
            let at = header.header_len as usize + i * CHUNK_ENTRY_LEN;
            let entry = ChunkEntry::parse(&bytes[at..]).unwrap();
            assert_ne!(entry.known_kind(), Some(ChunkKind::Index));
        }
    }

    #[test]
    fn an_underivable_index_is_stored_explicitly() {
        let mut file = sample_file();
        file.index.insert("deadbeef".to_string(), vec![1]);
        let bytes = write(&file, &WriteOptions::default()).unwrap();
        let header = GsigHeader::parse(&bytes).unwrap();
        let kinds: Vec<Option<ChunkKind>> = (0..header.chunk_count as usize)
            .map(|i| {
                let at = header.header_len as usize + i * CHUNK_ENTRY_LEN;
                ChunkEntry::parse(&bytes[at..]).unwrap().known_kind()
            })
            .collect();
        assert!(kinds.contains(&Some(ChunkKind::Index)));
    }

    #[test]
    fn a_guid_library_carries_a_sorted_guid_section_and_no_patterns() {
        let entries = vec![
            (
                0x0000_0000_0000_0000_0000_0000_0000_0002u128,
                "b".to_string(),
            ),
            (
                0x0000_0000_0000_0000_0000_0000_0000_0001u128,
                "a".to_string(),
            ),
        ];
        let bytes = write_guid_library("x86_64", &entries, &WriteOptions::default()).unwrap();
        let header = GsigHeader::parse(&bytes).unwrap();
        assert_eq!(header.scheme, Scheme::WarpFunctionGuidV1);
        assert_eq!(header.n_signatures, 0);
        let mut saw_guids = false;
        for i in 0..header.chunk_count as usize {
            let at = header.header_len as usize + i * CHUNK_ENTRY_LEN;
            let entry = ChunkEntry::parse(&bytes[at..]).unwrap();
            assert_ne!(entry.known_kind(), Some(ChunkKind::Patterns));
            saw_guids |= entry.known_kind() == Some(ChunkKind::Guids);
        }
        assert!(saw_guids);
    }

    /// A 64 KiB chunk size over a small library means one chunk per section;
    /// a tiny one proves the splitting works at all.
    #[test]
    fn a_small_chunk_size_splits_a_section() {
        let file = sample_file();
        let big = WriteOptions::default();
        let small = WriteOptions {
            chunk_size: 4,
            ..WriteOptions::default()
        };
        let a = GsigHeader::parse(&write(&file, &big).unwrap())
            .unwrap()
            .chunk_count;
        let b = GsigHeader::parse(&write(&file, &small).unwrap())
            .unwrap()
            .chunk_count;
        assert!(b > a, "{b} should exceed {a}");
    }
}
