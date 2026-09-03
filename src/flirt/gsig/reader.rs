//! The `gsig/1` reader.
//!
//! The file is `mmap`ed, the header and chunk table are parsed **without
//! inflating anything**, and then the sections are inflated into **one** arena
//! allocation whose size is known in advance from the chunk table's
//! `uncompressed_size` fields. Records hold `(offset, len)` into that arena;
//! nothing is copied per record.
//!
//! Zero-copy is not a goal — see the module docs of [`super`] — so the arena
//! is owned, not borrowed from the mapping, and the mapping is dropped as soon
//! as the last chunk is inflated. That keeps the loaded library independent of
//! the file, which is what a process-level cache keyed by path and mtime
//! wants.

use std::collections::HashMap;
use std::path::Path;

use super::codec::decompress_into;
use super::wire::{
    string_at, unpack_bitmap, IndexKind, WireIndexBucket, WireMeta, WireRecord, FLAG_HAS_CRC16,
    FLAG_HAS_FUNCTION_LEN, FLAG_HAS_MASK, NO_STRING,
};
use super::{
    Arch, ChunkEntry, ChunkKind, Compression, GsigError, GsigHeader, Scheme, CHUNK_ENTRY_LEN,
};
use crate::flirt::{FlirtLibraryKey, FlirtReference};

/// One signature, as the reader holds it: a fixed-size row plus spans into
/// the arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GsigRecord {
    /// String id of the function name.
    pub name: u32,
    /// String id of `source_binary`.
    pub source: u32,
    /// Byte offset of the pattern within the arena.
    pub pattern_off: u32,
    /// Pattern length in bytes.
    pub pattern_len: u16,
    /// Byte offset of the mask bitmap within the arena, or [`u32::MAX`] when
    /// the record has no mask — which means every pattern byte is fixed.
    pub mask_off: u32,
    /// Expected FLIRT CRC16, when the record records one.
    pub crc16: Option<u16>,
    /// How many bytes after the pattern the CRC covers.
    pub crc_len: u16,
    /// The function's total length, when the builder knew it.
    pub function_len: Option<u32>,
    /// Index of this record's first reference in the reference array.
    pub refs_off: u32,
    /// How many references it has.
    pub n_refs: u32,
}

/// A loaded `.gsig`.
///
/// The match indices are **rebuilt at load**, not serialised: `fast-flirt`
/// measures 944k patterns loading in 361 ms including inflation and trie
/// construction, so a format that pays alignment or schema-compiler costs to
/// avoid that is paying for nothing. [`Self::by_first_byte`] is the FLIRT
/// bucketing; [`Self::by_guid`] is the sorted array an equality scheme binary
/// searches.
pub struct GsigLibrary {
    header: GsigHeader,
    /// Strings, then patterns, then mask bitmaps, then the reference array —
    /// one allocation.
    arena: Box<[u8]>,
    /// `(offset, len)` of each interned string within the arena.
    str_spans: Box<[(u32, u32)]>,
    records: Box<[GsigRecord]>,
    /// `(offset, string id)` pairs, in record order.
    refs: Box<[(u32, u32)]>,
    /// Sorted `(guid, string id)`, for [`Scheme::WarpFunctionGuidV1`].
    by_guid: Option<Box<[(u128, u32)]>>,
    /// First fixed pattern byte to record indices. Records whose first byte
    /// is variant are in [`Self::always_try`] instead.
    by_first_byte: HashMap<u8, Vec<u32>>,
    always_try: Vec<u32>,
    schema_version: String,
    arch_name: String,
    prologue_len: usize,
    library: Option<FlirtLibraryKey>,
    stats: serde_json::Value,
    index_kind: IndexKind,
    explicit_index: Vec<WireIndexBucket>,
    /// Per-kind `(chunks, compressed, uncompressed)`, kept for
    /// `flirt_library_info_path` — the numbers a corpus publisher needs are
    /// exactly the ones the reader already had to read.
    chunk_summary: Vec<(u8, u32, u64, u64)>,
}

/// Everything one section inflated to, plus where it sits in the arena.
struct Span {
    off: usize,
    len: usize,
}

impl Span {
    fn slice<'a>(&self, arena: &'a [u8]) -> &'a [u8] {
        &arena[self.off..self.off + self.len]
    }
}

impl GsigLibrary {
    /// Parse and inflate a `.gsig` from memory.
    pub fn parse(data: &[u8]) -> Result<Self, GsigError> {
        let header = GsigHeader::parse(data)?;
        let entries = read_chunk_table(data, &header)?;

        // Size the arena from the table before inflating a single byte:
        // WARP's rule, and the reason `uncompressed_size` is recorded.
        let mut summary: HashMap<u8, (u32, u64, u64)> = HashMap::new();
        for entry in &entries {
            let stat = summary.entry(entry.kind).or_insert((0, 0, 0));
            stat.0 += 1;
            stat.1 += u64::from(entry.compressed_size);
            stat.2 += u64::from(entry.uncompressed_size);
        }
        // Only the sections this build knows are inflated; an unknown kind is
        // skipped by its recorded size, which is the whole point of recording
        // it. Chunks of one kind need not be contiguous in the file: the arena
        // is laid out in `ChunkKind::ALL` order and each kind keeps its own
        // write cursor, so a producer that interleaves still reads correctly.
        let mut spans: HashMap<u8, Span> = HashMap::new();
        let mut arena_len = 0usize;
        for kind in ChunkKind::ALL {
            let len = summary.get(&(kind as u8)).map_or(0, |s| s.2 as usize);
            spans.insert(
                kind as u8,
                Span {
                    off: arena_len,
                    len,
                },
            );
            arena_len += len;
        }

        let mut arena = vec![0u8; arena_len];
        let mut cursor: HashMap<u8, usize> = HashMap::new();
        for entry in &entries {
            let Some(span) = spans.get(&entry.kind) else {
                continue;
            };
            let compression = Compression::from_u8(entry.compression)
                .ok_or(GsigError::UnknownCompression(entry.compression))?;
            let start = entry.file_offset as usize;
            let end =
                start
                    .checked_add(entry.compressed_size as usize)
                    .ok_or(GsigError::Truncated {
                        what: "chunk payload",
                        have: data.len(),
                        need: usize::MAX,
                    })?;
            if end > data.len() {
                return Err(GsigError::Truncated {
                    what: "chunk payload",
                    have: data.len(),
                    need: end,
                });
            }
            let at = cursor.entry(entry.kind).or_insert(0);
            let dst = span.off + *at;
            decompress_into(
                compression,
                &data[start..end],
                &mut arena[dst..dst + entry.uncompressed_size as usize],
            )?;
            *at += entry.uncompressed_size as usize;
        }
        let arena = arena.into_boxed_slice();

        // ---- strings ---------------------------------------------------
        // postcard hands back `&str`s that borrow the arena, so the table
        // costs no second copy: all that is recorded is where each one sits.
        let string_span = &spans[&(ChunkKind::Strings as u8)];
        let strings: Vec<&str> = if string_span.len == 0 {
            Vec::new()
        } else {
            postcard::from_bytes(string_span.slice(&arena))
                .map_err(|e| GsigError::Decode(format!("string table: {e}")))?
        };
        let arena_base = arena.as_ptr() as usize;
        let mut str_spans: Vec<(u32, u32)> = Vec::with_capacity(strings.len());
        for s in &strings {
            let off = (s.as_ptr() as usize).wrapping_sub(arena_base);
            if off < string_span.off || off + s.len() > string_span.off + string_span.len {
                // Only reachable if postcard ever stopped borrowing, which
                // would make every recorded span wrong. Fail rather than hand
                // out offsets into nothing.
                return Err(GsigError::Decode(
                    "string table did not borrow from the arena".to_string(),
                ));
            }
            str_spans.push((off as u32, s.len() as u32));
        }

        // ---- meta ------------------------------------------------------
        let meta_span = &spans[&(ChunkKind::Meta as u8)];
        if meta_span.len == 0 {
            return Err(GsigError::MissingSection("meta"));
        }
        let meta: WireMeta = postcard::from_bytes(meta_span.slice(&arena))
            .map_err(|e| GsigError::Decode(format!("meta: {e}")))?;
        let schema_version = string_at(&strings, meta.schema_version)?.to_string();
        let arch_name = string_at(&strings, meta.arch)?.to_string();
        let library = if meta.library[0] == NO_STRING {
            None
        } else {
            Some(FlirtLibraryKey {
                name: string_at(&strings, meta.library[0])?.to_string(),
                version: string_at(&strings, meta.library[1])?.to_string(),
                variant: string_at(&strings, meta.library[2])?.to_string(),
                arch: string_at(&strings, meta.library[3])?.to_string(),
            })
        };
        let stats_text = string_at(&strings, meta.stats_json)?;
        let stats = if stats_text.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(stats_text)
                .map_err(|e| GsigError::Decode(format!("stats: {e}")))?
        };

        // ---- records ---------------------------------------------------
        let pattern_base = spans[&(ChunkKind::Patterns as u8)].off;
        let pattern_cap = spans[&(ChunkKind::Patterns as u8)].len;
        let mask_base = spans[&(ChunkKind::Masks as u8)].off;
        let mask_cap = spans[&(ChunkKind::Masks as u8)].len;

        let mut records = Vec::with_capacity(header.n_signatures as usize);
        let mut rest: &[u8] = spans[&(ChunkKind::Signatures as u8)].slice(&arena);
        let (mut pat_at, mut mask_at, mut ref_at) = (0usize, 0usize, 0u32);
        for i in 0..header.n_signatures {
            let (wire, tail) = postcard::take_from_bytes::<WireRecord>(rest)
                .map_err(|e| GsigError::Decode(format!("record {i}: {e}")))?;
            rest = tail;
            let pattern_len = usize::from(wire.pattern_len);
            if pat_at + pattern_len > pattern_cap {
                return Err(GsigError::RecordOverrun(i, "patterns"));
            }
            let mask_off = if wire.flags & FLAG_HAS_MASK != 0 {
                let bits = super::wire::bitmap_len(pattern_len);
                if mask_at + bits > mask_cap {
                    return Err(GsigError::RecordOverrun(i, "masks"));
                }
                let off = (mask_base + mask_at) as u32;
                mask_at += bits;
                off
            } else {
                u32::MAX
            };
            records.push(GsigRecord {
                name: wire.name,
                source: wire.source,
                pattern_off: (pattern_base + pat_at) as u32,
                pattern_len: wire.pattern_len,
                mask_off,
                crc16: (wire.flags & FLAG_HAS_CRC16 != 0).then_some(wire.crc16),
                crc_len: wire.crc_len,
                function_len: (wire.flags & FLAG_HAS_FUNCTION_LEN != 0)
                    .then_some(wire.function_len),
                refs_off: ref_at,
                n_refs: wire.n_refs,
            });
            pat_at += pattern_len;
            ref_at = ref_at.saturating_add(wire.n_refs);
        }

        // ---- references ------------------------------------------------
        let refs: Vec<(u32, u32)> = spans[&(ChunkKind::Refs as u8)]
            .slice(&arena)
            .chunks_exact(8)
            .map(|c| {
                (
                    u32::from_le_bytes([c[0], c[1], c[2], c[3]]),
                    u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
                )
            })
            .collect();
        if (ref_at as usize) > refs.len() {
            return Err(GsigError::RecordOverrun(header.n_signatures, "refs"));
        }

        // ---- guids -----------------------------------------------------
        let guid_span = &spans[&(ChunkKind::Guids as u8)];
        let by_guid = (guid_span.len > 0).then(|| {
            let mut pairs: Vec<(u128, u32)> = guid_span
                .slice(&arena)
                .chunks_exact(20)
                .map(|c| {
                    let mut g = [0u8; 16];
                    g.copy_from_slice(&c[..16]);
                    (
                        u128::from_le_bytes(g),
                        u32::from_le_bytes([c[16], c[17], c[18], c[19]]),
                    )
                })
                .collect();
            // The writer sorts, but a reader that binary searches must not
            // take a producer's word for it.
            pairs.sort_unstable();
            pairs.into_boxed_slice()
        });

        // ---- explicit index --------------------------------------------
        let index_kind = IndexKind::from_u8(meta.index_kind);
        let index_span = &spans[&(ChunkKind::Index as u8)];
        let explicit_index: Vec<WireIndexBucket> =
            if index_kind == IndexKind::Explicit && index_span.len > 0 {
                postcard::from_bytes(index_span.slice(&arena))
                    .map_err(|e| GsigError::Decode(format!("index: {e}")))?
            } else {
                Vec::new()
            };

        let mut chunk_summary: Vec<(u8, u32, u64, u64)> = summary
            .into_iter()
            .map(|(kind, (n, c, u))| (kind, n, c, u))
            .collect();
        chunk_summary.sort_unstable();

        let mut library_out = Self {
            header,
            arena,
            str_spans: str_spans.into_boxed_slice(),
            records: records.into_boxed_slice(),
            refs: refs.into_boxed_slice(),
            by_guid,
            by_first_byte: HashMap::new(),
            always_try: Vec::new(),
            schema_version,
            arch_name,
            prologue_len: meta.prologue_len as usize,
            library,
            stats,
            index_kind,
            explicit_index,
            chunk_summary,
        };
        library_out.build_first_byte_index();
        Ok(library_out)
    }

    /// `mmap` a `.gsig` and load it.
    ///
    /// The mapping exists only for the duration of the parse; see the module
    /// docs for why the arena is owned rather than borrowed.
    pub fn open(path: &Path) -> Result<Self, GsigError> {
        let file = std::fs::File::open(path)?;
        // SAFETY: the file is opened read-only and the mapping is confined to
        // this function. A concurrent truncation could still fault, which is
        // the standard `mmap` caveat and the same one `crate::triage` already
        // accepts for every input it maps.
        let map = unsafe { memmap2::Mmap::map(&file)? };
        Self::parse(&map)
    }

    /// The first-fixed-byte buckets the FLIRT matcher scans.
    fn build_first_byte_index(&mut self) {
        let mut by_first_byte: HashMap<u8, Vec<u32>> = HashMap::new();
        let mut always_try: Vec<u32> = Vec::new();
        for (i, record) in self.records.iter().enumerate() {
            let first_is_fixed = record.mask_off == u32::MAX
                || self
                    .arena
                    .get(record.mask_off as usize)
                    .is_some_and(|byte| byte & 1 != 0);
            if first_is_fixed && record.pattern_len > 0 {
                by_first_byte
                    .entry(self.arena[record.pattern_off as usize])
                    .or_default()
                    .push(i as u32);
            } else {
                always_try.push(i as u32);
            }
        }
        self.by_first_byte = by_first_byte;
        self.always_try = always_try;
    }

    /// The parsed header.
    pub fn header(&self) -> &GsigHeader {
        &self.header
    }

    /// The exact architecture string the JSON carried.
    pub fn arch(&self) -> &str {
        &self.arch_name
    }

    /// The coarse architecture tag from the header.
    pub fn arch_tag(&self) -> Arch {
        self.header.arch
    }

    /// How the records identify a function.
    pub fn scheme(&self) -> Scheme {
        self.header.scheme
    }

    /// The JSON `schema_version`.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// The JSON `prologue_len`.
    pub fn prologue_len(&self) -> usize {
        self.prologue_len
    }

    /// The `(name, version, variant, arch)` provenance key, when the file
    /// carried one.
    pub fn library(&self) -> Option<&FlirtLibraryKey> {
        self.library.as_ref()
    }

    /// The builder statistics, verbatim.
    pub fn stats(&self) -> &serde_json::Value {
        &self.stats
    }

    /// The signature records.
    pub fn records(&self) -> &[GsigRecord] {
        &self.records
    }

    /// How many GUID entries the file carries, `0` for a pattern library.
    pub fn guid_count(&self) -> usize {
        self.by_guid.as_ref().map_or(0, |g| g.len())
    }

    /// Per-kind chunk statistics: `(kind byte, chunks, compressed bytes,
    /// uncompressed bytes)`, ascending by kind.
    pub fn chunk_summary(&self) -> &[(u8, u32, u64, u64)] {
        &self.chunk_summary
    }

    /// Look one interned string up.
    pub fn string(&self, id: u32) -> Result<&str, GsigError> {
        if id == NO_STRING {
            return Ok("");
        }
        let (off, len) = *self
            .str_spans
            .get(id as usize)
            .ok_or(GsigError::BadStringId(id, self.str_spans.len() as u32))?;
        std::str::from_utf8(&self.arena[off as usize..(off + len) as usize])
            .map_err(|e| GsigError::Decode(format!("string {id}: {e}")))
    }

    /// One record's pattern bytes.
    pub fn pattern(&self, record: &GsigRecord) -> &[u8] {
        let start = record.pattern_off as usize;
        &self.arena[start..start + usize::from(record.pattern_len)]
    }

    /// One record's per-byte "is fixed" mask. An absent mask means every byte
    /// is fixed, which is exactly the JSON schema's rule.
    pub fn fixed(&self, record: &GsigRecord) -> Vec<bool> {
        let n = usize::from(record.pattern_len);
        if record.mask_off == u32::MAX {
            return vec![true; n];
        }
        let start = record.mask_off as usize;
        unpack_bitmap(&self.arena[start..start + super::wire::bitmap_len(n)], n)
    }

    /// One record's referenced names.
    pub fn refs(&self, record: &GsigRecord) -> Result<Vec<FlirtReference>, GsigError> {
        let start = record.refs_off as usize;
        let end = start + record.n_refs as usize;
        self.refs
            .get(start..end)
            .ok_or(GsigError::RecordOverrun(record.refs_off, "refs"))?
            .iter()
            .map(|(offset, id)| {
                Ok(FlirtReference {
                    offset: *offset,
                    name: self.string(*id)?.to_string(),
                })
            })
            .collect()
    }

    /// The name behind a GUID, by binary search over the sorted array.
    ///
    /// `None` for a file with no Guids section, and for a GUID it does not
    /// hold. Two library functions can share a GUID (identical code under two
    /// names); this returns the first in sorted order, and a caller that cares
    /// about ambiguity should use [`Self::guid_names`].
    pub fn lookup_guid(&self, guid: u128) -> Option<&str> {
        self.guid_names(guid).first().copied()
    }

    /// Every name recorded for a GUID, in sorted order.
    pub fn guid_names(&self, guid: u128) -> Vec<&str> {
        let Some(pairs) = self.by_guid.as_deref() else {
            return Vec::new();
        };
        let start = pairs.partition_point(|(g, _)| *g < guid);
        pairs[start..]
            .iter()
            .take_while(|(g, _)| *g == guid)
            .filter_map(|(_, id)| self.string(*id).ok())
            .collect()
    }

    /// The first-fixed-byte bucket for `byte`, and the records that must
    /// always be tried because their first pattern byte is variant.
    pub fn candidates_for(&self, byte: u8) -> (&[u32], &[u32]) {
        (
            self.by_first_byte.get(&byte).map_or(&[][..], |v| v),
            &self.always_try,
        )
    }

    /// The JSON `index` map, either recomputed or read back verbatim —
    /// whichever the writer decided. See [`IndexKind`].
    pub fn index(&self) -> Result<HashMap<String, Vec<usize>>, GsigError> {
        if self.index_kind == IndexKind::Explicit {
            let mut out = HashMap::with_capacity(self.explicit_index.len());
            for bucket in &self.explicit_index {
                out.insert(
                    self.string(bucket.key)?.to_string(),
                    bucket.entries.iter().map(|e| *e as usize).collect(),
                );
            }
            return Ok(out);
        }
        let mut out: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, record) in self.records.iter().enumerate() {
            if record.pattern_len < 4 {
                continue;
            }
            let fixed = self.fixed(record);
            if !fixed.iter().take(4).all(|b| *b) {
                continue;
            }
            out.entry(hex::encode(&self.pattern(record)[..4]))
                .or_default()
                .push(i);
        }
        Ok(out)
    }
}

fn read_chunk_table(data: &[u8], header: &GsigHeader) -> Result<Vec<ChunkEntry>, GsigError> {
    let base = header.header_len as usize;
    let need = base
        .checked_add(header.chunk_count as usize * CHUNK_ENTRY_LEN)
        .ok_or(GsigError::Truncated {
            what: "chunk table",
            have: data.len(),
            need: usize::MAX,
        })?;
    if data.len() < need {
        return Err(GsigError::Truncated {
            what: "chunk table",
            have: data.len(),
            need,
        });
    }
    (0..header.chunk_count as usize)
        .map(|i| ChunkEntry::parse(&data[base + i * CHUNK_ENTRY_LEN..]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flirt::gsig::writer::{write, write_guid_library, WriteOptions};

    fn sample() -> crate::flirt::FlirtLibraryFile {
        crate::flirt::gsig::sample_library_file()
    }

    #[test]
    fn a_written_library_reads_back_field_for_field() {
        let file = sample();
        let bytes = write(&file, &WriteOptions::default()).unwrap();
        let lib = GsigLibrary::parse(&bytes).unwrap();
        assert_eq!(lib.schema_version(), "2");
        assert_eq!(lib.arch(), "x86_64");
        assert_eq!(lib.prologue_len(), 8);
        assert_eq!(lib.records().len(), 2);
        assert_eq!(lib.library().unwrap().name, "sample");
        assert_eq!(lib.stats(), &file.stats);

        let alpha = &lib.records()[0];
        assert_eq!(lib.string(alpha.name).unwrap(), "alpha");
        assert_eq!(lib.string(alpha.source).unwrap(), "libsample.a");
        assert_eq!(hex::encode(lib.pattern(alpha)), "554889e5e8000000");
        assert_eq!(
            lib.fixed(alpha),
            vec![true, true, true, true, true, false, false, false]
        );
        assert_eq!(alpha.crc16, Some(0x1e1a));
        assert_eq!(alpha.crc_len, 16);
        assert_eq!(alpha.function_len, Some(48));
        let refs = lib.refs(alpha).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].offset, 5);
        assert_eq!(refs[0].name, "memcpy");

        let beta = &lib.records()[1];
        assert_eq!(beta.mask_off, u32::MAX);
        assert_eq!(lib.fixed(beta), vec![true; 8]);
        assert_eq!(beta.crc16, None);
        assert_eq!(beta.function_len, None);
        assert!(lib.refs(beta).unwrap().is_empty());
    }

    #[test]
    fn the_prefix_index_is_reproduced_exactly() {
        let file = sample();
        let bytes = write(&file, &WriteOptions::default()).unwrap();
        let lib = GsigLibrary::parse(&bytes).unwrap();
        assert_eq!(lib.index().unwrap(), file.index);
    }

    #[test]
    fn an_explicit_index_reads_back_verbatim() {
        let mut file = sample();
        file.index.insert("deadbeef".to_string(), vec![1]);
        let bytes = write(&file, &WriteOptions::default()).unwrap();
        let lib = GsigLibrary::parse(&bytes).unwrap();
        assert_eq!(lib.index().unwrap(), file.index);
    }

    #[test]
    fn the_first_byte_index_buckets_by_the_first_fixed_byte() {
        let bytes = write(&sample(), &WriteOptions::default()).unwrap();
        let lib = GsigLibrary::parse(&bytes).unwrap();
        let (bucket, always) = lib.candidates_for(0x55);
        assert_eq!(bucket, &[0, 1]);
        assert!(always.is_empty());
        assert!(lib.candidates_for(0x90).0.is_empty());
    }

    /// A record whose *first* byte is variant cannot be bucketed and must
    /// land in `always_try`, or the matcher silently stops finding it.
    #[test]
    fn a_variant_first_byte_lands_in_always_try() {
        let mut file = sample();
        file.entries[0].mask_hex = Some("00ffffffff000000".to_string());
        file.index.clear();
        let bytes = write(&file, &WriteOptions::default()).unwrap();
        let lib = GsigLibrary::parse(&bytes).unwrap();
        assert_eq!(lib.candidates_for(0x55).1.len(), 1);
    }

    #[test]
    fn chunks_split_and_reassemble_at_any_chunk_size() {
        let file = sample();
        for chunk_size in [1usize, 3, 17, 64 * 1024] {
            let bytes = write(
                &file,
                &WriteOptions {
                    chunk_size,
                    ..WriteOptions::default()
                },
            )
            .unwrap();
            let lib = GsigLibrary::parse(&bytes).unwrap();
            assert_eq!(lib.records().len(), 2, "chunk_size {chunk_size}");
            assert_eq!(
                hex::encode(lib.pattern(&lib.records()[1])),
                "554889e54883ec10"
            );
        }
    }

    #[test]
    fn a_guid_library_binary_searches() {
        let entries = vec![
            (7u128, "seven".to_string()),
            (3u128, "three".to_string()),
            (3u128, "three_alias".to_string()),
        ];
        let bytes = write_guid_library("x86_64", &entries, &WriteOptions::default()).unwrap();
        let lib = GsigLibrary::parse(&bytes).unwrap();
        assert_eq!(lib.scheme(), Scheme::WarpFunctionGuidV1);
        assert_eq!(lib.guid_count(), 3);
        assert_eq!(lib.lookup_guid(7), Some("seven"));
        assert_eq!(lib.guid_names(3), vec!["three", "three_alias"]);
        assert_eq!(lib.lookup_guid(9), None);
        assert!(lib.guid_names(0).is_empty());
    }

    #[test]
    fn a_truncated_file_is_an_error_not_a_panic() {
        let bytes = write(&sample(), &WriteOptions::default()).unwrap();
        for cut in [0usize, 4, 32, 63, 70, bytes.len() - 1] {
            assert!(GsigLibrary::parse(&bytes[..cut]).is_err(), "cut at {cut}");
        }
    }

    /// Splice one extra chunk of `kind` onto a written file, the way a later
    /// format version would add a section: a new chunk-table entry and a
    /// payload at the end, with every existing offset shifted by the entry
    /// the table grew by.
    fn with_extra_chunk(bytes: &[u8], kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut header = GsigHeader::parse(bytes).unwrap();
        let table_at = header.header_len as usize;
        let old_table_len = header.chunk_count as usize * CHUNK_ENTRY_LEN;
        let mut entries: Vec<ChunkEntry> = (0..header.chunk_count as usize)
            .map(|i| ChunkEntry::parse(&bytes[table_at + i * CHUNK_ENTRY_LEN..]).unwrap())
            .collect();
        for entry in &mut entries {
            entry.file_offset += CHUNK_ENTRY_LEN as u64;
        }
        let payloads = &bytes[table_at + old_table_len..];
        entries.push(ChunkEntry {
            kind,
            compression: Compression::None as u8,
            compressed_size: payload.len() as u32,
            uncompressed_size: payload.len() as u32,
            file_offset: (table_at + old_table_len + CHUNK_ENTRY_LEN + payloads.len()) as u64,
        });
        header.chunk_count += 1;

        let mut out = header.to_bytes().to_vec();
        for entry in &entries {
            out.extend_from_slice(&entry.to_bytes());
        }
        out.extend_from_slice(payloads);
        out.extend_from_slice(payload);
        out
    }

    /// The forward-compatibility rule, exercised rather than asserted: a
    /// section a later version adds is skipped by its recorded size, and
    /// every section this build does know still reads.
    #[test]
    fn an_unknown_chunk_kind_is_skipped_by_size() {
        let file = sample();
        let bytes = write(&file, &WriteOptions::default()).unwrap();
        let extended = with_extra_chunk(&bytes, 200, b"a section from the future");
        let lib = GsigLibrary::parse(&extended).unwrap();
        assert_eq!(lib.schema_version(), "2");
        assert_eq!(lib.records().len(), 2);
        assert_eq!(lib.refs(&lib.records()[0]).unwrap().len(), 1);
        assert_eq!(lib.index().unwrap(), file.index);
        assert!(lib
            .chunk_summary()
            .iter()
            .any(|(kind, _, _, _)| *kind == 200));
    }

    /// The same splice with a *known* kind proves the skip above is really
    /// about the kind and not about trailing bytes being ignored.
    #[test]
    fn a_second_run_of_a_known_kind_is_appended_to_its_section() {
        let bytes = write(&sample(), &WriteOptions::default()).unwrap();
        let extended = with_extra_chunk(&bytes, ChunkKind::Refs as u8, &[9, 0, 0, 0, 0, 0, 0, 0]);
        let lib = GsigLibrary::parse(&extended).unwrap();
        assert_eq!(lib.records().len(), 2);
        assert_eq!(lib.refs(&lib.records()[0]).unwrap()[0].name, "memcpy");
    }
}
