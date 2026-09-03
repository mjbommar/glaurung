//! The `postcard` structs that cross the wire, and the two representation
//! changes that make [`super`] small: an interned string table and bitmap
//! masks.
//!
//! Nothing here is public API. The types exist so the writer and the reader
//! encode and decode exactly the same shape, which is the failure mode a
//! hand-rolled binary format usually dies of.

use serde::{Deserialize, Serialize};

use super::GsigError;

/// The string id meaning "absent".
///
/// A sentinel rather than an `Option<u32>` because it appears in fixed-width
/// contexts (the library key array) where postcard's `Option` discriminant
/// would cost a byte each and buy nothing.
pub const NO_STRING: u32 = u32::MAX;

/// `flags` bit: the record has a mask bitmap in the Masks section.
///
/// **Absent means every byte is fixed**, which is exactly the JSON schema's
/// rule for a missing `mask_hex` and exactly v1 FLIRT behaviour.
pub const FLAG_HAS_MASK: u8 = 1 << 0;
/// `flags` bit: `crc16` is meaningful.
pub const FLAG_HAS_CRC16: u8 = 1 << 1;
/// `flags` bit: `function_len` is meaningful.
pub const FLAG_HAS_FUNCTION_LEN: u8 = 1 << 2;

/// One signature, on the wire.
///
/// Three `Option`s are packed into [`Self::flags`] rather than spent as
/// postcard `Option` discriminants, and no offset into any other section is
/// stored: a record's pattern is the next `pattern_len` bytes of the Patterns
/// section, its mask the next `ceil(pattern_len / 8)` bytes of Masks if
/// [`FLAG_HAS_MASK`] is set, its references the next `n_refs` entries of Refs.
/// The reader accumulates as it walks the stream, which is a `u32` of
/// bookkeeping per section instead of three `u32`s per record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRecord {
    /// String id of the function name.
    pub name: u32,
    /// String id of `source_binary`, the free-text provenance field.
    pub source: u32,
    /// Pattern length in bytes. Usually the library's `prologue_len`, but
    /// stored per record so a file with a ragged pattern length round-trips.
    pub pattern_len: u16,
    /// [`FLAG_HAS_MASK`] | [`FLAG_HAS_CRC16`] | [`FLAG_HAS_FUNCTION_LEN`].
    pub flags: u8,
    /// FLIRT CRC16 over the `crc_len` bytes after the pattern. Meaningless,
    /// and written as `0`, without [`FLAG_HAS_CRC16`].
    pub crc16: u16,
    /// How many bytes after the pattern the CRC covers. `0` means no CRC.
    pub crc_len: u16,
    /// The function's total length. Meaningless, and written as `0`, without
    /// [`FLAG_HAS_FUNCTION_LEN`].
    pub function_len: u32,
    /// How many entries this record claims from the Refs section.
    pub n_refs: u32,
}

/// Library-level metadata: the one thing in the file that is not per record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMeta {
    /// String id of the JSON `schema_version` (`"1"` or `"2"`).
    pub schema_version: u32,
    /// String id of the exact JSON `arch` string. The header's
    /// [`super::Arch`] tag is a coarse filter; this is the identity.
    pub arch: u32,
    /// The JSON `prologue_len`.
    pub prologue_len: u32,
    /// String ids of the `(name, version, variant, arch)` library key, or
    /// four [`NO_STRING`]s when the file carried none.
    pub library: [u32; 4],
    /// String id of the builder `stats` object, as compact JSON text.
    /// `serde_json`'s map is a `BTreeMap` here, so that text is canonical.
    pub stats_json: u32,
    /// [`IndexKind`] as a byte.
    pub index_kind: u8,
}

/// How the JSON `index` map — first-four-pattern-bytes to entry indices — is
/// carried.
///
/// It is derived data, and over all 419 harvested libraries (147,733
/// signatures) the derivation below reproduces it exactly, so the normal case
/// stores nothing at all. The explicit fallback exists because "usually
/// derivable" is not "always derivable", and a lossy round trip is not a round
/// trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IndexKind {
    /// Recompute it: file each entry under the hex of its first four pattern
    /// bytes, and only when those four bytes are all fixed. An absent mask
    /// means all fixed, so this one rule covers both the archive builder's
    /// index and the legacy linked-binary builder's.
    Derived = 0,
    /// The Index section holds it verbatim.
    Explicit = 1,
}

impl IndexKind {
    /// The kind for a raw byte; anything unrecognised is
    /// [`IndexKind::Derived`], which is the v1 behaviour a later version's
    /// new kind must degrade to.
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Explicit,
            _ => Self::Derived,
        }
    }
}

/// One explicit index bucket: a hex prefix and the entry indices under it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireIndexBucket {
    /// String id of the hex key.
    pub key: u32,
    /// Entry indices, ascending.
    pub entries: Vec<u32>,
}

/// Bytes a bitmap needs for `n` pattern bytes, at one bit per byte.
pub fn bitmap_len(n: usize) -> usize {
    n.div_ceil(8)
}

/// Pack a per-byte "is fixed" mask into a bitmap, LSB-first within each byte.
pub fn pack_bitmap(fixed: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; bitmap_len(fixed.len())];
    for (i, is_fixed) in fixed.iter().enumerate() {
        if *is_fixed {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

/// Unpack `n` bits of a bitmap written by [`pack_bitmap`].
pub fn unpack_bitmap(bits: &[u8], n: usize) -> Vec<bool> {
    (0..n)
        .map(|i| bits.get(i / 8).is_some_and(|b| b & (1 << (i % 8)) != 0))
        .collect()
}

/// Builds the interned string table.
///
/// Interning is where most of the size win is: the format survey found 15,418
/// distinct function names and 10,279 distinct reference names collapsing to a
/// 582 KB table, against 268 KB of reference-name text in glibc's JSON alone.
/// Ids are assigned only once every string is known, in **sorted** order, so
/// the table — and therefore every id in every other section — is a pure
/// function of the set of strings, never of insertion order.
#[derive(Debug, Default)]
pub struct StringTableBuilder {
    seen: std::collections::BTreeSet<String>,
}

impl StringTableBuilder {
    /// Note that `s` will need an id.
    pub fn add(&mut self, s: &str) {
        if !self.seen.contains(s) {
            self.seen.insert(s.to_string());
        }
    }

    /// Freeze the table: the sorted string list, and a lookup from string to
    /// id.
    pub fn finish(self) -> (Vec<String>, std::collections::HashMap<String, u32>) {
        let strings: Vec<String> = self.seen.into_iter().collect();
        let ids = strings
            .iter()
            .enumerate()
            .map(|(i, s)| (s.clone(), i as u32))
            .collect();
        (strings, ids)
    }
}

/// Look a string id up in a decoded table, naming the id rather than
/// panicking on a corrupt file.
pub fn string_at<'a>(strings: &'a [&'a str], id: u32) -> Result<&'a str, GsigError> {
    if id == NO_STRING {
        return Ok("");
    }
    strings
        .get(id as usize)
        .copied()
        .ok_or(GsigError::BadStringId(id, strings.len() as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bitmap_costs_one_bit_per_pattern_byte() {
        assert_eq!(bitmap_len(32), 4);
        assert_eq!(bitmap_len(1), 1);
        assert_eq!(bitmap_len(0), 0);
        assert_eq!(bitmap_len(9), 2);
    }

    #[test]
    fn a_mask_round_trips_through_its_bitmap() {
        for len in [1usize, 7, 8, 9, 32, 64, 65] {
            let fixed: Vec<bool> = (0..len).map(|i| i % 3 != 0).collect();
            let packed = pack_bitmap(&fixed);
            assert_eq!(packed.len(), bitmap_len(len));
            assert_eq!(unpack_bitmap(&packed, len), fixed);
        }
    }

    /// The measurement that made bitmaps non-negotiable, in miniature: a
    /// 32-byte mask is 4 bytes here and 32 bytes in the JSON schema's
    /// `mask_hex` (64 hex characters, in fact).
    #[test]
    fn a_bitmap_is_an_eighth_of_a_byte_mask() {
        let fixed = vec![true; 32];
        assert_eq!(pack_bitmap(&fixed).len() * 8, fixed.len());
    }

    #[test]
    fn string_ids_follow_sorted_order_not_insertion_order() {
        let mut a = StringTableBuilder::default();
        for s in ["zebra", "alpha", "middle", "alpha"] {
            a.add(s);
        }
        let mut b = StringTableBuilder::default();
        for s in ["middle", "alpha", "zebra"] {
            b.add(s);
        }
        let (sa, ia) = a.finish();
        let (sb, ib) = b.finish();
        assert_eq!(sa, vec!["alpha", "middle", "zebra"]);
        assert_eq!(sa, sb);
        assert_eq!(ia, ib);
    }

    #[test]
    fn an_out_of_range_string_id_is_an_error() {
        let strings = ["a", "b"];
        assert_eq!(string_at(&strings, 1).unwrap(), "b");
        assert_eq!(string_at(&strings, NO_STRING).unwrap(), "");
        assert!(matches!(
            string_at(&strings, 5),
            Err(GsigError::BadStringId(5, 2))
        ));
    }

    /// postcard has no schema evolution, so the record's own encoding must
    /// not drift silently. This pins the field order and the varint sizes.
    #[test]
    fn a_record_encodes_to_the_expected_bytes() {
        let record = WireRecord {
            name: 1,
            source: 0,
            pattern_len: 32,
            flags: FLAG_HAS_MASK | FLAG_HAS_CRC16,
            crc16: 0x1e1a,
            crc_len: 16,
            function_len: 0,
            n_refs: 2,
        };
        let bytes = postcard::to_stdvec(&record).unwrap();
        assert_eq!(
            bytes,
            vec![0x01, 0x00, 0x20, 0x03, 0x9a, 0x3c, 0x10, 0x00, 0x02]
        );
        let (back, rest) = postcard::take_from_bytes::<WireRecord>(&bytes).unwrap();
        assert_eq!(back, record);
        assert!(rest.is_empty());
    }
}
