//! Android / bionic packed relocation decoders.
//!
//! Real Android device `.so` files rarely carry a plain `.rela.dyn`. To shrink
//! the on-disk footprint of position-independent code, the AOSP build packs the
//! relative-relocation stream with `relocation_packer` into one of two compact
//! encodings that the bionic linker expands at load time:
//!
//! * **APS2** (`DT_ANDROID_REL` / `DT_ANDROID_RELA`) — a group-delta encoding of
//!   a full `Elf_Rel`/`Elf_Rela` table, prefixed with the ASCII magic `APS2`.
//!   Every field (offsets, `r_info`, addends) is stored as a stream of signed
//!   LEB128 values with per-group "grouped by …" flags that let the packer omit
//!   repeated fields entirely.
//! * **RELR** (`DT_RELR` / `DT_ANDROID_RELR`) — a bitmap encoding that stores
//!   *only* `R_*_RELATIVE` relocations (by far the common case for PIC). Even
//!   entries are addresses; odd entries are bitmaps describing the following
//!   `wordbits - 1` words.
//!
//! Without expanding these, a tool sees essentially *no* dynamic relocations on
//! a modern Android library, so GOT/xref resolution silently collapses. This
//! module decodes both into the crate's [`Relocation`] representation (RELR is
//! materialised as synthetic relative relocations with `r_info == 0`).
//!
//! References: bionic `linker/linker_reloc_iterators.h`
//! (`packed_reloc_iterator`) and `linker/linker_relocate.cpp` (`apply_relr`).

use crate::formats::elf::types::{ElfClass, ElfData, ElfError, Relocation, Result};
use crate::formats::elf::utils::EndianRead;

/// APS2 stream magic: the four ASCII bytes `APS2`.
pub const APS2_MAGIC: [u8; 4] = *b"APS2";

// Per-group flags used by the APS2 encoding.
const RELOCATION_GROUPED_BY_INFO_FLAG: i64 = 1;
const RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG: i64 = 2;
const RELOCATION_GROUPED_BY_ADDEND_FLAG: i64 = 4;
const RELOCATION_GROUP_HAS_ADDEND_FLAG: i64 = 8;

/// A minimal signed-LEB128 (SLEB128) cursor over a byte slice.
///
/// bionic decodes the *entire* APS2 payload — including nominally unsigned
/// fields such as `group_size` and `r_info` — with a single signed LEB128
/// decoder, so we match that behaviour exactly and reinterpret as needed.
struct Sleb128<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Sleb128<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Pop the next signed LEB128 value, advancing the cursor.
    fn pop(&mut self) -> Result<i64> {
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = *self.data.get(self.pos).ok_or(ElfError::Truncated {
                offset: self.pos,
                needed: 1,
            })?;
            self.pos += 1;
            // 7 payload bits per byte; guard against a malformed run that would
            // overflow the 64-bit accumulator.
            if shift >= 64 {
                return Err(ElfError::MalformedHeader(
                    "SLEB128 value exceeds 64 bits".to_string(),
                ));
            }
            result |= ((byte & 0x7f) as i64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                // Sign-extend if the value is negative and we have not filled
                // all 64 bits.
                if shift < 64 && (byte & 0x40) != 0 {
                    result |= -1i64 << shift;
                }
                return Ok(result);
            }
        }
    }
}

/// Decode an APS2 packed relocation stream into individual [`Relocation`]s.
///
/// `is_rela` selects whether addends are present (`DT_ANDROID_RELA` vs
/// `DT_ANDROID_REL`); it must match the tag the linker would have used.
pub fn decode_android_packed(data: &[u8], is_rela: bool) -> Result<Vec<Relocation>> {
    if data.len() < 4 || data[0..4] != APS2_MAGIC {
        return Err(ElfError::MalformedHeader(
            "missing APS2 magic in packed relocation stream".to_string(),
        ));
    }

    let mut dec = Sleb128::new(&data[4..]);

    let total = dec.pop()?;
    if total < 0 {
        return Err(ElfError::MalformedHeader(
            "negative APS2 relocation count".to_string(),
        ));
    }
    let total = total as usize;

    let mut relocs = Vec::with_capacity(total.min(1 << 20));

    // Running relocation state, updated in place as the linker does.
    let mut r_offset: i64 = dec.pop()?;
    let mut r_info: i64 = 0;
    let mut r_addend: i64 = 0;

    let mut emitted = 0usize;
    while emitted < total {
        if dec.is_empty() {
            return Err(ElfError::MalformedHeader(
                "APS2 stream truncated before all relocations decoded".to_string(),
            ));
        }
        let group_size = dec.pop()?;
        if group_size < 0 {
            return Err(ElfError::MalformedHeader(
                "negative APS2 group size".to_string(),
            ));
        }
        let group_size = group_size as usize;
        let group_flags = dec.pop()?;

        let grouped_by_info = group_flags & RELOCATION_GROUPED_BY_INFO_FLAG != 0;
        let grouped_by_offset_delta = group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG != 0;
        let grouped_by_addend = group_flags & RELOCATION_GROUPED_BY_ADDEND_FLAG != 0;
        let group_has_addend = group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG != 0;

        let mut group_offset_delta = 0i64;
        if grouped_by_offset_delta {
            group_offset_delta = dec.pop()?;
        }
        if grouped_by_info {
            r_info = dec.pop()?;
        }
        if group_has_addend && grouped_by_addend {
            if !is_rela {
                return Err(ElfError::MalformedHeader(
                    "APS2 addend flag set on a REL (no-addend) stream".to_string(),
                ));
            }
            r_addend = r_addend.wrapping_add(dec.pop()?);
        } else if !group_has_addend && is_rela {
            // A group without addends resets the running addend to zero.
            r_addend = 0;
        }

        for _ in 0..group_size {
            if emitted >= total {
                break;
            }
            if grouped_by_offset_delta {
                r_offset = r_offset.wrapping_add(group_offset_delta);
            } else {
                r_offset = r_offset.wrapping_add(dec.pop()?);
            }
            if !grouped_by_info {
                r_info = dec.pop()?;
            }
            if is_rela && group_has_addend && !grouped_by_addend {
                r_addend = r_addend.wrapping_add(dec.pop()?);
            }

            relocs.push(Relocation {
                r_offset: r_offset as u64,
                r_info: r_info as u64,
                r_addend: if is_rela { r_addend } else { 0 },
            });
            emitted += 1;
        }
    }

    Ok(relocs)
}

/// Decode a RELR relative-relocation table.
///
/// RELR stores *only* `R_*_RELATIVE` relocations, so each decoded entry is
/// returned as a synthetic [`Relocation`] with `r_info == 0` and `r_addend == 0`
/// — the caller supplies the appropriate `R_*_RELATIVE` semantics (add load
/// bias to the word already stored at `r_offset`).
pub fn decode_relr(data: &[u8], class: ElfClass, endian: ElfData) -> Result<Vec<Relocation>> {
    let word_size = match class {
        ElfClass::Elf32 => 4usize,
        ElfClass::Elf64 => 8usize,
    };
    // Number of address slots described by one bitmap entry.
    let bits_per_entry = (word_size * 8) as u64;

    let read_word = |off: usize| -> Result<u64> {
        match class {
            ElfClass::Elf32 => data.read_u32(off, endian).map(|v| v as u64),
            ElfClass::Elf64 => data.read_u64(off, endian),
        }
    };

    let mut relocs = Vec::new();
    let mut base: u64 = 0;
    let mut off = 0usize;
    while off + word_size <= data.len() {
        let entry = read_word(off)?;
        off += word_size;

        if entry & 1 == 0 {
            // Even entry: an absolute address where a relative reloc applies.
            relocs.push(relative_reloc(entry));
            base = entry.wrapping_add(word_size as u64);
        } else {
            // Odd entry: a bitmap covering the next (bits_per_entry - 1) words.
            let mut bits = entry >> 1;
            let mut addr = base;
            while bits != 0 {
                if bits & 1 != 0 {
                    relocs.push(relative_reloc(addr));
                }
                bits >>= 1;
                addr = addr.wrapping_add(word_size as u64);
            }
            base = base.wrapping_add((bits_per_entry - 1) * word_size as u64);
        }
    }

    Ok(relocs)
}

#[inline]
fn relative_reloc(offset: u64) -> Relocation {
    Relocation {
        r_offset: offset,
        r_info: 0,
        r_addend: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Append a signed-LEB128 encoding of `value` to `out`.
    fn push_sleb128(out: &mut Vec<u8>, mut value: i64) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7; // arithmetic shift keeps the sign
            let sign_bit = byte & 0x40 != 0;
            let more = !((value == 0 && !sign_bit) || (value == -1 && sign_bit));
            out.push(if more { byte | 0x80 } else { byte });
            if !more {
                break;
            }
        }
    }

    #[test]
    fn sleb128_roundtrip_positive_and_negative() {
        for v in [0i64, 1, 63, 64, 127, 128, -1, -63, -64, -8192, 0x1234_5678, -0x1234_5678] {
            let mut buf = Vec::new();
            push_sleb128(&mut buf, v);
            let mut dec = Sleb128::new(&buf);
            assert_eq!(dec.pop().unwrap(), v, "roundtrip failed for {v}");
            assert!(dec.is_empty());
        }
    }

    #[test]
    fn aps2_rejects_bad_magic() {
        let err = decode_android_packed(b"APS1\x00", false);
        assert!(err.is_err());
    }

    #[test]
    fn aps2_ungrouped_rel_stream() {
        // Two R_AARCH64_RELATIVE relocs, ungrouped, no addend.
        // Stream layout after magic: count, base_offset, [group_size, flags,
        // then per-reloc offset_delta + r_info].
        let mut s = Vec::new();
        s.extend_from_slice(&APS2_MAGIC);
        push_sleb128(&mut s, 2); // count
        push_sleb128(&mut s, 0x1000); // base offset
        push_sleb128(&mut s, 2); // group_size
        push_sleb128(&mut s, 0); // flags = 0 (fully ungrouped)
        // reloc 1
        push_sleb128(&mut s, 0x8); // offset delta -> 0x1008
        push_sleb128(&mut s, 1027); // r_info = R_AARCH64_RELATIVE (0x403)
        // reloc 2
        push_sleb128(&mut s, 0x8); // offset delta -> 0x1010
        push_sleb128(&mut s, 1027);

        let relocs = decode_android_packed(&s, false).unwrap();
        assert_eq!(relocs.len(), 2);
        assert_eq!(relocs[0].r_offset, 0x1008);
        assert_eq!(relocs[0].r_info, 1027);
        assert_eq!(relocs[0].reloc_type(), 1027);
        assert_eq!(relocs[1].r_offset, 0x1010);
        assert_eq!(relocs[0].r_addend, 0);
    }

    #[test]
    fn aps2_grouped_by_info_and_offset_delta_with_addend() {
        // Three relocs sharing r_info and a constant offset delta, each with an
        // individual addend delta. This exercises the common packer output.
        let mut s = Vec::new();
        s.extend_from_slice(&APS2_MAGIC);
        push_sleb128(&mut s, 3); // count
        push_sleb128(&mut s, 0x2000); // base offset
        push_sleb128(&mut s, 3); // group_size
        let flags = RELOCATION_GROUPED_BY_INFO_FLAG
            | RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG
            | RELOCATION_GROUP_HAS_ADDEND_FLAG;
        push_sleb128(&mut s, flags);
        push_sleb128(&mut s, 8); // group offset delta
        push_sleb128(&mut s, 1027); // shared r_info
        // per-reloc addend deltas (addend accumulates)
        push_sleb128(&mut s, 0x10);
        push_sleb128(&mut s, 0x20);
        push_sleb128(&mut s, -0x8);

        let relocs = decode_android_packed(&s, true).unwrap();
        assert_eq!(relocs.len(), 3);
        assert_eq!(relocs[0].r_offset, 0x2008);
        assert_eq!(relocs[1].r_offset, 0x2010);
        assert_eq!(relocs[2].r_offset, 0x2018);
        assert!(relocs.iter().all(|r| r.r_info == 1027));
        assert_eq!(relocs[0].r_addend, 0x10);
        assert_eq!(relocs[1].r_addend, 0x30);
        assert_eq!(relocs[2].r_addend, 0x28);
    }

    #[test]
    fn relr_bitmap_decoding_64bit() {
        // Entry 1: address 0x1000 (even -> absolute).
        // Entry 2: bitmap 0b101 << 1 | 1 => relocs at base=0x1008 and base+2*8.
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u64.to_le_bytes());
        let bitmap: u64 = (0b101u64 << 1) | 1;
        data.extend_from_slice(&bitmap.to_le_bytes());

        let relocs = decode_relr(&data, ElfClass::Elf64, ElfData::Little).unwrap();
        // base after first entry = 0x1008.
        // bitmap bit0 -> 0x1008, bit2 -> 0x1008 + 2*8 = 0x1018.
        let offsets: Vec<u64> = relocs.iter().map(|r| r.r_offset).collect();
        assert_eq!(offsets, vec![0x1000, 0x1008, 0x1018]);
        assert!(relocs.iter().all(|r| r.r_info == 0));
    }
}
