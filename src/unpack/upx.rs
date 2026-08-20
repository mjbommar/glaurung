//! Static unpacking of UPX-packed ELF images.
//!
//! A UPX-packed binary is not a program we can analyse: it is a decompressor
//! stub plus a compressed blob. Running function discovery over it finds the
//! stub, six or eight functions of loader code, and reports them as though they
//! were the program. That is worse than finding nothing, because the answer
//! looks like an answer.
//!
//! UPX's container is self-describing, which makes the honest fix available
//! statically. Three structures carry it:
//!
//! `l_info` / `p_info`
//!     Immediately after the packed file's own ELF header. `l_info` holds the
//!     `UPX!` magic, the stub size and the format code; `p_info` holds the
//!     **original file size** — recoverable even when nothing else is.
//! `b_info`
//!     One per compressed block: uncompressed size, compressed size, method,
//!     and filter id. Blocks whose compressed size equals their uncompressed
//!     size are stored verbatim.
//! the trailing `UPX!` pack header
//!     The last 32 bytes-ish of the file: version, format, method, level, the
//!     compressed and uncompressed lengths, and — the useful part — `u_adler`,
//!     an Adler-32 over the original bytes in *packing* order.
//!
//! # Why the layout needs the decompressed header
//!
//! The blocks are not laid out in output order and their target offsets are not
//! stored anywhere. Block 0 is the original ELF header and program headers;
//! decompressing it first yields the `PT_LOAD` table, and each following block
//! fills the next `PT_LOAD`'s file extent. The file regions no `PT_LOAD` claims
//! — alignment padding, and the section header table at the end — are packed in
//! a second chain that sits *after* the loader stub, and are recovered by
//! matching their sizes against the holes the `PT_LOAD` extents leave behind.
//!
//! # Why this cannot quietly produce the wrong image
//!
//! Reconstruction is checked against `u_adler` before anything is returned. A
//! decoder bug, a misread layout, or a filtered block we failed to notice all
//! change those bytes, so the outcome is a refusal rather than a plausible
//! binary that is not the one that was packed. `unpack` returning `Ok` means the
//! bytes hash to what the packer recorded.
//!
//! # What is not implemented
//!
//! LZMA-compressed blocks (`method 14`) and any non-zero *filter* are refused by
//! name. A filter rewrites branch displacements before compression; ignoring one
//! would yield an image that decompresses cleanly and disassembles into
//! nonsense, which is the exact failure this module exists to prevent.

use crate::unpack::nrv::{self, NrvError, M_STORED};

/// The `UPX!` marker, in both `l_info` and the trailing pack header.
const UPX_MAGIC: &[u8; 4] = b"UPX!";
/// Bytes in an `l_info` header.
const L_INFO_LEN: usize = 12;
/// Bytes in a `p_info` header.
const P_INFO_LEN: usize = 12;
/// Bytes in a `b_info` block header.
const B_INFO_LEN: usize = 12;
/// Bytes in the trailing pack header we read fields from.
const PACK_HEADER_LEN: usize = 32;
/// Refuse to allocate an "original file" larger than this. UPX itself will not
/// produce one and a corrupt `p_filesize` is otherwise an allocation of
/// whatever a 32-bit field says.
const MAX_ORIGINAL_SIZE: u32 = 512 * 1024 * 1024;
/// Highest method code UPX assigns. Beyond this the trailing bytes are not a
/// pack header, whatever else they may be.
const MAX_KNOWN_METHOD: u8 = 15;

/// Why an image could not be unpacked.
///
/// The variants are deliberately specific. "Could not unpack" is not an
/// actionable statement about a binary; "block 3 is LZMA-compressed and this
/// build decodes only NRV2B/2D/2E" is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpxError {
    /// No `UPX!` marker in a position consistent with a UPX container.
    NotUpx,
    /// The pack header says a filter was applied. Branch displacements were
    /// rewritten before compression and we do not reverse that.
    UnsupportedFilter(u8),
    /// A block uses a compression method this build does not implement.
    UnsupportedMethod(u8),
    /// A block failed to decode.
    Block { offset: usize, source: NrvError },
    /// A field or block extends past the end of the file.
    Truncated { what: &'static str, offset: usize },
    /// Block 0 did not decompress into something that starts with an ELF magic,
    /// so this is not the ELF container we know how to walk.
    NotElf,
    /// The recovered layout does not tile the original file exactly.
    Layout(String),
    /// Reconstruction completed but does not match the checksum UPX recorded.
    ChecksumMismatch { computed: u32, recorded: u32 },
}

impl std::fmt::Display for UpxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotUpx => write!(f, "not a UPX-packed image"),
            Self::UnsupportedFilter(id) => write!(
                f,
                "UPX filter 0x{id:02x} rewrote branch displacements before packing; \
                 unfiltering is not implemented, so the image is not unpacked"
            ),
            Self::UnsupportedMethod(m) => write!(
                f,
                "UPX compression method {m} is not implemented (this build decodes \
                 NRV2B, NRV2D, NRV2E and stored blocks)"
            ),
            Self::Block { offset, source } => {
                write!(f, "compressed block at file offset {offset}: {source}")
            }
            Self::Truncated { what, offset } => {
                write!(
                    f,
                    "{what} at file offset {offset} runs past the end of the file"
                )
            }
            Self::NotElf => write!(f, "the first packed block is not an ELF header"),
            Self::Layout(why) => write!(f, "packed block layout is inconsistent: {why}"),
            Self::ChecksumMismatch { computed, recorded } => write!(
                f,
                "reconstruction checksums 0x{computed:08x}, UPX recorded 0x{recorded:08x}; \
                 refusing to return an image that is not the one that was packed"
            ),
        }
    }
}

impl std::error::Error for UpxError {}

/// The trailing `UPX!` pack header, plus the `l_info`/`p_info` pair.
///
/// Everything here is readable without decompressing anything, which is what
/// makes it useful on an image we cannot unpack: the original size, the
/// compression method and the filter id are still real facts about the binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpxHeader {
    /// UPX version byte that produced the file.
    pub version: u8,
    /// UPX format code (22 is `linux/amd64` ELF64).
    pub format: u8,
    /// Compression method recorded for the image as a whole.
    pub method: u8,
    /// Compression level (`-1` .. `-9`).
    pub level: u8,
    /// Filter id; non-zero means branch displacements were rewritten.
    pub filter: u8,
    /// The filter's compression-tag byte.
    pub filter_cto: u8,
    /// Adler-32 of the original bytes, in the order UPX compressed them.
    pub u_adler: u32,
    /// Total uncompressed length.
    pub u_len: u32,
    /// Total compressed length.
    pub c_len: u32,
    /// Size of the original file, from `p_info`.
    pub original_size: u32,
    /// Largest uncompressed block, from `p_info`.
    pub block_size: u32,
    /// Size of the decompressor stub, from `l_info`.
    pub stub_size: u16,
    /// File offset of the `l_info` structure.
    pub l_info_offset: usize,
    /// File offset of the trailing pack header.
    pub pack_header_offset: usize,
}

/// One compressed block, as found in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpxBlock {
    /// File offset of this block's `b_info`.
    pub header_offset: usize,
    /// Uncompressed size.
    pub sz_unc: u32,
    /// Compressed size; equal to `sz_unc` when the block is stored verbatim.
    pub sz_cpr: u32,
    /// Compression method for this block.
    pub method: u8,
    /// Filter id for this block.
    pub filter: u8,
    /// Where the decompressed bytes belong in the original file.
    pub target_offset: u64,
}

/// A successfully reconstructed original image.
#[derive(Debug, Clone)]
pub struct Unpacked {
    /// What the container said about itself.
    pub header: UpxHeader,
    /// The blocks, in the order they were decoded.
    pub blocks: Vec<UpxBlock>,
    /// Entry point of the *original* program, not of the stub.
    pub original_entry: u64,
    /// The original file, byte for byte.
    pub bytes: Vec<u8>,
}

fn le32(data: &[u8], at: usize, what: &'static str) -> Result<u32, UpxError> {
    let b = data
        .get(at..at + 4)
        .ok_or(UpxError::Truncated { what, offset: at })?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn le16(data: &[u8], at: usize, what: &'static str) -> Result<u16, UpxError> {
    let b = data
        .get(at..at + 2)
        .ok_or(UpxError::Truncated { what, offset: at })?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn le64(data: &[u8], at: usize, what: &'static str) -> Result<u64, UpxError> {
    let b = data
        .get(at..at + 8)
        .ok_or(UpxError::Truncated { what, offset: at })?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn byte(data: &[u8], at: usize, what: &'static str) -> Result<u8, UpxError> {
    data.get(at)
        .copied()
        .ok_or(UpxError::Truncated { what, offset: at })
}

/// Adler-32's defined starting value.
const ADLER32_SEED: u32 = 1;

/// Adler-32, as UPX computes it over the blocks it is about to write.
fn adler32(seed: u32, data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a = seed & 0xffff;
    let mut b = (seed >> 16) & 0xffff;
    for &byte in data {
        a = (a + u32::from(byte)) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

/// Read what the container says about itself, without decompressing anything.
///
/// This is the answer that survives when unpacking cannot proceed: an LZMA
/// image or a filtered one still tells us its original size, its method and its
/// block layout, and reporting those is strictly better than reporting the
/// stub's functions.
pub fn parse_header(data: &[u8]) -> Result<UpxHeader, UpxError> {
    let pack_at = rfind(data, UPX_MAGIC).ok_or(UpxError::NotUpx)?;
    if pack_at + PACK_HEADER_LEN > data.len() {
        return Err(UpxError::Truncated {
            what: "UPX pack header",
            offset: pack_at,
        });
    }
    // `UPX!` is four bytes and appears in ordinary binaries that merely mention
    // UPX — a packer database, this crate's own test corpus, an analysis tool.
    // Calling one of those "packed" would be its own lie, so the trailing header
    // has to look like a pack header and not merely start with the marker.
    let method = byte(data, pack_at + 6, "pack header method")?;
    let level = byte(data, pack_at + 7, "pack header level")?;
    let version = byte(data, pack_at + 4, "pack header version")?;
    if method > MAX_KNOWN_METHOD || !(1..=13).contains(&level) || version == 0 {
        return Err(UpxError::NotUpx);
    }
    let l_info_offset = find_l_info(data).ok_or(UpxError::NotUpx)?;
    let stub_size = le16(data, l_info_offset + 8, "l_info.l_lsize")?;
    let p_at = l_info_offset + L_INFO_LEN;
    let original_size = le32(data, p_at + 4, "p_info.p_filesize")?;
    let block_size = le32(data, p_at + 8, "p_info.p_blocksize")?;

    Ok(UpxHeader {
        version: byte(data, pack_at + 4, "pack header version")?,
        format: byte(data, pack_at + 5, "pack header format")?,
        method: byte(data, pack_at + 6, "pack header method")?,
        level: byte(data, pack_at + 7, "pack header level")?,
        filter: byte(data, pack_at + 28, "pack header filter")?,
        filter_cto: byte(data, pack_at + 29, "pack header filter cto")?,
        u_adler: le32(data, pack_at + 8, "pack header u_adler")?,
        u_len: le32(data, pack_at + 16, "pack header u_len")?,
        c_len: le32(data, pack_at + 20, "pack header c_len")?,
        original_size,
        block_size,
        stub_size,
        l_info_offset,
        pack_header_offset: pack_at,
    })
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::rfind(hay, needle)
}

/// Locate the `l_info` that introduces the block chain.
///
/// The `UPX!` marker appears several times in a packed file — in `l_info`, in
/// the stub's own data, and in the trailing pack header — so position alone is
/// not enough. The one we want is followed by a `p_info` whose original size is
/// plausible and by a `b_info` that could describe a real block.
fn find_l_info(data: &[u8]) -> Option<usize> {
    let mut from = 0usize;
    while let Some(rel) = memchr::memmem::find(&data[from..], UPX_MAGIC) {
        let magic_at = from + rel;
        from = magic_at + 1;
        if magic_at < 4 {
            continue;
        }
        let l_info = magic_at - 4;
        let p_at = l_info + L_INFO_LEN;
        let Ok(filesize) = le32(data, p_at + 4, "p_info.p_filesize") else {
            continue;
        };
        let Ok(blocksize) = le32(data, p_at + 8, "p_info.p_blocksize") else {
            continue;
        };
        if !(64..=MAX_ORIGINAL_SIZE).contains(&filesize) || blocksize == 0 || blocksize > filesize {
            continue;
        }
        // The first b_info must describe a block that fits in the file.
        let b_at = p_at + P_INFO_LEN;
        let (Ok(sz_unc), Ok(sz_cpr)) = (
            le32(data, b_at, "b_info.sz_unc"),
            le32(data, b_at + 4, "b_info.sz_cpr"),
        ) else {
            continue;
        };
        if sz_unc == 0 || sz_unc > filesize || sz_cpr == 0 {
            continue;
        }
        if b_at + B_INFO_LEN + sz_cpr as usize > data.len() {
            continue;
        }
        return Some(l_info);
    }
    None
}

/// A block header and its decoded bytes.
struct DecodedBlock {
    info: UpxBlock,
    bytes: Vec<u8>,
    next: usize,
}

/// Decode the block whose `b_info` sits at `at`.
fn read_block(data: &[u8], at: usize) -> Result<DecodedBlock, UpxError> {
    let sz_unc = le32(data, at, "b_info.sz_unc")?;
    let sz_cpr = le32(data, at + 4, "b_info.sz_cpr")?;
    let method = byte(data, at + 8, "b_info.b_method")?;
    let filter = byte(data, at + 9, "b_info.b_ftid")?;
    if filter != 0 {
        return Err(UpxError::UnsupportedFilter(filter));
    }
    let payload_at = at + B_INFO_LEN;
    let want = sz_unc as usize;

    let (bytes, consumed) = if sz_cpr >= sz_unc {
        // Stored verbatim: UPX writes the block uncompressed when compressing it
        // would not have paid.
        if sz_cpr != sz_unc {
            return Err(UpxError::Layout(format!(
                "block at {at} has compressed size {sz_cpr} above uncompressed size {sz_unc}"
            )));
        }
        let raw = data
            .get(payload_at..payload_at + want)
            .ok_or(UpxError::Truncated {
                what: "stored block",
                offset: payload_at,
            })?;
        (raw.to_vec(), want)
    } else {
        if method == M_STORED {
            return Err(UpxError::UnsupportedMethod(method));
        }
        let end = std::cmp::min(data.len(), payload_at + sz_cpr as usize + 8);
        let src = data.get(payload_at..end).ok_or(UpxError::Truncated {
            what: "compressed block",
            offset: payload_at,
        })?;
        let out = nrv::decompress(src, want, method).map_err(|e| match e {
            NrvError::UnsupportedMethod(m) => UpxError::UnsupportedMethod(m),
            source => UpxError::Block { offset: at, source },
        })?;
        (out, sz_cpr as usize)
    };

    Ok(DecodedBlock {
        info: UpxBlock {
            header_offset: at,
            sz_unc,
            sz_cpr,
            method,
            filter,
            target_offset: 0,
        },
        bytes,
        next: payload_at + consumed,
    })
}

/// `PT_LOAD` file extents, read out of the decompressed original ELF headers.
fn load_extents(hdr: &[u8]) -> Result<(Vec<(u64, u64)>, u64), UpxError> {
    if hdr.len() < 64 || &hdr[..4] != b"\x7fELF" {
        return Err(UpxError::NotElf);
    }
    let class = hdr[4];
    let (entry, phoff, phentsize, phnum) = match class {
        2 => (
            le64(hdr, 24, "e_entry")?,
            le64(hdr, 32, "e_phoff")? as usize,
            le16(hdr, 54, "e_phentsize")? as usize,
            le16(hdr, 56, "e_phnum")? as usize,
        ),
        1 => (
            u64::from(le32(hdr, 24, "e_entry")?),
            le32(hdr, 28, "e_phoff")? as usize,
            le16(hdr, 42, "e_phentsize")? as usize,
            le16(hdr, 44, "e_phnum")? as usize,
        ),
        other => {
            return Err(UpxError::Layout(format!(
                "ELF class byte {other} is neither 32- nor 64-bit"
            )))
        }
    };
    let mut loads = Vec::new();
    for k in 0..phnum {
        let at = phoff + k * phentsize;
        let p_type = le32(hdr, at, "p_type")?;
        if p_type != 1 {
            continue; // PT_LOAD only
        }
        let (offset, filesz) = if class == 2 {
            (
                le64(hdr, at + 8, "p_offset")?,
                le64(hdr, at + 32, "p_filesz")?,
            )
        } else {
            (
                u64::from(le32(hdr, at + 4, "p_offset")?),
                u64::from(le32(hdr, at + 16, "p_filesz")?),
            )
        };
        if filesz > 0 {
            loads.push((offset, filesz));
        }
    }
    loads.sort_unstable();
    Ok((loads, entry))
}

/// Reconstruct the original image from a UPX-packed one.
///
/// Returns the original bytes only when they hash to the checksum UPX recorded;
/// every other outcome names what stopped it.
pub fn unpack(data: &[u8]) -> Result<Unpacked, UpxError> {
    let header = parse_header(data)?;
    if header.filter != 0 {
        return Err(UpxError::UnsupportedFilter(header.filter));
    }
    let total = header.original_size as usize;
    if total == 0 || header.original_size > MAX_ORIGINAL_SIZE {
        return Err(UpxError::Layout(format!(
            "p_info declares an original size of {total} bytes"
        )));
    }

    let mut out = vec![0u8; total];
    let mut blocks: Vec<UpxBlock> = Vec::new();
    // Adler-32 is accumulated in decode order, which is the order UPX itself
    // compressed the pieces in — not the order they appear in the output.
    let mut adler = ADLER32_SEED;
    let mut covered: Vec<(u64, u64)> = Vec::new();

    let place = |out: &mut Vec<u8>,
                 adler: &mut u32,
                 covered: &mut Vec<(u64, u64)>,
                 blocks: &mut Vec<UpxBlock>,
                 mut block: DecodedBlock,
                 at: u64|
     -> Result<(), UpxError> {
        let lo = at as usize;
        let hi = lo + block.bytes.len();
        if hi > out.len() {
            return Err(UpxError::Layout(format!(
                "block at file offset {} would write {lo}..{hi} of a {} byte image",
                block.info.header_offset,
                out.len()
            )));
        }
        out[lo..hi].copy_from_slice(&block.bytes);
        *adler = adler32(*adler, &block.bytes);
        covered.push((at, hi as u64));
        block.info.target_offset = at;
        blocks.push(block.info);
        Ok(())
    };

    // Block 0 is the original ELF header and program header table.
    let mut pos = header.l_info_offset + L_INFO_LEN + P_INFO_LEN;
    let first = read_block(data, pos)?;
    pos = first.next;
    let (loads, original_entry) = load_extents(&first.bytes)?;
    let header_len = first.bytes.len() as u64;
    place(&mut out, &mut adler, &mut covered, &mut blocks, first, 0)?;

    // One extent per PT_LOAD, in file order, minus whatever block 0 already
    // covered. UPX splits an extent larger than `p_blocksize` into several
    // blocks, so each extent is filled until it is full rather than assumed to
    // be one block.
    let mut reach = header_len;
    for (offset, filesz) in loads {
        let end = offset + filesz;
        if end <= reach {
            continue;
        }
        let mut at = std::cmp::max(offset, reach);
        if offset < reach && offset + filesz > reach {
            // Overlaps what is already placed: only the tail is still wanted.
            at = reach;
        }
        while at < end {
            let block = read_block(data, pos)?;
            pos = block.next;
            let len = block.bytes.len() as u64;
            if len == 0 || at + len > end {
                return Err(UpxError::Layout(format!(
                    "block at {} holds {len} bytes but only {} remain in the PT_LOAD \
                     extent ending at {end}",
                    block.info.header_offset,
                    end - at
                )));
            }
            place(&mut out, &mut adler, &mut covered, &mut blocks, block, at)?;
            at += len;
        }
        reach = end;
    }

    // Whatever no PT_LOAD claimed — alignment padding, and the section header
    // table at the end — is packed in a second chain that lives past the stub.
    let holes = holes_between(&covered, total as u64)?;
    if !holes.is_empty() {
        let start = find_hole_chain(data, pos, &holes)?;
        let mut at = start;
        for &(lo, hi) in &holes {
            let block = read_block(data, at)?;
            at = block.next;
            if block.bytes.len() as u64 != hi - lo {
                return Err(UpxError::Layout(format!(
                    "hole {lo}..{hi} wants {} bytes, block at {} holds {}",
                    hi - lo,
                    block.info.header_offset,
                    block.bytes.len()
                )));
            }
            place(&mut out, &mut adler, &mut covered, &mut blocks, block, lo)?;
        }
    }

    if adler != header.u_adler {
        return Err(UpxError::ChecksumMismatch {
            computed: adler,
            recorded: header.u_adler,
        });
    }

    Ok(Unpacked {
        header,
        blocks,
        original_entry,
        bytes: out,
    })
}

/// File ranges of the original that no placed block covers, in file order.
fn holes_between(covered: &[(u64, u64)], total: u64) -> Result<Vec<(u64, u64)>, UpxError> {
    let mut sorted = covered.to_vec();
    sorted.sort_unstable();
    let mut holes = Vec::new();
    let mut cursor = 0u64;
    for &(lo, hi) in &sorted {
        if lo < cursor {
            return Err(UpxError::Layout(format!(
                "placed blocks overlap at {lo} (already filled to {cursor})"
            )));
        }
        if lo > cursor {
            holes.push((cursor, lo));
        }
        cursor = hi;
    }
    if cursor > total {
        return Err(UpxError::Layout(format!(
            "placed blocks reach {cursor}, past the {total} byte original"
        )));
    }
    if cursor < total {
        holes.push((cursor, total));
    }
    Ok(holes)
}

/// Find where the second block chain starts.
///
/// Nothing records it: it sits past a stub whose length is only loosely related
/// to `l_lsize`. What does pin it down is the chain itself — the holes are known
/// exactly by this point, so the right offset is the first one from which *every
/// remaining hole* decodes to exactly its own size. A single size coincidence
/// cannot pass that; the whole chain has to line up.
fn find_hole_chain(data: &[u8], from: usize, holes: &[(u64, u64)]) -> Result<usize, UpxError> {
    let first = holes[0].1 - holes[0].0;
    let limit = data.len().saturating_sub(B_INFO_LEN);
    for cand in from..limit {
        let Ok(sz_unc) = le32(data, cand, "b_info.sz_unc") else {
            break;
        };
        if u64::from(sz_unc) != first {
            continue;
        }
        if chain_fits(data, cand, holes) {
            return Ok(cand);
        }
    }
    Err(UpxError::Layout(format!(
        "no block chain past offset {from} accounts for the {} unclaimed region(s), \
         the first of which is {first} bytes",
        holes.len()
    )))
}

/// Whether a candidate offset decodes into exactly the given holes, in order.
fn chain_fits(data: &[u8], mut at: usize, holes: &[(u64, u64)]) -> bool {
    for &(lo, hi) in holes {
        match read_block(data, at) {
            Ok(block) if block.bytes.len() as u64 == hi - lo => at = block.next,
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_file(rel: &str) -> Option<Vec<u8>> {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
        std::fs::read(p).ok()
    }

    #[test]
    fn a_binary_with_no_upx_marker_is_not_claimed() {
        let plain = b"\x7fELF\x02\x01\x01\x00 and nothing else at all, no marker here";
        assert_eq!(parse_header(plain).unwrap_err(), UpxError::NotUpx);
        assert_eq!(unpack(plain).unwrap_err(), UpxError::NotUpx);
    }

    #[test]
    fn header_fields_are_readable_on_every_packed_sample() {
        // The point of `parse_header` is that it works on images we cannot
        // unpack. Every sample here is real UPX output; several use LZMA or a
        // filter, and their headers must still parse.
        let names = [
            "samples/packed/hello-gfortran-O2.upx9",
            "samples/packed/hello-go.upx9",
            "samples/packed/hello-rust-release.upx9",
        ];
        let mut seen = 0;
        for name in names {
            let Some(data) = repo_file(name) else {
                continue;
            };
            let h = parse_header(&data).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(
                h.original_size > 0,
                "{name}: original size not recovered from p_info"
            );
            assert!(
                h.original_size as usize > data.len() / 2,
                "{name}: original size {} implausible against packed size {}",
                h.original_size,
                data.len()
            );
            seen += 1;
        }
        assert!(seen > 0, "no packed samples present to read headers from");
    }

    #[test]
    fn a_filtered_image_is_refused_by_name_not_silently_mangled() {
        // The Go and Rust samples were packed with filter 0x49, which rewrote
        // branch displacements. Decompressing them without unfiltering would
        // produce an image that disassembles into nonsense.
        let Some(data) = repo_file("samples/packed/hello-go.upx9") else {
            return;
        };
        let header = parse_header(&data).expect("header parses");
        assert_ne!(header.filter, 0, "sample is expected to be filtered");
        match unpack(&data) {
            Err(UpxError::UnsupportedFilter(id)) => assert_eq!(id, header.filter),
            other => panic!("expected a named filter refusal, got {other:?}"),
        }
    }

    #[test]
    fn nrv2b_packed_corpus_round_trips_to_the_original_bytes() {
        // Built by `tools/realistic_corpus.py`; skipped when the corpus has not
        // been built in this checkout.
        let Some(packed) = repo_file("tests/realistic_corpus/build/corpus.upx") else {
            return;
        };
        let Some(original) = repo_file("tests/realistic_corpus/build/corpus.strip") else {
            return;
        };
        let got = unpack(&packed).expect("corpus.upx unpacks");
        assert_eq!(
            got.bytes, original,
            "unpacked image differs from the file that was packed"
        );
        assert_eq!(got.original_entry, 0x1120, "original entry point");
        assert!(
            got.blocks.len() > 4,
            "expected a multi-block layout, got {}",
            got.blocks.len()
        );
    }

    #[test]
    fn packing_the_unstripped_build_round_trips_too() {
        let Some(packed) = repo_file("tests/realistic_corpus/build/corpus.upxg") else {
            return;
        };
        let Some(original) = repo_file("tests/realistic_corpus/build/corpus.dwarf") else {
            return;
        };
        let got = unpack(&packed).expect("corpus.upxg unpacks");
        assert_eq!(got.bytes, original);
    }

    #[test]
    fn no_unpacked_binary_in_the_corpus_is_mistaken_for_a_packed_one() {
        // Claiming a clean binary is packed is the same class of error as
        // reporting a stub's functions as the program's, and it is easy to make:
        // `UPX!` is four bytes, and plenty of binaries mention UPX without being
        // packed with it — a packer database, an analysis tool, this crate's own
        // test binaries. So the detector is measured against every real binary
        // in the tree rather than against the packed ones alone.
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut scanned = 0usize;
        let mut wrong: Vec<String> = Vec::new();
        let mut right = 0usize;
        for dir in ["samples", "tests"] {
            for entry in walk(&root.join(dir)) {
                let Ok(meta) = std::fs::metadata(&entry) else {
                    continue;
                };
                if !meta.is_file() || meta.len() < 64 || meta.len() > 40_000_000 {
                    continue;
                }
                let Ok(data) = std::fs::read(&entry) else {
                    continue;
                };
                if !data.starts_with(b"\x7fELF") && !data.starts_with(b"MZ") {
                    continue;
                }
                scanned += 1;
                if parse_header(&data).is_err() {
                    continue;
                }
                let name = entry.to_string_lossy().to_ascii_lowercase();
                if name.contains(".upx") {
                    right += 1;
                } else {
                    wrong.push(entry.to_string_lossy().into_owned());
                }
            }
        }
        assert!(
            scanned > 100,
            "only {scanned} binaries scanned; corpus missing?"
        );
        assert!(right > 0, "no packed sample was recognised at all");
        assert!(
            wrong.is_empty(),
            "{} binaries with no `.upx` in their name were reported as packed: {:?}",
            wrong.len(),
            &wrong[..std::cmp::min(5, wrong.len())]
        );
    }

    /// Every file under `dir`, recursively, without pulling in a walker crate.
    fn walk(dir: &std::path::Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(next) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&next) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.push(path);
                }
            }
        }
        out
    }

    #[test]
    fn a_corrupted_block_is_refused_rather_than_returned() {
        let Some(mut packed) = repo_file("tests/realistic_corpus/build/corpus.upx") else {
            return;
        };
        let header = parse_header(&packed).expect("header parses");
        // Flip a byte inside the first compressed block's payload.
        let payload = header.l_info_offset + L_INFO_LEN + P_INFO_LEN + B_INFO_LEN;
        packed[payload + 5] ^= 0xff;
        match unpack(&packed) {
            Ok(_) => panic!("a corrupted image must not unpack successfully"),
            Err(UpxError::ChecksumMismatch { .. })
            | Err(UpxError::Block { .. })
            | Err(UpxError::Layout(_))
            | Err(UpxError::NotElf) => {}
            Err(other) => panic!("unexpected error kind: {other}"),
        }
    }
}
