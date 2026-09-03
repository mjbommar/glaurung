//! `gsig/1` — the binary container a signature corpus ships in.
//!
//! # Why a second format at all
//!
//! The JSON library `python -m glaurung.tools.build_flirt_library` writes is a
//! fine *interchange* format and an impossible *distribution* format. Measured
//! over the 419 archives harvested onto this box (147,733 signatures):
//! **1,360 bytes per signature**, 201 MB of text, re-parsed from scratch on
//! every load. One library per `(distro, release, arch, package version)` is
//! the unit of usefulness — glibc 2.43 names 731 of 1,090 functions in a
//! stripped static binary, glibc 2.41 names *one* — so the corpus this project
//! is aiming at is 10^5 to 10^6 signatures, which is 1.2 GB of JSON.
//!
//! `gsig/1` is that same content in a chunked binary container. The numbers it
//! reaches, and the commands that produced them, are in the "The gsig/1
//! container" section of `docs/reference/function-signature-libraries.md`.
//!
//! # Layout
//!
//! ```text
//! 0                            HEADER_LEN                     ...
//! +--------------------------+-------------------------+------------------+
//! | GsigHeader (64 B, plain) | ChunkEntry * chunk_count | chunk payloads   |
//! +--------------------------+-------------------------+------------------+
//! ```
//!
//! The header and the chunk table are **never compressed**, so a reader can
//! answer "what is in this file, and how big does it inflate to" by reading
//! `HEADER_LEN + 24 * chunk_count` bytes — which is what
//! `glaurung.analysis.flirt_library_info_path` does, and what lets a chunk of
//! an unknown [`ChunkKind`] be skipped by its recorded size rather than
//! guessed at.
//!
//! Each *section* ([`ChunkKind`]) is split into [`CHUNK_SIZE`]-byte pieces,
//! and each piece is an independently compressed, standalone Zstandard frame.
//! Concatenating the payloads of every chunk of one kind, in file order,
//! reconstructs that section. That is the Zstandard *seekable* idea, and each
//! individual chunk really is a plain `.zst` frame that `zstd -d` will decode.
//! The whole file is **not** a bare `.zst`, because the format's own magic
//! (`b"GSIG"`) has to sit at byte 0 for [`FlirtLibrary::from_path`] to
//! dispatch on it; that is the one place we depart from the seekable format's
//! letter.
//!
//! [`FlirtLibrary::from_path`]: crate::flirt::FlirtLibrary::from_path
//!
//! # The record model
//!
//! Sections are columnar, which is what makes the compression work: every
//! pattern byte lives next to every other pattern byte rather than next to a
//! name.
//!
//! | Kind | Section | Encoding |
//! |---|---|---|
//! | 0 | [`ChunkKind::Meta`] | one `postcard` struct: schema version, arch string, prologue length, library key, builder stats, how the prefix index is stored |
//! | 1 | [`ChunkKind::Strings`] | `postcard` `Vec<&str>`, **sorted and deduplicated**; every other section refers to a string by its index here |
//! | 2 | [`ChunkKind::Signatures`] | `n_signatures` `postcard` records, concatenated |
//! | 3 | [`ChunkKind::Patterns`] | raw pattern bytes, concatenated in record order |
//! | 4 | [`ChunkKind::Masks`] | mask **bitmaps**, 1 bit per pattern byte, concatenated in record order |
//! | 5 | [`ChunkKind::Refs`] | `(u32 offset, u32 string id)` little-endian pairs, in record order |
//! | 6 | [`ChunkKind::Guids`] | `(u128 guid, u32 string id)` little-endian pairs, **sorted by guid** |
//! | 7 | [`ChunkKind::Index`] | the JSON `index` map, only when it is not derivable |
//!
//! No section stores an offset table. A record's pattern is the next
//! `pattern_len` bytes of [`ChunkKind::Patterns`], its mask the next
//! `ceil(pattern_len / 8)` bytes of [`ChunkKind::Masks`] if it has one, its
//! references the next `n_refs` entries of [`ChunkKind::Refs`]; the reader
//! accumulates as it goes. Masks as bitmaps rather than a byte per byte is
//! worth 8x on that section alone — 497 KB against 62 KB over the 15,534
//! signatures the format survey measured.
//!
//! # Versioning
//!
//! `postcard` has no struct-evolution story — upstream says so explicitly —
//! so the versioning lives in the container:
//!
//! * [`GsigHeader::format_version`] identifies the layout. It is `1`.
//! * [`GsigHeader::reader_min`] is what a *reader* must support. A producer
//!   that makes a genuinely incompatible change raises it and every older
//!   reader refuses the file with [`GsigError::ReaderTooOld`] instead of
//!   misreading it.
//! * [`GsigHeader::header_len`] lets the header itself grow: a v1 reader
//!   locates the chunk table at `header_len` rather than at a compiled-in 64.
//! * An unknown [`ChunkKind`] is skipped by its recorded size, so a section
//!   added later is invisible rather than fatal.
//!
//! **Every field added after v1 must default to v1 behaviour**, exactly as the
//! JSON schema's `#[serde(default)]` fields do: an absent mask means every
//! byte is fixed, an absent CRC means no CRC, and so on.
//!
//! # Determinism
//!
//! The bytes are a pure function of the input. Records are sorted by
//! `(name, pattern, mask, crc)`, the string table is sorted and deduplicated,
//! the chunk size and the codec are fixed, and nothing records a timestamp, a
//! path, or a hash-map iteration order. `tests/flirt_gsig_golden.rs` asserts
//! the SHA-256 of a committed fixture and that two writes of one input are
//! byte-identical.
//!
//! # What this module is not
//!
//! It is not zero-copy, deliberately. `fast-flirt` loads 944k patterns in
//! 361 ms *including* inflation and trie construction; paying rkyv's alignment
//! constraints or FlatBuffers' schema compiler to avoid a once-per-process
//! cost of that size buys nothing. The reader `mmap`s the file, parses the
//! header and chunk table without inflating anything, and then inflates the
//! sections it needs into **one** arena allocation.

mod codec;
mod convert;
mod reader;
mod warp;
mod wire;
mod writer;

/// A two-entry library covering every optional field the schema has: one
/// masked entry with a CRC, a length and a reference, and one bare v1-shaped
/// entry with none of them. Shared by the writer, reader and conversion tests
/// so all three are describing the same file.
#[cfg(test)]
pub(crate) fn sample_library_file() -> crate::flirt::FlirtLibraryFile {
    use crate::flirt::{FlirtLibraryKey, FlirtReference, FlirtSignatureEntry};
    crate::flirt::FlirtLibraryFile {
        schema_version: "2".to_string(),
        arch: "x86_64".to_string(),
        prologue_len: 8,
        entries: vec![
            FlirtSignatureEntry {
                name: "alpha".to_string(),
                prologue_hex: "554889e5e8000000".to_string(),
                source_binary: "libsample.a".to_string(),
                mask_hex: Some("ffffffffff000000".to_string()),
                crc16: Some(0x1e1a),
                crc_len: 16,
                function_len: Some(48),
                refs: vec![FlirtReference {
                    offset: 5,
                    name: "memcpy".to_string(),
                }],
                alternatives: Vec::new(),
            },
            FlirtSignatureEntry {
                name: "beta".to_string(),
                prologue_hex: "554889e54883ec10".to_string(),
                source_binary: "libsample.a".to_string(),
                mask_hex: None,
                crc16: None,
                crc_len: 0,
                function_len: None,
                refs: Vec::new(),
                alternatives: Vec::new(),
            },
        ],
        index: [("554889e5".to_string(), vec![0usize, 1])]
            .into_iter()
            .collect(),
        library: Some(FlirtLibraryKey {
            name: "sample".to_string(),
            version: "1.0.0".to_string(),
            variant: "gcc-O2".to_string(),
            arch: "x86_64".to_string(),
        }),
        stats: serde_json::json!({"unique_signatures": 2}),
    }
}

pub use codec::{decompress_into, Encoder};
pub use convert::{library_file_from_gsig, library_file_to_gsig};
pub use reader::{GsigConstraint, GsigGuidRecord, GsigLibrary, GsigRecord};
pub use warp::{
    warp_library_from_gsig, warp_library_to_gsig, WarpConstraintEntry, WarpEntry, WarpLibraryFile,
    WarpLibraryKey,
};
pub use writer::{write, write_guid_library, write_warp_library, WriteOptions};

/// The four magic bytes at offset 0 of every `.gsig` file.
pub const MAGIC: [u8; 4] = *b"GSIG";

/// The format version this module writes.
pub const FORMAT_VERSION: u16 = 1;

/// The highest [`GsigHeader::reader_min`] this module can honour.
pub const READER_VERSION: u16 = 1;

/// Size, in bytes, of the v1 header. Recorded in the header itself
/// ([`GsigHeader::header_len`]) so a later version can make it larger without
/// breaking a v1 reader's ability to find the chunk table.
pub const HEADER_LEN: usize = 64;

/// Size, in bytes, of one chunk-table entry.
pub const CHUNK_ENTRY_LEN: usize = 24;

/// Uncompressed size of one chunk.
///
/// 64 KiB is measured, not chosen: over 14,015 real prologues and names,
/// per-record zstd frames *expand* the data (0.91x), 64 KiB independent
/// chunks reach 2.45x, and a single unseekable block reaches 3.48x. Paying
/// 30% for independent, skippable frames is the trade the container is for.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// A coarse architecture tag, stored in the header so a reader can reject a
/// library for the wrong machine without inflating anything.
///
/// The *exact* architecture string the JSON carried is preserved separately in
/// [`ChunkKind::Meta`]; this is a filter, not the identity. An unrecognised
/// string maps to [`Arch::Unknown`] and round-trips unharmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Arch {
    /// Not one of the tags below. The Meta section still names it exactly.
    Unknown = 0,
    /// 32-bit x86.
    X86 = 1,
    /// 64-bit x86.
    X86_64 = 2,
    /// 32-bit ARM.
    Arm = 3,
    /// 64-bit ARM.
    Aarch64 = 4,
    /// 32-bit MIPS.
    Mips = 5,
    /// 64-bit MIPS.
    Mips64 = 6,
    /// 32-bit PowerPC.
    Ppc = 7,
    /// 64-bit PowerPC.
    Ppc64 = 8,
    /// 32-bit RISC-V.
    Riscv32 = 9,
    /// 64-bit RISC-V.
    Riscv64 = 10,
    /// IBM z/Architecture.
    S390x = 11,
    /// 64-bit SPARC.
    Sparc64 = 12,
    /// 64-bit LoongArch.
    Loongarch64 = 13,
}

impl Arch {
    /// The tag for an architecture string as the JSON libraries spell it.
    ///
    /// Deliberately generous about spelling (`x86-64`, `x86_64`, `amd64` all
    /// land on [`Arch::X86_64`]) because the tag is a filter; anything
    /// unrecognised is [`Arch::Unknown`], never a guess.
    pub fn from_name(name: &str) -> Self {
        let lower = name.to_ascii_lowercase();
        match lower.replace('-', "_").as_str() {
            "x86" | "i386" | "i486" | "i586" | "i686" | "x86_32" => Self::X86,
            "x86_64" | "amd64" | "x64" => Self::X86_64,
            "arm" | "armv7" | "armv7l" | "armhf" | "armel" | "arm32" | "thumb" => Self::Arm,
            "aarch64" | "arm64" | "aarch64_be" => Self::Aarch64,
            "mips" | "mipsel" => Self::Mips,
            "mips64" | "mips64el" => Self::Mips64,
            "ppc" | "powerpc" => Self::Ppc,
            "ppc64" | "powerpc64" | "ppc64el" | "ppc64le" => Self::Ppc64,
            "riscv32" | "rv32" => Self::Riscv32,
            "riscv64" | "rv64" => Self::Riscv64,
            "s390x" => Self::S390x,
            "sparc64" => Self::Sparc64,
            "loongarch64" => Self::Loongarch64,
            _ => Self::Unknown,
        }
    }

    /// The tag for a `u16` read out of a header. Unknown values are
    /// [`Arch::Unknown`], never an error: an architecture this build has not
    /// heard of is not a reason to refuse a file whose records it can read.
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::X86,
            2 => Self::X86_64,
            3 => Self::Arm,
            4 => Self::Aarch64,
            5 => Self::Mips,
            6 => Self::Mips64,
            7 => Self::Ppc,
            8 => Self::Ppc64,
            9 => Self::Riscv32,
            10 => Self::Riscv64,
            11 => Self::S390x,
            12 => Self::Sparc64,
            13 => Self::Loongarch64,
            _ => Self::Unknown,
        }
    }

    /// The canonical spelling of this tag, for display and for Python.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "arm",
            Self::Aarch64 => "aarch64",
            Self::Mips => "mips",
            Self::Mips64 => "mips64",
            Self::Ppc => "ppc",
            Self::Ppc64 => "ppc64",
            Self::Riscv32 => "riscv32",
            Self::Riscv64 => "riscv64",
            Self::S390x => "s390x",
            Self::Sparc64 => "sparc64",
            Self::Loongarch64 => "loongarch64",
        }
    }
}

/// How the records in a file identify a function.
///
/// One container, several identity schemes: a masked FLIRT pattern is a
/// *filter* that still needs a CRC and referenced names to resolve, while a
/// WARP function GUID is a plain equality key. They index differently — the
/// first by first fixed byte, the second by binary search over a sorted
/// `u128` array — so the reader has to know which it is holding before it
/// inflates anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Scheme {
    /// A scheme this build does not know. Records are still readable; no
    /// index is built for them.
    Unknown = 0,
    /// [`crate::flirt::MASKED_PATTERN_SCHEME`].
    FlirtMaskedPatternV1 = 1,
    /// [`crate::identity::warp::SCHEME`].
    WarpFunctionGuidV1 = 2,
}

impl Scheme {
    /// The tag for a scheme string.
    pub fn from_name(name: &str) -> Self {
        match name {
            crate::flirt::MASKED_PATTERN_SCHEME => Self::FlirtMaskedPatternV1,
            crate::identity::warp::SCHEME => Self::WarpFunctionGuidV1,
            _ => Self::Unknown,
        }
    }

    /// The tag for a `u16` read out of a header.
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::FlirtMaskedPatternV1,
            2 => Self::WarpFunctionGuidV1,
            _ => Self::Unknown,
        }
    }

    /// The scheme string, as `siglib_function.scheme` spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::FlirtMaskedPatternV1 => crate::flirt::MASKED_PATTERN_SCHEME,
            Self::WarpFunctionGuidV1 => crate::identity::warp::SCHEME,
        }
    }
}

/// Which section a chunk belongs to. See the module docs for each section's
/// encoding.
///
/// A reader that meets a `kind` it does not know **skips the chunk by its
/// recorded size**; that, plus [`GsigHeader::reader_min`], is the whole
/// forward-compatibility story.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChunkKind {
    /// Library-level metadata: one `postcard` struct.
    Meta = 0,
    /// The interned, sorted string table.
    Strings = 1,
    /// The `postcard` record stream.
    Signatures = 2,
    /// Raw pattern bytes.
    Patterns = 3,
    /// Mask bitmaps, one bit per pattern byte.
    Masks = 4,
    /// `(offset, string id)` reference pairs.
    Refs = 5,
    /// `(guid, string id)` pairs, sorted by guid.
    Guids = 6,
    /// The JSON `index` map, stored only when it is not derivable.
    Index = 7,
    /// The `postcard` [`wire::WireGuidRecord`] stream, parallel to
    /// [`Self::Guids`]: everything about an exact-match record except the
    /// GUID itself. Empty for a masked-pattern library.
    GuidRecords = 8,
    /// Fixed-width WARP constraints, `wire::CONSTRAINT_LEN` bytes each,
    /// claimed in order by [`Self::GuidRecords`].
    Constraints = 9,
}

impl ChunkKind {
    /// The kind for a raw `u8`, or `None` when this build does not know it.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Meta,
            1 => Self::Strings,
            2 => Self::Signatures,
            3 => Self::Patterns,
            4 => Self::Masks,
            5 => Self::Refs,
            6 => Self::Guids,
            7 => Self::Index,
            8 => Self::GuidRecords,
            9 => Self::Constraints,
            _ => return None,
        })
    }

    /// A short name, for `flirt_library_info_path` and for diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Meta => "meta",
            Self::Strings => "strings",
            Self::Signatures => "signatures",
            Self::Patterns => "patterns",
            Self::Masks => "masks",
            Self::Refs => "refs",
            Self::Guids => "guids",
            Self::Index => "index",
            Self::GuidRecords => "guid_records",
            Self::Constraints => "constraints",
        }
    }

    /// Every kind this build knows, in the order the writer emits them.
    pub const ALL: [Self; 10] = [
        Self::Meta,
        Self::Strings,
        Self::Signatures,
        Self::Patterns,
        Self::Masks,
        Self::Refs,
        Self::Guids,
        Self::Index,
        Self::GuidRecords,
        Self::Constraints,
    ];
}

/// How one chunk's payload is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Compression {
    /// Verbatim.
    None = 0,
    /// One standalone Zstandard frame.
    Zstd = 1,
}

impl Compression {
    /// The compression for a raw `u8`, or `None` when this build cannot
    /// inflate it — which, unlike an unknown [`ChunkKind`], *is* fatal for any
    /// chunk the reader actually needs.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::None,
            1 => Self::Zstd,
            _ => return None,
        })
    }

    /// A short name, for `flirt_library_info_path`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Zstd => "zstd",
        }
    }
}

/// The fixed, uncompressed file header.
///
/// Little-endian throughout, [`HEADER_LEN`] bytes:
///
/// | Offset | Size | Field |
/// |---|---|---|
/// | 0 | 4 | [`MAGIC`] |
/// | 4 | 2 | `format_version` |
/// | 6 | 2 | `reader_min` |
/// | 8 | 2 | `arch` |
/// | 10 | 2 | `scheme` |
/// | 12 | 4 | `n_signatures` |
/// | 16 | 4 | `n_strings` |
/// | 20 | 4 | `dict_id` |
/// | 24 | 4 | `chunk_count` |
/// | 28 | 4 | `header_len` |
/// | 32 | 32 | reserved, zero |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GsigHeader {
    /// The container layout version. [`FORMAT_VERSION`] for anything this
    /// module writes.
    pub format_version: u16,
    /// The lowest reader version that may open this file. A reader whose
    /// [`READER_VERSION`] is below this refuses rather than misreads.
    pub reader_min: u16,
    /// Coarse architecture tag; the exact string is in the Meta section.
    pub arch: Arch,
    /// How the records identify a function.
    pub scheme: Scheme,
    /// How many signature records the Signatures section holds.
    pub n_signatures: u32,
    /// How many entries the string table holds.
    pub n_strings: u32,
    /// Zstandard dictionary id, or `0` for none. A non-zero value names a
    /// dictionary in the distribution manifest; this module does not train or
    /// ship one yet, and refuses to read a file that needs one.
    pub dict_id: u32,
    /// How many chunk-table entries follow the header.
    pub chunk_count: u32,
    /// Where the chunk table starts — i.e. this header's own size.
    pub header_len: u32,
}

impl GsigHeader {
    /// Serialize to exactly [`HEADER_LEN`] bytes.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&self.format_version.to_le_bytes());
        out[6..8].copy_from_slice(&self.reader_min.to_le_bytes());
        out[8..10].copy_from_slice(&(self.arch as u16).to_le_bytes());
        out[10..12].copy_from_slice(&(self.scheme as u16).to_le_bytes());
        out[12..16].copy_from_slice(&self.n_signatures.to_le_bytes());
        out[16..20].copy_from_slice(&self.n_strings.to_le_bytes());
        out[20..24].copy_from_slice(&self.dict_id.to_le_bytes());
        out[24..28].copy_from_slice(&self.chunk_count.to_le_bytes());
        out[28..32].copy_from_slice(&self.header_len.to_le_bytes());
        out
    }

    /// Parse a header from the start of `data`.
    ///
    /// Checks the magic, then `reader_min`, then the dictionary id — in that
    /// order, so the error a caller sees names the first thing that is
    /// actually wrong.
    pub fn parse(data: &[u8]) -> Result<Self, GsigError> {
        if data.len() < HEADER_LEN {
            return Err(GsigError::Truncated {
                what: "header",
                have: data.len(),
                need: HEADER_LEN,
            });
        }
        if data[0..4] != MAGIC {
            let mut got = [0u8; 4];
            got.copy_from_slice(&data[0..4]);
            return Err(GsigError::BadMagic(got));
        }
        let u16_at = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]);
        let u32_at =
            |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
        let reader_min = u16_at(6);
        if reader_min > READER_VERSION {
            return Err(GsigError::ReaderTooOld {
                reader_min,
                have: READER_VERSION,
            });
        }
        let header_len = u32_at(28);
        if (header_len as usize) < HEADER_LEN {
            return Err(GsigError::BadHeaderLen(header_len));
        }
        let dict_id = u32_at(20);
        if dict_id != 0 {
            return Err(GsigError::UnknownDictionary(dict_id));
        }
        Ok(Self {
            format_version: u16_at(4),
            reader_min,
            arch: Arch::from_u16(u16_at(8)),
            scheme: Scheme::from_u16(u16_at(10)),
            n_signatures: u32_at(12),
            n_strings: u32_at(16),
            dict_id,
            chunk_count: u32_at(24),
            header_len,
        })
    }
}

/// One chunk-table entry. Little-endian, [`CHUNK_ENTRY_LEN`] bytes:
///
/// | Offset | Size | Field |
/// |---|---|---|
/// | 0 | 1 | `kind` |
/// | 1 | 1 | `compression` |
/// | 2 | 2 | reserved, zero |
/// | 4 | 4 | `compressed_size` |
/// | 8 | 4 | `uncompressed_size` |
/// | 12 | 4 | reserved, zero |
/// | 16 | 8 | `file_offset` |
///
/// `uncompressed_size` is WARP's rule and worth keeping: a reader allocates
/// exactly the right arena before inflating a single byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkEntry {
    /// The raw kind byte. Kept raw rather than as a [`ChunkKind`] so an
    /// unknown section survives a read/write round trip untouched.
    pub kind: u8,
    /// The raw compression byte.
    pub compression: u8,
    /// Bytes occupied in the file.
    pub compressed_size: u32,
    /// Bytes after inflation.
    pub uncompressed_size: u32,
    /// Where the payload starts.
    pub file_offset: u64,
}

impl ChunkEntry {
    /// Serialize to exactly [`CHUNK_ENTRY_LEN`] bytes.
    pub fn to_bytes(&self) -> [u8; CHUNK_ENTRY_LEN] {
        let mut out = [0u8; CHUNK_ENTRY_LEN];
        out[0] = self.kind;
        out[1] = self.compression;
        out[4..8].copy_from_slice(&self.compressed_size.to_le_bytes());
        out[8..12].copy_from_slice(&self.uncompressed_size.to_le_bytes());
        out[16..24].copy_from_slice(&self.file_offset.to_le_bytes());
        out
    }

    /// Parse one entry from the start of `data`.
    pub fn parse(data: &[u8]) -> Result<Self, GsigError> {
        if data.len() < CHUNK_ENTRY_LEN {
            return Err(GsigError::Truncated {
                what: "chunk table entry",
                have: data.len(),
                need: CHUNK_ENTRY_LEN,
            });
        }
        let u32_at =
            |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
        let mut off = [0u8; 8];
        off.copy_from_slice(&data[16..24]);
        Ok(Self {
            kind: data[0],
            compression: data[1],
            compressed_size: u32_at(4),
            uncompressed_size: u32_at(8),
            file_offset: u64::from_le_bytes(off),
        })
    }

    /// The kind, when this build knows it.
    pub fn known_kind(&self) -> Option<ChunkKind> {
        ChunkKind::from_u8(self.kind)
    }
}

/// Why a `.gsig` could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum GsigError {
    /// The file does not start with [`MAGIC`].
    #[error("not a gsig file: magic is {0:02x?}, expected 47:53:49:47 (\"GSIG\")")]
    BadMagic([u8; 4]),
    /// The file demands a newer reader than this build is.
    #[error("gsig file needs reader version {reader_min}, this build is {have}")]
    ReaderTooOld {
        /// What the file demands.
        reader_min: u16,
        /// What this build offers.
        have: u16,
    },
    /// `header_len` is smaller than the v1 header, so the chunk table would
    /// overlap the header.
    #[error("gsig header_len {0} is smaller than the v1 header ({HEADER_LEN})")]
    BadHeaderLen(u32),
    /// The file was compressed against a Zstandard dictionary. The reader
    /// refuses rather than producing wrong bytes.
    #[error("gsig file needs zstd dictionary {0}, which this build does not have")]
    UnknownDictionary(u32),
    /// A structure ran off the end of the file.
    #[error("gsig {what} is truncated: {have} bytes available, need {need}")]
    Truncated {
        /// Which structure.
        what: &'static str,
        /// Bytes available.
        have: usize,
        /// Bytes needed.
        need: usize,
    },
    /// A chunk names a compression this build cannot inflate.
    #[error("gsig chunk uses unknown compression {0}")]
    UnknownCompression(u8),
    /// Inflation failed, or produced the wrong number of bytes.
    #[error("gsig chunk failed to decompress: {0}")]
    Decompress(String),
    /// A `postcard` value would not decode.
    #[error("gsig record stream is malformed: {0}")]
    Decode(String),
    /// A `postcard` value would not encode.
    #[error("gsig record stream could not be encoded: {0}")]
    Encode(String),
    /// A string id points past the end of the string table.
    #[error("gsig string id {0} is out of range ({1} strings)")]
    BadStringId(u32, u32),
    /// The container's identity scheme is not the one the caller asked for.
    ///
    /// Reading a masked-pattern library through the GUID path (or the
    /// reverse) would return a well-formed, empty result rather than an
    /// error, and an empty signature library is indistinguishable from a
    /// legitimately empty harvest. Fail instead.
    #[error("gsig file is a {got} library, not {want}")]
    WrongScheme {
        /// The scheme the caller wanted.
        want: &'static str,
        /// The scheme the file declares.
        got: &'static str,
    },
    /// A record's pattern, mask or reference range runs off its section.
    #[error("gsig record {0} runs past the end of the {1} section")]
    RecordOverrun(u32, &'static str),
    /// A section is required for this file's scheme and is absent.
    #[error("gsig file has no {0} section")]
    MissingSection(&'static str),
    /// The library holds more of something than the format can count.
    #[error("gsig cannot hold {1} {0}: the field is a u32")]
    TooLarge(&'static str, usize),
    /// Reading or writing the file itself failed.
    #[error("gsig i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Does `data` begin with the `gsig` magic?
///
/// This is the dispatch [`crate::flirt::FlirtLibrary::from_path`] uses: JSON
/// libraries begin with `{` or whitespace, so four bytes settle it without
/// reading the file twice.
pub fn is_gsig(data: &[u8]) -> bool {
    data.len() >= MAGIC.len() && data[..MAGIC.len()] == MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_round_trips_through_bytes() {
        let header = GsigHeader {
            format_version: FORMAT_VERSION,
            reader_min: READER_VERSION,
            arch: Arch::X86_64,
            scheme: Scheme::FlirtMaskedPatternV1,
            n_signatures: 2690,
            n_strings: 3111,
            dict_id: 0,
            chunk_count: 7,
            header_len: HEADER_LEN as u32,
        };
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(&bytes[0..4], b"GSIG");
        assert_eq!(GsigHeader::parse(&bytes).unwrap(), header);
    }

    #[test]
    fn the_reserved_header_tail_is_zero() {
        let header = GsigHeader {
            format_version: FORMAT_VERSION,
            reader_min: READER_VERSION,
            arch: Arch::Aarch64,
            scheme: Scheme::WarpFunctionGuidV1,
            n_signatures: 1,
            n_strings: 1,
            dict_id: 0,
            chunk_count: 1,
            header_len: HEADER_LEN as u32,
        };
        assert!(header.to_bytes()[32..].iter().all(|b| *b == 0));
    }

    #[test]
    fn a_chunk_entry_round_trips_through_bytes() {
        let entry = ChunkEntry {
            kind: ChunkKind::Signatures as u8,
            compression: Compression::Zstd as u8,
            compressed_size: 40_000,
            uncompressed_size: CHUNK_SIZE as u32,
            file_offset: 1 << 33,
        };
        let bytes = entry.to_bytes();
        assert_eq!(bytes.len(), CHUNK_ENTRY_LEN);
        assert!(bytes[2..4].iter().all(|b| *b == 0));
        assert!(bytes[12..16].iter().all(|b| *b == 0));
        assert_eq!(ChunkEntry::parse(&bytes).unwrap(), entry);
    }

    #[test]
    fn bad_magic_is_named_not_guessed() {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(b"{\n  ");
        assert!(matches!(
            GsigHeader::parse(&bytes),
            Err(GsigError::BadMagic(_))
        ));
        assert!(!is_gsig(&bytes));
        assert!(is_gsig(b"GSIG\x01\x00"));
    }

    /// The whole forward-compatibility story in one test: a producer that
    /// raises `reader_min` gets a refusal, not a misread.
    #[test]
    fn a_future_reader_min_is_refused() {
        let header = GsigHeader {
            format_version: 9,
            reader_min: READER_VERSION + 1,
            arch: Arch::X86_64,
            scheme: Scheme::FlirtMaskedPatternV1,
            n_signatures: 0,
            n_strings: 0,
            dict_id: 0,
            chunk_count: 0,
            header_len: HEADER_LEN as u32,
        };
        assert!(matches!(
            GsigHeader::parse(&header.to_bytes()),
            Err(GsigError::ReaderTooOld { reader_min, have })
                if reader_min == READER_VERSION + 1 && have == READER_VERSION
        ));
    }

    /// A dictionary we do not have would silently produce wrong bytes, so it
    /// is refused up front rather than at the first inflate.
    #[test]
    fn an_unknown_dictionary_is_refused() {
        let header = GsigHeader {
            format_version: FORMAT_VERSION,
            reader_min: READER_VERSION,
            arch: Arch::X86_64,
            scheme: Scheme::FlirtMaskedPatternV1,
            n_signatures: 0,
            n_strings: 0,
            dict_id: 7,
            chunk_count: 0,
            header_len: HEADER_LEN as u32,
        };
        assert!(matches!(
            GsigHeader::parse(&header.to_bytes()),
            Err(GsigError::UnknownDictionary(7))
        ));
    }

    #[test]
    fn arch_spellings_collapse_and_unknown_stays_unknown() {
        for name in ["x86_64", "x86-64", "amd64", "X86_64"] {
            assert_eq!(Arch::from_name(name), Arch::X86_64, "{name}");
        }
        assert_eq!(Arch::from_name("arm64"), Arch::Aarch64);
        assert_eq!(Arch::from_name("m68k"), Arch::Unknown);
        for arch in [Arch::X86_64, Arch::Aarch64, Arch::Riscv64, Arch::Unknown] {
            assert_eq!(Arch::from_u16(arch as u16), arch);
        }
    }

    /// The scheme tags must track the two constants they mirror, or a
    /// `siglib_function.scheme` row and a header disagree silently.
    #[test]
    fn scheme_tags_track_the_scheme_constants() {
        assert_eq!(
            Scheme::from_name(crate::flirt::MASKED_PATTERN_SCHEME),
            Scheme::FlirtMaskedPatternV1
        );
        assert_eq!(
            Scheme::FlirtMaskedPatternV1.as_str(),
            crate::flirt::MASKED_PATTERN_SCHEME
        );
        assert_eq!(
            Scheme::from_name(crate::identity::warp::SCHEME),
            Scheme::WarpFunctionGuidV1
        );
        assert_eq!(
            Scheme::WarpFunctionGuidV1.as_str(),
            crate::identity::warp::SCHEME
        );
        assert_eq!(Scheme::from_name("ssdeep"), Scheme::Unknown);
    }

    #[test]
    fn every_known_chunk_kind_round_trips_its_byte() {
        for kind in ChunkKind::ALL {
            assert_eq!(ChunkKind::from_u8(kind as u8), Some(kind));
            assert!(!kind.as_str().is_empty());
        }
        assert_eq!(ChunkKind::from_u8(200), None);
    }
}
