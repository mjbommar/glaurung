//! Core DEX types, constants and errors.
//!
//! Layout reference: <https://source.android.com/docs/core/runtime/dex-format>.

use std::fmt;

/// DEX parsing errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DexError {
    /// Magic bytes were not `dex\n0NN\0`.
    InvalidMagic,
    /// Unsupported / unrecognised DEX version.
    UnsupportedVersion([u8; 3]),
    /// A structure ran past the end of the file.
    Truncated { offset: usize, needed: usize },
    /// An index referenced a table entry that does not exist.
    IndexOutOfRange { table: &'static str, index: u32 },
    /// A string was not valid Modified UTF-8.
    InvalidString,
    /// Header contradicted itself (bad sizes/offsets/endianness).
    MalformedHeader(String),
}

impl fmt::Display for DexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid DEX magic"),
            Self::UnsupportedVersion(v) => write!(
                f,
                "unsupported DEX version: {}{}{}",
                v[0] as char, v[1] as char, v[2] as char
            ),
            Self::Truncated { offset, needed } => {
                write!(f, "truncated at {:#x}, needed {} bytes", offset, needed)
            }
            Self::IndexOutOfRange { table, index } => {
                write!(f, "{} index {} out of range", table, index)
            }
            Self::InvalidString => write!(f, "string is not valid Modified UTF-8"),
            Self::MalformedHeader(m) => write!(f, "malformed DEX header: {}", m),
        }
    }
}

impl std::error::Error for DexError {}

pub type Result<T> = std::result::Result<T, DexError>;

/// The three ASCII version digits that follow `dex\n` in the magic.
pub const DEX_MAGIC_PREFIX: &[u8; 4] = b"dex\n";
/// Little-endian marker stored in `header.endian_tag`.
pub const ENDIAN_CONSTANT: u32 = 0x1234_5678;
/// Byte-swapped marker (big-endian DEX; extremely rare, unsupported for now).
pub const REVERSE_ENDIAN_CONSTANT: u32 = 0x7856_3412;
/// Canonical header size for all known DEX versions.
pub const HEADER_SIZE: usize = 0x70;
/// Sentinel used by `class_def_item` fields meaning "no index".
pub const NO_INDEX: u32 = 0xffff_ffff;

/// Parsed DEX header (`header_item`).
#[derive(Debug, Clone)]
pub struct DexHeader {
    /// The three version digits (e.g. `b"035"`, `b"039"`).
    pub version: [u8; 3],
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

/// `field_id_item`: a reference to a field.
#[derive(Debug, Clone, Copy)]
pub struct FieldId {
    /// Index into `type_ids` for the defining class.
    pub class_idx: u16,
    /// Index into `type_ids` for the field's type.
    pub type_idx: u16,
    /// Index into `string_ids` for the field's name.
    pub name_idx: u32,
}

/// `method_id_item`: a reference to a method.
#[derive(Debug, Clone, Copy)]
pub struct MethodId {
    /// Index into `type_ids` for the defining class.
    pub class_idx: u16,
    /// Index into `proto_ids` for the method prototype.
    pub proto_idx: u16,
    /// Index into `string_ids` for the method's name.
    pub name_idx: u32,
}

/// `proto_id_item`: a method prototype (shorty + return type + params).
#[derive(Debug, Clone, Copy)]
pub struct ProtoId {
    /// Index into `string_ids` for the short-form descriptor.
    pub shorty_idx: u32,
    /// Index into `type_ids` for the return type.
    pub return_type_idx: u32,
    /// File offset of the `type_list` of parameters (0 = none).
    pub parameters_off: u32,
}

/// `class_def_item`: a class definition.
#[derive(Debug, Clone, Copy)]
pub struct ClassDef {
    /// Index into `type_ids` for this class.
    pub class_idx: u32,
    /// `access_flags` bitmap (public/final/interface/abstract/…).
    pub access_flags: u32,
    /// Index into `type_ids` for the superclass, or [`NO_INDEX`].
    pub superclass_idx: u32,
    /// File offset of the interfaces `type_list` (0 = none).
    pub interfaces_off: u32,
    /// Index into `string_ids` for the source file name, or [`NO_INDEX`].
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

// access_flags bits (subset relevant to surface enumeration).
pub const ACC_PUBLIC: u32 = 0x1;
pub const ACC_PRIVATE: u32 = 0x2;
pub const ACC_PROTECTED: u32 = 0x4;
pub const ACC_STATIC: u32 = 0x8;
pub const ACC_FINAL: u32 = 0x10;
pub const ACC_INTERFACE: u32 = 0x200;
pub const ACC_ABSTRACT: u32 = 0x400;
pub const ACC_NATIVE: u32 = 0x100;
pub const ACC_ENUM: u32 = 0x4000;
