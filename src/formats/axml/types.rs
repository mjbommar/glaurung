//! Android binary XML (AXML) chunk types, value types and errors.
//!
//! AXML is the compiled form of `AndroidManifest.xml` and every other XML
//! resource inside an APK/AAB. It is a tree of little-endian `ResChunk_header`
//! chunks over a shared string pool.
//!
//! Layout reference: AOSP `frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h`.

use std::fmt;

/// AXML parsing errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AxmlError {
    /// The top-level chunk was not `RES_XML_TYPE`.
    NotXml,
    /// A chunk or field ran past the end of the buffer.
    Truncated { offset: usize, needed: usize },
    /// A string-pool index was out of range.
    BadStringIndex(u32),
    /// A chunk declared an impossible size.
    MalformedChunk(String),
}

impl fmt::Display for AxmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotXml => write!(f, "not an AXML (RES_XML_TYPE) document"),
            Self::Truncated { offset, needed } => {
                write!(f, "truncated at {:#x}, needed {} bytes", offset, needed)
            }
            Self::BadStringIndex(i) => write!(f, "string index {} out of range", i),
            Self::MalformedChunk(m) => write!(f, "malformed chunk: {}", m),
        }
    }
}

impl std::error::Error for AxmlError {}

pub type Result<T> = std::result::Result<T, AxmlError>;

// Chunk types (ResChunk_header.type).
pub const RES_STRING_POOL_TYPE: u16 = 0x0001;
pub const RES_XML_TYPE: u16 = 0x0003;
pub const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
pub const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
pub const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
pub const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
pub const RES_XML_CDATA_TYPE: u16 = 0x0104;
pub const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;

// ResStringPool_header.flags.
pub const SORTED_FLAG: u32 = 1 << 0;
pub const UTF8_FLAG: u32 = 1 << 8;

// Res_value.dataType (subset used for attribute rendering).
pub const TYPE_NULL: u8 = 0x00;
pub const TYPE_REFERENCE: u8 = 0x01;
pub const TYPE_ATTRIBUTE: u8 = 0x02;
pub const TYPE_STRING: u8 = 0x03;
pub const TYPE_FLOAT: u8 = 0x04;
pub const TYPE_INT_DEC: u8 = 0x10;
pub const TYPE_INT_HEX: u8 = 0x11;
pub const TYPE_INT_BOOLEAN: u8 = 0x12;

/// Sentinel string reference meaning "no string" (0xFFFFFFFF).
pub const NO_ENTRY: u32 = 0xffff_ffff;

/// A resolved XML attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlAttribute {
    /// Namespace URI (e.g. the Android namespace), empty if none.
    pub namespace: String,
    /// Local attribute name (e.g. `name`, `exported`).
    pub name: String,
    /// Best-effort rendered value (string, decimal int, `true`/`false`, or a
    /// `@0x…` resource reference).
    pub value: String,
}

/// A streamed XML event produced while walking the chunk tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmlEvent {
    StartElement {
        name: String,
        attributes: Vec<XmlAttribute>,
    },
    EndElement {
        name: String,
    },
}
