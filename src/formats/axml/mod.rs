//! Android binary XML (AXML) parser.
//!
//! Decodes the compiled `AndroidManifest.xml` (and any other AXML resource) into
//! a stream of [`XmlEvent`]s, then offers a manifest-focused analysis
//! ([`manifest::ManifestSummary`]) that surfaces the attack surface an app
//! exposes: package name, requested permissions, exported components
//! (activities/services/receivers/providers) and their deep-link intent
//! filters.
//!
//! Layout reference: AOSP `androidfw/ResourceTypes.h`.

pub mod manifest;
pub mod strings;
pub mod types;

use strings::StringPool;
pub use types::*;

fn u16le(data: &[u8], off: usize) -> Result<u16> {
    let b = data.get(off..off + 2).ok_or(AxmlError::Truncated {
        offset: off,
        needed: 2,
    })?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32le(data: &[u8], off: usize) -> Result<u32> {
    let b = data.get(off..off + 4).ok_or(AxmlError::Truncated {
        offset: off,
        needed: 4,
    })?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// True if `data` looks like an AXML document (`RES_XML_TYPE` magic).
pub fn is_axml(data: &[u8]) -> bool {
    data.len() >= 8 && u16::from_le_bytes([data[0], data[1]]) == RES_XML_TYPE
}

/// Decode an AXML document into a flat list of start/end element events.
///
/// Namespace and CDATA chunks are consumed for correctness but not emitted;
/// attribute values are rendered best-effort (see [`render_value`]).
pub fn parse_events(data: &[u8]) -> Result<Vec<XmlEvent>> {
    if !is_axml(data) {
        return Err(AxmlError::NotXml);
    }
    let total = u32le(data, 4)? as usize;
    let end = total.min(data.len());

    // Walk sibling chunks after the 8-byte document header.
    let mut pool: Option<StringPool> = None;
    let mut events = Vec::new();
    let mut off = u16le(data, 2)? as usize; // headerSize of the document chunk
    if off < 8 {
        off = 8;
    }

    while off + 8 <= end {
        let ctype = u16le(data, off)?;
        let chunk_size = u32le(data, off + 4)? as usize;
        if chunk_size < 8 || off + chunk_size > data.len() {
            // A zero or overflowing size would loop/overrun; stop cleanly.
            break;
        }
        let chunk = &data[off..off + chunk_size];

        match ctype {
            RES_STRING_POOL_TYPE => {
                pool = Some(StringPool::parse(chunk)?);
            }
            RES_XML_START_ELEMENT_TYPE => {
                if let Some(p) = &pool {
                    events.push(parse_start_element(chunk, p)?);
                }
            }
            RES_XML_END_ELEMENT_TYPE => {
                if let Some(p) = &pool {
                    let name = string_or_empty(p, u32le(chunk, 20)?);
                    events.push(XmlEvent::EndElement { name });
                }
            }
            // Namespace / CDATA / resource-map chunks carry no element data we
            // need for manifest analysis.
            _ => {}
        }

        off += chunk_size;
    }

    Ok(events)
}

fn parse_start_element(chunk: &[u8], pool: &StringPool) -> Result<XmlEvent> {
    // ResXMLTree_node (16) + ResXMLTree_attrExt.
    let name = string_or_empty(pool, u32le(chunk, 20)?);
    let attribute_start = u16le(chunk, 24)? as usize;
    let attribute_size = u16le(chunk, 26)? as usize;
    let attribute_count = u16le(chunk, 28)? as usize;

    // Attributes begin relative to the start of ResXMLTree_attrExt (offset 16).
    let base = 16 + attribute_start;
    let step = if attribute_size == 0 { 20 } else { attribute_size };

    let mut attributes = Vec::with_capacity(attribute_count);
    for i in 0..attribute_count {
        let a = base + i * step;
        if a + 20 > chunk.len() {
            break;
        }
        let ns_ref = u32le(chunk, a)?;
        let name_ref = u32le(chunk, a + 4)?;
        let raw_ref = u32le(chunk, a + 8)?;
        // Res_value: size(u16) res0(u8) dataType(u8) data(u32) at a+12.
        let data_type = *chunk.get(a + 15).ok_or(AxmlError::Truncated {
            offset: a + 15,
            needed: 1,
        })?;
        let data = u32le(chunk, a + 16)?;

        attributes.push(XmlAttribute {
            namespace: string_or_empty(pool, ns_ref),
            name: string_or_empty(pool, name_ref),
            value: render_value(pool, raw_ref, data_type, data),
        });
    }

    Ok(XmlEvent::StartElement { name, attributes })
}

fn string_or_empty(pool: &StringPool, index: u32) -> String {
    pool.get(index).unwrap_or("").to_string()
}

/// Render an attribute value: prefer the raw string when present, otherwise
/// interpret the typed `Res_value`.
fn render_value(pool: &StringPool, raw_ref: u32, data_type: u8, data: u32) -> String {
    if raw_ref != NO_ENTRY {
        if let Some(s) = pool.get(raw_ref) {
            return s.to_string();
        }
    }
    match data_type {
        TYPE_STRING => pool.get(data).unwrap_or("").to_string(),
        TYPE_INT_BOOLEAN => {
            if data != 0 {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        TYPE_INT_DEC => (data as i32).to_string(),
        TYPE_INT_HEX => format!("0x{:x}", data),
        TYPE_REFERENCE => format!("@0x{:08x}", data),
        TYPE_ATTRIBUTE => format!("?0x{:08x}", data),
        TYPE_NULL => String::new(),
        _ => format!("0x{:08x}", data),
    }
}

#[cfg(test)]
mod tests;
