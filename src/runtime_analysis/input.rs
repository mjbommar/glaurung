//! Stable, execution-scoped identities for captured input bytes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::capsule::{InputBytesIdentity, ProcessCapsule, Sensitivity};

pub const INPUT_PROVENANCE_REPORT_SCHEMA: &str = "glaurung-runtime-input-provenance-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputSourceIdentity {
    pub id: String,
    pub name: String,
    pub sha256: String,
    pub byte_len: u64,
    pub sensitivity: Sensitivity,
    pub byte_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputProvenanceReport {
    pub schema: String,
    pub capture_id: String,
    pub sources: Vec<InputSourceIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputByteIdentity {
    pub id: String,
    pub source_id: String,
    pub offset: u64,
}

fn source_id(capture_id: &str, source: &InputBytesIdentity) -> String {
    let mut digest = Sha256::new();
    digest.update(capture_id.as_bytes());
    digest.update([0]);
    digest.update(source.name.as_bytes());
    digest.update([0]);
    digest.update(source.sha256.as_bytes());
    digest.update([0]);
    digest.update(source.byte_len.to_le_bytes());
    format!("input-source-{}", hex::encode(digest.finalize()))
}

fn byte_id(source_id: &str, offset: u64) -> String {
    let mut digest = Sha256::new();
    digest.update(source_id.as_bytes());
    digest.update([0]);
    digest.update(offset.to_le_bytes());
    format!("input-byte-{}", hex::encode(digest.finalize()))
}

/// Project aggregate capsule provenance into execution-scoped input sources.
pub fn input_provenance(capsule: &ProcessCapsule) -> InputProvenanceReport {
    let sources = capsule
        .provenance
        .input_bytes
        .iter()
        .map(|source| InputSourceIdentity {
            id: source_id(&capsule.identity.capture_id, source),
            name: source.name.clone(),
            sha256: source.sha256.clone(),
            byte_len: source.byte_len,
            sensitivity: source.sensitivity,
            byte_identity: "(source_id,offset)".to_string(),
        })
        .collect();
    InputProvenanceReport {
        schema: INPUT_PROVENANCE_REPORT_SCHEMA.to_string(),
        capture_id: capsule.identity.capture_id.clone(),
        sources,
    }
}

/// Resolve one byte position without materializing an attacker-sized ID list.
pub fn resolve_input_byte(
    capsule: &ProcessCapsule,
    source_name: &str,
    offset: u64,
) -> Result<InputByteIdentity, String> {
    let source = capsule
        .provenance
        .input_bytes
        .iter()
        .find(|source| source.name == source_name)
        .ok_or_else(|| format!("unknown input source: {source_name}"))?;
    if offset >= source.byte_len {
        return Err(format!(
            "input byte offset {offset} is outside {source_name} length {}",
            source.byte_len
        ));
    }
    let source_id = source_id(&capsule.identity.capture_id, source);
    Ok(InputByteIdentity {
        id: byte_id(&source_id, offset),
        source_id,
        offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> InputBytesIdentity {
        InputBytesIdentity {
            name: "argv[1]".to_string(),
            sha256: "ab".repeat(32),
            byte_len: 3,
            sensitivity: Sensitivity::Public,
        }
    }

    #[test]
    fn identities_are_stable_scoped_and_offset_sensitive() {
        let source = source();
        let first_source = source_id("capture-1", &source);
        assert_eq!(first_source, source_id("capture-1", &source));
        assert_ne!(first_source, source_id("capture-2", &source));
        assert_ne!(byte_id(&first_source, 0), byte_id(&first_source, 1));
    }
}
