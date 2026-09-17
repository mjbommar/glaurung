//! Read-only, process-scoped access to sparse runtime page evidence.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use thiserror::Error;

use super::capsule::{CapsuleLimits, OmissionReason, PageContent, ProcessCapsule};
use crate::analysis::memory::{MemoryError, MemoryView};
use crate::core::address::{Address, AddressKind};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RuntimeMemoryError {
    #[error("invalid process capsule: {reason}")]
    InvalidCapsule { reason: String },
    #[error("runtime reads require a virtual address")]
    UnsupportedAddress,
    #[error("runtime read range overflowed")]
    Overflow,
    #[error("runtime read is outside every mapping for process {process_id}")]
    Unmapped { process_id: String },
    #[error("runtime mapping evidence is ambiguous at {address:#x}")]
    MappingAmbiguous { address: u64 },
    #[error("runtime read crosses a mapping boundary")]
    MappingBoundary,
    #[error("runtime mapping {mapping_id} is not readable")]
    PermissionDenied { mapping_id: String },
    #[error("runtime page evidence is absent at {address:#x}")]
    PageAbsent { address: u64 },
    #[error("runtime page evidence is ambiguous at {address:#x}")]
    PageAmbiguous { address: u64 },
    #[error("runtime page was omitted: {reason:?}: {detail}")]
    PageOmitted {
        reason: OmissionReason,
        detail: String,
    },
    #[error("runtime payload {payload_id} is unavailable")]
    PayloadUnavailable { payload_id: String },
    #[error("runtime payload {payload_id} disagrees with its declared identity")]
    PayloadInvalid { payload_id: String },
}

/// Sparse page bytes for one process in one validated capture.
pub struct RuntimeMemoryView<'a> {
    capsule: &'a ProcessCapsule,
    payloads: &'a BTreeMap<String, Vec<u8>>,
    process_id: &'a str,
}

impl<'a> RuntimeMemoryView<'a> {
    pub fn new(
        capsule: &'a ProcessCapsule,
        payloads: &'a BTreeMap<String, Vec<u8>>,
        process_id: &'a str,
    ) -> Result<Self, RuntimeMemoryError> {
        capsule
            .validate(CapsuleLimits::default())
            .map_err(|reason| RuntimeMemoryError::InvalidCapsule { reason })?;
        if !capsule
            .processes
            .iter()
            .any(|process| process.id == process_id)
        {
            return Err(RuntimeMemoryError::Unmapped {
                process_id: process_id.to_string(),
            });
        }
        Ok(Self {
            capsule,
            payloads,
            process_id,
        })
    }

    pub fn read_runtime_bytes(
        &self,
        address: u64,
        len: usize,
    ) -> Result<Vec<u8>, RuntimeMemoryError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let end = address
            .checked_add(u64::try_from(len).map_err(|_| RuntimeMemoryError::Overflow)?)
            .ok_or(RuntimeMemoryError::Overflow)?;
        let mappings: Vec<_> = self
            .capsule
            .mappings
            .iter()
            .filter(|mapping| {
                mapping.process_id == self.process_id
                    && mapping.start <= address
                    && address < mapping.end
            })
            .collect();
        if mappings.is_empty() {
            return Err(RuntimeMemoryError::Unmapped {
                process_id: self.process_id.to_string(),
            });
        }
        if mappings.len() != 1 {
            return Err(RuntimeMemoryError::MappingAmbiguous { address });
        }
        let mapping = mappings[0];
        if end > mapping.end {
            return Err(RuntimeMemoryError::MappingBoundary);
        }
        if !mapping.permissions.read {
            return Err(RuntimeMemoryError::PermissionDenied {
                mapping_id: mapping.id.clone(),
            });
        }

        let mut output = Vec::with_capacity(len);
        let mut cursor = address;
        while cursor < end {
            let pages: Vec<_> = self
                .capsule
                .pages
                .iter()
                .filter(|page| {
                    page.process_id == self.process_id
                        && page.mapping_id == mapping.id
                        && page.start <= cursor
                        && cursor < page.start.saturating_add(page.byte_len)
                })
                .collect();
            if pages.is_empty() {
                return Err(RuntimeMemoryError::PageAbsent { address: cursor });
            }
            if pages.len() != 1 {
                return Err(RuntimeMemoryError::PageAmbiguous { address: cursor });
            }
            let page = pages[0];
            let page_end = page
                .start
                .checked_add(page.byte_len)
                .ok_or(RuntimeMemoryError::Overflow)?;
            match &page.content {
                PageContent::Omitted { reason, detail } => {
                    return Err(RuntimeMemoryError::PageOmitted {
                        reason: *reason,
                        detail: detail.clone(),
                    });
                }
                PageContent::Captured { payload } => {
                    let bytes = self.payloads.get(&payload.id).ok_or_else(|| {
                        RuntimeMemoryError::PayloadUnavailable {
                            payload_id: payload.id.clone(),
                        }
                    })?;
                    if bytes.len() as u64 != payload.byte_len
                        || hex::encode(Sha256::digest(bytes)) != payload.sha256
                    {
                        return Err(RuntimeMemoryError::PayloadInvalid {
                            payload_id: payload.id.clone(),
                        });
                    }
                    let take_end = end.min(page_end);
                    let start_offset = usize::try_from(cursor - page.start)
                        .map_err(|_| RuntimeMemoryError::Overflow)?;
                    let take_len = usize::try_from(take_end - cursor)
                        .map_err(|_| RuntimeMemoryError::Overflow)?;
                    output.extend_from_slice(&bytes[start_offset..start_offset + take_len]);
                    cursor = take_end;
                }
            }
        }
        Ok(output)
    }
}

impl MemoryView for RuntimeMemoryView<'_> {
    fn read_bytes(&self, address: &Address, len: usize) -> Result<Vec<u8>, MemoryError> {
        if address.kind != AddressKind::VA {
            return Err(MemoryError::Unsupported(address.kind));
        }
        self.read_runtime_bytes(address.value, len)
            .map_err(|error| MemoryError::Translation(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_analysis::capsule::{PageRecord, PayloadReference, Sensitivity};
    use crate::runtime_analysis::correlation::tests::{capsule, hello_image};

    #[test]
    fn reads_across_adjacent_captured_pages_and_preserves_failures() {
        let image = hello_image();
        let mut capsule = capsule(&image);
        let first = vec![1, 2];
        let second = vec![3, 4];
        for (start, id, bytes) in [
            (0x7000_0000, "first", &first),
            (0x7000_0002, "second", &second),
        ] {
            capsule.pages.push(PageRecord {
                process_id: "process-main".to_string(),
                mapping_id: "mapping-main".to_string(),
                start,
                byte_len: bytes.len() as u64,
                content: PageContent::Captured {
                    payload: PayloadReference {
                        id: id.to_string(),
                        sha256: hex::encode(Sha256::digest(bytes)),
                        byte_len: bytes.len() as u64,
                        sensitivity: Sensitivity::Sensitive,
                    },
                },
            });
        }
        let payloads =
            BTreeMap::from([("first".to_string(), first), ("second".to_string(), second)]);
        let view = RuntimeMemoryView::new(&capsule, &payloads, "process-main").unwrap();
        assert_eq!(view.read_runtime_bytes(0x7000_0001, 3).unwrap(), [2, 3, 4]);
        assert!(matches!(
            view.read_runtime_bytes(0x7000_0004, 1),
            Err(RuntimeMemoryError::PageAbsent { .. })
        ));
    }

    #[test]
    fn reports_omission_permissions_boundaries_and_payload_tampering() {
        let image = hello_image();
        let mut capsule = capsule(&image);
        let bytes = vec![1, 2, 3, 4];
        capsule.pages.push(PageRecord {
            process_id: "process-main".to_string(),
            mapping_id: "mapping-main".to_string(),
            start: 0x7000_0000,
            byte_len: bytes.len() as u64,
            content: PageContent::Captured {
                payload: PayloadReference {
                    id: "page".to_string(),
                    sha256: hex::encode(Sha256::digest(&bytes)),
                    byte_len: bytes.len() as u64,
                    sensitivity: Sensitivity::Sensitive,
                },
            },
        });
        let tampered = BTreeMap::from([("page".to_string(), vec![9, 9, 9, 9])]);
        let view = RuntimeMemoryView::new(&capsule, &tampered, "process-main").unwrap();
        assert!(matches!(
            view.read_runtime_bytes(0x7000_0000, 1),
            Err(RuntimeMemoryError::PayloadInvalid { .. })
        ));

        capsule.pages[0].content = PageContent::Omitted {
            reason: OmissionReason::PermissionDenied,
            detail: "provider could not read the page".to_string(),
        };
        let empty_payloads = BTreeMap::new();
        let view = RuntimeMemoryView::new(&capsule, &empty_payloads, "process-main").unwrap();
        assert!(matches!(
            view.read_runtime_bytes(0x7000_0000, 1),
            Err(RuntimeMemoryError::PageOmitted {
                reason: OmissionReason::PermissionDenied,
                ..
            })
        ));

        capsule.mappings[0].permissions.read = false;
        let view = RuntimeMemoryView::new(&capsule, &empty_payloads, "process-main").unwrap();
        assert!(matches!(
            view.read_runtime_bytes(0x7000_0000, 1),
            Err(RuntimeMemoryError::PermissionDenied { .. })
        ));
        capsule.mappings[0].permissions.read = true;
        let mapping_end = capsule.mappings[0].end;
        let view = RuntimeMemoryView::new(&capsule, &empty_payloads, "process-main").unwrap();
        assert_eq!(
            view.read_runtime_bytes(mapping_end - 1, 2),
            Err(RuntimeMemoryError::MappingBoundary)
        );
    }

    #[test]
    fn rejects_overlapping_mapping_and_page_evidence_as_ambiguous() {
        let image = hello_image();
        let mut capsule = capsule(&image);
        let mut alias = capsule.mappings[0].clone();
        alias.id = "mapping-alias".to_string();
        capsule.mappings.push(alias);
        let empty_payloads = BTreeMap::new();
        let view = RuntimeMemoryView::new(&capsule, &empty_payloads, "process-main").unwrap();
        assert!(matches!(
            view.read_runtime_bytes(0x7000_0000, 1),
            Err(RuntimeMemoryError::MappingAmbiguous { .. })
        ));

        capsule.mappings.pop();
        let page = PageRecord {
            process_id: "process-main".to_string(),
            mapping_id: "mapping-main".to_string(),
            start: 0x7000_0000,
            byte_len: 2,
            content: PageContent::Omitted {
                reason: OmissionReason::Unknown,
                detail: "fixture".to_string(),
            },
        };
        capsule.pages.extend([page.clone(), page]);
        let view = RuntimeMemoryView::new(&capsule, &empty_payloads, "process-main").unwrap();
        assert!(matches!(
            view.read_runtime_bytes(0x7000_0000, 1),
            Err(RuntimeMemoryError::PageAmbiguous { .. })
        ));
    }
}
