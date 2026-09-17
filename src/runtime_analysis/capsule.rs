//! Versioned, provider-neutral process-capsule metadata.
//!
//! `glaurung-process-capsule-v1` deliberately stores payload references rather
//! than captured page bytes. This keeps public metadata separable from sensitive
//! memory while binding every payload by length and SHA-256.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use serde::{Deserialize, Serialize};

use crate::core::binary::{Arch, Endianness};

pub const SCHEMA: &str = "glaurung-process-capsule-v1";
pub const VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessCapsule {
    pub schema: String,
    pub version: u32,
    pub identity: CaptureIdentity,
    #[serde(default)]
    pub required_features: Vec<String>,
    pub target: RuntimeTarget,
    pub executable: ArtifactIdentity,
    #[serde(default)]
    pub processes: Vec<ProcessRecord>,
    #[serde(default)]
    pub modules: Vec<ModuleInstance>,
    #[serde(default)]
    pub mappings: Vec<MappingRecord>,
    #[serde(default)]
    pub threads: Vec<ThreadRecord>,
    #[serde(default)]
    pub pages: Vec<PageRecord>,
    #[serde(default)]
    pub runtime_objects: Vec<RuntimeObjectRecord>,
    #[serde(default)]
    pub object_snapshots: Vec<ObjectSnapshotRecord>,
    #[serde(default)]
    pub outputs: Vec<ProcessOutputRecord>,
    #[serde(default)]
    pub descriptors: Vec<DescriptorRecord>,
    #[serde(default)]
    pub events: Vec<EventRecord>,
    pub provenance: CaptureProvenance,
    #[serde(default)]
    pub completeness: Vec<CompletenessRecord>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureIdentity {
    pub capture_id: String,
    pub acquisition: AcquisitionMode,
    pub host_os: String,
    pub kernel: String,
    pub captured_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionMode {
    Live,
    Core,
    Trace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeTarget {
    pub architecture: Arch,
    pub endianness: Endianness,
    pub address_bits: u8,
    pub os_abi: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactIdentity {
    pub sha256: String,
    pub byte_len: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessRecord {
    pub id: String,
    pub os_pid: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<TerminalState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TerminalState {
    Running,
    Exited { code: i32 },
    Signaled { signal: u32, core_dumped: bool },
    Unknown { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleInstance {
    pub id: String,
    pub process_id: String,
    pub artifact: ArtifactIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_bias: Option<u64>,
    #[serde(default)]
    pub mapping_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingRecord {
    pub id: String,
    pub process_id: String,
    pub start: u64,
    pub end: u64,
    pub permissions: Permissions,
    pub backing: MappingBacking,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_offset: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub private: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MappingBacking {
    File {
        artifact_sha256: String,
        deleted: bool,
    },
    Anonymous,
    Special {
        name: String,
    },
    Unknown {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadRecord {
    pub id: String,
    pub process_id: String,
    pub os_tid: u64,
    #[serde(default)]
    pub registers: Vec<RegisterObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault: Option<FaultRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterObservation {
    /// Provider spelling. Projection into target storage is a later relation.
    pub provider_name: String,
    pub bit_width: u16,
    pub value_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultRecord {
    pub signal: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_pid: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_uid: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<AccessKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessKind {
    Read,
    Write,
    Execute,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRecord {
    pub process_id: String,
    pub mapping_id: String,
    pub start: u64,
    pub byte_len: u64,
    pub content: PageContent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PageContent {
    Captured {
        payload: PayloadReference,
    },
    Omitted {
        reason: OmissionReason,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadReference {
    pub id: String,
    pub sha256: String,
    pub byte_len: u64,
    pub sensitivity: Sensitivity,
}

/// One runtime allocation/storage instance, distinct from a decompiler variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeObjectRecord {
    pub id: String,
    pub process_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping_id: Option<String>,
    pub kind: RuntimeObjectKind,
    pub start: u64,
    pub byte_len: u64,
    pub created_at: EventPosition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<EventPosition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeObjectKind {
    Stack,
    Global,
    Heap,
    Mapping,
    Unknown,
}

/// A position in one process/thread event stream, not a wall-clock timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPosition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    pub sequence: u64,
}

/// Captured bytes for an interval within one runtime object at one event point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSnapshotRecord {
    pub id: String,
    pub process_id: String,
    pub object_id: String,
    pub point: EventPosition,
    pub object_offset: u64,
    pub byte_len: u64,
    pub content: PageContent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessOutputRecord {
    pub process_id: String,
    pub stream: OutputStream,
    pub payload: PayloadReference,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    Sensitive,
    Secret,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmissionReason {
    NotRequested,
    Budget,
    PermissionDenied,
    Unreadable,
    Raced,
    Redacted,
    ProviderUnsupported,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorRecord {
    pub process_id: String,
    pub number: u64,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default)]
    pub redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    pub process_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<u64>,
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureProvenance {
    pub producer: String,
    pub producer_version: String,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub input_artifacts: Vec<ArtifactIdentity>,
    #[serde(default)]
    pub input_bytes: Vec<InputBytesIdentity>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputBytesIdentity {
    /// Provider-scoped role such as `argv[1]` or `stdin`--never the bytes.
    pub name: String,
    pub sha256: String,
    pub byte_len: u64,
    pub sensitivity: Sensitivity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletenessRecord {
    pub evidence: String,
    pub status: CompletenessStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub requested: bool,
    pub obtained: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletenessStatus {
    Complete,
    Partial,
    Omitted,
    Denied,
    Raced,
    Unsupported,
    Truncated,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapsuleLimits {
    pub max_manifest_bytes: usize,
    pub max_processes: usize,
    pub max_modules: usize,
    pub max_mappings: usize,
    pub max_threads: usize,
    pub max_pages: usize,
    pub max_runtime_objects: usize,
    pub max_object_snapshots: usize,
    pub max_outputs: usize,
    pub max_descriptors: usize,
    pub max_events: usize,
    pub max_extensions: usize,
    pub max_page_bytes: u64,
    pub max_object_snapshot_bytes: u64,
    pub max_output_bytes: u64,
}

impl Default for CapsuleLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 64 * 1024 * 1024,
            max_processes: 1_024,
            max_modules: 16_384,
            max_mappings: 1_000_000,
            max_threads: 65_536,
            max_pages: 1_000_000,
            max_runtime_objects: 1_000_000,
            max_object_snapshots: 1_000_000,
            max_outputs: 2_048,
            max_descriptors: 1_000_000,
            max_events: 10_000_000,
            max_extensions: 1_024,
            max_page_bytes: 1 << 40,
            max_object_snapshot_bytes: 1 << 40,
            max_output_bytes: 16 * 1024 * 1024,
        }
    }
}

impl ProcessCapsule {
    pub fn from_json(bytes: &[u8], limits: CapsuleLimits) -> Result<Self, String> {
        if bytes.len() > limits.max_manifest_bytes {
            return Err(format!(
                "process capsule manifest bytes {} exceed limit {}",
                bytes.len(),
                limits.max_manifest_bytes
            ));
        }
        let capsule: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("parse process capsule: {error}"))?;
        capsule.validate(limits)?;
        Ok(capsule)
    }

    pub fn to_canonical_json(&self, limits: CapsuleLimits) -> Result<Vec<u8>, String> {
        self.validate(limits)?;
        let capsule = self.normalized();
        let mut bytes = serde_json::to_vec(&capsule)
            .map_err(|error| format!("serialize process capsule: {error}"))?;
        bytes.push(b'\n');
        if bytes.len() > limits.max_manifest_bytes {
            return Err(format!(
                "serialized process capsule bytes {} exceed limit {}",
                bytes.len(),
                limits.max_manifest_bytes
            ));
        }
        Ok(bytes)
    }

    pub fn from_cbor(bytes: &[u8], limits: CapsuleLimits) -> Result<Self, String> {
        if bytes.len() > limits.max_manifest_bytes {
            return Err(format!(
                "process capsule manifest bytes {} exceed limit {}",
                bytes.len(),
                limits.max_manifest_bytes
            ));
        }
        let mut reader = Cursor::new(bytes);
        let capsule: Self = ciborium::from_reader(&mut reader)
            .map_err(|error| format!("parse CBOR process capsule: {error}"))?;
        if reader.position() != bytes.len() as u64 {
            return Err("parse CBOR process capsule: trailing bytes".to_string());
        }
        capsule.validate(limits)?;
        Ok(capsule)
    }

    pub fn to_canonical_cbor(&self, limits: CapsuleLimits) -> Result<Vec<u8>, String> {
        self.validate(limits)?;
        let capsule = self.normalized();
        let mut bytes = Vec::new();
        ciborium::into_writer(&capsule, &mut bytes)
            .map_err(|error| format!("serialize CBOR process capsule: {error}"))?;
        if bytes.len() > limits.max_manifest_bytes {
            return Err(format!(
                "serialized process capsule bytes {} exceed limit {}",
                bytes.len(),
                limits.max_manifest_bytes
            ));
        }
        Ok(bytes)
    }

    fn normalized(&self) -> Self {
        let mut capsule = self.clone();
        capsule.required_features.sort();
        capsule.processes.sort_by(|a, b| a.id.cmp(&b.id));
        capsule.modules.sort_by(|a, b| a.id.cmp(&b.id));
        capsule.mappings.sort_by(|a, b| a.id.cmp(&b.id));
        capsule.threads.sort_by(|a, b| a.id.cmp(&b.id));
        capsule
            .pages
            .sort_by_key(|page| (page.process_id.clone(), page.start));
        capsule.runtime_objects.sort_by(|a, b| a.id.cmp(&b.id));
        capsule.object_snapshots.sort_by(|a, b| a.id.cmp(&b.id));
        capsule
            .descriptors
            .sort_by_key(|descriptor| (descriptor.process_id.clone(), descriptor.number));
        capsule.events.sort_by_key(|event| {
            (
                event.process_id.clone(),
                event.thread_id.clone(),
                event.sequence,
            )
        });
        capsule
            .completeness
            .sort_by(|a, b| a.evidence.cmp(&b.evidence));
        capsule.provenance.input_artifacts.sort_by(|a, b| {
            (&a.sha256, &a.display_path, a.byte_len).cmp(&(&b.sha256, &b.display_path, b.byte_len))
        });
        capsule
            .provenance
            .input_bytes
            .sort_by(|a, b| a.name.cmp(&b.name));
        capsule
    }

    pub fn validate(&self, limits: CapsuleLimits) -> Result<(), String> {
        if self.schema != SCHEMA || self.version != VERSION {
            return Err(format!(
                "unsupported process capsule {} v{}",
                self.schema, self.version
            ));
        }
        if !self.required_features.is_empty() {
            return Err(format!(
                "unsupported required process-capsule features: {}",
                self.required_features.join(", ")
            ));
        }
        require_text("capture_id", &self.identity.capture_id)?;
        require_text("host_os", &self.identity.host_os)?;
        require_text("kernel", &self.identity.kernel)?;
        require_text("captured_at", &self.identity.captured_at)?;
        validate_artifact("executable", &self.executable)?;
        if !matches!(self.target.address_bits, 16 | 32 | 64) {
            return Err(format!(
                "unsupported runtime address width {}",
                self.target.address_bits
            ));
        }
        check_count("processes", self.processes.len(), limits.max_processes)?;
        check_count("modules", self.modules.len(), limits.max_modules)?;
        check_count("mappings", self.mappings.len(), limits.max_mappings)?;
        check_count("threads", self.threads.len(), limits.max_threads)?;
        check_count("pages", self.pages.len(), limits.max_pages)?;
        check_count(
            "runtime_objects",
            self.runtime_objects.len(),
            limits.max_runtime_objects,
        )?;
        check_count(
            "object_snapshots",
            self.object_snapshots.len(),
            limits.max_object_snapshots,
        )?;
        check_count("outputs", self.outputs.len(), limits.max_outputs)?;
        check_count(
            "descriptors",
            self.descriptors.len(),
            limits.max_descriptors,
        )?;
        check_count("events", self.events.len(), limits.max_events)?;
        check_count("extensions", self.extensions.len(), limits.max_extensions)?;

        let process_ids = unique_ids("process", self.processes.iter().map(|item| &item.id))?;
        if process_ids.is_empty() {
            return Err("process capsule contains no process".to_string());
        }
        for process in &self.processes {
            if let Some(parent) = &process.parent_id {
                require_ref("parent process", parent, &process_ids)?;
                if parent == &process.id {
                    return Err(format!("process {} is its own parent", process.id));
                }
            }
        }
        let module_ids = unique_ids("module", self.modules.iter().map(|item| &item.id))?;
        let mapping_ids = unique_ids("mapping", self.mappings.iter().map(|item| &item.id))?;
        let thread_ids = unique_ids("thread", self.threads.iter().map(|item| &item.id))?;
        for module in &self.modules {
            require_ref("module process", &module.process_id, &process_ids)?;
            validate_artifact("module artifact", &module.artifact)?;
            for mapping in &module.mapping_ids {
                require_ref("module mapping", mapping, &mapping_ids)?;
                let mapped = self
                    .mappings
                    .iter()
                    .find(|candidate| candidate.id == *mapping)
                    .expect("validated mapping id exists");
                if mapped.process_id != module.process_id
                    || mapped.module_id.as_deref() != Some(module.id.as_str())
                {
                    return Err(format!(
                        "module {} mapping {} has inconsistent ownership",
                        module.id, mapping
                    ));
                }
            }
        }
        for mapping in &self.mappings {
            require_ref("mapping process", &mapping.process_id, &process_ids)?;
            if mapping.start >= mapping.end {
                return Err(format!(
                    "mapping {} has an empty or reversed range",
                    mapping.id
                ));
            }
            if let Some(module) = &mapping.module_id {
                require_ref("mapping module", module, &module_ids)?;
            }
            if let MappingBacking::File {
                artifact_sha256, ..
            } = &mapping.backing
            {
                validate_sha256("mapping artifact", artifact_sha256)?;
                if mapping.file_offset.is_none() {
                    return Err(format!("file mapping {} has no file offset", mapping.id));
                }
            }
        }
        for thread in &self.threads {
            require_ref("thread process", &thread.process_id, &process_ids)?;
            for register in &thread.registers {
                require_text("register provider_name", &register.provider_name)?;
                if register.bit_width == 0 || !is_lower_hex(&register.value_hex) {
                    return Err(format!(
                        "register {} has invalid width or value",
                        register.provider_name
                    ));
                }
                let expected_digits = usize::from(register.bit_width).div_ceil(4);
                if register.value_hex.len() != expected_digits {
                    return Err(format!(
                        "register {} value width does not match {} bits",
                        register.provider_name, register.bit_width
                    ));
                }
            }
        }
        let object_ids = unique_ids(
            "runtime object",
            self.runtime_objects.iter().map(|item| &item.id),
        )?;
        for object in &self.runtime_objects {
            require_ref("runtime object process", &object.process_id, &process_ids)?;
            let object_end = object
                .start
                .checked_add(object.byte_len)
                .ok_or_else(|| format!("runtime object {} range overflowed", object.id))?;
            if object.byte_len == 0 {
                return Err(format!("runtime object {} has zero length", object.id));
            }
            if let Some(mapping_id) = &object.mapping_id {
                require_ref("runtime object mapping", mapping_id, &mapping_ids)?;
                let mapping = self
                    .mappings
                    .iter()
                    .find(|candidate| candidate.id == *mapping_id)
                    .expect("validated mapping id exists");
                if mapping.process_id != object.process_id
                    || object.start < mapping.start
                    || object_end > mapping.end
                {
                    return Err(format!(
                        "runtime object {} is outside mapping {}",
                        object.id, mapping_id
                    ));
                }
            }
            for point in [
                &object.created_at,
                object.ended_at.as_ref().unwrap_or(&object.created_at),
            ] {
                if let Some(thread_id) = &point.thread_id {
                    require_ref("runtime object event thread", thread_id, &thread_ids)?;
                    let owner = self
                        .threads
                        .iter()
                        .find(|candidate| candidate.id == *thread_id)
                        .map(|candidate| candidate.process_id.as_str());
                    if owner != Some(object.process_id.as_str()) {
                        return Err(format!(
                            "runtime object {} event thread has inconsistent ownership",
                            object.id
                        ));
                    }
                }
            }
            if let Some(ended) = &object.ended_at {
                if ended.thread_id == object.created_at.thread_id
                    && ended.sequence < object.created_at.sequence
                {
                    return Err(format!(
                        "runtime object {} ends before it is created",
                        object.id
                    ));
                }
            }
        }
        let mut page_bytes = 0u64;
        let mut payload_ids = BTreeSet::new();
        for page in &self.pages {
            require_ref("page process", &page.process_id, &process_ids)?;
            require_ref("page mapping", &page.mapping_id, &mapping_ids)?;
            if page.byte_len == 0 || page.start.checked_add(page.byte_len).is_none() {
                return Err("page has empty or overflowing range".to_string());
            }
            let mapping = self
                .mappings
                .iter()
                .find(|candidate| candidate.id == page.mapping_id)
                .expect("validated mapping id exists");
            let page_end = page.start + page.byte_len;
            if mapping.process_id != page.process_id
                || page.start < mapping.start
                || page_end > mapping.end
            {
                return Err(format!(
                    "page at {:#x}..{:#x} is outside mapping {}",
                    page.start, page_end, page.mapping_id
                ));
            }
            page_bytes = page_bytes
                .checked_add(page.byte_len)
                .ok_or_else(|| "captured page byte count overflowed".to_string())?;
            if let PageContent::Captured { payload } = &page.content {
                require_text("payload id", &payload.id)?;
                if !payload_ids.insert(payload.id.clone()) {
                    return Err(format!("duplicate payload id: {}", payload.id));
                }
                validate_sha256("payload", &payload.sha256)?;
                if payload.byte_len != page.byte_len {
                    return Err(format!("payload {} length does not match page", payload.id));
                }
            }
        }
        let snapshot_ids = unique_ids(
            "object snapshot",
            self.object_snapshots.iter().map(|item| &item.id),
        )?;
        debug_assert_eq!(snapshot_ids.len(), self.object_snapshots.len());
        let mut snapshot_bytes = 0u64;
        for snapshot in &self.object_snapshots {
            require_ref(
                "object snapshot process",
                &snapshot.process_id,
                &process_ids,
            )?;
            require_ref("object snapshot object", &snapshot.object_id, &object_ids)?;
            let object = self
                .runtime_objects
                .iter()
                .find(|candidate| candidate.id == snapshot.object_id)
                .expect("validated runtime object id exists");
            if object.process_id != snapshot.process_id {
                return Err(format!(
                    "object snapshot {} has inconsistent process ownership",
                    snapshot.id
                ));
            }
            let snapshot_end = snapshot
                .object_offset
                .checked_add(snapshot.byte_len)
                .ok_or_else(|| format!("object snapshot {} range overflowed", snapshot.id))?;
            if snapshot.byte_len == 0 || snapshot_end > object.byte_len {
                return Err(format!(
                    "object snapshot {} is outside runtime object {}",
                    snapshot.id, object.id
                ));
            }
            if let Some(thread_id) = &snapshot.point.thread_id {
                require_ref("object snapshot event thread", thread_id, &thread_ids)?;
                let owner = self
                    .threads
                    .iter()
                    .find(|candidate| candidate.id == *thread_id)
                    .map(|candidate| candidate.process_id.as_str());
                if owner != Some(snapshot.process_id.as_str()) {
                    return Err(format!(
                        "object snapshot {} event thread has inconsistent ownership",
                        snapshot.id
                    ));
                }
            }
            if snapshot.point.thread_id == object.created_at.thread_id
                && snapshot.point.sequence < object.created_at.sequence
            {
                return Err(format!(
                    "object snapshot {} precedes runtime object creation",
                    snapshot.id
                ));
            }
            if let Some(ended) = &object.ended_at {
                if snapshot.point.thread_id == ended.thread_id
                    && snapshot.point.sequence > ended.sequence
                {
                    return Err(format!(
                        "object snapshot {} follows runtime object destruction",
                        snapshot.id
                    ));
                }
            }
            snapshot_bytes = snapshot_bytes
                .checked_add(snapshot.byte_len)
                .ok_or_else(|| "object snapshot byte count overflowed".to_string())?;
            if let PageContent::Captured { payload } = &snapshot.content {
                if payload.byte_len != snapshot.byte_len {
                    return Err(format!(
                        "payload {} length does not match object snapshot",
                        payload.id
                    ));
                }
                require_text("payload id", &payload.id)?;
                validate_sha256("payload", &payload.sha256)?;
                if !payload_ids.insert(payload.id.clone()) {
                    return Err(format!("duplicate payload id: {}", payload.id));
                }
            }
        }
        let mut output_bytes = 0u64;
        let mut output_streams = BTreeSet::new();
        for output in &self.outputs {
            require_ref("output process", &output.process_id, &process_ids)?;
            if !output_streams.insert((output.process_id.as_str(), output.stream)) {
                return Err(format!(
                    "duplicate {:?} output for process {}",
                    output.stream, output.process_id
                ));
            }
            require_text("output payload id", &output.payload.id)?;
            validate_sha256("output payload", &output.payload.sha256)?;
            if !payload_ids.insert(output.payload.id.clone()) {
                return Err(format!("duplicate payload id: {}", output.payload.id));
            }
            output_bytes = output_bytes
                .checked_add(output.payload.byte_len)
                .ok_or_else(|| "captured output byte count overflowed".to_string())?;
        }
        if page_bytes > limits.max_page_bytes {
            return Err(format!(
                "page bytes {page_bytes} exceed limit {}",
                limits.max_page_bytes
            ));
        }
        if snapshot_bytes > limits.max_object_snapshot_bytes {
            return Err(format!(
                "object snapshot bytes {snapshot_bytes} exceed limit {}",
                limits.max_object_snapshot_bytes
            ));
        }
        if output_bytes > limits.max_output_bytes {
            return Err(format!(
                "output bytes {output_bytes} exceed limit {}",
                limits.max_output_bytes
            ));
        }
        for descriptor in &self.descriptors {
            require_ref("descriptor process", &descriptor.process_id, &process_ids)?;
            require_text("descriptor kind", &descriptor.kind)?;
        }
        let mut sequences: BTreeMap<(&str, Option<&str>), u64> = BTreeMap::new();
        for event in &self.events {
            require_ref("event process", &event.process_id, &process_ids)?;
            if let Some(thread) = &event.thread_id {
                require_ref("event thread", thread, &thread_ids)?;
                let owner = self
                    .threads
                    .iter()
                    .find(|candidate| candidate.id == *thread)
                    .map(|candidate| candidate.process_id.as_str());
                if owner != Some(event.process_id.as_str()) {
                    return Err(format!(
                        "event thread {thread} does not belong to process {}",
                        event.process_id
                    ));
                }
            }
            require_text("event kind", &event.kind)?;
            let key = (event.process_id.as_str(), event.thread_id.as_deref());
            if let Some(previous) = sequences.insert(key, event.sequence) {
                if event.sequence <= previous {
                    return Err(format!("event sequence is not increasing for {key:?}"));
                }
            }
        }
        let event_positions: BTreeSet<_> = self
            .events
            .iter()
            .map(|event| {
                (
                    event.process_id.as_str(),
                    event.thread_id.as_deref(),
                    event.sequence,
                )
            })
            .collect();
        for object in &self.runtime_objects {
            for point in std::iter::once(&object.created_at).chain(object.ended_at.iter()) {
                if !event_positions.contains(&(
                    object.process_id.as_str(),
                    point.thread_id.as_deref(),
                    point.sequence,
                )) {
                    return Err(format!(
                        "runtime object {} references a missing event position",
                        object.id
                    ));
                }
            }
        }
        for snapshot in &self.object_snapshots {
            if !event_positions.contains(&(
                snapshot.process_id.as_str(),
                snapshot.point.thread_id.as_deref(),
                snapshot.point.sequence,
            )) {
                return Err(format!(
                    "object snapshot {} references a missing event position",
                    snapshot.id
                ));
            }
        }
        require_text("provenance producer", &self.provenance.producer)?;
        require_text(
            "provenance producer_version",
            &self.provenance.producer_version,
        )?;
        for artifact in &self.provenance.input_artifacts {
            validate_artifact("provenance input artifact", artifact)?;
        }
        let mut input_names = BTreeSet::new();
        for input in &self.provenance.input_bytes {
            require_text("provenance input name", &input.name)?;
            if !input_names.insert(&input.name) {
                return Err(format!("duplicate provenance input name: {}", input.name));
            }
            validate_sha256("provenance input", &input.sha256)?;
        }
        let mut evidence = BTreeSet::new();
        for record in &self.completeness {
            require_text("completeness evidence", &record.evidence)?;
            if !evidence.insert(&record.evidence) {
                return Err(format!(
                    "duplicate completeness evidence: {}",
                    record.evidence
                ));
            }
            if matches!(record.status, CompletenessStatus::Complete)
                && record
                    .expected
                    .is_some_and(|expected| record.obtained != expected)
            {
                return Err(format!(
                    "complete evidence {} did not obtain its expected count",
                    record.evidence
                ));
            }
        }
        Ok(())
    }
}

fn validate_artifact(label: &str, artifact: &ArtifactIdentity) -> Result<(), String> {
    validate_sha256(label, &artifact.sha256)?;
    if artifact.byte_len == 0 {
        return Err(format!("{label} has zero length"));
    }
    Ok(())
}

fn validate_sha256(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 64 || !is_lower_hex(value) {
        return Err(format!("{label} has invalid SHA-256"));
    }
    Ok(())
}

fn is_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require_text(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 16_384 || value.contains('\0') {
        return Err(format!("{label} is empty, oversized, or contains NUL"));
    }
    Ok(())
}

fn unique_ids<'a>(
    label: &str,
    values: impl Iterator<Item = &'a String>,
) -> Result<BTreeSet<String>, String> {
    let mut ids = BTreeSet::new();
    for value in values {
        require_text(&format!("{label} id"), value)?;
        if !ids.insert(value.clone()) {
            return Err(format!("duplicate {label} id: {value}"));
        }
    }
    Ok(ids)
}

fn require_ref(label: &str, value: &str, ids: &BTreeSet<String>) -> Result<(), String> {
    if !ids.contains(value) {
        return Err(format!("{label} references missing id: {value}"));
    }
    Ok(())
}

fn check_count(label: &str, actual: usize, limit: usize) -> Result<(), String> {
    if actual > limit {
        return Err(format!("{label} count {actual} exceeds limit {limit}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(digit: char) -> ArtifactIdentity {
        ArtifactIdentity {
            sha256: digit.to_string().repeat(64),
            byte_len: 4_096,
            build_id: Some("fixture-build-id".to_string()),
            display_path: Some("runtime-fixture".to_string()),
        }
    }

    fn fixture() -> ProcessCapsule {
        ProcessCapsule {
            schema: SCHEMA.to_string(),
            version: VERSION,
            identity: CaptureIdentity {
                capture_id: "capture-1".to_string(),
                acquisition: AcquisitionMode::Core,
                host_os: "linux".to_string(),
                kernel: "fixture".to_string(),
                captured_at: "1970-01-01T00:00:00Z".to_string(),
            },
            required_features: Vec::new(),
            target: RuntimeTarget {
                architecture: Arch::X86_64,
                endianness: Endianness::Little,
                address_bits: 64,
                os_abi: "linux".to_string(),
            },
            executable: artifact('a'),
            processes: vec![ProcessRecord {
                id: "process-1".to_string(),
                os_pid: 123,
                parent_id: None,
                terminal: Some(TerminalState::Signaled {
                    signal: 11,
                    core_dumped: true,
                }),
            }],
            modules: vec![ModuleInstance {
                id: "module-1".to_string(),
                process_id: "process-1".to_string(),
                artifact: artifact('a'),
                load_bias: Some(0x5555_0000),
                mapping_ids: vec!["mapping-1".to_string()],
            }],
            mappings: vec![MappingRecord {
                id: "mapping-1".to_string(),
                process_id: "process-1".to_string(),
                start: 0x5555_0000,
                end: 0x5555_1000,
                permissions: Permissions {
                    read: true,
                    execute: true,
                    ..Permissions::default()
                },
                backing: MappingBacking::File {
                    artifact_sha256: "a".repeat(64),
                    deleted: false,
                },
                module_id: Some("module-1".to_string()),
                file_offset: Some(0),
            }],
            threads: vec![ThreadRecord {
                id: "thread-1".to_string(),
                process_id: "process-1".to_string(),
                os_tid: 123,
                registers: vec![RegisterObservation {
                    provider_name: "rip".to_string(),
                    bit_width: 64,
                    value_hex: "0000000055550010".to_string(),
                }],
                fault: Some(FaultRecord {
                    signal: 11,
                    code: Some(1),
                    sender_pid: None,
                    sender_uid: None,
                    address: Some(0),
                    access: Some(AccessKind::Write),
                }),
            }],
            pages: vec![PageRecord {
                process_id: "process-1".to_string(),
                mapping_id: "mapping-1".to_string(),
                start: 0x5555_0000,
                byte_len: 4_096,
                content: PageContent::Captured {
                    payload: PayloadReference {
                        id: "page-1".to_string(),
                        sha256: "b".repeat(64),
                        byte_len: 4_096,
                        sensitivity: Sensitivity::Sensitive,
                    },
                },
            }],
            runtime_objects: Vec::new(),
            object_snapshots: Vec::new(),
            outputs: Vec::new(),
            descriptors: vec![DescriptorRecord {
                process_id: "process-1".to_string(),
                number: 3,
                kind: "file".to_string(),
                target: Some("input.txt".to_string()),
                redacted: false,
            }],
            events: vec![EventRecord {
                process_id: "process-1".to_string(),
                thread_id: Some("thread-1".to_string()),
                sequence: 1,
                kind: "terminal_fault".to_string(),
                address: Some(0x5555_0010),
                fields: BTreeMap::from([("signal".to_string(), "SIGSEGV".to_string())]),
            }],
            provenance: CaptureProvenance {
                producer: "glaurung-test".to_string(),
                producer_version: "1".to_string(),
                command: vec!["fixture".to_string()],
                input_artifacts: vec![artifact('a')],
                input_bytes: vec![InputBytesIdentity {
                    name: "argv[1]".to_string(),
                    sha256: "b".repeat(64),
                    byte_len: 3,
                    sensitivity: Sensitivity::Public,
                }],
                warnings: Vec::new(),
            },
            completeness: vec![CompletenessRecord {
                evidence: "threads".to_string(),
                status: CompletenessStatus::Complete,
                reason: None,
                requested: true,
                obtained: 1,
                expected: Some(1),
            }],
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn capsule_round_trip_is_canonical_across_input_order() {
        let capsule = fixture();
        let first = capsule
            .to_canonical_json(CapsuleLimits::default())
            .expect("serialize fixture capsule");
        let parsed = ProcessCapsule::from_json(&first, CapsuleLimits::default())
            .expect("parse fixture capsule");
        let second = parsed
            .to_canonical_json(CapsuleLimits::default())
            .expect("re-serialize fixture capsule");
        assert_eq!(first, second);
    }

    #[test]
    fn capsule_cbor_round_trip_is_canonical_and_rejects_trailing_data() {
        let capsule = fixture();
        let first = capsule
            .to_canonical_cbor(CapsuleLimits::default())
            .expect("serialize fixture capsule as CBOR");
        let parsed = ProcessCapsule::from_cbor(&first, CapsuleLimits::default())
            .expect("parse fixture CBOR capsule");
        let second = parsed
            .to_canonical_cbor(CapsuleLimits::default())
            .expect("re-serialize fixture CBOR capsule");
        assert_eq!(first, second);

        let mut trailing = first;
        trailing.push(0);
        let error = ProcessCapsule::from_cbor(&trailing, CapsuleLimits::default())
            .expect_err("trailing CBOR item must fail");
        assert!(error.contains("trailing bytes"));
    }

    #[test]
    fn runtime_objects_and_snapshots_are_time_scoped_and_bounded() {
        let mut capsule = fixture();
        capsule.events = (1..=4)
            .map(|sequence| EventRecord {
                process_id: "process-1".to_string(),
                thread_id: Some("thread-1".to_string()),
                sequence,
                kind: match sequence {
                    1 => "allocation",
                    4 => "deallocation",
                    _ => "object_snapshot",
                }
                .to_string(),
                address: Some(0x5555_0080),
                fields: BTreeMap::new(),
            })
            .collect();
        capsule.runtime_objects.push(RuntimeObjectRecord {
            id: "object-1".to_string(),
            process_id: "process-1".to_string(),
            mapping_id: Some("mapping-1".to_string()),
            kind: RuntimeObjectKind::Heap,
            start: 0x5555_0080,
            byte_len: 16,
            created_at: EventPosition {
                thread_id: Some("thread-1".to_string()),
                sequence: 1,
            },
            ended_at: Some(EventPosition {
                thread_id: Some("thread-1".to_string()),
                sequence: 4,
            }),
        });
        for (id, sequence, digit) in [("before", 2, 'c'), ("after", 3, 'd')] {
            capsule.object_snapshots.push(ObjectSnapshotRecord {
                id: id.to_string(),
                process_id: "process-1".to_string(),
                object_id: "object-1".to_string(),
                point: EventPosition {
                    thread_id: Some("thread-1".to_string()),
                    sequence,
                },
                object_offset: 0,
                byte_len: 16,
                content: PageContent::Captured {
                    payload: PayloadReference {
                        id: format!("object-{id}"),
                        sha256: digit.to_string().repeat(64),
                        byte_len: 16,
                        sensitivity: Sensitivity::Sensitive,
                    },
                },
            });
        }
        capsule
            .to_canonical_json(CapsuleLimits::default())
            .expect("time-scoped object snapshots validate");

        let mut outside = capsule.clone();
        outside.object_snapshots[1].object_offset = 8;
        outside.object_snapshots[1].byte_len = 16;
        assert!(outside
            .validate(CapsuleLimits::default())
            .expect_err("snapshot beyond object must fail")
            .contains("outside runtime object"));

        let mut after_lifetime = capsule.clone();
        after_lifetime.object_snapshots[1].point.sequence = 5;
        assert!(after_lifetime
            .validate(CapsuleLimits::default())
            .expect_err("snapshot after destruction must fail")
            .contains("follows runtime object destruction"));

        capsule.events.retain(|event| event.sequence != 3);
        assert!(capsule
            .validate(CapsuleLimits::default())
            .expect_err("snapshot without event position must fail")
            .contains("missing event position"));
    }

    #[test]
    fn capsule_json_and_cbor_decode_to_the_same_model_and_share_budgets() {
        let capsule = fixture();
        let limits = CapsuleLimits::default();
        let json = capsule
            .to_canonical_json(limits)
            .expect("serialize fixture JSON");
        let cbor = capsule
            .to_canonical_cbor(limits)
            .expect("serialize fixture CBOR");
        assert_eq!(
            ProcessCapsule::from_json(&json, limits).expect("parse fixture JSON"),
            ProcessCapsule::from_cbor(&cbor, limits).expect("parse fixture CBOR")
        );

        let tight = CapsuleLimits {
            max_manifest_bytes: cbor.len() - 1,
            ..limits
        };
        let error = ProcessCapsule::from_cbor(&cbor, tight)
            .expect_err("CBOR manifest budget must fail closed");
        assert!(error.contains("manifest bytes"));

        let truncated = &cbor[..cbor.len() - 1];
        ProcessCapsule::from_cbor(truncated, limits)
            .expect_err("truncated CBOR manifest must fail closed");
    }

    #[test]
    fn missing_page_payload_is_explicit_and_valid() {
        let mut capsule = fixture();
        capsule.pages[0].content = PageContent::Omitted {
            reason: OmissionReason::PermissionDenied,
            detail: "process_vm_readv denied".to_string(),
        };
        capsule
            .validate(CapsuleLimits::default())
            .expect("explicit omission is valid evidence");
    }

    #[test]
    fn cross_process_references_fail_closed() {
        let mut capsule = fixture();
        capsule.events[0].process_id = "missing-process".to_string();
        let error = capsule
            .validate(CapsuleLimits::default())
            .expect_err("missing process reference must fail");
        assert!(error.contains("references missing id"));
    }

    #[test]
    fn required_unknown_feature_is_rejected() {
        let mut capsule = fixture();
        capsule
            .required_features
            .push("future-memory-v2".to_string());
        let error = capsule
            .validate(CapsuleLimits::default())
            .expect_err("required feature must fail");
        assert!(error.contains("unsupported required"));
    }

    #[test]
    fn payload_length_and_hash_are_validated() {
        let mut capsule = fixture();
        let PageContent::Captured { payload } = &mut capsule.pages[0].content else {
            unreachable!()
        };
        payload.byte_len = 1;
        let error = capsule
            .validate(CapsuleLimits::default())
            .expect_err("payload mismatch must fail");
        assert!(error.contains("length does not match"));
    }

    #[test]
    fn provenance_inputs_require_unique_names_and_valid_hashes() {
        let mut capsule = fixture();
        let duplicate = capsule.provenance.input_bytes[0].clone();
        capsule.provenance.input_bytes.push(duplicate);
        let error = capsule
            .validate(CapsuleLimits::default())
            .expect_err("duplicate input role must fail");
        assert!(error.contains("duplicate provenance input name"));

        let mut capsule = fixture();
        capsule.provenance.input_bytes[0].sha256 = "not-a-hash".to_string();
        let error = capsule
            .validate(CapsuleLimits::default())
            .expect_err("invalid input hash must fail");
        assert!(error.contains("provenance input has invalid SHA-256"));
    }

    #[test]
    fn event_sequences_are_per_thread_and_strictly_increasing() {
        let mut capsule = fixture();
        capsule.events.push(capsule.events[0].clone());
        let error = capsule
            .validate(CapsuleLimits::default())
            .expect_err("duplicate sequence must fail");
        assert!(error.contains("not increasing"));
    }

    #[test]
    fn count_and_byte_budgets_fail_closed() {
        let capsule = fixture();
        let limits = CapsuleLimits {
            max_page_bytes: 1,
            ..CapsuleLimits::default()
        };
        let error = capsule.validate(limits).expect_err("page budget must fail");
        assert!(error.contains("page bytes"));
    }

    #[test]
    fn process_outputs_are_scoped_unique_and_independently_bounded() {
        let mut capsule = fixture();
        capsule.outputs.push(ProcessOutputRecord {
            process_id: "process-1".to_string(),
            stream: OutputStream::Stderr,
            payload: PayloadReference {
                id: "process-output-stderr".to_string(),
                sha256: "d".repeat(64),
                byte_len: 10,
                sensitivity: Sensitivity::Sensitive,
            },
            truncated: false,
        });
        capsule
            .validate(CapsuleLimits::default())
            .expect("one bounded output is valid");

        let limits = CapsuleLimits {
            max_output_bytes: 9,
            ..CapsuleLimits::default()
        };
        let error = capsule
            .validate(limits)
            .expect_err("output byte budget must fail closed");
        assert!(error.contains("output bytes"));

        capsule.outputs.push(capsule.outputs[0].clone());
        let error = capsule
            .validate(CapsuleLimits::default())
            .expect_err("duplicate process stream must fail closed");
        assert!(error.contains("duplicate Stderr output"));
    }

    #[test]
    fn page_must_belong_to_its_process_mapping() {
        let mut capsule = fixture();
        capsule.pages[0].start = 0x4444_0000;
        let error = capsule
            .validate(CapsuleLimits::default())
            .expect_err("out-of-mapping page must fail");
        assert!(error.contains("outside mapping"));
    }

    #[test]
    fn unknown_optional_extension_round_trips() {
        let mut value = serde_json::to_value(fixture()).expect("serialize fixture");
        value["provider.example"] = serde_json::json!({"future": true});
        let bytes = serde_json::to_vec(&value).expect("serialize extended fixture");
        let capsule = ProcessCapsule::from_json(&bytes, CapsuleLimits::default())
            .expect("optional extension imports");
        assert_eq!(
            capsule.extensions["provider.example"],
            serde_json::json!({"future": true})
        );
        let exported = capsule
            .to_canonical_json(CapsuleLimits::default())
            .expect("export extended fixture");
        assert!(String::from_utf8(exported)
            .expect("JSON is UTF-8")
            .contains("provider.example"));
    }

    #[test]
    fn manifest_size_budget_is_checked_before_parse() {
        let bytes = vec![b' '; 128];
        let limits = CapsuleLimits {
            max_manifest_bytes: 64,
            ..CapsuleLimits::default()
        };
        let error = ProcessCapsule::from_json(&bytes, limits)
            .expect_err("oversized manifest must fail before parsing");
        assert!(error.contains("manifest bytes"));
    }
}
