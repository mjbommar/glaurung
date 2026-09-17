//! Provider-neutral OS behavior derived from ordered capsule events.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::capsule::{CompletenessStatus, ProcessCapsule};
use super::crash::Evidence;

pub const MAPPING_BEHAVIOR_REPORT_SCHEMA: &str = "glaurung-runtime-mapping-behavior-report-v1";
pub const FILE_BEHAVIOR_REPORT_SCHEMA: &str = "glaurung-runtime-file-behavior-report-v1";
pub const DESCRIPTOR_BEHAVIOR_REPORT_SCHEMA: &str =
    "glaurung-runtime-descriptor-behavior-report-v1";
pub const PROCESS_BEHAVIOR_REPORT_SCHEMA: &str = "glaurung-runtime-process-behavior-report-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcessCreateOutcome {
    Success { child_os_pid: u64 },
    Failure { errno: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessCreateObservation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub caller_os_tid: u64,
    pub provider_syscall: String,
    pub outcome: Evidence<ProcessCreateOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcessWaitOutcome {
    Success { reaped_os_pid: u64 },
    Failure { errno: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessWaitObservation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub requested_pid: i64,
    pub provider_syscall: String,
    pub outcome: Evidence<ProcessWaitOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessBehaviorReport {
    pub schema: String,
    pub capture_id: String,
    pub event_scope: Evidence<String>,
    pub creations: Vec<ProcessCreateObservation>,
    pub waits: Vec<ProcessWaitObservation>,
    pub ignored_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingProtectionTransition {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub address: u64,
    pub byte_len: u64,
    pub created_sequence: u64,
    pub transition_sequence: u64,
    pub from_permissions: String,
    pub to_permissions: String,
    pub anonymous: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingLifetime {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub address: u64,
    pub byte_len: u64,
    pub created_sequence: u64,
    pub created_permissions: String,
    pub anonymous: bool,
    pub transition_indices: Vec<usize>,
    pub removed_sequence: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingBehaviorFinding {
    pub kind: String,
    pub lifetime_index: usize,
    pub transition_index: Option<usize>,
    pub conclusion: Evidence<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingBehaviorReport {
    pub schema: String,
    pub capture_id: String,
    pub event_scope: Evidence<String>,
    pub lifetimes: Vec<MappingLifetime>,
    pub transitions: Vec<MappingProtectionTransition>,
    pub findings: Vec<MappingBehaviorFinding>,
    pub ignored_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileOpenOutcome {
    Success { descriptor: u64 },
    Failure { errno: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOpenObservation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub resource_id: String,
    pub path: Evidence<String>,
    pub path_sha256: String,
    pub path_byte_len: u64,
    pub flags: String,
    pub mode: Option<String>,
    pub outcome: Evidence<FileOpenOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileWriteObservation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub resource_id: String,
    pub descriptor: u64,
    pub requested_byte_len: u64,
    pub content: Evidence<String>,
    pub content_sha256: String,
    pub content_byte_len: u64,
    pub outcome: Evidence<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileReadObservation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub resource_id: String,
    pub descriptor: u64,
    pub offset: u64,
    pub requested_byte_len: u64,
    pub content: Evidence<String>,
    pub content_sha256: String,
    pub content_byte_len: u64,
    pub outcome: Evidence<u64>,
    pub input_source_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_address: Option<u64>,
    pub user_return_module_offset: Option<u64>,
    pub user_frame_artifact_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDupObservation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub resource_id: String,
    pub source_descriptor: u64,
    pub outcome: Evidence<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileCloseObservation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub resource_id: String,
    pub descriptor: u64,
    pub outcome: Evidence<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileStatOutcome {
    Success { file_type: String },
    Failure { errno: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStatObservation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub resource_id: String,
    pub path: Evidence<String>,
    pub path_sha256: String,
    pub path_byte_len: u64,
    pub outcome: Evidence<FileStatOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChmodObservation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub resource_id: String,
    pub path: Evidence<String>,
    pub path_sha256: String,
    pub path_byte_len: u64,
    pub mode: String,
    pub outcome: Evidence<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileIoctlObservation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub resource_id: String,
    pub descriptor: u64,
    pub request: u64,
    pub scalar_argument: String,
    pub result: Evidence<i64>,
    pub errno: Option<String>,
    pub user_return_module_offset: Option<u64>,
    pub user_frame_artifact_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileBehaviorFinding {
    pub kind: String,
    pub resource_id: String,
    pub conclusion: Evidence<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileBehaviorReport {
    pub schema: String,
    pub capture_id: String,
    pub event_scope: Evidence<String>,
    pub opens: Vec<FileOpenObservation>,
    pub reads: Vec<FileReadObservation>,
    pub duplications: Vec<FileDupObservation>,
    pub writes: Vec<FileWriteObservation>,
    pub closes: Vec<FileCloseObservation>,
    pub stats: Vec<FileStatObservation>,
    pub chmods: Vec<FileChmodObservation>,
    pub ioctls: Vec<FileIoctlObservation>,
    pub dangerous_findings: Vec<FileBehaviorFinding>,
    pub ignored_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorEndpoint {
    pub descriptor: u64,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorResourceObservation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub resource_id: String,
    pub kind: String,
    pub flags: String,
    pub domain: Option<String>,
    pub socket_type: Option<String>,
    pub protocol: Option<String>,
    pub endpoints: Vec<DescriptorEndpoint>,
    pub outcome: Evidence<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorTransferObservation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub resource_id: String,
    pub descriptor: u64,
    pub endpoint: String,
    pub operation: String,
    pub requested_byte_len: u64,
    pub content: Evidence<String>,
    pub content_sha256: String,
    pub content_byte_len: u64,
    pub outcome: Evidence<u64>,
    pub input_source_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_address: Option<u64>,
    pub user_return_module_offset: Option<u64>,
    pub user_frame_artifact_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorCloseObservation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub resource_id: String,
    pub descriptor: u64,
    pub endpoint: String,
    pub outcome: Evidence<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorBindObservation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub resource_id: String,
    pub descriptor: u64,
    pub address: String,
    pub port: u16,
    pub outcome: Evidence<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorListenObservation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub resource_id: String,
    pub descriptor: u64,
    pub backlog: i64,
    pub outcome: Evidence<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorBehaviorFinding {
    pub kind: String,
    pub resource_id: String,
    pub conclusion: Evidence<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorBehaviorReport {
    pub schema: String,
    pub capture_id: String,
    pub event_scope: Evidence<String>,
    pub resources: Vec<DescriptorResourceObservation>,
    pub transfers: Vec<DescriptorTransferObservation>,
    pub binds: Vec<DescriptorBindObservation>,
    pub listens: Vec<DescriptorListenObservation>,
    pub closes: Vec<DescriptorCloseObservation>,
    pub dangerous_findings: Vec<DescriptorBehaviorFinding>,
    pub ignored_events: usize,
}

#[derive(Debug, Clone)]
struct MappingState {
    permissions: String,
    created_sequence: u64,
    anonymous: bool,
    lifetime_index: usize,
}

type MappingKey = (String, Option<String>, u64, u64);

/// Normalize bounded parent-side process creation and wait observations.
pub fn analyze_process_behavior(capsule: &ProcessCapsule) -> ProcessBehaviorReport {
    let process_event_count = capsule
        .events
        .iter()
        .filter(|event| matches!(event.kind.as_str(), "process_create" | "process_wait"))
        .count() as u64;
    let mut event_scope = completeness_scope(
        capsule,
        "process_events",
        "fork,vfork,clone(process),clone3(process),wait4",
    );
    if matches!(event_scope, Evidence::Observed { .. })
        && capsule
            .completeness
            .iter()
            .find(|record| record.evidence == "process_events")
            .is_some_and(|record| record.obtained != process_event_count)
    {
        event_scope = Evidence::Unknown {
            reason: format!(
                "process_events completeness records {} events but capsule contains {process_event_count}",
                capsule
                    .completeness
                    .iter()
                    .find(|record| record.evidence == "process_events")
                    .map_or(0, |record| record.obtained)
            ),
        };
    }
    let mut creations = Vec::new();
    let mut waits = Vec::new();
    let mut ignored_events = 0usize;
    for event in &capsule.events {
        match event.kind.as_str() {
            "process_create" => match normalize_process_create(event) {
                Some(observation) => creations.push(observation),
                None => ignored_events += 1,
            },
            "process_wait" => match normalize_process_wait(event) {
                Some(observation) => waits.push(observation),
                None => ignored_events += 1,
            },
            _ => {}
        }
    }
    ProcessBehaviorReport {
        schema: PROCESS_BEHAVIOR_REPORT_SCHEMA.to_string(),
        capture_id: capsule.identity.capture_id.clone(),
        event_scope,
        creations,
        waits,
        ignored_events,
    }
}

fn normalize_process_create(
    event: &super::capsule::EventRecord,
) -> Option<ProcessCreateObservation> {
    let caller_os_tid = event.fields.get("caller_os_tid")?.parse::<u64>().ok()?;
    let provider_syscall = event.fields.get("provider_syscall")?.clone();
    if !matches!(
        provider_syscall.as_str(),
        "fork" | "vfork" | "clone" | "clone3"
    ) {
        return None;
    }
    let outcome = match event.fields.get("result").map(String::as_str) {
        Some("success") => Evidence::Observed {
            value: ProcessCreateOutcome::Success {
                child_os_pid: event.fields.get("child_os_pid")?.parse::<u64>().ok()?,
            },
            source: "normalized successful process-creation result".to_string(),
        },
        Some("failure") => Evidence::Observed {
            value: ProcessCreateOutcome::Failure {
                errno: event.fields.get("errno")?.clone(),
            },
            source: "normalized failed process-creation result".to_string(),
        },
        _ => return None,
    };
    Some(ProcessCreateObservation {
        process_id: event.process_id.clone(),
        thread_id: event.thread_id.clone(),
        sequence: event.sequence,
        caller_os_tid,
        provider_syscall,
        outcome,
    })
}

fn normalize_process_wait(event: &super::capsule::EventRecord) -> Option<ProcessWaitObservation> {
    let requested_pid = event.fields.get("requested_pid")?.parse::<i64>().ok()?;
    let provider_syscall = event.fields.get("provider_syscall")?.clone();
    if provider_syscall != "wait4" {
        return None;
    }
    let outcome = match event.fields.get("result").map(String::as_str) {
        Some("success") => Evidence::Observed {
            value: ProcessWaitOutcome::Success {
                reaped_os_pid: event.fields.get("reaped_os_pid")?.parse::<u64>().ok()?,
            },
            source: "normalized successful wait4 result".to_string(),
        },
        Some("failure") => Evidence::Observed {
            value: ProcessWaitOutcome::Failure {
                errno: event.fields.get("errno")?.clone(),
            },
            source: "normalized failed wait4 result".to_string(),
        },
        _ => return None,
    };
    Some(ProcessWaitObservation {
        process_id: event.process_id.clone(),
        thread_id: event.thread_id.clone(),
        sequence: event.sequence,
        requested_pid,
        provider_syscall,
        outcome,
    })
}

/// Analyze exact-range mapping lifetimes without consulting provider-native data.
pub fn analyze_mapping_behavior(capsule: &ProcessCapsule) -> MappingBehaviorReport {
    let event_scope = capsule
        .completeness
        .iter()
        .find(|record| record.evidence == "mapping_events")
        .map_or_else(
            || Evidence::Unknown {
                reason: "capsule has no mapping-event completeness record".to_string(),
            },
            |record| {
                if record.status == CompletenessStatus::Complete {
                    Evidence::Observed {
                        value: "mmap,mprotect,munmap".to_string(),
                        source: "capsule mapping_events completeness record".to_string(),
                    }
                } else {
                    Evidence::Unknown {
                        reason: format!(
                            "mapping event stream is {:?}: {}",
                            record.status,
                            record.reason.as_deref().unwrap_or("no reason supplied")
                        ),
                    }
                }
            },
        );
    let mut events: Vec<_> = capsule.events.iter().collect();
    events.sort_by_key(|event| {
        (
            event.process_id.clone(),
            event.thread_id.clone(),
            event.sequence,
        )
    });
    let mut states: BTreeMap<MappingKey, MappingState> = BTreeMap::new();
    let mut lifetimes = Vec::new();
    let mut transitions = Vec::new();
    let mut findings = Vec::new();
    let mut ignored_events = 0usize;
    for event in events {
        if !matches!(
            event.kind.as_str(),
            "mapping_create" | "mapping_protect" | "mapping_remove"
        ) {
            continue;
        }
        if event.fields.get("result").map(String::as_str) != Some("success") {
            ignored_events += 1;
            continue;
        }
        let Some(address) = event.address else {
            ignored_events += 1;
            continue;
        };
        let Some(byte_len) = event
            .fields
            .get("length")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|length| *length != 0)
        else {
            ignored_events += 1;
            continue;
        };
        let key = (
            event.process_id.clone(),
            event.thread_id.clone(),
            address,
            byte_len,
        );
        match event.kind.as_str() {
            "mapping_create" => {
                let Some(permissions) = event.fields.get("permissions") else {
                    ignored_events += 1;
                    continue;
                };
                let anonymous = event
                    .fields
                    .get("flags")
                    .is_some_and(|flags| flags.split('|').any(|flag| flag == "MAP_ANONYMOUS"));
                let lifetime_index = lifetimes.len();
                lifetimes.push(MappingLifetime {
                    process_id: event.process_id.clone(),
                    thread_id: event.thread_id.clone(),
                    address,
                    byte_len,
                    created_sequence: event.sequence,
                    created_permissions: permissions.clone(),
                    anonymous,
                    transition_indices: Vec::new(),
                    removed_sequence: None,
                });
                if has_permission(permissions, "write") && has_permission(permissions, "execute") {
                    findings.push(MappingBehaviorFinding {
                        kind: "writable_executable_mapping".to_string(),
                        lifetime_index,
                        transition_index: None,
                        conclusion: Evidence::Inferred {
                            value: "mapping was created simultaneously writable and executable"
                                .to_string(),
                            source: "successful mapping_create event permissions".to_string(),
                        },
                    });
                }
                states.insert(
                    key,
                    MappingState {
                        permissions: permissions.clone(),
                        created_sequence: event.sequence,
                        anonymous,
                        lifetime_index,
                    },
                );
            }
            "mapping_protect" => {
                let Some(to_permissions) = event.fields.get("permissions") else {
                    ignored_events += 1;
                    continue;
                };
                let Some(state) = states.get_mut(&key) else {
                    ignored_events += 1;
                    continue;
                };
                let transition = MappingProtectionTransition {
                    process_id: event.process_id.clone(),
                    thread_id: event.thread_id.clone(),
                    address,
                    byte_len,
                    created_sequence: state.created_sequence,
                    transition_sequence: event.sequence,
                    from_permissions: state.permissions.clone(),
                    to_permissions: to_permissions.clone(),
                    anonymous: state.anonymous,
                };
                let became_executable = has_permission(to_permissions, "execute");
                let was_writable = has_permission(&state.permissions, "write");
                let transition_index = transitions.len();
                transitions.push(transition);
                lifetimes[state.lifetime_index]
                    .transition_indices
                    .push(transition_index);
                if was_writable && became_executable {
                    findings.push(MappingBehaviorFinding {
                        kind: "writable_to_executable".to_string(),
                        lifetime_index: state.lifetime_index,
                        transition_index: Some(transition_index),
                        conclusion: Evidence::Inferred {
                            value:
                                "mapping bytes were writable before the mapping became executable"
                                    .to_string(),
                            source: "ordered successful mapping_create/mapping_protect events"
                                .to_string(),
                        },
                    });
                }
                state.permissions = to_permissions.clone();
            }
            "mapping_remove" => {
                if let Some(state) = states.remove(&key) {
                    lifetimes[state.lifetime_index].removed_sequence = Some(event.sequence);
                } else {
                    ignored_events += 1;
                }
            }
            _ => unreachable!("mapping event kind was filtered above"),
        }
    }
    MappingBehaviorReport {
        schema: MAPPING_BEHAVIOR_REPORT_SCHEMA.to_string(),
        capture_id: capsule.identity.capture_id.clone(),
        event_scope,
        lifetimes,
        transitions,
        findings,
        ignored_events,
    }
}

fn has_permission(permissions: &str, expected: &str) -> bool {
    permissions.split('|').any(|item| item == expected)
}

/// Normalize non-file descriptor resources without merging them into static objects.
pub fn analyze_descriptor_behavior(capsule: &ProcessCapsule) -> DescriptorBehaviorReport {
    let event_scope = completeness_scope(
        capsule,
        "descriptor_events",
        "pipe2,socket,socketpair,bind,listen,read,write,sendto,recvfrom,close",
    );
    let mut resources = Vec::new();
    let mut transfers = Vec::new();
    let mut binds = Vec::new();
    let mut listens = Vec::new();
    let mut closes = Vec::new();
    let mut dangerous_findings = Vec::new();
    let mut ignored_events = 0usize;
    for event in &capsule.events {
        match event.kind.as_str() {
            "descriptor_pipe_create" => {
                let Some(resource_id) = event.fields.get("resource_id") else {
                    ignored_events += 1;
                    continue;
                };
                let Some(read_descriptor) = event
                    .fields
                    .get("read_descriptor")
                    .and_then(|value| value.parse::<u64>().ok())
                else {
                    ignored_events += 1;
                    continue;
                };
                let Some(write_descriptor) = event
                    .fields
                    .get("write_descriptor")
                    .and_then(|value| value.parse::<u64>().ok())
                else {
                    ignored_events += 1;
                    continue;
                };
                let outcome = if event.fields.get("result").map(String::as_str) == Some("success") {
                    Evidence::Observed {
                        value: "success".to_string(),
                        source: "normalized successful pipe2 result".to_string(),
                    }
                } else {
                    Evidence::Unknown {
                        reason: "pipe creation did not have a successful result".to_string(),
                    }
                };
                resources.push(DescriptorResourceObservation {
                    process_id: event.process_id.clone(),
                    thread_id: event.thread_id.clone(),
                    sequence: event.sequence,
                    resource_id: resource_id.clone(),
                    kind: "pipe".to_string(),
                    flags: event.fields.get("flags").cloned().unwrap_or_default(),
                    domain: None,
                    socket_type: None,
                    protocol: None,
                    endpoints: vec![
                        DescriptorEndpoint {
                            descriptor: read_descriptor,
                            role: "read".to_string(),
                        },
                        DescriptorEndpoint {
                            descriptor: write_descriptor,
                            role: "write".to_string(),
                        },
                    ],
                    outcome,
                });
            }
            "descriptor_socketpair_create" => {
                let Some(resource_id) = event.fields.get("resource_id") else {
                    ignored_events += 1;
                    continue;
                };
                let Some(first_descriptor) = event
                    .fields
                    .get("first_descriptor")
                    .and_then(|value| value.parse::<u64>().ok())
                else {
                    ignored_events += 1;
                    continue;
                };
                let Some(second_descriptor) = event
                    .fields
                    .get("second_descriptor")
                    .and_then(|value| value.parse::<u64>().ok())
                else {
                    ignored_events += 1;
                    continue;
                };
                let (Some(domain), Some(socket_type), Some(protocol)) = (
                    event.fields.get("domain"),
                    event.fields.get("socket_type"),
                    event.fields.get("protocol"),
                ) else {
                    ignored_events += 1;
                    continue;
                };
                let outcome = if event.fields.get("result").map(String::as_str) == Some("success") {
                    Evidence::Observed {
                        value: "success".to_string(),
                        source: "normalized successful socketpair result".to_string(),
                    }
                } else {
                    Evidence::Unknown {
                        reason: "socketpair creation did not have a successful result".to_string(),
                    }
                };
                resources.push(DescriptorResourceObservation {
                    process_id: event.process_id.clone(),
                    thread_id: event.thread_id.clone(),
                    sequence: event.sequence,
                    resource_id: resource_id.clone(),
                    kind: "socketpair".to_string(),
                    flags: String::new(),
                    domain: Some(domain.clone()),
                    socket_type: Some(socket_type.clone()),
                    protocol: Some(protocol.clone()),
                    endpoints: vec![
                        DescriptorEndpoint {
                            descriptor: first_descriptor,
                            role: "peer0".to_string(),
                        },
                        DescriptorEndpoint {
                            descriptor: second_descriptor,
                            role: "peer1".to_string(),
                        },
                    ],
                    outcome,
                });
            }
            "descriptor_socket_create" => {
                let (Some(resource_id), Some(domain), Some(socket_type), Some(protocol)) = (
                    event.fields.get("resource_id"),
                    event.fields.get("domain"),
                    event.fields.get("socket_type"),
                    event.fields.get("protocol"),
                ) else {
                    ignored_events += 1;
                    continue;
                };
                let (outcome, endpoints) = match event.fields.get("result").map(String::as_str) {
                    Some("success") => {
                        let Some(descriptor) = event
                            .fields
                            .get("descriptor")
                            .and_then(|value| value.parse::<u64>().ok())
                        else {
                            ignored_events += 1;
                            continue;
                        };
                        (
                            Evidence::Observed {
                                value: "success".to_string(),
                                source: "normalized successful socket result".to_string(),
                            },
                            vec![DescriptorEndpoint {
                                descriptor,
                                role: "socket".to_string(),
                            }],
                        )
                    }
                    Some("failure") => (
                        Evidence::Unknown {
                            reason: format!(
                                "socket creation failed: {}",
                                event
                                    .fields
                                    .get("errno")
                                    .map_or("unknown errno", String::as_str)
                            ),
                        },
                        Vec::new(),
                    ),
                    _ => {
                        ignored_events += 1;
                        continue;
                    }
                };
                resources.push(DescriptorResourceObservation {
                    process_id: event.process_id.clone(),
                    thread_id: event.thread_id.clone(),
                    sequence: event.sequence,
                    resource_id: resource_id.clone(),
                    kind: "socket".to_string(),
                    flags: String::new(),
                    domain: Some(domain.clone()),
                    socket_type: Some(socket_type.clone()),
                    protocol: Some(protocol.clone()),
                    endpoints,
                    outcome,
                });
            }
            "descriptor_read" | "descriptor_write" | "descriptor_send" | "descriptor_recv" => {
                let operation = event.kind.trim_start_matches("descriptor_");
                let Some(transfer) = normalize_descriptor_transfer(event, operation) else {
                    ignored_events += 1;
                    continue;
                };
                transfers.push(transfer);
            }
            "descriptor_stdin_read" => {
                let Some(transfer) = normalize_descriptor_transfer(event, "read") else {
                    ignored_events += 1;
                    continue;
                };
                if !resources
                    .iter()
                    .any(|resource| resource.resource_id == transfer.resource_id)
                {
                    resources.push(DescriptorResourceObservation {
                        process_id: event.process_id.clone(),
                        thread_id: event.thread_id.clone(),
                        sequence: event.sequence,
                        resource_id: transfer.resource_id.clone(),
                        kind: "standard_input".to_string(),
                        flags: event
                            .fields
                            .get("provider")
                            .cloned()
                            .unwrap_or_else(|| "unknown".to_string()),
                        domain: None,
                        socket_type: None,
                        protocol: None,
                        endpoints: vec![DescriptorEndpoint {
                            descriptor: transfer.descriptor,
                            role: "stdin".to_string(),
                        }],
                        outcome: Evidence::Observed {
                            value: "available".to_string(),
                            source: "acquisition-owned standard input provider".to_string(),
                        },
                    });
                }
                transfers.push(transfer);
            }
            "descriptor_close" => {
                let Some(close) = normalize_descriptor_close(event) else {
                    ignored_events += 1;
                    continue;
                };
                closes.push(close);
            }
            "descriptor_bind" => {
                let Some(bind) = normalize_descriptor_bind(event) else {
                    ignored_events += 1;
                    continue;
                };
                if bind.address == "0.0.0.0" && matches!(bind.outcome, Evidence::Observed { .. }) {
                    dangerous_findings.push(DescriptorBehaviorFinding {
                        kind: "wildcard_bind".to_string(),
                        resource_id: bind.resource_id.clone(),
                        conclusion: Evidence::Inferred {
                            value: "socket bound all IPv4 interfaces".to_string(),
                            source: "successful normalized AF_INET bind endpoint".to_string(),
                        },
                    });
                }
                binds.push(bind);
            }
            "descriptor_listen" => {
                let Some(listen) = normalize_descriptor_listen(event) else {
                    ignored_events += 1;
                    continue;
                };
                listens.push(listen);
            }
            _ => {}
        }
    }
    DescriptorBehaviorReport {
        schema: DESCRIPTOR_BEHAVIOR_REPORT_SCHEMA.to_string(),
        capture_id: capsule.identity.capture_id.clone(),
        event_scope,
        resources,
        transfers,
        binds,
        listens,
        closes,
        dangerous_findings,
        ignored_events,
    }
}

fn normalize_descriptor_transfer(
    event: &super::capsule::EventRecord,
    operation: &str,
) -> Option<DescriptorTransferObservation> {
    let resource_id = event.fields.get("resource_id")?.clone();
    let descriptor = event.fields.get("descriptor")?.parse::<u64>().ok()?;
    let endpoint = event.fields.get("endpoint")?.clone();
    if !matches!(
        (operation, endpoint.as_str()),
        ("read", "read")
            | ("read", "stdin")
            | ("write", "write")
            | ("send", "peer0" | "peer1")
            | ("recv", "peer0" | "peer1")
    ) {
        return None;
    }
    let requested_byte_len = event
        .fields
        .get("requested_byte_len")?
        .parse::<u64>()
        .ok()?;
    let content_sha256 = event.fields.get("content_sha256")?.clone();
    let content_byte_len = event.fields.get("content_byte_len")?.parse::<u64>().ok()?;
    let content = if event.fields.get("content_redacted").map(String::as_str) == Some("false") {
        event.fields.get("content_hex").map_or_else(
            || Evidence::Unknown {
                reason: "public descriptor-transfer content is missing".to_string(),
            },
            |value| match hex::decode(value) {
                Ok(bytes)
                    if bytes.len() as u64 == content_byte_len
                        && hex::encode(Sha256::digest(&bytes)) == content_sha256 =>
                {
                    Evidence::Observed {
                        value: value.clone(),
                        source: "hash-verified caller-authorized public IPC content"
                            .to_string(),
                    }
                }
                _ => Evidence::Unknown {
                    reason: "public descriptor-transfer content identity disagrees with its hash or length".to_string(),
                },
            },
        )
    } else {
        Evidence::Unknown {
            reason: "descriptor-transfer content was redacted by acquisition policy".to_string(),
        }
    };
    let result_field = match operation {
        "read" => "read_byte_len",
        "write" => "written_byte_len",
        "send" => "sent_byte_len",
        "recv" => "received_byte_len",
        _ => return None,
    };
    let outcome = match event.fields.get("result").map(String::as_str) {
        Some("success") => event
            .fields
            .get(result_field)?
            .parse::<u64>()
            .ok()
            .map(|value| Evidence::Observed {
                value,
                source: format!("normalized successful descriptor {operation} result"),
            })?,
        Some("failure") => Evidence::Unknown {
            reason: format!(
                "descriptor {operation} failed: {}",
                event
                    .fields
                    .get("errno")
                    .map_or("unknown errno", String::as_str)
            ),
        },
        _ => return None,
    };
    Some(DescriptorTransferObservation {
        process_id: event.process_id.clone(),
        thread_id: event.thread_id.clone(),
        sequence: event.sequence,
        resource_id,
        descriptor,
        endpoint,
        operation: operation.to_string(),
        requested_byte_len,
        content,
        content_sha256,
        content_byte_len,
        outcome,
        input_source_name: event.fields.get("input_source_name").cloned(),
        destination_address: event
            .fields
            .get("destination_address")
            .and_then(|value| value.parse().ok()),
        user_return_module_offset: event
            .fields
            .get("user_return_module_offset")
            .and_then(|value| value.parse().ok()),
        user_frame_artifact_sha256: event.fields.get("user_frame_artifact_sha256").cloned(),
    })
}

fn normalize_descriptor_close(
    event: &super::capsule::EventRecord,
) -> Option<DescriptorCloseObservation> {
    let outcome = match event.fields.get("result").map(String::as_str) {
        Some("success") => Evidence::Observed {
            value: "success".to_string(),
            source: "normalized successful descriptor close result".to_string(),
        },
        Some("failure") => Evidence::Unknown {
            reason: format!(
                "descriptor close failed: {}",
                event
                    .fields
                    .get("errno")
                    .map_or("unknown errno", String::as_str)
            ),
        },
        _ => return None,
    };
    Some(DescriptorCloseObservation {
        process_id: event.process_id.clone(),
        thread_id: event.thread_id.clone(),
        sequence: event.sequence,
        resource_id: event.fields.get("resource_id")?.clone(),
        descriptor: event.fields.get("descriptor")?.parse::<u64>().ok()?,
        endpoint: event.fields.get("endpoint")?.clone(),
        outcome,
    })
}

fn normalize_descriptor_bind(
    event: &super::capsule::EventRecord,
) -> Option<DescriptorBindObservation> {
    let outcome = match event.fields.get("result").map(String::as_str) {
        Some("success") => Evidence::Observed {
            value: "success".to_string(),
            source: "normalized successful bind result".to_string(),
        },
        Some("failure") => Evidence::Unknown {
            reason: format!(
                "socket bind failed: {}",
                event
                    .fields
                    .get("errno")
                    .map_or("unknown errno", String::as_str)
            ),
        },
        _ => return None,
    };
    Some(DescriptorBindObservation {
        process_id: event.process_id.clone(),
        thread_id: event.thread_id.clone(),
        sequence: event.sequence,
        resource_id: event.fields.get("resource_id")?.clone(),
        descriptor: event.fields.get("descriptor")?.parse::<u64>().ok()?,
        address: event.fields.get("address")?.clone(),
        port: event.fields.get("port")?.parse::<u16>().ok()?,
        outcome,
    })
}

fn normalize_descriptor_listen(
    event: &super::capsule::EventRecord,
) -> Option<DescriptorListenObservation> {
    let outcome = match event.fields.get("result").map(String::as_str) {
        Some("success") => Evidence::Observed {
            value: "success".to_string(),
            source: "normalized successful listen result".to_string(),
        },
        Some("failure") => Evidence::Unknown {
            reason: format!(
                "socket listen failed: {}",
                event
                    .fields
                    .get("errno")
                    .map_or("unknown errno", String::as_str)
            ),
        },
        _ => return None,
    };
    Some(DescriptorListenObservation {
        process_id: event.process_id.clone(),
        thread_id: event.thread_id.clone(),
        sequence: event.sequence,
        resource_id: event.fields.get("resource_id")?.clone(),
        descriptor: event.fields.get("descriptor")?.parse::<u64>().ok()?,
        backlog: event.fields.get("backlog")?.parse::<i64>().ok()?,
        outcome,
    })
}

/// Normalize public and redacted file-open observations from capsule events.
pub fn analyze_file_behavior(capsule: &ProcessCapsule) -> FileBehaviorReport {
    let event_scope = completeness_scope(
        capsule,
        "file_events",
        "openat,newfstatat,chmod,read(selected-content),write,close,dup,ioctl",
    );
    let mut opens = Vec::new();
    let mut reads = Vec::new();
    let mut duplications = Vec::new();
    let mut writes = Vec::new();
    let mut closes = Vec::new();
    let mut stats = Vec::new();
    let mut chmods = Vec::new();
    let mut ioctls = Vec::new();
    let mut dangerous_findings = Vec::new();
    let mut ignored_events = 0usize;
    for event in &capsule.events {
        if !matches!(
            event.kind.as_str(),
            "file_open"
                | "file_read"
                | "file_write"
                | "file_close"
                | "file_dup"
                | "file_stat"
                | "file_chmod"
                | "file_ioctl"
        ) {
            continue;
        }
        if event.kind == "file_write" {
            let Some(write) = normalize_file_write(event) else {
                ignored_events += 1;
                continue;
            };
            writes.push(write);
            continue;
        }
        if event.kind == "file_read" {
            let Some(read) = normalize_file_read(event) else {
                ignored_events += 1;
                continue;
            };
            reads.push(read);
            continue;
        }
        if event.kind == "file_close" {
            let Some(close) = normalize_file_close(event) else {
                ignored_events += 1;
                continue;
            };
            closes.push(close);
            continue;
        }
        if event.kind == "file_dup" {
            let Some(duplication) = normalize_file_dup(event) else {
                ignored_events += 1;
                continue;
            };
            duplications.push(duplication);
            continue;
        }
        if event.kind == "file_stat" {
            let Some(stat) = normalize_file_stat(event) else {
                ignored_events += 1;
                continue;
            };
            stats.push(stat);
            continue;
        }
        if event.kind == "file_chmod" {
            let Some(chmod) = normalize_file_chmod(event) else {
                ignored_events += 1;
                continue;
            };
            if matches!(&chmod.outcome, Evidence::Observed { .. }) {
                match parse_octal_mode(&chmod.mode) {
                    Some(mode) if mode & 0o002 != 0 => {
                        dangerous_findings.push(FileBehaviorFinding {
                            kind: "world_writable".to_string(),
                            resource_id: chmod.resource_id.clone(),
                            conclusion: Evidence::Inferred {
                                value: format!(
                                    "successful chmod mode {mode:04o} permits world write"
                                ),
                                source: "normalized successful chmod result and mode".to_string(),
                            },
                        });
                    }
                    Some(_) => {}
                    None => ignored_events += 1,
                }
            }
            chmods.push(chmod);
            continue;
        }
        if event.kind == "file_ioctl" {
            let Some(ioctl) = normalize_file_ioctl(event) else {
                ignored_events += 1;
                continue;
            };
            ioctls.push(ioctl);
            continue;
        }
        let Some(resource_id) = event.fields.get("resource_id") else {
            ignored_events += 1;
            continue;
        };
        let Some(path_sha256) = event.fields.get("path_sha256") else {
            ignored_events += 1;
            continue;
        };
        let Some(path_byte_len) = event
            .fields
            .get("path_byte_len")
            .and_then(|value| value.parse::<u64>().ok())
        else {
            ignored_events += 1;
            continue;
        };
        let Some(flags) = event.fields.get("flags") else {
            ignored_events += 1;
            continue;
        };
        let path = normalize_file_path(event, path_sha256, path_byte_len);
        let outcome = match event.fields.get("result").map(String::as_str) {
            Some("success") => event
                .fields
                .get("descriptor")
                .and_then(|value| value.parse::<u64>().ok())
                .map_or_else(
                    || Evidence::Unknown {
                        reason: "successful file_open event has no descriptor".to_string(),
                    },
                    |descriptor| Evidence::Observed {
                        value: FileOpenOutcome::Success { descriptor },
                        source: "normalized successful openat result".to_string(),
                    },
                ),
            Some("failure") => event.fields.get("errno").map_or_else(
                || Evidence::Unknown {
                    reason: "failed file_open event has no errno".to_string(),
                },
                |errno| Evidence::Observed {
                    value: FileOpenOutcome::Failure {
                        errno: errno.clone(),
                    },
                    source: "normalized failed openat result".to_string(),
                },
            ),
            _ => Evidence::Unknown {
                reason: "file_open event has no recognized result".to_string(),
            },
        };
        let mode = event.fields.get("mode").cloned();
        if flags.split('|').any(|flag| flag == "O_CREAT")
            && matches!(
                &outcome,
                Evidence::Observed {
                    value: FileOpenOutcome::Success { .. },
                    ..
                }
            )
        {
            match mode.as_deref().and_then(parse_octal_mode) {
                Some(mode_value) if mode_value & 0o022 != 0 => {
                    dangerous_findings.push(FileBehaviorFinding {
                        kind: "unsafe_file_create".to_string(),
                        resource_id: resource_id.clone(),
                        conclusion: Evidence::Inferred {
                            value: format!(
                                "created file mode {mode_value:04o} permits group/world write"
                            ),
                            source: "successful file_open creation flags and mode".to_string(),
                        },
                    });
                }
                Some(_) => {}
                None => ignored_events += 1,
            }
        }
        opens.push(FileOpenObservation {
            process_id: event.process_id.clone(),
            thread_id: event.thread_id.clone(),
            sequence: event.sequence,
            resource_id: resource_id.clone(),
            path,
            path_sha256: path_sha256.clone(),
            path_byte_len,
            flags: flags.clone(),
            mode,
            outcome,
        });
    }
    FileBehaviorReport {
        schema: FILE_BEHAVIOR_REPORT_SCHEMA.to_string(),
        capture_id: capsule.identity.capture_id.clone(),
        event_scope,
        opens,
        reads,
        duplications,
        writes,
        closes,
        stats,
        chmods,
        ioctls,
        dangerous_findings,
        ignored_events,
    }
}

fn normalize_file_chmod(event: &super::capsule::EventRecord) -> Option<FileChmodObservation> {
    let resource_id = event.fields.get("resource_id")?.clone();
    let path_sha256 = event.fields.get("path_sha256")?.clone();
    let path_byte_len = event.fields.get("path_byte_len")?.parse::<u64>().ok()?;
    let path = normalize_file_path(event, &path_sha256, path_byte_len);
    let mode = event.fields.get("mode")?.clone();
    let outcome = match event.fields.get("result").map(String::as_str) {
        Some("success") => Evidence::Observed {
            value: "success".to_string(),
            source: "normalized successful chmod result".to_string(),
        },
        Some("failure") => Evidence::Observed {
            value: format!(
                "failure:{}",
                event
                    .fields
                    .get("errno")
                    .map_or("unknown_errno", String::as_str)
            ),
            source: "normalized failed chmod result".to_string(),
        },
        _ => Evidence::Unknown {
            reason: "file_chmod event has no recognized result".to_string(),
        },
    };
    Some(FileChmodObservation {
        process_id: event.process_id.clone(),
        thread_id: event.thread_id.clone(),
        sequence: event.sequence,
        resource_id,
        path,
        path_sha256,
        path_byte_len,
        mode,
        outcome,
    })
}

fn normalize_file_ioctl(event: &super::capsule::EventRecord) -> Option<FileIoctlObservation> {
    let result = event.fields.get("result")?.parse::<i64>().ok()?;
    Some(FileIoctlObservation {
        process_id: event.process_id.clone(),
        thread_id: event.thread_id.clone(),
        sequence: event.sequence,
        resource_id: event.fields.get("resource_id")?.clone(),
        descriptor: event.fields.get("descriptor")?.parse::<u64>().ok()?,
        request: u64::from_str_radix(event.fields.get("request")?.strip_prefix("0x")?, 16).ok()?,
        scalar_argument: event.fields.get("scalar_argument")?.clone(),
        result: Evidence::Observed {
            value: result,
            source: "normalized ioctl kernel result".to_string(),
        },
        errno: event.fields.get("errno").cloned(),
        user_return_module_offset: event
            .fields
            .get("user_return_module_offset")
            .and_then(|value| value.parse::<u64>().ok()),
        user_frame_artifact_sha256: event.fields.get("user_frame_artifact_sha256").cloned(),
    })
}

fn normalize_file_dup(event: &super::capsule::EventRecord) -> Option<FileDupObservation> {
    let resource_id = event.fields.get("resource_id")?.clone();
    let source_descriptor = event.fields.get("source_descriptor")?.parse::<u64>().ok()?;
    let outcome = match event.fields.get("result").map(String::as_str) {
        Some("success") => event
            .fields
            .get("duplicate_descriptor")?
            .parse::<u64>()
            .ok()
            .map(|descriptor| Evidence::Observed {
                value: descriptor,
                source: "normalized successful dup result".to_string(),
            })?,
        Some("failure") => Evidence::Unknown {
            reason: format!(
                "descriptor duplication failed: {}",
                event
                    .fields
                    .get("errno")
                    .map_or("unknown errno", String::as_str)
            ),
        },
        _ => return None,
    };
    Some(FileDupObservation {
        process_id: event.process_id.clone(),
        thread_id: event.thread_id.clone(),
        sequence: event.sequence,
        resource_id,
        source_descriptor,
        outcome,
    })
}

fn normalize_file_read(event: &super::capsule::EventRecord) -> Option<FileReadObservation> {
    let resource_id = event.fields.get("resource_id")?.clone();
    let descriptor = event.fields.get("descriptor")?.parse::<u64>().ok()?;
    let offset = event.fields.get("offset")?.parse::<u64>().ok()?;
    let requested_byte_len = event
        .fields
        .get("requested_byte_len")?
        .parse::<u64>()
        .ok()?;
    let content_sha256 = event.fields.get("content_sha256")?.clone();
    let content_byte_len = event.fields.get("content_byte_len")?.parse::<u64>().ok()?;
    let content = normalize_public_content(event, &content_sha256, content_byte_len, "read");
    let outcome = match event.fields.get("result").map(String::as_str) {
        Some("success") => event
            .fields
            .get("read_byte_len")?
            .parse::<u64>()
            .ok()
            .map(|value| Evidence::Observed {
                value,
                source: "normalized successful read result".to_string(),
            })?,
        Some("failure") => Evidence::Unknown {
            reason: format!(
                "file read failed: {}",
                event
                    .fields
                    .get("errno")
                    .map_or("unknown errno", String::as_str)
            ),
        },
        _ => return None,
    };
    Some(FileReadObservation {
        process_id: event.process_id.clone(),
        thread_id: event.thread_id.clone(),
        sequence: event.sequence,
        resource_id,
        descriptor,
        offset,
        requested_byte_len,
        content,
        content_sha256,
        content_byte_len,
        outcome,
        input_source_name: event.fields.get("input_source_name").cloned(),
        destination_address: event
            .fields
            .get("destination_address")
            .and_then(|value| value.parse().ok()),
        user_return_module_offset: event
            .fields
            .get("user_return_module_offset")
            .and_then(|value| value.parse().ok()),
        user_frame_artifact_sha256: event.fields.get("user_frame_artifact_sha256").cloned(),
    })
}

fn normalize_public_content(
    event: &super::capsule::EventRecord,
    content_sha256: &str,
    content_byte_len: u64,
    operation: &str,
) -> Evidence<String> {
    if event.fields.get("content_redacted").map(String::as_str) != Some("false") {
        return Evidence::Unknown {
            reason: format!("file-{operation} content was redacted by acquisition policy"),
        };
    }
    event.fields.get("content_hex").map_or_else(
        || Evidence::Unknown {
            reason: format!("public file-{operation} content is missing"),
        },
        |value| match hex::decode(value) {
            Ok(bytes)
                if bytes.len() as u64 == content_byte_len
                    && hex::encode(Sha256::digest(&bytes)) == content_sha256 =>
            {
                Evidence::Observed {
                    value: value.clone(),
                    source: format!(
                        "hash-verified caller-authorized public content in normalized file_{operation} event"
                    ),
                }
            }
            _ => Evidence::Unknown {
                reason: format!(
                    "public file-{operation} content identity disagrees with its hash or length"
                ),
            },
        },
    )
}

fn normalize_file_path(
    event: &super::capsule::EventRecord,
    path_sha256: &str,
    path_byte_len: u64,
) -> Evidence<String> {
    if event.fields.get("path_redacted").map(String::as_str) != Some("false") {
        return Evidence::Unknown {
            reason: "file path was redacted by acquisition policy".to_string(),
        };
    }
    event.fields.get("path").map_or_else(
        || Evidence::Unknown {
            reason: "public file path is missing".to_string(),
        },
        |value| {
            if value.len() as u64 == path_byte_len
                && hex::encode(Sha256::digest(value.as_bytes())) == path_sha256
            {
                Evidence::Observed {
                    value: value.clone(),
                    source: format!(
                        "hash-verified caller-authorized public path in normalized {} event",
                        event.kind
                    ),
                }
            } else {
                Evidence::Unknown {
                    reason: "public file path identity disagrees with its hash or length"
                        .to_string(),
                }
            }
        },
    )
}

fn normalize_file_stat(event: &super::capsule::EventRecord) -> Option<FileStatObservation> {
    let resource_id = event.fields.get("resource_id")?.clone();
    let path_sha256 = event.fields.get("path_sha256")?.clone();
    let path_byte_len = event.fields.get("path_byte_len")?.parse::<u64>().ok()?;
    let path = normalize_file_path(event, &path_sha256, path_byte_len);
    let outcome = match event.fields.get("result").map(String::as_str) {
        Some("success") => event.fields.get("file_type").map_or_else(
            || Evidence::Unknown {
                reason: "successful file_stat event has no recognized file type".to_string(),
            },
            |file_type| Evidence::Observed {
                value: FileStatOutcome::Success {
                    file_type: file_type.clone(),
                },
                source: "normalized successful newfstatat result".to_string(),
            },
        ),
        Some("failure") => event.fields.get("errno").map_or_else(
            || Evidence::Unknown {
                reason: "failed file_stat event has no errno".to_string(),
            },
            |errno| Evidence::Observed {
                value: FileStatOutcome::Failure {
                    errno: errno.clone(),
                },
                source: "normalized failed newfstatat result".to_string(),
            },
        ),
        _ => Evidence::Unknown {
            reason: "file_stat event has no recognized result".to_string(),
        },
    };
    Some(FileStatObservation {
        process_id: event.process_id.clone(),
        thread_id: event.thread_id.clone(),
        sequence: event.sequence,
        resource_id,
        path,
        path_sha256,
        path_byte_len,
        outcome,
    })
}

fn normalize_file_write(event: &super::capsule::EventRecord) -> Option<FileWriteObservation> {
    let resource_id = event.fields.get("resource_id")?.clone();
    let descriptor = event.fields.get("descriptor")?.parse::<u64>().ok()?;
    let requested_byte_len = event
        .fields
        .get("requested_byte_len")?
        .parse::<u64>()
        .ok()?;
    let content_sha256 = event.fields.get("content_sha256")?.clone();
    let content_byte_len = event.fields.get("content_byte_len")?.parse::<u64>().ok()?;
    let content = if event.fields.get("content_redacted").map(String::as_str) == Some("false") {
        event.fields.get("content_hex").map_or_else(
            || Evidence::Unknown {
                reason: "public file-write content is missing".to_string(),
            },
            |value| match hex::decode(value) {
                Ok(bytes)
                    if bytes.len() as u64 == content_byte_len
                        && hex::encode(Sha256::digest(&bytes)) == content_sha256 =>
                {
                    Evidence::Observed {
                        value: value.clone(),
                        source: "hash-verified caller-authorized public content in normalized file_write event".to_string(),
                    }
                }
                _ => Evidence::Unknown {
                    reason: "public file-write content identity disagrees with its hash or length"
                        .to_string(),
                },
            },
        )
    } else {
        Evidence::Unknown {
            reason: "file-write content was redacted by acquisition policy".to_string(),
        }
    };
    let outcome = match event.fields.get("result").map(String::as_str) {
        Some("success") => event
            .fields
            .get("written_byte_len")?
            .parse::<u64>()
            .ok()
            .map(|value| Evidence::Observed {
                value,
                source: "normalized successful write result".to_string(),
            })?,
        Some("failure") => Evidence::Unknown {
            reason: format!(
                "file write failed: {}",
                event
                    .fields
                    .get("errno")
                    .map_or("unknown errno", String::as_str)
            ),
        },
        _ => return None,
    };
    Some(FileWriteObservation {
        process_id: event.process_id.clone(),
        thread_id: event.thread_id.clone(),
        sequence: event.sequence,
        resource_id,
        descriptor,
        requested_byte_len,
        content,
        content_sha256,
        content_byte_len,
        outcome,
    })
}

fn normalize_file_close(event: &super::capsule::EventRecord) -> Option<FileCloseObservation> {
    let resource_id = event.fields.get("resource_id")?.clone();
    let descriptor = event.fields.get("descriptor")?.parse::<u64>().ok()?;
    let outcome = match event.fields.get("result").map(String::as_str) {
        Some("success") => Evidence::Observed {
            value: "success".to_string(),
            source: "normalized successful close result".to_string(),
        },
        Some("failure") => Evidence::Unknown {
            reason: format!(
                "file close failed: {}",
                event
                    .fields
                    .get("errno")
                    .map_or("unknown errno", String::as_str)
            ),
        },
        _ => return None,
    };
    Some(FileCloseObservation {
        process_id: event.process_id.clone(),
        thread_id: event.thread_id.clone(),
        sequence: event.sequence,
        resource_id,
        descriptor,
        outcome,
    })
}

fn parse_octal_mode(text: &str) -> Option<u32> {
    let digits = text.trim_start_matches('0');
    if digits.is_empty() {
        Some(0)
    } else {
        u32::from_str_radix(digits, 8).ok()
    }
}

fn completeness_scope(capsule: &ProcessCapsule, evidence: &str, scope: &str) -> Evidence<String> {
    capsule
        .completeness
        .iter()
        .find(|record| record.evidence == evidence)
        .map_or_else(
            || Evidence::Unknown {
                reason: format!("capsule has no {evidence} completeness record"),
            },
            |record| {
                if record.status == CompletenessStatus::Complete {
                    Evidence::Observed {
                        value: scope.to_string(),
                        source: format!("capsule {evidence} completeness record"),
                    }
                } else {
                    Evidence::Unknown {
                        reason: format!(
                            "{evidence} stream is {:?}: {}",
                            record.status,
                            record.reason.as_deref().unwrap_or("no reason supplied")
                        ),
                    }
                }
            },
        )
}
