//! Linux x86-64 ELF core import into the provider-neutral process capsule.
//!
//! The importer never consults mapped paths on the importing host. The exact
//! executable is supplied by the caller, and a main-module relation requires
//! both an `NT_FILE` path match and agreement between captured mapping bytes
//! and the corresponding bytes of that executable.

use std::collections::{BTreeMap, BTreeSet};

use object::elf;
use object::endian::Endianness;
use object::read::elf::{ElfFile64, FileHeader, ProgramHeader};
use object::read::Object;
use sha2::{Digest, Sha256};

use super::capsule::{
    AccessKind, AcquisitionMode, ArtifactIdentity, CaptureIdentity, CaptureProvenance,
    CompletenessRecord, CompletenessStatus, FaultRecord, InputBytesIdentity, MappingBacking,
    MappingRecord, ModuleInstance, OmissionReason, PageContent, PageRecord, PayloadReference,
    Permissions, ProcessCapsule, ProcessRecord, RegisterObservation, RuntimeTarget, Sensitivity,
    TerminalState, ThreadRecord, SCHEMA, VERSION,
};
use crate::core::binary::{Arch, Endianness as TargetEndianness};

const PRSTATUS_SIZE: usize = 0x150;
const PRSTATUS_CURSIG_OFFSET: usize = 12;
const PRSTATUS_PID_OFFSET: usize = 32;
const PRSTATUS_REGS_OFFSET: usize = 112;
const X86_64_REGISTER_NAMES: [&str; 27] = [
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi",
    "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs",
    "gs",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfCoreLimits {
    pub max_core_bytes: usize,
    pub max_program_headers: usize,
    pub max_notes: usize,
    pub max_note_bytes: usize,
}

impl Default for ElfCoreLimits {
    fn default() -> Self {
        Self {
            max_core_bytes: 2 * 1024 * 1024 * 1024,
            max_program_headers: 1_000_000,
            max_notes: 1_000_000,
            max_note_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreImportInput<'a> {
    pub core_bytes: &'a [u8],
    pub core_display_path: Option<String>,
    pub executable_bytes: &'a [u8],
    pub executable_display_path: Option<String>,
    /// Capture time supplied by the acquisition layer, normally core mtime.
    pub captured_at: String,
    pub input_bytes: Vec<InputBytesIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedCore {
    pub capsule: ProcessCapsule,
    /// Sensitive page payloads keyed by their capsule-local payload ID.
    pub payloads: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone)]
struct PrStatus {
    pid: u32,
    current_signal: u16,
    registers: Vec<RegisterObservation>,
}

#[derive(Debug, Clone)]
struct SignalInfo {
    signal: u32,
    code: i32,
    sender_pid: Option<u32>,
    sender_uid: Option<u32>,
    address: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct ProcessInfo {
    pid: u32,
    ppid: u32,
}

#[derive(Debug, Clone)]
struct FileMapping {
    start: u64,
    end: u64,
    file_offset: u64,
    path: String,
}

#[derive(Debug)]
struct LoadSegment<'a> {
    start: u64,
    memory_len: u64,
    flags: u32,
    data: &'a [u8],
}

/// Import one Linux x86-64 ELF core without reading any host paths named by it.
pub fn import_elf_core(
    input: CoreImportInput<'_>,
    limits: ElfCoreLimits,
) -> Result<ImportedCore, String> {
    if input.core_bytes.len() > limits.max_core_bytes {
        return Err(format!(
            "ELF core bytes {} exceed limit {}",
            input.core_bytes.len(),
            limits.max_core_bytes
        ));
    }
    if input.executable_bytes.is_empty() {
        return Err("exact executable bytes are empty".to_string());
    }
    let file = ElfFile64::<Endianness>::parse(input.core_bytes)
        .map_err(|error| format!("parse ELF64 core: {error}"))?;
    let endian = file.endian();
    let header = file.elf_header();
    if header.e_type(endian) != elf::ET_CORE {
        return Err("ELF artifact is not ET_CORE".to_string());
    }
    if header.e_machine(endian) != elf::EM_X86_64 {
        return Err(format!(
            "unsupported ELF core machine {} (only x86-64 is implemented)",
            header.e_machine(endian)
        ));
    }
    if !matches!(endian, Endianness::Little) {
        return Err("x86-64 ELF core declares non-little-endian data".to_string());
    }
    let program_headers = file.elf_program_headers();
    if program_headers.len() > limits.max_program_headers {
        return Err(format!(
            "ELF core program headers {} exceed limit {}",
            program_headers.len(),
            limits.max_program_headers
        ));
    }

    let little = matches!(endian, Endianness::Little);
    let mut statuses = Vec::new();
    let mut process_info = None;
    let mut signal_info = None;
    let mut signal_thread_index = None;
    let mut file_mappings = Vec::new();
    let mut auxv = Vec::new();
    let mut thread_note_metadata: Vec<Vec<(String, usize, String)>> = Vec::new();
    let mut current_thread = None;
    let mut note_count = 0usize;
    for segment in program_headers {
        let Some(notes) = segment
            .notes(endian, input.core_bytes)
            .map_err(|error| format!("parse ELF core note segment: {error}"))?
        else {
            continue;
        };
        for note in notes {
            note_count = note_count
                .checked_add(1)
                .ok_or_else(|| "ELF core note count overflowed".to_string())?;
            if note_count > limits.max_notes {
                return Err(format!(
                    "ELF core notes {note_count} exceed limit {}",
                    limits.max_notes
                ));
            }
            let note = note.map_err(|error| format!("parse ELF core note: {error}"))?;
            if note.desc().len() > limits.max_note_bytes {
                return Err(format!(
                    "ELF core note bytes {} exceed limit {}",
                    note.desc().len(),
                    limits.max_note_bytes
                ));
            }
            match note.n_type(endian) {
                elf::NT_PRSTATUS => {
                    statuses.push(parse_prstatus(note.desc(), little)?);
                    thread_note_metadata.push(Vec::new());
                    current_thread = Some(statuses.len() - 1);
                }
                elf::NT_SIGINFO => {
                    if signal_info.is_some() {
                        return Err("ELF core contains multiple NT_SIGINFO notes".to_string());
                    }
                    signal_info = Some(parse_siginfo(note.desc(), little)?);
                    signal_thread_index = current_thread;
                }
                elf::NT_PRPSINFO => {
                    process_info = Some(parse_prpsinfo(note.desc(), little)?);
                }
                elf::NT_FILE => {
                    file_mappings = parse_nt_file(note.desc(), little)?;
                }
                elf::NT_AUXV => {
                    auxv = parse_auxv(note.desc(), little)?;
                }
                elf::NT_FPREGSET | elf::NT_X86_XSTATE => {
                    if let Some(index) = current_thread {
                        let kind = if note.n_type(endian) == elf::NT_FPREGSET {
                            "NT_FPREGSET"
                        } else {
                            "NT_X86_XSTATE"
                        };
                        thread_note_metadata[index].push((
                            kind.to_string(),
                            note.desc().len(),
                            sha256(note.desc()),
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    if statuses.is_empty() {
        return Err("ELF core contains no NT_PRSTATUS thread".to_string());
    }
    let process_pid = process_info.map_or(statuses[0].pid, |info| info.pid);
    let terminal_signal = signal_info
        .as_ref()
        .map(|info| info.signal)
        .or_else(|| {
            statuses
                .iter()
                .find(|status| status.current_signal != 0)
                .map(|status| u32::from(status.current_signal))
        })
        .ok_or_else(|| "ELF core has no terminal signal evidence".to_string())?;

    let loads = parse_loads(program_headers, endian, input.core_bytes)?;
    let executable = ArtifactIdentity {
        sha256: sha256(input.executable_bytes),
        byte_len: input.executable_bytes.len() as u64,
        build_id: executable_build_id(input.executable_bytes)?,
        display_path: input.executable_display_path.clone(),
    };
    let core_artifact = ArtifactIdentity {
        sha256: sha256(input.core_bytes),
        byte_len: input.core_bytes.len() as u64,
        build_id: None,
        display_path: input.core_display_path,
    };
    let main_path = verified_main_path(
        &loads,
        &file_mappings,
        input.executable_bytes,
        input.executable_display_path.as_deref(),
    );
    let process_id = format!("process-{process_pid}");
    let mut mappings = Vec::new();
    let mut pages = Vec::new();
    let mut payloads = BTreeMap::new();
    let mut main_mapping_ids = Vec::new();
    for (index, load) in loads.iter().enumerate() {
        let id = format!("mapping-{index:06}");
        let end = load
            .start
            .checked_add(load.memory_len)
            .ok_or_else(|| "ELF PT_LOAD virtual range overflowed".to_string())?;
        let file_mapping = file_mappings
            .iter()
            .find(|mapping| mapping.start == load.start && mapping.end == end);
        let is_main = main_path.is_some()
            && file_mapping
                .is_some_and(|mapping| Some(mapping.path.as_str()) == main_path.as_deref());
        if is_main {
            main_mapping_ids.push(id.clone());
        }
        let backing = match (file_mapping, is_main) {
            (Some(_), true) => MappingBacking::File {
                artifact_sha256: executable.sha256.clone(),
                deleted: false,
            },
            (Some(mapping), false) => MappingBacking::Unknown {
                reason: format!(
                    "NT_FILE path observed but artifact identity was not captured: {}",
                    mapping.path
                ),
            },
            (None, _) => MappingBacking::Anonymous,
        };
        mappings.push(MappingRecord {
            id: id.clone(),
            process_id: process_id.clone(),
            start: load.start,
            end,
            permissions: Permissions {
                read: load.flags & elf::PF_R != 0,
                write: load.flags & elf::PF_W != 0,
                execute: load.flags & elf::PF_X != 0,
                private: false,
            },
            backing,
            module_id: is_main.then(|| "module-main".to_string()),
            file_offset: file_mapping.map(|mapping| mapping.file_offset),
        });
        if !load.data.is_empty() {
            let payload_id = format!("core-load-{index:06}");
            payloads.insert(payload_id.clone(), load.data.to_vec());
            pages.push(PageRecord {
                process_id: process_id.clone(),
                mapping_id: id.clone(),
                start: load.start,
                byte_len: load.data.len() as u64,
                content: PageContent::Captured {
                    payload: PayloadReference {
                        id: payload_id,
                        sha256: sha256(load.data),
                        byte_len: load.data.len() as u64,
                        sensitivity: Sensitivity::Sensitive,
                    },
                },
            });
        }
        let captured_len = load.data.len() as u64;
        if captured_len < load.memory_len {
            pages.push(PageRecord {
                process_id: process_id.clone(),
                mapping_id: id,
                start: load.start + captured_len,
                byte_len: load.memory_len - captured_len,
                content: PageContent::Omitted {
                    reason: OmissionReason::ProviderUnsupported,
                    detail: "PT_LOAD memory range has no bytes in the core file".to_string(),
                },
            });
        }
    }

    // Linux interleaves process-wide notes immediately after the dumper's
    // PRSTATUS. Associate SIGINFO with that active thread instead of treating
    // the first PRSTATUS as a format-wide rule. All threads can carry the same
    // `pr_cursig`, so signal-number matching alone is not discriminating.
    let faulting_index = signal_thread_index.or_else(|| {
        let mut candidates = statuses
            .iter()
            .enumerate()
            .filter(|(_, status)| u32::from(status.current_signal) == terminal_signal);
        let candidate = candidates.next().map(|(index, _)| index);
        candidate.filter(|_| candidates.next().is_none())
    });
    let mut warnings = Vec::new();
    if faulting_index.is_none() {
        warnings.push("faulting thread is ambiguous: NT_SIGINFO was not associated with a thread-specific PRSTATUS and signal matching was not unique".to_string());
    }
    if main_path.is_none() {
        warnings.push(
            "main module was not joined: NT_FILE path and captured executable bytes did not both agree"
                .to_string(),
        );
    }
    let threads: Vec<ThreadRecord> = statuses
        .into_iter()
        .enumerate()
        .map(|(index, status)| ThreadRecord {
            id: format!("thread-{}", status.pid),
            process_id: process_id.clone(),
            os_tid: u64::from(status.pid),
            registers: status.registers,
            fault: (faulting_index == Some(index)).then(|| FaultRecord {
                signal: terminal_signal,
                code: signal_info.as_ref().map(|info| info.code),
                sender_pid: signal_info
                    .as_ref()
                    .and_then(|info| info.sender_pid)
                    .map(u64::from),
                sender_uid: signal_info
                    .as_ref()
                    .and_then(|info| info.sender_uid)
                    .map(u64::from),
                address: signal_info.as_ref().and_then(|info| info.address),
                access: Some(AccessKind::Unknown),
            }),
        })
        .collect();
    let thread_count = threads.len() as u64;
    let modules = (!main_mapping_ids.is_empty())
        .then(|| ModuleInstance {
            id: "module-main".to_string(),
            process_id: process_id.clone(),
            artifact: executable.clone(),
            load_bias: file_mappings
                .iter()
                .filter(|mapping| Some(mapping.path.as_str()) == main_path.as_deref())
                .filter_map(|mapping| mapping.start.checked_sub(mapping.file_offset))
                .min(),
            mapping_ids: main_mapping_ids,
        })
        .into_iter()
        .collect();
    let captured_page_bytes = pages
        .iter()
        .filter_map(|page| match page.content {
            PageContent::Captured { .. } => Some(page.byte_len),
            PageContent::Omitted { .. } => None,
        })
        .sum();
    let omitted_ranges = pages
        .iter()
        .filter(|page| matches!(page.content, PageContent::Omitted { .. }))
        .count() as u64;
    let extensions = BTreeMap::from([(
        "provider.elf_core".to_string(),
        serde_json::json!({
            "auxv": auxv.into_iter().map(|(kind, value)| {
                serde_json::json!({"type": kind, "value": format!("0x{value:x}")})
            }).collect::<Vec<_>>(),
            "parent_pid": process_info.map(|info| info.ppid),
            "thread_notes": thread_note_metadata.into_iter().enumerate().map(|(index, notes)| {
                serde_json::json!({
                    "thread_id": format!("thread-{}", threads_pid(&threads, index)),
                    "notes": notes.into_iter().map(|(kind, byte_len, hash)| {
                        serde_json::json!({"kind": kind, "byte_len": byte_len, "sha256": hash})
                    }).collect::<Vec<_>>()
                })
            }).collect::<Vec<_>>(),
        }),
    )]);
    let capsule = ProcessCapsule {
        schema: SCHEMA.to_string(),
        version: VERSION,
        identity: CaptureIdentity {
            capture_id: format!("core-{}", core_artifact.sha256),
            acquisition: AcquisitionMode::Core,
            host_os: "linux".to_string(),
            kernel: "unknown-from-core".to_string(),
            captured_at: input.captured_at,
        },
        required_features: Vec::new(),
        target: RuntimeTarget {
            architecture: Arch::X86_64,
            endianness: if little {
                TargetEndianness::Little
            } else {
                TargetEndianness::Big
            },
            address_bits: 64,
            os_abi: "linux".to_string(),
        },
        executable: executable.clone(),
        processes: vec![ProcessRecord {
            id: process_id,
            os_pid: u64::from(process_pid),
            parent_id: None,
            terminal: Some(TerminalState::Signaled {
                signal: terminal_signal,
                core_dumped: true,
            }),
        }],
        modules,
        mappings,
        threads,
        pages,
        runtime_objects: Vec::new(),
        object_snapshots: Vec::new(),
        outputs: Vec::new(),
        descriptors: Vec::new(),
        events: Vec::new(),
        provenance: CaptureProvenance {
            producer: "glaurung-elf-core-importer".to_string(),
            producer_version: "1".to_string(),
            command: Vec::new(),
            input_artifacts: vec![core_artifact, executable.clone()],
            input_bytes: input.input_bytes,
            warnings,
        },
        completeness: vec![
            CompletenessRecord {
                evidence: "descriptors".to_string(),
                status: CompletenessStatus::Unsupported,
                reason: Some("ELF cores do not preserve descriptor tables".to_string()),
                requested: true,
                obtained: 0,
                expected: None,
            },
            CompletenessRecord {
                evidence: "mappings".to_string(),
                status: CompletenessStatus::Complete,
                reason: None,
                requested: true,
                obtained: loads.len() as u64,
                expected: Some(loads.len() as u64),
            },
            CompletenessRecord {
                evidence: "page_bytes".to_string(),
                status: if omitted_ranges == 0 {
                    CompletenessStatus::Complete
                } else {
                    CompletenessStatus::Partial
                },
                reason: (omitted_ranges != 0)
                    .then(|| format!("{omitted_ranges} PT_LOAD ranges have no bytes in the core")),
                requested: true,
                obtained: captured_page_bytes,
                expected: None,
            },
            CompletenessRecord {
                evidence: "threads".to_string(),
                status: CompletenessStatus::Complete,
                reason: None,
                requested: true,
                obtained: thread_count,
                expected: Some(thread_count),
            },
        ],
        extensions,
    };
    capsule.validate(super::capsule::CapsuleLimits::default())?;
    Ok(ImportedCore { capsule, payloads })
}

fn parse_loads<'a>(
    headers: &[elf::ProgramHeader64<Endianness>],
    endian: Endianness,
    data: &'a [u8],
) -> Result<Vec<LoadSegment<'a>>, String> {
    headers
        .iter()
        .filter(|header| header.p_type(endian) == elf::PT_LOAD)
        .map(|header| {
            let memory_len = header.p_memsz(endian).into();
            if memory_len == 0 {
                return Err("ELF core PT_LOAD has zero memory size".to_string());
            }
            let bytes = header
                .data(endian, data)
                .map_err(|_| "ELF core PT_LOAD has an invalid file range".to_string())?;
            if bytes.len() as u64 > memory_len {
                return Err("ELF core PT_LOAD file size exceeds memory size".to_string());
            }
            Ok(LoadSegment {
                start: header.p_vaddr(endian).into(),
                memory_len,
                flags: header.p_flags(endian),
                data: bytes,
            })
        })
        .collect()
}

fn parse_prstatus(data: &[u8], little: bool) -> Result<PrStatus, String> {
    if data.len() < PRSTATUS_SIZE {
        return Err(format!(
            "x86-64 NT_PRSTATUS is truncated: {} bytes",
            data.len()
        ));
    }
    let registers = X86_64_REGISTER_NAMES
        .iter()
        .enumerate()
        .map(|(index, name)| RegisterObservation {
            provider_name: (*name).to_string(),
            bit_width: 64,
            value_hex: format!(
                "{:016x}",
                read_u64(data, PRSTATUS_REGS_OFFSET + index * 8, little)
                    .expect("validated prstatus register range")
            ),
        })
        .collect();
    Ok(PrStatus {
        pid: read_u32(data, PRSTATUS_PID_OFFSET, little).expect("validated prstatus pid range"),
        current_signal: read_u16(data, PRSTATUS_CURSIG_OFFSET, little)
            .expect("validated prstatus signal range"),
        registers,
    })
}

fn parse_siginfo(data: &[u8], little: bool) -> Result<SignalInfo, String> {
    if data.len() < 24 {
        return Err(format!("NT_SIGINFO is truncated: {} bytes", data.len()));
    }
    let signal = read_u32(data, 0, little).expect("validated siginfo signal range");
    let code = read_i32(data, 8, little).expect("validated siginfo code range");
    // Negative and zero si_code values are user/generated origins whose union
    // arm is not `_sigfault`; interpreting those bytes as an address invents
    // evidence (for example SI_TKILL from raise(SIGSEGV)).
    let address = (code > 0 && matches!(signal, 4 | 7 | 11))
        .then(|| read_u64(data, 16, little).expect("validated siginfo address range"));
    let sender_pid = (code <= 0)
        .then(|| read_u32(data, 16, little).expect("validated siginfo sender pid range"));
    let sender_uid = (code <= 0)
        .then(|| read_u32(data, 20, little).expect("validated siginfo sender uid range"));
    Ok(SignalInfo {
        signal,
        code,
        sender_pid,
        sender_uid,
        address,
    })
}

fn parse_prpsinfo(data: &[u8], little: bool) -> Result<ProcessInfo, String> {
    // Linux x86-64 `elf_prpsinfo`: four leading bytes, aligned `pr_flag`,
    // uid/gid, then pid/ppid/pgrp/sid.
    if data.len() < 32 {
        return Err(format!("NT_PRPSINFO is truncated: {} bytes", data.len()));
    }
    Ok(ProcessInfo {
        pid: read_u32(data, 24, little).expect("validated prpsinfo pid range"),
        ppid: read_u32(data, 28, little).expect("validated prpsinfo ppid range"),
    })
}

fn parse_nt_file(data: &[u8], little: bool) -> Result<Vec<FileMapping>, String> {
    let count = read_u64(data, 0, little).ok_or_else(|| "NT_FILE is truncated".to_string())?;
    let page_size =
        read_u64(data, 8, little).ok_or_else(|| "NT_FILE has no page size".to_string())?;
    if page_size == 0 {
        return Err("NT_FILE page size is zero".to_string());
    }
    let count = usize::try_from(count).map_err(|_| "NT_FILE count is oversized".to_string())?;
    let table_bytes = count
        .checked_mul(24)
        .and_then(|value| value.checked_add(16))
        .ok_or_else(|| "NT_FILE table size overflowed".to_string())?;
    if table_bytes > data.len() {
        return Err("NT_FILE mapping table is truncated".to_string());
    }
    let paths: Vec<&[u8]> = data[table_bytes..]
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .collect();
    if paths.len() != count {
        return Err(format!(
            "NT_FILE path count {} does not match mapping count {count}",
            paths.len()
        ));
    }
    (0..count)
        .map(|index| {
            let offset = 16 + index * 24;
            let start = read_u64(data, offset, little).expect("validated NT_FILE start");
            let end = read_u64(data, offset + 8, little).expect("validated NT_FILE end");
            let page_offset =
                read_u64(data, offset + 16, little).expect("validated NT_FILE offset");
            if start >= end {
                return Err("NT_FILE contains an empty mapping".to_string());
            }
            Ok(FileMapping {
                start,
                end,
                file_offset: page_offset
                    .checked_mul(page_size)
                    .ok_or_else(|| "NT_FILE byte offset overflowed".to_string())?,
                path: String::from_utf8_lossy(paths[index]).into_owned(),
            })
        })
        .collect()
}

fn parse_auxv(data: &[u8], little: bool) -> Result<Vec<(u64, u64)>, String> {
    if data.len() % 16 != 0 {
        return Err("NT_AUXV has a partial 64-bit entry".to_string());
    }
    let mut result = Vec::new();
    for offset in (0..data.len()).step_by(16) {
        let kind = read_u64(data, offset, little).expect("validated auxv type");
        let value = read_u64(data, offset + 8, little).expect("validated auxv value");
        if kind == 0 {
            break;
        }
        result.push((kind, value));
    }
    Ok(result)
}

fn verified_main_path(
    loads: &[LoadSegment<'_>],
    files: &[FileMapping],
    executable: &[u8],
    expected_path: Option<&str>,
) -> Option<String> {
    let expected_path = expected_path?;
    let candidates: BTreeSet<&str> = files
        .iter()
        .filter(|mapping| mapping.path == expected_path)
        .map(|mapping| mapping.path.as_str())
        .collect();
    candidates.into_iter().find_map(|path| {
        files
            .iter()
            .filter(|mapping| mapping.path == path)
            .any(|mapping| {
                let Some(load) = loads.iter().find(|load| load.start == mapping.start) else {
                    return false;
                };
                if load.data.is_empty() {
                    return false;
                }
                let Ok(offset) = usize::try_from(mapping.file_offset) else {
                    return false;
                };
                executable
                    .get(offset..offset.saturating_add(load.data.len()))
                    .is_some_and(|bytes| bytes == load.data)
            })
            .then(|| path.to_string())
    })
}

fn read_u16(data: &[u8], offset: usize, little: bool) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(if little {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    })
}

fn read_u32(data: &[u8], offset: usize, little: bool) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(if little {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

fn read_i32(data: &[u8], offset: usize, little: bool) -> Option<i32> {
    read_u32(data, offset, little).map(|value| value as i32)
}

fn read_u64(data: &[u8], offset: usize, little: bool) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(if little {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub(crate) fn executable_build_id(data: &[u8]) -> Result<Option<String>, String> {
    let file = object::File::parse(data)
        .map_err(|error| format!("parse exact executable for build ID: {error}"))?;
    file.build_id()
        .map(|value| value.map(hex::encode))
        .map_err(|error| format!("read exact executable build ID: {error}"))
}

fn threads_pid(threads: &[ThreadRecord], index: usize) -> u64 {
    threads.get(index).map_or(0, |thread| thread.os_tid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_and_non_core_inputs_fail_closed() {
        let error = import_elf_core(
            CoreImportInput {
                core_bytes: b"not an ELF core",
                core_display_path: None,
                executable_bytes: b"exact executable",
                executable_display_path: None,
                captured_at: "unknown".to_string(),
                input_bytes: Vec::new(),
            },
            ElfCoreLimits::default(),
        )
        .expect_err("malformed bytes must fail");
        assert!(error.contains("parse ELF64 core"));
    }

    #[test]
    fn import_budget_is_checked_before_parsing() {
        let error = import_elf_core(
            CoreImportInput {
                core_bytes: &[0; 2],
                core_display_path: None,
                executable_bytes: b"exact executable",
                executable_display_path: None,
                captured_at: "unknown".to_string(),
                input_bytes: Vec::new(),
            },
            ElfCoreLimits {
                max_core_bytes: 1,
                ..ElfCoreLimits::default()
            },
        )
        .expect_err("oversized input must fail before parsing");
        assert!(error.contains("exceed limit"));
    }
}
