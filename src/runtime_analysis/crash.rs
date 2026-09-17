//! First deterministic crash report over capsule and exact static evidence.

use std::collections::BTreeMap;
use std::fmt::Write;

use serde::{Deserialize, Serialize};
use sha2::Digest;

use super::capsule::{
    AccessKind, CapsuleLimits, EventRecord, MappingBacking, OutputStream, ProcessCapsule,
    TerminalState,
};
use super::correlation::{
    resolve_runtime_address, AddressResolution, OperationResolution, StaticCodeResolution,
};
use super::memory::RuntimeMemoryView;
use crate::core::binary::Arch;
use crate::program::image::ProgramImage;

pub const CRASH_REPORT_SCHEMA: &str = "glaurung-runtime-crash-report-v1";
pub const CRASH_COMPARISON_SCHEMA: &str = "glaurung-runtime-crash-comparison-v1";
const CRASH_MEMORY_WINDOW_BYTES: usize = 32;
const MAX_NATIVE_FRAMES: usize = 32;
const MAX_FRAME_POINTER_STEP: u64 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Evidence<T> {
    Observed { value: T, source: String },
    Inferred { value: T, source: String },
    Unknown { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultMappingContext {
    pub mapping_id: String,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub backing: String,
}

/// Compact product projection of the full runtime/static address relation.
///
/// This duplicates no mutable static state: every field is derived from the
/// exact `AddressResolution` retained alongside it in the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashLocation {
    pub module_id: String,
    pub mapping_id: String,
    pub runtime_va: u64,
    pub image_sha256: String,
    pub static_va: u64,
    pub function_entry: u64,
    pub function_name: Option<String>,
    pub block_start: u64,
    pub instruction_va: u64,
    pub instruction_end: u64,
    pub mnemonic: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashMemoryWindow {
    pub role: String,
    pub anchor: Evidence<u64>,
    pub start: Option<u64>,
    pub requested_len: usize,
    pub bytes_hex: Evidence<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeFrameConfidence {
    ObservedProgramCounter,
    FramePointerChain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeStackFrame {
    pub index: usize,
    pub pc: u64,
    pub frame_pointer: Option<u64>,
    pub return_slot: Option<u64>,
    pub confidence: NativeFrameConfidence,
    pub location: Evidence<CrashLocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeStack {
    pub frames: Vec<NativeStackFrame>,
    pub stop_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashReport {
    pub schema: String,
    pub capture_id: String,
    pub process_id: String,
    pub thread_id: String,
    pub architecture: String,
    pub signal: u32,
    pub signal_code: Evidence<i32>,
    pub signal_sender_pid: Evidence<u64>,
    pub signal_sender_uid: Evidence<u64>,
    pub stdout: Evidence<String>,
    pub stderr: Evidence<String>,
    pub pc: Evidence<u64>,
    pub sp: Evidence<u64>,
    pub registers: Evidence<Vec<super::capsule::RegisterObservation>>,
    pub fault_address: Evidence<u64>,
    pub access: Evidence<AccessKind>,
    pub class: Evidence<String>,
    pub fault_mapping: Evidence<FaultMappingContext>,
    pub location: Evidence<CrashLocation>,
    pub memory_windows: Vec<CrashMemoryWindow>,
    pub native_stack: Evidence<NativeStack>,
    pub static_location: Evidence<AddressResolution>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CrashAnalysis {
    Crash { report: Box<CrashReport> },
    NoCrash { process_id: String },
    Incomplete { reason: String },
    InvalidCapsule { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashComparison {
    pub schema: String,
    pub good: CrashAnalysis,
    pub bad: CrashAnalysis,
    pub contrast: CrashContrast,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum CrashContrast {
    BadOnly { class: Evidence<String> },
    GoodAlsoCrashed,
    BadDidNotCrash,
    Incomplete { reason: String },
}

pub fn compare_crashes(
    good_capsule: &ProcessCapsule,
    good_payloads: &BTreeMap<String, Vec<u8>>,
    bad_capsule: &ProcessCapsule,
    bad_payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
) -> CrashComparison {
    let good = analyze_crash(good_capsule, good_payloads, image);
    let bad = analyze_crash(bad_capsule, bad_payloads, image);
    let contrast = match (&good, &bad) {
        (CrashAnalysis::NoCrash { .. }, CrashAnalysis::Crash { report }) => {
            CrashContrast::BadOnly {
                class: report.class.clone(),
            }
        }
        (CrashAnalysis::Crash { .. }, _) => CrashContrast::GoodAlsoCrashed,
        (_, CrashAnalysis::NoCrash { .. }) => CrashContrast::BadDidNotCrash,
        (CrashAnalysis::InvalidCapsule { reason }, _)
        | (CrashAnalysis::Incomplete { reason }, _) => CrashContrast::Incomplete {
            reason: format!("good control: {reason}"),
        },
        (_, CrashAnalysis::InvalidCapsule { reason })
        | (_, CrashAnalysis::Incomplete { reason }) => CrashContrast::Incomplete {
            reason: format!("bad case: {reason}"),
        },
    };
    CrashComparison {
        schema: CRASH_COMPARISON_SCHEMA.to_string(),
        good,
        bad,
        contrast,
    }
}

/// Render a deterministic, redacted analyst summary of one typed analysis.
///
/// Raw memory windows and process output can contain secrets. The text surface
/// reports their availability and size only; JSON remains the explicit data
/// surface for callers authorized to handle those bytes.
pub fn render_crash_analysis(analysis: &CrashAnalysis) -> String {
    let mut output = String::new();
    writeln!(output, "Glaurung runtime crash analysis").expect("write string");
    match analysis {
        CrashAnalysis::NoCrash { process_id } => {
            writeln!(output, "Outcome: no crash").expect("write string");
            writeln!(output, "Process: {process_id}").expect("write string");
        }
        CrashAnalysis::Incomplete { reason } => {
            writeln!(output, "Outcome: incomplete").expect("write string");
            writeln!(output, "Reason: {reason}").expect("write string");
        }
        CrashAnalysis::InvalidCapsule { reason } => {
            writeln!(output, "Outcome: invalid capsule").expect("write string");
            writeln!(output, "Reason: {reason}").expect("write string");
        }
        CrashAnalysis::Crash { report } => {
            writeln!(output, "Outcome: crash").expect("write string");
            writeln!(output, "Schema: {}", report.schema).expect("write string");
            writeln!(output, "Capture: {}", report.capture_id).expect("write string");
            writeln!(output, "Process: {}", report.process_id).expect("write string");
            writeln!(output, "Thread: {}", report.thread_id).expect("write string");
            writeln!(output, "Architecture: {}", report.architecture).expect("write string");
            writeln!(output, "Signal: {}", report.signal).expect("write string");
            render_evidence(&mut output, "Class", &report.class, |value| value.clone());
            render_evidence(&mut output, "PC", &report.pc, |value| format!("{value:#x}"));
            render_evidence(&mut output, "SP", &report.sp, |value| format!("{value:#x}"));
            render_evidence(
                &mut output,
                "Fault address",
                &report.fault_address,
                |value| format!("{value:#x}"),
            );
            render_evidence(&mut output, "Access", &report.access, |value| {
                format!("{value:?}").to_ascii_lowercase()
            });
            match &report.location {
                Evidence::Observed { value, source } | Evidence::Inferred { value, source } => {
                    writeln!(
                        output,
                        "Location: {}!{} block {:#x}, instruction {:#x} {} [source: {}]",
                        value.module_id,
                        value.function_name.as_deref().unwrap_or("<unnamed>"),
                        value.block_start,
                        value.instruction_va,
                        value.mnemonic,
                        source
                    )
                    .expect("write string");
                }
                Evidence::Unknown { reason } => {
                    writeln!(output, "Location: unknown [reason: {reason}]").expect("write string");
                }
            }
            for window in &report.memory_windows {
                let status = match &window.bytes_hex {
                    Evidence::Observed { value, source } => {
                        format!("observed {} bytes [source: {source}]", value.len() / 2)
                    }
                    Evidence::Inferred { value, source } => {
                        format!("inferred {} bytes [source: {source}]", value.len() / 2)
                    }
                    Evidence::Unknown { reason } => format!("unknown [reason: {reason}]"),
                };
                writeln!(output, "Memory {}: {status}", window.role).expect("write string");
            }
            match &report.native_stack {
                Evidence::Observed { value, source } | Evidence::Inferred { value, source } => {
                    writeln!(
                        output,
                        "Native stack: {} frame(s), stopped: {} [source: {}]",
                        value.frames.len(),
                        value.stop_reason,
                        source
                    )
                    .expect("write string");
                }
                Evidence::Unknown { reason } => {
                    writeln!(output, "Native stack: unknown [reason: {reason}]")
                        .expect("write string");
                }
            }
            render_output_presence(&mut output, "Stdout", &report.stdout);
            render_output_presence(&mut output, "Stderr", &report.stderr);
            writeln!(
                output,
                "Sensitive bytes: redacted; use typed JSON explicitly"
            )
            .expect("write string");
        }
    }
    output
}

fn render_evidence<T>(
    output: &mut String,
    label: &str,
    evidence: &Evidence<T>,
    format_value: impl Fn(&T) -> String,
) {
    match evidence {
        Evidence::Observed { value, source } => {
            writeln!(
                output,
                "{label}: observed {} [source: {source}]",
                format_value(value)
            )
            .expect("write string");
        }
        Evidence::Inferred { value, source } => {
            writeln!(
                output,
                "{label}: inferred {} [source: {source}]",
                format_value(value)
            )
            .expect("write string");
        }
        Evidence::Unknown { reason } => {
            writeln!(output, "{label}: unknown [reason: {reason}]").expect("write string");
        }
    }
}

fn render_output_presence(output: &mut String, label: &str, evidence: &Evidence<String>) {
    match evidence {
        Evidence::Observed { value, source } => {
            writeln!(
                output,
                "{label}: observed {} byte(s), content redacted [source: {source}]",
                value.len()
            )
            .expect("write string");
        }
        Evidence::Inferred { value, source } => {
            writeln!(
                output,
                "{label}: inferred {} byte(s), content redacted [source: {source}]",
                value.len()
            )
            .expect("write string");
        }
        Evidence::Unknown { reason } => {
            writeln!(output, "{label}: unknown [reason: {reason}]").expect("write string");
        }
    }
}

pub fn analyze_crash(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
) -> CrashAnalysis {
    if let Err(reason) = capsule.validate(CapsuleLimits::default()) {
        return CrashAnalysis::InvalidCapsule { reason };
    }
    let signaled: Vec<_> = capsule
        .processes
        .iter()
        .filter_map(|process| match process.terminal {
            Some(TerminalState::Signaled { signal, .. }) => Some((process, signal)),
            _ => None,
        })
        .collect();
    if signaled.is_empty() {
        if capsule.processes.len() == 1 {
            return CrashAnalysis::NoCrash {
                process_id: capsule.processes[0].id.clone(),
            };
        }
        return CrashAnalysis::Incomplete {
            reason: "no uniquely selected crashed process".to_string(),
        };
    }
    if signaled.len() != 1 {
        return CrashAnalysis::Incomplete {
            reason: "multiple signaled processes require explicit selection".to_string(),
        };
    }
    let (process, signal) = signaled[0];
    let faulting: Vec<_> = capsule
        .threads
        .iter()
        .filter(|thread| thread.process_id == process.id && thread.fault.is_some())
        .collect();
    if faulting.len() != 1 {
        return CrashAnalysis::Incomplete {
            reason: format!(
                "expected one faulting thread for process {}, found {}",
                process.id,
                faulting.len()
            ),
        };
    }
    let thread = faulting[0];
    let fault = thread.fault.as_ref().expect("selected faulting thread");
    if fault.signal != signal {
        return CrashAnalysis::Incomplete {
            reason: format!(
                "process terminal signal {signal} disagrees with thread fault signal {}",
                fault.signal
            ),
        };
    }
    let (pc_name, sp_name) = register_names(capsule.target.architecture);
    let pc = observed_register(thread, pc_name);
    let sp = observed_register(thread, sp_name);
    let static_location = match &pc {
        Evidence::Observed { value, .. } => Evidence::Inferred {
            value: resolve_runtime_address(capsule, payloads, image, &process.id, *value),
            source: "exact capsule-to-ProgramImage correlation".to_string(),
        },
        Evidence::Unknown { reason } => Evidence::Unknown {
            reason: format!("PC unavailable: {reason}"),
        },
        Evidence::Inferred { .. } => unreachable!("register observations are never inferred"),
    };
    let fault_mapping = mapping_context(capsule, &process.id, fault.address);
    let access = classify_access(fault.access, &pc, fault.address, &static_location);
    let location = summarize_location(&static_location);
    let registers = Evidence::Observed {
        value: thread.registers.clone(),
        source: "faulting thread register set".to_string(),
    };
    let memory_windows =
        crash_memory_windows(capsule, payloads, &process.id, &pc, &sp, fault.address);
    let native_stack = unwind_native_stack(
        capsule,
        payloads,
        image,
        &process.id,
        thread,
        &pc,
        &static_location,
    );
    let stdout = observed_process_output(capsule, payloads, &process.id, OutputStream::Stdout);
    let stderr = observed_process_output(capsule, payloads, &process.id, OutputStream::Stderr);
    let fault_address = fault.address.map_or_else(
        || Evidence::Unknown {
            reason: "fault provider did not supply an address".to_string(),
        },
        |value| Evidence::Observed {
            value,
            source: "thread terminal fault".to_string(),
        },
    );
    let class = classify_crash(
        signal,
        fault.code,
        fault.sender_pid,
        process.os_pid,
        &stderr,
        fault.address,
        &sp,
        &access,
        &fault_mapping,
        &capsule.events,
        &process.id,
        image,
        &native_stack,
    );
    CrashAnalysis::Crash {
        report: Box::new(CrashReport {
            schema: CRASH_REPORT_SCHEMA.to_string(),
            capture_id: capsule.identity.capture_id.clone(),
            process_id: process.id.clone(),
            thread_id: thread.id.clone(),
            architecture: format!("{:?}", capsule.target.architecture),
            signal,
            signal_code: optional_observation(fault.code, "thread terminal signal code"),
            signal_sender_pid: optional_observation(
                fault.sender_pid,
                "thread terminal signal sender PID",
            ),
            signal_sender_uid: optional_observation(
                fault.sender_uid,
                "thread terminal signal sender UID",
            ),
            stdout,
            stderr,
            pc,
            sp,
            registers,
            fault_address,
            access,
            class,
            fault_mapping,
            location,
            memory_windows,
            native_stack,
            static_location,
        }),
    }
}

fn observed_process_output(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    process_id: &str,
    stream: OutputStream,
) -> Evidence<String> {
    let matches: Vec<_> = capsule
        .outputs
        .iter()
        .filter(|output| output.process_id == process_id && output.stream == stream)
        .collect();
    if matches.len() != 1 {
        return Evidence::Unknown {
            reason: format!("expected one {stream:?} record, found {}", matches.len()),
        };
    }
    let output = matches[0];
    if output.truncated {
        return Evidence::Unknown {
            reason: format!("captured {stream:?} is truncated"),
        };
    }
    let payload = &output.payload;
    let Some(bytes) = payloads.get(&payload.id) else {
        return Evidence::Unknown {
            reason: format!("output payload {} is unavailable", payload.id),
        };
    };
    if bytes.len() as u64 != payload.byte_len
        || hex::encode(sha2::Sha256::digest(bytes)) != payload.sha256
    {
        return Evidence::Unknown {
            reason: format!("output payload {} disagrees with its identity", payload.id),
        };
    }
    match String::from_utf8(bytes.clone()) {
        Ok(value) => Evidence::Observed {
            value,
            source: format!("captured {stream:?} payload {}", payload.sha256),
        },
        Err(_) => Evidence::Unknown {
            reason: format!("captured {stream:?} is not UTF-8"),
        },
    }
}

fn optional_observation<T>(value: Option<T>, source: &str) -> Evidence<T> {
    value.map_or_else(
        || Evidence::Unknown {
            reason: format!("provider did not supply {source}"),
        },
        |value| Evidence::Observed {
            value,
            source: source.to_string(),
        },
    )
}

fn unwind_native_stack(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    process_id: &str,
    thread: &super::capsule::ThreadRecord,
    pc: &Evidence<u64>,
    static_location: &Evidence<AddressResolution>,
) -> Evidence<NativeStack> {
    if capsule.target.architecture != Arch::X86_64 {
        return Evidence::Unknown {
            reason: "bounded native unwinding currently supports x86-64 only".to_string(),
        };
    }
    let Evidence::Observed { value: pc, .. } = pc else {
        return Evidence::Unknown {
            reason: "native unwinding requires an observed program counter".to_string(),
        };
    };
    let frame_pointer = observed_register(thread, "rbp");
    let Evidence::Observed {
        value: mut current_rbp,
        ..
    } = frame_pointer
    else {
        return Evidence::Inferred {
            value: NativeStack {
                frames: vec![NativeStackFrame {
                    index: 0,
                    pc: *pc,
                    frame_pointer: None,
                    return_slot: None,
                    confidence: NativeFrameConfidence::ObservedProgramCounter,
                    location: summarize_location(static_location),
                }],
                stop_reason: "frame pointer register is unavailable".to_string(),
            },
            source: "observed fault program counter".to_string(),
        };
    };
    let view = RuntimeMemoryView::new(capsule, payloads, process_id)
        .expect("validated capsule contains selected process");
    let mut frames = vec![NativeStackFrame {
        index: 0,
        pc: *pc,
        frame_pointer: Some(current_rbp),
        return_slot: None,
        confidence: NativeFrameConfidence::ObservedProgramCounter,
        location: summarize_location(static_location),
    }];
    let stop_reason = loop {
        if frames.len() >= MAX_NATIVE_FRAMES {
            break format!("frame limit {MAX_NATIVE_FRAMES} reached");
        }
        let chain = match view.read_runtime_bytes(current_rbp, 16) {
            Ok(bytes) => bytes,
            Err(error) => break format!("frame chain stopped: {error}"),
        };
        let next_rbp = u64::from_le_bytes(chain[0..8].try_into().expect("fixed frame word"));
        let return_pc = u64::from_le_bytes(chain[8..16].try_into().expect("fixed return word"));
        if return_pc == 0 {
            break "frame chain contains a null return address".to_string();
        }
        let return_slot = current_rbp
            .checked_add(8)
            .expect("readable 16-byte frame cannot overflow");
        let resolution = Evidence::Inferred {
            value: resolve_runtime_address(capsule, payloads, image, process_id, return_pc),
            source: "x86-64 frame-pointer return address".to_string(),
        };
        frames.push(NativeStackFrame {
            index: frames.len(),
            pc: return_pc,
            frame_pointer: (next_rbp != 0).then_some(next_rbp),
            return_slot: Some(return_slot),
            confidence: NativeFrameConfidence::FramePointerChain,
            location: summarize_location(&resolution),
        });
        if next_rbp == 0 {
            break "frame chain reached a null previous frame pointer".to_string();
        }
        let Some(step) = next_rbp.checked_sub(current_rbp) else {
            break "frame chain is not monotonically increasing".to_string();
        };
        if step < 16 || step > MAX_FRAME_POINTER_STEP || next_rbp % 8 != 0 {
            break format!("frame pointer step {step} is outside bounded ABI checks");
        }
        current_rbp = next_rbp;
    };
    Evidence::Inferred {
        value: NativeStack {
            frames,
            stop_reason,
        },
        source: "observed PC plus bounded x86-64 frame-pointer chain".to_string(),
    }
}

fn crash_memory_windows(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    process_id: &str,
    pc: &Evidence<u64>,
    sp: &Evidence<u64>,
    fault_address: Option<u64>,
) -> Vec<CrashMemoryWindow> {
    let view = RuntimeMemoryView::new(capsule, payloads, process_id)
        .expect("validated capsule contains selected process");
    let fault = fault_address.map_or_else(
        || Evidence::Unknown {
            reason: "fault provider did not supply an address".to_string(),
        },
        |value| Evidence::Observed {
            value,
            source: "thread terminal fault".to_string(),
        },
    );
    [
        ("program_counter", pc.clone(), CRASH_MEMORY_WINDOW_BYTES / 2),
        ("stack_pointer", sp.clone(), 0),
        ("fault_address", fault, CRASH_MEMORY_WINDOW_BYTES / 2),
    ]
    .into_iter()
    .map(|(role, anchor, bytes_before)| {
        let (Evidence::Observed { value, .. } | Evidence::Inferred { value, .. }) = &anchor else {
            return CrashMemoryWindow {
                role: role.to_string(),
                anchor,
                start: None,
                requested_len: CRASH_MEMORY_WINDOW_BYTES,
                bytes_hex: Evidence::Unknown {
                    reason: format!("{role} is unavailable"),
                },
            };
        };
        let start = value.saturating_sub(bytes_before as u64);
        let bytes_hex = match view.read_runtime_bytes(start, CRASH_MEMORY_WINDOW_BYTES) {
            Ok(bytes) => Evidence::Observed {
                value: hex::encode(bytes),
                source: "captured process-capsule page bytes".to_string(),
            },
            Err(error) => Evidence::Unknown {
                reason: error.to_string(),
            },
        };
        CrashMemoryWindow {
            role: role.to_string(),
            anchor,
            start: Some(start),
            requested_len: CRASH_MEMORY_WINDOW_BYTES,
            bytes_hex,
        }
    })
    .collect()
}

fn summarize_location(location: &Evidence<AddressResolution>) -> Evidence<CrashLocation> {
    let Evidence::Inferred {
        value: AddressResolution::Exact { address },
        ..
    } = location
    else {
        return Evidence::Unknown {
            reason: "crash location requires exact runtime/static correlation".to_string(),
        };
    };
    let (function_entry, function_name) = match &address.function {
        super::correlation::FunctionResolution::Exact { entry_va, name, .. }
        | super::correlation::FunctionResolution::Interior { entry_va, name, .. } => {
            (*entry_va, name.clone())
        }
        _ => {
            return Evidence::Unknown {
                reason: "crash location requires one resolved containing function".to_string(),
            };
        }
    };
    let StaticCodeResolution::Resolved {
        block_start,
        instruction_va,
        instruction_end,
        mnemonic,
        ..
    } = &address.code
    else {
        return Evidence::Unknown {
            reason: "crash location requires one resolved block and instruction".to_string(),
        };
    };
    let Some(module_id) = address.runtime.module_id.clone() else {
        return Evidence::Unknown {
            reason: "crash location requires one resolved runtime module".to_string(),
        };
    };
    Evidence::Inferred {
        value: CrashLocation {
            module_id,
            mapping_id: address.runtime.mapping_id.clone(),
            runtime_va: address.runtime.raw_va,
            image_sha256: address.image_sha256.clone(),
            static_va: address.static_va,
            function_entry,
            function_name,
            block_start: *block_start,
            instruction_va: *instruction_va,
            instruction_end: *instruction_end,
            mnemonic: mnemonic.clone(),
        },
        source: "exact runtime/static correlation projection".to_string(),
    }
}

fn register_names(arch: Arch) -> (&'static str, &'static str) {
    match arch {
        Arch::X86_64 => ("rip", "rsp"),
        Arch::X86 => ("eip", "esp"),
        Arch::AArch64 => ("pc", "sp"),
        Arch::ARM => ("r15", "r13"),
        _ => ("pc", "sp"),
    }
}

fn observed_register(thread: &super::capsule::ThreadRecord, name: &str) -> Evidence<u64> {
    let matches: Vec<_> = thread
        .registers
        .iter()
        .filter(|register| register.provider_name.eq_ignore_ascii_case(name))
        .collect();
    if matches.len() != 1 {
        return Evidence::Unknown {
            reason: format!(
                "expected one provider register {name}, found {}",
                matches.len()
            ),
        };
    }
    match u64::from_str_radix(&matches[0].value_hex, 16) {
        Ok(value) => Evidence::Observed {
            value,
            source: format!("thread register {}", matches[0].provider_name),
        },
        Err(error) => Evidence::Unknown {
            reason: format!("invalid provider register {name}: {error}"),
        },
    }
}

fn classify_access(
    observed: Option<AccessKind>,
    pc: &Evidence<u64>,
    fault_address: Option<u64>,
    location: &Evidence<AddressResolution>,
) -> Evidence<AccessKind> {
    if let Some(access) = observed.filter(|value| *value != AccessKind::Unknown) {
        return Evidence::Observed {
            value: access,
            source: "thread terminal fault".to_string(),
        };
    }
    if matches!(pc, Evidence::Observed { value, .. } if Some(*value) == fault_address) {
        return Evidence::Inferred {
            value: AccessKind::Execute,
            source: "fault address equals observed program counter".to_string(),
        };
    }
    let Evidence::Inferred {
        value: AddressResolution::Exact { address },
        ..
    } = location
    else {
        return Evidence::Unknown {
            reason: "access direction requires an exact static instruction".to_string(),
        };
    };
    let StaticCodeResolution::Resolved {
        operations: OperationResolution::Resolved { operations },
        ..
    } = &address.code
    else {
        return Evidence::Unknown {
            reason: "access direction requires resolved LLIR operations".to_string(),
        };
    };
    let writes = operations
        .iter()
        .any(|operation| matches!(operation.kind.as_str(), "store" | "cond_store"));
    let reads = operations
        .iter()
        .any(|operation| matches!(operation.kind.as_str(), "load" | "cond_load"));
    match (reads, writes) {
        (false, true) => Evidence::Inferred {
            value: AccessKind::Write,
            source: "exact static LLIR operation".to_string(),
        },
        (true, false) => Evidence::Inferred {
            value: AccessKind::Read,
            source: "exact static LLIR operation".to_string(),
        },
        _ => Evidence::Unknown {
            reason: "resolved operations do not establish one access direction".to_string(),
        },
    }
}

fn classify_crash(
    signal: u32,
    signal_code: Option<i32>,
    sender_pid: Option<u64>,
    process_pid: u64,
    stderr: &Evidence<String>,
    fault_address: Option<u64>,
    sp: &Evidence<u64>,
    access: &Evidence<AccessKind>,
    mapping: &Evidence<FaultMappingContext>,
    events: &[EventRecord],
    process_id: &str,
    image: &ProgramImage,
    native_stack: &Evidence<NativeStack>,
) -> Evidence<String> {
    let self_generated =
        signal_code.is_some_and(|code| code <= 0) && sender_pid == Some(process_pid);
    if signal == 6
        && self_generated
        && matches!(stderr, Evidence::Observed { value, .. } if value.contains("Assertion ") && value.contains(" failed."))
    {
        return Evidence::Inferred {
            value: "assertion_failure".to_string(),
            source: "self-generated SIGABRT plus complete captured assertion diagnostic"
                .to_string(),
        };
    }
    if signal == 6 && self_generated && proves_explicit_abort(image, native_stack) {
        return Evidence::Inferred {
            value: "explicit_abort".to_string(),
            source: "self-generated SIGABRT plus captured stack return from an exact static direct call to the ELF abort PLT entry".to_string(),
        };
    }
    if signal != 6 && self_generated {
        if let Some(name) = linux_signal_name(signal) {
            return Evidence::Inferred {
                value: format!("deliberate_signal:{name}"),
                source: "Linux user-origin siginfo with sender PID equal to crashed process"
                    .to_string(),
            };
        }
    }
    let access_value = match access {
        Evidence::Observed { value, .. } | Evidence::Inferred { value, .. } => Some(*value),
        Evidence::Unknown { .. } => None,
    };
    let null_class = match (fault_address, access_value) {
        (Some(0), Some(AccessKind::Write)) => Some("null_write"),
        (Some(0), Some(AccessKind::Read)) => Some("null_read"),
        (Some(0), Some(AccessKind::Execute)) => Some("null_execute"),
        _ => None,
    };
    if let Some(value) = null_class {
        return Evidence::Inferred {
            value: value.to_string(),
            source: "fault address plus access direction".to_string(),
        };
    }
    if proves_recursive_stack_exhaustion(signal, fault_address, sp, mapping, native_stack) {
        return Evidence::Inferred {
            value: "recursive_stack_exhaustion".to_string(),
            source: "fault at SP plus unmapped target and bounded repeated frame chain".to_string(),
        };
    }
    if let Some(value) =
        proves_guard_page_role(fault_address, access_value, mapping, events, process_id)
    {
        return Evidence::Inferred {
            value: value.to_string(),
            source: "fault access plus ordered successful mapping create/protect events"
                .to_string(),
        };
    }
    let mapping_class = match (access_value, mapping) {
        (Some(AccessKind::Read), Evidence::Observed { value, .. }) if !value.readable => {
            Some("read_protection_fault")
        }
        (Some(AccessKind::Write), Evidence::Observed { value, .. }) if !value.writable => {
            Some("write_protection_fault")
        }
        (Some(AccessKind::Execute), Evidence::Observed { value, .. }) if !value.executable => {
            Some("execute_protection_fault")
        }
        (Some(AccessKind::Execute), Evidence::Unknown { reason })
            if reason == "fault address is unmapped" =>
        {
            Some("invalid_control_target")
        }
        _ => None,
    };
    mapping_class.map_or_else(
        || Evidence::Unknown {
            reason: format!("signal {signal} and available evidence do not prove a crash class"),
        },
        |value| Evidence::Inferred {
            value: value.to_string(),
            source: "access direction plus captured mapping permissions".to_string(),
        },
    )
}

fn proves_guard_page_role(
    fault_address: Option<u64>,
    access: Option<AccessKind>,
    mapping: &Evidence<FaultMappingContext>,
    events: &[EventRecord],
    process_id: &str,
) -> Option<&'static str> {
    let fault_address = fault_address?;
    let class = match (access?, mapping) {
        (AccessKind::Read, Evidence::Observed { value, .. }) if !value.readable => {
            "guard_page_read"
        }
        (AccessKind::Write, Evidence::Observed { value, .. }) if !value.writable => {
            "guard_page_write"
        }
        _ => return None,
    };
    let covers = |event: &EventRecord| {
        let start = event.address?;
        let length = event.fields.get("length")?.parse::<u64>().ok()?;
        let end = start.checked_add(length)?;
        Some(start <= fault_address && fault_address < end)
    };
    for protect in events.iter().filter(|event| {
        event.process_id == process_id
            && event.kind == "mapping_protect"
            && event.fields.get("result").map(String::as_str) == Some("success")
            && event.fields.get("permissions").map(String::as_str) == Some("none")
            && covers(event) == Some(true)
    }) {
        let created = events.iter().any(|event| {
            event.process_id == process_id
                && event.thread_id == protect.thread_id
                && event.sequence < protect.sequence
                && event.kind == "mapping_create"
                && event.fields.get("result").map(String::as_str) == Some("success")
                && event.fields.get("permissions").map(String::as_str) == Some("read|write")
                && event
                    .fields
                    .get("flags")
                    .is_some_and(|flags| flags.split('|').any(|flag| flag == "MAP_ANONYMOUS"))
                && covers(event) == Some(true)
        });
        if created {
            return Some(class);
        }
    }
    None
}

/// Prove that one captured x86-64 return address immediately follows a direct
/// call to the ELF PLT entry named ``abort``.
///
/// The return address comes from the sparse runtime stack; the opcode and
/// displacement come from the exact static image selected by correlation; and
/// the callee name comes from the image's relocation-backed PLT map. Absence of
/// any link in that chain returns false rather than treating an arbitrary
/// self-generated SIGABRT as an explicit abort call.
fn proves_explicit_abort(image: &ProgramImage, native_stack: &Evidence<NativeStack>) -> bool {
    if image.arch() != Arch::X86_64 {
        return false;
    }
    let Evidence::Inferred { value: stack, .. } = native_stack else {
        return false;
    };
    let plt = crate::analysis::elf_plt::elf_plt_map(image.bytes());
    stack.frames.iter().skip(1).any(|frame| {
        if frame.return_slot.is_none() {
            return false;
        }
        let Evidence::Inferred {
            value: location, ..
        } = &frame.location
        else {
            return false;
        };
        let Some(call_va) = location.static_va.checked_sub(5) else {
            return false;
        };
        let Some(file_offset) = image.va_to_code_file_offset(call_va) else {
            return false;
        };
        let Some(instruction) = image.bytes().get(file_offset..file_offset + 5) else {
            return false;
        };
        if instruction[0] != 0xe8 {
            return false;
        }
        let displacement = i32::from_le_bytes(instruction[1..5].try_into().expect("four bytes"));
        let Some(target) = location
            .static_va
            .checked_add_signed(i64::from(displacement))
        else {
            return false;
        };
        plt.iter()
            .any(|(entry, name)| *entry == target && name == "abort@plt")
    })
}

fn linux_signal_name(signal: u32) -> Option<&'static str> {
    match signal {
        4 => Some("SIGILL"),
        5 => Some("SIGTRAP"),
        7 => Some("SIGBUS"),
        8 => Some("SIGFPE"),
        11 => Some("SIGSEGV"),
        _ => None,
    }
}

fn proves_recursive_stack_exhaustion(
    signal: u32,
    fault_address: Option<u64>,
    sp: &Evidence<u64>,
    mapping: &Evidence<FaultMappingContext>,
    native_stack: &Evidence<NativeStack>,
) -> bool {
    if signal != 11
        || !matches!(sp, Evidence::Observed { value, .. } if Some(*value) == fault_address)
        || !matches!(mapping, Evidence::Unknown { reason } if reason == "fault address is unmapped")
    {
        return false;
    }
    let Evidence::Inferred { value: stack, .. } = native_stack else {
        return false;
    };
    if stack.frames.len() != MAX_NATIVE_FRAMES
        || stack.stop_reason != format!("frame limit {MAX_NATIVE_FRAMES} reached")
    {
        return false;
    }
    let entries: Vec<_> = stack
        .frames
        .iter()
        .filter_map(|frame| match &frame.location {
            Evidence::Inferred { value, .. } => Some(value.function_entry),
            _ => None,
        })
        .collect();
    entries.len() == stack.frames.len()
        && entries
            .first()
            .is_some_and(|first| entries.iter().all(|entry| entry == first))
}

fn mapping_context(
    capsule: &ProcessCapsule,
    process_id: &str,
    address: Option<u64>,
) -> Evidence<FaultMappingContext> {
    let Some(address) = address else {
        return Evidence::Unknown {
            reason: "fault address is unavailable".to_string(),
        };
    };
    let mappings: Vec<_> = capsule
        .mappings
        .iter()
        .filter(|mapping| {
            mapping.process_id == process_id && mapping.start <= address && address < mapping.end
        })
        .collect();
    if mappings.len() != 1 {
        return Evidence::Unknown {
            reason: if mappings.is_empty() {
                "fault address is unmapped".to_string()
            } else {
                "fault address has ambiguous mapping ownership".to_string()
            },
        };
    }
    let mapping = mappings[0];
    let backing = match &mapping.backing {
        MappingBacking::File { .. } => "file",
        MappingBacking::Anonymous => "anonymous",
        MappingBacking::Special { .. } => "special",
        MappingBacking::Unknown { .. } => "unknown",
    };
    Evidence::Observed {
        value: FaultMappingContext {
            mapping_id: mapping.id.clone(),
            readable: mapping.permissions.read,
            writable: mapping.permissions.write,
            executable: mapping.permissions.execute,
            backing: backing.to_string(),
        },
        source: "captured mapping table".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_analysis::capsule::{FaultRecord, RegisterObservation};
    use crate::runtime_analysis::correlation::tests::{capsule, hello_image};

    #[test]
    fn running_capture_is_not_a_crash() {
        let image = hello_image();
        let capsule = capsule(&image);
        assert_eq!(
            analyze_crash(&capsule, &BTreeMap::new(), &image),
            CrashAnalysis::NoCrash {
                process_id: "process-main".to_string()
            }
        );
    }

    #[test]
    fn missing_faulting_thread_is_explicitly_incomplete() {
        let image = hello_image();
        let mut capsule = capsule(&image);
        capsule.processes[0].terminal = Some(TerminalState::Signaled {
            signal: 11,
            core_dumped: true,
        });
        assert!(matches!(
            analyze_crash(&capsule, &BTreeMap::new(), &image),
            CrashAnalysis::Incomplete { .. }
        ));
    }

    #[test]
    fn observed_write_supports_null_write_classification() {
        let image = hello_image();
        let mut capsule = capsule(&image);
        capsule.processes[0].terminal = Some(TerminalState::Signaled {
            signal: 11,
            core_dumped: true,
        });
        capsule.threads.push(super::super::capsule::ThreadRecord {
            id: "thread-main".to_string(),
            process_id: "process-main".to_string(),
            os_tid: 1,
            registers: vec![
                RegisterObservation {
                    provider_name: "rip".to_string(),
                    bit_width: 64,
                    value_hex: "0000000070002549".to_string(),
                },
                RegisterObservation {
                    provider_name: "rsp".to_string(),
                    bit_width: 64,
                    value_hex: "0000000070001000".to_string(),
                },
            ],
            fault: Some(FaultRecord {
                signal: 11,
                code: None,
                sender_pid: None,
                sender_uid: None,
                address: Some(0),
                access: Some(AccessKind::Write),
            }),
        });
        let CrashAnalysis::Crash { report } = analyze_crash(&capsule, &BTreeMap::new(), &image)
        else {
            panic!("expected crash report");
        };
        assert!(matches!(
            report.class,
            Evidence::Inferred { ref value, .. } if value == "null_write"
        ));
        assert!(matches!(report.static_location, Evidence::Inferred { .. }));

        let rendered = render_crash_analysis(&CrashAnalysis::Crash {
            report: report.clone(),
        });
        assert!(rendered.starts_with("Glaurung runtime crash analysis\nOutcome: crash\n"));
        assert!(rendered.contains("Class: inferred null_write"));
        assert!(rendered.contains("Access: observed write"));
        assert!(rendered.contains("Sensitive bytes: redacted; use typed JSON explicitly"));

        let good = crate::runtime_analysis::correlation::tests::capsule(&image);
        let comparison =
            compare_crashes(&good, &BTreeMap::new(), &capsule, &BTreeMap::new(), &image);
        assert!(matches!(
            comparison.contrast,
            CrashContrast::BadOnly {
                class: Evidence::Inferred { ref value, .. }
            } if value == "null_write"
        ));

        capsule.threads[0]
            .fault
            .as_mut()
            .expect("fixture fault")
            .signal = 7;
        assert!(matches!(
            analyze_crash(&capsule, &BTreeMap::new(), &image),
            CrashAnalysis::Incomplete { ref reason }
                if reason.contains("disagrees with thread fault signal")
        ));
    }

    #[test]
    fn fault_target_equal_to_pc_supports_execute_access() {
        let access = classify_access(
            None,
            &Evidence::Observed {
                value: 0x1234,
                source: "test register".to_string(),
            },
            Some(0x1234),
            &Evidence::Unknown {
                reason: "target is outside the static image".to_string(),
            },
        );
        assert!(matches!(
            access,
            Evidence::Inferred {
                value: AccessKind::Execute,
                ..
            }
        ));
    }

    #[test]
    fn access_and_mapping_permissions_support_protection_classes() {
        let mapping = Evidence::Observed {
            value: FaultMappingContext {
                mapping_id: "mapping-test".to_string(),
                readable: false,
                writable: false,
                executable: false,
                backing: "anonymous".to_string(),
            },
            source: "test mapping".to_string(),
        };
        for (access, expected) in [
            (AccessKind::Read, "read_protection_fault"),
            (AccessKind::Write, "write_protection_fault"),
            (AccessKind::Execute, "execute_protection_fault"),
        ] {
            let class = classify_crash(
                11,
                None,
                None,
                1,
                &Evidence::Unknown {
                    reason: "test stderr".to_string(),
                },
                Some(0x1234),
                &Evidence::Unknown {
                    reason: "test SP".to_string(),
                },
                &Evidence::Inferred {
                    value: access,
                    source: "test access".to_string(),
                },
                &mapping,
                &[],
                "process-test",
                &hello_image(),
                &Evidence::Unknown {
                    reason: "test stack".to_string(),
                },
            );
            assert!(matches!(
                class,
                Evidence::Inferred { value, .. } if value == expected
            ));
        }
    }

    #[test]
    fn guard_role_requires_an_ordered_successful_anonymous_transition() {
        let mapping = Evidence::Observed {
            value: FaultMappingContext {
                mapping_id: "mapping-test".to_string(),
                readable: false,
                writable: false,
                executable: false,
                backing: "anonymous".to_string(),
            },
            source: "test mapping".to_string(),
        };
        let event = |sequence, kind: &str, permissions: &str| EventRecord {
            process_id: "process-test".to_string(),
            thread_id: Some("thread-test".to_string()),
            sequence,
            kind: kind.to_string(),
            address: Some(0x1000),
            fields: BTreeMap::from([
                ("length".to_string(), "8192".to_string()),
                ("permissions".to_string(), permissions.to_string()),
                ("result".to_string(), "success".to_string()),
                ("flags".to_string(), "MAP_PRIVATE|MAP_ANONYMOUS".to_string()),
            ]),
        };
        let create = event(1, "mapping_create", "read|write");
        let protect = event(2, "mapping_protect", "none");
        assert_eq!(
            proves_guard_page_role(
                Some(0x1800),
                Some(AccessKind::Read),
                &mapping,
                &[create.clone(), protect.clone()],
                "process-test",
            ),
            Some("guard_page_read")
        );
        assert_eq!(
            proves_guard_page_role(
                Some(0x1800),
                Some(AccessKind::Read),
                &mapping,
                &[
                    event(1, "mapping_protect", "none"),
                    event(2, "mapping_create", "read|write"),
                ],
                "process-test",
            ),
            None
        );
    }

    #[test]
    fn unmapped_execute_target_is_an_invalid_control_target() {
        let class = classify_crash(
            11,
            None,
            None,
            1,
            &Evidence::Unknown {
                reason: "test stderr".to_string(),
            },
            Some(1),
            &Evidence::Unknown {
                reason: "test SP".to_string(),
            },
            &Evidence::Inferred {
                value: AccessKind::Execute,
                source: "test access".to_string(),
            },
            &Evidence::Unknown {
                reason: "fault address is unmapped".to_string(),
            },
            &[],
            "process-test",
            &hello_image(),
            &Evidence::Unknown {
                reason: "test stack".to_string(),
            },
        );
        assert!(matches!(
            class,
            Evidence::Inferred { value, .. } if value == "invalid_control_target"
        ));
    }
}
