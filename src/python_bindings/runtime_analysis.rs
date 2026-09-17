//! Python surface for the provider-neutral process-capsule contract.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use sha2::Digest;

use crate::program::image::ProgramImage;
use crate::runtime_analysis::behavior::{
    analyze_descriptor_behavior, analyze_file_behavior, analyze_mapping_behavior,
    analyze_process_behavior,
};
use crate::runtime_analysis::bundle::import_capsule_bundle;
use crate::runtime_analysis::capsule::{
    CapsuleLimits, InputBytesIdentity, OutputStream, PayloadReference, ProcessCapsule,
    ProcessOutputRecord, Sensitivity,
};
use crate::runtime_analysis::correlation::{
    classify_runtime_pages, resolve_runtime_address, runtime_identity_graph,
};
use crate::runtime_analysis::corruption::analyze_object_changes;
use crate::runtime_analysis::crash::{
    analyze_crash, compare_crashes, render_crash_analysis, CrashAnalysis,
};
use crate::runtime_analysis::elf_core::{
    executable_build_id, import_elf_core, CoreImportInput, ElfCoreLimits,
};
use crate::runtime_analysis::event_correlation::{correlate_input_events, correlate_ioctl_events};
use crate::runtime_analysis::input::{input_provenance, resolve_input_byte};
use crate::runtime_analysis::instruction_trace::analyze_instruction_trace;
use crate::runtime_analysis::stack_objects::analyze_stack_writes;

/// Validate capsule JSON and return its deterministic canonical representation.
#[pyfunction]
#[pyo3(name = "canonicalize_process_capsule_json")]
fn canonicalize_process_capsule_json_py(json_text: &str) -> PyResult<String> {
    let limits = CapsuleLimits::default();
    let capsule =
        ProcessCapsule::from_json(json_text.as_bytes(), limits).map_err(PyValueError::new_err)?;
    let bytes = capsule
        .to_canonical_json(limits)
        .map_err(PyValueError::new_err)?;
    String::from_utf8(bytes).map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Validate capsule JSON without weakening the Rust import limits.
#[pyfunction]
#[pyo3(name = "validate_process_capsule_json")]
fn validate_process_capsule_json_py(json_text: &str) -> PyResult<()> {
    ProcessCapsule::from_json(json_text.as_bytes(), CapsuleLimits::default())
        .map(|_| ())
        .map_err(PyValueError::new_err)
}

/// Read the GNU build ID from exact ELF executable bytes.
#[pyfunction]
#[pyo3(name = "elf_executable_build_id")]
fn elf_executable_build_id_py(executable_bytes: &[u8]) -> PyResult<Option<String>> {
    executable_build_id(executable_bytes).map_err(PyValueError::new_err)
}

/// Import a Linux x86-64 ELF core and return canonical metadata plus payloads.
#[pyfunction]
#[pyo3(name = "import_elf_core", signature = (
    core_bytes,
    executable_bytes,
    core_display_path = None,
    executable_display_path = None,
    captured_at = "unknown",
    invocation_input = None,
    stdout = None,
    stderr = None
))]
fn import_elf_core_py(
    core_bytes: &[u8],
    executable_bytes: &[u8],
    core_display_path: Option<String>,
    executable_display_path: Option<String>,
    captured_at: &str,
    invocation_input: Option<&[u8]>,
    stdout: Option<&[u8]>,
    stderr: Option<&[u8]>,
) -> PyResult<(String, Vec<(String, Vec<u8>)>)> {
    let input_bytes = invocation_input
        .map(|bytes| {
            vec![InputBytesIdentity {
                name: "argv[1]".to_string(),
                sha256: hex::encode(sha2::Sha256::digest(bytes)),
                byte_len: bytes.len() as u64,
                sensitivity: Sensitivity::Public,
            }]
        })
        .unwrap_or_default();
    let mut imported = import_elf_core(
        CoreImportInput {
            core_bytes,
            core_display_path,
            executable_bytes,
            executable_display_path,
            captured_at: captured_at.to_string(),
            input_bytes,
        },
        ElfCoreLimits::default(),
    )
    .map_err(PyValueError::new_err)?;
    let process_id = imported
        .capsule
        .processes
        .first()
        .ok_or_else(|| PyValueError::new_err("imported core has no process"))?
        .id
        .clone();
    for (stream, name, bytes) in [
        (OutputStream::Stdout, "stdout", stdout),
        (OutputStream::Stderr, "stderr", stderr),
    ] {
        let Some(bytes) = bytes else { continue };
        let id = format!("process-output-{name}");
        imported.capsule.outputs.push(ProcessOutputRecord {
            process_id: process_id.clone(),
            stream,
            payload: PayloadReference {
                id: id.clone(),
                sha256: hex::encode(sha2::Sha256::digest(bytes)),
                byte_len: bytes.len() as u64,
                sensitivity: Sensitivity::Sensitive,
            },
            truncated: false,
        });
        imported.payloads.insert(id, bytes.to_vec());
    }
    let metadata = imported
        .capsule
        .to_canonical_json(CapsuleLimits::default())
        .map_err(PyValueError::new_err)?;
    let metadata =
        String::from_utf8(metadata).map_err(|error| PyValueError::new_err(error.to_string()))?;
    Ok((metadata, imported.payloads.into_iter().collect()))
}

/// Import and verify public capsule metadata plus its exact payload directory.
#[pyfunction]
#[pyo3(name = "import_process_capsule_bundle")]
fn import_process_capsule_bundle_py(
    metadata_path: &str,
    payload_directory: &str,
) -> PyResult<(String, usize)> {
    let limits = CapsuleLimits::default();
    let imported = import_capsule_bundle(
        std::path::Path::new(metadata_path),
        std::path::Path::new(payload_directory),
        limits,
    )
    .map_err(PyValueError::new_err)?;
    let payload_count = imported.payloads.len();
    let metadata = imported
        .capsule
        .to_canonical_json(limits)
        .map_err(PyValueError::new_err)?;
    let metadata =
        String::from_utf8(metadata).map_err(|error| PyValueError::new_err(error.to_string()))?;
    Ok((metadata, payload_count))
}

/// Import a capsule bundle and return the payload bytes already verified by Rust.
///
/// This is the persistence-facing form of `import_process_capsule_bundle`. It
/// deliberately returns the bytes from the same file descriptors used for
/// validation, so a caller never validates paths and then reopens them in
/// Python across a time-of-check/time-of-use gap.
#[pyfunction]
#[pyo3(name = "load_process_capsule_bundle")]
fn load_process_capsule_bundle_py(
    metadata_path: &str,
    payload_directory: &str,
) -> PyResult<(String, Vec<(String, Vec<u8>)>)> {
    let limits = CapsuleLimits::default();
    let imported = import_capsule_bundle(
        std::path::Path::new(metadata_path),
        std::path::Path::new(payload_directory),
        limits,
    )
    .map_err(PyValueError::new_err)?;
    let metadata = imported
        .capsule
        .to_canonical_json(limits)
        .map_err(PyValueError::new_err)?;
    let metadata =
        String::from_utf8(metadata).map_err(|error| PyValueError::new_err(error.to_string()))?;
    Ok((metadata, imported.payloads.into_iter().collect()))
}

/// Resolve one runtime VA to an exact static image relation or typed failure.
#[pyfunction]
#[pyo3(name = "resolve_process_capsule_address")]
fn resolve_process_capsule_address_py(
    capsule_json: &str,
    payloads: Vec<(String, Vec<u8>)>,
    executable_bytes: &[u8],
    process_id: &str,
    raw_va: u64,
) -> PyResult<String> {
    let capsule = ProcessCapsule::from_json(capsule_json.as_bytes(), CapsuleLimits::default())
        .map_err(PyValueError::new_err)?;
    let mut payload_map = std::collections::BTreeMap::new();
    for (id, bytes) in payloads {
        if payload_map.insert(id.clone(), bytes).is_some() {
            return Err(PyValueError::new_err(format!(
                "duplicate runtime payload id: {id}"
            )));
        }
    }
    let image = ProgramImage::from_bytes(executable_bytes.to_vec())
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    let resolution = resolve_runtime_address(&capsule, &payload_map, &image, process_id, raw_va);
    serde_json::to_string(&resolution).map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Project one capsule process into explicit runtime module/mapping identities.
#[pyfunction]
#[pyo3(name = "process_capsule_runtime_identities")]
fn process_capsule_runtime_identities_py(capsule_json: &str, process_id: &str) -> PyResult<String> {
    let capsule = ProcessCapsule::from_json(capsule_json.as_bytes(), CapsuleLimits::default())
        .map_err(PyValueError::new_err)?;
    let graph = runtime_identity_graph(&capsule, process_id).map_err(PyValueError::new_err)?;
    serde_json::to_string(&graph).map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Classify runtime pages against one exact static image where evidence permits.
#[pyfunction]
#[pyo3(name = "classify_process_capsule_pages")]
fn classify_process_capsule_pages_py(
    capsule_json: &str,
    payloads: Vec<(String, Vec<u8>)>,
    executable_bytes: &[u8],
    process_id: &str,
) -> PyResult<String> {
    let capsule = ProcessCapsule::from_json(capsule_json.as_bytes(), CapsuleLimits::default())
        .map_err(PyValueError::new_err)?;
    let mut payload_map = std::collections::BTreeMap::new();
    for (id, bytes) in payloads {
        if payload_map.insert(id.clone(), bytes).is_some() {
            return Err(PyValueError::new_err(format!(
                "duplicate runtime payload id: {id}"
            )));
        }
    }
    let image = ProgramImage::from_bytes(executable_bytes.to_vec())
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    let pages = classify_runtime_pages(&capsule, &payload_map, &image, process_id)
        .map_err(PyValueError::new_err)?;
    serde_json::to_string(&pages).map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Diff ordered, hash-verified snapshots within each runtime object.
#[pyfunction]
#[pyo3(name = "analyze_process_capsule_object_changes")]
fn analyze_process_capsule_object_changes_py(
    capsule_json: &str,
    payloads: Vec<(String, Vec<u8>)>,
    executable_bytes: &[u8],
) -> PyResult<String> {
    let capsule = ProcessCapsule::from_json(capsule_json.as_bytes(), CapsuleLimits::default())
        .map_err(PyValueError::new_err)?;
    let mut payload_map = std::collections::BTreeMap::new();
    for (id, bytes) in payloads {
        if payload_map.insert(id.clone(), bytes).is_some() {
            return Err(PyValueError::new_err(format!(
                "duplicate runtime payload id: {id}"
            )));
        }
    }
    let image = ProgramImage::from_bytes(executable_bytes.to_vec())
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    serde_json::to_string(&analyze_object_changes(&capsule, &payload_map, &image))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Derive provider-neutral mapping transitions and W-to-X findings.
#[pyfunction]
#[pyo3(name = "analyze_process_capsule_mapping_behavior")]
fn analyze_process_capsule_mapping_behavior_py(capsule_json: &str) -> PyResult<String> {
    let capsule = ProcessCapsule::from_json(capsule_json.as_bytes(), CapsuleLimits::default())
        .map_err(PyValueError::new_err)?;
    serde_json::to_string(&analyze_mapping_behavior(&capsule))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Normalize bounded file-open facts without exposing redacted paths.
#[pyfunction]
#[pyo3(name = "analyze_process_capsule_file_behavior")]
fn analyze_process_capsule_file_behavior_py(capsule_json: &str) -> PyResult<String> {
    let capsule = ProcessCapsule::from_json(capsule_json.as_bytes(), CapsuleLimits::default())
        .map_err(PyValueError::new_err)?;
    serde_json::to_string(&analyze_file_behavior(&capsule))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Normalize non-file descriptor resources and transfers from capsule events.
#[pyfunction]
#[pyo3(name = "analyze_process_capsule_descriptor_behavior")]
fn analyze_process_capsule_descriptor_behavior_py(capsule_json: &str) -> PyResult<String> {
    let capsule = ProcessCapsule::from_json(capsule_json.as_bytes(), CapsuleLimits::default())
        .map_err(PyValueError::new_err)?;
    serde_json::to_string(&analyze_descriptor_behavior(&capsule))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Normalize bounded parent-side process creation and wait observations.
#[pyfunction]
#[pyo3(name = "analyze_process_capsule_process_behavior")]
fn analyze_process_capsule_process_behavior_py(capsule_json: &str) -> PyResult<String> {
    let capsule = ProcessCapsule::from_json(capsule_json.as_bytes(), CapsuleLimits::default())
        .map_err(PyValueError::new_err)?;
    serde_json::to_string(&analyze_process_behavior(&capsule))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Assign stable execution-scoped identities to capsule input sources.
#[pyfunction]
#[pyo3(name = "process_capsule_input_provenance")]
fn process_capsule_input_provenance_py(capsule_json: &str) -> PyResult<String> {
    let capsule = ProcessCapsule::from_json(capsule_json.as_bytes(), CapsuleLimits::default())
        .map_err(PyValueError::new_err)?;
    serde_json::to_string(&input_provenance(&capsule))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Resolve one bounded source offset to a stable input-byte identity.
#[pyfunction]
#[pyo3(name = "resolve_process_capsule_input_byte")]
fn resolve_process_capsule_input_byte_py(
    capsule_json: &str,
    source_name: &str,
    offset: u64,
) -> PyResult<String> {
    let capsule = ProcessCapsule::from_json(capsule_json.as_bytes(), CapsuleLimits::default())
        .map_err(PyValueError::new_err)?;
    serde_json::to_string(
        &resolve_input_byte(&capsule, source_name, offset).map_err(PyValueError::new_err)?,
    )
    .map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Join observed IOCTL events to exact static call and LLIR identities.
#[pyfunction]
#[pyo3(name = "correlate_process_capsule_ioctl_events")]
fn correlate_process_capsule_ioctl_events_py(
    capsule_json: &str,
    executable_bytes: &[u8],
) -> PyResult<String> {
    let capsule = ProcessCapsule::from_json(capsule_json.as_bytes(), CapsuleLimits::default())
        .map_err(PyValueError::new_err)?;
    let image = ProgramImage::from_bytes(executable_bytes.to_vec())
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    serde_json::to_string(&correlate_ioctl_events(&capsule, &image))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Join selected input events to exact static call and LLIR identities.
#[pyfunction]
#[pyo3(name = "correlate_process_capsule_input_events")]
fn correlate_process_capsule_input_events_py(
    capsule_json: &str,
    executable_bytes: &[u8],
) -> PyResult<String> {
    let capsule = ProcessCapsule::from_json(capsule_json.as_bytes(), CapsuleLimits::default())
        .map_err(PyValueError::new_err)?;
    let image = ProgramImage::from_bytes(executable_bytes.to_vec())
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    serde_json::to_string(&correlate_input_events(&capsule, &image))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Analyze one capsule and exact executable into a typed crash report.
#[pyfunction]
#[pyo3(name = "analyze_process_capsule_crash")]
fn analyze_process_capsule_crash_py(
    capsule_json: &str,
    payloads: Vec<(String, Vec<u8>)>,
    executable_bytes: &[u8],
) -> PyResult<String> {
    let capsule = ProcessCapsule::from_json(capsule_json.as_bytes(), CapsuleLimits::default())
        .map_err(PyValueError::new_err)?;
    let mut payload_map = std::collections::BTreeMap::new();
    for (id, bytes) in payloads {
        if payload_map.insert(id.clone(), bytes).is_some() {
            return Err(PyValueError::new_err(format!(
                "duplicate runtime payload id: {id}"
            )));
        }
    }
    let image = ProgramImage::from_bytes(executable_bytes.to_vec())
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    serde_json::to_string(&analyze_crash(&capsule, &payload_map, &image))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Analyze and render a deterministic summary with sensitive bytes redacted.
#[pyfunction]
#[pyo3(name = "render_process_capsule_crash")]
fn render_process_capsule_crash_py(
    capsule_json: &str,
    payloads: Vec<(String, Vec<u8>)>,
    executable_bytes: &[u8],
) -> PyResult<String> {
    let capsule = ProcessCapsule::from_json(capsule_json.as_bytes(), CapsuleLimits::default())
        .map_err(PyValueError::new_err)?;
    let mut payload_map = std::collections::BTreeMap::new();
    for (id, bytes) in payloads {
        if payload_map.insert(id.clone(), bytes).is_some() {
            return Err(PyValueError::new_err(format!(
                "duplicate runtime payload id: {id}"
            )));
        }
    }
    let image = ProgramImage::from_bytes(executable_bytes.to_vec())
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    Ok(render_crash_analysis(&analyze_crash(
        &capsule,
        &payload_map,
        &image,
    )))
}

/// Render an already-persisted typed crash analysis without reacquiring state.
#[pyfunction]
#[pyo3(name = "render_runtime_crash_analysis_json")]
fn render_runtime_crash_analysis_json_py(analysis_json: &str) -> PyResult<String> {
    let analysis: CrashAnalysis = serde_json::from_str(analysis_json)
        .map_err(|error| PyValueError::new_err(format!("invalid crash analysis: {error}")))?;
    Ok(render_crash_analysis(&analysis))
}

/// Compare a completed good control with its bad case under one exact image.
#[pyfunction]
#[pyo3(name = "compare_process_capsule_crashes")]
fn compare_process_capsule_crashes_py(
    good_capsule_json: &str,
    good_payloads: Vec<(String, Vec<u8>)>,
    bad_capsule_json: &str,
    bad_payloads: Vec<(String, Vec<u8>)>,
    executable_bytes: &[u8],
) -> PyResult<String> {
    let limits = CapsuleLimits::default();
    let good_capsule = ProcessCapsule::from_json(good_capsule_json.as_bytes(), limits)
        .map_err(PyValueError::new_err)?;
    let bad_capsule = ProcessCapsule::from_json(bad_capsule_json.as_bytes(), limits)
        .map_err(PyValueError::new_err)?;
    let collect = |items: Vec<(String, Vec<u8>)>| -> PyResult<std::collections::BTreeMap<_, _>> {
        let mut result = std::collections::BTreeMap::new();
        for (id, bytes) in items {
            if result.insert(id.clone(), bytes).is_some() {
                return Err(PyValueError::new_err(format!(
                    "duplicate runtime payload id: {id}"
                )));
            }
        }
        Ok(result)
    };
    let good_payloads = collect(good_payloads)?;
    let bad_payloads = collect(bad_payloads)?;
    let image = ProgramImage::from_bytes(executable_bytes.to_vec())
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    serde_json::to_string(&compare_crashes(
        &good_capsule,
        &good_payloads,
        &bad_capsule,
        &bad_payloads,
        &image,
    ))
    .map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Relate observed input writes to exact DWARF stack-object and field bounds.
#[pyfunction]
#[pyo3(name = "analyze_process_capsule_stack_writes")]
fn analyze_process_capsule_stack_writes_py(
    capsule_json: &str,
    payloads: Vec<(String, Vec<u8>)>,
    executable_bytes: &[u8],
) -> PyResult<String> {
    let capsule = ProcessCapsule::from_json(capsule_json.as_bytes(), CapsuleLimits::default())
        .map_err(PyValueError::new_err)?;
    let mut payload_map = std::collections::BTreeMap::new();
    for (id, bytes) in payloads {
        if payload_map.insert(id.clone(), bytes).is_some() {
            return Err(PyValueError::new_err(format!(
                "duplicate runtime payload id: {id}"
            )));
        }
    }
    let image = ProgramImage::from_bytes(executable_bytes.to_vec())
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    serde_json::to_string(&analyze_stack_writes(&capsule, &payload_map, &image))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Relate bounded instruction-step memory changes to exact LLIR stores.
#[pyfunction]
#[pyo3(name = "analyze_process_capsule_instruction_trace")]
fn analyze_process_capsule_instruction_trace_py(
    capsule_json: &str,
    payloads: Vec<(String, Vec<u8>)>,
    executable_bytes: &[u8],
) -> PyResult<String> {
    let capsule = ProcessCapsule::from_json(capsule_json.as_bytes(), CapsuleLimits::default())
        .map_err(PyValueError::new_err)?;
    let mut payload_map = std::collections::BTreeMap::new();
    for (id, bytes) in payloads {
        if payload_map.insert(id.clone(), bytes).is_some() {
            return Err(PyValueError::new_err(format!(
                "duplicate runtime payload id: {id}"
            )));
        }
    }
    let image = ProgramImage::from_bytes(executable_bytes.to_vec())
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    serde_json::to_string(&analyze_instruction_trace(&capsule, &payload_map, &image))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Register the runtime-analysis submodule.
pub fn register_runtime_analysis_bindings(
    py: Python<'_>,
    parent: &Bound<'_, PyModule>,
) -> PyResult<()> {
    let sub = PyModule::new(py, "runtime_analysis")?;
    sub.add_function(wrap_pyfunction!(
        canonicalize_process_capsule_json_py,
        &sub
    )?)?;
    sub.add_function(wrap_pyfunction!(validate_process_capsule_json_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(elf_executable_build_id_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(import_elf_core_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(import_process_capsule_bundle_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(load_process_capsule_bundle_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(resolve_process_capsule_address_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(
        process_capsule_runtime_identities_py,
        &sub
    )?)?;
    sub.add_function(wrap_pyfunction!(classify_process_capsule_pages_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(
        analyze_process_capsule_mapping_behavior_py,
        &sub
    )?)?;
    sub.add_function(wrap_pyfunction!(
        analyze_process_capsule_file_behavior_py,
        &sub
    )?)?;
    sub.add_function(wrap_pyfunction!(
        analyze_process_capsule_descriptor_behavior_py,
        &sub
    )?)?;
    sub.add_function(wrap_pyfunction!(
        analyze_process_capsule_process_behavior_py,
        &sub
    )?)?;
    sub.add_function(wrap_pyfunction!(process_capsule_input_provenance_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(
        analyze_process_capsule_stack_writes_py,
        &sub
    )?)?;
    sub.add_function(wrap_pyfunction!(
        analyze_process_capsule_instruction_trace_py,
        &sub
    )?)?;
    sub.add_function(wrap_pyfunction!(
        resolve_process_capsule_input_byte_py,
        &sub
    )?)?;
    sub.add_function(wrap_pyfunction!(
        correlate_process_capsule_ioctl_events_py,
        &sub
    )?)?;
    sub.add_function(wrap_pyfunction!(
        correlate_process_capsule_input_events_py,
        &sub
    )?)?;
    sub.add_function(wrap_pyfunction!(
        analyze_process_capsule_object_changes_py,
        &sub
    )?)?;
    sub.add_function(wrap_pyfunction!(analyze_process_capsule_crash_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(render_process_capsule_crash_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(
        render_runtime_crash_analysis_json_py,
        &sub
    )?)?;
    sub.add_function(wrap_pyfunction!(compare_process_capsule_crashes_py, &sub)?)?;
    parent.add_submodule(&sub)?;
    Ok(())
}
