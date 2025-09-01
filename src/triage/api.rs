#[cfg(any(test, feature = "python-ext"))]
use crate::core::binary::Format;
#[cfg(feature = "python-ext")]
use crate::core::triage::TriagedArtifact;
#[cfg(any(test, feature = "python-ext"))]
use crate::core::triage::{TriageError, TriageErrorKind, TriageHint};
#[cfg(feature = "python-ext")]
use crate::core::triage::Budgets;
#[cfg(feature = "python-ext")]
use crate::triage::config::EntropyConfig;
#[cfg(feature = "python-ext")]
use crate::triage::entropy::analyze_entropy;
#[cfg(feature = "python-ext")]
use crate::triage::headers;
// Removed unused import - using languages module instead
#[cfg(feature = "python-ext")]
use crate::triage::io::{
    IOLimits, SafeFileReader, MAX_ENTROPY_SIZE, MAX_HEADER_SIZE, MAX_SNIFF_SIZE,
};
#[cfg(feature = "python-ext")]
use crate::triage::packers::detect_packers;
#[cfg(feature = "python-ext")]
use crate::triage::parsers;
#[cfg(feature = "python-ext")]
use crate::triage::recurse::RecursionEngine;
#[cfg(feature = "python-ext")]
use crate::triage::score;
#[cfg(feature = "python-ext")]
use crate::triage::heuristics::{architecture, endianness};
#[cfg(feature = "python-ext")]
use crate::triage::sniffers::CombinedSniffer;
#[cfg(feature = "python-ext")]
use chrono::Utc;
#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
#[cfg(feature = "python-ext")]
use sha2::{Digest, Sha256};
#[cfg(feature = "python-ext")]
use std::path::Path;
#[cfg(feature = "python-ext")]
use tracing::{debug, info};

#[cfg(feature = "python-ext")]
fn generate_id(path: Option<&Path>, size: usize) -> String {
    let mut hasher = Sha256::new();
    if let Some(p) = path {
        hasher.update(p.to_string_lossy().as_bytes());
    }
    hasher.update(size.to_le_bytes());
    // Use non-deprecated timestamp API; include nanos for uniqueness
    let nanos: i128 = Utc::now().timestamp_nanos_opt().unwrap_or_default().into();
    hasher.update(nanos.to_le_bytes());
    let digest = hasher.finalize();
    format!(
        "triage_{}_{:x}",
        Utc::now().timestamp_millis(),
        u64::from_le_bytes(digest[..8].try_into().unwrap())
    )
}

// Map a sniffer hint to an expected binary format, when possible.
// We use both label and extension/mime to infer a coarse Format.
#[cfg(any(test, feature = "python-ext"))]
pub(crate) fn derive_format_from_hint(h: &TriageHint) -> Option<Format> {
    // Label-based mapping first
    if let Some(label) = &h.label {
        let l = label.to_ascii_lowercase();
        if l.contains("elf") {
            return Some(Format::ELF);
        }
        if l.contains("pe") || l == "exe" || l == "executable" {
            return Some(Format::PE);
        }
        if l.contains("macho") || l == "macho" {
            return Some(Format::MachO);
        }
        if l.contains("wasm") {
            return Some(Format::Wasm);
        }
        if l.contains("pyc") || l.contains("python") {
            return Some(Format::PythonBytecode);
        }
        // Container labels are intentionally not mapped to a binary executable format
    }
    // Extension-based mapping
    if let Some(ext) = &h.extension {
        let e = ext.to_ascii_lowercase();
        if e == "exe" || e == "dll" {
            return Some(Format::PE);
        }
        if e == "elf" || e == "so" {
            return Some(Format::ELF);
        }
        if e == "wasm" {
            return Some(Format::Wasm);
        }
        if e == "pyc" {
            return Some(Format::PythonBytecode);
        }
        if e == "dylib" || e == "macho" {
            return Some(Format::MachO);
        }
    }
    // MIME-based mapping
    if let Some(mime) = &h.mime {
        let m = mime.to_ascii_lowercase();
        if m.contains("application/x-elf") {
            return Some(Format::ELF);
        }
        if m.contains("application/x-dosexec")
            || m.contains("application/x-pe")
            || m.contains("application/x-msdownload")
        {
            return Some(Format::PE);
        }
        if m.contains("application/wasm") || m.contains("application/wasm") {
            return Some(Format::Wasm);
        }
        if m.contains("python") {
            return Some(Format::PythonBytecode);
        }
        if m.contains("x-sharedlib") {
            return Some(Format::ELF);
        }
    }
    None
}

// Compute header vs sniffer mismatch errors.
// - header_formats: formats derived from header validation.
// - container_labels: names from container detection (e.g., zip, tar).
#[cfg(any(test, feature = "python-ext"))]
pub(crate) fn compute_sniffer_header_mismatches(
    hints: &[TriageHint],
    header_formats: &[Format],
    container_labels: &[String],
) -> Vec<TriageError> {
    if header_formats.is_empty() || hints.is_empty() {
        return Vec::new();
    }
    // Do not mark mismatch if hint clearly indicates a container that we detected.
    let container_set: std::collections::HashSet<String> = container_labels
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let is_containerish = |h: &TriageHint| -> bool {
        if let Some(label) = &h.label {
            let l = label.to_ascii_lowercase();
            return matches!(
                l.as_str(),
                "zip"
                    | "jar"
                    | "gzip"
                    | "tar"
                    | "7z"
                    | "xz"
                    | "bzip2"
                    | "zstd"
                    | "lz4"
                    | "rar"
                    | "rar5"
                    | "ar"
                    | "cpio"
            );
        }
        false
    };
    let mut errors = Vec::new();
    for h in hints {
        // Skip container hints when containers detected; that’s not a header mismatch.
        if is_containerish(h) {
            if let Some(label) = &h.label {
                if container_set.contains(&label.to_ascii_lowercase()) {
                    continue;
                }
            }
        }
        if let Some(hfmt) = derive_format_from_hint(h) {
            if !header_formats.contains(&hfmt) {
                errors.push(TriageError::new(
                    TriageErrorKind::SnifferMismatch,
                    Some(format!(
                        "Sniffer suggests {:?} but headers indicate {:?}",
                        hfmt, header_formats
                    )),
                ));
            }
        }
    }
    errors
}

#[cfg(feature = "python-ext")]
fn build_artifact_from_buffers(
    path: String,
    size_bytes: usize,
    sniff_buf: &[u8],
    header_buf: &[u8],
    heur_buf: &[u8],
) -> TriagedArtifact {
    let id = generate_id(None, size_bytes);
    let span =
        tracing::info_span!("triage", triage_id = %id, path = %path, size_bytes = size_bytes);
    let _g = span.enter();
    info!("start");
    debug!(phase = "sniffing", "content+extension sniff");
    let sn = CombinedSniffer::sniff(sniff_buf, Some(Path::new(&path)));
    let hints = sn.hints;
    debug!(phase = "headers", "validate");
    let hdr = headers::validate(header_buf);
    let header_formats_snapshot: Vec<Format> = hdr.candidates.iter().map(|v| v.format).collect();
    let verdicts = hdr.candidates;
    debug!(phase = "entropy", "compute");
    let ecfg = EntropyConfig::default();
    let ea = analyze_entropy(heur_buf, &ecfg);
    let entropy = Some(ea.summary.clone());
    debug!(phase = "heuristics", "endianness and arch");
    let (e_guess, e_conf) = endianness::guess(heur_buf);
    let arch_guesses = architecture::infer(heur_buf);
    debug!(phase = "strings", "extract with language detection");
    let strings = {
        // Use language-aware string extraction
        let s = crate::triage::languages::extract_with_languages(
            heur_buf, 4,  // min_string_length from config or default
            40, // max_samples from config or default
        );
        if s.ascii_count == 0 && s.utf16le_count == 0 && s.utf16be_count == 0 {
            None
        } else {
            Some(s)
        }
    };
    debug!(phase = "parsers", "structured parse probes");
    let parser_results = parsers::parse(heur_buf);
    let containers = {
        // Use recursion engine to discover immediate children (containers)
        let engine = RecursionEngine::default();
        let mut tmp_budget = Budgets::new(size_bytes as u64, 0, 0);
        let v = engine.discover_children(heur_buf, &mut tmp_budget, 0);
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    };
    let packers = {
        let v = detect_packers(heur_buf);
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    };
    // Merge non-fatal errors
    // Cross-check sniffer hints vs header verdicts
    let header_formats: Vec<Format> = header_formats_snapshot;
    let container_labels: Vec<String> = containers
        .as_ref()
        .map(|v| v.iter().map(|c| c.type_name.clone()).collect())
        .unwrap_or_default();
    let mut cross = compute_sniffer_header_mismatches(&hints, &header_formats, &container_labels);

    let merged_errors = if sn.errors.is_empty() && hdr.errors.is_empty() && cross.is_empty() {
        None
    } else {
        Some({
            let mut e = sn.errors;
            e.extend(hdr.errors);
            e.append(&mut cross);
            e
        })
    };

    // Build preliminary artifact (pre-scoring) so scoring can consider context
    let prelim = TriagedArtifact::new(
        id,
        path,
        size_bytes as u64,
        None,
        hints,
        verdicts,
        entropy,
        Some(ea),
        strings.clone(),
        packers,
        containers,
        if parser_results.is_empty() {
            None
        } else {
            Some(parser_results.clone())
        },
        Some(Budgets::new(size_bytes as u64, 0, 0)),
        merged_errors.clone(),
        Some((e_guess, e_conf)),
        Some(arch_guesses.clone()),
    );
    // Score and rank verdicts
    let ranked = score::score(&prelim);
    let art = TriagedArtifact::new(
        prelim.id,
        prelim.path,
        prelim.size_bytes,
        prelim.sha256,
        prelim.hints,
        ranked,
        prelim.entropy,
        prelim.entropy_analysis,
        strings,
        prelim.packers,
        prelim.containers,
        prelim.parse_status,
        prelim.budgets,
        merged_errors,
        prelim.heuristic_endianness,
        prelim.heuristic_arch,
    );
    info!("complete");
    art
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::triage::sniffers::CombinedSniffer;
    use std::fs;
    use std::path::{Path, PathBuf};
    use crate::triage::recurse::RecursionEngine;
    use crate::core::triage::Budgets;

    #[test]
    fn header_vs_sniffer_mismatch_on_elf_with_exe_extension() {
        let path =
            PathBuf::from("samples/binaries/platforms/linux/amd64/export/rust/hello-rust-release");
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => return,
        }; // skip if absent
        let sniff_buf = &data[..data.len().min(crate::triage::io::MAX_SNIFF_SIZE as usize)];
        let header_buf = &data[..data.len().min(crate::triage::io::MAX_HEADER_SIZE as usize)];
        let sn = CombinedSniffer::sniff(sniff_buf, Some(Path::new("fake.exe")));
        let hdr = crate::triage::headers::validate(header_buf);
        let header_formats: Vec<Format> = hdr.candidates.iter().map(|v| v.format).collect();
        assert!(header_formats.contains(&Format::ELF));
        let errs = compute_sniffer_header_mismatches(&sn.hints, &header_formats, &[]);
        // Expect at least one mismatch due to exe extension vs ELF header
        assert!(!errs.is_empty());
        assert!(errs
            .iter()
            .any(|e| e.kind == TriageErrorKind::SnifferMismatch));
    }

    #[test]
    fn container_hint_exemption_for_zip_with_exe_extension() {
        // Use a real ZIP from samples; pretend it's named .exe to trigger extension conflict
        let path = PathBuf::from("samples/containers/zip/hello-cpp-g++-O0.zip");
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => return,
        };
        let sniff_buf = &data[..data.len().min(crate::triage::io::MAX_SNIFF_SIZE as usize)];
        let header_buf = &data[..data.len().min(crate::triage::io::MAX_HEADER_SIZE as usize)];
        let sn = CombinedSniffer::sniff(sniff_buf, Some(Path::new("fake.exe")));
        let hdr = crate::triage::headers::validate(header_buf);
        let header_formats: Vec<Format> = hdr.candidates.iter().map(|v| v.format).collect();
        // Discover containers to feed exemptions
        let engine = RecursionEngine::default();
        let mut tmp_budget = Budgets::new(data.len() as u64, 0, 0);
        let containers = engine.discover_children(&data, &mut tmp_budget, 0);
        let container_labels: Vec<String> = containers.into_iter().map(|c| c.type_name).collect();
        let errs = compute_sniffer_header_mismatches(&sn.hints, &header_formats, &container_labels);
        // With no validated headers and a matching container hint, do not emit a mismatch
        assert!(errs.is_empty());
    }

    #[test]
    fn non_binary_png_classifies_safely() {
        let path = PathBuf::from("assets/glaurung-original.png");
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => return,
        };
        let sniff_buf = &data[..data.len().min(crate::triage::io::MAX_SNIFF_SIZE as usize)];
        let header_buf = &data[..data.len().min(crate::triage::io::MAX_HEADER_SIZE as usize)];
        let sn = CombinedSniffer::sniff(sniff_buf, Some(&path));
        // Expect an image/png label
        assert!(sn.hints.iter().any(|h| h.mime.as_deref() == Some("image/png")));
        let hdr = crate::triage::headers::validate(header_buf);
        // Expect no executable header candidates
        assert!(hdr.candidates.is_empty());
        // No mismatches computed if there are no headers
        let errs = compute_sniffer_header_mismatches(&sn.hints, &[], &[]);
        assert!(errs.is_empty());
    }
}

#[cfg(feature = "python-ext")]
#[pyfunction]
#[pyo3(name = "analyze_path")]
#[pyo3(signature = (path, _max_read_bytes=10_485_760, _max_file_size=104_857_600))]
pub fn analyze_path_py(
    path: String,
    _max_read_bytes: u64,
    _max_file_size: u64,
) -> PyResult<TriagedArtifact> {
    let p = Path::new(&path);
    let limits = IOLimits {
        max_read_bytes: _max_read_bytes,
        max_file_size: _max_file_size,
    };
    let mut reader = SafeFileReader::open(p, limits.clone())
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
    if reader.size() == 0 {
        return Err(pyo3::exceptions::PyValueError::new_err("Empty file"));
    }
    let sniff = reader
        .read_prefix(MAX_SNIFF_SIZE)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
    let header = reader
        .read_prefix(MAX_HEADER_SIZE)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
    let heur = reader
        .read_prefix(MAX_ENTROPY_SIZE)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
    Ok(build_artifact_from_buffers(
        path,
        reader.size() as usize,
        &sniff,
        &header,
        &heur,
    ))
}

#[cfg(feature = "python-ext")]
#[pyfunction]
#[pyo3(name = "analyze_bytes")]
#[pyo3(signature = (data, _max_read_bytes=10_485_760))]
pub fn analyze_bytes_py(data: Vec<u8>, _max_read_bytes: u64) -> PyResult<TriagedArtifact> {
    if data.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err("Empty data"));
    }
    let sniff_len = data.len().min(MAX_SNIFF_SIZE as usize);
    let header_len = data.len().min(MAX_HEADER_SIZE as usize);
    let ent_len = data.len().min(MAX_ENTROPY_SIZE as usize);
    Ok(build_artifact_from_buffers(
        "<memory>".to_string(),
        data.len(),
        &data[..sniff_len],
        &data[..header_len],
        &data[..ent_len],
    ))
}
