use std::fs;
use std::path::Path;

use glaurung::core::triage::TriageErrorKind;
use glaurung::triage::api::analyze_path;
use glaurung::triage::containers::detect_containers;
use glaurung::triage::headers;
use glaurung::triage::io::{IOLimits, MAX_HEADER_SIZE, MAX_SNIFF_SIZE};
use glaurung::triage::sniffers::CombinedSniffer;

#[test]
fn adversarial_magic_dope_safe() {
    let p = Path::new("samples/adversarial/magic_dope_mz_elf.bin");
    let d = fs::read(p).expect("read magic_dope");
    let sniff = &d[..d.len().min(MAX_SNIFF_SIZE as usize)];
    let header = &d[..d.len().min(MAX_HEADER_SIZE as usize)];
    let _sn = CombinedSniffer::sniff(sniff, Some(p));
    let _hdr = headers::validate(header);
    // If no panic occurred, we are fine; regardless of verdicts
}

#[test]
fn adversarial_elf_truncated_reports_error() {
    let p = Path::new("samples/adversarial/elf_truncated_phdr.bin");
    let d = fs::read(p).expect("read elf_truncated");
    let hdr = headers::validate(&d);
    assert!(!hdr.errors.is_empty());
}

#[test]
fn adversarial_pe_bad_optional_header_reports_error() {
    let p = Path::new("samples/adversarial/pe_bad_optional_header.bin");
    let d = fs::read(p).expect("read pe_bad_optional");
    let hdr = headers::validate(&d);
    assert!(!hdr.errors.is_empty());
}

#[test]
fn adversarial_zip_masquerade_exe_is_exempt_from_mismatch() {
    // `compute_sniffer_header_mismatches` is `pub(crate)`, so this asserts the
    // same property through the public entry point: a ZIP carrying an `.exe`
    // extension is a detected container, not a sniffer/header mismatch.
    let p = Path::new("samples/adversarial/zip_masquerade_exe.exe");
    let limits = IOLimits {
        max_read_bytes: 1024 * 1024,
        max_file_size: u64::MAX,
    };
    let art = analyze_path(p, &limits).expect("analyze zip masquerade");
    let errs = art.errors.clone().unwrap_or_default();
    let mismatches: Vec<_> = errs
        .iter()
        .filter(|e| e.kind == TriageErrorKind::SnifferMismatch)
        .collect();
    assert!(
        mismatches.is_empty(),
        "unexpected sniffer/header mismatch: {:?}",
        mismatches
    );
}

#[test]
fn adversarial_truncated_gzip_detected_no_panic() {
    let p = Path::new("samples/adversarial/gzip_truncated.gz");
    let d = fs::read(p).expect("read gzip_truncated");
    let v = detect_containers(&d);
    assert!(v.iter().any(|c| c.type_name == "gzip"));
    // metadata may be None because of truncation; ensure no panic
}
