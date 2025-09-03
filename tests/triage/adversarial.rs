use std::fs;
use std::path::Path;

use glaurung::core::binary::Format;
use glaurung::core::triage::{Budgets, TriageErrorKind};
use glaurung::triage::api::compute_sniffer_header_mismatches;
use glaurung::triage::containers::detect_containers;
use glaurung::triage::headers;
use glaurung::triage::io::{MAX_HEADER_SIZE, MAX_SNIFF_SIZE};
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
    let p = Path::new("samples/adversarial/zip_masquerade_exe.exe");
    let d = fs::read(p).expect("read zip masquerade");
    let sniff = &d[..d.len().min(MAX_SNIFF_SIZE as usize)];
    let header = &d[..d.len().min(MAX_HEADER_SIZE as usize)];
    let sn = CombinedSniffer::sniff(sniff, Some(p));
    let hdr = headers::validate(header);
    let header_formats: Vec<Format> = hdr.candidates.iter().map(|v| v.format).collect();
    let containers = detect_containers(&d);
    let labels: Vec<String> = containers.iter().map(|c| c.type_name.clone()).collect();
    let errs = compute_sniffer_header_mismatches(&sn.hints, &header_formats, &labels);
    assert!(errs.is_empty());
}

#[test]
fn adversarial_truncated_gzip_detected_no_panic() {
    let p = Path::new("samples/adversarial/gzip_truncated.gz");
    let d = fs::read(p).expect("read gzip_truncated");
    let v = detect_containers(&d);
    assert!(v.iter().any(|c| c.type_name == "gzip"));
    // metadata may be None because of truncation; ensure no panic
}

