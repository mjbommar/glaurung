//! Integration test for IOC detection via string classification.
use std::fs;
use std::path::Path;

use glaurung::strings::{extract_summary, StringsConfig};

#[test]
fn ioc_counts_detected_in_sample_text() {
    // Keep IOC tests separate from symbols; this only exercises string classification.
    let rel = Path::new("adversarial/ioc_samples.txt");
    let path = Path::new("samples").join(rel);
    if !path.exists() {
        eprintln!(
            "IOC sample not present; skipping test (expected at {})",
            path.display()
        );
        return;
    }
    let data = match fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read {}: {}", path.display(), e);
            return;
        }
    };

    // Use a configuration that enables classification with modest budgets
    let cfg = StringsConfig {
        min_length: 3,
        max_samples: 64,
        max_scan_bytes: 64 * 1024,
        time_guard_ms: 50,
        enable_language: false,
        max_lang_detect: 0,
        min_len_for_detect: 10,
        enable_classification: true,
        max_classify: 128,
        max_ioc_per_string: 16,
    };
    let summary = extract_summary(&data, &cfg);

    let iocs = summary.ioc_counts.as_ref().cloned().unwrap_or_default();

    // Expect non-zero detections for the curated sample
    let get = |k: &str| -> u32 { *iocs.get(k).unwrap_or(&0) };
    assert!(get("url") >= 2, "expected at least two URLs");
    assert!(get("email") >= 2, "expected at least two emails");
    assert!(get("ipv4") >= 2, "expected at least two IPv4 addresses");
    assert!(get("ipv6") >= 1, "expected at least one IPv6 address");
    assert!(get("path_posix") >= 1, "expected a POSIX path");
    assert!(get("path_windows") >= 1, "expected a Windows path");
    assert!(get("path_unc") >= 1, "expected a UNC path");
    assert!(get("registry") >= 1, "expected a registry key");
    assert!(get("java_path") >= 1, "expected a Java class path");
}

