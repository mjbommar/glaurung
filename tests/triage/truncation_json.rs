use std::path::Path;

use glaurung::core::triage::TriageErrorKind;
use glaurung::triage::api::analyze_path;
use glaurung::triage::io::IOLimits;

/// Validate graceful truncation and JSON round-trip on a real sample under tight limits.
#[test]
fn graceful_truncation_and_json_roundtrip_on_real_sample() {
    // Use a known sample if available; otherwise skip
    let sample = Path::new("samples/containers/zip/hello-cpp-g++-O0.zip");
    if !sample.exists() {
        eprintln!("Skipping truncation test; sample not found: {}", sample.display());
        return;
    }

    // Very small read ceiling to force truncation conditions
    let limits = IOLimits {
        max_read_bytes: 4 * 1024,
        max_file_size: u64::MAX,
    };

    let artifact = analyze_path(sample, &limits).expect("analyze_path");

    // Budgets indicate truncation hit
    let budgets = artifact.budgets.as_ref().expect("budgets present");
    assert!(budgets.hit_byte_limit, "expected hit_byte_limit true");
    assert_eq!(budgets.limit_bytes, Some(limits.max_read_bytes));

    // Error taxonomy contains BudgetExceeded
    let errs = artifact.errors.clone().unwrap_or_default();
    assert!(errs.iter().any(|e| e.kind == TriageErrorKind::BudgetExceeded));

    // JSON schema persistence: round-trip equals
    let json = artifact.to_json_string().expect("serialize");
    let back = glaurung::core::triage::TriagedArtifact::from_json_str(&json).expect("deserialize");
    assert_eq!(artifact, back, "artifact must be stable through JSON round-trip");
}

