use glaurung::triage::api::analyze_path;
use glaurung::triage::io::IOLimits;

fn find_any_sample() -> Option<std::path::PathBuf> {
    let cand = vec![
        "samples/binaries/platforms/linux/amd64/export/rust/hello-rust-release",
        "samples/binaries/platforms/windows/i386/export/windows/i686/release/hello-c-mingw32-release.exe",
        "samples/containers/zip/hello-cpp-g++-O0.zip",
    ];
    for p in cand {
        let pb = std::path::PathBuf::from(p);
        if pb.exists() { return Some(pb); }
    }
    None
}

#[test]
fn json_output_is_stable_for_same_input() {
    let Some(path) = find_any_sample() else { return }; // skip if no samples
    let lim = IOLimits { max_read_bytes: 128 * 1024, max_file_size: u64::MAX };
    let a1 = analyze_path(&path, &lim).expect("analyze1");
    let a2 = analyze_path(&path, &lim).expect("analyze2");
    let j1 = a1.to_json_string().expect("json1");
    let j2 = a2.to_json_string().expect("json2");
    assert_eq!(j1, j2, "JSON outputs differ across identical runs");
}

#[test]
fn budgets_and_truncation_report_are_deterministic() {
    let Some(path) = find_any_sample() else { return };
    let lim = IOLimits { max_read_bytes: 4 * 1024, max_file_size: u64::MAX };
    let a = analyze_path(&path, &lim).expect("analyze");
    if let Some(b) = a.budgets.clone() {
        assert!(b.hit_byte_limit || b.bytes_read <= lim.max_read_bytes);
    }
    let j = a.to_json_string().expect("json");
    // Parse back to ensure stable schema
    let back = glaurung::core::triage::TriagedArtifact::from_json_str(&j).expect("from json");
    assert_eq!(a.schema_version, back.schema_version);
}

