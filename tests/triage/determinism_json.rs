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
        if pb.exists() {
            return Some(pb);
        }
    }
    None
}

/// Two fields of a `TriagedArtifact` are wall-clock derived *by design*:
/// `id` embeds a millisecond timestamp (`src/core/triage/verdict.rs:178`) and
/// `budgets.time_ms` records how long the run took. Everything else describes
/// the input and must be identical for identical input.
fn normalize(art: &mut glaurung::core::triage::TriagedArtifact) {
    art.id = String::from("<normalized>");
    if let Some(b) = art.budgets.as_mut() {
        b.time_ms = 0;
    }
}

#[test]
fn json_output_is_stable_for_same_input() {
    let Some(path) = find_any_sample() else {
        return;
    }; // skip if no samples
    let lim = IOLimits {
        max_read_bytes: 128 * 1024,
        max_file_size: u64::MAX,
    };
    // A single repeat is not enough: the known nondeterminism here is a
    // wall-clock guard, so a lightly loaded machine can produce two matching
    // runs by luck. Five runs makes an intermittent difference reliably visible.
    let mut first: Option<String> = None;
    for i in 0..5 {
        let mut a = analyze_path(&path, &lim).expect("analyze");
        normalize(&mut a);
        let j = a.to_json_string().expect("json");
        match &first {
            None => first = Some(j),
            Some(f) => assert_eq!(
                *f, j,
                "JSON outputs differ across identical runs (run 0 vs run {})",
                i
            ),
        }
    }
}

#[test]
fn budgets_and_truncation_report_are_deterministic() {
    let Some(path) = find_any_sample() else {
        return;
    };
    let lim = IOLimits {
        max_read_bytes: 4 * 1024,
        max_file_size: u64::MAX,
    };
    let a = analyze_path(&path, &lim).expect("analyze");
    if let Some(b) = a.budgets.clone() {
        assert!(b.hit_byte_limit || b.bytes_read <= lim.max_read_bytes);
    }
    let j = a.to_json_string().expect("json");
    // Parse back to ensure stable schema
    let back = glaurung::core::triage::TriagedArtifact::from_json_str(&j).expect("from json");
    assert_eq!(a.schema_version, back.schema_version);
}
