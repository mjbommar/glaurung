use crate::common::{sample_file_exists, sample_file_path};
use glaurung::triage::api::analyze_path;
use glaurung::triage::io::IOLimits;

// Try a likely Mach-O sample path (may not exist in CI); skip if absent.
const SAMPLE_MACHO: &str = "binaries/platforms/darwin/x86_64/release/hello-macos-x86_64-release";

#[test]
fn macho_symbols_summary_runs_on_sample() {
    if !sample_file_exists(SAMPLE_MACHO) {
        eprintln!("Mach-O sample not present; skipping test");
        return;
    }
    let path = sample_file_path(SAMPLE_MACHO);
    let limits = IOLimits { max_read_bytes: 256 * 1024, max_file_size: u64::MAX };
    let art = analyze_path(&path, &limits).expect("analyze_path ok");
    if let Some(sym) = art.symbols {
        assert!(sym.libs_count >= 0);
        // imports/exports_count may be zero in stripped or minimal builds; do not assert positivity.
    }
}

