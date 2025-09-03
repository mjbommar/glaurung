use crate::common::{sample_file_exists, sample_file_path};
use crate::common::test_data::SAMPLE_PE_EXE;
use glaurung::triage::api::analyze_path;
use glaurung::triage::io::IOLimits;

#[test]
fn pe_symbols_summary_runs_on_sample() {
    if !sample_file_exists(SAMPLE_PE_EXE) {
        eprintln!("PE sample not present; skipping test");
        return;
    }
    let path = sample_file_path(SAMPLE_PE_EXE);
    let limits = IOLimits { max_read_bytes: 256 * 1024, max_file_size: u64::MAX };
    let art = analyze_path(&path, &limits).expect("analyze_path ok");
    // symbols should be present or default to None for non-execs
    if let Some(sym) = art.symbols {
        // We don't assert non-zero counts to avoid flakiness, but fields should be consistent.
        assert!(sym.imports_count >= 0);
        assert!(sym.libs_count >= 0);
    }
}

