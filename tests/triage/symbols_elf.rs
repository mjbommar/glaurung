use crate::common::{sample_file_exists, sample_file_path};
use crate::common::test_data::SAMPLE_ELF_GCC;
use glaurung::triage::api::analyze_path;
use glaurung::triage::io::IOLimits;

#[test]
fn elf_symbols_summary_runs_on_sample() {
    if !sample_file_exists(SAMPLE_ELF_GCC) {
        eprintln!("ELF sample not present; skipping test");
        return;
    }
    let path = sample_file_path(SAMPLE_ELF_GCC);
    let limits = IOLimits { max_read_bytes: 256 * 1024, max_file_size: u64::MAX };
    let art = analyze_path(&path, &limits).expect("analyze_path ok");
    if let Some(sym) = art.symbols {
        assert!(sym.imports_count >= 0);
        assert!(sym.libs_count >= 0);
        // stripped heuristic is okay either way depending on sample build
    }
}

