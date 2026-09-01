use crate::common::test_data::SAMPLE_ELF_GCC;
use crate::common::{sample_file_exists, sample_file_path};
use glaurung::triage::api::analyze_path;
use glaurung::triage::io::IOLimits;

#[test]
fn elf_symbols_summary_runs_on_sample() {
    // The original guard returned early when the sample was absent and then
    // asserted `imports_count >= 0` on a `u32` -- two tautologies stacked, so
    // the test passed whether or not any symbol was recovered.
    assert!(
        sample_file_exists(SAMPLE_ELF_GCC),
        "tracked sample missing: samples/{} (corpus moved?)",
        SAMPLE_ELF_GCC
    );
    let path = sample_file_path(SAMPLE_ELF_GCC);
    let limits = IOLimits {
        max_read_bytes: 256 * 1024,
        max_file_size: u64::MAX,
    };
    let art = analyze_path(&path, &limits).expect("analyze_path ok");
    let sym = art.symbols.expect("ELF symbol summary present");
    println!(
        "imports={} exports={} libs={} stripped={}",
        sym.imports_count, sym.exports_count, sym.libs_count, sym.stripped
    );
    // A dynamically linked hello-world still imports from libc.
    assert!(sym.imports_count > 0, "no ELF imports recovered");
    assert!(sym.libs_count > 0, "no ELF needed libraries recovered");
}
