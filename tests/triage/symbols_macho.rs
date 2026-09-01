use crate::common::{sample_file_exists, sample_file_path};
use glaurung::triage::api::analyze_path;
use glaurung::triage::io::IOLimits;

/// The path this file used to name --
/// `binaries/platforms/darwin/x86_64/release/hello-macos-x86_64-release` --
/// has never existed; the tracked Mach-O corpus is a single file under
/// `darwin/amd64/`. The old test returned early on every run.
const SAMPLE_MACHO: &str = "binaries/platforms/darwin/amd64/export/native/multi_import-macho";

#[test]
fn macho_symbols_summary_runs_on_sample() {
    assert!(
        sample_file_exists(SAMPLE_MACHO),
        "tracked sample missing: samples/{} (corpus moved?)",
        SAMPLE_MACHO
    );
    let path = sample_file_path(SAMPLE_MACHO);
    let limits = IOLimits {
        max_read_bytes: 256 * 1024,
        max_file_size: u64::MAX,
    };
    let art = analyze_path(&path, &limits).expect("analyze_path ok");
    let sym = art.symbols.expect("Mach-O symbol summary present");
    println!(
        "imports={} exports={} libs={}",
        sym.imports_count, sym.exports_count, sym.libs_count
    );
    assert!(sym.imports_count > 0, "no Mach-O imports recovered");
    // `libs_count` is 0 for this sample and that is correct: its 14 load
    // commands contain no LC_LOAD_DYLIB (verified by hand), so there is
    // nothing to count. Do not assert on it here.
}
