use crate::common::test_data::SAMPLE_PE_EXE;
use crate::common::{sample_file_exists, sample_file_path};
use glaurung::triage::api::analyze_path;
use glaurung::triage::io::IOLimits;

/// KNOWN PRODUCT BUG (found by wiring this file; not fixed here because the
/// fix is in `src/`).
///
/// `summarize_pe` reads two optional-header fields at their **PE32** offsets
/// regardless of magic, so every PE32+ (x86-64 / ARM64) binary is parsed with
/// garbage:
///
/// * `src/symbols/pe.rs:137` — `NumberOfRvaAndSizes` is read at
///   `opt_off + 92`. That is correct for PE32; in PE32+ the field is at
///   `opt_off + 108` and offset 92 lands inside `SizeOfStackCommit` /
///   `SizeOfHeapReserve`. On the tracked MinGW x86-64 sample the real value is
///   16 and the code reads **0**, so `num_data_dirs == 0`, every data
///   directory is skipped, and `imports_count`, `exports_count` and
///   `libs_count` all come back 0 for a binary that plainly imports from
///   `KERNEL32.dll` and `msvcrt.dll` (`objdump -p` confirms both).
/// * `src/symbols/pe.rs:145` — `DllCharacteristics` is read at
///   `opt_off + 0x5E` (94) for PE32+. The field is at `opt_off + 0x46` (70)
///   in *both* PE32 and PE32+. The sample's real value is `0x160`; the code
///   reads `0x0`, so `nx`, `aslr` and `cfg` are reported false for every
///   64-bit PE.
///
/// Note `data_dir_offset` immediately above (line 128-136) *does* branch on
/// magic correctly, which is why this reads as an oversight rather than a
/// design choice.
///
/// Repro: `cargo test --features python-ext --test lib pe_symbols_summary`
#[test]
fn pe_symbols_summary_runs_on_sample() {
    // The original form of this test returned early when the sample was
    // absent and then asserted `imports_count >= 0` on a `u32` -- two
    // tautologies stacked, so it passed over a summary of all zeroes.
    assert!(
        sample_file_exists(SAMPLE_PE_EXE),
        "tracked sample missing: samples/{} (corpus moved?)",
        SAMPLE_PE_EXE
    );
    let path = sample_file_path(SAMPLE_PE_EXE);
    // The sample is 487 KB; the 256 KB ceiling this test used to pass would
    // truncate before the import directory even once the parse is fixed.
    let limits = IOLimits::default();
    let art = analyze_path(&path, &limits).expect("analyze_path ok");
    let sym = art.symbols.expect("PE symbol summary present");
    println!(
        "imports={} exports={} libs={} nx={:?} aslr={:?}",
        sym.imports_count, sym.exports_count, sym.libs_count, sym.nx, sym.aslr
    );
    // A MinGW console exe imports from at least KERNEL32.dll and msvcrt.dll.
    assert!(sym.imports_count > 0, "no PE imports recovered");
    assert!(sym.libs_count > 0, "no PE import DLLs recovered");
    assert_eq!(sym.nx, Some(true), "NX bit lost from DllCharacteristics");
}
