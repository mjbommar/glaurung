//! CFG discovery on a real PAC+BTI-hardened AArch64 binary.
//!
//! `tests/fixtures/android/pac_bti` is built by
//! `aarch64-linux-gnu-gcc -O2 -mbranch-protection=standard` (see
//! `tests/fixtures/android/pac.c`). Its GNU-property note advertises
//! `AArch64 feature: BTI, PAC, GCS`; it contains `paciasp`/`autiasp`, `bti`
//! landing pads, and register-indirect `br` tail calls — exactly the
//! instructions whose misclassification corrupts function discovery on Pixel
//! device binaries.

use glaurung::analysis::cfg::{analyze_functions_bytes, Budgets};

#[test]
fn discovers_functions_on_pac_bti_binary() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/android/pac_bti");
    let Ok(data) = std::fs::read(&path) else {
        eprintln!("skip: pac_bti fixture absent");
        return;
    };
    // Sanity: an AArch64 ELF.
    assert_eq!(&data[..4], b"\x7fELF");
    assert_eq!(data[18], 0xB7, "e_machine should be EM_AARCH64 (183)");

    let budgets = Budgets {
        max_functions: 64,
        max_blocks: 8192,
        max_instructions: 200_000,
        timeout_ms: 2000,
    };
    let (funcs, cg) = analyze_functions_bytes(&data, &budgets);

    // The source defines leaf/pick/compute/main; with symbols present the CFG
    // should recover a healthy set of functions, each with at least one block.
    assert!(
        funcs.len() >= 4,
        "expected >=4 functions on the hardened binary, got {}",
        funcs.len()
    );
    assert!(
        funcs.iter().all(|f| !f.basic_blocks.is_empty()),
        "every discovered function should have basic blocks"
    );
    // Well-formed call graph (compute -> fp(...) etc.).
    assert!(cg.edge_count() >= 1, "expected at least one call edge");
}
