//! Function discovery on a *stripped* PAC-hardened AArch64 binary.
//!
//! `pac_bti_stripped` (see fixtures README) has had its symbol table removed;
//! its only remaining dynamic symbols are UND imports, so symbol-based discovery
//! yields no internal functions. The PAC prologue scanner recovers them from the
//! `paciasp` function entries — the mechanism that keeps function discovery
//! working on real Pixel device `.so` files.

use glaurung::analysis::cfg::{analyze_functions_bytes, Budgets};

#[test]
fn pac_prologue_scan_recovers_stripped_functions() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/android/pac_bti_stripped");
    let Ok(data) = std::fs::read(&path) else {
        eprintln!("skip: pac_bti_stripped fixture absent");
        return;
    };
    assert_eq!(&data[..4], b"\x7fELF");

    let budgets = Budgets {
        max_functions: 128,
        max_blocks: 8192,
        max_instructions: 200_000,
        timeout_ms: 2000,
    };
    let (funcs, _cg) = analyze_functions_bytes(&data, &budgets);

    let starts: std::collections::BTreeSet<u64> =
        funcs.iter().map(|f| f.entry_point.value).collect();

    // These are the `paciasp` function entries objdump reports; none are
    // reachable from the (import-only) symbol table, so they can only come from
    // the PAC prologue scan.
    for entry in [0x6c0u64, 0x7cc, 0x860] {
        assert!(
            starts.contains(&entry),
            "expected PAC-prologue function at {entry:#x}; discovered {:?}",
            starts.iter().map(|v| format!("{v:#x}")).collect::<Vec<_>>()
        );
    }
}
