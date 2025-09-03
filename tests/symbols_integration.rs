use glaurung::core::binary::Format;
use glaurung::symbols::{self, types::BudgetCaps};
use std::path::Path;

fn read_sample(path: &str, _cap: u64) -> Option<Vec<u8>> {
    let p = Path::new(path);
    if !p.exists() {
        return None;
    }
    std::fs::read(p).ok()
}

#[test]
fn summarize_elf_on_upx_sample_if_present() {
    // Use a packed ELF sample if present; skip test gracefully otherwise
    let candidates = [
        "samples/packed/hello-rust-debug.upx9",
        "samples/packed/hello-rust-release.upx9",
        "samples/packed/hello-gfortran-O2.upx9",
    ];
    let mut data = None;
    for c in candidates {
        data = read_sample(c, 10 * 1024 * 1024);
        if data.is_some() {
            break;
        }
    }
    let Some(bytes) = data else { return }; // skip if none present
    let caps = BudgetCaps::default();
    let sum = symbols::summarize_symbols(&bytes, Format::ELF, &caps);
    // Basic assertions: counts are within caps, and not panicking
    assert!(sum.imports_count <= caps.max_imports);
    assert!(sum.exports_count <= caps.max_exports);
}
