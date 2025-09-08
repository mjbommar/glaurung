use glaurung::symbols::{self, types::BudgetCaps};
use std::fs;

fn try_paths<'a>(candidates: &[&'a str]) -> Option<&'a str> {
    for p in candidates {
        if std::path::Path::new(p).exists() {
            return Some(*p);
        }
    }
    None
}

#[test]
fn pe_entry_section_and_tls_if_present() {
    // Prefer Windows PE samples if present
    let pe = try_paths(&[
        "samples/binaries/platforms/windows/i386/export/windows/i686/release/hello-c-mingw32-release.exe",
        "samples/binaries/platforms/windows/i386/export/windows/i686/debug/hello-c-mingw32-debug.exe",
        "samples/binaries/platforms/windows/i386/export/windows/i686/O2/hello-c-mingw32-O2.exe",
        // Newly built TLS sample via MinGW (exported under linux/amd64 build)
        "samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64/pe_tls_callbacks-x86_64-mingw.exe",
    ]);
    let Some(path) = pe else { return }; // skip if absent
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(_) => return,
    };
    let caps = BudgetCaps::default();
    let sum = symbols::pe::summarize_pe(&data, &caps);
    // Entry section should generally be identified
    if let Some(name) = sum.entry_section.clone() {
        assert!(!name.is_empty());
    }
    // If TLS callbacks are present, tls_used should be true
    if let Some(cnt) = sum.tls_callback_count {
        assert!(cnt <= 1024);
        assert!(sum.tls_used);
    }
    // relocations_present is set to Some(...)
    assert!(sum.relocations_present.is_some());
}
