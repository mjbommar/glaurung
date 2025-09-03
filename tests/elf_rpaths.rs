use glaurung::symbols::{self, types::BudgetCaps};

fn load(path: &str) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

#[test]
fn elf_rpath_runpath_fields_present_if_any() {
    // Prefer newly built rpath/runpath variants if present
    let candidates = [
        "samples/binaries/platforms/linux/amd64/export/native/gcc/rpath/hello-gcc-rpath",
        "samples/binaries/platforms/linux/amd64/export/native/gcc/runpath/hello-gcc-runpath",
        "samples/binaries/platforms/linux/amd64/export/native/clang/rpath/hello-clang-rpath",
        "samples/binaries/platforms/linux/amd64/export/native/clang/runpath/hello-clang-runpath",
        // Fallbacks
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-cpp-g++-O2",
        "samples/binaries/platforms/linux/amd64/export/fortran/hello-gfortran-debug",
    ];
    let data = candidates.iter().find_map(|p| load(p));
    let Some(buf) = data else { return }; // skip if missing
    let caps = BudgetCaps::default();
    let sum = symbols::elf::summarize_elf(&buf, &caps);
    // If we selected rpath/runpath variants, ensure extracted values include /opt/test
    if let Some(rps) = sum.rpaths.clone() {
        if !rps.is_empty() {
            assert!(rps.iter().any(|s| s.contains("/opt/test")));
        }
    }
    if let Some(rps) = sum.runpaths.clone() {
        if !rps.is_empty() {
            assert!(rps.iter().any(|s| s.contains("/opt/test")));
        }
    }
}

#[test]
fn elf_stripped_heuristic_works_on_real_sample() {
    // If a stripped sample is available, validate the flag tends to true
    // Placeholder candidates; test skips if not present
    let candidates = [
        // Built by build-linux.sh
        "samples/binaries/platforms/linux/amd64/export/native/gcc/debug/hello-gcc-stripped",
        "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-stripped",
    ];
    if let Some(buf) = candidates.iter().find_map(|p| load(p)) {
        let caps = BudgetCaps::default();
        let sum = symbols::elf::summarize_elf(&buf, &caps);
        // We expect stripped to be true for known stripped sample
        assert!(sum.stripped);
    } else {
        // Nothing to do; repository may not include these paths
    }
}

#[test]
fn elf_unstripped_debug_sample_if_present() {
    let candidates = [
        "samples/binaries/platforms/linux/amd64/export/native/gcc/debug/hello-gcc-debug",
        "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug",
    ];
    if let Some(buf) = candidates.iter().find_map(|p| load(p)) {
        let caps = BudgetCaps::default();
        let sum = symbols::elf::summarize_elf(&buf, &caps);
        // Debug builds usually keep symtab
        assert!(!sum.stripped);
    }
}
