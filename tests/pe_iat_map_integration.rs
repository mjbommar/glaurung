use std::fs;
use std::path::Path;

#[test]
fn test_pe_iat_map_on_sample() {
    let path = Path::new(
        "samples/binaries/platforms/linux/amd64/cross/windows-x86_64/hello-c-x86_64-mingw.exe",
    );
    if !path.exists() {
        // Skip if sample not present
        return;
    }
    let data = fs::read(path).expect("read sample");
    let got = glaurung::analysis::pe_iat::pe_iat_map(&data);
    // Should at least parse and produce a vector (possibly empty on stripped edge cases)
    // Prefer asserting known imports if present
    if !got.is_empty() {
        let joined: String = got
            .iter()
            .map(|(_, s)| s)
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            joined.to_ascii_lowercase().contains("puts")
                || joined.to_ascii_lowercase().contains("printf")
        );
    }
}

#[test]
fn test_pe_iat_map_reads_pe32_plus_data_directories() {
    let path = Path::new(
        "samples/binaries/platforms/windows/i386/export/windows/x86_64/O0/hello-c-mingw64-O0.exe",
    );
    if !path.exists() {
        return;
    }
    let data = fs::read(path).expect("read sample");
    let got = glaurung::analysis::pe_iat::pe_iat_map(&data);
    let names: std::collections::BTreeSet<&str> =
        got.iter().map(|(_, name)| name.as_str()).collect();
    assert!(
        names.contains("GetLastError"),
        "expected PE32+ import names, got {} entries: {:?}",
        got.len(),
        got.iter().take(8).collect::<Vec<_>>()
    );
    assert!(got.iter().any(|(va, _)| *va != 0));
}
