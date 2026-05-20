use std::fs;
use std::path::Path;

#[test]
fn test_pe_iat_map_on_sample() {
    let path = Path::new(
        "samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64/hello-c-x86_64-mingw.exe",
    );
    if !path.exists() {
        // Skip if sample not present
        return;
    }
    let data = fs::read(path).expect("read sample");
    let got = glaurung::analysis::pe_iat::pe_iat_map(&data);
    let joined: String = got
        .iter()
        .map(|(_, s)| s)
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    assert!(
        joined.to_ascii_lowercase().contains("puts")
            || joined.to_ascii_lowercase().contains("printf"),
        "expected PE32+ MinGW IAT imports, got {got:?}"
    );
}

#[test]
fn test_pe_iat_map_on_suspicious_pe32_plus_sample() {
    let path = Path::new(
        "samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64/suspicious_win-c-x86_64-mingw.exe",
    );
    if !path.exists() {
        // Skip if sample not present
        return;
    }
    let data = fs::read(path).expect("read sample");
    let got = glaurung::analysis::pe_iat::pe_iat_map(&data);
    let names: std::collections::BTreeSet<_> = got.iter().map(|(_, s)| s.as_str()).collect();
    assert!(
        names.contains("CreateRemoteThread")
            && names.contains("VirtualAllocEx")
            && names.contains("VirtualProtect")
            && names.contains("WriteProcessMemory"),
        "expected process-injection imports in PE32+ IAT, got {got:?}"
    );
}
