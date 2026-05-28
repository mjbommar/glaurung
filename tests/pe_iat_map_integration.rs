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

#[test]
fn test_pe_import_thunk_map_finds_jmp_thunks() {
    let path = Path::new(
        "samples/binaries/platforms/windows/i386/export/windows/x86_64/O0/hello-c-mingw64-O0.exe",
    );
    if !path.exists() {
        return;
    }
    let data = fs::read(path).expect("read sample");
    let got = glaurung::analysis::pe_iat::pe_import_thunk_map(&data);
    let names: std::collections::BTreeSet<&str> =
        got.iter().map(|(_, name)| name.as_str()).collect();
    assert!(
        names.contains("malloc") || names.contains("LeaveCriticalSection"),
        "expected PE import thunk aliases, got {} entries: {:?}",
        got.len(),
        got.iter().take(8).collect::<Vec<_>>()
    );
    assert!(got.iter().any(|(va, _)| *va != 0));
}
