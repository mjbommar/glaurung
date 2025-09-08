use glaurung::core::binary::{Arch, Endianness, Format};
use glaurung::disasm::registry::{for_arch_with, Backend, BackendKind};

fn select_arch_from_artifact(art: &glaurung::core::triage::TriagedArtifact) -> (Arch, Endianness) {
    let arch = art
        .verdicts
        .first()
        .map(|v| v.arch)
        .or_else(|| {
            art.heuristic_arch
                .as_ref()
                .and_then(|v| v.first().map(|(a, _)| *a))
        })
        .unwrap_or(Arch::Unknown);
    let end = art
        .heuristic_endianness
        .map(|(e, _)| e)
        .unwrap_or(Endianness::Little);
    (arch, end)
}

#[test]
fn triage_selects_iced_for_x86_64() {
    let path = std::path::Path::new(
        "samples/binaries/platforms/linux/amd64/export/native/asm/gas/O0/hello-asm-gas-O0",
    );
    if !path.exists() {
        return; // skip if sample not present
    }
    let limits = glaurung::triage::io::IOLimits {
        max_read_bytes: 10_485_760,
        max_file_size: 104_857_600,
    };
    let art = glaurung::triage::api::analyze_path(path, &limits).expect("triage analyze_path");
    let (arch, end) = select_arch_from_artifact(&art);
    assert!(matches!(arch, Arch::X86_64 | Arch::X86));
    let backend = for_arch_with(arch.into(), end, None).expect("backend");
    match backend {
        Backend::Iced(_) => {}
        _ => panic!("expected iced backend for x86/x64, got different engine"),
    }
}

#[test]
fn triage_selects_capstone_for_arm64() {
    let path = std::path::Path::new(
        "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-asm-arm64-as",
    );
    if !path.exists() {
        return; // skip if sample not present
    }
    let limits = glaurung::triage::io::IOLimits {
        max_read_bytes: 10_485_760,
        max_file_size: 104_857_600,
    };
    let art = glaurung::triage::api::analyze_path(path, &limits).expect("triage analyze_path");
    let (arch, end) = select_arch_from_artifact(&art);
    assert!(matches!(arch, Arch::AArch64 | Arch::ARM));
    let backend = for_arch_with(arch.into(), end, None).expect("backend");
    match backend {
        Backend::Cap(_) => {}
        _ => panic!("expected capstone backend for ARM/ARM64, got different engine"),
    }
}
