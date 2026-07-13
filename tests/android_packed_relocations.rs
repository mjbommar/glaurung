//! End-to-end validation of Android/bionic packed-relocation decoding against
//! real AArch64 shared objects.
//!
//! Fixtures under `tests/fixtures/android/` are built by
//! `tests/fixtures/android/build.sh` (aarch64-linux-gnu-gcc + lld with
//! `--pack-dyn-relocs`). Ground-truth relocation targets were cross-checked with
//! `llvm-readelf`/`readelf`, which expand the packed streams natively.

use glaurung::formats::elf::ElfParser;

fn load(name: &str) -> Option<Vec<u8>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/android")
        .join(name);
    std::fs::read(path).ok()
}

#[test]
fn aps2_android_rela_matches_readelf() {
    let Some(data) = load("packed_android.so") else {
        eprintln!("skip: tests/fixtures/android/packed_android.so absent (run build.sh)");
        return;
    };
    let parser = ElfParser::parse(&data).expect("parse ELF");
    let relocs = parser
        .android_packed_relocations()
        .expect("decode packed relocs")
        .expect("packed_android.so has a DT_ANDROID_RELA stream");

    // readelf expands the packed .rela.dyn to exactly 25 entries.
    assert_eq!(relocs.len(), 25, "APS2 relocation count");

    // Every offset produced by readelf's expansion of the ANDROID_RELA stream.
    let mut got: Vec<u64> = relocs.iter().map(|r| r.r_offset).collect();
    got.sort_unstable();
    let mut expected: Vec<u64> = vec![
        0x20860, 0x20868, 0x309c0, // R_AARCH64_RELATIVE
        0x209a0, 0x209a8, 0x209b0, 0x209b8, // R_AARCH64_GLOB_DAT
        0x309f8, 0x30a00, 0x30a08, 0x30a10, 0x30a18, 0x30a20, 0x30a28, 0x30a30,
        0x30a38, 0x30a40, 0x30a48, 0x30a50, 0x30a58, 0x30a60, 0x30a68, 0x30a70,
        0x30a78, 0x30a80, // R_AARCH64_ABS64
    ];
    expected.sort_unstable();
    assert_eq!(got, expected, "APS2 relocation offsets");

    // The three RELATIVE relocations carry non-zero addends (the target vaddr).
    let relative_addends: std::collections::BTreeSet<i64> = relocs
        .iter()
        .filter(|r| r.reloc_type() == 1027) // R_AARCH64_RELATIVE
        .map(|r| r.r_addend)
        .collect();
    let expected_addends: std::collections::BTreeSet<i64> =
        [0x1078c, 0x107e0, 0x309c0].into_iter().collect();
    assert_eq!(relative_addends, expected_addends, "RELATIVE addends");
}

#[test]
fn relr_matches_readelf() {
    let Some(data) = load("packed_relr.so") else {
        eprintln!("skip: tests/fixtures/android/packed_relr.so absent (run build.sh)");
        return;
    };
    let parser = ElfParser::parse(&data).expect("parse ELF");
    let relocs = parser
        .relr_relocations()
        .expect("decode RELR")
        .expect("packed_relr.so has a DT_RELR table");

    let got: Vec<u64> = relocs.iter().map(|r| r.r_offset).collect();
    // readelf reports the RELR table relocates exactly these three locations.
    assert_eq!(got, vec![0x209c0, 0x209c8, 0x30b50], "RELR relocation offsets");
    assert!(
        relocs.iter().all(|r| r.r_info == 0),
        "RELR relocs are synthetic relative entries"
    );
}
