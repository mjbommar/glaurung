//! SELinux binary-policy header tests against real `secilc`-compiled policies.
//!
//! `tests/fixtures/android/sepolicy.{30,33,35}` are compiled from `pol.cil` by
//! `build_sepolicy.sh` (secilc). They are MLS kernel policies at the versions
//! Android 12-15 (30-33) and upstream (35) ship.

use super::*;

fn load(version: u32) -> Option<Vec<u8>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("tests/fixtures/android/sepolicy.{version}"));
    std::fs::read(path).ok()
}

#[test]
fn detects_sepolicy_magic() {
    let Some(data) = load(33) else {
        eprintln!("skip: sepolicy fixtures absent");
        return;
    };
    assert!(is_sepolicy(&data));
    assert!(!is_sepolicy(b"\x7fELF\x02\x01\x01\x00"));
    assert!(!is_sepolicy(b"dex\n035\0"));
    assert!(!is_sepolicy(b"short"));
}

#[test]
fn parses_header_across_versions() {
    for (version, expected_ocon) in [(30u32, 7u32), (33, 9), (35, 9)] {
        let Some(data) = load(version) else {
            eprintln!("skip: sepolicy.{version} absent");
            continue;
        };
        let hdr = parse_header(&data).expect("parse policydb header");
        assert_eq!(hdr.version, version);
        assert!(hdr.mls, "Android policies are MLS");
        assert_eq!(hdr.sym_num, 8, "kernel policy has 8 symbol tables");
        assert_eq!(hdr.ocon_num, expected_ocon);
        // Header is magic(4)+len(4)+"SE Linux"(8)+version+config+nsym+nocon.
        assert_eq!(hdr.body_offset, 8 + POLICYDB_STRING.len() + 16);
    }
}

#[test]
fn rejects_non_policy() {
    assert_eq!(parse_header(b"not a policy at all"), Err(PolicyError::BadMagic));
    // Correct magic, wrong identifier length.
    let mut bad = Vec::new();
    bad.extend_from_slice(&POLICYDB_MAGIC.to_le_bytes());
    bad.extend_from_slice(&3u32.to_le_bytes());
    bad.extend_from_slice(b"abc");
    assert_eq!(parse_header(&bad), Err(PolicyError::BadIdentifier));
}
