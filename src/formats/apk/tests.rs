//! APK reader tests + end-to-end APK -> DEX / AXML wiring.
//!
//! `sample_full.apk` (see `tests/fixtures/android/README.md`) is a real ZIP
//! bundling two `classes*.dex` (multidex) and the real termux binary manifest,
//! every member DEFLATE-compressed.

use super::*;
use crate::formats::axml::{manifest::ManifestSummary, parse_events};
use crate::formats::dex::DexParser;

fn load() -> Option<Vec<u8>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/android/sample_full.apk");
    std::fs::read(path).ok()
}

#[test]
fn enumerates_members_and_multidex() {
    let Some(data) = load() else {
        eprintln!("skip: sample_full.apk absent");
        return;
    };
    let apk = ApkReader::open(&data).expect("open apk");
    let names: Vec<&str> = apk.names().collect();
    assert!(names.contains(&"classes.dex"));
    assert!(names.contains(&"classes2.dex"));
    assert!(names.contains(&"AndroidManifest.xml"));

    // Multidex enumeration in natural order.
    assert_eq!(apk.dex_names(), vec!["classes.dex", "classes2.dex"]);
}

#[test]
fn inflates_and_parses_dex_member() {
    let Some(data) = load() else { return };
    let apk = ApkReader::open(&data).unwrap();
    let dex_bytes = apk.read("classes.dex").expect("inflate classes.dex");
    assert!(DexParser::is_dex(&dex_bytes), "extracted member is a DEX");
    let dex = DexParser::parse(&dex_bytes).unwrap();
    assert!(dex
        .class_names()
        .iter()
        .any(|n| n == "Lcom/glaurung/sample/Sample;"));
}

#[test]
fn extracts_and_analyzes_manifest() {
    let Some(data) = load() else { return };
    let apk = ApkReader::open(&data).unwrap();
    let manifest = apk.manifest_bytes().expect("AndroidManifest.xml present");
    let events = parse_events(&manifest).expect("parse axml");
    let summary = ManifestSummary::from_events(&events);
    assert_eq!(summary.package.as_deref(), Some("com.termux.api"));
    assert!(summary
        .exported_components()
        .iter()
        .any(|c| c.name == "com.termux.api.ShareAPI$ContentProvider"));
}

#[test]
fn rejects_non_zip() {
    assert!(matches!(ApkReader::open(b"not a zip"), Err(ApkError::NotZip)));
    assert!(matches!(
        ApkReader::open(b"\x7fELF\x02\x01\x01\x00garbage"),
        Err(ApkError::NotZip)
    ));
}
