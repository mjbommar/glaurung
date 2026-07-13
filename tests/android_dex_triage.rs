//! Triage-level detection of Android artifacts: DEX bytecode and APK containers.

use glaurung::core::binary::Format;
use glaurung::formats::dex::DexParser;
use glaurung::triage::{containers::detect_containers, headers::validate};

fn fixture(name: &str) -> Option<Vec<u8>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/android")
        .join(name);
    std::fs::read(path).ok()
}

#[test]
fn dex_magic_triaged_as_dex_format() {
    let Some(data) = fixture("sample.dex") else {
        eprintln!("skip: sample.dex absent");
        return;
    };
    let result = validate(&data);
    let dex = result
        .candidates
        .iter()
        .find(|v| v.format == Format::Dex)
        .expect("triage should surface a Dex candidate");
    // The endian constant is present, so this should be a high-confidence hit.
    assert!(dex.confidence > 0.9, "confidence was {}", dex.confidence);

    // And the format parser agrees.
    assert!(DexParser::is_dex(&data));
}

#[test]
fn apk_container_detected_from_zip() {
    let Some(data) = fixture("sample.apk") else {
        eprintln!("skip: sample.apk absent");
        return;
    };
    let children = detect_containers(&data);
    assert!(
        children.iter().any(|c| c.type_name == "apk"),
        "expected an 'apk' container, got {:?}",
        children.iter().map(|c| &c.type_name).collect::<Vec<_>>()
    );
}
