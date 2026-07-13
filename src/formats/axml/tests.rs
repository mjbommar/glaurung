//! AXML parser tests against a real device manifest.
//!
//! `tests/fixtures/android/AndroidManifest_termux_api.axml` is the compiled
//! manifest extracted from `com.termux.api` (F-Droid). Ground truth was taken
//! from `aapt2 dump xmltree`.

use super::manifest::{ComponentKind, ManifestSummary};
use super::*;

fn load() -> Option<Vec<u8>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/android/AndroidManifest_termux_api.axml");
    std::fs::read(path).ok()
}

#[test]
fn detects_axml() {
    let Some(data) = load() else {
        eprintln!("skip: termux manifest fixture absent");
        return;
    };
    assert!(is_axml(&data));
    assert!(!is_axml(b"<?xml version=\"1.0\"?>"));
}

#[test]
fn parses_package_and_permissions() {
    let Some(data) = load() else { return };
    let events = parse_events(&data).expect("parse axml");
    let summary = ManifestSummary::from_events(&events);

    assert_eq!(summary.package.as_deref(), Some("com.termux.api"));

    for perm in [
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
    ] {
        assert!(
            summary.uses_permissions.iter().any(|p| p == perm),
            "missing permission {perm}"
        );
    }
    // termux.api requests 30+ permissions.
    assert!(summary.uses_permissions.len() > 20);
}

#[test]
fn extracts_components_and_exported_flags() {
    let Some(data) = load() else { return };
    let events = parse_events(&data).unwrap();
    let summary = ManifestSummary::from_events(&events);

    // The ShareAPI content provider is the one explicitly exported component.
    let provider = summary
        .components
        .iter()
        .find(|c| c.name == "com.termux.api.ShareAPI$ContentProvider")
        .expect("ShareAPI provider present");
    assert_eq!(provider.kind, ComponentKind::Provider);
    assert_eq!(provider.exported, Some(true));
    assert!(provider.is_exported());

    // DialogActivity is explicitly not exported.
    let dialog = summary
        .components
        .iter()
        .find(|c| c.name == "com.termux.api.DialogActivity")
        .expect("DialogActivity present");
    assert_eq!(dialog.exported, Some(false));
    assert!(!dialog.is_exported());

    // A representative service is present.
    assert!(summary
        .components
        .iter()
        .any(|c| c.name == "com.termux.api.SpeechToTextAPI$SpeechToTextService"
            && c.kind == ComponentKind::Service));
}

#[test]
fn nfc_activity_has_intent_filter_actions() {
    let Some(data) = load() else { return };
    let events = parse_events(&data).unwrap();
    let summary = ManifestSummary::from_events(&events);

    let nfc = summary
        .components
        .iter()
        .find(|c| c.name == "com.termux.api.NfcActivity")
        .expect("NfcActivity present");
    assert!(!nfc.intent_filters.is_empty(), "NfcActivity has an intent-filter");
    let actions: Vec<&str> = nfc
        .intent_filters
        .iter()
        .flat_map(|f| f.actions.iter().map(|s| s.as_str()))
        .collect();
    assert!(actions.contains(&"android.nfc.action.NDEF_DISCOVERED"));
    assert!(actions.contains(&"android.intent.action.MAIN"));
}
