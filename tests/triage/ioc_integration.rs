//! Integration test for IOC detection via string classification.
use std::fs;
use std::path::Path;

use glaurung::strings::{extract_summary, StringsConfig};

fn classify_cfg() -> StringsConfig {
    // `StringsConfig` has grown fields since this test was written; take the
    // defaults for everything the test does not care about.
    StringsConfig {
        min_length: 3,
        max_samples: 64,
        max_scan_bytes: 64 * 1024,
        time_guard_ms: 1_000,
        enable_language: false,
        max_lang_detect: 0,
        min_len_for_detect: 10,
        enable_classification: true,
        max_classify: 128,
        max_ioc_per_string: 16,
        ..Default::default()
    }
}

#[test]
fn ioc_counts_detected_in_sample_text() {
    // Keep IOC tests separate from symbols; this only exercises string classification.
    let rel = Path::new("adversarial/ioc_samples.txt");
    let path = Path::new("samples").join(rel);
    assert!(
        path.exists(),
        "tracked sample missing: {} (corpus moved?)",
        path.display()
    );
    let data = fs::read(&path).expect("read ioc sample");

    let summary = extract_summary(&data, &classify_cfg());
    let iocs = summary.ioc_counts.as_ref().cloned().unwrap_or_default();

    println!("ioc_counts = {:?}", iocs);
    let get = |k: &str| -> u32 { *iocs.get(k).unwrap_or(&0) };
    assert!(
        get("url") >= 2,
        "expected at least two URLs (got {:?})",
        iocs
    );
    assert!(
        get("email") >= 2,
        "expected at least two emails (got {:?})",
        iocs
    );
    // NOTE: this used to assert `ipv4 >= 2` for the fixture's `192.168.1.10`
    // and `10.0.0.5`. `is_valid_network_ipv4` (src/strings/classify.rs:159,
    // added 2025-09-07, four days after this test was written and while it was
    // still unreachable) rejects every RFC1918 address, so the count is 0.
    // That is the codified intent for the *classify* path
    // (`classify.rs::test_private_ips_rejected`). See
    // `public_ipv4_is_counted_but_private_is_not` below, which pins both
    // halves of that rule on text this test controls.
    assert_eq!(
        get("ipv4"),
        0,
        "fixture holds only RFC1918 addresses, which classify.rs excludes (got {:?})",
        iocs
    );
    assert!(
        get("ipv6") >= 1,
        "expected at least one IPv6 address (got {:?})",
        iocs
    );
    assert!(
        get("path_posix") >= 1,
        "expected a POSIX path (got {:?})",
        iocs
    );
    assert!(
        get("path_windows") >= 1,
        "expected a Windows path (got {:?})",
        iocs
    );
    assert!(get("path_unc") >= 1, "expected a UNC path (got {:?})", iocs);
    assert!(
        get("registry") >= 1,
        "expected a registry key (got {:?})",
        iocs
    );
    assert!(
        get("java_path") >= 1,
        "expected a Java class path (got {:?})",
        iocs
    );
}

/// The positive half of the IPv4 rule the fixture cannot exercise: a routable
/// address must still be counted.
#[test]
fn public_ipv4_is_counted_but_private_is_not() {
    let cfg = classify_cfg();

    let public = extract_summary(b"beacon to 8.8.8.8 now", &cfg);
    let public_counts = public.ioc_counts.unwrap_or_default();
    assert!(
        public_counts.get("ipv4").copied().unwrap_or(0) >= 1,
        "public IPv4 must be counted (got {:?})",
        public_counts
    );

    let private = extract_summary(b"beacon to 192.168.1.10 now", &cfg);
    let private_counts = private.ioc_counts.unwrap_or_default();
    assert_eq!(
        private_counts.get("ipv4").copied().unwrap_or(0),
        0,
        "RFC1918 IPv4 is excluded by classify.rs (got {:?})",
        private_counts
    );
}

/// KNOWN PRODUCT BUG (found by wiring this file; not fixed here because the
/// fix is in `src/`).
///
/// `src/strings/classify.rs:179` evaluates `w[1] == w[0] + 1` inside
/// `is_valid_network_ipv4`'s "reject sequential octets" check. `.all()` does
/// not short-circuit before the second window, so any dotted-quad whose first
/// two octets are consecutive and whose second octet is 255 overflows: the
/// debug build panics with "attempt to add with overflow", the release build
/// wraps and silently misclassifies. `254.255.0.1` is the minimal repro.
///
/// Repro: `cargo test --features python-ext --test lib ipv4_with_255_octet`
#[test]
fn ipv4_with_255_octet_must_not_panic() {
    let cfg = classify_cfg();
    let summary = extract_summary(b"host 254.255.0.1 end", &cfg);
    // The value of the count is not the point; surviving the call is.
    println!("ioc_counts = {:?}", summary.ioc_counts);
}
