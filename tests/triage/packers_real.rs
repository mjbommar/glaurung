//! Integration tests for packer detection with real samples.

use glaurung::triage::api::analyze_path;
use glaurung::triage::config::PackerConfig;
use glaurung::triage::io::IOLimits;
use glaurung::triage::packers::detect_packers;
use std::fs;
use std::path::Path;

/// UPX-packed samples are produced by `samples/build-packed.sh`, which writes
/// to `samples/packed/` (`OUT_DIR="$ROOT_DIR/packed"`). The paths this file
/// originally used (`.../export/native/gcc/O0/hello-c-gcc-O0.upx9` and
/// friends) have never existed in the tracked corpus, so every loop over them
/// found nothing and the suite passed by doing no work.
const PACKED_SAMPLES: &[&str] = &[
    "samples/packed/hello-rust-release.upx9",
    "samples/packed/hello-go.upx9",
    "samples/packed/hello-gfortran-O0.upx9",
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-cpp-g++-O0.upx9",
];

fn read_tracked_sample(path: &str) -> Vec<u8> {
    assert!(
        Path::new(path).exists(),
        "tracked sample missing: {} (corpus moved?)",
        path
    );
    fs::read(path).expect("Failed to read sample")
}

/// Test UPX detection on packed binaries
#[test]
fn test_upx_detection_real_binaries() {
    let cfg = PackerConfig::default();

    for file_path in PACKED_SAMPLES {
        let data = read_tracked_sample(file_path);
        let packers = detect_packers(&data, &cfg);

        println!("Testing {}", file_path);
        println!("  File size: {} bytes", data.len());
        println!("  Detected packers: {:?}", packers);

        // Should detect UPX
        assert!(!packers.is_empty(), "Failed to detect UPX in {}", file_path);

        let upx_match = packers.iter().find(|p| p.name == "UPX");
        assert!(upx_match.is_some(), "UPX not detected in {}", file_path);

        println!("  UPX confidence: {:.2}", upx_match.unwrap().confidence);
    }
}

/// KNOWN PRODUCT BUG (found by wiring this file; not fixed here because the
/// fix is in `src/`).
///
/// A genuinely UPX-packed ELF scores **0.36** on the `UPX` match, below any
/// "probably packed" threshold, and a synthetic buffer carrying the `UPX!`
/// magic *and* the `$Id: UPX 4.2.4` version banner scores the same 0.36.
/// Two causes, both in `src/triage/packers.rs`:
///
/// * The `UPX0` / `UPX1` terms (+0.3 each, packers.rs:31-36) are PE section
///   names. On ELF only `UPX!` (+0.4) and the version banner (+0.2) fire, and
///   the total is then *scaled down* by `cfg.upx_detection_weight` (0.6):
///   0.6 * 0.6 = 0.36. A definitive vendor magic cannot reach 0.5.
/// * `PackerConfig::upx_version_weight` (src/triage/config.rs:868, default
///   0.2, with a Python getter and setter) is **read by nothing in `src/`** --
///   the version banner is worth a hardcoded +0.2 instead, so detecting the
///   version does not raise confidence over detecting the magic alone.
///
/// Repro: `cargo test --features python-ext --test lib upx_confidence`
#[test]
fn upx_confidence_clears_a_useful_threshold() {
    let cfg = PackerConfig::default();

    let data = read_tracked_sample("samples/packed/hello-rust-release.upx9");
    let packers = detect_packers(&data, &cfg);
    let packed_elf = packers
        .iter()
        .find(|p| p.name == "UPX")
        .expect("UPX detected")
        .confidence;

    let with_version = detect_packers(b"UPX!\x00\x00\x00\x00$Id: UPX 4.2.4 Copyright", &cfg);
    let magic_and_version = with_version
        .iter()
        .find(|p| p.name == "UPX")
        .expect("UPX detected")
        .confidence;
    let magic_only = detect_packers(b"UPX!\x00\x00\x00\x00 nothing else here", &cfg)
        .iter()
        .find(|p| p.name == "UPX")
        .expect("UPX detected")
        .confidence;

    assert!(
        packed_elf > 0.5,
        "real UPX-packed ELF scored {:.2}",
        packed_elf
    );
    assert!(
        magic_and_version > magic_only,
        "version banner did not raise confidence: {:.2} vs {:.2}",
        magic_and_version,
        magic_only
    );
}

/// Test that unpacked binaries don't trigger false positives
#[test]
fn test_no_false_positives_unpacked() {
    let cfg = PackerConfig::default();
    let test_files = vec![
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-c-gcc-O0",
        "samples/binaries/platforms/linux/amd64/export/lua/hello-lua5.4.luac",
        "samples/binaries/platforms/linux/amd64/export/java/jdk21/HelloWorld.class",
    ];

    for file_path in test_files {
        let data = read_tracked_sample(file_path);
        let packers = detect_packers(&data, &cfg);

        println!("Testing {} for false positives", file_path);
        println!("  Detected packers: {:?}", packers);

        // Should not detect UPX in unpacked files
        let upx_match = packers.iter().find(|p| p.name == "UPX");
        assert!(
            upx_match.is_none(),
            "False positive UPX detection in {}",
            file_path
        );
    }
}

/// Test packer detection through the full triage API
#[test]
fn test_packer_detection_via_triage_api() {
    let packed_file = "samples/packed/hello-rust-release.upx9";
    assert!(
        Path::new(packed_file).exists(),
        "tracked sample missing: {}",
        packed_file
    );

    let limits = IOLimits::default();
    let artifact = analyze_path(packed_file, &limits).expect("Failed to analyze packed file");

    println!("Triage result for packed binary:");
    println!("  Verdicts: {:?}", artifact.verdicts);
    println!("  Packers: {:?}", artifact.packers);

    // Should detect packer
    let packers = artifact
        .packers
        .clone()
        .expect("No packers field in result");
    assert!(!packers.is_empty(), "No packers detected");

    // Check confidence signals for packer
    if !artifact.verdicts.is_empty() {
        let verdict = &artifact.verdicts[0];
        if let Some(signals) = &verdict.signals {
            let packer_signal = signals.iter().find(|s| s.name.contains("packer"));
            println!("  Packer signal: {:?}", packer_signal);
        }
    }
}

/// Test comparison of packed vs unpacked entropy
#[test]
fn test_packed_vs_unpacked_entropy() {
    use glaurung::entropy::shannon_entropy as entropy_of_slice;

    let pairs = vec![(
        "samples/binaries/platforms/linux/amd64/export/rust/hello-rust-release",
        "samples/packed/hello-rust-release.upx9",
    )];

    for (orig_path, packed_path) in pairs {
        let orig_data = read_tracked_sample(orig_path);
        let packed_data = read_tracked_sample(packed_path);

        let orig_entropy = entropy_of_slice(&orig_data);
        let packed_entropy = entropy_of_slice(&packed_data);

        println!("Entropy comparison:");
        println!(
            "  Original: {} bytes, entropy: {:.4}",
            orig_data.len(),
            orig_entropy
        );
        println!(
            "  Packed:   {} bytes, entropy: {:.4}",
            packed_data.len(),
            packed_entropy
        );
        println!(
            "  Compression ratio: {:.2}x",
            orig_data.len() as f64 / packed_data.len() as f64
        );

        // UPX-packed files should have higher entropy due to compression
        assert!(
            packed_entropy > orig_entropy,
            "Packed entropy ({:.4}) should be higher than original ({:.4})",
            packed_entropy,
            orig_entropy
        );
    }
}

/// Test UPX version detection
#[test]
fn test_upx_version_detection() {
    // Synthetic byte string, not a binary fixture: the point is the signature.
    let test_data_with_version = b"UPX!\x00\x00\x00\x00$Id: UPX 4.2.4 Copyright";

    let packers = detect_packers(test_data_with_version, &PackerConfig::default());
    assert!(
        !packers.is_empty(),
        "Failed to detect UPX with version string"
    );

    let upx = &packers[0];
    assert_eq!(upx.name, "UPX");
    // The confidence this *should* carry is asserted by
    // `upx_confidence_clears_a_useful_threshold` above, which is red on a
    // real product bug.
    println!("UPX confidence with version: {:.2}", upx.confidence);
}

/// Test scanning limits for packer detection
#[test]
fn test_packer_scan_limits() {
    use std::time::Instant;

    let cfg = PackerConfig::default();
    // The last position sits inside the default 512 KB scan window; a
    // signature past `cfg.scan_limit` is deliberately not found.
    let positions = vec![0, 1024, 16384, cfg.scan_limit - 4];

    for pos in positions {
        let mut data = vec![0u8; cfg.scan_limit];
        data[pos..pos + 4].copy_from_slice(b"UPX!");

        let start = Instant::now();
        let packers = detect_packers(&data, &cfg);
        let duration = start.elapsed();

        println!("Scan with UPX at position {}: {:?}", pos, duration);
        assert!(
            !packers.is_empty(),
            "Failed to find UPX at position {}",
            pos
        );

        // Should complete quickly even for large files
        assert!(
            duration.as_millis() < 100,
            "Scan took too long: {:?}",
            duration
        );
    }
}
