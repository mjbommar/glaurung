//! `gsig/1` against every harvested signature library on this machine.
//!
//! `tests/flirt_gsig_golden.rs` pins one committed 12-signature fixture to a
//! sha256, which is the CI-portable tripwire for the writer and reader
//! drifting together. This file is the corpus-scale version of the same
//! property -- **lossless** JSON to gsig to JSON, and **deterministic** gsig
//! to gsig -- run against every real library `python -m
//! glaurung.tools.build_flirt_library` has harvested onto this box, under
//! `$HOME/.cache/glaurung/system-libs/sigs/`. That directory is a
//! machine-specific cache, not a repository fixture: it is read-only here,
//! never written to, and its absence skips this file's tests rather than
//! failing them -- the same shape as `tests/identity_retrieval/main.rs`'s
//! corpus gate.
//!
//! `python -m glaurung.tools.sig_convert roundtrip
//! ~/.cache/glaurung/system-libs/sigs/` is the same check with a
//! bytes-per-signature report on the way out; see the "The gsig/1 container"
//! section of `docs/reference/function-signature-libraries.md` for the
//! numbers it produced on 2026-09-03 (561 libraries, 222,339 signatures, 0
//! failures).

use std::path::{Path, PathBuf};

use glaurung::flirt::gsig::{library_file_from_gsig, library_file_to_gsig, GsigLibrary};
use glaurung::flirt::FlirtLibraryFile;

fn corpus_dir() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME must be set");
    PathBuf::from(home).join(".cache/glaurung/system-libs/sigs")
}

/// Every `*.flirt.json` file in the corpus, or an empty vec with a SKIP
/// notice if the directory is not there.
fn harvested_libraries() -> Vec<PathBuf> {
    let dir = corpus_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!(
            "SKIP: {} is absent. It is a machine-local harvest cache, not a \
             repository fixture; see docs/reference/function-signature-libraries.md \
             \"The gsig/1 container\" for how it is produced.",
            dir.display()
        );
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().ends_with(".flirt.json"))
        .collect();
    out.sort();
    out
}

fn read_library(path: &Path) -> FlirtLibraryFile {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{} must be readable ({e})", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{} must parse as a signature library ({e})", path.display()))
}

/// JSON to gsig to JSON must be lossless, and gsig to gsig must be
/// byte-identical, for every harvested library -- not just the committed
/// twelve-signature fixture.
#[test]
fn every_harvested_library_round_trips_losslessly() {
    let libraries = harvested_libraries();
    if libraries.is_empty() {
        return;
    }

    let mut total_signatures = 0usize;
    let mut total_json_bytes = 0u64;
    let mut total_gsig_bytes = 0u64;
    let mut failures: Vec<String> = Vec::new();

    for path in &libraries {
        let file = read_library(path);
        let options = Default::default();

        let first = match library_file_to_gsig(&file, &options) {
            Ok(bytes) => bytes,
            Err(e) => {
                failures.push(format!("{}: write failed: {e}", path.display()));
                continue;
            }
        };
        let loaded = match GsigLibrary::parse(&first) {
            Ok(lib) => lib,
            Err(e) => {
                failures.push(format!("{}: read-back failed: {e}", path.display()));
                continue;
            }
        };
        let back = match library_file_from_gsig(&loaded) {
            Ok(f) => f,
            Err(e) => {
                failures.push(format!("{}: rebuild failed: {e}", path.display()));
                continue;
            }
        };

        // Lossless: canonical JSON of the original equals canonical JSON of
        // the round-tripped copy. `serde_json::to_value` normalises key
        // order so this compares content, not text layout.
        let original_value = serde_json::to_value(&file).unwrap();
        let back_value = serde_json::to_value(&back).unwrap();
        if original_value != back_value {
            failures.push(format!(
                "{}: JSON -> gsig -> JSON changed content",
                path.display()
            ));
            continue;
        }

        // Deterministic: writing the round-tripped copy again reproduces the
        // exact same gsig bytes -- the property a content-addressed
        // distribution needs.
        let second = library_file_to_gsig(&back, &options).unwrap();
        if first != second {
            failures.push(format!(
                "{}: gsig -> gsig was not byte-identical",
                path.display()
            ));
            continue;
        }

        total_signatures += file.entries.len();
        total_json_bytes += std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        total_gsig_bytes += first.len() as u64;
    }

    assert!(
        failures.is_empty(),
        "{} of {} harvested libraries failed a lossless or deterministic \
         round trip:\n  {}",
        failures.len(),
        libraries.len(),
        failures.join("\n  ")
    );

    let per_sig_json = total_json_bytes as f64 / total_signatures.max(1) as f64;
    let per_sig_gsig = total_gsig_bytes as f64 / total_signatures.max(1) as f64;
    eprintln!(
        "{} harvested libraries, {total_signatures} signatures, 0 round-trip \
         failures: json {total_json_bytes} bytes ({per_sig_json:.0} B/sig), \
         gsig {total_gsig_bytes} bytes ({per_sig_gsig:.0} B/sig), {:.1}x smaller",
        libraries.len(),
        total_json_bytes as f64 / total_gsig_bytes.max(1) as f64
    );
    assert!(
        total_signatures > 10_000,
        "only {total_signatures} signatures were checked across {} libraries; \
         the corpus shrank, or the glob stopped matching",
        libraries.len()
    );
}

/// The matcher must resolve identically whichever format it loads: a record
/// with no CRC and a unique masked pattern must name the same thing (or
/// nothing) whether the library came from JSON or from its own gsig.
#[test]
fn a_harvested_librarys_matcher_agrees_between_formats() {
    let libraries = harvested_libraries();
    if libraries.is_empty() {
        return;
    }

    let mut checked = 0usize;
    for path in libraries.iter().take(25) {
        let file = read_library(path);
        if file.entries.is_empty() {
            continue;
        }
        let gsig_bytes = library_file_to_gsig(&file, &Default::default()).unwrap();

        let from_json = glaurung::flirt::FlirtLibrary::from_file(file.clone());
        let from_gsig = glaurung::flirt::FlirtLibrary::from_gsig_bytes(&gsig_bytes).unwrap();

        // Every entry whose own pattern is exactly `prologue_len` bytes must
        // resolve the same way from both compiled forms -- that includes
        // ambiguous verdicts, which is why this compares the full verdict
        // rather than unwrapping to a name.
        for entry in &file.entries {
            let pattern = hex::decode(&entry.prologue_hex).unwrap();
            if pattern.len() != file.prologue_len {
                continue;
            }
            let verdict_json = from_json.match_at(&pattern);
            let verdict_gsig = from_gsig.match_at(&pattern);
            assert_eq!(
                format!("{verdict_json:?}"),
                format!("{verdict_gsig:?}"),
                "{}: {} matched differently from JSON and gsig",
                path.display(),
                entry.name
            );
            checked += 1;
        }
    }
    assert!(
        checked > 100,
        "only {checked} entries were cross-checked; the sample or the corpus is too small"
    );
    eprintln!("{checked} entries agreed between the JSON-compiled and gsig-compiled matcher");
}
