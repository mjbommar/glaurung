//! `gsig/1` against a committed golden fixture.
//!
//! A round-trip test (see `tests/flirt_gsig_roundtrip.rs`) proves the reader
//! agrees with the writer. It cannot notice the two of them drifting
//! together -- a changed field order, a different chunk size, an `Option`
//! that stopped being packed into the flags byte. Every one of those
//! silently invalidates every `.gsig` already published, and a
//! content-addressed distribution notices only when a hash it has already
//! announced stops matching. This file is the tripwire: it pins the exact
//! bytes of one committed container to a sha256 written in the source, not
//! read back from a file that could drift alongside it.
//!
//! See `tests/fixtures/flirt/gsig/README.md` for what the fixture is, its
//! provenance, and how to refresh it -- deliberately, and never to make a
//! red test green.

use std::path::{Path, PathBuf};

use glaurung::flirt::gsig::{library_file_to_gsig, GsigLibrary, WriteOptions};
use glaurung::flirt::FlirtLibraryFile;

/// `sha256sum tests/fixtures/flirt/gsig/mingw_crt_three.x86_64.flirt.json`.
const JSON_SHA256: &str = "b3c067204d0d567fa85ddb619a54e81d52471db04a0ecaa3b15626d3aeae21d3";

/// `sha256sum tests/fixtures/flirt/gsig/mingw_crt_three.x86_64.flirt.gsig`.
const GSIG_SHA256: &str = "0cfcc67998b269834423f0d48c21a2892a83d18ff24d9f5e6043065c43bcd0e5";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> PathBuf {
    repo_root().join("tests/fixtures/flirt/gsig").join(name)
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{} must be readable ({e})", path.display()))
}

/// The committed fixtures must still be exactly what the README's table and
/// this file's constants claim. If this fails on an intentional format
/// change, refresh both per `tests/fixtures/flirt/gsig/README.md` -- never
/// loosen the assertion.
#[test]
fn the_committed_fixtures_match_their_recorded_sha256() {
    let json_bytes = read(&fixture("mingw_crt_three.x86_64.flirt.json"));
    let gsig_bytes = read(&fixture("mingw_crt_three.x86_64.flirt.gsig"));
    assert_eq!(
        sha256_hex(&json_bytes),
        JSON_SHA256,
        "the committed JSON fixture no longer matches its recorded hash"
    );
    assert_eq!(
        sha256_hex(&gsig_bytes),
        GSIG_SHA256,
        "the committed gsig fixture no longer matches its recorded hash -- \
         see tests/fixtures/flirt/gsig/README.md before refreshing this"
    );
}

/// Building `gsig/1` from the committed JSON, with the default codec,
/// reproduces the committed container byte for byte.
///
/// This is the property that actually matters for distribution: given the
/// same input and the same writer, the bytes -- and therefore the sha256 a
/// manifest names -- do not move across machines, compiler versions, or
/// `HashMap` iteration order.
#[test]
fn the_default_writer_reproduces_the_golden_gsig_bytes() {
    let json_bytes = read(&fixture("mingw_crt_three.x86_64.flirt.json"));
    let file: FlirtLibraryFile =
        serde_json::from_slice(&json_bytes).expect("golden JSON fixture must parse");
    let rebuilt =
        library_file_to_gsig(&file, &WriteOptions::default()).expect("golden library must write");

    let committed = read(&fixture("mingw_crt_three.x86_64.flirt.gsig"));
    assert_eq!(
        rebuilt, committed,
        "rewriting the golden JSON fixture did not reproduce the committed \
         gsig bytes -- the writer changed without the fixture being refreshed"
    );
    assert_eq!(sha256_hex(&rebuilt), GSIG_SHA256);
}

/// The golden `.gsig` reads back to signatures the shipped reader considers
/// real: a nonzero record count, names, and prologue bytes, not just "the
/// header parses".
#[test]
fn the_golden_gsig_reads_back_real_signatures() {
    let gsig_bytes = read(&fixture("mingw_crt_three.x86_64.flirt.gsig"));
    let lib = GsigLibrary::parse(&gsig_bytes).expect("golden gsig fixture must parse");
    assert_eq!(lib.header().n_signatures as usize, lib.records().len());
    assert!(
        lib.records().len() >= 10,
        "golden fixture should hold at least the twelve signatures the \
         README describes; found {}",
        lib.records().len()
    );
    for record in lib.records() {
        assert!(
            !lib.string(record.name).unwrap().is_empty(),
            "every golden record must carry a name"
        );
        assert!(
            !lib.pattern(record).is_empty(),
            "every golden record must carry a nonempty pattern"
        );
    }
}
