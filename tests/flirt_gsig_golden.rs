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

use glaurung::flirt::gsig::{
    library_file_to_gsig, warp_library_from_gsig, warp_library_to_gsig, GsigLibrary, Scheme,
    WarpLibraryFile, WriteOptions,
};
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

// --- the WARP (exact-match GUID) scheme --------------------------------------
//
// The same tripwire for the second scheme the container carries. A published
// set holds both, addressed by sha256, so a drift in either record layout
// invalidates blobs that have already been announced.

/// `sha256sum tests/fixtures/flirt/gsig/warp_sample.x86_64.warp.json`.
const WARP_JSON_SHA256: &str = "f6f4fe7487f5d7f8fee3d43da457dc48b0cce7b7586cae49319bfaaf53c53a07";

/// `sha256sum tests/fixtures/flirt/gsig/warp_sample.x86_64.warp.gsig`.
const WARP_GSIG_SHA256: &str = "b7d166126f02edbbeeb87414076ebef26a1f4ebf7388a750839d7406fa749717";

#[test]
fn the_committed_warp_fixtures_match_their_recorded_sha256() {
    let json_bytes = read(&fixture("warp_sample.x86_64.warp.json"));
    let gsig_bytes = read(&fixture("warp_sample.x86_64.warp.gsig"));
    assert_eq!(
        sha256_hex(&json_bytes),
        WARP_JSON_SHA256,
        "the committed WARP JSON fixture no longer matches its recorded hash"
    );
    assert_eq!(
        sha256_hex(&gsig_bytes),
        WARP_GSIG_SHA256,
        "the committed WARP gsig fixture no longer matches its recorded hash \
         -- see tests/fixtures/flirt/gsig/README.md before refreshing this"
    );
}

/// Building the WARP container from the committed JSON reproduces the
/// committed bytes exactly.
#[test]
fn the_default_writer_reproduces_the_golden_warp_gsig_bytes() {
    let json_bytes = read(&fixture("warp_sample.x86_64.warp.json"));
    let file: WarpLibraryFile =
        serde_json::from_slice(&json_bytes).expect("golden WARP JSON fixture must parse");
    let rebuilt =
        warp_library_to_gsig(&file, &WriteOptions::default()).expect("golden WARP must write");
    let committed = read(&fixture("warp_sample.x86_64.warp.gsig"));
    assert_eq!(
        rebuilt, committed,
        "rewriting the golden WARP JSON fixture did not reproduce the \
         committed gsig bytes -- the writer changed without the fixture \
         being refreshed"
    );
    assert_eq!(sha256_hex(&rebuilt), WARP_GSIG_SHA256);
}

/// The golden WARP `.gsig` reads back every field the knowledge base files in
/// a `siglib_function` row -- name, base name, block count, byte length,
/// ambiguity and constraints -- not merely a parseable header.
#[test]
fn the_golden_warp_gsig_reads_back_every_record_field() {
    let gsig_bytes = read(&fixture("warp_sample.x86_64.warp.gsig"));
    let lib = GsigLibrary::parse(&gsig_bytes).expect("golden WARP gsig must parse");
    assert_eq!(lib.scheme(), Scheme::WarpFunctionGuidV1);
    assert_eq!(lib.guid_records().len(), 4);
    assert_eq!(lib.header().n_signatures as usize, lib.guid_records().len());

    let scale = &lib.guid_records()[1];
    assert_eq!(lib.string(scale.name).unwrap(), "sample_scale");
    assert_eq!(lib.string(scale.base_name).unwrap(), "sample_scale");
    assert_eq!(scale.block_count, 4);
    assert_eq!(scale.byte_len, 197);
    assert!(scale.ambiguous);
    assert_eq!(scale.constraints.len(), 3);
    // `null` is not zero: the fixture has a callee at offset 0 and a caller
    // with no offset at all, and they must not collapse into each other.
    assert_eq!(scale.constraints[0].offset, Some(0));
    assert_eq!(scale.constraints[1].offset, None);
    assert_eq!(lib.string(scale.constraints[1].kind).unwrap(), "caller");

    // The shared GUID still reports both names, which is what stops a later
    // library from claiming an ambiguous identity unopposed.
    let mut names = lib.guid_names(scale.guid);
    names.sort_unstable();
    assert_eq!(names, vec!["sample_scale", "sample_scale_alias"]);
}

/// The JSON the reader hands back is the JSON the fixture holds, field for
/// field. This is the property
/// `glaurung.llm.kb.siglib.ingest_warp_library_file` depends on when it is
/// pointed at a `.gsig` instead of a `.warp.json`.
#[test]
fn the_golden_warp_gsig_round_trips_to_its_json() {
    let json_bytes = read(&fixture("warp_sample.x86_64.warp.json"));
    let original: serde_json::Value =
        serde_json::from_slice(&json_bytes).expect("golden WARP JSON must parse");
    let gsig_bytes = read(&fixture("warp_sample.x86_64.warp.gsig"));
    let lib = GsigLibrary::parse(&gsig_bytes).expect("golden WARP gsig must parse");
    let back = warp_library_from_gsig(&lib).expect("golden WARP gsig must convert back");
    assert_eq!(original, serde_json::to_value(&back).unwrap());
}
