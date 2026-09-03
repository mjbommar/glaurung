//! `src/identity/gate.rs` measured against real function identities.
//!
//! `src/identity/gate.rs`'s own unit tests cover the synthetic side (>=1e5
//! keys, determinism, zero-copy). This file covers the two things that need
//! real bytes: a corpus-wide run over every WARP function GUID this
//! repository's own sample binaries produce, and the negative control the
//! membership-gate deliverable asks for by name -- a gate built from a real
//! library's identities must reject every function of an unrelated sample
//! binary while still accepting the library's own functions read from a
//! *different* link layout of the same archive.

use std::path::{Path, PathBuf};

use glaurung::identity::gate::IdentityGate;
use glaurung::identity::warp::warp_functions_from_bytes;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every WARP function GUID `path` produces, as identity strings. Silently
/// empty for a file WARP cannot process (wrong architecture, not an object
/// file) -- the corpus below is not curated to be all-x86_64, and "this file
/// contributed nothing" is a fine outcome for a survey.
fn warp_identities(path: &Path) -> Vec<String> {
    let Ok(data) = std::fs::read(path) else {
        return Vec::new();
    };
    match warp_functions_from_bytes(&data) {
        Ok(functions) => functions.into_iter().map(|f| f.guid.to_string()).collect(),
        Err(_) => Vec::new(),
    }
}

fn sample_binaries_under(rel: &str) -> Vec<PathBuf> {
    let root = repo_root().join(rel);
    let mut out = Vec::new();
    let Ok(entries) = walk(&root) else {
        return out;
    };
    out.extend(entries);
    out
}

fn walk(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path)?);
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(out)
}

/// A real run over every function identity the sample corpus produces:
/// `docs/history/program-measures-2026-09-02.md` item 7's "real run over
/// every function identity in the sample corpus" requirement.
///
/// x86/x86-64 only, per WARP's current architecture coverage
/// (`docs/reference/function-identity-warp.md`); other architectures under
/// `samples/` simply contribute zero identities via [`warp_identities`]'s
/// silent-empty behaviour.
#[test]
fn real_corpus_gate_has_zero_false_negatives() {
    let binaries = sample_binaries_under("samples/binaries/platforms/linux/amd64/export/native");
    if binaries.is_empty() {
        eprintln!("SKIP: samples/binaries/platforms/linux/amd64/export/native not present");
        return;
    }

    let mut identities: Vec<String> = Vec::new();
    let mut files_contributing = 0usize;
    for path in &binaries {
        let ids = warp_identities(path);
        if !ids.is_empty() {
            files_contributing += 1;
        }
        identities.extend(ids);
    }

    assert!(
        identities.len() >= 50,
        "expected at least 50 WARP identities across the native sample corpus, \
         got {} from {} files ({} contributed at least one)",
        identities.len(),
        binaries.len(),
        files_contributing
    );

    let gate = IdentityGate::build(&identities).expect("gate must build over real identities");
    let mut misses = 0usize;
    for id in &identities {
        if !gate.contains(id) {
            misses += 1;
        }
    }
    assert_eq!(
        misses, 0,
        "a binary fuse filter has zero false negatives by construction; any miss here is a bug"
    );

    eprintln!(
        "real corpus: {} files, {} contributing, {} WARP identities, \
         n_keys={} bits_per_key={:.3}",
        binaries.len(),
        files_contributing,
        identities.len(),
        gate.n_keys(),
        gate.bits_per_key(),
    );
}

/// The membership-gate deliverable's negative-control test, at the Rust
/// layer: a gate built from one real library's WARP identities (`mathlib`,
/// read from one relink fixture) must reject every function of an entirely
/// unrelated sample binary, and every non-library driver function in the
/// SAME fixture, while still accepting the library's own functions read from
/// the OTHER relink layout -- proving the gate is testing identity, not
/// merely "did this come from the mathlib fixture directory".
#[test]
fn gate_rejects_every_function_of_an_unrelated_binary_except_true_library_members() {
    let link_a = repo_root().join("tests/fixtures/flirt/mathlib_link_a.x86_64.elf");
    let link_b = repo_root().join("tests/fixtures/flirt/mathlib_link_b.x86_64.elf");
    let unrelated = repo_root()
        .join("samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug");
    if !link_a.exists() || !link_b.exists() {
        eprintln!("SKIP: tests/fixtures/flirt/ relink fixtures not present");
        return;
    }
    if !unrelated.exists() {
        eprintln!("SKIP: sample binary {} not present", unrelated.display());
        return;
    }

    let data_a = std::fs::read(&link_a).unwrap();
    let functions_a = warp_functions_from_bytes(&data_a).expect("link A must parse under WARP");
    let library_identities: Vec<String> = functions_a
        .iter()
        .filter(|f| f.name.starts_with("mathlib_"))
        .map(|f| f.guid.to_string())
        .collect();
    assert!(
        library_identities.len() >= 15,
        "only {} mathlib_* WARP identities found in link A; fixture shrank?",
        library_identities.len()
    );
    let gate = IdentityGate::build(&library_identities).unwrap();

    // Positive control: the SAME functions read from the OTHER link layout
    // must still be accepted -- this is the WARP relink-invariance property
    // (`docs/reference/function-identity-warp.md`: 22/22) exercised through
    // the gate rather than through direct GUID equality.
    let data_b = std::fs::read(&link_b).unwrap();
    let functions_b = warp_functions_from_bytes(&data_b).expect("link B must parse under WARP");
    let mut link_b_mathlib_checked = 0usize;
    for f in &functions_b {
        if !f.name.starts_with("mathlib_") {
            continue;
        }
        link_b_mathlib_checked += 1;
        assert!(
            gate.contains(&f.guid.to_string()),
            "gate rejected a real library member from the other link layout: {}",
            f.name
        );
    }
    assert!(link_b_mathlib_checked >= 15);

    // Negative control: link A's own non-library driver functions, plus
    // every function of an unrelated sample binary.
    let mut false_positives: Vec<String> = Vec::new();
    for f in functions_a
        .iter()
        .filter(|f| !f.name.starts_with("mathlib_"))
    {
        if gate.contains(&f.guid.to_string()) {
            false_positives.push(format!("link A driver: {}", f.name));
        }
    }
    let unrelated_data = std::fs::read(&unrelated).unwrap();
    if let Ok(unrelated_functions) = warp_functions_from_bytes(&unrelated_data) {
        for f in &unrelated_functions {
            if gate.contains(&f.guid.to_string()) {
                false_positives.push(format!("unrelated binary: {}", f.name));
            }
        }
    }
    assert!(
        false_positives.is_empty(),
        "gate accepted {} function(s) that are not mathlib library members: {:?}",
        false_positives.len(),
        false_positives
    );
}
