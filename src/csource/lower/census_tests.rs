//! The feasibility census: what fraction of the fixture corpus this lowering
//! covers, and what stops the rest.
//!
//! `roadmap.md` section 6 asks for a number before it asks for code. The census
//! is that number, and it is produced by *attempting the real lowering* on every
//! function in `tests/decompiler_fixtures/src/`, not by a separate estimate that
//! could drift from what the emitter actually does. A refusal carries the
//! construct's name, so the failure table is a work queue as well as a
//! measurement.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::csource::lower::{lower_function, LowerError};
use crate::csource::parse::parse;

/// The fixture source directory, or `None` when the corpus is not present.
fn fixture_src() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/decompiler_fixtures/src");
    dir.is_dir().then_some(dir)
}

/// Every `.c` file in the fixture corpus, sorted.
fn fixture_sources(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "c"))
        .collect();
    out.sort();
    out
}

/// One function's census outcome.
struct Row {
    file: String,
    name: String,
    error: Option<LowerError>,
}

fn census() -> Option<Vec<Row>> {
    let dir = fixture_src()?;
    let mut rows = Vec::new();
    for path in fixture_sources(&dir) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let file = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();
        let tree = parse(&text).into_parts().0;
        for def in tree.functions(&text) {
            let error = lower_function(&tree, &text, &def).err();
            rows.push(Row {
                file: file.clone(),
                name: def.name.clone(),
                error,
            });
        }
    }
    Some(rows)
}

/// The refusal reason with its variable parts removed, so the frequency table
/// groups `parameter type `foo_t`` with `parameter type `bar_t``.
fn bucket(error: &LowerError) -> String {
    match error.what.find('`') {
        Some(quote) => format!("{}<name>", &error.what[..quote]),
        None => error.what.clone(),
    }
}

#[test]
fn fixture_corpus_lowering_census() {
    let Some(rows) = census() else {
        crate::testing::missing_fixture("tests/decompiler_fixtures/src");
        return;
    };
    let total = rows.len();
    let lowered = rows.iter().filter(|r| r.error.is_none()).count();
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    for row in rows.iter().filter(|r| r.error.is_some()) {
        *reasons
            .entry(bucket(row.error.as_ref().expect("filtered")))
            .or_default() += 1;
    }
    let files: std::collections::BTreeSet<&str> = rows.iter().map(|r| r.file.as_str()).collect();

    let mut table: Vec<(&String, &usize)> = reasons.iter().collect();
    table.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    println!("--- S4 lowering census over tests/decompiler_fixtures/src ---");
    println!("files: {}", files.len());
    println!(
        "functions: {total}; lowered: {lowered} ({:.2}%); refused: {}",
        100.0 * lowered as f64 / total.max(1) as f64,
        total - lowered
    );
    let mut samples: BTreeMap<String, String> = BTreeMap::new();
    for row in rows.iter().filter(|r| r.error.is_some()) {
        let e = row.error.as_ref().expect("filtered");
        samples
            .entry(bucket(e))
            .or_insert_with(|| format!("{}::{} -- {}", row.file, row.name, e.what));
    }
    for (reason, count) in &table {
        println!(
            "{count:>5}  {reason}   e.g. {}",
            samples.get(*reason).map(String::as_str).unwrap_or("")
        );
    }
    println!("--- functions that lower ---");
    for row in rows.iter().filter(|r| r.error.is_none()) {
        println!("  {}::{}", row.file, row.name);
    }

    // The corpus is large and single-construct by design; a census that found
    // nothing at all would mean the walk never reached a body.
    assert!(total > 500, "census saw only {total} functions");
    assert!(lowered > 0, "no fixture function lowered at all");
}
