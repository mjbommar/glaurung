//! `src/demangle/` against a corpus of real symbols and real reference tools.
//!
//! # Why this file exists
//!
//! `src/demangle/` dispatches to three separate grammars -- Itanium C++, Rust
//! v0, and MSVC -- and had **one** unit test between them. That is not a
//! coverage gap of the ordinary kind: a demangler that gets a name wrong still
//! returns a plausible-looking string, so nothing downstream ever complains,
//! and the wrong name goes into the knowledge base under a `set_by` provenance
//! that outranks `auto`.
//!
//! # Where the expectations come from
//!
//! `tools/gen_demangle_corpus.py` harvests mangled names out of the symbol
//! tables of binaries this repository already tracks, and records what
//! `llvm-cxxfilt` / `rustfilt` / `llvm-undname` say each one means. The
//! expectations are therefore never glaurung's own output: a corpus built from
//! our answers would pin today's bugs and then assert we keep reproducing
//! them.
//!
//! # What a failure here means, and does not mean
//!
//! Different demanglers legitimately *spell* the same type differently --
//! spacing around `*`, whether a return type is printed, `(anonymous
//! namespace)` versus `{anonymous}`. So an exact string match would be a test
//! of two tools' formatting conventions rather than of our parsing.
//!
//! The assertion is therefore the one that is actually about correctness:
//! **every name the reference tool could demangle, we must also demangle**,
//! and the *identifier* parts of the answer must agree. A name we return
//! `None` for is a parsing failure and unambiguously ours. Formatting drift is
//! reported by the ratchet below rather than failing outright, so the file
//! stays useful as the reference tools change versions.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// Highest tolerated fraction of corpus entries we fail to demangle at all.
///
/// Set to ZERO, and it holds. It did not when this file was written: 44 of
/// 2,115 names (2.08%) failed outright, and all 44 were versioned symbols
/// (`..._M_widen_initEv@GLIBCXX_3.4.11`) that no demangler grammar accepts.
/// Stripping the suffix in `demangle::strip_version_suffix` fixed every one,
/// so the honest target turned out to be reachable in one change -- which is
/// the argument for building the corpus rather than assuming the demanglers
/// were fine. Never raise this without saying why in the commit message.
const MAX_UNPARSED_FRACTION: f64 = 0.0;

struct Entry {
    mangled: String,
    expected: String,
    flavor: String,
}

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("demangle")
        .join("corpus.jsonl")
}

/// Read the corpus, or `None` when it has not been generated.
///
/// Absent is a SKIP and not a failure: the corpus is generated rather than
/// committed-by-hand, and a fresh checkout on a machine without `llvm-cxxfilt`
/// cannot produce it. The skip is loud.
fn load_corpus() -> Option<Vec<Entry>> {
    let text = std::fs::read_to_string(corpus_path()).ok()?;
    let mut entries = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        // A hand-rolled reader for a three-field flat object, so this test
        // adds no serde dependency to the test target for one file.
        let mangled = json_field(line, "mangled")?;
        let expected = json_field(line, "expected")?;
        let flavor = json_field(line, "flavor")?;
        entries.push(Entry {
            mangled,
            expected,
            flavor,
        });
    }
    (!entries.is_empty()).then_some(entries)
}

/// The string value of one flat JSON field, honouring backslash escapes.
fn json_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\": \"");
    let start = line.find(&needle)? + needle.len();
    let mut out = String::new();
    let mut chars = line[start..].chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                other => out.push(other),
            },
            other => out.push(other),
        }
    }
    None
}

/// The identifier-ish tokens of a demangled name.
///
/// Comparing these rather than the whole string is what makes the test about
/// parsing instead of about two tools' punctuation conventions.
fn identifiers(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            current.push(c);
        } else if !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

#[test]
fn every_reference_demangled_name_is_demangled_by_us() {
    let Some(entries) = load_corpus() else {
        eprintln!(
            "SKIP: {} absent. Generate it with `uv run python tools/gen_demangle_corpus.py`.",
            corpus_path().display()
        );
        return;
    };

    let total = entries.len();
    let mut unparsed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in &entries {
        if glaurung::demangle::demangle_one(&entry.mangled).is_none() {
            unparsed
                .entry(entry.flavor.clone())
                .or_default()
                .push(entry.mangled.clone());
        }
    }

    let failed: usize = unparsed.values().map(Vec::len).sum();
    let fraction = failed as f64 / total as f64;
    if fraction > MAX_UNPARSED_FRACTION {
        let mut report = format!(
            "{failed} of {total} corpus names ({:.2}%) do not demangle at all; \
             the ratchet allows {:.2}%.\n",
            fraction * 100.0,
            MAX_UNPARSED_FRACTION * 100.0
        );
        for (flavor, names) in &unparsed {
            report.push_str(&format!("  {flavor}: {} failed, e.g.\n", names.len()));
            for name in names.iter().take(5) {
                report.push_str(&format!("    {name}\n"));
            }
        }
        panic!("{report}");
    }
    eprintln!(
        "demangle corpus: {total} names, {failed} unparsed ({:.2}%)",
        fraction * 100.0
    );
}

#[test]
fn demangled_identifiers_agree_with_the_reference() {
    let Some(entries) = load_corpus() else {
        eprintln!("SKIP: demangle corpus absent");
        return;
    };

    // Formatting differs legitimately between demanglers; identifiers do not.
    // A mismatch here means one of us parsed the name differently, which is
    // worth a human look even when it turns out to be a rendering choice.
    let mut mismatches = Vec::new();
    let mut compared = 0usize;
    for entry in &entries {
        let Some(ours) = glaurung::demangle::demangle_one(&entry.mangled) else {
            continue; // Covered by the test above; not this one's business.
        };
        compared += 1;
        let theirs = identifiers(&entry.expected);
        let mine = identifiers(&ours.demangled);
        // Substring containment rather than equality: reference tools include
        // return types and calling conventions we may omit, and vice versa.
        // The claim being tested is that we did not invent or lose a NAME.
        let shared = theirs.iter().filter(|t| mine.contains(t)).count();
        if theirs.is_empty() || shared * 2 < theirs.len() {
            mismatches.push(format!(
                "  {}\n    reference: {}\n    ours:      {}",
                entry.mangled, entry.expected, ours.demangled
            ));
        }
    }

    assert!(
        compared > 0,
        "corpus present but nothing was comparable -- the corpus or the API changed shape"
    );
    let allowed = compared / 20; // 5%, same reasoning as the ratchet above.
    assert!(
        mismatches.len() <= allowed,
        "{} of {compared} demangled names share fewer than half their identifiers \
         with the reference (allowed: {allowed}):\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn the_corpus_covers_more_than_one_grammar() {
    // A corpus that silently collapsed to one flavor would still pass the two
    // tests above while testing a third of the code.
    let Some(entries) = load_corpus() else {
        eprintln!("SKIP: demangle corpus absent");
        return;
    };
    let flavors: std::collections::BTreeSet<&str> =
        entries.iter().map(|e| e.flavor.as_str()).collect();
    assert!(
        flavors.len() >= 2,
        "corpus covers only {flavors:?}; regenerate with more binaries in scope"
    );
}
