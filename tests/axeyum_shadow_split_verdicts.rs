//! The shadow-split regression set, replayed through the pinned Axeyum.
//!
//! `tests/corpora/axeyum-qfbv/shadow-splits/verdicts.tsv` names every z3-valid
//! script under that directory with z3's verdict and the verdict the pinned
//! Axeyum gave it (written by `tools/axeyum/split_verdicts.py`).  This test
//! drives each script through the pinned `axeyum-solver`'s SMT-LIB front door
//! and fails on any script that is listed but missing or present but unlisted,
//! any script Axeyum decides *differently* from z3 (a soundness finding on one
//! side), and any script whose committed Axeyum column is decided that Axeyum
//! no longer decides -- the **regression floor** (solver-034).  A script whose
//! committed column is undecided (`unmeasured`, `unknown:*`, `error:*`) is an
//! open capability gap the capture tier found: it is reported by name, never a
//! failure, and when Axeyum comes to decide it the report says so, so the
//! column can be promoted into the floor by rerunning `split_verdicts.py
//! --axeyum-results`.
//!
//! It needs the text bridge (`solver-axeyum-text`, which turns on Axeyum's
//! `full` profile) because the production `qfbv` profile carries no SMT-LIB
//! parser:
//!
//! ```sh
//! cargo test --features solver-axeyum-text --test axeyum_shadow_split_verdicts -- --nocapture
//! ```
//!
//! Set `GLAURUNG_SHADOW_SPLIT_AXEYUM_OUT=<file>` to also write
//! `capture<TAB>sha256<TAB>verdict<TAB>millis` per script, which
//! `split_verdicts.py --axeyum-results` folds back into the Axeyum column.
#![cfg(feature = "solver-axeyum-text")]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use axeyum_solver::{solve_smtlib, CheckResult, SolverConfig};

const VERDICTS: &str = "tests/corpora/axeyum-qfbv/shadow-splits/verdicts.tsv";
const PER_SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpora/axeyum-qfbv/shadow-splits")
}

/// One committed row: z3's verdict and the pinned Axeyum's.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pinned {
    z3: String,
    axeyum: String,
}

impl Pinned {
    /// The row is part of the regression floor: the pinned Axeyum decided it.
    fn in_floor(&self) -> bool {
        matches!(self.axeyum.as_str(), "sat" | "unsat")
    }
}

/// `(capture, sha256) -> pinned verdicts`, from the committed regression index.
fn read_verdicts(path: &Path) -> BTreeMap<(String, String), Pinned> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let mut rows = BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(
            fields.len(),
            4,
            "{VERDICTS}:{}: expected capture<TAB>sha256<TAB>z3<TAB>axeyum",
            number + 1
        );
        assert!(
            matches!(fields[2], "sat" | "unsat"),
            "{VERDICTS}:{}: z3 verdict must be sat or unsat, got {:?}",
            number + 1,
            fields[2]
        );
        let previous = rows.insert(
            (fields[0].to_string(), fields[1].to_string()),
            Pinned {
                z3: fields[2].to_string(),
                axeyum: fields[3].to_string(),
            },
        );
        assert!(
            previous.is_none(),
            "{VERDICTS}:{}: duplicate row",
            number + 1
        );
    }
    rows
}

/// Every `<capture>/<sha256>.smt2` under the live root, so an unlisted script
/// cannot hide beside the listed ones.
fn scripts_on_disk(root: &Path) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for capture in std::fs::read_dir(root).expect("shadow-splits root") {
        let capture = capture.expect("capture entry").path();
        if !capture.is_dir() {
            continue;
        }
        let name = capture.file_name().unwrap().to_string_lossy().into_owned();
        for script in std::fs::read_dir(&capture).expect("capture dir") {
            let script = script.expect("script entry").path();
            if script.extension().is_some_and(|ext| ext == "smt2") {
                found.push((
                    name.clone(),
                    script.file_stem().unwrap().to_string_lossy().into_owned(),
                ));
            }
        }
    }
    found.sort();
    found
}

/// What one replayed script means against its committed row.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    /// Decided like z3 (floor row held, or a new row that already agrees).
    Agrees,
    /// Both decided, differently: a soundness finding on one side.
    Disagreement,
    /// A floor row the pinned solver no longer decides.
    Regression,
    /// A committed-undecided row Axeyum now decides like z3.
    NowDecided,
    /// A committed-undecided row still undecided: an open capability gap.
    OpenGap,
}

fn classify(pinned: &Pinned, verdict: &str) -> Outcome {
    let decided = matches!(verdict, "sat" | "unsat");
    if decided && verdict != pinned.z3 {
        Outcome::Disagreement
    } else if pinned.in_floor() && !decided {
        Outcome::Regression
    } else if !pinned.in_floor() && decided {
        Outcome::NowDecided
    } else if !pinned.in_floor() {
        Outcome::OpenGap
    } else {
        Outcome::Agrees
    }
}

#[test]
fn classification_keeps_the_floor_and_never_fails_an_open_gap() {
    let floor = Pinned {
        z3: "sat".into(),
        axeyum: "sat".into(),
    };
    let gap = Pinned {
        z3: "unsat".into(),
        axeyum: "unmeasured".into(),
    };
    let stale_gap = Pinned {
        z3: "unsat".into(),
        axeyum: "unknown:WallTimeout".into(),
    };
    assert_eq!(classify(&floor, "sat"), Outcome::Agrees);
    assert_eq!(classify(&floor, "unsat"), Outcome::Disagreement);
    assert_eq!(classify(&floor, "unknown:WallTimeout"), Outcome::Regression);
    assert_eq!(classify(&floor, "error:parse"), Outcome::Regression);
    assert_eq!(classify(&gap, "unsat"), Outcome::NowDecided);
    assert_eq!(classify(&gap, "sat"), Outcome::Disagreement);
    assert_eq!(classify(&gap, "unknown:ResourceLimit"), Outcome::OpenGap);
    assert_eq!(classify(&stale_gap, "unknown:Other"), Outcome::OpenGap);
    assert_eq!(classify(&stale_gap, "unsat"), Outcome::NowDecided);
}

fn verdict_of(result: &CheckResult) -> String {
    match result {
        CheckResult::Sat(_) => "sat".to_string(),
        CheckResult::Unsat => "unsat".to_string(),
        CheckResult::Unknown(reason) => format!("unknown:{:?}", reason.kind),
    }
}

#[test]
fn pinned_axeyum_decides_every_shadow_split_verdict_like_z3() {
    let root = corpus_root();
    let rows = read_verdicts(&root.join("verdicts.tsv"));
    assert!(
        !rows.is_empty(),
        "{VERDICTS} lists no scripts; the test would check nothing"
    );

    let on_disk = scripts_on_disk(&root);
    let listed: Vec<(String, String)> = rows.keys().cloned().collect();
    assert_eq!(
        on_disk, listed,
        "scripts on disk and rows in {VERDICTS} differ; rerun tools/axeyum/split_verdicts.py"
    );

    let floor = rows.values().filter(|pinned| pinned.in_floor()).count();
    assert!(
        floor > 0,
        "{VERDICTS} pins no decided Axeyum verdict; the regression floor would be empty"
    );

    let config = SolverConfig::new().with_timeout(PER_SCRIPT_TIMEOUT);
    let mut report = String::new();
    let mut failures = Vec::new();
    let mut open_gaps = Vec::new();
    let mut now_decided = Vec::new();
    let mut max_millis = 0u128;
    let mut millis = Vec::with_capacity(rows.len());
    for ((capture, hash), pinned) in &rows {
        let path = root.join(capture).join(format!("{hash}.smt2"));
        let script = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let started = Instant::now();
        let verdict = match solve_smtlib(&script, &config) {
            Ok(outcome) => verdict_of(&outcome.result),
            Err(error) => format!("error:{error}"),
        };
        let elapsed = started.elapsed().as_millis();
        max_millis = max_millis.max(elapsed);
        millis.push(elapsed);
        writeln!(report, "{capture}\t{hash}\t{verdict}\t{elapsed}").unwrap();
        let z3 = &pinned.z3;
        match classify(pinned, &verdict) {
            Outcome::Agrees => {}
            // Both decided, differently: a soundness finding whichever side
            // is wrong. Always a failure, floor or not.
            Outcome::Disagreement => failures.push(format!(
                "{capture}/{hash}: DISAGREEMENT z3 {z3}, axeyum {verdict} ({elapsed} ms)"
            )),
            Outcome::Regression => failures.push(format!(
                "{capture}/{hash}: REGRESSION pinned axeyum {} (z3 {z3}), now {verdict} ({elapsed} ms)",
                pinned.axeyum
            )),
            Outcome::NowDecided => now_decided.push(format!(
                "{capture}/{hash}: pinned axeyum {}, now {verdict} like z3 ({elapsed} ms)",
                pinned.axeyum
            )),
            Outcome::OpenGap => open_gaps.push(format!(
                "{capture}/{hash}: z3 {z3}, axeyum {verdict} ({elapsed} ms)"
            )),
        }
    }
    if let Ok(out) = std::env::var("GLAURUNG_SHADOW_SPLIT_AXEYUM_OUT") {
        std::fs::write(&out, &report).unwrap_or_else(|error| panic!("cannot write {out}: {error}"));
    }
    millis.sort_unstable();
    let median = millis[millis.len() / 2];
    println!(
        "shadow-split replay: {} scripts ({floor} in the floor), {} failures, {} open capability gaps, {} newly decided, median {median} ms, max {max_millis} ms",
        rows.len(),
        failures.len(),
        open_gaps.len(),
        now_decided.len()
    );
    for line in &open_gaps {
        println!("open gap: {line}");
    }
    for line in &now_decided {
        println!("now decided (promote with split_verdicts.py --axeyum-results): {line}");
    }
    assert!(
        failures.is_empty(),
        "{} of {} scripts regressed or disagreed:\n{}",
        failures.len(),
        rows.len(),
        failures.join("\n")
    );
}
