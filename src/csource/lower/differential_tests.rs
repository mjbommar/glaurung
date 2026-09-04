//! The S4 gate, run over the fixture corpus.
//!
//! For every fixture function this lowering covers, and every built lane of
//! that fixture, lower the C and lift the binary and run both on the same
//! interpreter from the same inputs. The gate is that they agree.
//!
//! `tests/decompiler_fixtures/build/` is gitignored --- the harness builds it,
//! and a fresh clone has only `canary/`. The test therefore reports a missing
//! corpus through [`crate::testing::missing_fixture`] rather than failing, the
//! same convention the benches and the DWARF tests use.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
use crate::core::binary::Arch;
use crate::csource::lower::differential::{compare, vectors, Verdict};
use crate::csource::lower::{lower_function, LoweredFunction};
use crate::csource::parse::parse;
use crate::ir::lift_function::lift_function_from_bytes;
use crate::ir::types::LlirFunction;

/// The compiler/optimization lanes the harness builds for every fixture.
const LANES: [&str; 4] = ["gcc-O0", "gcc-O2", "clang-O0", "clang-O2"];

/// Instruction budget per run. Generous enough for the loop fixtures at the
/// probe values, small enough that a runaway lowering stops rather than hangs.
const STEPS: u64 = 400_000;

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/decompiler_fixtures")
}

/// Every function of `data` that discovery found, by name.
fn lift_all(data: &[u8]) -> BTreeMap<String, LlirFunction> {
    let (funcs, _calls) = analyze_functions_bytes(
        data,
        &Budgets {
            max_functions: 512,
            max_blocks: 2048,
            max_instructions: 200_000,
            timeout_ms: 10_000,
            total_timeout_ms: 0,
        },
    );
    let mut out = BTreeMap::new();
    for func in &funcs {
        if func.name.is_empty() {
            continue;
        }
        if let Ok(lifted) = lift_function_from_bytes(data, func, Arch::X86_64) {
            out.insert(func.name.clone(), lifted);
        }
    }
    out
}

/// One cell of the sweep: a fixture, a lane, a function.
#[derive(Debug, Default, Clone)]
struct Tally {
    matched: usize,
    diverged: usize,
    inconclusive: usize,
    /// Distinct (fixture, lane, function) triples actually compared. A cell
    /// count alone cannot say whether the sweep is wide or just repetitive.
    functions: usize,
    /// Fixture functions that lowered but whose name discovery did not find in
    /// the built binary --- inlined away, or renamed.
    unmatched_symbols: usize,
}

/// Sweep the corpus, returning the per-cell verdicts and a running tally.
///
/// `lanes` and `only` narrow the sweep so an iteration loop does not pay for
/// the whole corpus; the gate below runs it wide.
fn sweep(lanes: &[&str], only: Option<&str>) -> Option<(Tally, Vec<String>, Vec<String>)> {
    let root = fixtures_root();
    let src = root.join("src");
    let build = root.join("build");
    if !src.is_dir() || !build.is_dir() {
        return None;
    }
    let mut sources: Vec<PathBuf> = std::fs::read_dir(&src)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "c"))
        .collect();
    sources.sort();

    let mut tally = Tally::default();
    let mut divergences = Vec::new();
    let mut inconclusive = Vec::new();

    for path in sources {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        if only.is_some_and(|want| want != stem) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let tree = parse(&text).into_parts().0;
        let lowered: Vec<LoweredFunction> = tree
            .functions(&text)
            .iter()
            .filter_map(|def| lower_function(&tree, &text, def).ok())
            .collect();
        if lowered.is_empty() {
            continue;
        }
        for lane in lanes {
            let so = build.join(format!("{stem}-{lane}.so"));
            let Ok(data) = std::fs::read(&so) else {
                continue;
            };
            let lifted = lift_all(&data);
            for function in &lowered {
                let Some(reference) = lifted.get(&function.name) else {
                    tally.unmatched_symbols += 1;
                    continue;
                };
                tally.functions += 1;
                for args in vectors(function.params.len()) {
                    match compare(function, reference, &data, &args, STEPS) {
                        Verdict::Match { .. } => tally.matched += 1,
                        Verdict::Diverged { lowered, lifted } => {
                            tally.diverged += 1;
                            divergences.push(format!(
                                "{stem}:{lane}:{} args={args:x?} lowered={lowered:#x} lifted={lifted:#x}",
                                function.name
                            ));
                        }
                        Verdict::Inconclusive {
                            lowered: a,
                            lifted: b,
                        } => {
                            tally.inconclusive += 1;
                            inconclusive.push(format!(
                                "{stem}:{lane}:{} lowered={a} lifted={b}",
                                function.name
                            ));
                        }
                    }
                }
            }
        }
    }
    Some((tally, divergences, inconclusive))
}

/// Fixture functions whose lowering and binary legitimately disagree, with the
/// reason.
///
/// One entry, and it is not a defect on either side. `rotate_right` is
/// `(value >> amount) | (value << (32u - amount))`; every probe with
/// `amount >= 32` shifts by at least the operand's width, which C17 6.5.7p3
/// leaves **undefined**. x86 `shl`/`shr` reduce the count modulo 32 and the
/// lowering computes at 64 bits and truncates, so the two pick different
/// answers to a question C does not answer. Making them agree would mean
/// writing x86's count masking into the C lowering --- committing the front end
/// to one target's undefined behaviour, which is worse than recording it here.
const KNOWN_UB_DIVERGENCES: &[(&str, &str)] = &[("54_sha256_block", "rotate_right")];

/// Whether a divergence line names a known undefined-behaviour case.
fn is_known_ub(line: &str) -> bool {
    KNOWN_UB_DIVERGENCES
        .iter()
        .any(|(fixture, function)| line.starts_with(fixture) && line.contains(function))
}

/// Reduce an inconclusive line to the class it belongs to, so the report says
/// *why* the sweep could not decide rather than listing three hundred cells.
fn inconclusive_class(line: &str) -> String {
    let lowered_halted = line.contains("lowered=halted")
        || line.contains("lowered=no block")
        || line.contains("lowered=called out");
    let prefix = if lowered_halted {
        "LOWERING did not run: "
    } else {
        ""
    };
    if let Some(at) = line.find("UnsupportedIntrinsic(") {
        let rest = &line[at + "UnsupportedIntrinsic(".len()..];
        let name = rest.split(')').next().unwrap_or(rest);
        return format!("{prefix}lifted side has no helper for intrinsic {name}");
    }
    if line.contains("budget exhausted") && line.contains("lifted=budget exhausted") {
        return format!("{prefix}both sides exhausted the instruction budget");
    }
    if let Some(at) = line.find("lifted=halted: ") {
        let rest = &line[at + "lifted=halted: ".len()..];
        let name = rest.split('(').next().unwrap_or(rest);
        return format!("{prefix}lifted side halted: {name}");
    }
    format!("{prefix}{}", line.split(" lowered=").nth(1).unwrap_or(line))
}

/// Print a sweep's result and return it.
fn report(label: &str, lanes: &[&str], only: Option<&str>) -> Option<(Tally, Vec<String>)> {
    let (tally, divergences, inconclusive) = sweep(lanes, only)?;
    let total = tally.matched + tally.diverged + tally.inconclusive;
    println!("--- S4 differential: {label} ---");
    println!(
        "functions x lanes compared: {}; symbols not found in the binary: {}",
        tally.functions, tally.unmatched_symbols
    );
    println!(
        "cells: {total}; match: {}; diverged: {}; inconclusive: {}",
        tally.matched, tally.diverged, tally.inconclusive
    );
    let mut heads: BTreeMap<String, usize> = BTreeMap::new();
    for line in &divergences {
        let key = line.split(" args=").next().unwrap_or(line).to_string();
        *heads.entry(key).or_default() += 1;
    }
    for (key, count) in &heads {
        let known = if is_known_ub(key) { " [known UB]" } else { "" };
        println!("  DIVERGED x{count}{known}  {key}");
    }
    let mut classes: BTreeMap<String, usize> = BTreeMap::new();
    for line in &inconclusive {
        *classes.entry(inconclusive_class(line)).or_default() += 1;
    }
    let mut ranked: Vec<(&String, &usize)> = classes.iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (class, count) in ranked {
        println!("  inconclusive x{count}  {class}");
    }
    Some((tally, divergences))
}

#[test]
#[ignore = "sweeps the whole built fixture corpus at four lanes; run explicitly"]
fn s4_differential_over_the_whole_corpus() {
    let Some((tally, divergences)) = report("all lanes", &LANES, None) else {
        crate::testing::missing_fixture("tests/decompiler_fixtures/build");
        return;
    };
    assert!(tally.matched > 0, "the sweep proved nothing");
    let unexplained: Vec<&String> = divergences.iter().filter(|d| !is_known_ub(d)).collect();
    assert!(
        unexplained.is_empty(),
        "unexplained divergences: {unexplained:#?}"
    );
}

#[test]
fn s4_differential_on_the_gcc_o0_lane() {
    let Some((tally, divergences)) = report("gcc-O0", &["gcc-O0"], None) else {
        crate::testing::missing_fixture("tests/decompiler_fixtures/build");
        return;
    };
    // The gate, and it is a real one: every cell the sweep can decide must
    // agree, except the recorded undefined-behaviour case. A new divergence is
    // a real disagreement between lowered C and the binary its own compiler
    // produced, and it is worth stopping for whichever of the two is wrong ---
    // the `_Bool` conversion rule was found exactly this way.
    let unexplained: Vec<&String> = divergences.iter().filter(|d| !is_known_ub(d)).collect();
    assert!(
        unexplained.is_empty(),
        "unexplained divergences: {unexplained:#?}"
    );
    // Measured at 2710 on 2026-09-04 (`cargo test --features python-ext --lib
    // -- csource::lower::differential_tests`). The floor is a coverage guard,
    // not a target: it fails when the sweep stops finding the corpus or the
    // lowering stops covering it, which is the failure mode a green
    // zero-divergence assertion cannot see.
    assert!(
        tally.matched > 2500,
        "only {} cells agreed; the sweep is not covering the corpus",
        tally.matched
    );
    // A stale allow-list is worse than none: if the undefined-behaviour case
    // stops diverging, the entry must be removed rather than left to excuse a
    // future defect.
    assert!(
        divergences.iter().any(|d| is_known_ub(d)),
        "KNOWN_UB_DIVERGENCES is stale: nothing diverged for it"
    );
}
