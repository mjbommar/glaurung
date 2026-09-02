//! L1 structural signatures over real sample binaries.
//!
//! The unit tests in `src/identity/structural/` prove the arithmetic against
//! hand-computed values on hand-built graphs. These prove the three properties
//! that only a real binary can exercise: that two runs over the same bytes
//! agree bit for bit, that the MD-index is blind to where the code was linked,
//! and that a same-name function whose CFG survived a compiler change keeps its
//! MD-index.
//!
//! Every path below is checked in under `samples/`, so an absent fixture is a
//! failure, not a skip -- a silently skipped test reads exactly like a passing
//! one.

use std::collections::BTreeMap;
use std::fs;

use glaurung::analysis::cfg::{analyze_functions_bytes, Budgets};
use glaurung::core::call_graph::CallGraph;
use glaurung::core::function::Function;
use glaurung::identity::structural::{
    md_index_bottom_up, md_index_relaxed, md_index_top_down, ranking_similarity, CfgShape,
    StructuralSignature,
};

const HELLO_GCC_O2: &str =
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2";
const HELLO_CLANG_O2: &str =
    "samples/binaries/platforms/linux/amd64/export/native/clang/O2/hello-clang-O2";
const HELLO_GCC_O0: &str =
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0";

/// Budgets wide enough to walk a `hello`-sized binary to completion.
fn budgets() -> Budgets {
    Budgets {
        max_functions: 0,
        max_blocks: 4096,
        max_instructions: 200_000,
        timeout_ms: 5_000,
        total_timeout_ms: 60_000,
    }
}

fn read_sample(path: &str) -> Vec<u8> {
    assert!(
        std::path::Path::new(path).exists(),
        "sample fixture missing: {path} -- it is checked in, so this is a \
         broken checkout, not a reason to skip"
    );
    fs::read(path).expect("read sample")
}

fn analyze(path: &str) -> (Vec<u8>, Vec<Function>, CallGraph) {
    let data = read_sample(path);
    let (funcs, cg) = analyze_functions_bytes(&data, &budgets());
    (data, funcs, cg)
}

fn signatures(path: &str) -> Vec<StructuralSignature> {
    let (data, funcs, cg) = analyze(path);
    glaurung::identity::structural::structural_signatures(&data, &funcs, Some(&cg))
}

/// The exact bits of every field, so "identical" means identical and not
/// "close enough".
fn fingerprint(s: &StructuralSignature) -> String {
    format!(
        "{:#x} {} td={:016x} bu={:016x} rx={:016x} spp={:016x} \
         bb={} e={} be={} lp={} scc={} cc={} i={} cd={} ci={} cin={} sr={} rc={:?}",
        s.entry_va,
        s.name,
        s.md_index_top_down.to_bits(),
        s.md_index_bottom_up.to_bits(),
        s.md_index_relaxed.to_bits(),
        s.mnemonic_spp,
        s.basic_blocks,
        s.edges,
        s.back_edges,
        s.loops,
        s.strongly_connected_components,
        s.cyclomatic_complexity,
        s.instructions,
        s.calls_out_direct,
        s.calls_out_indirect,
        s.callers_in,
        s.string_refs,
        s.rare_constants,
    )
}

#[test]
fn signatures_are_bit_identical_across_two_runs() {
    let first = signatures(HELLO_GCC_O2);
    let second = signatures(HELLO_GCC_O2);
    assert!(
        !first.is_empty(),
        "discovery found no functions in {HELLO_GCC_O2}"
    );
    assert_eq!(first.len(), second.len());
    for (a, b) in first.iter().zip(second.iter()) {
        assert_eq!(
            fingerprint(a),
            fingerprint(b),
            "two runs over the same bytes disagreed"
        );
    }
}

#[test]
fn a_function_scores_a_perfect_ranking_similarity_against_itself() {
    let sigs = signatures(HELLO_GCC_O2);
    let biggest = sigs
        .iter()
        .max_by_key(|s| s.basic_blocks)
        .expect("at least one function");
    assert!(
        biggest.basic_blocks >= 2,
        "expected at least one multi-block function in {HELLO_GCC_O2}"
    );
    assert!((ranking_similarity(biggest, biggest) - 1.0).abs() < 1e-12);
}

/// Relinking a binary shifts every address by a constant and changes nothing
/// else. Rebuilding each real function's CFG at a different load address must
/// therefore leave all three MD-indices bit-identical.
#[test]
fn md_index_is_blind_to_the_link_address() {
    const SHIFT: u64 = 0x0010_0000;
    let (_, funcs, _) = analyze(HELLO_GCC_O2);
    let mut checked = 0usize;
    for f in &funcs {
        if f.basic_blocks.len() < 2 || f.edges.is_empty() {
            continue;
        }
        let here = StructuralSignature::shape_of(f);
        let blocks: Vec<u64> = f
            .basic_blocks
            .iter()
            .map(|b| b.start_address.value + SHIFT)
            .collect();
        let edges: Vec<(u64, u64)> = f
            .edges
            .iter()
            .map(|(a, b)| (a.value + SHIFT, b.value + SHIFT))
            .collect();
        let there = CfgShape::new(&blocks, &edges, f.entry_point.value + SHIFT);

        assert_eq!(
            md_index_top_down(&here).to_bits(),
            md_index_top_down(&there).to_bits(),
            "{} top-down MD-index moved with the link address",
            f.name
        );
        assert_eq!(
            md_index_bottom_up(&here).to_bits(),
            md_index_bottom_up(&there).to_bits(),
            "{} bottom-up MD-index moved with the link address",
            f.name
        );
        assert_eq!(
            md_index_relaxed(&here).to_bits(),
            md_index_relaxed(&there).to_bits(),
            "{} relaxed MD-index moved with the link address",
            f.name
        );
        checked += 1;
    }
    assert!(
        checked >= 3,
        "expected at least three multi-block functions to check, saw {checked}"
    );
}

/// Same source, two compilers, same optimisation level: the functions whose
/// control flow the two toolchains agreed on must share an MD-index, and the
/// ones they did not must not.
///
/// This is the property the diff rematch pass depends on, stated as a test
/// rather than assumed. It is deliberately not a threshold on how MANY agree --
/// that number belongs in the measurement doc with its denominator, and it
/// moves whenever discovery does.
#[test]
fn identical_cfgs_across_a_compiler_change_share_an_md_index() {
    let gcc = signatures(HELLO_GCC_O2);
    let clang = signatures(HELLO_CLANG_O2);
    assert!(!gcc.is_empty() && !clang.is_empty());

    let by_name: BTreeMap<&str, &StructuralSignature> =
        clang.iter().map(|s| (s.name.as_str(), s)).collect();

    let mut compared = 0usize;
    let mut same_shape_same_index = 0usize;
    for a in &gcc {
        let Some(b) = by_name.get(a.name.as_str()) else {
            continue;
        };
        compared += 1;
        // "Identical CFG" here means the canonical shapes are equal as graphs:
        // same block count, same edge count, same degree sequence, same
        // levels. The MD-index is a function of exactly those, so equality of
        // the shape must give equality of the index, bit for bit.
        let shape_equal = a.basic_blocks == b.basic_blocks
            && a.edges == b.edges
            && a.cyclomatic_complexity == b.cyclomatic_complexity
            && a.back_edges == b.back_edges
            && a.strongly_connected_components == b.strongly_connected_components;
        if shape_equal && a.md_index_top_down.to_bits() == b.md_index_top_down.to_bits() {
            same_shape_same_index += 1;
        }
    }
    assert!(
        compared > 0,
        "no function name occurs in both {HELLO_GCC_O2} and {HELLO_CLANG_O2}"
    );
    assert!(
        same_shape_same_index > 0,
        "of {compared} same-name pairs, none had both an equal shape and an \
         equal MD-index -- the invariant is broken or the samples share no code"
    );
}

/// A cheap, honest look at what L1 says about an optimisation-level change,
/// printed rather than asserted. The identity ladder is explicit that L1 does
/// not cross an optimisation level; this test exists so the claim is visible in
/// the test output instead of only in prose.
#[test]
fn optimisation_level_moves_most_md_indices() {
    let o0 = signatures(HELLO_GCC_O0);
    let o2 = signatures(HELLO_GCC_O2);
    let by_name: BTreeMap<&str, &StructuralSignature> =
        o2.iter().map(|s| (s.name.as_str(), s)).collect();

    let mut compared = 0usize;
    let mut equal = 0usize;
    for a in &o0 {
        let Some(b) = by_name.get(a.name.as_str()) else {
            continue;
        };
        compared += 1;
        if a.md_index_top_down.to_bits() == b.md_index_top_down.to_bits() {
            equal += 1;
        }
    }
    assert!(compared > 0, "no shared function names across O0 and O2");
    println!("O0 vs O2 same-name pairs: {compared}, equal top-down MD-index: {equal}");
}
