//! The GED distance, exercised against the real published source CFGs.
//!
//! `syntax::ged`'s unit tests check it against 124 vectors recorded from the
//! reference implementation and against exhaustive search on small matrices.
//! Those are exact but synthetic. This exercises the same code over the degree
//! sequences of every function in a materialized DecBench tree — 91,548 of them
//! in the full corpus — which is the population it will actually be asked
//! about, and which contains shapes no generator would think to produce.
//!
//! The corpus lives outside the repository, so these tests **skip** rather than
//! fail when it is absent. Point them at a tree with:
//!
//! ```text
//! GLAURUNG_DECBENCH_TREE=~/.cache/glaurung/decbench-full/tree \
//!   cargo test --features python-ext --test source_cfg_ged -- --nocapture
//! ```
//!
//! What is checked here is self-consistency, not parity: reproducing DecBench's
//! stored values needs a C front end and belongs to
//! `docs/design/static-c-analysis/parity-plan.md` level L3. What these catch is
//! a solver that is wrong in a way 124 vectors did not reach — a non-zero
//! self-distance, an asymmetry, or a panic on a real shape.

use std::collections::BTreeMap;
use std::path::PathBuf;

use glaurung::syntax::ged::{ged, GedGraph, GedNode};

/// The tree to read, or `None` when the corpus is not present on this machine.
///
/// Read from the environment rather than hard-coded because the corpus is a
/// ~1.1 GB download that lives outside the repository and is not required to
/// build or test Glaurung.
fn tree() -> Option<PathBuf> {
    let raw = std::env::var("GLAURUNG_DECBENCH_TREE").ok()?;
    let expanded = if let Some(rest) = raw.strip_prefix("~/") {
        PathBuf::from(std::env::var("HOME").ok()?).join(rest)
    } else {
        PathBuf::from(raw)
    };
    expanded.is_dir().then_some(expanded)
}

/// Every `source_cfgs/*.json` under the tree, capped so the test stays quick.
fn cfg_files(root: &std::path::Path, limit: usize) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    // Explicit stack rather than recursion: the substrate's own rule, and a
    // corpus is exactly the kind of input whose depth nobody has audited.
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut names: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        names.sort();
        for path in names {
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "json")
                && path.parent().is_some_and(|p| p.ends_with("source_cfgs"))
            {
                found.push(path);
                if found.len() >= limit {
                    return found;
                }
            }
        }
    }
    found
}

/// One published function CFG, reduced to what the distance actually reads.
///
/// The serialization carries nodes, edges, entry/exit id lists and a degeneracy
/// verdict; `vj_ged` reads only per-node in/out degree and the two flags, so
/// that is all this reconstructs.
fn to_graph(func: &serde_json::Value) -> Option<GedGraph> {
    let nodes = func.get("nodes")?.as_array()?;
    let edges = func.get("edges")?.as_array()?;
    let entry: Vec<u64> = func
        .get("entry")?
        .as_array()?
        .iter()
        .filter_map(|v| v.as_u64())
        .collect();
    let exit: Vec<u64> = func
        .get("exit")?
        .as_array()?
        .iter()
        .filter_map(|v| v.as_u64())
        .collect();

    let mut in_degree: BTreeMap<u64, u32> = BTreeMap::new();
    let mut out_degree: BTreeMap<u64, u32> = BTreeMap::new();
    let mut edge_count = 0u64;
    for edge in edges {
        let pair = edge.as_array()?;
        let (from, to) = (pair.first()?.as_u64()?, pair.get(1)?.as_u64()?);
        *out_degree.entry(from).or_default() += 1;
        *in_degree.entry(to).or_default() += 1;
        edge_count += 1;
    }

    let built = nodes
        .iter()
        .filter_map(|n| n.as_u64())
        .map(|id| {
            GedNode::new(
                in_degree.get(&id).copied().unwrap_or(0),
                out_degree.get(&id).copied().unwrap_or(0),
                entry.contains(&id),
                exit.contains(&id),
            )
        })
        .collect::<Vec<_>>();
    Some(GedGraph::new(built, edge_count))
}

/// Load `(binary, function, graph)` triples from up to `limit` CFG files.
fn corpus(limit: usize) -> Option<Vec<(String, String, GedGraph)>> {
    let root = tree()?;
    let mut out = Vec::new();
    for path in cfg_files(&root, limit) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let binary = json
            .get("binary")
            .and_then(|b| b.as_str())
            .unwrap_or("?")
            .to_string();
        let Some(functions) = json.get("functions").and_then(|f| f.as_object()) else {
            continue;
        };
        for (name, func) in functions {
            if let Some(graph) = to_graph(func) {
                out.push((binary.clone(), name.clone(), graph));
            }
        }
    }
    Some(out)
}

#[test]
fn every_published_cfg_scores_zero_against_itself() {
    let Some(graphs) = corpus(60) else {
        eprintln!("skipped: set GLAURUNG_DECBENCH_TREE to a materialized DecBench tree");
        return;
    };
    assert!(!graphs.is_empty(), "tree present but no source CFGs parsed");

    let mut exact = 0usize;
    for (binary, name, graph) in &graphs {
        let result = ged(graph, graph);
        if result.is_exact() {
            exact += 1;
            assert_eq!(
                result.value,
                0.0,
                "{binary}:{name} ({} nodes) scored {} against itself",
                graph.node_count(),
                result.value
            );
        } else {
            // Above the node cap the metric returns |dnodes| + |dedges|, which
            // is 0 for a graph against itself but is not an exact distance.
            assert_eq!(
                result.value, 0.0,
                "{binary}:{name} approximated self-distance"
            );
        }
    }
    eprintln!(
        "self-distance: {} functions, {exact} scored exactly, {} via the node-cap fallback",
        graphs.len(),
        graphs.len() - exact
    );
}

#[test]
fn the_distance_is_symmetric_over_real_pairs() {
    let Some(graphs) = corpus(40) else {
        eprintln!("skipped: set GLAURUNG_DECBENCH_TREE to a materialized DecBench tree");
        return;
    };
    // Adjacent pairs in corpus order: same binary, so the shapes are related
    // rather than arbitrary, which is the comparison the metric actually makes.
    let mut compared = 0usize;
    for window in graphs.chunks(2) {
        let [(_, a_name, a), (_, b_name, b)] = window else {
            continue;
        };
        let forward = ged(a, b);
        let backward = ged(b, a);
        assert_eq!(
            forward.value, backward.value,
            "asymmetric: {a_name} vs {b_name} gave {} one way and {} the other",
            forward.value, backward.value
        );
        assert_eq!(forward.approximated, backward.approximated);
        compared += 1;
    }
    eprintln!("symmetry: {compared} real pairs agreed in both directions");
}

#[test]
fn the_distance_is_deterministic_across_repeated_runs() {
    let Some(graphs) = corpus(20) else {
        eprintln!("skipped: set GLAURUNG_DECBENCH_TREE to a materialized DecBench tree");
        return;
    };
    for window in graphs.chunks(2) {
        let [(_, a_name, a), (_, _, b)] = window else {
            continue;
        };
        let first = ged(a, b);
        for _ in 0..3 {
            let again = ged(a, b);
            assert_eq!(first.value, again.value, "{a_name} varied between runs");
        }
    }
}

#[test]
fn no_real_cfg_shape_makes_the_distance_panic() {
    let Some(graphs) = corpus(60) else {
        eprintln!("skipped: set GLAURUNG_DECBENCH_TREE to a materialized DecBench tree");
        return;
    };
    // Pair every graph with the empty graph and with a single isolated node:
    // the two degenerate shapes the reference implementation itself cannot
    // express (its solver raises on a zero-by-zero matrix), and therefore the
    // two most likely to be untested anywhere else.
    let empty = GedGraph::empty();
    let singleton = GedGraph::from_nodes(vec![GedNode::plain(0, 0)]);
    let mut widest = 0usize;
    for (_, _, graph) in &graphs {
        widest = widest.max(graph.node_count());
        let _ = ged(graph, &empty);
        let _ = ged(&empty, graph);
        let _ = ged(graph, &singleton);
        let _ = ged(&singleton, graph);
    }
    eprintln!(
        "degenerate pairings: {} functions survived, widest {widest} nodes",
        graphs.len()
    );
}

/// Dump our distance for real published pairs, for the cross-implementation
/// differential in `tools/ged_cross_check.py`.
///
/// The unit tests check `syntax::ged` against 124 vectors recorded from the
/// reference and against exhaustive search; this exists so the same code can be
/// diffed against the *live* reference over thousands of real degree sequences,
/// which is a stronger claim than either. Writing a file rather than asserting
/// here keeps the Rust side free of any Python dependency.
///
/// Enabled only when `GLAURUNG_GED_DUMP` names an output path.
#[test]
fn dump_real_pair_distances_for_the_cross_check() {
    let Some(out) = std::env::var("GLAURUNG_GED_DUMP").ok() else {
        return;
    };
    let Some(graphs) = corpus(80) else {
        eprintln!("skipped: set GLAURUNG_DECBENCH_TREE too");
        return;
    };
    // Pair each graph with the next one. Adjacent entries share a binary, so
    // the shapes are related rather than arbitrary -- the comparison the metric
    // is actually asked to make.
    let mut rows = Vec::new();
    for pair in graphs.windows(2) {
        let [(bin_a, name_a, a), (bin_b, name_b, b)] = pair else {
            continue;
        };
        let result = ged(a, b);
        rows.push(format!(
            "{{\"a\":\"{bin_a}:{name_a}\",\"b\":\"{bin_b}:{name_b}\",\
\"value\":{},\"approximated\":{}}}",
            result.value, result.approximated
        ));
    }
    let body = format!("[{}]", rows.join(","));
    std::fs::write(&out, body).expect("dump path must be writable");
    eprintln!("wrote {} pair distances to {out}", rows.len());
}
