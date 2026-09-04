//! The Joern-parity layer --- stage S3 of
//! [`docs/design/static-c-analysis/roadmap.md`].
//!
//! # What this is for
//!
//! DecBench's `ged` column is `vj_ged(published source CFG, our CFG of the
//! stored decompiled C)`. Today the second argument is produced by Joern: one
//! JVM per file, no server mode, ~37 minutes for the 56-cell matrix gate. This
//! module is the replacement, and the only thing that has to be true for it to
//! work is *shape parity* --- `vj_ged` reads node in/out degrees and the
//! `is_entrypoint` / `is_exitpoint` flags, and nothing else. Statements, types
//! and operators never reach the distance.
//!
//! # What is NOT yet at parity
//!
//! This is the anchor, not the finished layer. It bridges S2's statement-
//! granular [`crate::csource::cfg`] output to the serialized shape DecBench
//! stores, so the end-to-end measurement can run and report a real number.
//! **It does not yet implement F-9**, Joern's expression-level node
//! granularity --- in particular that `&&`, `||` and `?:` materialize an
//! operator node of their own. Until that lands, every count here is a
//! *baseline to improve on*, not a parity claim. The inventory in
//! [`docs/design/static-c-analysis/implementation-inventory.md`] tracks the
//! rest (F-8..F-17); `tools/source_cfg_parity.py --provider glaurung` is the
//! number that says where we are.

pub mod chains;
pub mod flags;
pub mod nodes;
pub mod resolve;

use std::collections::BTreeMap;

use crate::syntax::cfg::{Cfg, NodeKind};

/// One function's CFG in the shape DecBench serializes and scores.
///
/// `REQ-OUT-1` / F-17. Node ids are dense and start at zero (F-14), so two runs
/// over the same text produce byte-identical output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParityCfg {
    /// Every node id, ascending.
    pub nodes: Vec<u32>,
    /// Directed edges as `(src, dst)`, deduplicated and sorted.
    pub edges: Vec<(u32, u32)>,
    /// Nodes carrying Joern's `is_entrypoint`.
    pub entry: Vec<u32>,
    /// Nodes carrying Joern's `is_exitpoint`.
    pub exit: Vec<u32>,
    /// A CFG with no real statement in it (F-13): scored, but not comparable
    /// the way a real graph is.
    pub degenerate: bool,
}

impl ParityCfg {
    /// Render as the JSON object DecBench's `--source-cfgs` flow accepts.
    ///
    /// Hand-written rather than derived: the field order is part of the
    /// contract a reviewer diffs against a stored file, and `serde` would order
    /// by declaration without saying so.
    pub fn to_json(&self) -> String {
        let list = |values: &[u32]| {
            values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        let edges = self
            .edges
            .iter()
            .map(|(src, dst)| format!("[{src},{dst}]"))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"nodes\":[{}],\"edges\":[{}],\"entry\":[{}],\"exit\":[{}],\"degenerate\":{}}}",
            list(&self.nodes),
            edges,
            list(&self.entry),
            list(&self.exit),
            self.degenerate
        )
    }
}

/// Names Joern never emits a scoreable CFG for (F-15).
///
/// A leading `<` is Joern's own synthetic (`<global>`, `<operator>...`); the
/// arithmetic and bracket prefixes are expression fragments that reached the
/// name slot; `JUMPOUT` and `__builtin_unreachable` are decompiler artifacts.
const NAME_BLACKLIST: [&str; 7] = ["<", "+", "*", "(", ">", "JUMPOUT", "__builtin_unreachable"];

/// Whether `name` is one DecBench scores at all.
pub fn is_scoreable_name(name: &str) -> bool {
    !name.is_empty() && !NAME_BLACKLIST.iter().any(|bad| name.starts_with(bad))
}

/// Every scoreable function CFG in one translation unit of C text.
///
/// Total on every input: a file the parser only partly recovered still yields
/// the functions it did recover, because a provider that returns nothing is
/// indistinguishable from a front end that lost every function --- the exact
/// ambiguity `tools/source_cfg_parity.py` exists to remove.
///
/// When a name appears more than once, the CFG with more nodes wins (F-15).
pub fn parity_cfgs(text: &str) -> BTreeMap<String, ParityCfg> {
    let tree = crate::csource::parse::parse(text);
    // `Coverage::Syntactic`, not the default: Joern's CFG construction is
    // syntax-directed and keeps statements control cannot reach, and 105 of the
    // 91,548 published source CFGs carry a component with no path from the
    // entry to prove it. S2 prunes them by design (`REQ-GEN-1`), so the parity
    // layer has to ask for the other graph rather than rebuild it.
    let functions = crate::csource::cfg::function_cfgs_with(
        tree.value(),
        text,
        crate::csource::cfg::Coverage::Syntactic,
    );
    // F-9 first: Joern's node granularity is a property of the graph the rest of
    // the layer then flags, coalesces and serializes, so applying it afterwards
    // would be measuring a different graph than the one scored.
    let granular = nodes::expression_granular_cfgs(tree.value(), text, functions.value());
    let mut out: BTreeMap<String, ParityCfg> = BTreeMap::new();
    for (index, function) in functions.value().iter().enumerate() {
        if !is_scoreable_name(&function.name) {
            continue;
        }
        let cfg = granular.get(index).unwrap_or(&function.cfg);
        let parity = parity_of(cfg);
        match out.get(&function.name) {
            Some(existing) if existing.nodes.len() >= parity.nodes.len() => {}
            _ => {
                out.insert(function.name.clone(), parity);
            }
        }
    }
    out
}

/// Project one S2 graph onto the basic-block view DecBench stores.
///
/// The chain contraction is F-10, reused from [`crate::syntax::cfg`] rather
/// than reimplemented --- that module was written with this caller in mind.
fn parity_of(cfg: &Cfg) -> ParityCfg {
    // The chain partition is the parity layer's own (`chains`), not
    // `Cfg::chain_partition`: the general one refuses to contract an anchor, so
    // the function-end node is always a singleton and F-12 deletes it every
    // time. Joern's `to_supergraph` has no anchor concept. Measured over the
    // 85,645 stored cells, using the general partition here scores 0.60% exact
    // against 72.44% with this one -- and 0.60% is *worse* than deriving the
    // flags inline, which is why the two must land together.
    let chains = chains::parity_chains(cfg);
    let blocks = flags::parity_blocks(cfg, &chains).renumbered();
    let nodes: Vec<u32> = (0..blocks.kept.len() as u32).collect();
    ParityCfg {
        nodes,
        edges: blocks.edges,
        entry: blocks.entry,
        exit: blocks.exit,
        degenerate: is_degenerate(cfg),
    }
}

/// F-13: no real statement anywhere in the graph.
///
/// `n == 0`, or `n == 1` whose only node is structural. A one-block function
/// with real statements is deliberately **not** degenerate.
fn is_degenerate(blocks: &Cfg) -> bool {
    match blocks.node_count() {
        0 => true,
        1 => matches!(blocks.nodes()[0].kind(), NodeKind::Entry | NodeKind::Exit),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both funcend regimes, end to end through the serialized shape.
    ///
    /// The corpus decides this, not intuition: a funcend block survives iff it
    /// coalesced with something. `base-passwd`'s `xasprintf` has one `return`,
    /// so FUNCTION_END has in-degree 1, merges, and stays exit-flagged
    /// (published `exit [0]`); `xstrdup` has two, so it keeps in-degree 2,
    /// remains a singleton, and F-12 deletes it (published `exit []`). An
    /// earlier version of this test asserted every returning function has an
    /// exit, which is the pre-F-12 assumption and is wrong for half the corpus.
    #[test]
    fn both_funcend_regimes_reach_the_serialized_shape() {
        let two_returns = parity_cfgs("int f(int a) { if (a) { return 1; } return 0; }");
        let f = two_returns.get("f").expect("f is recovered");
        assert!(!f.nodes.is_empty(), "a real function has nodes");
        assert_eq!(f.entry.len(), 1, "exactly one entry block");
        assert!(
            f.exit.is_empty(),
            "two returns keep FUNCTION_END at in-degree 2, so it stays a \
             singleton and F-12 deletes it -- the `xstrdup` regime: {f:?}"
        );
        assert!(
            !f.degenerate,
            "a function with statements is not degenerate"
        );

        let one_return = parity_cfgs("int g(int a) { int r = a + 1; return r; }");
        let g = one_return.get("g").expect("g is recovered");
        assert_eq!(
            g.exit.len(),
            1,
            "one return lets FUNCTION_END coalesce, so it survives flagged -- \
             the `xasprintf` regime: {g:?}"
        );
    }

    #[test]
    fn the_serialization_is_the_shape_decbench_stores() {
        let cfg = ParityCfg {
            nodes: vec![0, 1],
            edges: vec![(0, 1)],
            entry: vec![0],
            exit: vec![1],
            degenerate: false,
        };
        assert_eq!(
            cfg.to_json(),
            "{\"nodes\":[0,1],\"edges\":[[0,1]],\"entry\":[0],\"exit\":[1],\"degenerate\":false}"
        );
    }

    #[test]
    fn synthetic_and_fragment_names_are_not_scored() {
        for name in [
            "<global>",
            "+ 1",
            "*p",
            "(cast)",
            ">>",
            "JUMPOUT",
            "__builtin_unreachable",
        ] {
            assert!(!is_scoreable_name(name), "{name} must be filtered");
        }
        assert!(is_scoreable_name("main"));
        assert!(
            !is_scoreable_name(""),
            "an unnamed declarator is not a function"
        );
    }

    #[test]
    fn every_function_in_a_file_is_returned_not_just_the_first() {
        let cfgs =
            parity_cfgs("int a(void){return 1;} int b(void){return 2;} int c(void){return 3;}");
        assert_eq!(cfgs.keys().collect::<Vec<_>>(), vec!["a", "b", "c"]);
    }

    #[test]
    fn the_projection_is_deterministic() {
        let text = "int f(int a){ while (a) { a--; } return a; }";
        assert_eq!(parity_cfgs(text), parity_cfgs(text));
    }
}
