//! F-10 (parity variant): the chain partition Joern's `to_supergraph` produces.
//!
//! Owned by stage S3. [`parity_chains`] is the chain slice [`super::flags`]
//! takes --- `derive_flags`, `singleton_funcend` and `parity_blocks` all accept
//! `&[Vec<NodeId>]` rather than a [`crate::syntax::cfg::ChainPartition`]
//! precisely so this one can be substituted for it.
//!
//! # Why a second partition exists at all
//!
//! [`crate::syntax::cfg::Cfg::chain_partition`] contracts an edge when
//! `outdeg(src) == 1`, `indeg(dst) == 1`, `src != dst` **and neither end is an
//! anchor** ([`crate::syntax::cfg::NodeKind::is_anchor`], i.e. `Entry` or
//! `Exit`). That last conjunct is deliberate and belongs where it is: the
//! anchors are what `REQ-GEN-1`'s first two invariants are stated in terms of,
//! and its own doc comment says that "deciding whether the function-end node
//! survives is precisely the parity layer's business, not this one's". This
//! file is that business.
//!
//! Joern has no anchor concept. `to_supergraph` merges `METHOD` and
//! `METHOD_RETURN` into their neighbours like any other node, and the published
//! corpus shows it directly. All three of these are in
//! `~/.cache/glaurung/decbench-full/tree/O0`:
//!
//! * `base-passwd/source_cfgs/update-passwd.json` `xasprintf` --- one `return`,
//!   so `METHOD_RETURN` has in-degree 1 and merges: published block 0 is
//!   `"return result;\nFUNCTION_END"`, and the function is published `exit [0]`.
//!   Its block 2 likewise opens `"FUNCTION_START"` and then runs on through the
//!   whole prologue to `ret < 0`, so `METHOD` merged forward too.
//! * the same file's `xstrdup` --- two `return`s, so `METHOD_RETURN` has
//!   in-degree 2, stays a singleton, is deleted by F-12, and the function is
//!   published `exit []` with both `return` blocks at out-degree 0.
//! * `zlib/source_cfgs/example.json` `adler32` --- one node, no edges,
//!   `entry [0]`, `exit [0]`: `METHOD`, the body and `METHOD_RETURN` are one
//!   chain.
//!
//! The corpus rule those three pin is **a funcend block survives iff it
//! coalesced with something**, and under the anchor exclusion it never can. So
//! with `chain_partition` feeding [`super::flags::parity_blocks`], F-12's guard
//! fires on every function without exception: measured over the 18,033 scored
//! functions of the first 16 stored decompiled `.c` files of the `O0` tree,
//! `exit` came back empty 18,033 / 18,033 times (100%) where Joern publishes
//! empty for 44,832 of 91,548 (49.0%). Every one of the other 51% was a lost
//! exit flag and a `return` block reported at the wrong out-degree, on both of
//! which `cfgutils.similarity.vj_ged` scores.
//!
//! # What this does *not* change
//!
//! Only the anchor conjunct. The predicate, the single `O(V + E)` sweep from
//! chain heads, and the deterministic cycle break at the lowest id are the same
//! as [`crate::syntax::cfg::coalesce`]'s, because every argument that module
//! makes for them --- the contractible edges form a functional graph, so the
//! chains can be read off in one pass instead of contracting to an `O(V * E)`
//! fixpoint --- turns on the degree conditions alone and is untouched by
//! dropping a per-node filter. Anchors are ordinary nodes here; nothing else
//! moved.

use crate::syntax::cfg::Cfg;
use crate::syntax::ids::NodeId;

/// Partition `cfg`'s nodes into maximal contractible chains, Joern's way.
///
/// A chain is a run of nodes joined by edges the rule contracts:
/// `outdeg(src) == 1`, `indeg(dst) == 1` and `src != dst`. Unlike
/// [`crate::syntax::cfg::Cfg::chain_partition`] the function entry and the
/// function end are eligible on both sides of that test, which is what lets a
/// funcend block coalesce and so survive F-12 --- see the module docs for the
/// three published functions that fix the behaviour.
///
/// Chain `i` is block `i` for [`super::flags`], and each chain is in the order
/// control passes through it. Every node of `cfg` appears in exactly one chain,
/// so the result is a partition and not a selection; an empty graph gives an
/// empty `Vec` rather than a panic (`REQ-SYN-2`).
///
/// `O(V + E)`, one sweep. The partition depends only on the per-edge predicate,
/// so it is independent of the order the graph was assembled in; only the
/// rotation of a pure contractible cycle depends on ids, and that is broken at
/// the cycle's lowest id so two runs agree byte for byte (`REQ-OUT-3`). No hash
/// container is involved at any point.
pub fn parity_chains(cfg: &Cfg) -> Vec<Vec<NodeId>> {
    let count = cfg.node_count();
    // `next[i]` is the one node `i` can be contracted into, if any. At most one
    // exists: `outdeg == 1` gives each node a single candidate edge out and
    // `indeg == 1` a single one in, so these edges form a functional graph ---
    // disjoint simple paths and disjoint cycles, nothing else.
    let mut next: Vec<Option<NodeId>> = vec![None; count];
    let mut has_predecessor_in_chain = vec![false; count];
    for index in 0..count {
        let id = NodeId::new(index as u32);
        let out = cfg.successor_edges(id);
        if out.len() != 1 {
            continue;
        }
        let dst = out[0].dst;
        // A self-edge would make the "chain" a one-node cycle and, contracted,
        // would lose the loop that `vj_ged` reads as an out-edge; 3,914
        // published functions have one.
        if dst == id || cfg.in_degree(dst) != 1 {
            continue;
        }
        // Where `Cfg::chain_partition` also rejects `src_kind.is_anchor() ||
        // dst_kind.is_anchor()`. That is the whole difference.
        next[index] = Some(dst);
        has_predecessor_in_chain[dst.index()] = true;
    }

    let mut of_node = vec![u32::MAX; count];
    let mut chains: Vec<Vec<NodeId>> = Vec::new();
    for index in 0..count {
        if !has_predecessor_in_chain[index] && of_node[index] == u32::MAX {
            walk_chain(index, &next, &mut of_node, &mut chains);
        }
    }
    // Anything still unassigned is a pure contractible cycle --- unreachable
    // from the entry by construction, since every node in it already has its
    // one predecessor inside the cycle, so it is dead code such as
    // `a: goto b; b: goto a;`. Break it at its lowest id, which is what keeps
    // the result independent of anything but the graph.
    for index in 0..count {
        if of_node[index] == u32::MAX {
            walk_chain(index, &next, &mut of_node, &mut chains);
        }
    }
    chains
}

/// Walk one chain from `start`, appending it to `chains` and recording every
/// member in `of_node`.
///
/// Iterative, not recursive (`REQ-SYN-3`): a chain is as long as the function
/// is, and this runs over decompiler output. Stops at the first node already
/// assigned, which is what turns a contractible cycle into a single chain
/// rather than an endless walk.
fn walk_chain(
    start: usize,
    next: &[Option<NodeId>],
    of_node: &mut [u32],
    chains: &mut Vec<Vec<NodeId>>,
) {
    let chain_index = chains.len() as u32;
    let mut members = Vec::new();
    let mut cursor = Some(NodeId::new(start as u32));
    while let Some(node) = cursor {
        match of_node.get(node.index()) {
            Some(&assigned) if assigned == u32::MAX => {}
            _ => break,
        }
        of_node[node.index()] = chain_index;
        members.push(node);
        cursor = next.get(node.index()).copied().flatten();
    }
    chains.push(members);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csource::joern::flags::parity_blocks;
    use crate::syntax::cfg::{CfgEdge, CfgNode, EdgeKind, NodeKind};
    use crate::syntax::ids::Span;

    /// The S2 graph of one function of `text`.
    fn s2(text: &str, name: &str) -> Cfg {
        let tree = crate::csource::parse::parse(text);
        let functions = crate::csource::cfg::function_cfgs(tree.value(), text);
        functions
            .value()
            .iter()
            .find(|function| function.name == name)
            .map(|function| function.cfg.clone())
            .unwrap_or_else(|| panic!("{name} is recovered from the fixture"))
    }

    /// The block a chain slice puts `kind` in, if exactly one block holds it.
    fn block_holding(cfg: &Cfg, chains: &[Vec<NodeId>], kind: NodeKind) -> Option<u32> {
        let mut found = None;
        for (block, chain) in chains.iter().enumerate() {
            if chain
                .iter()
                .any(|id| cfg.node(*id).map(|n| n.kind()) == Some(kind))
            {
                if found.is_some() {
                    return None;
                }
                found = Some(block as u32);
            }
        }
        found
    }

    /// How many nodes a chain slice covers, counted with multiplicity.
    fn covered(chains: &[Vec<NodeId>]) -> usize {
        chains.iter().map(Vec::len).sum()
    }

    #[test]
    fn every_node_lands_in_exactly_one_chain() {
        // A partition, not a selection: `flags::BlockView` indexes blocks by
        // position in this slice and reads every source node's block out of it,
        // so a dropped node silently loses its edges.
        for text in [
            "int f(void){ return 1; }",
            "int g(int a){ if (a) { return 1; } return 0; }",
            "int h(int a){ while (a) { a = a - 1; } return a; }",
            "void e(void){ }",
            "int s(int a){ switch (a) { case 1: return 1; default: return 0; } }",
            "int j(int a){ start: if (a) { goto start; } return a; }",
        ] {
            let tree = crate::csource::parse::parse(text);
            let functions = crate::csource::cfg::function_cfgs(tree.value(), text);
            assert!(!functions.value().is_empty(), "{text} yields a function");
            for function in functions.value() {
                let chains = parity_chains(&function.cfg);
                let mut seen = vec![false; function.cfg.node_count()];
                for chain in &chains {
                    for id in chain {
                        assert!(!seen[id.index()], "{text}: node {id:?} is in two chains");
                        seen[id.index()] = true;
                    }
                }
                assert!(seen.iter().all(|hit| *hit), "{text}: a node has no chain");
                assert_eq!(covered(&chains), function.cfg.node_count());
            }
        }
    }

    #[test]
    fn xasprintf_the_funcend_merges_into_its_one_return_and_survives_flagged() {
        // O0/base-passwd/source_cfgs/update-passwd.json `xasprintf`: one
        // `return`, so METHOD_RETURN has in-degree 1 and merges. Published
        // block 0 is `return result; FUNCTION_END`, published `exit [0]`.
        let cfg = s2(
            "char *xasprintf(char *fmt){ char *result; int ret; ret = vasprintf(&result, fmt); \
             if (ret < 0) { exit(1); } return result; }",
            "xasprintf",
        );
        let chains = parity_chains(&cfg);
        let blocks = parity_blocks(&cfg, &chains);

        let exit_block =
            block_holding(&cfg, &chains, NodeKind::Exit).expect("one block holds the funcend");
        assert!(
            chains[exit_block as usize].len() > 1,
            "the funcend coalesced with the return that precedes it"
        );
        assert_eq!(
            blocks.removed_funcend, None,
            "a merged funcend is not a singleton, so F-12 does not fire"
        );
        assert_eq!(
            blocks.exit,
            vec![exit_block],
            "and the block keeps its exit flag, as published `exit [0]`"
        );

        // The regression this file exists for: the general partition refuses to
        // absorb the anchor, so the same function loses its exit flag.
        let general = parity_blocks(&cfg, cfg.chain_partition().chains());
        assert!(
            general.removed_funcend.is_some() && general.exit.is_empty(),
            "the anchor exclusion is what deletes the funcend here"
        );
    }

    #[test]
    fn xstrdup_two_returns_keep_the_funcend_a_singleton_so_f12_deletes_it() {
        // Same published file, `xstrdup`: two `return`s, so METHOD_RETURN keeps
        // in-degree 2, cannot coalesce, and is deleted --- published `exit []`,
        // with both `return` blocks at out-degree 0. Dropping the anchor rule
        // must not turn this regime into the other one.
        let cfg = s2(
            "char *xstrdup(char *string){ if (!string) { return 0; } \
             return strcpy(xmalloc(strlen(string) + 1), string); }",
            "xstrdup",
        );
        let chains = parity_chains(&cfg);
        let exit_block =
            block_holding(&cfg, &chains, NodeKind::Exit).expect("one block holds the funcend");
        assert_eq!(
            chains[exit_block as usize].len(),
            1,
            "two returns leave the funcend a singleton"
        );

        let blocks = parity_blocks(&cfg, &chains);
        assert_eq!(blocks.removed_funcend, Some(exit_block));
        assert!(blocks.exit.is_empty(), "published `exit []`");
        assert!(
            blocks.edges.iter().all(|(_, dst)| *dst != exit_block),
            "its in-edges went with it"
        );
        let returns: Vec<u32> = chains
            .iter()
            .enumerate()
            .filter(|(_, chain)| {
                chain
                    .iter()
                    .any(|id| cfg.node(*id).map(|n| n.kind()) == Some(NodeKind::Return))
            })
            .map(|(block, _)| block as u32)
            .collect();
        assert_eq!(returns.len(), 2, "the fixture has two return blocks");
        for block in returns {
            assert!(
                blocks.edges.iter().all(|(src, _)| *src != block),
                "return block {block} is a sink once the funcend is gone"
            );
        }
    }

    #[test]
    fn adler32_a_straight_line_function_is_one_block_that_is_both_entry_and_exit() {
        // O0/zlib/source_cfgs/example.json `adler32`: 1 node, 0 edges,
        // `entry [0]`, `exit [0]`, not degenerate. METHOD, the body and
        // METHOD_RETURN are one chain --- which needs *both* anchors absorbed,
        // so it is the strongest single check that the exclusion is gone.
        let cfg = s2(
            "unsigned adler32(unsigned adler, char *buf, unsigned len){ \
             unsigned s1; s1 = adler & 0xffff; return s1; }",
            "adler32",
        );
        let chains = parity_chains(&cfg);
        assert_eq!(chains.len(), 1, "the whole function is one chain");

        let blocks = parity_blocks(&cfg, &chains);
        assert_eq!(blocks.kept, vec![0]);
        assert!(blocks.edges.is_empty(), "every edge was contracted away");
        assert_eq!(blocks.entry, vec![0]);
        assert_eq!(blocks.exit, vec![0]);
        assert_eq!(blocks.removed_funcend, None);

        // Under the general partition the same function is three blocks with
        // the anchors stranded at each end.
        assert_eq!(cfg.chain_partition().chains().len(), 3);
    }

    #[test]
    fn the_entry_is_absorbed_forward_exactly_when_its_successor_has_one_predecessor() {
        // `xasprintf`'s published block 2 opens `FUNCTION_START` and runs on
        // through the prologue, so the entry merges forward; a loop header the
        // back edge also targets has in-degree 2 and stops it. Both halves of
        // the degree test have to still apply to an anchor.
        let merged = s2("int f(int a){ a = a + 1; return a; }", "f");
        let chains = parity_chains(&merged);
        let entry_block = block_holding(&merged, &chains, NodeKind::Entry).expect("one entry");
        assert!(
            chains[entry_block as usize].len() > 1,
            "the entry absorbed the statement after it"
        );

        let stopped = s2("int g(int a){ while (a) { a = a - 1; } return a; }", "g");
        let chains = parity_chains(&stopped);
        let entry_block = block_holding(&stopped, &chains, NodeKind::Entry).expect("one entry");
        assert_eq!(
            chains[entry_block as usize].len(),
            1,
            "the loop header has two predecessors, so the entry stays alone"
        );
    }

    /// A hand-built graph, for shapes the C front end cannot be made to emit.
    fn graph(kinds: &[NodeKind], edges: &[(u32, u32)]) -> Cfg {
        let nodes = kinds
            .iter()
            .enumerate()
            .map(|(index, kind)| CfgNode::single(*kind, Span::new(index as u32, index as u32 + 1)))
            .collect();
        let edges = edges
            .iter()
            .map(|(src, dst)| CfgEdge::new(NodeId::new(*src), NodeId::new(*dst), EdgeKind::Fall))
            .collect();
        Cfg::from_parts(nodes, edges, NodeId::new(0), NodeId::new(0))
    }

    /// The chains as node indices, for comparing partitions.
    fn shape(chains: &[Vec<NodeId>]) -> Vec<Vec<u32>> {
        chains
            .iter()
            .map(|chain| chain.iter().map(|id| id.index() as u32).collect())
            .collect()
    }

    #[test]
    fn a_self_edge_is_never_contracted() {
        // 3,914 published functions have a self-loop; contracting one would
        // erase an out-edge `vj_ged` reads. `Cfg::chain_partition` guards this
        // with `src != dst` and so must this.
        let cfg = graph(
            &[NodeKind::Entry, NodeKind::LoopHeader, NodeKind::Exit],
            &[(0, 1), (1, 1), (1, 2)],
        );
        let chains = parity_chains(&cfg);
        assert_eq!(
            shape(&chains),
            vec![vec![0], vec![1], vec![2]],
            "node 1 has out-degree 2, and its self-edge is not a chain link"
        );
        let blocks = parity_blocks(&cfg, &chains);
        assert!(
            blocks.edges.contains(&(1, 1)),
            "the self-loop survives into the block graph"
        );
    }

    #[test]
    fn an_unreachable_self_loop_keeps_its_place_in_the_chain_numbering() {
        // The `src != dst` guard's *only* observable effect, and it is not the
        // one the test above covers. A node whose sole successor is itself and
        // whose sole predecessor is itself --- dead code, `L: goto L;` --- comes
        // out as the chain `[0]` either way. What changes is when: without the
        // guard it is not a chain head, so the cycle sweep claims it and it is
        // numbered *after* every reachable chain. Block numbers are output ---
        // `flags::parity_blocks` indexes by position and `ParityCfg` serializes
        // the ids --- so that reordering is a different published CFG.
        let cfg = graph(
            &[NodeKind::Goto, NodeKind::Entry, NodeKind::Exit],
            &[(0, 0), (1, 2)],
        );
        let chains = parity_chains(&cfg);
        assert_eq!(
            shape(&chains),
            vec![vec![0], vec![1, 2]],
            "the self-loop is a chain head in index order, not a leftover cycle"
        );
        let blocks = parity_blocks(&cfg, &chains);
        assert!(
            blocks.edges.contains(&(0, 0)),
            "and the loop it carries is still an out-edge"
        );
        assert_eq!(blocks.entry, vec![1]);
    }

    #[test]
    fn a_pure_contractible_cycle_becomes_one_chain_broken_at_its_lowest_id() {
        // Dead code only --- `a: goto b; b: goto a;` unreachable from the
        // entry, since every node in such a cycle already has its one
        // predecessor inside it. The second sweep is what claims it; without a
        // deterministic break the rotation would depend on iteration order.
        let cfg = graph(
            &[
                NodeKind::Entry,
                NodeKind::Exit,
                NodeKind::Goto,
                NodeKind::Goto,
            ],
            &[(0, 1), (2, 3), (3, 2)],
        );
        let chains = parity_chains(&cfg);
        assert_eq!(
            shape(&chains),
            vec![vec![0, 1], vec![2, 3]],
            "the anchors merge, and the dead cycle is one chain starting at 2"
        );
        assert_eq!(covered(&chains), cfg.node_count(), "no node is stranded");
    }

    #[test]
    fn the_partition_is_independent_of_the_order_the_graph_was_assembled_in() {
        // The same abstract diamond under three node numberings and two edge
        // orders. `Cfg::chain_partition` makes this promise and the parity
        // variant inherits it: the predicate reads degrees and node identity,
        // never position in a container.
        let shape = [(0usize, 1usize), (1, 2), (2, 3), (3, 4), (2, 5), (5, 4)];
        let partitions: Vec<Vec<Vec<u32>>> = [
            (vec![0usize, 1, 2, 3, 4, 5], false),
            (vec![5usize, 4, 3, 2, 1, 0], true),
            (vec![3usize, 0, 5, 2, 4, 1], false),
        ]
        .iter()
        .map(|(permutation, reverse_edges)| {
            // `slot[i]` is the node id the abstract node `i` is stored at.
            let mut slot = vec![0usize; 6];
            for (position, &abstract_node) in permutation.iter().enumerate() {
                slot[abstract_node] = position;
            }
            let nodes: Vec<CfgNode> = permutation
                .iter()
                .map(|&abstract_node| {
                    let kind = match abstract_node {
                        0 => NodeKind::Entry,
                        4 => NodeKind::Exit,
                        _ => NodeKind::Stmt,
                    };
                    // The span identifies the abstract node across numberings.
                    CfgNode::single(kind, Span::new(100 + abstract_node as u32, 200))
                })
                .collect();
            let mut edges: Vec<CfgEdge> = shape
                .iter()
                .map(|&(from, to)| {
                    CfgEdge::new(
                        NodeId::new(slot[from] as u32),
                        NodeId::new(slot[to] as u32),
                        EdgeKind::Fall,
                    )
                })
                .collect();
            if *reverse_edges {
                edges.reverse();
            }
            let cfg = Cfg::from_parts(
                nodes,
                edges,
                NodeId::new(slot[0] as u32),
                NodeId::new(slot[4] as u32),
            );
            let mut groups: Vec<Vec<u32>> = parity_chains(&cfg)
                .iter()
                .map(|chain| {
                    let mut lows: Vec<u32> = chain
                        .iter()
                        .filter_map(|id| cfg.node(*id).map(|node| node.span().lo))
                        .collect();
                    lows.sort_unstable();
                    lows
                })
                .collect();
            groups.sort();
            groups
        })
        .collect();
        assert_eq!(partitions[0], partitions[1]);
        assert_eq!(partitions[1], partitions[2]);
        // 0 -> 1 -> 2 branches to 3 and 5, both of which reach 4. The general
        // partition answers `[[100], [101, 102], [103], [104], [105]]`; here
        // the entry 0 joins 1 and 2 because it is no longer excluded, while the
        // exit 4 still has two predecessors and stays alone.
        assert_eq!(
            partitions[0],
            vec![vec![100, 101, 102], vec![103], vec![104], vec![105]]
        );
    }

    #[test]
    fn an_empty_graph_partitions_into_nothing_rather_than_panicking() {
        let empty = Cfg::from_parts(Vec::new(), Vec::new(), NodeId::new(0), NodeId::new(0));
        assert!(parity_chains(&empty).is_empty());
        assert_eq!(
            parity_blocks(&empty, &parity_chains(&empty)),
            parity_blocks(&empty, &[])
        );
    }

    #[test]
    fn the_partition_and_the_blocks_it_feeds_are_deterministic() {
        let text = "int f(int a){ while (a) { if (a > 2) { break; } a = a - 1; } return a; }";
        let cfg = s2(text, "f");
        assert_eq!(parity_chains(&cfg), parity_chains(&cfg));
        assert_eq!(
            parity_blocks(&cfg, &parity_chains(&cfg)),
            parity_blocks(&cfg, &parity_chains(&cfg))
        );
    }

    #[test]
    fn our_own_s2_graphs_still_satisfy_the_two_corpus_invariants() {
        // 0 of 91,548 published functions have no entry flag and 0 have more
        // than one exit flag. Merging anchors into chains must not break
        // either: a partition that lost the entry node would silently drop the
        // entry flag with it.
        for text in [
            "int f(void){ return 1; }",
            "int g(int a){ if (a) { return 1; } return 0; }",
            "int h(int a){ while (a) { a = a - 1; } return a; }",
            "void e(void){ }",
            "int s(int a){ switch (a) { case 1: return 1; default: return 0; } }",
        ] {
            let tree = crate::csource::parse::parse(text);
            let functions = crate::csource::cfg::function_cfgs(tree.value(), text);
            for function in functions.value() {
                let blocks = parity_blocks(&function.cfg, &parity_chains(&function.cfg));
                assert!(
                    !blocks.entry.is_empty(),
                    "{text}: every function has an entry flag"
                );
                assert!(
                    blocks.exit.len() <= 1,
                    "{text}: no function has two exit flags"
                );
            }
        }
    }
}
