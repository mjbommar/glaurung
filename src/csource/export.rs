//! Turning a parsed C file into serializable graphs.
//!
//! The writers live in [`crate::syntax::graph_export`], which knows nothing
//! about C. This module is the other half: it reads a [`Tree`] and the
//! [`Cfg`]s built from it and produces the labelled views those writers take.
//!
//! # What this replaces
//!
//! `joern-export --repr {ast,cfg,cdg,ddg,pdg} --format {dot,graphml,...}` is
//! the shape a caller already knows, so [`Repr`] uses Joern's spelling and now
//! covers every representation it offers except `cpg14`, which is a code
//! property graph and is the one thing
//! `docs/design/static-c-analysis/requirements.md` section 8 declines.
//!
//! None of the three dependence graphs is a copy of Joern's.
//!
//! * [`Repr::Ddg`] labels every edge with the variable the dependence is
//!   about. `joern-export --repr ddg` does too, in its DOT; pyjoern's
//!   `Function.ddg` does not, so a Python caller of that API cannot tell which
//!   value an edge is for.
//! * [`Repr::Cdg`] labels every edge with the *arm* of the branch that decides
//!   it, so "runs when the guard holds" and "runs when it does not" are
//!   distinguishable rather than both being a bare pair.
//! * [`Repr::Pdg`] is the union, with each edge tagged `control` or `data`, on
//!   one node set --- which is what makes a slice computable from it.
//!
//! # Which control-flow graph
//!
//! [`Repr::Cfg`] exports [`crate::csource::cfg`], the general graph, and never
//! [`crate::csource::joern`], the parity graph. Same rule as
//! [`crate::csource::metrics`], same reason
//! (`docs/design/static-c-analysis/architecture.md` section 1): the parity
//! layer reproduces another tool's expression granularity so one similarity
//! score can be compared against it, and a person reading an exported graph
//! wants the graph their source describes. A caller who specifically wants the
//! parity shape already has [`crate::csource::joern::parity_cfgs`].
//!
//! # Totality
//!
//! Every entry point here is total (`REQ-SYN-2`). A file that is not C exports
//! zero graphs and the diagnostics saying so; a function the parser only partly
//! recovered exports the graph it did build. Span slicing goes through
//! [`snippet`], which returns an empty label rather than panicking on an offset
//! that is not a character boundary --- reachable input, because a label is cut
//! to a length and decompiler output contains multi-byte text.

use crate::csource::cfg::function_cfgs;
use crate::csource::parse::tag::NodeTag;
use crate::csource::parse::{parse, Tree};
use crate::syntax::cfg::Cfg;
use crate::syntax::dominance::ControlDependence;
use crate::syntax::diag::Parsed;
use crate::syntax::graph_export::{ExportEdge, ExportNode, GraphView};
use crate::syntax::ids::{NodeId, Span};

/// How long a source snippet in a node label may get, in characters.
///
/// Long enough to identify the statement, short enough that a Graphviz node
/// stays a box rather than a paragraph.
const LABEL_CHARS: usize = 48;

/// Which graph to export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Repr {
    /// The general control-flow graph, one per function.
    Cfg,
    /// The syntax tree, one per function definition.
    Ast,
    /// The data-dependence graph: definitions, uses, and the reaching edges
    /// between them.
    Ddg,
    /// The control-dependence graph: which branch decides each statement.
    Cdg,
    /// The program-dependence graph: control and data dependence on one node
    /// set, which is the graph a slice is taken from.
    Pdg,
}

impl Repr {
    /// Every representation, in declaration order, for a CLI choice list.
    pub const ALL: [Repr; 5] = [Repr::Cfg, Repr::Ast, Repr::Ddg, Repr::Cdg, Repr::Pdg];

    /// This representation's stable lowercase name, as a CLI accepts it.
    pub const fn name(self) -> &'static str {
        match self {
            Repr::Cfg => "cfg",
            Repr::Ast => "ast",
            Repr::Ddg => "ddg",
            Repr::Cdg => "cdg",
            Repr::Pdg => "pdg",
        }
    }

    /// Parses a representation name.
    pub fn parse(name: &str) -> Option<Repr> {
        match name.trim().to_ascii_lowercase().as_str() {
            "cfg" | "control-flow" | "control_flow" => Some(Repr::Cfg),
            "ast" | "tree" | "syntax" => Some(Repr::Ast),
            "ddg" | "dataflow" | "data-flow" => Some(Repr::Ddg),
            "cdg" | "control" | "control-dependence" => Some(Repr::Cdg),
            "pdg" | "program-dependence" => Some(Repr::Pdg),
            _ => None,
        }
    }
}

/// Every function's graph in `text`, in source order.
///
/// Functions are returned as a list rather than a name-keyed map because two
/// definitions in one file can carry the same name after recovery, and a map
/// would silently drop one --- the same reason
/// [`crate::csource::metrics`] reports a list.
pub fn export(text: &str, repr: Repr) -> Parsed<Vec<GraphView>> {
    let parsed = parse(text);
    let (tree, mut diagnostics) = parsed.into_parts();

    let views = match repr {
        Repr::Cfg => {
            let built = function_cfgs(&tree, text);
            let (cfgs, cfg_diags) = built.into_parts();
            for diagnostic in cfg_diags.iter() {
                diagnostics.push(diagnostic.clone());
            }
            cfgs.iter()
                .map(|function| cfg_view(&function.name, &function.cfg, text))
                .collect()
        }
        Repr::Ast => {
            let spans = tree.token_spans(text);
            tree.functions(text)
                .iter()
                .map(|function| ast_view(&function.name, &tree, function.node, &spans, text))
                .collect()
        }
        Repr::Ddg | Repr::Cdg | Repr::Pdg => {
            let built = function_cfgs(&tree, text);
            let (cfgs, cfg_diags) = built.into_parts();
            for diagnostic in cfg_diags.iter() {
                diagnostics.push(diagnostic.clone());
            }
            let spans = tree.token_spans(text);
            cfgs.iter()
                .map(|function| match repr {
                    Repr::Cdg => cdg_view(&function.name, &function.cfg, text),
                    Repr::Pdg => {
                        let flow = crate::csource::dataflow::analyze_function(
                            &tree, text, &spans, function,
                        );
                        pdg_view(&function.name, &function.cfg, &flow, text)
                    }
                    _ => {
                        let flow = crate::csource::dataflow::analyze_function(
                            &tree, text, &spans, function,
                        );
                        ddg_view(&flow, text)
                    }
                })
                .collect()
        }
    };
    Parsed::new(views, diagnostics)
}

/// One function's control-flow graph as a view.
///
/// Node labels carry the kind and the source the node covers, because a CFG
/// whose nodes read `stmt` eleven times tells a reader nothing. Edge labels
/// carry the edge kind; a back edge is marked in an attribute rather than the
/// label so the label stays the census key a consumer groups by.
pub fn cfg_view(name: &str, cfg: &Cfg, text: &str) -> GraphView {
    let mut view = GraphView::new(name);
    for (index, node) in cfg.nodes().iter().enumerate() {
        let kind = node.kind().name();
        let span = node.span();
        let text_of = snippet(text, span);
        let label = if text_of.is_empty() {
            kind.to_string()
        } else {
            format!("{kind}\n{text_of}")
        };
        view.nodes.push(
            ExportNode::new(index as u32, label)
                .with("kind", kind)
                .with("span", format!("{}:{}", span.lo, span.hi)),
        );
    }
    for edge in cfg.edges() {
        view.edges.push(
            ExportEdge::new(edge.src.index() as u32, edge.dst.index() as u32, edge.kind.name())
                .with("kind", edge.kind.name())
                .with("back", if edge.is_back { "true" } else { "false" }),
        );
    }
    view
}

/// One function definition's syntax tree as a view.
///
/// Every node is tagged; a node with no children also carries the source it
/// covers, which is what makes an exported AST readable at all. Interior nodes
/// are left to their tag, because their span is the union of their children's
/// and repeating it at every level is noise.
pub fn ast_view(
    name: &str,
    tree: &Tree,
    root: NodeId,
    token_spans: &[Span],
    text: &str,
) -> GraphView {
    let arena = tree.arena();
    let mut view = GraphView::new(name);
    // Dense output ids, assigned in preorder, so the export is stable and does
    // not leak arena indices that mean nothing outside this process.
    //
    // The reverse map is a slice indexed by arena id rather than a search
    // through `ids`: a linear lookup per child edge is quadratic in the node
    // count, and one recovered `sshd` function in the DecBench corpus carries
    // over a thousand statements.
    let mut ids: Vec<(NodeId, u32)> = Vec::new();
    let mut dense_of: Vec<Option<u32>> = vec![None; arena.len()];
    for node in arena.preorder(root) {
        let next = ids.len() as u32;
        if let Some(slot) = dense_of.get_mut(node.index()) {
            *slot = Some(next);
        }
        ids.push((node, next));
    }
    let dense = |node: NodeId| dense_of.get(node.index()).copied().flatten();

    for (node, id) in &ids {
        let tag = arena
            .tag(*node)
            .and_then(NodeTag::from_u16)
            .map_or("?", |tag| tag.name());
        let leaf = arena.child_count(*node) == 0;
        let span = arena.span(*node, token_spans).unwrap_or_default();
        let text_of = if leaf { snippet(text, span) } else { String::new() };
        let label = if text_of.is_empty() {
            tag.to_string()
        } else {
            format!("{tag}\n{text_of}")
        };
        view.nodes.push(
            ExportNode::new(*id, label)
                .with("tag", tag)
                .with("span", format!("{}:{}", span.lo, span.hi)),
        );
    }
    for (node, id) in &ids {
        for child in arena.children_iter(*node) {
            if let Some(child_id) = dense(child) {
                view.edges.push(ExportEdge::new(*id, child_id, ""));
            }
        }
    }
    view
}

/// One function's data-dependence graph as a view.
///
/// Nodes are the definitions and then the uses, in that order, so a node id is
/// stable and a reader can tell the two halves apart by the `role` attribute
/// without following an edge. Each edge is labelled with its variable, which
/// is the information the external comparison drops.
///
/// A dead store and an unresolved use are marked on the node rather than left
/// for the reader to derive from degree, because "this write is never read" is
/// the answer someone exports this graph to get.
pub fn ddg_view(flow: &crate::csource::dataflow::DataFlow, text: &str) -> GraphView {
    use crate::csource::dataflow::DataFlow;

    let mut view = GraphView::new(&flow.name);
    let def_count = flow.definitions.len() as u32;

    for (index, definition) in flow.definitions.iter().enumerate() {
        let dead = flow.is_dead_store(index as u32);
        let source = snippet(text, definition.span);
        view.nodes.push(
            ExportNode::new(
                index as u32,
                format!("def {}{}", definition.name, if dead { " (dead)" } else { "" }),
            )
            .with("role", "definition")
            .with("variable", definition.name.clone())
            .with("def_kind", definition.kind.name())
            .with("dead_store", if dead { "true" } else { "false" })
            .with("cfg_node", definition.node.to_string())
            .with("span", format!("{}:{}", definition.span.lo, definition.span.hi))
            .with("text", source),
        );
    }
    for (index, use_) in flow.uses.iter().enumerate() {
        let unresolved = flow.unresolved_uses.contains(&(index as u32));
        let source = snippet(text, use_.span);
        view.nodes.push(
            ExportNode::new(
                def_count + index as u32,
                format!(
                    "use {}{}",
                    use_.name,
                    if unresolved { " (unresolved)" } else { "" }
                ),
            )
            .with("role", "use")
            .with("variable", use_.name.clone())
            .with("unresolved", if unresolved { "true" } else { "false" })
            .with("cfg_node", use_.node.to_string())
            .with("span", format!("{}:{}", use_.span.lo, use_.span.hi))
            .with("text", source),
        );
    }
    for edge in &flow.edges {
        view.edges.push(
            ExportEdge::new(edge.def, def_count + edge.use_, edge.name.clone())
                .with("variable", edge.name.clone()),
        );
    }
    // Silence the unused-import warning in builds where the type alias is the
    // only reference; the parameter above already names it.
    let _: Option<&DataFlow> = None;
    view
}

/// One function's control-dependence graph as a view.
///
/// Nodes are the CFG's own nodes, so a reader can line this up against
/// `--repr cfg` node for node. Each edge carries the arm of the branch that
/// decides it, and each node carries its control-dependence depth --- the
/// length of the longest chain of decisions above it, computed on the graph
/// rather than from the syntax, so a `goto` out of a block or a decompiler's
/// flattened dispatch cannot fool it the way a brace count can.
pub fn cdg_view(name: &str, cfg: &Cfg, text: &str) -> GraphView {
    let cdg = ControlDependence::of(cfg);
    let post = cdg.post_dominators();
    let mut view = GraphView::new(name);

    for (index, node) in cfg.nodes().iter().enumerate() {
        let id = index as u32;
        let kind = node.kind().name();
        let span = node.span();
        let source = snippet(text, span);
        let label = if source.is_empty() {
            kind.to_string()
        } else {
            format!("{kind}\n{source}")
        };
        let mut export = ExportNode::new(id, label)
            .with("kind", kind)
            .with("depth", cdg.depth(id).to_string())
            .with("span", format!("{}:{}", span.lo, span.hi));
        if let Some(parent) = post.immediate(id) {
            export = export.with("ipdom", parent.to_string());
        }
        if post.dead_ends().contains(&id) {
            // The function end is unreachable from here: an infinite loop, a
            // `noreturn` call, or a transfer the builder could not resolve.
            export = export.with("reaches_exit", "false");
        }
        view.nodes.push(export);
    }
    for edge in cdg.edges() {
        view.edges.push(
            ExportEdge::new(edge.on, edge.node, edge.kind.name()).with("kind", edge.kind.name()),
        );
    }
    view
}

/// One function's program-dependence graph: control and data on one node set.
///
/// The union is the point. A control-dependence graph says which branch
/// decides a statement; a data-dependence graph says which write a read sees;
/// a slice needs both at once, and it needs them over the *same* nodes. So the
/// nodes here are the CFG's, the control edges are as in [`cdg_view`], and
/// each data edge is lifted from its (definition, use) pair to the pair of CFG
/// nodes those sit on. Every edge is tagged `control` or `data`.
///
/// Lifting loses the within-node ordering the data-dependence graph has, which
/// is why [`Repr::Ddg`] still exists separately: for reading dependences it is
/// the more precise graph, and this one is for slicing.
pub fn pdg_view(
    name: &str,
    cfg: &Cfg,
    flow: &crate::csource::dataflow::DataFlow,
    text: &str,
) -> GraphView {
    let mut view = cdg_view(name, cfg, text);
    for edge in view.edges.iter_mut() {
        *edge = edge.clone().with("dependence", "control");
    }

    // Data edges, lifted to the CFG nodes their endpoints sit on. A dependence
    // wholly inside one node adds a self-edge, which is real --- `x = x + 1`
    // on one straight-line node does depend on itself.
    let mut seen: Vec<(u32, u32, String)> = Vec::new();
    for edge in &flow.edges {
        let (Some(definition), Some(use_)) = (
            flow.definitions.get(edge.def as usize),
            flow.uses.get(edge.use_ as usize),
        ) else {
            continue;
        };
        let key = (definition.node, use_.node, edge.name.clone());
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        view.edges.push(
            ExportEdge::new(definition.node, use_.node, edge.name.clone())
                .with("dependence", "data")
                .with("variable", edge.name.clone()),
        );
    }
    view
}

/// The source `span` covers, collapsed to one line and cut to [`LABEL_CHARS`].
///
/// Returns an empty string rather than panicking when the span is empty, is out
/// of range, or does not land on character boundaries. All three are reachable:
/// a recovered parse inserts empty spans, and a node can cover multi-byte text.
fn snippet(text: &str, span: Span) -> String {
    let Some(raw) = text.get(span.lo as usize..span.hi as usize) else {
        return String::new();
    };
    let mut out = String::with_capacity(raw.len().min(LABEL_CHARS * 2));
    let mut space = false;
    let mut taken = 0usize;
    for ch in raw.chars() {
        if taken >= LABEL_CHARS {
            out.push_str("...");
            break;
        }
        if ch.is_whitespace() {
            space = !out.is_empty();
            continue;
        }
        if space {
            out.push(' ');
            taken += 1;
            space = false;
        }
        out.push(ch);
        taken += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::graph_export::{write, Format};

    const HELLO: &str = r#"
int greet(const char *name, int times)
{
    if (name == 0) {
        return -1;
    }
    for (int i = 0; i < times; i++) {
        puts(name);
    }
    return times;
}
"#;

    #[test]
    fn a_cfg_export_names_the_function_and_its_branches() {
        let views = export(HELLO, Repr::Cfg).into_parts().0;
        assert_eq!(views.len(), 1);
        let view = &views[0];
        assert_eq!(view.name, "greet");
        assert!(view.nodes.len() > 4, "{} nodes", view.nodes.len());
        assert!(view
            .nodes
            .iter()
            .any(|node| node.attrs.iter().any(|(k, v)| k == "kind" && v == "entry")));
        assert!(view
            .nodes
            .iter()
            .any(|node| node.attrs.iter().any(|(k, v)| k == "kind" && v == "loop_header")));
        assert!(view
            .edges
            .iter()
            .any(|edge| edge.attrs.iter().any(|(k, v)| k == "back" && v == "true")));
    }

    #[test]
    fn a_cfg_node_label_carries_the_source_it_covers() {
        let views = export(HELLO, Repr::Cfg).into_parts().0;
        let labels: Vec<&str> = views[0].nodes.iter().map(|n| n.label.as_str()).collect();
        assert!(
            labels.iter().any(|label| label.contains("puts(name)")),
            "{labels:?}"
        );
    }

    #[test]
    fn an_ast_export_is_a_tree_with_one_root() {
        let views = export(HELLO, Repr::Ast).into_parts().0;
        assert_eq!(views.len(), 1);
        let view = &views[0];
        // A tree over n nodes has exactly n-1 edges, and every node but the
        // root is the destination of exactly one of them.
        assert_eq!(view.edges.len(), view.nodes.len() - 1);
        let mut targets: Vec<u32> = view.edges.iter().map(|e| e.dst).collect();
        targets.sort_unstable();
        targets.dedup();
        assert_eq!(targets.len(), view.nodes.len() - 1);
        assert!(!targets.contains(&0), "node 0 is the root");
    }

    #[test]
    fn an_ast_leaf_carries_its_source_and_an_interior_node_does_not() {
        let views = export(HELLO, Repr::Ast).into_parts().0;
        let view = &views[0];
        assert!(
            view.nodes.iter().any(|n| n.label.contains('\n')),
            "no leaf label carried source"
        );
        let root = &view.nodes[0];
        assert!(!root.label.contains('\n'), "root label: {}", root.label);
    }

    #[test]
    fn every_representation_and_format_is_total_on_junk() {
        for junk in ["", "\u{0}\u{1}not C at all", "int f(", "}}}", "\u{4e2d}\u{6587}"] {
            for repr in Repr::ALL {
                let views = export(junk, repr).into_parts().0;
                for view in &views {
                    for format in Format::ALL {
                        assert!(!write(view, format).is_empty());
                    }
                }
            }
        }
    }

    #[test]
    fn a_partly_recovered_file_still_exports_the_functions_it_parsed() {
        // The second definition never closes; the first must survive it.
        let text = "int a(void) { return 1; }\nint b(void) { return 2;\n";
        let views = export(text, Repr::Cfg).into_parts().0;
        let names: Vec<&str> = views.iter().map(|v| v.name.as_str()).collect();
        assert!(names.contains(&"a"), "{names:?}");
    }

    #[test]
    fn a_multibyte_snippet_is_cut_without_panicking() {
        let text = "int f(void) { const char *s = \"\u{4e2d}\u{6587}\u{4e2d}\u{6587}\u{4e2d}\u{6587}\u{4e2d}\u{6587}\u{4e2d}\u{6587}\u{4e2d}\u{6587}\u{4e2d}\u{6587}\u{4e2d}\u{6587}\u{4e2d}\u{6587}\u{4e2d}\u{6587}\u{4e2d}\u{6587}\u{4e2d}\u{6587}\u{4e2d}\u{6587}\"; return 0; }";
        let views = export(text, Repr::Cfg).into_parts().0;
        assert_eq!(views.len(), 1);
        for node in &views[0].nodes {
            assert!(node.label.chars().count() < 128);
        }
    }

    #[test]
    fn repr_names_round_trip() {
        for repr in Repr::ALL {
            assert_eq!(Repr::parse(repr.name()), Some(repr));
        }
        assert_eq!(Repr::parse("ddg"), Some(Repr::Ddg));
        assert_eq!(Repr::parse("cdg"), Some(Repr::Cdg));
        assert_eq!(Repr::parse("pdg"), Some(Repr::Pdg));
        // `cpg14` is a code property graph, which `requirements.md` section 8
        // declines. It stays refused rather than faked.
        assert_eq!(Repr::parse("cpg14"), None, "not offered rather than faked");
        assert_eq!(Repr::parse("cpg"), None, "not offered rather than faked");
    }
}

#[cfg(test)]
mod ddg_tests {
    use super::*;
    use crate::syntax::graph_export::{write, Format};

    const SUM: &str = "int f(int n) { int s = 0; int dead = 7; for (int i = 0; i < n; i++) { s = s + i; } return s; }";

    #[test]
    fn a_ddg_export_separates_definitions_from_uses() {
        let views = export(SUM, Repr::Ddg).into_parts().0;
        assert_eq!(views.len(), 1);
        let view = &views[0];
        let roles: Vec<&str> = view
            .nodes
            .iter()
            .filter_map(|n| n.attrs.iter().find(|(k, _)| k == "role").map(|(_, v)| v.as_str()))
            .collect();
        assert!(roles.contains(&"definition"));
        assert!(roles.contains(&"use"));
        // Every edge runs definition -> use, never the other way.
        let def_count = roles.iter().filter(|r| **r == "definition").count() as u32;
        for edge in &view.edges {
            assert!(edge.src < def_count, "edge leaves a use: {edge:?}");
            assert!(edge.dst >= def_count, "edge enters a definition: {edge:?}");
        }
    }

    #[test]
    fn every_ddg_edge_names_its_variable() {
        // The thing pyjoern's DDG cannot tell you: which value an edge is for.
        let views = export(SUM, Repr::Ddg).into_parts().0;
        for edge in &views[0].edges {
            assert!(!edge.label.is_empty(), "unlabelled edge: {edge:?}");
            assert!(edge.attrs.iter().any(|(k, _)| k == "variable"));
        }
    }

    #[test]
    fn a_dead_store_is_marked_on_the_node() {
        let views = export(SUM, Repr::Ddg).into_parts().0;
        let dead: Vec<&str> = views[0]
            .nodes
            .iter()
            .filter(|n| n.attrs.iter().any(|(k, v)| k == "dead_store" && v == "true"))
            .filter_map(|n| n.attrs.iter().find(|(k, _)| k == "variable").map(|(_, v)| v.as_str()))
            .collect();
        assert_eq!(dead, vec!["dead"], "{:?}", dead);
    }

    #[test]
    fn the_ddg_serializes_in_every_format() {
        let views = export(SUM, Repr::Ddg).into_parts().0;
        for format in Format::ALL {
            let body = write(&views[0], format);
            assert!(body.contains('s') && !body.is_empty());
        }
    }
}

#[cfg(test)]
mod dependence_tests {
    use super::*;
    use crate::syntax::graph_export::{write, Format};

    /// A branch, a nested branch, a loop, and a value that flows through all
    /// three -- enough shape that every claim below is about something.
    const SHAPES: &str = r#"
int classify(int a, int b, int n)
{
    int total = 0;
    if (a > b) {
        if (n > 0) {
            total = a - b;
        }
    } else {
        total = b - a;
    }
    for (int i = 0; i < n; i++) {
        total = total + i;
    }
    return total;
}
"#;

    fn attr<'a>(node: &'a ExportNode, key: &str) -> Option<&'a str> {
        node.attrs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn a_cdg_shares_the_cfg_node_set() {
        // Lining the two up node for node is what makes the export readable
        // beside `--repr cfg`, so it is a promise worth pinning.
        let cfg = export(SHAPES, Repr::Cfg).into_parts().0;
        let cdg = export(SHAPES, Repr::Cdg).into_parts().0;
        assert_eq!(cdg.len(), cfg.len());
        assert_eq!(cdg[0].nodes.len(), cfg[0].nodes.len());
        for (a, b) in cdg[0].nodes.iter().zip(cfg[0].nodes.iter()) {
            assert_eq!(a.id, b.id);
        }
    }

    #[test]
    fn every_cdg_edge_names_the_arm_that_decides_it() {
        let views = export(SHAPES, Repr::Cdg).into_parts().0;
        assert!(!views[0].edges.is_empty(), "no control dependence found");
        for edge in &views[0].edges {
            assert!(!edge.label.is_empty(), "unlabelled: {edge:?}");
            // The label is an edge kind, not a variable name.
            assert!(
                ["true", "false", "case", "default", "fall", "fall_through", "jump"]
                    .contains(&edge.label.as_str()),
                "{edge:?}"
            );
        }
    }

    #[test]
    fn control_depth_grows_with_nesting() {
        let views = export(SHAPES, Repr::Cdg).into_parts().0;
        let depths: Vec<u32> = views[0]
            .nodes
            .iter()
            .filter_map(|node| attr(node, "depth"))
            .filter_map(|value| value.parse().ok())
            .collect();
        // The entry is unconditional; the doubly nested assignment is not.
        assert!(depths.contains(&0), "{depths:?}");
        assert!(
            depths.iter().any(|depth| *depth >= 2),
            "no doubly nested node found: {depths:?}"
        );
    }

    #[test]
    fn the_entry_depends_on_nothing() {
        let views = export(SHAPES, Repr::Cdg).into_parts().0;
        let entry = views[0]
            .nodes
            .iter()
            .find(|node| attr(node, "kind") == Some("entry"))
            .expect("an entry node");
        assert_eq!(attr(entry, "depth"), Some("0"));
        assert!(
            !views[0].edges.iter().any(|edge| edge.dst == entry.id),
            "the entry is control dependent on something"
        );
    }

    #[test]
    fn a_pdg_carries_both_kinds_of_edge_and_tags_each() {
        let views = export(SHAPES, Repr::Pdg).into_parts().0;
        let view = &views[0];
        let mut control = 0;
        let mut data = 0;
        for edge in &view.edges {
            match attr_edge(edge, "dependence") {
                Some("control") => control += 1,
                Some("data") => data += 1,
                other => panic!("untagged edge {edge:?}: {other:?}"),
            }
        }
        assert!(control > 0, "no control edges");
        assert!(data > 0, "no data edges");
        // Every data edge also names its variable.
        for edge in &view.edges {
            if attr_edge(edge, "dependence") == Some("data") {
                assert!(attr_edge(edge, "variable").is_some(), "{edge:?}");
            }
        }
    }

    fn attr_edge<'a>(edge: &'a ExportEdge, key: &str) -> Option<&'a str> {
        edge.attrs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn a_pdg_edge_never_names_a_node_it_does_not_have() {
        let views = export(SHAPES, Repr::Pdg).into_parts().0;
        for view in &views {
            let ids: Vec<u32> = view.nodes.iter().map(|node| node.id).collect();
            for edge in &view.edges {
                assert!(ids.contains(&edge.src), "{edge:?}");
                assert!(ids.contains(&edge.dst), "{edge:?}");
            }
        }
    }

    #[test]
    fn every_dependence_graph_serializes_in_every_format() {
        for repr in [Repr::Ddg, Repr::Cdg, Repr::Pdg] {
            let views = export(SHAPES, repr).into_parts().0;
            assert!(!views.is_empty(), "{repr:?} produced nothing");
            for format in Format::ALL {
                assert!(!write(&views[0], format).is_empty(), "{repr:?}/{format:?}");
            }
        }
    }

    #[test]
    fn every_representation_is_total_on_junk() {
        for junk in ["", "\u{0}\u{1}", "int f(", "}}}", "while(1){}", "\u{4e2d}\u{6587}"] {
            for repr in Repr::ALL {
                let views = export(junk, repr).into_parts().0;
                for view in &views {
                    for format in Format::ALL {
                        assert!(!write(view, format).is_empty());
                    }
                }
            }
        }
    }

    #[test]
    fn an_infinite_loop_still_exports_a_cdg() {
        // The shape that has no post-dominator tree without a virtual exit.
        let views = export("int f(void) { while (1) { } return 0; }", Repr::Cdg)
            .into_parts()
            .0;
        assert_eq!(views.len(), 1);
        assert!(!views[0].nodes.is_empty());
    }
}
