//! Turning a parsed C file into serializable graphs.
//!
//! The writers live in [`crate::syntax::graph_export`], which knows nothing
//! about C. This module is the other half: it reads a [`Tree`] and the
//! [`Cfg`]s built from it and produces the labelled views those writers take.
//!
//! # What this replaces
//!
//! `joern-export --repr {ast,cfg} --format {dot,graphml,...}` is the shape a
//! caller already knows, so [`Repr`] uses Joern's spelling of the two
//! representations we have. The three it also offers --- `cdg`, `ddg` and
//! `pdg` --- need a data-dependence analysis this front end does not do, and
//! are absent rather than stubbed: a `--repr ddg` that returned a control-flow
//! graph would be worse than an error.
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
}

impl Repr {
    /// Every representation, in declaration order, for a CLI choice list.
    pub const ALL: [Repr; 2] = [Repr::Cfg, Repr::Ast];

    /// This representation's stable lowercase name, as a CLI accepts it.
    pub const fn name(self) -> &'static str {
        match self {
            Repr::Cfg => "cfg",
            Repr::Ast => "ast",
        }
    }

    /// Parses a representation name.
    pub fn parse(name: &str) -> Option<Repr> {
        match name.trim().to_ascii_lowercase().as_str() {
            "cfg" | "control-flow" | "control_flow" => Some(Repr::Cfg),
            "ast" | "tree" | "syntax" => Some(Repr::Ast),
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
        assert_eq!(Repr::parse("ddg"), None, "not offered rather than faked");
    }
}
