//! Language-neutral graph serialization: one view type, four wire formats.
//!
//! # Why a view type rather than four writers per graph
//!
//! Two graphs want exporting today (the control-flow graph and the syntax
//! tree) and each wants four formats, which is eight code paths written
//! directly and four written through a common shape. The shape is the smaller
//! surface, and it is also the seam a third graph arrives at: a data-dependence
//! graph is nodes, edges and labels like the other two, so adding one is a
//! builder rather than four more writers.
//!
//! This sits beside [`crate::syntax::ged`] and [`crate::syntax::metrics`] for
//! the reason `docs/design/static-c-analysis/architecture.md` section 1 gives
//! for those: a writer that reads ids, labels and adjacency is neither
//! C-specific nor bound to one front end. Nothing here knows what a statement
//! is, and nothing here may reach into a language module (`REQ-SYN-8`).
//!
//! # The four formats, and why these four in 2026
//!
//! * [`to_dot`] --- Graphviz. Universal, human-readable, and what
//!   `glaurung graph` already emits for binary CFGs, so a reader who knows one
//!   knows the other. It is also `joern-export`'s default, which matters when
//!   the point is to replace it.
//! * [`to_graphml`] --- the interchange standard. `networkx`, `igraph`,
//!   `JGraphT`, Gephi and yEd all read it, and `joern-export` writes it, so a
//!   pipeline built on Joern's GraphML keeps working.
//! * [`to_json`] --- node-link JSON in the shape `networkx` reads. NetworkX
//!   3.4 deprecated the `link` keyword in favour of `edges` and 3.6 removed it,
//!   so the edge array is named **`edges`** here and
//!   `nx.node_link_graph(data)` loads it under the current default. Callers on
//!   older NetworkX pass `edges="edges"` explicitly.
//! * [`to_mermaid`] --- renders inline in Markdown, on GitHub, and in a chat
//!   transcript without a Graphviz install. A source CFG is small enough for
//!   this to be the format a person actually looks at.
//!
//! GraphSON and Neo4j CSV are deliberately absent. Both exist in
//! `joern-export` to feed a graph database, which is the code-property-graph
//! path `requirements.md` section 8 declines; adding them without that is
//! carrying a format nobody here reads.
//!
//! # Rules inherited from the substrate
//!
//! * **No panics** (`REQ-SYN-2`): every writer is total. An edge naming a node
//!   that does not exist is still written, because dropping it would make the
//!   export disagree with the graph it came from, and a reader that cares can
//!   compare the id sets.
//! * **Determinism** (`REQ-SYN-5`): nodes and edges are written in the order
//!   the view holds them, and attributes in insertion order, so two runs over
//!   one input produce identical bytes.
//! * **Escaping is per format and total**: no input string can terminate a
//!   quoted region early, including a lone `"`, a backslash, a newline, a `<`,
//!   an `&`, or a byte sequence that is not valid UTF-8 (it cannot be: the
//!   input is `&str`).

use std::fmt::Write as _;

/// One attribute pair on a node or an edge.
///
/// Values are strings in every format, which is what keeps GraphML's `<key>`
/// declarations to a single `attr.type` and keeps a reader from having to
/// guess whether `"3"` was an integer. A consumer that wants a number parses
/// one.
pub type Attr = (String, String);

/// One node of an exported graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportNode {
    /// Dense id, unique within the view. Written verbatim as `n<id>`.
    pub id: u32,
    /// Display label. May be empty.
    pub label: String,
    /// Attribute pairs, in the order a reader should see them.
    pub attrs: Vec<Attr>,
}

impl ExportNode {
    /// A node with a label and no attributes.
    pub fn new(id: u32, label: impl Into<String>) -> Self {
        Self {
            id,
            label: label.into(),
            attrs: Vec::new(),
        }
    }

    /// Adds one attribute, builder style.
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attrs.push((key.into(), value.into()));
        self
    }
}

/// One directed edge of an exported graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportEdge {
    /// Source node id.
    pub src: u32,
    /// Destination node id.
    pub dst: u32,
    /// Display label. May be empty, in which case no label is written.
    pub label: String,
    /// Attribute pairs, in the order a reader should see them.
    pub attrs: Vec<Attr>,
}

impl ExportEdge {
    /// An edge with a label and no attributes.
    pub fn new(src: u32, dst: u32, label: impl Into<String>) -> Self {
        Self {
            src,
            dst,
            label: label.into(),
            attrs: Vec::new(),
        }
    }

    /// Adds one attribute, builder style.
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attrs.push((key.into(), value.into()));
        self
    }
}

/// A graph ready to serialize: a name, nodes and edges.
///
/// Always directed. Both graphs this serves are directed, and a format that
/// declares itself undirected while carrying `src`/`dst` pairs would be lying
/// to its reader.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GraphView {
    /// Graph name, used as the DOT graph id, the GraphML `id`, and the
    /// `graph.name` field of the JSON.
    pub name: String,
    /// Nodes, in the order they are written.
    pub nodes: Vec<ExportNode>,
    /// Edges, in the order they are written.
    pub edges: Vec<ExportEdge>,
}

impl GraphView {
    /// An empty view with a name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }
}

/// The wire formats [`write`] can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Format {
    /// Graphviz DOT.
    Dot,
    /// GraphML, the XML interchange standard.
    GraphMl,
    /// Node-link JSON in the shape NetworkX reads.
    Json,
    /// Mermaid `flowchart`, for Markdown that renders itself.
    Mermaid,
}

impl Format {
    /// Every format, in declaration order, for a CLI choice list.
    pub const ALL: [Format; 4] = [
        Format::Dot,
        Format::GraphMl,
        Format::Json,
        Format::Mermaid,
    ];

    /// This format's stable lowercase name, as a CLI accepts it.
    pub const fn name(self) -> &'static str {
        match self {
            Format::Dot => "dot",
            Format::GraphMl => "graphml",
            Format::Json => "json",
            Format::Mermaid => "mermaid",
        }
    }

    /// The file extension conventionally used for this format, without a dot.
    pub const fn extension(self) -> &'static str {
        match self {
            Format::Dot => "dot",
            Format::GraphMl => "graphml",
            Format::Json => "json",
            Format::Mermaid => "mmd",
        }
    }

    /// Parses a format name, accepting the spellings a CLI is given.
    ///
    /// `graph-ml` and `graph_ml` are accepted alongside `graphml` because a
    /// caller who guesses is more likely to guess one of those than to read
    /// this list.
    pub fn parse(name: &str) -> Option<Format> {
        match name.trim().to_ascii_lowercase().as_str() {
            "dot" | "gv" | "graphviz" => Some(Format::Dot),
            "graphml" | "graph-ml" | "graph_ml" => Some(Format::GraphMl),
            "json" | "node-link" | "node_link" => Some(Format::Json),
            "mermaid" | "mmd" => Some(Format::Mermaid),
            _ => None,
        }
    }
}

/// Serializes `view` in `format`.
pub fn write(view: &GraphView, format: Format) -> String {
    match format {
        Format::Dot => to_dot(view),
        Format::GraphMl => to_graphml(view),
        Format::Json => to_json(view),
        Format::Mermaid => to_mermaid(view),
    }
}

/// Serializes `view` as Graphviz DOT.
pub fn to_dot(view: &GraphView) -> String {
    let mut out = String::with_capacity(64 + view.nodes.len() * 48 + view.edges.len() * 32);
    let _ = writeln!(out, "digraph {} {{", dot_quote(&view.name));
    out.push_str("  node [shape=box, fontname=monospace, fontsize=10];\n");
    for node in &view.nodes {
        let _ = write!(out, "  n{} [label={}", node.id, dot_quote(&node.label));
        for (key, value) in &node.attrs {
            let _ = write!(out, ", {}={}", dot_ident(key), dot_quote(value));
        }
        out.push_str("];\n");
    }
    for edge in &view.edges {
        let _ = write!(out, "  n{} -> n{}", edge.src, edge.dst);
        let mut wrote = false;
        if !edge.label.is_empty() {
            let _ = write!(out, " [label={}", dot_quote(&edge.label));
            wrote = true;
        }
        for (key, value) in &edge.attrs {
            out.push_str(if wrote { ", " } else { " [" });
            let _ = write!(out, "{}={}", dot_ident(key), dot_quote(value));
            wrote = true;
        }
        out.push_str(if wrote { "];\n" } else { ";\n" });
    }
    out.push_str("}\n");
    out
}

/// Serializes `view` as GraphML.
///
/// Attribute keys are declared once at the top, as the schema requires, with
/// separate declarations for the node domain and the edge domain because a
/// key's `for` attribute is part of its identity.
pub fn to_graphml(view: &GraphView) -> String {
    let node_keys = collect_keys(view.nodes.iter().map(|n| n.attrs.as_slice()), "label");
    let edge_keys = collect_keys(view.edges.iter().map(|e| e.attrs.as_slice()), "label");

    let mut out = String::with_capacity(256 + view.nodes.len() * 96 + view.edges.len() * 96);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n");
    for (index, key) in node_keys.iter().enumerate() {
        let _ = writeln!(
            out,
            "  <key id=\"nd{index}\" for=\"node\" attr.name=\"{}\" attr.type=\"string\"/>",
            xml_escape(key)
        );
    }
    for (index, key) in edge_keys.iter().enumerate() {
        let _ = writeln!(
            out,
            "  <key id=\"ed{index}\" for=\"edge\" attr.name=\"{}\" attr.type=\"string\"/>",
            xml_escape(key)
        );
    }
    let _ = writeln!(
        out,
        "  <graph id=\"{}\" edgedefault=\"directed\">",
        xml_escape(&view.name)
    );
    for node in &view.nodes {
        let _ = writeln!(out, "    <node id=\"n{}\">", node.id);
        write_graphml_data(&mut out, &node_keys, "nd", "label", &node.label);
        for (key, value) in &node.attrs {
            write_graphml_data(&mut out, &node_keys, "nd", key, value);
        }
        out.push_str("    </node>\n");
    }
    for (index, edge) in view.edges.iter().enumerate() {
        let _ = writeln!(
            out,
            "    <edge id=\"e{index}\" source=\"n{}\" target=\"n{}\">",
            edge.src, edge.dst
        );
        write_graphml_data(&mut out, &edge_keys, "ed", "label", &edge.label);
        for (key, value) in &edge.attrs {
            write_graphml_data(&mut out, &edge_keys, "ed", key, value);
        }
        out.push_str("    </edge>\n");
    }
    out.push_str("  </graph>\n</graphml>\n");
    out
}

/// Serializes `view` as node-link JSON.
///
/// The edge array is named `edges`, which is what NetworkX 3.6 reads by
/// default after the `link` keyword was deprecated in 3.4 and removed in 3.6.
pub fn to_json(view: &GraphView) -> String {
    let nodes: Vec<serde_json::Value> = view
        .nodes
        .iter()
        .map(|node| {
            let mut map = serde_json::Map::new();
            map.insert("id".into(), node.id.into());
            map.insert("label".into(), node.label.clone().into());
            for (key, value) in &node.attrs {
                map.insert(key.clone(), value.clone().into());
            }
            serde_json::Value::Object(map)
        })
        .collect();
    let edges: Vec<serde_json::Value> = view
        .edges
        .iter()
        .map(|edge| {
            let mut map = serde_json::Map::new();
            map.insert("source".into(), edge.src.into());
            map.insert("target".into(), edge.dst.into());
            map.insert("label".into(), edge.label.clone().into());
            for (key, value) in &edge.attrs {
                map.insert(key.clone(), value.clone().into());
            }
            serde_json::Value::Object(map)
        })
        .collect();

    let document = serde_json::json!({
        "directed": true,
        "multigraph": true,
        "graph": { "name": view.name },
        "nodes": nodes,
        "edges": edges,
    });
    // `to_string_pretty` cannot fail on a value built from owned strings and
    // integers, but the fallback keeps this total rather than unwrapping.
    serde_json::to_string_pretty(&document).unwrap_or_else(|_| String::from("{}"))
}

/// Serializes `view` as a Mermaid `flowchart`.
///
/// Mermaid has no attribute channel, so only labels survive. That is the
/// trade this format exists for: it renders where the others need a tool.
pub fn to_mermaid(view: &GraphView) -> String {
    let mut out = String::with_capacity(32 + view.nodes.len() * 32 + view.edges.len() * 24);
    out.push_str("flowchart TD\n");
    for node in &view.nodes {
        let _ = writeln!(out, "  n{}[{}]", node.id, mermaid_quote(&node.label));
    }
    for edge in &view.edges {
        if edge.label.is_empty() {
            let _ = writeln!(out, "  n{} --> n{}", edge.src, edge.dst);
        } else {
            let _ = writeln!(
                out,
                "  n{} -->|{}| n{}",
                edge.src,
                mermaid_label(&edge.label),
                edge.dst
            );
        }
    }
    out
}

/// The distinct attribute keys used across `groups`, `first` first, then the
/// rest in first-appearance order.
fn collect_keys<'a>(
    groups: impl Iterator<Item = &'a [Attr]>,
    first: &str,
) -> Vec<String> {
    let mut keys = vec![first.to_string()];
    for attrs in groups {
        for (key, _) in attrs {
            if !keys.iter().any(|seen| seen == key) {
                keys.push(key.clone());
            }
        }
    }
    keys
}

/// Writes one GraphML `<data>` element, if `key` was declared.
fn write_graphml_data(out: &mut String, keys: &[String], prefix: &str, key: &str, value: &str) {
    if let Some(index) = keys.iter().position(|seen| seen == key) {
        let _ = writeln!(
            out,
            "      <data key=\"{prefix}{index}\">{}</data>",
            xml_escape(value)
        );
    }
}

/// Quotes `text` as a DOT double-quoted id.
///
/// DOT's quoting rule is narrow: inside quotes only `"` needs escaping, and a
/// trailing backslash would escape the closing quote, so backslashes are
/// escaped too. Newlines become `\l` (left-justified line break), which is what
/// a multi-line node label wants in Graphviz.
fn dot_quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\l"),
            '\r' => {}
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Reduces `key` to a bare DOT identifier, so an attribute name can never
/// introduce syntax. Anything outside `[A-Za-z0-9_]` becomes `_`.
fn dot_ident(key: &str) -> String {
    let mut out: String = key
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect();
    if out.is_empty() || out.starts_with(|ch: char| ch.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// Escapes `text` for XML character data and attribute values.
fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // XML 1.0 forbids most control characters outright, so they are
            // dropped rather than escaped: a numeric reference to them is
            // itself invalid, and decompiler output does contain them.
            c if (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r' => {}
            other => out.push(other),
        }
    }
    out
}

/// Quotes `text` as a Mermaid node label.
///
/// Mermaid takes a quoted string inside the shape brackets, and inside it a
/// literal `"` must become the HTML entity: there is no backslash escape.
fn mermaid_quote(text: &str) -> String {
    format!("\"{}\"", mermaid_label(text))
}

/// Escapes `text` for use inside a Mermaid label.
fn mermaid_label(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("&quot;"),
            '|' => out.push_str("&#124;"),
            '\n' | '\r' => out.push(' '),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GraphView {
        let mut view = GraphView::new("greet");
        view.nodes
            .push(ExportNode::new(0, "entry").with("kind", "entry"));
        view.nodes
            .push(ExportNode::new(1, "if (name == NULL)").with("kind", "cond"));
        view.edges
            .push(ExportEdge::new(0, 1, "fall").with("kind", "fall"));
        view
    }

    #[test]
    fn dot_names_every_node_and_edge() {
        let out = to_dot(&sample());
        assert!(out.starts_with("digraph \"greet\" {\n"));
        assert!(out.contains("n0 [label=\"entry\", kind=\"entry\"];"));
        assert!(out.contains("n0 -> n1 [label=\"fall\", kind=\"fall\"];"));
        assert!(out.ends_with("}\n"));
    }

    #[test]
    fn dot_quoting_cannot_be_escaped_by_a_label() {
        let mut view = GraphView::new("x");
        view.nodes
            .push(ExportNode::new(0, "say \"hi\" \\ then\nnext"));
        let out = to_dot(&view);
        assert!(out.contains(r#"n0 [label="say \"hi\" \\ then\lnext"];"#), "{out}");
        // One opening and one closing quote per label: the escapes did not
        // terminate the quoted region early.
        assert_eq!(out.matches('"').count() - out.matches("\\\"").count(), 4);
    }

    #[test]
    fn dot_attribute_keys_cannot_introduce_syntax() {
        let mut view = GraphView::new("x");
        view.nodes
            .push(ExportNode::new(0, "n").with("a b\"]; evil [x", "1"));
        let out = to_dot(&view);
        assert!(out.contains("a_b____evil__x=\"1\""), "{out}");
    }

    #[test]
    fn graphml_declares_every_key_it_uses() {
        let out = to_graphml(&sample());
        assert!(out.contains(r#"<key id="nd0" for="node" attr.name="label" attr.type="string"/>"#));
        assert!(out.contains(r#"<key id="nd1" for="node" attr.name="kind" attr.type="string"/>"#));
        assert!(out.contains(r#"<key id="ed1" for="edge" attr.name="kind" attr.type="string"/>"#));
        assert!(out.contains(r#"<edge id="e0" source="n0" target="n1">"#));
    }

    #[test]
    fn graphml_escapes_markup_and_drops_control_bytes() {
        let mut view = GraphView::new("x");
        view.nodes
            .push(ExportNode::new(0, "a < b && c > \"d\"\u{1}"));
        let out = to_graphml(&view);
        assert!(out.contains("a &lt; b &amp;&amp; c &gt; &quot;d&quot;</data>"), "{out}");
        assert!(!out.contains('\u{1}'));
    }

    #[test]
    fn json_uses_the_edges_key_networkx_reads() {
        let out = to_json(&sample());
        let value: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(value["directed"], serde_json::json!(true));
        assert_eq!(value["graph"]["name"], serde_json::json!("greet"));
        assert_eq!(value["nodes"][1]["label"], serde_json::json!("if (name == NULL)"));
        assert_eq!(value["edges"][0]["source"], serde_json::json!(0));
        assert_eq!(value["edges"][0]["target"], serde_json::json!(1));
        assert!(value.get("links").is_none(), "the removed NetworkX key");
    }

    #[test]
    fn mermaid_escapes_the_two_characters_that_break_it() {
        let mut view = GraphView::new("x");
        view.nodes.push(ExportNode::new(0, "a \"b\" | c"));
        view.nodes.push(ExportNode::new(1, "d"));
        view.edges.push(ExportEdge::new(0, 1, "a|b"));
        let out = to_mermaid(&view);
        assert!(out.starts_with("flowchart TD\n"));
        assert!(out.contains(r#"n0["a &quot;b&quot; &#124; c"]"#), "{out}");
        assert!(out.contains("n0 -->|a&#124;b| n1"), "{out}");
    }

    #[test]
    fn every_writer_is_total_on_an_empty_graph() {
        let view = GraphView::new("");
        for format in Format::ALL {
            let out = write(&view, format);
            assert!(!out.is_empty(), "{format:?} wrote nothing");
        }
        assert!(serde_json::from_str::<serde_json::Value>(&to_json(&view)).is_ok());
    }

    #[test]
    fn an_edge_naming_a_missing_node_is_still_written() {
        let mut view = GraphView::new("x");
        view.nodes.push(ExportNode::new(0, "only"));
        view.edges.push(ExportEdge::new(0, 99, ""));
        assert!(to_dot(&view).contains("n0 -> n99;"));
        assert!(to_graphml(&view).contains("target=\"n99\""));
        assert!(to_mermaid(&view).contains("n0 --> n99"));
    }

    #[test]
    fn output_is_byte_identical_across_runs() {
        for format in Format::ALL {
            assert_eq!(write(&sample(), format), write(&sample(), format));
        }
    }

    #[test]
    fn format_names_round_trip() {
        for format in Format::ALL {
            assert_eq!(Format::parse(format.name()), Some(format));
            assert_eq!(Format::parse(&format.name().to_uppercase()), Some(format));
        }
        assert_eq!(Format::parse("graph-ml"), Some(Format::GraphMl));
        assert_eq!(Format::parse("nope"), None);
    }
}
