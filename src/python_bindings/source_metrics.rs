//! Python bindings for the C source metrics.
//!
//! [`crate::csource::metrics`] measures a single piece of C: how big it is, how
//! branchy, how deeply nested, what it calls, and Halstead's token figures.
//! This exposes that to Python, and the boundary is the one
//! [`crate::python_bindings::source_cfg`] and
//! [`crate::python_bindings::metrics`] already draw --- **Rust hands back plain
//! dicts, lists, ints, floats and strings, and nothing Python-shaped is ever
//! passed in**. The ergonomic wrappers live in `python/glaurung/source.py`,
//! where they cost nothing to change and cannot make the extension unimportable
//! in an environment missing some library.
//!
//! Plain data rather than a class hierarchy is also what the consumers want.
//! Three of the four use cases this exists for --- a JSON report, a feature
//! matrix for a corpus, a threshold gate in CI --- want a dict they can
//! serialize or a row they can stack; only interactive exploration wants
//! attributes, and that one is cheap to build in Python on top of a dict.
//!
//! Two invariants carry over from [`crate::csource::metrics`] and are
//! load-bearing here.
//!
//! * **Nothing raises on account of the input.** Parsing is total
//!   (`REQ-SYN-2`), so any byte sequence yields a report; a file the parser
//!   only partly recovered yields the functions it did recover alongside the
//!   diagnostics explaining the rest. A caller cannot tell "this file has no
//!   functions" from "this file failed" if the second one throws.
//! * **Determinism.** Every collection here comes from a `Vec` or a
//!   `BTreeMap`, so no hash iteration order reaches Python and two runs over
//!   the same text produce byte-identical output.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::csource::metrics::{self, FunctionMetrics, SourceReport};
use crate::csource::parse::parse;
use crate::syntax::cfg::Cfg;
use crate::syntax::diag::Diagnostics;
use crate::syntax::ids::NodeId;

/// Build the `{"lines", "tokens", "bytes", "functions", "diagnostics"}` dict.
fn report_dict<'py>(
    py: Python<'py>,
    report: &SourceReport,
    diagnostics: &Diagnostics,
    text: &str,
) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);

    let lines = PyDict::new(py);
    lines.set_item("lines", report.lines.lines)?;
    lines.set_item("code_lines", report.lines.code_lines)?;
    lines.set_item("blank_lines", report.lines.blank_lines)?;
    lines.set_item("other_lines", report.lines.other_lines)?;
    out.set_item("lines", lines)?;
    out.set_item("tokens", report.tokens)?;
    out.set_item("bytes", report.bytes)?;

    let functions = PyList::empty(py);
    for function in &report.functions {
        functions.append(function_dict(py, function)?)?;
    }
    out.set_item("functions", functions)?;

    let reported = PyList::empty(py);
    for diagnostic in diagnostics.iter() {
        let entry = PyDict::new(py);
        entry.set_item("severity", format!("{:?}", diagnostic.severity).to_lowercase())?;
        entry.set_item("message", diagnostic.message.clone())?;
        entry.set_item("start", diagnostic.span.lo)?;
        entry.set_item("end", diagnostic.span.hi)?;
        entry.set_item("text", diagnostic.render(text))?;
        reported.append(entry)?;
    }
    out.set_item("diagnostics", reported)?;
    Ok(out)
}

/// One function's measurement as a dict.
fn function_dict<'py>(py: Python<'py>, f: &FunctionMetrics) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);
    out.set_item("name", f.name.clone())?;
    out.set_item("start", f.span.lo)?;
    out.set_item("end", f.span.hi)?;
    out.set_item("has_body", f.has_body)?;
    out.set_item("parameters", f.parameters)?;
    out.set_item("short_circuits", f.short_circuits)?;
    out.set_item("unreachable_statements", f.unreachable_statements)?;

    let size = PyDict::new(py);
    size.set_item("first_line", f.size.first_line)?;
    size.set_item("last_line", f.size.last_line)?;
    size.set_item("lines", f.size.lines)?;
    size.set_item("code_lines", f.size.code_lines)?;
    size.set_item("tokens", f.size.tokens)?;
    size.set_item("bytes", f.size.bytes)?;
    out.set_item("size", size)?;

    let graph = PyDict::new(py);
    graph.set_item("nodes", f.graph.nodes)?;
    graph.set_item("edges", f.graph.edges)?;
    graph.set_item("reachable_nodes", f.graph.reachable_nodes)?;
    graph.set_item("unreachable_nodes", f.graph.unreachable_nodes)?;
    graph.set_item("dead_end_nodes", f.graph.dead_end_nodes)?;
    graph.set_item("cyclomatic", f.graph.cyclomatic)?;
    graph.set_item("decision_points", f.graph.decision_points)?;
    graph.set_item("back_edges", f.graph.back_edges)?;
    graph.set_item("loops", f.graph.loops)?;
    let node_kinds = PyDict::new(py);
    for (kind, count) in &f.graph.node_kinds {
        node_kinds.set_item(kind.name(), count)?;
    }
    graph.set_item("node_kinds", node_kinds)?;
    let edge_kinds = PyDict::new(py);
    for (kind, count) in &f.graph.edge_kinds {
        edge_kinds.set_item(kind.name(), count)?;
    }
    graph.set_item("edge_kinds", edge_kinds)?;
    out.set_item("graph", graph)?;

    let shape = PyDict::new(py);
    shape.set_item("max_nesting", f.shape.max_nesting)?;
    shape.set_item("max_loop_depth", f.shape.max_loop_depth)?;
    shape.set_item("cognitive", f.shape.cognitive)?;
    shape.set_item("calls", f.shape.calls)?;
    shape.set_item("callees", f.shape.callees.clone())?;
    shape.set_item("statements", f.shape.statements)?;
    shape.set_item("ast_nodes", f.shape.nodes)?;
    shape.set_item("truncated", f.shape.truncated)?;
    let tags = PyDict::new(py);
    for (tag, count) in &f.shape.tag_counts {
        tags.set_item(*tag, count)?;
    }
    shape.set_item("tag_counts", tags)?;
    out.set_item("shape", shape)?;

    let halstead = PyDict::new(py);
    halstead.set_item("distinct_operators", f.halstead.distinct_operators)?;
    halstead.set_item("distinct_operands", f.halstead.distinct_operands)?;
    halstead.set_item("total_operators", f.halstead.total_operators)?;
    halstead.set_item("total_operands", f.halstead.total_operands)?;
    halstead.set_item("vocabulary", f.halstead.vocabulary())?;
    halstead.set_item("length", f.halstead.length())?;
    halstead.set_item("volume", f.halstead.volume())?;
    halstead.set_item("difficulty", f.halstead.difficulty())?;
    halstead.set_item("effort", f.halstead.effort())?;
    out.set_item("halstead", halstead)?;

    Ok(out)
}

/// Measure one translation unit of C.
///
/// Returns the whole report as nested plain data. Total on every input: a file
/// that is not C at all yields zero functions and the diagnostics saying so,
/// never an exception.
#[pyfunction]
#[pyo3(name = "analyze")]
pub fn analyze_py<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyDict>> {
    // Pure Rust with no Python object access, and a whole-tree caller runs this
    // over thousands of files, so it has no business holding the GIL.
    let (report, diagnostics) = py.detach(|| metrics::analyze(text).into_parts());
    report_dict(py, &report, &diagnostics, text)
}

/// The functions a file defines, without measuring any of them.
///
/// One parse and no graph construction, for the common case of listing what is
/// in a file before deciding what to measure.
#[pyfunction]
#[pyo3(name = "functions")]
pub fn functions_py<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyList>> {
    let found = py.detach(|| {
        let tree = parse(text).into_parts().0;
        let index = metrics::LineIndex::new(text);
        tree.functions(text)
            .into_iter()
            .map(|f| {
                (
                    f.name,
                    f.span.lo,
                    f.span.hi,
                    index.line(f.span.lo),
                    index.line(f.span.hi.saturating_sub(1).max(f.span.lo)),
                    f.body.is_some(),
                )
            })
            .collect::<Vec<_>>()
    });

    let out = PyList::empty(py);
    for (name, start, end, first_line, last_line, has_body) in found {
        let entry = PyDict::new(py);
        entry.set_item("name", name)?;
        entry.set_item("start", start)?;
        entry.set_item("end", end)?;
        entry.set_item("first_line", first_line)?;
        entry.set_item("last_line", last_line)?;
        entry.set_item("has_body", has_body)?;
        out.append(entry)?;
    }
    Ok(out)
}

/// Serialize one general CFG.
fn cfg_dict<'py>(py: Python<'py>, cfg: &Cfg) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);
    let nodes = PyList::empty(py);
    for (index, node) in cfg.nodes().iter().enumerate() {
        let entry = PyDict::new(py);
        entry.set_item("id", index as u32)?;
        entry.set_item("kind", node.kind().name())?;
        entry.set_item("start", node.span().lo)?;
        entry.set_item("end", node.span().hi)?;
        nodes.append(entry)?;
    }
    out.set_item("nodes", nodes)?;

    let edges = PyList::empty(py);
    for edge in cfg.edges() {
        let entry = PyDict::new(py);
        entry.set_item("src", edge.src.raw())?;
        entry.set_item("dst", edge.dst.raw())?;
        entry.set_item("kind", edge.kind.name())?;
        entry.set_item("back", edge.is_back)?;
        edges.append(entry)?;
    }
    out.set_item("edges", edges)?;
    out.set_item("entry", cfg.entry().raw())?;
    out.set_item("exit", cfg.exit().raw())?;
    Ok(out)
}

/// Every function's **general** control-flow graph: the graph a person would
/// draw.
///
/// This is not
/// [`crate::python_bindings::source_cfg::parity_cfgs_py`], and the difference
/// matters. That one reproduces another tool's artifacts so a similarity metric
/// can be compared against it --- coalesced expression chains, a function-end
/// node deleted when it stayed a singleton, entry and exit as flags. This one
/// has real successors, real join points, real loop back edges, and typed
/// nodes and edges. Use this to look at control flow; use that one only to
/// reproduce a score.
///
/// A list rather than a name-keyed dict: two definitions in one file can carry
/// the same name after recovery, and a dict would silently drop one.
#[pyfunction]
#[pyo3(name = "control_flow_graphs")]
pub fn control_flow_graphs_py<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyList>> {
    let graphs = py.detach(|| {
        let tree = parse(text).into_parts().0;
        crate::csource::cfg::function_cfgs(&tree, text).into_parts().0
    });
    let out = PyList::empty(py);
    for graph in &graphs {
        let entry = PyDict::new(py);
        entry.set_item("name", graph.name.clone())?;
        entry.set_item("start", graph.span.lo)?;
        entry.set_item("end", graph.span.hi)?;
        entry.set_item("short_circuits", graph.short_circuits)?;
        entry.set_item("cfg", cfg_dict(py, &graph.cfg)?)?;
        out.append(entry)?;
    }
    Ok(out)
}

/// The names of the numbers [`features_py`] returns, in the order it returns
/// them.
///
/// A fixed, ordered, documented vector is the point: a caller stacking rows for
/// a hundred thousand functions needs the column meaning to be stable across
/// releases and identical across files.
pub const FEATURE_NAMES: &[&str] = &[
    // size
    "lines",
    "code_lines",
    "tokens",
    "bytes",
    "parameters",
    // graph
    "cfg_nodes",
    "cfg_edges",
    "reachable_nodes",
    "dead_end_nodes",
    "cyclomatic",
    "decision_points",
    "back_edges",
    "loops",
    // shape
    "max_nesting",
    "max_loop_depth",
    "cognitive",
    "calls",
    "statements",
    "ast_nodes",
    "short_circuits",
    "unreachable_statements",
    // halstead
    "halstead_distinct_operators",
    "halstead_distinct_operands",
    "halstead_total_operators",
    "halstead_total_operands",
    "halstead_vocabulary",
    "halstead_length",
    "halstead_volume",
    "halstead_difficulty",
    "halstead_effort",
    // node-kind census, in `NodeKind` discriminant order
    "nodes_entry",
    "nodes_exit",
    "nodes_stmt",
    "nodes_cond",
    "nodes_loop_header",
    "nodes_switch",
    "nodes_case",
    "nodes_label",
    "nodes_goto",
    "nodes_break",
    "nodes_continue",
    "nodes_return",
    "nodes_diverge",
];

/// The node-kind census columns, in the order [`FEATURE_NAMES`] lists them.
const KIND_COLUMNS: &[&str] = &[
    "entry",
    "exit",
    "stmt",
    "cond",
    "loop_header",
    "switch",
    "case",
    "label",
    "goto",
    "break",
    "continue",
    "return",
    "diverge",
];

/// One function's feature row.
fn feature_row(f: &FunctionMetrics) -> Vec<f64> {
    let mut row = vec![
        f64::from(f.size.lines),
        f64::from(f.size.code_lines),
        f64::from(f.size.tokens),
        f64::from(f.size.bytes),
        f64::from(f.parameters),
        f64::from(f.graph.nodes),
        f64::from(f.graph.edges),
        f64::from(f.graph.reachable_nodes),
        f64::from(f.graph.dead_end_nodes),
        f64::from(f.graph.cyclomatic),
        f64::from(f.graph.decision_points),
        f64::from(f.graph.back_edges),
        f64::from(f.graph.loops),
        f64::from(f.shape.max_nesting),
        f64::from(f.shape.max_loop_depth),
        f64::from(f.shape.cognitive),
        f64::from(f.shape.calls),
        f64::from(f.shape.statements),
        f64::from(f.shape.nodes),
        f64::from(f.short_circuits),
        f64::from(f.unreachable_statements),
        f64::from(f.halstead.distinct_operators),
        f64::from(f.halstead.distinct_operands),
        f64::from(f.halstead.total_operators),
        f64::from(f.halstead.total_operands),
        f64::from(f.halstead.vocabulary()),
        f64::from(f.halstead.length()),
        f.halstead.volume(),
        f.halstead.difficulty(),
        f.halstead.effort(),
    ];
    for column in KIND_COLUMNS {
        let count = f
            .graph
            .node_kinds
            .iter()
            .find(|(kind, _)| kind.name() == *column)
            .map(|(_, count)| *count)
            .unwrap_or(0);
        row.push(f64::from(count));
    }
    row
}

/// The feature-vector column names.
#[pyfunction]
#[pyo3(name = "feature_names")]
pub fn feature_names_py() -> Vec<&'static str> {
    FEATURE_NAMES.to_vec()
}

/// One fixed-width numeric row per function, for a corpus-scale consumer.
///
/// Returns `[(name, [f64; len(feature_names())]), ...]` in source order --- the
/// same data [`analyze_py`] reports, flattened.
///
/// **It exists for the stable column vector, not for speed.** Measured over
/// `tests/decompiler_fixtures/src` (196 files, 900 functions, 0.78 MB) with a
/// `maturin develop --release` build, best of five:
///
/// ```text
/// analyze   43.8 ms
/// features  41.3 ms     0.94x
/// ```
///
/// Parsing and graph construction dominate; building the nested dicts is 6% of
/// the run, not most of it. What this buys is a row whose meaning is fixed by
/// [`FEATURE_NAMES`] and does not move when the report's dict schema gains a
/// key.
#[pyfunction]
#[pyo3(name = "features")]
pub fn features_py<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyList>> {
    let rows = py.detach(|| {
        let report = metrics::analyze(text).into_parts().0;
        report
            .functions
            .iter()
            .map(|f| (f.name.clone(), feature_row(f)))
            .collect::<Vec<_>>()
    });
    let out = PyList::empty(py);
    for (name, row) in rows {
        out.append((name, row))?;
    }
    Ok(out)
}

/// Apply the one text normalization pass a dialect is allowed to go through.
///
/// `dialect` is `"preprocessed"` for a gcc-preprocessed translation unit, or
/// `"decompiled"` for a decompiler backend's output. Anything else is a
/// `ValueError` rather than a silent pass-through: normalizing the wrong side
/// reshapes what the parser sees, and a typo that quietly did nothing would be
/// invisible in every number downstream.
///
/// Exposed as its own function rather than as a flag on [`analyze_py`] because
/// normalization **rewrites the text**, so every byte offset a report carries
/// refers to the normalized string and not to the caller's original. Making
/// that a separate step means the caller holds the string its offsets describe.
#[pyfunction]
#[pyo3(name = "normalize")]
pub fn normalize_py(py: Python<'_>, text: &str, dialect: &str) -> PyResult<String> {
    use crate::csource::normalize::Dialect;
    let dialect = match dialect {
        "preprocessed" => Dialect::Preprocessed(text),
        "decompiled" => Dialect::Decompiled(text),
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown dialect {other:?}; expected \"preprocessed\" or \"decompiled\""
            )))
        }
    };
    Ok(py.detach(|| dialect.normalize()))
}

/// Serialize each function's graph in one of four wire formats.
///
/// The replacement for `joern-export --repr {ast,cfg} --format {dot,graphml,
/// ...}`, minus the three representations that need a data-dependence
/// analysis this front end does not do. `cdg`, `ddg` and `pdg` raise rather
/// than returning a control-flow graph under another name.
///
/// `repr` is `"cfg"` (the general control-flow graph, never the Joern-parity
/// one) or `"ast"`. `format` is `"dot"`, `"graphml"`, `"json"` or `"mermaid"`.
///
/// Returns one `(function name, serialized graph)` pair per function, in
/// source order. A list rather than a dict, because two definitions in one
/// file can carry the same name after recovery.
#[pyfunction]
#[pyo3(name = "export_graphs")]
pub fn export_graphs_py<'py>(
    py: Python<'py>,
    text: &str,
    repr: &str,
    format: &str,
) -> PyResult<Bound<'py, PyList>> {
    use crate::csource::export::{export, Repr};
    use crate::syntax::graph_export::{write, Format};

    let repr_value = Repr::parse(repr).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "unknown repr {repr:?}; expected one of {:?}",
            Repr::ALL.map(|r| r.name())
        ))
    })?;
    let format_value = Format::parse(format).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "unknown format {format:?}; expected one of {:?}",
            Format::ALL.map(|f| f.name())
        ))
    })?;

    let rendered = py.detach(|| {
        export(text, repr_value)
            .into_parts()
            .0
            .iter()
            .map(|view| (view.name.clone(), write(view, format_value)))
            .collect::<Vec<(String, String)>>()
    });

    let out = PyList::empty(py);
    for (name, body) in rendered {
        out.append((name, body))?;
    }
    Ok(out)
}

/// The `repr` and `format` names [`export_graphs_py`] accepts, as two lists.
///
/// A CLI builds its choice lists from these rather than repeating them, so a
/// format added in Rust cannot be missing from the command that offers it.
#[pyfunction]
#[pyo3(name = "export_choices")]
pub fn export_choices_py(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    use crate::csource::export::Repr;
    use crate::syntax::graph_export::Format;

    let out = PyDict::new(py);
    out.set_item("repr", Repr::ALL.map(|r| r.name()).to_vec())?;
    out.set_item("format", Format::ALL.map(|f| f.name()).to_vec())?;
    Ok(out)
}

/// Reaching definitions, uses and dead stores, per function.
///
/// The structured form of `export_graphs(repr="ddg")`, for a caller who wants
/// the answer rather than a rendering of it. Each function is a dict with
/// `name`, `definitions`, `uses`, `edges`, `unresolved_uses` and
/// `dead_stores`; the two defect lists index into the first two.
#[pyfunction]
#[pyo3(name = "data_flow")]
pub fn data_flow_py<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyList>> {
    use crate::csource::dataflow::analyze;

    let flows = py.detach(|| analyze(text).into_parts().0);
    let out = PyList::empty(py);
    for flow in &flows {
        let entry = PyDict::new(py);
        entry.set_item("name", flow.name.clone())?;

        let definitions = PyList::empty(py);
        for definition in &flow.definitions {
            let item = PyDict::new(py);
            item.set_item("name", definition.name.clone())?;
            item.set_item("binding", definition.binding.0)?;
            item.set_item("kind", definition.kind.name())?;
            item.set_item("cfg_node", definition.node)?;
            item.set_item(
                "declared_type",
                definition.declared.as_ref().map(|ty| ty.render()),
            )?;
            item.set_item("start", definition.span.lo)?;
            item.set_item("end", definition.span.hi)?;
            definitions.append(item)?;
        }
        entry.set_item("definitions", definitions)?;

        let uses = PyList::empty(py);
        for use_ in &flow.uses {
            let item = PyDict::new(py);
            item.set_item("name", use_.name.clone())?;
            item.set_item("binding", use_.binding.0)?;
            item.set_item("cfg_node", use_.node)?;
            item.set_item("start", use_.span.lo)?;
            item.set_item("end", use_.span.hi)?;
            uses.append(item)?;
        }
        entry.set_item("uses", uses)?;

        let edges = PyList::empty(py);
        for edge in &flow.edges {
            let item = PyDict::new(py);
            item.set_item("definition", edge.def)?;
            item.set_item("use", edge.use_)?;
            item.set_item("variable", edge.name.clone())?;
            edges.append(item)?;
        }
        entry.set_item("edges", edges)?;
        entry.set_item("unresolved_uses", flow.unresolved_uses.clone())?;
        entry.set_item("dead_stores", flow.dead_stores.clone())?;

        let bindings = PyList::empty(py);
        for (index, name) in flow.names.iter().enumerate() {
            let item = PyDict::new(py);
            item.set_item("name", name.clone())?;
            let ty = flow.types.get(index);
            item.set_item("type", ty.filter(|t| !t.is_empty()).map(|t| t.render()))?;
            item.set_item(
                "specifiers",
                ty.map(|t| t.specifiers.clone()).unwrap_or_default(),
            )?;
            item.set_item("pointer_depth", ty.map(|t| t.pointer_depth).unwrap_or(0))?;
            item.set_item("array_rank", ty.map(|t| t.array_rank).unwrap_or(0))?;
            item.set_item("is_const", ty.map(|t| t.is_const).unwrap_or(false))?;
            item.set_item("is_volatile", ty.map(|t| t.is_volatile).unwrap_or(false))?;
            bindings.append(item)?;
        }
        entry.set_item("bindings", bindings)?;
        entry.set_item(
            "type_conflicts",
            flow.type_conflicts().iter().map(|b| b.0).collect::<Vec<u32>>(),
        )?;
        entry.set_item(
            "unused_bindings",
            flow.unused_bindings().iter().map(|b| b.0).collect::<Vec<u32>>(),
        )?;
        out.append(entry)?;
    }
    Ok(out)
}

/// Control dependence and post-dominance, per function.
///
/// Which branch decides each statement, and how deeply each is nested in
/// decisions. The depth is computed on the graph rather than from the syntax,
/// so a `goto` out of a block or a decompiler's flattened dispatch cannot fool
/// it the way counting braces can.
#[pyfunction]
#[pyo3(name = "control_dependence")]
pub fn control_dependence_py<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyList>> {
    use crate::csource::cfg::function_cfgs;
    use crate::syntax::dominance::ControlDependence;

    let built = py.detach(|| {
        let tree = parse(text).into_parts().0;
        let cfgs = function_cfgs(&tree, text).into_parts().0;
        cfgs.iter()
            .map(|function| {
                let cdg = ControlDependence::of(&function.cfg);
                let nodes: Vec<(u32, String, u32, Option<u32>)> = (0..function.cfg.node_count()
                    as u32)
                    .map(|id| {
                        let kind = function
                            .cfg
                            .node(crate::syntax::ids::NodeId::new(id))
                            .map(|node| node.kind().name().to_string())
                            .unwrap_or_default();
                        (
                            id,
                            kind,
                            cdg.depth(id),
                            cdg.post_dominators().immediate(id),
                        )
                    })
                    .collect();
                let edges: Vec<(u32, u32, &'static str)> = cdg
                    .edges()
                    .iter()
                    .map(|edge| (edge.on, edge.node, edge.kind.name()))
                    .collect();
                let stuck: Vec<u32> = cdg.post_dominators().dead_ends().to_vec();
                (function.name.clone(), nodes, edges, stuck)
            })
            .collect::<Vec<_>>()
    });

    let out = PyList::empty(py);
    for (name, nodes, edges, stuck) in built {
        let entry = PyDict::new(py);
        entry.set_item("name", name)?;
        let node_list = PyList::empty(py);
        for (id, kind, depth, ipdom) in nodes {
            let item = PyDict::new(py);
            item.set_item("id", id)?;
            item.set_item("kind", kind)?;
            item.set_item("depth", depth)?;
            item.set_item("ipdom", ipdom)?;
            node_list.append(item)?;
        }
        entry.set_item("nodes", node_list)?;
        let edge_list = PyList::empty(py);
        for (on, node, kind) in edges {
            let item = PyDict::new(py);
            item.set_item("on", on)?;
            item.set_item("node", node)?;
            item.set_item("kind", kind)?;
            edge_list.append(item)?;
        }
        entry.set_item("edges", edge_list)?;
        entry.set_item("unreachable_exit", stuck)?;
        out.append(entry)?;
    }
    Ok(out)
}

/// The backward slice of one function's CFG node, over the program-dependence
/// graph.
///
/// Every node whose execution or value can affect `node`, found by walking
/// control and data dependence backwards to a fixed point.
#[pyfunction]
#[pyo3(name = "backward_slice")]
#[pyo3(signature = (text, function, node))]
pub fn backward_slice_py(
    py: Python<'_>,
    text: &str,
    function: &str,
    node: u32,
) -> PyResult<Vec<u32>> {
    use crate::csource::cfg::function_cfgs;
    use crate::csource::dataflow::analyze_function;
    use crate::syntax::dominance::{backward_slice, ControlDependence};

    let sliced = py.detach(|| {
        let tree = parse(text).into_parts().0;
        let spans = tree.token_spans(text);
        let cfgs = function_cfgs(&tree, text).into_parts().0;
        cfgs.iter()
            .find(|candidate| candidate.name == function)
            .map(|candidate| {
                let cdg = ControlDependence::of(&candidate.cfg);
                let flow = analyze_function(&tree, text, &spans, candidate);
                let data: Vec<(u32, u32)> = flow
                    .edges
                    .iter()
                    .filter_map(|edge| {
                        Some((
                            flow.definitions.get(edge.def as usize)?.node,
                            flow.uses.get(edge.use_ as usize)?.node,
                        ))
                    })
                    .collect();
                backward_slice(&cdg, &data, node)
            })
    });

    sliced.ok_or_else(|| {
        pyo3::exceptions::PyKeyError::new_err(format!("no function named {function:?}"))
    })
}

/// What each function does with the values passed to it, across calls.
///
/// Interprocedural summaries at a fixed point over the call graph: which
/// parameter reaches the return, and which reaches which other parameter. A
/// summary is marked incomplete when the body held something this analysis
/// could not resolve --- an indirect call, or a callee this translation unit
/// does not define --- so a caller inherits `unknown` rather than a clean no.
#[pyfunction]
#[pyo3(name = "call_summaries")]
pub fn call_summaries_py<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyList>> {
    use crate::csource::dataflow::{analyze, summarize, Sink};

    let summaries = py.detach(|| summarize(&analyze(text).into_parts().0));
    let out = PyList::empty(py);
    for summary in summaries.iter() {
        let entry = PyDict::new(py);
        entry.set_item("name", summary.name.clone())?;
        entry.set_item("parameters", summary.parameters)?;
        entry.set_item("complete", summary.complete)?;
        let flows = PyList::empty(py);
        for (index, sink) in &summary.flows {
            let item = PyDict::new(py);
            item.set_item("parameter", *index)?;
            match sink {
                Sink::Return => {
                    item.set_item("sink", "return")?;
                    item.set_item("sink_parameter", py.None())?;
                }
                Sink::Parameter(other) => {
                    item.set_item("sink", "parameter")?;
                    item.set_item("sink_parameter", *other)?;
                }
            }
            flows.append(item)?;
        }
        entry.set_item("flows", flows)?;
        out.append(entry)?;
    }
    Ok(out)
}

/// Whether a value in one function's parameter can reach another function.
///
/// Returns `"yes"`, `"no"` or `"unknown"`. The third is not a failure: an
/// indirect call names no callee and a function defined in another translation
/// unit has no body here, and reporting either as `"no"` would be a claim
/// rather than an analysis.
#[pyfunction]
#[pyo3(name = "reaches")]
#[pyo3(signature = (text, source, parameter, sink))]
pub fn reaches_py(
    py: Python<'_>,
    text: &str,
    source: &str,
    parameter: u32,
    sink: &str,
) -> PyResult<String> {
    use crate::csource::dataflow::{analyze, interproc::reaches, summarize};

    let verdict = py.detach(|| {
        let summaries = summarize(&analyze(text).into_parts().0);
        reaches(&summaries, source, parameter, sink)
    });
    Ok(verdict.name().to_string())
}


/// The bounds every solver-backed query runs under.
///
/// Exposed as keyword arguments rather than a class because there are four
/// knobs anyone actually turns and nine in the struct. The rest keep their
/// defaults, which are sized so a corpus sweep is minutes rather than hours.
///
/// `max_block_visits` is the one to raise first: it is the loop unroll depth,
/// and it is why 510 of 1,131 corpus paths are cut rather than decided.
#[cfg(feature = "symbolic")]
fn bounds_from(
    max_paths: Option<u64>,
    max_block_visits: Option<u32>,
    max_steps: Option<u64>,
    solver_timeout_ms: Option<u64>,
) -> crate::csource::equiv::Bounds {
    let mut bounds = crate::csource::equiv::Bounds::default();
    if let Some(v) = max_paths {
        bounds.max_paths = v;
    }
    if let Some(v) = max_block_visits {
        bounds.max_block_visits = v;
    }
    if let Some(v) = max_steps {
        bounds.max_steps = v;
    }
    if let Some(v) = solver_timeout_ms {
        bounds.solver_timeout_ms = v;
    }
    bounds
}

/// One path verdict as a dict.
#[cfg(feature = "symbolic")]
fn path_entry<'py>(
    py: Python<'py>,
    path: &crate::csource::feasibility::PathVerdict,
) -> PyResult<Bound<'py, PyDict>> {
    use crate::csource::feasibility::Verdict;

    let entry = PyDict::new(py);
    entry.set_item("decisions", path.decisions)?;
    match &path.verdict {
        Verdict::Feasible(w) => {
            entry.set_item("verdict", "feasible")?;
            entry.set_item("args", w.args.clone())?;
            entry.set_item("why", py.None())?;
        }
        Verdict::Infeasible => {
            entry.set_item("verdict", "infeasible")?;
            entry.set_item("args", py.None())?;
            entry.set_item("why", py.None())?;
        }
        Verdict::Unknown(why) => {
            entry.set_item("verdict", "unknown")?;
            entry.set_item("args", py.None())?;
            entry.set_item("why", describe(why))?;
        }
    }
    Ok(entry)
}

/// Everything one `Findings` says, as a dict.
#[cfg(feature = "symbolic")]
fn findings_entry<'py>(
    py: Python<'py>,
    found: &crate::csource::feasibility::Findings,
) -> PyResult<Bound<'py, PyDict>> {
    let report = &found.report;
    let out = PyDict::new(py);
    out.set_item("function", report.name.clone())?;

    let paths = PyList::empty(py);
    for path in &report.paths {
        paths.append(path_entry(py, path)?)?;
    }
    out.set_item("paths", paths)?;
    out.set_item("feasible", report.feasible())?;
    out.set_item("infeasible", report.infeasible())?;
    out.set_item("unknown", report.unknown())?;
    out.set_item("unreachable_blocks", report.unreachable_blocks.clone())?;

    // A cut path carries no verdict, and `total` is what says whether the
    // enumeration covered the function. An `unreachable_blocks` claim is only
    // made when it did; a consumer drawing any other conclusion from a partial
    // enumeration needs to know it was partial.
    let cuts = PyList::empty(py);
    for cut in &report.cuts {
        cuts.append(format!("{cut:?}"))?;
    }
    out.set_item("cuts", cuts)?;
    out.set_item("total", report.cuts.is_empty())?;
    out.set_item(
        "abstained",
        match &report.abstained {
            Some(why) => describe(why).into_pyobject(py)?.into_any(),
            None => py.None().into_bound(py),
        },
    )?;

    let redundant = PyList::empty(py);
    for r in &found.redundant {
        let item = PyDict::new(py);
        item.set_item("path", r.path)?;
        item.set_item("decision", r.decision)?;
        item.set_item("implied_by", r.implied_by)?;
        redundant.append(item)?;
    }
    out.set_item("redundant_guards", redundant)?;

    let violations = PyList::empty(py);
    for v in &found.violations {
        use crate::csource::feasibility::Property;
        let item = PyDict::new(py);
        item.set_item("path", v.path)?;
        match v.property {
            Property::DivisionByZero => {
                item.set_item("property", "division_by_zero")?;
                item.set_item("width", py.None())?;
            }
            Property::ShiftPastWidth { width } => {
                item.set_item("property", "shift_past_width")?;
                item.set_item("width", width)?;
            }
        }
        item.set_item("args", v.witness.args.clone())?;
        violations.append(item)?;
    }
    out.set_item("undefined_behaviour", violations)?;
    Ok(out)
}

/// Everything the solver can say about one function.
///
/// Needs an extension built with the `symbolic` feature, which is deliberately
/// opt-in: `python-ext` bundles the concrete emulator but not the symbolic
/// engine or a solver, and pulling an SMT backend into the default wheel is a
/// packaging decision this binding does not make on its own.
///
/// The **symbol always exists** and the unsupported build raises instead. That
/// is not politeness: `python/glaurung/_native/*.pyi` is generated from the
/// built module and `test_every_stub_matches_the_built_module` requires a
/// byte-for-byte match, so a symbol that appears under one feature set and not
/// another would make the stub describe exactly one build and be stale against
/// the other. One signature, two bodies.
///
/// The function is walked **once** for all four questions; asking them
/// separately would enumerate its paths three more times.
#[cfg(feature = "symbolic")]
#[pyfunction]
#[pyo3(name = "path_feasibility")]
#[pyo3(signature = (text, name, *, max_paths=None, max_block_visits=None, max_steps=None, solver_timeout_ms=None))]
pub fn path_feasibility_py<'py>(
    py: Python<'py>,
    text: &str,
    name: &str,
    max_paths: Option<u64>,
    max_block_visits: Option<u32>,
    max_steps: Option<u64>,
    solver_timeout_ms: Option<u64>,
) -> PyResult<Bound<'py, PyDict>> {
    use crate::csource::feasibility::findings_of;

    let bounds = bounds_from(max_paths, max_block_visits, max_steps, solver_timeout_ms);
    let found = py.detach(|| findings_of(text, name, &bounds));
    findings_entry(py, &found)
}

/// The same entry point on a build without the symbolic engine.
///
/// Raises rather than returning an empty result: "nothing to report" and "this
/// build cannot answer" are different facts, and a caller that cannot tell them
/// apart would record "nothing infeasible" for a function it never examined.
#[cfg(not(feature = "symbolic"))]
#[pyfunction]
#[pyo3(name = "path_feasibility")]
#[pyo3(signature = (text, name, *, max_paths=None, max_block_visits=None, max_steps=None, solver_timeout_ms=None))]
pub fn path_feasibility_py<'py>(
    py: Python<'py>,
    text: &str,
    name: &str,
    max_paths: Option<u64>,
    max_block_visits: Option<u32>,
    max_steps: Option<u64>,
    solver_timeout_ms: Option<u64>,
) -> PyResult<Bound<'py, PyDict>> {
    let _ = (text, name, max_paths, max_block_visits, max_steps, solver_timeout_ms);
    let _ = py;
    Err(unavailable())
}

/// Solver findings for every function in a translation unit that has any.
///
/// The high-level half: `path_feasibility` answers about one function and
/// reports everything including the ordinary case, which is what a caller
/// building its own analysis wants. This answers about a whole file and returns
/// **only functions with something to say** --- an infeasible path, a block no
/// input reaches, a guard an earlier one forces, or an input that makes it
/// execute undefined behaviour. A function whose every path is feasible and
/// whose guards are all load bearing is the ordinary case, and listing it would
/// bury the ones that are not.
///
/// Functions the lowering refuses are skipped rather than listed: "I could not
/// read this" is not a finding about the program. Ask `path_feasibility` by
/// name to see the refusal and the construct it names.
#[cfg(feature = "symbolic")]
#[pyfunction]
#[pyo3(name = "source_findings")]
#[pyo3(signature = (text, *, max_paths=None, max_block_visits=None, max_steps=None, solver_timeout_ms=None))]
pub fn source_findings_py<'py>(
    py: Python<'py>,
    text: &str,
    max_paths: Option<u64>,
    max_block_visits: Option<u32>,
    max_steps: Option<u64>,
    solver_timeout_ms: Option<u64>,
) -> PyResult<Bound<'py, PyList>> {
    use crate::csource::feasibility::findings_of;
    use crate::csource::parse::parse;

    let bounds = bounds_from(max_paths, max_block_visits, max_steps, solver_timeout_ms);
    let found = py.detach(|| {
        let tree = parse(text).into_parts().0;
        let mut out = Vec::new();
        for def in tree.functions(text) {
            if def.name.is_empty() {
                continue;
            }
            let one = findings_of(text, &def.name, &bounds);
            if one.report.abstained.is_some() || one.is_empty() {
                continue;
            }
            out.push(one);
        }
        out
    });

    let list = PyList::empty(py);
    for one in &found {
        list.append(findings_entry(py, one)?)?;
    }
    Ok(list)
}

/// The same entry point on a build without the symbolic engine.
#[cfg(not(feature = "symbolic"))]
#[pyfunction]
#[pyo3(name = "source_findings")]
#[pyo3(signature = (text, *, max_paths=None, max_block_visits=None, max_steps=None, solver_timeout_ms=None))]
pub fn source_findings_py<'py>(
    py: Python<'py>,
    text: &str,
    max_paths: Option<u64>,
    max_block_visits: Option<u32>,
    max_steps: Option<u64>,
    solver_timeout_ms: Option<u64>,
) -> PyResult<Bound<'py, PyList>> {
    let _ = (text, max_paths, max_block_visits, max_steps, solver_timeout_ms);
    let _ = py;
    Err(unavailable())
}

/// The one error both unsupported-build arms raise.
#[cfg(not(feature = "symbolic"))]
fn unavailable() -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(
        "glaurung was built without the `symbolic` feature, so solver-backed \
         source analysis is unavailable; rebuild with `maturin develop -F \
         pyo3/extension-module,python-ext,symbolic`",
    )
}

/// One abstention rendered for a Python consumer.
#[cfg(feature = "symbolic")]
fn describe(why: &crate::csource::feasibility::Unknown) -> String {
    use crate::csource::feasibility::Unknown;
    match why {
        Unknown::NotLowered(what) => format!("not lowered: {what}"),
        Unknown::NoInputSpec => "a parameter is not an integer type".to_string(),
        Unknown::Solver(m) => format!("solver: {m}"),
        Unknown::WitnessDidNotReproduce => "the witness did not reproduce".to_string(),
    }
}

/// Register the `source` submodule on the extension root.
pub fn register_source_metrics_bindings(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "source")?;
    sub.add_function(wrap_pyfunction!(analyze_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(functions_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(control_flow_graphs_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(feature_names_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(features_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(normalize_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(export_graphs_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(export_choices_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(data_flow_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(control_dependence_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(backward_slice_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(call_summaries_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(reaches_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(path_feasibility_py, &sub)?)?;
    sub.add_function(wrap_pyfunction!(source_findings_py, &sub)?)?;
    m.add_submodule(&sub)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The column names and the row builder are two lists that must agree, and
    /// nothing but this test makes them. A mismatch would not fail anywhere:
    /// it would silently shift every column after the missing one, and a
    /// consumer stacking rows would train on scrambled features.
    #[test]
    fn the_feature_names_and_the_feature_row_are_the_same_length() {
        let report = metrics::analyze(
            "int f(int a) { if (a && a) { while (a) { a--; } } return a; }",
        )
        .into_parts()
        .0;
        let function = report.functions.first().expect("one function");
        assert_eq!(
            FEATURE_NAMES.len(),
            feature_row(function).len(),
            "FEATURE_NAMES and feature_row disagree"
        );
    }

    /// Every kind column must name a real `NodeKind`, or it silently reports 0
    /// forever.
    #[test]
    fn every_kind_column_names_a_real_node_kind() {
        use crate::syntax::cfg::NodeKind;
        let known: Vec<&str> = [
            NodeKind::Entry,
            NodeKind::Exit,
            NodeKind::Stmt,
            NodeKind::Cond,
            NodeKind::LoopHeader,
            NodeKind::Switch,
            NodeKind::Case,
            NodeKind::Label,
            NodeKind::Goto,
            NodeKind::Break,
            NodeKind::Continue,
            NodeKind::Return,
            NodeKind::Diverge,
        ]
        .iter()
        .map(|k| k.name())
        .collect();
        for column in KIND_COLUMNS {
            assert!(known.contains(column), "unknown node kind column {column:?}");
        }
        assert_eq!(
            KIND_COLUMNS.len(),
            known.len(),
            "a NodeKind exists that no feature column reports"
        );
    }

    /// A feature row is the same numbers the report carries. If these two paths
    /// ever disagree, one of them is wrong and neither says so.
    #[test]
    fn a_feature_row_agrees_with_the_report_it_flattens() {
        let text = "int f(int a) { for (int i = 0; i < a; i++) { if (i) { a--; } } return a; }";
        let report = metrics::analyze(text).into_parts().0;
        let function = report.functions.first().expect("one function");
        let row = feature_row(function);
        let column = |name: &str| -> f64 {
            let index = FEATURE_NAMES
                .iter()
                .position(|n| *n == name)
                .unwrap_or_else(|| panic!("no column {name}"));
            row[index]
        };
        assert_eq!(column("cyclomatic"), f64::from(function.graph.cyclomatic));
        assert_eq!(column("cognitive"), f64::from(function.shape.cognitive));
        assert_eq!(column("max_nesting"), f64::from(function.shape.max_nesting));
        assert_eq!(column("loops"), f64::from(function.graph.loops));
        assert_eq!(
            column("nodes_loop_header"),
            f64::from(
                *function
                    .graph
                    .node_kinds
                    .iter()
                    .find(|(k, _)| k.name() == "loop_header")
                    .map(|(_, c)| c)
                    .unwrap_or(&0)
            )
        );
    }
}
