# C source files and graphs from Python

> **Kind:** guide · **Status:** maintained

Use `glaurung.source` for file-based C parsing, control-flow graphs, and directly
named calls. It runs the Rust parser in the Python process. It needs no Joern
installation, Java runtime, or Graphviz process.

The adapter covers graph topology and basic function metadata. It does not
implement Joern's query language, data-dependence analysis, or JIL statements.

## Install

In a project that uses uv:

```sh
uv add 'glaurung[graphs] @ git+https://github.com/mjbommar/glaurung.git'
```

In a Glaurung checkout, use `uv sync --locked --dev --extra graphs`. The `graphs`
extra installs NetworkX. Importing `glaurung.source` alone does not import NetworkX;
`parse_source(path, no_cfg=True)` works without it.

## Replace the import

For scripts that inspect graph topology, change:

```python
from pyjoern import fast_cfgs_from_source
```

to:

```python
from glaurung.source import fast_cfgs_from_source
```

The file argument stays the same. This example uses a committed C fixture:

```python
from glaurung.source import fast_cfgs_from_source

graphs = fast_cfgs_from_source("tests/decbench_corpus/src/branches.c")
for name, graph in sorted(graphs.items()):
    print(name, graph.number_of_nodes(), graph.number_of_edges())
```

Run from the checkout with `uv run --no-sync --with networkx python`.
Captured with the installed native extension on 2026-09-05:

```text
classify 5 4
nested 5 4
```

Each value is a NetworkX `DiGraph`. Nodes have `id`, `is_entrypoint`, and
`is_exitpoint` attributes. The graph has its function name in `graph.name` and
its absolute input path in `graph.graph["path"]`. Node attribute dictionaries
contain `"node"`; edge attribute dictionaries contain `"src"` and `"dst"`, as
pyjoern's normalized graphs do.

These are the coalesced graphs used by Glaurung's Joern-comparison adapter.
Their shape is not guaranteed to match every Joern release. They omit the
standalone function-end node, so a graph can have no flagged exit node. Node IDs
are local to each function: relabel nodes before merging graphs. Code that
reads `node.statements`, Joern labels, or types needs another analysis.

## Read functions and calls

```python
from glaurung import source

functions = source.parse_source("tests/decbench_corpus/src/branches.c")
function = functions["nested"]
print(function.filename, function.start_line, function.end_line)
print(function.cfg.number_of_nodes())
print(function.metrics.cognitive)

calls = source.parse_callgraph("tests/decbench_corpus/src/recursion.c")
print(sorted(calls.edges))
```

`Function` exposes `name`, `filename`, `start_line`, `end_line`, `callees`,
`cfg`, `metrics`, and `diagnostics`. Set `no_cfg=True` to omit the NetworkX CFG;
`function.cfg` is then `None`. Metrics still build the general control-flow
graph internally. See [source metrics](source-metrics.md) for those fields.

`parse_source(directory)` searches `*.c` and `*.h` recursively. It returns keys
of `(function_name, absolute_filename)` to preserve file-local names. A file
returns keys of `function_name`. Duplicate definitions inside one file raise
`ValueError`, because a name alone cannot pair their metadata and graphs safely.
The lower-level `glaurung.source.analyze_path()` keeps every recovered definition.

`parse_callgraph()` accepts one file. Its nodes are names, including isolated
functions and named external callees. It does not resolve includes or indirect
calls. Directory input raises rather than merging unrelated file-local names.

## Pseudocode and parser failures

Pass `is_decompilation=True` to normalize pseudocode before parsing. The adapter
normalizes in memory and never rewrites the input file. Line numbers and
positions refer to the normalized text.

Parser diagnostics emit `SourceParseWarning`; recovered functions remain
available. Read the diagnostic objects from `function.diagnostics` or
`graph.graph["diagnostics"]`. These diagnostics cover the whole input file.
Each has a severity, message, byte offsets, and a rendered source excerpt.

Pass `strict=True` to raise `SourceParseError` on any diagnostic, including a
warning. The exception keeps `path` and `diagnostics`. Missing or unreadable
files raise an `OSError` subclass. An empty file can return an empty mapping
without a diagnostic. Absence of diagnostics does not prove correct recovery.

## Compatibility limits

| pyjoern behavior or option | Glaurung behavior |
|---|---|
| `fast_cfgs_from_source(path)` | Same file-based calling form and name-to-graph mapping. Nodes carry topology roles, not JIL statements. |
| `lift_cfgs=False` or `supergraph=False` | Raises `NotImplementedError`; the adapter exposes only the coalesced comparison graph. |
| `timeout=120` | Explicit deadlines raise `NotImplementedError`. The default is `None`; run the call in a worker process if you need cancellation. |
| `parse_source(path)` | Returns the documented `Function` subset. Defaults to `no_ddg=True, no_ast=True`, unlike pyjoern. |
| `no_ddg=False`, `no_ast=False`, or `no_metadata=True` | Raises `NotImplementedError`. Accessing `.ddg` or `.ast` also raises. |
| Duplicate names in `fast_cfgs_from_source` | Keeps the graph with more nodes, with the first graph winning ties. |
| `parse_callgraph(directory)` | Raises `ValueError`; use one file at a time. |
| `JoernClient`, `JoernServer`, CPG queries | Not implemented by this adapter. |

The matching pyjoern entrypoints are defined in its
[CFG module](https://github.com/mahaloz/pyjoern/blob/master/pyjoern/cfg/__init__.py)
and [parser module](https://github.com/mahaloz/pyjoern/blob/master/pyjoern/parsing/fast_parser.py).
The implementation here is [the file API](../../python/glaurung/_source_files.py), with
[fixture-backed tests](../../python/tests/test_source_files.py). For general control-flow
metrics, use `glaurung.source`; the comparison graph partitions code differently.
