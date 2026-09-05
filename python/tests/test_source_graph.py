"""Graph export for C source, through `glaurung.source` and the CLI.

The Rust unit tests in `src/syntax/graph_export.rs` and `src/csource/export.rs`
pin the escaping, the totality and the shape of each writer against hand-written
strings. What is here is what only Python can check:

* the **PyO3 boundary**, which can drop a pair or raise on a name it should
  accept;
* that the two formats claiming to be readable by a third party **actually
  load** in NetworkX, which is the whole reason to prefer them over a bespoke
  encoding;
* the **CLI**, including the one flag whose name had to differ from Joern's.

NetworkX is not a dependency of this project -- `glaurung.source_cfg` imports it
lazily for exactly that reason -- so the tests that need it skip rather than
fail when it is absent.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

import glaurung

#: A function with a branch, a loop, a call and two returns, so the exported
#: graph has something in it worth asserting on.
GREET = """
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
"""


@pytest.mark.core
def test_the_choice_lists_come_from_rust():
    """A format added in Rust must appear here without a second edit."""
    assert set(glaurung.source.EXPORT_REPRS) == {"cfg", "ast", "ddg"}
    assert set(glaurung.source.EXPORT_FORMATS) == {
        "dot",
        "graphml",
        "json",
        "mermaid",
    }


@pytest.mark.core
@pytest.mark.parametrize("repr_name", ["cfg", "ast"])
@pytest.mark.parametrize("format_name", ["dot", "graphml", "json", "mermaid"])
def test_every_representation_and_format_produces_a_named_graph(repr_name, format_name):
    graphs = glaurung.source.export_graphs(GREET, repr=repr_name, format=format_name)
    assert len(graphs) == 1
    name, body = graphs[0]
    assert name == "greet"
    assert body.strip()


@pytest.mark.core
def test_an_unknown_repr_or_format_raises_rather_than_guessing():
    """`pdg` and `cdg` need post-dominators, which are not built.

    Returning some other graph under one of those names would be worse than an
    error, so the boundary refuses them. `ddg` was in this list until the
    data-dependence analysis landed; it is now served.
    """
    with pytest.raises(ValueError, match="pdg"):
        glaurung.source.export_graphs(GREET, repr="pdg", format="dot")
    with pytest.raises(ValueError, match="cdg"):
        glaurung.source.export_graphs(GREET, repr="cdg", format="dot")
    with pytest.raises(ValueError, match="graphson"):
        glaurung.source.export_graphs(GREET, repr="cfg", format="graphson")


@pytest.mark.core
def test_export_is_total_on_input_that_is_not_c():
    """No input raises, and a file with no function exports nothing."""
    for junk in ["", "\x00\x01 not C", "int f(", "}}}", "中文"]:
        for repr_name in glaurung.source.EXPORT_REPRS:
            graphs = glaurung.source.export_graphs(junk, repr=repr_name, format="dot")
            assert isinstance(graphs, list)


@pytest.mark.core
def test_a_partly_recovered_file_still_exports_what_parsed():
    text = "int a(void) { return 1; }\nint b(void) { return 2;\n"
    names = [name for name, _ in glaurung.source.export_graphs(text, repr="cfg")]
    assert "a" in names


@pytest.mark.core
def test_the_cfg_export_is_the_general_graph_not_the_parity_one():
    """The two graphs differ, and this one must be the readable one.

    The parity graph coalesces expression chains and deletes a singleton
    function-end node; the general graph keeps entry and exit as real nodes.
    Asserting that the export has strictly more nodes than the parity CFG is
    what would fail if this ever started reading `csource::joern`.
    """
    parity = glaurung._native.csource.parity_cfgs(GREET)["greet"]
    body = dict(glaurung.source.export_graphs(GREET, repr="cfg", format="json"))[
        "greet"
    ]
    exported = json.loads(body)
    assert len(exported["nodes"]) > len(parity["nodes"])
    kinds = {node["kind"] for node in exported["nodes"]}
    assert {"entry", "exit", "loop_header"} <= kinds


@pytest.mark.core
def test_json_round_trips_through_networkx():
    """The `edges` key, not the `links` key NetworkX removed in 3.6."""
    nx = pytest.importorskip("networkx")
    body = dict(glaurung.source.export_graphs(GREET, repr="cfg", format="json"))[
        "greet"
    ]
    data = json.loads(body)
    assert "edges" in data and "links" not in data

    graph = nx.node_link_graph(data)
    assert graph.is_directed()
    assert graph.number_of_nodes() == len(data["nodes"])
    assert graph.number_of_edges() == len(data["edges"])


@pytest.mark.core
def test_graphml_round_trips_through_networkx_with_its_attributes():
    nx = pytest.importorskip("networkx")
    body = dict(glaurung.source.export_graphs(GREET, repr="cfg", format="graphml"))[
        "greet"
    ]
    graph = nx.read_graphml(io.StringIO(body))
    assert graph.number_of_nodes() > 4
    kinds = {data.get("kind") for _, data in graph.nodes(data=True)}
    assert {"entry", "exit", "loop_header"} <= kinds
    # Every node carries a span, which is what makes an exported graph
    # traceable back to the source it came from.
    assert all("span" in data for _, data in graph.nodes(data=True))


@pytest.mark.core
def test_the_ast_export_is_a_tree():
    nx = pytest.importorskip("networkx")
    body = dict(glaurung.source.export_graphs(GREET, repr="ast", format="json"))[
        "greet"
    ]
    graph = nx.node_link_graph(json.loads(body))
    assert graph.number_of_nodes() > 10
    assert nx.is_tree(graph.to_undirected())


@pytest.mark.core
def test_export_path_reads_a_file_lossily(tmp_path: Path):
    """A byte that is not UTF-8 costs the byte, never the file."""
    target = tmp_path / "broken.c"
    target.write_bytes(b'int f(void) { char *s = "\xff\xfe"; return 0; }\n')
    graphs = glaurung.source.export_path(target, repr="cfg", format="dot")
    assert [name for name, _ in graphs] == ["f"]


@pytest.mark.core
def test_mermaid_escapes_what_would_break_a_renderer():
    text = 'int f(void) { puts("a|b"); return 0; }'
    body = dict(glaurung.source.export_graphs(text, repr="cfg", format="mermaid"))["f"]
    assert body.startswith("flowchart TD")
    # A raw `"` or `|` inside a label would end the label early.
    for line in body.splitlines():
        if line.strip().startswith("n") and '["' in line:
            inner = line.split('["', 1)[1].rsplit('"]', 1)[0]
            assert '"' not in inner and "|" not in inner, line


def _cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "glaurung.cli.main", "source-graph", *args],
        capture_output=True,
        text=True,
    )


@pytest.mark.core
def test_the_cli_writes_dot_to_stdout(tmp_path: Path):
    source = tmp_path / "greet.c"
    source.write_text(GREET)
    result = _cli(str(source), "--func", "greet")
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("// ")
    assert 'digraph "greet"' in result.stdout


@pytest.mark.core
def test_the_cli_graph_format_flag_is_not_the_output_format_flag(tmp_path: Path):
    """`--format` belongs to the CLI framework; the graph's is `--graph-format`.

    Both exist, they mean different things, and `json` is a legal value of each.
    A regression that merged them would make `--format json` silently change
    the graph encoding.
    """
    source = tmp_path / "greet.c"
    source.write_text(GREET)
    result = _cli(str(source), "--graph-format", "mermaid")
    assert result.returncode == 0, result.stderr
    assert "flowchart TD" in result.stdout


@pytest.mark.core
def test_the_cli_writes_one_file_per_function(tmp_path: Path):
    source = tmp_path / "two.c"
    source.write_text("int a(void) { return 1; }\nint b(void) { return 2; }\n")
    out = tmp_path / "graphs"
    result = _cli(str(source), "-o", str(out), "--graph-format", "graphml")
    assert result.returncode == 0, result.stderr
    written = sorted(p.name for p in out.glob("*.graphml"))
    assert len(written) == 2
    assert any("-a" in name for name in written)
    assert any("-b" in name for name in written)


@pytest.mark.core
def test_the_cli_reports_a_missing_function_rather_than_exiting_zero(tmp_path: Path):
    source = tmp_path / "greet.c"
    source.write_text(GREET)
    result = _cli(str(source), "--func", "nosuch")
    assert result.returncode == 1
    assert "nosuch" in result.stderr


@pytest.mark.slow
def test_the_whole_fixture_corpus_exports_in_every_format():
    """A boundary that serialized nothing would pass every test above.

    196 files is enough to catch a writer that fails on a construct the small
    inputs do not contain.
    """
    root = Path(__file__).resolve().parents[2] / "tests" / "decompiler_fixtures" / "src"
    sources = sorted(root.glob("*.c"))
    assert len(sources) > 100, f"corpus not found at {root}"

    total = 0
    for path in sources:
        for format_name in glaurung.source.EXPORT_FORMATS:
            graphs = glaurung.source.export_path(path, repr="cfg", format=format_name)
            total += len(graphs)
            for _, body in graphs:
                assert body.strip()
    assert total > 3000, total
