"""File-based Joern migration API over committed C fixtures."""

from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from glaurung import source


@pytest.fixture
def networkx_available():
    """Run graph tests only when the optional extra is installed."""
    return pytest.importorskip("networkx", reason="install glaurung[graphs]")


ROOT = Path(__file__).resolve().parents[2]
BRANCHES = ROOT / "tests/decbench_corpus/src/branches.c"
RECURSION = ROOT / "tests/decbench_corpus/src/recursion.c"


def test_cfgs_accept_path_and_keep_networkx_contract(networkx_available):
    graphs = source.fast_cfgs_from_source(BRANCHES)
    assert set(graphs) == {"classify", "nested"}
    graph = graphs["classify"]
    assert (graph.number_of_nodes(), graph.number_of_edges()) == (5, 4)
    assert graph.name == "classify"
    assert graph.graph["path"] == str(BRANCHES)
    assert graph.graph["diagnostics"] == ()
    assert sum(n.is_entrypoint for n in graph) == 1
    for node, attrs in graph.nodes(data=True):
        assert attrs["node"] is node
    for a, b, attrs in graph.edges(data=True):
        assert attrs == {"src": a, "dst": b}


def test_parse_source_exposes_functions_without_joern_process(networkx_available):
    functions = source.parse_source(str(BRANCHES))
    f = functions["nested"]
    assert f.name == "nested"
    assert f.filename == BRANCHES
    assert (f.start_line, f.end_line) == (2, 2)
    assert f.cfg is not None
    assert f.cfg.number_of_nodes() == 5
    assert f.metrics.has_body
    assert f.diagnostics == ()


def test_calls_include_recursion_and_isolated_functions(networkx_available):
    graph = source.parse_callgraph(RECURSION)
    assert set(graph.edges) == {("fib", "fib"), ("ackermann", "ackermann")}
    assert set(source.parse_callgraph(BRANCHES)) == {"classify", "nested"}


def test_directory_keeps_same_names_in_different_files(tmp_path, networkx_available):
    for name in ("a.c", "b.h"):
        shutil.copyfile(BRANCHES, tmp_path / name)
    result = source.parse_source(tmp_path)
    assert len(result) == 4
    assert ("classify", str(tmp_path / "a.c")) in result
    assert ("classify", str(tmp_path / "b.h")) in result
    with pytest.raises(ValueError, match="single file"):
        source.fast_cfgs_from_source(tmp_path)
    with pytest.raises(ValueError, match="single file"):
        source.parse_callgraph(tmp_path)


def test_source_input_is_not_modified(tmp_path, networkx_available):
    path = tmp_path / "branches.c"
    shutil.copyfile(BRANCHES, path)
    before = path.read_bytes()
    source.parse_source(path, is_decompilation=True)
    assert path.read_bytes() == before


def test_missing_file_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        source.fast_cfgs_from_source(tmp_path / "missing.c")


@pytest.mark.parametrize(
    "options", [{"lift_cfgs": False}, {"supergraph": False}, {"timeout": 1}]
)
def test_unsupported_cfg_options_are_explicit(options):
    with pytest.raises(NotImplementedError):
        source.fast_cfgs_from_source(BRANCHES, **options)


@pytest.mark.parametrize(
    "options", [{"no_ddg": False}, {"no_ast": False}, {"no_metadata": True}]
)
def test_unsupported_parse_options_are_explicit(options):
    with pytest.raises(NotImplementedError):
        source.parse_source(BRANCHES, **options)


def test_duplicate_definitions_do_not_pair_unrelated_metadata_and_cfg(tmp_path):
    path = tmp_path / "duplicate.c"
    path.write_bytes(BRANCHES.read_bytes() + BRANCHES.read_bytes())
    with pytest.raises(ValueError, match="duplicate"):
        source.parse_source(path)


def test_diagnostics_are_visible_and_strict_mode_rejects_damage(
    tmp_path, networkx_available
):
    path = tmp_path / "damaged.c"
    path.write_bytes(BRANCHES.read_bytes() + b"\nint broken(")
    with pytest.warns(source.SourceParseWarning):
        graphs = source.fast_cfgs_from_source(path)
    assert graphs["classify"].graph["diagnostics"]
    with pytest.raises(source.SourceParseError) as caught:
        source.parse_source(path, strict=True)
    assert caught.value.diagnostics
    assert caught.value.path == path


def test_no_cfg_does_not_fabricate_graphs():
    functions = source.parse_source(BRANCHES, no_cfg=True)
    assert all(f.cfg is None for f in functions.values())
    with pytest.raises(NotImplementedError):
        _ = functions["classify"].ddg
    with pytest.raises(NotImplementedError):
        _ = functions["classify"].ast


def test_import_and_metadata_only_do_not_load_networkx_or_pyjoern():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import glaurung.source as source; "
            "functions = source.parse_source(sys.argv[1], no_cfg=True); "
            "assert set(functions) == {'classify', 'nested'}; "
            "assert 'networkx' not in sys.modules; assert 'pyjoern' not in sys.modules",
            str(BRANCHES),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
