"""The C source metrics, through the Python API `glaurung.source`.

Three layers are covered, because each can be wrong on its own:

* the **PyO3 boundary** (`glaurung._native.source`), which can drop a field, or
  return a dict whose key order is a hash order rather than a `BTreeMap`'s;
* the **Python wrapper** (`glaurung.source`), whose properties reach into the
  nested dicts by name and would raise `KeyError` if either side renamed one;
* the **contract** the wrapper promises -- totality on any input, a stable
  feature-vector width, and a `hotspots` sort that a typo cannot silently skip.

The Rust unit tests in `src/csource/metrics/tests.rs` already pin the *values*
against hand-computed C. What is here is what only Python can check, plus a
corpus pass over `tests/decompiler_fixtures/src` that would catch a boundary
that serialized nothing.
"""

from __future__ import annotations

import csv
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

import glaurung

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = ROOT / "tests" / "decompiler_fixtures" / "src"


# --- the boundary ------------------------------------------------------------


@pytest.mark.core
def test_the_native_submodule_exposes_the_documented_surface():
    """A missing binding is invisible until someone calls it."""
    for name in (
        "analyze",
        "functions",
        "control_flow_graphs",
        "feature_names",
        "features",
        "normalize",
    ):
        assert hasattr(glaurung._native.source, name), f"missing binding: {name}"


@pytest.mark.core
def test_a_report_is_plain_json_serializable_data():
    """The report crosses process and file boundaries in every use case it has
    -- a CI gate's artifact, a dashboard's payload, a corpus dump. If any value
    is a Rust object rather than a plain int/float/str/list/dict, that fails at
    the point of use rather than here."""
    report = glaurung.source.analyze("int f(int a) { return a ? 1 : 0; }")
    encoded = json.dumps(report.to_dict())
    assert json.loads(encoded)["functions"][0]["name"] == "f"


@pytest.mark.core
def test_the_measurement_is_deterministic_across_calls():
    """`REQ-SYN-5`. A census that iterated a hash map would pass every value
    assertion and still produce a different dict order per run, which breaks
    every consumer that diffs two reports."""
    code = (FIXTURES / "03_loop_shapes.c").read_text()
    first = json.dumps(glaurung.source.analyze(code).to_dict(), sort_keys=False)
    second = json.dumps(glaurung.source.analyze(code).to_dict(), sort_keys=False)
    assert first == second


# --- the wrapper -------------------------------------------------------------


@pytest.mark.core
def test_every_wrapper_property_resolves_against_a_real_report():
    """Each property indexes the nested dicts by name. A rename on either side
    is a `KeyError` at first use, so every one of them is touched here rather
    than only the handful a doctest happens to show."""
    report = glaurung.source.analyze(
        "int f(int a, int b) { if (a && b) { while (a) { a -= g(b); } } return a; }",
        name="probe.c",
    )
    assert len(report) == 1
    assert repr(report).startswith("<SourceReport 'probe.c'")
    for attribute in ("lines", "code_lines", "blank_lines", "other_lines"):
        assert isinstance(getattr(report, attribute), int)
    assert isinstance(report.diagnostics, tuple)

    f = report.functions[0]
    assert f.name == "f"
    assert f.has_body is True
    assert f.parameters == 2
    assert f.callees == ["g"]
    assert f.calls == 1
    assert f.loops == 1
    assert f.max_loop_depth == 1
    assert f.cyclomatic >= 2
    assert f.cognitive >= 3
    assert f.max_nesting >= 2
    assert f.first_line == 1 and f.last_line == 1
    assert f.tokens > 0 and f.code_lines == 1 and f.lines == 1
    assert f.statements > 0
    assert f.decision_points >= 2
    assert f.unreachable_statements == 0
    assert f.node_kinds["loop_header"] == 1
    assert f.tag_counts["if_stmt"] == 1
    assert f.halstead["length"] == (
        f.halstead["total_operators"] + f.halstead["total_operands"]
    )
    assert f.halstead_volume > 0 and f.halstead_difficulty > 0
    assert f.halstead_effort == pytest.approx(f.halstead_volume * f.halstead_difficulty)
    assert "cyclomatic=" in repr(f)
    assert f.to_dict() is f.raw


@pytest.mark.core
def test_hotspots_ranks_and_rejects_an_unknown_metric():
    """A misspelled sort key must not quietly return source order: that reads
    as "no function is complex" rather than as the mistake it is."""
    code = (FIXTURES / "03_loop_shapes.c").read_text()
    report = glaurung.source.analyze(code)

    ranked = report.hotspots(by="cognitive", limit=3)
    assert len(ranked) == 3
    scores = [f.cognitive for f in ranked]
    assert scores == sorted(scores, reverse=True)

    everything = report.hotspots(by="cyclomatic", limit=None)
    assert len(everything) == len(report)

    with pytest.raises(ValueError, match="cannot rank by"):
        report.hotspots(by="cyclomatik")


@pytest.mark.core
def test_hotspots_ties_break_on_name_so_the_order_is_reproducible():
    """Several functions in a fixture score identically; without a tie-break the
    order would depend on the sort's stability and the input order."""
    code = "void a(void){} void c(void){} void b(void){}"
    report = glaurung.source.analyze(code)
    assert [f.name for f in report.hotspots(by="cyclomatic", limit=None)] == [
        "a",
        "b",
        "c",
    ]


# --- totality ----------------------------------------------------------------


@pytest.mark.core
@pytest.mark.parametrize(
    "code",
    [
        "",
        "\x00\x00\x00",
        "int f(void) { if (",
        "}}}}}}",
        "not C at all, just prose about C",
        "#define BROKEN(",
        "int f(void) { return 1; } trailing garbage",
    ],
)
def test_analysis_never_raises_on_any_input(code: str):
    """`REQ-SYN-2`. A caller cannot distinguish "this file defines no function"
    from "this file failed" if the second one throws, and both are ordinary
    outcomes when the input is a decompiler's output."""
    report = glaurung.source.analyze(code)
    assert isinstance(report.functions, tuple)
    assert report.raw["bytes"] == len(code.encode())


@pytest.mark.core
def test_one_broken_function_does_not_void_its_siblings():
    """`REQ-ROB-2`, and the property that distinguishes this front end from the
    JVM tool it replaces, where one bad byte costs the whole file."""
    report = glaurung.source.analyze(
        "int broken(void) { if ( } int fine(void) { return 1; }"
    )
    assert any(f.name == "fine" for f in report.functions)


# --- the feature vector ------------------------------------------------------


@pytest.mark.core
def test_every_feature_row_matches_the_declared_column_names():
    """A row that is shorter or longer than the header silently shifts every
    column after the gap, and a consumer stacking rows would never notice."""
    names = glaurung.source.feature_names()
    assert len(names) == len(set(names)), "duplicate feature column"
    code = (FIXTURES / "03_loop_shapes.c").read_text()
    rows = glaurung.source.features(code)
    assert len(rows) == len(glaurung.source.analyze(code))
    for name, row in rows:
        assert isinstance(name, str)
        assert len(row) == len(names), (
            f"{name}: {len(row)} values for {len(names)} columns"
        )
        assert all(isinstance(value, float) for value in row)


@pytest.mark.core
def test_a_feature_row_carries_the_same_numbers_as_the_report():
    """Two code paths compute the same quantities. If they ever disagree, one is
    wrong and nothing else in the suite would say so."""
    code = (FIXTURES / "03_loop_shapes.c").read_text()
    names = list(glaurung.source.feature_names())
    report = glaurung.source.analyze(code)
    rows = dict(glaurung.source.features(code))
    for f in report.functions:
        row = rows[f.name]
        assert row[names.index("cyclomatic")] == f.cyclomatic
        assert row[names.index("cognitive")] == f.cognitive
        assert row[names.index("max_nesting")] == f.max_nesting
        assert row[names.index("lines")] == f.lines
        assert row[names.index("parameters")] == f.parameters


# --- the other entry points --------------------------------------------------


@pytest.mark.core
def test_listing_functions_agrees_with_measuring_them():
    """`functions()` skips graph construction, so it is a second implementation
    of "what is in this file" and can drift from the first."""
    code = (FIXTURES / "03_loop_shapes.c").read_text()
    listed = [f["name"] for f in glaurung.source.functions(code) if f["has_body"]]
    measured = [f.name for f in glaurung.source.analyze(code).functions]
    assert listed == measured


@pytest.mark.core
def test_the_general_cfg_is_not_the_joern_parity_cfg():
    """These two must never be confused: one is the graph a person would draw,
    the other reproduces another tool's artifacts so a score can be compared.
    The general graph has typed nodes and real entry/exit nodes; the parity one
    has neither."""
    code = "int f(int a) { if (a) { return 1; } return 0; }"
    general = glaurung.source.control_flow_graphs(code)
    assert len(general) == 1
    cfg = general[0]["cfg"]
    kinds = {node["kind"] for node in cfg["nodes"]}
    assert "entry" in kinds and "exit" in kinds and "cond" in kinds
    assert all("kind" in edge and "back" in edge for edge in cfg["edges"])

    parity = glaurung.source_cfg.parity_cfgs(code)
    assert "f" in parity
    assert "entry" in parity["f"] and isinstance(parity["f"]["entry"], list), (
        "the parity layer expresses entry as a flag list, not as a node"
    )


@pytest.mark.core
def test_normalize_rejects_an_unknown_dialect():
    """A typo that quietly did nothing would be invisible in every number
    downstream, because the parser accepts un-normalized text too."""
    with pytest.raises(ValueError, match="unknown dialect"):
        glaurung.source.normalize("int f(void){}", "preprocesed")


@pytest.mark.core
def test_a_dialect_report_describes_the_normalized_text():
    """`normalize` rewrites the text, so the report's offsets address the
    normalized string. `SourceReport.source` must therefore hold that string and
    not the caller's original, or every span is off."""
    # A gcc-preprocessed unit: content under a system-header marker is
    # dropped, content under the user file's marker is kept. Both markers are
    # needed, because the stripper starts in the "system" state.
    original = (
        '# 1 "/usr/include/stdio.h" 1\n'
        "int from_a_system_header(void) { return 0; }\n"
        '# 12 "prog.c" 2\n'
        "int f(void) { return 0; }\n"
    )
    report = glaurung.source.analyze(original, dialect="preprocessed")
    assert [f.name for f in report.functions] == ["f"], (
        "the system header's function must be stripped, the user file's kept"
    )
    assert report.source != original
    assert report.raw["bytes"] == len(report.source.encode())
    f = report.functions[0]
    assert report.source[f.raw["start"] : f.raw["end"]].startswith("int f")


@pytest.mark.core
def test_the_preprocessed_dialect_strips_everything_without_a_line_marker():
    """A documented footgun, pinned so it stays documented.

    `strip_system_headers` starts in the "inside a system header" state and
    only keeps lines after a marker naming a non-system file. Ordinary C, which
    has no markers at all, is therefore stripped to nothing. Passing
    `dialect="preprocessed"` for a plain `.c` file yields zero functions and no
    diagnostic, which is exactly the silent-wrong-answer this test exists to
    keep visible.
    """
    plain = "int f(void) { return 0; }\n"
    assert len(glaurung.source.analyze(plain)) == 1
    assert len(glaurung.source.analyze(plain, dialect="preprocessed")) == 0


@pytest.mark.core
def test_analyze_path_reads_a_real_fixture():
    """The path entry point decodes lossily rather than raising, because
    decompiler output is not reliably UTF-8."""
    report = glaurung.source.analyze_path(FIXTURES / "03_loop_shapes.c")
    assert report.name is not None, "analyze_path always names the report"
    assert report.name.endswith("03_loop_shapes.c")
    assert len(report) > 1


# --- the corpus --------------------------------------------------------------


@pytest.mark.core
def test_the_fixture_corpus_measures_through_the_python_api():
    """A boundary that serialized nothing, or that raised on the tenth file,
    would pass every single-snippet test above. Asserted rather than skipped:
    these files are committed to this repository."""
    files = sorted(FIXTURES.glob("*.c"))
    assert len(files) > 100, f"expected the fixture corpus, found {len(files)}"

    functions = 0
    branchy = 0
    for path in files:
        report = glaurung.source.analyze_path(path)
        assert (
            report.code_lines + report.blank_lines + report.other_lines == report.lines
        ), f"line categories must partition {path.name}"
        for f in report.functions:
            functions += 1
            assert f.cyclomatic >= 1, f"{path.name}::{f.name}"
            assert f.cyclomatic <= f.decision_points + 1, f"{path.name}::{f.name}"
            assert f.code_lines <= f.lines, f"{path.name}::{f.name}"
            assert not f.raw["shape"]["truncated"], f"{path.name}::{f.name}"
            if f.cyclomatic > 3:
                branchy += 1

    assert functions > 500, f"only {functions} functions measured"
    assert branchy > 20, "no branchy function in the corpus makes the bounds vacuous"


# --- aggregates --------------------------------------------------------------


@pytest.mark.core
def test_gotos_and_structuredness_track_the_node_census():
    """The decompiler-QA headline: a structurer that gave up emits `goto`."""
    plain = glaurung.source.analyze("void f(int a) { if (a) { a++; } }").functions[0]
    assert plain.gotos == 0 and plain.is_structured is True

    spaghetti = glaurung.source.analyze(
        "void f(int a) { if (a) { goto out; } a++; out: return; }"
    ).functions[0]
    assert spaghetti.gotos == 1
    assert spaghetti.is_structured is False
    assert spaghetti.gotos == spaghetti.node_kinds["goto"]


@pytest.mark.core
def test_summary_aggregates_the_whole_unit():
    """A dashboard row and a build-over-build diff both read this rather than
    re-deriving it, so the keys are part of the contract."""
    report = glaurung.source.analyze_path(FIXTURES / "03_loop_shapes.c")
    summary = report.summary()

    assert summary["functions"] == len(report)
    assert summary["lines"] == report.lines
    assert summary["gotos"] == sum(f.gotos for f in report.functions)
    assert summary["structured_functions"] <= summary["functions"]

    cyclomatic = summary["distributions"]["cyclomatic"]
    values = [f.cyclomatic for f in report.functions]
    assert cyclomatic["min"] == min(values)
    assert cyclomatic["max"] == max(values)
    assert cyclomatic["mean"] == pytest.approx(sum(values) / len(values))
    assert set(summary["distributions"]) == set(glaurung.source._RANKABLE), (
        "every rankable metric must have a distribution"
    )
    assert json.dumps(summary)


@pytest.mark.core
def test_an_empty_unit_reports_no_distributions_rather_than_zeros():
    """A mean of zero over no functions reads like a measurement and is not
    one. The keys stay, the distributions go."""
    summary = glaurung.source.analyze("/* nothing here */").summary()
    assert summary["functions"] == 0
    assert summary["distributions"] == {}
    assert summary["gotos"] == 0


@pytest.mark.core
def test_the_call_graph_keeps_external_edges_and_drops_indirect_ones():
    """Dropping a call to `malloc` would make the graph claim the function
    calls nothing; an indirect call has no name to record at all."""
    code = (
        "void helper(void) { }\n"
        "void caller(struct s *p) { helper(); malloc(1); p->fn(); }\n"
    )
    report = glaurung.source.analyze(code)
    graph = report.call_graph()
    assert graph["helper"] == ()
    assert graph["caller"] == ("helper", "malloc")

    assert report.defined_names() == {"helper", "caller"}
    internal = tuple(n for n in graph["caller"] if n in report.defined_names())
    assert internal == ("helper",)

    caller = next(f for f in report.functions if f.name == "caller")
    assert caller.calls == 3, "the indirect call still counts as a call"
    assert len(caller.callees) == 2, "but contributes no named edge"


# --- comparison --------------------------------------------------------------


@pytest.mark.core
def test_compare_reports_per_function_movement_and_matched_totals():
    """Build-over-build tracking and cross-decompiler comparison are the same
    operation: measure two pieces of C, match by name, read what moved."""
    before = glaurung.source.analyze(
        "int a(int x) { if (x) { return 1; } return 0; }\nint b(int x) { return x; }\n"
    )
    after = glaurung.source.analyze(
        # `a` gains a nested branch and a goto; `b` is untouched; `c` is new.
        "int a(int x) { if (x) { if (x > 1) { goto out; } return 1; } out: return 0; }\n"
        "int b(int x) { return x; }\n"
        "int c(void) { return 0; }\n"
    )
    result = glaurung.source.compare(before, after)

    assert [e["name"] for e in result["matched"]] == ["a", "b"], (
        "matched must be every shared name, ordered by largest movement"
    )
    assert result["added"] == ["c"]
    assert result["removed"] == []

    moved = result["matched"][0]
    assert moved["name"] == "a", "the function that changed must sort first"
    assert moved["deltas"]["gotos"] == 1
    assert moved["deltas"]["cognitive"] > 0
    assert moved["before"]["gotos"] == 0 and moved["after"]["gotos"] == 1

    unchanged = next(e for e in result["matched"] if e["name"] == "b")
    assert all(delta == 0 for delta in unchanged["deltas"].values())

    # Totals cover matched functions only: the new `c` must not be attributed
    # to a regression in the functions that already existed.
    assert result["totals"]["gotos"]["delta"] == 1
    assert result["totals"]["cyclomatic"]["before"] == sum(
        f.cyclomatic for f in before.functions
    )
    assert json.dumps(result)


@pytest.mark.core
def test_compare_rejects_an_unknown_metric():
    """A typo would silently drop a column from the comparison, which reads as
    'nothing moved' for that metric."""
    report = glaurung.source.analyze("int f(void) { return 0; }")
    with pytest.raises(ValueError, match="cannot compare on"):
        glaurung.source.compare(report, report, metrics=("cyclomatik",))


@pytest.mark.core
def test_compare_a_report_with_itself_is_all_zeros():
    """The identity case. If this ever moves, the comparison is reading
    something that is not a property of the source."""
    report = glaurung.source.analyze_path(FIXTURES / "03_loop_shapes.c")
    result = glaurung.source.compare(report, report)
    assert result["added"] == [] and result["removed"] == []
    assert len(result["matched"]) == len(report)
    for entry in result["matched"]:
        assert all(delta == 0 for delta in entry["deltas"].values()), entry["name"]
    for totals in result["totals"].values():
        assert totals["delta"] == 0


# --- the CLI -----------------------------------------------------------------


def _cli(*args: str) -> subprocess.CompletedProcess:
    """Invoke `glaurung source-metrics` out of process.

    Out of process rather than by calling `main()`: the exit code is half of
    what the threshold mode promises, and an in-process call would test the
    function rather than the contract a CI job actually depends on.
    """
    return subprocess.run(
        [sys.executable, "-m", "glaurung.cli", "source-metrics", *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )


@pytest.mark.core
def test_the_cli_prints_a_ranked_table():
    """The default shape: one table across every file, ranked."""
    result = _cli(str(FIXTURES / "03_loop_shapes.c"), "--limit", "3")
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert "function" in lines[1] and "cyc" in lines[1] and "cog" in lines[1]
    assert len([line for line in lines[2:] if line.strip()]) == 3


@pytest.mark.core
def test_the_cli_emits_json_and_csv():
    """Both machine shapes have to parse with the stdlib, or no consumer can
    use them without knowing Glaurung's internals."""
    path = str(FIXTURES / "03_loop_shapes.c")

    as_json = _cli(path, "--json")
    assert as_json.returncode == 0, as_json.stderr
    payload = json.loads(as_json.stdout)
    assert payload[0]["path"].endswith("03_loop_shapes.c")
    assert payload[0]["functions"]

    as_csv = _cli(path, "--csv")
    assert as_csv.returncode == 0, as_csv.stderr
    rows = list(csv.reader(io.StringIO(as_csv.stdout)))
    header = rows[0]
    assert header[:2] == ["path", "function"]
    assert header[2:] == list(glaurung.source.feature_names())
    assert all(len(row) == len(header) for row in rows[1:])


@pytest.mark.core
def test_the_cli_threshold_mode_exits_non_zero_and_names_the_offender():
    """This is the CI-gate contract. A gate that reports violations on stdout
    and still exits 0 is worse than no gate."""
    path = str(FIXTURES / "03_loop_shapes.c")

    passing = _cli(path, "--fail-over", "cyclomatic=1000")
    assert passing.returncode == 0, passing.stderr

    failing = _cli(path, "--fail-over", "cyclomatic=2")
    assert failing.returncode == 1
    assert "threshold violation" in failing.stderr
    assert "cyclomatic" in failing.stderr


@pytest.mark.core
def test_the_cli_rejects_a_malformed_threshold_rather_than_ignoring_it():
    """An unparsed `--fail-over` would leave the gate passing silently."""
    path = str(FIXTURES / "03_loop_shapes.c")
    for bad in ("cyclomatic", "nonsense=3", "cyclomatic=lots"):
        result = _cli(path, "--fail-over", bad)
        assert result.returncode == 2, f"{bad!r} was accepted: {result.stdout}"


@pytest.mark.core
def test_the_cli_walks_a_directory():
    """The corpus use case: point it at a tree, get one ranked table."""
    result = _cli(str(ROOT / "tests" / "decbench_corpus" / "src"), "--limit", "5")
    assert result.returncode == 0, result.stderr
    assert "file(s)" in result.stdout
    assert result.stdout.splitlines()[0].split()[0].isdigit()


@pytest.mark.core
def test_the_cli_summary_mode_reports_one_line_per_file_and_a_total():
    """The whole-tree view: which files carry the complexity, and where the
    unstructured control flow is."""
    result = _cli(str(ROOT / "tests" / "decbench_corpus" / "src"), "--summary")
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert lines[0].split() == [
        "file",
        "fns",
        "lines",
        "maxcyc",
        "maxcog",
        "goto",
        "dead",
    ]
    assert lines[-1].startswith("TOTAL")
    # The total must be the sum of the rows, or the view lies about the tree.
    body = [line.split() for line in lines[1:-1]]
    assert sum(int(row[-6]) for row in body) == int(lines[-1].split()[1])

    as_json = _cli(
        str(ROOT / "tests" / "decbench_corpus" / "src"), "--summary", "--json"
    )
    assert as_json.returncode == 0, as_json.stderr
    payload = json.loads(as_json.stdout)
    assert {"functions", "gotos", "distributions"} <= set(payload[0])
