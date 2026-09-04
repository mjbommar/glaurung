"""Tests for `tools/metric_stratify.py`.

The tool implements `docs/design/metrics-research/what-ged-measures.md`
section 7 item 1: a null-baselined, size-stratified GED report over the
already-published DecBench `published_function_results.json` +
materialized-tree data. It needs nothing but the standard library, so every
test here is `core` except `test_real_corpus_matches_published_evidence`,
which is skipped unless the (multi-gigabyte, git-ignored) DecBench cache is
present on the machine running the suite.

Two kinds of ground truth are used:

* a small synthetic fixture (`_write_fixture`) with every expected number
  worked out by hand in the docstring of
  `test_synthetic_corpus_matches_hand_computed_numbers` -- this is what runs
  in ordinary CI;
* `docs/design/metrics-research/evidence.md`'s `m4.py` output, an already
  published, independently-computed set of numbers over the real corpus --
  this is the real-data regression, gated on `~/.cache/glaurung/decbench-full`
  existing.
"""

from __future__ import annotations

import importlib.util
import json
import math
import types
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = ROOT / "tools" / "metric_stratify.py"
PUBLISHED = (
    Path.home()
    / ".cache"
    / "glaurung"
    / "decbench-full"
    / "published_function_results.json"
)
TREE = Path.home() / ".cache" / "glaurung" / "decbench-full" / "tree"


def _load_tool() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("metric_stratify", TOOL_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def ms() -> types.ModuleType:
    return _load_tool()


# --- band_for / BAND_ORDER -------------------------------------------------
# Boundaries are pinned to `tools/source_cfg_census.py::_bucket`'s
# `(1,1),(2,3),(4,7),(8,15),(16,31),(32,60)` bands plus a ">60" tail, so a
# regression here would also desync this tool's per-band totals from that
# census's `node_count_buckets` -- the cross-check the module docstring's
# "Size bands" section relies on.


@pytest.mark.core
@pytest.mark.parametrize(
    "node_count,expected_band",
    [
        (1, "1"),
        (2, "2-3"),
        (3, "2-3"),
        (4, "4-7"),
        (7, "4-7"),
        (8, "8-15"),
        (15, "8-15"),
        (16, "16-31"),
        (31, "16-31"),
        (32, "32-60"),
        (60, "32-60"),
        (61, ">60"),
        (1000, ">60"),
    ],
)
def test_band_for_matches_source_cfg_census_buckets(
    ms: types.ModuleType, node_count: int, expected_band: str
) -> None:
    assert ms.band_for(node_count) == expected_band


@pytest.mark.core
def test_band_order_is_the_seven_bands_what_ged_measures_reports(
    ms: types.ModuleType,
) -> None:
    # docs/design/metrics-research/what-ged-measures.md section 3's table:
    # "=1 / 2..3 / 4..7 / 8..15 / 16..31 / 32..60 / >=61" (this tool spells
    # the last one ">60", the same set of node counts).
    assert ms.BAND_ORDER == ("1", "2-3", "4-7", "8-15", "16-31", "32-60", ">60")


# --- the null shape ----------------------------------------------------------
# what-ged-measures.md section 2.1 confirms, via `glaurung.source_cfg.parity_cfgs`,
# that `int f(void){return 0;}` parses to
# `{'nodes': [0], 'edges': [], 'entry': [0], 'exit': [0], 'degenerate': False}`
# -- one node, no edges, flagged both entry and exit.


@pytest.mark.core
def test_null_shape_matches_the_return_0_cfg_from_what_ged_measures(
    ms: types.ModuleType,
) -> None:
    assert ms.NULL_SHAPE == ms.NullShape(
        nodes=1, edges=0, has_entry=True, has_exit=True
    )
    return_0_shape = ms.SourceCfgShape(
        nodes=1, edges=0, has_entry=True, has_exit=True, degenerate=False
    )
    assert ms._matches_null(return_0_shape)


@pytest.mark.core
def test_null_shape_rejects_a_one_node_self_loop(ms: types.ModuleType) -> None:
    # A single node with a self-loop is still nodes=1 (same size band as the
    # null shape) but edges=1, not 0 -- the null decompiler's constant output
    # cannot produce it, so it must not count as a null-baseline hit.
    self_loop = ms.SourceCfgShape(
        nodes=1, edges=1, has_entry=True, has_exit=True, degenerate=False
    )
    assert not ms._matches_null(self_loop)


@pytest.mark.core
def test_null_shape_rejects_missing_exit_flag(ms: types.ModuleType) -> None:
    no_exit = ms.SourceCfgShape(
        nodes=1, edges=0, has_entry=True, has_exit=False, degenerate=False
    )
    assert not ms._matches_null(no_exit)


# --- streaming primitives ---------------------------------------------------

_STREAM_DOC: dict[str, Any] = {
    "schema_version": 2,
    "decompilers": ["a", "b"],
    "decompiler_versions": {"a": "1.0", "b": "2.0"},
    "metrics": ["ged", "type_match"],
    "nested": {"x": [1, 2, 3], "y": {"z": 'hello "world" \\ end'}},
    "an_int": 123456789,
    "perfect_values": {"ged": 0.0, "type_match": 1.0},
    "groups": [
        {
            "opt_level": "O0",
            "project": "p1",
            "binary": "b1",
            "functions": [
                {"function": "f1", "values": {"a": {"ged": 0.0}}},
            ],
        },
        {
            "opt_level": "O0",
            "project": "p1",
            "binary": "b2",
            "functions": [
                {
                    "function": "f2",
                    "values": {"a": {"ged": 2.0}, "b": {"ged": 0.0}},
                },
            ],
        },
    ],
    "samples": [{"function": "f1", "source_code": "int f(void){return 0;}"}],
}


@pytest.fixture()
def stream_doc_path(tmp_path: Path) -> Path:
    path = tmp_path / "stream_doc.json"
    path.write_text(json.dumps(_STREAM_DOC, indent=2))
    return path


@pytest.mark.core
@pytest.mark.parametrize("chunk_size", list(range(1, 40)) + [64, 256, 1 << 20])
def test_iter_named_array_matches_json_load_at_every_chunk_size(
    ms: types.ModuleType, stream_doc_path: Path, chunk_size: int
) -> None:
    # Chunk sizes 1-39 deliberately force a buffer refill mid-key, mid-string,
    # mid-object and mid-number -- the exact spots `_decode`'s truncation
    # guard exists for.
    got = list(ms.iter_named_array(stream_doc_path, "groups", chunk_size=chunk_size))
    assert got == _STREAM_DOC["groups"]


@pytest.mark.core
@pytest.mark.parametrize("chunk_size", list(range(1, 40)) + [64, 256, 1 << 20])
def test_read_top_level_scalar_matches_json_load_at_every_chunk_size(
    ms: types.ModuleType, stream_doc_path: Path, chunk_size: int
) -> None:
    assert ms.read_top_level_scalar(
        stream_doc_path, "perfect_values", chunk_size=chunk_size
    ) == {"ged": 0.0, "type_match": 1.0}
    assert (
        ms.read_top_level_scalar(stream_doc_path, "an_int", chunk_size=chunk_size)
        == 123456789
    )
    assert (
        ms.read_top_level_scalar(stream_doc_path, "nested", chunk_size=chunk_size)
        == _STREAM_DOC["nested"]
    )


@pytest.mark.core
def test_read_top_level_scalar_number_is_not_truncated_at_the_exact_boundary(
    ms: types.ModuleType, stream_doc_path: Path
) -> None:
    # `an_int`'s value "123456789" starts right after the literal `"an_int": `.
    # Pick the chunk size that lands the read buffer's edge on the FIRST
    # digit, so a naive (non-refilling) raw_decode would return 1, not
    # 123456789. This is the specific bug `_decode`'s `end == len(buf)`
    # re-read guard exists to prevent.
    text = stream_doc_path.read_text()
    digit_pos = text.index('"an_int": ') + len('"an_int": ')
    for chunk_size in range(digit_pos, digit_pos + 9):
        value = ms.read_top_level_scalar(
            stream_doc_path, "an_int", chunk_size=chunk_size
        )
        assert value == 123456789, f"truncated at chunk_size={chunk_size}: got {value}"


@pytest.mark.core
def test_read_top_level_scalar_refuses_to_skip_past_groups(
    ms: types.ModuleType, stream_doc_path: Path
) -> None:
    # "samples" is a real top-level key in `_STREAM_DOC`, but it comes AFTER
    # "groups" -- reading it would require fully decoding the (in real files,
    # 89k-function) "groups" array just to skip past it, defeating streaming.
    with pytest.raises(KeyError, match="samples"):
        ms.read_top_level_scalar(stream_doc_path, "samples", chunk_size=8)


@pytest.mark.core
def test_iter_named_array_raises_on_missing_key(
    ms: types.ModuleType, stream_doc_path: Path
) -> None:
    with pytest.raises(KeyError, match="nonexistent"):
        list(ms.iter_named_array(stream_doc_path, "nonexistent", chunk_size=64))


# --- synthetic corpus: hand-computed end-to-end numbers ---------------------


def _write_source_cfg(
    path: Path,
    opt: str,
    project: str,
    binary: str,
    functions: dict[str, dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {"opt": opt, "project": project, "binary": binary, "functions": functions}
        )
    )


def _write_fixture(tmp_path: Path) -> tuple[Path, Path]:
    """A tiny corpus with every expected `stratify()` number hand-computed below.

    Source CFGs (tree/O0/proj1/source_cfgs/{bin1,bin2}.json):

      bin1: f_null      1 node, 0 edges, entry+exit  -> band "1", matches NULL_SHAPE
            f_selfloop  1 node, 1 edge,  entry+exit  -> band "1", does NOT match null
            f_deg       degenerate=True               -> excluded entirely
            f_small     3 nodes                        -> band "2-3"
      bin2: g_mid        10 nodes                       -> band "8-15"

    Scored population N = 4 (f_deg excluded as degenerate).
    Null perfect: only f_null -> null_perfect_total=1, null_pct = 1/4*100 = 25.0%.

    published_function_results.json groups (metric "ged", perfect==0.0):

      bin1: f_null      {a: 0.0 (perfect), b: 5.0 (not)}
            f_selfloop  {a: 0.0 (perfect), b: 0.0 (perfect)}
            f_deg       {a: 0.0}                (degenerate source -> excluded)
            f_small     {a: 2.0 (not),     b: 0.0 (perfect)}
            f_missing   {a: 0.0}                (no source CFG -> excluded)
      bin2: g_mid        {a: 0.0 (perfect), c: 3.0 (not)}

    Decompiler "a" is scored on all 4 in-population functions and is perfect
    on 3 (f_null, f_selfloop, g_mid):
      perfect_pct_common = 3/4*100      = 75.0
      perfect_pct_own    = 3/4*100      = 75.0   (full coverage)
      excess_pts         = 75.0 - 25.0  = 50.0
      skill_score         = 50.0 / (100 - 25.0) = 0.666666...

    Decompiler "b" is scored on 3 (f_null, f_selfloop, f_small; not g_mid) and
    is perfect on 2 (f_selfloop, f_small):
      perfect_pct_common = 2/4*100 = 50.0
      perfect_pct_own    = 2/3*100 = 66.666...
      excess_pts          = 50.0 - 25.0 = 25.0
      skill_score          = 25.0 / 75.0 = 0.333333...

    Decompiler "c" is scored on 1 (g_mid) and is perfect on 0:
      perfect_pct_common = 0/4*100 = 0.0
      perfect_pct_own    = 0/1*100 = 0.0
      excess_pts          = 0.0 - 25.0 = -25.0
      skill_score          = -25.0 / 75.0 = -0.333333...
    """
    tree = tmp_path / "tree"
    _write_source_cfg(
        tree / "O0" / "proj1" / "source_cfgs" / "bin1.json",
        "O0",
        "proj1",
        "bin1",
        {
            "f_null": {
                "nodes": [0],
                "edges": [],
                "entry": [0],
                "exit": [0],
                "degenerate": False,
                "labels": {},
            },
            "f_selfloop": {
                "nodes": [0],
                "edges": [[0, 0]],
                "entry": [0],
                "exit": [0],
                "degenerate": False,
                "labels": {},
            },
            "f_deg": {
                "nodes": [],
                "edges": [],
                "entry": [],
                "exit": [],
                "degenerate": True,
                "labels": {},
            },
            "f_small": {
                "nodes": [0, 1, 2],
                "edges": [[0, 1], [1, 2]],
                "entry": [0],
                "exit": [2],
                "degenerate": False,
                "labels": {},
            },
        },
    )
    _write_source_cfg(
        tree / "O0" / "proj1" / "source_cfgs" / "bin2.json",
        "O0",
        "proj1",
        "bin2",
        {
            "g_mid": {
                "nodes": list(range(10)),
                "edges": [[i, i + 1] for i in range(9)],
                "entry": [0],
                "exit": [9],
                "degenerate": False,
                "labels": {},
            },
        },
    )

    results = tmp_path / "published_function_results.json"
    results.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "perfect_values": {"ged": 0.0, "type_match": 1.0},
                "groups": [
                    {
                        "opt_level": "O0",
                        "project": "proj1",
                        "binary": "bin1",
                        "functions": [
                            {
                                "function": "f_null",
                                "values": {"a": {"ged": 0.0}, "b": {"ged": 5.0}},
                            },
                            {
                                "function": "f_selfloop",
                                "values": {"a": {"ged": 0.0}, "b": {"ged": 0.0}},
                            },
                            {"function": "f_deg", "values": {"a": {"ged": 0.0}}},
                            {
                                "function": "f_small",
                                "values": {"a": {"ged": 2.0}, "b": {"ged": 0.0}},
                            },
                            {"function": "f_missing", "values": {"a": {"ged": 0.0}}},
                        ],
                    },
                    {
                        "opt_level": "O0",
                        "project": "proj1",
                        "binary": "bin2",
                        "functions": [
                            {
                                "function": "g_mid",
                                "values": {"a": {"ged": 0.0}, "c": {"ged": 3.0}},
                            },
                        ],
                    },
                ],
                "samples": [],
            },
            indent=2,
        )
    )
    return results, tree


@pytest.mark.core
def test_synthetic_corpus_matches_hand_computed_numbers(
    ms: types.ModuleType, tmp_path: Path
) -> None:
    results, tree = _write_fixture(tmp_path)
    report = ms.stratify(results, tree)

    pop = report["population"]
    assert pop["groups"] == 2
    assert pop["functions_seen"] == 6  # 5 in bin1 + 1 in bin2
    assert pop["functions_without_source_cfg"] == 1  # f_missing
    assert pop["functions_degenerate"] == 1  # f_deg
    assert pop["functions_scored_population"] == 4

    assert report["band_totals"] == {
        "1": 2,
        "2-3": 1,
        "4-7": 0,
        "8-15": 1,
        "16-31": 0,
        "32-60": 0,
        ">60": 0,
    }
    assert report["null"]["perfect_by_band"]["1"] == 1  # f_null only
    assert report["null"]["perfect_total"] == 1
    assert report["null"]["perfect_pct"] == pytest.approx(25.0)

    a = report["decompilers"]["a"]
    assert a["scored_total"] == 4
    assert a["perfect_total"] == 3
    assert a["perfect_pct_common"] == pytest.approx(75.0)
    assert a["perfect_pct_own"] == pytest.approx(75.0)
    assert a["excess_pts"] == pytest.approx(50.0)
    assert a["skill_score"] == pytest.approx(2.0 / 3.0)
    assert a["perfect_pct_common_by_band"]["1"] == pytest.approx(100.0)
    assert a["perfect_pct_common_by_band"]["2-3"] == pytest.approx(0.0)
    assert a["perfect_pct_common_by_band"]["8-15"] == pytest.approx(100.0)

    b = report["decompilers"]["b"]
    assert b["scored_total"] == 3
    assert b["perfect_total"] == 2
    assert b["perfect_pct_common"] == pytest.approx(50.0)
    assert b["perfect_pct_own"] == pytest.approx(200.0 / 3.0)
    assert b["excess_pts"] == pytest.approx(25.0)
    assert b["skill_score"] == pytest.approx(1.0 / 3.0)
    assert b["perfect_pct_common_by_band"]["1"] == pytest.approx(
        50.0
    )  # f_selfloop only
    assert b["perfect_pct_common_by_band"]["8-15"] == pytest.approx(0.0)  # not scored

    c = report["decompilers"]["c"]
    assert c["scored_total"] == 1
    assert c["perfect_total"] == 0
    assert c["perfect_pct_common"] == pytest.approx(0.0)
    assert c["perfect_pct_own"] == pytest.approx(0.0)
    assert c["excess_pts"] == pytest.approx(-25.0)
    assert c["skill_score"] == pytest.approx(-1.0 / 3.0)

    # "a" beats null everywhere and outranks "b" and "c" on every accounting
    # (own%: 75.0 > 66.67 > 0.0; same-population%/skill: 75.0 > 50.0 > 0.0);
    # this fixture does not exercise the coverage-driven ranking FLIP the
    # real-corpus test below does (claude-code/codex rank 1st-2nd by own%
    # but 9th-10th by same-population% -- see
    # `test_real_corpus_matches_published_evidence`).
    assert report["ranking_raw"] == ["a", "b", "c"]
    assert report["ranking_skill"] == ["a", "b", "c"]
    assert report["ranking_own"] == ["a", "b", "c"]


@pytest.mark.core
def test_functions_without_values_field_do_not_crash(
    ms: types.ModuleType, tmp_path: Path
) -> None:
    """A function entry with no `"values"` key at all (a decompiler run that
    produced nothing for it) must be counted in the population but score
    zero everywhere, not raise."""
    tree = tmp_path / "tree"
    _write_source_cfg(
        tree / "O0" / "p" / "source_cfgs" / "b.json",
        "O0",
        "p",
        "b",
        {
            "f": {
                "nodes": [0],
                "edges": [],
                "entry": [0],
                "exit": [0],
                "degenerate": False,
                "labels": {},
            }
        },
    )
    results = tmp_path / "results.json"
    results.write_text(
        json.dumps(
            {
                "perfect_values": {"ged": 0.0},
                "groups": [
                    {
                        "opt_level": "O0",
                        "project": "p",
                        "binary": "b",
                        "functions": [{"function": "f"}],
                    }
                ],
            }
        )
    )
    report = ms.stratify(results, tree)
    assert report["population"]["functions_scored_population"] == 1
    assert report["decompilers"] == {}
    assert report["null"]["perfect_total"] == 1


@pytest.mark.core
def test_unknown_metric_raises_key_error(ms: types.ModuleType, tmp_path: Path) -> None:
    results, tree = _write_fixture(tmp_path)
    with pytest.raises(KeyError, match="does-not-exist"):
        ms.stratify(results, tree, metric="does-not-exist")


@pytest.mark.core
def test_alternate_metric_uses_its_own_perfect_value(
    ms: types.ModuleType, tmp_path: Path
) -> None:
    # type_match's perfect value is 1.0, not 0.0 -- the whole point of
    # reading `perfect_values[metric]` from the document instead of
    # hard-coding 0.0 (see the module docstring's "The null baseline"
    # section and `read_top_level_scalar`).
    tree = tmp_path / "tree"
    _write_source_cfg(
        tree / "O0" / "p" / "source_cfgs" / "b.json",
        "O0",
        "p",
        "b",
        {
            "f": {
                "nodes": [0],
                "edges": [],
                "entry": [0],
                "exit": [0],
                "degenerate": False,
                "labels": {},
            }
        },
    )
    results = tmp_path / "results.json"
    results.write_text(
        json.dumps(
            {
                "perfect_values": {"ged": 0.0, "type_match": 1.0},
                "groups": [
                    {
                        "opt_level": "O0",
                        "project": "p",
                        "binary": "b",
                        "functions": [
                            {
                                "function": "f",
                                "values": {"x": {"ged": 9.0, "type_match": 1.0}},
                            }
                        ],
                    }
                ],
            }
        )
    )
    report = ms.stratify(results, tree, metric="type_match")
    assert report["perfect_value"] == 1.0
    assert report["decompilers"]["x"]["perfect_total"] == 1


@pytest.mark.core
def test_deterministic_output_regardless_of_decompiler_insertion_order(
    ms: types.ModuleType, tmp_path: Path
) -> None:
    """Feed the decompiler names in a different order per function and
    confirm the report's decompiler ordering is always alphabetically
    sorted -- the "no dict-iteration order reaching the report" requirement."""
    tree = tmp_path / "tree"
    _write_source_cfg(
        tree / "O0" / "p" / "source_cfgs" / "b.json",
        "O0",
        "p",
        "b",
        {
            name: {
                "nodes": [0],
                "edges": [],
                "entry": [0],
                "exit": [0],
                "degenerate": False,
                "labels": {},
            }
            for name in ("f1", "f2")
        },
    )
    results = tmp_path / "results.json"
    results.write_text(
        json.dumps(
            {
                "perfect_values": {"ged": 0.0},
                "groups": [
                    {
                        "opt_level": "O0",
                        "project": "p",
                        "binary": "b",
                        "functions": [
                            {
                                "function": "f1",
                                "values": {
                                    "zeta": {"ged": 0.0},
                                    "alpha": {"ged": 0.0},
                                    "mu": {"ged": 0.0},
                                },
                            },
                            {
                                "function": "f2",
                                "values": {
                                    "mu": {"ged": 0.0},
                                    "zeta": {"ged": 0.0},
                                    "alpha": {"ged": 0.0},
                                },
                            },
                        ],
                    }
                ],
            }
        )
    )
    report = ms.stratify(results, tree)
    assert list(report["decompilers"]) == ["alpha", "mu", "zeta"]
    # All three tie at 100%, so the alphabetical tiebreak in the sort keys
    # is what fixes the ranking order deterministically.
    assert report["ranking_raw"] == ["alpha", "mu", "zeta"]
    assert report["ranking_skill"] == ["alpha", "mu", "zeta"]
    assert report["ranking_own"] == ["alpha", "mu", "zeta"]

    text = json.dumps(report, sort_keys=True)
    assert '"alpha"' in text and json.loads(text) == report


# --- real-corpus regression, gated on the DecBench cache existing ----------


@pytest.mark.skipif(
    not (PUBLISHED.exists() and TREE.exists()),
    reason="needs ~/.cache/glaurung/decbench-full (published_function_results.json + tree)",
)
def test_real_corpus_matches_published_evidence(ms: types.ModuleType) -> None:
    """Cross-check against `docs/design/metrics-research/evidence.md`'s
    `m4.py` output (section 3), an independently-computed set of numbers over
    the same published data:

        benchmark functions joined to a non-degenerate published source CFG: 89014
        null decompiler (`return 0;` everywhere) -> perfect on 24243 of 89014 = 27.24%
        dewolf     2808  13193  21.28%   3.15%
        ghidra    22716  72961  31.13%  25.52%

    and section 3's per-band table, pooled over all thirteen columns
    (`m4.py` output, "GED zero-rate ... by source node count"):

        nodes>=1   cells=123273  perfect=90.36%
        nodes>=2   cells= 59823  perfect=35.77%
        nodes>=4   cells=103278  perfect=20.26%
        nodes>=8   cells= 98130  perfect= 8.66%
        nodes>=16  cells= 59731  perfect= 3.40%
        nodes>=32  cells= 25961  perfect= 1.10%
        nodes>=61  cells= 16769  perfect= 0.44%

    (that script's "nodes>=N" labels a fixed band starting at N, e.g.
    "nodes>=8" is this tool's "8-15" band, not a cumulative "8 or more"
    count -- `evidence.md` section 2 of `m4.py`'s script confirms the
    bucketing is `8 if n<=15 else ...`.)
    """
    report = ms.stratify(PUBLISHED, TREE)

    pop = report["population"]
    assert pop["functions_scored_population"] == 89014

    null = report["null"]
    assert null["perfect_total"] == 24243
    assert round(null["perfect_pct"], 2) == 27.24

    dewolf = report["decompilers"]["dewolf"]
    assert dewolf["scored_total"] == 13193
    assert dewolf["perfect_total"] == 2808
    assert round(dewolf["perfect_pct_own"], 2) == 21.28
    assert round(dewolf["perfect_pct_common"], 2) == 3.15
    # dewolf's entire GED standing is branchless functions (what-ged-measures.md
    # section 3): every one of its perfect cells is in the "1" band.
    assert dewolf["perfect_by_band"]["1"] == dewolf["perfect_total"]

    ghidra = report["decompilers"]["ghidra"]
    assert ghidra["scored_total"] == 72961
    assert ghidra["perfect_total"] == 22716
    assert round(ghidra["perfect_pct_common"], 2) == 25.52
    # A "well-regarded decompiler drops sharply": Ghidra's same-population
    # perfect% (25.52%) is BELOW the null baseline (27.24%), so it is
    # outscored, net, by `return 0;` on this metric.
    assert ghidra["perfect_pct_common"] < null["perfect_pct"]
    assert ghidra["skill_score"] < 0.0

    # Reconstruct m4.py's pooled-over-all-columns per-band rate from this
    # tool's per-decompiler `perfect_by_band`/`scored_by_band` (sum over
    # every column, divide once) and check it against the table above.
    expected_pooled = {
        "1": (111388, 123273, 90.36),
        "2-3": (21401, 59823, 35.77),
        "4-7": (20928, 103278, 20.26),
        "8-15": (8498, 98130, 8.66),
        "16-31": (2032, 59731, 3.40),
        "32-60": (285, 25961, 1.10),
        ">60": (74, 16769, 0.44),
    }
    decs = report["decompilers"]
    for band, (exp_perfect, exp_scored, exp_pct) in expected_pooled.items():
        pooled_perfect = sum(row["perfect_by_band"][band] for row in decs.values())
        pooled_scored = sum(row["scored_by_band"][band] for row in decs.values())
        assert pooled_perfect == exp_perfect, band
        assert pooled_scored == exp_scored, band
        assert round(100 * pooled_perfect / pooled_scored, 2) == exp_pct, band

    assert not math.isnan(report["null"]["perfect_pct"])

    # The ranking flip the module docstring's "The above-the-null headline"
    # section argues for: claude-code and codex have very low coverage (242
    # and 243 of 89,014 functions), so they rank 1st and 2nd by
    # own-denominator perfect% (55.37%, 53.91% -- higher than every
    # full-coverage column) but 9th and 10th, below the null baseline, once
    # every column is judged on the same population.
    assert report["ranking_own"].index("claude-code") == 0
    assert report["ranking_own"].index("codex") == 1
    assert report["ranking_raw"].index("claude-code") == 8
    assert report["ranking_raw"].index("codex") == 9
    for name in ("claude-code", "codex"):
        assert report["decompilers"][name]["skill_score"] < 0.0
