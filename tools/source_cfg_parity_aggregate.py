#!/usr/bin/env python3
"""Aggregate and audit checkpointed Joern/Glaurung source-CFG parity runs.

The full Joern pass is deliberately sharded because one JVM is started for
every stored decompiled C artifact. This tool refuses to produce a final report
unless the shards cover every complete triple exactly once, their summaries
agree with their JSONL ledgers, and the Glaurung comparison covers the same
stored function identities.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


Identity = tuple[int, str, str, str, str]
EXPECTED_STATUSES = {"exact", "mismatched", "uncovered", "no_source_cfg"}


def identity(row: dict[str, Any]) -> Identity:
    """Return the stable identity carried by every detail row."""
    return (
        int(row["ordinal"]),
        str(row["opt"]),
        str(row["project"]),
        str(row["binary"]),
        str(row["function"]),
    )


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unreadable JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object in {path}")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text().splitlines()
    except OSError as exc:
        raise ValueError(f"unreadable JSONL {path}: {exc}") from exc
    for lineno, line in enumerate(lines, 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL {path}:{lineno}: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"expected an object at {path}:{lineno}")
        rows.append(row)
    return rows


def unique_rows(
    rows: Iterable[dict[str, Any]], statuses: set[str], label: str
) -> dict[Identity, dict[str, Any]]:
    found: dict[Identity, dict[str, Any]] = {}
    for row in rows:
        if row.get("status") not in statuses:
            continue
        key = identity(row)
        if key in found:
            raise ValueError(f"duplicate {label} identity: {key}")
        found[key] = row
    return found


def graph_shape(record: dict[str, Any]) -> dict[str, Any]:
    graph = record.get("provider_graph")
    if not isinstance(graph, dict):
        return {"captured": False}
    roles = graph.get("roles")
    edges = graph.get("edges")
    if not isinstance(roles, list) or not isinstance(edges, list):
        raise ValueError(f"malformed provider graph for {identity(record)}")
    indegree = [0] * len(roles)
    outdegree = [0] * len(roles)
    normalized_edges: list[tuple[int, int]] = []
    for edge in edges:
        if not isinstance(edge, list) or len(edge) != 2:
            raise ValueError(f"malformed edge for {identity(record)}: {edge!r}")
        src, dst = int(edge[0]), int(edge[1])
        if not (0 <= src < len(roles) and 0 <= dst < len(roles)):
            raise ValueError(f"edge outside graph for {identity(record)}: {edge!r}")
        outdegree[src] += 1
        indegree[dst] += 1
        normalized_edges.append((src, dst))
    degree_roles = sorted(
        (indegree[index], outdegree[index], bool(role[0]), bool(role[1]))
        for index, role in enumerate(roles)
    )
    return {
        "captured": True,
        "nodes": len(roles),
        "edges": len(normalized_edges),
        "entries": sum(bool(role[0]) for role in roles),
        "exits": sum(bool(role[1]) for role in roles),
        "degree_roles": degree_roles,
    }


def is_declaration_like_joern_graph(record: dict[str, Any]) -> bool:
    """Whether Joern emitted its characteristic prototype-only CFG.

    Eclipse CDT/Joern exposes declarations as a one-node graph whose sole node
    is both entry and exit.  They are useful parser facts, but they are not
    executable function definitions and must not be reported as coverage gains
    over a provider whose contract is definition CFGs.  Keep this deliberately
    structural: the full-run documentation separately checks DecBench's
    ``// Function:`` markers in the stored text before drawing the stronger
    declaration-versus-definition conclusion.
    """
    graph = record.get("provider_graph")
    return isinstance(graph, dict) and graph.get("roles") == [[True, True]] and not graph.get(
        "edges"
    )


def load_joern_shards(directory: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    reports = sorted(directory.glob("report-*.json"))
    if not reports:
        raise ValueError(f"no reports in {directory}")
    all_rows: list[dict[str, Any]] = []
    starts: list[int] = []
    totals: Counter[str] = Counter()
    failures: list[dict[str, str]] = []
    wall_seconds = 0.0
    max_rss_kb = 0

    for path in reports:
        report = read_json(path)
        if report.get("provider") != "joern":
            raise ValueError(f"not a Joern report: {path}")
        if not report.get("graphs_captured"):
            raise ValueError(f"graph capture missing: {path}")
        start = int(report["start"])
        starts.append(start)
        detail_path = directory / f"details-{start:03d}.jsonl"
        rows = read_jsonl(detail_path)
        expected = sum(row.get("status") in EXPECTED_STATUSES for row in rows)
        gained = sum(row.get("status") == "gained" for row in rows)
        if expected != int(report["cells"]):
            raise ValueError(
                f"{detail_path} has {expected} stored cells, report says {report['cells']}"
            )
        if gained != int(report["gained"]):
            raise ValueError(
                f"{detail_path} has {gained} gains, report says {report['gained']}"
            )
        all_rows.extend(rows)
        for field in (
            "binaries",
            "cells",
            "attempted",
            "exact",
            "mismatched",
            "uncovered",
            "no_source_cfg",
            "gained",
        ):
            totals[field] += int(report[field])
        failures.extend(report.get("provider_failures", []))
        time_path = directory / f"time-{start:03d}.txt"
        if time_path.exists():
            values = dict(
                line.split("=", 1)
                for line in time_path.read_text().splitlines()
                if "=" in line
            )
            wall_seconds += float(values.get("wall_seconds", 0))
            max_rss_kb = max(max_rss_kb, int(values.get("max_rss_kb", 0)))

    expected_starts = list(range(0, 781, 10))
    if starts != expected_starts:
        missing = sorted(set(expected_starts) - set(starts))
        extra = sorted(set(starts) - set(expected_starts))
        raise ValueError(f"incomplete shard sequence: missing={missing}, extra={extra}")
    if totals["binaries"] != 785:
        raise ValueError(f"expected 785 binaries, got {totals['binaries']}")
    if totals["cells"] != 85_645:
        raise ValueError(f"expected 85,645 stored cells, got {totals['cells']}")

    return all_rows, {
        **dict(totals),
        "provider_failures": failures,
        "shards": len(reports),
        "wall_seconds_sum": wall_seconds,
        "max_rss_kb": max_rss_kb,
    }


def classify_difference(joern: dict[str, Any], ours: dict[str, Any]) -> dict[str, Any]:
    joern_status = str(joern["status"])
    ours_status = str(ours["status"])
    expected = float(joern["got"]) if "got" in joern else None
    got = float(ours["got"]) if "got" in ours else None
    jshape = graph_shape(joern)
    oshape = graph_shape(ours)
    if joern_status == "uncovered" and ours_status in {"exact", "mismatched"}:
        category = "joern_uncovered_glaurung_reported"
    elif ours_status == "uncovered" and joern_status in {"exact", "mismatched"}:
        category = "glaurung_uncovered_joern_reported"
    elif joern_status == "no_source_cfg" or ours_status == "no_source_cfg":
        category = "source_cfg_missing"
    elif not jshape["captured"] or not oshape["captured"]:
        category = "missing_graph_evidence"
    elif got == 0.0 and expected != 0.0:
        category = "glaurung_matches_source_isomorphically"
    elif expected == 0.0 and got != 0.0:
        category = "joern_matches_source_isomorphically"
    elif jshape["degree_roles"] == oshape["degree_roles"]:
        category = "same_degree_roles_different_wiring_or_oracle_drift"
    elif jshape["nodes"] != oshape["nodes"] or jshape["edges"] != oshape["edges"]:
        category = "different_graph_size"
    elif jshape["entries"] != oshape["entries"] or jshape["exits"] != oshape["exits"]:
        category = "different_entry_exit_roles"
    else:
        category = "different_degree_distribution"
    return {
        "ordinal": joern["ordinal"],
        "opt": joern["opt"],
        "project": joern["project"],
        "binary": joern["binary"],
        "function": joern["function"],
        "category": category,
        "joern_status": joern_status,
        "glaurung_status": ours_status,
        "joern_ged": expected,
        "glaurung_ged": got,
        "absolute_delta": abs(expected - got)
        if expected is not None and got is not None
        else None,
        "joern_shape": {k: v for k, v in jshape.items() if k != "degree_roles"},
        "glaurung_shape": {k: v for k, v in oshape.items() if k != "degree_roles"},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--joern-shards", type=Path, required=True)
    parser.add_argument("--glaurung-report", type=Path, required=True)
    parser.add_argument("--glaurung-details", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-markdown", type=Path, required=True)
    args = parser.parse_args()

    try:
        joern_rows, joern_summary = load_joern_shards(args.joern_shards)
        glaurung_report = read_json(args.glaurung_report)
        glaurung_rows = read_jsonl(args.glaurung_details)
        if not glaurung_report.get("graphs_captured"):
            raise ValueError("Glaurung report does not contain graph evidence")
        joern_expected = unique_rows(joern_rows, EXPECTED_STATUSES, "Joern")
        ours_expected = unique_rows(glaurung_rows, EXPECTED_STATUSES, "Glaurung")
        if set(joern_expected) != set(ours_expected):
            only_java = len(set(joern_expected) - set(ours_expected))
            only_ours = len(set(ours_expected) - set(joern_expected))
            raise ValueError(
                f"provider populations differ: only_joern={only_java}, "
                f"only_glaurung={only_ours}"
            )
        if len(ours_expected) != int(glaurung_report["cells"]):
            raise ValueError("Glaurung report and ledger cell counts disagree")

        differences = []
        for key in sorted(joern_expected):
            java = joern_expected[key]
            ours = ours_expected[key]
            both_reported = java["status"] in {"exact", "mismatched"} and ours[
                "status"
            ] in {"exact", "mismatched"}
            same_value = both_reported and float(java["got"]) == float(ours["got"])
            if not same_value:
                differences.append(classify_difference(java, ours))
        categories = Counter(row["category"] for row in differences)

        joern_gained = unique_rows(joern_rows, {"gained"}, "Joern gain")
        ours_gained = unique_rows(glaurung_rows, {"gained"}, "Glaurung gain")
        shared_gains = set(joern_gained) & set(ours_gained)
        only_joern_gains = set(joern_gained) - set(ours_gained)
        only_ours_gains = set(ours_gained) - set(joern_gained)
        shared_declaration_like = {
            key for key in shared_gains if is_declaration_like_joern_graph(joern_gained[key])
        }
        only_joern_declaration_like = {
            key
            for key in only_joern_gains
            if is_declaration_like_joern_graph(joern_gained[key])
        }
        only_joern_nontrivial = only_joern_gains - only_joern_declaration_like

        delta_values = [
            row["absolute_delta"]
            for row in differences
            if row["absolute_delta"] is not None
        ]
        result = {
            "joern": joern_summary,
            "glaurung": glaurung_report,
            "comparison": {
                "common_stored_cells": len(joern_expected),
                "equal_ged": len(joern_expected) - len(differences),
                "different_ged": len(differences),
                "difference_categories": dict(sorted(categories.items())),
                "delta_mean": statistics.fmean(delta_values) if delta_values else 0.0,
                "delta_median": statistics.median(delta_values) if delta_values else 0.0,
                "delta_max": max(delta_values, default=0.0),
                "gains_shared": len(shared_gains),
                "gains_shared_declaration_like_joern": len(shared_declaration_like),
                "gains_shared_nontrivial_joern": len(shared_gains)
                - len(shared_declaration_like),
                "gains_only_joern": len(only_joern_gains),
                "gains_only_joern_declaration_like": len(only_joern_declaration_like),
                "gains_only_joern_nontrivial": len(only_joern_nontrivial),
                "gains_only_glaurung": len(only_ours_gains),
            },
            "differences": differences,
            "only_joern_gains": [list(key) for key in sorted(only_joern_gains)],
            "only_glaurung_gains": [list(key) for key in sorted(only_ours_gains)],
        }
        args.output_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

        comparison = result["comparison"]
        lines = [
            "# Full-corpus Joern versus Glaurung source-CFG comparison",
            "",
            f"- Stored cells compared: **{comparison['common_stored_cells']:,}**",
            f"- Equal GED: **{comparison['equal_ged']:,}**",
            f"- Different GED: **{comparison['different_ged']:,}**",
            f"- Joern provider failures: **{len(joern_summary['provider_failures']):,}**",
            f"- Glaurung uncovered cells: **{glaurung_report['uncovered']:,}**",
            f"- Shared additional functions: **{comparison['gains_shared']:,}**",
            f"- Shared nontrivial Joern graphs: **{comparison['gains_shared_nontrivial_joern']:,}**",
            f"- Joern-only declaration-like graphs: **{comparison['gains_only_joern_declaration_like']:,}**",
            f"- Joern-only nontrivial graphs: **{comparison['gains_only_joern_nontrivial']:,}**",
            f"- Additional only in Glaurung: **{comparison['gains_only_glaurung']:,}**",
            "",
            "A declaration-like Joern graph is one entry-and-exit node with no edge.",
            "It is not counted as executable definition coverage. The stored-text",
            "marker audit belongs in the campaign record because graph shape alone",
            "cannot prove whether a syntactically tiny function has a body.",
            "",
            "## Difference categories",
            "",
            "| Category | Functions |",
            "|---|---:|",
        ]
        lines.extend(f"| `{name}` | {count:,} |" for name, count in sorted(categories.items()))
        lines += [
            "",
            "These categories localize metric-visible graph differences; they do not",
            "by themselves decide semantic correctness. Source review and structural",
            "invariants remain required before labelling either provider wrong.",
            "",
        ]
        args.output_markdown.write_text("\n".join(lines))
    except ValueError as exc:
        print(f"incomplete or invalid evidence: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
