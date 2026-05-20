#!/usr/bin/env python3
"""Compare Glaurung function discovery against Ghidra on vendored Windows PEs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from textwrap import dedent

import glaurung as g


REPO = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = REPO / "samples/binaries/platforms/windows/vendor/realworld"
DEFAULT_GHIDRA = Path("/nas4/data/tools/ghidra_12.1_PUBLIC/support/analyzeHeadless")

GHIDRA_SCRIPT = dedent(
    r"""
    // @category Analysis
    import ghidra.app.script.GhidraScript;
    import ghidra.program.model.listing.Function;
    import ghidra.program.model.listing.FunctionIterator;
    import ghidra.program.model.listing.InstructionIterator;
    import ghidra.program.model.listing.Program;

    public class GhidraWindowsParityMetrics extends GhidraScript {
        @Override
        protected void run() throws Exception {
            Program program = currentProgram;
            int instructions = 0;
            InstructionIterator insIter = program.getListing().getInstructions(true);
            while (insIter.hasNext()) {
                insIter.next();
                instructions++;
            }

            FunctionIterator funcs = program.getFunctionManager().getFunctions(true);
            FunctionIterator externs = program.getFunctionManager().getExternalFunctions();
            int internal = 0;
            int external = 0;
            int thunk = 0;
            int le8 = 0;
            int le32 = 0;
            while (funcs.hasNext()) {
                Function f = funcs.next();
                internal++;
                if (f.isThunk()) {
                    thunk++;
                }
                long bodyBytes = f.getBody().getNumAddresses();
                if (bodyBytes <= 8) {
                    le8++;
                }
                if (bodyBytes <= 32) {
                    le32++;
                }
                println(
                    "GHIDRA_FUNC entry=0x"
                        + Long.toHexString(f.getEntryPoint().getOffset())
                        + " body="
                        + bodyBytes
                        + " thunk="
                        + f.isThunk()
                );
            }
            while (externs.hasNext()) {
                externs.next();
                external++;
            }

            println("GHIDRA_PARITY manager_total=" + program.getFunctionManager().getFunctionCount());
            println("GHIDRA_PARITY internal_functions=" + internal);
            println("GHIDRA_PARITY external_functions=" + external);
            println("GHIDRA_PARITY thunk_functions=" + thunk);
            println("GHIDRA_PARITY le8_body_bytes=" + le8);
            println("GHIDRA_PARITY le32_body_bytes=" + le32);
            println("GHIDRA_PARITY instructions=" + instructions);
            println("GHIDRA_PARITY language=" + program.getLanguageID());
            println("GHIDRA_PARITY compiler=" + program.getCompilerSpec().getCompilerSpecID());
        }
    }
    """
).strip()


def sha256_16(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()[:16]


def repo_display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO))
    except ValueError:
        return str(path)


def load_targets(corpus: Path) -> list[dict[str, object]]:
    manifest = json.loads((corpus / "MANIFEST.json").read_text(encoding="utf-8"))
    return manifest["fixtures"]


def run_glaurung(path: Path, max_functions: int) -> dict[str, object]:
    start = time.perf_counter()
    funcs, cg, stats = g.analysis.analyze_functions_path_with_stats(
        str(path),
        max_functions=max_functions,
    )
    elapsed = time.perf_counter() - start
    return {
        "elapsed_s": elapsed,
        "functions": len(funcs),
        "callgraph_functions": cg.function_count(),
        "callgraph_edges": cg.edge_count(),
        "stats": dict(stats),
        "entry_vas": [f"0x{func.entry_point.value:x}" for func in funcs],
    }


def run_ghidra(
    ghidra: Path,
    script_dir: Path,
    path: Path,
    timeout_s: int,
    analysis_timeout_s: int,
) -> dict[str, object]:
    project_dir = Path(tempfile.mkdtemp(prefix="glaurung-ghidra-parity-"))
    cmd = [
        str(ghidra),
        str(project_dir),
        path.stem,
        "-import",
        str(path),
        "-analysisTimeoutPerFile",
        str(analysis_timeout_s),
        "-scriptPath",
        str(script_dir),
        "-postScript",
        "GhidraWindowsParityMetrics.java",
        "-deleteProject",
        "-max-cpu",
        "2",
    ]
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", "replace")
        return {
            "ok": False,
            "timed_out": True,
            "elapsed_s": time.perf_counter() - start,
            "metrics": {},
            "tail": "\n".join(output.splitlines()[-20:]),
        }
    finally:
        shutil.rmtree(project_dir, ignore_errors=True)

    metrics: dict[str, object] = {}
    functions: list[dict[str, object]] = []
    for line in proc.stdout.splitlines():
        match = re.search(r"GHIDRA_PARITY ([^=]+)=([^ ()]+)", line)
        if match:
            key, raw_value = match.group(1), match.group(2)
            metrics[key] = int(raw_value) if raw_value.isdigit() else raw_value
            continue
        func_match = re.search(
            r"GHIDRA_FUNC entry=(0x[0-9a-fA-F]+) body=([0-9]+) thunk=(true|false)",
            line,
        )
        if func_match:
            functions.append(
                {
                    "entry": func_match.group(1).lower(),
                    "body": int(func_match.group(2)),
                    "thunk": func_match.group(3) == "true",
                }
            )
    return {
        "ok": proc.returncode == 0 and "REPORT: Import succeeded" in proc.stdout,
        "timed_out": False,
        "elapsed_s": time.perf_counter() - start,
        "metrics": metrics,
        "functions": functions,
        "tail": "\n".join(proc.stdout.splitlines()[-20:]),
    }


def address_gap(row: dict[str, object]) -> dict[str, object]:
    gl_entries = {str(entry).lower() for entry in row["glaurung"].get("entry_vas", [])}
    gh_functions = row["ghidra"].get("functions", [])
    gh_entries = {str(func["entry"]).lower() for func in gh_functions}
    missing = [func for func in gh_functions if str(func["entry"]).lower() not in gl_entries]
    extra = sorted(gl_entries - gh_entries)
    return {
        "missing_entries": len(missing),
        "extra_entries": len(extra),
        "missing_thunks": sum(1 for func in missing if func.get("thunk")),
        "missing_le32": sum(1 for func in missing if int(func.get("body", 0)) <= 32),
        "sample_missing": missing[:16],
        "sample_extra": extra[:16],
    }


def recall(row: dict[str, object]) -> float:
    ghidra_total = int(row["ghidra"]["metrics"].get("internal_functions", 0))
    missing = int(row.get("address_gap", {}).get("missing_entries", 0))
    if ghidra_total <= 0:
        return 0.0
    return (ghidra_total - missing) / ghidra_total


def load_previous_rows(path: Path | None) -> list[dict[str, object]]:
    if path is None or not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def annotate_trends(
    rows: list[dict[str, object]],
    previous_rows: list[dict[str, object]],
) -> None:
    previous_by_key = {
        (str(row.get("file")), str(row.get("sha256_16"))): row for row in previous_rows
    }
    for row in rows:
        key = (str(row.get("file")), str(row.get("sha256_16")))
        previous = previous_by_key.get(key)
        if not previous:
            row["trend"] = {
                "has_previous": False,
                "missing_delta": 0,
                "extra_delta": 0,
                "recall_delta": 0.0,
                "new_bad_delta": False,
            }
            continue
        missing_delta = int(row["address_gap"]["missing_entries"]) - int(
            previous.get("address_gap", {}).get("missing_entries", 0)
        )
        extra_delta = int(row["address_gap"]["extra_entries"]) - int(
            previous.get("address_gap", {}).get("extra_entries", 0)
        )
        recall_delta = recall(row) - recall(previous)
        row["trend"] = {
            "has_previous": True,
            "missing_delta": missing_delta,
            "extra_delta": extra_delta,
            "recall_delta": recall_delta,
            "new_bad_delta": missing_delta > 0 or extra_delta > 5 or recall_delta < -0.005,
        }


def suspected_reason(row: dict[str, object]) -> str:
    gl = row["glaurung"]
    gh = row["ghidra"]
    stats = gl["stats"]
    metrics = gh["metrics"]
    gap_detail = row.get("address_gap", {})
    gap = int(metrics.get("internal_functions", 0)) - int(gl["functions"])
    gh_thunks = int(metrics.get("thunk_functions", 0))
    gl_thunks = int(stats.get("thunk_functions", 0))
    if stats.get("truncated"):
        return "glaurung_budget_truncated"
    if gap <= 0:
        return "parity_or_over"
    if gh_thunks > gl_thunks and gh_thunks - gl_thunks >= max(1, min(gap, gh_thunks) // 2):
        return "thunk_classification_gap"
    if int(gap_detail.get("missing_le32", 0)) >= max(1, gap // 2):
        return "address_missing_tiny_function_gap"
    if int(metrics.get("le32_body_bytes", 0)) >= gap:
        return "tiny_or_thunk_function_gap"
    return "seed_or_prologue_gap"


def render_markdown(rows: list[dict[str, object]]) -> str:
    headers = [
        "file",
        "src",
        "kb",
        "gl_funcs",
        "gl_s",
        "gl_trunc",
        "gl_pdata_entries",
        "gl_pdata_starts",
        "gl_pdata_seeds",
        "gl_pdata_rej",
        "gl_pdata_chain",
        "gl_prolog",
        "gl_tscan",
        "gl_stub",
        "gl_rawcall",
        "gl_rawsplit",
        "gl_codeptr",
        "gl_dataref",
        "gl_pdata_split",
        "gl_labels",
        "gl_tail",
        "gl_indir",
        "gl_thunks",
        "gl_le32",
        "gl_seed_sources",
        "gh_internal",
        "gh_external",
        "gh_thunks",
        "gh_le32",
        "recall",
        "gap",
        "addr_missing",
        "addr_extra",
        "miss_delta",
        "extra_delta",
        "bad_delta",
        "reason",
    ]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        gl = row["glaurung"]
        gh = row["ghidra"]
        metrics = gh["metrics"]
        stats = gl["stats"]
        pdata_rejected = sum(
            int(stats.get(name, 0))
            for name in (
                "pdata_zero_begin_rejected",
                "pdata_zero_size_rejected",
                "pdata_chained_unwind_rejected",
                "pdata_nonexec_rejected",
            )
        )
        gap = int(metrics.get("internal_functions", 0)) - int(gl["functions"])
        trend = row.get("trend", {})
        seed_sources = ",".join(
            f"{name}:{count}"
            for name, count in sorted(dict(stats.get("seed_kind_counts", {})).items())
        )
        lines.append(
            "| "
            + " | ".join(
                [
                    str(row["file"]),
                    str(row["source_label"]),
                    f"{int(row['size_bytes']) / 1024:.1f}",
                    str(gl["functions"]),
                    f"{float(gl['elapsed_s']):.3f}",
                    str(stats.get("truncated")),
                    str(stats.get("pdata_entries")),
                    str(stats.get("pdata_function_starts")),
                    str(stats.get("pdata_seeds_inserted")),
                    str(pdata_rejected),
                    str(stats.get("pdata_chained_unwind_parsed")),
                    str(stats.get("prologue_scan_seeds_inserted")),
                    str(stats.get("thunk_scan_seeds_inserted")),
                    str(stats.get("tiny_stub_scan_seeds_inserted")),
                    str(stats.get("raw_call_target_seeds_inserted")),
                    str(stats.get("raw_call_target_body_split_seeds_inserted")),
                    str(stats.get("data_ref_code_pointer_candidates")),
                    str(stats.get("data_ref_code_pointer_seeds_inserted")),
                    str(stats.get("pdata_body_overlap_starts")),
                    str(stats.get("code_label_count")),
                    str(stats.get("tail_call_seeds_added")),
                    str(stats.get("indirect_call_seeds_added")),
                    str(stats.get("thunk_functions")),
                    str(stats.get("tiny_functions_le32")),
                    seed_sources,
                    str(metrics.get("internal_functions")),
                    str(metrics.get("external_functions")),
                    str(metrics.get("thunk_functions")),
                    str(metrics.get("le32_body_bytes")),
                    f"{recall(row):.4f}",
                    str(gap),
                    str(row.get("address_gap", {}).get("missing_entries")),
                    str(row.get("address_gap", {}).get("extra_entries")),
                    str(trend.get("missing_delta", 0)),
                    str(trend.get("extra_delta", 0)),
                    str(trend.get("new_bad_delta", False)),
                    str(row["suspected_reason"]),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--ghidra", type=Path, default=DEFAULT_GHIDRA)
    parser.add_argument(
        "--max-functions",
        type=int,
        default=0,
        help="Glaurung function-count cap; 0 means unlimited.",
    )
    parser.add_argument("--analysis-timeout-s", type=int, default=75)
    parser.add_argument("--timeout-s", type=int, default=130)
    parser.add_argument("--output-json", type=Path, default=Path("/tmp/windows-ghidra-parity.json"))
    parser.add_argument("--output-md", type=Path, default=Path("/tmp/windows-ghidra-parity.md"))
    parser.add_argument(
        "--previous-json",
        type=Path,
        default=None,
        help="Optional previous parity JSON for trend/new-bad-delta annotations.",
    )
    args = parser.parse_args()

    if not args.ghidra.exists():
        raise SystemExit(f"Ghidra analyzeHeadless not found: {args.ghidra}")

    previous_rows = load_previous_rows(args.previous_json or args.output_json)

    with tempfile.TemporaryDirectory(prefix="glaurung-ghidra-script-") as script_tmp:
        script_dir = Path(script_tmp)
        (script_dir / "GhidraWindowsParityMetrics.java").write_text(
            GHIDRA_SCRIPT + "\n",
            encoding="utf-8",
        )
        rows = []
        for fixture in load_targets(args.corpus):
            path = args.corpus / str(fixture["file"])
            print(f"== {fixture['file']}", flush=True)
            row: dict[str, object] = {
                "file": fixture["file"],
                "source_label": fixture["source_label"],
                "path": repo_display_path(path),
                "size_bytes": path.stat().st_size,
                "sha256_16": sha256_16(path),
            }
            row["glaurung"] = run_glaurung(path, args.max_functions)
            row["ghidra"] = run_ghidra(
                args.ghidra,
                script_dir,
                path,
                args.timeout_s,
                args.analysis_timeout_s,
            )
            row["address_gap"] = address_gap(row)
            row["suspected_reason"] = suspected_reason(row)
            rows.append(row)
            annotate_trends(rows, previous_rows)
            args.output_json.write_text(json.dumps(rows, indent=2), encoding="utf-8")
            args.output_md.write_text(render_markdown(rows), encoding="utf-8")

    annotate_trends(rows, previous_rows)
    print(render_markdown(rows))
    print(f"wrote {args.output_json}")
    print(f"wrote {args.output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
