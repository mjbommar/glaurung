"""Windows-oriented risk triage command.

This command is a compact, headless analogue of the first Ghidra workflow
analysts usually run on a PE: inspect risky imports, jump from strings to
referencing functions, decompile the most promising functions, and surface
parser-like API sequences worth poking.
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import glaurung as g

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat
from ..utils.formatting import format_hex


_RISK_IMPORT_BUCKETS: dict[str, tuple[str, ...]] = {
    "file_io": (
        "CreateFile",
        "ReadFile",
        "WriteFile",
        "DeleteFile",
        "CopyFile",
        "MoveFile",
        "CreateFileMapping",
        "MapViewOfFile",
    ),
    "allocation": (
        "LocalAlloc",
        "HeapAlloc",
        "malloc",
        "calloc",
        "realloc",
        "VirtualAlloc",
    ),
    "registry": (
        "RegOpenKey",
        "RegCreateKey",
        "RegQueryValue",
        "RegSetValue",
        "RegDelete",
    ),
    "dynamic_loading": (
        "LoadLibrary",
        "GetProcAddress",
        "LdrGetProcedureAddress",
    ),
    "com": (
        "CoCreateInstance",
        "CLSIDFrom",
        "StringFromCLSID",
    ),
    "copy_format": (
        "memcpy",
        "memmove",
        "strcpy",
        "strcat",
        "sprintf",
        "swprintf",
        "wcscpy",
        "wcscat",
    ),
    "network": (
        "WinHttp",
        "InternetOpen",
        "InternetConnect",
        "HttpSendRequest",
        "WSAStartup",
        "socket",
        "connect",
        "recv",
        "send",
    ),
}

_SUSPICIOUS_STRING_TOKENS: tuple[str, ...] = (
    "credential",
    "password",
    "secret",
    "token",
    "private",
    "remoteaccess",
    "currentcontrolset",
    "services\\",
    "software\\",
    "clsid",
    "migrate",
    "backup",
    "restore",
    "failed",
    ".dll",
    ".exe",
    ".mdb",
    ".dat",
)


class WindowsRiskCommand(BaseCommand):
    """Build a Windows-specific risk summary for a binary."""

    def get_name(self) -> str:
        return "windows-risk"

    def get_help(self) -> str:
        return "Summarize PE/Windows imports, string xrefs, and risky function shapes"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", help="Path to binary")
        parser.add_argument(
            "--max-read-bytes",
            type=int,
            default=104_857_600,
            help="Max bytes to read (default: 100MB)",
        )
        parser.add_argument(
            "--max-file-size",
            type=int,
            default=1_073_741_824,
            help="Max file size accepted (default: 1GB)",
        )
        parser.add_argument(
            "--max-functions",
            type=int,
            default=4096,
            help="Max functions to discover (default: 4096)",
        )
        parser.add_argument(
            "--max-candidates",
            type=int,
            default=32,
            help="Max function summaries to keep (default: 32)",
        )
        parser.add_argument(
            "--max-decompile",
            type=int,
            default=16,
            help="Max candidate functions to decompile for API patterns (default: 16)",
        )
        parser.add_argument(
            "--timeout-ms",
            type=int,
            default=1000,
            help="Per-analysis timeout in milliseconds where supported",
        )
        parser.add_argument(
            "--str-min-len",
            type=int,
            default=6,
            help="Minimum string length (default: 6)",
        )
        parser.add_argument(
            "--str-max-samples",
            type=int,
            default=10_000,
            help="Max strings sampled for xref joins (default: 10000)",
        )
        parser.add_argument(
            "--max-xrefs",
            type=int,
            default=500_000,
            help="Max data xrefs recovered for string-to-function joins",
        )
        parser.add_argument(
            "--pdb-cache",
            default="",
            help="Optional Microsoft-style PDB cache for decompiler naming",
        )
        parser.add_argument(
            "--no-decompile",
            action="store_true",
            help="Skip decompiler-based per-function API pattern detection",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        try:
            path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        try:
            report = build_windows_risk_report(path, args)
        except Exception as e:
            formatter.output_plain(f"Error during Windows risk analysis: {e}")
            return 3

        if formatter.format_type == OutputFormat.JSON:
            formatter.output_json(report)
            return 0
        if formatter.format_type == OutputFormat.JSONL:
            formatter.output_jsonl(
                [
                    {"type": "summary", "data": report["summary"]},
                    {"type": "imports", "data": report["risk_imports"]},
                    {"type": "risk_items", "data": report["risk_items"]},
                    {"type": "functions", "data": report["functions"]},
                ]
            )
            return 0

        self._output_plain(report, formatter)
        return 0

    def _output_plain(self, report: dict[str, Any], formatter: BaseFormatter) -> None:
        summary = report["summary"]
        lines = [
            "Windows Risk Summary",
            f"path: {summary['path']}",
            (
                f"format: {summary['format']} arch: {summary['arch']} "
                f"functions: {summary['function_count']} "
                f"imports: {summary['import_count']} "
                f"strings: {summary['string_count']} "
                f"data_xrefs: {summary['data_xref_count']}"
            ),
            "",
            "Risk import buckets:",
        ]
        risk_imports = report["risk_imports"]
        if risk_imports:
            for bucket, names in risk_imports.items():
                sample = ", ".join(names[:8])
                if len(names) > 8:
                    sample += f", +{len(names) - 8} more"
                lines.append(f"  {bucket}: {sample}")
        else:
            lines.append("  none")

        lines.extend(["", "Top findings:"])
        if report["risk_items"]:
            for item in report["risk_items"][:12]:
                va = item.get("function_va")
                where = f" {format_hex(va)}" if isinstance(va, int) else ""
                lines.append(
                    f"  [{item['severity']}] {item['kind']}{where}: {item['summary']}"
                )
                evidence = item.get("evidence") or []
                if evidence:
                    lines.append(f"    evidence: {', '.join(evidence[:6])}")
        else:
            lines.append("  none")

        lines.extend(["", "Function summaries:"])
        if report["functions"]:
            for fn in report["functions"][: report["summary"]["function_rows"]]:
                apis = ", ".join(fn.get("api_hits") or [])
                strings = ", ".join(repr(s["text"]) for s in fn.get("strings", [])[:3])
                bits = []
                if apis:
                    bits.append(f"apis: {apis}")
                if strings:
                    bits.append(f"strings: {strings}")
                suffix = " | " + " | ".join(bits) if bits else ""
                lines.append(
                    f"  {format_hex(fn['entry_va'])} {fn['name']} "
                    f"score={fn['score']}{suffix}"
                )
        else:
            lines.append("  none")

        formatter.output_plain("\n".join(lines))


def build_windows_risk_report(path: Path, args: argparse.Namespace) -> dict[str, Any]:
    path_str = str(path)
    fmt, arch = _detect_format_arch(path_str, args)
    imports = _collect_imports(path_str, args)
    risk_imports = _bucket_imports(imports)
    strings = _extract_strings(path_str, args)
    funcs, _callgraph = g.analysis.analyze_functions_path(
        path_str,
        max_read_bytes=args.max_read_bytes,
        max_file_size=args.max_file_size,
        max_functions=max(args.max_functions, 1),
        max_blocks=1_000_000,
        max_instructions=30_000_000,
        timeout_ms=args.timeout_ms,
    )
    function_rows = [_function_row(func) for func in funcs]
    by_va = {row["entry_va"]: row for row in function_rows}

    data_xrefs = _collect_data_xrefs(path_str, args)
    _join_string_xrefs(path_str, args, data_xrefs, strings, by_va)
    _annotate_string_api_hints(function_rows, imports)

    candidates = _select_candidates(function_rows, args.max_candidates)
    if not args.no_decompile and args.max_decompile > 0:
        _annotate_decompile_hits(path_str, args, candidates, imports)

    risk_items = _build_risk_items(risk_imports, candidates)
    candidates.sort(key=_function_sort_key)

    return {
        "summary": {
            "path": path_str,
            "format": fmt,
            "arch": arch,
            "function_count": len(function_rows),
            "function_rows": min(len(candidates), args.max_candidates),
            "import_count": len(imports),
            "string_count": len(strings),
            "data_xref_count": len(data_xrefs),
        },
        "risk_imports": risk_imports,
        "risk_items": risk_items,
        "functions": candidates[: args.max_candidates],
    }


def _detect_format_arch(path: str, args: argparse.Namespace) -> tuple[str, str]:
    try:
        got = g.analysis.detect_entry_path(
            path,
            args.max_read_bytes,
            args.max_file_size,
        )
    except Exception:
        return "unknown", "unknown"
    if not got:
        return "unknown", "unknown"
    return str(got[0]), str(got[1])


def _collect_imports(path: str, args: argparse.Namespace) -> list[str]:
    try:
        _all, _dyn, imports, _exports, _libs = g.triage.list_symbols(
            path,
            args.max_read_bytes,
            args.max_file_size,
        )
    except Exception:
        return []
    return sorted({_clean_import_name(str(name)) for name in imports if str(name)})


def _clean_import_name(name: str) -> str:
    name = name.strip()
    if "!" in name:
        name = name.rsplit("!", 1)[1]
    if "::" in name:
        name = name.rsplit("::", 1)[1]
    return name


def _api_stem(name: str) -> str:
    clean = _clean_import_name(name)
    if len(clean) > 2 and clean[-1] in {"A", "W"} and clean[-2].islower():
        clean = clean[:-1]
    return clean.lower()


def _bucket_imports(imports: list[str]) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = {}
    for bucket, prefixes in _RISK_IMPORT_BUCKETS.items():
        hits: list[str] = []
        lower_prefixes = tuple(prefix.lower() for prefix in prefixes)
        for name in imports:
            stem = _api_stem(name)
            if stem.startswith(lower_prefixes):
                hits.append(name)
        if hits:
            buckets[bucket] = sorted(set(hits))
    return buckets


def _extract_strings(path: str, args: argparse.Namespace) -> list[dict[str, Any]]:
    try:
        artifact = g.triage.analyze_path(
            path,
            str_min_len=args.str_min_len,
            str_max_samples=args.str_max_samples,
            str_lang=False,
            str_classify=False,
        )
    except Exception:
        return []
    got = getattr(getattr(artifact, "strings", None), "strings", None) or []
    out = []
    for s in got:
        text = str(getattr(s, "text", ""))
        if len(text) < args.str_min_len or _looks_like_code_byte_string(text):
            continue
        out.append(
            {
                "offset": int(getattr(s, "offset", 0)),
                "encoding": str(getattr(s, "encoding", "unknown")),
                "text": text,
                "suspicious": _is_suspicious_string(text),
            }
        )
    return out


def _looks_like_code_byte_string(text: str) -> bool:
    if len(text) < 8 or len(text) > 24:
        return False
    if not text.isascii() or not text.isalpha() or not text.isupper():
        return False
    common_code_letters = sum(1 for ch in text if ch in "AEFHJMPQRSUVWXYZ")
    return common_code_letters / max(len(text), 1) >= 0.85


def _is_suspicious_string(text: str) -> bool:
    lower = text.lower()
    return any(token in lower for token in _SUSPICIOUS_STRING_TOKENS)


def _function_row(func: Any) -> dict[str, Any]:
    entry_va = int(getattr(getattr(func, "entry_point", None), "value", 0))
    basic_blocks = list(getattr(func, "basic_blocks", []) or [])
    instr_count = 0
    for block in basic_blocks:
        try:
            instr_count += int(getattr(block, "instruction_count", 0))
        except Exception:
            pass
    size = getattr(func, "size", None)
    if size is None:
        try:
            size = func.calculate_size()
        except Exception:
            size = 0
    return {
        "name": str(getattr(func, "name", f"sub_{entry_va:x}")),
        "entry_va": entry_va,
        "size": int(size or 0),
        "basic_blocks": len(basic_blocks),
        "instruction_count": instr_count,
        "strings": [],
        "api_hits": [],
        "patterns": [],
        "decompile_error": None,
        "score": 0,
    }


def _collect_data_xrefs(
    path: str,
    args: argparse.Namespace,
) -> list[tuple[int, int, int]]:
    try:
        return [
            (int(src), int(dst), int(src_fn))
            for src, dst, src_fn in g.analysis.data_xrefs_path(
                path,
                max_read_bytes=args.max_read_bytes,
                max_file_size=args.max_file_size,
                max_functions=max(args.max_functions, 1),
                max_blocks=1_000_000,
                max_instructions=30_000_000,
                timeout_ms=args.timeout_ms,
                max_xrefs=args.max_xrefs,
            )
        ]
    except Exception:
        return []


def _join_string_xrefs(
    path: str,
    args: argparse.Namespace,
    data_xrefs: list[tuple[int, int, int]],
    strings: list[dict[str, Any]],
    by_va: dict[int, dict[str, Any]],
) -> None:
    strings_by_offset = {int(s["offset"]): s for s in strings}
    range_index = [
        (int(s["offset"]), int(s["offset"]) + _string_storage_len(s), s)
        for s in strings
    ]
    seen: set[tuple[int, int, str]] = set()
    for src_va, dst_va, src_fn in data_xrefs:
        row = by_va.get(src_fn)
        if row is None:
            continue
        try:
            offset = g.analysis.va_to_file_offset_path(
                path,
                dst_va,
                max_read_bytes=args.max_read_bytes,
                max_file_size=args.max_file_size,
            )
        except Exception:
            continue
        if offset is None:
            continue
        string = strings_by_offset.get(int(offset))
        if string is None:
            string = _find_string_by_range(int(offset), range_index)
        if string is None:
            continue
        key = (src_fn, src_va, string["text"])
        if key in seen:
            continue
        seen.add(key)
        row["strings"].append(
            {
                "src_va": src_va,
                "dst_va": dst_va,
                "text": string["text"],
                "encoding": string["encoding"],
                "suspicious": string["suspicious"],
            }
        )
        row["score"] += 2 if string["suspicious"] else 1


def _string_storage_len(string: dict[str, Any]) -> int:
    text_len = len(str(string["text"]))
    encoding = str(string["encoding"]).lower()
    if "16" in encoding:
        return max(2, text_len * 2)
    return max(1, text_len)


def _find_string_by_range(
    offset: int,
    range_index: list[tuple[int, int, dict[str, Any]]],
) -> dict[str, Any] | None:
    for start, end, string in range_index:
        if start <= offset < end:
            return string
    return None


def _select_candidates(
    function_rows: list[dict[str, Any]],
    max_candidates: int,
) -> list[dict[str, Any]]:
    ranked = sorted(function_rows, key=_function_sort_key)
    return [dict(row) for row in ranked[: max(max_candidates, 1)]]


def _function_sort_key(row: dict[str, Any]) -> tuple[int, int, int, int, int]:
    return (
        -_pattern_priority(row),
        -int(row["score"]),
        -len(row["strings"]),
        -int(row["instruction_count"]),
        int(row["entry_va"]),
    )


def _pattern_priority(row: dict[str, Any]) -> int:
    patterns = set(row.get("patterns") or [])
    if "file-read-allocation-parser" in patterns:
        return 4
    if "dynamic-api-resolution" in patterns:
        return 3
    if "registry-write" in patterns:
        return 2
    if patterns:
        return 1
    return 0


def _annotate_string_api_hints(
    function_rows: list[dict[str, Any]],
    imports: list[str],
) -> None:
    risk_api_names = _risk_api_name_pool(imports)
    for row in function_rows:
        if not row["strings"]:
            continue
        text = "\n".join(str(s["text"]) for s in row["strings"])
        api_hits = _scan_api_hits(text, risk_api_names)
        patterns = _patterns_from_api_hits(api_hits)
        _merge_row_api_hits(row, api_hits, patterns)


def _annotate_decompile_hits(
    path: str,
    args: argparse.Namespace,
    candidates: list[dict[str, Any]],
    imports: list[str],
) -> None:
    risk_api_names = _risk_api_name_pool(imports)
    for row in candidates[: args.max_decompile]:
        try:
            pseudocode = g.ir.decompile_at(
                path,
                int(row["entry_va"]),
                timeout_ms=args.timeout_ms,
                style="c",
                pdb_cache=args.pdb_cache,
            )
        except Exception as e:
            row["decompile_error"] = str(e)
            continue
        api_hits = _scan_api_hits(pseudocode, risk_api_names)
        _merge_row_api_hits(row, api_hits, _patterns_from_api_hits(api_hits))


def _risk_api_name_pool(imports: list[str]) -> list[str]:
    return sorted(
        {api for names in _RISK_IMPORT_BUCKETS.values() for api in names}
        | {_clean_import_name(name) for name in imports}
    )


def _merge_row_api_hits(
    row: dict[str, Any],
    api_hits: list[str],
    patterns: list[str],
) -> None:
    old_api_hits = set(row.get("api_hits") or [])
    old_patterns = set(row.get("patterns") or [])
    new_api_hits = set(api_hits) - old_api_hits
    new_patterns = set(patterns) - old_patterns
    if new_api_hits:
        row["api_hits"] = sorted(
            old_api_hits | set(api_hits), key=lambda item: item.lower()
        )
        row["score"] += len(new_api_hits)
    if new_patterns:
        row["patterns"] = sorted(old_patterns | set(patterns))
        row["score"] += 8 * len(new_patterns)


def _scan_api_hits(pseudocode: str, api_names: list[str]) -> list[str]:
    lower = pseudocode.lower()
    hits = []
    for name in api_names:
        clean = _clean_import_name(name)
        if not clean:
            continue
        stem = _api_stem(clean)
        if _contains_api_name(lower, clean.lower()) or _contains_api_name(lower, stem):
            hits.append(clean)
    return sorted(set(hits), key=lambda item: item.lower())


def _contains_api_name(lower_text: str, needle: str) -> bool:
    if not needle:
        return False
    suffix = "[aw]?" if len(needle) > 2 and needle[-1] not in {"a", "w"} else ""
    pattern = rf"(?<![a-z0-9_]){re.escape(needle)}{suffix}(?![a-z0-9_])"
    return re.search(pattern, lower_text) is not None


def _patterns_from_api_hits(api_hits: list[str]) -> list[str]:
    stems = {_api_stem(name) for name in api_hits}
    patterns = []
    if (
        any(stem.startswith("createfile") for stem in stems)
        and any(stem.startswith("readfile") for stem in stems)
        and any(stem in {"localalloc", "heapalloc", "malloc"} for stem in stems)
    ):
        patterns.append("file-read-allocation-parser")
    if any(stem.startswith("regsetvalue") for stem in stems):
        patterns.append("registry-write")
    if any(stem.startswith("loadlibrary") for stem in stems) and any(
        stem.startswith("getprocaddress") for stem in stems
    ):
        patterns.append("dynamic-api-resolution")
    if any(
        stem in {"memcpy", "memmove", "strcpy", "strcat", "sprintf"} for stem in stems
    ):
        patterns.append("copy-or-format-sink")
    if any(stem.startswith("writefile") for stem in stems) and any(
        stem.startswith("deletefile") for stem in stems
    ):
        patterns.append("temp-file-write-delete")
    return patterns


def _build_risk_items(
    risk_imports: dict[str, list[str]],
    functions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    items = []
    for bucket, names in risk_imports.items():
        severity = "medium" if bucket in {"file_io", "registry"} else "low"
        if bucket in {"dynamic_loading", "copy_format"}:
            severity = "medium"
        items.append(
            {
                "kind": f"import-bucket:{bucket}",
                "severity": severity,
                "summary": f"{len(names)} risky import(s) in {bucket}",
                "evidence": names[:12],
                "function_va": None,
            }
        )

    for row in functions:
        suspicious_strings = [s for s in row["strings"] if s.get("suspicious")]
        if suspicious_strings:
            items.append(
                {
                    "kind": "function-string-xrefs",
                    "severity": "medium",
                    "summary": (
                        f"{row['name']} references "
                        f"{len(suspicious_strings)} suspicious string(s)"
                    ),
                    "evidence": [s["text"] for s in suspicious_strings[:8]],
                    "function_va": row["entry_va"],
                }
            )
        for pattern in row.get("patterns", []):
            severity = "high" if pattern == "file-read-allocation-parser" else "medium"
            items.append(
                {
                    "kind": pattern,
                    "severity": severity,
                    "summary": f"{row['name']} has {pattern.replace('-', ' ')} shape",
                    "evidence": row.get("api_hits", [])[:12],
                    "function_va": row["entry_va"],
                }
            )

    severity_rank = defaultdict(lambda: 0, {"high": 3, "medium": 2, "low": 1})
    return sorted(
        items,
        key=lambda item: (
            -severity_rank[str(item["severity"])],
            str(item["kind"]),
            int(item["function_va"] or 0),
        ),
    )
