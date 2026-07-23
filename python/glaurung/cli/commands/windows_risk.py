"""Windows-oriented risk triage command.

This command is a compact, headless analogue of the first Ghidra workflow
analysts usually run on a PE: inspect risky imports, jump from strings to
referencing functions, decompile the most promising functions, and surface
parser-like API sequences worth poking.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from collections.abc import Callable
from functools import lru_cache
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
        "GetTempPath",
        "GetTempFileName",
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
        "CopyMemory",
        "RtlCopyMemory",
        "RtlMoveMemory",
        "lstrcpy",
        "lstrcat",
        "lstrcpyn",
        "memcpy",
        "memmove",
        "strncpy",
        "strcpy",
        "strcat",
        "sprintf",
        "wsprintf",
        "swprintf",
        "wcsncpy",
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
    "resource": (
        "FindResource",
        "FindResourceEx",
        "SizeofResource",
        "LoadResource",
        "LockResource",
        "EnumResource",
        "BeginUpdateResource",
        "UpdateResource",
        "EndUpdateResource",
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

_CAPABILITY_ORDER: tuple[str, ...] = (
    "allocation",
    "copy_format",
    "dynamic_loading",
    "file_io",
    "network",
    "registry",
    "resource",
    "com",
)

_SIGNAL_ORDER: tuple[str, ...] = (
    "file-read-allocation-parser",
    "file-read-allocation-flow",
    "file-read-allocation-argument-flow",
    "file-read-length-field-allocation-flow",
    "registry-query-size-allocation-flow",
    "resource-size-allocation-flow",
    "resource-size-buffer-flow",
    "dynamic-api-resolution",
    "dynamic-api-resolution-flow",
    "registry-write",
    "resource-extraction",
    "copy-or-format-sink",
    "temp-file-write-delete",
    "network-client",
    "metadata-role:tls-callback",
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
            default=30_000,
            help="Max functions to discover (default: 30000; 0 = unlimited)",
        )
        parser.add_argument(
            "--max-candidates",
            type=int,
            default=0,
            help=(
                "Max function summaries to keep in JSON output (default: 0 = "
                "unlimited; pre-2026-05-25 default was 32 which silently "
                "truncated big binaries like dnsapi.dll)"
            ),
        )
        parser.add_argument(
            "--max-decompile",
            type=int,
            default=256,
            help=(
                "Max candidate functions to decompile for API patterns "
                "(default: 256; 0 = unlimited; pre-2026-05-25 default was 16)"
            ),
        )
        parser.add_argument(
            "--timeout-ms",
            type=int,
            default=30_000,
            help="Per-analysis timeout in milliseconds (default: 30000)",
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
                f"exports: {summary['export_count']} "
                f"strings: {summary['string_count']} "
                f"data_xrefs: {summary['data_xref_count']}"
            ),
            "",
            "PE metadata:",
        ]
        pe_metadata = report.get("pe_metadata") or {}
        if pe_metadata:
            resources = pe_metadata.get("resources") or {}
            version = pe_metadata.get("version_info") or {}
            manifest = pe_metadata.get("manifest") or {}
            tls = pe_metadata.get("tls") or {}
            if resources:
                lines.append(
                    "  resources: "
                    f"leaves={resources.get('leaf_count', 0)} "
                    f"types={resources.get('resources_by_type', {})}"
                )
            if version.get("found"):
                lines.append(
                    "  version: "
                    f"file={version.get('file_version')} "
                    f"product={version.get('product_version')} "
                    f"description={version.get('file_description')}"
                )
            if manifest.get("found"):
                lines.append(
                    "  manifest: "
                    f"level={manifest.get('requested_execution_level')} "
                    f"ui_access={manifest.get('ui_access')} "
                    f"deps={manifest.get('dependencies', [])[:4]}"
                )
            if tls:
                lines.append(
                    "  tls: "
                    f"has_tls={tls.get('has_tls')} "
                    f"callbacks={tls.get('callback_count', 0)}"
                )
        else:
            lines.append("  none")

        lines.extend(
            [
                "",
                "Risk import buckets:",
            ]
        )
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
                    lines.append(
                        "    evidence: "
                        + ", ".join(_format_evidence_item(e) for e in evidence[:6])
                    )
        else:
            lines.append("  none")

        lines.extend(["", "Function summaries:"])
        if report["functions"]:
            for fn in report["functions"][: report["summary"]["function_rows"]]:
                apis = ", ".join(fn.get("api_hits") or [])
                api_buckets = ", ".join(
                    f"{bucket}={len(names)}"
                    for bucket, names in sorted((fn.get("api_buckets") or {}).items())
                )
                roles = ", ".join(fn.get("metadata_roles") or [])
                strings = ", ".join(repr(s["text"]) for s in fn.get("strings", [])[:3])
                calls = ", ".join(call["target"] for call in fn.get("calls", [])[:4])
                stack_vars = ", ".join(
                    var["display"] for var in fn.get("stack_vars", [])[:4]
                )
                constants = ", ".join(
                    const["hex"] for const in fn.get("suspicious_constants", [])[:4]
                )
                function_summary = fn.get("function_summary") or {}
                capabilities = ", ".join(function_summary.get("capabilities") or [])
                risk_signals = ", ".join(function_summary.get("risk_signals") or [])
                api_calls = ", ".join(
                    _format_api_call_summary(call)
                    for call in fn.get("api_calls", [])[:3]
                )
                bits = []
                if capabilities:
                    bits.append(f"caps: {capabilities}")
                if risk_signals:
                    bits.append(f"signals: {risk_signals}")
                if roles:
                    bits.append(f"roles: {roles}")
                if apis:
                    bits.append(f"apis: {apis}")
                if api_buckets:
                    bits.append(f"buckets: {api_buckets}")
                if api_calls:
                    bits.append(f"args: {api_calls}")
                if calls:
                    bits.append(f"calls: {calls}")
                if stack_vars:
                    bits.append(f"stack: {stack_vars}")
                if constants:
                    bits.append(f"consts: {constants}")
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
    imports, exports, libs = _collect_symbol_names(path_str, args)
    risk_imports = _bucket_imports(imports)
    pe_metadata = _collect_pe_metadata(path_str, args, exports, libs)
    strings = _extract_strings(path_str, args)
    funcs, callgraph = g.analysis.analyze_functions_path(
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
    _annotate_calls(function_rows, callgraph)
    _annotate_pe_metadata_roles(function_rows, pe_metadata)
    _annotate_named_import_functions(function_rows, imports)
    _annotate_call_imports(function_rows, imports)

    data_xrefs = _collect_data_xrefs(path_str, args)
    _join_string_xrefs(path_str, args, data_xrefs, strings, by_va)
    _annotate_string_api_hints(function_rows, imports)

    # 0 = unlimited; treat any non-positive cap as "keep everything".
    cap_candidates = args.max_candidates if args.max_candidates > 0 else len(function_rows)
    candidates = _select_candidates(function_rows, cap_candidates)
    if not args.no_decompile:
        _annotate_decompile_hits(path_str, args, candidates, imports)
    _annotate_function_summaries(candidates)

    risk_items = _build_risk_items(risk_imports, candidates)
    candidates.sort(key=_function_sort_key)

    # Resolve PDB-public names for any function_va that risk_items / functions
    # reference. We want the consumer to be able to triage by name without a
    # second per-VA decompile round-trip (this used to be the standard cost
    # of going from sub_XXX -> NetrGetJoinInformation).
    _annotate_public_names(risk_items, candidates, path_str, args)

    final_functions = candidates if args.max_candidates <= 0 else candidates[: args.max_candidates]
    return {
        "summary": {
            "path": path_str,
            "format": fmt,
            "arch": arch,
            "function_count": len(function_rows),
            "function_rows": len(final_functions),
            "import_count": len(imports),
            "export_count": len(exports),
            "lib_count": len(libs),
            "string_count": len(strings),
            "data_xref_count": len(data_xrefs),
        },
        "pe_metadata": pe_metadata,
        "risk_imports": risk_imports,
        "risk_items": risk_items,
        "functions": final_functions,
    }


def _annotate_public_names(
    risk_items: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    path_str: str,
    args: argparse.Namespace,
) -> None:
    """Decorate every risk_item and function row with `public_name` (PDB
    public symbol) and `score`. Best-effort: missing PDB / cache misses
    leave the field as None so consumers can still .get() safely."""
    pdb_cache = getattr(args, "pdb_cache", None)
    pdb_map: dict[int, str] = {}
    if pdb_cache:
        try:
            pdb_map = dict(g.symbols.pdb_symbol_map(path_str, pdb_cache))
        except Exception:  # pragma: no cover - PDB lookup is best-effort
            pdb_map = {}

    # Index candidates by VA so we can carry score across to risk_items.
    score_by_va = {int(row["entry_va"]): int(row.get("score", 0)) for row in candidates}

    for item in risk_items:
        va = item.get("function_va")
        if isinstance(va, int):
            item["public_name"] = pdb_map.get(int(va))
            item["score"] = score_by_va.get(int(va), 0)
        else:
            item["public_name"] = None
            item["score"] = 0
    for row in candidates:
        va = int(row.get("entry_va", 0) or 0)
        row["public_name"] = pdb_map.get(va)


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


def _collect_symbol_names(
    path: str, args: argparse.Namespace
) -> tuple[list[str], list[str], list[str]]:
    try:
        _all, _dyn, imports, _exports, _libs = g.triage.list_symbols(
            path,
            args.max_read_bytes,
            args.max_file_size,
        )
    except Exception:
        return [], [], []
    return (
        sorted({_clean_import_name(str(name)) for name in imports if str(name)}),
        sorted({_clean_import_name(str(name)) for name in _exports if str(name)}),
        sorted({str(name) for name in _libs if str(name)}),
    )


def _collect_pe_metadata(
    path: str,
    args: argparse.Namespace,
    exports: list[str],
    libs: list[str],
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "exports": list(exports),
        "libs": list(libs),
    }
    resources = _collect_resource_metadata(path, args)
    if resources:
        metadata["resources"] = resources
    manifest = _collect_manifest_metadata(path, args)
    if manifest:
        metadata["manifest"] = manifest
    version = _collect_version_metadata(path, args)
    if version:
        metadata["version_info"] = version
    tls = _collect_tls_metadata(path, args)
    if tls:
        metadata["tls"] = tls
    return metadata


def _collect_resource_metadata(path: str, args: argparse.Namespace) -> dict[str, Any]:
    try:
        raw = g.analysis.pe_list_resources_path(
            path,
            max_read_bytes=args.max_read_bytes,
            max_file_size=args.max_file_size,
            max_resources=4096,
            max_resource_depth=32,
            max_resource_data_bytes=1_048_576,
            preview_bytes=0,
        )
    except Exception as exc:
        return {"warnings": [str(exc)], "stop_reasons": ["resources_unavailable"]}
    return {
        "leaf_count": int(raw.get("leaf_count", 0)),
        "total_directories": int(raw.get("total_directories", 0)),
        "total_entries": int(raw.get("total_entries", 0)),
        "resource_bytes_total": int(raw.get("resource_bytes_total", 0)),
        "resources_by_type": dict(raw.get("resources_by_type") or {}),
        "truncated": bool(raw.get("truncated", False)),
        "warnings": list(raw.get("warnings") or []),
        "stop_reasons": list(raw.get("stop_reasons") or []),
    }


def _collect_manifest_metadata(path: str, args: argparse.Namespace) -> dict[str, Any]:
    try:
        resource = g.analysis.pe_view_resource_path(
            path,
            type_filter="manifest",
            max_read_bytes=args.max_read_bytes,
            max_file_size=args.max_file_size,
            max_text_bytes=65_536,
        )
    except Exception as exc:
        return {
            "found": False,
            "warnings": [str(exc)],
            "stop_reasons": ["manifest_unavailable"],
        }
    if resource is None:
        return {"found": False, "stop_reasons": ["manifest_not_found"]}
    text = resource.get("text") or ""
    try:
        from glaurung.llm.tools.pe_view_manifest import _decode_manifest_text

        decoded = _decode_manifest_text(path, text).model_dump(mode="json")
    except Exception as exc:
        return {
            "found": True,
            "evidence": resource.get("evidence"),
            "warnings": [f"manifest_decode_error:{exc}"],
        }
    return {
        "found": True,
        "evidence": resource.get("evidence"),
        "assembly_identity": decoded.get("assembly_identity") or {},
        "requested_execution_level": decoded.get("requested_execution_level"),
        "ui_access": decoded.get("ui_access"),
        "dpi_awareness": decoded.get("dpi_awareness") or [],
        "compatibility_guids": decoded.get("compatibility_guids") or [],
        "dependencies": decoded.get("dependencies") or [],
        "warnings": (decoded.get("warnings") or [])
        + list(resource.get("warnings") or []),
        "text_truncated": bool(resource.get("text_truncated", False)),
    }


def _collect_version_metadata(path: str, args: argparse.Namespace) -> dict[str, Any]:
    try:
        resource = g.analysis.pe_view_resource_path(
            path,
            type_filter="versioninfo",
            max_read_bytes=args.max_read_bytes,
            max_file_size=args.max_file_size,
            max_payload_bytes=65_536,
        )
    except Exception as exc:
        return {
            "found": False,
            "warnings": [str(exc)],
            "stop_reasons": ["version_info_unavailable"],
        }
    if resource is None:
        return {"found": False, "stop_reasons": ["version_info_not_found"]}
    payload = resource.get("data")
    if not isinstance(payload, bytes):
        return {
            "found": False,
            "evidence": resource.get("evidence"),
            "stop_reasons": ["version_info_payload_not_available"],
        }
    try:
        from glaurung.llm.tools.pe_decode_version_info import _decode_version_info

        decoded = _decode_version_info(path, payload).model_dump(mode="json")
    except Exception as exc:
        return {
            "found": True,
            "evidence": resource.get("evidence"),
            "warnings": [f"version_info_decode_error:{exc}"],
        }
    strings = decoded.get("strings") or {}
    return {
        "found": bool(decoded.get("fixed_file_info") or strings),
        "evidence": resource.get("evidence"),
        "file_version": decoded.get("file_version"),
        "product_version": decoded.get("product_version"),
        "file_description": strings.get("FileDescription"),
        "company_name": strings.get("CompanyName"),
        "original_filename": strings.get("OriginalFilename"),
        "product_name": strings.get("ProductName"),
        "file_type": decoded.get("file_type"),
        "translations": decoded.get("translations") or [],
        "warnings": (decoded.get("warnings") or [])
        + list(resource.get("warnings") or []),
        "stop_reasons": decoded.get("stop_reasons") or [],
    }


def _collect_tls_metadata(path: str, args: argparse.Namespace) -> dict[str, Any]:
    tls_func = getattr(g.analysis, "pe_tls_path", None)
    if tls_func is None:
        return {"available": False, "stop_reasons": ["pe_tls_path_unavailable"]}
    try:
        raw = tls_func(
            path,
            max_read_bytes=args.max_read_bytes,
            max_file_size=args.max_file_size,
        )
    except Exception as exc:
        return {"available": False, "warnings": [str(exc)]}
    return {
        "available": True,
        "has_tls": bool(raw.get("has_tls", False)),
        "has_callbacks": bool(raw.get("has_callbacks", False)),
        "callback_count": int(raw.get("callback_count", 0)),
        "address_of_callbacks": int(raw.get("address_of_callbacks", 0)),
        "callbacks": [int(v) for v in raw.get("callbacks") or []][:64],
        "callback_rvas": [int(v) for v in raw.get("callback_rvas") or []][:64],
        "truncated": bool(raw.get("truncated", False)),
        "stop_reasons": list(raw.get("stop_reasons") or []),
    }


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
        for name in imports:
            if _matches_risk_import(bucket, name, prefixes):
                hits.append(name)
        if hits:
            buckets[bucket] = sorted(set(hits))
    return buckets


def _matches_risk_import(
    bucket: str,
    name: str,
    prefixes: tuple[str, ...],
) -> bool:
    stem = _api_stem(name)
    for prefix in prefixes:
        lower_prefix = prefix.lower()
        if bucket == "network" and lower_prefix in {"connect", "recv", "send"}:
            if stem == lower_prefix:
                return True
            continue
        if stem.startswith(lower_prefix):
            return True
    return False


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
        "stack_vars": [],
        "suspicious_constants": [],
        "api_hits": [],
        "api_buckets": {},
        "api_sequence": [],
        "api_calls": [],
        "imports": [],
        "calls": [],
        "call_count": 0,
        "function_summary": {},
        "flow_hints": [],
        "metadata_roles": [],
        "metadata_refs": [],
        "patterns": [],
        "decompile_error": None,
        "score": 0,
    }


def _annotate_calls(function_rows: list[dict[str, Any]], callgraph: Any) -> None:
    if callgraph is None:
        return
    by_name: dict[str, dict[str, Any]] = {}
    for row in function_rows:
        va = int(row["entry_va"])
        by_name[str(row["name"])] = row
        by_name[f"sub_{va:x}"] = row

    seen: set[tuple[int, str, tuple[int, ...]]] = set()
    for edge in getattr(callgraph, "edges", []) or []:
        caller_name = str(getattr(edge, "caller", ""))
        row = by_name.get(caller_name)
        if row is None:
            continue
        callee_name = str(getattr(edge, "callee", ""))
        call_sites = _edge_call_sites(edge)
        key = (int(row["entry_va"]), callee_name, tuple(call_sites))
        if key in seen:
            continue
        seen.add(key)
        callee_row = by_name.get(callee_name)
        call_kind = _edge_call_type(edge)
        row["calls"].append(
            {
                "target": callee_name,
                "target_va": int(callee_row["entry_va"]) if callee_row else None,
                "kind": call_kind,
                "call_sites": call_sites,
            }
        )

    for row in function_rows:
        row["calls"].sort(
            key=lambda call: (
                int(call["target_va"]) if call["target_va"] is not None else 2**64 - 1,
                str(call["target"]),
            )
        )
        row["call_count"] = len(row["calls"])


def _edge_call_sites(edge: Any) -> list[int]:
    sites = []
    for site in getattr(edge, "call_sites", []) or []:
        try:
            sites.append(int(getattr(site, "value", site)))
        except Exception:
            continue
    return sorted(set(sites))


def _edge_call_type(edge: Any) -> str:
    call_type = getattr(edge, "call_type", None)
    value = getattr(call_type, "value", None)
    if callable(value):
        try:
            return str(value()).lower()
        except Exception:
            pass
    if call_type is None:
        return "unknown"
    return str(call_type).lower()


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
            string = _read_xref_string_at_offset(path, int(offset), args)
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


def _read_xref_string_at_offset(
    path: str,
    offset: int,
    args: argparse.Namespace,
) -> dict[str, Any] | None:
    if offset < 0:
        return None
    before = 128
    after = 1024
    try:
        file_size = Path(path).stat().st_size
        read_limit = min(
            file_size,
            int(getattr(args, "max_read_bytes", file_size)),
            int(getattr(args, "max_file_size", file_size)),
        )
    except Exception:
        return None
    if offset >= read_limit:
        return None
    start = max(0, offset - before)
    size = min(before + after, read_limit - start)
    try:
        with open(path, "rb") as fh:
            fh.seek(start)
            data = fh.read(size)
    except OSError:
        return None
    origin = offset - start
    candidates = [
        _ascii_string_from_window(data, origin),
        _utf16le_string_from_window(data, origin),
    ]
    min_len = int(getattr(args, "str_min_len", 6))
    best: dict[str, Any] | None = None
    for text, encoding in candidates:
        if len(text) < min_len or _looks_like_code_byte_string(text):
            continue
        candidate = {
            "offset": offset,
            "encoding": encoding,
            "text": text,
            "suspicious": _is_suspicious_string(text),
        }
        if best is None or len(text) > len(str(best["text"])):
            best = candidate
    return best


def _ascii_string_from_window(data: bytes, origin: int) -> tuple[str, str]:
    if origin < 0 or origin >= len(data) or not _is_ascii_string_byte(data[origin]):
        return "", "ascii"
    start = origin
    while start > 0 and _is_ascii_string_byte(data[start - 1]):
        start -= 1
    end = origin
    while end < len(data) and _is_ascii_string_byte(data[end]):
        end += 1
    return data[start:end].decode("ascii", errors="ignore"), "ascii"


def _is_ascii_string_byte(value: int) -> bool:
    return value in {9, 10, 13} or 0x20 <= value <= 0x7E


def _utf16le_string_from_window(data: bytes, origin: int) -> tuple[str, str]:
    if origin < 0 or origin + 1 >= len(data):
        return "", "utf16le"
    if not _is_utf16le_printable_at(data, origin):
        return "", "utf16le"
    start = origin
    while start >= 2 and _is_utf16le_printable_at(data, start - 2):
        start -= 2
    end = origin
    while end + 1 < len(data) and _is_utf16le_printable_at(data, end):
        end += 2
    try:
        return data[start:end].decode("utf-16le"), "utf16le"
    except UnicodeDecodeError:
        return "", "utf16le"


def _is_utf16le_printable_at(data: bytes, offset: int) -> bool:
    if offset < 0 or offset + 1 >= len(data):
        return False
    if data[offset + 1] != 0:
        return False
    return _is_ascii_string_byte(data[offset])


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
    metadata_roles = set(row.get("metadata_roles") or [])
    if (
        "registry-write" in patterns
        or "resource-extraction" in patterns
        or "tls_callback" in metadata_roles
    ):
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


def _annotate_pe_metadata_roles(
    function_rows: list[dict[str, Any]],
    pe_metadata: dict[str, Any],
) -> None:
    by_va = {int(row["entry_va"]): row for row in function_rows}
    tls = pe_metadata.get("tls") or {}
    for idx, va in enumerate(int(value) for value in tls.get("callbacks") or []):
        row = by_va.get(va)
        if row is None:
            continue
        _add_metadata_role(
            row,
            "tls_callback",
            {
                "kind": "tls_callback",
                "index": idx,
                "va": va,
                "address_of_callbacks": int(tls.get("address_of_callbacks", 0)),
            },
            score=6,
        )


def _annotate_named_import_functions(
    function_rows: list[dict[str, Any]],
    imports: list[str],
) -> None:
    lookup = _api_name_lookup(imports)
    for row in function_rows:
        name = str(row.get("name", ""))
        canonical = lookup.get(name.lower()) or lookup.get(_api_stem(name))
        if canonical is None:
            continue
        _merge_row_api_hits(row, [canonical], _patterns_from_api_hits([canonical]))
        _add_metadata_role(
            row,
            "import_thunk",
            {"kind": "import_thunk", "name": canonical},
            score=1,
        )


def _annotate_call_imports(
    function_rows: list[dict[str, Any]],
    imports: list[str],
) -> None:
    lookup = _api_name_lookup(imports)
    if not lookup:
        return
    by_va = {int(row["entry_va"]): row for row in function_rows}
    for row in function_rows:
        ordered_hits: list[str] = []
        for call in sorted(row.get("calls") or [], key=_call_sort_key):
            target_names = [str(call.get("target", ""))]
            target_va = call.get("target_va")
            if target_va is not None and int(target_va) in by_va:
                target_names.append(str(by_va[int(target_va)].get("name", "")))
            canonical = _first_import_match(target_names, lookup)
            if canonical is None:
                continue
            ordered_hits.append(canonical)
        if not ordered_hits:
            continue
        _merge_row_api_sequence(row, ordered_hits)
        _merge_row_api_hits(row, ordered_hits, _patterns_from_api_hits(ordered_hits))


def _call_sort_key(call: dict[str, Any]) -> tuple[int, str]:
    sites = call.get("call_sites") or []
    first_site = min((int(site) for site in sites), default=2**64 - 1)
    return (first_site, str(call.get("target", "")))


def _first_import_match(
    names: list[str],
    lookup: dict[str, str],
) -> str | None:
    for name in names:
        canonical = lookup.get(name.lower()) or lookup.get(_api_stem(name))
        if canonical is not None:
            return canonical
    return None


def _add_metadata_role(
    row: dict[str, Any],
    role: str,
    ref: dict[str, Any],
    *,
    score: int,
) -> None:
    roles = list(row.get("metadata_roles") or [])
    if role not in roles:
        roles.append(role)
        row["metadata_roles"] = sorted(roles)
        row["score"] += score

    refs = list(row.get("metadata_refs") or [])
    ref_key = (str(ref.get("kind")), int(ref.get("va", 0)), str(ref.get("name", "")))
    seen = {
        (str(item.get("kind")), int(item.get("va", 0)), str(item.get("name", "")))
        for item in refs
    }
    if ref_key not in seen:
        refs.append(ref)
        row["metadata_refs"] = refs[:64]


def _annotate_decompile_hits(
    path: str,
    args: argparse.Namespace,
    candidates: list[dict[str, Any]],
    imports: list[str],
) -> None:
    risk_api_names = _risk_api_name_pool(imports)
    # 0 = unlimited; respect explicit cap if positive.
    targets = candidates if args.max_decompile <= 0 else candidates[: args.max_decompile]
    for row in targets:
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
        api_sequence = _scan_api_sequence(pseudocode, risk_api_names)
        api_hits = _scan_api_hits(pseudocode, risk_api_names)
        api_calls = _extract_api_calls(pseudocode, risk_api_names)
        _merge_row_stack_vars(row, _extract_stack_vars(pseudocode))
        _merge_row_suspicious_constants(
            row,
            _extract_suspicious_constants(pseudocode, risk_api_names),
        )
        _merge_row_api_sequence(row, api_sequence)
        _merge_row_api_calls(row, api_calls)
        _merge_row_api_hits(row, api_hits, _patterns_from_api_hits(api_hits))
        _merge_row_flow_hints(
            row,
            _flow_hints_from_api_sequence(api_sequence)
            + _flow_hints_from_api_calls(api_calls),
        )


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
        row["imports"] = row["api_hits"]
        row["api_buckets"] = _api_buckets_for_hits(row["api_hits"])
        row["score"] += len(new_api_hits)
    if new_patterns:
        row["patterns"] = sorted(old_patterns | set(patterns))
        row["score"] += 8 * len(new_patterns)


def _api_buckets_for_hits(api_hits: list[str]) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = {}
    for bucket, prefixes in _RISK_IMPORT_BUCKETS.items():
        names = sorted(
            {
                _clean_import_name(name)
                for name in api_hits
                if _matches_risk_import(bucket, name, prefixes)
            },
            key=lambda item: item.lower(),
        )
        if names:
            buckets[bucket] = names
    return buckets


def _merge_row_stack_vars(
    row: dict[str, Any],
    stack_vars: list[dict[str, Any]],
) -> None:
    if not stack_vars:
        return
    existing = list(row.get("stack_vars") or [])
    seen = {(str(var.get("base")), int(var.get("offset", 0))) for var in existing}
    for var in stack_vars:
        key = (str(var.get("base")), int(var.get("offset", 0)))
        if key in seen:
            continue
        seen.add(key)
        existing.append(var)
    row["stack_vars"] = existing[:64]


def _merge_row_suspicious_constants(
    row: dict[str, Any],
    constants: list[dict[str, Any]],
) -> None:
    if not constants:
        return
    existing = list(row.get("suspicious_constants") or [])
    seen = {
        (int(const.get("value", 0)), str(const.get("context", "")))
        for const in existing
    }
    for const in constants:
        key = (int(const.get("value", 0)), str(const.get("context", "")))
        if key in seen:
            continue
        seen.add(key)
        existing.append(const)
    row["suspicious_constants"] = existing[:64]


def _merge_row_api_sequence(row: dict[str, Any], api_sequence: list[str]) -> None:
    if not api_sequence:
        return
    existing = list(row.get("api_sequence") or [])
    row["api_sequence"] = (existing + api_sequence)[:128]


def _merge_row_api_calls(
    row: dict[str, Any],
    api_calls: list[dict[str, Any]],
) -> None:
    if not api_calls:
        return
    existing = list(row.get("api_calls") or [])
    seen = {
        (
            str(call.get("name")),
            tuple(str(arg.get("expr", "")) for arg in call.get("args", [])),
        )
        for call in existing
    }
    for call in api_calls:
        key = (
            str(call.get("name")),
            tuple(str(arg.get("expr", "")) for arg in call.get("args", [])),
        )
        if key in seen:
            continue
        seen.add(key)
        existing.append(call)
    row["api_calls"] = existing[:64]


def _merge_row_flow_hints(
    row: dict[str, Any],
    flow_hints: list[dict[str, Any]],
) -> None:
    if not flow_hints:
        return
    existing = list(row.get("flow_hints") or [])
    seen = {str(hint.get("kind")) for hint in existing}
    added = 0
    for hint in flow_hints:
        kind = str(hint.get("kind"))
        if kind in seen:
            continue
        seen.add(kind)
        existing.append(hint)
        added += 1
    if added:
        row["flow_hints"] = existing
        row["score"] += 10 * added


def _annotate_function_summaries(function_rows: list[dict[str, Any]]) -> None:
    for row in function_rows:
        row["function_summary"] = _build_function_summary(row)


def _build_function_summary(row: dict[str, Any]) -> dict[str, Any]:
    suspicious_strings = [
        str(item.get("text", ""))
        for item in row.get("strings", [])
        if item.get("suspicious") and str(item.get("text", ""))
    ]
    capabilities = _ordered_unique(
        str(bucket) for bucket in (row.get("api_buckets") or {}).keys()
    )
    flow_kinds = [
        str(hint.get("kind"))
        for hint in row.get("flow_hints", [])
        if str(hint.get("kind", ""))
    ]
    metadata_signals = [
        f"metadata-role:{_metadata_role_signal_name(str(role))}"
        for role in row.get("metadata_roles", [])
    ]
    risk_signals = _ordered_unique(
        list(row.get("patterns") or []) + flow_kinds + metadata_signals,
        order=_SIGNAL_ORDER,
    )
    return {
        "capabilities": _ordered_unique(capabilities, order=_CAPABILITY_ORDER),
        "risk_signals": risk_signals,
        "call_summary": _call_summary(row),
        "string_summary": {
            "total": len(row.get("strings") or []),
            "suspicious": suspicious_strings[:16],
        },
        "argument_roles": _argument_roles_summary(row),
        "data_flows": _data_flow_summary(row),
        "metadata_roles": list(row.get("metadata_roles") or []),
    }


def _ordered_unique(
    values: Any,
    *,
    order: tuple[str, ...] = (),
) -> list[str]:
    seen = set()
    out = []
    for value in values:
        text = str(value)
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    rank = {name: idx for idx, name in enumerate(order)}
    return sorted(out, key=lambda item: (rank.get(item, len(rank)), item.lower()))


def _metadata_role_signal_name(role: str) -> str:
    return role.replace("_", "-")


def _call_summary(row: dict[str, Any]) -> dict[str, Any]:
    imports = set(row.get("imports") or [])
    import_calls = []
    internal_calls = []
    for call in row.get("calls", []):
        target = str(call.get("target", ""))
        if not target:
            continue
        if target in imports or _api_stem(target) in {_api_stem(name) for name in imports}:
            import_calls.append(target)
        elif call.get("target_va") is not None:
            internal_calls.append(target)
    return {
        "total": int(row.get("call_count", len(row.get("calls") or []))),
        "imports": _ordered_unique(import_calls)[:32],
        "internal": _ordered_unique(internal_calls)[:32],
    }


def _argument_roles_summary(row: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    roles: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen: set[tuple[str, str, str, str]] = set()
    for call in row.get("api_calls", []):
        api = str(call.get("name", ""))
        if not api:
            continue
        for arg in call.get("args", []):
            role = str(arg.get("role", ""))
            if not role:
                continue
            param = str(arg.get("param") or f"arg{arg.get('index', '?')}")
            expr = str(arg.get("expr", ""))
            key = (role, api, param, expr)
            if key in seen:
                continue
            seen.add(key)
            item: dict[str, Any] = {
                "api": api,
                "param": param,
                "expr": expr,
            }
            c_type = str(arg.get("type", ""))
            if c_type:
                item["type"] = c_type
            if isinstance(arg.get("value"), int):
                item["value"] = int(arg["value"])
            if arg.get("hex"):
                item["hex"] = str(arg["hex"])
            roles[role].append(item)
    return {role: values[:16] for role, values in sorted(roles.items())}


def _data_flow_summary(row: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for hint in row.get("flow_hints", []):
        kind = str(hint.get("kind", ""))
        if not kind:
            continue
        out.append(
            {
                "kind": kind,
                "summary": str(hint.get("summary", "")),
                "evidence": list(hint.get("evidence") or [])[:12],
            }
        )
    return out[:16]


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


def _scan_api_sequence(pseudocode: str, api_names: list[str]) -> list[str]:
    lower = pseudocode.lower()
    hits: list[tuple[int, int, str]] = []
    for name in api_names:
        clean = _clean_import_name(name)
        if not clean:
            continue
        for needle in {clean.lower(), _api_stem(clean)}:
            if not needle:
                continue
            suffix = "[aw]?" if len(needle) > 2 and needle[-1] not in {"a", "w"} else ""
            pattern = rf"(?<![a-z0-9_]){re.escape(needle)}{suffix}(?![a-z0-9_])"
            for match in re.finditer(pattern, lower):
                hits.append((match.start(), match.end(), clean))
    hits.sort(key=lambda item: (item[0], -(item[1] - item[0]), -len(item[2])))
    out: list[str] = []
    seen_spans: set[tuple[int, int]] = set()
    for start, end, name in hits:
        span = (start, end)
        if span in seen_spans:
            continue
        seen_spans.add(span)
        out.append(name)
        if len(out) >= 128:
            break
    return out


def _extract_stack_vars(pseudocode: str) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    pattern = _stack_ref_pattern()
    for match in pattern.finditer(pseudocode):
        base = match.group("base")
        raw_value = _parse_int_literal(match.group("value"))
        if raw_value is None:
            continue
        offset = raw_value if match.group("sign") == "+" else -raw_value
        key = (base, offset)
        if key in seen:
            continue
        seen.add(key)
        refs.append(
            {
                "base": base,
                "offset": offset,
                "display": f"{base}{offset:+#x}",
            }
        )
        if len(refs) >= 64:
            break
    refs.sort(key=lambda var: (str(var["base"]), int(var["offset"])))
    return refs


def _extract_suspicious_constants(
    pseudocode: str,
    api_names: list[str],
) -> list[dict[str, Any]]:
    api_stems = {_api_stem(name) for name in api_names}
    constants: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    call_pattern = re.compile(
        r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<args>[^;\n{}]*)\)"
    )
    literal_pattern = re.compile(
        r"(?<![A-Za-z0-9_])(0x[0-9a-fA-F]+|\d+)(?![A-Za-z0-9_])"
    )
    for call in call_pattern.finditer(pseudocode):
        context = call.group("name")
        if _api_stem(context) not in api_stems:
            continue
        args = _stack_ref_pattern().sub("", call.group("args"))
        for literal in literal_pattern.finditer(args):
            value = _parse_int_literal(literal.group(1))
            if value is None or value < 4:
                continue
            key = (value, context)
            if key in seen:
                continue
            seen.add(key)
            constants.append({"value": value, "hex": hex(value), "context": context})
            if len(constants) >= 64:
                return constants
    return constants


def _extract_api_calls(
    pseudocode: str,
    api_names: list[str],
) -> list[dict[str, Any]]:
    api_lookup = _api_name_lookup(api_names)
    calls: list[dict[str, Any]] = []
    call_pattern = re.compile(
        r"(?:(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*)?"
        r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<args>[^{}]*)\)"
    )
    pending_args: dict[int, str] = {}
    for statement in _split_pseudocode_statements(pseudocode):
        if _record_pending_arg(statement, pending_args):
            continue
        call_match = _first_call_match(statement, call_pattern)
        if call_match is None:
            if _statement_has_raw_call(statement):
                pending_args.clear()
            continue
        raw_name = call_match.group("name")
        canonical_name = api_lookup.get(raw_name.lower()) or api_lookup.get(
            _api_stem(raw_name)
        )
        if canonical_name is not None:
            arg_exprs = _fill_call_arg_exprs(
                canonical_name,
                _split_call_args(call_match.group("args")),
                pending_args,
            )
            call_row = _api_call_row(canonical_name, arg_exprs)
            lhs = call_match.group("lhs")
            if lhs:
                call_row["assigned_to"] = lhs
            calls.append(call_row)
            if len(calls) >= 64:
                break
        pending_args.clear()
    return calls


# Map the winapi-proto stdint/base type spellings to the conventional Win32
# typedefs so the risk report reads the way Windows headers (and IDA/Ghidra)
# do — `DWORD` rather than `uint32_t`. Kept in sync with the Rust
# `ir::winapi_prototypes::to_windows_type` used by the decompiler call hints.
_WINDOWS_TYPEDEFS = {
    "uint8_t": "BYTE",
    "uint16_t": "WORD",
    "uint32_t": "DWORD",
    "uint64_t": "DWORD64",
    "int8_t": "CHAR",
    "int16_t": "SHORT",
    "int32_t": "LONG",
    "int64_t": "LONGLONG",
    "uintptr_t": "SIZE_T",
    "intptr_t": "SSIZE_T",
    "void *": "LPVOID",
    "void * *": "LPVOID *",
    "uint8_t *": "LPVOID",
    "uint16_t *": "LPWORD",
    "uint32_t *": "LPDWORD",
    "uint64_t *": "PDWORD64",
    "int32_t *": "LPLONG",
}


def _to_windows_type(c_type: str) -> str:
    """Windows-typedef display spelling for a proto C type (pass-through if not
    in the table)."""
    return _WINDOWS_TYPEDEFS.get(c_type.strip(), c_type)


def _api_call_row(name: str, arg_exprs: list[str]) -> dict[str, Any]:
    proto = _prototype_for_api(name)
    params = list(proto.get("params") or []) if proto else []
    args = []
    for idx, expr in enumerate(arg_exprs):
        arg: dict[str, Any] = {"index": idx, "expr": expr}
        if idx < len(params):
            param = params[idx]
            param_name = str(param.get("name", ""))
            c_type = str(param.get("c_type", ""))
            if param_name:
                arg["param"] = param_name
            if c_type:
                arg["type"] = _to_windows_type(c_type)
            role = _param_role(param_name, c_type)
            if role:
                arg["role"] = role
        value = _parse_expr_int_literal(expr)
        if value is not None:
            arg["value"] = value
            arg["hex"] = hex(value)
        args.append(arg)

    row: dict[str, Any] = {
        "name": name,
        "return_type": str(proto.get("return_type")) if proto else None,
        "args": args,
    }
    roles = sorted({str(arg["role"]) for arg in args if "role" in arg})
    if roles:
        row["roles"] = roles
    return row


def _api_name_lookup(api_names: list[str]) -> dict[str, str]:
    lookup: dict[str, str] = {}
    for name in sorted(api_names, key=lambda item: (len(item), item.lower())):
        clean = _clean_import_name(name)
        if not clean:
            continue
        lookup[clean.lower()] = clean
        lookup.setdefault(_api_stem(clean), clean)
    return lookup


def _split_pseudocode_statements(pseudocode: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    quote = ""
    escaped = False
    for ch in pseudocode:
        if quote:
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
            current.append(ch)
            continue
        if ch == ";":
            statement = "".join(current).strip()
            if statement:
                statements.append(statement)
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        statements.append(tail)
    return statements


def _record_pending_arg(statement: str, pending_args: dict[int, str]) -> bool:
    match = re.search(
        r"(?:^|[:\s])arg(?P<idx>\d+)\s*=\s*(?P<expr>.+)\Z",
        statement.strip(),
    )
    if match is None:
        return False
    pending_args[int(match.group("idx"))] = match.group("expr").strip()
    return True


def _first_call_match(
    statement: str,
    call_pattern: re.Pattern[str],
) -> re.Match[str] | None:
    for match in call_pattern.finditer(statement):
        if match.group("name") in {"if", "for", "while", "switch"}:
            continue
        return match
    return None


def _statement_has_raw_call(statement: str) -> bool:
    return re.search(r"\b0x[0-9a-fA-F]+\s*\(", statement) is not None


def _fill_call_arg_exprs(
    name: str,
    arg_exprs: list[str],
    pending_args: dict[int, str],
) -> list[str]:
    if not pending_args:
        return arg_exprs
    proto = _prototype_for_api(name)
    params = list(proto.get("params") or []) if proto else []
    limit = len(params) if params else max(pending_args) + 1
    out = list(arg_exprs)
    while len(out) < limit:
        idx = len(out)
        expr = pending_args.get(idx)
        if expr is None:
            break
        out.append(expr)
    return out


@lru_cache(maxsize=1)
def _load_winapi_prototypes() -> dict[str, dict[str, Any]]:
    path = (
        Path(__file__).resolve().parents[4]
        / "data"
        / "types"
        / "stdlib-winapi-protos.json"
    )
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {}

    protos: dict[str, dict[str, Any]] = {}
    for proto in data.get("prototypes", []):
        if not isinstance(proto, dict):
            continue
        name = str(proto.get("name", ""))
        if not name:
            continue
        protos[name.lower()] = proto
        protos.setdefault(_api_stem(name), proto)
    return protos


def _prototype_for_api(name: str) -> dict[str, Any] | None:
    clean = _clean_import_name(name)
    protos = _load_winapi_prototypes()
    return protos.get(clean.lower()) or protos.get(_api_stem(clean))


def _split_call_args(args: str) -> list[str]:
    out: list[str] = []
    current: list[str] = []
    depth = 0
    quote = ""
    escaped = False
    for ch in args:
        if quote:
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
            current.append(ch)
            continue
        if ch in "([{<":
            depth += 1
            current.append(ch)
            continue
        if ch in ")]}>":
            depth = max(0, depth - 1)
            current.append(ch)
            continue
        if ch == "," and depth == 0:
            out.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail or args.strip():
        out.append(tail)
    return out


def _param_role(param_name: str, c_type: str) -> str | None:
    name = param_name.lower()
    c_type_lower = c_type.lower()
    if "buffer" in name or name in {"lpdata", "lpbaseaddress", "lpaddress", "buf"}:
        return "buffer"
    if _looks_like_output_length_param(name):
        return "out_length"
    if _looks_like_length_param(name):
        return "length"
    if "flag" in name or name.endswith("flags") or "mode" in name:
        return "flags"
    if (
        c_type_lower == "handle"
        or c_type_lower == "hwnd"
        or c_type_lower.startswith("h")
        or (name.startswith("h") and "handle" in c_type_lower)
    ):
        return "handle"
    if any(token in name for token in ("filename", "pathname", "path", "commandline")):
        return "path"
    if any(
        token in name for token in ("procname", "modulename", "keyname", "valuename")
    ):
        return "name"
    if _is_pointer_ctype(c_type_lower):
        return "pointer"
    return None


def _looks_like_length_param(name: str) -> bool:
    compact = name.replace("_", "")
    if compact in {"ubytes", "nbytes", "nnumberofbytestoread", "cb", "cch"}:
        return True
    if compact.startswith(("cb", "cch")) and len(compact) > 2:
        return True
    return any(
        token in compact
        for token in (
            "size",
            "length",
            "bytecount",
            "numberofbytes",
            "bytesread",
            "bytestoread",
            "count",
        )
    )


def _looks_like_output_length_param(name: str) -> bool:
    compact = name.replace("_", "")
    if compact in {"lpcbdata", "lpcchvalue", "lpcbvalue"}:
        return True
    if compact.startswith(("lpcb", "pcb", "lpcch", "pcch")) and len(compact) > 4:
        return True
    return any(
        token in compact
        for token in (
            "numberofbytesread",
            "numberofbyteswritten",
            "bytesread",
            "byteswritten",
        )
    )


def _is_pointer_ctype(c_type_lower: str) -> bool:
    if "*" in c_type_lower:
        return True
    if c_type_lower.startswith("lp") or c_type_lower.startswith("p"):
        return True
    return c_type_lower in {"voidptr", "uintptr_t"}


def _parse_expr_int_literal(expr: str) -> int | None:
    stripped = expr.strip()
    if not re.fullmatch(r"0x[0-9a-fA-F]+|\d+", stripped):
        return None
    return _parse_int_literal(stripped)


def _format_api_call_summary(call: dict[str, Any]) -> str:
    parts = []
    interesting_roles = {
        "buffer",
        "length",
        "out_length",
        "path",
        "name",
        "flags",
        "handle",
    }
    for arg in call.get("args", []):
        role = str(arg.get("role", ""))
        if role not in interesting_roles:
            continue
        label = str(arg.get("param") or f"arg{arg.get('index', '?')}")
        parts.append(f"{label}={arg.get('expr', '')}")
        if len(parts) >= 3:
            break
    name = str(call.get("name", "api"))
    if not parts:
        return f"{name}({len(call.get('args', []))} args)"
    return f"{name}({', '.join(parts)})"


def _format_evidence_item(item: Any) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, int):
        return format_hex(item)
    try:
        return json.dumps(item, sort_keys=True)
    except TypeError:
        return str(item)


def _stack_ref_pattern() -> re.Pattern[str]:
    return re.compile(
        r"\b(?P<base>[re]?[bs]p)\s*(?P<sign>[+-])\s*(?P<value>0x[0-9a-fA-F]+|\d+)"
    )


def _parse_int_literal(value: str) -> int | None:
    try:
        return int(value, 0)
    except ValueError:
        return None


def _contains_api_name(lower_text: str, needle: str) -> bool:
    if not needle:
        return False
    suffix = "[aw]?" if len(needle) > 2 and needle[-1] not in {"a", "w"} else ""
    pattern = rf"(?<![a-z0-9_]){re.escape(needle)}{suffix}(?![a-z0-9_])"
    return re.search(pattern, lower_text) is not None


def _flow_hints_from_api_sequence(api_sequence: list[str]) -> list[dict[str, Any]]:
    stems = [_api_stem(name) for name in api_sequence]
    ordered = _ordered_file_read_allocation_flow(stems)
    if not ordered:
        return []
    evidence = [api_sequence[idx] for idx in ordered]
    return [
        {
            "kind": "file-read-allocation-flow",
            "summary": "ordered CreateFile/ReadFile/allocation/ReadFile sequence",
            "evidence": evidence,
        }
    ]


def _flow_hints_from_api_calls(api_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    for alloc_idx, alloc_call in enumerate(api_calls):
        if not _is_allocation_call(alloc_call):
            continue
        alloc_size = _first_arg_with_role(alloc_call, "length")
        if alloc_size is None:
            continue
        alloc_expr = str(alloc_size.get("expr", ""))
        if not alloc_expr:
            continue
        normalized_alloc_expr = _normalize_expr(alloc_expr)
        for read_call in api_calls[alloc_idx + 1 :]:
            if not _api_stem(str(read_call.get("name", ""))).startswith("readfile"):
                continue
            read_length = _first_arg_with_role(read_call, "length")
            if read_length is None:
                continue
            read_expr = str(read_length.get("expr", ""))
            if _normalize_expr(read_expr) != normalized_alloc_expr:
                continue
            evidence = [
                _format_role_evidence(alloc_call, alloc_size),
                _format_role_evidence(read_call, read_length),
            ]
            read_buffer = _first_arg_with_role(read_call, "buffer")
            if read_buffer is not None:
                evidence.append(_format_role_evidence(read_call, read_buffer))
            hints.append(
                {
                    "kind": "file-read-allocation-argument-flow",
                    "summary": "allocation size is reused as ReadFile length",
                    "evidence": evidence,
                }
            )
            break
    hints.extend(_file_read_length_field_flow_hints(api_calls))
    hints.extend(_resource_size_flow_hints(api_calls))
    hints.extend(_registry_query_size_flow_hints(api_calls))
    hints.extend(_dynamic_api_resolution_flow_hints(api_calls))
    return hints[:16]


def _file_read_length_field_flow_hints(
    api_calls: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    for alloc_idx, alloc_call in enumerate(api_calls):
        if not _is_allocation_call(alloc_call):
            continue
        alloc_size = _first_arg_with_role(alloc_call, "length")
        if alloc_size is None:
            continue
        alloc_expr = str(alloc_size.get("expr", ""))
        normalized_alloc_expr = _normalize_expr(alloc_expr)
        if not normalized_alloc_expr:
            continue

        length_seed = _find_prior_small_read_into_expr(
            api_calls[:alloc_idx],
            normalized_alloc_expr,
        )
        if length_seed is None:
            continue

        later_read = _find_later_read_with_length_expr(
            api_calls[alloc_idx + 1 :],
            normalized_alloc_expr,
        )
        if later_read is None:
            continue

        seed_call, seed_buffer, seed_length = length_seed
        read_call, read_length = later_read
        hints.append(
            {
                "kind": "file-read-length-field-allocation-flow",
                "summary": (
                    "small ReadFile length field controls allocation and "
                    "later ReadFile length"
                ),
                "evidence": [
                    _format_role_evidence(seed_call, seed_buffer),
                    _format_role_evidence(seed_call, seed_length),
                    _format_role_evidence(alloc_call, alloc_size),
                    _format_role_evidence(read_call, read_length),
                ],
            }
        )
    return hints


def _find_prior_small_read_into_expr(
    prior_calls: list[dict[str, Any]],
    normalized_expr: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    for call in reversed(prior_calls):
        if not _is_readfile_call(call):
            continue
        buffer_arg = _first_arg_with_role(call, "buffer")
        length_arg = _first_arg_with_role(call, "length")
        if buffer_arg is None or length_arg is None:
            continue
        if _normalize_expr(str(buffer_arg.get("expr", ""))) != normalized_expr:
            continue
        if not _is_small_fixed_read_length(length_arg):
            continue
        return call, buffer_arg, length_arg
    return None


def _find_later_read_with_length_expr(
    later_calls: list[dict[str, Any]],
    normalized_expr: str,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    for call in later_calls:
        if not _is_readfile_call(call):
            continue
        length_arg = _first_arg_with_role(call, "length")
        if length_arg is None:
            continue
        if _normalize_expr(str(length_arg.get("expr", ""))) == normalized_expr:
            return call, length_arg
    return None


def _resource_size_flow_hints(api_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    size_sources: list[tuple[int, dict[str, Any], str]] = []
    for idx, call in enumerate(api_calls):
        if not _is_sizeofresource_call(call):
            continue
        assigned_to = str(call.get("assigned_to", ""))
        if not assigned_to:
            continue
        size_sources.append((idx, call, _normalize_expr(assigned_to)))

    seen: set[tuple[str, str, str]] = set()
    for size_idx, size_call, normalized_size in size_sources:
        if not normalized_size:
            continue
        for later_call in api_calls[size_idx + 1 :]:
            kind = _resource_size_flow_kind(later_call)
            if kind is None:
                continue
            size_arg = _resource_size_arg(later_call)
            if size_arg is None:
                continue
            if _normalize_expr(str(size_arg.get("expr", ""))) != normalized_size:
                continue
            key = (
                kind,
                str(size_call.get("assigned_to", "")),
                str(later_call.get("name", "")),
            )
            if key in seen:
                continue
            seen.add(key)
            hints.append(
                {
                    "kind": kind,
                    "summary": (
                        "SizeofResource result controls a later "
                        f"{str(later_call.get('name', 'API'))} size argument"
                    ),
                    "evidence": [
                        f"{size_call.get('name', 'SizeofResource')}.return="
                        f"{size_call.get('assigned_to')}",
                        _format_role_evidence(later_call, size_arg),
                    ],
                }
            )
    return hints


def _resource_size_flow_kind(call: dict[str, Any]) -> str | None:
    if _is_allocation_call(call):
        return "resource-size-allocation-flow"
    stem = _api_stem(str(call.get("name", "")))
    if stem.startswith("writefile") or _is_copy_or_format_sink_stem(stem):
        return "resource-size-buffer-flow"
    return None


def _resource_size_arg(call: dict[str, Any]) -> dict[str, Any] | None:
    length_arg = _first_arg_with_role(call, "length")
    if length_arg is not None:
        return length_arg
    stem = _api_stem(str(call.get("name", "")))
    if _is_copy_or_format_sink_stem(stem):
        args = list(call.get("args") or [])
        if len(args) >= 3:
            return args[2]
    return None


def _registry_query_size_flow_hints(
    api_calls: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    for alloc_idx, alloc_call in enumerate(api_calls):
        if not _is_allocation_call(alloc_call):
            continue
        alloc_size = _first_arg_with_role(alloc_call, "length")
        if alloc_size is None:
            continue
        normalized_size = _normalize_expr(str(alloc_size.get("expr", "")))
        if not normalized_size:
            continue

        prior_query = _find_prior_registry_size_query(
            api_calls[:alloc_idx],
            normalized_size,
        )
        if prior_query is None:
            continue
        later_query = _find_later_registry_value_read(
            api_calls[alloc_idx + 1 :],
            normalized_size,
        )
        if later_query is None:
            continue

        size_call, size_arg = prior_query
        value_call, value_buffer, value_size = later_query
        hints.append(
            {
                "kind": "registry-query-size-allocation-flow",
                "summary": (
                    "RegQueryValueEx size controls allocation and later "
                    "registry value read size"
                ),
                "evidence": [
                    _format_role_evidence(size_call, size_arg),
                    _format_role_evidence(alloc_call, alloc_size),
                    _format_role_evidence(value_call, value_buffer),
                    _format_role_evidence(value_call, value_size),
                ],
            }
        )
    return hints


def _dynamic_api_resolution_flow_hints(
    api_calls: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    loaded_modules: dict[str, dict[str, Any]] = {}
    seen: set[tuple[str, str]] = set()
    for call in api_calls:
        assigned_to = str(call.get("assigned_to", ""))
        if assigned_to and _is_loadlibrary_call(call):
            loaded_modules[_normalize_expr(assigned_to)] = call
            continue
        if not _is_getprocaddress_call(call):
            continue
        module_arg = _first_arg_with_role(call, "handle")
        proc_arg = _first_arg_with_role(call, "name")
        if module_arg is None:
            continue
        module_expr = _normalize_expr(str(module_arg.get("expr", "")))
        load_call = loaded_modules.get(module_expr)
        if load_call is None:
            continue
        proc_expr = str(proc_arg.get("expr", "")) if proc_arg is not None else ""
        key = (module_expr, proc_expr)
        if key in seen:
            continue
        seen.add(key)
        evidence = [
            f"{load_call.get('name', 'LoadLibrary')}.return="
            f"{load_call.get('assigned_to')}",
            _format_role_evidence(call, module_arg),
        ]
        if proc_arg is not None:
            evidence.append(_format_role_evidence(call, proc_arg))
        hints.append(
            {
                "kind": "dynamic-api-resolution-flow",
                "summary": "LoadLibrary result is used for GetProcAddress dispatch",
                "evidence": evidence,
            }
        )
    return hints


def _find_prior_registry_size_query(
    prior_calls: list[dict[str, Any]],
    normalized_size_expr: str,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    for call in reversed(prior_calls):
        if not _is_regqueryvalue_call(call):
            continue
        data_arg = _first_arg_with_role(call, "buffer")
        size_arg = _first_arg_with_role(call, "out_length")
        if data_arg is None or size_arg is None:
            continue
        if not _is_null_expr(str(data_arg.get("expr", ""))):
            continue
        if _normalize_expr(str(size_arg.get("expr", ""))) != normalized_size_expr:
            continue
        return call, size_arg
    return None


def _find_later_registry_value_read(
    later_calls: list[dict[str, Any]],
    normalized_size_expr: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    for call in later_calls:
        if not _is_regqueryvalue_call(call):
            continue
        data_arg = _first_arg_with_role(call, "buffer")
        size_arg = _first_arg_with_role(call, "out_length")
        if data_arg is None or size_arg is None:
            continue
        if _is_null_expr(str(data_arg.get("expr", ""))):
            continue
        if _normalize_expr(str(size_arg.get("expr", ""))) != normalized_size_expr:
            continue
        return call, data_arg, size_arg
    return None


def _is_readfile_call(call: dict[str, Any]) -> bool:
    return _api_stem(str(call.get("name", ""))).startswith("readfile")


def _is_sizeofresource_call(call: dict[str, Any]) -> bool:
    return _api_stem(str(call.get("name", ""))) == "sizeofresource"


def _is_regqueryvalue_call(call: dict[str, Any]) -> bool:
    return _api_stem(str(call.get("name", ""))).startswith("regqueryvalue")


def _is_loadlibrary_call(call: dict[str, Any]) -> bool:
    return _api_stem(str(call.get("name", ""))).startswith("loadlibrary")


def _is_getprocaddress_call(call: dict[str, Any]) -> bool:
    return _api_stem(str(call.get("name", ""))).startswith("getprocaddress")


def _is_small_fixed_read_length(arg: dict[str, Any]) -> bool:
    value = arg.get("value")
    if not isinstance(value, int):
        return False
    return 1 <= value <= 16


def _is_allocation_call(call: dict[str, Any]) -> bool:
    stem = _api_stem(str(call.get("name", "")))
    return stem in {"localalloc", "heapalloc", "malloc", "calloc", "realloc"}


def _first_arg_with_role(
    call: dict[str, Any],
    role: str,
) -> dict[str, Any] | None:
    for arg in call.get("args", []):
        if arg.get("role") == role:
            return arg
    return None


def _normalize_expr(expr: str) -> str:
    return re.sub(r"\s+", "", expr).lower()


def _is_null_expr(expr: str) -> bool:
    return _normalize_expr(expr) in {"0", "0x0", "null", "nullptr", "none"}


def _format_role_evidence(call: dict[str, Any], arg: dict[str, Any]) -> str:
    name = str(call.get("name", "api"))
    param = str(arg.get("param") or f"arg{arg.get('index', '?')}")
    return f"{name}.{param}={arg.get('expr', '')}"


def _ordered_file_read_allocation_flow(stems: list[str]) -> list[int] | None:
    create_idx = _find_stem_index(stems, 0, lambda stem: stem.startswith("createfile"))
    if create_idx is None:
        return None
    first_read_idx = _find_stem_index(
        stems, create_idx + 1, lambda stem: stem.startswith("readfile")
    )
    if first_read_idx is None:
        return None
    alloc_idx = _find_stem_index(
        stems,
        first_read_idx + 1,
        lambda stem: stem in {"localalloc", "heapalloc", "malloc", "calloc", "realloc"},
    )
    if alloc_idx is None:
        return None
    second_read_idx = _find_stem_index(
        stems, alloc_idx + 1, lambda stem: stem.startswith("readfile")
    )
    if second_read_idx is None:
        return None
    return [create_idx, first_read_idx, alloc_idx, second_read_idx]


def _find_stem_index(
    stems: list[str],
    start: int,
    predicate: Callable[[str], bool],
) -> int | None:
    for idx in range(start, len(stems)):
        if predicate(stems[idx]):
            return idx
    return None


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
    if any(_is_copy_or_format_sink_stem(stem) for stem in stems):
        patterns.append("copy-or-format-sink")
    if any(stem.startswith("writefile") for stem in stems) and any(
        stem.startswith("deletefile") for stem in stems
    ):
        patterns.append("temp-file-write-delete")
    if (
        any(stem.startswith("findresource") for stem in stems)
        and any(stem == "sizeofresource" for stem in stems)
        and any(stem == "loadresource" for stem in stems)
        and any(stem == "lockresource" for stem in stems)
    ):
        patterns.append("resource-extraction")
    if _has_network_client_shape(stems):
        patterns.append("network-client")
    return patterns


def _has_network_client_shape(stems: set[str]) -> bool:
    winsock = (
        "wsastartup" in stems
        and "socket" in stems
        and "connect" in stems
        and bool(stems & {"send", "recv"})
    )
    winhttp = (
        "winhttpopen" in stems
        and "winhttpconnect" in stems
        and (
            "winhttpsendrequest" in stems
            or "winhttpopenrequest" in stems
            or "winhttpreceiveresponse" in stems
        )
    )
    wininet = any(stem.startswith("internetopen") for stem in stems) and (
        "internetconnect" in stems
        or "internetopenurl" in stems
        or "httpsendrequest" in stems
        or "internetreadfile" in stems
    )
    return winsock or winhttp or wininet


def _is_copy_or_format_sink_stem(stem: str) -> bool:
    prefixes = (
        "copymemory",
        "rtlcopymemory",
        "rtlmovememory",
        "lstrcpy",
        "lstrcat",
        "lstrcpyn",
        "memcpy",
        "memmove",
        "strncpy",
        "strcpy",
        "strcat",
        "sprintf",
        "wsprintf",
        "swprintf",
        "wcsncpy",
        "wcscpy",
        "wcscat",
    )
    return stem.startswith(prefixes)


def _build_risk_items(
    risk_imports: dict[str, list[str]],
    functions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    items = []
    for bucket, names in risk_imports.items():
        severity = "medium" if bucket in {"file_io", "registry"} else "low"
        if bucket in {"dynamic_loading", "copy_format", "resource"}:
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
        for role in row.get("metadata_roles", []):
            if role != "tls_callback":
                continue
            items.append(
                {
                    "kind": "metadata-role:tls-callback",
                    "severity": "medium",
                    "summary": f"{row['name']} is a PE TLS callback entrypoint",
                    "evidence": [
                        ref
                        for ref in row.get("metadata_refs", [])
                        if ref.get("kind") == "tls_callback"
                    ][:4],
                    "function_va": row["entry_va"],
                }
            )
        for hint in row.get("flow_hints", []):
            items.append(
                {
                    "kind": hint.get("kind", "flow-hint"),
                    "severity": "high",
                    "summary": (
                        f"{row['name']} has {hint.get('summary', 'flow hint')}"
                    ),
                    "evidence": list(hint.get("evidence") or [])[:12],
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
