"""Decompile command — render a function's lifted LLIR as C-like pseudocode.

Thin wrapper around the native ``glaurung.ir.decompile_at`` /
``glaurung.ir.decompile_all`` bindings. The full decompiler pipeline
(cfg discovery → LLIR lift → SSA → structural analysis → AST lowering →
expression reconstruction → DCE → name resolution → call-arg reconstruction)
runs inside the Rust extension; this command is just the CLI frontend.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Optional

import glaurung as g
from glaurung.windows_config import load_windows_analysis_config

from .base import BaseCommand
from .. import cache as _cache
from ..formatters.base import BaseFormatter, OutputFormat
from ..func_ref import (
    FuncResolutionError,
    parse_func_arg,
    resolve_func_to_va,
)

log = logging.getLogger(__name__)


def _decompile_at_cached(
    *,
    path: str,
    func_va: int,
    style: str,
    types: bool,
    timeout_ms: int,
    max_blocks: int,
    max_instructions: int,
    pdb_cache: str,
    cache_dir_arg: Optional[str],
) -> str:
    """Run ``g.ir.decompile_at`` with optional persistent caching.

    Entries are keyed by (glaurung version, sha256(binary), VA, decompile
    flags). Cache logic is best-effort: any cache I/O failure logs a WARNING
    and falls through to the live decompile, so behaviour is identical to a
    direct ``decompile_at`` call when caching is disabled or unavailable.
    """
    cache_dir = _cache.resolve_cache_dir(cache_dir_arg)
    paths = None
    if cache_dir is not None:
        try:
            flags = _cache.canonical_flag_dict(
                [
                    ("style", style or "plain"),
                    ("types", bool(types)),
                    ("timeout_ms", int(timeout_ms)),
                    ("max_blocks", int(max_blocks)),
                    ("max_instructions", int(max_instructions)),
                    # The PDB cache *path* is a machine-local detail and must
                    # not enter the key, but its *presence* changes name
                    # resolution and therefore the output.
                    ("pdb_cache_present", bool(pdb_cache)),
                    # Bump when the flag schema grows so old entries invalidate.
                    ("schema", 2),
                ]
            )
            paths = _cache.build_paths(
                cache_dir,
                namespace="decomp",
                binary_sha256=_cache.sha256_file(Path(path)),
                va=func_va,
                flags=flags,
                suffix=f".{style or 'plain'}.c",
            )
            hit = _cache.read_text(paths)
            if hit is not None:
                log.debug("decomp cache HIT %s", paths.file)
                return hit
            log.debug("decomp cache MISS %s", paths.file)
        except OSError as exc:
            log.warning(
                "decomp cache: setup failed (%s); falling back to live decompile",
                exc,
            )
            paths = None

    text = g.ir.decompile_at(
        path,
        int(func_va),
        max_blocks=max_blocks,
        max_instructions=max_instructions,
        timeout_ms=timeout_ms,
        types=types,
        style=style,
        pdb_cache=pdb_cache,
    )
    if paths is not None:
        _cache.write_text(paths, text)
    return text


class DecompileCommand(BaseCommand):
    """Produce pseudocode for one or more discovered functions."""

    def get_name(self) -> str:
        return "decompile"

    def get_help(self) -> str:
        return "Decompile one or more functions to pseudocode"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", help="Path to file")
        parser.add_argument(
            "--analysis-config",
            help=(
                "Optional Windows analysis config YAML/JSON. Defaults to "
                ".glaurung/windows-analysis.yaml or "
                "$GLAURUNG_WINDOWS_ANALYSIS_CONFIG when present."
            ),
        )
        parser.add_argument(
            "--func",
            dest="func",
            type=parse_func_arg,
            default=None,
            help="Function selector: hex VA (0x140001480), decimal, or a "
                 "function name like 'main' resolved against analysis. If "
                 "omitted, the detected entry point is used. Stripped "
                 "binaries only have sub_<VA> names so VA is preferred.",
        )
        parser.add_argument(
            "--all",
            dest="all",
            action="store_true",
            help="Decompile up to --limit discovered functions instead of one.",
        )
        parser.add_argument(
            "--vas",
            dest="vas",
            default=None,
            help="Decompile exactly this comma/space-separated list of entry "
                 "VAs (each hex 0x... or decimal) in a single analysis pass. "
                 "Emits a JSON list of {name, entry_va, pseudocode}. Intended "
                 "for batch/benchmark harnesses that already know their target "
                 "function set (e.g. DWARF low_pc addresses).",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=8,
            help="Max number of functions to decompile with --all (default: 8).",
        )
        parser.add_argument(
            "--no-types",
            dest="types",
            action="store_false",
            default=True,
            help="Disable type-annotation pass in the output.",
        )
        parser.add_argument(
            "--timeout-ms",
            type=int,
            default=None,
            help="Per-function analysis timeout in milliseconds. Defaults to analysis config.",
        )
        parser.add_argument(
            "--max-blocks",
            type=int,
            default=None,
            help="Per-function max basic blocks. Defaults to analysis config.",
        )
        parser.add_argument(
            "--max-instructions",
            type=int,
            default=None,
            help="Per-function max instructions. Defaults to analysis config.",
        )
        parser.add_argument(
            "--range-start",
            type=lambda x: int(x, 0),
            default=None,
            help="Explicit function range start VA for range-seeded decompile.",
        )
        parser.add_argument(
            "--range-end",
            type=lambda x: int(x, 0),
            default=None,
            help="Explicit exclusive function range end VA for range-seeded decompile.",
        )
        parser.add_argument(
            "--style",
            choices=["plain", "c", "decbench"],
            default="plain",
            help="Pseudocode style: 'plain' keeps the register-level detail "
                 "(default); 'c' strips the %% prefix and annotations for a "
                 "closer-to-C view; 'decbench' emits parseable C (a real "
                 "'long name(long arg0, ...)' signature with declared locals) "
                 "for external tooling that parses the output as C.",
        )
        parser.add_argument(
            "--pdb-cache",
            default="",
            help="Optional Microsoft-style PDB cache directory used to resolve "
                 "PE/PDB public function names in decompile output.",
        )
        parser.add_argument(
            "--cache-dir",
            default=None,
            help="Optional persistent cache directory for single-function "
                 "decompile output. Entries are keyed by (glaurung version, "
                 "sha256(binary), VA, decompile flags). Falls back to "
                 "$GLAURUNG_CACHE_DIR when unset. Append-only — clear the "
                 "directory manually if disk fills up.",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        try:
            path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        as_json = formatter.format_type in (OutputFormat.JSON, OutputFormat.JSONL)

        try:
            config = load_windows_analysis_config(args.analysis_config).with_overrides(
                max_blocks=args.max_blocks,
                max_instructions=args.max_instructions,
                timeout_ms=args.timeout_ms,
                pdb_cache_dir=args.pdb_cache or None,
            )
            timeout_ms = config.timeout_ms
            max_blocks = config.max_blocks
            max_instructions = config.max_instructions
            # Native style token: "" (plain), "c" (register-view), or "decbench"
            # (parseable C). The public --style values map straight through.
            style = "" if args.style == "plain" else args.style

            # Batch-by-VA mode: decompile exactly the requested entry VAs in a
            # single analysis pass. Mirrors the JSON shape of --all.
            if args.vas is not None:
                try:
                    vas = _parse_va_list(args.vas)
                except ValueError as e:
                    formatter.output_plain(f"Error: {e}")
                    return 2
                results = g.ir.decompile_many(
                    str(path),
                    vas,
                    max_blocks=max_blocks,
                    max_instructions=max_instructions,
                    timeout_ms=timeout_ms,
                    types=args.types,
                    style=style,
                    pdb_cache=args.pdb_cache or config.pdb_cache_dir or "",
                )
                if as_json:
                    payload = [
                        {"name": name, "entry_va": int(va), "pseudocode": text}
                        for name, va, text in results
                    ]
                    print(json.dumps(payload, indent=2))
                else:
                    for name, va, text in results:
                        formatter.output_plain(text)
                return 0

            if args.all:
                results = g.ir.decompile_all(
                    str(path),
                    args.limit,
                    timeout_ms=timeout_ms,
                    pdb_cache=args.pdb_cache or config.pdb_cache_dir or "",
                    style=style,
                )
                if as_json:
                    payload = [
                        {"name": name, "entry_va": int(va), "pseudocode": text}
                        for name, va, text in results
                    ]
                    print(json.dumps(payload, indent=2))
                else:
                    for name, va, text in results:
                        formatter.output_plain(text)
                return 0

            # Single-function mode.
            func_va: Optional[int] = None
            if isinstance(args.func, int):
                func_va = args.func
            elif isinstance(args.func, str):
                # Name-resolution path. Run a bounded discovery pass so
                # the lookup terminates predictably on large binaries.
                try:
                    discovered = g.analysis.analyze_functions_path(
                        str(path), max_functions=2000,
                    )[0]
                except Exception as e:
                    formatter.output_plain(
                        f"Error: --func name resolution failed during analysis: {e}"
                    )
                    return 2
                try:
                    func_va = resolve_func_to_va(args.func, discovered)
                except FuncResolutionError as e:
                    formatter.output_plain(f"Error: {e}")
                    return 2
            else:
                got = g.analysis.detect_entry_path(str(path))
                if got is None:
                    formatter.output_plain(
                        "Error: could not detect entry point; pass --func 0xVA"
                    )
                    return 2
                func_va = int(got[3])

            try:
                if args.range_end is not None or args.range_start is not None:
                    range_start = args.range_start if args.range_start is not None else int(func_va)
                    if args.range_end is None:
                        formatter.output_plain("Error: --range-end is required with --range-start")
                        return 2
                    text = g.ir.decompile_range_at(
                        str(path),
                        int(func_va),
                        int(range_start),
                        int(args.range_end),
                        max_blocks=max_blocks,
                        max_instructions=max_instructions,
                        timeout_ms=timeout_ms,
                        types=args.types,
                        style=style,
                        pdb_cache=args.pdb_cache or config.pdb_cache_dir or "",
                    )
                else:
                    text = _decompile_at_cached(
                        path=str(path),
                        func_va=int(func_va),
                        style=style,
                        types=args.types,
                        timeout_ms=timeout_ms,
                        max_blocks=max_blocks,
                        max_instructions=max_instructions,
                        pdb_cache=args.pdb_cache or config.pdb_cache_dir or "",
                        cache_dir_arg=args.cache_dir,
                    )
            except ValueError as e:
                formatter.output_plain(f"Error: {e}")
                return 2

            if as_json:
                # Best-effort name: only resolvable when --func was a name.
                name = args.func if isinstance(args.func, str) else ""
                print(
                    json.dumps(
                        {"name": name, "entry_va": int(func_va), "pseudocode": text},
                        indent=2,
                    )
                )
            else:
                formatter.output_plain(text)
            return 0
        except Exception as e:  # pragma: no cover - surfaces as CLI error
            formatter.output_plain(f"Error: {e}")
            return 1


def _parse_va_list(raw: str) -> list[int]:
    """Parse a comma/space-separated list of entry VAs (hex ``0x..`` or decimal).

    Returns the de-duplicated VAs in first-seen order. Raises ``ValueError`` on
    any unparseable token so the caller can surface a clean CLI error.
    """
    seen: set[int] = set()
    out: list[int] = []
    for tok in raw.replace(",", " ").split():
        try:
            va = int(tok, 0)
        except ValueError as e:
            raise ValueError(f"invalid VA in --vas: {tok!r}") from e
        if va not in seen:
            seen.add(va)
            out.append(va)
    if not out:
        raise ValueError("--vas was empty")
    return out
