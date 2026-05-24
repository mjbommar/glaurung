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

from .base import BaseCommand
from .. import cache as _cache
from ..formatters.base import BaseFormatter, OutputFormat

log = logging.getLogger(__name__)


def _decompile_with_cache(
    *,
    path: str,
    func_va: int,
    style: str,
    timeout_ms: int,
    types: bool,
    pdb_cache: str,
    cache_dir_arg: Optional[str],
) -> str:
    """Run ``g.ir.decompile_at`` with optional persistent caching.

    Cache logic is best-effort: any cache failure logs a WARNING and
    falls through to the live decompile path. Behaviour is identical
    to a direct ``decompile_at`` call when caching is disabled.
    """

    cache_dir = _cache.resolve_cache_dir(cache_dir_arg)
    paths = None
    if cache_dir is not None:
        try:
            binary_sha = _cache.sha256_file(Path(path))
            flags = _cache.canonical_flag_dict(
                [
                    ("style", style or "plain"),
                    ("types", bool(types)),
                    ("timeout_ms", int(timeout_ms)),
                    # The PDB cache *path* shouldn't be part of the key
                    # (it's a machine-local detail), but its *presence*
                    # changes name resolution and therefore output.
                    ("pdb_cache_present", bool(pdb_cache)),
                    # Reserved for future flags so existing entries
                    # naturally invalidate when the schema grows.
                    ("schema", 1),
                ]
            )
            paths = _cache.build_paths(
                cache_dir,
                namespace="decomp",
                binary_sha256=binary_sha,
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
            "--func",
            dest="func",
            type=lambda x: int(x, 0),
            default=None,
            help="Entry VA of the function to decompile (hex or decimal). "
            "If omitted, the detected entry point is used.",
        )
        parser.add_argument(
            "--all",
            dest="all",
            action="store_true",
            help="Decompile up to --limit discovered functions instead of one.",
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
            default=500,
            help="Per-function analysis timeout in milliseconds (default: 500).",
        )
        parser.add_argument(
            "--style",
            choices=["plain", "c"],
            default="plain",
            help="Pseudocode style: 'plain' keeps the register-level detail "
            "(default); 'c' strips the %% prefix and annotations for a "
            "closer-to-C view.",
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
            help="Optional persistent cache directory for decompile output. "
            "Entries are keyed by (glaurung version, sha256(binary), VA, "
            "decompile flags). Falls back to $GLAURUNG_CACHE_DIR when "
            "unset. Append-only — clear the directory manually if disk "
            "fills up.",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        try:
            path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        as_json = formatter.format_type in (OutputFormat.JSON, OutputFormat.JSONL)

        try:
            if args.all:
                results = g.ir.decompile_all(
                    str(path),
                    args.limit,
                    timeout_ms=args.timeout_ms,
                    pdb_cache=args.pdb_cache,
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
            func_va: Optional[int] = args.func
            if func_va is None:
                got = g.analysis.detect_entry_path(str(path))
                if got is None:
                    formatter.output_plain(
                        "Error: could not detect entry point; pass --func 0xVA"
                    )
                    return 2
                func_va = int(got[3])

            try:
                style = "c" if args.style == "c" else ""
                text = _decompile_with_cache(
                    path=str(path),
                    func_va=int(func_va),
                    style=style,
                    timeout_ms=args.timeout_ms,
                    types=args.types,
                    pdb_cache=args.pdb_cache,
                    cache_dir_arg=args.cache_dir,
                )
            except ValueError as e:
                formatter.output_plain(f"Error: {e}")
                return 2

            if as_json:
                print(
                    json.dumps({"entry_va": int(func_va), "pseudocode": text}, indent=2)
                )
            else:
                formatter.output_plain(text)
            return 0
        except Exception as e:  # pragma: no cover - surfaces as CLI error
            formatter.output_plain(f"Error: {e}")
            return 1
