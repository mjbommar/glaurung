"""Type/prototype data management CLI commands."""

from __future__ import annotations

import argparse
from pathlib import Path

from glaurung.types.sync import (
    DEFAULT_CACHE_DIR,
    DEFAULT_GENERATED_DIR,
    DEFAULT_LOCK_PATH,
    DEFAULT_OUTPUT_PATH,
    DEFAULT_OVERLAY_PATH,
    sync_windows_api_types,
)

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class TypesCommand(BaseCommand):
    """Manage generated type and prototype databases."""

    def get_name(self) -> str:
        return "types"

    def get_help(self) -> str:
        return "Manage generated type/prototype data"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        subparsers = parser.add_subparsers(
            dest="types_action",
            required=True,
            help="Type-data action to run",
        )
        sync = subparsers.add_parser(
            "sync",
            help="Regenerate Windows API prototypes from pinned metadata",
        )
        self._add_common_child_arguments(sync)
        sync.add_argument("--source-lock", type=Path, default=DEFAULT_LOCK_PATH)
        sync.add_argument("--overlay", type=Path, default=DEFAULT_OVERLAY_PATH)
        sync.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
        sync.add_argument("--generated-dir", type=Path, default=DEFAULT_GENERATED_DIR)
        sync.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
        sync.add_argument(
            "--header",
            dest="headers",
            action="append",
            type=Path,
            default=[],
            help="Local SDK/WDK-style header to parse with Clang AST JSON",
        )
        sync.add_argument(
            "--clang",
            default="clang",
            help="Clang executable for --header augmentation",
        )
        sync.add_argument(
            "--clang-arg",
            dest="clang_args",
            action="append",
            default=[],
            help="Extra argument passed to Clang before each --header path",
        )
        sync.add_argument(
            "--offline",
            action="store_true",
            help="Refuse network and use only cached NuGet packages",
        )
        sync.add_argument(
            "--no-overlays",
            action="store_true",
            help="Do not merge curated Glaurung semantic/prototype overlays",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        if args.types_action != "sync":
            raise ValueError(f"unsupported types action: {args.types_action}")

        manifest = sync_windows_api_types(
            source_lock=args.source_lock,
            overlay_path=args.overlay,
            output_path=args.output,
            generated_dir=args.generated_dir,
            cache_dir=args.cache_dir,
            offline=bool(args.offline),
            include_overlays=not bool(args.no_overlays),
            header_paths=list(args.headers or []),
            clang=str(args.clang),
            clang_args=list(args.clang_args or []),
        )
        if formatter.format_type == OutputFormat.JSON:
            formatter.output_json(manifest)
        elif formatter.format_type == OutputFormat.JSONL:
            formatter.output_jsonl(manifest)
        else:
            formatter.output_plain(_format_sync_human(manifest))
        return 0

    def _add_common_child_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--format",
            choices=["plain", "rich", "json", "jsonl"],
            default=argparse.SUPPRESS,
            help="Output format (default: plain)",
        )
        parser.add_argument(
            "--json",
            action="store_true",
            default=argparse.SUPPRESS,
            help="Alias for --format json",
        )
        parser.add_argument(
            "--no-color",
            action="store_true",
            default=argparse.SUPPRESS,
            help="Disable colored output (forces plain format)",
        )
        parser.add_argument(
            "--quiet",
            "-q",
            action="store_true",
            default=argparse.SUPPRESS,
            help="Suppress non-essential output",
        )
        parser.add_argument(
            "--verbose",
            "-v",
            action="store_true",
            default=argparse.SUPPRESS,
            help="Enable verbose output",
        )


def _format_sync_human(manifest: dict) -> str:
    lines = [
        "# Windows API type sync",
        f"prototypes: {manifest.get('prototype_count', 0)}",
        f"bundle: {manifest.get('output_path')}",
        f"manifest: {manifest.get('manifest_path')}",
        f"sha256: {manifest.get('bundle_sha256')}",
    ]
    for source in manifest.get("source_results", []) or []:
        lines.append(
            "source "
            f"{source.get('source_id')}: "
            f"{source.get('package')} {source.get('version')} "
            f"prototypes={source.get('prototype_count', 0)} "
            f"sha256={source.get('winmd_sha256')}"
        )
    for header in manifest.get("header_results", []) or []:
        lines.append(
            "header "
            f"{header.get('header_path')}: "
            f"prototypes={header.get('prototype_count', 0)} "
            f"sha256={header.get('header_sha256')}"
        )
    overlay = manifest.get("overlay")
    if overlay:
        lines.append(
            "overlay: "
            f"added={overlay.get('prototype_added', 0)} "
            f"updated={overlay.get('prototype_updated', 0)} "
            f"semantics={overlay.get('semantics_attached', 0)}"
        )
    return "\n".join(lines)
