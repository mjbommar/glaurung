"""Windows PE/COFF inspection CLI commands."""

from __future__ import annotations

import argparse
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.tools.pe_list_resources import (
    PeListResourcesResult,
    build_tool as build_pe_list_resources,
)
from glaurung.llm.tools.pe_view_manifest import (
    PeManifestResult,
    build_tool as build_pe_view_manifest,
)

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class PeCommand(BaseCommand):
    """Inspect Windows PE/COFF-specific structures."""

    def get_name(self) -> str:
        return "pe"

    def get_help(self) -> str:
        return "Inspect Windows PE/COFF resources and metadata"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        subparsers = parser.add_subparsers(
            dest="pe_action",
            required=True,
            help="PE action to run",
        )
        resources = subparsers.add_parser(
            "resources", help="List PE resource directory leaves"
        )
        self._add_common_child_arguments(resources)
        manifest = subparsers.add_parser("manifest", help="Decode RT_MANIFEST")
        self._add_common_child_arguments(manifest)
        manifest.add_argument("--max-text-bytes", type=int, default=65_536)

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        if args.pe_action == "resources":
            path = self.validate_file_path(args.path)
            result = _list_resources(path, args)
            payload = result.model_dump(mode="json")
            if formatter.format_type == OutputFormat.JSON:
                formatter.output_json(payload)
            elif formatter.format_type == OutputFormat.JSONL:
                formatter.output_jsonl(payload)
            else:
                formatter.output_plain(_format_resources_human(result))
            return 0 if "input_not_pe_or_unparseable" not in result.stop_reasons else 4
        if args.pe_action == "manifest":
            path = self.validate_file_path(args.path)
            result = _view_manifest(path, args)
            payload = result.model_dump(mode="json")
            if formatter.format_type == OutputFormat.JSON:
                formatter.output_json(payload)
            elif formatter.format_type == OutputFormat.JSONL:
                formatter.output_jsonl(payload)
            else:
                formatter.output_plain(_format_manifest_human(result))
            return 0 if result.found else 4
        raise ValueError(f"unsupported PE action: {args.pe_action}")

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
        parser.add_argument(
            "path", help="PE executable, DLL, SYS, MUI, or resource file"
        )
        parser.add_argument(
            "--type",
            dest="type_filter",
            help="Filter by resource type name or ID, e.g. VERSIONINFO or 16",
        )
        parser.add_argument(
            "--name",
            dest="name_filter",
            help="Filter by resource name or ID",
        )
        parser.add_argument(
            "--language-id",
            type=_parse_int,
            help="Filter by language ID, decimal or hex",
        )
        parser.add_argument("--min-size", type=int, default=None)
        parser.add_argument("--max-size", type=int, default=None)
        parser.add_argument("--limit", type=int, default=256)
        parser.add_argument("--max-resources", type=int, default=4096)
        parser.add_argument("--max-resource-depth", type=int, default=32)
        parser.add_argument("--max-resource-data-bytes", type=int, default=1_048_576)
        parser.add_argument("--preview-bytes", type=int, default=16)
        parser.add_argument("--max-read-bytes", type=int, default=104_857_600)
        parser.add_argument("--max-file-size", type=int, default=104_857_600)


def _list_resources(path: Path, args: argparse.Namespace) -> PeListResourcesResult:
    artifact = g.triage.analyze_path(
        str(path),
        int(args.max_read_bytes),
        int(args.max_file_size),
        1,
    )
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    ctx.budgets.max_read_bytes = int(args.max_read_bytes)
    ctx.budgets.max_file_size = int(args.max_file_size)
    tool = build_pe_list_resources()
    return tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(path),
            type_filter=args.type_filter,
            name_filter=args.name_filter,
            language_id=args.language_id,
            min_size=args.min_size,
            max_size=args.max_size,
            limit=args.limit,
            max_resources_scan=args.max_resources,
            max_resource_depth=args.max_resource_depth,
            max_resource_data_bytes=args.max_resource_data_bytes,
            preview_bytes=args.preview_bytes,
            add_to_kb=False,
        ),
    )


def _view_manifest(path: Path, args: argparse.Namespace) -> PeManifestResult:
    artifact = g.triage.analyze_path(
        str(path),
        int(args.max_read_bytes),
        int(args.max_file_size),
        1,
    )
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    ctx.budgets.max_read_bytes = int(args.max_read_bytes)
    ctx.budgets.max_file_size = int(args.max_file_size)
    tool = build_pe_view_manifest()
    return tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(path),
            language_id=args.language_id,
            max_text_bytes=args.max_text_bytes,
            add_to_kb=False,
        ),
    )


def _format_resources_human(result: PeListResourcesResult) -> str:
    lines = [
        f"# PE resources: {Path(result.path).name}",
        (
            f"leaves: {result.leaf_count}  matched: {result.matched_resource_count}  "
            f"directories: {result.total_directories}  bytes: {result.resource_bytes_total}"
        ),
    ]
    if result.stop_reasons:
        lines.append(f"stop: {', '.join(result.stop_reasons)}")
    if result.warnings:
        lines.append(f"warnings: {', '.join(result.warnings[:8])}")
    if result.resources_by_type:
        lines.append("types:")
        for resource_type, count in sorted(result.resources_by_type.items()):
            lines.append(f"  {resource_type}: {count}")
    if result.resources:
        lines.append("resources:")
        for resource in result.resources:
            line = (
                f"  {resource.evidence}  size={resource.size}  "
                f"magic={resource.magic}  entropy={resource.entropy:.2f}  "
                f"sha256={resource.sha256[:16]}  preview={resource.preview_hex}"
            )
            if resource.warnings:
                line += f"  warnings={','.join(resource.warnings)}"
            lines.append(line)
    return "\n".join(lines)


def _format_manifest_human(result: PeManifestResult) -> str:
    lines = [f"# PE manifest: {Path(result.path).name}"]
    if result.evidence:
        lines.append(f"evidence: {result.evidence}")
    if result.requested_execution_level:
        lines.append(f"requested_execution_level: {result.requested_execution_level}")
    if result.ui_access is not None:
        lines.append(f"ui_access: {str(result.ui_access).lower()}")
    if result.assembly_identity:
        identity = ", ".join(
            f"{key}={value}" for key, value in sorted(result.assembly_identity.items())
        )
        lines.append(f"assembly_identity: {identity}")
    if result.dependencies:
        lines.append("dependencies:")
        for dependency in result.dependencies:
            lines.append(f"  {dependency}")
    if result.compatibility_guids:
        lines.append("compatibility_guids:")
        for guid in result.compatibility_guids:
            lines.append(f"  {guid}")
    if result.warnings:
        lines.append(f"warnings: {', '.join(result.warnings[:8])}")
    if result.stop_reasons:
        lines.append(f"stop: {', '.join(result.stop_reasons)}")
    return "\n".join(lines)


def _parse_int(value: str) -> int:
    return int(value, 0)
