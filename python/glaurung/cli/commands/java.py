"""Daily-use Java/JVM agent CLI command."""

from __future__ import annotations

import argparse
from typing import Any

from glaurung.llm.agents.java_runner import (
    JavaAgentRunResult,
    run_java_agent_analysis,
)

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class JavaCommand(BaseCommand):
    """Run focused Java/JVM pydantic-ai agents."""

    def get_name(self) -> str:
        return "java"

    def get_help(self) -> str:
        return "Run Java/JVM agent workflows"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        subparsers = parser.add_subparsers(
            dest="java_action",
            required=True,
            help="Java workflow to run",
        )
        for action in ("triage", "security", "recovery"):
            child = subparsers.add_parser(action, help=f"Run Java {action} agent")
            self._add_common_child_arguments(child)
            child.set_defaults(java_profile=action)

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        path = self.validate_file_path(args.path)
        result = run_java_agent_analysis(
            path,
            profile=args.java_profile,
            model=args.model,
            prompt=args.prompt,
            config_roots=args.config_root,
            mapping_path=args.mapping_path,
            max_classes=args.max_classes,
            max_resources=args.max_resources,
            max_findings=args.max_findings,
        )
        payload = result.model_dump(mode="json")
        if formatter.format_type == OutputFormat.JSON:
            formatter.output_json(payload)
        elif formatter.format_type == OutputFormat.JSONL:
            formatter.output_jsonl(payload)
        elif formatter.format_type == OutputFormat.RICH:
            formatter.output_rich(
                formatter.create_markdown(
                    _format_markdown(
                        result,
                        show_tools=args.show_tools,
                        max_tool_calls=args.max_tool_calls,
                        show_evidence=args.show_evidence,
                    )
                )
            )
        else:
            formatter.output_plain(
                _format_markdown(
                    result,
                    show_tools=args.show_tools,
                    max_tool_calls=args.max_tool_calls,
                    show_evidence=args.show_evidence,
                )
            )
        return 0

    def _add_common_child_arguments(self, parser: argparse.ArgumentParser) -> None:
        # Repeat output flags on child parsers so `glaurung java security x --json`
        # works like non-nested commands.
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
        parser.add_argument("path", help="JAR/ZIP archive to analyze")
        parser.add_argument(
            "--model", help="pydantic-ai model name, e.g. openai:gpt-5.5"
        )
        parser.add_argument(
            "--prompt",
            help="Optional custom prompt. The selected Java profile context is still seeded.",
        )
        parser.add_argument(
            "--config-root",
            action="append",
            default=[],
            help="Configuration directory/file root for behavior correlation.",
        )
        parser.add_argument(
            "--mapping-path", help="Optional ProGuard/Mojang/Tiny mapping"
        )
        parser.add_argument("--max-classes", type=int, default=512)
        parser.add_argument("--max-resources", type=int, default=128)
        parser.add_argument("--max-findings", type=int, default=64)
        parser.add_argument(
            "--show-tools",
            action="store_true",
            help="Show the tool-call evidence trail in plain/rich output.",
        )
        parser.add_argument(
            "--max-tool-calls",
            type=int,
            default=8,
            help="Maximum tool calls to show with --show-tools.",
        )
        parser.add_argument(
            "--show-evidence",
            action="store_true",
            help="Show per-finding evidence lines in plain/rich output.",
        )


def _format_markdown(
    result: JavaAgentRunResult,
    *,
    show_tools: bool = False,
    max_tool_calls: int = 8,
    show_evidence: bool = False,
) -> str:
    assessment = result.assessment
    lines = [
        f"# Java {result.profile.title()} Analysis",
        "",
        f"- archive: `{result.path}`",
        f"- model: `{result.model}`",
        f"- context: {result.context.headline}",
        f"- tools: {result.tool_call_count}",
        "",
        "## Summary",
        "",
        assessment.summary,
    ]
    findings = getattr(assessment, "findings", [])
    if findings:
        lines.extend(["", "## Findings", ""])
        for finding in findings:
            title = getattr(finding, "title", "finding")
            severity = getattr(finding, "severity", "info")
            location = _finding_location(finding)
            lines.append(f"- **{severity}** {title}{location}")
            evidence = getattr(finding, "evidence", [])
            if show_evidence and evidence:
                lines.append("  Evidence:")
                lines.extend(f"  - {item}" for item in evidence[:4])
    next_tools = getattr(assessment, "recommended_next_tools", [])
    if next_tools:
        lines.extend(["", "## Next Tools", ""])
        lines.extend(f"- `{tool}`" for tool in next_tools)
    if show_tools and result.tool_calls:
        lines.extend(["", "## Tool Calls", ""])
        lines.extend(
            _format_tool_call(call.model_dump())
            for call in result.tool_calls[: max(0, max_tool_calls)]
        )
    return "\n".join(lines) + "\n"


def _finding_location(finding: Any) -> str:
    class_name = getattr(finding, "class_name", None)
    method_name = getattr(finding, "method_name", None)
    descriptor = getattr(finding, "method_descriptor", None)
    if class_name and method_name:
        return f" in `{class_name}.{method_name}{descriptor or ''}`"
    if class_name:
        return f" in `{class_name}`"
    return ""


def _format_tool_call(call: dict[str, Any]) -> str:
    marker = " seeded" if call.get("seeded") else ""
    error = f" error={call['error']!r}" if call.get("error") else ""
    return f"- `{call.get('tool', '')}`{marker}{error}"
