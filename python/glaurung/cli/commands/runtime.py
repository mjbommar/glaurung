"""Read-only analyst surfaces over persisted runtime evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class RuntimeCommand(BaseCommand):
    """Inspect persisted runtime captures without reacquiring live state."""

    def get_name(self) -> str:
        return "runtime"

    def get_help(self) -> str:
        return "Inspect persisted runtime summaries and static-operation links"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        actions = parser.add_subparsers(dest="runtime_action", required=True)

        capture = actions.add_parser(
            "capture", help="Launch and persist one cooperatively stopped child"
        )
        capture.add_argument("--timeout", type=float, default=5.0)
        capture.add_argument("--run-id", default=None)
        capture.add_argument(
            "--checkpoint", choices=("requested", "entry", "exit"), default="requested"
        )
        capture.add_argument("--cwd", type=Path, default=None)
        capture.add_argument(
            "--env",
            action="append",
            default=[],
            metavar="NAME=VALUE",
            help="Set one child environment value; repeat as needed",
        )
        capture.add_argument(
            "--inherit-environment",
            action="store_true",
            help="Explicitly inherit the caller environment into the child",
        )
        capture.add_argument(
            "--public-input",
            default=None,
            help="Record these UTF-8 input bytes as public capture identity",
        )
        capture.add_argument(
            "--allow-proc-mem-fallback",
            action="store_true",
            help="Allow /proc/PID/mem if process_vm_readv cannot read selected pages",
        )
        capture.add_argument("project", type=Path, help="Existing or new project")
        capture.add_argument("binary", type=Path, help="Exact child executable")
        capture.add_argument(
            "program_args",
            nargs=argparse.REMAINDER,
            help="Child arguments; place them after --",
        )

        summary = actions.add_parser(
            "summary", help="Show a redacted persisted capture summary"
        )
        self._add_capture_arguments(summary)

        import_capture = actions.add_parser(
            "import", help="Verify and persist a process-capsule bundle"
        )
        import_capture.add_argument(
            "project", type=Path, help="Existing or new .glaurung project"
        )
        import_capture.add_argument(
            "metadata", type=Path, help="Path to process-capsule JSON metadata"
        )
        import_capture.add_argument(
            "payload_directory", type=Path, help="Exact capsule payload directory"
        )
        import_capture.add_argument(
            "--binary",
            type=Path,
            default=None,
            help="Exact executable; required when creating a new project",
        )
        import_capture.add_argument(
            "--run-id",
            default=None,
            help="Explicit run identity (default: the capsule capture identity)",
        )

        xrefs = actions.add_parser(
            "observed-xrefs",
            help="List persisted runtime occurrences linked to static LLIR operations",
        )
        self._add_capture_arguments(xrefs)

        crash = actions.add_parser(
            "crash", help="Explain one persisted deterministic crash analysis"
        )
        self._add_capture_arguments(crash)

        mappings = actions.add_parser(
            "mapping-history", help="Show persisted mapping permission lifetimes"
        )
        self._add_capture_arguments(mappings)

        evidence = actions.add_parser(
            "evidence", help="Export a deterministic persisted evidence packet"
        )
        self._add_capture_arguments(evidence)
        evidence.add_argument(
            "--include-sensitive",
            action="store_true",
            help="Include capsule, report documents, and payload bytes",
        )

        compare = actions.add_parser(
            "compare", help="Compare two persisted captures of the same project"
        )
        compare.add_argument("project", type=Path, help="Path to .glaurung project")
        compare.add_argument("left_capture_id", help="Left capture identity")
        compare.add_argument("right_capture_id", help="Right capture identity")

    @staticmethod
    def _add_capture_arguments(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("project", type=Path, help="Path to .glaurung project")
        parser.add_argument("capture_id", help="Persisted capture identity")

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        from glaurung.llm.kb.persistent import PersistentKnowledgeBase
        from glaurung.llm.kb.runtime_relations import (
            compare_runtime_captures_json,
            persist_process_capsule,
            runtime_capture_summary_json,
            runtime_crash_explanation_json,
            runtime_evidence_packet_json,
            runtime_mapping_history_json,
        )

        project = Path(args.project)
        if args.runtime_action not in {"import", "capture"} and not project.is_file():
            formatter.output_plain(f"Error: project not found: {project}")
            return 2

        if args.runtime_action == "capture":
            from glaurung.runtime_capture import capture_stopped_child

            environment: dict[str, str] = {}
            for assignment in args.env:
                name, separator, value = assignment.partition("=")
                if not separator or not name or "\x00" in assignment:
                    raise ValueError(
                        "--env must be a non-empty NAME=VALUE without NUL bytes"
                    )
                if name in environment:
                    raise ValueError(f"duplicate --env name: {name}")
                environment[name] = value
            program_args = list(args.program_args)
            if program_args[:1] == ["--"]:
                program_args.pop(0)
            capture = capture_stopped_child(
                args.binary,
                program_args,
                environment=environment,
                cwd=args.cwd,
                timeout=args.timeout,
                checkpoint=args.checkpoint,
                public_input=(
                    None if args.public_input is None else args.public_input.encode()
                ),
                allow_proc_mem_fallback=args.allow_proc_mem_fallback,
                inherit_environment=args.inherit_environment,
            )
            with PersistentKnowledgeBase.open(project, binary_path=args.binary) as kb:
                persisted = persist_process_capsule(
                    kb,
                    capture.capsule_json,
                    list(capture.payloads),
                    run_id=args.run_id,
                )
                payload = runtime_capture_summary_json(kb, persisted.capture_id)
            if formatter.format_type in {OutputFormat.JSON, OutputFormat.JSONL}:
                formatter.output_plain(payload)
            else:
                formatter.output_plain(
                    f"captured owned child as {persisted.capture_id} in {project}"
                )
            return 0

        if args.runtime_action == "import":
            from glaurung import runtime_analysis

            capsule_json, payloads = runtime_analysis.load_process_capsule_bundle(
                str(args.metadata), str(args.payload_directory)
            )
            with PersistentKnowledgeBase.open(project, binary_path=args.binary) as kb:
                capture = persist_process_capsule(
                    kb, capsule_json, payloads, run_id=args.run_id
                )
                payload = runtime_capture_summary_json(kb, capture.capture_id)
            if formatter.format_type in {OutputFormat.JSON, OutputFormat.JSONL}:
                formatter.output_plain(payload)
            else:
                formatter.output_plain(
                    f"imported capture {capture.capture_id} into {project}"
                )
            return 0

        with PersistentKnowledgeBase.open(project) as kb:
            if args.runtime_action == "compare":
                payload = compare_runtime_captures_json(
                    kb, args.left_capture_id, args.right_capture_id
                )
                if formatter.format_type in {OutputFormat.JSON, OutputFormat.JSONL}:
                    formatter.output_plain(payload)
                else:
                    self._output_comparison(json.loads(payload), formatter)
                return 0

            if args.runtime_action == "crash":
                payload = runtime_crash_explanation_json(kb, args.capture_id)
                if formatter.format_type in {OutputFormat.JSON, OutputFormat.JSONL}:
                    formatter.output_plain(payload)
                else:
                    from glaurung import runtime_analysis

                    formatter.output_plain(
                        runtime_analysis.render_runtime_crash_analysis_json(payload)
                    )
                return 0

            if args.runtime_action == "mapping-history":
                payload = runtime_mapping_history_json(kb, args.capture_id)
                if formatter.format_type in {OutputFormat.JSON, OutputFormat.JSONL}:
                    formatter.output_plain(payload)
                else:
                    self._output_mapping_history(json.loads(payload), formatter)
                return 0

            if args.runtime_action == "evidence":
                payload = runtime_evidence_packet_json(
                    kb,
                    args.capture_id,
                    include_sensitive=args.include_sensitive,
                )
                if formatter.format_type in {OutputFormat.JSON, OutputFormat.JSONL}:
                    formatter.output_plain(payload.rstrip("\n"))
                else:
                    self._output_evidence_packet(json.loads(payload), formatter)
                return 0

            payload = runtime_capture_summary_json(kb, args.capture_id)
            summary = json.loads(payload)
            if args.runtime_action == "observed-xrefs":
                operations = summary["observed_operations"]
                if formatter.format_type == OutputFormat.JSON:
                    formatter.output_json(operations)
                elif formatter.format_type == OutputFormat.JSONL:
                    formatter.output_jsonl(operations)
                else:
                    self._output_observed_xrefs(operations, formatter)
                return 0

            if formatter.format_type in {OutputFormat.JSON, OutputFormat.JSONL}:
                formatter.output_plain(payload)
            else:
                self._output_summary(summary, formatter)
            return 0

    @staticmethod
    def _output_summary(summary: dict[str, Any], formatter: BaseFormatter) -> None:
        capture = summary["capture"]
        formatter.output_plain(
            f"capture {capture['capture_id']} (run {capture['run_id']})"
        )
        formatter.output_plain(
            f"executable {capture['executable_sha256']}  acquisition {capture['acquisition']}"
        )
        for name, count in sorted(summary["counts"].items()):
            formatter.output_plain(f"{name}: {count}")

    @staticmethod
    def _output_observed_xrefs(
        operations: list[dict[str, Any]], formatter: BaseFormatter
    ) -> None:
        if not operations:
            formatter.output_plain("(no observed static-operation links)")
            return
        formatter.output_plain(
            "event  machine_va  function  llir_block  op  kind  occurrence"
        )
        for operation in operations:
            formatter.output_plain(
                f"{operation['event_sequence']}  "
                f"0x{operation['machine_va']:x}  "
                f"0x{operation['function_entry']:x}  "
                f"0x{operation['block_start']:x}  "
                f"{operation['operation_index']}  "
                f"{operation['operation_kind']}  "
                f"{operation['occurrence_id']}"
            )

    @staticmethod
    def _output_comparison(
        comparison: dict[str, Any], formatter: BaseFormatter
    ) -> None:
        formatter.output_plain(
            f"same executable: {str(comparison['same_executable']).lower()}"
        )
        for name, delta in sorted(comparison["count_delta_right_minus_left"].items()):
            if delta:
                formatter.output_plain(f"{name}: {delta:+d}")

    @staticmethod
    def _output_mapping_history(
        report: dict[str, Any], formatter: BaseFormatter
    ) -> None:
        formatter.output_plain(f"capture {report['capture_id']}")
        scope = report["event_scope"]
        formatter.output_plain(f"event scope: {scope['status']}")
        transitions = report["transitions"]
        for index, lifetime in enumerate(report["lifetimes"]):
            history = [lifetime["created_permissions"]]
            history.extend(
                transitions[transition_index]["to_permissions"]
                for transition_index in lifetime["transition_indices"]
            )
            history.append(
                "unmapped"
                if lifetime["removed_sequence"] is not None
                else "still mapped"
            )
            formatter.output_plain(
                f"mapping {index}: "
                f"0x{lifetime['address']:x}-"
                f"0x{lifetime['address'] + lifetime['byte_len']:x}  "
                + " -> ".join(history)
            )
        if report["ignored_events"]:
            formatter.output_plain(f"ignored events: {report['ignored_events']}")

    @staticmethod
    def _output_evidence_packet(
        packet: dict[str, Any], formatter: BaseFormatter
    ) -> None:
        capture = packet["capture_summary"]["capture"]
        formatter.output_plain(f"evidence packet for capture {capture['capture_id']}")
        formatter.output_plain(f"export policy: {packet['export_policy']}")
        formatter.output_plain(f"analysis reports: {len(packet['analysis_reports'])}")
        formatter.output_plain(f"payloads: {len(packet['payloads'])}")
        formatter.output_plain("omitted: " + ", ".join(packet["omissions"]))
