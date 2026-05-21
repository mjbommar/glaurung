"""Windows-focused analysis and parity commands."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import glaurung as g
from glaurung import windows_analysis
from glaurung.llm.agents.windows_interactive_analyst import (
    WindowsInteractiveAnalystConfig,
    WindowsInteractiveAnalystSessionState,
    run_windows_interactive_analyst,
)
from glaurung.llm.agents.windows_analyst_command_loop import (
    WindowsAnalystLoopCommand,
    WindowsAnalystLoopConfig,
    WindowsAnalystLoopResult,
    run_windows_analyst_command_loop,
)
from glaurung.llm.agents.windows_corpus_curator import (
    WindowsCorpusCuratorConfig,
    WindowsCorpusCuratorResult,
    run_windows_corpus_curator,
)
from glaurung.llm.agents.windows_target_pipeline import (
    WindowsTargetPipelineConfig,
    WindowsTargetPipelineResult,
    run_windows_target_pipeline,
)
from glaurung.llm.tools.windows_build_corpus import WindowsBuildCorpusArgs
from glaurung.llm.tools.windows_bootstrap_project_facts import (
    WindowsBootstrapProjectFactsArgs,
    WindowsBootstrapProjectFactsResult,
    build_tool as build_windows_bootstrap_project_facts,
)
from glaurung.llm.tools.windows_emit_review_packet import WindowsReviewPacket
from glaurung.llm.tools.windows_high_volume_preflight import (
    WindowsHighVolumePreflightArgs,
    WindowsHighVolumePreflightResult,
    build_tool as build_windows_high_volume_preflight,
)
from glaurung.llm.tools.windows_project_fact_manifest import (
    WindowsProjectFactManifestArgs,
    WindowsProjectFactManifestResult,
    build_tool as build_windows_project_fact_manifest,
)
from glaurung.llm.tools.windows_pipeline_blocker_task_plan import (
    WindowsPipelineBlockerTaskPlanArgs,
    WindowsPipelineBlockerTaskPlanResult,
    build_tool as build_windows_pipeline_blocker_task_plan,
)
from glaurung.llm.tools.windows_symbol_similarity_extraction_plan import (
    WindowsSymbolSimilarityExtractionPlanArgs,
    WindowsSymbolSimilarityExtractionPlanResult,
    build_tool as build_windows_symbol_similarity_extraction_plan,
)
from glaurung.llm.tools.windows_function_similarity_manifest import (
    WindowsFunctionSimilarityManifestArgs,
    WindowsFunctionSimilarityManifestResult,
    build_tool as build_windows_function_similarity_manifest,
)
from glaurung.llm.tools.windows_runner_artifact_review import (
    WindowsRunnerArtifactReviewArgs,
    WindowsRunnerArtifactReviewResult,
    build_tool as build_windows_runner_artifact_review,
)
from glaurung.llm.tools.windows_runner_artifact_promotion_plan import (
    WindowsRunnerArtifactPromotionPlanArgs,
    WindowsRunnerArtifactPromotionPlanResult,
    build_tool as build_windows_runner_artifact_promotion_plan,
)
from glaurung.llm.tools.windows_runner_artifact_promotion_apply import (
    WindowsRunnerArtifactPromotionApplyArgs,
    WindowsRunnerArtifactPromotionApplyResult,
    build_tool as build_windows_runner_artifact_promotion_apply,
)
from glaurung.llm.context import MemoryContext

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class WindowsCommand(BaseCommand):
    """Windows PE analysis convenience commands."""

    def get_name(self) -> str:
        return "windows"

    def get_help(self) -> str:
        return "Run Windows PE analysis helpers"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        subparsers = parser.add_subparsers(
            dest="windows_action",
            required=True,
            help="Windows action to run",
        )
        diff = subparsers.add_parser(
            "diff-ghidra",
            help="Compare Glaurung function starts with a Ghidra parity JSON report",
        )
        self._add_common_child_arguments(diff)
        diff.add_argument("path", help="Windows PE file to compare")
        diff.add_argument(
            "--ghidra-json",
            required=True,
            help="Ghidra parity JSON file from scripts/windows_ghidra_parity.py",
        )
        diff.add_argument("--limit", type=int, default=32)
        diff.add_argument("--max-read-bytes", type=int, default=104_857_600)
        diff.add_argument("--max-file-size", type=int, default=104_857_600)
        diff.add_argument("--max-functions", type=int, default=0)
        diff.add_argument("--max-blocks", type=int, default=1_000_000)
        diff.add_argument("--max-instructions", type=int, default=30_000_000)
        diff.add_argument("--timeout-ms", type=int, default=600_000)

        analyst = subparsers.add_parser(
            "analyst",
            help="Ask the deterministic Windows analyst workflow a bounded question",
        )
        self._add_common_child_arguments(analyst)
        analyst.add_argument(
            "--intent",
            required=True,
            choices=[
                "explain_function",
                "boundary_gap",
                "triage_queue",
                "patch_diff",
                "candidate_handoff",
                "pipeline_blockers",
            ],
            help="Interactive analyst workflow intent",
        )
        analyst.add_argument("--question", required=True)
        analyst.add_argument(
            "--comparison-path",
            default=(
                "docs/windows-port/"
                "glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
            ),
        )
        analyst.add_argument(
            "--diagnostics-path",
            default="docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json",
        )
        analyst.add_argument("--file")
        analyst.add_argument("--address")
        analyst.add_argument("--max-items", type=int, default=8)
        analyst.add_argument("--binary-a")
        analyst.add_argument("--binary-b")
        analyst.add_argument("--seeds-path")
        analyst.add_argument("--pdb-backed", action="store_true")
        analyst.add_argument(
            "--candidate-packet-path",
            help="Optional JSON review packet for candidate_handoff intent",
        )
        analyst.add_argument(
            "--evidence-export-manifest-path",
            help=(
                "Optional evidence-review export manifest for candidate_handoff "
                "when --candidate-packet-path is not supplied"
            ),
        )
        analyst.add_argument(
            "--candidate-id",
            help="Optional candidate id to select from an evidence export manifest",
        )
        analyst.add_argument(
            "--review-packet-output-path",
            help="Optional JSON path to persist a review-packet handoff",
        )
        analyst.add_argument(
            "--blocker-worklist-path",
            help=(
                "Optional target-pipeline blocker worklist JSON artifact for "
                "pipeline_blockers intent"
            ),
        )
        analyst.add_argument(
            "--blocker-task-plan-path",
            help=(
                "Optional pipeline blocker task-plan JSON artifact for "
                "pipeline_blockers intent"
            ),
        )
        analyst.add_argument(
            "--state-path",
            help="Optional JSON file with bounded analyst session state",
        )
        analyst.add_argument(
            "--session-id",
            help=(
                "Named analyst session. When set, state is automatically "
                "loaded and written under --session-dir."
            ),
        )
        analyst.add_argument(
            "--session-dir",
            default=".glaurung/windows-analyst/sessions",
            help="Directory for --session-id analyst state files",
        )
        analyst.add_argument(
            "--write-state",
            action="store_true",
            help="Write updated analyst session state back to --state-path",
        )

        analyst_loop = subparsers.add_parser(
            "analyst-loop",
            help="Run a bounded multi-turn Windows analyst command script",
        )
        self._add_common_child_arguments(analyst_loop)
        analyst_loop.add_argument(
            "--script-path",
            required=True,
            help=(
                "JSON script containing a commands array of analyst intents. "
                "A top-level JSON list is also accepted."
            ),
        )
        analyst_loop.add_argument(
            "--comparison-path",
            default=(
                "docs/windows-port/"
                "glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
            ),
        )
        analyst_loop.add_argument(
            "--diagnostics-path",
            default="docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json",
        )
        analyst_loop.add_argument("--max-turns", type=int, default=32)
        analyst_loop.add_argument("--default-max-items", type=int, default=8)
        analyst_loop.add_argument(
            "--continue-on-error",
            action="store_false",
            dest="stop_on_error",
            default=True,
            help="Continue running later commands after a failed turn",
        )
        analyst_loop.add_argument(
            "--state-path",
            help="Optional JSON file with bounded analyst session state",
        )
        analyst_loop.add_argument(
            "--session-id",
            help=(
                "Named analyst session. When set, state is automatically "
                "loaded and written under --session-dir."
            ),
        )
        analyst_loop.add_argument(
            "--session-dir",
            default=".glaurung/windows-analyst/sessions",
            help="Directory for --session-id analyst state files",
        )
        analyst_loop.add_argument(
            "--write-state",
            action="store_true",
            help="Write updated analyst session state back to --state-path",
        )

        corpus_guard = subparsers.add_parser(
            "corpus-guard",
            help="Check vendored Windows corpus manifest/dashboard/local-file drift",
        )
        self._add_common_child_arguments(corpus_guard)
        corpus_guard.add_argument(
            "--corpus-root",
            default="samples/binaries/platforms/windows/vendor/realworld",
        )
        corpus_guard.add_argument(
            "--comparison-path",
            default=(
                "docs/windows-port/"
                "glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
            ),
        )
        corpus_guard.add_argument("--manifest-path")
        corpus_guard.add_argument(
            "--accepted-drift-path",
            help=(
                "Optional JSON policy file with intentional corpus drift acceptances"
            ),
        )
        corpus_guard.add_argument(
            "--review-notes-path",
            help="Optional markdown path for corpus guard review/release notes",
        )
        corpus_guard.add_argument("--max-selected", type=int, default=12)
        corpus_guard.add_argument(
            "--allow-drift",
            action="store_true",
            help="Report drift but return success instead of failing the command",
        )

        preflight = subparsers.add_parser(
            "high-volume-preflight",
            help="Check runner readiness for high-volume Windows target-pipeline runs",
        )
        self._add_common_child_arguments(preflight)
        preflight.add_argument("--build-corpus-manifest", required=True)
        preflight.add_argument("--corpus-root", required=True)
        preflight.add_argument("--project-root", required=True)
        preflight.add_argument("--metadata-root")
        preflight.add_argument("--target-id")
        preflight.add_argument("--filename")
        preflight.add_argument("--surface")
        preflight.add_argument("--priority")
        preflight.add_argument("--binary-kind")
        preflight.add_argument("--max-targets", type=int, default=8)
        preflight.add_argument("--max-matches-per-target", type=int, default=4)
        preflight.add_argument("--require-ghidra", action="store_true")
        preflight.add_argument("--analyze-headless-path")
        preflight.add_argument("--require-bsim", action="store_true")
        preflight.add_argument("--bsim-path")
        preflight.add_argument(
            "--artifacts-dir",
            default="artifacts/windows-target-pipeline/high-volume",
        )
        preflight.add_argument(
            "--add-to-kb",
            action="store_true",
            help="Record the preflight result in the transient memory KB",
        )
        preflight.add_argument(
            "--allow-blocked",
            action="store_true",
            help="Return success even when the preflight reports blockers",
        )

        project_facts = subparsers.add_parser(
            "project-fact-manifest",
            help="Inspect ASB .glaurung project fact coverage records",
        )
        self._add_common_child_arguments(project_facts)
        project_facts.add_argument("--project-facts-path")
        project_facts.add_argument("--target-id")
        project_facts.add_argument("--binary-filename")
        project_facts.add_argument("--build-label")
        project_facts.add_argument("--requires-fact")
        project_facts.add_argument("--missing-fact")
        project_facts.add_argument("--min-function-names", type=int, default=0)
        project_facts.add_argument("--min-call-xrefs", type=int, default=0)
        project_facts.add_argument(
            "--add-to-kb",
            action="store_true",
            help="Record the manifest query in the transient memory KB",
        )

        bootstrap_project = subparsers.add_parser(
            "bootstrap-project-facts",
            help="Create or update a .glaurung Windows PE project fact cache",
        )
        self._add_common_child_arguments(bootstrap_project)
        bootstrap_project.add_argument("--pe-path", required=True)
        bootstrap_project.add_argument("--project-path", required=True)
        bootstrap_project.add_argument("--pdb-cache-dir")
        bootstrap_project.add_argument(
            "--analysis-config",
            dest="analysis_config_path",
            help=(
                "Optional Windows analysis config YAML/JSON. Defaults to "
                ".glaurung/windows-analysis.yaml or "
                "$GLAURUNG_WINDOWS_ANALYSIS_CONFIG when present."
            ),
        )
        bootstrap_project.add_argument("--max-read-bytes", type=int)
        bootstrap_project.add_argument("--max-file-size", type=int)
        bootstrap_project.add_argument("--max-functions", type=int)
        bootstrap_project.add_argument("--max-blocks", type=int)
        bootstrap_project.add_argument("--max-instructions", type=int)
        bootstrap_project.add_argument("--timeout-ms", type=int)
        bootstrap_project.add_argument(
            "--project-facts-output-path",
            help="Optional pe-project-facts.yaml path to update with this project.",
        )
        bootstrap_project.add_argument("--project-fact-id")
        bootstrap_project.add_argument("--target-id")
        bootstrap_project.add_argument("--build-label")
        bootstrap_project.add_argument("--build-number")
        bootstrap_project.add_argument("--architecture", default="x64")
        bootstrap_project.add_argument("--binary-filename")
        bootstrap_project.add_argument("--manifest-note")
        bootstrap_project.add_argument(
            "--struct-name",
            action="append",
            default=[],
            dest="struct_names",
            help="PDB struct/class/union name to import; may be repeated",
        )
        bootstrap_project.add_argument(
            "--no-index-callgraph",
            action="store_false",
            dest="index_callgraph",
            default=True,
        )
        bootstrap_project.add_argument(
            "--no-index-pe-direct-calls",
            action="store_false",
            dest="index_pe_direct_calls",
            default=True,
        )
        bootstrap_project.add_argument(
            "--no-index-function-boundaries",
            action="store_false",
            dest="index_function_boundaries",
            default=True,
        )
        bootstrap_project.add_argument(
            "--no-index-function-chunks",
            action="store_false",
            dest="index_function_chunks",
            default=True,
        )
        bootstrap_project.add_argument(
            "--no-index-data-xrefs",
            action="store_false",
            dest="index_data_xrefs",
            default=True,
        )
        bootstrap_project.add_argument(
            "--no-index-cfg",
            action="store_false",
            dest="index_cfg",
            default=True,
        )
        bootstrap_project.add_argument(
            "--no-index-cfg-dominance",
            action="store_false",
            dest="index_cfg_dominance",
            default=True,
        )
        bootstrap_project.add_argument(
            "--no-index-branch-conditions",
            action="store_false",
            dest="index_branch_conditions",
            default=True,
        )
        bootstrap_project.add_argument(
            "--no-index-sysinfo-dispatch",
            action="store_false",
            dest="index_sysinfo_dispatch",
            default=True,
        )
        bootstrap_project.add_argument(
            "--no-index-callsite-path-conditions",
            action="store_false",
            dest="index_callsite_path_conditions",
            default=True,
        )
        bootstrap_project.add_argument(
            "--no-import-pdb-facts",
            action="store_false",
            dest="import_pdb_facts",
            default=True,
        )
        bootstrap_project.add_argument("--max-pdb-prototypes", type=int, default=512)
        bootstrap_project.add_argument("--force-reindex", action="store_true")
        bootstrap_project.add_argument(
            "--add-to-kb",
            action="store_true",
            help="Record the bootstrap result in the transient memory KB",
        )

        blocker_tasks = subparsers.add_parser(
            "blocker-task-plan",
            help=(
                "Turn high-volume preflight and target-pipeline blocker "
                "artifacts into concrete follow-up tasks"
            ),
        )
        self._add_common_child_arguments(blocker_tasks)
        blocker_tasks.add_argument("--blocker-worklist-path")
        blocker_tasks.add_argument("--preflight-path")
        blocker_tasks.add_argument("--build-corpus-manifest")
        blocker_tasks.add_argument("--corpus-root")
        blocker_tasks.add_argument("--project-root")
        blocker_tasks.add_argument("--metadata-root")
        blocker_tasks.add_argument(
            "--artifact-dir",
            default="artifacts/windows-target-pipeline/high-volume",
        )
        blocker_tasks.add_argument("--max-tasks", type=int, default=32)
        blocker_tasks.add_argument("--output-path")
        blocker_tasks.add_argument(
            "--add-to-kb",
            action="store_true",
            help="Record the generated task plan in the transient memory KB",
        )

        symbol_similarity = subparsers.add_parser(
            "symbol-similarity-plan",
            help="Plan PDB/symbol-server and BSim extraction for a Windows patch pair",
        )
        self._add_common_child_arguments(symbol_similarity)
        symbol_similarity.add_argument("--binary-a", required=True)
        symbol_similarity.add_argument("--binary-b", required=True)
        symbol_similarity.add_argument("--target-id")
        symbol_similarity.add_argument("--component")
        symbol_similarity.add_argument("--build-label-a")
        symbol_similarity.add_argument("--build-label-b")
        symbol_similarity.add_argument("--pdb-identity-path")
        symbol_similarity.add_argument("--symbol-cache-root")
        symbol_similarity.add_argument("--ghidra-project-dir")
        symbol_similarity.add_argument(
            "--analyze-headless-path",
            default="analyzeHeadless",
        )
        symbol_similarity.add_argument("--bsim-ctl-path", default="bsim")
        symbol_similarity.add_argument(
            "--artifact-dir",
            default="artifacts/windows-symbol-similarity",
        )
        symbol_similarity.add_argument("--require-external-tools", action="store_true")
        symbol_similarity.add_argument("--output-script-path")
        symbol_similarity.add_argument(
            "--add-to-kb",
            action="store_true",
            help="Record the generated extraction plan in the transient memory KB",
        )

        function_similarity = subparsers.add_parser(
            "function-similarity-manifest",
            help=(
                "Generate a deterministic Glaurung opcode/body similarity "
                "manifest for a patch pair"
            ),
        )
        self._add_common_child_arguments(function_similarity)
        function_similarity.add_argument("--binary-a", required=True)
        function_similarity.add_argument("--binary-b", required=True)
        function_similarity.add_argument("--output-path")
        function_similarity.add_argument("--ngram-size", type=int, default=3)
        function_similarity.add_argument(
            "--min-similarity-score",
            type=float,
            default=0.55,
        )
        function_similarity.add_argument("--max-functions", type=int, default=2048)
        function_similarity.add_argument("--max-rows", type=int, default=128)
        function_similarity.add_argument("--include-same", action="store_true")
        function_similarity.add_argument(
            "--no-match-added-removed",
            action="store_false",
            dest="match_added_removed",
            default=True,
        )
        function_similarity.add_argument(
            "--include-anonymous",
            action="store_false",
            dest="skip_anonymous",
            default=True,
        )
        function_similarity.add_argument(
            "--add-to-kb",
            action="store_true",
            help="Record the similarity manifest in the transient memory KB",
        )

        runner_review = subparsers.add_parser(
            "runner-artifact-review",
            help=(
                "Review high-volume Windows runner artifacts for blockers "
                "and baseline-promotion readiness"
            ),
        )
        self._add_common_child_arguments(runner_review)
        runner_review.add_argument("--artifact-dir", required=True)
        runner_review.add_argument(
            "--mode",
            choices=["auto", "target_pipeline", "ghidra_parity"],
            default="auto",
        )
        runner_review.add_argument("--output-path")
        runner_review.add_argument(
            "--add-to-kb",
            action="store_true",
            help="Record the artifact review in the transient memory KB",
        )

        promotion_plan = subparsers.add_parser(
            "runner-artifact-promotion-plan",
            help=(
                "Plan reviewed runner artifact promotion into docs/metadata baselines"
            ),
        )
        self._add_common_child_arguments(promotion_plan)
        promotion_plan.add_argument("--artifact-dir", required=True)
        promotion_plan.add_argument("--review-path")
        promotion_plan.add_argument("--docs-root", default="docs/windows-port")
        promotion_plan.add_argument("--output-path")
        promotion_plan.add_argument(
            "--add-to-kb",
            action="store_true",
            help="Record the promotion plan in the transient memory KB",
        )

        promotion_apply = subparsers.add_parser(
            "runner-artifact-promotion-apply",
            help=(
                "Verify and optionally apply reviewed runner artifact promotion plans"
            ),
        )
        self._add_common_child_arguments(promotion_apply)
        promotion_apply.add_argument("--plan-path", required=True)
        promotion_apply.add_argument(
            "--apply-changes",
            action="store_true",
            help="Copy verified artifacts into their destination paths",
        )
        promotion_apply.add_argument("--output-path")
        promotion_apply.add_argument(
            "--review-markdown-path",
            help="Optional markdown path for a baseline commit readiness report",
        )
        promotion_apply.add_argument(
            "--add-to-kb",
            action="store_true",
            help="Record the promotion apply result in the transient memory KB",
        )

        pipeline = subparsers.add_parser(
            "target-pipeline",
            help="Run deterministic target triage, packet emission, review, and evidence checks",
        )
        self._add_common_child_arguments(pipeline)
        pipeline.add_argument("--build-corpus-manifest", required=True)
        pipeline.add_argument("--corpus-root")
        pipeline.add_argument("--project-root")
        pipeline.add_argument("--target-id")
        pipeline.add_argument("--filename")
        pipeline.add_argument("--surface")
        pipeline.add_argument("--priority")
        pipeline.add_argument("--binary-kind")
        pipeline.add_argument(
            "--comparison-path",
            default=(
                "docs/windows-port/"
                "glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
            ),
        )
        pipeline.add_argument(
            "--diagnostics-path",
            default="docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json",
        )
        pipeline.add_argument("--validation-inventory-path")
        pipeline.add_argument("--build-label")
        pipeline.add_argument("--attacker-class", default="unknown")
        pipeline.add_argument("--source-role", default="unknown")
        pipeline.add_argument("--source-arg")
        pipeline.add_argument("--source-arg-index", type=int)
        pipeline.add_argument("--infer-source-roles", action="store_true")
        pipeline.add_argument("--call-symbol")
        pipeline.add_argument("--sink-kind")
        pipeline.add_argument("--sinks-path")
        pipeline.add_argument("--sources-path")
        pipeline.add_argument("--gates-path")
        pipeline.add_argument("--project-facts-path")
        pipeline.add_argument("--ghidra-delta-path")
        pipeline.add_argument(
            "--vulnerability-seeds-path",
            help=(
                "Optional ASB pe-vulnerability-seeds.yaml packet source for "
                "invariant-driven review packets."
            ),
        )
        pipeline.add_argument(
            "--include-vulnerability-seeds",
            action="store_true",
            help=(
                "Include vulnerability-seed packets using the default ASB "
                "metadata path when --vulnerability-seeds-path is not supplied."
            ),
        )
        pipeline.add_argument("--vulnerability-seed-public-id")
        pipeline.add_argument("--vulnerability-seed-surface")
        pipeline.add_argument("--vulnerability-seed-invariant-family")
        pipeline.add_argument(
            "--operation-backlog-path",
            help=(
                "Optional ASB pe-operation-classification-backlog.yaml packet "
                "source for classifier work-item review packets."
            ),
        )
        pipeline.add_argument(
            "--include-operation-backlog",
            action="store_true",
            help=(
                "Include operation-backlog packets using the default ASB "
                "metadata path when --operation-backlog-path is not supplied."
            ),
        )
        pipeline.add_argument("--operation-backlog-required-capability")
        pipeline.add_argument("--operation-backlog-triage-category")
        pipeline.add_argument(
            "--operation-backlog-min-callsite-count", type=int, default=0
        )
        pipeline.add_argument(
            "--patch-diff-binary-a",
            help="Optional pre-change binary path for patch-diff packet emission",
        )
        pipeline.add_argument(
            "--patch-diff-binary-b",
            help="Optional post-change binary path for patch-diff packet emission",
        )
        pipeline.add_argument(
            "--patch-diff-seeds-path",
            help="Optional ASB vulnerability-seed metadata for patch-diff review",
        )
        pipeline.add_argument(
            "--patch-diff-function-identity-path",
            help="Optional PDB/BSim function identity YAML for patch-diff review",
        )
        pipeline.add_argument("--patch-diff-pdb-backed", action="store_true")
        pipeline.add_argument("--patch-diff-max-diff-rows", type=int, default=32)
        pipeline.add_argument("--patch-diff-max-items", type=int, default=20)
        pipeline.add_argument("--max-targets", type=int, default=4)
        pipeline.add_argument("--max-packets-per-target", type=int, default=16)
        pipeline.add_argument("--max-candidates", type=int, default=32)
        pipeline.add_argument("--candidate-packets-export-path")
        pipeline.add_argument("--evidence-operator-markdown-path")
        pipeline.add_argument("--evidence-export-manifest-path")
        pipeline.add_argument("--evidence-candidate-packets-export-path")
        pipeline.add_argument("--pipeline-export-manifest-path")
        pipeline.add_argument(
            "--blocker-worklist-path",
            help=(
                "Optional JSON path for ranked high-volume blocker work items "
                "derived from validation, sink-to-gate, and evidence review."
            ),
        )
        pipeline.add_argument(
            "--no-require-project-grounding",
            action="store_false",
            dest="require_project_grounding",
            default=True,
        )
        pipeline.add_argument(
            "--no-require-kdnet-attach",
            action="store_false",
            dest="require_kdnet_attach",
            default=True,
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        if args.windows_action == "analyst":
            return _execute_analyst(args, formatter)
        if args.windows_action == "analyst-loop":
            return _execute_analyst_loop(args, formatter)
        if args.windows_action == "corpus-guard":
            return _execute_corpus_guard(args, formatter)
        if args.windows_action == "high-volume-preflight":
            return _execute_high_volume_preflight(args, formatter)
        if args.windows_action == "project-fact-manifest":
            return _execute_project_fact_manifest(args, formatter)
        if args.windows_action == "bootstrap-project-facts":
            return _execute_bootstrap_project_facts(args, formatter)
        if args.windows_action == "blocker-task-plan":
            return _execute_blocker_task_plan(args, formatter)
        if args.windows_action == "symbol-similarity-plan":
            return _execute_symbol_similarity_plan(args, formatter)
        if args.windows_action == "function-similarity-manifest":
            return _execute_function_similarity_manifest(args, formatter)
        if args.windows_action == "runner-artifact-review":
            return _execute_runner_artifact_review(args, formatter)
        if args.windows_action == "runner-artifact-promotion-plan":
            return _execute_runner_artifact_promotion_plan(args, formatter)
        if args.windows_action == "runner-artifact-promotion-apply":
            return _execute_runner_artifact_promotion_apply(args, formatter)
        if args.windows_action == "target-pipeline":
            return _execute_target_pipeline(args, formatter)
        if args.windows_action != "diff-ghidra":
            raise ValueError(f"unsupported Windows action: {args.windows_action}")
        path = self.validate_file_path(args.path)
        report = windows_analysis.diff_ghidra(
            path,
            args.ghidra_json,
            limit=args.limit,
            max_read_bytes=args.max_read_bytes,
            max_file_size=args.max_file_size,
            max_functions=args.max_functions,
            max_blocks=args.max_blocks,
            max_instructions=args.max_instructions,
            timeout_ms=args.timeout_ms,
        )
        if formatter.format_type == OutputFormat.JSON:
            formatter.output_json(report)
            return 0
        if formatter.format_type == OutputFormat.JSONL:
            formatter.output_jsonl(
                [
                    {"type": "summary", "data": _summary(report)},
                    *({"type": "missing", "data": item} for item in report["missing"]),
                    *({"type": "extra", "data": item} for item in report["extra"]),
                ]
            )
            return 0
        formatter.output_plain(_format_diff_human(path, report))
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


def _summary(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": report["path"],
        "glaurung_functions": report["glaurung_functions"],
        "ghidra_functions": report["ghidra_functions"],
        "missing_count": report["missing_count"],
        "extra_count": report["extra_count"],
        "seed_kind_counts": report["stats"].get("seed_kind_counts", {}),
        "data_ref_code_pointer_candidates": report["stats"].get(
            "data_ref_code_pointer_candidates", 0
        ),
        "data_ref_code_pointer_seeds_inserted": report["stats"].get(
            "data_ref_code_pointer_seeds_inserted", 0
        ),
        "pdata_body_overlap_starts": report["stats"].get(
            "pdata_body_overlap_starts", 0
        ),
        "code_label_count": report["stats"].get("code_label_count", 0),
    }


def _execute_analyst(args: argparse.Namespace, formatter: BaseFormatter) -> int:
    state_path = _resolve_analyst_state_path(args)
    session_state = _load_analyst_state(state_path)
    candidate_packet = _load_candidate_packet(args.candidate_packet_path)
    result = run_windows_interactive_analyst(
        WindowsInteractiveAnalystConfig(
            intent=args.intent,
            question=args.question,
            comparison_path=args.comparison_path,
            diagnostics_path=args.diagnostics_path,
            file=args.file,
            address=args.address,
            max_items=args.max_items,
            binary_a=args.binary_a,
            binary_b=args.binary_b,
            seeds_path=args.seeds_path,
            pdb_backed=args.pdb_backed,
            candidate_packet=candidate_packet,
            candidate_id=args.candidate_id,
            evidence_export_manifest_path=args.evidence_export_manifest_path,
            blocker_worklist_path=args.blocker_worklist_path,
            blocker_task_plan_path=args.blocker_task_plan_path,
            review_packet_output_path=args.review_packet_output_path,
            session_state=session_state,
        )
    )
    should_write_state = args.write_state or bool(args.session_id)
    if should_write_state:
        if not state_path:
            raise ValueError("--write-state requires --state-path or --session-id")
        _write_analyst_state(state_path, result.session_state)
    payload = result.model_dump(mode="json")
    if state_path:
        payload["analyst_state_path"] = state_path
    if formatter.format_type == OutputFormat.JSON:
        formatter.output_json(payload)
        return 0
    if formatter.format_type == OutputFormat.JSONL:
        formatter.output_jsonl(
            [
                {"type": "answer", "data": payload},
                *(
                    {"type": "uncertainty", "data": item}
                    for item in result.known_uncertainty
                ),
                *({"type": "next_tool", "data": item} for item in result.next_tools),
            ]
        )
        return 0
    formatter.output_plain(_format_analyst_human(result))
    return 0


def _execute_analyst_loop(args: argparse.Namespace, formatter: BaseFormatter) -> int:
    state_path = _resolve_analyst_state_path(args)
    session_state = _load_analyst_state(state_path)
    commands = _load_analyst_loop_commands(args.script_path)
    result = run_windows_analyst_command_loop(
        WindowsAnalystLoopConfig(
            commands=commands,
            comparison_path=args.comparison_path,
            diagnostics_path=args.diagnostics_path,
            session_state=session_state,
            max_turns=args.max_turns,
            default_max_items=args.default_max_items,
            stop_on_error=args.stop_on_error,
        )
    )
    should_write_state = args.write_state or bool(args.session_id)
    if should_write_state:
        if not state_path:
            raise ValueError("--write-state requires --state-path or --session-id")
        _write_analyst_state(state_path, result.final_session_state)
    payload = result.model_dump(mode="json")
    if state_path:
        payload["analyst_state_path"] = state_path
    if formatter.format_type == OutputFormat.JSON:
        formatter.output_json(payload)
    elif formatter.format_type == OutputFormat.JSONL:
        formatter.output_jsonl(
            [
                {
                    "type": "summary",
                    "data": {
                        "turn_count": result.turn_count,
                        "completed_turn_count": result.completed_turn_count,
                        "failed_turn_count": result.failed_turn_count,
                        "analyst_state_path": state_path,
                    },
                },
                *(
                    {
                        "type": "turn",
                        "data": turn.model_dump(mode="json"),
                    }
                    for turn in result.turns
                ),
            ]
        )
    else:
        formatter.output_plain(_format_analyst_loop_human(result, state_path))
    return 1 if result.failed_turn_count else 0


def _load_analyst_loop_commands(path_text: str) -> list[WindowsAnalystLoopCommand]:
    path = Path(path_text)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get("commands")
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected a commands array or top-level list")
    return [WindowsAnalystLoopCommand.model_validate(item) for item in raw]


def _load_candidate_packet(path_text: str | None) -> WindowsReviewPacket | None:
    if not path_text:
        return None
    path = Path(path_text)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict) and isinstance(raw.get("packet"), dict):
        raw = raw["packet"]
    return WindowsReviewPacket.model_validate(raw)


def _resolve_analyst_state_path(args: argparse.Namespace) -> str | None:
    if args.state_path:
        return str(args.state_path)
    if not args.session_id:
        return None
    session_id = str(args.session_id)
    if session_id in {"", ".", ".."} or "/" in session_id or "\\" in session_id:
        raise ValueError("--session-id must be a simple name, not a path")
    return str(Path(args.session_dir) / f"{session_id}.json")


def _load_analyst_state(
    path_text: str | None,
) -> WindowsInteractiveAnalystSessionState | None:
    if not path_text:
        return None
    path = Path(path_text)
    if not path.exists():
        return None
    raw = json.loads(path.read_text(encoding="utf-8"))
    return WindowsInteractiveAnalystSessionState.model_validate(raw)


def _write_analyst_state(
    path_text: str,
    state: WindowsInteractiveAnalystSessionState,
) -> None:
    path = Path(path_text)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(state.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _execute_corpus_guard(args: argparse.Namespace, formatter: BaseFormatter) -> int:
    result = run_windows_corpus_curator(
        WindowsCorpusCuratorConfig(
            corpus_root=args.corpus_root,
            comparison_path=args.comparison_path,
            manifest_path=args.manifest_path,
            accepted_drift_path=args.accepted_drift_path,
            review_notes_path=args.review_notes_path,
            max_selected=args.max_selected,
            fail_on_drift=False,
        )
    )
    payload = result.model_dump(mode="json")
    if formatter.format_type == OutputFormat.JSON:
        formatter.output_json(payload)
    elif formatter.format_type == OutputFormat.JSONL:
        formatter.output_jsonl(
            [
                {
                    "type": "summary",
                    "data": {
                        "fixture_count": result.fixture_count,
                        "manifest_drift_count": result.manifest_drift_count,
                        "accepted_drift_count": result.accepted_drift_count,
                        "unaccepted_manifest_drift_count": result.unaccepted_manifest_drift_count,
                        "drift_guard_passed": result.drift_guard_passed,
                        "review_notes_path": result.review_notes_path,
                    },
                },
                *(
                    {"type": "manifest_drift", "data": item.model_dump(mode="json")}
                    for item in result.manifest_drift
                ),
                *(
                    {
                        "type": "accepted_manifest_drift",
                        "data": item.model_dump(mode="json"),
                    }
                    for item in result.accepted_drift
                ),
                *(
                    {
                        "type": "unaccepted_manifest_drift",
                        "data": item.model_dump(mode="json"),
                    }
                    for item in result.unaccepted_manifest_drift
                ),
            ]
        )
    else:
        formatter.output_plain(_format_corpus_guard_human(result))
    if result.unaccepted_manifest_drift and not args.allow_drift:
        return 1
    return 0


def _execute_high_volume_preflight(
    args: argparse.Namespace,
    formatter: BaseFormatter,
) -> int:
    tool = build_windows_high_volume_preflight()
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(
        file_path=str(args.build_corpus_manifest),
        artifact=artifact,
    )
    result = tool.run(
        ctx=ctx,
        kb=ctx.kb,
        args=WindowsHighVolumePreflightArgs(
            build_corpus_manifest=args.build_corpus_manifest,
            corpus_root=args.corpus_root,
            project_root=args.project_root,
            metadata_root=args.metadata_root,
            target_id=args.target_id,
            filename=args.filename,
            surface=args.surface,
            priority=args.priority,
            binary_kind=args.binary_kind,
            max_targets=args.max_targets,
            max_matches_per_target=args.max_matches_per_target,
            require_ghidra=args.require_ghidra,
            analyze_headless_path=args.analyze_headless_path,
            require_bsim=args.require_bsim,
            bsim_path=args.bsim_path,
            artifacts_dir=args.artifacts_dir,
            add_to_kb=args.add_to_kb,
        ),
    )
    payload = result.model_dump(mode="json")
    if formatter.format_type == OutputFormat.JSON:
        formatter.output_json(payload)
    elif formatter.format_type == OutputFormat.JSONL:
        formatter.output_jsonl(
            [
                {
                    "type": "summary",
                    "data": {
                        "ready": result.ready,
                        "target_count": result.target_count,
                        "ready_target_count": result.ready_target_count,
                        "blocked_target_count": result.blocked_target_count,
                        "metadata_ready": result.metadata_ready,
                        "optional_metadata_ready": result.optional_metadata_ready,
                    },
                },
                *(
                    {"type": "target", "data": item.model_dump(mode="json")}
                    for item in result.targets
                ),
                *({"type": "blocker", "data": item} for item in result.blockers),
                *({"type": "warning", "data": item} for item in result.warnings),
            ]
        )
    else:
        formatter.output_plain(_format_high_volume_preflight_human(result))
    if result.ready or args.allow_blocked:
        return 0
    return 1


def _execute_project_fact_manifest(
    args: argparse.Namespace,
    formatter: BaseFormatter,
) -> int:
    tool = build_windows_project_fact_manifest()
    artifact = g.triage.analyze_bytes(b"MZ")
    file_path = args.project_facts_path or "<windows-project-facts>"
    ctx = MemoryContext(file_path=str(file_path), artifact=artifact)
    result = tool.run(
        ctx=ctx,
        kb=ctx.kb,
        args=WindowsProjectFactManifestArgs(
            project_facts_path=args.project_facts_path,
            target_id=args.target_id,
            binary_filename=args.binary_filename,
            build_label=args.build_label,
            requires_fact=args.requires_fact,
            missing_fact=args.missing_fact,
            min_function_names=args.min_function_names,
            min_call_xrefs=args.min_call_xrefs,
            add_to_kb=args.add_to_kb,
        ),
    )
    payload = result.model_dump(mode="json")
    if formatter.format_type == OutputFormat.JSON:
        formatter.output_json(payload)
    elif formatter.format_type == OutputFormat.JSONL:
        formatter.output_jsonl(
            [
                {
                    "type": "summary",
                    "data": {
                        "project_facts_path": result.project_facts_path,
                        "record_count_total": result.record_count_total,
                        "record_count": len(result.records),
                        "records_with_call_xrefs_total": (
                            result.records_with_call_xrefs_total
                        ),
                        "records_with_cfg_total": result.records_with_cfg_total,
                    },
                },
                *(
                    {"type": "record", "data": item.model_dump(mode="json")}
                    for item in result.records
                ),
            ]
        )
    else:
        formatter.output_plain(_format_project_fact_manifest_human(result))
    return 0


def _execute_bootstrap_project_facts(
    args: argparse.Namespace,
    formatter: BaseFormatter,
) -> int:
    tool = build_windows_bootstrap_project_facts()
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(args.pe_path), artifact=artifact)
    result = tool.run(
        ctx=ctx,
        kb=ctx.kb,
        args=WindowsBootstrapProjectFactsArgs(
            pe_path=args.pe_path,
            project_path=args.project_path,
            pdb_cache_dir=args.pdb_cache_dir,
            struct_names=list(args.struct_names),
            analysis_config_path=args.analysis_config_path,
            max_read_bytes=args.max_read_bytes,
            max_file_size=args.max_file_size,
            max_functions=args.max_functions,
            max_blocks=args.max_blocks,
            max_instructions=args.max_instructions,
            timeout_ms=args.timeout_ms,
            index_callgraph=args.index_callgraph,
            index_pe_direct_calls=args.index_pe_direct_calls,
            index_function_boundaries=args.index_function_boundaries,
            index_function_chunks=args.index_function_chunks,
            index_data_xrefs=args.index_data_xrefs,
            index_cfg=args.index_cfg,
            index_cfg_dominance=args.index_cfg_dominance,
            index_branch_conditions=args.index_branch_conditions,
            index_sysinfo_dispatch=args.index_sysinfo_dispatch,
            index_callsite_path_conditions=args.index_callsite_path_conditions,
            import_pdb_facts=args.import_pdb_facts,
            max_pdb_prototypes=args.max_pdb_prototypes,
            force_reindex=args.force_reindex,
            project_facts_output_path=args.project_facts_output_path,
            project_fact_id=args.project_fact_id,
            target_id=args.target_id,
            build_label=args.build_label,
            build_number=args.build_number,
            architecture=args.architecture,
            binary_filename=args.binary_filename,
            manifest_note=args.manifest_note,
            add_to_kb=args.add_to_kb,
        ),
    )
    payload = result.model_dump(mode="json")
    if formatter.format_type == OutputFormat.JSON:
        formatter.output_json(payload)
    elif formatter.format_type == OutputFormat.JSONL:
        formatter.output_jsonl(
            [
                {
                    "type": "summary",
                    "data": {
                        "pe_path": result.pe_path,
                        "project_path": result.project_path,
                        "step_count": len(result.steps),
                        "failed_step_count": _failed_bootstrap_step_count(result),
                        "fact_coverage": result.fact_coverage,
                        "missing_capabilities": result.missing_capabilities,
                        "project_facts_output_path": result.project_facts_output_path,
                        "project_fact_record_id": result.project_fact_record_id,
                    },
                },
                *(
                    {"type": "step", "data": item.model_dump(mode="json")}
                    for item in result.steps
                ),
            ]
        )
    else:
        formatter.output_plain(_format_bootstrap_project_facts_human(result))
    return 1 if _failed_bootstrap_step_count(result) else 0


def _execute_blocker_task_plan(
    args: argparse.Namespace,
    formatter: BaseFormatter,
) -> int:
    tool = build_windows_pipeline_blocker_task_plan()
    artifact = g.triage.analyze_bytes(b"MZ")
    file_path = (
        args.preflight_path or args.blocker_worklist_path or "<windows-blockers>"
    )
    ctx = MemoryContext(file_path=str(file_path), artifact=artifact)
    result = tool.run(
        ctx=ctx,
        kb=ctx.kb,
        args=WindowsPipelineBlockerTaskPlanArgs(
            blocker_worklist_path=args.blocker_worklist_path,
            preflight_path=args.preflight_path,
            build_corpus_manifest=args.build_corpus_manifest,
            corpus_root=args.corpus_root,
            project_root=args.project_root,
            metadata_root=args.metadata_root,
            artifact_dir=args.artifact_dir,
            max_tasks=args.max_tasks,
            output_path=args.output_path,
            add_to_kb=args.add_to_kb,
        ),
    )
    payload = result.model_dump(mode="json")
    if formatter.format_type == OutputFormat.JSON:
        formatter.output_json(payload)
    elif formatter.format_type == OutputFormat.JSONL:
        formatter.output_jsonl(
            [
                {
                    "type": "summary",
                    "data": {
                        "task_count": result.task_count,
                        "source_paths": result.source_paths,
                        "output_path": result.output_path,
                    },
                },
                *(
                    {"type": "task", "data": item.model_dump(mode="json")}
                    for item in result.tasks
                ),
                *({"type": "warning", "data": item} for item in result.warnings),
            ]
        )
    else:
        formatter.output_plain(_format_blocker_task_plan_human(result))
    return 0


def _execute_symbol_similarity_plan(
    args: argparse.Namespace,
    formatter: BaseFormatter,
) -> int:
    tool = build_windows_symbol_similarity_extraction_plan()
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(args.binary_b), artifact=artifact)
    result = tool.run(
        ctx=ctx,
        kb=ctx.kb,
        args=WindowsSymbolSimilarityExtractionPlanArgs(
            binary_a=args.binary_a,
            binary_b=args.binary_b,
            target_id=args.target_id,
            component=args.component,
            build_label_a=args.build_label_a,
            build_label_b=args.build_label_b,
            pdb_identity_path=args.pdb_identity_path,
            symbol_cache_root=args.symbol_cache_root,
            ghidra_project_dir=args.ghidra_project_dir,
            analyze_headless_path=args.analyze_headless_path,
            bsim_ctl_path=args.bsim_ctl_path,
            artifact_dir=args.artifact_dir,
            require_external_tools=args.require_external_tools,
            output_script_path=args.output_script_path,
            add_to_kb=args.add_to_kb,
        ),
    )
    payload = result.model_dump(mode="json")
    if formatter.format_type == OutputFormat.JSON:
        formatter.output_json(payload)
    elif formatter.format_type == OutputFormat.JSONL:
        formatter.output_jsonl(
            [
                {
                    "type": "summary",
                    "data": {
                        "ready_to_execute": result.ready_to_execute,
                        "external_tools_ready": result.external_tools_ready,
                        "similarity_manifest_path": result.similarity_manifest_path,
                        "identity_output_path": result.identity_output_path,
                    },
                },
                *(
                    {"type": "step", "data": item.model_dump(mode="json")}
                    for item in result.steps
                ),
                *({"type": "blocker", "data": item} for item in result.blockers),
                *({"type": "warning", "data": item} for item in result.warnings),
            ]
        )
    else:
        formatter.output_plain(_format_symbol_similarity_plan_human(result))
    return 0 if result.ready_to_execute else 1


def _execute_function_similarity_manifest(
    args: argparse.Namespace,
    formatter: BaseFormatter,
) -> int:
    tool = build_windows_function_similarity_manifest()
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(args.binary_b), artifact=artifact)
    result = tool.run(
        ctx=ctx,
        kb=ctx.kb,
        args=WindowsFunctionSimilarityManifestArgs(
            binary_a=args.binary_a,
            binary_b=args.binary_b,
            output_path=args.output_path,
            ngram_size=args.ngram_size,
            min_similarity_score=args.min_similarity_score,
            max_functions=args.max_functions,
            max_rows=args.max_rows,
            include_same=args.include_same,
            match_added_removed=args.match_added_removed,
            skip_anonymous=args.skip_anonymous,
            add_to_kb=args.add_to_kb,
        ),
    )
    payload = result.model_dump(mode="json")
    if formatter.format_type == OutputFormat.JSON:
        formatter.output_json(payload)
    elif formatter.format_type == OutputFormat.JSONL:
        formatter.output_jsonl(
            [
                {
                    "type": "summary",
                    "data": {
                        "similarity_record_count": result.similarity_record_count,
                        "output_path": result.output_path,
                        "coverage": result.coverage,
                    },
                },
                *(
                    {"type": "similarity", "data": item.model_dump(mode="json")}
                    for item in result.similarities
                ),
            ]
        )
    else:
        formatter.output_plain(_format_function_similarity_manifest_human(result))
    return 0 if result.similarity_record_count else 1


def _execute_runner_artifact_review(
    args: argparse.Namespace,
    formatter: BaseFormatter,
) -> int:
    tool = build_windows_runner_artifact_review()
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(args.artifact_dir), artifact=artifact)
    result = tool.run(
        ctx=ctx,
        kb=ctx.kb,
        args=WindowsRunnerArtifactReviewArgs(
            artifact_dir=args.artifact_dir,
            mode=args.mode,
            output_path=args.output_path,
            add_to_kb=args.add_to_kb,
        ),
    )
    payload = result.model_dump(mode="json")
    if formatter.format_type == OutputFormat.JSON:
        formatter.output_json(payload)
    elif formatter.format_type == OutputFormat.JSONL:
        formatter.output_jsonl(
            [
                {
                    "type": "summary",
                    "data": {
                        "mode": result.mode,
                        "promotion_ready": result.promotion_ready,
                        "artifact_count_present": result.artifact_count_present,
                        "blocker_count": len(result.blockers),
                        "task_count": result.task_count,
                    },
                },
                *(
                    {"type": "artifact", "data": item.model_dump(mode="json")}
                    for item in result.artifacts
                ),
                *({"type": "blocker", "data": item} for item in result.blockers),
                *({"type": "warning", "data": item} for item in result.warnings),
            ]
        )
    else:
        formatter.output_plain(_format_runner_artifact_review_human(result))
    return 0 if result.review_ready else 1


def _execute_runner_artifact_promotion_plan(
    args: argparse.Namespace,
    formatter: BaseFormatter,
) -> int:
    tool = build_windows_runner_artifact_promotion_plan()
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(args.artifact_dir), artifact=artifact)
    result = tool.run(
        ctx=ctx,
        kb=ctx.kb,
        args=WindowsRunnerArtifactPromotionPlanArgs(
            artifact_dir=args.artifact_dir,
            review_path=args.review_path,
            docs_root=args.docs_root,
            output_path=args.output_path,
            add_to_kb=args.add_to_kb,
        ),
    )
    payload = result.model_dump(mode="json")
    if formatter.format_type == OutputFormat.JSON:
        formatter.output_json(payload)
    elif formatter.format_type == OutputFormat.JSONL:
        formatter.output_jsonl(
            [
                {
                    "type": "summary",
                    "data": {
                        "promotion_allowed": result.promotion_allowed,
                        "action_count": result.action_count,
                        "blocker_count": len(result.blockers),
                    },
                },
                *(
                    {"type": "action", "data": item.model_dump(mode="json")}
                    for item in result.actions
                ),
                *({"type": "blocker", "data": item} for item in result.blockers),
                *({"type": "warning", "data": item} for item in result.warnings),
            ]
        )
    else:
        formatter.output_plain(_format_runner_artifact_promotion_plan_human(result))
    return 0 if result.promotion_allowed else 1


def _execute_runner_artifact_promotion_apply(
    args: argparse.Namespace,
    formatter: BaseFormatter,
) -> int:
    tool = build_windows_runner_artifact_promotion_apply()
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(args.plan_path), artifact=artifact)
    result = tool.run(
        ctx=ctx,
        kb=ctx.kb,
        args=WindowsRunnerArtifactPromotionApplyArgs(
            plan_path=args.plan_path,
            apply_changes=args.apply_changes,
            output_path=args.output_path,
            review_markdown_path=args.review_markdown_path,
            add_to_kb=args.add_to_kb,
        ),
    )
    payload = result.model_dump(mode="json")
    if formatter.format_type == OutputFormat.JSON:
        formatter.output_json(payload)
    elif formatter.format_type == OutputFormat.JSONL:
        formatter.output_jsonl(
            [
                {
                    "type": "summary",
                    "data": {
                        "verification_passed": result.verification_passed,
                        "apply_requested": result.apply_requested,
                        "action_count": result.action_count,
                        "applied_count": result.applied_count,
                        "changed_destination_count": result.changed_destination_count,
                        "baseline_commit_ready": result.baseline_commit_ready,
                    },
                },
                *(
                    {"type": "action", "data": item.model_dump(mode="json")}
                    for item in result.actions
                ),
                *({"type": "blocker", "data": item} for item in result.blockers),
                *({"type": "warning", "data": item} for item in result.warnings),
            ]
        )
    else:
        formatter.output_plain(_format_runner_artifact_promotion_apply_human(result))
    return 0 if result.verification_passed else 1


def _execute_target_pipeline(args: argparse.Namespace, formatter: BaseFormatter) -> int:
    result = run_windows_target_pipeline(
        WindowsTargetPipelineConfig(
            build_corpus=WindowsBuildCorpusArgs(
                manifest_path=args.build_corpus_manifest,
                corpus_root=args.corpus_root,
                project_root=args.project_root,
                target_id=args.target_id,
                filename=args.filename,
                surface=args.surface,
                priority=args.priority,
                binary_kind=args.binary_kind,
                max_matches=1,
            ),
            comparison_path=args.comparison_path,
            diagnostics_path=args.diagnostics_path,
            validation_inventory_path=args.validation_inventory_path,
            build_label=args.build_label,
            attacker_class=args.attacker_class,
            source_role=args.source_role,
            source_arg=args.source_arg,
            source_arg_index=args.source_arg_index,
            infer_source_roles=args.infer_source_roles,
            call_symbol=args.call_symbol,
            sink_kind=args.sink_kind,
            sinks_path=args.sinks_path,
            sources_path=args.sources_path,
            gates_path=args.gates_path,
            project_facts_path=args.project_facts_path,
            ghidra_delta_path=args.ghidra_delta_path,
            vulnerability_seeds_path=args.vulnerability_seeds_path,
            include_vulnerability_seeds=args.include_vulnerability_seeds,
            vulnerability_seed_public_id=args.vulnerability_seed_public_id,
            vulnerability_seed_surface=args.vulnerability_seed_surface,
            vulnerability_seed_invariant_family=(
                args.vulnerability_seed_invariant_family
            ),
            operation_backlog_path=args.operation_backlog_path,
            include_operation_backlog=args.include_operation_backlog,
            operation_backlog_required_capability=(
                args.operation_backlog_required_capability
            ),
            operation_backlog_triage_category=args.operation_backlog_triage_category,
            operation_backlog_min_callsite_count=(
                args.operation_backlog_min_callsite_count
            ),
            patch_diff_binary_a=args.patch_diff_binary_a,
            patch_diff_binary_b=args.patch_diff_binary_b,
            patch_diff_seeds_path=args.patch_diff_seeds_path,
            patch_diff_function_identity_path=args.patch_diff_function_identity_path,
            patch_diff_pdb_backed=args.patch_diff_pdb_backed,
            patch_diff_max_diff_rows=args.patch_diff_max_diff_rows,
            patch_diff_max_items=args.patch_diff_max_items,
            require_project_grounding=args.require_project_grounding,
            require_kdnet_attach=args.require_kdnet_attach,
            max_targets=args.max_targets,
            max_packets_per_target=args.max_packets_per_target,
            max_candidates=args.max_candidates,
            candidate_packets_export_path=args.candidate_packets_export_path,
            evidence_operator_markdown_path=args.evidence_operator_markdown_path,
            evidence_export_manifest_path=args.evidence_export_manifest_path,
            evidence_candidate_packets_export_path=(
                args.evidence_candidate_packets_export_path
            ),
            pipeline_export_manifest_path=args.pipeline_export_manifest_path,
            blocker_worklist_path=args.blocker_worklist_path,
        )
    )
    payload = result.model_dump(mode="json")
    if formatter.format_type == OutputFormat.JSON:
        formatter.output_json(payload)
    elif formatter.format_type == OutputFormat.JSONL:
        formatter.output_jsonl(
            [
                {
                    "type": "summary",
                    "data": {
                        "candidate_count": result.candidate_count,
                        "planned_count": result.planned_count,
                        "sink_review_count": result.sink_review_count,
                        "evidence_review_count": result.evidence_review_count,
                        "blocker_work_item_count": result.blocker_work_item_count,
                    },
                },
                *(
                    {"type": "blocker_work_item", "data": item.model_dump(mode="json")}
                    for item in result.blocker_worklist
                ),
                *(
                    {"type": "evidence_review", "data": item.model_dump(mode="json")}
                    for item in result.evidence_review.review_items
                ),
            ]
        )
    else:
        formatter.output_plain(_format_target_pipeline_human(result))
    return 0


def _format_runner_artifact_promotion_plan_human(
    result: WindowsRunnerArtifactPromotionPlanResult,
) -> str:
    status = "READY" if result.promotion_allowed else "BLOCKED"
    lines = [
        f"Windows runner artifact promotion plan: {status}",
        f"  actions={result.action_count} docs_root={result.docs_root}",
    ]
    if result.output_path:
        lines.append(f"  output={result.output_path}")
    if result.actions:
        lines.append("Actions:")
        lines.extend(f"  {action.command}" for action in result.actions[:20])
    if result.blockers:
        lines.append("Blockers:")
        lines.extend(f"  {blocker}" for blocker in result.blockers[:20])
    if result.warnings:
        lines.append("Warnings:")
        lines.extend(f"  {warning}" for warning in result.warnings[:20])
    return "\n".join(lines)


def _format_runner_artifact_promotion_apply_human(
    result: WindowsRunnerArtifactPromotionApplyResult,
) -> str:
    status = "VERIFIED" if result.verification_passed else "BLOCKED"
    mode = "apply" if result.apply_requested else "dry-run"
    lines = [
        f"Windows runner artifact promotion apply: {status}",
        (
            f"  mode={mode} actions={result.action_count} "
            f"applied={result.applied_count} "
            f"would_change={result.changed_destination_count}"
        ),
    ]
    if result.output_path:
        lines.append(f"  output={result.output_path}")
    if result.review_markdown_path:
        lines.append(f"  review_markdown={result.review_markdown_path}")
    lines.append(
        f"  baseline_commit_ready={'yes' if result.baseline_commit_ready else 'no'}"
    )
    if result.actions:
        lines.append("Actions:")
        lines.extend(
            (f"  {action.status} {action.source_path} -> {action.destination_path}")
            for action in result.actions[:20]
        )
    if result.blockers:
        lines.append("Blockers:")
        lines.extend(f"  {blocker}" for blocker in result.blockers[:20])
    if result.warnings:
        lines.append("Warnings:")
        lines.extend(f"  {warning}" for warning in result.warnings[:20])
    return "\n".join(lines)


def _format_runner_artifact_review_human(
    result: WindowsRunnerArtifactReviewResult,
) -> str:
    status = "PROMOTION-READY" if result.promotion_ready else "BLOCKED"
    lines = [
        f"Windows runner artifact review: {status}",
        (
            f"  mode={result.mode} artifacts={result.artifact_count_present} "
            f"candidates={result.candidate_count} tasks={result.task_count}"
        ),
    ]
    if result.promotable_artifacts:
        lines.append("Promotable artifacts:")
        lines.extend(f"  {item}" for item in result.promotable_artifacts[:20])
    if result.blockers:
        lines.append("Blockers:")
        lines.extend(f"  {blocker}" for blocker in result.blockers[:20])
    if result.next_actions:
        lines.append("Next actions:")
        lines.extend(f"  {action}" for action in result.next_actions[:20])
    if result.warnings:
        lines.append("Warnings:")
        lines.extend(f"  {warning}" for warning in result.warnings[:20])
    return "\n".join(lines)


def _format_symbol_similarity_plan_human(
    result: WindowsSymbolSimilarityExtractionPlanResult,
) -> str:
    status = "READY" if result.ready_to_execute else "BLOCKED"
    lines = [
        f"Windows symbol similarity extraction plan: {status}",
        (
            f"  external_tools_ready={result.external_tools_ready} "
            f"steps={len(result.steps)}"
        ),
        f"  similarity_manifest={result.similarity_manifest_path}",
        f"  identity_output={result.identity_output_path}",
    ]
    if result.output_script_path:
        lines.append(f"  script={result.output_script_path}")
    for step in result.steps[:20]:
        lines.append(
            f"  {step.kind} ready={step.ready} tool={step.next_tool_name or '-'}"
        )
        if step.command_text:
            lines.append(f"    {step.command_text}")
    if result.blockers:
        lines.append("Blockers:")
        lines.extend(f"  {blocker}" for blocker in result.blockers[:20])
    if result.warnings:
        lines.append("Warnings:")
        lines.extend(f"  {warning}" for warning in result.warnings[:20])
    return "\n".join(lines)


def _format_function_similarity_manifest_human(
    result: WindowsFunctionSimilarityManifestResult,
) -> str:
    lines = [
        "Windows function similarity manifest",
        (
            f"  records={result.similarity_record_count} "
            f"functions_a={result.functions_a} functions_b={result.functions_b}"
        ),
    ]
    if result.output_path:
        lines.append(f"  output={result.output_path}")
    for item in result.similarities[:20]:
        lines.append(
            f"  {item.status} {item.function} -> "
            f"{item.matched_function or '-'} score={item.similarity_score:.4f} "
            f"algo={item.similarity_algorithm}"
        )
    if result.missing_capabilities:
        lines.append("Missing:")
        lines.extend(f"  {item}" for item in result.missing_capabilities)
    return "\n".join(lines)


def _format_bootstrap_project_facts_human(
    result: WindowsBootstrapProjectFactsResult,
) -> str:
    failed = _failed_bootstrap_step_count(result)
    status = "PASS" if failed == 0 else "FAILED"
    lines = [
        f"Windows project-fact bootstrap: {status}",
        f"  pe={result.pe_path}",
        f"  project={result.project_path}",
        (
            f"  coverage={','.join(result.fact_coverage) or '-'} "
            f"missing={','.join(result.missing_capabilities) or '-'}"
        ),
    ]
    if result.project_facts_output_path:
        lines.append(
            f"  manifest={result.project_facts_output_path} "
            f"record={result.project_fact_record_id or '-'}"
        )
    for step in result.steps[:20]:
        if step.ran:
            lines.append(
                f"  {step.name} ok={step.ok} count={step.count} "
                f"elapsed_ms={step.elapsed_ms}"
            )
        else:
            lines.append(f"  {step.name} skipped")
        if step.error:
            lines.append(f"    error={step.error}")
    return "\n".join(lines)


def _failed_bootstrap_step_count(result: WindowsBootstrapProjectFactsResult) -> int:
    return sum(1 for step in result.steps if not step.ok)


def _format_project_fact_manifest_human(
    result: WindowsProjectFactManifestResult,
) -> str:
    lines = [
        "Windows project-fact manifest",
        (
            f"  records={len(result.records)}/{result.record_count_total} "
            f"with_call_xrefs={result.records_with_call_xrefs_total} "
            f"with_cfg={result.records_with_cfg_total}"
        ),
        f"  path={result.project_facts_path}",
    ]
    for record in result.records[:20]:
        lines.append(
            f"  {record.id} target={record.target_id} "
            f"binary={record.binary_filename} build={record.build_label}"
        )
        lines.append(
            f"    coverage={','.join(record.fact_coverage) or '-'} "
            f"missing={','.join(record.missing_facts) or '-'}"
        )
        lines.append(
            f"    call_xrefs={record.counts.call_xref_count} "
            f"cfg_edges={record.counts.cfg_edge_count} "
            f"functions={record.counts.function_name_count}"
        )
    if len(result.records) > 20:
        lines.append(f"  ... {len(result.records) - 20} more")
    return "\n".join(lines)


def _format_blocker_task_plan_human(
    result: WindowsPipelineBlockerTaskPlanResult,
) -> str:
    lines = [
        "Windows pipeline blocker task plan",
        f"  tasks={result.task_count} sources={len(result.source_paths)}",
    ]
    if result.output_path:
        lines.append(f"Output: {result.output_path}")
    for task in result.tasks[:20]:
        lines.append(
            f"  #{task.rank} {task.kind} priority={task.priority} "
            f"targets={','.join(task.target_ids) or '-'} "
            f"tool={task.next_tool_name or '-'}"
        )
        if task.blockers:
            lines.append(f"    blocker={task.blockers[0]}")
    if result.warnings:
        lines.append("Warnings:")
        lines.extend(f"  {warning}" for warning in result.warnings[:20])
    return "\n".join(lines)


def _format_high_volume_preflight_human(
    result: WindowsHighVolumePreflightResult,
) -> str:
    status = "PASS" if result.ready else "BLOCKED"
    lines = [
        f"Windows high-volume preflight: {status}",
        (
            f"  targets={result.ready_target_count}/{result.target_count} "
            f"blocked={result.blocked_target_count} "
            f"metadata_ready={result.metadata_ready} "
            f"optional_metadata_ready={result.optional_metadata_ready}"
        ),
    ]
    if result.high_volume_command:
        lines.append(f"High-volume command: {result.high_volume_command}")
    if result.targets:
        lines.append("Targets:")
        lines.extend(
            (
                f"  {target.target_id} ready={target.ready} "
                f"corpus={target.corpus_match_count} "
                f"projects={target.project_match_count}"
            )
            for target in result.targets[:20]
        )
    if result.blockers:
        lines.append("Blockers:")
        lines.extend(f"  {blocker}" for blocker in result.blockers[:20])
    if result.warnings:
        lines.append("Warnings:")
        lines.extend(f"  {warning}" for warning in result.warnings[:20])
    return "\n".join(lines)


def _format_corpus_guard_human(result: WindowsCorpusCuratorResult) -> str:
    status = "PASS" if result.drift_guard_passed else "FAIL"
    lines = [
        f"Windows corpus guard: {status}",
        (
            f"  fixtures={result.fixture_count} "
            f"fast={result.fast_baseline_count} stress={result.stress_count} "
            f"drift={result.manifest_drift_count} "
            f"accepted={result.accepted_drift_count} "
            f"unaccepted={result.unaccepted_manifest_drift_count}"
        ),
        (
            f"  missing_dashboard={len(result.missing_dashboard_entries)} "
            f"missing_local={len(result.missing_local_files)}"
        ),
    ]
    if result.review_notes_path:
        lines.append(f"  review_notes={result.review_notes_path}")
    if result.manifest_drift:
        lines.append("Manifest drift:")
        lines.extend(
            (
                f"  {item.file} field={item.field} reason={item.reason} "
                f"current={item.current!r} recorded={item.recorded!r}"
            )
            for item in result.manifest_drift[:20]
        )
        if len(result.manifest_drift) > 20:
            lines.append(f"  ... {len(result.manifest_drift) - 20} more")
    else:
        lines.append("Manifest drift: none")
    if result.accepted_drift:
        lines.append("Accepted drift:")
        lines.extend(
            (
                f"  {item.drift.file} field={item.drift.field} "
                f"reason={item.acceptance.acceptance_reason}"
            )
            for item in result.accepted_drift[:20]
        )
    if result.unaccepted_manifest_drift:
        lines.append("Unaccepted drift:")
        lines.extend(
            (f"  {item.file} field={item.field} reason={item.reason}")
            for item in result.unaccepted_manifest_drift[:20]
        )
    return "\n".join(lines)


def _format_target_pipeline_human(result: WindowsTargetPipelineResult) -> str:
    lines = [
        "Windows target pipeline",
        (
            f"  targets={result.ready_fanout_count}/{result.selected_target_count} "
            f"candidates={result.candidate_count} planned={result.planned_count} "
            f"sink_reviews={result.sink_review_count} "
            f"evidence_items={result.evidence_review_count}"
        ),
        (
            f"  ready_runtime={result.validation.ready_for_runtime_validation_count} "
            f"blocked={len(result.blockers)}"
        ),
    ]
    if result.validation.candidate_packets_export_path:
        lines.append(
            f"Candidate packet export: {result.validation.candidate_packets_export_path}"
        )
    if result.evidence_review.export_manifest_path:
        lines.append(
            f"Evidence export manifest: {result.evidence_review.export_manifest_path}"
        )
    if result.export_manifest_path:
        lines.append(f"Pipeline export manifest: {result.export_manifest_path}")
    if result.blocker_worklist_path:
        lines.append(f"Blocker worklist: {result.blocker_worklist_path}")
    if result.blocker_worklist:
        lines.append("Top blocker work items:")
        lines.extend(
            (
                f"  #{item.rank} {item.kind} count={item.count} "
                f"candidates={len(item.candidate_ids)} blocker={item.blocker}"
            )
            for item in result.blocker_worklist[:8]
        )
    if result.blockers:
        lines.append("Blockers:")
        lines.extend(f"  {blocker}" for blocker in result.blockers[:12])
    lines.append(f"Tool sequence: {', '.join(result.tool_sequence)}")
    return "\n".join(lines)


def _format_analyst_human(result) -> str:
    lines = [
        f"Windows analyst ({result.intent})",
        result.answer,
    ]
    if result.addresses:
        lines.append("Addresses:")
        lines.extend(f"  {address}" for address in result.addresses)
    if result.known_uncertainty:
        lines.append("Known uncertainty:")
        lines.extend(f"  {item}" for item in result.known_uncertainty[:12])
    if result.next_tools:
        lines.append("Next tools:")
        lines.extend(f"  {tool}" for tool in result.next_tools)
    if result.review_packet_handoff_path:
        lines.append(f"Review packet handoff: {result.review_packet_handoff_path}")
    lines.append(f"Tool sequence: {', '.join(result.tool_sequence)}")
    return "\n".join(lines)


def _format_analyst_loop_human(
    result: WindowsAnalystLoopResult,
    state_path: str | None,
) -> str:
    lines = [
        "Windows analyst command loop",
        (
            f"  turns={result.completed_turn_count}/{result.turn_count} "
            f"failed={result.failed_turn_count}"
        ),
    ]
    if state_path:
        lines.append(f"  state={state_path}")
    for turn in result.turns:
        header = f"Turn {turn.turn}: {turn.command.intent}"
        if turn.error:
            lines.append(f"{header} ERROR {turn.error}")
            continue
        if turn.result is None:
            lines.append(f"{header} skipped")
            continue
        lines.append(f"{header}")
        lines.append(f"  {turn.result.answer}")
        if turn.result.addresses:
            lines.append(f"  addresses={', '.join(turn.result.addresses[:8])}")
        if turn.result.next_tools:
            lines.append(f"  next={', '.join(turn.result.next_tools[:6])}")
    lines.append(f"Tool sequence: {', '.join(result.tool_sequence)}")
    return "\n".join(lines)


def _format_addr_row(item: dict[str, Any], *, include_seed: bool) -> str:
    address = item.get("address")
    section = item.get("section") or "?"
    head = item.get("bytes", {}).get("hex", "")
    cause = item.get("suspected_cause", "?")
    classification = item.get("function_start_classification") or {}
    state = classification.get("state") or "unknown"
    action = classification.get("recommended_action") or "-"
    seed = f" seed={item.get('seed_kind')}" if include_seed else ""
    containing = item.get("containing_function") or {}
    owner = containing.get("entry", "-") if containing else "-"
    label_count = len(item.get("labels") or [])
    prov_count = len(item.get("provenance") or [])
    ptr_count = len(item.get("code_pointer_refs") or [])
    return (
        f"  {address} section={section}{seed} owner={owner} "
        f"labels={label_count} provenance={prov_count} codeptrs={ptr_count} "
        f"state={state} action={action} bytes={head[:32]} cause={cause}"
    )


def _format_diff_human(path: Path, report: dict[str, Any]) -> str:
    summary = _summary(report)
    lines = [
        f"Windows Ghidra parity: {path.name}",
        (
            f"  functions: glaurung={summary['glaurung_functions']} "
            f"ghidra={summary['ghidra_functions']} "
            f"missing={summary['missing_count']} extra={summary['extra_count']}"
        ),
        (
            "  facts: "
            f"codeptr_candidates={summary['data_ref_code_pointer_candidates']} "
            f"codeptr_seeds={summary['data_ref_code_pointer_seeds_inserted']} "
            f"pdata_body_splits={summary['pdata_body_overlap_starts']} "
            f"labels={summary['code_label_count']}"
        ),
        f"  seed_kinds: {summary['seed_kind_counts']}",
    ]
    lines.append("Missing Ghidra starts:")
    if report["missing"]:
        lines.extend(
            _format_addr_row(item, include_seed=False) for item in report["missing"]
        )
    else:
        lines.append("  none")
    lines.append("Glaurung-only starts:")
    if report["extra"]:
        lines.extend(
            _format_addr_row(item, include_seed=True) for item in report["extra"]
        )
    else:
        lines.append("  none")
    return "\n".join(lines)
