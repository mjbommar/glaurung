"""Plan symbol-server and BSim extraction for Windows patch pairs."""

from __future__ import annotations

import json
from pathlib import Path
import shlex
import shutil
from typing import Any, Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_agent_evidence_bundle import (
    WindowsEvidenceBundle,
    WindowsEvidenceCoverage,
    WindowsEvidenceSubject,
    evidence_ref,
    make_windows_evidence_bundle,
)


WindowsSymbolSimilarityStepKind = Literal[
    "tool_check",
    "pdb_identity",
    "symbol_cache",
    "ghidra_import",
    "bsim_index",
    "bsim_query",
    "normalize_similarity",
    "identity_extract",
]


class WindowsSymbolSimilarityExtractionPlanArgs(BaseModel):
    binary_a: str = Field(..., description="Pre-change Windows PE path.")
    binary_b: str = Field(..., description="Post-change Windows PE path.")
    target_id: str | None = None
    component: str | None = None
    build_label_a: str | None = None
    build_label_b: str | None = None
    pdb_identity_path: str | None = Field(
        None,
        description="Optional ASB pe-identity-manifest.yaml path.",
    )
    symbol_cache_root: str | None = Field(
        None,
        description="Optional Microsoft symbol-cache root to use in generated commands.",
    )
    ghidra_project_dir: str | None = Field(
        None,
        description="Directory for generated Ghidra/BSim project commands.",
    )
    analyze_headless_path: str = "analyzeHeadless"
    bsim_ctl_path: str = "bsim"
    artifact_dir: str = "artifacts/windows-symbol-similarity"
    require_external_tools: bool = Field(
        False,
        description="If true, missing analyzeHeadless/BSim commands block execution.",
    )
    output_script_path: str | None = Field(
        None,
        description="Optional shell script path with the generated runner commands.",
    )
    add_to_kb: bool = False


class WindowsSymbolSimilarityExtractionStep(BaseModel):
    kind: WindowsSymbolSimilarityStepKind
    title: str
    ready: bool
    command: list[str] = Field(default_factory=list)
    command_text: str | None = None
    outputs: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    next_tool_name: str | None = None
    next_tool_args: dict[str, Any] = Field(default_factory=dict)
    reason_codes: list[str] = Field(default_factory=list)


class WindowsSymbolSimilarityExtractionPlanResult(BaseModel):
    claim_level: str = "symbol_similarity_extraction_plan_not_analysis"
    binary_a: str
    binary_b: str
    binary_paths_exist: bool
    external_tools_ready: bool
    ready_to_execute: bool
    analyze_headless_path: str
    bsim_ctl_path: str
    symbol_cache_root: str | None = None
    ghidra_project_dir: str
    artifact_dir: str
    similarity_manifest_path: str
    identity_output_path: str
    output_script_path: str | None = None
    identity_extract_args: dict[str, Any]
    steps: list[WindowsSymbolSimilarityExtractionStep]
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    evidence_bundle: WindowsEvidenceBundle
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsSymbolSimilarityExtractionPlanTool(
    MemoryTool[
        WindowsSymbolSimilarityExtractionPlanArgs,
        WindowsSymbolSimilarityExtractionPlanResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_symbol_similarity_extraction_plan",
                description=(
                    "Generate a deterministic runner plan for Windows patch-pair "
                    "PDB/symbol-server and Ghidra BSim similarity extraction, "
                    "including the manifest handoff consumed by patch-diff review."
                ),
                tags=("windows", "patch", "pdb", "bsim", "similarity"),
            ),
            WindowsSymbolSimilarityExtractionPlanArgs,
            WindowsSymbolSimilarityExtractionPlanResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsSymbolSimilarityExtractionPlanArgs,
    ) -> WindowsSymbolSimilarityExtractionPlanResult:
        binary_a = Path(args.binary_a).expanduser()
        binary_b = Path(args.binary_b).expanduser()
        artifact_dir = Path(args.artifact_dir).expanduser()
        ghidra_project_dir = Path(args.ghidra_project_dir or artifact_dir / "ghidra").expanduser()
        similarity_manifest_path = str(artifact_dir / "external-similarity.yaml")
        identity_output_path = str(artifact_dir / "function-identities.yaml")

        analyze_ready = _command_ready(args.analyze_headless_path)
        bsim_ready = _command_ready(args.bsim_ctl_path)
        binaries_exist = binary_a.is_file() and binary_b.is_file()
        external_tools_ready = analyze_ready and bsim_ready
        blockers = _dedupe(
            [
                *(["binary_a missing"] if not binary_a.is_file() else []),
                *(["binary_b missing"] if not binary_b.is_file() else []),
                *(
                    ["analyzeHeadless unavailable"]
                    if args.require_external_tools and not analyze_ready
                    else []
                ),
                *(
                    ["BSim command unavailable"]
                    if args.require_external_tools and not bsim_ready
                    else []
                ),
            ]
        )
        identity_args = _identity_extract_args(
            args,
            binary_a=binary_a,
            binary_b=binary_b,
            similarity_manifest_path=similarity_manifest_path,
            identity_output_path=identity_output_path,
        )
        steps = _steps(
            args,
            binary_a=binary_a,
            binary_b=binary_b,
            artifact_dir=artifact_dir,
            ghidra_project_dir=ghidra_project_dir,
            similarity_manifest_path=similarity_manifest_path,
            identity_output_path=identity_output_path,
            identity_args=identity_args,
            analyze_ready=analyze_ready,
            bsim_ready=bsim_ready,
        )
        ready_to_execute = binaries_exist and (
            external_tools_ready or not args.require_external_tools
        )
        output_script_path = _write_script(args.output_script_path, steps)
        warnings = []
        if not external_tools_ready and not args.require_external_tools:
            warnings.append(
                "external tools were not all found locally; generated plan is still runnable on a prepared runner"
            )
        notes = [
            "This is an extraction plan and handoff manifest scaffold, not analysis output.",
            "The external similarity manifest must be produced by the generated BSim/export steps before identity extraction consumes it.",
        ]
        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_symbol_similarity_extraction_plan",
                    props={
                        "binary_a": str(binary_a),
                        "binary_b": str(binary_b),
                        "ready_to_execute": ready_to_execute,
                        "similarity_manifest_path": similarity_manifest_path,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
        return WindowsSymbolSimilarityExtractionPlanResult(
            binary_a=str(binary_a),
            binary_b=str(binary_b),
            binary_paths_exist=binaries_exist,
            external_tools_ready=external_tools_ready,
            ready_to_execute=ready_to_execute,
            analyze_headless_path=args.analyze_headless_path,
            bsim_ctl_path=args.bsim_ctl_path,
            symbol_cache_root=args.symbol_cache_root,
            ghidra_project_dir=str(ghidra_project_dir),
            artifact_dir=str(artifact_dir),
            similarity_manifest_path=similarity_manifest_path,
            identity_output_path=identity_output_path,
            output_script_path=output_script_path,
            identity_extract_args=identity_args,
            steps=steps,
            blockers=blockers,
            warnings=warnings,
            evidence_bundle=_evidence_bundle(
                args=args,
                steps=steps,
                blockers=blockers,
                warnings=warnings,
                ready_to_execute=ready_to_execute,
                similarity_manifest_path=similarity_manifest_path,
                identity_output_path=identity_output_path,
                notes=notes,
            ),
            evidence_node_id=evidence_node_id,
            notes=notes,
        )


def _steps(
    args: WindowsSymbolSimilarityExtractionPlanArgs,
    *,
    binary_a: Path,
    binary_b: Path,
    artifact_dir: Path,
    ghidra_project_dir: Path,
    similarity_manifest_path: str,
    identity_output_path: str,
    identity_args: dict[str, Any],
    analyze_ready: bool,
    bsim_ready: bool,
) -> list[WindowsSymbolSimilarityExtractionStep]:
    project_a = _project_name(binary_a, args.build_label_a or "a")
    project_b = _project_name(binary_b, args.build_label_b or "b")
    steps = [
        WindowsSymbolSimilarityExtractionStep(
            kind="tool_check",
            title="Check Ghidra analyzeHeadless and BSim commands",
            ready=analyze_ready and bsim_ready,
            blockers=_dedupe(
                [
                    *(["analyzeHeadless unavailable"] if not analyze_ready else []),
                    *(["BSim command unavailable"] if not bsim_ready else []),
                ]
            ),
            reason_codes=["tool_check", "ghidra_bsim"],
        )
    ]
    if args.pdb_identity_path:
        steps.append(
            WindowsSymbolSimilarityExtractionStep(
                kind="pdb_identity",
                title="Load PDB identity manifest for patch pair",
                ready=Path(args.pdb_identity_path).expanduser().is_file(),
                outputs=[args.pdb_identity_path],
                next_tool_name="windows_pdb_identity_manifest",
                next_tool_args={
                    "identity_path": args.pdb_identity_path,
                    "target_id": args.target_id,
                    "binary_filename": args.component,
                },
                reason_codes=["pdb_identity_manifest"],
            )
        )
    if args.symbol_cache_root:
        steps.append(
            _command_step(
                kind="symbol_cache",
                title="Populate Microsoft symbol cache for both binaries",
                command=[
                    "symchk",
                    str(binary_a),
                    str(binary_b),
                    "/s",
                    f"SRV*{args.symbol_cache_root}*https://msdl.microsoft.com/download/symbols",
                ],
                outputs=[args.symbol_cache_root],
                reason_codes=["symbol_server_cache"],
            )
        )
    steps.extend(
        [
            _command_step(
                kind="ghidra_import",
                title="Import old binary into a Ghidra project",
                command=[
                    args.analyze_headless_path,
                    str(ghidra_project_dir),
                    project_a,
                    "-import",
                    str(binary_a),
                    "-overwrite",
                ],
                outputs=[str(ghidra_project_dir / project_a)],
                reason_codes=["ghidra_import", "old_build"],
            ),
            _command_step(
                kind="ghidra_import",
                title="Import new binary into a Ghidra project",
                command=[
                    args.analyze_headless_path,
                    str(ghidra_project_dir),
                    project_b,
                    "-import",
                    str(binary_b),
                    "-overwrite",
                ],
                outputs=[str(ghidra_project_dir / project_b)],
                reason_codes=["ghidra_import", "new_build"],
            ),
            _command_step(
                kind="bsim_index",
                title="Index both imported programs into the BSim database",
                command=[
                    args.bsim_ctl_path,
                    "index",
                    str(ghidra_project_dir),
                    project_a,
                    project_b,
                ],
                outputs=[str(artifact_dir / "bsim-index")],
                reason_codes=["bsim_index"],
            ),
            _command_step(
                kind="bsim_query",
                title="Query BSim matches and export external similarity manifest",
                command=[
                    args.bsim_ctl_path,
                    "query",
                    str(ghidra_project_dir),
                    project_b,
                    "--against",
                    project_a,
                    "--output",
                    similarity_manifest_path,
                ],
                outputs=[similarity_manifest_path],
                reason_codes=["bsim_query", "external_similarity_manifest"],
            ),
            WindowsSymbolSimilarityExtractionStep(
                kind="normalize_similarity",
                title="Normalize BSim export to Glaurung external-similarity YAML",
                ready=True,
                outputs=[similarity_manifest_path],
                next_tool_name="windows_patch_function_identity_extract",
                next_tool_args={"external_similarity_manifest_path": similarity_manifest_path},
                reason_codes=["normalize_similarity_manifest"],
            ),
            WindowsSymbolSimilarityExtractionStep(
                kind="identity_extract",
                title="Feed similarity/PDB facts into patch identity extraction",
                ready=True,
                outputs=[identity_output_path],
                next_tool_name="windows_patch_function_identity_extract",
                next_tool_args=identity_args,
                reason_codes=["windows_patch_function_identity_extract"],
            ),
        ]
    )
    return steps


def _identity_extract_args(
    args: WindowsSymbolSimilarityExtractionPlanArgs,
    *,
    binary_a: Path,
    binary_b: Path,
    similarity_manifest_path: str,
    identity_output_path: str,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "binary_a": str(binary_a),
        "binary_b": str(binary_b),
        "external_similarity_manifest_path": similarity_manifest_path,
        "identity_output_path": identity_output_path,
    }
    if args.pdb_identity_path:
        out["pdb_identity_manifest"] = {
            "identity_path": args.pdb_identity_path,
            "target_id": args.target_id,
            "binary_filename": args.component,
            "build_label": args.build_label_b,
            "cache_status": "cached",
        }
    return out


def _command_step(
    *,
    kind: WindowsSymbolSimilarityStepKind,
    title: str,
    command: list[str],
    outputs: list[str],
    reason_codes: list[str],
) -> WindowsSymbolSimilarityExtractionStep:
    return WindowsSymbolSimilarityExtractionStep(
        kind=kind,
        title=title,
        ready=True,
        command=command,
        command_text=shlex.join(command),
        outputs=outputs,
        reason_codes=reason_codes,
    )


def _command_ready(command: str) -> bool:
    path = Path(command).expanduser()
    if path.is_file():
        return True
    return shutil.which(command) is not None


def _project_name(binary: Path, suffix: str) -> str:
    stem = binary.name.replace(".", "_").replace("-", "_")
    return f"{stem}_{suffix}"


def _write_script(
    path_text: str | None,
    steps: list[WindowsSymbolSimilarityExtractionStep],
) -> str | None:
    if not path_text:
        return None
    path = Path(path_text).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        "# Generated by windows_symbol_similarity_extraction_plan.",
    ]
    for step in steps:
        lines.append("")
        lines.append(f"# {step.title}")
        if step.command_text:
            lines.append(step.command_text)
        elif step.next_tool_name:
            lines.append(f"# next tool: {step.next_tool_name}")
            lines.append(
                "# args: "
                + json.dumps(step.next_tool_args, sort_keys=True, separators=(",", ":"))
            )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _evidence_bundle(
    *,
    args: WindowsSymbolSimilarityExtractionPlanArgs,
    steps: list[WindowsSymbolSimilarityExtractionStep],
    blockers: list[str],
    warnings: list[str],
    ready_to_execute: bool,
    similarity_manifest_path: str,
    identity_output_path: str,
    notes: list[str],
) -> WindowsEvidenceBundle:
    return make_windows_evidence_bundle(
        claim_level="triage_evidence_bundle_not_finding",
        subject=WindowsEvidenceSubject(
            kind="generic",
            target_id=args.target_id,
            component=args.component,
            attributes={
                "ready_to_execute": ready_to_execute,
                "step_count": len(steps),
                "similarity_manifest_path": similarity_manifest_path,
                "identity_output_path": identity_output_path,
                "warning_count": len(warnings),
            },
        ),
        source_tools=["windows_symbol_similarity_extraction_plan"],
        tool_sequence=["windows_symbol_similarity_extraction_plan"],
        evidence_refs=[
            evidence_ref(
                kind="tool_result",
                source="windows_symbol_similarity_extraction_plan",
                summary=(
                    "planned symbol-server/BSim extraction and patch-identity handoff"
                ),
                reason_codes=[
                    "symbol_similarity_extraction_plan_not_analysis",
                    "external_similarity_manifest",
                ],
            )
        ],
        coverage=WindowsEvidenceCoverage(
            fact_coverage=[similarity_manifest_path, identity_output_path],
            missing_facts=blockers,
            validation_ready=False,
        ),
        reason_codes=["symbol_similarity_extraction_plan_not_analysis"],
        blockers=blockers,
        next_actions=[
            "Run generated Ghidra/BSim commands on a prepared runner.",
            "Feed the produced external similarity manifest into windows_patch_function_identity_extract.",
        ],
        notes=notes,
    )


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> WindowsSymbolSimilarityExtractionPlanTool:
    return WindowsSymbolSimilarityExtractionPlanTool()
