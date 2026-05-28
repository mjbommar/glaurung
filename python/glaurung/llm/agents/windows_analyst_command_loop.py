"""Bounded command-loop wrapper for the Windows interactive analyst."""

from __future__ import annotations

from pydantic import BaseModel, Field

from .windows_interactive_analyst import (
    InteractiveIntent,
    WindowsInteractiveAnalystConfig,
    WindowsInteractiveAnalystResult,
    WindowsInteractiveAnalystSessionState,
    run_windows_interactive_analyst,
)


class WindowsAnalystLoopCommand(BaseModel):
    """One deterministic analyst command in a multi-turn session."""

    intent: InteractiveIntent
    question: str
    file: str | None = None
    address: str | None = None
    max_items: int | None = Field(None, ge=1, le=64)
    binary_a: str | None = None
    binary_b: str | None = None
    seeds_path: str | None = None
    pdb_backed: bool = False
    candidate_id: str | None = None
    evidence_export_manifest_path: str | None = None
    blocker_worklist_path: str | None = None
    blocker_task_plan_path: str | None = None
    review_packet_output_path: str | None = None


class WindowsAnalystLoopConfig(BaseModel):
    """Configuration for a bounded analyst command loop."""

    commands: list[WindowsAnalystLoopCommand] = Field(min_length=1)
    comparison_path: str = Field(
        "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
    )
    diagnostics_path: str = Field(
        "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json"
    )
    session_state: WindowsInteractiveAnalystSessionState | None = None
    max_turns: int = Field(32, ge=1, le=128)
    default_max_items: int = Field(8, ge=1, le=64)
    stop_on_error: bool = True


class WindowsAnalystLoopTurn(BaseModel):
    """Result for one command-loop turn."""

    turn: int
    command: WindowsAnalystLoopCommand
    result: WindowsInteractiveAnalystResult | None = None
    error: str | None = None


class WindowsAnalystLoopResult(BaseModel):
    """Aggregate result for a deterministic command-loop transcript."""

    claim_level: str = "interactive_command_loop_not_finding"
    turn_count: int
    completed_turn_count: int
    failed_turn_count: int
    turns: list[WindowsAnalystLoopTurn]
    final_session_state: WindowsInteractiveAnalystSessionState
    next_tools: list[str]
    tool_sequence: list[str]
    notes: list[str] = Field(default_factory=list)


def run_windows_analyst_command_loop(
    config: WindowsAnalystLoopConfig,
) -> WindowsAnalystLoopResult:
    """Run a bounded list of analyst commands while carrying session state."""

    state = config.session_state
    turns: list[WindowsAnalystLoopTurn] = []
    tool_sequence: list[str] = ["windows_analyst_command_loop"]
    for idx, command in enumerate(config.commands[: config.max_turns], start=1):
        try:
            result = run_windows_interactive_analyst(
                WindowsInteractiveAnalystConfig(
                    intent=command.intent,
                    question=command.question,
                    comparison_path=config.comparison_path,
                    diagnostics_path=config.diagnostics_path,
                    file=command.file,
                    address=command.address,
                    max_items=command.max_items or config.default_max_items,
                    binary_a=command.binary_a,
                    binary_b=command.binary_b,
                    seeds_path=command.seeds_path,
                    pdb_backed=command.pdb_backed,
                    candidate_id=command.candidate_id,
                    evidence_export_manifest_path=(
                        command.evidence_export_manifest_path
                    ),
                    blocker_worklist_path=command.blocker_worklist_path,
                    blocker_task_plan_path=command.blocker_task_plan_path,
                    review_packet_output_path=command.review_packet_output_path,
                    session_state=state,
                )
            )
            state = result.session_state
            turns.append(
                WindowsAnalystLoopTurn(turn=idx, command=command, result=result)
            )
            tool_sequence.extend(result.tool_sequence)
        except Exception as exc:
            turns.append(
                WindowsAnalystLoopTurn(
                    turn=idx,
                    command=command,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
            if config.stop_on_error:
                break

    completed = sum(1 for turn in turns if turn.result is not None)
    failed = sum(1 for turn in turns if turn.error is not None)
    final_state = state or WindowsInteractiveAnalystSessionState()
    return WindowsAnalystLoopResult(
        turn_count=len(turns),
        completed_turn_count=completed,
        failed_turn_count=failed,
        turns=turns,
        final_session_state=final_state,
        next_tools=_dedupe(
            [
                tool
                for turn in turns
                if turn.result is not None
                for tool in turn.result.next_tools
            ]
        ),
        tool_sequence=_dedupe(tool_sequence),
        notes=[
            "Command-loop answers are deterministic tool summaries, not vulnerability verdicts.",
            "The final session state can be persisted and resumed by the Windows analyst CLI.",
        ],
    )


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
