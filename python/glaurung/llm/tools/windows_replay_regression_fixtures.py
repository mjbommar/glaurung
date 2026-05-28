from __future__ import annotations

import re
from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_api_contract_primitives import (
    WindowsApiContractPrimitivesArgs,
    WindowsApiContractPrimitivesTool,
)
from .windows_check_gate_to_sink import (
    WindowsCheckGateToSinkArgs,
    WindowsCheckGateToSinkTool,
)
from .windows_compare_selector_cases import (
    WindowsCompareSelectorCasesArgs,
    WindowsCompareSelectorCasesTool,
)
from .windows_syscall_stub_atlas import (
    WindowsSyscallStubAtlasArgs,
    WindowsSyscallStubAtlasTool,
)
from .windows_regression_fixture_catalog import (
    WindowsRegressionFixture,
    WindowsRegressionFixtureCatalogArgs,
    WindowsRegressionFixtureCatalogTool,
    WindowsRegressionFixtureCase,
)


class WindowsFixtureReplayArgs(BaseModel):
    fixtures_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-regression-fixtures.yaml.",
    )
    gates_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-gates.yaml.",
    )
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml.",
    )
    primitive: str | None = Field(None, description="Optional primitive filter.")
    bug_class: str | None = Field(None, description="Optional bug class filter.")
    max_fixtures: int = Field(64, description="Maximum fixtures to replay.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact replay evidence node to the KB.",
    )


class WindowsFixtureCaseReplay(BaseModel):
    fixture_id: str
    primitive: str
    case_id: str
    expected: str
    detected: bool
    passed: bool
    status: Literal["passed", "failed", "unsupported"]
    unsupported: bool = False
    signal: str
    details: list[str] = Field(default_factory=list)


class WindowsFixtureReplayResult(BaseModel):
    replays: list[WindowsFixtureCaseReplay]
    fixture_count: int
    case_count: int
    passed_count: int
    failed_count: int
    unsupported_count: int
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsReplayRegressionFixturesTool(
    MemoryTool[WindowsFixtureReplayArgs, WindowsFixtureReplayResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_replay_regression_fixtures",
                description=(
                    "Replay ASB reduced Windows regression fixtures through "
                    "current deterministic primitive checks."
                ),
                tags=("windows", "pe", "fixtures", "regression", "replay"),
            ),
            WindowsFixtureReplayArgs,
            WindowsFixtureReplayResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsFixtureReplayArgs,
    ) -> WindowsFixtureReplayResult:
        catalog = WindowsRegressionFixtureCatalogTool().run(
            ctx,
            kb,
            WindowsRegressionFixtureCatalogArgs(
                fixtures_path=args.fixtures_path,
                bug_class=args.bug_class,
                primitive=args.primitive,
            ),
        )
        fixtures = catalog.fixtures[: max(0, args.max_fixtures)]
        replays: list[WindowsFixtureCaseReplay] = []
        for fixture in fixtures:
            detector = _DETECTORS.get(fixture.primitive)
            for case in fixture.cases:
                replay = _replay_case(ctx, kb, args, fixture, case, detector)
                replays.append(replay)

        passed_count = sum(1 for replay in replays if replay.status == "passed")
        failed_count = sum(1 for replay in replays if replay.status == "failed")
        unsupported_count = sum(1 for replay in replays if replay.unsupported)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_replay_regression_fixtures",
                    props={
                        "fixture_count": len(fixtures),
                        "case_count": len(replays),
                        "passed_count": passed_count,
                        "failed_count": failed_count,
                        "unsupported_count": unsupported_count,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsFixtureReplayResult(
            replays=replays,
            fixture_count=len(fixtures),
            case_count=len(replays),
            passed_count=passed_count,
            failed_count=failed_count,
            unsupported_count=unsupported_count,
            evidence_node_id=evidence_node_id,
            notes=[
                "fixture replay uses reduced pseudocode checks; it is not live reachability or exploit proof"
            ],
        )


Detector = Callable[
    [MemoryContext, KnowledgeBase, WindowsFixtureReplayArgs, str],
    tuple[bool, str, list[str]],
]


def _replay_case(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsFixtureReplayArgs,
    fixture: WindowsRegressionFixture,
    case: WindowsRegressionFixtureCase,
    detector: Detector | None,
) -> WindowsFixtureCaseReplay:
    if detector is None:
        return WindowsFixtureCaseReplay(
            fixture_id=fixture.id,
            primitive=fixture.primitive,
            case_id=case.id,
            expected=case.expected,
            detected=False,
            passed=False,
            status="unsupported",
            unsupported=True,
            signal="unsupported_primitive",
            details=[f"no replay detector for primitive {fixture.primitive!r}"],
        )
    detected, signal, details = detector(ctx, kb, args, case.pseudocode)
    expected_detected = case.expected == "positive"
    return WindowsFixtureCaseReplay(
        fixture_id=fixture.id,
        primitive=fixture.primitive,
        case_id=case.id,
        expected=case.expected,
        detected=detected,
        passed=detected == expected_detected,
        status="passed" if detected == expected_detected else "failed",
        signal=signal,
        details=details,
    )


def _detect_unchecked_user_pointer_write(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsFixtureReplayArgs,
    pseudocode: str,
) -> tuple[bool, str, list[str]]:
    result = WindowsCheckGateToSinkTool().run(
        ctx,
        kb,
        WindowsCheckGateToSinkArgs(
            gates_path=args.gates_path,
            sinks_path=args.sinks_path,
            pseudocode=pseudocode,
            gate_kind="user_pointer",
            sink_kind="copy",
        ),
    )
    bad = [
        str(assessment.status)
        for assessment in result.assessments
        if assessment.status in {"missing", "gate_after_sink"}
    ]
    return bool(bad), "missing_or_late_user_pointer_gate", bad


def _detect_weak_length_check_before_copy(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsFixtureReplayArgs,
    pseudocode: str,
) -> tuple[bool, str, list[str]]:
    del ctx, kb, args
    lines = pseudocode.splitlines()
    copy_line = _first_line(lines, r"\bRtlCopyMemory\s*\(")
    if copy_line is None:
        return False, "no_copy_sink", []
    status_line = _first_line(lines[:copy_line], r"\bStatus\s*=")
    return_line = _first_line(lines[:copy_line], r"\breturn\b")
    detected = status_line is not None and (
        return_line is None or return_line < status_line
    )
    return detected, "status_set_but_copy_continues", [f"copy_line={copy_line + 1}"]


def _detect_refcount_missing_on_error_path(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsFixtureReplayArgs,
    pseudocode: str,
) -> tuple[bool, str, list[str]]:
    del ctx, kb, args
    lines = pseudocode.splitlines()
    deref = _first_line(lines, r"\bObDereferenceObject\s*\(")
    later_use = _first_line(lines[(deref or 0) + 1 :], r"\bUseObject\s*\(")
    detected = deref is not None and later_use is not None
    return (
        detected,
        "use_after_ob_dereference",
        [f"deref_line={deref + 1}" if deref is not None else "no_deref"],
    )


def _detect_use_after_completion(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsFixtureReplayArgs,
    pseudocode: str,
) -> tuple[bool, str, list[str]]:
    del ctx, kb, args
    lines = pseudocode.splitlines()
    complete = _first_line(lines, r"\bIoCompleteRequest\s*\(")
    later_irp = _first_line(lines[(complete or 0) + 1 :], r"\bIrp\s*->")
    detected = complete is not None and later_irp is not None
    return (
        detected,
        "irp_access_after_completion",
        [f"complete_line={complete + 1}" if complete is not None else "no_completion"],
    )


def _detect_callback_stale_pointer(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsFixtureReplayArgs,
    pseudocode: str,
) -> tuple[bool, str, list[str]]:
    del ctx, kb, args
    lines = pseudocode.splitlines()
    deref = _first_line(lines, r"\bObDereferenceObject\s*\(")
    later_callback = _first_line(
        lines[(deref or 0) + 1 :], r"\bCallback\s*\(\s*Object\s*\)"
    )
    detected = deref is not None and later_callback is not None
    return (
        detected,
        "callback_after_ob_dereference",
        [f"deref_line={deref + 1}" if deref is not None else "no_deref"],
    )


def _detect_irql_context_violation(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsFixtureReplayArgs,
    pseudocode: str,
) -> tuple[bool, str, list[str]]:
    del ctx, kb, args
    lines = pseudocode.splitlines()
    raise_line = _first_line(lines, r"\bKeRaiseIrql\b")
    helper_line = _first_line(
        lines, r"\b(Pageable|Blocking|PageableOrBlocking)Helper\s*\("
    )
    lower_line = _first_line(lines, r"\bKeLowerIrql\b")
    detected = (
        raise_line is not None
        and helper_line is not None
        and lower_line is not None
        and raise_line < helper_line < lower_line
    )
    return (
        detected,
        "helper_reached_at_raised_irql",
        [
            f"raise={raise_line}",
            f"helper={helper_line}",
            f"lower={lower_line}",
        ],
    )


def _detect_integer_overflow_into_allocation_copy(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsFixtureReplayArgs,
    pseudocode: str,
) -> tuple[bool, str, list[str]]:
    del ctx, kb, args
    lines = pseudocode.splitlines()
    multiply = _first_line(lines, r"\bCount\s*\*\s*sizeof\s*\(")
    allocation = _first_line(lines, r"\bExAllocatePool")
    copy = _first_line(lines, r"\bRtlCopyMemory\s*\(")
    guard = _first_line(lines[: multiply or 0], r"\bCount\s*>\s*[A-Za-z0-9_]+")
    detected = (
        multiply is not None
        and allocation is not None
        and copy is not None
        and guard is None
    )
    return (
        detected,
        "count_to_bytes_without_prior_cap",
        [
            f"multiply={multiply}",
            f"guard={guard}",
        ],
    )


def _detect_selector_case_missing_validation(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsFixtureReplayArgs,
    pseudocode: str,
) -> tuple[bool, str, list[str]]:
    result = WindowsCompareSelectorCasesTool().run(
        ctx,
        kb,
        WindowsCompareSelectorCasesArgs(
            gates_path=args.gates_path,
            sinks_path=args.sinks_path,
            pseudocode=pseudocode,
            gate_kind="user_pointer",
            sink_kind="copy",
        ),
    )
    signals = [
        diff.reason
        for diff in result.differences
        if diff.kind in {"sink_without_gate", "gate_missing_in_cases"}
    ]
    return bool(signals), "selector_case_gate_asymmetry", signals


def _api_contract_primitive_detector(primitive_kind: str) -> Detector:
    def detect(
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsFixtureReplayArgs,
        pseudocode: str,
    ) -> tuple[bool, str, list[str]]:
        del args
        result = WindowsApiContractPrimitivesTool().run(
            ctx,
            kb,
            WindowsApiContractPrimitivesArgs(pseudocode=pseudocode),
        )
        count = result.primitive_counts.get(primitive_kind, 0)
        snippets = [
            primitive.snippet
            for primitive in result.primitives
            if primitive.kind == primitive_kind
        ]
        return (
            bool(count),
            f"api_contract_primitive:{primitive_kind}",
            [
                f"{primitive_kind}={count}",
                *snippets[:4],
            ],
        )

    return detect


def _detect_syscall_stub(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsFixtureReplayArgs,
    pseudocode: str,
) -> tuple[bool, str, list[str]]:
    del args
    result = WindowsSyscallStubAtlasTool().run(
        ctx,
        kb,
        WindowsSyscallStubAtlasArgs(pseudocode=pseudocode),
    )
    rows = [
        f"{stub.user_stub_symbol}:{stub.syscall_hex}:{stub.service_table}"
        for stub in result.stubs
    ]
    return (
        bool(result.stubs),
        "syscall_stub_atlas",
        [f"syscalls={len(rows)}", *rows[:4]],
    )


def _first_line(lines: list[str], pattern: str) -> int | None:
    regex = re.compile(pattern)
    for index, line in enumerate(lines):
        if regex.search(line):
            return index
    return None


_API_CONTRACT_REPLAY_PRIMITIVES = {
    "probe_for_read",
    "probe_for_write",
    "user_buffer_copy",
    "return_length_write",
    "string_conversion_copy",
    "ioctl_call",
    "pool_allocation",
    "pool_free",
    "registry_query",
    "registry_write",
    "object_reference",
    "object_release",
    "irp_access",
    "mdl_access",
    "alpc_message",
    "trace_emit",
    "callback_registration",
    "callback_dispatch",
    "requestor_mode_read",
    "privilege_check",
    "token_reference",
    "token_query",
    "token_release",
}


_DETECTORS: dict[str, Detector] = {
    "syscall_stub": _detect_syscall_stub,
    "unchecked_user_pointer_write": _detect_unchecked_user_pointer_write,
    "weak_length_check_before_copy": _detect_weak_length_check_before_copy,
    "refcount_missing_on_error_path": _detect_refcount_missing_on_error_path,
    "use_after_completion": _detect_use_after_completion,
    "callback_then_stale_pointer_dereference": _detect_callback_stale_pointer,
    "irql_context_violation": _detect_irql_context_violation,
    "integer_overflow_into_allocation_copy": _detect_integer_overflow_into_allocation_copy,
    "selector_case_missing_validation": _detect_selector_case_missing_validation,
    **{
        primitive: _api_contract_primitive_detector(primitive)
        for primitive in _API_CONTRACT_REPLAY_PRIMITIVES
    },
}


def build_tool() -> MemoryTool[WindowsFixtureReplayArgs, WindowsFixtureReplayResult]:
    return WindowsReplayRegressionFixturesTool()
