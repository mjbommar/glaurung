from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_syscall_stub_atlas import ServiceTableKind


ModuleAddressStatus = Literal[
    "inside_loaded_module",
    "outside_loaded_modules",
    "expected_module",
    "unexpected_module",
    "unknown",
]


class WindowsKernelIdentityFact(BaseModel):
    version: str | None = None
    build_number: int | None = None
    product_name: str | None = None
    architecture: str | None = None
    kernel_base: int | None = None
    kernel_base_hex: str | None = None
    kernel_size: int | None = None
    kernel_pdb_guid: str | None = None
    kernel_pdb_age: int | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    evidence: list[str] = Field(default_factory=list)


class WindowsLoadedModuleFact(BaseModel):
    name: str
    path: str | None = None
    base_va: int
    base_hex: str
    end_va: int
    end_hex: str
    size: int
    pdb_guid: str | None = None
    pdb_age: int | None = None
    timestamp: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.85)
    evidence: list[str] = Field(default_factory=list)


class WindowsLiveSyscallFact(BaseModel):
    service_table: ServiceTableKind
    syscall_number: int
    syscall_hex: str
    symbol: str | None = None
    handler_va: int | None = None
    handler_hex: str | None = None
    handler_module: str | None = None
    expected_handler_va: int | None = None
    expected_handler_hex: str | None = None
    expected_module: str | None = None
    module_status: ModuleAddressStatus
    matches_expected_handler: bool | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


class WindowsLiveCallbackFact(BaseModel):
    kind: str
    routine_va: int | None = None
    routine_hex: str | None = None
    routine_name: str | None = None
    module_name: str | None = None
    module_status: ModuleAddressStatus
    registration_va: int | None = None
    registration_hex: str | None = None
    active: bool | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


class WindowsDriverDispatchFact(BaseModel):
    driver_name: str
    major_function: str
    handler_va: int | None = None
    handler_hex: str | None = None
    handler_name: str | None = None
    module_name: str | None = None
    module_status: ModuleAddressStatus
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


class WindowsDriverObjectFact(BaseModel):
    driver_name: str
    object_va: int | None = None
    object_hex: str | None = None
    driver_start_va: int | None = None
    driver_start_hex: str | None = None
    driver_size: int | None = None
    module_name: str | None = None
    dispatch_count: int
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


class WindowsLiveKernelSnapshotArgs(BaseModel):
    snapshot_json: str | None = Field(
        None,
        description=(
            "Optional JSON snapshot from a read-only live collector. Supported "
            "top-level sections include kernel/identity, modules, syscalls, "
            "callbacks, and driver_objects."
        ),
    )
    snapshot_path: str | None = Field(
        None,
        description="Optional path to a live-kernel snapshot JSON file.",
    )
    expected_handler_map_json: str | None = Field(
        None,
        description=(
            "Optional static expected syscall-handler map. Accepts a dict keyed "
            "by symbol or syscall number, or a list of rows with symbol/number, "
            "handler_va, and handler_module fields."
        ),
    )
    max_modules: int = Field(512, ge=0, description="Maximum modules to return.")
    max_syscalls: int = Field(4096, ge=0, description="Maximum syscalls to return.")
    max_callbacks: int = Field(
        1024,
        ge=0,
        description="Maximum registered callbacks to return.",
    )
    max_driver_objects: int = Field(
        256,
        ge=0,
        description="Maximum driver objects to return.",
    )
    max_dispatches: int = Field(
        2048,
        ge=0,
        description="Maximum driver dispatch entries to return.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact live-kernel snapshot evidence node.",
    )


class WindowsLiveKernelSnapshotResult(BaseModel):
    kernel_identity: WindowsKernelIdentityFact | None = None
    module_count: int
    syscall_count: int
    callback_count: int
    driver_object_count: int
    driver_dispatch_count: int
    modules: list[WindowsLoadedModuleFact]
    syscalls: list[WindowsLiveSyscallFact]
    callbacks: list[WindowsLiveCallbackFact]
    driver_objects: list[WindowsDriverObjectFact]
    driver_dispatches: list[WindowsDriverDispatchFact]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class _ExpectedHandlerRecord(BaseModel):
    handler_va: int | None = None
    handler_module: str | None = None
    handler_name: str | None = None
    evidence: list[str] = Field(default_factory=list)


class _ExpectedHandlerMaps(BaseModel):
    by_symbol: dict[str, _ExpectedHandlerRecord] = Field(default_factory=dict)
    by_number: dict[int, _ExpectedHandlerRecord] = Field(default_factory=dict)


class WindowsLiveKernelSnapshotTool(
    MemoryTool[WindowsLiveKernelSnapshotArgs, WindowsLiveKernelSnapshotResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_live_kernel_snapshot",
                description=(
                    "Normalize a read-only live Windows kernel snapshot into "
                    "kernel identity, loaded-module ranges, syscall table rows, "
                    "registered callbacks, and driver dispatch facts."
                ),
                tags=("windows", "kernel", "live", "ssdt", "callbacks", "drivers"),
            ),
            WindowsLiveKernelSnapshotArgs,
            WindowsLiveKernelSnapshotResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsLiveKernelSnapshotArgs,
    ) -> WindowsLiveKernelSnapshotResult:
        snapshot = _load_snapshot(args)
        expected_handlers = _expected_handler_maps(args.expected_handler_map_json)
        kernel_identity = _kernel_identity(snapshot)
        modules = _loaded_modules(snapshot)[: args.max_modules]
        syscalls = _live_syscalls(snapshot, modules, expected_handlers)[
            : args.max_syscalls
        ]
        callbacks = _live_callbacks(snapshot, modules)[: args.max_callbacks]
        driver_objects, driver_dispatches = _driver_objects_and_dispatches(
            snapshot,
            modules,
            max_driver_objects=args.max_driver_objects,
            max_dispatches=args.max_dispatches,
        )
        coverage = _coverage(
            kernel_identity=kernel_identity,
            modules=modules,
            syscalls=syscalls,
            callbacks=callbacks,
            driver_objects=driver_objects,
            driver_dispatches=driver_dispatches,
        )
        missing = _missing_capabilities(coverage)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_live_kernel_snapshot",
                    props={
                        "module_count": len(modules),
                        "syscall_count": len(syscalls),
                        "callback_count": len(callbacks),
                        "driver_object_count": len(driver_objects),
                        "driver_dispatch_count": len(driver_dispatches),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsLiveKernelSnapshotResult(
            kernel_identity=kernel_identity,
            module_count=len(modules),
            syscall_count=len(syscalls),
            callback_count=len(callbacks),
            driver_object_count=len(driver_objects),
            driver_dispatch_count=len(driver_dispatches),
            modules=modules,
            syscalls=syscalls,
            callbacks=callbacks,
            driver_objects=driver_objects,
            driver_dispatches=driver_dispatches,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "live-kernel snapshot rows are read-only ground truth imported from "
                "an external collector; this tool does not hook or modify the target",
                "module attribution is range-based and should be paired with PDB "
                "identity reconciliation before making enforcement decisions",
            ],
        )


def _load_snapshot(args: WindowsLiveKernelSnapshotArgs) -> dict[str, Any]:
    if args.snapshot_json:
        data = json.loads(args.snapshot_json)
    elif args.snapshot_path:
        data = json.loads(Path(args.snapshot_path).expanduser().read_text())
    else:
        raise ValueError("snapshot_json or snapshot_path is required")
    if not isinstance(data, dict):
        raise ValueError("live kernel snapshot must be a JSON object")
    return data


def _expected_handler_maps(value: str | None) -> _ExpectedHandlerMaps:
    maps = _ExpectedHandlerMaps()
    if not value:
        return maps
    raw = json.loads(value)
    if isinstance(raw, dict):
        for key, item in raw.items():
            if isinstance(item, dict):
                _add_expected_handler_record(maps, key, item)
            else:
                _add_expected_handler_record(maps, key, {"handler_va": item})
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                _add_expected_handler_record(maps, None, item)
    else:
        raise ValueError("expected_handler_map_json must be a JSON object or list")
    return maps


def _add_expected_handler_record(
    maps: _ExpectedHandlerMaps,
    key: str | None,
    item: dict[str, Any],
) -> None:
    record = _ExpectedHandlerRecord(
        handler_va=_int_or_none(
            item.get("expected_handler_va")
            or item.get("handler_va")
            or item.get("handler")
            or item.get("va")
        ),
        handler_module=_str_or_none(
            item.get("expected_module")
            or item.get("handler_module")
            or item.get("module")
        ),
        handler_name=_str_or_none(
            item.get("handler_name") or item.get("name") or item.get("symbol")
        ),
        evidence=["expected_handler_map"],
    )
    symbol = _str_or_none(
        item.get("symbol") or item.get("user_stub_symbol") or item.get("syscall_name")
    )
    if symbol:
        maps.by_symbol[symbol] = record
    number = _int_or_none(
        item.get("syscall_number")
        or item.get("number")
        or item.get("service_number")
        or item.get("index")
    )
    if number is not None:
        maps.by_number[number] = record
    if key:
        keyed_number = _int_or_none(key)
        if keyed_number is None:
            maps.by_symbol[key] = record
        else:
            maps.by_number[keyed_number] = record


def _kernel_identity(snapshot: dict[str, Any]) -> WindowsKernelIdentityFact | None:
    row = _first_mapping(snapshot, "kernel", "identity", "system")
    if not row:
        return None
    base = _int_or_none(
        row.get("kernel_base")
        or row.get("ntoskrnl_base")
        or row.get("base")
        or row.get("image_base")
    )
    size = _int_or_none(
        row.get("kernel_size")
        or row.get("ntoskrnl_size")
        or row.get("size")
        or row.get("image_size")
    )
    return WindowsKernelIdentityFact(
        version=_str_or_none(row.get("version") or row.get("os_version")),
        build_number=_int_or_none(row.get("build_number") or row.get("build")),
        product_name=_str_or_none(row.get("product_name") or row.get("product")),
        architecture=_str_or_none(row.get("architecture") or row.get("arch")),
        kernel_base=base,
        kernel_base_hex=_hex_or_none(base),
        kernel_size=size,
        kernel_pdb_guid=_str_or_none(row.get("kernel_pdb_guid") or row.get("pdb_guid")),
        kernel_pdb_age=_int_or_none(row.get("kernel_pdb_age") or row.get("pdb_age")),
        confidence=0.86,
        evidence=["kernel_identity"],
    )


def _loaded_modules(snapshot: dict[str, Any]) -> list[WindowsLoadedModuleFact]:
    modules: list[WindowsLoadedModuleFact] = []
    for row in _list_section(snapshot, "modules", "loaded_modules", "kernel_modules"):
        name = _str_or_none(
            row.get("name") or row.get("module") or row.get("image_name")
        )
        base = _int_or_none(
            row.get("base_va") or row.get("base") or row.get("start") or row.get("va")
        )
        if not name or base is None:
            continue
        size = _int_or_none(row.get("size") or row.get("image_size"))
        end = _int_or_none(row.get("end_va") or row.get("end"))
        if size is None and end is not None and end > base:
            size = end - base
        if end is None and size is not None:
            end = base + size
        if size is None or end is None or end <= base:
            continue
        modules.append(
            WindowsLoadedModuleFact(
                name=name,
                path=_str_or_none(row.get("path") or row.get("image_path")),
                base_va=base,
                base_hex=_hex(base),
                end_va=end,
                end_hex=_hex(end),
                size=size,
                pdb_guid=_str_or_none(row.get("pdb_guid") or row.get("guid")),
                pdb_age=_int_or_none(row.get("pdb_age") or row.get("age")),
                timestamp=_str_or_none(
                    row.get("timestamp") or row.get("time_date_stamp")
                ),
                confidence=0.88,
                evidence=["loaded_modules"],
            )
        )
    modules.sort(key=lambda item: item.base_va)
    return modules


def _live_syscalls(
    snapshot: dict[str, Any],
    modules: list[WindowsLoadedModuleFact],
    expected_handlers: _ExpectedHandlerMaps,
) -> list[WindowsLiveSyscallFact]:
    facts: list[WindowsLiveSyscallFact] = []
    for row in _list_section(snapshot, "syscalls", "ssdt", "syscall_table"):
        number = _int_or_none(
            row.get("syscall_number")
            or row.get("number")
            or row.get("service_number")
            or row.get("index")
        )
        if number is None:
            continue
        symbol = _str_or_none(row.get("symbol") or row.get("name"))
        expected = _expected_handler_for_syscall(expected_handlers, symbol, number)
        handler_va = _int_or_none(
            row.get("handler_va")
            or row.get("handler")
            or row.get("target")
            or row.get("address")
        )
        expected_handler_va = _int_or_none(
            row.get("expected_handler_va") or row.get("expected_handler")
        )
        if expected_handler_va is None and expected is not None:
            expected_handler_va = expected.handler_va
        expected_module = _str_or_none(
            row.get("expected_module") or row.get("expected_handler_module")
        )
        if expected_module is None and expected is not None:
            expected_module = expected.handler_module
        module = _find_module(modules, handler_va)
        module_status = _module_status(module, handler_va, expected_module)
        facts.append(
            WindowsLiveSyscallFact(
                service_table=_service_table(
                    row.get("service_table") or row.get("table")
                ),
                syscall_number=number,
                syscall_hex=_hex(number),
                symbol=symbol or (expected.handler_name if expected else None),
                handler_va=handler_va,
                handler_hex=_hex_or_none(handler_va),
                handler_module=module.name if module else None,
                expected_handler_va=expected_handler_va,
                expected_handler_hex=_hex_or_none(expected_handler_va),
                expected_module=expected_module,
                module_status=module_status,
                matches_expected_handler=None
                if expected_handler_va is None or handler_va is None
                else expected_handler_va == handler_va,
                confidence=0.84 if handler_va is not None else 0.55,
                evidence=[
                    "live_syscall_table",
                    *_module_evidence(module, handler_va),
                    *((expected.evidence if expected else [])[:2]),
                ],
            )
        )
    facts.sort(key=lambda item: (str(item.service_table), item.syscall_number))
    return facts


def _expected_handler_for_syscall(
    expected_handlers: _ExpectedHandlerMaps,
    symbol: str | None,
    number: int,
) -> _ExpectedHandlerRecord | None:
    if symbol is not None and symbol in expected_handlers.by_symbol:
        return expected_handlers.by_symbol[symbol]
    return expected_handlers.by_number.get(number)


def _live_callbacks(
    snapshot: dict[str, Any],
    modules: list[WindowsLoadedModuleFact],
) -> list[WindowsLiveCallbackFact]:
    facts: list[WindowsLiveCallbackFact] = []
    for row in _list_section(snapshot, "callbacks", "kernel_callbacks"):
        kind = _str_or_none(
            row.get("kind") or row.get("type") or row.get("callback_type")
        )
        routine_va = _int_or_none(
            row.get("routine_va")
            or row.get("routine")
            or row.get("callback")
            or row.get("address")
        )
        if not kind and routine_va is None:
            continue
        module = _find_module(modules, routine_va)
        facts.append(
            WindowsLiveCallbackFact(
                kind=kind or "unknown",
                routine_va=routine_va,
                routine_hex=_hex_or_none(routine_va),
                routine_name=_str_or_none(row.get("routine_name") or row.get("name")),
                module_name=module.name if module else None,
                module_status=_module_status(module, routine_va, None),
                registration_va=_int_or_none(
                    row.get("registration_va") or row.get("registration")
                ),
                registration_hex=_hex_or_none(
                    _int_or_none(row.get("registration_va") or row.get("registration"))
                ),
                active=_bool_or_none(row.get("active") or row.get("enabled")),
                confidence=0.82 if routine_va is not None else 0.6,
                evidence=["kernel_callbacks", *_module_evidence(module, routine_va)],
            )
        )
    return facts


def _driver_objects_and_dispatches(
    snapshot: dict[str, Any],
    modules: list[WindowsLoadedModuleFact],
    *,
    max_driver_objects: int,
    max_dispatches: int,
) -> tuple[list[WindowsDriverObjectFact], list[WindowsDriverDispatchFact]]:
    objects: list[WindowsDriverObjectFact] = []
    dispatches: list[WindowsDriverDispatchFact] = []
    for row in _list_section(snapshot, "driver_objects", "drivers")[
        :max_driver_objects
    ]:
        driver_name = _str_or_none(row.get("driver_name") or row.get("name"))
        if not driver_name:
            continue
        object_va = _int_or_none(row.get("object_va") or row.get("object"))
        driver_start = _int_or_none(
            row.get("driver_start_va") or row.get("driver_start") or row.get("base")
        )
        module = _find_module(modules, driver_start)
        dispatch_rows = _dispatch_rows(row.get("major_functions"))
        objects.append(
            WindowsDriverObjectFact(
                driver_name=driver_name,
                object_va=object_va,
                object_hex=_hex_or_none(object_va),
                driver_start_va=driver_start,
                driver_start_hex=_hex_or_none(driver_start),
                driver_size=_int_or_none(row.get("driver_size") or row.get("size")),
                module_name=module.name if module else None,
                dispatch_count=len(dispatch_rows),
                confidence=0.82,
                evidence=["driver_objects", *_module_evidence(module, driver_start)],
            )
        )
        for major, dispatch in dispatch_rows:
            if len(dispatches) >= max_dispatches:
                break
            handler_va = _int_or_none(
                dispatch.get("handler_va")
                or dispatch.get("handler")
                or dispatch.get("routine")
                or dispatch.get("address")
            )
            handler_module = _find_module(modules, handler_va)
            dispatches.append(
                WindowsDriverDispatchFact(
                    driver_name=driver_name,
                    major_function=major,
                    handler_va=handler_va,
                    handler_hex=_hex_or_none(handler_va),
                    handler_name=_str_or_none(
                        dispatch.get("handler_name") or dispatch.get("name")
                    ),
                    module_name=handler_module.name if handler_module else None,
                    module_status=_module_status(handler_module, handler_va, None),
                    confidence=0.82 if handler_va is not None else 0.55,
                    evidence=[
                        "driver_dispatch_table",
                        *_module_evidence(handler_module, handler_va),
                    ],
                )
            )
        if len(dispatches) >= max_dispatches:
            break
    return objects, dispatches


def _dispatch_rows(value: Any) -> list[tuple[str, dict[str, Any]]]:
    rows: list[tuple[str, dict[str, Any]]] = []
    if isinstance(value, dict):
        for major, raw in value.items():
            rows.append(
                (str(major), raw if isinstance(raw, dict) else {"handler": raw})
            )
    elif isinstance(value, list):
        for raw in value:
            if not isinstance(raw, dict):
                continue
            major = _str_or_none(
                raw.get("major_function") or raw.get("major") or raw.get("name")
            )
            if not major:
                continue
            rows.append((major, raw))
    return rows


def _coverage(
    *,
    kernel_identity: WindowsKernelIdentityFact | None,
    modules: list[WindowsLoadedModuleFact],
    syscalls: list[WindowsLiveSyscallFact],
    callbacks: list[WindowsLiveCallbackFact],
    driver_objects: list[WindowsDriverObjectFact],
    driver_dispatches: list[WindowsDriverDispatchFact],
) -> list[str]:
    coverage: list[str] = []
    if kernel_identity is not None:
        coverage.append("kernel_identity")
    if modules:
        coverage.append("loaded_modules")
    if syscalls:
        coverage.append("live_syscall_table")
    if callbacks:
        coverage.append("kernel_callbacks")
    if driver_objects:
        coverage.append("driver_objects")
    if driver_dispatches:
        coverage.append("driver_dispatch_table")
    if any(row.module_status == "outside_loaded_modules" for row in syscalls):
        coverage.append("syscall_handler_outside_loaded_modules")
    if any(row.module_status == "unexpected_module" for row in syscalls):
        coverage.append("syscall_unexpected_module")
    if any(row.matches_expected_handler is False for row in syscalls):
        coverage.append("syscall_expected_handler_mismatch")
    return coverage


def _missing_capabilities(coverage: list[str]) -> list[str]:
    expected = [
        "kernel_identity",
        "loaded_modules",
        "live_syscall_table",
        "kernel_callbacks",
        "driver_objects",
        "driver_dispatch_table",
    ]
    seen = set(coverage)
    return [item for item in expected if item not in seen]


def _module_status(
    module: WindowsLoadedModuleFact | None,
    va: int | None,
    expected_module: str | None,
) -> ModuleAddressStatus:
    if va is None:
        return "unknown"
    if module is None:
        return "outside_loaded_modules"
    if expected_module:
        if module.name.lower() == expected_module.lower():
            return "expected_module"
        return "unexpected_module"
    return "inside_loaded_module"


def _module_evidence(
    module: WindowsLoadedModuleFact | None,
    va: int | None,
) -> list[str]:
    if va is None:
        return ["no_address"]
    if module is None:
        return ["outside_loaded_modules"]
    return [f"module:{module.name}:{module.base_hex}-{module.end_hex}"]


def _find_module(
    modules: list[WindowsLoadedModuleFact],
    va: int | None,
) -> WindowsLoadedModuleFact | None:
    if va is None:
        return None
    for module in modules:
        if module.base_va <= va < module.end_va:
            return module
    return None


def _list_section(snapshot: dict[str, Any], *keys: str) -> list[dict[str, Any]]:
    for key in keys:
        value = snapshot.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _first_mapping(snapshot: dict[str, Any], *keys: str) -> dict[str, Any] | None:
    for key in keys:
        value = snapshot.get(key)
        if isinstance(value, dict):
            return value
    return None


def _service_table(value: Any) -> ServiceTableKind:
    text = str(value or "unknown").lower()
    if text in {"native", "nt", "ntdll", "ssdt"}:
        return "native"
    if text in {"win32k", "gui", "shadow", "win32u"}:
        return "win32k"
    return "unknown"


def _bool_or_none(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "enabled", "active"}:
            return True
        if lowered in {"0", "false", "no", "disabled", "inactive"}:
            return False
    return None


def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _hex_or_none(value: int | None) -> str | None:
    return None if value is None else _hex(value)


def build_tool() -> WindowsLiveKernelSnapshotTool:
    return WindowsLiveKernelSnapshotTool()
