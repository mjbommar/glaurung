"""Bounded Linux acquisition for child processes launched by Glaurung.

This module is an acquisition provider, not a second runtime data model. It
collects a stopped child into the canonical Rust-validated process capsule and
never accepts an existing PID.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from datetime import datetime, timezone
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import signal
import subprocess
import struct
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from typing import Any, cast

from glaurung import runtime_analysis


_MAX_DESCRIPTORS = 256
_MAX_BACKING_ARTIFACTS = 64
_MAX_BACKING_ARTIFACT_BYTES = 32 * 1024 * 1024
_MAX_TOTAL_BACKING_BYTES = 128 * 1024 * 1024
_MAX_SELECTED_PAGES = 64
_MAX_TRACE_BYTES = 8 * 1024 * 1024
_MAX_PROCESS_OUTPUT_BYTES = 1024 * 1024
_MAX_STDIN_BYTES = 1024 * 1024
_MAX_CHECKPOINT_STACK_BYTES = 1024 * 1024
_CHECKPOINT_WRITE_WINDOW_BYTES = 64
_MAX_ENVIRONMENT_VALUE_BYTES = 1024 * 1024
_MAX_SELECTED_ENVIRONMENT = 64
_PROC_FILES = ("maps", "status", "stat", "cmdline", "auxv")
_PTRACE_GETREGS = 12
_PTRACE_SINGLESTEP = 9
_PTRACE_ATTACH = 16
_PTRACE_DETACH = 17
_MAX_INSTRUCTION_TRACE_STEPS = 4096
_INSTRUCTION_TRACE_STACK_BYTES = 4096
_INSTRUCTION_TRACE_HEAP_BYTES = 1024 * 1024
_WAIT_ALL = 0x40000000
_X86_64_REGISTER_NAMES = (
    "r15",
    "r14",
    "r13",
    "r12",
    "rbp",
    "rbx",
    "r11",
    "r10",
    "r9",
    "r8",
    "rax",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "orig_rax",
    "rip",
    "cs",
    "eflags",
    "rsp",
    "ss",
    "fs_base",
    "gs_base",
    "ds",
    "es",
    "fs",
    "gs",
)


class _X86_64Registers(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in _X86_64_REGISTER_NAMES]


class _IOVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


def _proc_argv_location(pid: int, index: int, expected: bytes) -> int:
    """Resolve one argv string through Linux ``/proc/<pid>/stat`` bounds."""
    stat = Path(f"/proc/{pid}/stat").read_text()
    comm_end = stat.rfind(")")
    if comm_end < 0:
        raise RuntimeError("process stat has no command terminator")
    fields = [stat[: stat.find("(")].strip(), stat[stat.find("(") : comm_end + 1]]
    fields.extend(stat[comm_end + 1 :].split())
    if len(fields) <= 48:
        raise RuntimeError("process stat has no argument bounds")
    try:
        argument_start = int(fields[47])
        argument_end = int(fields[48])
    except ValueError as error:
        raise RuntimeError("process stat argument bounds are malformed") from error
    if argument_start <= 0 or argument_end <= argument_start:
        raise RuntimeError("process stat argument bounds are empty")
    encoded = _process_vm_read(pid, argument_start, argument_end - argument_start)
    entries = encoded.split(b"\0")
    if entries and entries[-1] == b"":
        entries.pop()
    if index >= len(entries) or entries[index] != expected:
        raise RuntimeError(f"kernel argv[{index}] bytes disagree with declared input")
    return argument_start + sum(len(value) + 1 for value in entries[:index])


@dataclass(frozen=True)
class StoppedChildCapture:
    """Canonical metadata and hash-bound sensitive page payloads."""

    capsule_json: str
    payloads: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True)
class TracedCoreCapture:
    """Canonical core evidence enriched with normalized mapping events."""

    capsule_json: str
    payloads: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True)
class MappingTraceCapture:
    """Canonical terminal evidence enriched with bounded mapping events."""

    capsule_json: str
    payloads: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True)
class _CheckpointMapping:
    start: int
    end: int
    permissions_text: str


@dataclass(frozen=True)
class _ReadCheckpoint:
    child_pid: int
    maps_text: str
    stack_mapping: _CheckpointMapping
    instruction_pointer: int
    stack_pointer: int
    stack_bytes: bytes
    before_stack_pointer: int
    before_stack_bytes: bytes
    destination: int
    read_bytes: bytes


@dataclass(frozen=True)
class HeapSnapshotCapture:
    """Canonical allocation lifetimes and bounded object byte snapshots."""

    capsule_json: str
    payloads: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True)
class InstructionTraceCapture:
    """Canonical bounded instruction events and stack snapshots."""

    capsule_json: str
    payloads: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True)
class CounterfactualValidation:
    """A separately captured execution validating one proposed branch witness."""

    validation_json: str
    materialized_input: bytes
    capture: InstructionTraceCapture | TracedCoreCapture


def validate_instruction_trace_counterfactual_child(
    executable: str | Path,
    original_capsule_json: str,
    original_payloads: Sequence[tuple[str, bytes]],
    original_arguments: Sequence[str],
    *,
    source_id: str,
    candidate_sequence: int,
    environment: Mapping[str, str] | None = None,
    cwd: str | Path | None = None,
    timeout: float = 5.0,
    expected_crash_class: str | None = None,
) -> CounterfactualValidation:
    """Materialize and validate one satisfiable argv branch counterfactual.

    The proposal is recomputed from the original capsule and exact executable;
    callers cannot supply a detached solver model. Validation launches a new
    owned child and emits a separate relation between the proposal and that
    capture. Only public invocation inputs are supported by this first bounded
    surface.
    """
    if candidate_sequence < 0:
        raise ValueError("candidate sequence must be non-negative")
    binary = Path(executable).resolve(strict=True)
    binary_bytes = binary.read_bytes()
    original_report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            original_capsule_json, list(original_payloads), binary_bytes
        )
    )
    matches = [
        candidate
        for candidate in original_report.get("solver_query_candidates", [])
        if candidate.get("source_id") == source_id
        and candidate.get("sequence") == candidate_sequence
    ]
    if len(matches) != 1:
        raise ValueError(
            "counterfactual identity does not select one original candidate"
        )
    candidate = matches[0]
    counterfactual = candidate.get("counterfactual")
    if not isinstance(counterfactual, dict) or counterfactual.get("status") != (
        "satisfiable"
    ):
        raise ValueError("selected counterfactual has no satisfiable witness")
    source_name = candidate.get("source_name")
    match = re.fullmatch(r"argv\[(\d+)\]", source_name or "")
    if match is None or int(match.group(1)) == 0:
        raise ValueError(
            "counterfactual validation currently supports argv inputs only"
        )
    argument_position = int(match.group(1)) - 1
    if argument_position >= len(original_arguments):
        raise ValueError("counterfactual argv source is absent from original arguments")
    original_input = os.fsencode(original_arguments[argument_position])
    provenance = json.loads(
        runtime_analysis.process_capsule_input_provenance(original_capsule_json)
    )
    sources = [source for source in provenance["sources"] if source["id"] == source_id]
    if len(sources) != 1:
        raise ValueError("counterfactual source identity is absent from the capsule")
    source = sources[0]
    if source["sensitivity"] != "public":
        raise ValueError("counterfactual validation refuses non-public input")
    if (
        source["byte_len"] != len(original_input)
        or source["sha256"] != hashlib.sha256(original_input).hexdigest()
    ):
        raise ValueError("original argv bytes disagree with captured input identity")

    materialized = bytearray(original_input)
    seen_offsets: set[int] = set()
    mutations = counterfactual.get("mutations")
    if not isinstance(mutations, list) or not mutations:
        raise ValueError("satisfiable counterfactual has no byte mutations")
    for mutation in mutations:
        if not isinstance(mutation, dict) or mutation.get("source_id") != source_id:
            raise ValueError("counterfactual mutation has the wrong source identity")
        offset = mutation.get("source_offset")
        replacement_hex = mutation.get("replacement_hex")
        if (
            not isinstance(offset, int)
            or offset < 0
            or offset >= len(materialized)
            or offset in seen_offsets
        ):
            raise ValueError("counterfactual mutation offset is invalid or duplicated")
        if not isinstance(replacement_hex, str) or not re.fullmatch(
            r"[0-9a-f]{2}", replacement_hex
        ):
            raise ValueError("counterfactual replacement is not one canonical byte")
        seen_offsets.add(offset)
        materialized[offset] = int(replacement_hex, 16)
    materialized_bytes = bytes(materialized)
    validation_arguments = list(original_arguments)
    validation_arguments[argument_position] = os.fsdecode(materialized_bytes)
    operation = candidate.get("static_operation")
    if expected_crash_class is not None:
        if not expected_crash_class or cwd is not None:
            raise ValueError(
                "crash counterfactual validation requires a class and no custom cwd"
            )
        crash_environment = dict(environment or {})
        crash_environment.pop("GLAURUNG_RUNTIME_TRACE_BEGIN", None)
        crash_environment.pop("GLAURUNG_RUNTIME_TRACE_END", None)
        validation_capture = capture_traced_child_core(
            binary,
            validation_arguments,
            environment=crash_environment,
            timeout=timeout,
            public_input=materialized_bytes,
        )
        crash = json.loads(
            runtime_analysis.analyze_process_capsule_crash(
                validation_capture.capsule_json,
                list(validation_capture.payloads),
                binary_bytes,
            )
        )
        observed_edge = None
        crash_report = crash.get("report") if crash.get("outcome") == "crash" else None
        observed_class = (
            crash_report.get("class", {}).get("value")
            if isinstance(crash_report, dict)
            else None
        )
        if observed_class == expected_crash_class:
            status = "validated"
            reason = None
        elif crash.get("outcome") != "crash":
            status = "disproved"
            reason = "materialized input did not produce a crash"
        else:
            status = "disproved"
            reason = "materialized input produced a different crash class"
        validation_kind = "crash_class"
    else:
        validation_capture = capture_instruction_trace_child(
            binary,
            validation_arguments,
            environment=environment,
            cwd=cwd,
            timeout=timeout,
            public_input=materialized_bytes,
        )
        validation_report = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                validation_capture.capsule_json,
                list(validation_capture.payloads),
                binary_bytes,
            )
        )
        validation_matches = [
            observed
            for observed in validation_report.get("solver_query_candidates", [])
            if observed.get("static_operation") == operation
        ]
        if len(validation_matches) != 1:
            status = "unknown"
            reason = (
                "validation capture does not contain one matching branch occurrence"
            )
            observed_edge = None
        else:
            observed_edge = validation_matches[0].get("observed_edge")
            expected_taken = counterfactual.get("predicted_branch_taken")
            expected_target = counterfactual.get("predicted_target_static_va")
            if not isinstance(observed_edge, dict) or (
                observed_edge.get("branch_taken") != expected_taken
                or observed_edge.get("target_static_va") != expected_target
            ):
                status = "disproved"
                reason = "validation capture traversed a different branch edge"
            else:
                status = "validated"
                reason = None
        validation_kind = "observed_branch_edge"
        crash_report = None
    original_capsule = json.loads(original_capsule_json)
    validation_capsule = json.loads(validation_capture.capsule_json)
    relation: dict[str, Any] = {
        "schema": "glaurung-runtime-counterfactual-validation-v1",
        "status": status,
        "validation_kind": validation_kind,
        "original_capture_id": original_capsule["identity"]["capture_id"],
        "validation_capture_id": validation_capsule["identity"]["capture_id"],
        "image_sha256": original_report["image_sha256"],
        "source_id": source_id,
        "source_name": source_name,
        "candidate_sequence": candidate_sequence,
        "mutations": mutations,
        "static_operation": operation,
        "predicted_branch_taken": counterfactual.get("predicted_branch_taken"),
        "predicted_target_static_va": counterfactual.get("predicted_target_static_va"),
        "observed_edge": observed_edge,
    }
    if expected_crash_class is not None:
        relation["expected_crash_class"] = expected_crash_class
        relation["observed_crash_class"] = (
            crash_report.get("class") if isinstance(crash_report, dict) else None
        )
        relation["crash_static_location"] = (
            crash_report.get("static_location")
            if isinstance(crash_report, dict)
            else None
        )
    if reason is not None:
        relation["reason"] = reason
    return CounterfactualValidation(
        validation_json=json.dumps(relation, sort_keys=True, separators=(",", ":")),
        materialized_input=materialized_bytes,
        capture=validation_capture,
    )


def stable_live_capture_projection(capsule_json: str) -> str:
    """Project one validated live capsule onto repeatable, non-volatile facts.

    This W3 projection deliberately excludes process/thread IDs, timestamps,
    raw virtual addresses, register values, page bytes, paths, and provider
    extensions. It is not yet the broader live/core semantic projection.
    """
    canonical = runtime_analysis.canonicalize_process_capsule_json(capsule_json)
    capsule: dict[str, Any] = json.loads(canonical)
    mappings = {item["id"]: item for item in capsule["mappings"]}

    def artifact(item: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: item[key] for key in ("sha256", "byte_len", "build_id") if key in item
        }

    def mapping(item: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "byte_len": item["end"] - item["start"],
            "permissions": item["permissions"],
            "backing": item["backing"],
            **({"file_offset": item["file_offset"]} if "file_offset" in item else {}),
        }

    module_facts: list[dict[str, Any]] = [
        {
            "artifact": artifact(module["artifact"]),
            "mappings": sorted(
                (mapping(mappings[item]) for item in module["mapping_ids"]),
                key=lambda value: json.dumps(value, sort_keys=True),
            ),
        }
        for module in capsule["modules"]
    ]
    module_facts.sort(key=lambda value: str(value["artifact"]["sha256"]))
    projection = {
        "schema": "glaurung-live-capture-stable-facts-v1",
        "target": capsule["target"],
        "executable": artifact(capsule["executable"]),
        "terminal_states": sorted(
            process["terminal"]["kind"] for process in capsule["processes"]
        ),
        "modules": module_facts,
        "unowned_mappings": sorted(
            (mapping(item) for item in capsule["mappings"] if "module_id" not in item),
            key=lambda value: json.dumps(value, sort_keys=True),
        ),
        "threads": sorted(
            (
                sorted(
                    (register["provider_name"], register["bit_width"])
                    for register in thread["registers"]
                )
                for thread in capsule["threads"]
            ),
            key=lambda value: json.dumps(value),
        ),
        "pages": sorted(
            (
                {
                    "byte_len": page["byte_len"],
                    "content_status": page["content"]["status"],
                    "mapping": mapping(mappings[page["mapping_id"]]),
                }
                for page in capsule["pages"]
            ),
            key=lambda value: json.dumps(value, sort_keys=True),
        ),
        "descriptors": sorted(
            (
                {
                    "number": item["number"],
                    "kind": item["kind"],
                    "redacted": item["redacted"],
                }
                for item in capsule["descriptors"]
            ),
            key=lambda value: value["number"],
        ),
        "inputs": sorted(
            capsule["provenance"]["input_bytes"], key=lambda value: value["name"]
        ),
        "completeness": sorted(
            capsule["completeness"], key=lambda value: value["evidence"]
        ),
    }
    return json.dumps(projection, sort_keys=True, separators=(",", ":")) + "\n"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _failure_status(detail: str) -> str:
    lowered = detail.lower()
    if "permission" in lowered or "operation not permitted" in lowered:
        return "denied"
    if "no such" in lowered or "disappear" in lowered or "esrch" in lowered:
        return "disappeared"
    if "partial" in lowered:
        return "partial"
    if "budget" in lowered or "exceed" in lowered:
        return "truncated"
    if "changed" in lowered or "race" in lowered:
        return "raced"
    return "unknown"


def _wait_stopped(pid: int, timeout: float) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        waited, status = os.waitpid(pid, os.WUNTRACED | os.WNOHANG)
        if waited == pid:
            if os.WIFSTOPPED(status):
                return os.WSTOPSIG(status)
            raise RuntimeError(f"child exited before checkpoint: status={status}")
        time.sleep(0.01)
    raise TimeoutError("child did not reach a stopped checkpoint")


def _read_proc_file(pid: int, name: str) -> bytes:
    return Path(f"/proc/{pid}/{name}").read_bytes()


def _thread_ids(pid: int) -> list[int]:
    return sorted(int(item.name) for item in Path(f"/proc/{pid}/task").iterdir())


def _ptrace(request: int, tid: int, data: object = 0) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    result = libc.ptrace(
        ctypes.c_ulong(request),
        ctypes.c_ulong(tid),
        ctypes.c_void_p(),
        data,
    )
    if result == -1:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _wait_ptrace_stop(tid: int, timeout: float) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        waited, status = os.waitpid(tid, os.WNOHANG | _WAIT_ALL)
        if waited == tid:
            if os.WIFSTOPPED(status):
                return os.WSTOPSIG(status)
            raise RuntimeError(f"thread {tid} left before register capture")
        time.sleep(0.005)
    raise TimeoutError(f"thread {tid} did not enter ptrace stop")


def _capture_thread_registers(
    tids: Sequence[int], timeout: float
) -> tuple[dict[int, list[dict[str, object]]], dict[int, str]]:
    captured: dict[int, list[dict[str, object]]] = {}
    failures: dict[int, str] = {}
    for tid in tids:
        attached = False
        try:
            _ptrace(_PTRACE_ATTACH, tid)
            attached = True
            _wait_ptrace_stop(tid, timeout)
            values = _X86_64Registers()
            _ptrace(_PTRACE_GETREGS, tid, ctypes.byref(values))
            captured[tid] = [
                {
                    "provider_name": name,
                    "bit_width": 64,
                    "value_hex": f"{getattr(values, name):016x}",
                }
                for name in _X86_64_REGISTER_NAMES
            ]
        except (OSError, RuntimeError, TimeoutError) as error:
            failures[tid] = f"{type(error).__name__}: {error}"
        finally:
            if attached:
                try:
                    _ptrace(_PTRACE_DETACH, tid)
                except OSError as error:
                    failures[tid] = f"ptrace detach failed: {error}"
                    captured.pop(tid, None)
    return captured, failures


def _process_vm_read(pid: int, start: int, byte_len: int) -> bytes:
    buffer = ctypes.create_string_buffer(byte_len)
    local = _IOVec(ctypes.cast(buffer, ctypes.c_void_p), byte_len)
    remote = _IOVec(ctypes.c_void_p(start), byte_len)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.process_vm_readv.restype = ctypes.c_ssize_t
    result = libc.process_vm_readv(
        ctypes.c_int(pid),
        ctypes.byref(local),
        ctypes.c_ulong(1),
        ctypes.byref(remote),
        ctypes.c_ulong(1),
        ctypes.c_ulong(0),
    )
    if result == -1:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    if result != byte_len:
        raise OSError(
            f"partial process_vm_readv: obtained {result} of {byte_len} bytes"
        )
    return buffer.raw


def _proc_mem_read(pid: int, start: int, byte_len: int) -> bytes:
    descriptor = os.open(f"/proc/{pid}/mem", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        data = os.pread(descriptor, byte_len, start)
    finally:
        os.close(descriptor)
    if len(data) != byte_len:
        raise OSError(
            f"partial /proc memory read: obtained {len(data)} of {byte_len} bytes"
        )
    return data


def _mapping_bounds(mapping: Mapping[str, object]) -> tuple[int, int]:
    start = mapping.get("start")
    end = mapping.get("end")
    if not isinstance(start, int) or not isinstance(end, int):
        raise TypeError("runtime mapping has non-integer bounds")
    return start, end


def _device_inode(device: str, inode: str) -> tuple[int, int, int]:
    major_text, separator, minor_text = device.partition(":")
    if not separator:
        raise ValueError(f"malformed procfs mapping device: {device!r}")
    return int(major_text, 16), int(minor_text, 16), int(inode)


def _read_bounded_file(descriptor: int, byte_len: int) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    while offset < byte_len:
        chunk = os.pread(descriptor, min(1024 * 1024, byte_len - offset), offset)
        if not chunk:
            raise OSError(f"mapped backing ended after {offset} of {byte_len} bytes")
        chunks.append(chunk)
        offset += len(chunk)
    return b"".join(chunks)


def _capture_backing_artifacts(
    pid: int, maps_text: str, executable: Path
) -> tuple[
    dict[tuple[int, int, int], dict[str, object]],
    dict[str, str],
    dict[str, str],
]:
    executable_realpath = executable.resolve(strict=True)
    candidates: dict[tuple[int, int, int], tuple[str, str, str]] = {}
    for line in maps_text.splitlines():
        columns = line.split(maxsplit=5)
        if len(columns) < 6:
            continue
        address, permissions, _offset, device, inode, path = columns
        identity_path = path.removesuffix(" (deleted)")
        if not identity_path or identity_path.startswith("[") or "x" not in permissions:
            continue
        try:
            if Path(identity_path).resolve() == executable_realpath:
                continue
        except OSError:
            pass
        key = _device_inode(device, inode)
        candidates.setdefault(key, (address, path, identity_path))

    artifacts: dict[tuple[int, int, int], dict[str, object]] = {}
    failures: dict[str, str] = {}
    sources: dict[str, str] = {}
    total_bytes = 0
    for index, (key, (address, display_path, identity_path)) in enumerate(
        sorted(candidates.items())
    ):
        failure_key = f"{key[0]:x}:{key[1]:x}:{key[2]}"
        if index >= _MAX_BACKING_ARTIFACTS:
            failures[failure_key] = "backing artifact count budget exceeded"
            continue
        map_file = f"/proc/{pid}/map_files/{address}"
        try:
            descriptor = os.open(map_file, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            source = "procfs map_files handle"
        except OSError as map_file_error:
            try:
                descriptor = os.open(
                    identity_path,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                )
                source = (
                    "observed path with device/inode revalidation after "
                    f"map_files failure: {type(map_file_error).__name__}: "
                    f"{map_file_error}"
                )
            except OSError as path_error:
                failures[failure_key] = (
                    f"map_files: {map_file_error}; revalidated path: {path_error}"
                )
                continue
        try:
            try:
                stat = os.fstat(descriptor)
                observed_key = (
                    os.major(stat.st_dev),
                    os.minor(stat.st_dev),
                    stat.st_ino,
                )
                if observed_key != key:
                    raise OSError(
                        f"map_files identity changed: expected {key}, got {observed_key}"
                    )
                if stat.st_size <= 0:
                    raise OSError("mapped backing has no bounded regular-file length")
                if stat.st_size > _MAX_BACKING_ARTIFACT_BYTES:
                    raise OSError("mapped backing exceeds per-artifact byte budget")
                if total_bytes + stat.st_size > _MAX_TOTAL_BACKING_BYTES:
                    raise OSError("mapped backings exceed aggregate byte budget")
                data = _read_bounded_file(descriptor, stat.st_size)
            finally:
                os.close(descriptor)
        except (OSError, ValueError) as error:
            failures[failure_key] = f"{type(error).__name__}: {error}"
            continue
        sha256 = _sha256(data)
        artifact: dict[str, object] = {
            "sha256": sha256,
            "byte_len": len(data),
            "display_path": display_path,
            "module_id": f"module-file-{index:04d}",
        }
        try:
            build_id = runtime_analysis.elf_executable_build_id(data)
        except ValueError:
            build_id = None
        if build_id is not None:
            artifact["build_id"] = build_id
        artifacts[key] = artifact
        sources[failure_key] = source
        total_bytes += len(data)
    return artifacts, failures, sources


def _capture_selected_pages(
    pid: int,
    process_id: str,
    mappings: Sequence[dict[str, object]],
    registers: Mapping[int, Sequence[dict[str, object]]],
    *,
    allow_proc_mem_fallback: bool,
) -> tuple[
    list[dict[str, object]],
    list[tuple[str, bytes]],
    dict[str, dict[str, str]],
]:
    page_size = os.sysconf("SC_PAGE_SIZE")
    selected: dict[tuple[str, int], tuple[dict[str, object], set[str]]] = {}
    for tid, observations in registers.items():
        values = {
            str(item["provider_name"]): int(str(item["value_hex"]), 16)
            for item in observations
        }
        for role in ("rip", "rsp"):
            address = values[role]
            mapping = next(
                (
                    item
                    for item in mappings
                    if _mapping_bounds(item)[0] <= address < _mapping_bounds(item)[1]
                ),
                None,
            )
            if mapping is None:
                continue
            mapping_start, _ = _mapping_bounds(mapping)
            start = address - (address % page_size)
            start = max(start, mapping_start)
            key = (str(mapping["id"]), start)
            if key not in selected:
                selected[key] = (mapping, set())
            selected[key][1].add(f"thread-{tid}:{role}")

    for mapping in mappings:
        permissions = mapping.get("permissions")
        if mapping.get("module_id") != "module-main" or not isinstance(
            permissions, dict
        ):
            continue
        if not permissions.get("execute"):
            continue
        mapping_start, mapping_end = _mapping_bounds(mapping)
        start = mapping_start
        while start < mapping_end and len(selected) < _MAX_SELECTED_PAGES:
            key = (str(mapping["id"]), start)
            if key not in selected:
                selected[key] = (mapping, {"main-module-executable"})
            start += page_size

    pages: list[dict[str, object]] = []
    payloads: list[tuple[str, bytes]] = []
    reads: dict[str, dict[str, str]] = {}
    for (mapping_id, start), (mapping, roles) in sorted(selected.items()):
        _, mapping_end = _mapping_bounds(mapping)
        byte_len = min(page_size, mapping_end - start)
        payload_id = f"live-page-{start:016x}"
        permissions = mapping["permissions"]
        assert isinstance(permissions, dict)
        detail = ",".join(sorted(roles))
        if not permissions["read"]:
            content: dict[str, object] = {
                "status": "omitted",
                "reason": "permission_denied",
                "detail": f"selected for {detail}; mapping is not readable",
            }
            reads[payload_id] = {"status": "denied", "source": "mapping permissions"}
        else:
            source = "process_vm_readv"
            try:
                data = _process_vm_read(pid, start, byte_len)
            except OSError as primary_error:
                if not allow_proc_mem_fallback:
                    content = {
                        "status": "omitted",
                        "reason": "unreadable",
                        "detail": f"{source}: {primary_error}",
                    }
                    reads[payload_id] = {
                        "status": _failure_status(str(primary_error)),
                        "source": source,
                        "detail": str(primary_error),
                    }
                else:
                    source = "/proc/<pid>/mem explicit fallback"
                    try:
                        data = _proc_mem_read(pid, start, byte_len)
                    except OSError as fallback_error:
                        content = {
                            "status": "omitted",
                            "reason": "unreadable",
                            "detail": (
                                f"process_vm_readv: {primary_error}; "
                                f"fallback: {fallback_error}"
                            ),
                        }
                        combined_error = (
                            f"process_vm_readv: {primary_error}; "
                            f"fallback: {fallback_error}"
                        )
                        reads[payload_id] = {
                            "status": _failure_status(combined_error),
                            "source": source,
                            "detail": combined_error,
                        }
                    else:
                        payloads.append((payload_id, data))
                        content = {
                            "status": "captured",
                            "payload": {
                                "id": payload_id,
                                "sha256": _sha256(data),
                                "byte_len": len(data),
                                "sensitivity": "sensitive",
                            },
                        }
                        reads[payload_id] = {"status": "captured", "source": source}
            else:
                payloads.append((payload_id, data))
                content = {
                    "status": "captured",
                    "payload": {
                        "id": payload_id,
                        "sha256": _sha256(data),
                        "byte_len": len(data),
                        "sensitivity": "sensitive",
                    },
                }
                reads[payload_id] = {"status": "captured", "source": source}
        pages.append(
            {
                "process_id": process_id,
                "mapping_id": mapping_id,
                "start": start,
                "byte_len": byte_len,
                "content": content,
            }
        )
    return pages, payloads, reads


def _parse_maps(
    data: str,
    *,
    process_id: str,
    executable: Path,
    executable_sha256: str,
    backing_artifacts: Mapping[tuple[int, int, int], Mapping[str, object]],
) -> tuple[list[dict[str, object]], list[str]]:
    mappings: list[dict[str, object]] = []
    executable_mapping_ids: list[str] = []
    executable_realpath = executable.resolve(strict=True)
    for index, line in enumerate(data.splitlines()):
        columns = line.split(maxsplit=5)
        if len(columns) < 5:
            raise ValueError(f"malformed /proc maps line: {line!r}")
        address, permissions, offset, device, inode = columns[:5]
        path = columns[5] if len(columns) == 6 else ""
        start_text, separator, end_text = address.partition("-")
        if not separator:
            raise ValueError(f"malformed /proc maps range: {address!r}")
        mapping_id = f"mapping-{index:06d}"
        deleted = path.endswith(" (deleted)")
        identity_path = path.removesuffix(" (deleted)")
        is_executable = False
        if identity_path and not identity_path.startswith("["):
            try:
                is_executable = Path(identity_path).resolve() == executable_realpath
            except OSError:
                pass
        if is_executable:
            backing: dict[str, object] = {
                "kind": "file",
                "artifact_sha256": executable_sha256,
                "deleted": deleted,
            }
            executable_mapping_ids.append(mapping_id)
            module_id: str | None = "module-main"
            file_offset: int | None = int(offset, 16)
        elif path and not path.startswith("["):
            artifact = backing_artifacts.get(_device_inode(device, inode))
            if artifact is not None:
                artifact_sha256 = artifact.get("sha256")
                captured_module_id = artifact.get("module_id")
                if not isinstance(artifact_sha256, str) or not isinstance(
                    captured_module_id, str
                ):
                    raise TypeError("captured backing identity is malformed")
                backing = {
                    "kind": "file",
                    "artifact_sha256": artifact_sha256,
                    "deleted": deleted,
                }
                module_id = captured_module_id
                file_offset = int(offset, 16)
            else:
                backing = {
                    "kind": "unknown",
                    "reason": "path observed but backing identity was not captured",
                }
                module_id = None
                file_offset = None
        elif path.startswith("[") and path.endswith("]"):
            backing = {"kind": "special", "name": path}
            module_id = None
            file_offset = None
        else:
            backing = {"kind": "anonymous"}
            module_id = None
            file_offset = None
        mapping: dict[str, object] = {
            "id": mapping_id,
            "process_id": process_id,
            "start": int(start_text, 16),
            "end": int(end_text, 16),
            "permissions": {
                "read": permissions[0] == "r",
                "write": permissions[1] == "w",
                "execute": permissions[2] == "x",
                "private": permissions[3] == "p",
            },
            "backing": backing,
        }
        if module_id is not None:
            mapping["module_id"] = module_id
        if file_offset is not None:
            mapping["file_offset"] = file_offset
        mappings.append(mapping)
    return mappings, executable_mapping_ids


def _descriptor_records(
    pid: int, process_id: str, public_paths: Sequence[str] = ()
) -> tuple[list[dict[str, object]], bool]:
    entries = sorted(Path(f"/proc/{pid}/fd").iterdir(), key=lambda item: int(item.name))
    truncated = len(entries) > _MAX_DESCRIPTORS
    authorized = set(public_paths)
    records: list[dict[str, object]] = []
    for entry in entries[:_MAX_DESCRIPTORS]:
        record: dict[str, object] = {
            "process_id": process_id,
            "number": int(entry.name),
            "kind": "unknown",
            "redacted": True,
        }
        try:
            target = os.readlink(entry)
        except OSError:
            target = None
        if target in authorized:
            record.update(target=target, redacted=False)
        records.append(record)
    return (
        records,
        truncated,
    )


def _terminate_owned_group(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("owned child process group did not terminate") from error


def _wait_for_traced_checkpoint_child(
    tracer_pid: int,
    executable: Path,
    trace_path: Path,
    stop_count: int,
    timeout: float,
) -> int:
    """Return the tracer-owned executable child at its cooperative stop."""
    deadline = time.monotonic() + timeout
    children_path = Path(f"/proc/{tracer_pid}/task/{tracer_pid}/children")
    executable = executable.resolve(strict=True)
    while time.monotonic() < deadline:
        try:
            child_pids = [int(value) for value in children_path.read_text().split()]
        except (FileNotFoundError, ProcessLookupError):
            child_pids = []
        for child_pid in child_pids:
            try:
                if Path(f"/proc/{child_pid}/exe").resolve(strict=True) != executable:
                    continue
                status = Path(f"/proc/{child_pid}/status").read_text()
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            state = next(
                (
                    line.split(":", 1)[1].strip()
                    for line in status.splitlines()
                    if line.startswith("State:")
                ),
                "",
            )
            try:
                trace_tail = _bounded_file(
                    trace_path, _MAX_TRACE_BYTES, "mapping trace"
                ).decode("utf-8", errors="strict")
            except FileNotFoundError:
                trace_tail = ""
            if (
                state[:1] in {"T", "t"}
                and trace_tail.count("stopped by SIGSTOP") >= stop_count
            ):
                return child_pid
        time.sleep(0.005)
    raise TimeoutError("mapping-traced child did not reach its cooperative checkpoint")


def _checkpoint_stack_state(
    child_pid: int,
) -> tuple[str, _CheckpointMapping, int, int, bytes]:
    """Capture ordinary mapping, RIP/RSP, and bounded stack evidence."""
    maps_text = _read_proc_file(child_pid, "maps").decode(errors="strict")
    stack_mapping: _CheckpointMapping | None = None
    for line in maps_text.splitlines():
        columns = line.split(maxsplit=5)
        if len(columns) != 6 or columns[5] != "[stack]":
            continue
        start_text, end_text = columns[0].split("-", 1)
        stack_mapping = _CheckpointMapping(
            start=int(start_text, 16),
            end=int(end_text, 16),
            permissions_text=columns[1],
        )
        break
    if stack_mapping is None:
        raise RuntimeError("checkpoint has no provider-identified stack mapping")
    syscall_fields = _read_proc_file(child_pid, "syscall").decode().split()
    if len(syscall_fields) < 3:
        raise RuntimeError(
            "checkpoint syscall state has no stack and instruction pointers"
        )
    try:
        stack_pointer = int(syscall_fields[-2], 0)
        instruction_pointer = int(syscall_fields[-1], 0)
    except ValueError as error:
        raise RuntimeError("checkpoint syscall pointers are malformed") from error
    if not stack_mapping.start <= stack_pointer < stack_mapping.end:
        raise RuntimeError("checkpoint stack pointer is outside the stack mapping")
    stack_byte_len = stack_mapping.end - stack_pointer
    if stack_byte_len > _MAX_CHECKPOINT_STACK_BYTES:
        raise RuntimeError("checkpoint stack extent exceeds acquisition budget")
    stack_bytes = _process_vm_read(child_pid, stack_pointer, stack_byte_len)
    return (
        maps_text,
        stack_mapping,
        instruction_pointer,
        stack_pointer,
        stack_bytes,
    )


def _checkpoint_read_snapshot(
    child_pid: int,
    trace_path: Path,
    before_stack_pointer: int,
    before_stack_bytes: bytes,
    timeout: float,
) -> _ReadCheckpoint:
    """Capture the completed raw read and its same-execution after state."""
    (
        maps_text,
        stack_mapping,
        instruction_pointer,
        stack_pointer,
        stack_bytes,
    ) = _checkpoint_stack_state(child_pid)

    deadline = time.monotonic() + timeout
    readhex = re.compile(
        r"readhex\(\d+,\s*(?P<destination>0x[0-9a-fA-F]+),\s*"
        r"\d+,\s*(?P<content>[0-9a-fA-F]*)\)\s*=\s*(?P<result>\d+)"
    )
    while time.monotonic() < deadline:
        try:
            trace = _bounded_file(trace_path, _MAX_TRACE_BYTES, "mapping trace").decode(
                "utf-8", errors="strict"
            )
            normalized = _normalize_raw_reads(trace)
        except FileNotFoundError:
            time.sleep(0.005)
            continue
        candidates: list[tuple[int, bytes]] = []
        for matched in readhex.finditer(normalized):
            destination = int(matched.group("destination"), 16)
            content = bytes.fromhex(matched.group("content"))
            result = int(matched.group("result"))
            end = destination + result
            if (
                result > 0
                and len(content) == result
                and stack_mapping.start <= destination
                and end <= stack_mapping.end
            ):
                candidates.append((destination, content))
        if candidates:
            destination, expected = candidates[-1]
            observed = _process_vm_read(child_pid, destination, len(expected))
            if observed != expected:
                raise RuntimeError("checkpoint memory disagrees with traced read bytes")
            return _ReadCheckpoint(
                child_pid=child_pid,
                maps_text=maps_text,
                stack_mapping=stack_mapping,
                instruction_pointer=instruction_pointer,
                stack_pointer=stack_pointer,
                stack_bytes=stack_bytes,
                before_stack_pointer=before_stack_pointer,
                before_stack_bytes=before_stack_bytes,
                destination=destination,
                read_bytes=observed,
            )
        time.sleep(0.005)
    raise TimeoutError("checkpoint trace has no completed stack-destination read")


def _bounded_file(path: Path, limit: int, label: str) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise RuntimeError(f"{label} exceeds {limit}-byte acquisition budget")
    return path.read_bytes()


def _trace_permissions(text: str) -> str:
    if text == "PROT_NONE":
        return "none"
    permissions = [
        name
        for flag, name in (
            ("PROT_READ", "read"),
            ("PROT_WRITE", "write"),
            ("PROT_EXEC", "execute"),
        )
        if flag in text.split("|")
    ]
    return "|".join(permissions)


def _trace_ioctl_request(text: str) -> int | None:
    """Recover a Linux x86-64 ioctl request from strace's bounded spelling."""
    text = text.strip()
    if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", text):
        value = int(text, 0)
        return value if 0 <= value <= 0xFFFFFFFF else None
    decoded = re.fullmatch(
        r"_IOC\((?P<direction>[^,]+),\s*(?P<type>0x[0-9a-fA-F]+|\d+),"
        r"\s*(?P<number>0x[0-9a-fA-F]+|\d+),"
        r"\s*(?P<size>0x[0-9a-fA-F]+|\d+)\)",
        text,
    )
    if decoded is None:
        return None
    direction_flags = {
        "_IOC_NONE": 0,
        "_IOC_WRITE": 1,
        "_IOC_READ": 2,
    }
    direction = 0
    for flag in decoded.group("direction").split("|"):
        value = direction_flags.get(flag.strip())
        if value is None:
            return None
        direction |= value
    ioctl_type = int(decoded.group("type"), 0)
    number = int(decoded.group("number"), 0)
    size = int(decoded.group("size"), 0)
    if direction > 3 or ioctl_type > 0xFF or number > 0xFF or size > 0x3FFF:
        return None
    return (direction << 30) | (size << 16) | (ioctl_type << 8) | number


def _normalize_raw_reads(trace: str) -> str:
    """Turn raw reads plus strace hex dumps into one parseable line."""
    lines = trace.splitlines()
    normalized: list[str] = []
    raw_read = re.compile(
        r"^(?P<prefix>(?:\[pid\s+)?\d+(?:\])?\s+)"
        r"read\((?P<descriptor>0x[0-9a-fA-F]+|\d+),\s*"
        r"(?P<destination>0x[0-9a-fA-F]+),\s*"
        r"(?P<requested>0x[0-9a-fA-F]+|\d+)\)\s+=\s+"
        r"(?P<result>0x[0-9a-fA-F]+|-?\d+)$"
    )
    index = 0
    while index < len(lines):
        matched = raw_read.fullmatch(lines[index])
        if matched is None:
            normalized.append(lines[index])
            index += 1
            continue
        result = int(matched.group("result"), 0)
        cursor = index + 1
        dumped = bytearray()
        while cursor < len(lines) and lines[cursor].startswith(" |"):
            fields = lines[cursor].split("|", 2)
            if len(fields) >= 2:
                dumped.extend(
                    int(value, 16)
                    for value in re.findall(
                        r"(?<![0-9a-fA-F])[0-9a-fA-F]{2}(?![0-9a-fA-F])", fields[1]
                    )
                )
            cursor += 1
        descriptor = int(matched.group("descriptor"), 0)
        if result > 0 and not dumped and descriptor != 0:
            normalized.append(lines[index])
            index += 1
            continue
        if result > 0 and len(dumped) != result:
            raise ValueError("read byte dump is missing, truncated, or oversized")
        effect = bytes(dumped[: max(result, 0)])
        normalized.append(
            f"{matched.group('prefix')}readhex({descriptor}, "
            f"{matched.group('destination')}, "
            f"{int(matched.group('requested'), 0)}, {effect.hex()}) = {result}"
        )
        index = cursor
    return "\n".join(normalized)


def _normalize_stdin_raw_reads(trace: str) -> str:
    """Compatibility wrapper for the first descriptor-zero raw-read gate."""
    return _normalize_raw_reads(trace)


def _parse_os_trace(
    trace: str,
    capsule: Mapping[str, Any],
    *,
    public_paths: Sequence[str] = (),
    public_content_paths: Sequence[str] = (),
    public_ipc_content: bool = False,
    stdin_provider: str = "dev_null",
    public_stdin_content: bool = False,
) -> list[dict[str, object]]:
    """Normalize the bounded strace scope into provider-neutral events."""
    processes = capsule.get("processes")
    threads = capsule.get("threads")
    if not isinstance(processes, list) or len(processes) != 1:
        raise ValueError("traced capsule must contain exactly one process")
    if not isinstance(threads, list):
        raise ValueError("traced capsule threads are malformed")
    process_id = str(processes[0]["id"])
    thread_ids = {
        int(thread["os_tid"]): str(thread["id"])
        for thread in threads
        if isinstance(thread, dict) and isinstance(thread.get("os_tid"), int)
    }
    prefix = re.compile(r"^(?:\[pid\s+)?(?P<tid>\d+)(?:\])?\s+")
    events: list[dict[str, object]] = []
    sequences: dict[str | None, int] = {}
    open_resources: dict[int, dict[str, object]] = {}
    ipc_resources: dict[int, dict[str, object]] = {}
    resource_offsets: dict[str, int] = {}
    public_content_hashes = {
        _sha256(os.fsencode(path)) for path in public_content_paths
    }
    executable = capsule.get("executable")
    executable_path = (
        str(executable.get("display_path"))
        if isinstance(executable, dict) and executable.get("display_path") is not None
        else None
    )
    executable_sha256 = (
        str(executable.get("sha256")) if isinstance(executable, dict) else None
    )
    for line in trace.splitlines():
        stack_frame = re.fullmatch(
            r" > (?P<path>.+?)\((?P<symbol>[^()]*)\) "
            r"\[(?P<module_offset>0x[0-9a-fA-F]+)\]",
            line,
        )
        if stack_frame is not None:
            if (
                events
                and executable_path is not None
                and stack_frame.group("path") == executable_path
            ):
                fields = events[-1].get("fields")
                if (
                    isinstance(fields, dict)
                    and "user_return_module_offset" not in fields
                ):
                    fields["user_return_module_offset"] = str(
                        int(stack_frame.group("module_offset"), 16)
                    )
                    fields["user_frame_artifact_sha256"] = executable_sha256 or ""
                    fields["provider_user_frame_symbol"] = stack_frame.group("symbol")
            continue
        match = prefix.match(line)
        os_tid: int | None = None
        if match is not None:
            os_tid = int(match.group("tid"))
            line = line[match.end() :]
        thread_id = thread_ids.get(os_tid) if os_tid is not None else None
        if thread_id is None and len(thread_ids) == 1:
            thread_id = next(iter(thread_ids.values()))

        event: dict[str, object] | None = None
        mmap = re.fullmatch(r"mmap\((.*)\)\s+=\s+(0x[0-9a-f]+)", line)
        if mmap is not None:
            arguments = [item.strip() for item in mmap.group(1).split(",", 5)]
            if len(arguments) == 6:
                event = {
                    "kind": "mapping_create",
                    "address": int(mmap.group(2), 16),
                    "fields": {
                        "length": str(int(arguments[1], 0)),
                        "permissions": _trace_permissions(arguments[2]),
                        "flags": arguments[3],
                        "result": "success",
                        "provider_syscall": "mmap",
                    },
                }
        protect = re.fullmatch(
            r"mprotect\((0x[0-9a-f]+),\s*(\d+),\s*([^)]*)\)\s+=\s+0", line
        )
        if protect is not None:
            event = {
                "kind": "mapping_protect",
                "address": int(protect.group(1), 16),
                "fields": {
                    "length": protect.group(2),
                    "permissions": _trace_permissions(protect.group(3)),
                    "result": "success",
                    "provider_syscall": "mprotect",
                },
            }
        unmap = re.fullmatch(r"munmap\((0x[0-9a-f]+),\s*(\d+)\)\s+=\s+0", line)
        if unmap is not None:
            event = {
                "kind": "mapping_remove",
                "address": int(unmap.group(1), 16),
                "fields": {
                    "length": unmap.group(2),
                    "result": "success",
                    "provider_syscall": "munmap",
                },
            }
        recognized_thread_create = False
        process_create = re.fullmatch(
            r"(?P<syscall>fork|vfork)\(\)\s+=\s+(?P<result>-?\d+)"
            r"(?:\s+(?P<errno>[A-Z][A-Z0-9_]+)\s+.*)?",
            line,
        )
        if process_create is None:
            process_create = re.fullmatch(
                r"(?P<syscall>clone|clone3)\((?P<arguments>.*)\)\s+=\s+"
                r"(?P<result>-?\d+)"
                r"(?:\s+(?P<errno>[A-Z][A-Z0-9_]+)\s+.*)?",
                line,
            )
        if process_create is not None:
            syscall = process_create.group("syscall")
            arguments = process_create.groupdict().get("arguments") or ""
            is_process = syscall in {"fork", "vfork"} or (
                "SIGCHLD" in arguments and "CLONE_THREAD" not in arguments
            )
            if is_process:
                result = int(process_create.group("result"))
                fields = {
                    "caller_os_tid": str(os_tid or processes[0].get("os_pid", 0)),
                    "provider_syscall": syscall,
                    "result": "success" if result >= 0 else "failure",
                }
                if result >= 0:
                    fields["child_os_pid"] = str(result)
                elif process_create.group("errno") is not None:
                    fields["errno"] = process_create.group("errno")
                event = {"kind": "process_create", "fields": fields}
            else:
                recognized_thread_create = True
        waited = re.fullmatch(
            r"wait4\((?P<requested_pid>-?\d+),\s*.*\)\s+=\s+"
            r"(?P<result>-?\d+)"
            r"(?:\s+(?P<errno>[A-Z][A-Z0-9_]+)\s+.*)?",
            line,
        )
        if waited is not None:
            result = int(waited.group("result"))
            fields = {
                "requested_pid": waited.group("requested_pid"),
                "provider_syscall": "wait4",
                "result": "success" if result >= 0 else "failure",
            }
            if result >= 0:
                fields["reaped_os_pid"] = str(result)
            elif waited.group("errno") is not None:
                fields["errno"] = waited.group("errno")
            event = {"kind": "process_wait", "fields": fields}
        stated = re.fullmatch(
            r'newfstatat\((?P<dirfd>[^,]+),\s*(?P<path>"(?:\\.|[^"\\])*")'
            r",\s*(?P<stat>.*),\s*(?P<flags>[^,)]*)\)\s+=\s+(?P<result>-?\d+)"
            r"(?:\s+(?P<errno>[A-Z][A-Z0-9_]+)\s+.*)?",
            line,
        )
        if stated is not None:
            try:
                path = ast.literal_eval(stated.group("path"))
            except (SyntaxError, ValueError):
                path = None
            if isinstance(path, str):
                path_bytes = os.fsencode(path)
                result = int(stated.group("result"))
                fields = {
                    "dirfd": stated.group("dirfd").strip(),
                    "flags": stated.group("flags").strip(),
                    "path_sha256": _sha256(path_bytes),
                    "path_byte_len": str(len(path_bytes)),
                    "path_redacted": str(path not in public_paths).lower(),
                    "result": "success" if result >= 0 else "failure",
                }
                if path in public_paths:
                    fields["path"] = path
                if result >= 0:
                    file_types = {
                        "S_IFREG": "regular_file",
                        "S_IFDIR": "directory",
                        "S_IFCHR": "character_device",
                        "S_IFBLK": "block_device",
                        "S_IFIFO": "fifo",
                        "S_IFSOCK": "socket",
                        "S_IFLNK": "symbolic_link",
                    }
                    mode_match = re.search(
                        r"st_mode=(S_IF[A-Z]+)", stated.group("stat")
                    )
                    if mode_match is not None and mode_match.group(1) in file_types:
                        fields["file_type"] = file_types[mode_match.group(1)]
                elif stated.group("errno") is not None:
                    fields["errno"] = stated.group("errno")
                event = {"kind": "file_stat", "fields": fields}
        changed_mode = re.fullmatch(
            r'chmod\((?P<path>"(?:\\.|[^"\\])*")\s*,\s*(?P<mode>[^)]*)\)'
            r"\s+=\s+(?P<result>-?\d+)"
            r"(?:\s+(?P<errno>[A-Z][A-Z0-9_]+)\s+.*)?",
            line,
        )
        if changed_mode is not None:
            try:
                path = ast.literal_eval(changed_mode.group("path"))
            except (SyntaxError, ValueError):
                path = None
            if isinstance(path, str):
                path_bytes = os.fsencode(path)
                result = int(changed_mode.group("result"))
                fields = {
                    "mode": changed_mode.group("mode").strip(),
                    "path_sha256": _sha256(path_bytes),
                    "path_byte_len": str(len(path_bytes)),
                    "path_redacted": str(path not in public_paths).lower(),
                    "result": "success" if result >= 0 else "failure",
                }
                if path in public_paths:
                    fields["path"] = path
                if result < 0 and changed_mode.group("errno") is not None:
                    fields["errno"] = changed_mode.group("errno")
                event = {"kind": "file_chmod", "fields": fields}
        opened = re.fullmatch(
            r'openat\((?P<dirfd>[^,]+),\s*(?P<path>"(?:\\.|[^"\\])*")'
            r",\s*(?P<flags>[^,)]*)"
            r"(?:,\s*(?P<mode>[^)]*))?\)\s+=\s+(?P<result>-?\d+)"
            r"(?:\s+(?P<errno>[A-Z][A-Z0-9_]+)\s+.*)?",
            line,
        )
        if opened is not None:
            try:
                path = ast.literal_eval(opened.group("path"))
            except (SyntaxError, ValueError):
                path = None
            if isinstance(path, str):
                path_bytes = os.fsencode(path)
                result = int(opened.group("result"))
                fields = {
                    "dirfd": opened.group("dirfd"),
                    "flags": opened.group("flags").strip(),
                    "path_sha256": _sha256(path_bytes),
                    "path_byte_len": str(len(path_bytes)),
                    "path_redacted": str(path not in public_paths).lower(),
                    "result": "success" if result >= 0 else "failure",
                }
                if opened.group("mode") is not None:
                    fields["mode"] = opened.group("mode").strip()
                if path in public_paths:
                    fields["path"] = path
                if result >= 0:
                    fields["descriptor"] = str(result)
                elif opened.group("errno") is not None:
                    fields["errno"] = opened.group("errno")
                event = {"kind": "file_open", "fields": fields}
        pipe_created = re.fullmatch(
            r"pipe2\(\[(?P<read_descriptor>\d+),\s*(?P<write_descriptor>\d+)\],"
            r"\s*(?P<flags>[^)]*)\)\s+=\s+0",
            line,
        )
        if pipe_created is not None:
            event = {
                "kind": "descriptor_pipe_create",
                "fields": {
                    "read_descriptor": pipe_created.group("read_descriptor"),
                    "write_descriptor": pipe_created.group("write_descriptor"),
                    "flags": pipe_created.group("flags").strip(),
                    "result": "success",
                },
            }
        socketpair_created = re.fullmatch(
            r"socketpair\((?P<domain>[^,]+),\s*(?P<socket_type>[^,]+),"
            r"\s*(?P<protocol>[^,]+),\s*\[(?P<first_descriptor>\d+),"
            r"\s*(?P<second_descriptor>\d+)\]\)\s+=\s+0",
            line,
        )
        if socketpair_created is not None:
            event = {
                "kind": "descriptor_socketpair_create",
                "fields": {
                    "domain": socketpair_created.group("domain").strip(),
                    "socket_type": socketpair_created.group("socket_type").strip(),
                    "protocol": socketpair_created.group("protocol").strip(),
                    "first_descriptor": socketpair_created.group("first_descriptor"),
                    "second_descriptor": socketpair_created.group("second_descriptor"),
                    "result": "success",
                },
            }
        socket_created = re.fullmatch(
            r"socket\((?P<domain>[^,]+),\s*(?P<socket_type>[^,]+),"
            r"\s*(?P<protocol>[^)]+)\)\s+=\s+(?P<result>-?\d+)"
            r"(?:\s+(?P<errno>[A-Z][A-Z0-9_]+)\s+.*)?",
            line,
        )
        if socket_created is not None:
            result = int(socket_created.group("result"))
            fields = {
                "domain": socket_created.group("domain").strip(),
                "socket_type": socket_created.group("socket_type").strip(),
                "protocol": socket_created.group("protocol").strip(),
                "result": "success" if result >= 0 else "failure",
            }
            if result >= 0:
                fields["descriptor"] = str(result)
            elif socket_created.group("errno") is not None:
                fields["errno"] = socket_created.group("errno")
            event = {"kind": "descriptor_socket_create", "fields": fields}
        bound = re.fullmatch(
            r"bind\((?P<descriptor>\d+),\s*\{sa_family=AF_INET,"
            r"\s*sin_port=htons\((?P<port>\d+)\),"
            r'\s*sin_addr=inet_addr\("(?P<address>[0-9.]+)"\)\},'
            r"\s*(?P<address_len>\d+)\)\s+=\s+(?P<result>-?\d+)"
            r"(?:\s+(?P<errno>[A-Z][A-Z0-9_]+)\s+.*)?",
            line,
        )
        if bound is not None:
            descriptor = int(bound.group("descriptor"))
            ipc_resource = ipc_resources.get(descriptor)
            if ipc_resource is not None:
                result = int(bound.group("result"))
                fields = {
                    "descriptor": str(descriptor),
                    "resource_id": str(ipc_resource["resource_id"]),
                    "endpoint": str(ipc_resource["endpoint"]),
                    "address": bound.group("address"),
                    "port": bound.group("port"),
                    "address_byte_len": bound.group("address_len"),
                    "result": "success" if result >= 0 else "failure",
                }
                if result < 0 and bound.group("errno") is not None:
                    fields["errno"] = bound.group("errno")
                event = {"kind": "descriptor_bind", "fields": fields}
        listened = re.fullmatch(
            r"listen\((?P<descriptor>\d+),\s*(?P<backlog>-?\d+)\)"
            r"\s+=\s+(?P<result>-?\d+)"
            r"(?:\s+(?P<errno>[A-Z][A-Z0-9_]+)\s+.*)?",
            line,
        )
        if listened is not None:
            descriptor = int(listened.group("descriptor"))
            ipc_resource = ipc_resources.get(descriptor)
            if ipc_resource is not None:
                result = int(listened.group("result"))
                fields = {
                    "descriptor": str(descriptor),
                    "resource_id": str(ipc_resource["resource_id"]),
                    "endpoint": str(ipc_resource["endpoint"]),
                    "backlog": listened.group("backlog"),
                    "result": "success" if result >= 0 else "failure",
                }
                if result < 0 and listened.group("errno") is not None:
                    fields["errno"] = listened.group("errno")
                event = {"kind": "descriptor_listen", "fields": fields}
        sent = re.fullmatch(
            r'sendto\((?P<descriptor>\d+),\s*(?P<data>"(?:\\.|[^"\\])*")'
            r",\s*(?P<requested>\d+),\s*(?P<flags>[^,]+),\s*NULL,\s*0\)"
            r"\s+=\s+(?P<result>-?\d+)"
            r"(?:\s+(?P<errno>[A-Z][A-Z0-9_]+)\s+.*)?",
            line,
        )
        if sent is not None:
            descriptor = int(sent.group("descriptor"))
            ipc_resource = ipc_resources.get(descriptor)
            try:
                data = ast.literal_eval(sent.group("data"))
            except (SyntaxError, ValueError):
                data = None
            if ipc_resource is not None and isinstance(data, str):
                data_bytes = os.fsencode(data)
                result = int(sent.group("result"))
                effect = data_bytes[:result] if result >= 0 else b""
                fields = {
                    "descriptor": str(descriptor),
                    "resource_id": str(ipc_resource["resource_id"]),
                    "endpoint": str(ipc_resource["endpoint"]),
                    "requested_byte_len": sent.group("requested"),
                    "flags": sent.group("flags").strip(),
                    "content_sha256": _sha256(effect),
                    "content_byte_len": str(len(effect)),
                    "content_redacted": str(not public_ipc_content).lower(),
                    "result": "success" if result >= 0 else "failure",
                }
                if public_ipc_content:
                    fields["content_hex"] = effect.hex()
                if result >= 0:
                    fields["sent_byte_len"] = str(result)
                elif sent.group("errno") is not None:
                    fields["errno"] = sent.group("errno")
                event = {"kind": "descriptor_send", "fields": fields}
        received = re.fullmatch(
            r'recvfrom\((?P<descriptor>\d+),\s*(?P<data>"(?:\\.|[^"\\])*")'
            r",\s*(?P<requested>\d+),\s*(?P<flags>[^,]+),\s*NULL,\s*NULL\)"
            r"\s+=\s+(?P<result>-?\d+)"
            r"(?:\s+(?P<errno>[A-Z][A-Z0-9_]+)\s+.*)?",
            line,
        )
        if received is not None:
            descriptor = int(received.group("descriptor"))
            ipc_resource = ipc_resources.get(descriptor)
            try:
                data = ast.literal_eval(received.group("data"))
            except (SyntaxError, ValueError):
                data = None
            if ipc_resource is not None and isinstance(data, str):
                data_bytes = os.fsencode(data)
                result = int(received.group("result"))
                effect = data_bytes[:result] if result >= 0 else b""
                fields = {
                    "descriptor": str(descriptor),
                    "resource_id": str(ipc_resource["resource_id"]),
                    "endpoint": str(ipc_resource["endpoint"]),
                    "requested_byte_len": received.group("requested"),
                    "flags": received.group("flags").strip(),
                    "content_sha256": _sha256(effect),
                    "content_byte_len": str(len(effect)),
                    "content_redacted": str(not public_ipc_content).lower(),
                    "result": "success" if result >= 0 else "failure",
                }
                if public_ipc_content:
                    fields["content_hex"] = effect.hex()
                if result >= 0:
                    fields["received_byte_len"] = str(result)
                elif received.group("errno") is not None:
                    fields["errno"] = received.group("errno")
                event = {"kind": "descriptor_recv", "fields": fields}
        read = re.fullmatch(
            r'read\((?P<descriptor>\d+),\s*(?P<data>"(?:\\.|[^"\\])*")'
            r",\s*(?P<requested>\d+)\)\s+=\s+(?P<result>-?\d+)"
            r"(?:\s+(?P<errno>[A-Z][A-Z0-9_]+)\s+.*)?",
            line,
        )
        raw_read = re.fullmatch(
            r"readhex\((?P<descriptor>\d+),\s*"
            r"(?P<destination>0x[0-9a-fA-F]+),\s*"
            r"(?P<requested>\d+),\s*(?P<content_hex>[0-9a-fA-F]*)\)\s+=\s+"
            r"(?P<result>-?\d+)",
            line,
        )
        if raw_read is not None:
            descriptor = int(raw_read.group("descriptor"))
            result = int(raw_read.group("result"))
            effect = bytes.fromhex(raw_read.group("content_hex"))
            destination = str(int(raw_read.group("destination"), 16))
            resource = open_resources.get(descriptor)
            ipc_resource = ipc_resources.get(descriptor)
            if descriptor == 0:
                fields = {
                    "descriptor": "0",
                    "resource_id": f"standard-input:{process_id}",
                    "endpoint": "stdin",
                    "provider": stdin_provider,
                    "destination_address": destination,
                    "requested_byte_len": raw_read.group("requested"),
                    "content_sha256": _sha256(effect),
                    "content_byte_len": str(len(effect)),
                    "content_redacted": str(not public_stdin_content).lower(),
                    "result": "success" if result >= 0 else "failure",
                }
                if public_stdin_content:
                    fields["content_hex"] = effect.hex()
                if result >= 0:
                    fields["read_byte_len"] = str(result)
                event = {"kind": "descriptor_stdin_read", "fields": fields}
            elif resource is not None and resource["content_public"] is True:
                resource_id = str(resource["resource_id"])
                offset = resource_offsets.get(resource_id)
                if offset is None:
                    raise ValueError("tracked file resource offset is missing")
                fields = {
                    "descriptor": str(descriptor),
                    "resource_id": resource_id,
                    "offset": str(offset),
                    "destination_address": destination,
                    "requested_byte_len": raw_read.group("requested"),
                    "content_sha256": _sha256(effect),
                    "content_byte_len": str(len(effect)),
                    "content_hex": effect.hex(),
                    "content_redacted": "false",
                    "result": "success" if result >= 0 else "failure",
                }
                if result >= 0:
                    fields["read_byte_len"] = str(result)
                    resource_offsets[resource_id] = offset + result
                event = {"kind": "file_read", "fields": fields}
            elif ipc_resource is not None:
                fields = {
                    "descriptor": str(descriptor),
                    "resource_id": str(ipc_resource["resource_id"]),
                    "endpoint": str(ipc_resource["endpoint"]),
                    "destination_address": destination,
                    "requested_byte_len": raw_read.group("requested"),
                    "content_sha256": _sha256(effect),
                    "content_byte_len": str(len(effect)),
                    "content_redacted": str(not public_ipc_content).lower(),
                    "result": "success" if result >= 0 else "failure",
                }
                if public_ipc_content:
                    fields["content_hex"] = effect.hex()
                if result >= 0:
                    fields["read_byte_len"] = str(result)
                event = {"kind": "descriptor_read", "fields": fields}
        if read is not None:
            descriptor = int(read.group("descriptor"))
            resource = open_resources.get(descriptor)
            ipc_resource = ipc_resources.get(descriptor)
            try:
                data = ast.literal_eval(read.group("data"))
            except (SyntaxError, ValueError):
                data = None
            if descriptor == 0 and isinstance(data, str):
                data_bytes = os.fsencode(data)
                result = int(read.group("result"))
                effect = data_bytes[:result] if result >= 0 else b""
                fields = {
                    "descriptor": "0",
                    "resource_id": f"standard-input:{process_id}",
                    "endpoint": "stdin",
                    "provider": stdin_provider,
                    "requested_byte_len": read.group("requested"),
                    "content_sha256": _sha256(effect),
                    "content_byte_len": str(len(effect)),
                    "content_redacted": str(not public_stdin_content).lower(),
                    "result": "success" if result >= 0 else "failure",
                }
                if public_stdin_content:
                    fields["content_hex"] = effect.hex()
                if result >= 0:
                    fields["read_byte_len"] = str(result)
                elif read.group("errno") is not None:
                    fields["errno"] = read.group("errno")
                event = {"kind": "descriptor_stdin_read", "fields": fields}
            elif (
                resource is not None
                and resource["content_public"] is True
                and isinstance(data, str)
            ):
                resource_id = str(resource["resource_id"])
                offset = resource_offsets.get(resource_id)
                if offset is None:
                    raise ValueError("tracked file resource offset is missing")
                data_bytes = os.fsencode(data)
                result = int(read.group("result"))
                effect = data_bytes[:result] if result >= 0 else b""
                fields = {
                    "descriptor": str(descriptor),
                    "resource_id": str(resource["resource_id"]),
                    "offset": str(offset),
                    "requested_byte_len": read.group("requested"),
                    "content_sha256": _sha256(effect),
                    "content_byte_len": str(len(effect)),
                    "content_hex": effect.hex(),
                    "content_redacted": "false",
                    "result": "success" if result >= 0 else "failure",
                }
                if result >= 0:
                    fields["read_byte_len"] = str(result)
                    resource_offsets[resource_id] = offset + result
                elif read.group("errno") is not None:
                    fields["errno"] = read.group("errno")
                event = {"kind": "file_read", "fields": fields}
            elif ipc_resource is not None and isinstance(data, str):
                data_bytes = os.fsencode(data)
                result = int(read.group("result"))
                effect = data_bytes[:result] if result >= 0 else b""
                fields = {
                    "descriptor": str(descriptor),
                    "resource_id": str(ipc_resource["resource_id"]),
                    "endpoint": str(ipc_resource["endpoint"]),
                    "requested_byte_len": read.group("requested"),
                    "content_sha256": _sha256(effect),
                    "content_byte_len": str(len(effect)),
                    "content_redacted": str(not public_ipc_content).lower(),
                    "result": "success" if result >= 0 else "failure",
                }
                if public_ipc_content:
                    fields["content_hex"] = effect.hex()
                if result >= 0:
                    fields["read_byte_len"] = str(result)
                elif read.group("errno") is not None:
                    fields["errno"] = read.group("errno")
                event = {"kind": "descriptor_read", "fields": fields}
        written = re.fullmatch(
            r'write\((?P<descriptor>\d+),\s*(?P<data>"(?:\\.|[^"\\])*")'
            r",\s*(?P<requested>\d+)\)\s+=\s+(?P<result>-?\d+)"
            r"(?:\s+(?P<errno>[A-Z][A-Z0-9_]+)\s+.*)?",
            line,
        )
        if written is not None:
            descriptor = int(written.group("descriptor"))
            resource = open_resources.get(descriptor)
            ipc_resource = ipc_resources.get(descriptor)
            try:
                data = ast.literal_eval(written.group("data"))
            except (SyntaxError, ValueError):
                data = None
            if resource is not None and isinstance(data, str):
                data_bytes = os.fsencode(data)
                result = int(written.group("result"))
                effect = data_bytes[:result] if result >= 0 else b""
                content_public = resource["path_sha256"] in public_content_hashes
                fields = {
                    "descriptor": str(descriptor),
                    "resource_id": str(resource["resource_id"]),
                    "requested_byte_len": written.group("requested"),
                    "content_sha256": _sha256(effect),
                    "content_byte_len": str(len(effect)),
                    "content_redacted": str(not content_public).lower(),
                    "result": "success" if result >= 0 else "failure",
                }
                if content_public:
                    fields["content_hex"] = effect.hex()
                if result >= 0:
                    fields["written_byte_len"] = str(result)
                    resource_id = str(resource["resource_id"])
                    flags = str(resource["flags"])
                    if "O_APPEND" in flags.split("|"):
                        resource_offsets.pop(resource_id, None)
                    else:
                        offset = resource_offsets.get(resource_id)
                        if offset is None:
                            raise ValueError("tracked file resource offset is missing")
                        resource_offsets[resource_id] = offset + result
                elif written.group("errno") is not None:
                    fields["errno"] = written.group("errno")
                event = {"kind": "file_write", "fields": fields}
            elif ipc_resource is not None and isinstance(data, str):
                data_bytes = os.fsencode(data)
                result = int(written.group("result"))
                effect = data_bytes[:result] if result >= 0 else b""
                fields = {
                    "descriptor": str(descriptor),
                    "resource_id": str(ipc_resource["resource_id"]),
                    "endpoint": str(ipc_resource["endpoint"]),
                    "requested_byte_len": written.group("requested"),
                    "content_sha256": _sha256(effect),
                    "content_byte_len": str(len(effect)),
                    "content_redacted": str(not public_ipc_content).lower(),
                    "result": "success" if result >= 0 else "failure",
                }
                if public_ipc_content:
                    fields["content_hex"] = effect.hex()
                if result >= 0:
                    fields["written_byte_len"] = str(result)
                elif written.group("errno") is not None:
                    fields["errno"] = written.group("errno")
                event = {"kind": "descriptor_write", "fields": fields}
        ioctl = re.fullmatch(
            r"ioctl\((?P<descriptor>\d+),\s*(?P<request>.+),"
            r"\s*(?P<argument>NULL|0x[0-9a-fA-F]+|-?\d+)\)\s+=\s+"
            r"(?P<result>-?\d+)"
            r"(?:\s+(?P<errno>[A-Z][A-Z0-9_]+)\s+.*)?",
            line,
        )
        if ioctl is not None:
            descriptor = int(ioctl.group("descriptor"))
            resource = open_resources.get(descriptor)
            request = _trace_ioctl_request(ioctl.group("request"))
            if resource is not None and request is not None:
                result = int(ioctl.group("result"))
                fields = {
                    "descriptor": str(descriptor),
                    "resource_id": str(resource["resource_id"]),
                    "request": f"0x{request:08x}",
                    "scalar_argument": ioctl.group("argument"),
                    "result": str(result),
                }
                if result < 0 and ioctl.group("errno") is not None:
                    fields["errno"] = ioctl.group("errno")
                event = {"kind": "file_ioctl", "fields": fields}
        duplicated = re.fullmatch(
            r"dup\((?P<source_descriptor>\d+)\)\s+=\s+(?P<result>-?\d+)"
            r"(?:\s+(?P<errno>[A-Z][A-Z0-9_]+)\s+.*)?",
            line,
        )
        if duplicated is not None:
            source_descriptor = int(duplicated.group("source_descriptor"))
            resource = open_resources.get(source_descriptor)
            if resource is not None:
                result = int(duplicated.group("result"))
                fields = {
                    "source_descriptor": str(source_descriptor),
                    "resource_id": str(resource["resource_id"]),
                    "result": "success" if result >= 0 else "failure",
                }
                if result >= 0:
                    fields["duplicate_descriptor"] = str(result)
                elif duplicated.group("errno") is not None:
                    fields["errno"] = duplicated.group("errno")
                event = {"kind": "file_dup", "fields": fields}
        closed = re.fullmatch(
            r"close\((?P<descriptor>\d+)\)\s+=\s+(?P<result>-?\d+)"
            r"(?:\s+(?P<errno>[A-Z][A-Z0-9_]+)\s+.*)?",
            line,
        )
        if closed is not None:
            descriptor = int(closed.group("descriptor"))
            resource = open_resources.get(descriptor)
            ipc_resource = ipc_resources.get(descriptor)
            if resource is not None:
                result = int(closed.group("result"))
                fields = {
                    "descriptor": str(descriptor),
                    "resource_id": str(resource["resource_id"]),
                    "result": "success" if result >= 0 else "failure",
                }
                if result < 0 and closed.group("errno") is not None:
                    fields["errno"] = closed.group("errno")
                event = {"kind": "file_close", "fields": fields}
            elif ipc_resource is not None:
                result = int(closed.group("result"))
                fields = {
                    "descriptor": str(descriptor),
                    "resource_id": str(ipc_resource["resource_id"]),
                    "endpoint": str(ipc_resource["endpoint"]),
                    "result": "success" if result >= 0 else "failure",
                }
                if result < 0 and closed.group("errno") is not None:
                    fields["errno"] = closed.group("errno")
                event = {"kind": "descriptor_close", "fields": fields}
        if (
            event is None
            and not recognized_thread_create
            and line.startswith(
                (
                    "openat(",
                    "newfstatat(",
                    "chmod(",
                    "pipe2(",
                    "socketpair(",
                    "socket(",
                    "fork(",
                    "vfork(",
                    "clone(",
                    "clone3(",
                    "wait4(",
                )
            )
        ):
            raise ValueError("in-scope path event could not be normalized")
        unresolved_file_io = re.match(
            r"(?P<operation>read|write|close|dup|ioctl|sendto|recvfrom|bind|listen)\((?P<descriptor>\d+)",
            line,
        )
        if (
            event is None
            and unresolved_file_io is not None
            and int(unresolved_file_io.group("descriptor")) in open_resources
            and (
                unresolved_file_io.group("operation") != "read"
                or open_resources[int(unresolved_file_io.group("descriptor"))][
                    "content_public"
                ]
                is True
            )
        ):
            raise ValueError(
                "in-scope operation on a tracked file resource could not be normalized"
            )
        if (
            event is None
            and unresolved_file_io is not None
            and int(unresolved_file_io.group("descriptor")) in ipc_resources
        ):
            raise ValueError(
                "in-scope operation on a tracked descriptor resource could not be normalized"
            )
        if event is None:
            continue
        sequence = sequences.get(thread_id, 0) + 1
        sequences[thread_id] = sequence
        event.update(
            {
                "process_id": process_id,
                "sequence": sequence,
                **({"thread_id": thread_id} if thread_id is not None else {}),
            }
        )
        if event["kind"] == "file_open":
            event_fields = event.get("fields")
            if not isinstance(event_fields, dict):
                raise ValueError("normalized file_open event has no fields")
            resource_scope = (
                thread_id if thread_id is not None else f"os-tid:{os_tid or 0}"
            )
            resource_key = (
                f"{process_id}\0{resource_scope}\0{sequence}\0"
                f"{event_fields.get('path_sha256', '')}"
            ).encode()
            event_fields["resource_id"] = "file-open-" + _sha256(resource_key)[:32]
            descriptor = event_fields.get("descriptor")
            if isinstance(descriptor, str):
                open_resources[int(descriptor)] = {
                    "resource_id": event_fields["resource_id"],
                    "path_sha256": event_fields["path_sha256"],
                    "flags": event_fields["flags"],
                    "content_public": event_fields["path_sha256"]
                    in public_content_hashes,
                }
                resource_offsets[str(event_fields["resource_id"])] = 0
        elif event["kind"] == "file_dup":
            event_fields = event.get("fields")
            if not isinstance(event_fields, dict):
                raise ValueError("normalized file_dup event has no fields")
            if event_fields.get("result") == "success":
                source_descriptor = event_fields.get("source_descriptor")
                duplicate_descriptor = event_fields.get("duplicate_descriptor")
                if not isinstance(source_descriptor, str) or not isinstance(
                    duplicate_descriptor, str
                ):
                    raise ValueError("successful file_dup descriptors are malformed")
                open_resources[int(duplicate_descriptor)] = dict(
                    open_resources[int(source_descriptor)]
                )
        elif event["kind"] == "descriptor_pipe_create":
            event_fields = event.get("fields")
            if not isinstance(event_fields, dict):
                raise ValueError(
                    "normalized descriptor_pipe_create event has no fields"
                )
            resource_scope = (
                thread_id if thread_id is not None else f"os-tid:{os_tid or 0}"
            )
            resource_key = f"{process_id}\0{resource_scope}\0{sequence}\0pipe".encode()
            resource_id = "pipe-" + _sha256(resource_key)[:32]
            event_fields["resource_id"] = resource_id
            read_descriptor = event_fields.get("read_descriptor")
            write_descriptor = event_fields.get("write_descriptor")
            if not isinstance(read_descriptor, str) or not isinstance(
                write_descriptor, str
            ):
                raise ValueError("successful pipe descriptors are malformed")
            ipc_resources[int(read_descriptor)] = {
                "resource_id": resource_id,
                "endpoint": "read",
            }
            ipc_resources[int(write_descriptor)] = {
                "resource_id": resource_id,
                "endpoint": "write",
            }
        elif event["kind"] == "descriptor_socketpair_create":
            event_fields = event.get("fields")
            if not isinstance(event_fields, dict):
                raise ValueError(
                    "normalized descriptor_socketpair_create has no fields"
                )
            resource_scope = (
                thread_id if thread_id is not None else f"os-tid:{os_tid or 0}"
            )
            resource_key = (
                f"{process_id}\0{resource_scope}\0{sequence}\0socketpair\0"
                f"{event_fields.get('domain', '')}\0{event_fields.get('socket_type', '')}"
            ).encode()
            resource_id = "socketpair-" + _sha256(resource_key)[:32]
            event_fields["resource_id"] = resource_id
            first_descriptor = event_fields.get("first_descriptor")
            second_descriptor = event_fields.get("second_descriptor")
            if not isinstance(first_descriptor, str) or not isinstance(
                second_descriptor, str
            ):
                raise ValueError("successful socketpair descriptors are malformed")
            ipc_resources[int(first_descriptor)] = {
                "resource_id": resource_id,
                "endpoint": "peer0",
            }
            ipc_resources[int(second_descriptor)] = {
                "resource_id": resource_id,
                "endpoint": "peer1",
            }
        elif event["kind"] == "descriptor_socket_create":
            event_fields = event.get("fields")
            if not isinstance(event_fields, dict):
                raise ValueError("normalized descriptor_socket_create has no fields")
            resource_scope = (
                thread_id if thread_id is not None else f"os-tid:{os_tid or 0}"
            )
            resource_key = (
                f"{process_id}\0{resource_scope}\0{sequence}\0socket\0"
                f"{event_fields.get('domain', '')}\0{event_fields.get('socket_type', '')}"
            ).encode()
            resource_id = "socket-" + _sha256(resource_key)[:32]
            event_fields["resource_id"] = resource_id
            if event_fields.get("result") == "success":
                descriptor = event_fields.get("descriptor")
                if not isinstance(descriptor, str):
                    raise ValueError("successful socket descriptor is malformed")
                ipc_resources[int(descriptor)] = {
                    "resource_id": resource_id,
                    "endpoint": "socket",
                }
        elif event["kind"] in {"file_stat", "file_chmod"}:
            event_fields = event.get("fields")
            if not isinstance(event_fields, dict):
                raise ValueError(f"normalized {event['kind']} event has no fields")
            resource_scope = (
                thread_id if thread_id is not None else f"os-tid:{os_tid or 0}"
            )
            resource_key = (
                f"{process_id}\0{resource_scope}\0{sequence}\0"
                f"{event_fields.get('path_sha256', '')}"
            ).encode()
            resource_kind = "stat" if event["kind"] == "file_stat" else "chmod"
            event_fields["resource_id"] = (
                f"file-{resource_kind}-" + _sha256(resource_key)[:32]
            )
        elif event["kind"] == "file_close":
            event_fields = event.get("fields")
            if (
                isinstance(event_fields, dict)
                and event_fields.get("result") == "success"
            ):
                descriptor = event_fields.get("descriptor")
                if isinstance(descriptor, str):
                    resource = open_resources.pop(int(descriptor), None)
                    if resource is not None and not any(
                        candidate.get("resource_id") == resource.get("resource_id")
                        for candidate in open_resources.values()
                    ):
                        resource_offsets.pop(str(resource["resource_id"]), None)
        elif event["kind"] == "descriptor_close":
            event_fields = event.get("fields")
            if (
                isinstance(event_fields, dict)
                and event_fields.get("result") == "success"
            ):
                descriptor = event_fields.get("descriptor")
                if isinstance(descriptor, str):
                    ipc_resources.pop(int(descriptor), None)
        events.append(event)
    return events


def _attach_event_input_provenance(
    events: Sequence[dict[str, object]],
) -> list[dict[str, str | int]]:
    """Identify successful bytes entering the process at normalized events."""
    identities: list[dict[str, str | int]] = []
    for event in events:
        kind = event.get("kind")
        if kind not in {
            "file_read",
            "descriptor_read",
            "descriptor_recv",
            "descriptor_stdin_read",
            "environment_read",
        }:
            continue
        fields = event.get("fields")
        successful_result = "present" if kind == "environment_read" else "success"
        if not isinstance(fields, dict) or fields.get("result") != successful_result:
            continue
        content_sha256 = fields.get("content_sha256")
        content_byte_len = fields.get("content_byte_len")
        if not isinstance(content_sha256, str) or not isinstance(content_byte_len, str):
            raise ValueError("successful input event has no bounded content identity")
        byte_len = int(content_byte_len)
        if byte_len == 0:
            continue
        process_id = event.get("process_id")
        sequence = event.get("sequence")
        if not isinstance(process_id, str) or not isinstance(sequence, int):
            raise ValueError("successful input event has no occurrence identity")
        thread_id = event.get("thread_id")
        thread_scope = thread_id if isinstance(thread_id, str) else "process"
        name = f"event:{process_id}:{thread_scope}:{sequence}:{kind}"
        fields["input_source_name"] = name
        identities.append(
            {
                "name": name,
                "sha256": content_sha256,
                "byte_len": byte_len,
                "sensitivity": (
                    "public"
                    if fields.get("content_redacted") == "false"
                    else "sensitive"
                ),
            }
        )
    return identities


def capture_traced_child_core(
    executable: str | Path,
    arguments: Sequence[str] = (),
    *,
    environment: Mapping[str, str] | None = None,
    timeout: float = 5.0,
    public_input: bytes | None = None,
) -> TracedCoreCapture:
    """Trace mapping changes in one launched child and import its ELF core.

    This deliberately has no PID-attach surface. The raw provider trace is
    bounded, normalized, and discarded; analyzers consume capsule events only.
    """
    if sys.platform != "linux" or platform.machine().lower() not in {
        "x86_64",
        "amd64",
    }:
        raise OSError("traced-core acquisition currently requires Linux x86-64")
    tracer = shutil.which("strace")
    if tracer is None:
        raise OSError("traced-core acquisition requires strace")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    binary = Path(executable).resolve(strict=True)
    binary_bytes = binary.read_bytes()
    child_env = os.environ.copy()
    if environment is not None:
        child_env.update(environment)
    temporary_root = Path(os.environ.get("TMPDIR", Path.home() / ".cache/glaurung/tmp"))
    temporary_root.mkdir(parents=True, exist_ok=True)

    def enable_core_dump() -> None:
        resource.setrlimit(
            resource.RLIMIT_CORE,
            (resource.RLIM_INFINITY, resource.RLIM_INFINITY),
        )

    with tempfile.TemporaryDirectory(
        prefix="glaurung-traced-core-", dir=temporary_root
    ) as directory:
        capture_dir = Path(directory)
        trace_path = capture_dir / "mapping.trace"
        stdout_path = capture_dir / "stdout.bin"
        stderr_path = capture_dir / "stderr.bin"
        command = [
            tracer,
            "-f",
            "-qq",
            "-e",
            "trace=mmap,mprotect,munmap",
            "-o",
            str(trace_path),
            "--",
            str(binary),
            *arguments,
        ]
        with (
            stdout_path.open("wb") as stdout_file,
            stderr_path.open("wb") as stderr_file,
        ):
            proc = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                cwd=capture_dir,
                env=child_env,
                start_new_session=True,
                preexec_fn=enable_core_dump,
            )
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                _terminate_owned_group(proc)
                raise TimeoutError(
                    "traced child did not terminate before timeout"
                ) from error
        trace_bytes = _bounded_file(trace_path, _MAX_TRACE_BYTES, "mapping trace")
        stdout = _bounded_file(stdout_path, _MAX_PROCESS_OUTPUT_BYTES, "stdout")
        stderr = _bounded_file(stderr_path, _MAX_PROCESS_OUTPUT_BYTES, "stderr")
        core_files = [
            item
            for item in capture_dir.iterdir()
            if item.name.startswith("core") and item.is_file() and not item.is_symlink()
        ]
        if len(core_files) != 1:
            raise RuntimeError(
                f"expected exactly one regular core file, found {len(core_files)}; "
                "host core policy may suppress or redirect dumps"
            )
        core_bytes = core_files[0].read_bytes()
        captured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        capsule_json, payloads = runtime_analysis.import_elf_core(
            core_bytes,
            binary_bytes,
            str(core_files[0]),
            str(binary),
            captured_at,
            public_input,
            stdout,
            stderr,
        )
        capsule: dict[str, Any] = json.loads(capsule_json)
        trace_sha256 = _sha256(trace_bytes)
        events = _parse_os_trace(trace_bytes.decode("utf-8", errors="strict"), capsule)
        capsule["identity"]["acquisition"] = "trace"
        capsule["identity"]["capture_id"] = "trace-" + _sha256(core_bytes + trace_bytes)
        capsule["events"] = events
        capsule["provenance"]["producer"] = "glaurung-python-traced-core"
        capsule["provenance"]["producer_version"] = "1"
        capsule["provenance"]["command"] = [
            "strace",
            "--event-scope=mmap,mprotect,munmap",
            "--",
            str(binary),
        ]
        capsule["completeness"].append(
            {
                "evidence": "mapping_events",
                "status": "complete",
                "requested": True,
                "obtained": len(events),
                "expected": len(events),
            }
        )
        capsule["provider.strace"] = {
            "trace_sha256": trace_sha256,
            "trace_byte_len": len(trace_bytes),
            "event_scope": ["mmap", "mprotect", "munmap"],
            "normalized_event_count": len(events),
            "truncated": False,
            "lost_events": 0,
        }
        canonical = runtime_analysis.canonicalize_process_capsule_json(
            json.dumps(capsule, separators=(",", ":"), ensure_ascii=False)
        )
        return TracedCoreCapture(canonical, tuple(payloads))


def capture_mapping_trace_child(
    executable: str | Path,
    arguments: Sequence[str] = (),
    *,
    environment: Mapping[str, str] | None = None,
    cwd: str | Path | None = None,
    timeout: float = 5.0,
    public_input: bytes | None = None,
    public_paths: Sequence[str] = (),
    public_content_paths: Sequence[str] = (),
    public_ipc_content: bool = False,
    stdin_bytes: bytes | None = None,
    public_stdin_content: bool = False,
    capture_read_destinations: bool = False,
    capture_read_checkpoint: bool = False,
) -> MappingTraceCapture:
    """Trace bounded mapping and file events in one normally exiting child.

    This provider has no PID-attach surface. It retains only normalized,
    bounded events; the raw trace is hash-bound in provenance and then
    discarded. File paths are redacted unless explicitly listed as public.
    """
    if sys.platform != "linux" or platform.machine().lower() not in {
        "x86_64",
        "amd64",
    }:
        raise OSError("mapping-trace acquisition currently requires Linux x86-64")
    tracer = shutil.which("strace")
    if tracer is None:
        raise OSError("mapping-trace acquisition requires strace")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if len(public_paths) > 256 or len(set(public_paths)) != len(public_paths):
        raise ValueError("public paths must be unique and contain at most 256 entries")
    if any(not path or "\x00" in path for path in public_paths):
        raise ValueError("public paths must be non-empty strings without NUL bytes")
    if len(public_content_paths) > 256 or len(set(public_content_paths)) != len(
        public_content_paths
    ):
        raise ValueError(
            "public content paths must be unique and contain at most 256 entries"
        )
    if not set(public_content_paths).issubset(public_paths):
        raise ValueError("public content paths must also be authorized public paths")
    if not isinstance(public_ipc_content, bool):
        raise TypeError("public_ipc_content must be a boolean")
    if stdin_bytes is not None and not isinstance(stdin_bytes, bytes):
        raise TypeError("stdin_bytes must be bytes or None")
    if stdin_bytes is not None and len(stdin_bytes) > _MAX_STDIN_BYTES:
        raise ValueError("stdin bytes exceed acquisition budget")
    if not isinstance(public_stdin_content, bool):
        raise TypeError("public_stdin_content must be a boolean")
    if public_stdin_content and stdin_bytes is None:
        raise ValueError("public stdin content requires supplied stdin bytes")
    if not isinstance(capture_read_destinations, bool):
        raise TypeError("capture_read_destinations must be a boolean")
    if not isinstance(capture_read_checkpoint, bool):
        raise TypeError("capture_read_checkpoint must be a boolean")
    if capture_read_checkpoint and not capture_read_destinations:
        raise ValueError("read checkpoint requires captured read destinations")
    binary = Path(executable).resolve(strict=True)
    binary_bytes = binary.read_bytes()
    child_env = os.environ.copy()
    if environment is not None:
        child_env.update(environment)
    if capture_read_checkpoint:
        child_env["GLAURUNG_RUNTIME_CHECKPOINT"] = "1"
        child_env["GLAURUNG_RUNTIME_CHECKPOINT_BEFORE_READ"] = "1"
    temporary_root = Path(os.environ.get("TMPDIR", Path.home() / ".cache/glaurung/tmp"))
    temporary_root.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix="glaurung-mapping-trace-", dir=temporary_root
    ) as directory:
        capture_dir = Path(directory)
        trace_path = capture_dir / "mapping.trace"
        command = [
            tracer,
            "-f",
            "-qq",
            "-k",
            "-s",
            "256",
            "-e",
            "trace=mmap,mprotect,munmap,openat,newfstatat,chmod,read,write,close,dup,ioctl,pipe2,socket,socketpair,bind,listen,sendto,recvfrom,clone,clone3,fork,vfork,wait4",
            "-o",
            str(trace_path),
            "--",
            str(binary),
            *arguments,
        ]
        if stdin_bytes is not None or capture_read_destinations:
            command[command.index("-o") : command.index("-o")] = [
                "-e",
                "raw=read",
                "-e",
                "read=all" if capture_read_destinations else "read=0",
            ]
        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=child_env,
            start_new_session=True,
        )
        checkpoint_snapshot: _ReadCheckpoint | None = None
        try:
            if capture_read_checkpoint:
                if stdin_bytes is not None:
                    assert proc.stdin is not None
                    proc.stdin.write(stdin_bytes)
                    proc.stdin.close()
                    proc.stdin = None
                checkpoint_child = _wait_for_traced_checkpoint_child(
                    proc.pid, binary, trace_path, 1, timeout
                )
                (
                    _before_maps,
                    _before_stack_mapping,
                    _before_instruction_pointer,
                    before_stack_pointer,
                    before_stack_bytes,
                ) = _checkpoint_stack_state(checkpoint_child)
                os.killpg(proc.pid, signal.SIGCONT)
                checkpoint_child = _wait_for_traced_checkpoint_child(
                    proc.pid, binary, trace_path, 2, timeout
                )
                checkpoint_snapshot = _checkpoint_read_snapshot(
                    checkpoint_child,
                    trace_path,
                    before_stack_pointer,
                    before_stack_bytes,
                    timeout,
                )
                os.killpg(proc.pid, signal.SIGCONT)
            stdout, stderr = proc.communicate(input=stdin_bytes, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            _terminate_owned_group(proc)
            proc.communicate()
            raise TimeoutError(
                "mapping-traced child did not terminate before timeout"
            ) from error
        except Exception:
            _terminate_owned_group(proc)
            proc.communicate()
            raise
        trace_bytes = _bounded_file(trace_path, _MAX_TRACE_BYTES, "mapping trace")
        if len(stdout) > _MAX_PROCESS_OUTPUT_BYTES:
            raise RuntimeError("stdout exceeds acquisition budget")
        if len(stderr) > _MAX_PROCESS_OUTPUT_BYTES:
            raise RuntimeError("stderr exceeds acquisition budget")
        if proc.returncode is None:
            raise RuntimeError("mapping tracer has no terminal return code")
        traced_pid_match = re.search(
            rb"^(?:\[pid\s+)?(?P<pid>\d+)(?:\])?\s+", trace_bytes, re.MULTILINE
        )
        if traced_pid_match is None:
            raise RuntimeError("mapping trace has no provider-identified child PID")
        traced_pid = int(traced_pid_match.group("pid"))

        def artifact(data: bytes, path: Path) -> dict[str, object]:
            value: dict[str, object] = {
                "sha256": _sha256(data),
                "byte_len": len(data),
                "display_path": str(path),
            }
            build_id = runtime_analysis.elf_executable_build_id(data)
            if build_id is not None:
                value["build_id"] = build_id
            return value

        process_id = "process-main"
        terminal = (
            {"kind": "exited", "code": proc.returncode}
            if proc.returncode >= 0
            else {
                "kind": "signaled",
                "signal": -proc.returncode,
                "core_dumped": False,
            }
        )
        payloads = []
        outputs = []
        for name, data in (("stdout", stdout), ("stderr", stderr)):
            payload_id = f"process-output-{name}"
            payloads.append((payload_id, data))
            outputs.append(
                {
                    "process_id": process_id,
                    "stream": name,
                    "payload": {
                        "id": payload_id,
                        "sha256": _sha256(data),
                        "byte_len": len(data),
                        "sensitivity": "sensitive",
                    },
                    "truncated": False,
                }
            )
        captured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        disclosure_policy = json.dumps(
            {
                "public_path_hashes": sorted(
                    _sha256(os.fsencode(path)) for path in public_paths
                ),
                "public_content_path_hashes": sorted(
                    _sha256(os.fsencode(path)) for path in public_content_paths
                ),
                "public_ipc_content": public_ipc_content,
                "public_stdin_content": public_stdin_content,
                "capture_read_destinations": capture_read_destinations,
                "capture_read_checkpoint": capture_read_checkpoint,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        executable_artifact = artifact(binary_bytes, binary)
        capsule: dict[str, Any] = {
            "schema": "glaurung-process-capsule-v1",
            "version": 1,
            "identity": {
                "capture_id": "mapping-trace-"
                + _sha256(
                    binary_bytes
                    + trace_bytes
                    + stdout
                    + stderr
                    + (public_input or b"")
                    + (stdin_bytes or b"")
                    + disclosure_policy
                ),
                "acquisition": "trace",
                "host_os": "linux",
                "kernel": platform.release(),
                "captured_at": captured_at,
            },
            "required_features": [],
            "target": {
                "architecture": "X86_64",
                "endianness": "Little",
                "address_bits": 64,
                "os_abi": "linux",
            },
            "executable": executable_artifact,
            "processes": [
                {"id": process_id, "os_pid": traced_pid, "terminal": terminal}
            ],
            "modules": [],
            "mappings": [],
            "threads": [],
            "pages": [],
            "runtime_objects": [],
            "object_snapshots": [],
            "outputs": outputs,
            "descriptors": [],
            "events": [],
            "provenance": {
                "producer": "glaurung-python-mapping-trace",
                "producer_version": "1",
                "command": [
                    "strace",
                    "--user-stack-frames=true",
                    "--event-scope=mmap,mprotect,munmap,openat,newfstatat,chmod,read,write,close,dup,ioctl,pipe2,socket,socketpair,bind,listen,sendto,recvfrom,clone,clone3,fork,vfork,wait4",
                    f"--public-path-count={len(public_paths)}",
                    f"--public-content-path-count={len(public_content_paths)}",
                    f"--public-ipc-content={str(public_ipc_content).lower()}",
                    f"--stdin-provider={'pipe' if stdin_bytes is not None else 'dev-null'}",
                    f"--public-stdin-content={str(public_stdin_content).lower()}",
                    f"--capture-read-destinations={str(capture_read_destinations).lower()}",
                    f"--capture-read-checkpoint={str(capture_read_checkpoint).lower()}",
                    "--",
                    str(binary),
                ],
                "input_artifacts": [executable_artifact],
                "input_bytes": (
                    []
                    if public_input is None
                    else [
                        {
                            "name": "argv[1]",
                            "sha256": _sha256(public_input),
                            "byte_len": len(public_input),
                            "sensitivity": "public",
                        }
                    ]
                ),
                "warnings": [],
            },
            "completeness": [
                {
                    "evidence": "mapping_events",
                    "status": "complete",
                    "requested": True,
                    "obtained": 0,
                    "expected": 0,
                },
                {
                    "evidence": "runtime_state",
                    "status": "omitted",
                    "reason": "terminal mapping trace captures no threads, mappings, or pages",
                    "requested": False,
                    "obtained": 0,
                    "expected": 0,
                },
            ],
        }
        trace_text = trace_bytes.decode("utf-8", errors="strict")
        if stdin_bytes is not None or capture_read_destinations:
            trace_text = _normalize_raw_reads(trace_text)
        events = _parse_os_trace(
            trace_text,
            capsule,
            public_paths=public_paths,
            public_content_paths=public_content_paths,
            public_ipc_content=public_ipc_content,
            stdin_provider="pipe" if stdin_bytes is not None else "dev_null",
            public_stdin_content=public_stdin_content,
        )
        event_inputs = _attach_event_input_provenance(events)
        capsule["provenance"]["input_bytes"].extend(event_inputs)
        capsule["events"] = events
        if checkpoint_snapshot is not None:
            stack_mapping = checkpoint_snapshot.stack_mapping
            destination = checkpoint_snapshot.destination
            effect_bytes = checkpoint_snapshot.read_bytes
            matching_reads = []
            for event in events:
                fields = event.get("fields")
                if not isinstance(fields, Mapping):
                    continue
                if (
                    event.get("kind") in {"descriptor_read", "descriptor_stdin_read"}
                    and int(str(fields.get("destination_address", "-1"))) == destination
                    and fields.get("content_sha256") == _sha256(effect_bytes)
                ):
                    matching_reads.append(event)
            if len(matching_reads) != 1:
                raise RuntimeError(
                    "checkpoint snapshot does not match exactly one normalized read"
                )
            read_event = matching_reads[0]
            before_offset = destination - checkpoint_snapshot.before_stack_pointer
            after_offset = destination - checkpoint_snapshot.stack_pointer
            snapshot_byte_len = min(
                _CHECKPOINT_WRITE_WINDOW_BYTES,
                len(checkpoint_snapshot.before_stack_bytes) - before_offset,
                len(checkpoint_snapshot.stack_bytes) - after_offset,
            )
            if (
                before_offset < 0
                or after_offset < 0
                or snapshot_byte_len < len(effect_bytes)
            ):
                raise RuntimeError(
                    "pre-read checkpoint does not cover the destination interval"
                )
            before_bytes = checkpoint_snapshot.before_stack_bytes[
                before_offset : before_offset + snapshot_byte_len
            ]
            after_bytes = checkpoint_snapshot.stack_bytes[
                after_offset : after_offset + snapshot_byte_len
            ]
            if after_bytes[: len(effect_bytes)] != effect_bytes:
                raise RuntimeError(
                    "post-read checkpoint window disagrees with traced read bytes"
                )
            checkpoint_mappings, executable_mapping_ids = _parse_maps(
                checkpoint_snapshot.maps_text,
                process_id=process_id,
                executable=binary,
                executable_sha256=str(executable_artifact["sha256"]),
                backing_artifacts={},
            )
            if not executable_mapping_ids:
                raise RuntimeError(
                    "checkpoint mappings do not identify the exact executable"
                )
            stack_records = [
                mapping
                for mapping in checkpoint_mappings
                if mapping.get("backing") == {"kind": "special", "name": "[stack]"}
                and mapping.get("start") == stack_mapping.start
                and mapping.get("end") == stack_mapping.end
            ]
            if len(stack_records) != 1:
                raise RuntimeError("checkpoint stack mapping identity is ambiguous")
            stack_record = stack_records[0]
            mapping_id = str(stack_record["id"])
            object_id = "object-checkpoint-stack-mapping"
            before_payload_id = "object-checkpoint-before-read-bytes"
            payload_id = "object-checkpoint-after-read-bytes"
            stack_payload_id = "checkpoint-stack-bytes"
            capsule["mappings"] = checkpoint_mappings
            capsule["modules"] = [
                {
                    "id": "module-main",
                    "process_id": process_id,
                    "artifact": executable_artifact,
                    "mapping_ids": executable_mapping_ids,
                }
            ]
            capsule["threads"] = [
                {
                    "id": "thread-checkpoint",
                    "process_id": process_id,
                    "os_tid": checkpoint_snapshot.child_pid,
                    "registers": [
                        {
                            "provider_name": "rip",
                            "bit_width": 64,
                            "value_hex": f"{checkpoint_snapshot.instruction_pointer:016x}",
                        },
                        {
                            "provider_name": "rsp",
                            "bit_width": 64,
                            "value_hex": f"{checkpoint_snapshot.stack_pointer:016x}",
                        },
                    ],
                }
            ]
            capsule["events"].extend(
                [
                    {
                        "process_id": process_id,
                        "thread_id": "thread-checkpoint",
                        "sequence": 0,
                        "kind": "capture_checkpoint",
                        "fields": {"phase": "before_read"},
                    },
                    {
                        "process_id": process_id,
                        "thread_id": "thread-checkpoint",
                        "sequence": 1,
                        "kind": "capture_checkpoint",
                        "fields": {"phase": "after_read"},
                    },
                ]
            )
            capsule["pages"] = [
                {
                    "process_id": process_id,
                    "mapping_id": mapping_id,
                    "start": checkpoint_snapshot.stack_pointer,
                    "byte_len": len(checkpoint_snapshot.stack_bytes),
                    "content": {
                        "status": "captured",
                        "payload": {
                            "id": stack_payload_id,
                            "sha256": _sha256(checkpoint_snapshot.stack_bytes),
                            "byte_len": len(checkpoint_snapshot.stack_bytes),
                            "sensitivity": "sensitive",
                        },
                    },
                }
            ]
            capsule["runtime_objects"].append(
                {
                    "id": object_id,
                    "process_id": process_id,
                    "mapping_id": mapping_id,
                    "kind": "mapping",
                    "start": stack_mapping.start,
                    "byte_len": stack_mapping.end - stack_mapping.start,
                    "created_at": {
                        "thread_id": "thread-checkpoint",
                        "sequence": 0,
                    },
                }
            )
            for sequence, snapshot_id, snapshot_payload_id, data in (
                (
                    0,
                    "snapshot-checkpoint-before-read-bytes",
                    before_payload_id,
                    before_bytes,
                ),
                (
                    1,
                    "snapshot-checkpoint-after-read-bytes",
                    payload_id,
                    after_bytes,
                ),
            ):
                capsule["object_snapshots"].append(
                    {
                        "id": snapshot_id,
                        "process_id": process_id,
                        "object_id": object_id,
                        "point": {
                            "thread_id": "thread-checkpoint",
                            "sequence": sequence,
                        },
                        "object_offset": destination - stack_mapping.start,
                        "byte_len": len(data),
                        "content": {
                            "status": "captured",
                            "payload": {
                                "id": snapshot_payload_id,
                                "sha256": _sha256(data),
                                "byte_len": len(data),
                                "sensitivity": "sensitive",
                            },
                        },
                    }
                )
            payloads.append((before_payload_id, before_bytes))
            payloads.append((payload_id, after_bytes))
            payloads.append((stack_payload_id, checkpoint_snapshot.stack_bytes))
            capsule["completeness"][1] = {
                "evidence": "runtime_state",
                "status": "partial",
                "reason": (
                    "checkpoint captures mappings, RIP/RSP, and bounded stack bytes; "
                    "other registers, backing files, and pages are omitted"
                ),
                "requested": True,
                "obtained": len(checkpoint_mappings) + 2,
            }
            capsule["completeness"].append(
                {
                    "evidence": "read_checkpoint_memory",
                    "status": "complete",
                    "requested": True,
                    "obtained": 2,
                    "expected": 2,
                }
            )
        mapping_event_count = sum(
            str(event.get("kind", "")).startswith("mapping_") for event in events
        )
        capsule["completeness"][0]["obtained"] = mapping_event_count
        capsule["completeness"][0]["expected"] = mapping_event_count
        file_event_count = sum(
            str(event["kind"]).startswith("file_") for event in events
        )
        capsule["completeness"].append(
            {
                "evidence": "file_events",
                "status": "complete",
                "requested": True,
                "obtained": file_event_count,
                "expected": file_event_count,
            }
        )
        capsule["completeness"].append(
            {
                "evidence": "input_events",
                "status": "complete",
                "requested": True,
                "obtained": len(event_inputs),
                "expected": len(event_inputs),
            }
        )
        descriptor_event_count = sum(
            str(event["kind"]).startswith("descriptor_") for event in events
        )
        capsule["completeness"].append(
            {
                "evidence": "descriptor_events",
                "status": "complete",
                "requested": True,
                "obtained": descriptor_event_count,
                "expected": descriptor_event_count,
            }
        )
        process_event_count = sum(
            str(event["kind"]).startswith("process_") for event in events
        )
        capsule["completeness"].append(
            {
                "evidence": "process_events",
                "status": "complete",
                "requested": True,
                "obtained": process_event_count,
                "expected": process_event_count,
            }
        )
        capsule["provider.strace"] = {
            "trace_sha256": _sha256(trace_bytes),
            "trace_byte_len": len(trace_bytes),
            "event_scope": [
                "mmap",
                "mprotect",
                "munmap",
                "openat",
                "newfstatat",
                "chmod",
                "read",
                "write",
                "close",
                "dup",
                "ioctl",
                "pipe2",
                "socketpair",
                "socket",
                "bind",
                "listen",
                "sendto",
                "recvfrom",
                "clone",
                "clone3",
                "fork",
                "vfork",
                "wait4",
            ],
            "normalized_event_count": len(events),
            "truncated": False,
            "lost_events": 0,
            "user_stack_frames": True,
        }
        canonical = runtime_analysis.canonicalize_process_capsule_json(
            json.dumps(capsule, separators=(",", ":"), ensure_ascii=False)
        )
        return MappingTraceCapture(canonical, tuple(payloads))


def _parse_environment_trace(
    trace: str,
    *,
    process_id: str,
    selected_environment: Sequence[str],
    public_environment: Sequence[str],
) -> list[dict[str, object]]:
    """Normalize selected successful getenv calls from bounded ltrace output."""
    selected = set(selected_environment)
    public = set(public_environment)
    events: list[dict[str, object]] = []
    sequence = 0
    call = re.compile(
        r"^(?P<pid>\d+) \[(?P<pc>0x[0-9a-fA-F]+)\] .+?->getenv\("
        r"(?P<name>\"(?:\\.|[^\"\\])*\")\)\s+=\s+"
        r"(?P<value>nil|\"(?:\\.|[^\"\\])*\")$"
    )
    observed_selected: set[str] = set()
    for line in trace.splitlines():
        if "->getenv(" not in line:
            continue
        matched = call.fullmatch(line)
        if matched is None:
            if any(f'getenv("{name}' in line for name in selected):
                raise ValueError(
                    "selected getenv observation was truncated or malformed"
                )
            continue
        try:
            name = ast.literal_eval(matched.group("name"))
        except (SyntaxError, ValueError) as error:
            raise ValueError("selected getenv name is malformed") from error
        if not isinstance(name, str) or name not in selected:
            continue
        observed_selected.add(name)
        sequence += 1
        fields: dict[str, str] = {
            "name": name,
            "name_sha256": _sha256(name.encode()),
            "result": "missing" if matched.group("value") == "nil" else "present",
        }
        if matched.group("value") != "nil":
            try:
                value = ast.literal_eval(matched.group("value"))
            except (SyntaxError, ValueError) as error:
                raise ValueError("selected getenv value is malformed") from error
            if not isinstance(value, str):
                raise ValueError("selected getenv value is not text")
            value_bytes = os.fsencode(value)
            if len(value_bytes) > _MAX_ENVIRONMENT_VALUE_BYTES:
                raise ValueError("selected getenv value exceeds acquisition budget")
            fields.update(
                {
                    "value_sha256": _sha256(value_bytes),
                    "value_byte_len": str(len(value_bytes)),
                    "content_sha256": _sha256(value_bytes),
                    "content_byte_len": str(len(value_bytes)),
                    "content_redacted": str(name not in public).lower(),
                }
            )
            if name in public:
                fields["content_hex"] = value_bytes.hex()
        events.append(
            {
                "kind": "environment_read",
                "process_id": process_id,
                "sequence": sequence,
                "address": int(matched.group("pc"), 16),
                "fields": fields,
            }
        )
    missing = selected - observed_selected
    if missing:
        raise ValueError(
            "selected environment variables were not read: "
            + ", ".join(sorted(missing))
        )
    return events


def capture_environment_trace_child(
    executable: str | Path,
    arguments: Sequence[str] = (),
    *,
    environment: Mapping[str, str] | None = None,
    selected_environment: Sequence[str],
    public_environment: Sequence[str] = (),
    cwd: str | Path | None = None,
    timeout: float = 5.0,
    public_input: bytes | None = None,
) -> MappingTraceCapture:
    """Capture actual selected getenv calls from one owned Linux child."""
    if sys.platform != "linux" or platform.machine().lower() not in {
        "x86_64",
        "amd64",
    }:
        raise OSError("environment-trace acquisition currently requires Linux x86-64")
    tracer = shutil.which("ltrace")
    if tracer is None:
        raise OSError("environment-trace acquisition requires ltrace")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if (
        not selected_environment
        or len(selected_environment) > _MAX_SELECTED_ENVIRONMENT
    ):
        raise ValueError("selected environment must contain between 1 and 64 names")
    if len(set(selected_environment)) != len(selected_environment):
        raise ValueError("selected environment names must be unique")
    if any(not name or "\x00" in name or "=" in name for name in selected_environment):
        raise ValueError("selected environment names are invalid")
    if not set(public_environment).issubset(selected_environment):
        raise ValueError("public environment must be a subset of selected environment")
    if environment is None or not set(selected_environment).issubset(environment):
        raise ValueError("selected environment must be explicitly caller supplied")
    for name in selected_environment:
        if len(os.fsencode(environment[name])) > _MAX_ENVIRONMENT_VALUE_BYTES:
            raise ValueError("selected environment value exceeds acquisition budget")

    binary = Path(executable).resolve(strict=True)
    binary_bytes = binary.read_bytes()
    child_env = os.environ.copy()
    child_env.update(environment)
    temporary_root = Path(os.environ.get("TMPDIR", Path.home() / ".cache/glaurung/tmp"))
    temporary_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="glaurung-environment-trace-", dir=temporary_root
    ) as directory:
        trace_path = Path(directory) / "environment.trace"
        command = [
            tracer,
            "-f",
            "-i",
            "-s",
            str(_MAX_ENVIRONMENT_VALUE_BYTES),
            "-e",
            "getenv",
            "-o",
            str(trace_path),
            "--",
            str(binary),
            *arguments,
        ]
        proc = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=child_env,
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            _terminate_owned_group(proc)
            proc.communicate()
            raise TimeoutError(
                "environment-traced child did not terminate before timeout"
            ) from error
        trace_bytes = _bounded_file(trace_path, _MAX_TRACE_BYTES, "environment trace")
        if (
            len(stdout) > _MAX_PROCESS_OUTPUT_BYTES
            or len(stderr) > _MAX_PROCESS_OUTPUT_BYTES
        ):
            raise RuntimeError(
                "environment-traced process output exceeds acquisition budget"
            )
        if proc.returncode is None:
            raise RuntimeError("environment tracer has no terminal return code")
        pid_match = re.search(rb"^(?P<pid>\d+) \[", trace_bytes, re.MULTILINE)
        if pid_match is None:
            raise RuntimeError("environment trace has no provider-identified child PID")
        process_id = "process-main"
        events = _parse_environment_trace(
            trace_bytes.decode("utf-8", errors="strict"),
            process_id=process_id,
            selected_environment=selected_environment,
            public_environment=public_environment,
        )
        event_inputs = _attach_event_input_provenance(events)

        def artifact(data: bytes, path: Path) -> dict[str, object]:
            value: dict[str, object] = {
                "sha256": _sha256(data),
                "byte_len": len(data),
                "display_path": str(path),
            }
            build_id = runtime_analysis.elf_executable_build_id(data)
            if build_id is not None:
                value["build_id"] = build_id
            return value

        executable_artifact = artifact(binary_bytes, binary)
        payloads: list[tuple[str, bytes]] = []
        outputs = []
        for name, data in (("stdout", stdout), ("stderr", stderr)):
            payload_id = f"process-output-{name}"
            payloads.append((payload_id, data))
            outputs.append(
                {
                    "process_id": process_id,
                    "stream": name,
                    "payload": {
                        "id": payload_id,
                        "sha256": _sha256(data),
                        "byte_len": len(data),
                        "sensitivity": "sensitive",
                    },
                    "truncated": False,
                }
            )
        input_bytes: list[dict[str, str | int]] = []
        if public_input is not None:
            input_bytes.append(
                {
                    "name": "argv[1]",
                    "sha256": _sha256(public_input),
                    "byte_len": len(public_input),
                    "sensitivity": "public",
                }
            )
        input_bytes.extend(event_inputs)
        disclosure = json.dumps(
            {"public_environment": sorted(public_environment)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        terminal = (
            {"kind": "exited", "code": proc.returncode}
            if proc.returncode >= 0
            else {
                "kind": "signaled",
                "signal": -proc.returncode,
                "core_dumped": False,
            }
        )
        capsule = {
            "schema": "glaurung-process-capsule-v1",
            "version": 1,
            "identity": {
                "capture_id": "environment-trace-"
                + _sha256(
                    binary_bytes
                    + trace_bytes
                    + stdout
                    + stderr
                    + (public_input or b"")
                    + disclosure
                ),
                "acquisition": "trace",
                "host_os": "linux",
                "kernel": platform.release(),
                "captured_at": datetime.now(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
            },
            "required_features": [],
            "target": {
                "architecture": "X86_64",
                "endianness": "Little",
                "address_bits": 64,
                "os_abi": "linux",
            },
            "executable": executable_artifact,
            "processes": [
                {
                    "id": process_id,
                    "os_pid": int(pid_match.group("pid")),
                    "terminal": terminal,
                }
            ],
            "modules": [],
            "mappings": [],
            "threads": [],
            "pages": [],
            "runtime_objects": [],
            "object_snapshots": [],
            "outputs": outputs,
            "descriptors": [],
            "events": events,
            "provenance": {
                "producer": "glaurung-python-environment-trace",
                "producer_version": "1",
                "command": [
                    "ltrace",
                    "--event-scope=getenv",
                    f"--selected-count={len(selected_environment)}",
                    f"--public-count={len(public_environment)}",
                    "--",
                    str(binary),
                ],
                "input_artifacts": [executable_artifact],
                "input_bytes": input_bytes,
                "warnings": [],
            },
            "completeness": [
                {
                    "evidence": "environment_events",
                    "status": "complete",
                    "requested": True,
                    "obtained": len(events),
                    "expected": len(events),
                },
                {
                    "evidence": "runtime_state",
                    "status": "omitted",
                    "reason": "terminal environment trace captures no threads, mappings, or pages",
                    "requested": False,
                    "obtained": 0,
                    "expected": 0,
                },
            ],
            "provider.ltrace": {
                "trace_sha256": _sha256(trace_bytes),
                "trace_byte_len": len(trace_bytes),
                "event_scope": ["getenv"],
                "normalized_event_count": len(events),
                "truncated": False,
                "lost_events": 0,
            },
        }
        canonical = runtime_analysis.canonicalize_process_capsule_json(
            json.dumps(capsule, separators=(",", ":"), ensure_ascii=False)
        )
        return MappingTraceCapture(canonical, tuple(payloads))


_HEAP_RECORD = struct.Struct("<8sB7xQQQQQQQQQII")
_HEAP_MAGIC = b"GOBJv4\0\0"
_HEAP_CREATE = 1
_HEAP_END = 2
_HEAP_SUMMARY = 3
_HEAP_WRITE = 4
_HEAP_PRE_WRITE = 5
_HEAP_NO_MODULE = (1 << 64) - 1


def _parse_heap_snapshot_records(
    data: bytes,
    *,
    require_summary: bool = True,
) -> tuple[list[dict[str, Any]], int]:
    # Heterogeneous per-field values (ints plus the ``bytes`` payload).
    records: list[dict[str, Any]] = []
    offset = 0
    summaries = 0
    dropped = 0
    previous_provider_sequence = 0
    while offset < len(data):
        if len(data) - offset < _HEAP_RECORD.size:
            raise ValueError("truncated heap snapshot record header")
        (
            magic,
            kind,
            provider_sequence,
            os_tid,
            object_id,
            address,
            caller_address,
            caller_module_base,
            object_size,
            argument0,
            argument1,
            byte_len,
            record_dropped,
        ) = _HEAP_RECORD.unpack_from(data, offset)
        offset += _HEAP_RECORD.size
        if magic != _HEAP_MAGIC:
            raise ValueError("invalid heap snapshot record magic")
        if provider_sequence != previous_provider_sequence + 1 or os_tid == 0:
            raise ValueError("heap provider sequence or thread identity is invalid")
        previous_provider_sequence = provider_sequence
        if byte_len > 256 or byte_len > object_size or len(data) - offset < byte_len:
            raise ValueError("invalid heap snapshot record byte length")
        payload = data[offset : offset + byte_len]
        offset += byte_len
        stream_end_offset = offset
        dropped = max(dropped, record_dropped)
        if kind == _HEAP_SUMMARY:
            if (
                object_id != 0
                or address != 0
                or caller_address != 0
                or caller_module_base != _HEAP_NO_MODULE
                or object_size != 0
                or argument0 != 0
                or argument1 != 0
                or byte_len != 0
            ):
                raise ValueError("malformed heap snapshot summary")
            summaries += 1
            if offset != len(data):
                raise ValueError("heap snapshot summary is not the final record")
            continue
        if kind not in {_HEAP_CREATE, _HEAP_END, _HEAP_WRITE, _HEAP_PRE_WRITE}:
            raise ValueError(f"unsupported heap snapshot record kind {kind}")
        if object_id == 0 or object_size == 0 or address + object_size > 1 << 64:
            raise ValueError("invalid heap object identity or range")
        if kind == _HEAP_CREATE and (
            argument0 == 0
            or argument1 == 0
            or argument0 > ((1 << 64) - 1) // argument1
            or argument0 * argument1 != object_size
        ):
            raise ValueError("calloc arguments disagree with heap object extent")
        if kind == _HEAP_END and (
            caller_address != 0
            or caller_module_base != _HEAP_NO_MODULE
            or argument0 != 0
            or argument1 != 0
        ):
            raise ValueError("heap end record carries call arguments")
        if kind == _HEAP_WRITE and (argument0 > 255 or argument1 != object_size):
            raise ValueError("memset arguments disagree with heap write extent")
        if kind == _HEAP_PRE_WRITE and (
            argument0 > 255 or argument1 == 0 or caller_address == 0 or byte_len == 0
        ):
            raise ValueError("pre-write snapshot has malformed memset context")
        records.append(
            {
                "kind": kind,
                "provider_sequence": provider_sequence,
                "os_tid": os_tid,
                "object_id": object_id,
                "address": address,
                "caller_address": caller_address,
                "caller_module_base": caller_module_base,
                "object_size": object_size,
                "argument0": argument0,
                "argument1": argument1,
                "bytes": payload,
                "_stream_end_offset": stream_end_offset,
            }
        )
    if require_summary and summaries != 1:
        raise ValueError(f"expected one heap snapshot summary, found {summaries}")
    if not require_summary and summaries != 0:
        raise ValueError("heap snapshot prefix unexpectedly contains a summary")
    return records, dropped


def capture_heap_snapshots_child(
    executable: str | Path,
    interposer: str | Path,
    arguments: Sequence[str] = (),
    *,
    environment: Mapping[str, str] | None = None,
    timeout: float = 5.0,
    public_input: bytes | None = None,
) -> HeapSnapshotCapture:
    """Capture bounded ``calloc`` lifetimes from one launched Linux child.

    The exact caller-supplied interposer is hash-bound in provenance. Existing
    PIDs cannot be attached, allocator internals are not inspected, and raw
    provider records are normalized into the canonical capsule before return.
    """
    if sys.platform != "linux" or platform.machine().lower() not in {
        "x86_64",
        "amd64",
    }:
        raise OSError("heap snapshot acquisition currently requires Linux x86-64")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if environment is not None and {
        "LD_PRELOAD",
        "GLAURUNG_HEAP_SNAPSHOT_FD",
    }.intersection(environment):
        raise ValueError("provider environment variables are acquisition-owned")
    binary = Path(executable).resolve(strict=True)
    provider = Path(interposer).resolve(strict=True)
    binary_bytes = binary.read_bytes()
    provider_bytes = provider.read_bytes()
    temporary_root = Path(os.environ.get("TMPDIR", Path.home() / ".cache/glaurung/tmp"))
    temporary_root.mkdir(parents=True, exist_ok=True)
    child_env = os.environ.copy()
    if environment is not None:
        child_env.update(environment)
    child_env["LD_PRELOAD"] = str(provider)

    with tempfile.TemporaryDirectory(
        prefix="glaurung-heap-snapshot-", dir=temporary_root
    ) as directory:
        capture_dir = Path(directory)
        records_path = capture_dir / "heap-records.bin"
        stdout_path = capture_dir / "stdout.bin"
        stderr_path = capture_dir / "stderr.bin"
        records_fd = os.open(
            records_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        child_env["GLAURUNG_HEAP_SNAPSHOT_FD"] = str(records_fd)
        try:
            with (
                stdout_path.open("wb") as stdout_file,
                stderr_path.open("wb") as stderr_file,
            ):
                proc = subprocess.Popen(
                    [str(binary), *arguments],
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    cwd=capture_dir,
                    env=child_env,
                    pass_fds=(records_fd,),
                    start_new_session=True,
                )
                try:
                    return_code = proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired as error:
                    _terminate_owned_group(proc)
                    raise TimeoutError(
                        "heap-snapshot child did not terminate before timeout"
                    ) from error
                os_pid = proc.pid
        finally:
            os.close(records_fd)

        record_bytes = _bounded_file(records_path, _MAX_TRACE_BYTES, "heap records")
        stdout = _bounded_file(stdout_path, _MAX_PROCESS_OUTPUT_BYTES, "stdout")
        stderr = _bounded_file(stderr_path, _MAX_PROCESS_OUTPUT_BYTES, "stderr")
        raw_records, dropped = _parse_heap_snapshot_records(record_bytes)
        if dropped != 0:
            raise RuntimeError(f"heap snapshot provider dropped {dropped} record(s)")

        creates: dict[int, dict[str, object]] = {}
        ends: dict[int, dict[str, object]] = {}
        writes: list[dict[str, object]] = []
        for record in raw_records:
            object_id_value = record["object_id"]
            if not isinstance(object_id_value, int):
                raise TypeError("heap object ID is not an integer")
            object_id = object_id_value
            if record["kind"] == _HEAP_WRITE:
                writes.append(record)
                continue
            if record["kind"] == _HEAP_PRE_WRITE:
                continue
            target = creates if record["kind"] == _HEAP_CREATE else ends
            if object_id in target:
                raise ValueError(f"duplicate heap record for object {object_id}")
            target[object_id] = record
        if not set(ends).issubset(creates):
            raise ValueError("heap end record references an unknown object")
        for record in writes:
            object_id_value = record["object_id"]
            if not isinstance(object_id_value, int) or object_id_value not in creates:
                raise ValueError("heap write record references an unknown object")
        for object_id, ended in ends.items():
            created = creates[object_id]
            if (ended["address"], ended["object_size"]) != (
                created["address"],
                created["object_size"],
            ):
                raise ValueError(
                    f"heap object {object_id} changed identity before free"
                )

        process_id = "process-main"
        provider_threads = {
            int(record["os_tid"]): f"thread-provider-{int(record['os_tid']):016x}"
            for record in raw_records
        }

        def provider_thread_id(record: dict[str, object]) -> str:
            os_tid_value = record["os_tid"]
            if not isinstance(os_tid_value, int):
                raise TypeError("heap provider thread ID is not an integer")
            return provider_threads[os_tid_value]

        def provider_fields(record: dict[str, object]) -> dict[str, str]:
            return {
                "provider_sequence": str(record["provider_sequence"]),
                "provider_os_tid": str(record["os_tid"]),
            }

        events: list[dict[str, object]] = []
        runtime_objects: list[dict[str, object]] = []
        object_snapshots: list[dict[str, object]] = []
        payloads: list[tuple[str, bytes]] = []
        observed_write_count = sum(
            record["kind"] == _HEAP_WRITE for record in raw_records
        )
        event_sequence = 0
        lifecycle: dict[int, dict[str, int]] = {}
        for record in raw_records:
            object_id_value = record["object_id"]
            if not isinstance(object_id_value, int):
                raise TypeError("heap object ID is not an integer")
            object_id = object_id_value
            object_name = f"heap-object-{object_id:016x}"
            if record["kind"] == _HEAP_PRE_WRITE:
                event_sequence += 1
                payload_id = f"{object_name}-pre-write-{event_sequence:016x}"
                data = record["bytes"]
                assert isinstance(data, bytes)
                payloads.append((payload_id, data))
                events.append(
                    {
                        "process_id": process_id,
                        "thread_id": provider_thread_id(record),
                        "sequence": event_sequence,
                        "kind": "object_snapshot",
                        "address": record["address"],
                        "fields": {
                            "object_id": object_name,
                            "phase": "before_write",
                            **provider_fields(record),
                        },
                    }
                )
                object_snapshots.append(
                    {
                        "id": f"{object_name}-pre-write-{event_sequence:016x}",
                        "process_id": process_id,
                        "object_id": object_name,
                        "point": {
                            "thread_id": provider_thread_id(record),
                            "sequence": event_sequence,
                        },
                        "object_offset": 0,
                        "byte_len": len(data),
                        "content": {
                            "status": "captured",
                            "payload": {
                                "id": payload_id,
                                "sha256": _sha256(data),
                                "byte_len": len(data),
                                "sensitivity": "sensitive",
                            },
                        },
                    }
                )
                continue
            if record["kind"] == _HEAP_WRITE:
                caller_module_base = record["caller_module_base"]
                if not isinstance(caller_module_base, int):
                    raise TypeError("heap write module base is not an integer")
                event_sequence += 1
                write_bytes = record["bytes"]
                if not isinstance(write_bytes, bytes):
                    raise TypeError("heap write bytes are not bytes")
                payload_id = f"{object_name}-write-{event_sequence:016x}"
                if write_bytes:
                    payloads.append((payload_id, write_bytes))
                write_fields = {
                    "object_id": object_name,
                    "byte_len": str(record["object_size"]),
                    "provider": "memset_interposer",
                    "caller_return_va": str(record["caller_address"]),
                    "caller_main_module": str(
                        caller_module_base != _HEAP_NO_MODULE
                    ).lower(),
                    "caller_module_base": str(caller_module_base),
                    "fill_byte": str(record["argument0"]),
                    "requested_byte_len": str(record["argument1"]),
                    **provider_fields(record),
                }
                if write_bytes:
                    write_fields.update(
                        {
                            "write_bytes_payload_id": payload_id,
                            "write_bytes_sha256": _sha256(write_bytes),
                            "write_bytes_byte_len": str(len(write_bytes)),
                        }
                    )
                events.append(
                    {
                        "process_id": process_id,
                        "thread_id": provider_thread_id(record),
                        "sequence": event_sequence,
                        "kind": "memory_write",
                        "address": record["address"],
                        "fields": write_fields,
                    }
                )
                continue
            is_create = record["kind"] == _HEAP_CREATE
            if is_create:
                event_sequence += 1
                lifecycle.setdefault(object_id, {})["created"] = event_sequence
                events.append(
                    {
                        "process_id": process_id,
                        "thread_id": provider_thread_id(record),
                        "sequence": event_sequence,
                        "kind": "allocation",
                        "address": record["address"],
                        "fields": {
                            "object_id": object_name,
                            "byte_len": str(record["object_size"]),
                            "provider": "calloc_interposer",
                            "caller_return_va": str(record["caller_address"]),
                            "caller_main_module": str(
                                record["caller_module_base"] != _HEAP_NO_MODULE
                            ).lower(),
                            "caller_module_base": str(record["caller_module_base"]),
                            "calloc_count": str(record["argument0"]),
                            "calloc_element_size": str(record["argument1"]),
                            **provider_fields(record),
                        },
                    }
                )
            event_sequence += 1
            phase = "before" if is_create else "after"
            payload_id = f"{object_name}-{phase}"
            data = record["bytes"]
            assert isinstance(data, bytes)
            payloads.append((payload_id, data))
            events.append(
                {
                    "process_id": process_id,
                    "thread_id": provider_thread_id(record),
                    "sequence": event_sequence,
                    "kind": "object_snapshot",
                    "address": record["address"],
                    "fields": {
                        "object_id": object_name,
                        "phase": phase,
                        **provider_fields(record),
                    },
                }
            )
            object_snapshots.append(
                {
                    "id": f"{object_name}-{phase}",
                    "process_id": process_id,
                    "object_id": object_name,
                    "point": {
                        "thread_id": provider_thread_id(record),
                        "sequence": event_sequence,
                    },
                    "object_offset": 0,
                    "byte_len": len(data),
                    "content": {
                        "status": "captured",
                        "payload": {
                            "id": payload_id,
                            "sha256": _sha256(data),
                            "byte_len": len(data),
                            "sensitivity": "sensitive",
                        },
                    },
                }
            )
            if not is_create:
                event_sequence += 1
                lifecycle.setdefault(object_id, {})["ended"] = event_sequence
                events.append(
                    {
                        "process_id": process_id,
                        "thread_id": provider_thread_id(record),
                        "sequence": event_sequence,
                        "kind": "deallocation",
                        "address": record["address"],
                        "fields": {
                            "object_id": object_name,
                            "byte_len": str(record["object_size"]),
                            "provider": "calloc_interposer",
                            **provider_fields(record),
                        },
                    }
                )
        for object_id, created in sorted(creates.items()):
            object_name = f"heap-object-{object_id:016x}"
            positions = lifecycle[object_id]
            runtime_object: dict[str, object] = {
                "id": object_name,
                "process_id": process_id,
                "kind": "heap",
                "start": created["address"],
                "byte_len": created["object_size"],
                "created_at": {
                    "thread_id": provider_thread_id(created),
                    "sequence": positions["created"],
                },
            }
            if "ended" in positions:
                runtime_object["ended_at"] = {
                    "thread_id": provider_thread_id(ends[object_id]),
                    "sequence": positions["ended"],
                }
            runtime_objects.append(runtime_object)

        def artifact(data: bytes, path: Path) -> dict[str, object]:
            value: dict[str, object] = {
                "sha256": _sha256(data),
                "byte_len": len(data),
                "display_path": str(path),
            }
            build_id = runtime_analysis.elf_executable_build_id(data)
            if build_id is not None:
                value["build_id"] = build_id
            return value

        output_records = []
        for name, data in (("stdout", stdout), ("stderr", stderr)):
            payload_id = f"process-output-{name}"
            payloads.append((payload_id, data))
            output_records.append(
                {
                    "process_id": process_id,
                    "stream": name,
                    "payload": {
                        "id": payload_id,
                        "sha256": _sha256(data),
                        "byte_len": len(data),
                        "sensitivity": "sensitive",
                    },
                    "truncated": False,
                }
            )
        terminal = (
            {"kind": "exited", "code": return_code}
            if return_code >= 0
            else {"kind": "signaled", "signal": -return_code, "core_dumped": False}
        )
        captured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        capsule: dict[str, Any] = {
            "schema": "glaurung-process-capsule-v1",
            "version": 1,
            "identity": {
                "capture_id": "heap-trace-" + _sha256(record_bytes),
                "acquisition": "trace",
                "host_os": "linux",
                "kernel": platform.release(),
                "captured_at": captured_at,
            },
            "required_features": [],
            "target": {
                "architecture": "X86_64",
                "endianness": "Little",
                "address_bits": 64,
                "os_abi": "linux",
            },
            "executable": artifact(binary_bytes, binary),
            "processes": [{"id": process_id, "os_pid": os_pid, "terminal": terminal}],
            "modules": [],
            "mappings": [],
            "threads": [
                {
                    "id": thread_id,
                    "process_id": process_id,
                    "os_tid": provider_tid,
                    "registers": [],
                }
                for provider_tid, thread_id in sorted(provider_threads.items())
            ],
            "pages": [],
            "runtime_objects": runtime_objects,
            "object_snapshots": object_snapshots,
            "outputs": output_records,
            "descriptors": [],
            "events": events,
            "provenance": {
                "producer": "glaurung-python-heap-snapshot",
                "producer_version": "1",
                "command": ["heap-snapshot", "--", str(binary)],
                "input_artifacts": [
                    artifact(binary_bytes, binary),
                    artifact(provider_bytes, provider),
                ],
                "input_bytes": (
                    []
                    if public_input is None
                    else [
                        {
                            "name": "argv[1]",
                            "sha256": _sha256(public_input),
                            "byte_len": len(public_input),
                            "sensitivity": "public",
                        }
                    ]
                ),
                "warnings": [],
            },
            "completeness": [
                {
                    "evidence": "heap_object_lifetimes",
                    "status": "complete",
                    "requested": True,
                    "obtained": len(runtime_objects),
                    "expected": len(runtime_objects),
                },
                {
                    "evidence": "heap_object_snapshots",
                    "status": "complete",
                    "requested": True,
                    "obtained": len(object_snapshots),
                    "expected": len(object_snapshots),
                },
                {
                    "evidence": "heap_object_writes",
                    "status": "complete",
                    "requested": True,
                    "obtained": observed_write_count,
                    "expected": observed_write_count,
                },
            ],
            "provider.heap_snapshot": {
                "artifact_sha256": _sha256(provider_bytes),
                "record_sha256": _sha256(record_bytes),
                "record_byte_len": len(record_bytes),
                "max_object_bytes": 256,
                "dropped_records": dropped,
                "allocator_scope": ["calloc", "free"],
                "write_scope": ["memset"],
            },
        }
        canonical = runtime_analysis.canonicalize_process_capsule_json(
            json.dumps(capsule, separators=(",", ":"), ensure_ascii=False)
        )
        return HeapSnapshotCapture(canonical, tuple(payloads))


def capture_instruction_trace_child(
    executable: str | Path,
    arguments: Sequence[str] = (),
    *,
    environment: Mapping[str, str] | None = None,
    cwd: str | Path | None = None,
    timeout: float = 5.0,
    max_steps: int = _MAX_INSTRUCTION_TRACE_STEPS,
    public_input: bytes | None = None,
    public_paths: Sequence[str] = (),
    capture_heap_timeline: bool = False,
    heap_interposer: str | Path | None = None,
) -> InstructionTraceCapture:
    """Single-step one owned child between cooperative trace checkpoints.

    The child opts in with ``GLAURUNG_RUNTIME_TRACE_BEGIN`` and
    ``GLAURUNG_RUNTIME_TRACE_END``. The provider records bounded instruction
    transitions and stack-byte changes; it never accepts an existing PID.
    ``heap_interposer`` adds one fail-closed allocation/write/free chain to the
    same capsule and event stream. It is mutually exclusive with the generic
    heap-mapping timeline because those representations overlap.
    """
    if sys.platform != "linux" or platform.machine().lower() not in {
        "x86_64",
        "amd64",
    }:
        raise OSError("instruction tracing currently requires Linux x86-64")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if not isinstance(max_steps, int) or isinstance(max_steps, bool):
        raise TypeError("max_steps must be an integer")
    if not 1 <= max_steps <= _MAX_INSTRUCTION_TRACE_STEPS:
        raise ValueError(
            f"max_steps must be between 1 and {_MAX_INSTRUCTION_TRACE_STEPS}"
        )
    if len(public_paths) > 256 or len(set(public_paths)) != len(public_paths):
        raise ValueError("public paths must be unique and bounded")
    if any(not path or "\x00" in path for path in public_paths):
        raise ValueError("public paths must be non-empty and contain no NUL")
    if capture_heap_timeline and heap_interposer is not None:
        raise ValueError(
            "capture_heap_timeline and heap_interposer are mutually exclusive"
        )
    binary = Path(executable).resolve(strict=True)
    binary_bytes = binary.read_bytes()
    binary_sha256 = _sha256(binary_bytes)
    binary_build_id = runtime_analysis.elf_executable_build_id(binary_bytes)
    child_env = os.environ.copy()
    if (
        environment is not None
        and heap_interposer is not None
        and {
            "LD_PRELOAD",
            "GLAURUNG_HEAP_SNAPSHOT_FD",
        }.intersection(environment)
    ):
        raise ValueError("provider environment variables are acquisition-owned")
    if environment is not None:
        child_env.update(environment)
    provider_path = (
        Path(heap_interposer).resolve(strict=True)
        if heap_interposer is not None
        else None
    )
    provider_bytes = provider_path.read_bytes() if provider_path is not None else None
    temporary_root = Path(os.environ.get("TMPDIR", Path.home() / ".cache/glaurung/tmp"))
    temporary_root.mkdir(parents=True, exist_ok=True)
    provider_file = (
        tempfile.TemporaryFile(dir=temporary_root)
        if provider_path is not None
        else None
    )
    if provider_path is not None and provider_file is not None:
        child_env["LD_PRELOAD"] = str(provider_path)
        child_env["GLAURUNG_HEAP_SNAPSHOT_FD"] = str(provider_file.fileno())
    child_env["GLAURUNG_RUNTIME_TRACE_BEGIN"] = "1"
    child_env["GLAURUNG_RUNTIME_TRACE_END"] = "1"
    if capture_heap_timeline or provider_path is not None:
        child_env["GLAURUNG_RUNTIME_POST_TRACE"] = "1"
    trace_sequence_base = 2 if provider_path is not None else 0
    try:
        proc = subprocess.Popen(
            [str(binary), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=child_env,
            pass_fds=(() if provider_file is None else (provider_file.fileno(),)),
            start_new_session=True,
        )
    except BaseException:
        if provider_file is not None:
            provider_file.close()
        raise
    attached = False
    try:
        if _wait_stopped(proc.pid, timeout) != signal.SIGSTOP:
            raise RuntimeError("trace begin checkpoint did not use SIGSTOP")
        provider_begin_byte_len = (
            os.fstat(provider_file.fileno()).st_size
            if provider_file is not None
            else None
        )
        checkpoint_heap_identity: tuple[int, int, int] | None = None
        checkpoint_heap_before: bytes | None = None
        checkpoint_heap_trace_end: bytes | None = None
        checkpoint_heap_post: bytes | None = None
        if provider_file is not None and provider_begin_byte_len is not None:
            begin_record_bytes = os.pread(
                provider_file.fileno(), provider_begin_byte_len, 0
            )
            begin_records, begin_dropped = _parse_heap_snapshot_records(
                begin_record_bytes, require_summary=False
            )
            begin_creates = [
                record
                for record in begin_records
                if record["kind"] == _HEAP_CREATE
                and record["caller_module_base"] != _HEAP_NO_MODULE
            ]
            if begin_dropped != 0 or len(begin_creates) != 1:
                raise RuntimeError(
                    "combined heap trace requires one main-module object at trace begin"
                )
            begin_created = begin_creates[0]
            if begin_created["os_tid"] != proc.pid:
                raise RuntimeError(
                    "combined heap-provider event belongs to another thread"
                )
            begin_object_size = int(begin_created["object_size"])
            if not 0 < begin_object_size <= 256:
                raise RuntimeError(
                    "combined heap object exceeds the checkpoint snapshot budget"
                )
            checkpoint_heap_identity = (
                int(begin_created["object_id"]),
                int(begin_created["address"]),
                begin_object_size,
            )
            checkpoint_heap_before = _process_vm_read(
                proc.pid,
                checkpoint_heap_identity[1],
                checkpoint_heap_identity[2],
            )
        captured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        maps_text = _read_proc_file(proc.pid, "maps").decode(errors="strict")
        mappings, executable_mapping_ids = _parse_maps(
            maps_text,
            process_id="process-main",
            executable=binary,
            executable_sha256=binary_sha256,
            backing_artifacts={},
        )
        if not executable_mapping_ids:
            raise RuntimeError(
                "instruction trace did not identify the exact executable"
            )
        descriptors, descriptors_truncated = _descriptor_records(
            proc.pid, "process-main", public_paths
        )
        stack_mappings = [
            mapping
            for mapping in mappings
            if mapping["backing"] == {"kind": "special", "name": "[stack]"}
        ]
        if len(stack_mappings) != 1:
            raise RuntimeError("instruction trace requires one stack mapping")
        heap_mappings = [
            mapping
            for mapping in mappings
            if mapping["backing"] == {"kind": "special", "name": "[heap]"}
        ]
        if capture_heap_timeline and len(heap_mappings) != 1:
            raise RuntimeError("heap timeline requires one heap mapping")
        heap_mapping = heap_mappings[0] if capture_heap_timeline else None
        stack_mapping = stack_mappings[0]
        stack_mapping_start = stack_mapping.get("start")
        stack_mapping_end = stack_mapping.get("end")
        stack_mapping_id = stack_mapping.get("id")
        if (
            not isinstance(stack_mapping_start, int)
            or isinstance(stack_mapping_start, bool)
            or not isinstance(stack_mapping_end, int)
            or isinstance(stack_mapping_end, bool)
            or not isinstance(stack_mapping_id, str)
            or stack_mapping_start >= stack_mapping_end
        ):
            raise RuntimeError("instruction trace stack mapping is malformed")

        _ptrace(_PTRACE_ATTACH, proc.pid)
        attached = True
        _wait_ptrace_stop(proc.pid, timeout)
        registers = _X86_64Registers()
        _ptrace(_PTRACE_GETREGS, proc.pid, ctypes.byref(registers))
        stack_start = int(registers.rsp)
        stack_end = min(
            stack_mapping_end,
            stack_start + _INSTRUCTION_TRACE_STACK_BYTES,
        )
        if not stack_mapping_start <= stack_start < stack_end:
            raise RuntimeError("trace checkpoint stack pointer is outside its mapping")
        before_stack = _process_vm_read(proc.pid, stack_start, stack_end - stack_start)
        before_heap: bytes | None = None
        middle_heap: bytes | None = None
        after_heap: bytes | None = None
        heap_mapping_start: int | None = None
        heap_mapping_end: int | None = None
        heap_mapping_id: str | None = None
        if heap_mapping is not None:
            heap_start_value = heap_mapping.get("start")
            heap_end_value = heap_mapping.get("end")
            heap_id_value = heap_mapping.get("id")
            if (
                not isinstance(heap_start_value, int)
                or isinstance(heap_start_value, bool)
                or not isinstance(heap_end_value, int)
                or isinstance(heap_end_value, bool)
                or not isinstance(heap_id_value, str)
                or not 0
                < heap_end_value - heap_start_value
                <= _INSTRUCTION_TRACE_HEAP_BYTES
            ):
                raise RuntimeError("heap timeline mapping exceeds acquisition budget")
            heap_mapping_start = heap_start_value
            heap_mapping_end = heap_end_value
            heap_mapping_id = heap_id_value
            before_heap = _process_vm_read(
                proc.pid, heap_mapping_start, heap_mapping_end - heap_mapping_start
            )
        previous_stack = before_stack
        input_location_fields: dict[str, str] = {"phase": "trace_begin"}
        input_runtime_address: int | None = None
        if public_input is not None:
            input_runtime_address = _proc_argv_location(proc.pid, 1, public_input)
            input_location_fields.update(
                {
                    "input_source_name": "argv[1]",
                    "input_runtime_address": str(input_runtime_address),
                    "input_byte_len": str(len(public_input)),
                    "input_sha256": _sha256(public_input),
                    "input_location_provider": "linux_proc_stat_argument_bounds",
                }
            )
        events: list[dict[str, object]] = [
            {
                "process_id": "process-main",
                "thread_id": "thread-trace",
                "sequence": trace_sequence_base,
                "kind": "capture_checkpoint",
                "fields": input_location_fields,
            }
        ]
        change_payloads: list[tuple[str, bytes]] = []
        register_steps: list[dict[str, object]] = []
        observed_steps = 0
        pending_begin_stop = True
        endpoint_stack: bytes | None = None
        deadline = time.monotonic() + timeout
        while observed_steps < max_steps and time.monotonic() < deadline:
            before_rip = int(registers.rip)
            before_registers = {
                name: f"{getattr(registers, name):016x}"
                for name in _X86_64_REGISTER_NAMES
            }
            instruction_prefix = _process_vm_read(proc.pid, before_rip, 1)
            _ptrace(_PTRACE_SINGLESTEP, proc.pid)
            remaining = max(deadline - time.monotonic(), 0.001)
            stop_signal = _wait_ptrace_stop(proc.pid, remaining)
            _ptrace(_PTRACE_GETREGS, proc.pid, ctypes.byref(registers))
            after_rip = int(registers.rip)
            current_stack = _process_vm_read(
                proc.pid, stack_start, stack_end - stack_start
            )
            if pending_begin_stop and stop_signal == signal.SIGSTOP:
                pending_begin_stop = False
                previous_stack = current_stack
                continue
            pending_begin_stop = False
            if stop_signal == signal.SIGSTOP:
                endpoint_stack = current_stack
                break
            if stop_signal != signal.SIGTRAP:
                raise RuntimeError(
                    f"instruction trace observed unsupported stop signal {stop_signal}"
                )
            observed_steps += 1
            intervals: list[dict[str, object]] = []
            index = 0
            while index < len(current_stack):
                if previous_stack[index] == current_stack[index]:
                    index += 1
                    continue
                start = index
                while (
                    index < len(current_stack)
                    and previous_stack[index] != current_stack[index]
                ):
                    index += 1
                intervals.append(
                    {
                        "start": stack_start + start,
                        "end": stack_start + index,
                        "before_hex": previous_stack[start:index].hex(),
                        "after_hex": current_stack[start:index].hex(),
                    }
                )
            fields: dict[str, str] = {
                "after_address": str(after_rip),
                "step_ordinal": str(observed_steps - 1),
            }
            if instruction_prefix == b"\xe8":
                fields["control_transfer"] = "direct_call"
            if intervals:
                change_bytes = json.dumps(
                    {
                        "schema": "glaurung-instruction-step-evidence-v1",
                        "changes": intervals,
                        "registers": before_registers,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                change_payload_id = f"instruction-step-changes-{observed_steps:06d}"
                fields.update(
                    {
                        "stack_changes_payload_id": change_payload_id,
                        "stack_changes_sha256": _sha256(change_bytes),
                        "stack_changes_byte_len": str(len(change_bytes)),
                        "stack_changes_sensitivity": "sensitive",
                    }
                )
                change_payloads.append((change_payload_id, change_bytes))
            events.append(
                {
                    "process_id": "process-main",
                    "thread_id": "thread-trace",
                    "sequence": trace_sequence_base + observed_steps,
                    "kind": "instruction_step",
                    "address": before_rip,
                    "fields": fields,
                }
            )
            register_steps.append(
                {
                    "sequence": trace_sequence_base + observed_steps,
                    "address": before_rip,
                    "registers": before_registers,
                }
            )
            previous_stack = current_stack
        else:
            raise RuntimeError("instruction trace exhausted its step or time budget")

        final_sequence = trace_sequence_base + observed_steps + 1
        events.append(
            {
                "process_id": "process-main",
                "thread_id": "thread-trace",
                "sequence": final_sequence,
                "kind": "capture_checkpoint",
                "fields": {"phase": "trace_end"},
            }
        )
        if endpoint_stack is None:
            raise RuntimeError("instruction trace has no end-checkpoint stack state")
        provider_trace_end_byte_len = (
            os.fstat(provider_file.fileno()).st_size
            if provider_file is not None
            else None
        )
        if checkpoint_heap_identity is not None:
            checkpoint_heap_trace_end = _process_vm_read(
                proc.pid,
                checkpoint_heap_identity[1],
                checkpoint_heap_identity[2],
            )
        after_stack = endpoint_stack
        if heap_mapping_start is not None and heap_mapping_end is not None:
            middle_heap = _process_vm_read(
                proc.pid, heap_mapping_start, heap_mapping_end - heap_mapping_start
            )
        register_trace_bytes = json.dumps(
            {
                "schema": "glaurung-instruction-register-trace-v1",
                "steps": register_steps,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        register_trace_payload_id = "instruction-register-trace"
        final_stack_pointer = int(registers.rsp)
        final_stack_byte_len = stack_mapping_end - final_stack_pointer
        if not 0 < final_stack_byte_len <= _MAX_CHECKPOINT_STACK_BYTES:
            raise RuntimeError("trace end stack extent exceeds acquisition budget")
        final_stack_page = _process_vm_read(
            proc.pid, final_stack_pointer, final_stack_byte_len
        )
        _ptrace(_PTRACE_DETACH, proc.pid)
        attached = False
        os.killpg(proc.pid, signal.SIGCONT)
        post_sequence = final_sequence
        provider_post_byte_len: int | None = None
        if capture_heap_timeline or provider_path is not None:
            if _wait_stopped(proc.pid, timeout) != signal.SIGSTOP:
                raise RuntimeError("post-trace checkpoint did not use SIGSTOP")
            if provider_file is not None:
                provider_post_byte_len = os.fstat(provider_file.fileno()).st_size
            if checkpoint_heap_identity is not None:
                checkpoint_heap_post = _process_vm_read(
                    proc.pid,
                    checkpoint_heap_identity[1],
                    checkpoint_heap_identity[2],
                )
            if capture_heap_timeline:
                if heap_mapping_start is None or heap_mapping_end is None:
                    raise RuntimeError("heap timeline lost its mapping identity")
                current_maps = _read_proc_file(proc.pid, "maps").decode(errors="strict")
                current_mappings, _ = _parse_maps(
                    current_maps,
                    process_id="process-main",
                    executable=binary,
                    executable_sha256=binary_sha256,
                    backing_artifacts={},
                )
                if not any(
                    mapping.get("start") == heap_mapping_start
                    and mapping.get("end") == heap_mapping_end
                    and mapping.get("backing") == {"kind": "special", "name": "[heap]"}
                    for mapping in current_mappings
                ):
                    raise RuntimeError(
                        "heap mapping changed before post-trace checkpoint"
                    )
                after_heap = _process_vm_read(
                    proc.pid, heap_mapping_start, heap_mapping_end - heap_mapping_start
                )
            post_sequence += 3 if provider_path is not None else 1
            events.append(
                {
                    "process_id": "process-main",
                    "thread_id": "thread-trace",
                    "sequence": post_sequence,
                    "kind": "capture_checkpoint",
                    "fields": {"phase": "post_trace"},
                }
            )
            os.killpg(proc.pid, signal.SIGCONT)
        stdout, stderr = proc.communicate(timeout=timeout)
        if (
            len(stdout) > _MAX_PROCESS_OUTPUT_BYTES
            or len(stderr) > _MAX_PROCESS_OUTPUT_BYTES
        ):
            raise RuntimeError(
                "instruction-traced child output exceeds acquisition budget"
            )
        terminal = (
            {"kind": "exited", "code": proc.returncode}
            if proc.returncode is not None and proc.returncode >= 0
            else {
                "kind": "signaled",
                "signal": -int(proc.returncode),
                "core_dumped": False,
            }
        )
        provider_records: list[dict[str, Any]] = []
        provider_record_bytes = b""
        if provider_file is not None:
            provider_file.flush()
            provider_file.seek(0)
            provider_record_bytes = provider_file.read(_MAX_TRACE_BYTES + 1)
            if len(provider_record_bytes) > _MAX_TRACE_BYTES:
                raise RuntimeError(
                    "combined heap-provider records exceed acquisition budget"
                )
            provider_records, provider_dropped = _parse_heap_snapshot_records(
                provider_record_bytes
            )
            if provider_dropped != 0:
                raise RuntimeError(
                    f"combined heap provider dropped {provider_dropped} record(s)"
                )
        artifact: dict[str, object] = {
            "sha256": binary_sha256,
            "byte_len": len(binary_bytes),
            "display_path": str(binary),
        }
        if binary_build_id is not None:
            artifact["build_id"] = binary_build_id
        object_id = "object-instruction-trace-stack-mapping"
        before_payload_id = "instruction-trace-stack-before"
        after_payload_id = "instruction-trace-stack-after"
        page_payload_id = "instruction-trace-final-stack-page"
        snapshots = []
        for snapshot_id, payload_id, sequence, data in (
            ("snapshot-instruction-trace-before", before_payload_id, 0, before_stack),
            (
                "snapshot-instruction-trace-after",
                after_payload_id,
                final_sequence,
                after_stack,
            ),
        ):
            snapshots.append(
                {
                    "id": snapshot_id,
                    "process_id": "process-main",
                    "object_id": object_id,
                    "point": {"thread_id": "thread-trace", "sequence": sequence},
                    "object_offset": stack_start - stack_mapping_start,
                    "byte_len": len(data),
                    "content": {
                        "status": "captured",
                        "payload": {
                            "id": payload_id,
                            "sha256": _sha256(data),
                            "byte_len": len(data),
                            "sensitivity": "sensitive",
                        },
                    },
                }
            )
        runtime_objects = [
            {
                "id": object_id,
                "process_id": "process-main",
                "mapping_id": stack_mapping_id,
                "kind": "mapping",
                "start": stack_mapping_start,
                "byte_len": stack_mapping_end - stack_mapping_start,
                "created_at": {"thread_id": "thread-trace", "sequence": 0},
            }
        ]
        input_snapshot_payloads: list[tuple[str, bytes]] = []
        if (
            public_input is not None
            and input_runtime_address is not None
            and not (
                stack_start <= input_runtime_address
                and input_runtime_address + len(public_input) <= stack_end
            )
        ):
            input_object_id = "object-instruction-trace-argv-1"
            input_payload_id = "instruction-trace-argv-1-before"
            runtime_objects.append(
                {
                    "id": input_object_id,
                    "process_id": "process-main",
                    "mapping_id": stack_mapping_id,
                    "kind": "stack",
                    "start": input_runtime_address,
                    "byte_len": len(public_input),
                    "created_at": {"thread_id": "thread-trace", "sequence": 0},
                }
            )
            snapshots.append(
                {
                    "id": "snapshot-instruction-trace-argv-1-before",
                    "process_id": "process-main",
                    "object_id": input_object_id,
                    "point": {"thread_id": "thread-trace", "sequence": 0},
                    "object_offset": 0,
                    "byte_len": len(public_input),
                    "content": {
                        "status": "captured",
                        "payload": {
                            "id": input_payload_id,
                            "sha256": _sha256(public_input),
                            "byte_len": len(public_input),
                            "sensitivity": "public",
                        },
                    },
                }
            )
            input_snapshot_payloads.append((input_payload_id, public_input))
        heap_payloads: list[tuple[str, bytes]] = []
        if (
            before_heap is not None
            and middle_heap is not None
            and after_heap is not None
            and heap_mapping_start is not None
            and heap_mapping_end is not None
            and heap_mapping_id is not None
        ):
            heap_object_id = "object-instruction-trace-heap-mapping"
            runtime_objects.append(
                {
                    "id": heap_object_id,
                    "process_id": "process-main",
                    "mapping_id": heap_mapping_id,
                    "kind": "mapping",
                    "start": heap_mapping_start,
                    "byte_len": heap_mapping_end - heap_mapping_start,
                    "created_at": {"thread_id": "thread-trace", "sequence": 0},
                }
            )
            for phase, sequence, data in (
                ("before", 0, before_heap),
                ("after_store", final_sequence, middle_heap),
                ("after_write", post_sequence, after_heap),
            ):
                payload_id = f"instruction-trace-heap-{phase}"
                snapshot_id = f"snapshot-instruction-trace-heap-{phase}"
                heap_payloads.append((payload_id, data))
                snapshots.append(
                    {
                        "id": snapshot_id,
                        "process_id": "process-main",
                        "object_id": heap_object_id,
                        "point": {
                            "thread_id": "thread-trace",
                            "sequence": sequence,
                        },
                        "object_offset": 0,
                        "byte_len": len(data),
                        "content": {
                            "status": "captured",
                            "payload": {
                                "id": payload_id,
                                "sha256": _sha256(data),
                                "byte_len": len(data),
                                "sensitivity": "sensitive",
                            },
                        },
                    }
                )
        provider_payloads: list[tuple[str, bytes]] = []
        combined_provider: dict[str, object] | None = None
        if provider_path is not None:
            main_creates = [
                record
                for record in provider_records
                if record["kind"] == _HEAP_CREATE
                and record["caller_module_base"] != _HEAP_NO_MODULE
            ]
            if len(main_creates) != 1:
                raise RuntimeError(
                    "combined heap trace requires one complete main-module object chain"
                )
            created = main_creates[0]
            related = [
                record
                for record in provider_records
                if record["object_id"] == created["object_id"]
            ]
            pre_writes = [
                record for record in related if record["kind"] == _HEAP_PRE_WRITE
            ]
            writes = [record for record in related if record["kind"] == _HEAP_WRITE]
            ends = [record for record in related if record["kind"] == _HEAP_END]
            if not (
                len(ends) == 1
                and len(pre_writes) == len(writes)
                and len(writes) <= 1
                and len(related) == 2 + 2 * len(writes)
                and all(
                    record["caller_module_base"] != _HEAP_NO_MODULE
                    for record in [*pre_writes, *writes]
                )
            ):
                raise RuntimeError(
                    "combined heap trace requires one complete main-module object chain"
                )
            pre_write = pre_writes[0] if pre_writes else None
            write = writes[0] if writes else None
            ended = ends[0]
            if any(record["os_tid"] != proc.pid for record in related):
                raise RuntimeError(
                    "combined heap-provider event belongs to another thread"
                )
            if (
                provider_begin_byte_len is None
                or provider_trace_end_byte_len is None
                or provider_post_byte_len is None
            ):
                raise RuntimeError("combined heap-provider phase evidence is missing")
            created_end = int(created["_stream_end_offset"])
            ended_end = int(ended["_stream_end_offset"])
            if not (
                created_end <= provider_begin_byte_len
                and provider_begin_byte_len == provider_trace_end_byte_len
                and provider_post_byte_len < ended_end
            ):
                raise RuntimeError(
                    "combined heap-provider events do not match checkpoint phases"
                )
            if write is not None and pre_write is not None:
                pre_write_end = int(pre_write["_stream_end_offset"])
                write_end = int(write["_stream_end_offset"])
                if not (
                    provider_trace_end_byte_len
                    < pre_write_end
                    <= provider_post_byte_len
                    and provider_trace_end_byte_len
                    < write_end
                    <= provider_post_byte_len
                ):
                    raise RuntimeError(
                        "combined heap-provider events do not match checkpoint phases"
                    )
            provider_order = [created, *pre_writes, *writes, ended]
            if any(
                int(left["provider_sequence"]) >= int(right["provider_sequence"])
                for left, right in zip(provider_order, provider_order[1:])
            ):
                raise RuntimeError(
                    "combined heap-provider object order is inconsistent"
                )
            if any(
                (created["address"], created["object_size"])
                != (record["address"], record["object_size"])
                for record in [*pre_writes, ended]
            ):
                raise RuntimeError("combined heap-provider object identity changed")
            object_start = int(created["address"])
            object_end = object_start + int(created["object_size"])
            if any(
                int(record["address"]) < object_start
                or int(record["address"]) + int(record["object_size"]) > object_end
                for record in writes
            ):
                raise RuntimeError(
                    "combined heap-provider write exceeds its runtime object"
                )
            if checkpoint_heap_identity != (
                int(created["object_id"]),
                int(created["address"]),
                int(created["object_size"]),
            ) or any(
                data is None
                for data in (
                    checkpoint_heap_before,
                    checkpoint_heap_trace_end,
                    checkpoint_heap_post,
                )
            ):
                raise RuntimeError(
                    "combined heap checkpoint snapshots lost object identity"
                )
            provider_object_id = f"heap-object-{int(created['object_id']):016x}"
            runtime_objects.append(
                {
                    "id": provider_object_id,
                    "process_id": "process-main",
                    "kind": "heap",
                    "start": created["address"],
                    "byte_len": created["object_size"],
                    "created_at": {"thread_id": "thread-trace", "sequence": 0},
                    "ended_at": {
                        "thread_id": "thread-trace",
                        "sequence": post_sequence + 2,
                    },
                }
            )

            def provider_fields(record: dict[str, object]) -> dict[str, str]:
                return {
                    "provider_sequence": str(record["provider_sequence"]),
                    "provider_os_tid": str(record["os_tid"]),
                    "provider_stream_end_offset": str(record["_stream_end_offset"]),
                }

            events.extend(
                [
                    {
                        "process_id": "process-main",
                        "thread_id": "thread-trace",
                        "sequence": 0,
                        "kind": "allocation",
                        "address": created["address"],
                        "fields": {
                            "object_id": provider_object_id,
                            "byte_len": str(created["object_size"]),
                            "provider": "calloc_interposer",
                            "caller_return_va": str(created["caller_address"]),
                            "caller_main_module": "true",
                            "caller_module_base": str(created["caller_module_base"]),
                            "calloc_count": str(created["argument0"]),
                            "calloc_element_size": str(created["argument1"]),
                            **provider_fields(created),
                        },
                    },
                    {
                        "process_id": "process-main",
                        "thread_id": "thread-trace",
                        "sequence": post_sequence + 2,
                        "kind": "deallocation",
                        "address": ended["address"],
                        "fields": {
                            "object_id": provider_object_id,
                            "byte_len": str(ended["object_size"]),
                            "provider": "calloc_interposer",
                            **provider_fields(ended),
                        },
                    },
                ]
            )
            if write is not None:
                write_bytes = write["bytes"]
                assert isinstance(write_bytes, bytes)
                events.append(
                    {
                        "process_id": "process-main",
                        "thread_id": "thread-trace",
                        "sequence": final_sequence + 2,
                        "kind": "memory_write",
                        "address": write["address"],
                        "fields": {
                            "object_id": provider_object_id,
                            "byte_len": str(write["object_size"]),
                            "provider": "memset_interposer",
                            "caller_return_va": str(write["caller_address"]),
                            "caller_main_module": "true",
                            "caller_module_base": str(write["caller_module_base"]),
                            "fill_byte": str(write["argument0"]),
                            "requested_byte_len": str(write["argument1"]),
                            "write_bytes_payload_id": "combined-heap-write",
                            "write_bytes_sha256": _sha256(write_bytes),
                            "write_bytes_byte_len": str(len(write_bytes)),
                            **provider_fields(write),
                        },
                    }
                )
                provider_payloads.append(("combined-heap-write", write_bytes))
            for snapshot_id, payload_id, sequence, data in (
                (
                    "combined-heap-trace-begin",
                    "combined-heap-trace-begin",
                    trace_sequence_base,
                    checkpoint_heap_before,
                ),
                (
                    "combined-heap-trace-end",
                    "combined-heap-trace-end",
                    final_sequence,
                    checkpoint_heap_trace_end,
                ),
                (
                    "combined-heap-post-trace",
                    "combined-heap-post-trace",
                    post_sequence,
                    checkpoint_heap_post,
                ),
            ):
                assert isinstance(data, bytes)
                provider_payloads.append((payload_id, data))
                snapshots.append(
                    {
                        "id": snapshot_id,
                        "process_id": "process-main",
                        "object_id": provider_object_id,
                        "point": {"thread_id": "thread-trace", "sequence": sequence},
                        "object_offset": 0,
                        "byte_len": len(data),
                        "content": {
                            "status": "captured",
                            "payload": {
                                "id": payload_id,
                                "sha256": _sha256(data),
                                "byte_len": len(data),
                                "sensitivity": "sensitive",
                            },
                        },
                    }
                )
            combined_provider = {
                "artifact_sha256": _sha256(provider_bytes or b""),
                "record_sha256": _sha256(provider_record_bytes),
                "record_byte_len": len(provider_record_bytes),
                "thread_id": "thread-trace",
                "record_scope": (
                    "one complete main-module object chain with zero or one write"
                ),
                "phase_byte_lengths": {
                    "trace_begin": provider_begin_byte_len,
                    "trace_end": provider_trace_end_byte_len,
                    "post_trace": provider_post_byte_len,
                    "terminal": len(provider_record_bytes),
                },
            }
            events.sort(
                key=lambda event: (
                    str(event.get("thread_id", "")),
                    int(cast(int, event["sequence"])),
                )
            )
        input_artifacts = [artifact]
        if provider_path is not None and provider_bytes is not None:
            provider_artifact: dict[str, object] = {
                "sha256": _sha256(provider_bytes),
                "byte_len": len(provider_bytes),
                "display_path": str(provider_path),
            }
            provider_build_id = runtime_analysis.elf_executable_build_id(provider_bytes)
            if provider_build_id is not None:
                provider_artifact["build_id"] = provider_build_id
            input_artifacts.append(provider_artifact)
        capsule = {
            "schema": "glaurung-process-capsule-v1",
            "version": 1,
            "identity": {
                "capture_id": f"trace-{_sha256(binary_sha256.encode() + before_stack + provider_record_bytes)}",
                "acquisition": "trace",
                "host_os": "linux",
                "kernel": platform.release(),
                "captured_at": captured_at,
            },
            "required_features": [],
            "target": {
                "architecture": "X86_64",
                "endianness": "Little",
                "address_bits": 64,
                "os_abi": "linux",
            },
            "executable": artifact,
            "processes": [
                {"id": "process-main", "os_pid": proc.pid, "terminal": terminal}
            ],
            "modules": [
                {
                    "id": "module-main",
                    "process_id": "process-main",
                    "artifact": artifact,
                    "mapping_ids": executable_mapping_ids,
                }
            ],
            "mappings": mappings,
            "threads": [
                {
                    "id": "thread-trace",
                    "process_id": "process-main",
                    "os_tid": proc.pid,
                    "registers": [
                        {
                            "provider_name": name,
                            "bit_width": 64,
                            "value_hex": f"{getattr(registers, name):016x}",
                        }
                        for name in _X86_64_REGISTER_NAMES
                    ],
                }
            ],
            "pages": [
                {
                    "process_id": "process-main",
                    "mapping_id": stack_mapping_id,
                    "start": final_stack_pointer,
                    "byte_len": len(final_stack_page),
                    "content": {
                        "status": "captured",
                        "payload": {
                            "id": page_payload_id,
                            "sha256": _sha256(final_stack_page),
                            "byte_len": len(final_stack_page),
                            "sensitivity": "sensitive",
                        },
                    },
                }
            ],
            "runtime_objects": runtime_objects,
            "object_snapshots": snapshots,
            "outputs": [],
            "descriptors": descriptors,
            "events": events,
            "provenance": {
                "producer": "glaurung.runtime_capture.capture_instruction_trace_child",
                "producer_version": "1",
                "command": [str(binary), *arguments],
                "input_artifacts": input_artifacts,
                "input_bytes": (
                    []
                    if public_input is None
                    else [
                        {
                            "name": "argv[1]",
                            "sha256": _sha256(public_input),
                            "byte_len": len(public_input),
                            "sensitivity": "public",
                        }
                    ]
                ),
                "warnings": [],
            },
            "completeness": [
                {
                    "evidence": "instruction_steps",
                    "status": "complete",
                    "requested": True,
                    "obtained": observed_steps,
                    "expected": observed_steps,
                },
                {
                    "evidence": "trace_stack_snapshots",
                    "status": "complete",
                    "requested": True,
                    "obtained": 2,
                    "expected": 2,
                },
                {
                    "evidence": "trace_heap_timeline",
                    "status": "complete" if capture_heap_timeline else "unknown",
                    "reason": None if capture_heap_timeline else "not requested",
                    "requested": capture_heap_timeline,
                    "obtained": 3 if capture_heap_timeline else 0,
                    "expected": 3 if capture_heap_timeline else 0,
                },
                {
                    "evidence": "combined_heap_provider",
                    "status": "complete"
                    if combined_provider is not None
                    else "unknown",
                    "reason": None
                    if combined_provider is not None
                    else "not requested",
                    "requested": provider_path is not None,
                    "obtained": 1 if combined_provider is not None else 0,
                    "expected": 1 if provider_path is not None else 0,
                },
                {
                    "evidence": "trace_final_stack_page",
                    "status": "complete",
                    "requested": True,
                    "obtained": 1,
                    "expected": 1,
                },
                {
                    "evidence": "instruction_step_change_payloads",
                    "status": "complete",
                    "requested": True,
                    "obtained": len(change_payloads),
                    "expected": len(change_payloads),
                },
                {
                    "evidence": "instruction_step_registers",
                    "status": "complete",
                    "requested": True,
                    "obtained": len(register_steps),
                    "expected": observed_steps,
                },
                {
                    "evidence": "descriptors",
                    "status": "truncated" if descriptors_truncated else "raced",
                    "reason": (
                        f"descriptor count exceeded {_MAX_DESCRIPTORS}"
                        if descriptors_truncated
                        else "procfs descriptor enumeration is not atomic"
                    ),
                    "requested": True,
                    "obtained": len(descriptors),
                },
                {
                    "evidence": "runtime_state",
                    "status": "partial",
                    "reason": (
                        "trace captures one thread, executable and stack mappings, "
                        "final registers/page, and bounded stack changes only"
                    ),
                    "requested": True,
                    "obtained": len(mappings) + observed_steps + 3,
                },
            ],
            "provider.ptrace_single_step": {
                "max_steps": max_steps,
                "observed_steps": observed_steps,
                "stack_window_start": stack_start,
                "stack_window_byte_len": len(before_stack),
                "scope": "owned cooperative child",
                "register_trace": {
                    "payload_id": register_trace_payload_id,
                    "sha256": _sha256(register_trace_bytes),
                    "byte_len": len(register_trace_bytes),
                    "sensitivity": "sensitive",
                    "step_count": len(register_steps),
                },
            },
            **(
                {"provider.heap_snapshot": combined_provider}
                if combined_provider is not None
                else {}
            ),
        }
        canonical = runtime_analysis.canonicalize_process_capsule_json(
            json.dumps(capsule, separators=(",", ":"), ensure_ascii=False)
        )
        return InstructionTraceCapture(
            capsule_json=canonical,
            payloads=(
                (before_payload_id, before_stack),
                (after_payload_id, after_stack),
                (page_payload_id, final_stack_page),
                (register_trace_payload_id, register_trace_bytes),
                *input_snapshot_payloads,
                *change_payloads,
                *heap_payloads,
                *provider_payloads,
            ),
        )
    except subprocess.TimeoutExpired as error:
        raise TimeoutError("instruction-traced child did not terminate") from error
    finally:
        if attached:
            try:
                _ptrace(_PTRACE_DETACH, proc.pid)
            except OSError:
                pass
        if provider_file is not None:
            provider_file.close()
        _terminate_owned_group(proc)


def capture_stopped_child(
    executable: str | Path,
    arguments: Sequence[str] = (),
    *,
    environment: Mapping[str, str] | None = None,
    cwd: str | Path | None = None,
    timeout: float = 5.0,
    checkpoint: str = "requested",
    public_input: bytes | None = None,
    allow_proc_mem_fallback: bool = False,
    inherit_environment: bool = False,
) -> StoppedChildCapture:
    """Launch, capture, and terminate one child that cooperatively stops itself.

    The child must deliver ``SIGSTOP`` to itself. Glaurung starts it in a new
    process group and only signals that owned group during cleanup. Existing
    PIDs cannot be supplied or attached to this API. The caller environment is
    not inherited unless ``inherit_environment`` is explicitly enabled.
    """
    if sys.platform != "linux" or platform.machine().lower() not in {
        "x86_64",
        "amd64",
    }:
        raise OSError("stopped-child acquisition currently requires Linux x86-64")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if not isinstance(inherit_environment, bool):
        raise TypeError("inherit_environment must be a boolean")
    binary = Path(executable).resolve(strict=True)
    binary_bytes = binary.read_bytes()
    binary_sha256 = _sha256(binary_bytes)
    binary_build_id = runtime_analysis.elf_executable_build_id(binary_bytes)
    child_env = os.environ.copy() if inherit_environment else {}
    if environment is not None:
        child_env.update(environment)
    proc = subprocess.Popen(
        [str(binary), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=cwd,
        env=child_env,
        start_new_session=True,
    )
    try:
        stop_signal = _wait_stopped(proc.pid, timeout)
        captured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        process_id = "process-main"
        proc_files = {name: _read_proc_file(proc.pid, name) for name in _PROC_FILES}
        maps_before = proc_files["maps"]
        tids_before = _thread_ids(proc.pid)
        registers, register_failures = _capture_thread_registers(tids_before, timeout)
        descriptors, descriptors_truncated = _descriptor_records(proc.pid, process_id)
        backing_artifacts, backing_failures, backing_sources = (
            _capture_backing_artifacts(
                proc.pid, maps_before.decode(errors="replace"), binary
            )
        )
        mappings, executable_mapping_ids = _parse_maps(
            maps_before.decode(errors="replace"),
            process_id=process_id,
            executable=binary,
            executable_sha256=binary_sha256,
            backing_artifacts=backing_artifacts,
        )
        if not executable_mapping_ids:
            raise ValueError("capture did not identify an exact executable mapping")
        pages, payloads, page_reads = _capture_selected_pages(
            proc.pid,
            process_id,
            mappings,
            registers,
            allow_proc_mem_fallback=allow_proc_mem_fallback,
        )
        maps_after = _read_proc_file(proc.pid, "maps")
        tids_after = _thread_ids(proc.pid)
        artifact: dict[str, object] = {
            "sha256": binary_sha256,
            "byte_len": len(binary_bytes),
            "display_path": str(binary),
        }
        if binary_build_id is not None:
            artifact["build_id"] = binary_build_id
        captured_modules = []
        captured_artifact_records = []
        for captured in backing_artifacts.values():
            module_id = captured["module_id"]
            assert isinstance(module_id, str)
            captured_artifact = {
                key: value for key, value in captured.items() if key != "module_id"
            }
            mapping_ids = [
                str(mapping["id"])
                for mapping in mappings
                if mapping.get("module_id") == module_id
            ]
            captured_modules.append(
                {
                    "id": module_id,
                    "process_id": process_id,
                    "artifact": captured_artifact,
                    "mapping_ids": mapping_ids,
                }
            )
            captured_artifact_records.append(captured_artifact)
        mappings_stable = maps_before == maps_after
        threads_stable = tids_before == tids_after
        disappeared_tids = sorted(set(tids_before) - set(tids_after))
        appeared_tids = sorted(set(tids_after) - set(tids_before))
        acquisition_outcomes = {
            "proc_files": {
                name: {"status": "captured", "byte_len": len(data)}
                for name, data in sorted(proc_files.items())
            },
            "registers": {
                str(tid): (
                    {
                        "status": _failure_status(register_failures[tid]),
                        "detail": register_failures[tid],
                    }
                    if tid in register_failures
                    else {"status": "captured", "count": len(registers[tid])}
                )
                for tid in tids_before
            },
            "pages": page_reads,
            "module_backings": {
                **{
                    identity: {
                        "status": _failure_status(detail),
                        "detail": detail,
                    }
                    for identity, detail in sorted(backing_failures.items())
                },
                **{
                    identity: {
                        "status": "captured",
                        "source": source,
                        **(
                            {"prior_attempt_status": _failure_status(source)}
                            if "after map_files failure" in source
                            else {}
                        ),
                    }
                    for identity, source in sorted(backing_sources.items())
                },
            },
            "mapping_revalidation": {
                "status": "complete" if mappings_stable else "raced",
                "before_sha256": _sha256(maps_before),
                "after_sha256": _sha256(maps_after),
            },
            "thread_revalidation": {
                "status": "complete" if threads_stable else "raced",
                "disappeared_tids": disappeared_tids,
                "appeared_tids": appeared_tids,
            },
            "descriptors": {
                "status": "truncated" if descriptors_truncated else "raced",
                "obtained": len(descriptors),
            },
        }
        input_bytes = []
        if public_input is not None:
            input_bytes.append(
                {
                    "name": "controlled-input",
                    "sha256": _sha256(public_input),
                    "byte_len": len(public_input),
                    "sensitivity": "public",
                }
            )
        capture_seed = b"\0".join(
            (binary_sha256.encode(), str(proc.pid).encode(), proc_files["stat"])
        )
        capsule = {
            "schema": "glaurung-process-capsule-v1",
            "version": 1,
            "identity": {
                "capture_id": f"live-{_sha256(capture_seed)}",
                "acquisition": "live",
                "host_os": "linux",
                "kernel": platform.release(),
                "captured_at": captured_at,
            },
            "required_features": [],
            "target": {
                "architecture": "X86_64",
                "endianness": "Little",
                "address_bits": 64,
                "os_abi": "linux",
            },
            "executable": artifact,
            "processes": [
                {"id": process_id, "os_pid": proc.pid, "terminal": {"kind": "running"}}
            ],
            "modules": [
                {
                    "id": "module-main",
                    "process_id": process_id,
                    "artifact": artifact,
                    "mapping_ids": executable_mapping_ids,
                },
                *captured_modules,
            ],
            "mappings": mappings,
            "threads": [
                {
                    "id": f"thread-{tid}",
                    "process_id": process_id,
                    "os_tid": tid,
                    "registers": registers.get(tid, []),
                }
                for tid in tids_before
            ],
            "pages": pages,
            "outputs": [],
            "descriptors": descriptors,
            "events": [],
            "provenance": {
                "producer": "glaurung.runtime_capture.capture_stopped_child",
                "producer_version": "1",
                "command": [],
                "input_artifacts": [artifact, *captured_artifact_records],
                "input_bytes": input_bytes,
                "warnings": [],
            },
            "completeness": [
                {
                    "evidence": "mappings",
                    "status": "complete" if mappings_stable else "raced",
                    "reason": None
                    if mappings_stable
                    else "maps changed during capture",
                    "requested": True,
                    "obtained": len(mappings),
                    "expected": len(mappings),
                },
                {
                    "evidence": "module_backings",
                    "status": "complete" if not backing_failures else "partial",
                    "reason": (
                        None
                        if not backing_failures
                        else "one or more executable file backings were unavailable"
                    ),
                    "requested": True,
                    "obtained": len(backing_artifacts) + 1,
                    "expected": len(backing_artifacts) + len(backing_failures) + 1,
                },
                {
                    "evidence": "threads",
                    "status": "complete" if threads_stable else "raced",
                    "reason": None
                    if threads_stable
                    else "thread set changed during capture",
                    "requested": True,
                    "obtained": len(tids_before),
                    "expected": len(tids_before),
                },
                {
                    "evidence": "registers",
                    "status": "complete" if not register_failures else "partial",
                    "reason": (
                        None
                        if not register_failures
                        else "one or more stopped threads could not be read with ptrace"
                    ),
                    "requested": True,
                    "obtained": sum(len(values) for values in registers.values()),
                    "expected": len(tids_before) * len(_X86_64_REGISTER_NAMES),
                },
                {
                    "evidence": "pages",
                    "status": (
                        "omitted"
                        if not pages
                        else "complete"
                        if len(payloads) == len(pages)
                        else "partial"
                    ),
                    "reason": (
                        "no captured register resolved to a mapped PC/SP page"
                        if not pages
                        else None
                        if len(payloads) == len(pages)
                        else "one or more selected PC/SP pages were unavailable"
                    ),
                    "requested": True,
                    "obtained": len(payloads),
                    "expected": len(pages),
                },
                {
                    "evidence": "descriptors",
                    "status": "truncated" if descriptors_truncated else "raced",
                    "reason": (
                        f"descriptor count exceeded {_MAX_DESCRIPTORS}"
                        if descriptors_truncated
                        else "procfs descriptor enumeration is not atomic"
                    ),
                    "requested": True,
                    "obtained": len(descriptors),
                },
            ],
            "provider.procfs": {
                "checkpoint": checkpoint,
                "checkpoint_signal": stop_signal,
                "register_failures": {
                    str(tid): reason
                    for tid, reason in sorted(register_failures.items())
                },
                "page_reads": page_reads,
                "backing_failures": backing_failures,
                "backing_sources": backing_sources,
                "acquisition_outcomes": acquisition_outcomes,
                "files": {
                    name: {"size": len(data), "sha256": _sha256(data)}
                    for name, data in sorted(proc_files.items())
                },
            },
        }
        capsule_json = runtime_analysis.canonicalize_process_capsule_json(
            json.dumps(capsule, separators=(",", ":"), ensure_ascii=False)
        )
        return StoppedChildCapture(capsule_json=capsule_json, payloads=tuple(payloads))
    finally:
        _terminate_owned_group(proc)
