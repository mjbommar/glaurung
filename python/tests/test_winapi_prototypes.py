"""Tests for the Win32 API prototype bundle (#198)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


_HELLO = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)
_PE_HELLO = Path(
    "samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64/hello-c-x86_64-mingw.exe"
)
_BUNDLE = Path("data/types/stdlib-winapi-protos.json")


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing path {p}")
    return p


def test_winapi_bundle_file_is_well_formed() -> None:
    p = _need(_BUNDLE)
    data = json.loads(p.read_text())
    assert data["bundle_name"] == "stdlib-winapi-protos"
    assert data["set_by"] == "stdlib"
    assert data["generated"] is True
    assert isinstance(data["prototypes"], list)
    # Every prototype has the required fields.
    for proto in data["prototypes"]:
        assert proto.get("name"), f"prototype without name: {proto}"
        assert proto.get("return_type"), f"{proto['name']} missing return_type"
        assert isinstance(proto.get("params", []), list)
    # Must hit the canonical malware-relevant surface area.
    names = {p["name"] for p in data["prototypes"]}
    expected = {
        # process injection trinity
        "CreateRemoteThread",
        "VirtualAllocEx",
        "WriteProcessMemory",
        # persistence
        "RegOpenKeyExA",
        "RegSetValueExA",
        "CreateServiceA",
        # network C2
        "WinHttpOpen",
        "WinHttpConnect",
        "WinHttpSendRequest",
        # file I/O
        "CreateFileA",
        "ReadFile",
        "WriteFile",
        "DeviceIoControl",
        # syscall trampolines
        "NtCreateFile",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        # curated kernel / CRT sink modelling
        "strcpy_s",
        "strnlen",
        "ExAllocatePoolWithTag",
        "ProbeForRead",
        # crypto
        "CryptAcquireContextA",
        "CryptEncrypt",
        "CryptDecrypt",
    }
    missing = expected - names
    assert not missing, f"WinAPI bundle missing essential prototypes: {missing}"


def test_pe_auto_load_imports_winapi_bundle(tmp_path: Path) -> None:
    """PE projects should auto-load the WinAPI bundle alongside libc."""
    binary = _need(_PE_HELLO)
    db = tmp_path / "winapi.glaurung"
    kb = PersistentKnowledgeBase.open(
        db,
        binary_path=binary,
        auto_load_stdlib=True,
    )
    # Spot-check Win32 prototypes are present.
    create_process = xref_db.get_function_prototype(kb, "CreateProcessA")
    assert create_process is not None
    assert create_process.return_type == "BOOL"
    # First param of CreateProcessA is lpApplicationName: a string pointer.
    assert create_process.params[0].name == "lpApplicationName"
    assert create_process.params[0].c_type in {"PSTR", "PCSTR", "LPCSTR"}

    # WinHttpOpen — wide-char API.
    winhttp = xref_db.get_function_prototype(kb, "WinHttpOpen")
    assert winhttp is not None
    assert winhttp.return_type == "HINTERNET"
    assert winhttp.params[0].c_type == "LPCWSTR"

    # NtCreateFile — syscall trampoline.
    nt = xref_db.get_function_prototype(kb, "NtCreateFile")
    assert nt is not None
    assert nt.return_type == "NTSTATUS"
    assert any("OBJECT_ATTRIBUTES" in p.c_type for p in nt.params)

    strcpy = xref_db.get_function_prototype(kb, "strcpy_s")
    assert strcpy is not None
    assert strcpy.params[0].name == "destinationBuffer"
    assert strcpy.params[1].c_type == "rsize_t"

    pool = xref_db.get_function_prototype(kb, "ExAllocatePoolWithTag")
    assert pool is not None
    assert pool.return_type == "PVOID"
    assert pool.params[1].name == "NumberOfBytes"

    # libc protos still load alongside.
    assert xref_db.get_function_prototype(kb, "printf") is not None
    loaded = {
        (row["bundle_kind"], row["bundle_name"])
        for row in PersistentKnowledgeBase.list_stdlib_bundle_loads(kb)
    }
    assert ("prototype", "stdlib-libc-protos") in loaded
    assert ("prototype", "stdlib-winapi-protos") in loaded
    kb.close()


def test_explicit_winapi_only_load(tmp_path: Path) -> None:
    """`bundles=["stdlib-winapi-protos"]` loads ONLY Win32 protos —
    no libc."""
    binary = _need(_HELLO)
    db = tmp_path / "winapi-only.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    summary = xref_db.import_stdlib_prototypes(
        kb,
        bundles=["stdlib-winapi-protos"],
    )
    bs = summary.get("stdlib-winapi-protos", {})
    assert bs.get("prototypes", 0) >= 20_000, f"expected ≥20k protos, got {bs}"

    assert xref_db.get_function_prototype(kb, "CreateFileA") is not None
    assert xref_db.get_function_prototype(kb, "ProbeForRead") is not None
    assert xref_db.get_function_prototype(kb, "printf") is None  # libc not loaded
    kb.close()


def test_winapi_semantics_survive_kb_import(tmp_path: Path) -> None:
    """Phase-A roadmap guard: Windows API metadata must survive the
    stdlib import path, not collapse to just name/return/param types."""
    binary = _need(_HELLO)
    db = tmp_path / "winapi-semantics.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.import_stdlib_prototypes(kb, bundles=["stdlib-winapi-protos"])

    device_io = xref_db.get_function_prototype(kb, "DeviceIoControl")
    assert device_io is not None
    assert device_io.module == "KERNEL32.dll"
    assert device_io.calling_convention == "system"
    assert device_io.source == "microsoft-win32metadata"
    assert device_io.source_kind == "nuget_winmd"
    assert device_io.source_package == "Microsoft.Windows.SDK.Win32Metadata"
    assert device_io.confidence is not None
    assert abs(device_io.confidence - 0.99) < 0.0001
    assert device_io.provenance["source_id"] == "microsoft-win32metadata"
    assert device_io.semantics["api_class"] == "ioctl_boundary"
    assert "ioctl" in device_io.risk_tags
    assert device_io.param_by_name("lpInBuffer").role == "source"
    assert device_io.param_by_name("nInBufferSize").role == "length"

    strcpy = xref_db.get_function_prototype(kb, "strcpy_s")
    assert strcpy is not None
    assert strcpy.module == "ucrtbase.dll"
    assert strcpy.param_by_name("destinationBuffer").role == "buffer"
    assert strcpy.param_by_name("numberOfElements").role == "length"
    assert strcpy.param_by_name("source").role == "source"
    assert "bounds_sensitive" in strcpy.risk_tags

    probe = xref_db.get_function_prototype(kb, "ProbeForRead")
    assert probe is not None
    assert probe.module == "ntoskrnl.exe"
    assert probe.semantics["api_class"] == "user_pointer_probe"
    assert probe.param_by_role("length").name == "Length"

    allocator = xref_db.get_function_prototype(kb, "ExAllocatePoolWithTag")
    assert allocator is not None
    assert allocator.semantics["api_class"] == "kernel_allocator"
    assert allocator.param_by_name("Tag").role == "tag"

    protect = xref_db.get_function_prototype(kb, "NtProtectVirtualMemory")
    assert protect is not None
    assert protect.param_by_name("BaseAddress").role == "buffer"
    assert protect.param_by_name("RegionSize").role == "length"
    assert protect.semantics["api_class"] == "native_memory_protection"
    assert "memory_protection" in protect.risk_tags

    remote_alloc = xref_db.get_function_prototype(kb, "VirtualAllocEx")
    assert remote_alloc is not None
    assert remote_alloc.semantics["api_class"] == "process_memory_allocation"
    assert remote_alloc.param_by_name("dwSize").role == "length"
    assert "process_injection" in remote_alloc.risk_tags

    process_write = xref_db.get_function_prototype(kb, "WriteProcessMemory")
    assert process_write is not None
    assert process_write.semantics["api_class"] == "process_memory_write"
    assert process_write.param_by_name("lpBuffer").role == "source"
    assert "cross_process_write" in process_write.risk_tags

    ioctl_protos = xref_db.list_function_prototypes_by_risk_tag(kb, "ioctl")
    assert {p.function_name for p in ioctl_protos} >= {"DeviceIoControl"}
    injection_protos = xref_db.list_function_prototypes_by_risk_tag(
        kb, "process_injection"
    )
    assert {p.function_name for p in injection_protos} >= {
        "CreateRemoteThread",
        "VirtualAllocEx",
        "WriteProcessMemory",
    }
    length_role_protos = xref_db.list_function_prototypes_by_param_role(kb, "length")
    length_names = {p.function_name for p in length_role_protos}
    assert {"DeviceIoControl", "ProbeForRead", "ExAllocatePoolWithTag"} <= length_names

    semantics = xref_db.get_function_semantics(kb, "DeviceIoControl")
    assert semantics is not None
    assert semantics["roles"]["lpOutBuffer"] == "buffer"
    kb.close()
