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
        "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
        # persistence
        "RegOpenKeyExA", "RegSetValueExA", "CreateServiceA",
        # network C2
        "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
        # file I/O
        "CreateFileA", "ReadFile", "WriteFile",
        # syscall trampolines
        "NtCreateFile", "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
        # crypto
        "CryptAcquireContextA", "CryptEncrypt", "CryptDecrypt",
    }
    missing = expected - names
    assert not missing, f"WinAPI bundle missing essential prototypes: {missing}"


def test_winapi_bundle_imports_via_persistent_open(tmp_path: Path) -> None:
    """Auto-loading stdlib bundles on KB open must include the WinAPI
    prototype bundle alongside the libc one."""
    binary = _need(_HELLO)
    db = tmp_path / "winapi.glaurung"
    kb = PersistentKnowledgeBase.open(
        db, binary_path=binary, auto_load_stdlib=True,
    )
    # Spot-check Win32 prototypes are present.
    create_process = xref_db.get_function_prototype(kb, "CreateProcessA")
    assert create_process is not None
    assert create_process.return_type == "BOOL"
    # First param of CreateProcessA is lpApplicationName: LPCSTR.
    assert create_process.params[0].name == "lpApplicationName"
    assert create_process.params[0].c_type == "LPCSTR"

    # WinHttpOpen — wide-char API.
    winhttp = xref_db.get_function_prototype(kb, "WinHttpOpen")
    assert winhttp is not None
    assert winhttp.return_type == "HINTERNET"
    assert winhttp.params[0].c_type == "LPCWSTR"

    # NtCreateFile — syscall trampoline.
    nt = xref_db.get_function_prototype(kb, "NtCreateFile")
    assert nt is not None
    assert nt.return_type == "NTSTATUS"
    assert any(p.c_type == "POBJECT_ATTRIBUTES" for p in nt.params)

    # libc protos still load alongside.
    assert xref_db.get_function_prototype(kb, "printf") is not None
    kb.close()


def test_explicit_winapi_only_load(tmp_path: Path) -> None:
    """`bundles=["stdlib-winapi-protos"]` loads ONLY Win32 protos —
    no libc."""
    binary = _need(_HELLO)
    db = tmp_path / "winapi-only.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    summary = xref_db.import_stdlib_prototypes(
        kb, bundles=["stdlib-winapi-protos"],
    )
    bs = summary.get("stdlib-winapi-protos", {})
    assert bs.get("prototypes", 0) >= 100, f"expected ≥100 protos, got {bs}"

    assert xref_db.get_function_prototype(kb, "CreateFileA") is not None
    assert xref_db.get_function_prototype(kb, "printf") is None  # libc not loaded
    kb.close()
