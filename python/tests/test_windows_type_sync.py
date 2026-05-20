"""Tests for generated Windows API type/prototype synchronization."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from glaurung.types import sync as win_sync


def test_windows_api_source_lock_is_well_formed() -> None:
    data = json.loads(win_sync.DEFAULT_LOCK_PATH.read_text())
    sources = win_sync._package_sources(data)
    assert {source.source_id for source in sources} == {
        "microsoft-win32metadata",
        "microsoft-wdkmetadata",
    }
    for source in sources:
        assert source.version
        assert source.nupkg_url.startswith("https://api.nuget.org/v3-flatcontainer/")
        assert source.nupkg_sha256
        assert source.winmd_path.endswith(".winmd")

    optional = data["optional_sources"]
    assert optional["headers"]["status"] == "augmentation_source"
    assert optional["pdb_symbol_server"]["url"].endswith("/download/symbols")
    assert {entry["id"] for entry in optional["supplemental"]} >= {
        "phnt-system-informer",
        "reactos",
        "wine",
    }


def test_overlay_adds_prototypes_and_semantics(tmp_path: Path) -> None:
    overlay = {
        "source": "test-overlay",
        "source_kind": "curated_overlay",
        "prototype_overrides": [
            {
                "name": "strcpy_s",
                "return_type": "errno_t",
                "params": [
                    {"name": "dst", "c_type": "char *", "role": "buffer"},
                    {"name": "dstsz", "c_type": "rsize_t", "role": "length"},
                    {"name": "src", "c_type": "const char *", "role": "source"},
                ],
            }
        ],
        "semantics": [
            {
                "name": "strcpy_s",
                "api_class": "bounded_copy",
                "roles": {"dst": "buffer", "src": "source"},
            }
        ],
    }
    overlay_path = tmp_path / "overlay.json"
    overlay_path.write_text(json.dumps(overlay), encoding="utf-8")
    prototypes: dict[str, dict] = {}

    summary = win_sync._apply_overlay(prototypes, overlay, overlay_path)

    assert summary["prototype_added"] == 1
    assert summary["semantics_attached"] == 1
    proto = prototypes["strcpy_s"]
    assert proto["params"][0]["role"] == "buffer"
    assert proto["semantics"]["api_class"] == "bounded_copy"


def test_header_source_parses_clang_ast(tmp_path: Path) -> None:
    if shutil.which("clang") is None:
        pytest.skip("clang is required for header augmentation")

    header = tmp_path / "sample.h"
    header.write_text(
        "typedef unsigned long DWORD;\n"
        "typedef void * HANDLE;\n"
        "DWORD HeaderOnlyThing(HANDLE hDevice, const char *name);\n",
        encoding="utf-8",
    )
    result = win_sync._sync_header_source(header, clang="clang", clang_args=[])
    prototypes: dict[str, dict] = {}

    win_sync._merge_header_prototypes(
        prototypes,
        result["prototypes"],
        header=header,
        header_sha256=result["header_sha256"],
        confidence=result["confidence"],
    )

    proto = prototypes["headeronlything"]
    assert proto["name"] == "HeaderOnlyThing"
    assert proto["return_type"] == "DWORD"
    assert proto["params"][0] == {"name": "hDevice", "c_type": "HANDLE"}
    assert proto["params"][1] == {"name": "name", "c_type": "const char *"}
    assert proto["source_kind"] == "clang_header_ast"


def test_checked_in_generated_manifest_matches_bundle() -> None:
    manifest = json.loads(
        (win_sync.DEFAULT_GENERATED_DIR / "MANIFEST.json").read_text()
    )
    bundle = json.loads(win_sync.DEFAULT_OUTPUT_PATH.read_text())

    assert manifest["analysis_network_policy"].startswith("offline by default")
    assert manifest["prototype_count"] == len(bundle["prototypes"])
    assert manifest["bundle_sha256"] == win_sync._sha256_file(
        win_sync.DEFAULT_OUTPUT_PATH
    )
    assert manifest["prototype_count"] >= 20_000


def test_real_nuget_sync_smoke(tmp_path: Path) -> None:
    if os.environ.get("GLAURUNG_RUN_NETWORK_TESTS") != "1":
        pytest.skip("set GLAURUNG_RUN_NETWORK_TESTS=1 for real NuGet metadata sync")

    manifest = win_sync.sync_windows_api_types(
        output_path=tmp_path / "stdlib-winapi-protos.json",
        generated_dir=tmp_path / "generated",
        cache_dir=tmp_path / "cache",
    )
    bundle = json.loads((tmp_path / "stdlib-winapi-protos.json").read_text())
    names = {proto["name"] for proto in bundle["prototypes"]}

    assert manifest["prototype_count"] >= 20_000
    assert {"CreateFileW", "DeviceIoControl", "NtCreateFile", "strcpy_s"} <= names
