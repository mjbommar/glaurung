"""Real-binary integration coverage for the reusable decompiler session."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import glaurung as g
import pytest


def _build_fixture(tmp_path: Path) -> tuple[Path, int]:
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("gcc is unavailable")
    source = tmp_path / "session.c"
    binary = tmp_path / "session.so"
    source.write_text(
        "__attribute__((noinline)) int session_target(int x) { return x + 7; }\n"
    )
    built = subprocess.run(
        [compiler, "-shared", "-fPIC", "-g", "-O0", "-o", str(binary), str(source)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr
    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=32)
    target = next(
        function for function in functions if function.name == "session_target"
    )
    return binary, int(target.entry_point.value)


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_session_reuses_exact_discovery_without_changing_output(tmp_path: Path) -> None:
    """Two identical queries reuse discovery and remain output-identical."""
    binary, address = _build_fixture(tmp_path)

    session = g.ir.DecompilerSession(str(binary))
    first = session.decompile_at(address, style="decbench")
    c_style = session.decompile_at(address, style="c")
    second = session.decompile_at(address, style="decbench")
    standalone = g.ir.decompile_at(str(binary), address, style="decbench")

    assert first == second == standalone
    assert c_style != first
    assert session.path == str(binary)
    assert session.discovery_cache_stats == {
        "entries": 1,
        "evictions": 0,
        "hits": 1,
        "misses": 1,
    }
    assert session.artifact_cache_stats == {
        "entries": 2,
        "evictions": 0,
        "hits": 1,
        "misses": 2,
    }
    session.clear_caches()
    assert session.discovery_cache_stats == {
        "entries": 0,
        "evictions": 0,
        "hits": 0,
        "misses": 0,
    }
    assert session.artifact_cache_stats == {
        "entries": 0,
        "evictions": 0,
        "hits": 0,
        "misses": 0,
    }


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_diagnostics_bypass_rendered_artifact_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,  # ty: ignore[unresolved-attribute]
) -> None:
    """A diagnostic request must execute the pipeline and emit fresh evidence."""
    binary, address = _build_fixture(tmp_path)
    session = g.ir.DecompilerSession(str(binary))
    monkeypatch.setenv("GLAURUNG_PASS_HEALTH", "1")

    first = session.decompile_at(address, style="decbench")
    second = session.decompile_at(address, style="decbench")

    assert first == second
    assert session.artifact_cache_stats == {
        "entries": 0,
        "evictions": 0,
        "hits": 0,
        "misses": 0,
    }
    assert session.discovery_cache_stats == {
        "entries": 1,
        "evictions": 0,
        "hits": 1,
        "misses": 1,
    }


def test_session_rejects_an_unparseable_image(tmp_path: Path) -> None:
    """Construction fails before retaining a session for invalid input."""
    invalid = tmp_path / "not-an-object"
    invalid.write_bytes(b"not an object")

    with pytest.raises(  # ty: ignore[unresolved-attribute]
        ValueError, match="image parse failed"
    ):
        g.ir.DecompilerSession(str(invalid))
