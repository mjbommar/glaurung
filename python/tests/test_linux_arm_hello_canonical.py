"""Canonical C recovery across hosted Linux ARM Hello World layouts."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import glaurung as g
import pytest

from glaurung.tools.build_flirt_library import build_library_from_archive


EXPECTED = """// glaurung: main @ {va:#x}
int main(void) {{
    extern int puts(const char *);
    puts("Hello, World!");
    return 0;
}}
"""

TARGETS = {
    "aarch64": ("aarch64-linux-gnu-gcc", "aarch64-linux-gnu-strip"),
    "armv7": ("arm-linux-gnueabihf-gcc", "arm-linux-gnueabihf-strip"),
}


def _tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        pytest.skip(f"{name} unavailable")
    return path


def _build_hello(
    tmp_path: Path,
    target: str,
    optimization: str,
    linkage: str,
    stripped: bool,
) -> Path:
    compiler_name, strip_name = TARGETS[target]
    compiler = _tool(compiler_name)
    source = tmp_path / "hello.c"
    binary = tmp_path / "hello"
    source.write_text(
        '#include <stdio.h>\nint main(void) { puts("Hello, World!"); return 0; }\n'
    )
    flags = {
        "pie": ["-fPIE", "-pie"],
        "nonpie": ["-fno-pie", "-no-pie"],
        "static": ["-static"],
    }[linkage]
    built = subprocess.run(
        [compiler, f"-{optimization}", *flags, "-o", str(binary), str(source)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr
    if stripped:
        stripped_result = subprocess.run(
            [_tool(strip_name), "--strip-all", str(binary)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert stripped_result.returncode == 0, stripped_result.stderr
    return binary


def _assert_canonical(binary: Path) -> None:
    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=2000)
    main = next((function for function in functions if function.name == "main"), None)
    assert main is not None, [function.name for function in functions]
    va = int(main.entry_point.value)
    recovered = g.ir.decompile_at(str(binary), va, style="decbench")
    assert recovered == EXPECTED.format(va=va)


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("optimization", ["O0", "O1", "O2", "O3"])
@pytest.mark.parametrize("linkage", ["pie", "nonpie"])
@pytest.mark.parametrize("stripped", [False, True], ids=["symbols", "stripped"])
def test_dynamic_hello_is_canonical(
    tmp_path: Path,
    target: str,
    optimization: str,
    linkage: str,
    stripped: bool,
) -> None:
    """Both ARM ABIs must converge on one source program."""
    _assert_canonical(
        _build_hello(tmp_path, target, optimization, linkage, stripped)
    )


@pytest.fixture(scope="module", params=TARGETS)
def cross_libc_signatures(
    request: pytest.FixtureRequest,
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[str, Path]:
    """Build signatures from each cross-toolchain's exact static libc."""
    target = str(request.param)
    compiler_name, _ = TARGETS[target]
    compiler = _tool(compiler_name)
    query = subprocess.run(
        [compiler, "-print-file-name=libc.a"],
        capture_output=True,
        text=True,
        check=False,
    )
    archive = Path(query.stdout.strip())
    if query.returncode != 0 or not archive.is_file():
        pytest.skip(f"{target} static libc unavailable")
    library = build_library_from_archive(
        archive,
        library_name="glibc",
        version="cross-toolchain",
        variant=target,
        arch=target,
    )
    output = tmp_path_factory.mktemp(f"glibc-signatures-{target}") / "libc.json"
    output.write_text(json.dumps(library))
    return target, output


@pytest.mark.slow
@pytest.mark.parametrize("optimization", ["O0", "O2"])
def test_stripped_static_hello_is_canonical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cross_libc_signatures: tuple[str, Path],
    optimization: str,
) -> None:
    """Unwind boundaries and archive signatures recover copied libc calls."""
    target, signatures = cross_libc_signatures
    monkeypatch.setenv("GLAURUNG_FLIRT_LIB", str(signatures))
    binary = _build_hello(tmp_path, target, optimization, "static", True)
    _assert_canonical(binary)
