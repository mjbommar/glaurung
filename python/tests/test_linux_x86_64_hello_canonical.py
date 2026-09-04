"""Canonical C recovery across the native x86-64 Hello World matrix."""

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


def _build_hello(
    tmp_path: Path,
    compiler: str,
    optimization: str,
    linkage: str,
    stripped: bool,
) -> Path:
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
        strip = shutil.which("strip")
        assert strip is not None
        stripped_result = subprocess.run(
            [strip, "--strip-all", str(binary)],
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


@pytest.mark.parametrize("compiler_name", ["gcc", "clang"])
@pytest.mark.parametrize("optimization", ["O0", "O1", "O2", "O3"])
@pytest.mark.parametrize("linkage", ["pie", "nonpie"])
@pytest.mark.parametrize("stripped", [False, True], ids=["symbols", "stripped"])
def test_dynamic_hello_is_canonical(
    tmp_path: Path,
    compiler_name: str,
    optimization: str,
    linkage: str,
    stripped: bool,
) -> None:
    """All ordinary hosted layouts must converge on one source program."""
    compiler = shutil.which(compiler_name)
    if compiler is None:
        pytest.skip(f"{compiler_name} unavailable")
    _assert_canonical(_build_hello(tmp_path, compiler, optimization, linkage, stripped))


@pytest.fixture(scope="module")
def host_libc_signatures(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build relocation-masked signatures from the exact host static libc."""
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("gcc unavailable")
    query = subprocess.run(
        [gcc, "-print-file-name=libc.a"],
        capture_output=True,
        text=True,
        check=False,
    )
    archive = Path(query.stdout.strip())
    if query.returncode != 0 or not archive.is_file():
        pytest.skip("host static libc unavailable")
    library = build_library_from_archive(
        archive,
        library_name="glibc",
        version="host",
        variant="host-x86_64",
        arch="x86_64",
    )
    output = tmp_path_factory.mktemp("glibc-signatures") / "libc.flirt.json"
    output.write_text(json.dumps(library))
    return output


@pytest.mark.slow
@pytest.mark.parametrize("compiler_name", ["gcc", "clang"])
@pytest.mark.parametrize("optimization", ["O0", "O2"])
def test_stripped_static_hello_is_canonical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    host_libc_signatures: Path,
    compiler_name: str,
    optimization: str,
) -> None:
    """A copied libc body must recover its public name and prototype."""
    compiler = shutil.which(compiler_name)
    if compiler is None:
        pytest.skip(f"{compiler_name} unavailable")
    monkeypatch.setenv("GLAURUNG_FLIRT_LIB", str(host_libc_signatures))
    binary = _build_hello(tmp_path, compiler, optimization, "static", True)
    _assert_canonical(binary)
