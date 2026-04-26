"""Tests for Java classfile + JAR parser (#209)."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

import glaurung as g


_HELLO_CLASS = Path(
    "samples/binaries/platforms/linux/amd64/export/java/HelloWorld.class"
)
_HELLO_JAR = Path(
    "samples/binaries/platforms/linux/amd64/export/java/HelloWorld.jar"
)
_HELLO_C = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing {p}")
    return p


def test_parse_class_recovers_methods() -> None:
    info = g.analysis.parse_java_class_path(str(_need(_HELLO_CLASS)))
    assert info is not None
    assert info["class_name"] == "HelloWorld"
    assert info["super_class"] == "java/lang/Object"
    method_names = [m["name"] for m in info["methods"]]
    for expected in ("main", "printMessage", "getCounter", "printGlobalInfo"):
        assert expected in method_names
    assert any(m["name"] == "<init>" for m in info["methods"])
    main_m = next(m for m in info["methods"] if m["name"] == "main")
    assert main_m["descriptor"] == "([Ljava/lang/String;)V"


def test_parse_class_returns_none_on_non_class() -> None:
    info = g.analysis.parse_java_class_path(str(_need(_HELLO_C)))
    assert info is None


def test_classfile_cli_renders_class(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    binary = _need(_HELLO_CLASS)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["classfile", str(binary)])
    assert rc == 0
    out = buf.getvalue()
    assert "class HelloWorld" in out
    assert "main([Ljava/lang/String;)V" in out
    assert "printMessage" in out


def test_classfile_cli_walks_jar(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    jar = _need(_HELLO_JAR)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["classfile", str(jar)])
    assert rc == 0
    out = buf.getvalue()
    # Should mention at least one class.
    assert "class file" in out
    assert "class HelloWorld" in out
    assert "parsed" in out


def test_classfile_cli_json_format(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    binary = _need(_HELLO_CLASS)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["classfile", str(binary), "--format", "json"])
    assert rc == 0
    info = json.loads(buf.getvalue())
    assert info["class_name"] == "HelloWorld"
    assert any(m["name"] == "main" for m in info["methods"])


def test_classfile_cli_rejects_non_class(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    binary = _need(_HELLO_C)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["classfile", str(binary)])
    assert rc == 4
    assert "not a Java class" in buf.getvalue()
