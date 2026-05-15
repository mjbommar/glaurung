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
_HELLO_JAR = Path("samples/binaries/platforms/linux/amd64/export/java/HelloWorld.jar")
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
    assert main_m["code"]["max_stack"] > 0
    assert main_m["code"]["max_locals"] >= 1
    assert main_m["code"]["code_length"] > 0
    assert all(f["code"] is None for f in info["fields"])


def test_parse_class_bytes_recovers_methods() -> None:
    data = _need(_HELLO_CLASS).read_bytes()
    info = g.analysis.parse_java_class_bytes(data)
    assert info is not None
    assert info["class_name"] == "HelloWorld"
    assert info["super_class"] == "java/lang/Object"
    main_m = next(m for m in info["methods"] if m["name"] == "main")
    assert main_m["code"]["code_length"] > 0


def test_parse_class_bytes_recovers_method_xrefs() -> None:
    data = _need(_HELLO_CLASS).read_bytes()
    info = g.analysis.parse_java_class_bytes(data)
    assert info is not None

    print_message = next(m for m in info["methods"] if m["name"] == "printMessage")
    xrefs = print_message["code"]["xrefs"]

    assert any(
        x["kind"] == "field"
        and x["owner"] == "java/lang/System"
        and x["name"] == "out"
        and x["bci"] == 0
        for x in xrefs
    )
    assert any(
        x["kind"] == "method"
        and x["owner"] == "java/io/PrintStream"
        and x["name"] == "println"
        and x["bci"] == 7
        for x in xrefs
    )

    default_init = next(
        m for m in info["methods"] if m["name"] == "<init>" and m["descriptor"] == "()V"
    )
    assert any(
        x["kind"] == "string"
        and x["string_value"] == "Hello, World from Java!"
        and x["bci"] == 1
        for x in default_init["code"]["xrefs"]
    )


def test_parse_class_returns_none_on_non_class() -> None:
    info = g.analysis.parse_java_class_path(str(_need(_HELLO_C)))
    assert info is None


def test_parse_class_bytes_returns_none_on_non_class() -> None:
    info = g.analysis.parse_java_class_bytes(_need(_HELLO_C).read_bytes())
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


def test_classfile_cli_walks_jar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from glaurung.cli.main import GlaurungCLI

    def fail_write_bytes(self: Path, data: bytes) -> int:
        raise AssertionError(
            f"JAR class entries should be parsed from bytes, not {self}"
        )

    monkeypatch.setattr(Path, "write_bytes", fail_write_bytes)
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
