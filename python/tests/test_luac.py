"""Tests for Lua bytecode parser (#211)."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

import glaurung as g


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing {p}")
    return p


_SAMPLES = "samples/binaries/platforms/linux/amd64/export/lua"


def test_parse_lua_53_recovers_source() -> None:
    binary = _need(Path(f"{_SAMPLES}/hello-lua5.3.luac"))
    info = g.analysis.parse_lua_bytecode_path(str(binary))
    assert info is not None
    assert info["kind"] in ("Lua 5.3", "Lua 5.4")
    # Source filename embedded in debug info — should mention hello.lua.
    assert info["source"] is not None
    assert "hello" in info["source"]


def test_parse_luajit_detected() -> None:
    binary = _need(Path(f"{_SAMPLES}/hello-luajit.luac"))
    info = g.analysis.parse_lua_bytecode_path(str(binary))
    assert info is not None
    assert info["kind"] == "LuaJIT"


def test_parse_returns_none_on_native_binary() -> None:
    binary = _need(Path(
        "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
    ))
    assert g.analysis.parse_lua_bytecode_path(str(binary)) is None


def test_luac_cli_renders_summary(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    binary = _need(Path(f"{_SAMPLES}/hello-lua5.3.luac"))
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["luac", str(binary)])
    assert rc == 0
    out = buf.getvalue()
    assert "engine:" in out
    assert "source:" in out
    assert "hello" in out


def test_luac_cli_json(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    binary = _need(Path(f"{_SAMPLES}/hello-lua5.3.luac"))
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["luac", str(binary), "--format", "json"])
    assert rc == 0
    info = json.loads(buf.getvalue())
    assert info["kind"].startswith("Lua")


def test_luac_cli_rejects_non_lua(tmp_path: Path) -> None:
    from glaurung.cli.main import GlaurungCLI

    binary = _need(Path(
        "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
    ))
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["luac", str(binary)])
    assert rc == 4
    assert "not Lua" in buf.getvalue()
