"""Unit tests for the persistent CLI cache (decompile + name-func).

These tests mock at the Rust seam (``glaurung.ir.decompile_at`` and the
LLM-backed ``SuggestFunctionNameTool``) so they run without samples or
network access. The cache layer is pure Python; this is the right place
to verify its semantics in isolation.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest  # noqa: F401  — used by fixtures

from glaurung.cli import cache as _cache


# --- cache primitives -------------------------------------------------


def test_sha256_file_matches_known_value(tmp_path: Path) -> None:
    target = tmp_path / "blob.bin"
    target.write_bytes(b"hello-world\n")
    # Sanity: same hash via two different chunk paths.
    expected = "d79f2e37784e5cd8631963896ebc6c9c66934af94a1854504717eaec04bc3d09"
    assert _cache.sha256_file(target) == expected


def test_flags_hash_is_stable_and_order_independent() -> None:
    a = _cache.flags_hash({"style": "c", "types": True, "timeout": 500})
    b = _cache.flags_hash({"timeout": 500, "types": True, "style": "c"})
    assert a == b
    assert len(a) == 8
    # Different flag content -> different hash.
    c = _cache.flags_hash({"style": "plain", "types": True, "timeout": 500})
    assert c != a


def test_resolve_cache_dir_prefers_arg(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GLAURUNG_CACHE_DIR", str(tmp_path / "env"))
    out = _cache.resolve_cache_dir(str(tmp_path / "arg"))
    assert out == Path(tmp_path / "arg")


def test_resolve_cache_dir_falls_back_to_env(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GLAURUNG_CACHE_DIR", str(tmp_path / "env"))
    out = _cache.resolve_cache_dir(None)
    assert out == Path(tmp_path / "env")


def test_resolve_cache_dir_none_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("GLAURUNG_CACHE_DIR", raising=False)
    assert _cache.resolve_cache_dir(None) is None
    assert _cache.resolve_cache_dir("") is None


def test_write_then_read_roundtrip(tmp_path: Path) -> None:
    paths = _cache.build_paths(
        tmp_path,
        namespace="decomp",
        binary_sha256="a" * 64,
        va=0x1234,
        flags={"style": "plain"},
        suffix=".plain.c",
    )
    _cache.write_text(paths, "function sub_1234 { ... }")
    assert _cache.read_text(paths) == "function sub_1234 { ... }"
    # Layout matches the spec.
    rel = paths.file.relative_to(tmp_path)
    parts = rel.parts
    assert parts[0] == "decomp"
    # parts[1] = version, parts[2] = sha
    assert parts[2] == "a" * 64
    assert parts[3].startswith("1234.")
    assert parts[3].endswith(".plain.c")


def test_write_is_atomic_no_part_file_left_behind(tmp_path: Path) -> None:
    paths = _cache.build_paths(
        tmp_path,
        namespace="decomp",
        binary_sha256="b" * 64,
        va=0xCAFE,
        flags={"style": "c"},
        suffix=".c.c",
    )
    _cache.write_text(paths, "body")
    # No .part artefacts left in the entry's dir.
    leftovers = [p for p in paths.dir.iterdir() if p.suffix == ".part"]
    assert leftovers == []


def test_read_returns_none_on_miss(tmp_path: Path) -> None:
    paths = _cache.build_paths(
        tmp_path,
        namespace="decomp",
        binary_sha256="c" * 64,
        va=0x1,
        flags={},
        suffix=".plain.c",
    )
    assert _cache.read_text(paths) is None


def test_write_failure_is_swallowed(tmp_path: Path, caplog) -> None:
    paths = _cache.build_paths(
        tmp_path,
        namespace="decomp",
        binary_sha256="d" * 64,
        va=0x2,
        flags={},
        suffix=".plain.c",
    )
    with mock.patch("os.replace", side_effect=OSError("disk full")):
        # Must not raise.
        _cache.write_text(paths, "ignored")
    # Nothing committed on disk.
    assert _cache.read_text(paths) is None


# --- decompile integration (mock at the Rust seam) --------------------


@pytest.fixture
def fake_binary(tmp_path: Path) -> Path:
    binary = tmp_path / "fake.bin"
    binary.write_bytes(b"MZ" + b"\x00" * 64 + b"payload")
    return binary


def _decompile_args(path: Path, cache_dir: Path | None, style: str = "plain"):
    return SimpleNamespace(
        path=str(path),
        func=0x1840,
        all=False,
        limit=8,
        types=True,
        timeout_ms=500,
        style=style,
        pdb_cache="",
        cache_dir=str(cache_dir) if cache_dir is not None else None,
    )


def _run_decompile(args, mocked_text: str = "function sub_1840 { ret; }"):
    """Invoke DecompileCommand.execute with the Rust call mocked.

    Returns (rc, formatter_lines, decompile_call_count, args_seen).
    """
    from glaurung.cli.commands.decompile import DecompileCommand
    from glaurung.cli.formatters.base import OutputFormat

    lines: list[str] = []

    class _Fmt:
        format_type = OutputFormat.PLAIN

        def output_plain(self, s: str) -> None:
            lines.append(s)

    cmd = DecompileCommand()
    call_log: list[dict] = []

    def _fake_decompile_at(path, va, **kwargs):
        call_log.append({"path": path, "va": va, **kwargs})
        return mocked_text

    with (
        mock.patch("glaurung.ir.decompile_at", side_effect=_fake_decompile_at),
        # detect_entry_path is only called when --func is omitted; we
        # always pass a VA, so this mock is defensive.
        mock.patch("glaurung.analysis.detect_entry_path", return_value=None),
    ):
        rc = cmd.execute(args, _Fmt())

    return rc, lines, call_log


def test_decompile_cache_miss_writes_then_hits(
    fake_binary: Path, tmp_path: Path
) -> None:
    cache_dir = tmp_path / "gcache"
    args = _decompile_args(fake_binary, cache_dir)

    rc1, lines1, calls1 = _run_decompile(args)
    assert rc1 == 0
    assert len(calls1) == 1, "miss path must call decompile_at exactly once"
    assert lines1[-1].startswith("function sub_1840"), lines1

    # Second invocation: same key, must NOT call decompile_at.
    rc2, lines2, calls2 = _run_decompile(args, mocked_text="DIFFERENT")
    assert rc2 == 0
    assert calls2 == [], "hit path must skip the Rust call entirely"
    assert lines2[-1].startswith("function sub_1840"), (
        "cache hit should replay the cached body, not the mocked text"
    )


def test_decompile_different_flags_produce_different_entries(
    fake_binary: Path, tmp_path: Path
) -> None:
    cache_dir = tmp_path / "gcache"
    plain_args = _decompile_args(fake_binary, cache_dir, style="plain")
    c_args = _decompile_args(fake_binary, cache_dir, style="c")

    rc, _, calls_plain = _run_decompile(plain_args, mocked_text="PLAIN_BODY")
    assert rc == 0
    rc, _, calls_c = _run_decompile(c_args, mocked_text="C_STYLE_BODY")
    assert rc == 0

    # Both styles must have called through (distinct entries).
    assert len(calls_plain) == 1
    assert len(calls_c) == 1

    # Re-running each must hit, not call through.
    _, _, calls_plain_2 = _run_decompile(plain_args, mocked_text="X")
    _, _, calls_c_2 = _run_decompile(c_args, mocked_text="X")
    assert calls_plain_2 == []
    assert calls_c_2 == []

    # Two distinct files on disk.
    entries = list((cache_dir / "decomp").rglob("*.c"))
    assert len(entries) == 2


def test_decompile_no_cache_dir_means_no_caching(
    fake_binary: Path, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("GLAURUNG_CACHE_DIR", raising=False)
    args = _decompile_args(fake_binary, None)

    # Two back-to-back runs: both must call through.
    _, _, calls1 = _run_decompile(args)
    _, _, calls2 = _run_decompile(args)
    assert len(calls1) == 1
    assert len(calls2) == 1


def test_decompile_env_var_enables_cache(
    fake_binary: Path, tmp_path: Path, monkeypatch
) -> None:
    cache_dir = tmp_path / "envcache"
    monkeypatch.setenv("GLAURUNG_CACHE_DIR", str(cache_dir))

    args = _decompile_args(fake_binary, None)  # arg unset -> env wins
    _, _, calls1 = _run_decompile(args, mocked_text="ENV_BODY")
    _, lines2, calls2 = _run_decompile(args, mocked_text="WILL_NOT_BE_USED")
    assert len(calls1) == 1
    assert calls2 == [], "env-configured cache should hit on second run"
    assert "ENV_BODY" in "\n".join(lines2)


def test_decompile_unwritable_cache_dir_falls_through(
    fake_binary: Path, tmp_path: Path, caplog
) -> None:
    cache_dir = tmp_path / "gcache"
    args = _decompile_args(fake_binary, cache_dir)

    # Simulate write failure: mkdir works, but os.replace blows up.
    with mock.patch("glaurung.cli.cache.os.replace", side_effect=OSError("EROFS")):
        rc, lines, calls = _run_decompile(args, mocked_text="LIVE_BODY")

    # Command must still succeed and emit the live result.
    assert rc == 0
    assert len(calls) == 1
    assert "LIVE_BODY" in "\n".join(lines)

    # Subsequent invocation (with replace now working) is a miss again
    # because the previous write failed cleanly.
    rc2, lines2, calls2 = _run_decompile(args, mocked_text="SECOND_LIVE")
    assert rc2 == 0
    assert len(calls2) == 1
    assert "SECOND_LIVE" in "\n".join(lines2)


def test_decompile_byte_identical_stdout_on_hit(
    fake_binary: Path, tmp_path: Path
) -> None:
    cache_dir = tmp_path / "gcache"
    args = _decompile_args(fake_binary, cache_dir)
    body = "function sub_1840 @ 0x1840 {\n  ret;\n}\n"

    _, lines1, _ = _run_decompile(args, mocked_text=body)
    _, lines2, calls2 = _run_decompile(args, mocked_text="MOCK_SHOULD_NOT_RUN")
    assert calls2 == []
    # Byte-identical formatter output.
    assert "\n".join(lines1) == "\n".join(lines2)


# --- name-func cache wiring -------------------------------------------


def test_name_func_cache_paths_use_model_in_key(tmp_path: Path) -> None:
    from glaurung.cli.commands.name_func import _build_name_func_cache_paths

    a = _build_name_func_cache_paths(
        cache_dir_arg=str(tmp_path),
        binary_path=str(_make_fake_binary(tmp_path)),
        func_va=0xCAFE,
        model_name="openai:gpt-5.4-mini",
        original_name=None,
    )
    b = _build_name_func_cache_paths(
        cache_dir_arg=str(tmp_path),
        binary_path=str(_make_fake_binary(tmp_path)),
        func_va=0xCAFE,
        model_name="anthropic:claude-haiku-4-5",
        original_name=None,
    )
    assert a is not None and b is not None
    assert a.file != b.file, "different model -> different cache entry"


def test_name_func_cache_disabled_returns_none(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("GLAURUNG_CACHE_DIR", raising=False)
    from glaurung.cli.commands.name_func import _build_name_func_cache_paths

    out = _build_name_func_cache_paths(
        cache_dir_arg=None,
        binary_path=str(_make_fake_binary(tmp_path)),
        func_va=0x1,
        model_name="openai:gpt-5.4-mini",
        original_name=None,
    )
    assert out is None


def test_name_func_original_name_changes_key(tmp_path: Path) -> None:
    from glaurung.cli.commands.name_func import _build_name_func_cache_paths

    binary = _make_fake_binary(tmp_path)
    a = _build_name_func_cache_paths(
        cache_dir_arg=str(tmp_path),
        binary_path=str(binary),
        func_va=0xFEED,
        model_name="openai:gpt-5.4-mini",
        original_name=None,
    )
    b = _build_name_func_cache_paths(
        cache_dir_arg=str(tmp_path),
        binary_path=str(binary),
        func_va=0xFEED,
        model_name="openai:gpt-5.4-mini",
        original_name="?some_mangled_name@@YAHXZ",
    )
    assert a is not None and b is not None
    assert a.file != b.file


def _make_fake_binary(tmp_path: Path) -> Path:
    binary = tmp_path / "nf.bin"
    if not binary.exists():
        binary.write_bytes(b"MZ" + b"\x00" * 32 + b"payload")
    return binary
