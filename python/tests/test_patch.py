"""Tests for the binary patcher (#185 v0)."""

from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.llm.kb.patch import (
    _parse_hex,
    patch_at_va,
    render_patch_markdown,
)


_SWITCHY = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing path {p}")
    return p


def test_parse_hex_accepts_canonical_forms() -> None:
    assert _parse_hex("90") == b"\x90"
    assert _parse_hex("90 90") == b"\x90\x90"
    assert _parse_hex("488b45f8") == b"\x48\x8b\x45\xf8"
    assert _parse_hex("48,8b,45,f8") == b"\x48\x8b\x45\xf8"


def test_parse_hex_rejects_malformed() -> None:
    for bad in ("", "9", "9z", "48 8b 4"):
        with pytest.raises(ValueError):
            _parse_hex(bad)


def test_patch_writes_bytes_at_va_and_preserves_rest(tmp_path: Path) -> None:
    """Round-trip: patch + read back the result + diff against the
    original to confirm only the targeted bytes changed."""
    src = _need(_SWITCHY)
    out = tmp_path / "switchy-patched"

    # Read original bytes at the function entry to know what to expect.
    import glaurung as g
    funcs, _ = g.analysis.analyze_functions_path(str(src))
    target = next((f for f in funcs if f.name == "main"), None)
    if target is None:
        pytest.skip("no `main` in switchy")
    va = int(target.entry_point.value)

    result = patch_at_va(
        str(src), str(out), va, payload="90 90 90 90",  # 4-byte NOP sled
    )
    assert result.va == va
    assert result.patched_hex == "90909090"
    # Original hex must be a valid hex string of the same length.
    assert len(result.original_hex) == 8
    assert all(c in "0123456789abcdef" for c in result.original_hex.lower())

    # Output exists, and only the patched bytes differ from the input.
    assert out.exists()
    src_bytes = src.read_bytes()
    out_bytes = out.read_bytes()
    assert len(src_bytes) == len(out_bytes), "patch must not change file size"
    diffs = sum(1 for a, b in zip(src_bytes, out_bytes) if a != b)
    assert diffs <= 4, f"expected ≤4 byte differences; got {diffs}"
    # The 4 patched bytes are 0x90.
    assert out_bytes[result.file_offset : result.file_offset + 4] == b"\x90\x90\x90\x90"


def test_patch_refuses_overwrite_without_force(tmp_path: Path) -> None:
    src = _need(_SWITCHY)
    out = tmp_path / "exists.bin"
    out.write_bytes(b"already")

    funcs_va = 0x1140  # arbitrary; just needs to map to a file offset
    with pytest.raises(FileExistsError):
        patch_at_va(str(src), str(out), funcs_va, payload="90 90")
    # With force=True, overwrite succeeds.
    result = patch_at_va(
        str(src), str(out), funcs_va, payload="90 90",
        overwrite_output=True,
    )
    assert result.patched_hex == "9090"


def test_patch_rejects_payload_past_eof(tmp_path: Path) -> None:
    src = _need(_SWITCHY)
    out = tmp_path / "x.bin"
    # Pick a bogus VA — should fail at va_to_file_offset.
    with pytest.raises((ValueError, RuntimeError)):
        patch_at_va(str(src), str(out), 0xdeadbeef, payload="90")


def test_render_patch_markdown_includes_before_after(tmp_path: Path) -> None:
    src = _need(_SWITCHY)
    out = tmp_path / "rendered.bin"
    import glaurung as g
    funcs, _ = g.analysis.analyze_functions_path(str(src))
    target = next((f for f in funcs if f.name == "main"))
    result = patch_at_va(
        str(src), str(out), int(target.entry_point.value), payload="90",
    )
    md = render_patch_markdown(result, input_path=str(src))
    assert "Patch applied" in md
    assert "before:" in md and "after:" in md
    assert "90" in md


def test_cli_subcommand(tmp_path: Path) -> None:
    """End-to-end: `glaurung patch <in> <out> --va <va> --bytes 90`."""
    import io
    from contextlib import redirect_stdout

    from glaurung.cli.main import GlaurungCLI

    src = _need(_SWITCHY)
    out = tmp_path / "patched.bin"

    import glaurung as g
    funcs, _ = g.analysis.analyze_functions_path(str(src))
    main = next(f for f in funcs if f.name == "main")
    va = int(main.entry_point.value)

    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run([
            "patch", str(src), str(out),
            "--va", hex(va), "--bytes", "90 90",
        ])
    assert rc == 0
    assert out.exists()
    assert "Patch applied" in buf.getvalue()
