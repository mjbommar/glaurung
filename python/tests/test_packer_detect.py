"""Tests for packer / obfuscator detection (#187)."""

from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.llm.kb.packer_detect import detect_packer


_HELLO = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)
_SWITCHY = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing path {p}")
    return p


def test_clean_binary_is_not_packed() -> None:
    """Hello-world binaries compiled with stock clang/gcc are not
    packed — the detector must say so."""
    binary = _need(_HELLO)
    verdict = detect_packer(str(binary))
    assert verdict.is_packed is False
    assert verdict.packer_name is None
    # Real binary entropy sits well below the 7.2 packer gate.
    assert 4.0 < verdict.overall_entropy < 7.0


def test_synthetic_packed_binary_detects_upx(tmp_path: Path) -> None:
    """Build a fake binary containing UPX magic bytes and confirm the
    detector flags it as UPX. We don't actually pack a binary —
    detection only cares about the indicator strings."""
    fake = tmp_path / "fake-upx.bin"
    # Just enough of a binary to look "real" — followed by UPX magic.
    fake.write_bytes(
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100
        + b"$Info: This file is packed with the UPX executable packer "
        + b"http://upx.sf.net" + b"\x00" * 100
    )
    verdict = detect_packer(str(fake))
    assert verdict.is_packed is True
    assert verdict.packer_name == "UPX"
    assert verdict.family == "upx"
    assert verdict.confidence >= 0.9
    assert any("UPX" in i or "upx" in i.lower() for i in verdict.indicators)


def test_themida_section_marker(tmp_path: Path) -> None:
    fake = tmp_path / "fake-themida.bin"
    fake.write_bytes(
        b"\x4d\x5a" + b"\x00" * 200    # MZ header
        + b".themida\x00\x00\x00\x00"  # section name
        + b"\x00" * 200
    )
    verdict = detect_packer(str(fake))
    assert verdict.is_packed
    assert verdict.packer_name == "Themida"


def test_vmprotect_section_marker(tmp_path: Path) -> None:
    fake = tmp_path / "fake-vmp.bin"
    fake.write_bytes(
        b"\x4d\x5a" + b"\x00" * 200
        + b".vmp0\x00\x00\x00"         # section name
        + b"\x00" * 200
    )
    verdict = detect_packer(str(fake))
    assert verdict.is_packed
    assert verdict.packer_name == "VMProtect"


def test_high_entropy_no_signature_flags_generic(tmp_path: Path) -> None:
    """A file with no known signature but high overall entropy
    should be flagged as packed (family='generic'). Use random-ish
    bytes to hit the entropy gate."""
    import os
    fake = tmp_path / "noisy.bin"
    fake.write_bytes(os.urandom(8192))   # entropy ~7.99
    verdict = detect_packer(str(fake))
    assert verdict.is_packed is True
    assert verdict.packer_name is None
    assert verdict.family == "generic"
    assert verdict.overall_entropy > 7.2


def test_missing_file_returns_clean_failure(tmp_path: Path) -> None:
    bogus = tmp_path / "definitely-not-a-real-file.bin"
    verdict = detect_packer(str(bogus))
    assert verdict.is_packed is False
    assert any("not found" in n for n in verdict.notes)


def test_cli_subcommand_runs(tmp_path: Path) -> None:
    """Smoke-test the `glaurung detect-packer` CLI."""
    import io
    import sys
    from contextlib import redirect_stdout

    from glaurung.cli.main import GlaurungCLI

    binary = _need(_SWITCHY)
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["detect-packer", str(binary)])
    out = buf.getvalue()
    # rc=0 means not packed (correct for switchy).
    assert rc == 0
    assert "not packed" in out
    assert "entropy" in out
