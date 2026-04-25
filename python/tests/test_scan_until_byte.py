"""Tests for the scan_until_byte memory tool (#176)."""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g


def _hello_path() -> Path:
    p = Path(
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
    )
    if not p.exists():
        pytest.skip(f"missing sample binary {p}")
    return p


def _make_ctx(binary: Path):
    try:
        from glaurung.llm.context import Budgets, MemoryContext
        from glaurung.llm.kb.adapters import import_triage
    except ImportError:
        pytest.skip("LLM dependencies not available")
    art = g.triage.analyze_path(str(binary), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(
        file_path=str(binary), artifact=art, budgets=Budgets(max_read_bytes=65536)
    )
    import_triage(ctx.kb, art, str(binary))
    return ctx


def test_finds_null_terminator_starting_at_offset(tmp_path: Path) -> None:
    from glaurung.llm.context import Budgets, MemoryContext
    from glaurung.llm.kb.adapters import import_triage
    from glaurung.llm.tools.scan_until_byte import build_tool

    # Synthesize a tiny "binary" so the test doesn't depend on a specific
    # rodata layout. Three NUL-terminated C strings, back to back.
    data = b"hello\x00world\x00\x00final"
    target = tmp_path / "stringy.bin"
    target.write_bytes(data)

    art = g.triage.analyze_path(str(target), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(
        file_path=str(target), artifact=art, budgets=Budgets(max_read_bytes=4096)
    )
    import_triage(ctx.kb, art, str(target))

    tool = build_tool()

    # Scan from offset 0 → terminator at offset 5.
    r = tool.run(ctx, ctx.kb, tool.input_model(file_offset=0))
    assert r.found
    assert r.sentinel_value == 0x00
    assert r.sentinel_offset == 5
    assert r.bytes_consumed == 5
    assert bytes.fromhex(r.data_hex) == b"hello"
    assert not r.truncated

    # Scan from offset 6 → next terminator at offset 11.
    r2 = tool.run(ctx, ctx.kb, tool.input_model(file_offset=6))
    assert r2.found and r2.sentinel_offset == 11
    assert bytes.fromhex(r2.data_hex) == b"world"

    # include_sentinel: bytes_consumed includes the terminator byte.
    r3 = tool.run(
        ctx, ctx.kb,
        tool.input_model(file_offset=0, include_sentinel=True),
    )
    assert r3.found
    assert r3.bytes_consumed == 6
    assert bytes.fromhex(r3.data_hex) == b"hello\x00"


def test_truncates_when_no_sentinel_within_cap(tmp_path: Path) -> None:
    from glaurung.llm.context import Budgets, MemoryContext
    from glaurung.llm.kb.adapters import import_triage
    from glaurung.llm.tools.scan_until_byte import build_tool

    # 200 bytes of `A`s with no nulls — scan should truncate cleanly.
    target = tmp_path / "no_terminator.bin"
    target.write_bytes(b"A" * 200)
    art = g.triage.analyze_path(str(target), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(
        file_path=str(target), artifact=art, budgets=Budgets(max_read_bytes=4096)
    )
    import_triage(ctx.kb, art, str(target))

    tool = build_tool()
    r = tool.run(ctx, ctx.kb, tool.input_model(file_offset=0, max_scan_bytes=64))
    assert not r.found
    assert r.sentinel_value is None
    assert r.bytes_consumed == 64
    assert r.truncated  # we hit max_scan_bytes, not EOF


def test_multiple_sentinels(tmp_path: Path) -> None:
    """Scan should stop at the FIRST byte in the sentinel set, whichever it is."""
    from glaurung.llm.context import Budgets, MemoryContext
    from glaurung.llm.kb.adapters import import_triage
    from glaurung.llm.tools.scan_until_byte import build_tool

    # `\n` (0x0A) appears at offset 4, `\r` (0x0D) at offset 8 — record-separator scan.
    target = tmp_path / "lines.bin"
    target.write_bytes(b"abcd\nefg\rhij")
    art = g.triage.analyze_path(str(target), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(
        file_path=str(target), artifact=art, budgets=Budgets(max_read_bytes=4096)
    )
    import_triage(ctx.kb, art, str(target))

    tool = build_tool()
    r = tool.run(
        ctx, ctx.kb,
        tool.input_model(file_offset=0, sentinels=[0x0A, 0x0D]),
    )
    assert r.found
    assert r.sentinel_value == 0x0A
    assert r.sentinel_offset == 4
    assert bytes.fromhex(r.data_hex) == b"abcd"

    # Skip past the \n; next stop should be the \r at offset 8.
    r2 = tool.run(
        ctx, ctx.kb,
        tool.input_model(file_offset=5, sentinels=[0x0A, 0x0D]),
    )
    assert r2.found
    assert r2.sentinel_value == 0x0D
    assert r2.sentinel_offset == 8


def test_rejects_empty_sentinel_set() -> None:
    from glaurung.llm.tools.scan_until_byte import ScanUntilByteArgs
    with pytest.raises(ValueError):
        ScanUntilByteArgs(file_offset=0, sentinels=[])


def test_rejects_va_and_offset_together(tmp_path: Path) -> None:
    from glaurung.llm.context import Budgets, MemoryContext
    from glaurung.llm.kb.adapters import import_triage
    from glaurung.llm.tools.scan_until_byte import build_tool

    target = tmp_path / "tiny.bin"
    target.write_bytes(b"\x00")
    art = g.triage.analyze_path(str(target), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(
        file_path=str(target), artifact=art, budgets=Budgets(max_read_bytes=4096)
    )
    import_triage(ctx.kb, art, str(target))

    tool = build_tool()
    with pytest.raises(ValueError):
        tool.run(ctx, ctx.kb, tool.input_model(va=0x1000, file_offset=0))


def test_works_against_real_binary_offset() -> None:
    """End-to-end: open a real ELF, scan from a known file offset and
    verify the recovered bytes match what reading the file directly
    produces. Uses file_offset (not VA) since the triage strings list
    is just `list[str]` without VA info."""
    from glaurung.llm.tools.scan_until_byte import build_tool

    binary = _hello_path()
    ctx = _make_ctx(binary)

    raw = binary.read_bytes()
    # Pick the start of the ELF rodata-ish region heuristically: skip the
    # ELF header and program headers, then find the first NUL-terminated
    # ASCII run of length >= 4. Use that run's start offset for the scan.
    start_off = -1
    expected: bytes = b""
    i = 0x1000  # well past the 64-byte ELF header
    while i < min(len(raw), 0x4000):
        if 32 <= raw[i] < 127:
            j = i
            while j < len(raw) and 32 <= raw[j] < 127:
                j += 1
            if j - i >= 4 and j < len(raw) and raw[j] == 0:
                start_off = i
                expected = raw[i:j]
                break
            i = j
        i += 1

    if start_off < 0:
        pytest.skip("no NUL-terminated ASCII run found near offset 0x1000")

    tool = build_tool()
    r = tool.run(
        ctx, ctx.kb,
        tool.input_model(file_offset=start_off, max_scan_bytes=128),
    )
    assert r.found
    assert bytes.fromhex(r.data_hex) == expected
    assert r.sentinel_value == 0
    assert r.evidence_node_id is not None
