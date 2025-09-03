import pytest

import glaurung as g


def test_module_structure():
    # Core types exposed at root
    assert hasattr(g, "Format")
    assert hasattr(g, "Arch")
    # Triage submodule exposed
    assert hasattr(g, "triage")


def test_create_hint_and_error():
    T = g.triage
    h = T.TriageHint(
        T.SnifferSource.Infer, mime="application/zip", extension=None, label="zip"
    )
    assert h.mime == "application/zip"
    e = T.TriageError(T.TriageErrorKind.SnifferMismatch, "ext vs header")
    assert e.kind == T.TriageErrorKind.SnifferMismatch


def test_verdict_bits_validation():
    T = g.triage
    with pytest.raises(ValueError):
        T.TriageVerdict(g.Format.PE, g.Arch.X86, 16, g.Endianness.Little, 0.1)
    ok = T.TriageVerdict(g.Format.ELF, g.Arch.X86_64, 64, g.Endianness.Little, 0.9)
    assert ok.bits == 64


def test_artifact_round_trip():
    T = g.triage
    hint = T.TriageHint(T.SnifferSource.MimeGuess, None, "exe", "pe")
    verdict = T.TriageVerdict(g.Format.PE, g.Arch.X86, 32, g.Endianness.Little, 0.8)
    art = T.TriagedArtifact(
        id="id1",
        path="/tmp/x",
        size_bytes=123,
        schema_version="1.0.0",  # Add required schema_version
        sha256="a" * 64,
        hints=[hint],
        verdicts=[verdict],
        entropy=T.EntropySummary(7.5, 4096, None),
        strings=T.StringsSummary(1, 0, 0, [T.DetectedString("hello", "ascii")]),
        packers=[T.PackerMatch("UPX", 0.9)],
        containers=[T.ContainerChild("zip", 0, 10)],
        parse_status=[T.ParserResult(T.ParserKind.Object, True, None)],
        budgets=T.Budgets(1024, 10, 0),
        errors=None,
    )
    s = art.to_json()
    back = T.TriagedArtifact.from_json(s)
    # Quick checks
    assert back.id == art.id
    assert back.size_bytes == 123
    assert back.verdicts[0].format == g.Format.PE
