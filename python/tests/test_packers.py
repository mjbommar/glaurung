import glaurung as g


def test_upx_detection_in_bytes():
    # Construct a synthetic buffer containing UPX markers
    data = bytearray(b"MZ")
    data.extend(b"\x00" * 1024)
    data.extend(b"UPX!packed")
    data.extend(b"UPX0")
    data.extend(b"UPX1")

    art = g.triage.analyze_bytes(bytes(data))
    assert isinstance(art, g.triage.TriagedArtifact)

    # Packers should include UPX with reasonable confidence
    assert art.packers is not None
    names = {p.name for p in art.packers}
    assert "UPX" in names
