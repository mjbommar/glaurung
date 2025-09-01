import glaurung as g


def test_entropy_classification_and_indicators_bytes():
    # Low-entropy header: 1024 zeros
    data = bytearray(b"\x00" * 1024)
    # High-entropy-ish body: uniform 0..255 repeated to fill 8192 bytes
    body = bytes([i % 256 for i in range(8192)])
    data.extend(body)

    art = g.triage.analyze_bytes(bytes(data))
    assert isinstance(art, g.triage.TriagedArtifact)
    assert art.entropy is not None
    assert art.entropy_analysis is not None

    ea = art.entropy_analysis
    assert ea is not None
    pi = ea.packed_indicators
    assert pi.has_low_entropy_header is True
    assert pi.has_high_entropy_body is True
    assert 0.0 <= pi.verdict <= 1.0

    # Classification should be at least compressed or higher
    k = ea.classification_kind
    assert k in {"Compressed", "Encrypted", "Random"}
