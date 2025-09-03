import glaurung as g


def test_artifact_ctph_similarity_on_bytes():
    data1 = b"A" * 4096
    data2 = bytearray(data1)
    data2[100] = ord("B")

    a1 = g.triage.analyze_bytes(bytes(data1))
    a2 = g.triage.analyze_bytes(bytes(data2))

    s11 = a1.ctph_similarity(a1)
    assert s11 is not None and 0.99 <= s11 <= 1.0

    s12 = a1.ctph_similarity(a2)
    assert s12 is not None and 0.0 <= s12 <= 1.0
    assert s12 <= s11

