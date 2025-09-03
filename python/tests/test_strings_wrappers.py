import glaurung as gl


def test_defang_normalization_basic():
    s = "hxxps://ex[.]ample(.)com/path"
    n = gl.strings.defang(s)
    assert n == "https://ex.ample.com/path"


def test_search_text_finds_iocs_and_symbols():
    text = (
        "Contact user@example.org or visit http://a.example.com. "
        "IPv4 10.0.0.1 [2001:db8::1] C\\Windows\\cmd.exe"
    )
    matches = gl.strings.search_text(text)
    kinds = {m.kind for m in matches}
    assert "email" in kinds
    assert "url" in kinds
    assert "ipv4" in kinds and "ipv6" in kinds
    assert "path_windows" in kinds or "path_unc" in kinds


def test_similarity_helpers():
    s = gl.strings.similarity_score("prinf", "printf", algo="jaro_winkler")
    assert s > 0.85
    best = gl.strings.similarity_best_match(
        "CreateFileW",
        ["CreateFileA", "ReadFile", "CloseHandle"],
        algo="jaro_winkler",
        min_score=0.7,
    )
    assert best is not None
    assert best[0].startswith("CreateFile")
