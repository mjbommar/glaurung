from pathlib import Path

import pytest
import glaurung as g


def test_analyze_bytes_empty_raises_valueerror():
    with pytest.raises(ValueError):
        g.triage.analyze_bytes(b"")


def test_analyze_bytes_uses_native_and_reports_size():
    data = b"hello world"
    art = g.triage.analyze_bytes(data)
    assert isinstance(art, g.triage.TriagedArtifact)
    assert art.size_bytes == len(data)
    assert art.id.startswith("triage_")


def test_strings_ioc_samples_present_for_simple_data():
    data = b"Visit http://example.com and email test@example.org"
    art = g.triage.analyze_bytes(data, enable_classification=True, max_classify=10)
    assert art.strings is not None
    ss = art.strings
    # counts should include at least one URL or email
    if ss.ioc_counts is not None:
        any_ioc = any(v > 0 for v in ss.ioc_counts.values())
        assert any_ioc
    # optional ioc_samples may be present with offsets
    if ss.ioc_samples is not None:
        assert all(hasattr(s, "kind") and hasattr(s, "text") for s in ss.ioc_samples)


def test_analyze_path_nonexistent_raises_valueerror(tmp_path: Path):
    bogus = tmp_path / "no_such_file_123456.bin"
    assert not bogus.exists()
    with pytest.raises(ValueError):
        g.triage.analyze_path(str(bogus))
