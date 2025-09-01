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


def test_analyze_path_nonexistent_raises_valueerror(tmp_path: Path):
    bogus = tmp_path / "no_such_file_123456.bin"
    assert not bogus.exists()
    with pytest.raises(ValueError):
        g.triage.analyze_path(str(bogus))
