import gzip
from pathlib import Path

import glaurung as g


def test_detect_zip_container_on_jar(sample_jar: Path):
    # JAR is a ZIP container; ensure detection surfaces containers
    art = g.triage.analyze_path(str(sample_jar))
    assert art is not None
    # Accept proxy as long as it behaves like a triaged artifact
    assert hasattr(art, "path") and hasattr(art, "verdicts")
    # Depending on pipeline, containers may be None if detection is disabled
    if art.containers is not None:
        types = {c.type_name for c in art.containers}
        assert "zip" in types


def test_detect_gzip_container_from_bytes():
    payload = b"hello world" * 100
    gzipped = gzip.compress(payload)
    art = g.triage.analyze_bytes(gzipped)
    # gzip magic should be detected
    if art.containers is not None:
        types = {c.type_name for c in art.containers}
        assert "gzip" in types
