from pathlib import Path

import pytest

from glaurung import triage as T


def repo_root() -> Path:
    # python/tests is two levels below repo root
    return Path(__file__).resolve().parents[2]


def test_ioc_text_sample():
    p = repo_root() / "samples" / "adversarial" / "ioc_samples.txt"
    if not p.exists():
        pytest.skip(f"ioc_samples.txt not present: {p}")
    art = T.analyze_path(str(p))
    strings = getattr(art, "strings", None)
    assert strings is not None
    iocs = getattr(strings, "ioc_counts", None) or {}
    # Expect a variety of IOC hits
    assert iocs.get("url", 0) >= 2
    assert iocs.get("email", 0) >= 2
    assert iocs.get("ipv4", 0) >= 2
    assert iocs.get("ipv6", 0) >= 1
    assert iocs.get("path_posix", 0) >= 1
    # Windows path may be recorded as path_windows
    assert iocs.get("path_windows", 0) >= 1 or iocs.get("windows_path", 0) >= 1
    # Registry key
    assert iocs.get("registry", 0) >= 1 or iocs.get("registry_key", 0) >= 1
    # Java class path
    assert iocs.get("java_path", 0) >= 1
