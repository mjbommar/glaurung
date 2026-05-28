"""Tests for the Microsoft symbol-server PDB fetcher (glaurung.pdb_fetch).

Network-dependent tests are skipped when the corpus/cache is absent so
the suite stays green off-box. The CodeView parser test is deterministic
and runs whenever a sample PE is present.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.pdb_fetch import CodeView, cache_path_for, read_codeview

# Real corpus binary with a known CodeView key (build 26100 srvnet.sys).
_SRVNET = Path(
    "/nas4/data/workspace-infosec/cold-hunt-durable/v7vm/System32/drivers/srvnet.sys"
)
_SRVNET_KEY = "B6E2A3ECD974FE7547E7C62C458C71FD1"
_CACHE = Path("/nas4/data/symbol-cache/microsoft")


@pytest.mark.skipif(not _SRVNET.is_file(), reason="corpus srvnet.sys absent")
def test_read_codeview_matches_known_key() -> None:
    cv = read_codeview(_SRVNET)
    assert cv is not None
    assert cv.pdb_name == "srvnet.pdb"
    # GUID string is 32 hex chars; key appends the age (here "1").
    assert cv.guid_age_key == _SRVNET_KEY
    assert len(cv.guid_age_key) >= 33


@pytest.mark.skipif(not _SRVNET.is_file(), reason="corpus srvnet.sys absent")
def test_cache_path_layout() -> None:
    cv = read_codeview(_SRVNET)
    assert cv is not None
    p = cache_path_for(cv, _CACHE)
    # Canonical MS layout: <cache>/<pdb>/<GUID+AGE>/<pdb>
    assert p == _CACHE / "srvnet.pdb" / _SRVNET_KEY / "srvnet.pdb"


def test_read_codeview_non_pe_returns_none(tmp_path: Path) -> None:
    junk = tmp_path / "notpe.bin"
    junk.write_bytes(b"not a pe file at all")
    assert read_codeview(junk) is None


def test_codeview_namedtuple_shape() -> None:
    cv = CodeView(pdb_name="x.pdb", guid_age_key="ABCD1", pdb_path="x.pdb")
    assert cv.pdb_name == "x.pdb"
    assert cv.guid_age_key == "ABCD1"


@pytest.mark.skipif(
    not (_CACHE / "srvnet.pdb" / _SRVNET_KEY / "srvnet.pdb").is_file(),
    reason="srvnet PDB not in local cache",
)
def test_ensure_pdb_cached_hit_no_download() -> None:
    """Cache-hit path must return the path without any network call."""
    from glaurung.pdb_fetch import ensure_pdb_cached

    p = ensure_pdb_cached(_SRVNET, _CACHE, download=False)
    assert p is not None
    assert p.is_file()
    assert p.name == "srvnet.pdb"
