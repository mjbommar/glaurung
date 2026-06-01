"""Integration test: kickoff applies Microsoft PDB names to discovered
functions BY DEFAULT (no opt-in flag) when a matching PDB is resolvable.

Uses a real build-26100 driver whose PDB is in the local symbol cache.
Skips cleanly when the corpus / cache is absent (off-box CI).
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from glaurung.llm.kb.kickoff import kickoff_analysis
from glaurung.pdb_fetch import default_cache_dir

_SRVNET = Path(
    "/nas4/data/workspace-infosec/cold-hunt-durable/v7vm/System32/drivers/srvnet.sys"
)
_CACHE = Path("/nas4/data/symbol-cache/microsoft")
_SRVNET_PDB = _CACHE / "srvnet.pdb" / "B6E2A3ECD974FE7547E7C62C458C71FD1" / "srvnet.pdb"

_have_inputs = _SRVNET.is_file() and _SRVNET_PDB.is_file()


def test_default_cache_dir_resolution(monkeypatch, tmp_path) -> None:
    """$GLAURUNG_PDB_CACHE wins; else a local _NT_SYMBOL_PATH dir; else
    the per-user default. Pure unit, no corpus needed."""
    monkeypatch.setenv("GLAURUNG_PDB_CACHE", str(tmp_path / "envcache"))
    assert default_cache_dir() == tmp_path / "envcache"

    monkeypatch.delenv("GLAURUNG_PDB_CACHE", raising=False)
    sym = tmp_path / "ntsym"
    sym.mkdir()
    monkeypatch.setenv("_NT_SYMBOL_PATH", f"srv*{sym}*https://msdl.microsoft.com/x")
    assert default_cache_dir() == sym

    monkeypatch.delenv("_NT_SYMBOL_PATH", raising=False)
    assert default_cache_dir() == Path.home() / ".cache" / "glaurung" / "symbols"


@pytest.mark.skipif(not _have_inputs, reason="srvnet.sys / cached PDB absent")
def test_kickoff_pdb_on_by_default(monkeypatch) -> None:
    # Point the DEFAULT resolver at the real cache; pass NO enable flag.
    monkeypatch.setenv("GLAURUNG_PDB_CACHE", str(_CACHE))
    with tempfile.TemporaryDirectory() as td:
        # Default behaviour (pdb=True) must name hundreds of internals.
        on = kickoff_analysis(
            str(_SRVNET), db_path=str(Path(td) / "on.glaurung"), fetch_pdb=False
        )
        assert on.pdb_cache_hit is True
        assert on.pdb_name == "srvnet.pdb"
        assert on.functions_named_pdb > 500
        assert on.functions_named_pdb > on.functions_named  # beats exports-only

        # Explicit opt-out leaves everything as sub_/exports.
        off = kickoff_analysis(
            str(_SRVNET), db_path=str(Path(td) / "off.glaurung"),
            pdb=False, fetch_pdb=False,
        )
        assert off.functions_named_pdb == 0


@pytest.mark.skipif(not _have_inputs, reason="srvnet.sys / cached PDB absent")
def test_kickoff_pdb_names_are_real_symbols(monkeypatch) -> None:
    import sqlite3

    monkeypatch.setenv("GLAURUNG_PDB_CACHE", str(_CACHE))
    with tempfile.TemporaryDirectory() as td:
        db = str(Path(td) / "k.glaurung")
        kickoff_analysis(str(_SRVNET), db_path=db, fetch_pdb=False)
        c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        names = {
            r[0]
            for r in c.execute(
                "SELECT canonical FROM function_names WHERE set_by='pdb'"
            ).fetchall()
        }
        # Known srvnet internal functions only a PDB could supply.
        assert "SmbCompressionDecompress" in names
        assert "SrvNetAllocateBuffer" in names
