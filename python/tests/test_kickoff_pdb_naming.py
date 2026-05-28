"""Integration test: kickoff applies Microsoft PDB names to discovered
functions when given a PDB cache.

Uses a real build-26100 driver whose PDB is in the local symbol cache.
Skips cleanly when the corpus / cache is absent (off-box CI).
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from glaurung.llm.kb.kickoff import kickoff_analysis

_SRVNET = Path(
    "/nas4/data/workspace-infosec/cold-hunt-durable/v7vm/System32/drivers/srvnet.sys"
)
_CACHE = Path("/nas4/data/symbol-cache/microsoft")
_SRVNET_PDB = _CACHE / "srvnet.pdb" / "B6E2A3ECD974FE7547E7C62C458C71FD1" / "srvnet.pdb"

_have_inputs = _SRVNET.is_file() and _SRVNET_PDB.is_file()


@pytest.mark.skipif(not _have_inputs, reason="srvnet.sys / cached PDB absent")
def test_kickoff_applies_pdb_names() -> None:
    with tempfile.TemporaryDirectory() as td:
        db = str(Path(td) / "k.glaurung")
        # Baseline: no PDB cache -> exports only.
        base = kickoff_analysis(str(_SRVNET), db_path=db)
        assert base.functions_named_pdb == 0

        db2 = str(Path(td) / "k2.glaurung")
        named = kickoff_analysis(
            str(_SRVNET), db_path=db2,
            pdb_cache=str(_CACHE), fetch_pdb=False,
        )
        # PDB naming must add hundreds of authoritative names.
        assert named.pdb_cache_hit is True
        assert named.pdb_name == "srvnet.pdb"
        assert named.functions_named_pdb > 500
        # And it must beat the exports-only baseline substantially.
        assert named.functions_named_pdb > base.functions_named


@pytest.mark.skipif(not _have_inputs, reason="srvnet.sys / cached PDB absent")
def test_kickoff_pdb_names_are_real_symbols() -> None:
    import sqlite3

    with tempfile.TemporaryDirectory() as td:
        db = str(Path(td) / "k.glaurung")
        kickoff_analysis(
            str(_SRVNET), db_path=db, pdb_cache=str(_CACHE), fetch_pdb=False
        )
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
