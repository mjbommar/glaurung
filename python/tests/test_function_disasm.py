"""Integration test: KB-aware single-function disassembly with symbol
annotation, CFG-derived bounds, and a coverage footer.

Builds a real dxgmms2 KB (PDB naming on by default) once, then checks that
direct call targets and IAT references get named, intra-function jumps do
NOT pollute the coverage caveats, and name-or-VA both resolve.
Skips cleanly when the corpus / cached PDB is absent.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

_BIN = Path(
    "/nas4/data/workspace-infosec/cold-hunt-durable/v7vm/System32/drivers/dxgmms2.sys"
)
_CACHE = Path("/nas4/data/symbol-cache/microsoft")
_PDB = _CACHE / "dxgmms2.pdb" / "4ECC952D95F55A5623F337C0F59360841" / "dxgmms2.pdb"
_have = _BIN.is_file() and _PDB.is_file()

pytestmark = pytest.mark.skipif(not _have, reason="dxgmms2.sys / cached PDB absent")


@pytest.fixture(scope="module")
def kb_db(monkeypatch_module=None):
    from glaurung.llm.kb.kickoff import kickoff_analysis
    import os

    os.environ["GLAURUNG_PDB_CACHE"] = str(_CACHE)
    td = tempfile.mkdtemp(prefix="glaurung-fdtest-")
    db = str(Path(td) / "dxgmms2.glaurung")
    s = kickoff_analysis(str(_BIN), db_path=db, fetch_pdb=False,
                         max_functions_for_kb_lift=0)
    assert s.functions_named_pdb > 1000
    return db


def test_named_call_targets_and_clean_coverage(kb_db) -> None:
    from glaurung.llm.kb.function_disasm import disasm_function

    fd = disasm_function(str(_BIN), db_path=kb_db,
                         function="VidSchiCheckPendingDeviceCommand")
    assert fd.name == "VidSchiCheckPendingDeviceCommand"
    assert fd.end_va > fd.start_va
    comments = [i.comment for i in fd.insns if i.comment]
    # The crash free site: the scalar deleting destructor call is annotated.
    assert any("VIDSCH_SYNC_POINT" in c for c in comments)
    # An IAT import (call [rip+slot]) is named.
    assert any("SpinLock" in c for c in comments)
    # Intra-function jumps must NOT be counted as unresolved targets.
    cov = fd.coverage.to_dict()
    assert cov["facts"]["indirect calls unresolved"] == 0
    assert cov["complete"] is True


def test_resolve_by_va_matches_by_name(kb_db) -> None:
    from glaurung.llm.kb.function_disasm import disasm_function

    by_name = disasm_function(str(_BIN), db_path=kb_db,
                              function="VidSchiCheckPendingDeviceCommand")
    by_va = disasm_function(str(_BIN), db_path=kb_db,
                            function=hex(by_name.start_va))
    assert by_va.start_va == by_name.start_va
    assert len(by_va.insns) == len(by_name.insns)


def test_binary_path_resolved_from_db(kb_db) -> None:
    from glaurung.llm.kb.function_disasm import disasm_function

    # No binary_path passed -> resolved from the DB's binaries table.
    fd = disasm_function(db_path=kb_db, function="VidSchiCheckPendingDeviceCommand")
    assert fd.insns
