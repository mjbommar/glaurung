"""Lock-state analysis: must model BOTH raw Ke* APIs and the C++ RAII
wrapper (AcquireSpinLock::Acquire), resolve the underlying lock object
through the guard indirection, and never emit a held-state claim it can't
back. Regression for the 2026-06-01 false "wrong-lock" finding, where a
tracer that saw only raw imports missed a wrapper acquire entirely.
"""
from __future__ import annotations

import os
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
def kb_db():
    from glaurung.llm.kb.kickoff import kickoff_analysis

    os.environ["GLAURUNG_PDB_CACHE"] = str(_CACHE)
    td = tempfile.mkdtemp(prefix="glaurung-locktest-")
    db = str(Path(td) / "dxgmms2.glaurung")
    kickoff_analysis(str(_BIN), db_path=db, fetch_pdb=False,
                     max_functions_for_kb_lift=0)
    return db


def test_raw_ke_spinlock_modeled(kb_db):
    from glaurung.llm.kb.lock_state import analyze_locks

    rep = analyze_locks(str(_BIN), db_path=kb_db, function="VidSchSubmitWaitFromCpu")
    prims = {o.primitive for o in rep.ops}
    assert any("KeAcquireInStackQueuedSpinLock" in p for p in prims)
    # The device scheduler lock is at object offset +0x7c0.
    assert any(o.lock_id and o.lock_id.endswith("0x7c0")
               for o in rep.ops if o.kind == "acquire")


def test_raii_wrapper_acquire_is_modeled(kb_db):
    """THE regression: the wrapper acquire must be seen, and resolve to the
    same +0x7c0 lock the raw-API sibling uses -- not silently ignored."""
    from glaurung.llm.kb.lock_state import analyze_locks

    rep = analyze_locks(str(_BIN), db_path=kb_db,
                        function="VidSchSignalSyncObjectsFromCpu")
    acquires = [o for o in rep.ops if o.kind == "acquire"]
    assert acquires, "wrapper acquire was missed entirely (the 2026-06-01 bug)"
    assert any("Acquire@AcquireSpinLock" in o.primitive for o in acquires)
    # Resolved through the guard indirection + byte-decoded immediate.
    assert any(o.lock_id == "+0x7c0" for o in acquires)
    # Balanced acquire/release for that lock.
    assert rep.balance.get("+0x7c0") == (1, 1)


def test_cfg_dataflow_must_held(kb_db):
    """CFG-aware (requirement b): where the wrapper acquire dominates, the
    free-reaching call must be provably holding +0x7c0 (not a linear sweep)."""
    from glaurung.llm.kb.lock_state import analyze_locks

    rep = analyze_locks(str(_BIN), db_path=kb_db,
                        function="VidSchSignalSyncObjectsFromCpu")
    assert rep.cfg_blocks > 0 and rep.cfg_edges > 0  # real glaurung CFG used
    inner = [h for h in rep.held_at_calls
             if "VidSchiSignalSyncObjectsFromCpu" in h.callee]
    assert inner, "expected a held-at-call record for the inner signal call"
    assert "+0x7c0" in inner[0].must  # provably held on ALL paths


def test_coverage_is_honest(kb_db):
    from glaurung.llm.kb.lock_state import analyze_locks

    rep = analyze_locks(str(_BIN), db_path=kb_db,
                        function="VidSchSignalSyncObjectsFromCpu")
    d = rep.to_dict()
    caveats = " ".join(d["coverage"]["caveats"]).lower()
    assert "intraprocedural" in caveats  # the limit that bit us is declared
    assert d["coverage"]["facts"]["indirect calls unresolved"] == 0
    assert any("Acquire@AcquireSpinLock" in p
               for p in d["coverage"]["facts"]["lock primitives modeled"])
