"""Function identity in a PE that has no COFF symbol table.

Why this lane exists
--------------------

The DecBench name-to-body resolver was built against mingw output, which
carries a COFF symbol table with i386 decoration (`_worker@4`). **Shipped
Windows binaries have no COFF symbol table at all**: `win10-dismcore.dll` holds
zero COFF symbols against 4 exports and 222 imports, and `lld-link` produces
the same shape. A resolver reading only that table reports every function in
such a binary as absent -- which is indistinguishable, downstream, from a
binary whose functions genuinely are not there.

So identity has three sources, and they answer different questions:

* **COFF** carries decoration, and only mingw-style builds have it;
* **exports** survive in shipped binaries and carry the undecorated name;
* **imports** are the only source that can prove a name is *external*.

`SymbolEntry.source` records which one answered, because a test for the
decoration ladder must be able to look at COFF alone -- export names are
undecorated, so they match exactly whether or not the ladder works, and would
silently rescue a broken one. That separation is why
`test_decbench_symbol_resolution.py` filters to COFF and this file does not.

The fixtures
------------

`identN.dll` at both bitnesses, plus `helperN.dll` whose generated import
library is what makes `imported_helper` a *real* entry in ident's import table.
Synthesizing that entry would have tested the test.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE_DIR = ROOT / "tests" / "pe_identity"
sys.path.insert(0, str(ROOT / "tools"))

import decbench_symbols as S  # ty: ignore[unresolved-import]  # added above

BITNESS = ["32", "64"]
LOCAL_BODIES = ["local_body", "calls_import", "calls_local"]


def dll(bits: str) -> Path:
    return FIXTURE_DIR / f"ident{bits}.dll"


@pytest.fixture(scope="module", params=BITNESS, ids=[f"pe{b}" for b in BITNESS])
def target(request) -> tuple[str, Path]:
    p = dll(request.param)
    if not p.is_file():
        pytest.skip(f"{p.name} absent")
    return request.param, p


def test_the_fixtures_match_their_manifest():
    m = json.loads((FIXTURE_DIR / "MANIFEST.json").read_text())
    for name, rec in m.items():
        if not isinstance(rec, dict):
            continue
        p = FIXTURE_DIR / name
        assert p.is_file(), f"{name} is committed; the checkout is broken"
        assert hashlib.sha256(p.read_bytes()).hexdigest() == rec["sha256"], name


def test_these_fixtures_really_have_no_coff_symbols(target):
    """The premise. If lld ever starts emitting one, this lane stops testing
    what it claims to and the COFF path would quietly cover for it."""
    _, p = target
    coff = [e for e in S.load_entries(str(p)) if e.source == "coff"]
    assert not coff, (
        f"{p.name} grew a COFF symbol table ({len(coff)} rows) -- this lane "
        "exists to cover the case where there is none."
    )


@pytest.mark.parametrize("func", LOCAL_BODIES)
def test_a_local_body_resolves_from_the_export_table(target, func):
    bits, p = target
    r = S.resolve_many(str(p), [func])[func]
    assert r.ok, (
        f"{p.name}: {func} did not resolve ({r.disposition}). It is an export "
        "of this DLL; with no COFF table the export table is the only place "
        "its address exists."
    )
    assert r.source == "export", r.source
    assert r.address and r.address > 0x1000, hex(r.address or 0)
    # PE32 loads at 0x10000000 here, PE32+ at 0x180000000: the address must be
    # a real VA rather than an RVA that happens to look plausible.
    base = 0x10000000 if bits == "32" else 0x180000000
    assert r.address >= base, f"{hex(r.address)} is below image base {hex(base)}"


def test_an_import_is_reported_as_external(target):
    """DecBench F1b. `imported_helper` lives in helperN.dll.

    Answering a local-body request with the IAT slot's address would decompile
    a thunk as though it were the function, which is worse than reporting
    nothing -- it looks like a successful recovery.
    """
    _, p = target
    r = S.resolve_many(str(p), ["imported_helper"])["imported_helper"]
    assert r.disposition is S.Disposition.IMPORT, (
        f"{p.name}: imported_helper reported {r.disposition}, not IMPORT"
    )
    assert r.address is None


def test_an_absent_name_is_still_absent(target):
    """The negative control: merging three sources must not make everything
    resolve to something."""
    _, p = target
    r = S.resolve_many(str(p), ["definitely_not_here"])["definitely_not_here"]
    assert r.disposition is S.Disposition.ABSENT
    assert r.address is None


def test_the_pdb_is_locatable_at_both_bitnesses(target):
    import glaurung

    _, p = target
    s = glaurung.symbols.list_symbols(str(p))
    assert s.debug_info_present is True
    assert s.pdb_path and s.pdb_path.lower().endswith(".pdb"), s.pdb_path


def test_export_addresses_agree_with_the_pdb(target):
    """Two independent sources for the same identity must not disagree.

    The export table and the PDB are produced by different parts of the linker;
    if they disagree about where `local_body` starts, one of the two readers is
    wrong and every downstream address is suspect.
    """
    import glaurung

    _, p = target
    # PE32 PDB public symbols are cdecl-DECORATED (`_local_body`) while the
    # export table is not, so the two must be compared canonically. The same
    # i386 decoration the F1a ladder exists for, arriving from a third source.
    exports = {
        S.canonical_name(n): va
        for va, n, _o, f in glaurung.pe_export_entries(str(p))
        if f is None
    }
    pdb = glaurung.symbols.pdb_symbol_map(str(p), str(FIXTURE_DIR))
    by_name = {S.canonical_name(v): k for k, v in pdb.items()}
    checked = 0
    for func in LOCAL_BODIES:
        if func in exports and func in by_name:
            assert exports[func] == by_name[func], (
                f"{func}: export table says {hex(exports[func])}, PDB says "
                f"{hex(by_name[func])}"
            )
            checked += 1
    assert checked, f"no function was cross-checkable; pdb had {sorted(by_name)}"


def test_an_import_thunk_is_not_offered_as_the_function(target):
    """The PDB names the import THUNK at a local address, and it must not win.

    `pdb_symbol_map` reports `imported_helper` (PE32: `_imported_helper`) at an
    address inside this image -- the jump thunk, not the callee. It is a
    genuine local address, which is what makes it dangerous: handing it back
    looks like a successful recovery and decompiles a two-instruction jump as
    the function body. This is the "local/import/thunk disposition" the lane is
    named for.
    """
    import glaurung

    _, p = target
    pdb = glaurung.symbols.pdb_symbol_map(str(p), str(FIXTURE_DIR))
    thunks = {
        va for va, name in pdb.items() if S.canonical_name(name) == "imported_helper"
    }
    assert thunks, "the PDB no longer names the thunk; this test is vacuous"
    r = S.resolve_many(str(p), ["imported_helper"])["imported_helper"]
    assert r.disposition is S.Disposition.IMPORT
    assert r.address not in thunks


def test_a_forwarded_export_is_not_a_local_body():
    """A forwarder names code in ANOTHER module.

    None of these fixtures forwards, so this asserts the classification rule
    directly rather than through a binary: `pe_export_entries` reports
    `forwarder`, and `load_entries` records a forwarded export as undefined so
    it can never satisfy a local-body request.
    """
    fwd = S.SymbolEntry(0, "Forwarded", "text", False, "export")
    local = S.SymbolEntry(0x180001000, "Real", "text", True, "export")
    assert S.resolve("Forwarded", [fwd]).disposition is S.Disposition.IMPORT
    assert S.resolve("Real", [local]).ok
