"""Tests for PE import-call-site recovery (xrefs-to-imported-symbol).

Covers the Rust `analysis.pe_import_call_sites_path` binding and the
`windows_analysis.import_callers` attribution helper.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g
import glaurung.windows_analysis as wa

ROOT = Path(__file__).resolve().parents[2]
OVERLAY_PE = ROOT / "python/tests/samples/pe_with_overlay.exe"
MSVC_PDB = ROOT / "tests/fixtures/msvc-pdb"
KERNEL32 = MSVC_PDB / "kernel32.dll"


@pytest.mark.skipif(not OVERLAY_PE.is_file(), reason="overlay PE sample missing")
def test_call_sites_are_well_formed_and_named() -> None:
    sites = g.analysis.pe_import_call_sites_path(str(OVERLAY_PE))
    assert sites, "expected at least one import call site"
    iat_names = {va: name for va, name in g.analysis.pe_iat_map_path(str(OVERLAY_PE))}
    for site_va, iat_va, name in sites:
        assert isinstance(site_va, int) and site_va > 0
        # every recorded target must be a real IAT slot with the matching name
        assert iat_va in iat_names
        assert iat_names[iat_va] == name
        assert name  # non-empty import name


@pytest.mark.skipif(not OVERLAY_PE.is_file(), reason="overlay PE sample missing")
def test_import_callers_groups_every_site() -> None:
    sites = g.analysis.pe_import_call_sites_path(str(OVERLAY_PE))
    rows = wa.import_callers(str(OVERLAY_PE))  # no PDB -> grouped per import only
    assert sum(row["count"] for row in rows) == len(sites)
    # filtering to one symbol matches the raw count for that symbol
    target = sites[0][2]
    raw = sum(1 for s in sites if s[2] == target)
    filtered = wa.import_callers(str(OVERLAY_PE), target)
    assert sum(row["count"] for row in filtered) == raw
    assert all(row["import_name"] == target for row in filtered)


@pytest.mark.skipif(not KERNEL32.is_file(), reason="kernel32 msvc-pdb fixture missing")
def test_import_callers_pdb_attribution() -> None:
    sites = g.analysis.pe_import_call_sites_path(str(KERNEL32))
    assert sites, "kernel32 should have import call sites"
    symmap = g.symbols.pdb_symbol_map(str(KERNEL32), str(MSVC_PDB))
    if not symmap:
        pytest.skip("kernel32 PDB public-symbol map unavailable in this environment")
    rows = wa.import_callers(str(KERNEL32), pdb_cache=str(MSVC_PDB))
    # at least some call sites should attribute to a named containing function
    attributed = [r for r in rows if r["function"] is not None]
    assert attributed, "expected PDB attribution of at least one call site"
    for r in attributed:
        assert r["function_va"] is not None
        assert r["function_hex"] == f"0x{r['function_va']:x}"
        # the function entry must precede its call sites
        assert min(r["call_sites"]) >= r["function_va"]
