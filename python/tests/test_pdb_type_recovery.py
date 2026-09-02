"""What a PDB gives the decompiler today, and what it does not.

Phase 4 of the test estate wants a hermetic PDB type/layout lane carrying
"source declarations through recovered fields and prototypes". This is that
lane. It is built from a real PE32+/PDB pair produced by `clang-cl` and
`lld-link` on Linux, so the source types are ground truth.

What works
----------

**Names.** `pdb_symbol_map` returns all five functions at their correct VAs,
and `list_symbols().pdb_path` locates the PDB from the PE. That second part is
recent: `pdb_path` was never exposed to Python and its underlying scan read the
debug *directory* rather than following the pointer inside it, so the PDB could
not be located from the binary at all.

What now works
--------------

**Types.** `src/symbols/pdb.rs` joins `S_GPROC32`/`S_LPROC32` module symbols
to their `LF_PROCEDURE` records by TypeIndex and translates their section
offsets to PE VAs. The decompiler applies those declarations through the same
authoritative contract path used by DWARF, while retaining conflicting machine
inference as health metadata. The assertions below are the literal source
declarations from `tests/pdb_types/types.c`.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE_DIR = ROOT / "tests" / "pdb_types"
DLL = FIXTURE_DIR / "types.dll"
PDB = FIXTURE_DIR / "types.pdb"

#: `(function, source declaration, why the PDB is needed)`.
#:
#: These assert the SOURCE type, which is the answer a PDB makes available.
PROTOTYPES = [
    pytest.param("point_sum", "int point_sum(struct Point arg0)"),
    # The renderer emits `typedef struct Record Record;` before this definition,
    # so the alias is the same authoritative PDB type in valid standalone C.
    pytest.param("record_value", "int record_value(Record * arg0)"),
    pytest.param("mix_float", "double mix_float(double arg0, float arg1)"),
    pytest.param("widen", "unsigned long long widen(unsigned int arg0)"),
    pytest.param("scale_pair", "int scale_pair(int arg0, short arg1, char arg2)"),
]


#: Just the function names, for the tests that do not care about types.
#: `pytest.param` objects carry their values in `.values`, so indexing the
#: list directly stopped working when these grew xfail marks.
FUNCS = [param.values[0] for param in PROTOTYPES]


def decompile(func: str) -> str:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "glaurung.cli",
            "decompile",
            str(DLL),
            "--func",
            func,
            "--style",
            "decbench",
            "--no-color",
            "--pdb-cache",
            str(FIXTURE_DIR),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=600,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-800:]
    return proc.stdout


def signature(func: str) -> str:
    for line in decompile(func).splitlines():
        if func + "(" in line and "//" not in line:
            return line.split("{")[0].strip()
    raise AssertionError(f"no signature line for {func}")


def signature_from(body: str, func: str) -> str:
    for line in body.splitlines():
        if func + "(" in line and "//" not in line:
            return line.split("{")[0].strip()
    raise AssertionError(f"no signature line for {func}:\n{body}")


def test_the_fixture_matches_its_manifest():
    m = json.loads((FIXTURE_DIR / "MANIFEST.json").read_text())
    for name in ("types.dll", "types.pdb"):
        p = FIXTURE_DIR / name
        assert p.is_file(), f"{name} is committed; the checkout is broken"
        assert hashlib.sha256(p.read_bytes()).hexdigest() == m[name]["sha256"], (
            f"{name} does not match MANIFEST.json"
        )


# --- what works ------------------------------------------------------------


def test_the_pdb_is_locatable_from_the_pe():
    """Without `pdb_path` the PDB cannot be found from the binary at all."""
    import glaurung

    s = glaurung.symbols.list_symbols(str(DLL))
    assert s.debug_info_present is True
    assert s.pdb_path and s.pdb_path.lower().endswith(".pdb"), s.pdb_path


def test_every_function_is_named_from_the_pdb():
    import glaurung

    m = glaurung.symbols.pdb_symbol_map(str(DLL), str(FIXTURE_DIR))
    assert set(m.values()) >= set(FUNCS), sorted(m.values())
    # Addresses must be real VAs in the image, not RVAs or zero.
    assert all(va > 0x1000 for va in m), sorted(hex(v) for v in m)


# --- authoritative declaration recovery ------------------------------------


@pytest.mark.parametrize(("func", "expected"), PROTOTYPES)
def test_recovered_prototype_matches_the_source_declaration(func, expected):
    """The PDB describes these types exactly; the decompiler should use them.

    A signature change moves the def-use census; re-run it alongside.
    """
    assert signature(func) == expected


def test_all_four_entry_points_apply_the_same_pdb_declaration() -> None:
    """Address, range, batch, and whole-image paths must not drift."""
    import glaurung as g

    path = str(DLL)
    cache = str(FIXTURE_DIR)
    va = next(
        address
        for address, name in g.symbols.pdb_symbol_map(path, cache).items()
        if name == "point_sum"
    )
    by_address = g.ir.decompile_at(path, va, style="decbench", pdb_cache=cache)
    by_range = g.ir.decompile_range_at(
        path, va, va, va + 14, style="decbench", pdb_cache=cache
    )
    [(_name, _va, by_batch, *_extra)] = g.ir.decompile_many(
        path, [va], style="decbench", pdb_cache=cache
    )
    [by_all] = [
        row[2]
        for row in g.ir.decompile_all(path, style="decbench", pdb_cache=cache)
        if row[0] == "point_sum"
    ]

    assert {
        signature_from(body, "point_sum")
        for body in (by_address, by_range, by_batch, by_all)
    } == {"int point_sum(struct Point arg0)"}


def test_pdb_conflict_metadata_retains_machine_inference() -> None:
    """PDB wins rendering without deleting a contradictory inferred fact."""
    import glaurung as g

    path = str(DLL)
    cache = str(FIXTURE_DIR)
    va = next(
        address
        for address, name in g.symbols.pdb_symbol_map(path, cache).items()
        if name == "point_sum"
    )
    g.ir.take_render_verification()
    g.ir.decompile_at(path, va, style="decbench", pdb_cache=cache)
    report = g.ir.take_render_verification()
    conflicts = [
        conflict
        for conflict in report["prototype_conflicts"]
        if conflict["function"] == "point_sum"
    ]
    assert conflicts, report
    assert conflicts[0]["authoritative_source"] == "pdb"
    assert conflicts[0]["candidate_source"] == "inferred"


def test_without_a_pdb_cache_machine_recovery_remains_available() -> None:
    """Optional PDB evidence must not become a requirement to decompile PE."""
    import glaurung as g

    path = str(DLL)
    va = next(
        address
        for address, name in g.symbols.pdb_symbol_map(path, str(FIXTURE_DIR)).items()
        if name == "point_sum"
    )
    body = g.ir.decompile_at(path, va, style="decbench")
    assert "point_sum(" in body
    assert signature_from(body, "point_sum") != "int point_sum(struct Point arg0)"
