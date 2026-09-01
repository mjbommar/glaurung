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

What does not
-------------

**Types.** `src/symbols/pdb.rs` parses the TPI stream in detail --
`LF_PROCEDURE` return types and arglists, struct field layouts, bitfield
storage -- and `src/ir/pdb_fields.rs` applies FIELD displacement hints only.
Its own docstring is explicit: it "does not infer the concrete struct type of a
base register yet". Nothing applies procedure prototypes to recovered
signatures, so every parameter type below comes from ABI/dataflow inference
with the PDB sitting unread beside it.

The missing link is specific and worth stating, because "wire the prototypes
up" sounds like an afternoon and is not. `PdbFunctionPrototype` is a TPI record
keyed by `type_index` and carries **no address**. `PdbPublicSymbol` carries a
name and an address but **no type index**. The records that carry both are
`S_GPROC32`/`S_LPROC32` in the DBI module streams, and the reader does not
parse them. Until it does there is no VA -> prototype mapping to apply.

Why these assertions are written as they are
--------------------------------------------

The recovered types are pinned as *what they are today*, each with the source
declaration beside it. A test that asserted the correct types would fail on day
one and be deleted; a test that asserts nothing would let the gap widen
silently. When prototypes are wired up these assertions SHOULD fail, and the
failure message says what the right answer is.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE_DIR = ROOT / "tests" / "pdb_types"
DLL = FIXTURE_DIR / "types.dll"
PDB = FIXTURE_DIR / "types.pdb"

#: (function, source declaration, recovered-today signature).
#: `scale_pair` is the control: it has no struct or double, and ABI inference
#: alone gets its arity and widths right. The other four are what PDB types
#: would fix.
PROTOTYPES = [
    (
        "point_sum",
        "int point_sum(struct Point p)",
        "unsigned int point_sum(long arg0)",
        "a by-value struct is flattened to the register that carries it",
    ),
    (
        "record_value",
        "int record_value(struct Record *r)",
        "unsigned int record_value(int * arg0)",
        "the pointee is guessed from the first access, not read from the PDB",
    ),
    (
        "scale_pair",
        "int scale_pair(int a, short b, char c)",
        "unsigned int scale_pair(int arg0, short arg1, signed char arg2)",
        "CONTROL: arity and integer widths are right without the PDB",
    ),
    (
        "mix_float",
        "double mix_float(double d, float f)",
        "double mix_float(float arg0, float arg1)",
        "the double parameter is recovered as float -- both arrive in xmm",
    ),
    (
        "widen",
        "unsigned long long widen(unsigned int v)",
        "unsigned long widen(int arg0)",
        "signedness and long-long width are not recoverable from the ABI alone",
    ),
]


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
    assert set(m.values()) >= {p[0] for p in PROTOTYPES}, sorted(m.values())
    # Addresses must be real VAs in the image, not RVAs or zero.
    assert all(va > 0x1000 for va in m), sorted(hex(v) for v in m)


# --- what does not, pinned so a fix is visible ------------------------------


@pytest.mark.parametrize(
    ("func", "source", "today", "why"),
    PROTOTYPES,
    ids=[p[0] for p in PROTOTYPES],
)
def test_recovered_prototype_is_what_it_is_today(func, source, today, why):
    """Pin the current signature against the source declaration.

    When PDB procedure prototypes are wired up this SHOULD fail, and the
    message carries the answer it should then produce.
    """
    got = signature(func)
    assert got == today, (
        f"{func}: recovered signature changed.\n"
        f"  source declares : {source}\n"
        f"  pinned as       : {today}\n"
        f"  now produces    : {got}\n"
        f"  ({why})\n"
        "If this is the PDB prototype wiring landing, update the pin -- and "
        "check the def-use census, because a signature change moves it."
    )


def test_the_control_case_needs_no_pdb():
    """`scale_pair` proves the lane measures PDB types, not general breakage.

    Its arity and integer widths are right from ABI inference alone. If this
    one ever regresses, the problem is not the PDB.
    """
    assert signature("scale_pair") == (
        "unsigned int scale_pair(int arg0, short arg1, signed char arg2)"
    )


def test_no_struct_type_reaches_a_recovered_signature():
    """The gap, stated once as a property rather than five pins.

    Both `struct Point` and `struct Record` are fully described in the PDB's
    TPI stream -- `find_struct_layout` returns their fields -- and neither name
    appears in any recovered prototype.
    """
    sigs = " ".join(signature(f) for f, *_ in PROTOTYPES)
    assert not re.search(r"\bstruct\s+(Point|Record)\b", sigs), (
        "a PDB struct type reached a signature -- the prototype wiring may "
        f"have landed; update this lane:\n{sigs}"
    )
