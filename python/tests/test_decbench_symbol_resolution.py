"""The DecBench name -> local-body resolver, against a real i386 PE.

Why a committed .dll
--------------------

The failure this pins (DecBench class F1a, 33 rows in the pinned run) is a
property of REAL i386 stdcall decoration: `worker_fn(int)` is `_worker_fn@4` in
the symbol table, and the `@4` is the callee-popped argument byte count, so it
differs per function and cannot be derived from the name. A hand-written symbol
table would encode my belief about what mingw emits rather than what it emits,
which is exactly the bug -- so the fixture is a real PE32 built by
`tests/decbench_adapter/build.sh` and committed, the way the decompiler canary
set is.

`tests/decbench_adapter/MANIFEST.json` records which symbol pins which clause.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE_DIR = ROOT / "tests" / "decbench_adapter"
FIXTURE = FIXTURE_DIR / "stdcall_symbols.dll"
sys.path.insert(0, str(ROOT / "tools"))

import decbench_symbols as S  # ty: ignore[unresolved-import]  # added above


@pytest.fixture(scope="module")
def entries() -> list[S.SymbolEntry]:
    assert FIXTURE.is_file(), (
        f"{FIXTURE} is COMMITTED, not built. If it is missing the checkout is "
        "broken; rebuild with tests/decbench_adapter/build.sh."
    )
    rows = S.load_entries(str(FIXTURE))
    assert rows, "the object reader returned no symbols for the fixture"
    return rows


def resolve(entries, name):
    return S.resolve(name, entries, allow_stdcall=True)


def test_the_fixture_matches_its_manifest():
    """A vacuity guard. Every test below is meaningless over the wrong bytes."""
    m = json.loads((FIXTURE_DIR / "MANIFEST.json").read_text())
    digest = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    assert digest == m["sha256"], (
        "stdcall_symbols.dll does not match MANIFEST.json. It is committed and "
        "hermetic; a mismatch means it was rebuilt without refreshing the "
        "manifest, and the clause coverage recorded there is no longer true."
    )


# --- The F1a defect itself ------------------------------------------------


@pytest.mark.parametrize(
    ("request_name", "raw"),
    [
        ("worker_fn", "_worker_fn@4"),
        ("entry_fn", "_entry_fn@12"),
        ("handler_fn", "_handler_fn@16"),
    ],
)
def test_stdcall_decorated_functions_resolve(entries, request_name, raw):
    """Clause 3, and the whole point: `_name@N` must resolve.

    This is the 33-row failure. The old resolver tried `name` then `_name` and
    stopped, so every stdcall function in the four Windows DecBench projects
    was reported unresolved while its body sat in the binary.
    """
    r = resolve(entries, request_name)
    assert r.ok, (
        f"{request_name} did not resolve ({r.disposition}). This is DecBench "
        f"failure class F1a: the symbol table holds {raw!r}."
    )
    assert r.raw_symbol == raw
    assert r.decoration is S.Decoration.STDCALL
    assert r.address


def test_the_old_two_rule_resolver_missed_all_of_them(entries):
    """The RED assertion, kept as a regression witness.

    Reproduces the previous logic (`by_name.get(nm) or by_name.get("_" + nm)`)
    and shows it finds nothing for the stdcall shapes -- so this file would have
    failed before the fix, which is the only thing that proves it tests it.
    """
    by_name = {}
    for e in entries:
        by_name.setdefault(e.name, e.address)
    for name in ("worker_fn", "entry_fn", "handler_fn"):
        old = by_name.get(name) or by_name.get("_" + name)
        assert old is None, (
            f"{name} resolves under the OLD two-rule logic, so this fixture no "
            "longer reproduces F1a and the test above proves nothing."
        )


# --- The rest of the contract ---------------------------------------------


def test_exact_name_beats_the_underscore_fallback(entries):
    """Clause 1. `worker` and `_worker` are different functions here."""
    r = resolve(entries, "worker")
    assert r.ok and r.decoration is S.Decoration.EXACT
    assert r.raw_symbol == "worker"
    exact = next(e for e in entries if e.name == "worker")
    under = next(e for e in entries if e.name == "_worker")
    assert exact.address != under.address, "fixture no longer separates them"
    assert r.address == exact.address, (
        "took the underscore symbol; that silently returns a DIFFERENT "
        "function's body and every downstream comparison is against the wrong "
        "code."
    )


def test_plain_cdecl_underscore_still_resolves(entries):
    """Clause 2 -- the one case the old resolver got right. Do not regress it."""
    r = resolve(entries, "crc32_fn")
    assert r.ok and r.decoration is S.Decoration.CDECL
    assert r.raw_symbol == "_crc32_fn"


def test_duplicate_canonical_names_are_ambiguous_not_first_wins(entries):
    """Clause 4. `_dup@8` and `_dup@12` are one name at two addresses."""
    r = resolve(entries, "dup")
    assert r.disposition is S.Disposition.AMBIGUOUS, (
        f"got {r.disposition}; picking one of two addresses that claim the same "
        "name yields a body that is confidently the wrong function."
    )
    assert r.address is None
    assert len(r.candidates) == 2, r.candidates
    assert all("_dup@" in c for c in r.candidates), r.candidates


def test_a_data_symbol_cannot_satisfy_a_function_request(entries):
    """Clause 5. `__lookalike` is data named like a function."""
    r = resolve(entries, "_lookalike")
    assert r.disposition is S.Disposition.NON_CODE, (
        f"got {r.disposition}; a data address decompiled as a function body "
        "produces plausible garbage rather than an error."
    )
    assert r.address is None


@pytest.mark.parametrize(
    "request_name", ["__register_frame_info", "__deregister_frame_info"]
)
def test_an_import_is_reported_as_an_import_not_as_absent(entries, request_name):
    """Clause 5's other half, and DecBench failure class F1b (63 rows).

    An undefined symbol has no local body *by construction*. Collapsing that
    into "absent" loses the distinction the scoring contract needs: "this
    identity is external, do not expect a body" is a correct outcome, while
    "we looked and could not find it" is a resolver failure. They must not
    share a bucket, and neither may ever return the IAT address as though it
    were a local function.
    """
    r = resolve(entries, request_name)
    assert r.disposition is S.Disposition.IMPORT, (
        f"got {r.disposition}; an import reported as absent is counted as a "
        "resolver failure it is not, and an import reported as local would "
        "decompile an IAT thunk as if it were the function's body."
    )
    assert r.address is None
    assert r.candidates and all(c.startswith("_") for c in r.candidates)


def test_an_absent_name_is_absent_not_an_error(entries):
    r = resolve(entries, "no_such_function_anywhere")
    assert r.disposition is S.Disposition.ABSENT
    assert r.address is None and not r.candidates


def test_stdcall_matching_is_opt_in(entries):
    """Clause 3's restriction. On ELF, `@` means version decoration.

    `memcpy@GLIBC_2.14` must never be matched as a local body for `memcpy`, so
    the `@N` rule is off unless the caller says the binary is i386 PE.
    """
    r = S.resolve("worker_fn", entries, allow_stdcall=False)
    assert not r.ok, "stdcall matching leaked into the non-i386-PE path"
    assert r.disposition is S.Disposition.ABSENT


def test_every_resolution_records_how_it_matched(entries):
    """Clause 6: a checkpoint must be auditable without re-reading the binary."""
    rec = resolve(entries, "worker_fn").as_record()
    assert rec["decoration"] == "stdcall-at"
    assert rec["raw_symbol"] == "_worker_fn@4"
    assert rec["disposition"] == "local"
    assert isinstance(rec["address"], int)
    json.dumps(rec)  # must be checkpoint-serializable


# --- canonical_name ---------------------------------------------------------


@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        ("_worker@4", "worker"),
        ("_entry@12", "entry"),
        ("@fastcall@8", "fastcall"),
        ("_crc32", "crc32"),
        ("worker", "worker"),
        ("_", ""),
        ("main", "main"),
        # Not decoration: no digits after the `@`.
        ("memcpy@GLIBC_2.14", "memcpy@GLIBC_2.14"),
    ],
)
def test_canonical_name(symbol, expected):
    assert S.canonical_name(symbol) == expected
