"""Durable function identity: annotations must survive a recompile.

Every annotation in a ``.glaurung`` KB is keyed on
``(binary_id, absolute entry VA)`` where ``binary_id`` is anchored to the
SHA-256 of the whole file. Recompile the binary and both halves of that
key move at once: a new ``binaries`` row is inserted and every stored VA
points at different code. The old annotations are still in the file, and
nothing can reach them.

These tests build a REAL recompile pair with the host compiler -- the
same C source, rebuilt after an unrelated edit -- and require that a
manually-typed function name, prototype and stack variable are
recoverable in the new build via a content-derived identity.

The pair is our own C, compiled here. Nothing is mocked: the sha256
really changes, the entry VA really moves, and the annotations really
are orphaned before the port runs.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.kb import function_identity as fid
from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


# The function whose annotation must survive. Its body is byte-for-byte
# the same C in both builds; only its address moves.
_TARGET = "checksum"

_COMMON = """
int checksum(const unsigned char *p, int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) {
        acc = (acc << 3) ^ (int)p[i];
        if (acc < 0) acc = -acc;
    }
    return acc;
}
"""

_V1_SRC = (
    "#include <stdio.h>\n"
    + _COMMON
    + """
int helper(int x) { return x + 1; }

int main(int argc, char **argv) {
    (void)argv;
    unsigned char buf[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    printf("%d %d\\n", checksum(buf, 8), helper(argc));
    return 0;
}
"""
)

# v2 is the same program after an unrelated edit: two new functions land
# ahead of `checksum` in the text section, so `checksum` shifts to a new
# (and differently aligned) address without a single byte of its own
# source changing.
_V2_SRC = (
    "#include <stdio.h>\n"
    + """
int padding_a(int x) { return x * 7 - 3; }
int padding_b(int x) { return padding_a(x) ^ 0x5a5a; }
"""
    + _COMMON
    + """
int helper(int x) { return padding_b(x) + 1; }

int main(int argc, char **argv) {
    (void)argv;
    unsigned char buf[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    printf("%d %d\\n", checksum(buf, 8), helper(argc));
    return 0;
}
"""
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def recompile_pair(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """Compile the same program twice, the second time after an
    unrelated edit. Returns ``(v1, v2)``."""
    if shutil.which("gcc") is None:
        pytest.skip("gcc is not on PATH; cannot build a real recompile pair")
    d = tmp_path_factory.mktemp("recompile")
    out: list[Path] = []
    for name, src in (("v1", _V1_SRC), ("v2", _V2_SRC)):
        c = d / f"{name}.c"
        c.write_text(src)
        exe = d / name
        r = subprocess.run(
            ["gcc", "-O1", "-o", str(exe), str(c)],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            pytest.skip(f"gcc failed to build {name}: {r.stderr.strip()[-300:]}")
        out.append(exe)
    return out[0], out[1]


def _entry_va(binary: Path, name: str) -> int:
    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    for f in funcs:
        if f.name == name:
            return int(f.entry_point.value)
    raise AssertionError(f"{name} not found in {binary}")


# ---------------------------------------------------------------------------
# The premise: the recompile really does break the key.
# ---------------------------------------------------------------------------


def test_recompile_changes_the_sha256_and_moves_the_function(
    recompile_pair: tuple[Path, Path],
) -> None:
    """Both halves of ``(binary_id, entry_va)`` move on a recompile."""
    v1, v2 = recompile_pair
    assert _sha256(v1) != _sha256(v2), (
        "the two builds hash identically -- the fixture is not exercising "
        "the recompile case at all"
    )
    va1, va2 = _entry_va(v1, _TARGET), _entry_va(v2, _TARGET)
    assert va1 != va2, (
        f"{_TARGET} sits at {va1:#x} in both builds; the fixture is not "
        "exercising the address-shift case"
    )


def test_a_recompile_orphans_every_annotation_keyed_by_va(
    recompile_pair: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    """The defect, stated as a test. Annotate v1, open the SAME project
    file against v2, and the annotation is unreachable -- no error, no
    warning, just zero rows."""
    v1, v2 = recompile_pair
    db = tmp_path / "orphan.glaurung"

    kb1 = PersistentKnowledgeBase.open(db, binary_path=v1)
    xref_db.set_function_name(kb1, _entry_va(v1, _TARGET), "verify_packet_crc")
    old_binary_id = kb1.binary_id
    kb1.close()

    kb2 = PersistentKnowledgeBase.open(db, binary_path=v2)
    assert kb2.binary_id != old_binary_id, (
        "the recompiled binary reused the old binaries row; the premise of "
        "this test no longer holds"
    )
    assert xref_db.get_function_name(kb2, _entry_va(v2, _TARGET)) is None
    assert xref_db.list_function_names(kb2) == [], (
        "annotations leaked across binary_id -- they should be orphaned, "
        "which is precisely the defect the identity index repairs"
    )
    kb2.close()


# ---------------------------------------------------------------------------
# The identity itself has to survive the recompile.
# ---------------------------------------------------------------------------


def test_the_identity_of_an_unchanged_function_survives_the_recompile(
    recompile_pair: tuple[Path, Path],
) -> None:
    """``checksum`` is the same C in both builds. Its content-derived
    identity must therefore be the same string, even though it moved to a
    differently aligned address (which makes the assembler emit a
    different-length alignment NOP ahead of the loop head)."""
    v1, v2 = recompile_pair
    id1 = fid.compute_identities(str(v1))
    id2 = fid.compute_identities(str(v2))
    va1, va2 = _entry_va(v1, _TARGET), _entry_va(v2, _TARGET)
    assert va1 in id1 and va2 in id2, "the target function got no identity at all"
    assert id1[va1].identity == id2[va2].identity, (
        f"{_TARGET} changed identity across a recompile that did not touch "
        f"it: {id1[va1].identity} at {va1:#x} vs {id2[va2].identity} at "
        f"{va2:#x}. A content-derived identity that moves when the content "
        "did not cannot carry an annotation forward."
    )


def test_a_function_that_really_changed_gets_a_different_identity(
    recompile_pair: tuple[Path, Path],
) -> None:
    """The identity has to discriminate, not just agree. ``helper``
    gained a call in v2; its identity must move."""
    v1, v2 = recompile_pair
    id1 = fid.compute_identities(str(v1))
    id2 = fid.compute_identities(str(v2))
    h1 = id1[_entry_va(v1, "helper")].identity
    h2 = id2[_entry_va(v2, "helper")].identity
    assert h1 != h2, (
        f"`helper` has identity {h1} in both builds, but v2's helper calls "
        "padding_b and v1's does not -- the identity is not discriminating"
    )


# ---------------------------------------------------------------------------
# Storage + lookup.
# ---------------------------------------------------------------------------


def test_identities_are_stored_and_looked_up_by_entry_va(
    recompile_pair: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    v1, _ = recompile_pair
    db = tmp_path / "store.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=v1)
    assert not fid.is_indexed(kb)
    n = fid.index_function_identities(kb, str(v1))
    assert n > 0, "indexing stored no identities at all"
    assert fid.is_indexed(kb)
    va = _entry_va(v1, _TARGET)
    row = fid.get_function_identity(kb, va)
    assert row is not None, f"no identity stored for {_TARGET} at {va:#x}"
    assert row.scheme == fid.STRUCTURAL_V1
    assert row.identity
    # Re-indexing refreshes in place rather than duplicating.
    assert fid.index_function_identities(kb, str(v1)) == n
    assert len(fid.list_function_identities(kb)) == n
    kb.close()


def test_an_unknown_scheme_is_an_error_not_an_empty_result(
    recompile_pair: tuple[Path, Path],
) -> None:
    """An identity scheme this build cannot compute must say so. Returning
    an empty map would be indistinguishable from a binary with no
    functions, and would silently index nothing."""
    v1, _ = recompile_pair
    with pytest.raises(ValueError, match="unknown identity scheme"):
        fid.compute_identities(str(v1), scheme="warp-function-guid-v1")


def test_lookup_by_identity_finds_the_function_in_another_binary(
    recompile_pair: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    """The lookup the VA key cannot do: given a stored identity from the
    old build, find where that function lives in the new one."""
    v1, v2 = recompile_pair
    db = tmp_path / "lookup.glaurung"

    kb1 = PersistentKnowledgeBase.open(db, binary_path=v1)
    fid.index_function_identities(kb1, str(v1))
    old_identity = fid.get_function_identity(kb1, _entry_va(v1, _TARGET))
    assert old_identity is not None
    kb1.close()

    kb2 = PersistentKnowledgeBase.open(db, binary_path=v2)
    fid.index_function_identities(kb2, str(v2))
    found = fid.resolve_entry_va(kb2, old_identity.identity)
    assert found == _entry_va(v2, _TARGET), (
        f"identity {old_identity.identity} resolved to {found} in the new "
        f"build; {_TARGET} is at {_entry_va(v2, _TARGET):#x}"
    )
    kb2.close()


def test_an_unknown_identity_resolves_to_nothing(
    recompile_pair: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    v1, _ = recompile_pair
    db = tmp_path / "unknown.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=v1)
    fid.index_function_identities(kb, str(v1))
    assert fid.resolve_entry_va(kb, "0000000000000000") is None
    kb.close()


# ---------------------------------------------------------------------------
# The decisive test: recover a manual annotation after a recompile.
# ---------------------------------------------------------------------------


def test_a_manual_annotation_is_recoverable_after_a_recompile(
    recompile_pair: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    """Annotate v1 by hand, rebuild the binary so its sha256 changes,
    and recover the annotation in v2 through the identity index."""
    v1, v2 = recompile_pair
    db = tmp_path / "port.glaurung"

    va1 = _entry_va(v1, _TARGET)
    kb1 = PersistentKnowledgeBase.open(db, binary_path=v1)
    fid.index_function_identities(kb1, str(v1))
    xref_db.set_function_name(kb1, va1, "verify_packet_crc")
    xref_db.set_comment(kb1, va1, "rolling XOR checksum; overflow-clamped")
    xref_db.set_function_prototype(
        kb1,
        "verify_packet_crc",
        "int",
        [
            xref_db.FunctionParam(name="buf", c_type="const unsigned char *"),
            xref_db.FunctionParam(name="len", c_type="int"),
        ],
    )
    xref_db.set_stack_var(kb1, va1, -8, "accumulator", c_type="int")
    source_binary_id = kb1.binary_id
    kb1.close()

    # --- the rebuild happens here: new file, new sha256, new binary_id ---
    va2 = _entry_va(v2, _TARGET)
    kb2 = PersistentKnowledgeBase.open(db, binary_path=v2)
    fid.index_function_identities(kb2, str(v2))

    # Precondition: nothing is reachable yet.
    assert xref_db.get_function_name(kb2, va2) is None

    summary = fid.port_annotations(kb2, source_binary_id=source_binary_id)
    assert summary.matched > 0, (
        f"no function in the new build matched an identity from binary_id="
        f"{source_binary_id}: {summary}"
    )

    name = xref_db.get_function_name(kb2, va2)
    assert name is not None, (
        f"{_TARGET} moved {va1:#x} -> {va2:#x} across the recompile and its "
        f"manual name was not recovered. port summary: {summary}"
    )
    assert name.canonical == "verify_packet_crc"
    assert name.set_by == "manual", (
        "a ported analyst name lost its manual provenance, so the next "
        f"automatic pass will silently overwrite it (set_by={name.set_by!r})"
    )

    assert xref_db.get_comment(kb2, va2) == (
        "rolling XOR checksum; overflow-clamped"
    ), "the entry-VA comment did not follow the function to its new address"

    proto = xref_db.get_function_prototype(kb2, "verify_packet_crc")
    assert proto is not None, (
        "the prototype is keyed by function_name, so porting the name "
        "without porting the prototype leaves it orphaned in the old "
        "binary_id"
    )
    assert proto.return_type == "int"
    assert [p.name for p in proto.params] == ["buf", "len"]

    var = xref_db.get_stack_var(kb2, va2, -8)
    assert var is not None, "the stack variable did not follow the function"
    assert var.name == "accumulator"
    kb2.close()


def test_the_port_refuses_to_clobber_a_manual_annotation_in_the_target(
    recompile_pair: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    """Manual always wins -- including over a port. If the analyst has
    already named the function in the new build, the old build's name
    must not overwrite it."""
    v1, v2 = recompile_pair
    db = tmp_path / "noclobber.glaurung"

    kb1 = PersistentKnowledgeBase.open(db, binary_path=v1)
    fid.index_function_identities(kb1, str(v1))
    xref_db.set_function_name(kb1, _entry_va(v1, _TARGET), "old_name")
    source_binary_id = kb1.binary_id
    kb1.close()

    va2 = _entry_va(v2, _TARGET)
    kb2 = PersistentKnowledgeBase.open(db, binary_path=v2)
    fid.index_function_identities(kb2, str(v2))
    xref_db.set_function_name(kb2, va2, "name_i_typed_today")

    summary = fid.port_annotations(kb2, source_binary_id=source_binary_id)
    got = xref_db.get_function_name(kb2, va2)
    assert got is not None and got.canonical == "name_i_typed_today", (
        f"the port overwrote a manual name in the target with {got and got.canonical!r}"
    )
    assert summary.names_skipped_manual >= 1, (
        f"the port did not report the skip it performed: {summary}"
    )
    kb2.close()


def test_an_ambiguous_identity_is_never_ported(
    recompile_pair: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    """Two functions with the same identity (in either build) cannot be
    told apart, so neither may carry an annotation across. A silent
    wrong port is worse than no port."""
    v1, v2 = recompile_pair
    db = tmp_path / "ambiguous.glaurung"

    kb1 = PersistentKnowledgeBase.open(db, binary_path=v1)
    fid.index_function_identities(kb1, str(v1))
    ids = fid.list_function_identities(kb1)
    by_value: dict[str, list[int]] = {}
    for r in ids:
        by_value.setdefault(r.identity, []).append(r.entry_va)
    dupes = {k: v for k, v in by_value.items() if len(v) > 1}
    if not dupes:
        pytest.skip("this build has no colliding identities to exercise")
    for va in next(iter(dupes.values())):
        xref_db.set_function_name(kb1, va, f"ambiguous_{va:x}")
    source_binary_id = kb1.binary_id
    kb1.close()

    kb2 = PersistentKnowledgeBase.open(db, binary_path=v2)
    fid.index_function_identities(kb2, str(v2))
    summary = fid.port_annotations(kb2, source_binary_id=source_binary_id)
    assert summary.ambiguous > 0, (
        f"the source build has colliding identities {list(dupes)} but the "
        f"port reported none ambiguous: {summary}"
    )
    for identity in dupes:
        for _bid, entry_va in fid.find_by_identity(kb2, identity):
            got = xref_db.get_function_name(kb2, entry_va)
            assert got is None or not got.canonical.startswith("ambiguous_"), (
                f"an ambiguous identity was ported anyway, onto {entry_va:#x}"
            )
    kb2.close()
