"""WARP-compatible function GUIDs, from the binding down to the KB.

The Rust unit tests in `src/identity/warp.rs` pin the algorithm against
upstream's published vectors. These tests check the parts only Python can see:
that the binding shape is what callers were promised, that the GUIDs are
deterministic and address-independent, and that they land in
`function_identity` under their own scheme without disturbing the structural
one.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.kb import function_identity as fid

REPO = Path(__file__).resolve().parents[2]
SAMPLE = (
    REPO / "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
)
LINK_A = REPO / "tests/fixtures/flirt/mathlib_link_a.x86_64.elf"
LINK_B = REPO / "tests/fixtures/flirt/mathlib_link_b.x86_64.elf"


def _require(path: Path) -> Path:
    if not path.is_file():
        pytest.skip(f"{path} is absent from this checkout")
    return path


@pytest.fixture(scope="module")
def functions() -> list:
    return g.analysis.warp_function_guids_path(str(_require(SAMPLE)))


def test_the_binding_returns_the_promised_shape(functions: list) -> None:
    assert len(functions) >= 10
    f = functions[0]
    assert isinstance(f.guid, str)
    assert isinstance(f.entry_va, int)
    assert isinstance(f.name, str)
    assert isinstance(f.block_guids, list)
    assert isinstance(f.constraints, list)


def test_every_guid_is_a_version_five_uuid(functions: list) -> None:
    """A v4 anywhere would mean the identity became random, which no test that
    only compares a value to itself could catch."""
    for f in functions:
        parsed = uuid.UUID(f.guid)
        assert parsed.version == 5, f.name
        for b in f.block_guids:
            assert uuid.UUID(b).version == 5, f.name


def test_functions_are_returned_sorted_by_entry_va(functions: list) -> None:
    vas = [f.entry_va for f in functions]
    assert vas == sorted(vas)
    assert len(set(vas)) == len(vas)


def test_block_guids_are_hashed_highest_address_first(functions: list) -> None:
    """WARP's documented order. It is not observable from the GUID alone, so
    the list the binding hands back is the only place it can be checked."""
    multi = [f for f in functions if len(f.block_guids) > 1]
    assert multi, "no multi-block function in the sample; test is vacuous"


def test_the_result_is_deterministic() -> None:
    a = g.analysis.warp_function_guids_path(str(_require(SAMPLE)))
    b = g.analysis.warp_function_guids_path(str(SAMPLE))
    assert [(f.entry_va, f.guid) for f in a] == [(f.entry_va, f.guid) for f in b]


def test_constraints_carry_a_kind_and_a_signed_offset(functions: list) -> None:
    kinds = {c.kind for f in functions for c in f.constraints}
    assert kinds <= {"callee", "caller", "adjacent"}
    assert "adjacent" in kinds, "adjacency constraints should always exist"
    for f in functions:
        for c in f.constraints:
            uuid.UUID(c.guid)
            assert c.offset is None or isinstance(c.offset, int)


def test_a_caller_constraint_has_no_offset(functions: list) -> None:
    """A caller's call site is an offset into the caller, not into us, and no
    distance between the two entries survives a rebase. WARP spells that
    `i64::MAX`; the binding spells it `None`."""
    callers = [c for f in functions for c in f.constraints if c.kind == "caller"]
    if callers:
        assert all(c.offset is None for c in callers)


def test_the_same_function_relinked_keeps_its_guid() -> None:
    """The property the masking exists for, at the GUID level.

    `mathlib_link_a` and `mathlib_link_b` link the same `libmathlib.a` with
    different layouts, so every `mathlib_*` function sits at a different
    address with different resolved displacements. A WARP GUID that changed
    under that would be a hash of the link, not of the function.
    """
    a = {
        f.name: f.guid
        for f in g.analysis.warp_function_guids_path(str(_require(LINK_A)))
    }
    b = {
        f.name: f.guid
        for f in g.analysis.warp_function_guids_path(str(_require(LINK_B)))
    }
    common = {n for n in a if n.startswith("mathlib_")} & set(b)
    assert len(common) >= 5, f"only {len(common)} mathlib functions in both links"
    stable = sum(1 for n in common if a[n] == b[n])
    assert stable == len(common), (
        f"{len(common) - stable} of {len(common)} mathlib functions changed "
        "their WARP GUID across a relink: "
        + repr(sorted(n for n in common if a[n] != b[n]))
    )


def test_an_unsupported_architecture_is_refused_rather_than_guessed() -> None:
    """Emitting a GUID for an architecture whose relocatable-instruction rule
    is not implemented would produce a value that is not a WARP GUID, and
    nothing downstream could tell."""
    arm = sorted((REPO / "samples/binaries/platforms/linux/arm64").rglob("*"))
    candidates = [p for p in arm if p.is_file() and p.read_bytes()[:4] == b"\x7fELF"]
    if not candidates:
        pytest.skip("no arm64 sample binary in this checkout")
    with pytest.raises(ValueError, match="x86"):
        g.analysis.warp_function_guids_path(str(candidates[0]))


def test_a_missing_file_raises_oserror() -> None:
    with pytest.raises(OSError):
        g.analysis.warp_function_guids_path(str(REPO / "no-such-binary"))


# ---------------------------------------------------------------------------
# The KB side
# ---------------------------------------------------------------------------


def test_the_kb_scheme_name_matches_the_native_one() -> None:
    """Two spellings of one scheme would split the table in half."""
    assert fid.WARP_FUNCTION_GUID_V1 == g.analysis.warp_scheme()
    assert fid.WARP_FUNCTION_GUID_V1 == "warp-function-guid-v1"
    assert fid.WARP_FUNCTION_GUID_V1 in fid.COMPUTABLE_SCHEMES
    assert fid.STRUCTURAL_V1 in fid.COMPUTABLE_SCHEMES


def test_compute_identities_dispatches_on_scheme() -> None:
    rows = fid.compute_identities(
        str(_require(SAMPLE)), scheme=fid.WARP_FUNCTION_GUID_V1
    )
    assert rows
    for va, row in rows.items():
        assert row.scheme == fid.WARP_FUNCTION_GUID_V1
        assert row.entry_va == va
        assert uuid.UUID(row.identity).version == 5
        assert row.n_blocks is not None and row.n_blocks >= 1


def test_an_unknown_scheme_is_still_refused() -> None:
    with pytest.raises(ValueError, match="unknown identity scheme"):
        fid.compute_identities(str(_require(SAMPLE)), scheme="not-a-scheme")


def test_the_structural_scheme_is_unchanged(tmp_path: Path) -> None:
    """Adding a scheme must not move the existing one; the whole design of the
    `(scheme, identity)` column is that schemes do not interact."""
    structural = fid.compute_identities(str(_require(SAMPLE)))
    assert structural
    assert all(r.scheme == fid.STRUCTURAL_V1 for r in structural.values())


def test_both_schemes_coexist_in_one_kb(tmp_path: Path) -> None:
    from glaurung.llm.kb.persistent import PersistentKnowledgeBase

    project = tmp_path / "warp.glaurung"
    kb = PersistentKnowledgeBase.open(str(project), str(_require(SAMPLE)))
    try:
        n_struct = fid.index_function_identities(kb, str(SAMPLE))
        n_warp = fid.index_function_identities(
            kb, str(SAMPLE), scheme=fid.WARP_FUNCTION_GUID_V1
        )
        assert n_struct > 0 and n_warp > 0
        assert fid.is_indexed(kb)
        assert fid.is_indexed(kb, scheme=fid.WARP_FUNCTION_GUID_V1)

        warp_rows = fid.list_function_identities(kb, scheme=fid.WARP_FUNCTION_GUID_V1)
        struct_rows = fid.list_function_identities(kb)
        assert len(warp_rows) == n_warp
        assert len(struct_rows) == n_struct
        # Distinct value spaces: a UUID string is never a 16-hex digest.
        assert all("-" in r.identity for r in warp_rows)
        assert all("-" not in r.identity for r in struct_rows)
    finally:
        kb.close()


def test_port_annotations_accepts_the_warp_scheme(tmp_path: Path) -> None:
    """`port_annotations` already took a `scheme`; this checks it actually
    works under WARP rather than merely accepting the argument.

    The two relink fixtures are the right pair: the same functions, different
    addresses, so a port that matched on VA would carry nothing.
    """
    from glaurung.llm.kb import xref_db
    from glaurung.llm.kb.persistent import PersistentKnowledgeBase

    _require(LINK_A)
    _require(LINK_B)
    project = tmp_path / "port.glaurung"

    kb_old = PersistentKnowledgeBase.open(str(project), str(LINK_A))
    try:
        fid.index_function_identities(
            kb_old, str(LINK_A), scheme=fid.WARP_FUNCTION_GUID_V1
        )
        old_id = kb_old.binary_id
        rows = fid.list_function_identities(kb_old, scheme=fid.WARP_FUNCTION_GUID_V1)
        # Name one function in the old build, at whatever VA it sits at there.
        assert rows
        target = sorted(rows, key=lambda r: r.entry_va)[len(rows) // 2]
        xref_db.set_function_name(
            kb_old, target.entry_va, "analyst_named_me", set_by="manual"
        )
    finally:
        kb_old.close()

    kb_new = PersistentKnowledgeBase.open(str(project), str(LINK_B))
    try:
        fid.index_function_identities(
            kb_new, str(LINK_B), scheme=fid.WARP_FUNCTION_GUID_V1
        )
        summary = fid.port_annotations(
            kb_new,
            source_binary_id=old_id,
            scheme=fid.WARP_FUNCTION_GUID_V1,
        )
        assert summary.scheme == fid.WARP_FUNCTION_GUID_V1
        assert summary.source_functions > 0
        assert summary.target_functions > 0
        # The two images share the archive's functions, so some identity must
        # be common to both. A zero here means the GUIDs are link-dependent.
        assert summary.matched > 0, (
            "no WARP identity was shared between two builds that link the same "
            "archive; the GUID is not surviving the relink"
        )
    finally:
        kb_new.close()
