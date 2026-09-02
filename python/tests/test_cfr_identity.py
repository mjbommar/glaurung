"""The Canonical Function Representation, through its Python surface.

These exercise the binding and the KB writer against real binaries from
``tests/fixtures``/``samples`` -- there is no way to fake a lifted SSA
dataflow graph, and a fixture that did would be testing the fixture.

The invariance and metric properties are asserted on the Rust side, in
``src/identity/cfr/tests.rs`` and ``tests/identity_cfr_retrieval.rs``;
what is checked here is the shape of what crosses the boundary and that
the scheme reaches the ``function_identity`` table without disturbing the
scheme already in it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.kb.function_identity import (
    CFR_V1,
    STRUCTURAL_V1,
    compute_cfr_identities,
    index_cfr_identities,
    list_function_identities,
)

ROOT = Path(__file__).resolve().parent.parent.parent


def _first_existing(*candidates: str) -> Path:
    for candidate in candidates:
        path = ROOT / candidate
        if path.exists():
            return path
    pytest.skip(f"none of {candidates} is present in this checkout")
    raise AssertionError("unreachable")


@pytest.fixture(scope="module")
def elf_binary() -> Path:
    """A real ELF with a symbol table, small enough to sign in milliseconds."""
    return _first_existing(
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0",
        "tests/fixtures/hello-rust-release",
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
    )


def test_the_scheme_name_is_the_one_the_kb_writes(elf_binary: Path) -> None:
    """The Rust constant and the Python constant must not drift apart."""
    assert g.analysis.CFR_SCHEME == CFR_V1


def test_signatures_have_the_documented_shape(elf_binary: Path) -> None:
    signatures = g.analysis.cfr_signatures_path(str(elf_binary))
    assert signatures, f"no functions signed in {elf_binary}"
    for signature in signatures:
        assert signature.entry_va > 0
        assert signature.block_count >= 1
        assert len(signature.digest) == 64
        assert int(signature.digest, 16) >= 0
        assert signature.scheme == CFR_V1
        # (major, minor, settings); settings 0 is the default projection.
        assert signature.version == (1, 0, 0)
        # The multiset is sorted by hash, which is what makes the cosine an
        # O(n + m) merge join rather than a set intersection.
        hashes = [h for h, _ in signature.features]
        assert hashes == sorted(hashes)
        assert len(set(hashes)) == len(hashes)
        assert all(count >= 1 for _, count in signature.features)
        assert signature.width_unknown <= signature.width_total


def test_signing_the_same_file_twice_gives_the_same_bytes(elf_binary: Path) -> None:
    """Determinism, from Python, where a HashMap iteration order would show."""
    first = g.analysis.cfr_signatures_path(str(elf_binary))
    second = g.analysis.cfr_signatures_path(str(elf_binary))
    assert [s.digest for s in first] == [s.digest for s in second]
    assert [s.features for s in first] == [s.features for s in second]


def test_a_function_is_its_own_nearest_neighbour(elf_binary: Path) -> None:
    signatures = [
        s for s in g.analysis.cfr_signatures_path(str(elf_binary)) if s.features
    ]
    assert signatures
    subject = max(signatures, key=lambda s: len(s.features))
    assert g.analysis.cfr_similarity(subject, subject) == pytest.approx(1.0)
    assert g.analysis.cfr_distance(subject, subject) == pytest.approx(0.0, abs=1e-9)
    for other in signatures:
        if other.entry_va == subject.entry_va:
            continue
        assert g.analysis.cfr_similarity(subject, other) <= 1.0 + 1e-12


def test_similarity_is_symmetric(elf_binary: Path) -> None:
    signatures = g.analysis.cfr_signatures_path(str(elf_binary))
    assert len(signatures) >= 2
    a, b = signatures[0], signatures[-1]
    assert g.analysis.cfr_similarity(a, b) == pytest.approx(
        g.analysis.cfr_similarity(b, a)
    )
    assert g.analysis.cfr_distance(a, b) == pytest.approx(g.analysis.cfr_distance(b, a))


def test_nosize_is_a_different_version_and_refuses_the_comparison(
    elf_binary: Path,
) -> None:
    """A setting is part of the identity, so mixing the two is not a low score.

    Two projections are two different quotients. Answering "0.02 similar"
    would read as "distant but related"; answering 0.0 says the question
    has no answer, which is the truth.
    """
    plain = g.analysis.cfr_signatures_path(str(elf_binary))
    collapsed = g.analysis.cfr_signatures_path(str(elf_binary), nosize=True)
    assert plain[0].version == (1, 0, 0)
    assert collapsed[0].version == (1, 0, 1)
    assert g.analysis.cfr_similarity(plain[0], collapsed[0]) == 0.0


def test_a_missing_file_raises_rather_than_returning_nothing(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        g.analysis.cfr_signatures_path(str(tmp_path / "does-not-exist"))


def test_compute_cfr_identities_keys_by_entry_va(elf_binary: Path) -> None:
    identities = compute_cfr_identities(str(elf_binary))
    assert identities
    for entry_va, identity in identities.items():
        assert identity.entry_va == entry_va
        assert identity.scheme == CFR_V1
        assert len(identity.identity) == 64
        assert identity.binary_id == 0


def test_the_cfr_writer_does_not_disturb_the_structural_scheme(
    elf_binary: Path, tmp_path: Path
) -> None:
    """Both schemes coexist in one table, which is the point of the column.

    ``function_identity``'s primary key is ``(binary_id, entry_va,
    scheme)``, so a second scheme is new rows rather than a migration.
    Writing CFR must leave the structural rows exactly as they were.
    """
    from glaurung.llm.kb.function_identity import index_function_identities
    from glaurung.llm.kb.persistent import PersistentKnowledgeBase

    kb = PersistentKnowledgeBase.open(tmp_path / "project.glaurung", elf_binary)
    try:
        structural_before = index_function_identities(kb, str(elf_binary))
        structural_rows = list_function_identities(kb, scheme=STRUCTURAL_V1)
        assert len(structural_rows) == structural_before

        stored = index_cfr_identities(kb, str(elf_binary))
        assert stored > 0

        cfr_rows = list_function_identities(kb, scheme=CFR_V1)
        assert len(cfr_rows) == stored
        assert all(row.scheme == CFR_V1 for row in cfr_rows)
        assert all(len(row.identity) == 64 for row in cfr_rows)

        after = list_function_identities(kb, scheme=STRUCTURAL_V1)
        assert [(r.entry_va, r.identity) for r in after] == [
            (r.entry_va, r.identity) for r in structural_rows
        ]

        # Idempotent: a second pass refreshes in place rather than duplicating.
        assert index_cfr_identities(kb, str(elf_binary)) == stored
        assert len(list_function_identities(kb, scheme=CFR_V1)) == stored
    finally:
        kb.close()
