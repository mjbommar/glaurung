"""`python/glaurung/llm/kb/siglib.py`: signature-library provenance and
`function_match` auditing (item 7, `docs/history/program-measures-2026-09-02.md`).

Real fixtures throughout, per project policy:

- `data/sigs/glaurung-base.x86_64.flirt.json`, the shipped masked FLIRT
  library built from `libmathlib.a`.
- `tests/fixtures/flirt/mathlib_link_a.x86_64.elf` and
  `mathlib_link_b.x86_64.elf`, the two committed relink layouts of the same
  archive -- the load-bearing property throughout this module and
  `src/flirt/`/`src/identity/warp.rs` is that a signature or GUID computed
  from one layout must resolve the same way in the other.
- `samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug`,
  an entirely unrelated binary the gate and the matchers must reject.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.kb import siglib
from glaurung.llm.kb.persistent import PersistentKnowledgeBase

_REPO = Path(__file__).resolve().parents[2]
_FLIRT_LIB = _REPO / "data/sigs/glaurung-base.x86_64.flirt.json"
_LINK_A = _REPO / "tests/fixtures/flirt/mathlib_link_a.x86_64.elf"
_LINK_B = _REPO / "tests/fixtures/flirt/mathlib_link_b.x86_64.elf"
_STRIPPED = _REPO / "tests/fixtures/flirt/mathlib_link_a.stripped.x86_64.elf"
_UNRELATED = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing fixture {p}")
    return p


def _fresh_kb(tmp_path: Path, binary_path: Path) -> PersistentKnowledgeBase:
    return PersistentKnowledgeBase.open(
        tmp_path / "kb.glaurung", binary_path=str(binary_path)
    )


# ---------------------------------------------------------------------------
# base_name_of
# ---------------------------------------------------------------------------


def test_base_name_of_plain_c_symbol_is_unchanged() -> None:
    assert siglib.base_name_of("mathlib_add") == "mathlib_add"


def test_base_name_of_strips_a_leading_underscore() -> None:
    # Not a valid mangling, so the demangler declines and the fallback path
    # (namespace split, then underscore strip) runs directly on the name.
    assert siglib.base_name_of("_mathlib_add") == "mathlib_add"


def test_base_name_of_strips_namespace_from_a_literal_string() -> None:
    assert siglib.base_name_of("Foo::bar") == "bar"


def test_base_name_of_demangles_and_strips_namespace_and_signature() -> None:
    # _ZN10HelloWorld12printMessageEv -> "HelloWorld::printMessage()"
    assert siglib.base_name_of("_ZN10HelloWorld12printMessageEv") == "printMessage"


# ---------------------------------------------------------------------------
# siglib / siglib_function provenance
# ---------------------------------------------------------------------------


def test_ingest_flirt_library_records_the_mathlib_key(tmp_path: Path) -> None:
    lib_path = _need(_FLIRT_LIB)
    kb = _fresh_kb(tmp_path, _need(_LINK_A))
    summary = siglib.ingest_flirt_library(kb, str(lib_path))

    row = siglib.get_siglib(
        kb,
        name="mathlib",
        version="1.0.0",
        variant="gcc-15.2.0-O2",
        architecture="x86_64",
    )
    assert row is not None
    assert row.siglib_id == summary.siglib_id
    assert row.source_sha256

    functions = siglib.list_siglib_functions(kb, row.siglib_id)
    assert len(functions) == summary.functions_ingested
    assert summary.functions_ingested == 16, (
        f"shipped library has 16 signed mathlib_* signatures; got "
        f"{summary.functions_ingested}"
    )
    names = {f.name for f in functions}
    assert names == {f.name for f in functions if f.name.startswith("mathlib_")}
    # Plain C symbols: base_name is the name unchanged.
    for f in functions:
        assert f.base_name == f.name
        assert f.scheme == siglib.FLIRT_MASKED_PATTERN_V1


def test_ingest_flirt_library_is_idempotent(tmp_path: Path) -> None:
    lib_path = _need(_FLIRT_LIB)
    kb = _fresh_kb(tmp_path, _need(_LINK_A))
    first = siglib.ingest_flirt_library(kb, str(lib_path))
    second = siglib.ingest_flirt_library(kb, str(lib_path))
    assert first.siglib_id == second.siglib_id
    functions = siglib.list_siglib_functions(kb, first.siglib_id)
    assert len(functions) == first.functions_ingested
    # Re-ingesting bumps occurrences (Lumina's popularity counter) rather
    # than duplicating rows.
    assert all(f.occurrences == 2 for f in functions)


def test_ingest_flirt_library_rejects_a_schema_v1_file_with_no_key(
    tmp_path: Path,
) -> None:
    v1 = tmp_path / "v1.flirt.json"
    v1.write_text(
        '{"schema_version": "1", "arch": "x86_64", "prologue_len": 8, '
        '"entries": [], "index": {}}'
    )
    kb = _fresh_kb(tmp_path, _need(_LINK_A))
    with pytest.raises(ValueError, match="library"):
        siglib.ingest_flirt_library(kb, str(v1))


def test_ingest_flirt_library_accepts_a_gsig_container(tmp_path: Path) -> None:
    """`ingest_flirt_library` reads either format -- through the Rust reader
    that wrote it, never by parsing container bytes in Python -- and records
    the same provenance either way, except the hash: it is deliberately the
    hash of the file *as it sits on disk*, so the JSON and the container it
    was built from record different hashes because they are different blobs
    of the same content."""
    json_path = _need(_FLIRT_LIB)
    gsig_path = tmp_path / "mathlib.x86_64.flirt.gsig"
    g.analysis.flirt_gsig_write_from_json_str(
        json_path.read_text(), str(gsig_path), "zstd"
    )

    (tmp_path / "from_json").mkdir()
    (tmp_path / "from_gsig").mkdir()
    kb_json = _fresh_kb(tmp_path / "from_json", _need(_LINK_A))
    kb_gsig = _fresh_kb(tmp_path / "from_gsig", _need(_LINK_A))
    from_json = siglib.ingest_flirt_library(kb_json, str(json_path))
    from_gsig = siglib.ingest_flirt_library(kb_gsig, str(gsig_path))

    assert from_gsig.functions_ingested == from_json.functions_ingested
    row_json = siglib.get_siglib(
        kb_json,
        name="mathlib",
        version="1.0.0",
        variant="gcc-15.2.0-O2",
        architecture="x86_64",
    )
    row_gsig = siglib.get_siglib(
        kb_gsig,
        name="mathlib",
        version="1.0.0",
        variant="gcc-15.2.0-O2",
        architecture="x86_64",
    )
    assert row_json is not None and row_gsig is not None
    assert row_json.source_sha256 != row_gsig.source_sha256, (
        "the JSON and gsig are different blobs and must record different "
        "content-addressed hashes"
    )

    names_json = {
        f.name for f in siglib.list_siglib_functions(kb_json, row_json.siglib_id)
    }
    names_gsig = {
        f.name for f in siglib.list_siglib_functions(kb_gsig, row_gsig.siglib_id)
    }
    assert names_json == names_gsig


# ---------------------------------------------------------------------------
# The BinaryFuse8 gate
# ---------------------------------------------------------------------------


def test_build_identity_filter_over_the_flirt_library(tmp_path: Path) -> None:
    lib_path = _need(_FLIRT_LIB)
    kb = _fresh_kb(tmp_path, _need(_LINK_A))
    siglib.ingest_flirt_library(kb, str(lib_path))

    build = siglib.build_identity_filter(
        kb, scheme=siglib.FLIRT_MASKED_PATTERN_V1, architecture="x86_64"
    )
    assert build.n_keys == 16
    # BinaryFuse8's ~9 bits/key figure is asymptotic; a binary fuse filter
    # has a fixed minimum segment/fingerprint-array size regardless of how
    # few keys go in, so at n=16 the per-key overhead is dominated by that
    # floor rather than by the construction's steady-state behaviour (see
    # `src/identity/gate.rs`'s test over 150,000 keys for the asymptotic
    # number: 9.393 bits/key measured). 200 is a generous ceiling for a
    # 16-key gate, not a claim about scale.
    assert 0.0 < build.bits_per_key < 200.0

    functions = siglib.list_siglib_functions(kb, 1)
    for f in functions:
        assert siglib.gate_contains(
            kb,
            scheme=siglib.FLIRT_MASKED_PATTERN_V1,
            architecture="x86_64",
            identity=f.identity,
        ), f"gate rejected a real member: {f.name}"

    # No gate yet for a scheme/arch that was never built: "no opinion", not
    # a negative.
    assert (
        siglib.gate_contains(
            kb, scheme="unrelated-scheme", architecture="x86_64", identity="x"
        )
        is None
    )


def test_gate_stats_count_probes(tmp_path: Path) -> None:
    lib_path = _need(_FLIRT_LIB)
    kb = _fresh_kb(tmp_path, _need(_LINK_A))
    siglib.ingest_flirt_library(kb, str(lib_path))
    siglib.build_identity_filter(
        kb, scheme=siglib.FLIRT_MASKED_PATTERN_V1, architecture="x86_64"
    )
    stats = siglib.GateStats()
    functions = siglib.list_siglib_functions(kb, 1)
    for f in functions:
        siglib.gate_contains(
            kb,
            scheme=siglib.FLIRT_MASKED_PATTERN_V1,
            architecture="x86_64",
            identity=f.identity,
            stats=stats,
        )
    assert stats.probes == len(functions)
    assert stats.negatives == 0
    siglib.gate_contains(
        kb,
        scheme=siglib.FLIRT_MASKED_PATTERN_V1,
        architecture="x86_64",
        identity="0" * 64,
        stats=stats,
    )
    assert stats.probes == len(functions) + 1
    assert stats.negatives == 1


# ---------------------------------------------------------------------------
# FLIRT match path
# ---------------------------------------------------------------------------


def test_match_flirt_library_names_the_stripped_image(tmp_path: Path) -> None:
    lib_path = _need(_FLIRT_LIB)
    stripped = _need(_STRIPPED)
    kb = _fresh_kb(tmp_path, stripped)
    ingested = siglib.ingest_flirt_library(kb, str(lib_path))

    summary = siglib.match_flirt_library(
        kb,
        str(stripped),
        siglib_id=ingested.siglib_id,
        flirt_library_path=str(lib_path),
    )
    assert summary.matched == 16
    assert summary.ambiguous == 0

    # Every match wrote a real siglib_function reference and named evidence.
    cur = kb._conn.execute(
        "SELECT entry_va, sigfn_id, evidence, ambiguous FROM function_match "
        "WHERE binary_id = ? AND scheme = ?",
        (kb.binary_id, siglib.FLIRT_MASKED_PATTERN_V1),
    )
    rows = cur.fetchall()
    assert len(rows) == 16
    for _entry_va, sigfn_id, evidence, ambiguous in rows:
        assert ambiguous == 0
        assert sigfn_id is not None
        assert evidence in ("flirt-L1", "flirt-L2", "flirt-L4")


def test_match_flirt_library_evidence_agrees_across_link_layouts(
    tmp_path: Path,
) -> None:
    """The two relink fixtures must produce identical `function_match`
    evidence for every `mathlib_*` function: evidence is a property of the
    signature and the bytes, not of which link produced them."""
    lib_path = _need(_FLIRT_LIB)
    link_a = _need(_LINK_A)
    link_b = _need(_LINK_B)

    kb_a = PersistentKnowledgeBase.open(
        tmp_path / "a.glaurung", binary_path=str(link_a)
    )
    ingested_a = siglib.ingest_flirt_library(kb_a, str(lib_path))
    summary_a = siglib.match_flirt_library(
        kb_a,
        str(link_a),
        siglib_id=ingested_a.siglib_id,
        flirt_library_path=str(lib_path),
    )

    kb_b = PersistentKnowledgeBase.open(
        tmp_path / "b.glaurung", binary_path=str(link_b)
    )
    ingested_b = siglib.ingest_flirt_library(kb_b, str(lib_path))
    summary_b = siglib.match_flirt_library(
        kb_b,
        str(link_b),
        siglib_id=ingested_b.siglib_id,
        flirt_library_path=str(lib_path),
    )

    assert summary_a.matched == summary_b.matched == 16
    assert summary_a.ambiguous == summary_b.ambiguous == 0

    def _evidence_by_name(
        kb: PersistentKnowledgeBase, siglib_id: int
    ) -> dict[str, str]:
        cur = kb._conn.execute(
            "SELECT sf.name, fm.evidence FROM function_match fm "
            "JOIN siglib_function sf ON sf.sigfn_id = fm.sigfn_id "
            "WHERE fm.binary_id = ? AND fm.scheme = ? AND sf.siglib_id = ?",
            (kb.binary_id, siglib.FLIRT_MASKED_PATTERN_V1, siglib_id),
        )
        return {name: evidence for name, evidence in cur.fetchall()}

    evidence_a = _evidence_by_name(kb_a, ingested_a.siglib_id)
    evidence_b = _evidence_by_name(kb_b, ingested_b.siglib_id)
    assert evidence_a == evidence_b
    assert len(evidence_a) == 16


def test_match_flirt_library_gate_never_false_negatives(tmp_path: Path) -> None:
    lib_path = _need(_FLIRT_LIB)
    stripped = _need(_STRIPPED)
    kb = _fresh_kb(tmp_path, stripped)
    ingested = siglib.ingest_flirt_library(kb, str(lib_path))
    siglib.build_identity_filter(
        kb, scheme=siglib.FLIRT_MASKED_PATTERN_V1, architecture="x86_64"
    )
    summary = siglib.match_flirt_library(
        kb,
        str(stripped),
        siglib_id=ingested.siglib_id,
        flirt_library_path=str(lib_path),
        gate_architecture="x86_64",
    )
    assert summary.matched == 16
    # Every real match's masked-pattern identity must have registered a gate
    # hit -- a binary fuse filter has zero false negatives by construction,
    # and this is that guarantee measured on real data.
    assert summary.gate_stats.probes == 16
    assert summary.gate_stats.negatives == 0


# ---------------------------------------------------------------------------
# WARP match path
# ---------------------------------------------------------------------------


def test_ingest_and_match_warp_library_across_a_relink(tmp_path: Path) -> None:
    """22 of 22 `mathlib_*` functions keep the same WARP GUID across the
    relink (`docs/reference/function-identity-warp.md`'s own measurement),
    but two of those 22 -- `mathlib_get_global_seed` and
    `mathlib_set_global_seed` -- share ONE GUID with each other in both
    links: WARP deliberately never prunes colliding functions. So ingesting
    22 named functions yields 21 *distinct* identities, and matching must
    report the collision as ambiguous with no name applied rather than
    picking one -- "no name beats a wrong name" holding for WARP too.
    """
    link_a = _need(_LINK_A)
    link_b = _need(_LINK_B)
    kb = _fresh_kb(tmp_path, link_b)
    siglib_id = siglib.get_or_create_siglib(
        kb,
        name="mathlib",
        version="1.0.0",
        variant="gcc-15.2.0-O2",
        architecture="x86_64",
    )
    ingested = siglib.ingest_warp_library(
        kb, str(link_a), siglib_id=siglib_id, name_prefix="mathlib_"
    )
    assert ingested == 22, (
        f"expected 22 mathlib_* WARP GUIDs from link A, got {ingested}"
    )

    summary = siglib.match_warp_library(kb, str(link_b), siglib_id=siglib_id)
    # 20 functions have a unique GUID and resolve cleanly; the 2 that share
    # the collided GUID (present in link B too, since the collision is a
    # property of the bytes, not the link) are each an ambiguous match.
    assert summary.matched == 20, (
        "every mathlib_* WARP GUID computed from link A except the two that "
        f"collide with each other must resolve against link B; matched={summary.matched}"
    )
    assert summary.ambiguous == 2

    cur = kb._conn.execute(
        "SELECT evidence, ambiguous FROM function_match WHERE binary_id = ? "
        "AND scheme = ?",
        (kb.binary_id, siglib.WARP_FUNCTION_GUID_V1),
    )
    rows = cur.fetchall()
    for evidence, ambiguous in rows:
        if ambiguous:
            assert evidence is None, "an ambiguous WARP match must carry no evidence"
        else:
            assert evidence == "warp-guid"


def test_warp_gate_rejects_every_function_of_an_unrelated_binary(
    tmp_path: Path,
) -> None:
    """The membership-gate deliverable's negative-control test: a gate built
    from the mathlib library's WARP identities must reject every function of
    an entirely unrelated sample binary, while still accepting the library's
    own functions from a *different* link layout."""
    link_a = _need(_LINK_A)
    link_b = _need(_LINK_B)
    unrelated = _need(_UNRELATED)

    kb = _fresh_kb(tmp_path, link_a)
    siglib_id = siglib.get_or_create_siglib(
        kb,
        name="mathlib",
        version="1.0.0",
        variant="gcc-15.2.0-O2",
        architecture="x86_64",
    )
    siglib.ingest_warp_library(
        kb, str(link_a), siglib_id=siglib_id, name_prefix="mathlib_"
    )
    build = siglib.build_identity_filter(
        kb, scheme=siglib.WARP_FUNCTION_GUID_V1, architecture="x86_64"
    )
    # 22 named functions, 21 distinct GUIDs: `mathlib_get_global_seed` and
    # `mathlib_set_global_seed` collide (see the relink test above), and the
    # gate is built over distinct identities.
    assert build.n_keys == 21

    # Positive control: link B's mathlib_* GUIDs are the same identities and
    # must all be accepted.
    link_b_functions = g.analysis.warp_function_guids_path(str(link_b))
    link_b_mathlib = [f for f in link_b_functions if f.name.startswith("mathlib_")]
    assert len(link_b_mathlib) == 22
    for fn in link_b_mathlib:
        assert siglib.gate_contains(
            kb,
            scheme=siglib.WARP_FUNCTION_GUID_V1,
            architecture="x86_64",
            identity=str(fn.guid),
        )

    # Negative control: an unrelated binary's functions (and link A's own
    # non-library driver functions) must be rejected.
    unrelated_functions = g.analysis.warp_function_guids_path(str(unrelated))
    driver_functions = [
        f
        for f in g.analysis.warp_function_guids_path(str(link_a))
        if not f.name.startswith("mathlib_")
    ]
    false_positives = []
    for fn in list(unrelated_functions) + list(driver_functions):
        if siglib.gate_contains(
            kb,
            scheme=siglib.WARP_FUNCTION_GUID_V1,
            architecture="x86_64",
            identity=str(fn.guid),
        ):
            false_positives.append(fn.name)
    assert not false_positives, (
        f"gate accepted {len(false_positives)} function(s) that are not "
        f"mathlib library members: {false_positives}"
    )


def test_warp_match_path_skips_lookup_on_a_gate_negative(tmp_path: Path) -> None:
    link_a = _need(_LINK_A)
    unrelated = _need(_UNRELATED)
    kb = _fresh_kb(tmp_path, unrelated)
    siglib_id = siglib.get_or_create_siglib(
        kb,
        name="mathlib",
        version="1.0.0",
        variant="gcc-15.2.0-O2",
        architecture="x86_64",
    )
    siglib.ingest_warp_library(
        kb, str(link_a), siglib_id=siglib_id, name_prefix="mathlib_"
    )
    siglib.build_identity_filter(
        kb, scheme=siglib.WARP_FUNCTION_GUID_V1, architecture="x86_64"
    )

    summary = siglib.match_warp_library(
        kb, str(unrelated), siglib_id=siglib_id, gate_architecture="x86_64"
    )
    assert summary.matched == 0
    assert summary.ambiguous == 0
    # Every function of the unrelated binary should be rejected by the gate
    # before any siglib_function lookup runs.
    assert summary.gate_stats.probes == summary.candidates
    assert summary.gate_stats.negatives == summary.candidates


# ---------------------------------------------------------------------------
# function_match round trip
# ---------------------------------------------------------------------------


def test_record_and_list_function_match(tmp_path: Path) -> None:
    kb = _fresh_kb(tmp_path, _need(_LINK_A))
    siglib.record_function_match(
        kb,
        entry_va=0x1000,
        scheme="test-scheme",
        sigfn_id=None,
        score=0.9,
        confidence=0.8,
        rank=1,
        ambiguous=False,
        evidence="test-evidence",
    )
    rows = siglib.list_function_matches(kb, 0x1000)
    assert len(rows) == 1
    assert rows[0].evidence == "test-evidence"
    assert rows[0].ambiguous is False

    # Re-recording the same (binary_id, entry_va, scheme, rank) replaces
    # rather than accumulates.
    siglib.record_function_match(
        kb, entry_va=0x1000, scheme="test-scheme", rank=1, ambiguous=True, evidence=None
    )
    rows = siglib.list_function_matches(kb, 0x1000)
    assert len(rows) == 1
    assert rows[0].ambiguous is True
    assert rows[0].evidence is None
