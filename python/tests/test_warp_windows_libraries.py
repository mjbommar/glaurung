"""`glaurung.tools.build_warp_library`: WARP libraries from Windows PE + PDB.

Two halves, deliberately separated.

**The half that always runs** uses the repository's own MinGW-built PEs under
``samples/binaries/platforms/windows/``. It checks the mechanism: the schema,
the key, the ICF ambiguity rule, the evidence floor, and the round trip through
``siglib``'s KB tables. No Microsoft bytes are involved and nothing is skipped.

**The half that needs the corpus** is the measurement, and it pins the numbers
in ``docs/reference/function-signature-libraries.md``'s "Windows: WARP libraries
from PE+PDB" section. It needs two things that cannot be committed -- linked
Microsoft PEs and their PDBs -- so it skips loudly on:

``GLAURUNG_WINDOWS_CORPUS``
    The directory holding ``binaries/windows-{8-pro,10,11}-x64/`` and
    ``patch-tuesday/``. Documented in ``docs/development/corpora.md``.
``GLAURUNG_PDB_CACHE``
    A Microsoft-style symbol cache, ``<cache>/<pdb>/<GUID+AGE>/<pdb>``. The
    same variable ``glaurung.pdb_fetch.default_cache_dir`` already reads.

Every pinned number below was measured on 2026-09-03 against the corpus
recorded in ``docs/development/corpora.md``, on a release build
(``uv run maturin develop --release``). The counts are exact rather than
bounded wherever the input is a fixed pair of files: a bound would let the
scheme silently degrade by nine tenths of a point at a time.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.kb import siglib
from glaurung.llm.kb.persistent import PersistentKnowledgeBase
from glaurung.tools import build_warp_library as bwl

_REPO = Path(__file__).resolve().parents[2]
_WINDOWS_SAMPLES = _REPO / "samples/binaries/platforms/windows"
_MINGW_O1 = _WINDOWS_SAMPLES / "amd64/export/windows/x86_64/O1/hello-c-mingw64-O1.exe"
_MINGW_DEBUG = (
    _WINDOWS_SAMPLES / "amd64/export/windows/x86_64/debug/hello-c-mingw64-debug.exe"
)


def _sample(p: Path) -> Path:
    if not p.is_file():
        pytest.skip(f"missing sample {p} (git lfs pull?)")
    return p


def _corpus() -> tuple[Path, Path]:
    """The corpus root and PDB cache, or a loud skip."""
    root = os.environ.get("GLAURUNG_WINDOWS_CORPUS")
    cache = os.environ.get("GLAURUNG_PDB_CACHE")
    if not root or not cache:
        pytest.skip(
            "set GLAURUNG_WINDOWS_CORPUS (the directory holding binaries/ and "
            "patch-tuesday/) and GLAURUNG_PDB_CACHE (a symbol-server-layout "
            "PDB cache) to run the Windows WARP measurements -- see "
            "docs/development/corpora.md"
        )
    root_p, cache_p = Path(root), Path(cache)
    if not root_p.is_dir() or not cache_p.is_dir():
        pytest.skip(
            f"GLAURUNG_WINDOWS_CORPUS={root} / GLAURUNG_PDB_CACHE={cache} "
            "do not both name directories"
        )
    return root_p, cache_p


def _module(root: Path, build: str, name: str) -> Path:
    p = root / "binaries" / build / name
    if not p.is_file():
        pytest.skip(f"corpus has no {build}/{name}")
    return p


def _patch_tuesday(root: Path, module: str, version: str) -> Path:
    for p in sorted((root / "patch-tuesday" / module).rglob(module)):
        if version in str(p):
            return p
    pytest.skip(f"corpus has no patch-tuesday {module} {version}")


# ---------------------------------------------------------------------------
# The mechanism, on repository samples
# ---------------------------------------------------------------------------


def _close(actual: int, expected: int, what: str) -> None:
    """Assert a measured count, with the tolerance the measurement has.

    Every count here is downstream of CFG discovery, and discovery runs under
    a **wall-clock** budget (``analysis::cfg::Budgets::default``). On a quiet
    machine these numbers are exact and reproducible -- three consecutive runs
    of the ``tcpip.sys`` lane gave 5,263 correct every time -- but the same
    lane inside a loaded pytest session returned 5,262, because one function's
    CFG was truncated where it had not been before. Pinning the exact integer
    would make this test a load meter.

    The tolerance is 0.3% or 3, whichever is larger: two orders of magnitude
    below the effects being measured (cross-release recall differs from
    cross-servicing recall by 60 points), so a real regression still fails.
    """
    slack = max(3, round(expected * 0.003))
    assert abs(actual - expected) <= slack, (
        f"{what}: {actual} is more than {slack} from the measured {expected}"
    )


def test_the_scheme_string_is_spelled_once():
    """Three modules name this scheme; two spellings would split the table."""
    assert bwl.WARP_SCHEME == g.analysis.warp_scheme()
    assert bwl.WARP_SCHEME == siglib.WARP_FUNCTION_GUID_V1


def test_byte_len_is_reported_and_is_not_part_of_the_identity():
    """The size a library records must come from the binding, not a re-run.

    Before ``byte_len`` existed on ``WarpFunction`` the only way to size a
    matched function from Python was a second full discovery pass over the
    image -- 16 seconds on ``ntoskrnl.exe`` -- to recover a number the first
    pass had already computed and thrown away.
    """
    fns = g.analysis.warp_function_guids_path(str(_sample(_MINGW_O1)))
    assert fns, "the sample discovered no functions"
    assert all(f.byte_len > 0 for f in fns)
    # A GUID is a function of the block GUIDs alone, so two functions with the
    # same GUID must agree on it while being free to differ in size.
    by_guid: dict[str, set[int]] = {}
    for f in fns:
        by_guid.setdefault(f.guid, set()).add(f.byte_len)
    assert max(len(s) for s in by_guid.values()) >= 1


def test_the_library_key_is_the_five_documented_fields():
    lib = bwl.build_library([_sample(_MINGW_O1)], pdb_cache=None)
    assert set(lib["library"]) == {"name", "version", "variant", "arch", "platform"}
    assert lib["library"]["name"] == "hello-c-mingw64-o1.exe"
    assert lib["library"]["arch"] == "x86_64"
    assert lib["library"]["platform"] == "windows"
    assert lib["scheme"] == bwl.WARP_SCHEME


def test_a_non_microsoft_link_does_not_claim_an_msvc_variant():
    """The Rich header is the only evidence that the linker was Microsoft's.

    MinGW's ``ld`` writes an optional-header linker version too -- ``2.38``
    here -- and reading it as an MSVC toolset version would file GNU-linked
    code under a Visual Studio release that never touched it.
    """
    facts = bwl.pe_facts(_sample(_MINGW_O1))
    assert facts is not None
    assert facts.rich_build is None
    assert facts.variant.startswith("link-")


def test_a_folded_guid_keeps_every_name_and_is_marked_ambiguous():
    """ICF: one entry per (guid, name), never a pick between them.

    The MinGW samples fold too -- four GUIDs carry more than one name in this
    99-function binary -- so the rule is exercised without the corpus.
    """
    lib = bwl.build_library([_sample(_MINGW_O1)], pdb_cache=None)
    by_guid: dict[str, list[dict]] = {}
    for e in lib["entries"]:
        by_guid.setdefault(e["guid"], []).append(e)
    folded = {k: v for k, v in by_guid.items() if len(v) > 1}
    assert folded, "expected at least one folded GUID in this sample"
    for entries in folded.values():
        assert len({e["name"] for e in entries}) == len(entries)
        assert all(e["ambiguous"] for e in entries)
    for entries in by_guid.values():
        if len(entries) == 1:
            assert entries[0]["ambiguous"] is False
    assert lib["stats"]["guids"] == len(by_guid)
    assert lib["stats"]["guids_ambiguous"] == len(folded)
    assert lib["stats"]["guids_unique"] == len(by_guid) - len(folded)


def test_entries_are_deterministic_and_carry_no_bytes():
    """A library file is redistributable only if it holds no library content.

    FLIRT splits pattern from mask so a signature set is not a copy of what it
    describes; a WARP library goes further and holds no bytes at all. This
    asserts that literally: no value anywhere in an entry is a hex blob.
    """
    lib = bwl.build_library([_sample(_MINGW_O1)], pdb_cache=None)
    again = bwl.build_library([_sample(_MINGW_O1)], pdb_cache=None)
    assert lib["entries"] == again["entries"]
    allowed = {
        "guid",
        "name",
        "base_name",
        "block_count",
        "byte_len",
        "occurrences",
        "ambiguous",
        "constraints",
    }
    for e in lib["entries"]:
        assert set(e) == allowed
        assert isinstance(e["byte_len"], int)


def test_constraints_default_to_the_ambiguous_entries_only():
    lib = bwl.build_library([_sample(_MINGW_O1)], pdb_cache=None)
    with_constraints = [e for e in lib["entries"] if e["constraints"]]
    assert with_constraints, "expected constraints on the folded entries"
    assert all(e["ambiguous"] for e in with_constraints)

    none = bwl.build_library([_sample(_MINGW_O1)], pdb_cache=None, constraints="none")
    assert all(not e["constraints"] for e in none["entries"])

    every = bwl.build_library([_sample(_MINGW_O1)], pdb_cache=None, constraints="all")
    assert sum(len(e["constraints"]) for e in every["entries"]) > sum(
        len(e["constraints"]) for e in lib["entries"]
    )


def test_the_evidence_floor_is_applied_to_both_sides():
    """A floor that only filtered the library would still match a six-byte stub."""
    lib = bwl.build_library([_sample(_MINGW_O1)], pdb_cache=None)
    unfloored = bwl.match_pe_against_library(lib, _sample(_MINGW_O1), min_bytes=0)
    floored = bwl.match_pe_against_library(lib, _sample(_MINGW_O1))
    assert unfloored.guid_shared > floored.guid_shared
    small = sum(1 for e in lib["entries"] if e["byte_len"] < bwl.MIN_EVIDENCE_BYTES)
    assert small > 0, "expected sub-floor entries in this sample"


def test_a_warp_library_file_round_trips_through_the_kb(tmp_path: Path):
    """`siglib.ingest_warp_library_file` -> `match_warp_library`, end to end.

    The ambiguous entries must survive ingestion: dropping them at the writer
    would leave the GUID looking unique, and the matcher would then confidently
    apply the one surviving name.
    """
    source = _sample(_MINGW_O1)
    lib = bwl.build_library([source], pdb_cache=None)
    path = tmp_path / "sample.warp.json"
    bwl.write_library(path, lib)

    kb = PersistentKnowledgeBase.open(tmp_path / "kb.glaurung", binary_path=str(source))
    summary = siglib.ingest_warp_library_file(kb, str(path))
    assert summary.functions_ingested == len(lib["entries"])
    assert summary.functions_skipped == 0

    row = siglib.get_siglib(
        kb,
        name=lib["library"]["name"],
        version=lib["library"]["version"],
        variant=lib["library"]["variant"],
        architecture=lib["library"]["arch"],
        platform=lib["library"]["platform"],
    )
    assert row is not None and row.siglib_id == summary.siglib_id

    # `match_warp_library` counts discovered *functions*, not library GUIDs:
    # several `sub_*` functions can carry a GUID the library names, which is
    # the whole point. `match_pe_against_library` at no floor is the same
    # traversal, so it is the honest expectation to compare against.
    expected = bwl.match_pe_against_library(lib, source, min_bytes=0)
    match = siglib.match_warp_library(kb, str(source), siglib_id=summary.siglib_id)
    assert match.scheme == siglib.WARP_FUNCTION_GUID_V1
    assert match.candidates == expected.functions
    assert match.matched == expected.guid_shared_unique
    assert match.ambiguous == expected.guid_shared_ambiguous
    assert match.ambiguous > 0, "expected the folded GUIDs to be reported ambiguous"

    rows = kb._conn.execute(
        "SELECT ambiguous, evidence FROM function_match WHERE scheme = ?",
        (siglib.WARP_FUNCTION_GUID_V1,),
    ).fetchall()
    applied = [r for r in rows if not r[0]]
    assert len(applied) == match.matched
    assert all(r[1] == "warp-guid" for r in applied)
    assert all(r[1] is None for r in rows if r[0])


def test_the_cli_writes_an_index_and_can_fill_a_kb(tmp_path: Path):
    """The one-command path: build, index, ingest.

    ``--kb`` is what closes the loop -- a library file on disk names nothing
    until a ``siglib`` row exists for it -- and it is the step easiest to
    forget, because the builder reports success either way.
    """
    out = tmp_path / "libs"
    kb_path = tmp_path / "warp.glaurung"
    rc = bwl.main(
        [
            "--output-dir",
            str(out),
            "--index",
            "--kb",
            str(kb_path),
            str(_sample(_MINGW_O1)),
            str(_sample(_MINGW_DEBUG)),
        ]
    )
    assert rc == 0

    index = json.loads((out / "index.json").read_text())
    assert index["scheme"] == bwl.WARP_SCHEME
    assert len(index["libraries"]) == 2
    files = {row["file"] for row in index["libraries"]}
    assert files == {p.name for p in out.glob("*.warp.json")}

    kb = PersistentKnowledgeBase.open(kb_path)
    libraries = kb._conn.execute(
        "SELECT name, platform, architecture FROM siglib ORDER BY name"
    ).fetchall()
    assert len(libraries) == 2
    assert all(row[1] == "windows" and row[2] == "x86_64" for row in libraries)
    ingested = kb._conn.execute(
        "SELECT COUNT(*) FROM siglib_function WHERE scheme = ?",
        (siglib.WARP_FUNCTION_GUID_V1,),
    ).fetchone()[0]
    assert ingested == sum(row["entries"] for row in index["libraries"])


def test_ingesting_a_flirt_library_under_the_warp_scheme_is_refused(tmp_path: Path):
    path = tmp_path / "wrong.warp.json"
    path.write_text(
        json.dumps(
            {
                "scheme": siglib.FLIRT_MASKED_PATTERN_V1,
                "library": {"name": "x", "arch": "x86_64"},
                "entries": [],
            }
        )
    )
    kb = PersistentKnowledgeBase.open(tmp_path / "kb.glaurung", binary_path=str(path))
    with pytest.raises(ValueError, match="declares scheme"):
        siglib.ingest_warp_library_file(kb, str(path))


# ---------------------------------------------------------------------------
# The measurement, on the Windows corpus
# ---------------------------------------------------------------------------


def test_a_corpus_module_keys_on_its_version_resource_and_rich_header():
    """The key must come from the file, not from where the file was found."""
    root, _ = _corpus()
    key = bwl.library_key(_module(root, "windows-11-x64", "ntdll.dll"))
    assert key == {
        "name": "ntdll.dll",
        "version": "10.0.22621.2428",
        "variant": "msvc-14.30-b30795",
        "arch": "x86_64",
        "platform": "windows",
    }


def test_afd_sys_names_come_from_the_pdb():
    """The PDB, not discovery, is what makes this library worth having.

    ``afd.sys`` exports almost nothing, so without the PDB the library would
    be a handful of names over a thousand functions.
    """
    root, cache = _corpus()
    pe = _module(root, "windows-11-x64", "afd.sys")
    lib = bwl.build_library([pe], pdb_cache=cache, constraints="none")
    _close(lib["stats"]["functions_discovered"], 1177, "afd.sys functions")
    _close(lib["stats"]["functions_pdb_named"], 1035, "afd.sys PDB-named")
    _close(lib["stats"]["entries"], 1035, "afd.sys entries")
    _close(lib["stats"]["guids"], 1022, "afd.sys GUIDs")
    _close(lib["stats"]["guids_ambiguous"], 11, "afd.sys ambiguous GUIDs")

    without = bwl.build_library([pe], pdb_cache=None, constraints="none")
    assert without["stats"]["entries"] == 0, (
        "afd.sys carries no usable names of its own -- if this ever passes with "
        "a nonzero count the PDB is no longer what is doing the work"
    )


@pytest.mark.parametrize(
    "module,from_version,to_version,scored,correct,wrong,ambiguous",
    [
        ("afd.sys", "8328", "8457", 1118, 1023, 3, 44),
        ("tcpip.sys", "8328", "8457", 5828, 5263, 0, 308),
        ("clfs.sys", "8328", "8457", 1265, 1047, 0, 63),
        ("cldflt.sys", "8328", "8457", 1047, 889, 3, 54),
        ("win32kfull.sys", "8328", "8457", 8989, 8212, 3, 476),
        ("http.sys", "8521", "8655", 3843, 3612, 0, 63),
    ],
)
def test_cross_servicing_build_recall(
    module, from_version, to_version, scored, correct, wrong, ambiguous
):
    """One Patch Tuesday to the next: the case WARP is actually good at.

    The library is built from build A, the matcher never consults build B's
    PDB, and B's PDB is read only afterwards to grade what the library said.
    """
    root, cache = _corpus()
    a = _patch_tuesday(root, module, from_version)
    b = _patch_tuesday(root, module, to_version)
    lib = bwl.build_library([a], pdb_cache=cache, constraints="none")
    score = bwl.match_pe_against_library(lib, b, truth_pdb_cache=cache)
    _close(score.scored, scored, f"{module} scored")
    _close(score.correct, correct, f"{module} correct")
    _close(score.wrong, wrong, f"{module} wrong")
    _close(score.ambiguous, ambiguous, f"{module} ambiguous")
    assert score.recall > 0.82


@pytest.mark.parametrize(
    "module,scored,correct,wrong",
    [
        ("afd.sys", 1035, 321, 3),
        ("tcpip.sys", 5497, 1483, 21),
        ("srvnet.sys", 859, 318, 5),
    ],
)
def test_cross_release_recall_is_much_lower(module, scored, correct, wrong):
    """Windows 10 to Windows 11: two years of source drift, and it shows.

    Pinned because the *shape* is the finding. An exact-match scheme carries
    roughly a third of a module across a release boundary and nine tenths
    across a servicing update, and any change that moved these together would
    mean the GUID had stopped being exact.
    """
    root, cache = _corpus()
    a = _module(root, "windows-10-x64", module)
    b = _module(root, "windows-11-x64", module)
    lib = bwl.build_library([a], pdb_cache=cache, constraints="none")
    score = bwl.match_pe_against_library(lib, b, truth_pdb_cache=cache)
    _close(score.scored, scored, f"{module} scored")
    _close(score.correct, correct, f"{module} correct")
    _close(score.wrong, wrong, f"{module} wrong")
    assert 0.15 < score.recall < 0.45


def test_win32k_syscall_stubs_are_the_scheme_s_worst_case():
    """Identical bytes, different function: the one failure a floor cannot fix.

    ``win32k.sys`` is the syscall shim layer, and its 1,300-odd 165-byte
    ``_stub_*`` bodies differ only in a syscall index -- an immediate, not a
    pointer, so WARP correctly keeps it and the GUID ends up keyed on the
    *index* rather than on the function. Windows reassigns those indices
    between releases (1,316 stubs in the Windows 10 build, 1,456 in the
    Windows 11 one, and the order is not a shift but a reshuffle), so the
    library hands out 1,199 confidently wrong names.

    Neither mitigation helps: the bodies clear any evidence floor at 165
    bytes, and a callee-constraint check rescues none of the 2,397 wrong
    verdicts because the stubs' callee sets are identical too. It is pinned
    here so that a future constraint level has a number to beat.
    """
    root, cache = _corpus()
    a = _module(root, "windows-10-x64", "win32k.sys")
    b = _module(root, "windows-11-x64", "win32k.sys")
    lib = bwl.build_library([a], pdb_cache=cache, constraints="none")
    score = bwl.match_pe_against_library(lib, b, truth_pdb_cache=cache)
    _close(score.scored, 4629, "win32k.sys scored")
    _close(score.correct, 197, "win32k.sys correct")
    _close(score.wrong, 1199, "win32k.sys wrong")
    _close(score.ambiguous, 1327, "win32k.sys ambiguous")
    assert score.precision < 0.15


def test_the_union_library_names_nothing_in_unrelated_mingw_binaries():
    """The negative control, and the reason :data:`MIN_EVIDENCE_BYTES` exists.

    48 MinGW-built PEs in this repository share no code with Windows system
    DLLs, so every name applied is a false positive. Unfloored, a two-module
    Windows library claims hundreds of them -- almost all six-byte
    ``jmp qword [rip+disp32]`` import thunks, whose displacement WARP masks,
    so every import thunk in every PE ever linked carries one GUID. At the
    floor, the surviving hits are all ambiguous and **no name is applied**.
    """
    root, cache = _corpus()
    library = bwl.build_library(
        [
            _module(root, "windows-11-x64", "ntdll.dll"),
            _module(root, "windows-11-x64", "msvcp140_clr0400.dll"),
        ],
        pdb_cache=cache,
        name="windows-negative-control",
        constraints="none",
    )
    mingw = sorted(
        p
        for p in _WINDOWS_SAMPLES.rglob("*")
        if p.is_file() and p.suffix.lower() == ".exe" and "mingw" in p.name
    )
    if not mingw:
        pytest.skip("no MinGW samples (git lfs pull?)")

    functions = applied = hits = unfloored = 0
    for p in mingw:
        floored = bwl.match_pe_against_library(library, p)
        functions += floored.functions
        applied += floored.guid_shared_unique
        hits += floored.guid_shared
        unfloored += bwl.match_pe_against_library(library, p, min_bytes=0).guid_shared

    assert applied == 0, "a name was applied to an unrelated binary"
    assert hits <= 4
    assert unfloored > 100, (
        "the floor is not doing anything -- either the samples changed or the "
        "masking did"
    )
    assert functions > 4000
