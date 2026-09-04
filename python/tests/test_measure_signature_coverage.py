"""`tools/measure_signature_coverage.py` counts a known input correctly.

The fixture is the one the signature lane already measures by hand: the
`mathlib` relink pair in `tests/fixtures/flirt/`, against the shipped
`data/sigs/glaurung-base.x86_64.flirt.json`, which
`docs/reference/function-signature-libraries.md` records as naming **16 of
16** signed functions in both links. Pinning the tool's arithmetic against a
number established independently is the point: a coverage measurement whose
counting is wrong is worse than none, because the answer is a percentage and
nothing about it looks wrong.

The WARP half is exercised with the committed synthetic GUID library, which
carries no GUID any real binary produces -- so it must contribute exactly
zero names, which is the negative control the FLIRT half cannot provide.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "measure_signature_coverage.py"
FLIRT_LIB = ROOT / "data" / "sigs" / "glaurung-base.x86_64.flirt.json"
WARP_GSIG = (
    ROOT / "tests" / "fixtures" / "flirt" / "gsig" / "warp_sample.x86_64.warp.gsig"
)
LINK_A = ROOT / "tests" / "fixtures" / "flirt" / "mathlib_link_a.x86_64.elf"
LINK_B = ROOT / "tests" / "fixtures" / "flirt" / "mathlib_link_b.x86_64.elf"


def _load_tool():
    spec = importlib.util.spec_from_file_location("measure_signature_coverage", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Registered before execution: the tool's `@dataclass`es are written under
    # `from __future__ import annotations`, and `dataclasses` resolves a
    # string annotation by looking the defining module up in `sys.modules`.
    # An unregistered module makes every one of them fail to construct.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tool():
    return _load_tool()


@pytest.fixture(scope="module")
def sig_dir(tmp_path_factory):
    """A signature directory holding one blob of each scheme.

    Copied rather than pointed at in place, because the tool writes its
    merged library into a cache directory keyed by the input set and the
    repository's own trees are not scratch space.
    """
    d = tmp_path_factory.mktemp("sigs")
    shutil.copy(FLIRT_LIB, d / FLIRT_LIB.name)
    shutil.copy(WARP_GSIG, d / WARP_GSIG.name)
    return d


@pytest.fixture(scope="module")
def scanned(tool, sig_dir):
    return tool.SignatureSet.scan(sig_dir, "x86_64")


def test_scan_splits_a_directory_by_the_blobs_own_scheme(scanned):
    """Which scheme a blob is, read off the file, not off its name."""
    assert len(scanned.flirt_blobs) == 1
    assert len(scanned.warp_blobs) == 1


def test_names_the_sixteen_mathlib_functions_in_both_links(tool, scanned, tmp_path):
    """The measured result the signature page records, reproduced by the tool.

    Both links are scored: an exact matcher names 0 of 16 across a relink, so
    a tool that measured only one layout would not be measuring the property
    that makes a masked signature worth having.
    """
    cache = tmp_path / "cache"
    library = scanned.merged_flirt_library(cache)
    assert library is not None
    warp_index = scanned.warp_index()
    names = scanned.flirt_names(cache)
    truth = tool.TruthSource("elf-symtab")

    for binary in (LINK_A, LINK_B):
        r = tool.score_binary(
            binary,
            flirt_library=library,
            warp_index=warp_index,
            truth_source=truth,
            library_names=names,
        )
        assert r.error is None, r.error
        assert r.named == 16, (binary.name, r.to_dict())
        assert r.correct == 16, (binary.name, r.to_dict())
        assert r.wrong == 0
        assert r.ambiguous == 0
        # Every named function is one the library carries a name for, so the
        # two denominators' numerators coincide here by construction.
        assert r.library_named == 16
        assert r.library_correct == 16
        assert r.library_functions == 16
        # The synthetic WARP library shares no GUID with real code.
        assert r.named_warp == 0
        assert r.named_flirt == 16
        # `scored` is every discovered function the truth names, matched or
        # not -- the population correct and wrong are told apart on.
        assert r.scored > r.named
        assert r.functions_total >= r.scored


def test_the_two_denominators_are_computed_from_the_sums(tool):
    """Aggregate ratios come from summed counts, never from averaged ratios."""
    rows = [
        tool.BinaryResult(
            path="a",
            functions_total=100,
            named=10,
            library_functions=20,
            library_named=8,
            correct=7,
            wrong=3,
            scored=40,
        ),
        tool.BinaryResult(
            path="b",
            functions_total=900,
            named=90,
            library_functions=80,
            library_named=72,
            correct=70,
            wrong=20,
            scored=360,
        ),
    ]
    totals = tool.aggregate(rows)
    assert totals["functions_total"] == 1000
    assert totals["named"] == 100
    assert totals["of_all_functions"] == pytest.approx(0.1)
    assert totals["of_library_functions"] == pytest.approx(80 / 100)
    assert totals["precision"] == pytest.approx(77 / 100)
    assert totals["recall_of_scored"] == pytest.approx(77 / 400)


def test_two_schemes_disagreeing_at_one_address_names_nothing(tool):
    """No name beats a wrong name, across schemes as well as within one."""
    assert tool.combine({4: "a"}, {4: "b"}) == {4: None}
    assert tool.combine({4: "a"}, {4: "a"}) == {4: "a"}
    assert tool.combine({4: "a"}, {4: None}) == {4: None}
    assert tool.combine({4: None}, {}) == {4: None}
    assert tool.combine({4: "a"}, {8: "b"}) == {4: "a", 8: "b"}


def test_truth_is_a_set_of_names_per_address(tool):
    """Two symbols at one address are both acceptable identifications."""
    truth = tool._nm_text_symbols(LINK_A)
    assert truth, "the unstripped fixture has a symbol table"
    assert all(isinstance(v, set) for v in truth.values())
    assert any(
        name.startswith("mathlib_") for names in truth.values() for name in names
    )


def test_object_format_is_read_from_magic(tool, tmp_path):
    """A denominator must not be chosen from a file extension."""
    assert tool.object_format(LINK_A) == "elf"
    pe = tmp_path / "not-really.elf"
    pe.write_bytes(b"MZ" + b"\0" * 64)
    assert tool.object_format(pe) == "pe"
    text = tmp_path / "script.dll"
    text.write_text("#!/bin/sh\n")
    assert tool.object_format(text) is None
