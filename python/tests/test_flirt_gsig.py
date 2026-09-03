"""The `gsig/1` container's Python surface: bindings, the builder's
``--format gsig``, and ``glaurung.tools.sig_convert``.

Real fixtures throughout: `data/sigs/glaurung-base.x86_64.flirt.json` (the
shipped mathlib library) and `tests/fixtures/flirt/gsig/` (the committed
golden pair). The container's own byte-level properties -- determinism, chunk
layout, forward compatibility -- are `src/flirt/gsig/`'s Rust unit tests and
`tests/flirt_gsig_golden.rs`; this file is about what a Python caller sees.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import glaurung as g
from glaurung.tools import sig_convert
from glaurung.tools.build_flirt_library import (
    FORMAT_GSIG,
    FORMAT_JSON,
    build_library_from_archive,
    main as build_main,
)

REPO = Path(__file__).resolve().parents[2]
ARCHIVE = REPO / "samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a"
SHIPPED_JSON = REPO / "data/sigs/glaurung-base.x86_64.flirt.json"
GOLDEN_JSON = REPO / "tests/fixtures/flirt/gsig/mingw_crt_three.x86_64.flirt.json"
GOLDEN_GSIG = REPO / "tests/fixtures/flirt/gsig/mingw_crt_three.x86_64.flirt.gsig"


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing fixture {p}")
    return p


# ---------------------------------------------------------------------------
# flirt_library_info_path
# ---------------------------------------------------------------------------


def test_info_path_reports_json_format() -> None:
    info = g.analysis.flirt_library_info_path(str(_need(SHIPPED_JSON)))
    assert info["format"] == "json"
    assert info["schema_version"] == "2"
    assert info["arch"] == "x86_64"
    assert info["n_signatures"] >= 15
    assert info["library"]["name"] == "mathlib"


def test_info_path_reports_gsig_format_and_chunk_table() -> None:
    info = g.analysis.flirt_library_info_path(str(_need(GOLDEN_GSIG)))
    assert info["format"] == "gsig"
    assert info["format_version"] == 1
    assert info["scheme"] == g.analysis.FLIRT_MASKED_PATTERN_SCHEME
    assert info["n_signatures"] == 12
    assert info["library"] == {
        "name": "mingw_crt_three",
        "version": "13.0.0",
        "variant": "mingw-w64-gcc",
        "arch": "x86_64",
    }
    kinds = {row["name"] for row in info["chunks"]}
    assert {"meta", "strings", "signatures", "patterns"} <= kinds
    for row in info["chunks"]:
        assert row["chunks"] >= 1
        assert row["uncompressed_bytes"] > 0


def test_info_path_rejects_neither_format(tmp_path: Path) -> None:
    junk = tmp_path / "junk.flirt"
    junk.write_bytes(b"not a signature library at all")
    with pytest.raises(ValueError):
        g.analysis.flirt_library_info_path(str(junk))


# ---------------------------------------------------------------------------
# flirt_library_to_json_str / flirt_gsig_write_from_json_str: the round trip
# ---------------------------------------------------------------------------


def test_json_to_gsig_to_json_is_lossless() -> None:
    text = _need(GOLDEN_JSON).read_text()
    original = json.loads(text)

    # Canonical form both sides compare against, since the golden JSON on
    # disk may not itself be in the writer's own key order.
    canonical_original = json.loads(
        g.analysis.flirt_library_to_json_str(str(GOLDEN_JSON))
    )

    lib = json.loads(g.analysis.flirt_library_to_json_str(str(GOLDEN_GSIG)))
    assert lib == canonical_original
    assert lib["library"] == original["library"]
    assert len(lib["entries"]) == len(original["entries"])


def test_writing_a_gsig_reproduces_the_golden_bytes(tmp_path: Path) -> None:
    """The writer is deterministic: the same JSON, the same codec, gives the
    exact bytes already committed at `tests/fixtures/flirt/gsig/`."""
    text = _need(GOLDEN_JSON).read_text()
    out = tmp_path / "rebuilt.gsig"
    report = g.analysis.flirt_gsig_write_from_json_str(text, str(out), "zstd")
    assert out.read_bytes() == _need(GOLDEN_GSIG).read_bytes()
    assert report["n_signatures"] == 12


def test_an_unknown_codec_is_rejected() -> None:
    text = _need(GOLDEN_JSON).read_text()
    with pytest.raises(ValueError, match="unknown gsig codec"):
        g.analysis.flirt_gsig_write_from_json_str(text, "ignored.gsig", "brotli")


# ---------------------------------------------------------------------------
# flirt_library_match_bytes: both formats resolve one lookup identically
# ---------------------------------------------------------------------------


def test_match_bytes_agrees_between_json_and_gsig() -> None:
    lib = json.loads(_need(GOLDEN_JSON).read_text())
    # `crc_len == 0` so the pattern alone (no CRC-covered tail bytes, which
    # this test does not have access to) is enough to resolve the match.
    entry = next(e for e in lib["entries"] if e["crc_len"] == 0)
    probe = bytes.fromhex(entry["prologue_hex"])

    from_json = g.analysis.flirt_library_match_bytes(str(GOLDEN_JSON), probe)
    from_gsig = g.analysis.flirt_library_match_bytes(str(GOLDEN_GSIG), probe)
    assert from_json == from_gsig
    assert entry["name"] in from_json["names"]


def test_match_bytes_reports_no_match_for_unrelated_bytes() -> None:
    probe = bytes(range(64))
    result = g.analysis.flirt_library_match_bytes(str(_need(GOLDEN_GSIG)), probe)
    assert result["names"] == []
    assert result["ambiguous"] is False
    assert result["evidence"] is None


# ---------------------------------------------------------------------------
# build_flirt_library.py --format gsig
# ---------------------------------------------------------------------------


def test_builder_writes_a_gsig_directly(tmp_path: Path) -> None:
    _need(ARCHIVE)
    out = tmp_path / "mathlib.x86_64.flirt.gsig"
    rc = build_main(
        [
            "--archive",
            str(ARCHIVE),
            "--library-name",
            "mathlib",
            "--library-version",
            "1.0.0",
            "--variant",
            "gcc-15.2.0-O2",
            "--arch",
            "x86_64",
            "--format",
            FORMAT_GSIG,
            "--output",
            str(out),
            "--quiet",
        ]
    )
    assert rc == 0
    info = g.analysis.flirt_library_info_path(str(out))
    assert info["format"] == "gsig"
    assert info["n_signatures"] >= 15


def test_builder_gsig_output_matches_the_json_output(tmp_path: Path) -> None:
    """The two `--format` values must describe the same library, not two
    different builds that happen to share a name."""
    _need(ARCHIVE)
    json_lib = build_library_from_archive(
        ARCHIVE,
        library_name="mathlib",
        version="1.0.0",
        variant="gcc-15.2.0-O2",
        arch="x86_64",
    )
    out = tmp_path / "mathlib.gsig"
    rc = build_main(
        [
            "--archive",
            str(ARCHIVE),
            "--library-name",
            "mathlib",
            "--library-version",
            "1.0.0",
            "--variant",
            "gcc-15.2.0-O2",
            "--arch",
            "x86_64",
            "--format",
            FORMAT_GSIG,
            "--output",
            str(out),
            "--quiet",
        ]
    )
    assert rc == 0
    from_gsig = json.loads(g.analysis.flirt_library_to_json_str(str(out)))
    assert from_gsig["library"] == json_lib["library"]
    assert len(from_gsig["entries"]) == len(json_lib["entries"])
    assert {e["name"] for e in from_gsig["entries"]} == {
        e["name"] for e in json_lib["entries"]
    }


def test_builder_defaults_to_json(tmp_path: Path) -> None:
    """`--format` must not change the default: every existing caller,
    fixture and committed library is JSON."""
    _need(ARCHIVE)
    out = tmp_path / "mathlib.flirt.json"
    rc = build_main(
        [
            "--archive",
            str(ARCHIVE),
            "--library-name",
            "mathlib",
            "--library-version",
            "1.0.0",
            "--variant",
            "gcc-15.2.0-O2",
            "--arch",
            "x86_64",
            "--output",
            str(out),
            "--quiet",
        ]
    )
    assert rc == 0
    assert out.read_text().lstrip().startswith("{")
    assert g.analysis.flirt_library_info_path(str(out))["format"] == FORMAT_JSON


# ---------------------------------------------------------------------------
# glaurung.tools.sig_convert
# ---------------------------------------------------------------------------


def test_sig_convert_to_gsig_and_back(tmp_path: Path) -> None:
    gsig_path = tmp_path / "roundtrip.gsig"
    json_path = tmp_path / "roundtrip.flirt.json"
    report = sig_convert.to_gsig(_need(GOLDEN_JSON), gsig_path)
    assert report["n_signatures"] == 12
    assert gsig_path.read_bytes() == _need(GOLDEN_GSIG).read_bytes()

    sig_convert.to_json(gsig_path, json_path)
    assert sig_convert.canonical_json(
        sig_convert.read_library(json_path)
    ) == sig_convert.canonical_json(sig_convert.read_library(GOLDEN_JSON))


def test_sig_convert_roundtrip_reports_no_failures() -> None:
    result = sig_convert.roundtrip(_need(GOLDEN_JSON))
    assert result["json_identical"] is True
    assert result["gsig_identical"] is True
    assert result["n_signatures"] == 12


def test_sig_convert_cli_info_prints_json(capsys: pytest.CaptureFixture[str]) -> None:
    rc = sig_convert.main(["info", str(_need(GOLDEN_GSIG))])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["format"] == "gsig"


def test_sig_convert_cli_roundtrip_over_a_directory(tmp_path: Path) -> None:
    """The directory form is what a corpus-wide sanity check runs; a single
    fixture directory proves the plumbing without touching an external
    machine-specific cache."""
    fixtures_dir = _need(GOLDEN_JSON).parent
    rc = sig_convert.main(["roundtrip", str(fixtures_dir)])
    assert rc == 0


def test_sig_convert_module_runs_as_a_script() -> None:
    """`python -m glaurung.tools.sig_convert` is the documented entry point;
    exercised as a real subprocess so an import-time regression cannot hide
    behind calling the functions directly."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "glaurung.tools.sig_convert",
            "info",
            str(_need(GOLDEN_GSIG)),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["format"] == "gsig"


# ---------------------------------------------------------------------------
# FlirtLibrary::from_path dispatch, from the Python matcher entry point
# ---------------------------------------------------------------------------


def test_matcher_entry_point_accepts_a_gsig_library() -> None:
    """`flirt_match_functions_with_evidence_path` -- the entry point real
    analysis calls -- must not be JSON-only."""
    data = bytes.fromhex(
        json.loads(_need(GOLDEN_JSON).read_text())["entries"][0]["prologue_hex"]
    )
    # Not a real binary, so this only needs to not raise ValueError for the
    # library format; a coff/pe/elf parse failure on the *data* argument
    # would be a different test's concern.
    with pytest.raises(Exception) as excinfo:
        g.analysis.flirt_match_functions_with_evidence_path(
            "/nonexistent/path/does/not/matter", str(GOLDEN_GSIG)
        )
    # Must fail on the missing binary path, not on the gsig library.
    assert "gsig" not in str(excinfo.value).lower()


# ---------------------------------------------------------------------------
# The second identity scheme: warp-function-guid-v1 in the same container
# ---------------------------------------------------------------------------

WARP_JSON = REPO / "tests/fixtures/flirt/gsig/warp_sample.x86_64.warp.json"
WARP_GSIG = REPO / "tests/fixtures/flirt/gsig/warp_sample.x86_64.warp.gsig"


def test_detect_scheme_reads_both_formats_and_both_schemes() -> None:
    assert sig_convert.detect_scheme(_need(GOLDEN_JSON)) == sig_convert.FLIRT_SCHEME
    assert sig_convert.detect_scheme(_need(GOLDEN_GSIG)) == sig_convert.FLIRT_SCHEME
    assert sig_convert.detect_scheme(_need(WARP_JSON)) == sig_convert.WARP_SCHEME
    assert sig_convert.detect_scheme(_need(WARP_GSIG)) == sig_convert.WARP_SCHEME


def test_an_explicit_scheme_that_is_wrong_is_an_error(tmp_path: Path) -> None:
    """``--scheme`` asserts rather than discovers.

    Reading a masked-pattern library through the GUID path returns an empty,
    well-formed library rather than an error, and an empty signature library
    is indistinguishable from a legitimately empty harvest.
    """
    with pytest.raises(ValueError, match="not warp-function-guid-v1"):
        sig_convert.to_gsig(_need(GOLDEN_JSON), tmp_path / "x.gsig", scheme="warp")
    with pytest.raises(ValueError, match="not flirt-masked-pattern-v1"):
        sig_convert.to_gsig(_need(WARP_JSON), tmp_path / "y.gsig", scheme="flirt")


def test_a_warp_library_round_trips_through_the_container(tmp_path: Path) -> None:
    original = json.loads(_need(WARP_JSON).read_text())
    container = tmp_path / "roundtrip.gsig"
    report = sig_convert.to_gsig(WARP_JSON, container)
    assert report["n_signatures"] == len(original["entries"])
    assert sig_convert.read_library(container) == original
    # ...and writing it again is byte-identical, which is what lets a
    # distribution address the blob by its hash.
    again = tmp_path / "again.gsig"
    sig_convert.to_gsig(container, again)
    assert again.read_bytes() == container.read_bytes()


def test_the_warp_container_is_smaller_than_its_json() -> None:
    """The size claim, measured on the committed fixture rather than asserted.

    The corpus-scale number is in ``docs/reference/signature-distribution.md``;
    this only holds that the container is not somehow *larger*, which a badly
    chunked writer can manage on a small input.
    """
    assert _need(WARP_GSIG).stat().st_size < _need(WARP_JSON).stat().st_size


def test_a_warp_container_reports_its_scheme_and_guid_count() -> None:
    info = g.analysis.flirt_library_info_path(str(_need(WARP_GSIG)))
    assert info["format"] == "gsig"
    assert info["scheme"] == "warp-function-guid-v1"
    assert info["n_guids"] == 4
    assert info["prologue_len"] == 0
    names = {chunk["name"] for chunk in info["chunks"]}
    assert {"guids", "guid_records", "constraints"} <= names
    assert "patterns" not in names


def test_reading_a_flirt_container_as_warp_is_refused() -> None:
    with pytest.raises(ValueError, match="not warp-function-guid-v1"):
        g.analysis.warp_library_to_json_str(str(_need(GOLDEN_GSIG)))
