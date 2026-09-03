"""The Rust sysroot harvester emits a valid manifest and builds real signatures.

`glaurung.tools.harvest_rust_sysroot` is the Rust half of ledger item 11 in
`docs/design/signature-library-program-2026-09-03.md`: it reads a rustup
sysroot's `.rlib` archives -- no distribution package manager involved -- and
its manifest is checked against the **same** schema
`test_system_archive_harvest.py` applies to the Docker and network harvesters,
because the whole point of a shared harvest-manifest shape is that one
catalogue can hold rows from every backend.

Everything here except the last, explicitly opt-in test runs with no Rust
toolchain installed: `tests/fixtures/rust_sysroot/` commits one real
`.rlib` (the `panic_unwind` crate, 36,178 bytes, MIT OR Apache-2.0) inside a
fabricated sysroot directory tree, which is enough to exercise the harvester,
the manifest schema, and the FLIRT archive builder end to end.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from glaurung.tools import harvest_rust_sysroot as hrs

from test_system_archive_harvest import (  # noqa: E402 (rootdir is on sys.path)
    ARCHIVE_SCHEMA,
    COMPILER_KEYS,
    IMAGE_KEYS,
    MANIFEST_SCHEMA,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_RLIB = (
    ROOT
    / "tests"
    / "fixtures"
    / "rust_sysroot"
    / "libpanic_unwind-e6943c8b7850575a.rlib"
)

#: The measured facts about the committed fixture -- see
#: tests/fixtures/rust_sysroot/README.md for how they were obtained.
FIXTURE_CRATE = "panic_unwind"
FIXTURE_HASH = "e6943c8b7850575a"
FIXTURE_TOOLCHAIN_NAME = "1.88.0-x86_64-unknown-linux-gnu"
FIXTURE_TARGET = "x86_64-unknown-linux-gnu"
FIXTURE_RELEASE = "1.88.0"
FIXTURE_COMMIT_HASH = "6b00bc3880198600130e1cf62b8f8a93494488cc"
FIXTURE_COMMIT_DATE = "2025-06-23"
FIXTURE_UNIQUE_SIGNATURES = 4
FIXTURE_RAW_SIGNATURES = 4


def _fake_toolchain(root: Path) -> hrs.ToolchainInfo:
    """A :class:`ToolchainInfo` for the committed fixture, with a fabricated
    sysroot directory under ``root`` -- no rustup, no subprocess."""
    lib_dir = root / "lib" / "rustlib" / FIXTURE_TARGET / "lib"
    lib_dir.mkdir(parents=True)
    shutil.copyfile(FIXTURE_RLIB, lib_dir / FIXTURE_RLIB.name)
    return hrs.ToolchainInfo(
        name=FIXTURE_TOOLCHAIN_NAME,
        channel=FIXTURE_RELEASE,
        root=root,
        host=FIXTURE_TARGET,
        release=FIXTURE_RELEASE,
        commit_hash=FIXTURE_COMMIT_HASH,
        commit_date=FIXTURE_COMMIT_DATE,
        llvm_version="20.1.5",
        version_line=f"rustc {FIXTURE_RELEASE} ({FIXTURE_COMMIT_HASH[:9]} {FIXTURE_COMMIT_DATE})",
    )


def test_fixture_is_present_and_small():
    assert FIXTURE_RLIB.is_file()
    assert FIXTURE_RLIB.stat().st_size < 200_000


# ---------------------------------------------------------------------------
# Pure functions: no filesystem, no fixture needed.
# ---------------------------------------------------------------------------


def test_channel_for_toolchain_strips_the_host_suffix():
    assert (
        hrs.channel_for_toolchain(
            "1.88.0-x86_64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"
        )
        == "1.88.0"
    )
    assert (
        hrs.channel_for_toolchain(
            "nightly-2026-05-01-x86_64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"
        )
        == "nightly-2026-05-01"
    )
    assert (
        hrs.channel_for_toolchain(
            "stable-x86_64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"
        )
        == "stable"
    )
    # No host suffix present: returned unchanged rather than mangled.
    assert (
        hrs.channel_for_toolchain("weird-name", "x86_64-unknown-linux-gnu")
        == "weird-name"
    )


def test_channel_manifest_url_is_dated_only_for_dated_nightlies():
    assert (
        hrs.channel_manifest_url_for("1.88.0")
        == "https://static.rust-lang.org/dist/channel-rust-1.88.0.toml"
    )
    assert (
        hrs.channel_manifest_url_for("stable")
        == "https://static.rust-lang.org/dist/channel-rust-stable.toml"
    )
    assert (
        hrs.channel_manifest_url_for("nightly-2026-05-01")
        == "https://static.rust-lang.org/dist/2026-05-01/channel-rust-nightly.toml"
    )


def test_discover_toolchains_reads_directory_names(tmp_path: Path):
    toolchains = tmp_path / "toolchains"
    for name in ("1.88.0-x86_64-unknown-linux-gnu", "stable-x86_64-unknown-linux-gnu"):
        (toolchains / name).mkdir(parents=True)
    (toolchains / "not-a-dir.txt").write_text("")
    found = hrs.discover_toolchains(tmp_path)
    assert found == [
        "1.88.0-x86_64-unknown-linux-gnu",
        "stable-x86_64-unknown-linux-gnu",
    ]
    assert hrs.discover_toolchains(tmp_path, only=("stable",)) == [
        "stable-x86_64-unknown-linux-gnu"
    ]


def test_discover_toolchains_empty_rustup_home_is_not_an_error(tmp_path: Path):
    assert hrs.discover_toolchains(tmp_path / "does-not-exist") == []


# ---------------------------------------------------------------------------
# classify_rlib: the fixture, and two synthetic edge cases.
# ---------------------------------------------------------------------------


def test_classify_rlib_reads_the_fixture():
    finding = hrs.classify_rlib(FIXTURE_RLIB)
    assert finding.crate == FIXTURE_CRATE
    assert finding.rlib_hash == FIXTURE_HASH
    assert finding.outcome == hrs.OUTCOME_ARCHIVE
    assert finding.object_member.endswith(".rcgu.o")
    assert "lib.rmeta" in finding.members
    assert finding.text_bytes > 0
    assert finding.llvmbc_bytes > 0
    # unwind bindings are extern declarations with no bodies of their own,
    # measured directly with `nm --defined-only`; panic_unwind is not that
    # case, which is why it was chosen as the fixture. `nm` counts every
    # defined text symbol (5, measured); the FLIRT builder additionally
    # drops functions below its minimum length/fixed-byte floor, so its own
    # signature count (FIXTURE_RAW_SIGNATURES, 4) is a strict subset.
    assert (
        finding.defined_text_symbols is None
        or finding.defined_text_symbols >= FIXTURE_RAW_SIGNATURES
    )


def _write_ar(path: Path, members: list[tuple[str, bytes]]) -> None:
    """Write a minimal GNU `ar` archive -- enough for `classify_rlib` to read
    without shelling out to the `ar` binary."""
    out = bytearray(b"!<arch>\n")
    for name, data in members:
        header = f"{name:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}"
        assert len(header) == 58
        out += header.encode("ascii") + b"\x60\n"
        out += data
        if len(data) % 2:
            out += b"\n"
    path.write_bytes(bytes(out))


def test_classify_rlib_metadata_only_has_no_object_member(tmp_path: Path):
    path = tmp_path / "libfoo-abcdef0123456789.rlib"
    _write_ar(path, [("lib.rmeta", b"rustc metadata, not an object file")])
    finding = hrs.classify_rlib(path, count_symbols=False)
    assert finding.outcome == hrs.OUTCOME_METADATA_ONLY
    assert finding.crate == "foo"
    assert finding.rlib_hash == "abcdef0123456789"
    assert finding.object_member == ""
    assert finding.text_bytes == 0


def test_classify_rlib_rejects_a_non_archive(tmp_path: Path):
    path = tmp_path / "libbroken-0000000000000000.rlib"
    path.write_bytes(b"not an ar archive at all")
    finding = hrs.classify_rlib(path, count_symbols=False)
    assert finding.outcome == hrs.OUTCOME_NOT_ARCHIVE
    assert finding.members == ()


# ---------------------------------------------------------------------------
# harvest_toolchain: manifest schema, shared with the other two harvesters.
# ---------------------------------------------------------------------------


def test_harvest_toolchain_manifest_matches_the_shared_schema(tmp_path: Path):
    toolchain = _fake_toolchain(tmp_path / "toolchain_root")
    output = tmp_path / "harvest"
    index = hrs.harvest_toolchain(
        toolchain, target=toolchain.host, output=output, network=False
    )

    manifest_path = output / f"rust-{toolchain.name}" / toolchain.host / "manifest.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text())

    for key, kind in MANIFEST_SCHEMA.items():
        assert key in manifest, f"manifest missing {key!r}"
        assert isinstance(manifest[key], kind), f"{key!r} has wrong type"
    assert IMAGE_KEYS <= set(manifest["image"])
    assert COMPILER_KEYS <= set(manifest["compiler"])

    assert len(manifest["archives"]) == 1
    row = manifest["archives"][0]
    for key, kind in ARCHIVE_SCHEMA.items():
        assert key in row, f"archive row missing {key!r}"
        assert isinstance(row[key], kind), f"{key!r} has wrong type"
    assert row["crate"] == FIXTURE_CRATE
    assert row["package"] == FIXTURE_CRATE
    assert row["outcome"] == hrs.OUTCOME_ARCHIVE
    assert row["package_version"] == FIXTURE_RELEASE
    assert row["rlib_hash"] == FIXTURE_HASH
    assert row["rustc_commit_hash"] == FIXTURE_COMMIT_HASH
    assert row["licence"] == "MIT OR Apache-2.0"

    # The index dict returned in-process matches what landed on disk, and is
    # itself a valid `is_image_harvest` shape for
    # `samples/docker/harvest_system_archives.py --index-root`.
    index_path = output / f"rust-{toolchain.name}" / "index.json"
    on_disk = json.loads(index_path.read_text())
    assert on_disk == index
    assert on_disk["schema_version"] == hrs.SCHEMA_VERSION
    assert isinstance(on_disk["image"], dict)
    assert isinstance(on_disk["triplets"], list)
    assert on_disk["triplets"][0]["triplet"] == FIXTURE_TARGET


def test_harvest_toolchain_manifest_json_is_canonical(tmp_path: Path):
    toolchain = _fake_toolchain(tmp_path / "toolchain_root")
    output = tmp_path / "harvest"
    hrs.harvest_toolchain(
        toolchain, target=toolchain.host, output=output, network=False
    )
    for path in (
        output / f"rust-{toolchain.name}" / toolchain.host / "manifest.json",
        output / f"rust-{toolchain.name}" / "index.json",
    ):
        raw = path.read_text()
        assert json.dumps(json.loads(raw), indent=2, sort_keys=True) + "\n" == raw


def test_harvest_toolchain_without_network_records_no_rust_std_component(
    tmp_path: Path,
):
    toolchain = _fake_toolchain(tmp_path / "toolchain_root")
    output = tmp_path / "harvest"
    hrs.harvest_toolchain(
        toolchain, target=toolchain.host, output=output, network=False
    )
    manifest = json.loads(
        (
            output / f"rust-{toolchain.name}" / toolchain.host / "manifest.json"
        ).read_text()
    )
    assert manifest["source"]["rust_std_component"] == {}
    assert manifest["source"]["channel_manifest_url"] == (
        "https://static.rust-lang.org/dist/channel-rust-1.88.0.toml"
    )


# ---------------------------------------------------------------------------
# build_set: the FLIRT archive builder, on the committed fixture.
# ---------------------------------------------------------------------------


def test_build_set_builds_the_fixture_crate(tmp_path: Path):
    toolchain = _fake_toolchain(tmp_path / "toolchain_root")
    harvest_root = tmp_path / "harvest"
    hrs.harvest_toolchain(
        toolchain, target=toolchain.host, output=harvest_root, network=False
    )

    sigs_output = tmp_path / "sigs"
    summary = hrs.build_set(
        harvest_root, sigs_output, crates=(FIXTURE_CRATE,), merge=False
    )

    assert summary["totals"]["built_this_run"] == 1
    assert summary["totals"]["failures"] == 0
    assert not summary["zero_signature_rlibs"]

    row = summary["libraries"][0]
    assert row["library_name"] == FIXTURE_CRATE
    assert row["library_version"] == FIXTURE_RELEASE
    assert row["unique_signatures"] == FIXTURE_UNIQUE_SIGNATURES
    assert row["raw_signatures"] == FIXTURE_RAW_SIGNATURES
    assert (
        row["key"]
        == f"rust-std/{FIXTURE_RELEASE}/{FIXTURE_RELEASE}-{FIXTURE_TARGET}/x86_64/{FIXTURE_CRATE}"
    )

    out_path = sigs_output / row["output"]
    assert out_path.is_file()
    lib = json.loads(out_path.read_text())
    assert lib["library"]["name"] == FIXTURE_CRATE
    assert lib["library"]["version"] == FIXTURE_RELEASE
    assert len(lib["entries"]) == FIXTURE_UNIQUE_SIGNATURES

    index_on_disk = json.loads((sigs_output / "index.json").read_text())
    assert index_on_disk == summary


def test_build_set_merge_keeps_rows_this_run_did_not_touch(tmp_path: Path):
    toolchain = _fake_toolchain(tmp_path / "toolchain_root")
    harvest_root = tmp_path / "harvest"
    hrs.harvest_toolchain(
        toolchain, target=toolchain.host, output=harvest_root, network=False
    )
    sigs_output = tmp_path / "sigs"

    first = hrs.build_set(
        harvest_root, sigs_output, crates=(FIXTURE_CRATE,), merge=False
    )
    assert first["totals"]["built_this_run"] == 1

    # A second run that matches no crate in this harvest must not erase the
    # row the first run wrote -- extending the shared index without
    # clobbering rows is the whole point of `merge=True`.
    second = hrs.build_set(
        harvest_root, sigs_output, crates=("no-such-crate",), merge=True
    )
    assert second["totals"]["built_this_run"] == 0
    assert second["totals"]["carried_from_previous_index"] == 1
    assert second["totals"]["libraries"] == 1
    assert second["libraries"][0]["library_name"] == FIXTURE_CRATE

    # Without merge, the scoped run's index describes only what it built.
    third = hrs.build_set(
        harvest_root, sigs_output, crates=("no-such-crate",), merge=False
    )
    assert third["totals"]["libraries"] == 0


def test_build_set_skips_crates_outside_the_selection(tmp_path: Path):
    toolchain = _fake_toolchain(tmp_path / "toolchain_root")
    harvest_root = tmp_path / "harvest"
    hrs.harvest_toolchain(
        toolchain, target=toolchain.host, output=harvest_root, network=False
    )
    summary = hrs.build_set(
        harvest_root, tmp_path / "sigs", crates=("std", "core"), merge=False
    )
    assert summary["totals"]["built_this_run"] == 0
    assert summary["totals"]["libraries"] == 0


# ---------------------------------------------------------------------------
# Optional: a real installed toolchain. Skipped everywhere one is not
# available; opt in explicitly with GLAURUNG_RUST_SYSROOT for a machine whose
# rustup home is not `~/.rustup`.
# ---------------------------------------------------------------------------

_REAL_RUSTUP_HOME = (
    Path(os.environ["GLAURUNG_RUST_SYSROOT"]).expanduser()
    if os.environ.get("GLAURUNG_RUST_SYSROOT")
    else hrs.default_rustup_home()
)
_HAS_REAL_TOOLCHAIN = (
    bool(shutil.which("rustc")) and (_REAL_RUSTUP_HOME / "toolchains").is_dir()
)


@pytest.mark.skipif(
    not _HAS_REAL_TOOLCHAIN,
    reason="no local rustup sysroot; set GLAURUNG_RUST_SYSROOT to opt in",
)
def test_real_installed_toolchain_harvests_end_to_end(tmp_path: Path):
    names = hrs.discover_toolchains(_REAL_RUSTUP_HOME)
    assert names, "rustup toolchains/ exists but is empty"
    toolchain = hrs.load_toolchain(_REAL_RUSTUP_HOME, names[0])
    assert toolchain is not None
    assert toolchain.release

    index = hrs.harvest_toolchain(
        toolchain, target=toolchain.host, output=tmp_path, network=False
    )
    assert index["totals"]["archives"] > 0
    # Re-validate the schema against real, not fabricated, data.
    manifest_path = (
        tmp_path / f"rust-{toolchain.name}" / toolchain.host / "manifest.json"
    )
    manifest = json.loads(manifest_path.read_text())
    for key, kind in MANIFEST_SCHEMA.items():
        assert isinstance(manifest[key], kind)
    for row in manifest["archives"]:
        for key, kind in ARCHIVE_SCHEMA.items():
            assert isinstance(row[key], kind)
