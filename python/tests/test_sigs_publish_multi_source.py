"""Publishing the whole database: several sources, several identity schemes.

`tools/publish_signature_set.py` began as "one directory of FLIRT JSON in, one
manifest out". The signature-library programme's `base` set is not that: it is
four harvesters (Docker images, distro network cells, the Rust sysroot, the
ARM GNU toolchain) plus the WARP GUID builder, under two identity schemes,
with the previous release's blobs already on a CDN. This file pins the three
properties that makes non-obvious:

* **two schemes coexist in one manifest**, each blob carrying its own `kind`,
  and each converted to `gsig/1` through the writer for its own scheme;
* **a serial is a superset of the one it carries forward from** -- every
  previously published key keeps its exact sha256, so the CDN objects stay
  valid and no client re-downloads anything it already has;
* **a contested key is resolved by history first**, then by source class, then
  by `--prefer-image`, and is a hard failure if nothing distinguishes it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from glaurung.sigs.manifest import Manifest

ROOT = Path(__file__).resolve().parents[2]
PUBLISH = ROOT / "tools" / "publish_signature_set.py"

#: The dry run recorded in `docs/reference/signature-distribution.md`. Present
#: only on a machine that has run the harvesters, so every test that reads it
#: skips loudly rather than silently passing over an absent file.
PUBLISHED_2026_09_1 = (
    Path.home() / ".cache" / "glaurung" / "release" / "2026.09.1" / "manifest.json"
)


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(PUBLISH), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def _flirt_body(n: int, tag: str) -> str:
    return json.dumps(
        {
            "schema_version": "2",
            "arch": "x86_64",
            "prologue_len": 8,
            "entries": [
                {"name": f"{tag}_{i:04d}", "prologue_hex": f"554889e5{i:08x}"}
                for i in range(n)
            ],
            "index": {},
        }
    )


def _flirt_corpus(directory: Path, rows: list[dict], bodies: dict[str, str]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name, body in bodies.items():
        (directory / name).write_text(body, encoding="utf-8")
    (directory / "index.json").write_text(
        json.dumps({"schema_version": 1, "libraries": rows}), encoding="utf-8"
    )
    return directory


def _flirt_row(name: str, *, library: str, image: str, signatures: int = 12) -> dict:
    return {
        "key": f"{image}.x86_64-linux-gnu.{library}",
        "output": name,
        "library_name": f"{library}-dev",
        "library_version": "1.2.3",
        "variant": "gcc-11-O2",
        "arch": "x86_64",
        "triplet": "x86_64-linux-gnu",
        "image": image,
        "archive": f"{library}.a",
        "archive_sha256": "d" * 64,
        "unique_signatures": signatures,
    }


def _warp_corpus(directory: Path) -> Path:
    """A two-module WARP corpus, built from the committed golden fixture."""
    directory.mkdir(parents=True, exist_ok=True)
    fixture = json.loads(
        (ROOT / "tests/fixtures/flirt/gsig/warp_sample.x86_64.warp.json").read_text(
            encoding="utf-8"
        )
    )
    rows = []
    for module, version in (("alpha.sys", "1.0.0"), ("beta.dll", "2.0.0")):
        library = dict(fixture)
        library["library"] = dict(fixture["library"], name=module, version=version)
        name = f"{module}-{version}-msvc-14.20-b27412.x86_64.warp.json"
        (directory / name).write_text(json.dumps(library), encoding="utf-8")
        rows.append(
            {
                "file": name,
                "module": module,
                "version": version,
                "variant": "msvc-14.20-b27412",
                "source": "corpus:test",
                "entries": len(fixture["entries"]),
                "unique": len(fixture["entries"]) - 1,
            }
        )
    (directory / "index.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "scheme": "warp-function-guid-v1",
                "libraries": rows,
            }
        ),
        encoding="utf-8",
    )
    return directory


@pytest.fixture
def two_schemes(tmp_path):
    flirt = _flirt_corpus(
        tmp_path / "flirt",
        [
            _flirt_row(
                "libz.flirt.json", library="libz", image="linux-amd64", signatures=9
            ),
            _flirt_row(
                "libm.flirt.json",
                library="libm",
                image="debian-trixie-amd64",
                signatures=4,
            ),
        ],
        {
            "libz.flirt.json": _flirt_body(9, "z"),
            "libm.flirt.json": _flirt_body(4, "m"),
        },
    )
    warp = _warp_corpus(tmp_path / "warp")
    return flirt, warp, tmp_path / "out"


def _publish(
    flirt: Path, warp: Path, out: Path, *extra: str
) -> subprocess.CompletedProcess:
    return _run(
        "--source",
        f"{flirt}:*.flirt.json",
        "--source",
        f"{warp}:*.warp.json:windows-warp:warp",
        "--set",
        "base",
        "--set-version",
        "2026.09.2",
        "--serial",
        "2",
        "--out",
        str(out),
        "--unsigned",
        "--quiet",
        *extra,
    )


# --- two schemes in one manifest ---------------------------------------------


def test_a_set_carries_both_identity_schemes(two_schemes):
    flirt, warp, out = two_schemes
    result = _publish(flirt, warp, out)
    assert result.returncode == 0, result.stderr[-2000:]
    manifest = Manifest.read(out / "manifest.json")
    kinds = {blob.key: blob.kind for blob in manifest.blobs}
    assert kinds == {
        "libm/1.2.3/gcc-11-O2/x86_64": "flirt-masked-pattern-v1",
        "libz/1.2.3/gcc-11-O2/x86_64": "flirt-masked-pattern-v1",
        "warp:alpha.sys/1.0.0/msvc-14.20-b27412/x86_64": "warp-function-guid-v1",
        "warp:beta.dll/2.0.0/msvc-14.20-b27412/x86_64": "warp-function-guid-v1",
    }


def test_every_blob_is_a_gsig_container_whatever_its_scheme(two_schemes):
    """`format` says `gsig/1` **and** the bytes actually start with `GSIG`.

    Asserting only the manifest field would pass on a tool that recorded the
    format and shipped the JSON, which is exactly the failure that would make
    a client's dispatch-on-magic silently fall back to the JSON parser.
    """
    flirt, warp, out = two_schemes
    assert _publish(flirt, warp, out).returncode == 0
    manifest = Manifest.read(out / "manifest.json")
    for blob in manifest.blobs:
        assert blob.format == "gsig/1", blob.key
        body = (out / "blobs" / blob.sha256).read_bytes()
        assert body[:4] == b"GSIG", blob.key
        assert blob.size_bytes == len(body)


def test_a_warp_blob_keeps_the_provenance_its_index_recorded(two_schemes):
    flirt, warp, out = two_schemes
    assert _publish(flirt, warp, out).returncode == 0
    manifest = Manifest.read(out / "manifest.json")
    blob = manifest.by_key("warp:alpha.sys/1.0.0/msvc-14.20-b27412/x86_64")
    assert blob is not None
    assert blob.provenance.source == "corpus:test"
    assert blob.provenance.package == "alpha.sys"
    assert blob.provenance.version == "1.0.0"
    assert blob.provenance.variant == "msvc-14.20-b27412"
    assert blob.provenance.arch == "x86_64"


def test_an_unsigned_dry_run_warns_that_its_aws_commands_are_incomplete(two_schemes):
    """An unsigned run still prints the upload recipe, and must say why it
    cannot be run as printed.

    The failure it guards against is an operator pasting the `aws` lines and
    uploading blobs for a manifest that can never be verified, leaving the
    bucket holding objects no signed manifest names.
    """
    flirt, warp, out = two_schemes
    result = _publish(flirt, warp, out)
    assert result.returncode == 0, result.stderr[-2000:]
    assert "--unsigned: manifest.json.minisig does not exist" in result.stdout
    assert "minisign -Sm" in result.stdout
    # ...and nothing was signed.
    assert not (out / "manifest.json.minisig").exists()


def test_unsigned_refuses_to_upload(two_schemes):
    flirt, warp, out = two_schemes
    result = _publish(flirt, warp, out, "--upload")
    assert result.returncode != 0
    assert "mutually exclusive" in result.stderr


def test_convert_none_publishes_the_harvesters_own_bytes(two_schemes):
    """The escape hatch still works, and says so in `format`."""
    flirt, warp, out = two_schemes
    assert _publish(flirt, warp, out, "--convert", "none").returncode == 0
    manifest = Manifest.read(out / "manifest.json")
    assert {blob.format for blob in manifest.blobs} == {"flirt-json/2"}
    for blob in manifest.blobs:
        assert (out / "blobs" / blob.sha256).read_bytes()[:1] == b"{"


# --- carry-forward -----------------------------------------------------------


def test_a_later_serial_is_a_superset_of_the_one_it_carries_forward(two_schemes):
    """Every earlier key keeps its exact sha256, so the CDN copies are reused.

    This is the whole reason the store is content-addressed. If a re-cut
    changed the digest of a blob whose *content* had not changed, every client
    would re-download it and every already-uploaded object would be orphaned.
    """
    flirt, warp, out = two_schemes
    first = out / "serial1"
    assert (
        _run(
            "--source",
            f"{flirt}:*.flirt.json",
            "--set",
            "base",
            "--set-version",
            "2026.09.1",
            "--serial",
            "1",
            "--out",
            str(first),
            "--unsigned",
            "--quiet",
        ).returncode
        == 0
    )
    earlier = Manifest.read(first / "manifest.json")

    second = out / "serial2"
    assert (
        _publish(
            flirt, warp, second, "--carry-forward", str(first / "manifest.json")
        ).returncode
        == 0
    )
    later = Manifest.read(second / "manifest.json")

    earlier_by_key = {blob.key: blob for blob in earlier.blobs}
    later_by_key = {blob.key: blob for blob in later.blobs}
    assert set(earlier_by_key) <= set(later_by_key)
    for key, blob in earlier_by_key.items():
        assert later_by_key[key].sha256 == blob.sha256, key
        assert later_by_key[key].format == blob.format, key
        assert later_by_key[key].size_bytes == blob.size_bytes, key
    # ...and the new material really is there too.
    assert len(later_by_key) > len(earlier_by_key)
    assert any(blob.kind == "warp-function-guid-v1" for blob in later.blobs)


def test_carried_blobs_are_copied_into_the_new_release_directory(two_schemes):
    """`SHA256SUMS` names them, so the files have to be present to check."""
    flirt, warp, out = two_schemes
    first = out / "serial1"
    assert (
        _run(
            "--source",
            f"{flirt}:*.flirt.json",
            "--set",
            "base",
            "--set-version",
            "2026.09.1",
            "--serial",
            "1",
            "--out",
            str(first),
            "--unsigned",
            "--quiet",
        ).returncode
        == 0
    )
    second = out / "serial2"
    assert (
        _publish(
            flirt, warp, second, "--carry-forward", str(first / "manifest.json")
        ).returncode
        == 0
    )
    manifest = Manifest.read(second / "manifest.json")
    for blob in manifest.blobs:
        assert (second / "blobs" / blob.sha256).is_file(), blob.key
    sums = (second / "SHA256SUMS").read_text(encoding="utf-8")
    for blob in manifest.blobs:
        assert f"{blob.sha256}  blobs/{blob.sha256}" in sums


def test_carry_forward_refuses_a_serial_that_does_not_advance(two_schemes):
    flirt, warp, out = two_schemes
    first = out / "serial1"
    assert (
        _run(
            "--source",
            f"{flirt}:*.flirt.json",
            "--set",
            "base",
            "--set-version",
            "2026.09.1",
            "--serial",
            "5",
            "--out",
            str(first),
            "--unsigned",
            "--quiet",
        ).returncode
        == 0
    )
    result = _publish(
        flirt, warp, out / "serial2", "--carry-forward", str(first / "manifest.json")
    )
    assert result.returncode != 0
    assert "must exceed" in result.stderr


# --- contested keys ----------------------------------------------------------


def test_a_network_cell_beats_a_docker_image_for_one_key(tmp_path):
    """The network cell carries the *upstream* package hash; the image does not."""
    corpus = _flirt_corpus(
        tmp_path / "corpus",
        [
            _flirt_row("a.flirt.json", library="libz", image="linux-amd64"),
            _flirt_row("b.flirt.json", library="libz", image="debian-trixie-amd64"),
        ],
        {"a.flirt.json": _flirt_body(3, "img"), "b.flirt.json": _flirt_body(4, "net")},
    )
    out = tmp_path / "out"
    result = _run(
        "--blobs",
        str(corpus),
        "--pattern",
        "*.flirt.json",
        "--set",
        "base",
        "--set-version",
        "1",
        "--serial",
        "1",
        "--out",
        str(out),
        "--unsigned",
        "--quiet",
    )
    assert result.returncode == 0, result.stderr[-2000:]
    manifest = Manifest.read(out / "manifest.json")
    assert len(manifest.blobs) == 1
    assert manifest.blobs[0].provenance.image == "debian-trixie-amd64"
    assert manifest.blobs[0].provenance.source == "distro-archive"


def test_history_outranks_the_source_class(tmp_path):
    """A published key is never re-litigated, however the classes now rank.

    Without this, adding a network cell for a library a Docker image already
    published would change that key's blob -- and its sha256 -- for a reason
    that has nothing to do with the signatures in it.
    """
    corpus = _flirt_corpus(
        tmp_path / "corpus",
        [_flirt_row("a.flirt.json", library="libz", image="linux-amd64")],
        {"a.flirt.json": _flirt_body(3, "img")},
    )
    first = tmp_path / "first"
    assert (
        _run(
            "--blobs",
            str(corpus),
            "--pattern",
            "*.flirt.json",
            "--set",
            "base",
            "--set-version",
            "1",
            "--serial",
            "1",
            "--out",
            str(first),
            "--unsigned",
            "--quiet",
        ).returncode
        == 0
    )
    published = Manifest.read(first / "manifest.json").blobs[0]

    # A network cell for the same key turns up in the next harvest.
    (corpus / "b.flirt.json").write_text(_flirt_body(4, "net"), encoding="utf-8")
    index = json.loads((corpus / "index.json").read_text())
    index["libraries"].append(
        _flirt_row("b.flirt.json", library="libz", image="debian-trixie-amd64")
    )
    (corpus / "index.json").write_text(json.dumps(index), encoding="utf-8")

    second = tmp_path / "second"
    assert (
        _run(
            "--blobs",
            str(corpus),
            "--pattern",
            "*.flirt.json",
            "--set",
            "base",
            "--set-version",
            "2",
            "--serial",
            "2",
            "--out",
            str(second),
            "--unsigned",
            "--quiet",
            "--carry-forward",
            str(first / "manifest.json"),
        ).returncode
        == 0
    )
    later = Manifest.read(second / "manifest.json")
    assert len(later.blobs) == 1
    assert later.blobs[0].sha256 == published.sha256


def test_an_unresolvable_collision_is_still_a_hard_failure(tmp_path):
    corpus = _flirt_corpus(
        tmp_path / "corpus",
        [
            _flirt_row("a.flirt.json", library="libz", image="linux-amd64"),
            _flirt_row("b.flirt.json", library="libz", image="linux-arm64"),
        ],
        {"a.flirt.json": _flirt_body(3, "a"), "b.flirt.json": _flirt_body(4, "b")},
    )
    result = _run(
        "--blobs",
        str(corpus),
        "--pattern",
        "*.flirt.json",
        "--set",
        "base",
        "--set-version",
        "1",
        "--serial",
        "1",
        "--out",
        str(tmp_path / "out"),
        "--unsigned",
        "--quiet",
    )
    assert result.returncode != 0
    assert "key collision" in result.stderr
    assert "--prefer-image" in result.stderr


# --- the real published release ----------------------------------------------


@pytest.mark.skipif(
    not PUBLISHED_2026_09_1.is_file(),
    reason=(
        f"{PUBLISHED_2026_09_1} is not readable on this machine, so the "
        "carry-forward property cannot be checked against the release that "
        "is actually live. Run the harvesters and the 2026.09.1 publish, or "
        "read the recorded numbers in "
        "docs/reference/signature-distribution.md."
    ),
)
def test_the_live_serial_2_manifest_carries_every_serial_1_blob_unchanged():
    """The dry run at `~/.cache/glaurung/release/2026.09.2`, if it is there.

    This is the assertion the 2026.09.2 dry run exists to support: serial 2
    must list every serial-1 blob with the *same* sha256, so publishing it
    uploads only what is new. It skips loudly rather than passing quietly when
    either release directory is absent -- a green test over a file that is not
    there is worse than no test.
    """
    later_path = PUBLISHED_2026_09_1.parent.parent / "2026.09.2" / "manifest.json"
    if not later_path.is_file():
        pytest.skip(
            f"{later_path} has not been built; run the publish dry run in "
            "docs/reference/signature-distribution.md first"
        )
    earlier = Manifest.read(PUBLISHED_2026_09_1)
    later = Manifest.read(later_path)
    assert later.serial > earlier.serial
    later_by_key = {blob.key: blob for blob in later.blobs}
    missing = [blob.key for blob in earlier.blobs if blob.key not in later_by_key]
    assert not missing, (
        f"serial {later.serial} dropped {len(missing)} key(s): {missing[:5]}"
    )
    changed = [
        blob.key
        for blob in earlier.blobs
        if later_by_key[blob.key].sha256 != blob.sha256
    ]
    assert not changed, (
        f"{len(changed)} carried key(s) changed sha256, so every client "
        f"re-downloads them: {changed[:5]}"
    )
    assert len(later.blobs) > len(earlier.blobs)


@pytest.mark.skipif(
    os.environ.get("GLAURUNG_SIGS_NETWORK_TEST") is None,
    reason="reads the harvest cache; opt in with GLAURUNG_SIGS_NETWORK_TEST=1",
)
def test_the_harvest_cache_still_has_the_three_source_shapes():
    """The three `index.json` shapes the publisher sniffs, as they are on disk."""
    cache = Path.home() / ".cache" / "glaurung" / "system-libs"
    flirt = json.loads((cache / "sigs" / "index.json").read_text())
    armtc = json.loads((cache / "armtc-13.2.1" / "sigs" / "index.json").read_text())
    warp = json.loads((cache / "warp" / "index.json").read_text())
    assert "output" in flirt["libraries"][0]
    assert "triplet" not in armtc["libraries"][0]
    assert warp["scheme"] == "warp-function-guid-v1"
    assert "file" in warp["libraries"][0]
