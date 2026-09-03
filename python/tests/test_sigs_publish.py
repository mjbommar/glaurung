"""`tools/publish_signature_set.py`: what it produces, and what it refuses.

Two properties are load-bearing and are asserted rather than described:

* it is a **dry run by construction**. The module imports no network client
  at all, and the only place a URL appears in its output is inside a printed
  command. A tool that could publish is one keystroke from publishing, and
  this repository's contribution rules put the upstream action on a human.
* a **key collision is a hard failure**. Two blobs claiming one
  `(library, version, variant, arch)` key means the harvester is not
  distinguishing two builds, and publishing either silently would ship a
  library under a name that does not identify it.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from glaurung.sigs import minisign
from glaurung.sigs.manifest import Manifest, validate_against_schema

ROOT = Path(__file__).resolve().parents[2]
PUBLISH = ROOT / "tools" / "publish_signature_set.py"


def _corpus(directory: Path, records: list[dict], bodies: dict[str, str]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name, body in bodies.items():
        (directory / name).write_text(body, encoding="utf-8")
    (directory / "index.json").write_text(
        json.dumps({"schema_version": 1, "libraries": records}), encoding="utf-8"
    )
    return directory


def _record(name: str, *, library: str, image: str = "test", signatures: int = 12):
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


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(PUBLISH), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


@pytest.fixture
def simple(tmp_path):
    corpus = _corpus(
        tmp_path / "corpus",
        [
            _record("libz.flirt.json", library="libz", signatures=109),
            _record("libm.flirt.json", library="libm", signatures=42),
            _record("empty.flirt.json", library="empty", signatures=0),
        ],
        {
            "libz.flirt.json": json.dumps({"entries": ["z"] * 109}),
            "libm.flirt.json": json.dumps({"entries": ["m"] * 42}),
            "empty.flirt.json": json.dumps({"entries": []}),
        },
    )
    return corpus, tmp_path / "out", tmp_path / "keys" / "k.key"


# --- the produced release directory ------------------------------------------


def test_produces_every_release_artefact(simple):
    corpus, out, key = simple
    result = _run(
        "--blobs",
        str(corpus),
        "--set",
        "base",
        "--set-version",
        "2026.09.1",
        "--serial",
        "7",
        "--out",
        str(out),
        "--secret-key",
        str(key),
        "--generate-key",
        "--quiet",
    )
    assert result.returncode == 0, result.stderr[-2000:]

    for name in ("manifest.json", "manifest.json.minisig", "SHA256SUMS", "NOTICE"):
        assert (out / name).is_file(), name

    manifest = Manifest.read(out / "manifest.json")
    assert manifest.set_name == "base"
    assert manifest.serial == 7
    assert validate_against_schema(manifest.to_dict()) == []

    # Blobs are named by their digest, and only by their digest.
    for blob in manifest.blobs:
        path = out / "blobs" / blob.sha256
        assert path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == blob.sha256
        assert path.stat().st_size == blob.size_bytes


def test_the_signature_it_writes_verifies(simple):
    corpus, out, key = simple
    assert (
        _run(
            "--blobs",
            str(corpus),
            "--set",
            "base",
            "--set-version",
            "2026.09.1",
            "--serial",
            "1",
            "--out",
            str(out),
            "--secret-key",
            str(key),
            "--generate-key",
            "--quiet",
        ).returncode
        == 0
    )

    public = minisign.SecretKey.read(key).public_key()
    minisign.verify_file(out / "manifest.json", out / "manifest.json.minisig", [public])

    signature = minisign.Signature.read(out / "manifest.json.minisig")
    manifest = Manifest.read(out / "manifest.json")
    assert signature.trusted_comment == manifest.trusted_comment()
    assert "serial=1" in signature.trusted_comment


def test_generates_a_keypair_and_never_writes_the_secret_key_world_readable(simple):
    corpus, out, key = simple
    result = _run(
        "--blobs",
        str(corpus),
        "--set",
        "base",
        "--set-version",
        "1",
        "--serial",
        "1",
        "--out",
        str(out),
        "--secret-key",
        str(key),
        "--generate-key",
        "--quiet",
    )
    assert result.returncode == 0
    assert key.is_file()
    assert key.stat().st_mode & 0o777 == 0o600
    assert key.with_suffix(".pub").is_file()
    assert "never commit" in result.stderr


def test_refuses_to_run_without_a_key(simple):
    corpus, out, key = simple
    result = _run(
        "--blobs",
        str(corpus),
        "--set",
        "base",
        "--set-version",
        "1",
        "--serial",
        "1",
        "--out",
        str(out),
        "--secret-key",
        str(key),
    )
    assert result.returncode != 0
    assert "--generate-key" in result.stderr


def test_empty_libraries_are_dropped_not_published(simple):
    """Five glibc archives have been 8-byte stubs since 2.34; MinGW import
    libraries are pure thunks. A harvest legitimately yields blobs with no
    signatures, and shipping them inflates the set with entries that can never
    match anything."""
    corpus, out, key = simple
    result = _run(
        "--blobs",
        str(corpus),
        "--set",
        "base",
        "--set-version",
        "1",
        "--serial",
        "1",
        "--out",
        str(out),
        "--secret-key",
        str(key),
        "--generate-key",
        "--quiet",
    )
    assert result.returncode == 0
    keys = {blob.key for blob in Manifest.read(out / "manifest.json").blobs}
    assert not any(k.startswith("empty/") for k in keys)
    assert len(keys) == 2
    assert "skipped 1 source file" in result.stderr


def test_sha256sums_is_checkable_by_sha256sum(simple, tmp_path):
    corpus, out, key = simple
    assert (
        _run(
            "--blobs",
            str(corpus),
            "--set",
            "base",
            "--set-version",
            "1",
            "--serial",
            "1",
            "--out",
            str(out),
            "--secret-key",
            str(key),
            "--generate-key",
            "--quiet",
        ).returncode
        == 0
    )
    check = subprocess.run(
        ["sha256sum", "-c", "SHA256SUMS"], cwd=out, capture_output=True, text=True
    )
    assert check.returncode == 0, check.stdout + check.stderr


def test_the_notice_states_the_licence_position_and_lists_provenance(simple):
    corpus, out, key = simple
    assert (
        _run(
            "--blobs",
            str(corpus),
            "--set",
            "base",
            "--set-version",
            "1",
            "--serial",
            "1",
            "--out",
            str(out),
            "--secret-key",
            str(key),
            "--generate-key",
            "--quiet",
        ).returncode
        == 0
    )
    notice = (out / "NOTICE").read_text()
    assert "no byte from the original libraries" in notice
    assert "TAKEDOWN" in notice
    for fragment in ("libz-dev", "libm-dev", "1.2.3", "x86_64"):
        assert fragment in notice, fragment


def test_a_dotted_library_name_survives_key_derivation(tmp_path):
    """`<image>.<triplet>.<library>` where image AND library contain dots.

    `alpine-v3.20-aarch64.aarch64-linux-musl.libm-2.36` is a real harvest key.
    Splitting on the last dot made the library name `35` and published a blob
    keyed `35/2.35-0ubuntu3.14/...`, which identifies nothing.
    """
    record = {
        "key": "alpine-v3.20-aarch64.aarch64-linux-musl.libm-2.36",
        "output": "libm.flirt.json",
        "library_name": "libc6-dev",
        "library_version": "2.36",
        "variant": "alpine-3.20",
        "arch": "aarch64",
        "triplet": "aarch64-linux-musl",
        "image": "alpine-v3.20-aarch64",
        "archive": "libm-2.36.a",
        "unique_signatures": 5,
    }
    corpus = _corpus(
        tmp_path / "corpus",
        [record],
        {"libm.flirt.json": json.dumps({"entries": ["m"] * 5})},
    )
    out = tmp_path / "out"
    assert (
        _run(
            "--blobs",
            str(corpus),
            "--set",
            "base",
            "--set-version",
            "1",
            "--serial",
            "1",
            "--out",
            str(out),
            "--secret-key",
            str(tmp_path / "k.key"),
            "--generate-key",
            "--quiet",
        ).returncode
        == 0
    )
    keys = [blob.key for blob in Manifest.read(out / "manifest.json").blobs]
    assert keys == ["libm-2.36/2.36/alpine-3.20/aarch64"]


def test_the_archive_name_is_the_fallback_when_there_is_no_triplet(tmp_path):
    record = {
        "key": "img.libz",
        "output": "libz.flirt.json",
        "library_version": "1.2.11",
        "variant": "gcc-11-O2",
        "arch": "x86_64",
        "archive": "/home/someone/build/x86_64/lib/libz.a",
        "unique_signatures": 3,
    }
    corpus = _corpus(
        tmp_path / "corpus",
        [record],
        {"libz.flirt.json": json.dumps({"entries": ["z"] * 3})},
    )
    out = tmp_path / "out"
    assert (
        _run(
            "--blobs",
            str(corpus),
            "--set",
            "base",
            "--set-version",
            "1",
            "--serial",
            "1",
            "--out",
            str(out),
            "--secret-key",
            str(tmp_path / "k.key"),
            "--generate-key",
            "--quiet",
        ).returncode
        == 0
    )
    keys = [blob.key for blob in Manifest.read(out / "manifest.json").blobs]
    assert keys == ["libz/1.2.11/gcc-11-O2/x86_64"]


def test_provenance_is_carried_from_the_harvest_index(simple):
    corpus, out, key = simple
    assert (
        _run(
            "--blobs",
            str(corpus),
            "--set",
            "base",
            "--set-version",
            "1",
            "--serial",
            "1",
            "--out",
            str(out),
            "--secret-key",
            str(key),
            "--generate-key",
            "--quiet",
        ).returncode
        == 0
    )
    manifest = Manifest.read(out / "manifest.json")
    blob = next(b for b in manifest.blobs if b.key.startswith("libz/"))
    assert blob.provenance.package == "libz-dev"
    assert blob.provenance.version == "1.2.3"
    assert blob.provenance.arch == "x86_64"
    assert blob.provenance.input_sha256 == "d" * 64
    assert blob.signatures == 109
    assert blob.urls, "a blob with no URL cannot be fetched"


def test_the_blob_directory_holds_exactly_what_the_manifest_names(simple):
    """`gh release upload blobs/*` must not ship an unlisted asset.

    Orphans arise from an earlier run that aborted after copying some blobs,
    or a re-run with different filters. The 2026-09-03 dry run produced 172
    files for a 171-blob manifest exactly this way.
    """
    corpus, out, key = simple
    args = [
        "--blobs",
        str(corpus),
        "--set",
        "base",
        "--set-version",
        "1",
        "--serial",
        "1",
        "--out",
        str(out),
        "--secret-key",
        str(key),
        "--generate-key",
        "--quiet",
    ]
    assert _run(*args).returncode == 0

    # Plant an orphan, as an aborted earlier run would.
    orphan = out / "blobs" / ("f" * 64)
    orphan.write_bytes(b"left over from a run that failed halfway")
    assert _run(*args).returncode == 0

    manifest = Manifest.read(out / "manifest.json")
    on_disk = {p.name for p in (out / "blobs").iterdir() if p.is_file()}
    assert on_disk == {blob.sha256 for blob in manifest.blobs}
    assert not orphan.exists()


def test_a_narrower_rerun_prunes_what_it_no_longer_publishes(simple):
    corpus, out, key = simple
    base = [
        "--blobs",
        str(corpus),
        "--set",
        "base",
        "--set-version",
        "1",
        "--serial",
        "1",
        "--out",
        str(out),
        "--secret-key",
        str(key),
        "--generate-key",
        "--quiet",
    ]
    assert _run(*base).returncode == 0
    assert len(list((out / "blobs").iterdir())) == 2

    assert _run(*base, "--min-signatures", "100").returncode == 0
    manifest = Manifest.read(out / "manifest.json")
    assert len(manifest.blobs) == 1
    assert {p.name for p in (out / "blobs").iterdir()} == {manifest.blobs[0].sha256}


# --- the dry run is a dry run ------------------------------------------------


def test_prints_the_publish_commands_without_running_them(simple):
    corpus, out, key = simple
    result = _run(
        "--blobs",
        str(corpus),
        "--set",
        "base",
        "--set-version",
        "2026.09.1",
        "--serial",
        "1",
        "--out",
        str(out),
        "--secret-key",
        str(key),
        "--generate-key",
        "--quiet",
    )
    assert result.returncode == 0
    assert "DRY RUN: nothing was published" in result.stdout
    assert "gh release create 2026.09.1" in result.stdout
    assert "--draft" in result.stdout
    assert "gh release edit 2026.09.1" in result.stdout
    assert "rclone copy" in result.stdout
    assert "minisign -Vm manifest.json" in result.stdout


def test_the_tool_imports_no_network_client():
    """Structural, not behavioural: it cannot publish because it cannot speak."""
    source = PUBLISH.read_text()
    for forbidden in ("urllib", "requests", "httpx", "socket", "http.client"):
        assert f"import {forbidden}" not in source, forbidden
    # ...and it never runs a subprocess either, so it cannot shell out to `gh`.
    assert "subprocess" not in source


# --- refusals ----------------------------------------------------------------


def test_a_key_collision_is_a_hard_failure(tmp_path):
    """Two blobs, one key, different bytes: publishing either would be a lie."""
    corpus = _corpus(
        tmp_path / "corpus",
        [
            _record("a.flirt.json", library="libz", image="linux-amd64"),
            _record("b.flirt.json", library="libz", image="linux-arm64"),
        ],
        {
            "a.flirt.json": json.dumps({"entries": ["a"], "built_on": "amd64"}),
            "b.flirt.json": json.dumps({"entries": ["b"], "built_on": "arm64"}),
        },
    )
    result = _run(
        "--blobs",
        str(corpus),
        "--set",
        "base",
        "--set-version",
        "1",
        "--serial",
        "1",
        "--out",
        str(tmp_path / "out"),
        "--secret-key",
        str(tmp_path / "k.key"),
        "--generate-key",
        "--quiet",
    )
    assert result.returncode != 0
    assert "key collision" in result.stderr


def test_prefer_image_resolves_a_collision_deterministically(tmp_path):
    corpus = _corpus(
        tmp_path / "corpus",
        [
            _record("a.flirt.json", library="libz", image="linux-amd64"),
            _record("b.flirt.json", library="libz", image="linux-arm64"),
        ],
        {
            "a.flirt.json": json.dumps({"entries": ["a"], "built_on": "amd64"}),
            "b.flirt.json": json.dumps({"entries": ["b"], "built_on": "arm64"}),
        },
    )
    out = tmp_path / "out"
    for order, expected in (
        (["linux-amd64", "linux-arm64"], "amd64"),
        (["linux-arm64", "linux-amd64"], "arm64"),
    ):
        args = ["--prefer-image", order[0], "--prefer-image", order[1]]
        result = _run(
            "--blobs",
            str(corpus),
            "--set",
            "base",
            "--set-version",
            "1",
            "--serial",
            "1",
            "--out",
            str(out),
            "--secret-key",
            str(tmp_path / "k.key"),
            "--generate-key",
            "--quiet",
            *args,
        )
        assert result.returncode == 0, result.stderr[-1000:]
        manifest = Manifest.read(out / "manifest.json")
        assert len(manifest.blobs) == 1
        body = (out / "blobs" / manifest.blobs[0].sha256).read_text()
        assert expected in body


def test_identical_bytes_under_one_key_deduplicate_instead_of_colliding(tmp_path):
    """The 26-43 percent cross-release overlap is free at the blob level."""
    same = json.dumps({"entries": ["same"]})
    corpus = _corpus(
        tmp_path / "corpus",
        [
            _record("a.flirt.json", library="libz", image="linux-amd64"),
            _record("b.flirt.json", library="libz", image="linux-arm64"),
        ],
        {"a.flirt.json": same, "b.flirt.json": same},
    )
    result = _run(
        "--blobs",
        str(corpus),
        "--set",
        "base",
        "--set-version",
        "1",
        "--serial",
        "1",
        "--out",
        str(tmp_path / "out"),
        "--secret-key",
        str(tmp_path / "k.key"),
        "--generate-key",
        "--quiet",
    )
    assert result.returncode == 0, result.stderr[-1000:]
    manifest = Manifest.read(tmp_path / "out" / "manifest.json")
    assert len(manifest.blobs) == 1
    assert len(list((tmp_path / "out" / "blobs").iterdir())) == 1


def test_an_empty_input_directory_is_refused(tmp_path):
    empty = tmp_path / "nothing"
    empty.mkdir()
    result = _run(
        "--blobs",
        str(empty),
        "--set",
        "base",
        "--set-version",
        "1",
        "--serial",
        "1",
        "--out",
        str(tmp_path / "out"),
        "--secret-key",
        str(tmp_path / "k.key"),
        "--generate-key",
    )
    assert result.returncode != 0
    assert "no blobs matched" in result.stderr


def test_the_release_tag_can_differ_from_the_set_version(simple):
    """The bundled subset carries its own set_version and the release's URLs."""
    corpus, out, key = simple
    assert (
        _run(
            "--blobs",
            str(corpus),
            "--set",
            "base",
            "--set-version",
            "2026.09.1-bundled",
            "--release-tag",
            "2026.09.1",
            "--serial",
            "1",
            "--out",
            str(out),
            "--secret-key",
            str(key),
            "--generate-key",
            "--quiet",
        ).returncode
        == 0
    )
    manifest = Manifest.read(out / "manifest.json")
    assert manifest.set_version == "2026.09.1-bundled"
    assert all("/releases/download/2026.09.1/" in b.urls[0] for b in manifest.blobs)
