"""`tools/publish_signature_set.py`: what it produces, and what it refuses.

Three properties are load-bearing and are asserted rather than described:

* **GitHub Releases (secondary) is print-only, unconditionally.** The tool
  never imports an HTTP/network client and never invokes `gh`; the only place
  a GitHub URL appears in its output is inside a printed command.
* **S3 (`assets.glaurung.dev`, primary) is dry-run by default.** Without
  `--upload` it never shells out at all -- proved behaviourally, by making a
  `subprocess.run` call raise and running the tool in-process. `--upload`
  drives the `aws` CLI for real, blobs first, then the signature, then the
  manifest last, and never overwrites an existing blob key.
* a **key collision is a hard failure**. Two blobs claiming one
  `(library, version, variant, arch)` key means the harvester is not
  distinguishing two builds, and publishing either silently would ship a
  library under a name that does not identify it.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from glaurung.sigs import minisign, paths
from glaurung.sigs.manifest import Manifest, validate_against_schema

ROOT = Path(__file__).resolve().parents[2]
PUBLISH = ROOT / "tools" / "publish_signature_set.py"


def _load_publish_module():
    """Import the tool in-process, so a test can monkeypatch its `subprocess`.

    Registered in `sys.modules` under its own name before `exec_module`
    because its dataclasses use `from __future__ import annotations`:
    `dataclasses` resolves string type annotations by looking the defining
    module back up in `sys.modules[cls.__module__]`, which fails with a
    confusing `AttributeError` on `None` if the module was never registered.
    """
    spec = importlib.util.spec_from_file_location("publish_signature_set", PUBLISH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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


def test_assets_glaurung_dev_is_the_first_url_github_the_second(simple):
    """S3 (assets.glaurung.dev) is primary; GitHub Releases is secondary.
    R2 and Hugging Face are gone -- exactly two URLs, in that order."""
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
    manifest = Manifest.read(out / "manifest.json")
    for blob in manifest.blobs:
        assert list(blob.urls) == [
            f"https://assets.glaurung.dev/sigs/blob/{blob.sha256}.gsig.zst",
            f"https://github.com/glaurung-re/glaurung-sigs/releases/download/2026.09.1/{blob.sha256}",
        ]


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
    assert "minisign -Vm manifest.json" in result.stdout

    # S3 (primary) is printed as commands too, not executed.
    assert "assets.glaurung.dev" in result.stdout
    # `--profile` sits between `aws` and the subcommand, so check the pieces
    # rather than a contiguous "aws s3 cp"-shaped string.
    assert "aws" in result.stdout and "--profile personal-sso" in result.stdout
    assert "s3api head-object" in result.stdout
    assert "s3 cp" in result.stdout
    assert "--cache-control" in result.stdout
    assert "immutable" in result.stdout

    # R2 and Hugging Face are gone entirely.
    assert "rclone" not in result.stdout
    assert "huggingface-cli" not in result.stdout


def test_the_tool_imports_no_http_client():
    """Structural: no HTTP/socket transport, ever -- only the `aws` CLI, and
    only behind `--upload` (see the behavioural test below)."""
    source = PUBLISH.read_text()
    for forbidden in ("urllib", "requests", "httpx", "socket", "http.client"):
        assert f"import {forbidden}" not in source, forbidden


def test_the_tool_never_runs_gh():
    """`gh` is never invoked, only ever printed -- unconditionally, `--upload`
    included. Structural: `gh` never appears as a subprocess argument."""
    source = PUBLISH.read_text()
    assert '"gh"' not in source
    assert "'gh'" not in source


def test_dry_run_never_shells_out(simple, monkeypatch):
    """The load-bearing behavioural claim: without `--upload`, nothing is
    executed at all, even though the module imports `subprocess` for the
    `--upload` path. A structural text search cannot tell dry-run-by-default
    apart from dry-run-by-accident; making the call raise can."""
    corpus, out, key = simple
    module = _load_publish_module()

    def _boom(*args, **kwargs):
        raise AssertionError("a dry run must never invoke a subprocess")

    monkeypatch.setattr(module.subprocess, "run", _boom)
    code = module.main(
        [
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
    )
    assert code == 0


def test_upload_checks_head_object_before_ever_uploading_a_blob(simple, monkeypatch):
    """`--upload`: blobs first, then the signature, then the manifest last;
    every blob is checked with `head-object` first and is never overwritten
    if the check says it already exists."""
    corpus, out, key = simple
    module = _load_publish_module()
    calls: list[list[str]] = []

    def _fake_run(args, **kwargs):
        calls.append(list(args))
        if "head-object" in args:
            # Simulate: nothing exists yet at this key.
            return subprocess.CompletedProcess(
                args, returncode=1, stdout="", stderr="Not Found"
            )
        return subprocess.CompletedProcess(args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", _fake_run)
    code = module.main(
        [
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
            "--upload",
            "--s3-bucket",
            "test-bucket",
            "--aws-profile",
            "test-profile",
        ]
    )
    assert code == 0

    manifest = Manifest.read(out / "manifest.json")
    n = len(manifest.blobs)
    assert n >= 1

    # Blobs first: a head-object/cp pair per blob, in the same order the
    # manifest lists them.
    for i, blob in enumerate(manifest.blobs):
        head_call, cp_call = calls[2 * i], calls[2 * i + 1]
        key_arg = f"sigs/blob/{blob.sha256}.gsig.zst"
        assert "head-object" in head_call and key_arg in head_call
        assert "s3" in cp_call and "cp" in cp_call
        assert f"s3://test-bucket/{key_arg}" in cp_call
        assert "--cache-control" in cp_call
        assert "public, max-age=31536000, immutable" in cp_call
        assert "--content-type" in cp_call
        assert "application/octet-stream" in cp_call
        assert "test-profile" in cp_call

    # Then the signature, then the manifest -- in that order, last.
    sig_call, manifest_call = calls[2 * n], calls[2 * n + 1]
    sig_joined, manifest_joined = " ".join(sig_call), " ".join(manifest_call)
    assert "sigs/v1/manifest.json.minisig" in sig_joined
    assert (
        "sigs/v1/manifest.json" in manifest_joined and "minisig" not in manifest_joined
    )
    for call in (sig_call, manifest_call):
        assert "public, max-age=300" in call
        assert "--metadata-directive" in call and "REPLACE" in call
    assert len(calls) == 2 * n + 2


def test_upload_never_overwrites_an_existing_blob(simple, monkeypatch):
    corpus, out, key = simple
    module = _load_publish_module()
    calls: list[list[str]] = []

    def _fake_run(args, **kwargs):
        calls.append(list(args))
        if "head-object" in args:
            # Every blob already exists.
            return subprocess.CompletedProcess(args, returncode=0, stdout="", stderr="")
        return subprocess.CompletedProcess(args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", _fake_run)
    code = module.main(
        [
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
            "--upload",
            "--s3-bucket",
            "test-bucket",
            "--aws-profile",
            "test-profile",
        ]
    )
    assert code == 0
    manifest = Manifest.read(out / "manifest.json")
    n = len(manifest.blobs)
    # One head-object per blob, no blob `cp`, then the signature and
    # manifest `cp` (those two are always uploaded).
    blob_cp_calls = [
        c for c in calls if "s3" in c and "cp" in c and "blobs" in " ".join(c)
    ]
    assert not blob_cp_calls
    assert len(calls) == n + 2


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
    assert all(
        b.urls[0].startswith("https://assets.glaurung.dev/") for b in manifest.blobs
    )
    assert all("/releases/download/2026.09.1/" in b.urls[1] for b in manifest.blobs)


# --- --signature: the production (external-signing) flow --------------------


def test_signature_first_run_refuses_and_prints_the_command_to_sign(simple):
    """Step 1 of the real flow: build, then refuse until it is signed."""
    corpus, out, key = simple
    signature = out / "manifest.json.minisig"
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
        "--quiet",
        "--signature",
        str(signature),
    )
    assert result.returncode != 0
    assert (out / "manifest.json").is_file(), "the manifest is still built"
    assert not signature.is_file()
    assert f"minisign -Sm {out / 'manifest.json'} -s {key}" in result.stderr
    assert '-t "2026.09.1 serial=1"' in result.stderr


def test_signature_second_run_verifies_and_reuses_the_signed_manifest(
    simple, monkeypatch
):
    """Step 2: sign externally (simulated), re-run, and it proceeds."""
    corpus, out, key = simple
    args = [
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
        "--quiet",
    ]
    signature = out / "manifest.json.minisig"

    # Step 1: build only; refuses because nothing is signed yet.
    assert _run(*args, "--signature", str(signature)).returncode != 0
    manifest_bytes_after_build = (out / "manifest.json").read_bytes()

    # Simulate the maintainer running the printed command by hand, with a
    # (password-less, for the test) key standing in for their real one.
    signer_secret, signer_public = minisign.generate_keypair()
    minisign.sign_file(
        signer_secret,
        out / "manifest.json",
        trusted_comment="2026.09.1 serial=1",
    )
    assert (out / "manifest.json").read_bytes() == manifest_bytes_after_build, (
        "signing must not have touched the manifest bytes"
    )

    trusted_dir = out.parent / "trusted"
    trusted_dir.mkdir()
    (trusted_dir / "signer.pub").write_text(signer_public.to_text())
    monkeypatch.setenv(paths.ENV_KEYS_DIR, str(trusted_dir))

    # Step 2: re-run the identical command, now with a real signature.
    result = _run(*args, "--signature", str(signature))
    assert result.returncode == 0, result.stderr[-2000:]
    assert "externally signed" in result.stdout
    assert (out / "manifest.json").read_bytes() == manifest_bytes_after_build, (
        "the already-signed manifest.json must be reused byte for byte"
    )
    manifest = Manifest.read(out / "manifest.json")
    assert manifest.serial == 1


def test_signature_refuses_if_it_does_not_verify(simple, monkeypatch):
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
        "--quiet",
    ]
    signature = out / "manifest.json.minisig"
    assert _run(*args, "--signature", str(signature)).returncode != 0

    # Signed by a key nobody trusts.
    untrusted_secret, _ = minisign.generate_keypair()
    minisign.sign_file(
        untrusted_secret, out / "manifest.json", trusted_comment="1 serial=1"
    )
    trusted_dir = out.parent / "trusted"
    trusted_dir.mkdir()
    _, some_other_public = minisign.generate_keypair()
    (trusted_dir / "someone-else.pub").write_text(some_other_public.to_text())
    monkeypatch.setenv(paths.ENV_KEYS_DIR, str(trusted_dir))

    result = _run(*args, "--signature", str(signature))
    assert result.returncode != 0
    assert "does not verify" in result.stderr


def test_signature_refuses_if_the_trusted_comment_names_the_wrong_release(
    simple, monkeypatch
):
    """A validly-signed comment for a different set_version/serial is a lie."""
    corpus, out, key = simple
    args = [
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
        "--quiet",
    ]
    signature = out / "manifest.json.minisig"
    assert _run(*args, "--signature", str(signature)).returncode != 0

    signer_secret, signer_public = minisign.generate_keypair()
    # Wrong serial in the trusted comment.
    minisign.sign_file(
        signer_secret,
        out / "manifest.json",
        trusted_comment="2026.09.1 serial=999",
    )
    trusted_dir = out.parent / "trusted"
    trusted_dir.mkdir()
    (trusted_dir / "signer.pub").write_text(signer_public.to_text())
    monkeypatch.setenv(paths.ENV_KEYS_DIR, str(trusted_dir))

    result = _run(*args, "--signature", str(signature))
    assert result.returncode != 0
    assert "trusted comment" in result.stderr


def test_signature_refuses_if_blobs_changed_since_it_was_signed(simple, monkeypatch):
    """The signature covers specific bytes; a rebuild with different blobs
    must never be waved through under an old signature's authority."""
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
        "--quiet",
    ]
    signature = out / "manifest.json.minisig"
    assert _run(*args, "--signature", str(signature)).returncode != 0

    signer_secret, signer_public = minisign.generate_keypair()
    minisign.sign_file(
        signer_secret, out / "manifest.json", trusted_comment="1 serial=1"
    )
    trusted_dir = out.parent / "trusted"
    trusted_dir.mkdir()
    (trusted_dir / "signer.pub").write_text(signer_public.to_text())
    monkeypatch.setenv(paths.ENV_KEYS_DIR, str(trusted_dir))

    # The corpus changes (a new library appears) before the second run.
    (corpus / "extra.flirt.json").write_text(json.dumps({"entries": ["e"] * 20}))
    index = json.loads((corpus / "index.json").read_text())
    index["libraries"].append(
        _record("extra.flirt.json", library="extra", signatures=20)
    )
    (corpus / "index.json").write_text(json.dumps(index))

    result = _run(*args, "--signature", str(signature))
    assert result.returncode != 0
    assert "does not match" in result.stderr
