#!/usr/bin/env python3
"""Build a signed, content-addressed signature-set release.

Input is a directory of signature blobs plus the harvester's `index.json`,
which carries the per-library provenance (package, version, arch, variant,
archive sha256) this tool copies into the manifest. Output is a directory:

    <out>/blobs/<sha256>            one file per blob, named by its digest
    <out>/manifest.json             the signed document
    <out>/manifest.json.minisig     its detached minisign signature
    <out>/SHA256SUMS                so a mirror can be checked without us
    <out>/NOTICE                    the licence position, per blob

Two publish paths follow, and they are deliberately not symmetric:

* **GitHub Releases** (secondary) is always print-only. This tool prints the
  exact `gh release create` / `upload` / `edit` commands and never runs them:
  this repository's contribution rules put an upstream publish action on a
  human, and a tool that *could* run it is one keystroke from running it.
* **S3** (`assets.glaurung.dev`, primary) is dry-run *by default*; `--upload`
  makes it real. Unlike GitHub Releases this is the maintainer's own bucket
  in their own AWS account (CLI profile `personal-sso`), not an upstream
  project, so `--upload` shells out to the `aws` CLI directly. Blobs are
  uploaded first, then the detached signature, then the manifest last, so a
  client can never observe a manifest whose blobs are not there yet. Every
  blob key is checked with `aws s3api head-object` first and is never
  overwritten if found: the store is content-addressed and immutable, so an
  existing key already holds the right bytes.

Example (the dry run recorded in docs/reference/signature-distribution.md)::

    uv run python tools/publish_signature_set.py \\
        --blobs ~/.cache/glaurung/system-libs/sigs \\
        --set base --set-version 2026.09.1 --serial 1 \\
        --secret-key ~/.cache/glaurung/keys/glaurung-sigs-dev.key \\
        --out ~/.cache/glaurung/release/2026.09.1

`--generate-key` writes a fresh keypair if one does not exist. The secret key
is written `0600` outside the repository and must never be committed; only the
`.pub` belongs in `data/sigs/trusted-keys/`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "python"))

from glaurung.sigs import minisign  # noqa: E402
from glaurung.sigs.manifest import (  # noqa: E402
    SCHEMA_VERSION,
    BlobEntry,
    Manifest,
    Provenance,
    validate_against_schema,
)
from glaurung.sigs.paths import keys_dir  # noqa: E402

#: The GitHub repository the (secondary) release goes to. Only used to
#: *print* commands -- this tool never runs `gh` itself.
DEFAULT_REPO = "glaurung-re/glaurung-sigs"

#: The primary distribution bucket: private, versioned, us-east-1, sitting
#: behind a CloudFront distribution with origin access control in the
#: maintainer's personal AWS account. Its name doubles as the public
#: hostname (`https://assets.glaurung.dev/...`), which is why
#: `--blob-base-url` defaults to `https://<--s3-bucket>` rather than to a
#: hardcoded string.
DEFAULT_S3_BUCKET = "assets.glaurung.dev"

#: The `aws` CLI profile that can write to that bucket.
DEFAULT_AWS_PROFILE = "personal-sso"

#: Object layout under the bucket (docs/reference/signature-distribution.md):
#: blobs are immutable and long-TTL, the manifest and its signature are
#: rewritten every release and served with a short TTL.
S3_BLOB_PREFIX = "sigs/blob"
S3_MANIFEST_KEY = "sigs/v1/manifest.json"
S3_SIGNATURE_KEY = "sigs/v1/manifest.json.minisig"

S3_BLOB_CACHE_CONTROL = "public, max-age=31536000, immutable"
S3_MANIFEST_CACHE_CONTROL = "public, max-age=300"

#: The container format the current harvester emits. `gsig/1` replaces this
#: once the chunked container lands; the field exists so a client can tell.
DEFAULT_FORMAT = "flirt-json/2"

#: The identity scheme those records are under. Tracks
#: `glaurung.llm.kb.siglib.FLIRT_MASKED_PATTERN_V1`.
DEFAULT_KIND = "flirt-masked-pattern-v1"

#: The licence line every derived-signature blob carries. The reasoning is in
#: docs/reference/signature-distribution.md; the short form is Hex-Rays' own
#: statement that a signature file "contains no byte from the original
#: libraries, except for the names of the functions".
DEFAULT_LICENCE = (
    "signatures and names only, derived; inputs under their own licence "
    "(see provenance) -- no library bytes are redistributed"
)

NOTICE_TEMPLATE = """\
NOTICE -- Glaurung signature set {set_name} {set_version} (serial {serial})

WHAT THIS RELEASE CONTAINS

  Function *signatures*: masked byte patterns, CRC16 values over a bounded
  window, function names, and references by name and offset. It contains no
  object code, no archives, and no library bytes. The format deliberately
  splits pattern from mask so that a signature set is not a copy of the
  library it describes; Hex-Rays states the same property of FLIRT, that a
  signature file "contains no byte from the original libraries, except for
  the names of the functions".

WHAT IT DOES NOT CONTAIN

  No `.a`, `.o`, `.lib`, `.deb`, `.rpm` or `.apk` is redistributed here. Each
  blob's `provenance` in manifest.json names the package, version,
  architecture and input digest it was derived from, which is sufficient to
  re-fetch the input from its original distributor and re-derive the blob
  independently.

LICENCE POSITION

  The inputs are under their own licences -- LGPL-2.1-or-later for glibc,
  GPL-3.0 with the GCC Runtime Library Exception for libstdc++ and libgcc,
  and so on, recorded per blob. Redistributing those *archives* would carry
  corresponding-source obligations; redistributing derived signatures and
  names does not, on the reasoning above. Nothing here is a grant of rights
  in the inputs.

  Signature sets derived from inputs whose licence forbids redistribution of
  the inputs, or whose licence cannot be determined, are not published. Sets
  derived on a licensed build device (MSVC) are marked as such in their
  provenance.

TAKEDOWN

  If you hold rights in an input and object to the derived signatures being
  distributed, say so and the affected blobs are withdrawn: a new manifest is
  published with a higher serial and without them. Because clients refuse a
  serial below the one they hold, a withdrawal cannot be rolled back by
  replaying an older signed manifest.

PER-BLOB PROVENANCE

  {blob_count} blob(s), {signature_count} signature(s), {byte_count} bytes.
  Full provenance for every blob is in manifest.json; a summary follows.

{provenance_table}
"""


# --- inputs ------------------------------------------------------------------


@dataclass(frozen=True)
class SourceBlob:
    """One candidate file plus whatever the harvester recorded about it."""

    path: Path
    key: str
    signatures: int
    record: dict[str, Any]


def _load_index(blobs_dir: Path) -> dict[str, dict[str, Any]]:
    """The harvester's `index.json`, keyed by output filename.

    Absent is not fatal: a directory of blobs with no index still publishes,
    with `source: "unknown"` provenance, which is honest rather than invented.
    """
    index_path = blobs_dir / "index.json"
    if not index_path.is_file():
        return {}
    payload = json.loads(index_path.read_text(encoding="utf-8"))
    records = payload.get("libraries") or []
    return {
        str(record.get("output") or ""): record
        for record in records
        if isinstance(record, dict) and record.get("output")
    }


def _library_name(record: dict[str, Any], fallback: str) -> str:
    """The library's own name, out of a harvest key with ambiguous dots.

    The harvester's key is `<image>.<triplet>.<library>`, and **both** outer
    parts can contain dots: `alpine-v3.20-aarch64` as an image, `libm-2.36` as
    a library (glibc's `libm.a` is an ld script pointing at the versioned
    archive). So `rsplit(".", 1)` is wrong in both directions, and it was: it
    turned `linux-amd64.x86_64-linux-gnu.libm-2.35` into the library name
    `35`, which then published a blob keyed `35/2.35-.../x86_64`.

    The triplet is a recorded field, so splitting on it is exact. The archive
    basename is the fallback, which handles a record with no triplet and works
    whether `archive` is a bare name or the absolute path older harvests wrote.
    """
    harvest_key = str(record.get("key") or "")
    triplet = str(record.get("triplet") or "")
    if triplet and f".{triplet}." in harvest_key:
        return harvest_key.split(f".{triplet}.", 1)[1]
    archive = str(record.get("archive") or "")
    if archive:
        stem = Path(archive).name
        if stem.endswith(".a"):
            return stem[:-2]
        if stem:
            return stem
    if harvest_key:
        return harvest_key.rsplit(".", 1)[-1]
    return fallback


def _library_key(record: dict[str, Any], fallback: str) -> str:
    """`<library>/<version>/<variant>/<arch>` -- the unit of usefulness.

    Built from the harvester's own fields rather than from the filename, so
    two harvesters that name files differently still produce the same key for
    the same build point.
    """
    library = _library_name(record, fallback)
    version = str(record.get("library_version") or "unknown")
    variant = str(record.get("variant") or "unknown")
    arch = str(record.get("arch") or "unknown")
    return f"{library}/{version}/{variant}/{arch}"


def collect(
    blobs_dir: Path,
    *,
    pattern: str,
    min_signatures: int,
    limit: int | None,
    prefer_images: Sequence[str] = (),
) -> tuple[list[SourceBlob], list[str]]:
    """Candidate blobs, plus the reason each rejection was rejected.

    Empty libraries are the common case and they are dropped here, not
    silently published: five glibc archives have been 8-byte stubs since 2.34
    and MinGW import libraries are pure thunks, so a harvest legitimately
    produces many zero-signature outputs. Publishing them would inflate the
    set with blobs that can never match anything.
    """
    index = _load_index(blobs_dir)
    chosen: list[SourceBlob] = []
    rejected: list[str] = []
    for path in sorted(blobs_dir.glob(pattern)):
        if path.name == "index.json" or not path.is_file():
            continue
        record = index.get(path.name, {})
        signatures = int(record.get("unique_signatures") or 0)
        if not record:
            # No index entry: keep it, but it cannot be filtered on a count
            # it does not have.
            signatures = -1
        elif signatures < min_signatures:
            rejected.append(f"{path.name}: {signatures} signatures")
            continue
        chosen.append(
            SourceBlob(
                path=path,
                key=_library_key(record, path.name.split(".")[0]),
                signatures=max(signatures, 0),
                record=record,
            )
        )
    if prefer_images:
        chosen, dropped = _resolve_by_image(chosen, prefer_images)
        rejected.extend(dropped)
    if limit is not None:
        chosen = chosen[:limit]
    return chosen, rejected


def _resolve_by_image(
    sources: Sequence[SourceBlob], prefer: Sequence[str]
) -> tuple[list[SourceBlob], list[str]]:
    """Keep one source per key, choosing by builder image in `prefer` order.

    Measured on the 2026-09-03 Docker harvest: 134 of 245 keys are contested,
    and the contesting blobs differ **only** in an absolute build path the
    harvester embeds in the blob's own provenance
    (`/home/.../system-libs/linux-amd64/...` versus `.../linux-arm64/...`).
    The builder image is not part of a signature's identity -- the same
    cross-compiled `arm-linux-gnueabihf` glibc is the same library whichever
    host built it -- so the bytes should be identical and are not.

    That is a harvester defect, not a distribution one, and this function is
    the operator's escape rather than its fix: without `--prefer-image` the
    collision is a hard failure, which is what keeps the defect visible. Once
    the absolute path is out of the emitted blob the two hash the same and the
    content-addressed store deduplicates them for free.
    """
    order = {name: rank for rank, name in enumerate(prefer)}
    best: dict[str, SourceBlob] = {}
    dropped: list[str] = []
    for source in sources:
        current = best.get(source.key)
        if current is None:
            best[source.key] = source
            continue
        current_rank = order.get(str(current.record.get("image") or ""), len(order))
        rank = order.get(str(source.record.get("image") or ""), len(order))
        loser, winner = (source, current) if current_rank <= rank else (current, source)
        best[source.key] = winner
        dropped.append(
            f"{loser.path.name}: key {loser.key!r} also built by image "
            f"{winner.record.get('image')!r}, which --prefer-image ranks higher"
        )
    return sorted(best.values(), key=lambda s: s.path.name), dropped


# --- manifest construction ---------------------------------------------------


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _provenance(record: dict[str, Any]) -> Provenance:
    if not record:
        return Provenance(source="unknown")
    return Provenance(
        source=str(record.get("source") or "docker-harvest"),
        package=str(record.get("library_name") or ""),
        version=str(record.get("library_version") or ""),
        arch=str(record.get("arch") or ""),
        archive=str(record.get("archive") or ""),
        input_sha256=str(record.get("archive_sha256") or ""),
        variant=str(record.get("variant") or ""),
        triplet=str(record.get("triplet") or ""),
        image=str(record.get("image") or ""),
    )


def _blob_key(digest: str) -> str:
    """The S3 object key a blob is uploaded to and served from."""
    return f"{S3_BLOB_PREFIX}/{digest}.gsig.zst"


def _urls(digest: str, *, repo: str, tag: str, blob_base_url: str) -> list[str]:
    """Mirrors in preference order. An empty option drops that family.

    `assets.glaurung.dev` (S3 behind CloudFront) is primary and listed
    first; GitHub Releases is the secondary family. Hugging Face and
    Cloudflare R2 were dropped on 2026-09-03 -- the maintainer has AWS only.

    Empty is meaningful, not a mistake: a release built for a test to serve
    from disk has no GitHub asset and must not claim one -- a URL that
    cannot answer costs every client a failed request before it reaches the
    mirror that can.
    """
    urls = []
    if blob_base_url:
        urls.append(f"{blob_base_url}/{_blob_key(digest)}")
    if repo:
        urls.append(f"https://github.com/{repo}/releases/download/{tag}/{digest}")
    return urls


def build_manifest(
    sources: Sequence[SourceBlob],
    out_blobs: Path,
    *,
    set_name: str,
    set_version: str,
    serial: int,
    valid_days: int,
    min_version: str,
    repo: str,
    blob_base_url: str,
    licence: str,
    blob_format: str,
    kind: str,
    release_tag: str | None = None,
) -> tuple[Manifest, dict[str, Path]]:
    """Copy each source to `<out_blobs>/<sha256>` and describe it.

    Two sources that hash the same become one blob. That deduplication is
    worth 26 to 43 percent between adjacent releases of one distro line, and
    it is free precisely because the store is content-addressed.
    """
    out_blobs.mkdir(parents=True, exist_ok=True)
    entries: dict[str, BlobEntry] = {}
    written: dict[str, Path] = {}
    now = datetime.now(timezone.utc)
    for source in sources:
        digest = _sha256(source.path)
        size = source.path.stat().st_size
        target = out_blobs / digest
        if not target.is_file():
            tmp = target.with_name(target.name + ".part")
            shutil.copyfile(source.path, tmp)
            os.replace(tmp, target)
        written[digest] = target
        entry = BlobEntry(
            key=source.key,
            kind=kind,
            format=blob_format,
            compression="none",
            sha256=digest,
            size_bytes=size,
            uncompressed_bytes=size,
            signatures=source.signatures,
            licence=licence,
            provenance=_provenance(source.record),
            urls=tuple(
                _urls(
                    digest,
                    repo=repo,
                    tag=release_tag or set_version,
                    blob_base_url=blob_base_url,
                )
            ),
        )
        # Two harvest outputs can legitimately share a key (the same build
        # point harvested from two images). Identical bytes are the same blob;
        # differing bytes are a real collision the operator must resolve.
        existing = entries.get(source.key)
        if existing is not None:
            if existing.sha256 != digest:
                raise SystemExit(
                    f"key collision: {source.key!r} maps to both "
                    f"{existing.sha256} and {digest}. Two different builds "
                    "share a key; the harvester's variant field is not "
                    "distinguishing them."
                )
            continue
        entries[source.key] = entry

    # Remove anything in the blob directory the manifest does not name.
    #
    # This is not tidiness. The publish recipe is `gh release upload <tag>
    # blobs/*`, so an unlisted file becomes a release asset nothing points at
    # and nothing verifies. Orphans arise easily: an earlier run that aborted
    # on a key collision after copying some blobs, or a re-run with different
    # `--min-signatures` or `--prefer-image`. Measured on the 2026-09-03 dry
    # run, exactly this produced 172 files for a 171-blob manifest.
    named = set(written)
    for stale in out_blobs.iterdir():
        if stale.is_file() and len(stale.name) == 64 and stale.name not in named:
            stale.unlink()

    manifest = Manifest(
        schema_version=SCHEMA_VERSION,
        set_name=set_name,
        set_version=set_version,
        serial=serial,
        built_utc=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        valid_until=(now + timedelta(days=valid_days)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        min_glaurung_version=min_version,
        blobs=tuple(sorted(entries.values(), key=lambda b: b.key)),
    )
    return manifest, written


# --- outputs -----------------------------------------------------------------


def write_sha256sums(out: Path, manifest: Manifest) -> Path:
    """A plain `sha256sum -c`-checkable file over the blobs and the manifest."""
    lines = [f"{blob.sha256}  blobs/{blob.sha256}" for blob in manifest.blobs]
    manifest_digest = hashlib.sha256(manifest.to_json().encode("utf-8")).hexdigest()
    lines.append(f"{manifest_digest}  manifest.json")
    path = out / "SHA256SUMS"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_notice(out: Path, manifest: Manifest) -> Path:
    rows = ["  {:<52} {:>7}  {}".format("KEY", "SIGS", "PROVENANCE")]
    for blob in manifest.blobs:
        prov = blob.provenance
        origin = " ".join(
            part
            for part in (prov.source, prov.package, prov.version, prov.arch)
            if part
        )
        rows.append(f"  {blob.key:<52} {blob.signatures:>7}  {origin}")
    path = out / "NOTICE"
    path.write_text(
        NOTICE_TEMPLATE.format(
            set_name=manifest.set_name,
            set_version=manifest.set_version,
            serial=manifest.serial,
            blob_count=len(manifest.blobs),
            signature_count=manifest.total_signatures,
            byte_count=manifest.total_bytes,
            provenance_table="\n".join(rows),
        ),
        encoding="utf-8",
    )
    return path


def publish_commands(out: Path, manifest: Manifest, *, repo: str) -> list[str]:
    """The exact GitHub Releases (secondary) commands. Printed, never executed.

    This tool never runs `gh` itself, regardless of `--upload` -- `--upload`
    only drives the S3 (primary) upload, below. See `s3_dry_run_lines` /
    `execute_s3_upload`.
    """
    tag = manifest.set_version
    return [
        "# GitHub Releases (secondary). Immutable releases require",
        "# create-draft, upload, then publish: an asset uploaded after",
        "# publication returns 422.",
        f"gh release create {tag} --repo {repo} --draft \\",
        f"    --title 'glaurung signature set {manifest.set_name} {tag}' \\",
        f"    --notes-file {out / 'NOTICE'}",
        f"gh release upload {tag} --repo {repo} \\",
        f"    {out / 'manifest.json'} {out / 'manifest.json.minisig'} \\",
        f"    {out / 'SHA256SUMS'} {out / 'NOTICE'}",
        f"gh release upload {tag} --repo {repo} {out / 'blobs'}/*",
        f"gh release edit {tag} --repo {repo} --draft=false",
        "",
        "# Verify from outside, with stock minisign and sha256sum:",
        "minisign -Vm manifest.json -p data/sigs/trusted-keys/*.pub",
        "sha256sum -c SHA256SUMS",
    ]


# --- S3 (assets.glaurung.dev), primary ---------------------------------------


def _aws_base_args(profile: str) -> list[str]:
    return ["aws", "--profile", profile] if profile else ["aws"]


def _head_object_args(bucket: str, key: str, profile: str) -> list[str]:
    return _aws_base_args(profile) + [
        "s3api",
        "head-object",
        "--bucket",
        bucket,
        "--key",
        key,
    ]


def _blob_cp_args(local: Path, bucket: str, key: str, profile: str) -> list[str]:
    return _aws_base_args(profile) + [
        "s3",
        "cp",
        str(local),
        f"s3://{bucket}/{key}",
        "--cache-control",
        S3_BLOB_CACHE_CONTROL,
        "--content-type",
        "application/octet-stream",
    ]


def _manifest_cp_args(local: Path, bucket: str, key: str, profile: str) -> list[str]:
    # `--metadata-directive REPLACE` only matters for an S3-to-S3 copy (it
    # picks the new call's headers over the source object's); a local-file
    # upload always sets fresh metadata with a plain PutObject. It is passed
    # anyway so the command stays correct if this ever becomes a copy (e.g.
    # promoting a staged object), and so the intent -- these headers always
    # win -- is documented at the call site rather than only in prose.
    return _aws_base_args(profile) + [
        "s3",
        "cp",
        str(local),
        f"s3://{bucket}/{key}",
        "--cache-control",
        S3_MANIFEST_CACHE_CONTROL,
        "--metadata-directive",
        "REPLACE",
    ]


def _format_args(args: Sequence[str]) -> str:
    return " ".join(args)


def s3_dry_run_lines(
    out: Path, manifest: Manifest, *, bucket: str, profile: str
) -> list[str]:
    """The exact `aws` commands `--upload` would run. Printed only, here.

    Order matters: blobs first, then the signature, then the manifest last,
    so a client can never fetch a manifest naming a blob that is not there
    yet. Every blob key is checked with `head-object` first and is skipped
    if it already exists -- the store is content-addressed and immutable, so
    an existing key already holds the right bytes and must never be
    overwritten. `--upload` performs that check for real; a dry run only
    names it.
    """
    lines = [
        "# S3 (assets.glaurung.dev), primary. Requires --upload; this is a dry run.",
        "# Blobs first, then the signature, then the manifest -- a client must",
        "# never see a manifest whose blobs are missing. Each blob key is",
        "# checked with head-object first and is never overwritten if found.",
    ]
    for blob in manifest.blobs:
        key = _blob_key(blob.sha256)
        local = out / "blobs" / blob.sha256
        lines.append(
            _format_args(_head_object_args(bucket, key, profile))
            + "  # skip the upload below if this succeeds (never overwrite)"
        )
        lines.append(_format_args(_blob_cp_args(local, bucket, key, profile)))
    lines.append(
        _format_args(
            _manifest_cp_args(
                out / "manifest.json.minisig", bucket, S3_SIGNATURE_KEY, profile
            )
        )
    )
    lines.append(
        _format_args(
            _manifest_cp_args(out / "manifest.json", bucket, S3_MANIFEST_KEY, profile)
        )
    )
    return lines


def execute_s3_upload(
    out: Path, manifest: Manifest, *, bucket: str, profile: str
) -> None:
    """Actually run the `aws` CLI. Never overwrites an existing blob key.

    Blobs first, then the signature, then the manifest last -- the same
    order `s3_dry_run_lines` prints, so a client can never observe a
    manifest whose blobs are missing.
    """
    for blob in manifest.blobs:
        key = _blob_key(blob.sha256)
        check = subprocess.run(
            _head_object_args(bucket, key, profile), capture_output=True, text=True
        )
        if check.returncode == 0:
            print(f"  exists, not overwritten: s3://{bucket}/{key}")
            continue
        local = out / "blobs" / blob.sha256
        result = subprocess.run(
            _blob_cp_args(local, bucket, key, profile), capture_output=True, text=True
        )
        if result.returncode != 0:
            raise SystemExit(f"upload failed for {key}:\n{result.stderr}")
        print(f"  uploaded: s3://{bucket}/{key}")

    for local_name, key in (
        ("manifest.json.minisig", S3_SIGNATURE_KEY),
        ("manifest.json", S3_MANIFEST_KEY),
    ):
        result = subprocess.run(
            _manifest_cp_args(out / local_name, bucket, key, profile),
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise SystemExit(f"upload failed for {key}:\n{result.stderr}")
        print(f"  uploaded: s3://{bucket}/{key}")


# --- CLI ---------------------------------------------------------------------


def sign_command(manifest_path: Path, secret_key: Path, manifest: Manifest) -> str:
    """The exact interactive `minisign` command that produces a valid signature.

    This is the **normal** production flow: the maintainer's real key is
    password-protected, and `glaurung.sigs.minisign.SecretKey` only reads
    minisign's password-less form -- correctly, since decrypting a
    scrypt-protected key needs a passphrase this tool must never see or ask
    for. `--secret-key`/`--generate-key` (below) remain the local-testing
    flow only, for a throwaway password-less dev key.
    """
    return (
        f"minisign -Sm {manifest_path} -s {secret_key} "
        f'-t "{manifest.set_version} serial={manifest.serial}"'
    )


def _load_trusted_keys(directory: Path | None = None) -> list[minisign.PublicKey]:
    """Every `*.pub` under the trusted-key directory (default: the shipped one).

    Duplicated in miniature from `glaurung.sigs.client.load_trusted_keys`
    rather than imported from it: `client.py` is the module that speaks HTTP,
    and this tool's whole point is that it does not import anything that can.
    """
    source = directory or keys_dir()
    if not source.is_dir():
        return []
    keys: list[minisign.PublicKey] = []
    for path in sorted(source.glob("*.pub")):
        keys.append(minisign.PublicKey.read(path))
    return keys


def _manifest_bodies_agree(a: Manifest, b: Manifest) -> bool:
    """Same manifest, ignoring the two fields that legitimately vary by run.

    `built_utc`/`valid_until` are computed at build time, so a manifest
    rebuilt from the same `--blobs`/`--set`/`--serial` a second time is
    byte-different from the one a maintainer already signed externally, even
    though nothing about the release changed. Everything else must match
    exactly, or reusing the already-signed copy would silently publish
    different blobs under an old signature's authority.
    """
    fields = ("set_name", "set_version", "serial", "min_glaurung_version", "blobs")
    return all(getattr(a, f) == getattr(b, f) for f in fields)


def _resolve_key(path: Path, generate: bool) -> minisign.SecretKey:
    if path.is_file():
        return minisign.SecretKey.read(path)
    if not generate:
        raise SystemExit(
            f"no secret key at {path}. Generate one with --generate-key, or "
            "with `minisign -G -W -s <path>`."
        )
    secret, public = minisign.generate_keypair()
    secret.write(path)
    public_path = path.with_suffix(".pub")
    public_path.write_text(public.to_text(), encoding="utf-8")
    print(
        f"generated a new keypair\n"
        f"  secret (0600, never commit): {path}\n"
        f"  public  (commit this):       {public_path}\n"
        f"  key id:                      {public.key_id_hex}",
        file=sys.stderr,
    )
    return secret


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="publish_signature_set.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--blobs", type=Path, required=True, help="Directory of signature blobs"
    )
    parser.add_argument(
        "--pattern",
        default="*.flirt.json",
        help="Glob selecting blob files inside --blobs (default: %(default)s)",
    )
    parser.add_argument("--set", dest="set_name", default="base", help="Set name")
    parser.add_argument("--set-version", required=True, help="e.g. 2026.09.1")
    parser.add_argument(
        "--serial",
        type=int,
        required=True,
        help="Monotonic; must exceed the previously published serial",
    )
    parser.add_argument("--out", type=Path, required=True, help="Release directory")
    parser.add_argument(
        "--secret-key",
        type=Path,
        default=Path.home() / ".cache" / "glaurung" / "keys" / "glaurung-sigs-dev.key",
        help="minisign secret key (default: %(default)s)",
    )
    parser.add_argument(
        "--generate-key",
        action="store_true",
        help="Create the keypair if --secret-key does not exist. Local-"
        "testing flow only -- see --signature for the production flow.",
    )
    parser.add_argument(
        "--signature",
        type=Path,
        default=None,
        help=f"Path to a manifest.json.minisig produced externally (stock "
        f"minisign, a password-protected production key -- the normal "
        f"publish flow). Verified against {keys_dir()}/*.pub before "
        f"anything is printed or uploaded; refuses to proceed if it is "
        f"missing or does not verify. When --out already holds a "
        f"manifest.json built from the same --blobs/--set/--serial, that "
        f"exact copy is kept so the externally-produced signature stays "
        f"valid.",
    )
    parser.add_argument(
        "--release-tag",
        default=None,
        help="Git tag the blob URLs point at (default: --set-version). The "
        "bundled fallback set needs this: it is a strict subset cut from a "
        "release, carries its own set_version so `sigs status` can tell them "
        "apart, and must still point at the real release's assets so an "
        "online client can upgrade a bundled blob.",
    )
    parser.add_argument("--valid-days", type=int, default=180)
    parser.add_argument("--min-glaurung-version", default="0.1.0")
    parser.add_argument(
        "--repo", default=DEFAULT_REPO, help="GitHub Releases repo (secondary)"
    )
    parser.add_argument(
        "--s3-bucket",
        default=DEFAULT_S3_BUCKET,
        help="Primary S3 bucket (default: %(default)s)",
    )
    parser.add_argument(
        "--aws-profile",
        default=DEFAULT_AWS_PROFILE,
        help="aws CLI profile used for --upload (default: %(default)s)",
    )
    parser.add_argument(
        "--blob-base-url",
        default=None,
        help="Base URL blobs and the manifest are served from (default: "
        "https://<--s3-bucket>). Empty string drops the assets.glaurung.dev "
        "URL family entirely; only tests should need that.",
    )
    parser.add_argument(
        "--upload",
        action="store_true",
        help="Actually run the S3 upload via the aws CLI, instead of "
        "printing the commands. GitHub Releases always stays print-only.",
    )
    parser.add_argument("--licence", default=DEFAULT_LICENCE)
    parser.add_argument("--format", dest="blob_format", default=DEFAULT_FORMAT)
    parser.add_argument("--kind", default=DEFAULT_KIND)
    parser.add_argument(
        "--min-signatures",
        type=int,
        default=1,
        help="Drop blobs with fewer signatures (default: %(default)s). Empty "
        "archives are common and legitimate; publishing them is not.",
    )
    parser.add_argument(
        "--prefer-image",
        action="append",
        default=[],
        metavar="IMAGE",
        help="When two harvest outputs claim the same library key, keep the "
        "one from this builder image; repeatable, first wins. Without it a "
        "collision is a hard error, which is the correct default: two blobs "
        "under one key means the harvester is not distinguishing two builds.",
    )
    parser.add_argument(
        "--limit", type=int, default=None, help="Publish at most this many blobs"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Suppress the per-blob listing"
    )
    args = parser.parse_args(argv)

    blobs_dir: Path = args.blobs.expanduser()
    if not blobs_dir.is_dir():
        raise SystemExit(f"--blobs {blobs_dir} is not a directory")
    out: Path = args.out.expanduser()

    secret_key_path = args.secret_key.expanduser()
    blob_base_url = (
        args.blob_base_url
        if args.blob_base_url is not None
        else f"https://{args.s3_bucket}"
    )

    sources, rejected = collect(
        blobs_dir,
        pattern=args.pattern,
        min_signatures=args.min_signatures,
        limit=args.limit,
        prefer_images=args.prefer_image,
    )
    if not sources:
        raise SystemExit(f"no blobs matched {args.pattern!r} under {blobs_dir}")

    manifest, _written = build_manifest(
        sources,
        out / "blobs",
        set_name=args.set_name,
        set_version=args.set_version,
        serial=args.serial,
        valid_days=args.valid_days,
        min_version=args.min_glaurung_version,
        repo=args.repo,
        blob_base_url=blob_base_url,
        licence=args.licence,
        blob_format=args.blob_format,
        kind=args.kind,
        release_tag=args.release_tag,
    )

    schema_errors = validate_against_schema(manifest.to_dict())
    if schema_errors:
        raise SystemExit(
            "the manifest this tool built violates its own schema:\n  "
            + "\n  ".join(schema_errors)
        )

    # An externally-produced --signature was made against a manifest.json
    # some earlier invocation already wrote; keep that exact copy (including
    # its built_utc/valid_until) rather than overwriting it with a fresh
    # timestamp, which would silently invalidate the signature. Anything
    # other than the timestamps must match, or this is a different release
    # wearing an old one's signature.
    existing_path = out / "manifest.json"
    if args.signature is not None and existing_path.is_file():
        existing = Manifest.read(existing_path)
        if _manifest_bodies_agree(manifest, existing):
            manifest = existing
        else:
            raise SystemExit(
                f"{existing_path} does not match what --blobs/--set/--serial "
                "would build now (only built_utc/valid_until may legitimately "
                "differ). Rebuild without --signature, sign the fresh "
                "manifest.json, then re-run with --signature."
            )
    manifest_path = manifest.write(out / "manifest.json")
    sums_path = write_sha256sums(out, manifest)
    notice_path = write_notice(out, manifest)
    sign_cmd = sign_command(manifest_path, secret_key_path, manifest)

    if args.signature is not None:
        signature_source = Path(args.signature).expanduser()
        if not signature_source.is_file():
            raise SystemExit(
                f"--signature {signature_source} does not exist; run:\n  {sign_cmd}"
            )
        signature_path = out / "manifest.json.minisig"
        if signature_source != signature_path:
            signature_path.write_bytes(signature_source.read_bytes())
        trusted = _load_trusted_keys()
        if not trusted:
            raise SystemExit(f"no trusted public keys under {keys_dir()}")
        try:
            key = minisign.verify_file(manifest_path, signature_path, trusted)
        except minisign.MinisignError as exc:
            raise SystemExit(
                f"--signature does not verify against a trusted key under "
                f"{keys_dir()}: {exc}"
            )
        comment = minisign.Signature.read(signature_path).trusted_comment
        if (
            manifest.set_version not in comment
            or f"serial={manifest.serial}" not in comment
        ):
            raise SystemExit(
                "--signature's trusted comment does not name this set's "
                f"version ({manifest.set_version!r}) and serial "
                f"({manifest.serial}); refusing to publish: {comment!r}"
            )
        signed_by = (
            f"{signature_path}  (externally signed, key {key.key_id_hex}, verified)"
        )
    else:
        # Local-testing flow only: a throwaway password-less key this tool
        # can read and sign with itself.
        secret = _resolve_key(secret_key_path, args.generate_key)
        signature_path = minisign.sign_file(
            secret,
            manifest_path,
            trusted_comment=manifest.trusted_comment(),
            untrusted_comment=(
                f"glaurung signature set {manifest.set_name} {manifest.set_version}"
            ),
        )
        # Prove what was just written actually verifies, with the *public*
        # half only, before telling anyone to publish it.
        public = secret.public_key()
        minisign.verify_file(manifest_path, signature_path, [public])
        signed_by = (
            f"{signature_path}  (key {public.key_id_hex}, local dev/testing key)"
        )

    if not args.quiet:
        for blob in manifest.blobs:
            print(f"  {blob.sha256}  {blob.size_bytes:>10}  {blob.key}")
    if rejected:
        print(
            f"\nskipped {len(rejected)} source file(s): below "
            f"--min-signatures={args.min_signatures}, or superseded by "
            "--prefer-image",
            file=sys.stderr,
        )

    print(
        f"\nset {manifest.set_name} {manifest.set_version} serial "
        f"{manifest.serial}\n"
        f"  blobs      {len(manifest.blobs)}\n"
        f"  signatures {manifest.total_signatures}\n"
        f"  bytes      {manifest.total_bytes}\n"
        f"  manifest   {manifest_path}\n"
        f"  signature  {signed_by}\n"
        f"  checksums  {sums_path}\n"
        f"  notice     {notice_path}"
    )
    print(
        f"\nTo (re-)sign {manifest_path} by hand with a production key "
        f"(the normal flow -- see docs/reference/signature-distribution.md):"
        f"\n  {sign_cmd}\n"
        f"Then re-run this exact command with "
        f"--signature {out / 'manifest.json.minisig'} added."
    )
    if args.upload:
        print(
            "\n--- Uploading to S3 (assets.glaurung.dev) now. GitHub Releases "
            "still requires the manual commands below. ---\n"
        )
        execute_s3_upload(
            out, manifest, bucket=args.s3_bucket, profile=args.aws_profile
        )
        print()
    else:
        print("\n--- DRY RUN: nothing was published. Run these by hand: ---\n")
        for line in s3_dry_run_lines(
            out, manifest, bucket=args.s3_bucket, profile=args.aws_profile
        ):
            print(line)
        print()

    for line in publish_commands(out, manifest, repo=args.repo):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
