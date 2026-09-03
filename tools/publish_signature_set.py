#!/usr/bin/env python3
"""Build a signed, content-addressed signature-set release. Never publishes it.

Input is a directory of signature blobs plus the harvester's `index.json`,
which carries the per-library provenance (package, version, arch, variant,
archive sha256) this tool copies into the manifest. Output is a directory a
human can hand to `gh release create` unchanged:

    <out>/blobs/<sha256>            one file per blob, named by its digest
    <out>/manifest.json             the signed document
    <out>/manifest.json.minisig     its detached minisign signature
    <out>/SHA256SUMS                so a mirror can be checked without us
    <out>/NOTICE                    the licence position, per blob

The last step prints the exact `gh release create` and mirror-upload commands
and stops. It does not run them, and it has no network code at all: this
repository's contribution rules put the upstream publish on a human, and a
tool that *could* publish is one keystroke from publishing.

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

#: The GitHub repository the release goes to. Only used to *print* commands.
DEFAULT_REPO = "glaurung-re/glaurung-sigs"

#: Mirror roots, in the order the manifest lists them per blob. GitHub
#: Releases is primary (2 GiB per asset, no bandwidth cap); R2 is the
#: contractual `$0`-egress fallback that has to exist *before* GitHub's
#: acceptable-use throttling makes it necessary.
DEFAULT_R2_BASE = "https://sigs.glaurung.dev/blob"
DEFAULT_HF_REPO = "datasets/glaurung/sigs"

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


def _urls(digest: str, *, repo: str, tag: str, r2_base: str, hf_repo: str) -> list[str]:
    """Mirrors in preference order. An empty option drops that mirror.

    Empty is meaningful, not a mistake: a set published to a private mirror
    only, or a release built for a test to serve from disk, has no GitHub
    asset and must not claim one -- a URL that cannot answer costs every
    client a failed request before it reaches the mirror that can.
    """
    urls = []
    if repo:
        urls.append(f"https://github.com/{repo}/releases/download/{tag}/{digest}")
    if r2_base:
        urls.append(f"{r2_base}/{digest}")
    if hf_repo:
        urls.append(f"hf://{hf_repo}/blobs/{digest}")
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
    r2_base: str,
    hf_repo: str,
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
                    r2_base=r2_base,
                    hf_repo=hf_repo,
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


def publish_commands(
    out: Path, manifest: Manifest, *, repo: str, r2_bucket: str, hf_repo: str
) -> list[str]:
    """The exact commands a human runs next. Printed, never executed."""
    tag = manifest.set_version
    return [
        "# 1. GitHub Releases (primary). Immutable releases require",
        "#    create-draft, upload, then publish: an asset uploaded after",
        "#    publication returns 422.",
        f"gh release create {tag} --repo {repo} --draft \\",
        f"    --title 'glaurung signature set {manifest.set_name} {tag}' \\",
        f"    --notes-file {out / 'NOTICE'}",
        f"gh release upload {tag} --repo {repo} \\",
        f"    {out / 'manifest.json'} {out / 'manifest.json.minisig'} \\",
        f"    {out / 'SHA256SUMS'} {out / 'NOTICE'}",
        f"gh release upload {tag} --repo {repo} {out / 'blobs'}/*",
        f"gh release edit {tag} --repo {repo} --draft=false",
        "",
        "# 2. Cloudflare R2 mirror ($0 egress). Must exist BEFORE GitHub's",
        "#    acceptable-use throttling makes it necessary.",
        f"rclone copy {out / 'blobs'} r2:{r2_bucket}/blob --checksum --transfers 8",
        f"rclone copy {out / 'manifest.json'} r2:{r2_bucket}/v1/",
        f"rclone copy {out / 'manifest.json.minisig'} r2:{r2_bucket}/v1/",
        "",
        "# 3. Hugging Face mirror (optional second mirror; anonymous",
        "#    resolver limit is 3,000 requests per 5-minute window per IP,",
        "#    which is why it is a mirror and not the primary).",
        f"huggingface-cli upload {hf_repo} {out} . --repo-type dataset",
        "",
        "# 4. Verify from outside, with stock minisign and sha256sum:",
        f"minisign -Vm manifest.json -p data/sigs/trusted-keys/*.pub",
        "sha256sum -c SHA256SUMS",
    ]


# --- CLI ---------------------------------------------------------------------


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
        help="Create the keypair if --secret-key does not exist",
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
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--r2-base", default=DEFAULT_R2_BASE)
    parser.add_argument("--r2-bucket", default="glaurung-sigs")
    parser.add_argument("--hf-repo", default=DEFAULT_HF_REPO)
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

    secret = _resolve_key(args.secret_key.expanduser(), args.generate_key)

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
        r2_base=args.r2_base,
        hf_repo=args.hf_repo,
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

    manifest_path = manifest.write(out / "manifest.json")
    signature_path = minisign.sign_file(
        secret,
        manifest_path,
        trusted_comment=manifest.trusted_comment(),
        untrusted_comment=(
            f"glaurung signature set {manifest.set_name} {manifest.set_version}"
        ),
    )
    sums_path = write_sha256sums(out, manifest)
    notice_path = write_notice(out, manifest)

    # Prove what we just wrote actually verifies, with the *public* half only,
    # before telling anyone to publish it.
    public = secret.public_key()
    minisign.verify_file(manifest_path, signature_path, [public])

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
        f"  signature  {signature_path}  (key {public.key_id_hex})\n"
        f"  checksums  {sums_path}\n"
        f"  notice     {notice_path}"
    )
    print("\n--- DRY RUN: nothing was published. Run these by hand: ---\n")
    for line in publish_commands(
        out, manifest, repo=args.repo, r2_bucket=args.r2_bucket, hf_repo=args.hf_repo
    ):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
