#!/usr/bin/env python3
"""Build a signed, content-addressed signature-set release.

Input is any number of directories of signature blobs, each with its
harvester's `index.json` carrying the per-library provenance (package,
version, arch, variant, archive sha256) this tool copies into the manifest.
Four harvesters write three index shapes and the WARP builder writes a fourth,
so `_load_index` sniffs rather than assuming; `_library_name` explains the
three ways a library's own name is recovered from a harvest key.

Every blob is rewritten as a `gsig/1` container before it is hashed, so the
digest names the container and not the JSON (`--convert none` opts out). Two
identity schemes ship side by side -- `flirt-masked-pattern-v1` and
`warp-function-guid-v1` -- each converted through the writer for its own
scheme, each recorded in the manifest entry's `kind`.

Output is a directory:

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

Example (the 2026.09.2 dry run recorded in
docs/reference/signature-distribution.md)::

    uv run python tools/publish_signature_set.py \\
        --source "$HOME/.cache/glaurung/system-libs/sigs:**/*.flirt.json" \\
        --source "$HOME/.cache/glaurung/system-libs/armtc-13.2.1/sigs:*.flirt.json:cortex-m:cortex-m" \\
        --source "$HOME/.cache/glaurung/system-libs/warp:*.warp.json:windows-warp:warp" \\
        --carry-forward "$HOME/.cache/glaurung/release/2026.09.1/manifest.json" \\
        --set base --set-version 2026.09.2 --serial 2 \\
        --out "$HOME/.cache/glaurung/release/2026.09.2" \\
        --unsigned --quiet

`--unsigned` builds and measures without signing: no key is read, and the
exact `minisign -Sm` command is printed instead. `--generate-key` writes a
fresh throwaway keypair for local testing; the secret key is written `0600`
outside the repository and must never be committed, and only the `.pub`
belongs in `data/sigs/trusted-keys/`.
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
from typing import Any, Iterable, Mapping, Sequence

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

#: The container a blob ships in once it has been converted. `--convert none`
#: publishes the harvester's own bytes instead and records `RAW_FORMAT`.
DEFAULT_FORMAT = "gsig/1"

#: What the harvesters write, and what serial 1 published: JSON.
RAW_FORMAT = "flirt-json/2"

#: The identity scheme masked-pattern records are under. Tracks
#: `glaurung.llm.kb.siglib.FLIRT_MASKED_PATTERN_V1`.
DEFAULT_KIND = "flirt-masked-pattern-v1"

#: The identity scheme exact-match GUID records are under. Tracks
#: `glaurung.llm.kb.siglib.WARP_FUNCTION_GUID_V1`.
WARP_KIND = "warp-function-guid-v1"

#: `sig_convert`'s `--scheme` value for each kind.
SCHEME_FOR_KIND = {DEFAULT_KIND: "flirt", WARP_KIND: "warp"}

#: Manifest keys are `<library>/<version>/<variant>/<arch>`, and Decision 1 of
#: the programme notes makes the *scheme* part of the key too. The
#: masked-pattern scheme is left unprefixed because 292 of its keys are
#: already published under those exact strings and a carried-forward blob has
#: to match by key; every other scheme carries its prefix.
KEY_PREFIX = {DEFAULT_KIND: "", WARP_KIND: "warp:"}

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
    #: The identity scheme, copied into the manifest entry's `kind`.
    kind: str = DEFAULT_KIND
    #: The report bucket: one distro cell, one Docker image, one Rust
    #: toolchain, `cortex-m`, or `windows-warp`. Reporting rolls these up.
    bucket: str = "unknown"
    #: How the resolver ranks this blob against another claiming the same
    #: key. See `_resolve_contested`.
    source_class: str = "unknown"


#: How a contested key is resolved when history does not already decide it,
#: best first.
#:
#: A network cell wins over a Docker image because it carries the *upstream*
#: package hash -- the `.deb`/`.apk` digest the distributor published -- so its
#: provenance can be re-fetched by anyone. A Docker image's provenance is a
#: `dpkg -l` line inside a container we built, which is weaker evidence about
#: the same bytes. Measured on this corpus the rule never fires: all 96
#: contested keys are Docker-versus-Docker (`linux-amd64` against
#: `linux-arm64`), which is what `--prefer-image` is for.
SOURCE_CLASS_ORDER = ("network", "rust", "cortex-m", "warp", "docker", "unknown")


def _classify_image(image: str) -> str:
    """Which `SOURCE_CLASS_ORDER` class a harvest record's `image` belongs to."""
    if image.startswith(("debian-", "ubuntu-", "alpine-", "fedora-")):
        return "network"
    if image.startswith("rust-"):
        return "rust"
    if image:
        return "docker"
    return "unknown"


def _load_index(blobs_dir: Path) -> tuple[str, dict[str, dict[str, Any]]]:
    """A source directory's `index.json`, and which shape it is in.

    Three harvesters write three shapes and none of them is going to be
    retrofitted for a publisher's convenience, so the publisher sniffs:

    * the FLIRT harvest keys rows by `output` and counts `unique_signatures`;
    * the Cortex-M harvest does the same but has no `triplet`, and encodes the
      library name in its own `key` instead;
    * the WARP builder keys rows by `file`, counts `unique`, and declares a
      top-level `scheme`.

    Absent is not fatal: a directory of blobs with no index still publishes,
    with `source: "unknown"` provenance, which is honest rather than invented.

    Returns:
        `("flirt", rows)` or `("warp", rows)`, rows keyed by filename.
    """
    index_path = blobs_dir / "index.json"
    if not index_path.is_file():
        return "flirt", {}
    payload = json.loads(index_path.read_text(encoding="utf-8"))
    records = payload.get("libraries") or []
    shape = "warp" if payload.get("scheme") == WARP_KIND else "flirt"
    field = "file" if shape == "warp" else "output"
    return shape, {
        str(record.get(field) or ""): record
        for record in records
        if isinstance(record, dict) and record.get(field)
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
    # The Rust sysroot harvester writes a slash-separated key,
    # `rust-std/<version>/<variant>/<arch>/<crate>`, and a matching nested
    # output path. Its last segment is the crate name -- which is what a key
    # should carry. The `archive` fallback below would instead give
    # `libaddr2line-98301de5f7086436.rlib`, whose embedded codegen hash
    # changes between two builds of the same rustc and would make every
    # release look like a new library.
    if "/" in harvest_key:
        return harvest_key.rsplit("/", 1)[-1]
    if triplet and f".{triplet}." in harvest_key:
        return harvest_key.split(f".{triplet}.", 1)[1]
    # The Cortex-M harvest records no triplet -- there is no distro triplet to
    # record -- and spells its key `<library>.<version>.<variant>.<arch>`. The
    # last three are recorded fields, so stripping them is exact, where the
    # archive fallback below is not: every Cortex-M multilib's `newlib` comes
    # out of a file called `libc.a`, so 12 distinct libraries would all be
    # named `libc` and collide on one key.
    suffix = ".{}.{}.{}".format(
        record.get("library_version") or "",
        record.get("variant") or "",
        record.get("arch") or "",
    )
    if harvest_key.endswith(suffix) and len(harvest_key) > len(suffix):
        return harvest_key[: -len(suffix)]
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


def _warp_key(record: dict[str, Any], path: Path) -> tuple[str, str]:
    """`(manifest key, report bucket)` for one WARP library.

    The WARP index records `module`, `version` and `variant` but no `arch`:
    the architecture is in the filename, which is where the builder puts it
    (`afd.sys-10.0.19041.1766-msvc-14.20-b27412.x86_64.warp.json`). Taking it
    from the filename is exact for every file that builder writes.
    """
    stem = path.name
    for suffix in (".warp.json", ".warp.gsig", ".gsig", ".json"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    arch = stem.rsplit(".", 1)[-1] if "." in stem else "unknown"
    key = "{}{}/{}/{}/{}".format(
        KEY_PREFIX[WARP_KIND],
        record.get("module") or stem,
        record.get("version") or "unknown",
        record.get("variant") or "unknown",
        arch,
    )
    return key, "windows-warp"


def collect(
    blobs_dir: Path,
    *,
    pattern: str,
    min_signatures: int,
    limit: int | None = None,
    prefer_images: Sequence[str] = (),
    bucket: str | None = None,
    source_class: str | None = None,
) -> tuple[list[SourceBlob], list[str]]:
    """Candidate blobs from one source directory, plus every rejection reason.

    Empty libraries are the common case and they are dropped here, not
    silently published: five glibc archives have been 8-byte stubs since 2.34
    and MinGW import libraries are pure thunks, so a harvest legitimately
    produces many zero-signature outputs. Publishing them would inflate the
    set with blobs that can never match anything.

    Args:
        blobs_dir: A directory of blobs with (usually) an `index.json`.
        pattern: Glob selecting blob files. `*` accepts both schemes.
        min_signatures: Drop a blob below this count.
        limit: Keep at most this many, after resolution.
        prefer_images: Accepted for signature compatibility; resolution now
            happens once across all sources, in `_resolve_contested`.
        bucket: Override the report bucket for every blob here. Needed for the
            Cortex-M harvest, whose rows record no `image` to derive one from.
        source_class: Override the resolution class, for the same reason.
    """
    del prefer_images
    shape, index = _load_index(blobs_dir)
    chosen: list[SourceBlob] = []
    rejected: list[str] = []
    for path in sorted(blobs_dir.glob(pattern)):
        if path.name == "index.json" or not path.is_file():
            continue
        # The FLIRT harvest writes flat filenames; the Rust sysroot harvest
        # writes `rust-std/<version>/<variant>/<arch>/<crate>.flirt.json` and
        # records that whole relative path as the row's `output`. Try the
        # relative path first, then the bare name, so both index correctly.
        # Getting this wrong is silent: an unmatched row leaves the blob with
        # no provenance and no signature count, so it cannot be filtered and
        # publishes with `source: "unknown"`.
        relative = path.relative_to(blobs_dir).as_posix()
        record = index.get(relative) or index.get(path.name) or {}
        count_field = "unique" if shape == "warp" else "unique_signatures"
        signatures = int(record.get(count_field) or 0)
        if not record:
            # No index entry: keep it, but it cannot be filtered on a count
            # it does not have.
            signatures = -1
        elif signatures < min_signatures:
            rejected.append(f"{path.name}: {signatures} signatures")
            continue
        if shape == "warp":
            key, derived_bucket = _warp_key(record, path)
            kind, derived_class = WARP_KIND, "warp"
        else:
            key = _library_key(record, path.name.split(".")[0])
            image = str(record.get("image") or "")
            kind = DEFAULT_KIND
            derived_class = _classify_image(image)
            derived_bucket = image or "unknown"
        chosen.append(
            SourceBlob(
                path=path,
                key=key,
                signatures=max(signatures, 0),
                record=record,
                kind=kind,
                bucket=bucket or derived_bucket,
                source_class=source_class or derived_class,
            )
        )
    if limit is not None:
        chosen = chosen[:limit]
    return chosen, rejected


def _resolve_contested(
    sources: Sequence[SourceBlob],
    *,
    prefer_images: Sequence[str] = (),
    published: Mapping[str, BlobEntry] | None = None,
) -> tuple[list[SourceBlob], list[str], dict[str, BlobEntry]]:
    """Keep one source per `(scheme, library, version, variant, arch)` key.

    Three rules, in order, and the order is the point:

    1. **History decides first.** A key the previous manifest already
       published keeps that blob: the resolution was made once, is signed, and
       is on a CDN. Re-litigating it every release would churn hashes for no
       reason and cost every client a re-download. Measured against serial 1,
       this alone settles all 96 contested keys.
    2. **Then the source class**, `SOURCE_CLASS_ORDER`: a network cell beats a
       Docker image because it carries the upstream package hash.
    3. **Then `--prefer-image`**, for a contest *inside* one class.

    Anything still contested after all three is a hard error, which is the
    correct default: two different blobs under one key means a harvester's
    `variant` field is not distinguishing two builds, and that defect should
    stay visible rather than being silently resolved by sort order.

    Measured on the 2026-09-03 Docker harvest: 96 of 316 keys are contested,
    every one of them `linux-amd64` against `linux-arm64`, and the contesting
    blobs differ **only** in an absolute build path the harvester embeds in
    the blob's own provenance. Once that path is out of the emitted blob the
    two hash the same and the content-addressed store deduplicates them free.

    Returns:
        `(kept, dropped-with-reasons, carried-forward entries by key)`.
    """
    published = published or {}
    class_rank = {name: i for i, name in enumerate(SOURCE_CLASS_ORDER)}
    image_rank = {name: i for i, name in enumerate(prefer_images)}

    grouped: dict[str, list[SourceBlob]] = {}
    for source in sources:
        grouped.setdefault(source.key, []).append(source)

    kept: list[SourceBlob] = []
    dropped: list[str] = []
    carried: dict[str, BlobEntry] = {}
    for key, contenders in sorted(grouped.items()):
        if key in published:
            carried[key] = published[key]
            for loser in contenders:
                dropped.append(
                    f"{loser.path.name}: key {key!r} was already published as "
                    f"{published[key].sha256[:12]}; carried forward unchanged"
                )
            continue
        if len(contenders) == 1:
            kept.append(contenders[0])
            continue

        def rank(blob: SourceBlob) -> tuple[int, int, str]:
            return (
                class_rank.get(blob.source_class, len(class_rank)),
                image_rank.get(str(blob.record.get("image") or ""), len(image_rank)),
                blob.path.name,
            )

        ordered = sorted(contenders, key=rank)
        # Identical bytes under one key are not a collision, they are the
        # deduplication the content-addressed store exists for -- worth 26 to
        # 43 percent between adjacent releases of one distro line. Check that
        # before ranking, or a corpus that overlaps perfectly fails to
        # publish. Conversion preserves this: the writer is deterministic, so
        # identical input JSON produces an identical container.
        if len({_sha256(c.path) for c in ordered}) == 1:
            kept.append(ordered[0])
            dropped.extend(
                f"{loser.path.name}: key {key!r} is byte-identical to "
                f"{ordered[0].path.name}; deduplicated"
                for loser in ordered[1:]
            )
            continue
        winner, runner_up = ordered[0], ordered[1]
        if rank(winner)[:2] == rank(runner_up)[:2]:
            raise SystemExit(
                f"key collision: {key!r} is claimed by "
                + ", ".join(
                    f"{c.path.name} (class {c.source_class}, image "
                    f"{c.record.get('image') or '-'})"
                    for c in ordered
                )
                + ".\nNothing distinguishes them: the source class is the same "
                "and --prefer-image does not rank them. Either the harvester's "
                "variant field is not separating two builds, or you want "
                "--prefer-image <image> to say which one wins."
            )
        kept.append(winner)
        for loser in ordered[1:]:
            dropped.append(
                f"{loser.path.name}: key {key!r} also produced by "
                f"{winner.path.name} (class {winner.source_class}, image "
                f"{winner.record.get('image') or '-'}), which ranks higher"
            )
    return sorted(kept, key=lambda s: (s.key, s.path.name)), dropped, carried


# --- manifest construction ---------------------------------------------------


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _provenance(source: SourceBlob) -> Provenance:
    """The provenance the *source index* recorded, per scheme.

    The two index shapes name different things, and flattening them into one
    set of field names would lose the distinction between "the `.deb` this
    archive came out of" and "the PE this GUID was computed from". So each
    scheme fills the fields it actually has, and `source` says which harvester
    spoke.
    """
    record = source.record
    if not record:
        return Provenance(source="unknown")
    if source.kind == WARP_KIND:
        return Provenance(
            # e.g. `corpus:windows-10-x64` -- the WARP builder's own label for
            # the PE corpus a module was read out of.
            source=str(record.get("source") or "warp-pe-pdb"),
            package=str(record.get("module") or ""),
            version=str(record.get("version") or ""),
            arch=source.key.rsplit("/", 1)[-1],
            variant=str(record.get("variant") or ""),
        )
    return Provenance(
        source=str(record.get("source") or _default_flirt_source(source)),
        package=str(record.get("library_name") or ""),
        version=str(record.get("library_version") or ""),
        arch=str(record.get("arch") or ""),
        archive=str(record.get("archive") or ""),
        input_sha256=str(record.get("archive_sha256") or ""),
        variant=str(record.get("variant") or ""),
        triplet=str(record.get("triplet") or ""),
        image=str(record.get("image") or ""),
    )


def _default_flirt_source(source: SourceBlob) -> str:
    """What produced a masked-pattern blob, when its index row does not say.

    Serial 1 recorded `docker-harvest` for every blob including the network
    cells, which is not quite true of any of them and flatly untrue of the
    Cortex-M set (a vendor tarball, no container involved). The class the
    resolver already computed is the honest answer.
    """
    return {
        "network": "distro-archive",
        "rust": "rust-sysroot",
        "cortex-m": "arm-gnu-toolchain",
        "docker": "docker-harvest",
    }.get(source.source_class, "unknown")


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


def _materialize(
    source: SourceBlob, out_blobs: Path, *, convert: bool, codec: str
) -> tuple[str, int, str]:
    """Put one source's *published bytes* in `<out_blobs>/<sha256>`.

    With `convert`, the blob is rewritten as a `gsig/1` container through the
    Rust writer, so the digest names the container and not the JSON. Without
    it the harvester's own bytes are copied, which is what serial 1 published.

    The conversion is deterministic -- sorted string table, fixed codec and
    chunk size, no timestamp or path in the file -- which is the property that
    lets the manifest name a blob by its hash at all. `tests/flirt_gsig_*.rs`
    hold it.

    Returns:
        `(sha256, size in bytes, format string)`.
    """
    out_blobs.mkdir(parents=True, exist_ok=True)
    if not convert:
        digest = _sha256(source.path)
        target = out_blobs / digest
        if not target.is_file():
            tmp = target.with_name(target.name + ".part")
            shutil.copyfile(source.path, tmp)
            os.replace(tmp, target)
        return digest, source.path.stat().st_size, RAW_FORMAT

    from glaurung.tools import sig_convert  # noqa: PLC0415

    staged = out_blobs / f".convert-{os.getpid()}.gsig"
    report = sig_convert.to_gsig(
        source.path,
        staged,
        codec=codec,
        scheme=SCHEME_FOR_KIND.get(source.kind, "auto"),
    )
    digest = str(report["sha256"])
    size = int(report["bytes_written"])
    target = out_blobs / digest
    if target.is_file():
        staged.unlink()
    else:
        os.replace(staged, target)
    return digest, size, DEFAULT_FORMAT


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
    convert: bool = False,
    codec: str = "zstd",
    carried: Mapping[str, BlobEntry] | None = None,
    carried_blobs: Path | None = None,
) -> tuple[Manifest, dict[str, Path]]:
    """Publish each source to `<out_blobs>/<sha256>` and describe it.

    Two sources that hash the same become one blob. That deduplication is
    worth 26 to 43 percent between adjacent releases of one distro line, and
    it is free precisely because the store is content-addressed.

    `carried` entries are copied into the manifest **verbatim** -- same
    sha256, same `format`, same recorded provenance -- so the CDN object a
    previous serial published is reused rather than replaced. Their URLs are
    left alone too: a carried blob's GitHub URL points at the release that
    actually holds it, and rewriting it to this release's tag would name an
    asset nobody uploaded.
    """
    out_blobs.mkdir(parents=True, exist_ok=True)
    entries: dict[str, BlobEntry] = {}
    written: dict[str, Path] = {}
    now = datetime.now(timezone.utc)

    for key, entry in sorted((carried or {}).items()):
        entries[key] = entry
        target = out_blobs / entry.sha256
        source_path = (carried_blobs / entry.sha256) if carried_blobs else None
        if not target.is_file() and source_path is not None and source_path.is_file():
            tmp = target.with_name(target.name + ".part")
            shutil.copyfile(source_path, tmp)
            os.replace(tmp, target)
        if target.is_file():
            written[entry.sha256] = target

    for source in sources:
        digest, size, fmt = _materialize(
            source, out_blobs, convert=convert, codec=codec
        )
        written[digest] = out_blobs / digest
        entry = BlobEntry(
            key=source.key,
            kind=source.kind or kind,
            # `_materialize` is the only thing that knows what it wrote, so
            # it names the format. `--format` overrides it, for a producer
            # publishing a container this tool did not build.
            format=blob_format or fmt,
            compression="none",
            sha256=digest,
            size_bytes=size,
            uncompressed_bytes=size,
            signatures=source.signatures,
            licence=licence,
            provenance=_provenance(source),
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
        # differing bytes are a real collision `_resolve_contested` should
        # already have settled, so reaching here means it did not.
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
    # The trusted comment must be the manifest's canonical one: the client
    # compares the signed comment against the manifest body and refuses a
    # mismatch, so a shorter comment verifies with stock minisign and then
    # fails in every client.
    return (
        f"minisign -Sm {manifest_path} -s {secret_key} "
        f'-t "{manifest.trusted_comment()}"'
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


def _parse_source_spec(
    spec: str, default_pattern: str
) -> tuple[Path, str, str | None, str | None]:
    """`DIR[:PATTERN[:BUCKET[:CLASS]]]` -> the four things `collect` needs.

    Split from the right on at most three colons, so a Windows-style drive
    letter or any other colon inside the path survives.
    """
    parts = spec.split(":")
    if len(parts) > 4:
        head = ":".join(parts[:-3])
        parts = [head, *parts[-3:]]
    directory = Path(parts[0])
    pattern = parts[1] if len(parts) > 1 and parts[1] else default_pattern
    bucket = parts[2] if len(parts) > 2 and parts[2] else None
    source_class = parts[3] if len(parts) > 3 and parts[3] else None
    if source_class is not None and source_class not in SOURCE_CLASS_ORDER:
        raise SystemExit(
            f"--source class {source_class!r} is not one of "
            f"{', '.join(SOURCE_CLASS_ORDER)}"
        )
    return directory, pattern, bucket, source_class


def summarize(
    manifest: Manifest,
    sources: Sequence[SourceBlob],
    carried: Mapping[str, BlobEntry],
) -> list[str]:
    """The per-source size table, and the per-scheme signature counts.

    This is the number the programme actually needs before an upload: what a
    client downloads, broken down by where it came from, so a decision to
    include or exclude a source is made against its real cost rather than
    against the JSON it was derived from.
    """
    bucket_of = {source.key: source.bucket for source in sources}
    for key in carried:
        bucket_of.setdefault(key, "carried-forward (serial < this one)")

    rows: dict[str, tuple[int, int, int]] = {}
    schemes: dict[str, tuple[int, int]] = {}
    for blob in manifest.blobs:
        bucket = bucket_of.get(blob.key, "unknown")
        count, size, sigs = rows.get(bucket, (0, 0, 0))
        rows[bucket] = (count + 1, size + blob.size_bytes, sigs + blob.signatures)
        s_blobs, s_sigs = schemes.get(blob.kind, (0, 0))
        schemes[blob.kind] = (s_blobs + 1, s_sigs + blob.signatures)

    out = ["", "blobs and bytes by source:", ""]
    out.append(
        "  {:<44} {:>6} {:>10} {:>14}".format("SOURCE", "BLOBS", "SIGS", "BYTES")
    )
    for bucket in sorted(rows):
        count, size, sigs = rows[bucket]
        out.append(f"  {bucket:<44} {count:>6} {sigs:>10} {size:>14,}")
    out.append(
        "  {:<44} {:>6} {:>10} {:>14,}".format(
            "TOTAL",
            len(manifest.blobs),
            manifest.total_signatures,
            manifest.total_bytes,
        )
    )
    out.extend(["", "signatures by scheme:", ""])
    for kind in sorted(schemes):
        s_blobs, s_sigs = schemes[kind]
        out.append(f"  {kind:<44} {s_blobs:>6} {s_sigs:>10}")
    return out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="publish_signature_set.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--blobs",
        type=Path,
        action="append",
        default=[],
        metavar="DIR",
        help="Directory of signature blobs. Repeatable: every directory given "
        "is published into one set, and each is read with whichever "
        "index.json shape it has (FLIRT harvest, Cortex-M harvest, WARP "
        "builder). Use --source for finer control.",
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="DIR[:PATTERN[:BUCKET[:CLASS]]]",
        help="A blob directory with an explicit glob, report bucket and "
        "resolution class, colon-separated. Repeatable. The bucket is what "
        "the size report groups by; the class is how a contested key is "
        f"ranked ({', '.join(SOURCE_CLASS_ORDER)}).",
    )
    parser.add_argument(
        "--pattern",
        default="**/*.json",
        help="Glob selecting blob files inside each --blobs directory "
        "(default: %(default)s -- both *.flirt.json and *.warp.json, and "
        "recursive, because the Rust sysroot harvest nests its output under "
        "rust-std/<version>/<variant>/<arch>/. index.json is always skipped)",
    )
    parser.add_argument(
        "--convert",
        choices=("gsig", "none"),
        default="gsig",
        help="Rewrite every blob as a gsig/1 container before hashing it "
        "(default: %(default)s), or publish the harvester's own JSON bytes. "
        "Conversion changes a blob's sha256, so it is not free: a key already "
        "published as JSON must be carried forward, not reconverted, or every "
        "client re-downloads it.",
    )
    parser.add_argument(
        "--codec",
        default="zstd",
        help="gsig codec (default: %(default)s). Part of the blob's identity: "
        "changing it changes every hash.",
    )
    parser.add_argument(
        "--carry-forward",
        type=Path,
        default=None,
        metavar="MANIFEST",
        help="A previously published manifest.json. Every key it names is "
        "reused verbatim -- same sha256, same format -- so the CDN objects "
        "stay valid and clients re-download nothing. Blobs are copied from "
        "<MANIFEST dir>/blobs when they are there; a missing local copy is "
        "reported, not fatal, since the published object is what matters.",
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
        "--unsigned",
        action="store_true",
        help="Build and measure the release without signing it. The manifest, "
        "SHA256SUMS and NOTICE are written and the exact `minisign -Sm` "
        "command is printed; no key is read and nothing is signed. This is "
        "the honest shape of a dry run whose signing key belongs to a human: "
        "the alternative -- signing with the local dev key -- produces an "
        "artifact that looks publishable and is not. Implies no --upload.",
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
    parser.add_argument(
        "--format",
        dest="blob_format",
        default=None,
        help="Override the container name recorded in each manifest entry. "
        f"Defaults to what was actually written: {DEFAULT_FORMAT} with "
        f"--convert gsig, {RAW_FORMAT} with --convert none.",
    )
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

    specs = [(Path(d), args.pattern, None, None) for d in args.blobs]
    specs.extend(_parse_source_spec(spec, args.pattern) for spec in args.source)
    if not specs:
        raise SystemExit("give at least one --blobs directory or --source spec")
    out: Path = args.out.expanduser()

    secret_key_path = args.secret_key.expanduser()
    blob_base_url = (
        args.blob_base_url
        if args.blob_base_url is not None
        else f"https://{args.s3_bucket}"
    )

    published: dict[str, BlobEntry] = {}
    carried_blobs: Path | None = None
    if args.carry_forward is not None:
        previous_path = args.carry_forward.expanduser()
        previous = Manifest.read(previous_path)
        if previous.serial >= args.serial:
            raise SystemExit(
                f"--carry-forward names serial {previous.serial} but this run "
                f"is serial {args.serial}. A serial must exceed the one it "
                "carries forward from, or a client that already holds the "
                "older set will refuse this one."
            )
        published = {blob.key: blob for blob in previous.blobs}
        carried_blobs = previous_path.parent / "blobs"

    sources: list[SourceBlob] = []
    rejected: list[str] = []
    for directory, pattern, bucket, source_class in specs:
        directory = directory.expanduser()
        if not directory.is_dir():
            raise SystemExit(f"{directory} is not a directory")
        found, skipped = collect(
            directory,
            pattern=pattern,
            min_signatures=args.min_signatures,
            bucket=bucket,
            source_class=source_class,
        )
        if not found:
            raise SystemExit(f"no blobs matched {pattern!r} under {directory}")
        sources.extend(found)
        rejected.extend(skipped)

    sources, contested, carried = _resolve_contested(
        sources, prefer_images=args.prefer_image, published=published
    )
    rejected.extend(contested)
    if args.limit is not None:
        sources = sources[: args.limit]

    # A carried-forward key whose sources all lost a contest is already in
    # `carried`; the rest of the previous manifest is carried too, so serial N
    # is a superset of serial N-1 by construction rather than by luck.
    still_present = {source.key for source in sources}
    for key, entry in published.items():
        if key not in still_present:
            carried.setdefault(key, entry)

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
        convert=args.convert == "gsig",
        codec=args.codec,
        carried=carried,
        carried_blobs=carried_blobs,
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

    if args.unsigned:
        if args.upload:
            raise SystemExit(
                "--unsigned and --upload are mutually exclusive: an unsigned "
                "manifest is not publishable, and a client would refuse it."
            )
        signed_by = "(none -- --unsigned; the maintainer signs, see below)"
    elif args.signature is not None:
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
        expected = manifest.trusted_comment()
        if comment != expected:
            raise SystemExit(
                "--signature's trusted comment is not this manifest's canonical "
                "comment, so clients would refuse it; refusing to publish.\n"
                f"  signed:   {comment!r}\n"
                f"  expected: {expected!r}\n"
                f"Re-sign with: {sign_command(manifest_path, secret_key_path, manifest)}"
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

    for line in summarize(manifest, sources, carried):
        print(line)

    print(
        f"\nset {manifest.set_name} {manifest.set_version} serial "
        f"{manifest.serial}\n"
        f"  blobs      {len(manifest.blobs)}"
        + (f"  ({len(carried)} carried forward unchanged)" if carried else "")
        + f"\n  signatures {manifest.total_signatures}\n"
        f"  bytes      {manifest.total_bytes} "
        f"({manifest.total_bytes / 1024 / 1024:.1f} MiB)\n"
        f"  manifest   {manifest_path} "
        f"({manifest_path.stat().st_size} bytes)\n"
        f"  signature  {signed_by}\n"
        f"  checksums  {sums_path}\n"
        f"  notice     {notice_path}\n"
        f"  trusted comment (what the maintainer must sign with):\n"
        f"    {manifest.trusted_comment()}"
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
        if args.unsigned:
            # The commands below name a `manifest.json.minisig` this run did
            # not produce. Say so where they are printed, not only in the
            # `--unsigned` help: the failure mode is an operator pasting the
            # `aws` lines and uploading blobs for a manifest that can never be
            # verified, which leaves the bucket holding objects no signed
            # manifest names.
            print(
                "# !! --unsigned: manifest.json.minisig does not exist, so the\n"
                "# !! last two `aws s3 cp` lines below cannot run. Sign the\n"
                "# !! manifest first (command printed above) and re-run with\n"
                "# !! --signature; then these commands are complete.\n"
            )
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
