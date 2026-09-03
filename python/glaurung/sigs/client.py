"""Fetch, verify and cache a signature set.

The whole path, in order, because the order is the security argument:

1. Download the manifest and its detached `.minisig`. Nothing is trusted yet.
2. Verify the minisign signature against a **bundled** trusted public key.
   Both signatures are checked -- the file signature and the global signature
   that covers the trusted comment -- and the trusted comment's set/version/
   serial must equal the manifest body's, so the downgrade defence cannot be
   defeated by editing the unsigned copy of those numbers.
3. Refuse a serial below the one already cached. A genuinely-signed older
   manifest is still a downgrade.
4. Fetch each missing blob **by its sha256**, from whichever mirror answers,
   with HTTP range resume. Hash what arrived; a mismatch deletes the partial
   file and raises. Only then does it enter the cache under its digest.
5. Write `manifest.json`, `manifest.json.minisig` and `catalog.json`.

Because a blob's name *is* its hash and it is only written after the hash
matches, a mirror is untrusted infrastructure: it can refuse to serve, but it
cannot substitute content.

Offline mode (`GLAURUNG_SIGS_OFFLINE=1`, or `offline=True`) forbids every
network call and falls back to the cache, then to the bundled `base` set that
ships in the wheel. That fallback is the reason a fresh install with no
network is still able to name library functions at all.

Only `http`, `https` and `file` URLs are followed. `file://` exists so the
end-to-end test -- and an air-gapped mirror on a USB stick -- work through the
same code path as a real fetch rather than a special case.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

from . import minisign
from .catalog import Catalog, CatalogEntry
from .manifest import BlobEntry, Manifest, ManifestError, parse_version
from .paths import (
    blob_path,
    bundled_blob_dir,
    bundled_manifest_path,
    bundled_signature_path,
    cache_root,
    cached_manifest_path,
    cached_signature_path,
    default_manifest_url,
    is_offline,
    keys_dir,
)

__all__ = [
    "BlobVerificationError",
    "DowngradeError",
    "FetchError",
    "FetchResult",
    "OfflineError",
    "TrustError",
    "fetch",
    "load_trusted_keys",
    "resolve",
    "verify_cache",
]

#: How much of a blob to hash at a time. 1 MiB keeps a 400 MB set off the heap.
_CHUNK = 1 << 20

_ALLOWED_SCHEMES = frozenset({"http", "https", "file"})

_UA = "glaurung-sigs/1"

ProgressHook = Callable[[str, int, int], None]


class FetchError(Exception):
    """The set could not be fetched."""


class OfflineError(FetchError):
    """Network access was required but forbidden."""


class TrustError(FetchError):
    """The manifest is not signed by a trusted key, or not signed correctly."""


class DowngradeError(FetchError):
    """The offered manifest's serial is below the cached one."""


class BlobVerificationError(FetchError):
    """A blob's bytes do not hash to the digest the manifest names."""


@dataclass
class FetchResult:
    """What a fetch did, in enough detail for a CLI to print it honestly."""

    manifest: Manifest
    root: Path
    source: str
    downloaded: list[str] = field(default_factory=list)
    already_cached: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    bytes_downloaded: int = 0
    warnings: list[str] = field(default_factory=list)
    verified_by: str = ""

    @property
    def blob_count(self) -> int:
        return len(self.downloaded) + len(self.already_cached)


# --- trusted keys ------------------------------------------------------------


def load_trusted_keys(directory: Path | None = None) -> list[minisign.PublicKey]:
    """Every `*.pub` in the trusted-key directory.

    A directory rather than one file because key *rotation* has to be a
    non-event: the new key ships alongside the old one for a release or two,
    both verify, then the old one is deleted. A single embedded key makes
    rotation a flag day.
    """
    source = directory or keys_dir()
    if not source.is_dir():
        return []
    keys: list[minisign.PublicKey] = []
    for path in sorted(source.glob("*.pub")):
        try:
            keys.append(minisign.PublicKey.read(path))
        except (minisign.MinisignError, OSError) as exc:
            raise TrustError(f"trusted key {path} is unreadable: {exc}") from exc
    return keys


# --- transport ---------------------------------------------------------------


def _check_url(url: str) -> str:
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise FetchError(
            f"refusing URL with scheme {scheme!r}: only "
            f"{sorted(_ALLOWED_SCHEMES)} are followed"
        )
    return scheme


def _get(url: str, *, timeout: float, offset: int = 0) -> tuple[bytes, bool]:
    """Fetch `url`, optionally from `offset`. Returns (bytes, is_partial_resume).

    `file://` ignores the offset and returns the whole file: local reads have
    nothing to resume and adding a seek would be a second code path to get
    wrong. The caller handles both by truncating its partial file when
    `is_partial_resume` is False.
    """
    scheme = _check_url(url)
    if scheme == "file":
        path = Path(urllib.request.url2pathname(urllib.parse.urlparse(url).path))
        try:
            return path.read_bytes(), False
        except OSError as exc:
            raise FetchError(f"{url}: {exc}") from exc

    headers = {"User-Agent": _UA}
    if offset > 0:
        headers["Range"] = f"bytes={offset}-"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            resumed = response.status == 206
            return response.read(), resumed
    except urllib.error.HTTPError as exc:
        if offset > 0 and exc.code in (416, 501):
            # Range unsupported or out of range: start over from zero.
            return _get(url, timeout=timeout, offset=0)
        raise FetchError(f"{url}: HTTP {exc.code} {exc.reason}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FetchError(f"{url}: {exc}") from exc


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --- manifest acquisition ----------------------------------------------------


def _verify_manifest_bytes(
    body: bytes, signature_text: str, keys: Sequence[minisign.PublicKey]
) -> tuple[Manifest, minisign.PublicKey]:
    """Verify, parse, and cross-check the signed trusted comment."""
    try:
        signature = minisign.Signature.from_text(signature_text)
    except minisign.MinisignError as exc:
        raise TrustError(f"manifest signature is malformed: {exc}") from exc
    try:
        key = minisign.verify_bytes(body, signature, list(keys))
    except minisign.MinisignError as exc:
        raise TrustError(f"manifest signature does not verify: {exc}") from exc

    try:
        manifest = Manifest.from_json(body)
    except ManifestError as exc:
        raise FetchError(f"manifest is not usable: {exc}") from exc

    # The trusted comment is signed; the manifest body's copy of the same
    # numbers is not covered independently, so they must agree or one of them
    # is a lie.
    if signature.trusted_comment != manifest.trusted_comment():
        raise TrustError(
            "the signed trusted comment does not describe this manifest:\n"
            f"  signed:   {signature.trusted_comment}\n"
            f"  manifest: {manifest.trusted_comment()}"
        )
    return manifest, key


def _signature_url(manifest_url: str) -> str:
    return manifest_url + ".minisig"


# --- the public entry points -------------------------------------------------


def fetch(
    set_name: str = "base",
    manifest_url: str | None = None,
    *,
    root: Path | None = None,
    offline: bool | None = None,
    keys: Sequence[minisign.PublicKey] | None = None,
    timeout: float = 60.0,
    only: Iterable[str] | None = None,
    progress: ProgressHook | None = None,
    glaurung_version: str | None = None,
) -> FetchResult:
    """Bring the cache up to date with a signed signature set.

    Args:
        set_name: Which set to fetch; the manifest must declare the same name.
        manifest_url: Where the signed manifest is. Defaults to
            `GLAURUNG_SIGS_MANIFEST_URL`, then the release URL.
        root: Cache root; defaults to `GLAURUNG_SIG_DIR` or
            `~/.cache/glaurung/sigs`.
        offline: Forbid the network. `None` consults `GLAURUNG_SIGS_OFFLINE`.
        keys: Trusted public keys; defaults to the bundled `trusted-keys/`.
        only: Fetch just these library keys instead of the whole set.
        progress: Called `(key, done_bytes, total_bytes)` per blob.
        glaurung_version: Overrides the version checked against
            `min_glaurung_version`; for tests.

    Returns:
        A :class:`FetchResult` describing what happened.

    Raises:
        OfflineError: network needed but forbidden and nothing is cached.
        TrustError: the manifest is unsigned, or signed by an untrusted key.
        DowngradeError: the offered serial is below the cached one.
        BlobVerificationError: a downloaded blob does not match its digest.
    """
    root = Path(root) if root is not None else cache_root()
    trusted = list(keys) if keys is not None else load_trusted_keys()
    catalog = Catalog.load(root)

    if is_offline(offline):
        return _fetch_offline(set_name, root, trusted, catalog, only)

    url = manifest_url or default_manifest_url()
    body, _ = _get(url, timeout=timeout)
    signature_bytes, _ = _get(_signature_url(url), timeout=timeout)
    manifest, key = _verify_manifest_bytes(
        body, signature_bytes.decode("utf-8", "replace"), trusted
    )
    result = FetchResult(
        manifest=manifest, root=root, source=url, verified_by=key.key_id_hex
    )
    _check_set_and_serial(manifest, set_name, catalog, result, glaurung_version)

    _materialize(manifest, root, result, only=only, timeout=timeout, progress=progress)
    _commit(root, catalog, manifest, result, body, signature_bytes, key.key_id_hex)
    return result


def _commit(
    root: Path,
    catalog: Catalog,
    manifest: Manifest,
    result: FetchResult,
    manifest_bytes: bytes,
    signature_bytes: bytes,
    key_id: str,
) -> None:
    """Persist the verified manifest, its signature and the catalog.

    Both the online and the offline path go through here. They used not to:
    an offline fetch installed the bundled blobs into the cache and never
    wrote `catalog.json`, so the blobs were present, content-addressed, and
    unreachable -- the Rust loader maps a library key to a digest through the
    catalog and there was nothing to map. A cache the loader cannot read is
    not a cache.
    """
    root.mkdir(parents=True, exist_ok=True)
    cached_manifest_path(root).write_bytes(manifest_bytes)
    cached_signature_path(root).write_bytes(signature_bytes)
    catalog.update_from_manifest(
        manifest,
        key_id=key_id,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
    )
    present = set(result.downloaded) | set(result.already_cached)
    for blob in manifest.blobs:
        if blob.key in present:
            catalog.record(blob.key, _entry_for(blob))
    catalog.save(root)


def _entry_for(blob: BlobEntry) -> CatalogEntry:
    return CatalogEntry(
        sha256=blob.sha256,
        format=blob.format,
        kind=blob.kind,
        signatures=blob.signatures,
        size_bytes=blob.size_bytes,
        arch=blob.provenance.arch,
    )


def _check_set_and_serial(
    manifest: Manifest,
    set_name: str,
    catalog: Catalog,
    result: FetchResult,
    glaurung_version: str | None,
) -> None:
    if manifest.set_name != set_name:
        raise FetchError(
            f"asked for set {set_name!r} but the manifest declares "
            f"{manifest.set_name!r}"
        )
    if catalog.set_name == manifest.set_name and manifest.serial < catalog.serial:
        raise DowngradeError(
            f"refusing serial {manifest.serial}: the cache already holds "
            f"serial {catalog.serial} of set {catalog.set_name!r}. A "
            "correctly-signed older manifest is still a downgrade."
        )
    ours = glaurung_version if glaurung_version is not None else _our_version()
    if parse_version(ours) < parse_version(manifest.min_glaurung_version):
        raise FetchError(
            f"this set needs glaurung >= {manifest.min_glaurung_version}, "
            f"and this is {ours}"
        )
    if manifest.is_expired():
        result.warnings.append(
            f"set {manifest.set_name} {manifest.set_version} expired at "
            f"{manifest.valid_until}; a newer set is probably published"
        )


def _our_version() -> str:
    try:
        from importlib.metadata import version

        return version("glaurung")
    except Exception:
        return "0.0.0"


def _fetch_offline(
    set_name: str,
    root: Path,
    trusted: Sequence[minisign.PublicKey],
    catalog: Catalog,
    only: Iterable[str] | None,
) -> FetchResult:
    """Cache first, then the bundled set. Never the network."""
    manifest_file = cached_manifest_path(root)
    signature_file = cached_signature_path(root)
    if manifest_file.is_file() and signature_file.is_file():
        manifest_bytes = manifest_file.read_bytes()
        signature_bytes = signature_file.read_bytes()
        manifest, key = _verify_manifest_bytes(
            manifest_bytes, signature_bytes.decode("utf-8", "replace"), trusted
        )
        if manifest.set_name == set_name:
            result = FetchResult(
                manifest=manifest,
                root=root,
                source=str(manifest_file),
                verified_by=key.key_id_hex,
            )
            _account_offline(manifest, root, result, only)
            _commit(
                root,
                catalog,
                manifest,
                result,
                manifest_bytes,
                signature_bytes,
                key.key_id_hex,
            )
            return result

    bundled = bundled_manifest_path()
    if not bundled.is_file():
        raise OfflineError(
            f"{set_name!r} is not cached at {root} and no bundled set ships "
            "with this installation"
        )
    manifest_bytes = bundled.read_bytes()
    signature_bytes = bundled_signature_path().read_bytes()
    manifest, key = _verify_manifest_bytes(
        manifest_bytes, signature_bytes.decode("utf-8", "replace"), trusted
    )
    if manifest.set_name != set_name:
        raise OfflineError(
            f"{set_name!r} is not cached at {root}; the bundled set is "
            f"{manifest.set_name!r}"
        )
    result = FetchResult(
        manifest=manifest,
        root=root,
        source=f"bundled:{bundled}",
        verified_by=key.key_id_hex,
    )
    _account_offline(manifest, root, result, only, bundled_dir=bundled_blob_dir())
    _commit(
        root,
        catalog,
        manifest,
        result,
        manifest_bytes,
        signature_bytes,
        key.key_id_hex,
    )
    return result


def _account_offline(
    manifest: Manifest,
    root: Path,
    result: FetchResult,
    only: Iterable[str] | None,
    bundled_dir: Path | None = None,
) -> None:
    wanted = set(only) if only is not None else None
    for blob in manifest.blobs:
        if wanted is not None and blob.key not in wanted:
            continue
        target = blob_path(blob.sha256, root)
        if target.is_file() and target.stat().st_size == blob.size_bytes:
            result.already_cached.append(blob.key)
            continue
        source = bundled_dir / blob.sha256 if bundled_dir is not None else None
        if source is not None and source.is_file():
            # A bundled blob is copied into the cache so the loader has one
            # place to look, and so a later online fetch treats it as present.
            _install_bundled(source, blob, root)
            result.downloaded.append(blob.key)
            result.bytes_downloaded += blob.size_bytes
            continue
        result.skipped.append(blob.key)
    if result.skipped:
        result.warnings.append(
            f"{len(result.skipped)} blob(s) are not cached and cannot be "
            "fetched offline"
        )


def _install_bundled(source: Path, blob: BlobEntry, root: Path) -> None:
    digest = _sha256_file(source)
    if digest != blob.sha256:
        raise BlobVerificationError(
            f"bundled blob {source.name} hashes to {digest}, but the bundled "
            f"manifest names {blob.sha256}"
        )
    root.mkdir(parents=True, exist_ok=True)
    target = blob_path(blob.sha256, root)
    tmp = target.with_name(target.name + ".part")
    shutil.copyfile(source, tmp)
    os.replace(tmp, target)


# --- blob download -----------------------------------------------------------


def _materialize(
    manifest: Manifest,
    root: Path,
    result: FetchResult,
    *,
    only: Iterable[str] | None,
    timeout: float,
    progress: ProgressHook | None,
) -> None:
    wanted = set(only) if only is not None else None
    root.mkdir(parents=True, exist_ok=True)
    for blob in manifest.blobs:
        if wanted is not None and blob.key not in wanted:
            continue
        target = blob_path(blob.sha256, root)
        if target.is_file() and target.stat().st_size == blob.size_bytes:
            result.already_cached.append(blob.key)
            if progress is not None:
                progress(blob.key, blob.size_bytes, blob.size_bytes)
            continue
        _download_blob(blob, root, timeout=timeout, progress=progress)
        result.downloaded.append(blob.key)
        result.bytes_downloaded += blob.size_bytes


def _download_blob(
    blob: BlobEntry,
    root: Path,
    *,
    timeout: float,
    progress: ProgressHook | None,
) -> Path:
    """Download one blob from the first mirror that answers, resuming if possible."""
    if not blob.urls:
        raise FetchError(f"blob {blob.key!r} lists no URLs")
    partial_dir = root / ".partial"
    partial_dir.mkdir(parents=True, exist_ok=True)
    partial = partial_dir / f"{blob.sha256}.part"

    errors: list[str] = []
    for url in blob.urls:
        offset = partial.stat().st_size if partial.is_file() else 0
        if offset >= blob.size_bytes:
            # A leftover partial at or past the full size is not resumable
            # evidence of anything; start again rather than guess.
            partial.unlink(missing_ok=True)
            offset = 0
        try:
            body, resumed = _get(url, timeout=timeout, offset=offset)
        except FetchError as exc:
            errors.append(str(exc))
            continue
        with partial.open("ab" if (resumed and offset) else "wb") as handle:
            handle.write(body)
        if progress is not None:
            progress(blob.key, partial.stat().st_size, blob.size_bytes)
        digest = _sha256_file(partial)
        if digest != blob.sha256:
            # Content-addressing means this is unambiguous: whatever arrived,
            # it is not the blob the signed manifest names. Delete it -- a
            # bad partial must never be resumed into a "successful" fetch.
            partial.unlink(missing_ok=True)
            errors.append(
                f"{url}: sha256 mismatch, got {digest}, expected {blob.sha256}"
            )
            continue
        target = blob_path(blob.sha256, root)
        os.replace(partial, target)
        return target

    raise BlobVerificationError(
        f"could not fetch blob {blob.key!r} ({blob.sha256}):\n  " + "\n  ".join(errors)
    )


# --- reading the cache back --------------------------------------------------


def resolve(key: str, root: Path | None = None) -> Path | None:
    """The cached file for a library key, or None. Bundled blobs included."""
    root = Path(root) if root is not None else cache_root()
    entry = Catalog.load(root).get(key)
    if entry is not None:
        candidate = blob_path(entry.sha256, root)
        if candidate.is_file():
            return candidate
    bundled = bundled_manifest_path()
    if bundled.is_file():
        try:
            manifest = Manifest.read(bundled)
        except (ManifestError, OSError):
            return None
        blob = manifest.by_key(key)
        if blob is not None:
            candidate = bundled_blob_dir() / blob.sha256
            if candidate.is_file():
                return candidate
    return None


def verify_cache(
    root: Path | None = None,
    *,
    keys: Sequence[minisign.PublicKey] | None = None,
    deep: bool = True,
) -> tuple[Manifest | None, list[str]]:
    """Re-verify the cached manifest and every cached blob's digest.

    `deep=False` checks sizes only, which is what the fetch path does; the
    point of `deep=True` is to catch bit-rot and hand edits that a size check
    cannot see.

    Returns the verified manifest (or None if none is cached) and a list of
    problems, empty when the cache is sound.
    """
    root = Path(root) if root is not None else cache_root()
    trusted = list(keys) if keys is not None else load_trusted_keys()
    problems: list[str] = []

    manifest_file = cached_manifest_path(root)
    signature_file = cached_signature_path(root)
    if not manifest_file.is_file():
        manifest_file = bundled_manifest_path()
        signature_file = bundled_signature_path()
        if not manifest_file.is_file():
            return None, ["no manifest is cached and none is bundled"]
    try:
        manifest, _ = _verify_manifest_bytes(
            manifest_file.read_bytes(),
            signature_file.read_text(encoding="utf-8"),
            trusted,
        )
    except FetchError as exc:
        return None, [str(exc)]

    catalog = Catalog.load(root)
    for blob in manifest.blobs:
        path = blob_path(blob.sha256, root)
        if not path.is_file():
            bundled = bundled_blob_dir() / blob.sha256
            if bundled.is_file():
                path = bundled
            else:
                continue
        size = path.stat().st_size
        if size != blob.size_bytes:
            problems.append(
                f"{blob.key}: cached size {size} != manifest {blob.size_bytes}"
            )
            continue
        if deep:
            digest = _sha256_file(path)
            if digest != blob.sha256:
                problems.append(
                    f"{blob.key}: cached sha256 {digest} != manifest {blob.sha256}"
                )
    if catalog.serial and manifest.serial != catalog.serial:
        problems.append(
            f"catalog records serial {catalog.serial} but the cached manifest "
            f"is serial {manifest.serial}"
        )
    return manifest, problems
