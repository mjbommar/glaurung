"""Persistent, content-addressed cache for expensive CLI sub-operations.

This module backs the ``--cache-dir`` flag / ``GLAURUNG_CACHE_DIR`` env var
plumbed through :mod:`glaurung.cli.commands.decompile` and
:mod:`glaurung.cli.commands.name_func`. The cache is best-effort: any I/O
error from the cache path is logged at WARNING and the caller falls back
to the un-cached path. Cache misses never propagate as user-facing
errors.

Layout under ``<cache_dir>``::

    decomp/<glaurung_version>/<sha256>/<va_hex>.<flags_hash>.c
    name-func/<glaurung_version>/<sha256>/<va_hex>.<flags_hash>.json

* ``<glaurung_version>`` is :func:`importlib.metadata.version("glaurung")`
  so version bumps invalidate cleanly without manual clearing.
* ``<sha256>`` is a chunked-read hex SHA-256 of the binary file's bytes.
* ``<va_hex>`` is the function VA in lowercase hex, no ``0x`` prefix.
* ``<flags_hash>`` is the first 8 hex chars of SHA-256 of a canonical
  JSON encoding of the decompile-affecting flags. This keeps two
  different invocations (e.g. ``--style plain`` vs ``--style c``) from
  clobbering each other.

The cache is append-only by design. There is no eviction or size
limit; operators clear ``<cache_dir>`` manually if disk pressure
becomes an issue.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger(__name__)

_HASH_CHUNK = 1 << 20  # 1 MiB chunks for sha256(file)


def get_glaurung_version() -> str:
    """Return a stable version tag for cache namespacing.

    Uses ``importlib.metadata.version("glaurung")`` when available;
    falls back to ``"unknown"`` (so caches still work for editable /
    in-tree dev installs that haven't registered metadata).
    """

    try:
        return metadata.version("glaurung")
    except metadata.PackageNotFoundError:  # pragma: no cover — dev path
        return "unknown"


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 of ``path``'s bytes, chunked.

    Raises whatever :func:`open` would raise on read errors so the
    caller can degrade gracefully.
    """

    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_HASH_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def flags_hash(flags: dict[str, Any]) -> str:
    """Return a short stable hash (8 hex chars) of a flag dict.

    The dict is canonicalised by sorting keys and JSON-encoding with
    ``sort_keys=True`` + ``separators=(",", ":")``. Only the first 8
    hex chars of SHA-256 are used — eight hex chars is 32 bits of
    entropy, which is plenty for the (binary, va) namespace this hash
    lives inside.
    """

    canonical = json.dumps(flags, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:8]


def va_to_key(va: int) -> str:
    """Render a VA as lowercase hex without ``0x``."""

    return f"{int(va):x}"


@dataclass(frozen=True)
class CachePaths:
    """Concrete on-disk paths for a single cache entry."""

    cache_dir: Path
    namespace: str  # "decomp" or "name-func"
    glaurung_version: str
    binary_sha256: str
    va_hex: str
    flags_hash: str
    suffix: str  # ".c", ".plain.c", ".json", ...

    @property
    def dir(self) -> Path:
        return (
            self.cache_dir / self.namespace / self.glaurung_version / self.binary_sha256
        )

    @property
    def file(self) -> Path:
        return self.dir / f"{self.va_hex}.{self.flags_hash}{self.suffix}"


def build_paths(
    cache_dir: Path | str,
    *,
    namespace: str,
    binary_sha256: str,
    va: int,
    flags: dict[str, Any],
    suffix: str,
) -> CachePaths:
    """Helper to assemble :class:`CachePaths` from raw inputs."""

    return CachePaths(
        cache_dir=Path(cache_dir),
        namespace=namespace,
        glaurung_version=get_glaurung_version(),
        binary_sha256=binary_sha256,
        va_hex=va_to_key(va),
        flags_hash=flags_hash(flags),
        suffix=suffix,
    )


def read_text(paths: CachePaths) -> str | None:
    """Best-effort read of a text cache entry.

    Returns the entry's contents on hit, ``None`` on miss or any I/O
    failure. Cache errors are logged at WARNING and swallowed.
    """

    target = paths.file
    try:
        if not target.exists():
            return None
        return target.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("cache: read failed for %s: %s", target, exc)
        return None


def write_text(paths: CachePaths, body: str) -> None:
    """Best-effort atomic write of a text cache entry.

    Writes ``<file>.part`` via :class:`tempfile.NamedTemporaryFile` in
    the destination directory, then :func:`os.replace`s into place.
    Errors are logged and swallowed.
    """

    target = paths.file
    try:
        paths.dir.mkdir(parents=True, exist_ok=True)
        # NamedTemporaryFile in the destination dir guarantees that the
        # subsequent os.replace is a same-filesystem rename, which is
        # atomic on POSIX and Windows.
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(paths.dir),
            prefix=target.name + ".",
            suffix=".part",
            delete=False,
        ) as tmp:
            tmp.write(body)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = tmp.name
        os.replace(tmp_path, target)
    except OSError as exc:
        log.warning("cache: write failed for %s: %s", target, exc)
        # Best-effort cleanup of any leftover .part file.
        try:
            for leftover in paths.dir.glob(target.name + ".*.part"):
                leftover.unlink(missing_ok=True)
        except OSError:
            pass


def resolve_cache_dir(arg_value: str | None) -> Path | None:
    """Resolve the effective cache dir from CLI arg + env fallback.

    Precedence: explicit ``--cache-dir`` > ``GLAURUNG_CACHE_DIR`` env >
    ``None`` (caching disabled). Returns an absolute :class:`Path` or
    ``None``.
    """

    raw = arg_value or os.environ.get("GLAURUNG_CACHE_DIR") or None
    if not raw:
        return None
    return Path(raw).expanduser()


def canonical_flag_dict(items: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    """Normalise a sequence of (key, value) pairs into a canonical dict.

    ``None`` values are kept (they signal "default"), but bool /
    numeric values are passed through unchanged. The returned dict is
    insertion-ordered by sorted key to keep diff noise low.
    """

    out: dict[str, Any] = {}
    for key, value in sorted(items, key=lambda kv: kv[0]):
        out[key] = value
    return out
