"""Where signature data lives, resolved without ever consulting the cwd.

Three roots, and the reason each exists:

``bundled_data_dir()``
    Read-only files that ship *inside the distribution*: the manifest JSON
    Schema, the trusted minisign public keys, the signed bundled manifest,
    and the tiny content-addressed ``base`` blobs it names. This is the "a
    fresh install with no network still works" path.

``cache_root()``
    The writable content-addressed cache, ``~/.cache/glaurung/sigs/``, or
    whatever ``GLAURUNG_SIG_DIR`` names. Blobs are files named by their
    sha256; ``catalog.json`` maps library keys to those names. The Rust
    loader in ``src/flirt/`` reads the same directory by the same convention.

``keys_dir()``
    Which minisign public keys are trusted, defaulting to the bundled
    ``trusted-keys/`` so key rotation is a release, not a config edit.

The cwd is deliberately not in any of these. ``src/flirt/mod.rs``'s
``default_library_path`` resolves ``data/sigs/…`` relative to
``std::env::current_dir()``, which means the shipped library is found only
when you happen to run from a source checkout -- the exact defect the
bundled-fallback path exists to fix.
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = [
    "ENV_CACHE_DIR",
    "ENV_DATA_DIR",
    "ENV_KEYS_DIR",
    "ENV_MANIFEST_URL",
    "ENV_OFFLINE",
    "blob_path",
    "bundled_data_dir",
    "cache_root",
    "catalog_path",
    "default_manifest_url",
    "is_offline",
    "keys_dir",
    "schema_path",
]

#: Overrides the content-addressed cache root. Shared with the Rust loader,
#: whose resolution order is `GLAURUNG_SIG_DIR`, then `~/.cache/glaurung/sigs/`,
#: then the bundled `base` set.
ENV_CACHE_DIR = "GLAURUNG_SIG_DIR"

#: Forbids all network access in the fetch path. Mirrors `HF_HUB_OFFLINE`.
ENV_OFFLINE = "GLAURUNG_SIGS_OFFLINE"

#: Overrides where the signed manifest is fetched from -- a mirror, or a
#: `file://` URL, which is what the end-to-end test uses.
ENV_MANIFEST_URL = "GLAURUNG_SIGS_MANIFEST_URL"

#: Overrides the bundled read-only data directory. Exists so a test can point
#: at a wheel unpacked into a temporary directory and prove the *installed*
#: layout resolves, rather than only ever exercising the source tree.
ENV_DATA_DIR = "GLAURUNG_SIGS_DATA_DIR"

#: Overrides the trusted-key directory. A local key can be trusted for a dry
#: run without editing the shipped set.
ENV_KEYS_DIR = "GLAURUNG_SIGS_TRUSTED_KEYS"

#: Where the human publishes. Only a default: `--manifest-url`, the env var
#: above, and every mirror URL inside the manifest all override it.
DEFAULT_MANIFEST_URL = "https://github.com/glaurung-re/glaurung-sigs/releases/latest/download/manifest.json"

_TRUE = frozenset({"1", "true", "yes", "on"})

_THIS = Path(__file__).resolve()


def _data_dir_candidates() -> list[Path]:
    """Every layout `data/sigs/` can be in, in preference order.

    `parents[3]` is the repository root in a source checkout
    (`sigs/` -> `glaurung/` -> `python/` -> root), and `parents[2]` is
    site-packages in an installed wheel (`sigs/` -> `glaurung/` ->
    site-packages), because maturin's `include` preserves a path relative to
    the project root for any file that is not under `python-source`. Both are
    computed from `__file__`; neither reads the cwd.
    """
    return [
        _THIS.parents[3] / "data" / "sigs",
        _THIS.parents[2] / "data" / "sigs",
    ]


def bundled_data_dir() -> Path:
    """The read-only bundled signature data directory.

    Returns the first candidate that exists; if none does -- which would mean
    a distribution built without the `data/sigs/*` include -- the source-tree
    candidate is returned anyway, so the caller reports a missing *file*
    rather than a confusing missing *directory*.
    """
    override = os.environ.get(ENV_DATA_DIR)
    if override:
        return Path(override)
    candidates = _data_dir_candidates()
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[0]


def schema_path() -> Path:
    """The manifest JSON Schema that ships with the distribution."""
    return bundled_data_dir() / "manifest.schema.json"


def bundled_manifest_path() -> Path:
    return bundled_data_dir() / "bundled-manifest.json"


def bundled_signature_path() -> Path:
    return bundled_data_dir() / "bundled-manifest.json.minisig"


def bundled_blob_dir() -> Path:
    """Content-addressed bundled blobs, named by sha256 exactly as in the cache."""
    return bundled_data_dir() / "base"


def keys_dir() -> Path:
    override = os.environ.get(ENV_KEYS_DIR)
    if override:
        return Path(override)
    return bundled_data_dir() / "trusted-keys"


def cache_root() -> Path:
    """The writable content-addressed cache root. Not created here."""
    override = os.environ.get(ENV_CACHE_DIR)
    if override:
        return Path(override)
    return Path.home() / ".cache" / "glaurung" / "sigs"


def blob_path(sha256: str, root: Path | None = None) -> Path:
    """Where a blob with this digest lives in the cache."""
    return (root or cache_root()) / sha256


def catalog_path(root: Path | None = None) -> Path:
    return (root or cache_root()) / "catalog.json"


def cached_manifest_path(root: Path | None = None) -> Path:
    return (root or cache_root()) / "manifest.json"


def cached_signature_path(root: Path | None = None) -> Path:
    return (root or cache_root()) / "manifest.json.minisig"


def is_offline(explicit: bool | None = None) -> bool:
    """Whether the fetch path may touch the network.

    An explicit argument always wins, so a caller that means "go online" is
    not silently overridden by an environment the user forgot about.
    """
    if explicit is not None:
        return explicit
    return os.environ.get(ENV_OFFLINE, "").strip().lower() in _TRUE


def default_manifest_url() -> str:
    return os.environ.get(ENV_MANIFEST_URL) or DEFAULT_MANIFEST_URL
