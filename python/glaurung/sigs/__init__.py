"""Signed, content-addressed distribution of function-signature libraries.

The matcher was already precise; coverage was the whole problem. Measured on
2026-09-03, a glibc library built from this box's own `libc.a` names 731 of
1,090 text functions in a stripped `-O2 -static` binary with zero wrong -- and
the *same* binary against glibc libraries from Debian trixie, bookworm and
bullseye scores 1, 0 and 0. Cross-distro transfer is nil, so the unit of
usefulness is one library per `(library, version, variant, arch)`, the corpus
is 10^5 to 10^6 signatures rather than 10^3, and it cannot ship inside a wheel.

This package is the channel that gets it to a user's machine:

- :mod:`~glaurung.sigs.manifest` -- the signed, content-addressed manifest.
- :mod:`~glaurung.sigs.minisign` -- Ed25519 signing and verification in
  minisign's file formats.
- :mod:`~glaurung.sigs.client` -- fetch, verify, cache; the downgrade,
  offline and tamper defences.
- :mod:`~glaurung.sigs.catalog` -- the cache index the Rust loader reads.
- :mod:`~glaurung.sigs.paths` -- where everything lives, cwd-independently.

The user-facing surface is `glaurung sigs list|fetch|verify|status|path`, and
the reference is `docs/reference/signature-distribution.md`.
"""

from __future__ import annotations

from .catalog import Catalog, CatalogEntry
from .client import (
    BlobVerificationError,
    DowngradeError,
    FetchError,
    FetchResult,
    OfflineError,
    TrustError,
    fetch,
    load_trusted_keys,
    resolve,
    verify_cache,
)
from .manifest import (
    SCHEMA_VERSION,
    BlobEntry,
    Manifest,
    ManifestError,
    Provenance,
    validate_against_schema,
)
from .paths import (
    ENV_CACHE_DIR,
    ENV_DATA_DIR,
    ENV_KEYS_DIR,
    ENV_MANIFEST_URL,
    ENV_OFFLINE,
    blob_path,
    bundled_data_dir,
    cache_root,
    catalog_path,
    is_offline,
    keys_dir,
)

__all__ = [
    "BlobEntry",
    "BlobVerificationError",
    "Catalog",
    "CatalogEntry",
    "DowngradeError",
    "ENV_CACHE_DIR",
    "ENV_DATA_DIR",
    "ENV_KEYS_DIR",
    "ENV_MANIFEST_URL",
    "ENV_OFFLINE",
    "FetchError",
    "FetchResult",
    "Manifest",
    "ManifestError",
    "OfflineError",
    "Provenance",
    "SCHEMA_VERSION",
    "TrustError",
    "blob_path",
    "bundled_data_dir",
    "cache_root",
    "catalog_path",
    "fetch",
    "is_offline",
    "keys_dir",
    "load_trusted_keys",
    "resolve",
    "validate_against_schema",
    "verify_cache",
]
