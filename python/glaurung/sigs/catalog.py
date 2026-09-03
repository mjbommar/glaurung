"""`catalog.json`: the cache's own index, and the Rust loader's entry point.

The cache directory holds blobs named by sha256 and nothing else that says
what they are. `catalog.json` beside them maps a library key --
`<library>/<version>/<variant>/<arch>` -- to the digest that answers it, plus
the few facts a loader needs to decide whether it can read the file at all
(`format`, `kind`) without opening it.

This is the file `src/flirt/`'s resolution order consults after
`GLAURUNG_SIG_DIR`: the Rust side never verifies a signature, because
verification already happened here, at fetch time, before the bytes were
allowed into the cache. See the "Where verification lives" section of
`docs/reference/signature-distribution.md` for why that split is the right
one and what would change it.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Mapping

from .manifest import Manifest, utc_now_iso
from .paths import catalog_path

__all__ = ["Catalog", "CatalogEntry", "CATALOG_SCHEMA_VERSION"]

CATALOG_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class CatalogEntry:
    """One resolvable library key."""

    sha256: str
    format: str
    kind: str
    signatures: int = 0
    size_bytes: int = 0
    arch: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "format": self.format,
            "kind": self.kind,
            "signatures": self.signatures,
            "size_bytes": self.size_bytes,
            "arch": self.arch,
        }

    @classmethod
    def from_dict(cls, obj: Mapping[str, Any]) -> "CatalogEntry":
        return cls(
            sha256=str(obj.get("sha256", "")),
            format=str(obj.get("format", "")),
            kind=str(obj.get("kind", "")),
            signatures=int(obj.get("signatures", 0) or 0),
            size_bytes=int(obj.get("size_bytes", 0) or 0),
            arch=str(obj.get("arch", "")),
        )


@dataclass
class Catalog:
    """What the cache currently holds, for one set."""

    set_name: str = ""
    set_version: str = ""
    serial: int = 0
    verified_utc: str = ""
    manifest_sha256: str = ""
    #: Which public key verified the manifest that produced these entries.
    verified_by_key_id: str = ""
    entries: dict[str, CatalogEntry] = field(default_factory=dict)
    schema_version: int = CATALOG_SCHEMA_VERSION

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[str]:
        return iter(self.entries)

    def get(self, key: str) -> CatalogEntry | None:
        return self.entries.get(key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "set": self.set_name,
            "set_version": self.set_version,
            "serial": self.serial,
            "verified_utc": self.verified_utc,
            "manifest_sha256": self.manifest_sha256,
            "verified_by_key_id": self.verified_by_key_id,
            "entries": {
                key: entry.to_dict() for key, entry in sorted(self.entries.items())
            },
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_dict(cls, obj: Mapping[str, Any]) -> "Catalog":
        raw = obj.get("entries") or {}
        return cls(
            schema_version=int(obj.get("schema_version", CATALOG_SCHEMA_VERSION)),
            set_name=str(obj.get("set", "")),
            set_version=str(obj.get("set_version", "")),
            serial=int(obj.get("serial", 0) or 0),
            verified_utc=str(obj.get("verified_utc", "")),
            manifest_sha256=str(obj.get("manifest_sha256", "")),
            verified_by_key_id=str(obj.get("verified_by_key_id", "")),
            entries={
                key: CatalogEntry.from_dict(value)
                for key, value in raw.items()
                if isinstance(value, Mapping)
            },
        )

    @classmethod
    def load(cls, root: Path | None = None) -> "Catalog":
        """Read the catalog, or an empty one. A corrupt catalog is not fatal.

        The cache is reconstructible from the network, so a truncated
        `catalog.json` -- a machine that lost power mid-write, say -- should
        cost a re-fetch, not an unusable installation.
        """
        path = catalog_path(root)
        if not path.is_file():
            return cls()
        try:
            return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, ValueError, OSError):
            return cls()

    def save(self, root: Path | None = None) -> Path:
        """Write atomically: a reader never sees a half-written catalog."""
        path = catalog_path(root)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(self.to_json(), encoding="utf-8")
        os.replace(tmp, path)
        return path

    def update_from_manifest(
        self, manifest: Manifest, *, key_id: str = "", manifest_sha256: str = ""
    ) -> "Catalog":
        """Record what a verified manifest says, replacing the previous set state."""
        self.set_name = manifest.set_name
        self.set_version = manifest.set_version
        self.serial = manifest.serial
        self.verified_utc = utc_now_iso()
        self.verified_by_key_id = key_id
        self.manifest_sha256 = manifest_sha256
        return self

    def record(self, key: str, entry: CatalogEntry) -> None:
        self.entries[key] = entry
