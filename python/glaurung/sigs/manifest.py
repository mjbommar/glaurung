"""The signed, content-addressed distribution manifest.

One JSON document describes a whole signature *set*: which blobs it contains,
what each one is, where it came from, and where to get it. Blobs are named by
their sha256 on disk and in every URL, so mirrors are interchangeable, a stale
mirror cannot serve a mismatched file under a live name, and the 26-43 percent
signature overlap measured between adjacent releases of one distro
deduplicates for free once the corpus is split per library per release.

The manifest is the *only* signed object. Each blob's sha256 is inside it, so
one Ed25519 signature transitively covers the set -- Nix's `narinfo` model,
and the reason a blob needs no signature of its own.

Three fields exist purely as defences, and each is checked by
:mod:`glaurung.sigs.client`:

``serial``
    Monotonic. A client refuses a manifest whose serial is below the one it
    already has cached, so an attacker cannot replay a genuinely-signed older
    set to reintroduce a withdrawn blob. The serial is also copied into the
    minisign *trusted comment*, which is signed, so it cannot be edited.

``valid_until``
    A staleness horizon. Past it the client still works -- refusing would
    brick an air-gapped install -- but says so, which is the honest form of
    "this set is old" rather than a silent one.

``min_glaurung_version``
    The producer's statement that an older reader cannot correctly interpret
    this set. It is how a future `gsig/1` set says "you need a reader that
    understands chunked containers" without every old client mis-parsing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "BlobEntry",
    "Manifest",
    "ManifestError",
    "Provenance",
    "SCHEMA_VERSION",
    "parse_version",
    "validate_against_schema",
]

#: Bumped only on an incompatible manifest change. Every field added after
#: this version must be optional with a default equal to the v1 behaviour, the
#: same rule the FLIRT library JSON schema follows.
SCHEMA_VERSION = 1

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class ManifestError(ValueError):
    """A manifest is missing a field, has a wrong type, or fails a rule."""


def _require(obj: Mapping[str, Any], key: str, kind: type, where: str) -> Any:
    if key not in obj:
        raise ManifestError(f"{where}: missing required field {key!r}")
    value = obj[key]
    # bool is a subclass of int; a boolean where a count belongs is a defect.
    if kind is int and isinstance(value, bool):
        raise ManifestError(f"{where}.{key}: expected int, got bool")
    if not isinstance(value, kind):
        raise ManifestError(
            f"{where}.{key}: expected {kind.__name__}, got {type(value).__name__}"
        )
    return value


def _optional(obj: Mapping[str, Any], key: str, kind: type, where: str, default: Any):
    if key not in obj or obj[key] is None:
        return default
    return _require(obj, key, kind, where)


@dataclass(frozen=True)
class Provenance:
    """Enough to re-fetch the input and re-derive the blob from scratch.

    That is the legal position made operational: we redistribute signatures
    and names, never archives or objects, and every blob carries the pointer
    back to the package it was derived from so the derivation is reproducible
    by anyone who disbelieves it.
    """

    source: str
    package: str = ""
    version: str = ""
    arch: str = ""
    archive: str = ""
    input_sha256: str = ""
    input_sha1: str = ""
    variant: str = ""
    triplet: str = ""
    image: str = ""
    buildinfo: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"source": self.source}
        for name in (
            "package",
            "version",
            "arch",
            "archive",
            "input_sha256",
            "input_sha1",
            "variant",
            "triplet",
            "image",
            "buildinfo",
        ):
            value = getattr(self, name)
            if value:
                out[name] = value
        return out

    @classmethod
    def from_dict(
        cls, obj: Mapping[str, Any], where: str = "provenance"
    ) -> "Provenance":
        if not isinstance(obj, Mapping):
            raise ManifestError(f"{where}: expected an object")
        return cls(
            source=_require(obj, "source", str, where),
            package=_optional(obj, "package", str, where, ""),
            version=_optional(obj, "version", str, where, ""),
            arch=_optional(obj, "arch", str, where, ""),
            archive=_optional(obj, "archive", str, where, ""),
            input_sha256=_optional(obj, "input_sha256", str, where, ""),
            input_sha1=_optional(obj, "input_sha1", str, where, ""),
            variant=_optional(obj, "variant", str, where, ""),
            triplet=_optional(obj, "triplet", str, where, ""),
            image=_optional(obj, "image", str, where, ""),
            buildinfo=_optional(obj, "buildinfo", str, where, ""),
        )


@dataclass(frozen=True)
class BlobEntry:
    """One `(scheme, library, version, variant, arch)` key, as one file."""

    #: `<library>/<version>/<variant>/<arch>` -- the unit of usefulness. No
    #: exact or masked scheme crosses an optimisation level, so a corpus
    #: spanning compilers and `-O` levels is N keys, not one.
    key: str
    #: The identity scheme the blob's records are under, e.g.
    #: `flirt-masked-pattern-v1` or `warp-function-guid-v1`. Matches
    #: `glaurung.llm.kb.siglib`'s scheme constants.
    kind: str
    #: The container the bytes are in: `flirt-json/2` today, `gsig/1` once the
    #: chunked container lands. A client that does not know a format skips the
    #: blob rather than mis-parsing it.
    format: str
    #: Transport compression of the stored bytes. `none` today -- see
    #: docs/reference/signature-distribution.md for why the cache holds
    #: uncompressed blobs.
    compression: str
    #: sha256 of the stored bytes; the blob's name on disk and in every URL.
    sha256: str
    size_bytes: int
    uncompressed_bytes: int
    signatures: int
    licence: str
    provenance: Provenance
    urls: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _SHA256_RE.match(self.sha256):
            raise ManifestError(
                f"blob {self.key!r}: sha256 must be 64 lowercase hex digits, "
                f"got {self.sha256!r}"
            )
        if self.size_bytes < 0 or self.uncompressed_bytes < 0:
            raise ManifestError(f"blob {self.key!r}: negative size")
        if self.compression == "none" and self.size_bytes != self.uncompressed_bytes:
            raise ManifestError(
                f"blob {self.key!r}: compression is 'none' but size_bytes "
                f"{self.size_bytes} != uncompressed_bytes {self.uncompressed_bytes}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "kind": self.kind,
            "format": self.format,
            "compression": self.compression,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "uncompressed_bytes": self.uncompressed_bytes,
            "signatures": self.signatures,
            "licence": self.licence,
            "provenance": self.provenance.to_dict(),
            "urls": list(self.urls),
        }

    @classmethod
    def from_dict(cls, obj: Mapping[str, Any], index: int = 0) -> "BlobEntry":
        if not isinstance(obj, Mapping):
            raise ManifestError(f"blobs[{index}]: expected an object")
        where = f"blobs[{index}]"
        urls = _optional(obj, "urls", list, where, [])
        for position, url in enumerate(urls):
            if not isinstance(url, str):
                raise ManifestError(f"{where}.urls[{position}]: expected a string")
        return cls(
            key=_require(obj, "key", str, where),
            kind=_require(obj, "kind", str, where),
            format=_require(obj, "format", str, where),
            compression=_optional(obj, "compression", str, where, "none"),
            sha256=_require(obj, "sha256", str, where),
            size_bytes=_require(obj, "size_bytes", int, where),
            uncompressed_bytes=_optional(
                obj,
                "uncompressed_bytes",
                int,
                where,
                _require(obj, "size_bytes", int, where),
            ),
            signatures=_optional(obj, "signatures", int, where, 0),
            licence=_optional(obj, "licence", str, where, ""),
            provenance=Provenance.from_dict(
                _require(obj, "provenance", dict, where), f"{where}.provenance"
            ),
            urls=tuple(urls),
        )


@dataclass(frozen=True)
class Manifest:
    """A whole signature set, signed as one document."""

    set_name: str
    set_version: str
    serial: int
    built_utc: str
    valid_until: str
    min_glaurung_version: str
    blobs: tuple[BlobEntry, ...] = ()
    schema_version: int = SCHEMA_VERSION
    #: Free-form producer note; never trusted for anything.
    notice: str = ""

    def __post_init__(self) -> None:
        if not _SET_NAME_RE.match(self.set_name):
            raise ManifestError(
                f"set name {self.set_name!r} must match {_SET_NAME_RE.pattern}"
            )
        if self.serial < 1:
            raise ManifestError(f"serial must be >= 1, got {self.serial}")
        seen: dict[str, str] = {}
        for blob in self.blobs:
            if blob.key in seen:
                raise ManifestError(f"duplicate blob key {blob.key!r}")
            seen[blob.key] = blob.sha256

    # -- lookup ---------------------------------------------------------------

    def by_key(self, key: str) -> BlobEntry | None:
        for blob in self.blobs:
            if blob.key == key:
                return blob
        return None

    def by_sha256(self, digest: str) -> BlobEntry | None:
        for blob in self.blobs:
            if blob.sha256 == digest:
                return blob
        return None

    @property
    def total_bytes(self) -> int:
        return sum(blob.size_bytes for blob in self.blobs)

    @property
    def total_signatures(self) -> int:
        return sum(blob.signatures for blob in self.blobs)

    def is_expired(self, now: datetime | None = None) -> bool:
        """Whether `valid_until` has passed. An unparseable date is not expired."""
        try:
            until = datetime.fromisoformat(self.valid_until.replace("Z", "+00:00"))
        except ValueError:
            return False
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        return (now or datetime.now(timezone.utc)) > until

    def trusted_comment(self) -> str:
        """What goes in minisign's signed trusted-comment field.

        Set name, version and serial, so the downgrade defence cannot be
        defeated by editing the manifest's unsigned copy of the same numbers:
        the client compares this against the manifest body and refuses a
        mismatch.
        """
        return (
            f"glaurung-sigs set={self.set_name} version={self.set_version} "
            f"serial={self.serial} blobs={len(self.blobs)} built={self.built_utc}"
        )

    # -- serialisation --------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "schema_version": self.schema_version,
            "set": self.set_name,
            "set_version": self.set_version,
            "serial": self.serial,
            "built_utc": self.built_utc,
            "valid_until": self.valid_until,
            "min_glaurung_version": self.min_glaurung_version,
            "blobs": [
                blob.to_dict() for blob in sorted(self.blobs, key=lambda b: b.key)
            ],
        }
        if self.notice:
            out["notice"] = self.notice
        return out

    def to_json(self) -> str:
        """Deterministic bytes: sorted keys, sorted blobs, fixed indent.

        A manifest that re-serialises differently would break the signature
        for no reason, and would make "did this release change?" unanswerable
        by diff.
        """
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_dict(cls, obj: Mapping[str, Any]) -> "Manifest":
        if not isinstance(obj, Mapping):
            raise ManifestError("manifest: expected a JSON object")
        where = "manifest"
        schema_version = _require(obj, "schema_version", int, where)
        if schema_version > SCHEMA_VERSION:
            raise ManifestError(
                f"manifest schema_version {schema_version} is newer than this "
                f"client understands ({SCHEMA_VERSION}); upgrade glaurung"
            )
        raw_blobs = _require(obj, "blobs", list, where)
        return cls(
            schema_version=schema_version,
            set_name=_require(obj, "set", str, where),
            set_version=_require(obj, "set_version", str, where),
            serial=_require(obj, "serial", int, where),
            built_utc=_require(obj, "built_utc", str, where),
            valid_until=_require(obj, "valid_until", str, where),
            min_glaurung_version=_require(obj, "min_glaurung_version", str, where),
            blobs=tuple(
                BlobEntry.from_dict(entry, i) for i, entry in enumerate(raw_blobs)
            ),
            notice=_optional(obj, "notice", str, where, ""),
        )

    @classmethod
    def from_json(cls, text: str | bytes) -> "Manifest":
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ManifestError(f"manifest is not valid JSON: {exc}") from exc
        return cls.from_dict(obj)

    @classmethod
    def read(cls, path: str | Path) -> "Manifest":
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    def write(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_json(), encoding="utf-8")
        return target

    def with_blobs(self, blobs: Iterable[BlobEntry]) -> "Manifest":
        return replace(self, blobs=tuple(blobs))


# --- version comparison ------------------------------------------------------


def parse_version(text: str) -> tuple[int, ...]:
    """A dotted numeric version as a tuple, ignoring any suffix.

    `min_glaurung_version` is compared with this rather than with
    `packaging.version`, which is not a declared dependency. Only the numeric
    prefix is compared, so `0.9.0` and `0.9.0.dev3` order the same -- which is
    the conservative answer for a *minimum*: a dev build of 0.9.0 is treated
    as satisfying a 0.9.0 floor rather than being locked out.
    """
    parts: list[int] = []
    for chunk in text.strip().split("."):
        digits = ""
        for ch in chunk:
            if not ch.isdigit():
                break
            digits += ch
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) or (0,)


# --- JSON Schema -------------------------------------------------------------
#
# A dependency-free validator for the subset of JSON Schema `manifest.schema.json`
# uses. It exists so the schema file is *executed*, not decorative: a schema
# nothing checks is a second source of truth that silently drifts from the
# dataclasses above. `jsonschema` is not a declared dependency and this needs
# roughly forty lines, so adding one to run the other is the wrong trade.

_TYPES: dict[str, type | tuple[type, ...]] = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def _validate_node(
    value: Any, schema: Mapping[str, Any], where: str, errors: list[str]
) -> None:
    expected = schema.get("type")
    if expected is not None:
        kinds = _TYPES.get(expected)
        if kinds is None:
            errors.append(f"{where}: schema names unknown type {expected!r}")
            return
        if expected == "integer" and isinstance(value, bool):
            errors.append(f"{where}: expected integer, got boolean")
            return
        if expected != "boolean" and isinstance(value, bool) and kinds is not bool:
            errors.append(f"{where}: expected {expected}, got boolean")
            return
        if not isinstance(value, kinds):
            errors.append(f"{where}: expected {expected}, got {type(value).__name__}")
            return

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{where}: {value!r} is not one of {schema['enum']}")
    if isinstance(value, str) and "pattern" in schema:
        if re.search(schema["pattern"], value) is None:
            errors.append(f"{where}: {value!r} does not match {schema['pattern']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{where}: {value} < minimum {schema['minimum']}")
    if isinstance(value, dict):
        for name in schema.get("required", ()):
            if name not in value:
                errors.append(f"{where}: missing required property {name!r}")
        properties = schema.get("properties", {})
        for name, child in value.items():
            if name in properties:
                _validate_node(child, properties[name], f"{where}.{name}", errors)
            elif schema.get("additionalProperties") is False:
                errors.append(f"{where}: unexpected property {name!r}")
    if isinstance(value, list):
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for i, item in enumerate(value):
                _validate_node(item, item_schema, f"{where}[{i}]", errors)


def validate_against_schema(
    document: Mapping[str, Any], schema: Mapping[str, Any] | None = None
) -> Sequence[str]:
    """Every way `document` violates the manifest schema. Empty means valid."""
    if schema is None:
        from .paths import schema_path

        schema = json.loads(schema_path().read_text(encoding="utf-8"))
    errors: list[str] = []
    _validate_node(document, schema, "manifest", errors)
    return errors


def utc_now_iso() -> str:
    """`built_utc` in the one spelling the manifest uses."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
