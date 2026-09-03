"""The manifest model, its JSON Schema, and the invariants the client relies on.

The manifest is the only signed object in the distribution channel, so its
shape is a security boundary and not merely a data format. Two things are
therefore asserted here rather than assumed:

* serialisation is **deterministic** -- sorted keys, sorted blobs, fixed
  indent -- because a document that re-serialises differently breaks its own
  signature for no reason and makes "did this release change?" unanswerable
  by diff;
* the committed `data/sigs/manifest.schema.json` describes the dataclasses.
  A schema nothing executes is a second source of truth that drifts, which is
  why `validate_against_schema` implements the subset it uses instead of
  taking a dependency on `jsonschema`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from glaurung.sigs import manifest as m

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data" / "sigs"
SCHEMA = json.loads((DATA / "manifest.schema.json").read_text())

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def _blob(key: str = "libz/1.2.11/gcc-11-O2/x86_64", digest: str = DIGEST_A, **kw):
    fields = dict(
        key=key,
        kind="flirt-masked-pattern-v1",
        format="flirt-json/2",
        compression="none",
        sha256=digest,
        size_bytes=100,
        uncompressed_bytes=100,
        signatures=109,
        licence="derived signatures and names only",
        provenance=m.Provenance(
            source="snapshot.debian.org",
            package="zlib1g-dev",
            version="1:1.2.11.dfsg-2ubuntu9.2",
            arch="x86_64",
            input_sha256="c" * 64,
        ),
        urls=("https://example.invalid/blob/" + digest,),
    )
    fields.update(kw)
    return m.BlobEntry(**fields)


def _manifest(**kw) -> m.Manifest:
    fields = dict(
        set_name="base",
        set_version="2026.09.1",
        serial=41,
        built_utc="2026-09-03T12:00:00Z",
        valid_until="2027-03-03T00:00:00Z",
        min_glaurung_version="0.1.0",
        blobs=(_blob(),),
    )
    fields.update(kw)
    return m.Manifest(**fields)


# --- round trip and determinism ----------------------------------------------


def test_round_trips_through_json():
    original = _manifest()
    assert m.Manifest.from_json(original.to_json()) == original


def test_serialisation_is_deterministic_and_order_independent():
    """Two manifests differing only in blob order serialise identically."""
    one = _manifest(
        blobs=(_blob("a/1/v/x86_64", DIGEST_A), _blob("b/1/v/x86_64", DIGEST_B))
    )
    other = _manifest(
        blobs=(_blob("b/1/v/x86_64", DIGEST_B), _blob("a/1/v/x86_64", DIGEST_A))
    )
    assert one.to_json() == other.to_json()
    assert one.to_json() == one.to_json()


def test_a_manifest_ends_with_exactly_one_newline():
    """Signed bytes are the file's bytes; trailing-whitespace drift is a break."""
    text = _manifest().to_json()
    assert text.endswith("}\n")
    assert not text.endswith("\n\n")


# --- the invariants the client depends on ------------------------------------


def test_the_trusted_comment_carries_the_set_version_and_serial():
    comment = _manifest().trusted_comment()
    assert "set=base" in comment
    assert "version=2026.09.1" in comment
    assert "serial=41" in comment


def test_a_changed_serial_changes_the_trusted_comment():
    """Otherwise the downgrade defence would be unsigned."""
    assert (
        _manifest(serial=41).trusted_comment() != _manifest(serial=40).trusted_comment()
    )


def test_a_serial_below_one_is_refused():
    with pytest.raises(m.ManifestError, match="serial"):
        _manifest(serial=0)


def test_duplicate_blob_keys_are_refused():
    with pytest.raises(m.ManifestError, match="duplicate"):
        _manifest(blobs=(_blob(digest=DIGEST_A), _blob(digest=DIGEST_B)))


def test_a_malformed_digest_is_refused():
    for bad in ("A" * 64, "a" * 63, "", "not-a-digest"):
        with pytest.raises(m.ManifestError, match="sha256"):
            _blob(digest=bad)


def test_uncompressed_size_must_agree_when_compression_is_none():
    """A blob that claims no compression but two sizes is describing nothing."""
    with pytest.raises(m.ManifestError, match="compression"):
        _blob(size_bytes=100, uncompressed_bytes=200)


def test_a_newer_schema_version_is_refused_rather_than_misread():
    payload = _manifest().to_dict()
    payload["schema_version"] = m.SCHEMA_VERSION + 1
    with pytest.raises(m.ManifestError, match="newer than this client"):
        m.Manifest.from_dict(payload)


def test_missing_required_fields_name_themselves():
    payload = _manifest().to_dict()
    del payload["serial"]
    with pytest.raises(m.ManifestError, match="serial"):
        m.Manifest.from_dict(payload)


def test_a_boolean_where_a_count_belongs_is_a_type_error():
    payload = _manifest().to_dict()
    payload["serial"] = True
    with pytest.raises(m.ManifestError, match="bool"):
        m.Manifest.from_dict(payload)


def test_expiry_is_computed_from_valid_until():
    assert _manifest(valid_until="2000-01-01T00:00:00Z").is_expired()
    assert not _manifest(valid_until="2999-01-01T00:00:00Z").is_expired()
    # An unparseable date must not read as expired; that would be a silent
    # downgrade of the set's status on a typo.
    assert not _manifest(valid_until="whenever").is_expired()


def test_version_comparison_orders_dotted_numbers():
    assert m.parse_version("0.9.0") < m.parse_version("0.10.0")
    assert m.parse_version("1.0") > m.parse_version("0.99.99")
    # A dev suffix satisfies its own floor rather than being locked out.
    assert m.parse_version("0.9.0.dev3") >= m.parse_version("0.9.0")


# --- the schema file ---------------------------------------------------------


def test_a_valid_manifest_passes_the_committed_schema():
    assert m.validate_against_schema(_manifest().to_dict(), SCHEMA) == []


def test_the_schema_catches_what_the_dataclasses_catch():
    payload = _manifest().to_dict()
    payload["serial"] = 0
    assert any("minimum" in e for e in m.validate_against_schema(payload, SCHEMA))

    payload = _manifest().to_dict()
    payload["blobs"][0]["sha256"] = "nope"
    assert any(
        "does not match" in e for e in m.validate_against_schema(payload, SCHEMA)
    )

    payload = _manifest().to_dict()
    del payload["blobs"][0]["provenance"]
    assert any("provenance" in e for e in m.validate_against_schema(payload, SCHEMA))

    payload = _manifest().to_dict()
    payload["set"] = "Base Set"
    assert any(
        "does not match" in e for e in m.validate_against_schema(payload, SCHEMA)
    )


def test_the_schema_resolves_from_the_package_without_a_cwd():
    """`validate_against_schema` with no schema argument reads the shipped file."""
    assert m.validate_against_schema(_manifest().to_dict()) == []


def test_the_bundled_manifest_is_valid_against_the_shipped_schema():
    """The artefact we ship must satisfy the schema we ship."""
    bundled = json.loads((DATA / "bundled-manifest.json").read_text())
    assert m.validate_against_schema(bundled, SCHEMA) == []
    parsed = m.Manifest.from_dict(bundled)
    assert parsed.set_name == "base"
    assert parsed.blobs, "the bundled set must not be empty"
