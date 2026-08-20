"""The whole-binary bundle carries what no other artifact does.

Before this, Glaurung could not emit the one thing it exists to produce. The
annotations lived in `export --output-format json`, the decompiled code in
`decompile --all` (never persisted), and the file metadata in `triage --json` —
three disjoint slices in three unrelated schemas, and no artifact held more than
two of the four things an analyst needs.

These tests assert the *difference*, not the presence. A test that checked
"bundle returns a dict with functions" would pass against the old export too;
what matters is the fields the old one could never carry — cross-references,
content-derived identity, and decompiled bodies — and that provenance survives
the trip rather than being flattened into bare strings.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import realistic_corpus  # noqa: E402

from glaurung.llm.kb import bundle, export, xref_db  # noqa: E402
from glaurung.llm.kb.persistent import PersistentKnowledgeBase  # noqa: E402

VA = 0x1380


@pytest.fixture
def populated(tmp_path):
    """A KB with one function annotated from two different sources."""
    binary = str(realistic_corpus.variant_path("dwarf"))
    kb = PersistentKnowledgeBase.open(str(tmp_path / "b.glaurung"), binary_path=binary)
    xref_db.set_function_name(kb, VA, "opaque_always_true", set_by="dwarf")
    xref_db.set_comment(kb, VA, "an analyst note", set_by="manual")
    return kb, binary


pytestmark = pytest.mark.skipif(
    bool(realistic_corpus.missing_tools()),
    reason="needs " + ", ".join(realistic_corpus.missing_tools() or ["-"]),
)


def test_the_bundle_carries_fields_the_flat_export_cannot(populated):
    """The point of the artifact: structure alongside annotation.

    `export_kb` has no concept of a function — it is a set of annotation tables
    keyed by address. The bundle is function-centric, and each function carries
    the cross-references that the flat export drops entirely.
    """
    kb, binary = populated
    flat = export.export_kb(kb)
    rich = bundle.build(kb, binary_path=binary)

    assert "functions" not in flat, (
        "the flat export grew a functions key; this test is comparing the wrong "
        "two things and needs rewriting"
    )
    assert rich["functions"], "the bundle found no functions at all"
    function = rich["functions"][0]
    for field in ("entry_va", "name", "prototype", "stack_vars", "xrefs"):
        assert field in function, (
            f"bundle function is missing {field!r}: {sorted(function)}"
        )


def test_provenance_survives_the_trip(populated):
    """A name is a string plus who said so, and the pair has to arrive together.

    Every interchange format surveyed drops this. A consumer that cannot tell a
    DWARF name from a guess cannot make decisions with it.
    """
    kb, binary = populated
    rich = bundle.build(kb, binary_path=binary)
    named = [f for f in rich["functions"] if f.get("name")]
    assert named, "no named function in the bundle"
    assert named[0]["name"]["set_by"] == "dwarf", (
        f"provenance was flattened away: {named[0]['name']}"
    )


def test_absence_is_recorded_rather_than_implied(populated):
    """`null` and "not present" mean different things to a consumer.

    A function with no recovered prototype must say so, so that "we looked and
    found nothing" is distinguishable from "this was never examined".
    """
    kb, binary = populated
    rich = bundle.build(kb, binary_path=binary)
    function = rich["functions"][0]
    assert "prototype" in function and function["prototype"] is None, (
        "a function with no prototype should carry an explicit null, got "
        f"{function.get('prototype')!r}"
    )


def test_bodies_are_opt_in_and_actually_decompile(populated):
    """The expensive part is opt-in, and when asked for it must be real.

    Decompilation costs orders of magnitude more than everything else here, so
    the default omits it. When requested, a body that is always `None` would be
    a silently useless artifact, so this asserts real text comes back.
    """
    kb, binary = populated
    without = bundle.build(kb, binary_path=binary, include_bodies=False)
    assert without["counts"]["with_body"] == 0
    assert "body" not in without["functions"][0]

    with_bodies = bundle.build(kb, binary_path=binary, include_bodies=True)
    body = with_bodies["functions"][0].get("body")
    assert body is not None, "include_bodies produced no body field at all"
    assert body.get("text"), (
        f"include_bodies produced an empty body: {body.get('error', '(no error)')}"
    )
    assert with_bodies["counts"]["with_body"] == 1


def test_bodies_require_the_image_and_say_so(populated):
    """Decompilation reads the binary, not the KB — refuse rather than emit nulls."""
    kb, _binary = populated
    with pytest.raises(ValueError, match="binary_path"):
        bundle.build(kb, include_bodies=True)


def test_the_bundle_is_json_serialisable(populated):
    """An artifact that cannot be written to a file is not an artifact."""
    import json

    kb, binary = populated
    text = json.dumps(bundle.build(kb, binary_path=binary))
    assert json.loads(text)["schema"] == bundle.SCHEMA


def test_the_bundle_names_the_exact_image_it_describes(populated):
    """Binary identity is the anchor; a bundle without it is undeliverable.

    Read from the `binaries` row rather than recomputed from `binary_path`,
    because recomputing would silently describe a *different* file if the caller
    passed the wrong one — and a bundle that misidentifies its subject is worse
    than one that omits the field.
    """
    import hashlib

    kb, binary = populated
    rich = bundle.build(kb, binary_path=binary)
    identity = rich["binary"]
    assert identity["sha256"], f"bundle carries no binary identity: {identity}"
    on_disk = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    assert identity["sha256"] == on_disk, (
        f"bundle names {identity['sha256'][:16]} but the image on disk hashes "
        f"{on_disk[:16]} — the artifact is describing the wrong file"
    )
