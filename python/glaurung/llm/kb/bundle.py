"""One artifact carrying a whole binary's analysis: structure *and* annotation.

Glaurung could not previously emit what it exists to produce. Three artifacts
each held a disjoint slice, in three unrelated schemas:

* ``export --output-format json`` — annotations with no structure at all. Seven
  of the KB's tables, not one call edge, no function boundaries, no xrefs.
* ``decompile --all`` — pseudocode text with no annotations, never persisted.
* ``triage --format json`` — file metadata with no functions.

So the one thing an analyst actually wants — *this binary's functions, with
their boundaries, their decompiled bodies, their recovered types and their
cross-references, in one file* — could not be obtained, even though all four
live inside the system. This module is that file.

Design notes, and what they cost:

**Function identity travels with every function.** The KB keys everything on
``(binary_id, absolute VA)``, which does not survive a rebuild: recompile and
the sha256 changes, so every annotation is orphaned. Each function here also
carries its content-derived identity (``function_identity``), so a consumer can
re-attach annotations to a rebuilt binary. That is the difference between an
export and a durable record.

**Provenance travels with every fact that has one.** A name is not a string, it
is a string plus who said so. ``set_by`` is carried through rather than
flattened, because a consumer that cannot tell a DWARF name from a guess cannot
make decisions with it — and every surveyed interchange format drops exactly
this.

**Bodies are opt-in.** Decompiling every function is the expensive part by two
orders of magnitude, and a caller who wants the structural skeleton should not
pay for it. `include_bodies=False` is the fast path.

**Absence is recorded, not implied.** A function with no recovered prototype
carries ``"prototype": null`` rather than being silently omitted, so a consumer
can tell "we looked and found nothing" from "this was never examined".
"""

from __future__ import annotations

from typing import Any, Optional

from .persistent import PersistentKnowledgeBase

#: Bump only for a breaking change. New optional fields do not need one.
SCHEMA = "glaurung.bundle/1"


def _function_rows(kb: PersistentKnowledgeBase) -> list[dict[str, Any]]:
    """Every function the KB knows about, keyed by entry VA.

    Built from the union of the tables that mention a function rather than from
    any single one, because no table is authoritative: a function can have a
    name and no prototype, boundaries and no name, or xrefs and neither.
    """
    from . import xref_db as _xref_db

    by_va: dict[int, dict[str, Any]] = {}

    for row in _xref_db.list_function_names(kb):
        by_va.setdefault(row.entry_va, {})["name"] = {
            "value": row.canonical,
            "demangled": row.demangled,
            "aliases": list(row.aliases or []),
            "set_by": row.set_by,
        }

    cur = kb._conn.cursor()

    # Boundaries, where the Windows analysis recorded them.
    try:
        cur.execute(
            "SELECT function_va, start_va, end_va FROM function_boundaries "
            "WHERE binary_id = ?",
            (kb.binary_id,),
        )
        for function_va, start_va, end_va in cur.fetchall():
            entry = by_va.setdefault(int(function_va), {})
            entry.setdefault("boundaries", []).append(
                {"start_va": int(start_va), "end_va": int(end_va)}
            )
    except Exception:
        pass  # table absent on a KB that never ran the Windows path

    # Content-derived identity, so annotations can be re-attached after a rebuild.
    try:
        cur.execute(
            "SELECT entry_va, scheme, identity, n_blocks FROM function_identity "
            "WHERE binary_id = ?",
            (kb.binary_id,),
        )
        for entry_va, scheme, identity, n_blocks in cur.fetchall():
            entry = by_va.setdefault(int(entry_va), {})
            entry.setdefault("identity", []).append(
                {"scheme": scheme, "value": identity, "n_blocks": n_blocks}
            )
    except Exception:
        pass

    for va, body in by_va.items():
        body["entry_va"] = va
    return [by_va[va] for va in sorted(by_va)]


def _attach_prototypes(kb: PersistentKnowledgeBase, functions: list[dict]) -> None:
    """Prototypes are keyed by NAME, not by VA — a known defect, worked around.

    `function_prototypes` is the only annotation table keyed by function name,
    with no rename cascade, so a renamed function orphans its prototype. Here
    that means a prototype can only be attached to a function that has a name;
    an unnamed function gets `null` rather than a wrong match.
    """
    from . import xref_db as _xref_db

    by_name = {p.function_name: p for p in _xref_db.list_function_prototypes(kb)}
    for function in functions:
        name = (function.get("name") or {}).get("value")
        proto = by_name.get(name) if name else None
        function["prototype"] = (
            None
            if proto is None
            else {
                "return_type": proto.return_type,
                "params": [p.as_dict() for p in proto.params],
                "is_variadic": proto.is_variadic,
                "calling_convention": proto.calling_convention,
                "set_by": getattr(proto, "source_kind", None),
            }
        )


def _attach_stack_vars(kb: PersistentKnowledgeBase, functions: list[dict]) -> None:
    from . import xref_db as _xref_db

    for function in functions:
        try:
            variables = _xref_db.list_stack_vars(kb, function_va=function["entry_va"])
        except Exception:
            variables = []
        function["stack_vars"] = [
            {
                "offset": v.offset,
                "name": v.name,
                "c_type": v.c_type,
                "set_by": v.set_by,
            }
            for v in variables
        ]


def _attach_xrefs(kb: PersistentKnowledgeBase, functions: list[dict]) -> None:
    """Cross-references, which no existing export carries at all."""
    from . import xref_db as _xref_db

    for function in functions:
        try:
            refs = _xref_db.list_xrefs_in_function(kb, function["entry_va"])
        except Exception:
            refs = []
        function["xrefs"] = [
            {
                "src_va": r.src_va,
                "dst_va": r.dst_va,
                "kind": str(r.kind),
            }
            for r in refs
        ]


def _attach_bodies(
    kb: PersistentKnowledgeBase, functions: list[dict], binary_path: str
) -> None:
    """Decompiled C, with names applied — the thing persisted nowhere else."""
    from . import xref_db as _xref_db

    for function in functions:
        try:
            text = _xref_db.render_decompile_with_names(
                kb, binary_path, function["entry_va"]
            )
        except Exception as exc:  # a function we cannot lift is not a failure
            function["body"] = {"language": "c", "text": None, "error": str(exc)[:200]}
            continue
        function["body"] = {"language": "c", "text": text}


def _binary_identity(
    kb: PersistentKnowledgeBase, binary_path: Optional[str]
) -> dict[str, Any]:
    """What file this bundle describes.

    Read from the `binaries` row rather than recomputed, so the bundle names the
    exact image the annotations were made against — recomputing from
    `binary_path` would silently describe a *different* file if the caller
    passed the wrong one.
    """
    cur = kb._conn.cursor()
    try:
        cur.execute(
            "SELECT sha256, format, arch, bits, size_bytes FROM binaries "
            "WHERE binary_id = ?",
            (kb.binary_id,),
        )
        row = cur.fetchone()
    except Exception:
        row = None
    if row is None:
        return {"sha256": None, "path": binary_path}
    sha256, fmt, arch, bits, size_bytes = row
    return {
        "sha256": sha256,
        "format": fmt,
        "arch": arch,
        "bits": bits,
        "size_bytes": size_bytes,
        "path": binary_path,
    }


def build(
    kb: PersistentKnowledgeBase,
    *,
    binary_path: Optional[str] = None,
    include_bodies: bool = False,
) -> dict[str, Any]:
    """Assemble the whole-binary bundle.

    Args:
        kb: An open knowledge base.
        binary_path: Needed only when `include_bodies` is set; decompilation
            reads the image, not the KB.
        include_bodies: Decompile every function. Expensive — this is the part
            that costs orders of magnitude more than everything else combined.

    Returns:
        A JSON-serialisable dict. See the module docstring for the shape and
        for why identity and provenance travel with each function.
    """
    from . import export as _export

    functions = _function_rows(kb)
    _attach_prototypes(kb, functions)
    _attach_stack_vars(kb, functions)
    _attach_xrefs(kb, functions)
    if include_bodies:
        if not binary_path:
            raise ValueError(
                "include_bodies requires binary_path — bodies are decompiled from the image, not read from the KB"
            )
        _attach_bodies(kb, functions, binary_path)

    annotations = _export.export_kb(kb)
    return {
        "schema": SCHEMA,
        "binary": _binary_identity(kb, binary_path),
        "functions": functions,
        "types": annotations.get("types", []),
        "data_labels": annotations.get("data_labels", []),
        "comments": annotations.get("comments", []),
        "evidence": annotations.get("evidence", []),
        "counts": {
            "functions": len(functions),
            "with_name": sum(1 for f in functions if f.get("name")),
            "with_prototype": sum(1 for f in functions if f.get("prototype")),
            "with_identity": sum(1 for f in functions if f.get("identity")),
            "with_body": sum(1 for f in functions if (f.get("body") or {}).get("text")),
            "xrefs": sum(len(f.get("xrefs") or []) for f in functions),
        },
    }
