"""Write facts read out of C source into a `.glaurung` project.

Phase 4 of `docs/development/roadmap/source-semantics.md`. The source front end
recovers prototypes, declared types and data dependence from a translation
unit; this puts them where the rest of the tool can already query them, with
``set_by = "source"`` so the provenance ladder decides precedence rather than
arrival order.

# Why the knowledge base rather than a query language

Cloning CPGQL would be a large amount of work whose only unique benefit is
running somebody else's existing Joern queries unchanged -- a *compatibility*
requirement, not a capability one. The knowledge base is already a queryable
store with provenance, already holds names, prototypes, types and xrefs, and
already resolves "manual always wins". The query surface is then whatever
queries the KB, which includes the LLM tools in ``glaurung.llm`` -- a consumer
Joern does not have.

# Where source sits in the ladder

``source`` ranks 70: below ``dwarf``/``pdb``/``gopclntab`` and above
``stdlib``. Debug info is the *toolchain's* statement about the binary that was
actually built, and source is the programmer's statement about what was
intended; the two disagree whenever a macro, a conditional compilation branch,
or an inlining decision came between them, and the one describing the shipped
artifact wins. See `glaurung.llm.kb.provenance`.

# What this does not do

It does not resolve `#include`, because the front end does not: a typedef from
a header is written as the opaque name the source spells. It does not match
source functions to binary addresses -- the key is the function *name*, which
is what `function_prototypes` is keyed by, and a stripped binary with no
matching name simply gets no row.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import glaurung

from .xref_db import FunctionParam, set_function_prototype

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .persistent import PersistentKnowledgeBase

#: The provenance string every fact this module writes carries.
SET_BY = "source"


@dataclass(frozen=True)
class SourceFactCounts:
    """What one ingestion wrote, so a caller can report it without re-querying.

    ``skipped_prototypes`` is not a failure: a prototype is skipped when a
    stronger source already recorded one, which is the ladder doing its job.
    """

    functions: int = 0
    prototypes: int = 0
    skipped_prototypes: int = 0
    dependence_edges: int = 0
    dead_stores: int = 0
    unused_bindings: int = 0
    #: Paths proved takeable by some input.
    feasible_paths: int = 0
    #: Paths proved takeable by none, which is the finding.
    infeasible_paths: int = 0

    def total(self) -> int:
        """Every row written."""
        return self.prototypes + self.dependence_edges + self.infeasible_paths


def ingest_source(
    kb: PersistentKnowledgeBase,
    code: str,
    *,
    origin: str | None = None,
    write_dependence: bool = True,
    write_feasibility: bool = True,
) -> SourceFactCounts:
    """Read `code` and write what it says into `kb`.

    Args:
        kb: The open project to write into.
        code: One translation unit of C. Any byte sequence is acceptable; the
            front end is total, so an unparseable file yields no functions and
            no rows rather than an exception.
        origin: The file the text came from, recorded on each fact so a reader
            can tell which source a claim came from.
        write_dependence: Whether to write the data-dependence edges as well as
            the prototypes. They are the bulk of the rows, and a caller who
            only wants types can skip them.
        write_feasibility: Whether to write path-feasibility verdicts. Requires
            an extension built with the ``symbolic`` feature; without one the
            capability is simply absent and no rows are written, which is not
            an error.

    Returns:
        What was written, as :class:`SourceFactCounts`.
    """
    functions = 0
    prototypes = 0
    skipped = 0
    edges = 0
    dead = 0
    unused = 0
    feasible = 0
    infeasible = 0

    flows = glaurung.source.data_flow(code)
    for flow in flows:
        name = flow.get("name") or ""
        if not name:
            # A definition the parser recovered without a name cannot be keyed.
            continue
        functions += 1

        if _write_prototype(kb, flow, origin=origin):
            prototypes += 1
        else:
            skipped += 1

        dead += len(flow.get("dead_stores", ()))
        unused += len(flow.get("unused_bindings", ()))

        if write_dependence:
            edges += _write_dependence(kb, flow, origin=origin)

        if write_feasibility:
            # Not named `dead`: that is the dead-store accumulator above, and
            # rebinding it here silently zeroed `dead_stores` on every
            # iteration. `test_the_dead_store_and_unused_counts_are_reported`
            # is what caught it.
            reachable, unreachable = _write_feasibility(kb, code, name, origin=origin)
            feasible += reachable
            infeasible += unreachable

    return SourceFactCounts(
        functions=functions,
        prototypes=prototypes,
        skipped_prototypes=skipped,
        dependence_edges=edges,
        dead_stores=dead,
        unused_bindings=unused,
        feasible_paths=feasible,
        infeasible_paths=infeasible,
    )


def ingest_source_path(
    kb: PersistentKnowledgeBase,
    path: str | Path,
    *,
    dialect: str | None = None,
    write_dependence: bool = True,
) -> SourceFactCounts:
    """:func:`ingest_source` over a file, read lossily.

    Args:
        kb: The open project to write into.
        path: The C file to read. Decoded with ``errors="replace"``, because a
            decompiler's output is not always valid UTF-8 and losing the file
            over one byte would be worse than losing the byte.
        dialect: Passed to :func:`glaurung.source.normalize` first when given.
        write_dependence: As :func:`ingest_source`.

    Returns:
        What was written.

    Raises:
        OSError: If the file cannot be read.
    """
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    if dialect is not None:
        text = glaurung.source.normalize(text, dialect)
    return ingest_source(kb, text, origin=str(path), write_dependence=write_dependence)


def _write_prototype(
    kb: PersistentKnowledgeBase, flow: dict[str, Any], *, origin: str | None
) -> bool:
    """Write one function's prototype. Returns whether a row was written.

    The parameters are the bindings the analysis marked as parameters, in
    declaration order, with the type the source spells. A function whose
    parameters carry no recovered type is still written -- the name and arity
    are facts even when the types are not.
    """
    name = flow["name"]
    bindings = flow.get("bindings", [])
    definitions = flow.get("definitions", [])

    # Parameter bindings, in the order they were declared.
    parameter_indices = [
        definition["binding"]
        for definition in definitions
        if definition.get("kind") == "parameter"
    ]
    params: list[FunctionParam] = []
    for index in parameter_indices:
        if index >= len(bindings):
            continue
        binding = bindings[index]
        params.append(
            FunctionParam(
                name=binding.get("name", ""),
                c_type=binding.get("type") or "",
            )
        )

    before = _prototype_set_by(kb, name)
    set_function_prototype(
        kb,
        name,
        # The front end does not model a return type; the prototype records
        # the parameters it does know and leaves this for a stronger source.
        return_type=None,
        params=params,
        set_by=SET_BY,
        source=origin,
        source_kind="c_source",
        provenance={"origin": origin} if origin else None,
    )
    after = _prototype_set_by(kb, name)
    # The writer refuses silently when a stronger source holds the row, so the
    # only way to know whether this wrote is to look.
    return after == SET_BY and before != SET_BY or (before is None and after == SET_BY)


def _prototype_set_by(kb: PersistentKnowledgeBase, name: str) -> str | None:
    """The `set_by` currently recorded for `name`, or `None` for no row.

    Creates the annotation schema first: this can be the first thing a fresh
    project touches, and `set_function_prototype` would otherwise be the only
    caller that ever makes the table.
    """
    from .xref_db import _ensure_schema

    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT set_by FROM function_prototypes "
        "WHERE binary_id = ? AND function_name = ?",
        (kb.binary_id, name),
    )
    row = cur.fetchone()
    return row[0] if row else None


def _write_dependence(
    kb: PersistentKnowledgeBase, flow: dict[str, Any], *, origin: str | None
) -> int:
    """Write one function's data-dependence edges. Returns how many.

    Written to the generic ``kb_nodes``/``kb_edges`` tables rather than a new
    one: a dependence edge is a typed edge between two identified points, which
    is exactly what those tables are for, and adding a table would need a
    schema version bump for a shape that already fits.
    """
    import json

    name = flow["name"]
    definitions = flow.get("definitions", [])
    uses = flow.get("uses", [])
    edges = flow.get("edges", [])
    if not edges:
        return 0

    conn = kb._conn
    cur = conn.cursor()
    written = 0
    for position, edge in enumerate(edges):
        definition = (
            definitions[edge["definition"]]
            if edge["definition"] < len(definitions)
            else None
        )
        use = uses[edge["use"]] if edge["use"] < len(uses) else None
        if definition is None or use is None:
            continue

        src_id = f"srcdef:{name}:{definition['start']}"
        dst_id = f"srcuse:{name}:{use['start']}"
        _upsert_node(
            cur,
            kb,
            src_id,
            kind="source_definition",
            label=definition.get("name", ""),
            props={
                "function": name,
                "variable": definition.get("name", ""),
                "def_kind": definition.get("kind"),
                "declared_type": definition.get("declared_type"),
                "start": definition.get("start"),
                "end": definition.get("end"),
                "origin": origin,
                "set_by": SET_BY,
            },
        )
        _upsert_node(
            cur,
            kb,
            dst_id,
            kind="source_use",
            label=use.get("name", ""),
            props={
                "function": name,
                "variable": use.get("name", ""),
                "start": use.get("start"),
                "end": use.get("end"),
                "origin": origin,
                "set_by": SET_BY,
            },
        )
        cur.execute(
            "INSERT OR REPLACE INTO kb_edges "
            "(session_id, edge_id, src_node_id, dst_node_id, kind, props_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                # The real session, never NULL: the UNIQUE constraint is on
                # `(session_id, node_id)`, and SQL says NULL is not equal to
                # NULL, so a NULL here makes `INSERT OR REPLACE` insert a
                # duplicate rather than replace. Re-ingesting the same file
                # then doubles every row, which
                # `test_ingesting_twice_is_idempotent` catches.
                kb.session_id,
                f"srcflow:{name}:{position}",
                src_id,
                dst_id,
                "source_data_dependence",
                json.dumps(
                    {
                        "function": name,
                        "variable": edge.get("variable"),
                        "origin": origin,
                        "set_by": SET_BY,
                    }
                ),
            ),
        )
        written += 1

    conn.commit()
    return written


def _upsert_node(
    cur: Any,
    kb: PersistentKnowledgeBase,
    node_id: str,
    *,
    kind: str,
    label: str,
    props: dict[str, Any],
) -> None:
    """Insert or replace one `kb_nodes` row."""
    import json

    cur.execute(
        "INSERT OR REPLACE INTO kb_nodes "
        "(session_id, node_id, kind, label, text, props_json, tags_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        # The real session id, for the NULL-is-not-NULL reason on `kb_edges`.
        (kb.session_id, node_id, kind, label, None, json.dumps(props), "[]"),
    )


def _write_feasibility(
    kb: PersistentKnowledgeBase,
    code: str,
    name: str,
    *,
    origin: str | None,
) -> tuple[int, int]:
    """Write one function's path-feasibility verdicts. Returns (feasible, infeasible).

    Only the **infeasible** paths become rows. A feasible path is the ordinary
    case and writing one row per path of every function would bury the finding
    in its own background: an infeasible path is a path a reachability answer
    reports and no input can take, which is the whole reason phase 3 exists.
    The feasible count is still returned so a caller can report the denominator.

    Requires an extension built with the ``symbolic`` feature. Without one the
    call raises :class:`RuntimeError` and this writes nothing -- the capability
    is opt-in at build time, not a failure at run time.

    Only ``RuntimeError`` is caught, and deliberately not ``Exception``: the
    front end is total, so anything else escaping here is a defect and must not
    be turned into a silent zero.
    """
    import json

    try:
        paths = glaurung.source.path_feasibility(code, name)
    except RuntimeError:
        return (0, 0)

    feasible = 0
    infeasible = 0
    conn = kb._conn
    cur = conn.cursor()
    for position, path in enumerate(paths):
        verdict = path.get("verdict")
        if verdict == "feasible":
            feasible += 1
            continue
        if verdict != "infeasible":
            continue
        infeasible += 1
        node_id = f"srcpath:{name}:{position}"
        _upsert_node(
            cur,
            kb,
            node_id,
            kind="source_infeasible_path",
            label=name,
            props={
                "function": name,
                "decisions": path.get("decisions"),
                "origin": origin,
                "set_by": SET_BY,
            },
        )
        cur.execute(
            "INSERT OR REPLACE INTO kb_edges "
            "(session_id, edge_id, src_node_id, dst_node_id, kind, props_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                # The real session, for the NULL-is-not-NULL reason recorded on
                # `_write_dependence`.
                kb.session_id,
                f"srcpathof:{name}:{position}",
                node_id,
                node_id,
                "source_infeasible_path",
                json.dumps(
                    {
                        "function": name,
                        "decisions": path.get("decisions"),
                        "origin": origin,
                        "set_by": SET_BY,
                    }
                ),
            ),
        )

    conn.commit()
    return (feasible, infeasible)
