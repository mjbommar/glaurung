"""Read analyst-chosen names out of a `.glaurung` project, for any command.

Several commands need the same thing: the names recorded in the project, keyed
by entry VA, so their output agrees with what the analyst decided rather than
with what the binary happens to say. Keeping one loader means `decompile`,
`graph` and anything added later cannot drift apart on what `--db` means or on
how a broken project file is handled.

A missing, unreadable, or empty project is never fatal. Analyst state is
something a command may *consult*, not something it may *require* to be present
and well-formed -- a typo in a path must not stop a disassembly.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional

log = logging.getLogger(__name__)


def load_analyst_names(db_path: Optional[str], binary: str) -> dict[int, str]:
    """``{entry_va: name}`` from a project file, or ``{}``.

    Every row in ``function_names`` is returned, not only the ``manual`` ones: a
    DWARF or FLIRT name recorded in the project is still a name the analyst
    expects to see, and the KB's provenance ranking has already decided which
    one survives per VA. Filtering to `manual` here would second-guess that.
    """
    if not db_path:
        return {}
    kb = None
    try:
        from glaurung.llm.kb.persistent import PersistentKnowledgeBase

        kb = PersistentKnowledgeBase.open(db_path, binary_path=binary)
        from glaurung.llm.kb import xref_db

        rows = xref_db.list_function_names(kb)
    except Exception as exc:  # noqa: BLE001 - a bad project must not kill the command
        log.warning(
            "--db %s: could not read function names (%s); ignoring", db_path, exc
        )
        return {}
    finally:
        if kb is not None:
            try:
                kb.close()
            except Exception:  # noqa: BLE001
                pass
    out: dict[int, str] = {}
    for row in rows:
        if row.entry_va is None or not row.canonical:
            continue
        out[int(row.entry_va)] = str(row.canonical)
    return out


def load_analyst_locals(
    db_path: Optional[str], binary: str, function_va: int
) -> dict[int, tuple[str, str]]:
    """``{frame_offset: (name, c_type)}`` for one function, or ``{}``.

    Keyed by frame OFFSET because that is what the project file records and
    what survives a recompile; the decompiler joins it to its own promoted
    local names through the frame coordinates it publishes for exactly this.

    A slot with a name but no type, or a type but no name, is normal -- an
    analyst usually does one and then the other -- so both halves are optional
    and are carried as empty strings rather than dropped.
    """
    if not db_path:
        return {}
    kb = None
    try:
        from glaurung.llm.kb.persistent import PersistentKnowledgeBase

        kb = PersistentKnowledgeBase.open(db_path, binary_path=binary)
        from glaurung.llm.kb import xref_db

        rows = xref_db.list_stack_vars(kb, function_va=int(function_va))
    except Exception as exc:  # noqa: BLE001
        log.warning("--db %s: could not read stack vars (%s); ignoring", db_path, exc)
        return {}
    finally:
        if kb is not None:
            try:
                kb.close()
            except Exception:  # noqa: BLE001
                pass
    return {
        int(row.offset): (str(row.name or ""), str(row.c_type or ""))
        for row in rows
        if row.offset is not None
    }


def overlay_digest(analyst_names: Optional[dict[int, str]]) -> str:
    """Stable digest of an overlay, for a cache key.

    ``None`` and an empty overlay digest identically, so adding ``--db`` to a
    project with no names does not needlessly miss entries built without it.
    Keyed on the CONTENT rather than on presence, so renaming a function and
    renaming it back agree.
    """
    if not analyst_names:
        return ""
    payload = "\n".join(f"{va:x}={name}" for va, name in sorted(analyst_names.items()))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def locals_digest(analyst_locals: Optional[dict[int, tuple[str, str]]]) -> str:
    """Digest of a stack-variable overlay, for the same cache key.

    Separate from `overlay_digest` because the two overlays are loaded
    independently -- one is per binary, one is per function -- and a rename of a
    LOCAL must invalidate a cached decompile just as surely as a rename of a
    function does.
    """
    if not analyst_locals:
        return ""
    payload = "\n".join(
        f"{off}={name}:{ctype}" for off, (name, ctype) in sorted(analyst_locals.items())
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
