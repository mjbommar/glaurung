"""Resolve a DecBench function name to a local body address in a compiled binary.

Why this is its own module
--------------------------

The resolver used to live inside ``decbench_redecompile_tree.py``, which reads
the sample-set manifest and walks the whole corpus **at import time**. Nothing
could import the resolver to test it without starting a multi-hour run, so the
resolver had no tests at all -- and it was wrong in four separate ways that only
a test could have shown.

The i386 stdcall defect (F1a)
-----------------------------

i386 PE decorates by calling convention, and the old resolver knew only one of
the two decorations. cdecl ``crc32`` is ``_crc32`` in the symbol table -- that
case was handled. **stdcall ``worker(int)`` is ``_worker@4``**, and nothing
matched it, so 33 functions in the pinned DecBench run were reported as
"unresolved" when their bodies were present in the binary all along. The
``@N`` suffix is the callee-popped argument byte count, so it varies per
function and cannot be guessed from the name alone -- it has to be matched as a
pattern.

The contract
------------

1. An exact name match always wins.
2. cdecl ``_name`` remains a fallback.
3. ``_name@N`` is accepted **only** for i386 PE function symbols.
4. More than one candidate code address is an explicit ambiguity. Never
   first-entry-wins: two functions that canonicalize to the same name are a
   dataset problem, and silently picking one produces a body that is confidently
   the wrong function.
5. A data, TLS or import symbol can never satisfy a local-body request. An
   import is reported as an import (``Disposition.IMPORT``) rather than as
   absent, because "this identity has no local body by construction" and "we
   failed to find it" need different downstream handling -- that distinction is
   DecBench failure class F1b.
6. The decoration used and the raw symbol chosen are recorded, so a checkpoint
   can be audited without re-reading the binary.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import Iterable, Sequence

#: A stdcall/fastcall decorated i386 symbol: `_name@N` (stdcall, `@`) or
#: `@name@N` (fastcall). `N` is the argument byte count, always decimal.
_STDCALL = re.compile(r"^(?P<sigil>[_@])(?P<base>.+?)@(?P<bytes>\d+)$")

#: Symbol kinds that can back a *function body*. `unknown` is included because
#: several PE producers emit COFF symbols with no kind information at all, and
#: excluding it would regress the plain-cdecl path that works today.
CODE_KINDS = frozenset({"text", "unknown"})

#: Kinds that must never satisfy a local-body request, however the name matches.
NON_CODE_KINDS = frozenset({"data", "tls", "section", "file", "label"})


class Disposition(enum.StrEnum):
    """Why a request did or did not produce an address."""

    LOCAL = "local"
    """A local function body was found; `address` is set."""

    IMPORT = "import"
    """The name exists but is an undefined/imported symbol. No local body
    exists by construction -- this is not a resolver failure."""

    AMBIGUOUS = "ambiguous"
    """Two or more distinct code addresses matched. Never guess."""

    NON_CODE = "non-code"
    """The name matched only data/TLS/section symbols."""

    ABSENT = "absent"
    """Nothing in the symbol table matched under any accepted decoration."""


class Decoration(enum.StrEnum):
    """Which naming rule produced the match. Recorded in the checkpoint."""

    EXACT = "exact"
    CDECL = "cdecl-underscore"
    STDCALL = "stdcall-at"
    NONE = "none"


@dataclass(frozen=True)
class SymbolEntry:
    """One row of a binary's symbol table."""

    address: int
    name: str
    kind: str
    defined: bool

    @property
    def is_code(self) -> bool:
        return self.kind in CODE_KINDS


@dataclass(frozen=True)
class Resolution:
    """The outcome of resolving one requested name."""

    request: str
    disposition: Disposition
    address: int | None = None
    decoration: Decoration = Decoration.NONE
    raw_symbol: str | None = None
    candidates: tuple[str, ...] = field(default=())

    @property
    def ok(self) -> bool:
        return self.disposition is Disposition.LOCAL

    def as_record(self) -> dict:
        """The checkpoint form. Contract clause 6."""
        return {
            "request": self.request,
            "disposition": str(self.disposition),
            "address": self.address,
            "decoration": str(self.decoration),
            "raw_symbol": self.raw_symbol,
            "candidates": list(self.candidates),
        }


def canonical_name(symbol: str) -> str:
    """Strip i386 decoration to the source-level name.

    ``_worker@4`` -> ``worker``; ``@fast@8`` -> ``fast``; ``_crc32`` ->
    ``crc32``. A bare ``worker`` is returned unchanged, which is why exact
    matching has to be tried before anything else: ``worker`` and ``_worker``
    can both exist, as distinct functions.
    """
    m = _STDCALL.match(symbol)
    if m:
        return m.group("base")
    if symbol.startswith("_"):
        return symbol[1:]
    return symbol


def _distinct_addresses(entries: Iterable[SymbolEntry]) -> list[SymbolEntry]:
    """Collapse aliases at one address; keep genuinely distinct addresses.

    Two names for one address is an alias and harmless -- the body is the same
    bytes either way. Two addresses for one name is the ambiguity clause 4
    exists for.
    """
    seen: dict[int, SymbolEntry] = {}
    for e in entries:
        seen.setdefault(e.address, e)
    return sorted(seen.values(), key=lambda e: e.address)


def resolve(
    request: str,
    entries: Sequence[SymbolEntry],
    *,
    allow_stdcall: bool = True,
) -> Resolution:
    """Resolve one source-level function name against a symbol table.

    Args:
        request: The source-level name DecBench asks for, e.g. ``worker``.
        entries: Every symbol table row for the binary.
        allow_stdcall: Whether ``_name@N`` may match. False for non-i386-PE
            binaries, where an `@` in a symbol means something else entirely
            (ELF versioning: ``memcpy@GLIBC_2.14``). Contract clause 3.

    Returns:
        A `Resolution` recording the address and how it was reached.
    """
    by_name: dict[str, list[SymbolEntry]] = {}
    for e in entries:
        by_name.setdefault(e.name, []).append(e)

    # Clause 1 then 2 then 3, in order. Each tier is considered on its own: a
    # data symbol named exactly `worker` must not shadow a real `_worker@4`
    # function, so a tier that matches only non-code falls through rather than
    # terminating the search.
    tiers: list[tuple[Decoration, list[SymbolEntry]]] = [
        (Decoration.EXACT, by_name.get(request, [])),
        (Decoration.CDECL, by_name.get("_" + request, [])),
    ]
    if allow_stdcall:
        stdcall = [
            e
            for name, group in by_name.items()
            if (m := _STDCALL.match(name)) and m.group("base") == request
            for e in group
        ]
        tiers.append((Decoration.STDCALL, stdcall))

    saw_non_code: list[str] = []
    saw_import: list[str] = []

    for decoration, group in tiers:
        if not group:
            continue
        code = [e for e in group if e.is_code and e.defined]
        if not code:
            # Record why this tier was rejected, then keep looking.
            saw_non_code += [e.name for e in group if e.kind in NON_CODE_KINDS]
            saw_import += [e.name for e in group if not e.defined]
            continue
        distinct = _distinct_addresses(code)
        if len(distinct) > 1:
            # Clause 4. Report every candidate: the caller needs to fix the
            # dataset, and needs to know which symbols collided to do it.
            return Resolution(
                request=request,
                disposition=Disposition.AMBIGUOUS,
                decoration=decoration,
                candidates=tuple(f"{e.name}@0x{e.address:x}" for e in distinct),
            )
        hit = distinct[0]
        return Resolution(
            request=request,
            disposition=Disposition.LOCAL,
            address=hit.address,
            decoration=decoration,
            raw_symbol=hit.name,
        )

    # Clause 5: distinguish "it is an import" from "it is data" from "absent".
    if saw_import:
        return Resolution(
            request=request,
            disposition=Disposition.IMPORT,
            candidates=tuple(sorted(set(saw_import))),
        )
    if saw_non_code:
        return Resolution(
            request=request,
            disposition=Disposition.NON_CODE,
            candidates=tuple(sorted(set(saw_non_code))),
        )
    return Resolution(request=request, disposition=Disposition.ABSENT)


def load_entries(binary: str) -> list[SymbolEntry]:
    """Read a binary's symbol table via glaurung's own object reader.

    `readelf` returns nothing for PE, which is why the 12 Windows binaries in
    the corpus were recorded `no-symbols` and never decompiled at all.
    """
    import glaurung

    try:
        rows = glaurung.symbol_table_entries(binary)
    except Exception:
        return []
    return [SymbolEntry(a, n, k, d) for a, n, k, d in rows]


def is_i386_pe(binary: str) -> bool:
    """Whether `_name@N` decoration should be honoured for this binary.

    Contract clause 3 restricts stdcall matching to i386 PE. On ELF an `@` in a
    symbol name is version decoration (`memcpy@GLIBC_2.14`) and matching it
    would resolve a versioned import as if it were a local body.
    """
    import glaurung

    try:
        t = glaurung.triage.analyze_path(binary)
    except Exception:
        return False
    verdicts = getattr(t, "verdicts", None) or []
    for v in verdicts:
        fmt = str(getattr(v, "format", "")).lower()
        arch = str(getattr(v, "arch", "")).lower()
        if "pe" in fmt and ("x86" in arch and "64" not in arch):
            return True
    return False


def resolve_many(binary: str, requests: Iterable[str]) -> dict[str, Resolution]:
    """Resolve every requested name against one binary, in one table read."""
    entries = load_entries(binary)
    allow = is_i386_pe(binary)
    return {r: resolve(r, entries, allow_stdcall=allow) for r in requests}
