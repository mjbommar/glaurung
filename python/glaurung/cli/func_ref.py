"""Helpers for resolving a ``--func`` CLI argument to a virtual address.

Glaurung CLI commands that operate on a single function (``decompile``,
``name-func``, ``xrefs``, ``cfg``, ``frame``) historically accepted only a
hex/decimal VA via ``type=lambda x: int(x, 0)``. That made name-based
lookup ergonomic-impossible: callers had to grep a ``.glaurung`` project
or analyse output for the entry VA before they could decompile by name.

This module standardizes a permissive parser that:

* Returns ``int`` when the input is parseable as a Python int literal in any
  base (``0x140001480``, ``1234``, ``0o777``, ``0b...``).
* Returns ``str`` when the input is a non-numeric identifier, deferring
  resolution to the per-command implementation (which knows whether a
  project DB, an in-memory analysis result, or PDB cache should be used).

Each command's ``execute()`` body is responsible for calling
:func:`resolve_func_to_va` once it has a binary path or analysis handle.
The helper accepts a function name and a fresh analysis result, picks the
best match, and returns the entry VA -- or raises ``LookupError`` listing
the candidates that *did* match.
"""

from __future__ import annotations

import difflib
from typing import Iterable


def parse_func_arg(value: str) -> int | str:
    """Argparse ``type=`` callable for ``--func`` arguments.

    Returns ``int`` for numeric (hex/dec/oct/bin) input, ``str`` for
    names. Never raises ``argparse.ArgumentTypeError`` -- name strings
    are valid and the resolver does the lookup later.
    """
    if value is None:
        return None  # type: ignore[return-value]
    text = value.strip()
    if not text:
        raise ValueError("empty --func argument")
    # int(text, 0) accepts 0x.., 0o.., 0b.., and bare decimal.
    try:
        return int(text, 0)
    except ValueError:
        return text


class FuncResolutionError(LookupError):
    """Raised when a function name cannot be resolved against a binary."""


def resolve_func_to_va(name: str, functions: Iterable) -> int:
    """Resolve a function ``name`` to its entry VA against an analysis result.

    ``functions`` is an iterable of objects exposing ``.name`` and
    ``.entry_point`` (with ``.entry_point.value`` returning an int VA).
    Matching is exact first; if no exact match, falls back to suffix
    match (handles ``sessmgr.dll!session_create`` style decorated names).

    Raises ``FuncResolutionError`` listing candidates on miss.
    """
    candidates = list(functions)
    by_name: dict[str, list] = {}
    for fn in candidates:
        by_name.setdefault(fn.name, []).append(fn)

    matches = by_name.get(name, [])
    if not matches:
        # suffix fallback (e.g. user said `foo` but the binary has `mod!foo`)
        suffix_matches = [
            fn for fn in candidates
            if fn.name.endswith("!" + name) or fn.name.endswith("." + name)
        ]
        if suffix_matches:
            matches = suffix_matches

    if not matches:
        # Distinguish "stripped binary with only sub_ names" from "wrong name".
        named = sum(
            1 for fn in candidates
            if not fn.name.startswith("sub_") and not fn.name.startswith(".")
        )
        hint = ""
        if named == 0:
            hint = (
                " (binary appears stripped: no user-named functions recovered. "
                "Pass a hex VA like 0x140001480 instead, or use a PDB cache.)"
            )
        else:
            # First: substring match in either direction.
            similar = [
                fn.name for fn in candidates
                if name.lower() in fn.name.lower()
                or fn.name.lower() in name.lower()
            ][:6]
            # Fallback: fuzzy near-misses via difflib.
            if not similar:
                pool = [fn.name for fn in candidates]
                similar = difflib.get_close_matches(name, pool, n=5, cutoff=0.4)
            if similar:
                hint = f" Did you mean: {', '.join(similar)}?"
        raise FuncResolutionError(
            f"no function named '{name}' in this binary.{hint}"
        )

    if len(matches) > 1:
        addrs = ", ".join(f"0x{m.entry_point.value:x}" for m in matches)
        raise FuncResolutionError(
            f"function name '{name}' is ambiguous; "
            f"multiple matches: {addrs}. Pass the VA directly."
        )
    return int(matches[0].entry_point.value)
