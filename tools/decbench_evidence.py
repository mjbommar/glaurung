"""Shape Glaurung's CLI evidence into the arrays DecBench's models declare.

Glaurung's `decompile --style decbench --format json` payload has carried
`variables` and `line_mappings` since `db2e7735`, but both adapters -- ours in
`decbench_glaurung.py` and DecBench's in-tree `decompilers/raw/glaurung_raw.py`
-- still hardcode them empty, with comments that predate the feature. The
metric therefore falls back to parsing the emitted C text.

Forwarding the arrays is the whole change. The shaping rules below mirror
DecBench's own JSON-over-CLI backend, `decompilers/raw/kuna_raw.py`, whose
golden case in `tests/test_raw_line_provenance.py` is the executable spec: a
line beyond the emitted text is dropped, an address outside the function is
dropped, a row left with no addresses vanishes, and addresses are rebased into
the caller's address space, sorted and deduped.

FAIL-CLOSED. Nothing here invents evidence. A malformed row is discarded rather
than repaired, and an absent field yields an empty list. DecBench validates
every surviving address against the binary's DWARF ranges anyway
(`decompilers/provenance.py`), so a value we cannot justify only costs us the
claim -- but a value we fabricate would corrupt someone else's denominator.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

#: Exactly the fields `decbench.models.decompilation.VariableInfo` declares.
#: Glaurung additionally emits `static_variable` and `static_type`, which carry
#: our own identity model and mean nothing to DecBench.
VARIABLE_FIELDS = frozenset(
    {
        "name",
        "type",
        "kind",
        "arg_index",
        "stack_offset",
        "size",
        "line_numbers",
        "addresses",
    }
)


def _int_or_none(value: Any) -> int | None:
    """Return `value` as an int, or None if it is not a plain integer."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _keep_addresses(raw: Any, *, entry_va: int, size: int, delta: int) -> list[int]:
    """Filter addresses to the function's own span and rebase them.

    Args:
        raw: Candidate address list from the CLI payload.
        entry_va: The function's entry as the payload reports it.
        size: The function's byte size, or 0 when unknown.
        delta: Added to each surviving address to reach the caller's space.

    Returns:
        Sorted, deduplicated, rebased addresses. An unknown `size` skips the
        upper bound rather than rejecting everything: Glaurung reports
        `size: null` for many functions, and treating that as a zero-length
        span would silently discard the whole payload.

        A `.cold` fragment placed BELOW the entry is dropped by the lower
        bound. That loses real evidence, but matches the in-tree backend and
        never claims an address outside the span we can justify.
    """
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return []
    kept: set[int] = set()
    for item in raw:
        address = _int_or_none(item)
        if address is None or address < entry_va:
            continue
        if size > 0 and address >= entry_va + size:
            continue
        kept.add(address + delta)
    return sorted(kept)


def shape_evidence(
    record: Mapping[str, Any], *, file_addr: int, line_count: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Shape one CLI record's evidence for `FunctionDecompilation`.

    Args:
        record: One object from Glaurung's `--format json` payload.
        file_addr: The address DecBench keys this function by, which may differ
            from the payload's `entry_va` (PE image base, Thumb bit).
        line_count: Number of lines in the emitted C, used to reject a line
            number that does not exist in it.

    Returns:
        `(line_mappings, variables)` as plain dicts ready to construct
        `LineMapping` and `VariableInfo`. Both are empty when the payload
        carries nothing usable.
    """
    entry_va = _int_or_none(record.get("entry_va"))
    if entry_va is None:
        return [], []
    size = _int_or_none(record.get("size")) or 0
    delta = file_addr - entry_va

    rows: list[dict[str, Any]] = []
    raw_mappings = record.get("line_mappings")
    if isinstance(raw_mappings, Sequence) and not isinstance(
        raw_mappings, (str, bytes)
    ):
        for row in raw_mappings:
            if not isinstance(row, Mapping):
                continue
            number = _int_or_none(row.get("line_number"))
            if number is None or not 1 <= number <= line_count:
                continue
            addresses = _keep_addresses(
                row.get("addresses"), entry_va=entry_va, size=size, delta=delta
            )
            if addresses:
                rows.append({"line_number": number, "addresses": addresses})
    rows.sort(key=lambda row: row["line_number"])
    kept_lines = {row["line_number"] for row in rows}

    variables: list[dict[str, Any]] = []
    raw_variables = record.get("variables")
    if isinstance(raw_variables, Sequence) and not isinstance(
        raw_variables, (str, bytes)
    ):
        for variable in raw_variables:
            if not isinstance(variable, Mapping):
                continue
            name = variable.get("name")
            if not isinstance(name, str) or not name:
                continue
            shaped = {
                key: value
                for key, value in variable.items()
                if key in VARIABLE_FIELDS and key not in ("addresses", "line_numbers")
            }
            shaped["name"] = name
            shaped["addresses"] = _keep_addresses(
                variable.get("addresses"), entry_va=entry_va, size=size, delta=delta
            )
            # A line number whose row did not survive is not evidence; DecBench
            # prunes these itself, and carrying them would only invite a
            # mismatch between our artifact and its sanitized view of it.
            raw_lines = variable.get("line_numbers")
            if isinstance(raw_lines, Sequence) and not isinstance(
                raw_lines, (str, bytes)
            ):
                shaped["line_numbers"] = sorted(
                    {
                        number
                        for number in (_int_or_none(item) for item in raw_lines)
                        if number is not None and number in kept_lines
                    }
                )
            else:
                shaped["line_numbers"] = []
            variables.append(shaped)
    return rows, variables


#: What our recovery knows that a parse of the emitted C cannot: where the slot
#: lives, how big it is, and which instructions touch it. Everything else --
#: the spelling of the type, the ABI position, the kind -- the parser reads out
#: of the C text we ourselves rendered, so it is already our answer.
ENRICHED_FIELDS = ("stack_offset", "size", "addresses", "line_numbers")


def merge_variables(
    parsed: Sequence[Mapping[str, Any]], ours: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """Enrich DecBench's own parse with our evidence, never replacing it.

    `type_match` runs `parse_c_variables` ONLY when `variables` is empty, so
    handing it a partial inventory silently suppresses its own. Measured on
    `O0/grep/main` against upstream `8cfc2165`: DecBench parses 84 declarations
    including `argc`/`argv` with ABI positions, Glaurung emits 26 promoted
    stack slots and no arguments at all, and substituting ours took type_match
    from 0.3947 to 0.2105. Merging restores 0.3947 exactly while keeping our
    offsets and addresses attached.

    Args:
        parsed: DecBench's inventory, as mappings.
        ours: Glaurung's structured variables, as mappings.

    Returns:
        The parser's inventory in order, each row overlaid with any of
        `ENRICHED_FIELDS` we supply, followed by names only we reported. Never
        smaller than `parsed`.
    """
    merged: dict[str, dict[str, Any]] = {
        str(row.get("name", "")): dict(row) for row in parsed if row.get("name")
    }
    for row in ours:
        name = str(row.get("name", ""))
        if not name:
            continue
        existing = merged.get(name)
        if existing is None:
            merged[name] = dict(row)
            continue
        for field in ENRICHED_FIELDS:
            value = row.get(field)
            if value is None:
                continue
            if isinstance(value, (list, tuple)) and not value and existing.get(field):
                continue
            existing[field] = value
    return list(merged.values())
