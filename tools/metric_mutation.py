#!/usr/bin/env python3
"""Mutation harness for decompiler-quality metrics: sensitivity AND specificity.

`docs/design/metrics-research/calibration.md` section 2 asks for a mutation
instrument with **two halves**, and records that the pilot in
`what-ged-measures.md` section 5 built only the first one -- which is why no
specificity number appears anywhere in that directory. This is both halves.

  * **Sensitivity.** Inject a defect that changes what the program does. A
    metric that still calls the result perfect did not see the defect. The
    class-level rate is the detection rate.
  * **Specificity.** Apply a rewrite that a correct decompiler is entitled to
    emit and that a C compiler must treat as equivalent. A metric that stops
    calling the result perfect has raised a false alarm, and is punishing a
    decompiler for being right in a different way.

Neither half is a metric on its own: a metric that flags everything has perfect
sensitivity, and a metric that flags nothing has perfect specificity. The report
is a confusion matrix per mutation class per metric, and the summary is the
**pair**, never their average.

The two metrics scored here are the two that are actually in circulation, and
they differ (`docs/design/metrics-research/README.md`, "Two things worth
knowing"):

  * ``ged`` -- `decbench.metrics.ged.GEDMetric._compute_uncached`, which is
    three steps: role-labelled isomorphism (score 0.0), a size lower bound above
    the 200-node cap, then ``max(1.0, vj_ged(...))``. **Perfect is exactly
    isomorphic**; the clamp means a non-isomorphic pair can never score 0.
  * ``vj_ged_raw`` -- bare ``vj_ged``, the semantics our fork's local gate still
    runs. Perfect there means only that two multisets of
    ``(in_degree, out_degree, is_entrypoint, is_exitpoint)`` agree, which is a
    strictly weaker claim.

Both verdicts are computed here from first principles rather than imported,
because the DecBench fork's venv is not the environment the Glaurung suite runs
in. The isomorphism test replicates DecBench's joint 1-WL colour refinement and
then confirms with an exact backtracking search, so it is not an approximation;
``vj_ged == 0`` is decided exactly by multiset equality, which is sound because
every cell of the VJ cost matrix is a function of those four numbers alone
(`docs/design/static-c-analysis/joern-behavior.md` section 2). The numeric VJ
distance, used only for magnitude reporting, is a pure-Python
shortest-augmenting-path LSAP.

Determinism. Every site choice is drawn from a `random.Random` seeded with
``(seed, unit key, mutation class)``, so a result does not depend on corpus
order, on ``--limit``, or on which classes were selected. The seed is recorded
in the report. Nothing here reads a wall clock; the one budget is a step count.

Declines are results. A mutation whose pattern does not occur, or whose
precondition fails, is reported with its reason -- never dropped. A class that
declines 99% of the time has a detection rate computed over a handful of
mutants, and the report has to say so.

    export TMPDIR="$HOME/.cache/glaurung/tmp"

    # the published benchmark sources (300 real functions), both halves
    uv run python tools/metric_mutation.py --corpus samples

    # Glaurung's own decompiled C, at scale
    uv run python tools/metric_mutation.py --corpus tree --limit 400

    # one class, with the per-decline breakdown
    uv run python tools/metric_mutation.py --classes goto-ify --verbose

Exit codes: 0 when the run produced mutants; 1 when a class that was selected
produced none at all (an instrument that measured nothing must not read as a
pass); 2 when the corpus or the extension is missing.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Sequence

# --------------------------------------------------------------------------
# corpus locations
# --------------------------------------------------------------------------

#: The 300 published benchmark functions, each carrying its real `source_code`.
DEFAULT_SAMPLES = (
    Path.home()
    / ".cache"
    / "glaurung"
    / "decbench-full"
    / "published_function_results.json"
)

#: The materialized evaluation tree, whose `decompiled/*.c` are Glaurung's own.
DEFAULT_TREE = Path.home() / ".cache" / "glaurung" / "decbench-full" / "tree"

#: Fixed default seed. Changing it is a new experiment, not a re-run.
DEFAULT_SEED = 20260904

#: DecBench's `GED_MAX_NODES`, above which GED stops computing a distance.
GED_MAX_NODES = 200

#: `cfgutils.similarity.ged.INVALID_CHOICE_PENALTY`, the role-mismatch cost.
INVALID_CHOICE_PENALTY = 100000

#: Rows above which the pure-Python LSAP is not run. Magnitude only: it can
#: never change a perfect/not-perfect verdict, which step 1 already decided.
DEFAULT_MAGNITUDE_MAX_ROWS = 160

#: Backtracking steps allowed per isomorphism test. Work, not wall clock
#: (`calibration.md` section 5): exhaustion is an error that is reported and
#: excluded, never a value that scores something.
ISO_STEP_BUDGET = 200000


class Declined(Exception):
    """A mutation could not be applied, with the reason it could not.

    Raised by every mutator instead of returning ``None`` so that a decline
    always carries a reason into the report. `calibration.md` treats decline
    rates as findings -- the pilot's 0.55%-style rates are data about the
    corpus, not noise to be swallowed.
    """


class IsomorphismBudgetExhausted(Exception):
    """The backtracking isomorphism search exceeded :data:`ISO_STEP_BUDGET`."""


# --------------------------------------------------------------------------
# C text utilities
# --------------------------------------------------------------------------

_KEYWORD_CALLS = frozenset(
    {"if", "while", "for", "switch", "return", "sizeof", "defined", "do"}
)

_TYPE_WORDS = (
    r"const|static|volatile|register|extern|auto|inline|typedef|"
    r"unsigned|signed|struct|union|enum|"
    r"int|char|long|short|float|double|void|_Bool|_Complex"
)

#: A statement that declares something. Wrapping one in braces, or duplicating
#: it into two branches, changes scope -- so every mutator that moves a
#: statement declines on this.
_DECL_RE = re.compile(
    rf"^\s*(?:(?:{_TYPE_WORDS})\b|\w+_t\b|[A-Za-z_]\w*\s+\**\s*[A-Za-z_]\w*\s*(?:=|;|\[|,))"
)

_LABEL_DEF_RE = re.compile(r"(?m)^\s*(?!case\b|default\b)([A-Za-z_]\w*)\s*:(?!:)")


def code_mask(text: str) -> list[bool]:
    """Mark every character that is ordinary C code.

    Positions inside a string literal, a character literal, a comment, or a
    preprocessor directive line are ``False``. Every regex in this module is
    filtered through this, because a ``<`` inside ``#include <stdio.h>`` and a
    ``==`` inside a string are not operators.

    Args:
        text: C source text.

    Returns:
        A list of length ``len(text)``; ``True`` where the character is code.
    """
    mask = [True] * len(text)
    index = 0
    length = len(text)
    at_line_start = True
    while index < length:
        char = text[index]
        if char == "\n":
            at_line_start = True
            index += 1
            continue
        if at_line_start and char in " \t":
            index += 1
            continue
        if at_line_start and char == "#":
            # A directive runs to the end of the line, and keeps running while
            # the line ends with a backslash.
            while index < length:
                mask[index] = False
                if text[index] == "\n" and not text[index - 1 : index] == "\\":
                    break
                index += 1
            at_line_start = True
            continue
        at_line_start = False
        if char == "/" and text[index : index + 2] == "//":
            while index < length and text[index] != "\n":
                mask[index] = False
                index += 1
            continue
        if char == "/" and text[index : index + 2] == "/*":
            end = text.find("*/", index + 2)
            end = length if end < 0 else end + 2
            for position in range(index, end):
                mask[position] = False
            index = end
            continue
        if char in "\"'":
            quote = char
            mask[index] = False
            index += 1
            while index < length:
                mask[index] = False
                if text[index] == "\\":
                    index += 2
                    if index - 1 < length:
                        mask[index - 1] = False
                    continue
                if text[index] == quote:
                    index += 1
                    break
                index += 1
            continue
        index += 1
    return mask


def code_sites(
    text: str, pattern: re.Pattern[str], mask: list[bool]
) -> list[re.Match[str]]:
    """Every match of `pattern` that lies entirely in code.

    Args:
        text: C source text.
        pattern: The compiled pattern to search for.
        mask: The :func:`code_mask` of `text`.

    Returns:
        The matches, in source order.
    """
    return [
        match
        for match in pattern.finditer(text)
        if all(
            mask[position]
            for position in range(match.start(), max(match.end(), match.start() + 1))
        )
    ]


def pick(
    rng: random.Random, sites: Sequence[re.Match[str]], what: str
) -> re.Match[str]:
    """Choose one site, deterministically for a given seeded `rng`.

    Args:
        rng: The seeded generator for this (unit, class) pair.
        sites: Candidate sites.
        what: Name of the thing being looked for, used in the decline reason.

    Returns:
        One of `sites`.

    Raises:
        Declined: If `sites` is empty.
    """
    if not sites:
        raise Declined(f"no {what}")
    return sites[rng.randrange(len(sites))]


def match_forward(
    text: str, start: int, mask: list[bool], opener: str, closer: str
) -> int:
    """Index of the delimiter matching the one at `start`.

    Args:
        text: C source text.
        start: Index of the opening delimiter.
        mask: The :func:`code_mask` of `text`.
        opener: The opening delimiter character.
        closer: The closing delimiter character.

    Returns:
        The index of the matching closing delimiter.

    Raises:
        Declined: If the delimiter is never closed.
    """
    depth = 0
    for index in range(start, len(text)):
        if not mask[index]:
            continue
        if text[index] == opener:
            depth += 1
        elif text[index] == closer:
            depth -= 1
            if depth == 0:
                return index
    raise Declined(f"unbalanced {opener!r}")


def next_code(text: str, index: int, mask: list[bool]) -> int | None:
    """Index of the first code character at or after `index`, or None."""
    for position in range(max(index, 0), len(text)):
        if mask[position] and not text[position].isspace():
            return position
    return None


def prev_code(text: str, index: int, mask: list[bool]) -> int | None:
    """Index of the last code character at or before `index`, or None."""
    for position in range(min(index, len(text) - 1), -1, -1):
        if mask[position] and not text[position].isspace():
            return position
    return None


def word_at(text: str, end: int) -> str:
    """The identifier ending at `end` inclusive, or the empty string."""
    stop = min(end + 1, len(text))
    start = stop
    while start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"):
        start -= 1
    return text[start:stop]


def split_top_level(
    text: str, mask: list[bool], base: int, separator: str
) -> list[tuple[int, int]]:
    """Spans of `text` split on `separator` at paren/bracket/brace depth zero.

    Args:
        text: The whole source text.
        mask: The :func:`code_mask` of `text`.
        base: Index in `text` at which the region to split begins.
        separator: A single separator character, or ``"&&"`` / ``"||"``.

    Returns:
        ``(start, end)`` spans, one per part, in source order. The region is
        assumed to run to the end of `text`; callers slice first.
    """
    spans: list[tuple[int, int]] = []
    depth = 0
    part_start = base
    index = base
    width = len(separator)
    while index < len(text):
        if not mask[index]:
            index += 1
            continue
        char = text[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif depth == 0 and text[index : index + width] == separator:
            spans.append((part_start, index))
            part_start = index + width
            index += width
            continue
        index += 1
    spans.append((part_start, len(text)))
    return spans


def paren_body(text: str, open_index: int, mask: list[bool]) -> tuple[int, int]:
    """``(first, last)`` indices bounding the contents of a parenthesis pair."""
    close_index = match_forward(text, open_index, mask, "(", ")")
    return open_index + 1, close_index


def has_code_word(text: str, mask: list[bool], word: str) -> bool:
    """Whether `word` occurs as a whole identifier in code."""
    return bool(code_sites(text, re.compile(rf"\b{re.escape(word)}\b"), mask))


def require_blank_gap(text: str, start: int, end: int) -> None:
    """Insist that ``text[start:end]`` is whitespace.

    Every structural mutator here reassembles a region from its parts, so
    anything sitting in a gap between those parts is dropped. Whitespace may be
    dropped; a comment or -- the case that actually occurred in the corpus, in
    `shadow`'s ``usage`` -- an ``#endif`` between ``}`` and ``else`` may not.
    A rewrite that deletes a directive is not meaning-preserving, so the site is
    declined instead.

    Args:
        text: C source text.
        start: Start of the gap.
        end: End of the gap.

    Raises:
        Declined: If the gap holds anything but whitespace.
    """
    if text[start:end].strip():
        raise Declined("directive or comment inside the rewritten region")


def braced_body_after(text: str, index: int, mask: list[bool]) -> tuple[int, int]:
    """``(open, close)`` of the braced block starting at or after `index`.

    Raises:
        Declined: If the next code character is not ``{``, or if anything but
            whitespace separates `index` from it.
    """
    start = next_code(text, index, mask)
    if start is None or text[start] != "{":
        raise Declined("body is not a braced block")
    require_blank_gap(text, index, start)
    return start, match_forward(text, start, mask, "{", "}")


# --------------------------------------------------------------------------
# CFGs and the two metric verdicts
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Cfg:
    """A control-flow graph reduced to what DecBench's GED can read.

    Attributes:
        nodes: Node ids.
        edges: Directed edges.
        entry: Ids flagged ``is_entrypoint``.
        exit: Ids flagged ``is_exitpoint``.
        degenerate: The front end's own flag; a degenerate source CFG is
            dropped from GED's denominator upstream, so units with one are
            excluded here too.
    """

    nodes: tuple[int, ...]
    edges: tuple[tuple[int, int], ...]
    entry: frozenset[int]
    exit: frozenset[int]
    degenerate: bool

    @staticmethod
    def from_serialized(serialized: dict[str, object]) -> "Cfg":
        """Build a :class:`Cfg` from `glaurung.source_cfg.parity_cfgs` output.

        Args:
            serialized: One function's ``{"nodes", "edges", "entry", "exit",
                "degenerate"}`` mapping.

        Returns:
            The corresponding :class:`Cfg`.
        """
        nodes = tuple(int(n) for n in serialized["nodes"])  # type: ignore[arg-type]
        edges = tuple((int(a), int(b)) for a, b in serialized["edges"])  # type: ignore[misc]
        return Cfg(
            nodes=nodes,
            edges=edges,
            entry=frozenset(int(n) for n in serialized["entry"]),  # type: ignore[arg-type]
            exit=frozenset(int(n) for n in serialized["exit"]),  # type: ignore[arg-type]
            degenerate=bool(serialized.get("degenerate", False)),
        )

    def role(self, node: int) -> tuple[bool, bool]:
        """The ``(is_entrypoint, is_exitpoint)`` pair GED labels nodes with."""
        return (node in self.entry, node in self.exit)

    def degrees(self) -> dict[int, tuple[int, int]]:
        """``{node: (in_degree, out_degree)}``, counting parallel edges once.

        `networkx.DiGraph` collapses duplicate edges, and the published CFGs
        are rebuilt into one, so the same collapsing is applied here.
        """
        distinct = set(self.edges)
        in_degree: Counter[int] = Counter()
        out_degree: Counter[int] = Counter()
        for source, target in distinct:
            out_degree[source] += 1
            in_degree[target] += 1
        return {node: (in_degree[node], out_degree[node]) for node in self.nodes}

    def distinct_edges(self) -> set[tuple[int, int]]:
        """The edge set, with parallel edges collapsed as `networkx` does."""
        return set(self.edges)


def _joint_wl_colors(
    left: Cfg, right: Cfg, rounds: int = 8
) -> tuple[dict[int, int], dict[int, int]]:
    """DecBench's `_add_joint_refinement_colors`, reimplemented exactly.

    The palette is shared between the two graphs, so a colour that occurs in
    only one of them is by itself proof of non-isomorphism. The loop stops when
    neither graph's colour count grew, which is DecBench's own condition.

    Args:
        left: The first graph.
        right: The second graph.
        rounds: Refinement rounds; DecBench uses 8.

    Returns:
        One ``{node: colour}`` mapping per graph.
    """
    graphs = (left, right)
    degrees = [graph.degrees() for graph in graphs]
    predecessors: list[dict[int, list[int]]] = []
    successors: list[dict[int, list[int]]] = []
    for graph in graphs:
        preds: dict[int, list[int]] = {node: [] for node in graph.nodes}
        succs: dict[int, list[int]] = {node: [] for node in graph.nodes}
        for source, target in graph.distinct_edges():
            succs[source].append(target)
            preds[target].append(source)
        predecessors.append(preds)
        successors.append(succs)

    def assign(signatures: list[dict[int, tuple[object, ...]]]) -> list[dict[int, int]]:
        palette: dict[tuple[object, ...], int] = {}
        assigned: list[dict[int, int]] = [{}, {}]
        for index, graph in enumerate(graphs):
            for node in graph.nodes:
                assigned[index][node] = palette.setdefault(
                    signatures[index][node], len(palette)
                )
        return assigned

    colors = assign(
        [
            {
                node: (
                    graph.role(node),
                    degrees[index][node][0],
                    degrees[index][node][1],
                )
                for node in graph.nodes
            }
            for index, graph in enumerate(graphs)
        ]
    )
    for _ in range(rounds):
        refined = [
            {
                node: (
                    colors[index][node],
                    tuple(sorted(colors[index][p] for p in predecessors[index][node])),
                    tuple(sorted(colors[index][s] for s in successors[index][node])),
                )
                for node in graph.nodes
            }
            for index, graph in enumerate(graphs)
        ]
        new_colors = assign(refined)
        grew = any(
            len(set(new_colors[index].values())) != len(set(colors[index].values()))
            for index in range(2)
        )
        colors = new_colors
        if not grew:
            break
    return colors[0], colors[1]


def is_isomorphic(left: Cfg, right: Cfg) -> bool:
    """DecBench's role-labelled CFG isomorphism test, decided exactly.

    DecBench colours both graphs with a joint 1-WL refinement and then hands
    them to VF2 with a categorical match on ``(role, iso_color)``. This does the
    same in two stages: the colour multisets must agree (which is what makes
    VF2 cheap upstream), and then a backtracking search confirms an actual
    role- and colour-respecting isomorphism exists.

    Args:
        left: The reference graph.
        right: The candidate graph.

    Returns:
        Whether the two graphs are isomorphic under DecBench's node labelling.

    Raises:
        IsomorphismBudgetExhausted: If the search exceeded
            :data:`ISO_STEP_BUDGET` steps. Reported by the caller and excluded
            from the matrix; never silently answered.
    """
    if len(left.nodes) != len(right.nodes):
        return False
    left_edges = left.distinct_edges()
    right_edges = right.distinct_edges()
    if len(left_edges) != len(right_edges):
        return False
    if Counter(left.role(n) for n in left.nodes) != Counter(
        right.role(n) for n in right.nodes
    ):
        return False

    left_colors, right_colors = _joint_wl_colors(left, right)
    if Counter(left_colors.values()) != Counter(right_colors.values()):
        return False

    left_succ = {node: set() for node in left.nodes}
    left_pred = {node: set() for node in left.nodes}
    for source, target in left_edges:
        left_succ[source].add(target)
        left_pred[target].add(source)
    right_succ = {node: set() for node in right.nodes}
    right_pred = {node: set() for node in right.nodes}
    for source, target in right_edges:
        right_succ[source].add(target)
        right_pred[target].add(source)

    candidates: dict[int, list[int]] = {
        node: sorted(
            other
            for other in right.nodes
            if right_colors[other] == left_colors[node]
            and right.role(other) == left.role(node)
        )
        for node in left.nodes
    }
    if any(not options for options in candidates.values()):
        return False

    # Most constrained first, then by node id so the order is total.
    order = sorted(left.nodes, key=lambda node: (len(candidates[node]), node))
    mapping: dict[int, int] = {}
    used: set[int] = set()
    steps = 0

    def extend(position: int) -> bool:
        nonlocal steps
        if position == len(order):
            return True
        node = order[position]
        for option in candidates[node]:
            steps += 1
            if steps > ISO_STEP_BUDGET:
                raise IsomorphismBudgetExhausted(
                    f"isomorphism search exceeded {ISO_STEP_BUDGET} steps "
                    f"on a {len(left.nodes)}-node pair"
                )
            if option in used:
                continue
            consistent = True
            for mapped, image in mapping.items():
                if (mapped in left_succ[node]) != (image in right_succ[option]):
                    consistent = False
                    break
                if (mapped in left_pred[node]) != (image in right_pred[option]):
                    consistent = False
                    break
            if not consistent:
                continue
            # Self-loops are part of the label, not of the neighbour check.
            if (node in left_succ[node]) != (option in right_succ[option]):
                continue
            mapping[node] = option
            used.add(option)
            if extend(position + 1):
                return True
            del mapping[node]
            used.discard(option)
        return False

    return extend(0)


def vj_ged_is_zero(left: Cfg, right: Cfg) -> bool:
    """Whether bare ``vj_ged`` would return exactly 0.

    Every cell of the VJ cost matrix is a function of ``(in_degree,
    out_degree, is_entrypoint, is_exitpoint)``; deletion and insertion cost
    ``1 + in + out``, which is strictly positive. A total of zero therefore
    requires equal node counts and a zero-cost bijection, i.e. equal multisets
    of those four numbers. This is exact, not a heuristic.

    Args:
        left: The reference graph.
        right: The candidate graph.

    Returns:
        Whether the two degree/role multisets agree.
    """
    if len(left.nodes) != len(right.nodes):
        return False
    left_degrees = left.degrees()
    right_degrees = right.degrees()
    return Counter(
        (left_degrees[n][0], left_degrees[n][1], *left.role(n)) for n in left.nodes
    ) == Counter(
        (right_degrees[n][0], right_degrees[n][1], *right.role(n)) for n in right.nodes
    )


def _lsap(cost: list[list[float]]) -> float:
    """Minimum-cost perfect assignment on a square matrix.

    The Jonker-Volgenant shortest-augmenting-path form, which is what
    `scipy.optimize.linear_sum_assignment` computes. Ties are broken by the
    ascending column scan and a strict ``<``, so the traceback is a total order
    (`calibration.md` section 5, determinism point 2).

    Args:
        cost: A square, finite cost matrix.

    Returns:
        The minimum total cost.
    """
    size = len(cost)
    infinity = float("inf")
    potential_u = [0.0] * (size + 1)
    potential_v = [0.0] * (size + 1)
    match = [0] * (size + 1)
    way = [0] * (size + 1)
    for row in range(1, size + 1):
        match[0] = row
        column = 0
        minimal = [infinity] * (size + 1)
        used = [False] * (size + 1)
        while True:
            used[column] = True
            current_row = match[column]
            delta = infinity
            next_column = 0
            for candidate in range(1, size + 1):
                if used[candidate]:
                    continue
                value = (
                    cost[current_row - 1][candidate - 1]
                    - potential_u[current_row]
                    - potential_v[candidate]
                )
                if value < minimal[candidate]:
                    minimal[candidate] = value
                    way[candidate] = column
                if minimal[candidate] < delta:
                    delta = minimal[candidate]
                    next_column = candidate
            for candidate in range(size + 1):
                if used[candidate]:
                    potential_u[match[candidate]] += delta
                    potential_v[candidate] -= delta
                else:
                    minimal[candidate] -= delta
            column = next_column
            if match[column] == 0:
                break
        while column:
            previous = way[column]
            match[column] = match[previous]
            column = previous
    return sum(cost[match[c] - 1][c - 1] for c in range(1, size + 1))


def vj_ged(left: Cfg, right: Cfg) -> float:
    """`decbench.metrics.vj_ged.vj_ged`, reimplemented without scipy.

    Args:
        left: The source-side graph.
        right: The decompiled-side graph.

    Returns:
        The VJ graph edit distance.
    """
    left_nodes = list(left.nodes)
    right_nodes = list(right.nodes)
    left_degrees = left.degrees()
    right_degrees = right.degrees()
    n = len(left_nodes)
    m = len(right_nodes)
    size = n + m
    # A sentinel stands in for numpy's `inf`: a feasible assignment avoiding
    # every sentinel always exists (the two diagonals plus the zero block), so
    # the optimum never selects one.
    blocked = 1e12
    cost = [[0.0] * size for _ in range(size)]
    for row in range(n, size):
        for column in range(m):
            cost[row][column] = blocked
    for row in range(n):
        for column in range(m, size):
            cost[row][column] = blocked
    for index, node in enumerate(right_nodes):
        cost[n + index][index] = 1.0 + right_degrees[node][0] + right_degrees[node][1]
    for index, node in enumerate(left_nodes):
        cost[index][m + index] = 1.0 + left_degrees[node][0] + left_degrees[node][1]
    for row, left_node in enumerate(left_nodes):
        for column, right_node in enumerate(right_nodes):
            value = float(
                abs(left_degrees[left_node][1] - right_degrees[right_node][1])
                + abs(left_degrees[left_node][0] - right_degrees[right_node][0])
            )
            if left.role(left_node) != right.role(right_node):
                value += INVALID_CHOICE_PENALTY
            cost[row][column] = value
    return _lsap(cost)


@dataclass(frozen=True)
class Verdict:
    """One metric's opinion about one (reference, mutant) pair.

    Attributes:
        perfect: Whether the metric calls the mutant a perfect match.
        value: The metric's number, when it was computed.
        method: How `value` was reached, mirroring GED's own `method` metadata.
    """

    perfect: bool
    value: float | None
    method: str


def ged_verdict(
    reference: Cfg, mutant: Cfg, *, magnitude_max_rows: int = DEFAULT_MAGNITUDE_MAX_ROWS
) -> Verdict:
    """`GEDMetric._compute_uncached`'s three steps.

    Step 1 decides the perfect verdict on its own: isomorphic scores 0.0, and
    both remaining branches are wrapped in ``max(1.0, ...)``, so a
    non-isomorphic pair can never score 0. Steps 2 and 3 only set the
    magnitude, and step 3 is skipped above `magnitude_max_rows` because the
    pure-Python LSAP is cubic -- a skip that is reported and can never change a
    verdict.

    Args:
        reference: The unmutated function's CFG, standing in for the source.
        mutant: The mutated function's CFG, standing in for the decompilation.
        magnitude_max_rows: Cost-matrix rows above which step 3 is not run.

    Returns:
        The metric's :class:`Verdict`.
    """
    if is_isomorphic(reference, mutant):
        return Verdict(perfect=True, value=0.0, method="isomorphism")
    if len(reference.nodes) > GED_MAX_NODES or len(mutant.nodes) > GED_MAX_NODES:
        approximate = max(
            1.0,
            float(
                abs(len(reference.nodes) - len(mutant.nodes))
                + abs(len(reference.distinct_edges()) - len(mutant.distinct_edges()))
            ),
        )
        return Verdict(perfect=False, value=approximate, method="size_lower_bound")
    if len(reference.nodes) + len(mutant.nodes) > magnitude_max_rows:
        return Verdict(perfect=False, value=None, method="vj_ged (magnitude skipped)")
    return Verdict(
        perfect=False, value=max(1.0, vj_ged(reference, mutant)), method="vj_ged"
    )


def vj_ged_raw_verdict(
    reference: Cfg, mutant: Cfg, *, magnitude_max_rows: int = DEFAULT_MAGNITUDE_MAX_ROWS
) -> Verdict:
    """Bare ``vj_ged``, the semantics our fork's local gate still runs.

    Args:
        reference: The unmutated function's CFG.
        mutant: The mutated function's CFG.
        magnitude_max_rows: Cost-matrix rows above which the value is skipped.

    Returns:
        The metric's :class:`Verdict`. ``perfect`` is decided exactly by
        multiset equality even when the value itself is skipped.
    """
    perfect = vj_ged_is_zero(reference, mutant)
    if perfect:
        return Verdict(perfect=True, value=0.0, method="degree_multiset")
    if len(reference.nodes) + len(mutant.nodes) > magnitude_max_rows:
        return Verdict(perfect=False, value=None, method="vj_ged (magnitude skipped)")
    return Verdict(perfect=False, value=vj_ged(reference, mutant), method="vj_ged")


#: The metrics under test, in report order.
METRICS: dict[str, Callable[..., Verdict]] = {
    "ged": ged_verdict,
    "vj_ged_raw": vj_ged_raw_verdict,
}


# --------------------------------------------------------------------------
# the mutation catalogue
# --------------------------------------------------------------------------

#: ``changes`` -- the ground-truth label. ``True`` means the mutant must behave
#: differently from the original on some input, so a metric that calls it
#: perfect has a false negative. ``False`` means a C compiler must treat the two
#: as equivalent, so a metric that stops calling it perfect has a false alarm.
Mutator = Callable[[str, random.Random], str]


@dataclass(frozen=True)
class MutationClass:
    """One named source-to-source rewrite, with its ground-truth label.

    Attributes:
        name: The class name used in the report.
        changes: Whether the rewrite changes observable behaviour.
        apply: The rewrite. Raises :class:`Declined` when it does not apply.
        rationale: Why `changes` has the value it has. Every specificity class
            has to argue this; `calibration.md` section 2.1 requires the label
            be justified per class, not assumed.
        caveat: A stated limit on `rationale`, or the empty string.
    """

    name: str
    changes: bool
    apply: Mutator
    rationale: str
    caveat: str = ""


# ---- sensitivity: rewrites that change what the program does --------------

_IF_RE = re.compile(r"\bif\s*\(")
_WHILE_RE = re.compile(r"\bwhile\s*\(")
_FOR_RE = re.compile(r"\bfor\s*\(")
_ELSE_RE = re.compile(r"\belse\b")
_EQ_RE = re.compile(r"(?<![=!<>])==(?!=)")
_LT_RE = re.compile(r"(?<![<>=!])<(?![<=])")
_GT_RE = re.compile(r"(?<![<>=!\-])>(?![>=])")
_LE_RE = re.compile(r"(?<![<>=!])<=")
_GE_RE = re.compile(r"(?<![<>=!\-])>=")
_AND_RE = re.compile(r"(?<!&)&&(?!&)")
_OR_RE = re.compile(r"(?<!\|)\|\|(?!\|)")
_PLUS_RE = re.compile(r"(?<=[\w)\]])\s*\+(?![+=])\s*(?=[\w(])")
_INT_RE = re.compile(r"(?<![\w.])([0-9]+)(?![\w.])")
_INC_STMT_RE = re.compile(r"(?<![\w.>])([A-Za-z_]\w*)\+\+\s*;")
_DEC_STMT_RE = re.compile(r"(?<![\w.>])([A-Za-z_]\w*)--\s*;")
_BREAK_RE = re.compile(r"\bbreak\s*;")
_PLUS_ASSIGN_RE = re.compile(r"\+=")
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_DO_RE = re.compile(r"\bdo\b")


def _replace(text: str, start: int, end: int, replacement: str) -> str:
    """Splice `replacement` into `text` over ``[start, end)``."""
    return text[:start] + replacement + text[end:]


def _flip_operator(
    text: str,
    rng: random.Random,
    table: Sequence[tuple[re.Pattern[str], str]],
    what: str,
) -> str:
    """Replace one occurrence of one of `table`'s operators with its partner."""
    mask = code_mask(text)
    options = [
        (match, replacement)
        for pattern, replacement in table
        for match in code_sites(text, pattern, mask)
    ]
    if not options:
        raise Declined(f"no {what}")
    match, replacement = options[rng.randrange(len(options))]
    return _replace(text, match.start(), match.end(), replacement)


def mutate_negate_condition(text: str, rng: random.Random) -> str:
    """Wrap one ``if`` condition in ``!( ... )``."""
    mask = code_mask(text)
    site = pick(rng, code_sites(text, _IF_RE, mask), "if statement")
    first, last = paren_body(text, site.end() - 1, mask)
    return _replace(text, first, last, "!(" + text[first:last] + ")")


def mutate_equality_flip(text: str, rng: random.Random) -> str:
    """Turn one ``==`` into ``!=``."""
    return _flip_operator(text, rng, [(_EQ_RE, "!=")], "== operator")


def mutate_relational_flip(text: str, rng: random.Random) -> str:
    """Reverse one relational operator: ``<`` to ``>=``, ``>`` to ``<=``."""
    return _flip_operator(
        text,
        rng,
        [(_LT_RE, ">="), (_GT_RE, "<="), (_LE_RE, ">"), (_GE_RE, "<")],
        "relational operator",
    )


def mutate_off_by_one(text: str, rng: random.Random) -> str:
    """Shift one relational bound by one: ``<`` to ``<=``, ``>=`` to ``>``."""
    return _flip_operator(
        text,
        rng,
        [(_LT_RE, "<="), (_GT_RE, ">="), (_LE_RE, "<"), (_GE_RE, ">")],
        "relational bound",
    )


def mutate_logic_flip(text: str, rng: random.Random) -> str:
    """Swap one ``&&`` for ``||`` or one ``||`` for ``&&``."""
    return _flip_operator(
        text, rng, [(_AND_RE, "||"), (_OR_RE, "&&")], "logical operator"
    )


def mutate_arith_flip(text: str, rng: random.Random) -> str:
    """Turn one binary ``+`` into ``-``."""
    mask = code_mask(text)
    site = pick(rng, code_sites(text, _PLUS_RE, mask), "binary + operator")
    return _replace(text, site.start(), site.end(), " - ")


def mutate_assign_op_flip(text: str, rng: random.Random) -> str:
    """Turn one ``+=`` into ``-=``."""
    return _flip_operator(text, rng, [(_PLUS_ASSIGN_RE, "-=")], "+= operator")


def mutate_constant_bump(text: str, rng: random.Random) -> str:
    """Add one to a decimal integer literal."""
    mask = code_mask(text)
    site = pick(rng, code_sites(text, _INT_RE, mask), "integer literal")
    return _replace(text, site.start(), site.end(), str(int(site.group(1)) + 1))


def mutate_incr_to_decr(text: str, rng: random.Random) -> str:
    """Turn one ``x++;`` into ``x--;`` (or the reverse)."""
    mask = code_mask(text)
    options = code_sites(text, _INC_STMT_RE, mask) + code_sites(
        text, _DEC_STMT_RE, mask
    )
    site = pick(rng, options, "increment or decrement statement")
    name = site.group(1)
    operator = "--" if "++" in site.group(0) else "++"
    return _replace(text, site.start(), site.end(), f"{name}{operator};")


def mutate_null_body(text: str, rng: random.Random) -> str:
    """Replace the whole function body with ``{ return 0; }``.

    The null decompiler of `calibration.md` section 4, applied per function.
    """
    del rng
    mask = code_mask(text)
    start = next((i for i in range(len(text)) if mask[i] and text[i] == "{"), None)
    if start is None:
        raise Declined("no function body")
    end = match_forward(text, start, mask, "{", "}")
    return _replace(text, start, end + 1, "{ return 0; }")


def _reject_do_while(text: str, mask: list[bool], site: re.Match[str]) -> None:
    """Decline when a ``while`` token is the tail of a ``do ... while``.

    Raises:
        Declined: If this `while` closes a do-loop, or if the unit contains a
            ``do`` whose shape cannot be resolved from the text alone.
    """
    previous = prev_code(text, site.start() - 1, mask)
    if previous is not None and text[previous] == "}":
        depth = 0
        for index in range(previous, -1, -1):
            if not mask[index]:
                continue
            if text[index] == "}":
                depth += 1
            elif text[index] == "{":
                depth -= 1
                if depth == 0:
                    before = prev_code(text, index - 1, mask)
                    if before is not None and word_at(text, before) == "do":
                        raise Declined("do-while tail")
                    return
        raise Declined("unbalanced block before while")
    if code_sites(text, _DO_RE, mask):
        raise Declined("unbraced do-while cannot be excluded")


def mutate_while_to_if(text: str, rng: random.Random) -> str:
    """Turn one ``while`` loop into an ``if``, deleting the back edge."""
    mask = code_mask(text)
    sites = []
    for candidate in code_sites(text, _WHILE_RE, mask):
        try:
            _reject_do_while(text, mask, candidate)
        except Declined:
            continue
        sites.append(candidate)
    site = pick(rng, sites, "while loop that is not a do-while tail")
    return _replace(text, site.start(), site.start() + len("while"), "if")


def mutate_drop_break(text: str, rng: random.Random) -> str:
    """Delete one ``break;``."""
    mask = code_mask(text)
    site = pick(rng, code_sites(text, _BREAK_RE, mask), "break statement")
    return _replace(text, site.start(), site.end(), ";")


def mutate_else_to_if_false(text: str, rng: random.Random) -> str:
    """Turn one ``else`` into ``if (0)``, deleting the fallback arm."""
    mask = code_mask(text)
    site = pick(rng, code_sites(text, _ELSE_RE, mask), "else clause")
    return _replace(text, site.start(), site.end(), "if (0)")


def _statement_call_sites(text: str, mask: list[bool]) -> list[tuple[int, int, str]]:
    """Spans of statements that are exactly one call, plus the callee name."""
    found: list[tuple[int, int, str]] = []
    for match in code_sites(text, _CALL_RE, mask):
        name = match.group(1)
        if name in _KEYWORD_CALLS:
            continue
        try:
            close = match_forward(text, match.end() - 1, mask, "(", ")")
        except Declined:
            continue
        after = next_code(text, close + 1, mask)
        if after is None or text[after] != ";":
            continue
        before = prev_code(text, match.start() - 1, mask)
        if before is None or text[before] not in ";{}":
            continue
        found.append((match.start(), after + 1, name))
    return found


def mutate_drop_call(text: str, rng: random.Random) -> str:
    """Delete one statement that is nothing but a call.

    `calibration.md` section 2.1's `drop-call`: the result was unused, so only
    the callee's side effects are lost.
    """
    mask = code_mask(text)
    sites = _statement_call_sites(text, mask)
    if not sites:
        raise Declined("no call statement")
    start, end, _ = sites[rng.randrange(len(sites))]
    return _replace(text, start, end, "")


def mutate_swap_args(text: str, rng: random.Random) -> str:
    """Exchange two identifier arguments at one call site."""
    mask = code_mask(text)
    options: list[tuple[int, int, int, int]] = []
    for match in code_sites(text, _CALL_RE, mask):
        if match.group(1) in _KEYWORD_CALLS:
            continue
        try:
            first, last = paren_body(text, match.end() - 1, mask)
        except Declined:
            continue
        inner = text[first:last]
        if not inner.strip():
            continue
        spans = [
            (first + start, first + end)
            for start, end in split_top_level(inner, code_mask(inner), 0, ",")
        ]
        simple = [
            span
            for span in spans
            if re.fullmatch(r"\s*[A-Za-z_]\w*\s*", text[span[0] : span[1]])
        ]
        for index in range(len(simple)):
            for other in range(index + 1, len(simple)):
                if (
                    text[simple[index][0] : simple[index][1]].strip()
                    != text[simple[other][0] : simple[other][1]].strip()
                ):
                    options.append((*simple[index], *simple[other]))
    if not options:
        raise Declined("no call with two distinct identifier arguments")
    left_start, left_end, right_start, right_end = options[rng.randrange(len(options))]
    left = text[left_start:left_end].strip()
    right = text[right_start:right_end].strip()
    out = _replace(text, right_start, right_end, left)
    return _replace(out, left_start, left_end, right)


# ---- specificity: rewrites a C compiler must treat as equivalent ----------


def mutate_whitespace_reflow(text: str, rng: random.Random) -> str:
    """Insert a newline and indentation after a statement terminator.

    C outside a preprocessor directive, a string, or a character constant is
    free-form, so this cannot change meaning. :func:`code_mask` excludes all
    three, so the insertion point is always in free-form territory.
    """
    mask = code_mask(text)
    sites = code_sites(text, re.compile(r";"), mask)
    site = pick(rng, sites, "statement terminator")
    return _replace(text, site.end(), site.end(), "\n    \n\t")


def mutate_comment_insert(text: str, rng: random.Random) -> str:
    """Insert a block comment at a statement boundary.

    A comment is replaced by one space in translation phase 3, so this is a
    whitespace change and nothing more.
    """
    mask = code_mask(text)
    sites = code_sites(text, re.compile(r";"), mask)
    site = pick(rng, sites, "statement terminator")
    return _replace(text, site.end(), site.end(), " /* metric mutation probe */ ")


def mutate_rename_parameter(text: str, rng: random.Random) -> str:
    """Rename one parameter, and every reference to it, consistently.

    A parameter's name is not observable. The rewrite declines when the new
    name already occurs, so it cannot capture; occurrences after ``.`` or
    ``->`` are member names in a different namespace and are left alone.
    """
    mask = code_mask(text)
    body = next((i for i in range(len(text)) if mask[i] and text[i] == "{"), None)
    if body is None:
        raise Declined("no function body")
    header = text[:body]
    header_mask = mask[:body]
    opens = [i for i in range(body) if header_mask[i] and header[i] == "("]
    if not opens:
        raise Declined("no parameter list")
    first, last = paren_body(text, opens[-1], mask)
    inner = text[first:last]
    if not inner.strip() or inner.strip() == "void":
        raise Declined("no parameters")
    names: list[str] = []
    for start, end in split_top_level(inner, code_mask(inner), 0, ","):
        piece = inner[start:end]
        found = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", piece)
        if found and found.group(1) not in {"void", "int", "char", "long", "short"}:
            names.append(found.group(1))
    if not names:
        raise Declined("no named parameter")
    old = names[rng.randrange(len(names))]
    new = f"{old}_gmr"
    if has_code_word(text, mask, new):
        raise Declined(f"renamed identifier {new} already present")
    pattern = re.compile(rf"(?<![\w.])(?<!->)\b{re.escape(old)}\b")
    sites = code_sites(text, pattern, mask)
    if not sites:
        raise Declined("parameter never referenced")
    out = text
    for site in reversed(sites):
        out = _replace(out, site.start(), site.end(), new)
    return out


def mutate_int_literal_identity(text: str, rng: random.Random) -> str:
    """Rewrite a decimal integer literal ``N`` as ``(N + 0)``.

    Constant folding on an integer literal. Restricted to integer literals on
    purpose: ``x + 0`` on a general expression is *not* an identity for
    floating point (``-0.0 + 0.0`` is ``0.0``), and ``x * 1`` changes the type
    of a narrow operand in a variadic argument position.
    """
    mask = code_mask(text)
    site = pick(rng, code_sites(text, _INT_RE, mask), "integer literal")
    return _replace(text, site.start(), site.end(), f"({site.group(1)} + 0)")


def mutate_if_else_swap(text: str, rng: random.Random) -> str:
    """Swap the arms of an ``if``/``else`` and negate the condition.

    ``!(C)`` evaluates ``C`` exactly once, in the same place, so side effects
    and short-circuiting inside ``C`` are unaffected; only which arm runs on
    which value changes, and that is swapped back.
    """
    mask = code_mask(text)
    options: list[tuple[int, int, int, int, int, int]] = []
    for match in code_sites(text, _IF_RE, mask):
        try:
            first, last = paren_body(text, match.end() - 1, mask)
            then_open, then_close = braced_body_after(text, last + 1, mask)
        except Declined:
            continue
        after = next_code(text, then_close + 1, mask)
        if after is None or word_at(text, after + len("else") - 1) != "else":
            continue
        try:
            require_blank_gap(text, then_close + 1, after)
            else_open, else_close = braced_body_after(text, after + len("else"), mask)
        except Declined:
            continue
        options.append((first, last, then_open, then_close, else_open, else_close))
    if not options:
        raise Declined("no if/else with two braced arms")
    first, last, then_open, then_close, else_open, else_close = options[
        rng.randrange(len(options))
    ]
    condition = text[first:last]
    then_arm = text[then_open : then_close + 1]
    else_arm = text[else_open : else_close + 1]
    out = _replace(text, then_open, else_close + 1, f"{else_arm} else {then_arm}")
    return _replace(out, first, last, f"!({condition})")


def _split_condition_on_and(
    text: str, first: int, last: int, mask: list[bool]
) -> tuple[str, str]:
    """Split a condition at its first top-level ``&&``.

    Raises:
        Declined: If there is no top-level ``&&``, or if a top-level ``||`` is
            present -- ``||`` binds looser, so splitting at ``&&`` would
            reassociate the expression and change its meaning.
    """
    inner = text[first:last]
    inner_mask = mask[first:last]
    if len(split_top_level(inner, inner_mask, 0, "||")) > 1:
        raise Declined("top-level || in condition")
    parts = split_top_level(inner, inner_mask, 0, "&&")
    if len(parts) < 2:
        raise Declined("no top-level && in condition")
    head = inner[parts[0][0] : parts[0][1]]
    tail = inner[parts[1][0] :]
    return head.strip(), tail.strip()


def mutate_demorgan(text: str, rng: random.Random) -> str:
    """Rewrite ``A && B`` as ``!(!(A) || !(B))`` in one condition.

    De Morgan preserves short-circuit evaluation exactly: ``!(A)`` is true
    precisely when ``A`` is false, and ``||`` stops there, so ``B`` is
    evaluated under exactly the same condition as before. The value is 0 or 1
    either way.
    """
    mask = code_mask(text)
    options: list[tuple[int, int]] = []
    for pattern in (_IF_RE, _WHILE_RE):
        for match in code_sites(text, pattern, mask):
            try:
                first, last = paren_body(text, match.end() - 1, mask)
                _split_condition_on_and(text, first, last, mask)
            except Declined:
                continue
            options.append((first, last))
    if not options:
        raise Declined("no condition with a top-level && and no top-level ||")
    first, last = options[rng.randrange(len(options))]
    head, tail = _split_condition_on_and(text, first, last, mask)
    return _replace(text, first, last, f"!(!({head}) || !({tail}))")


def mutate_and_to_nested_if(text: str, rng: random.Random) -> str:
    """Rewrite ``if (A && B) { X }`` as ``if (A) { if (B) { X } }``.

    Declines when an ``else`` follows, which would have to be duplicated into
    both arms, and when the condition has a top-level ``||``.
    """
    mask = code_mask(text)
    options: list[tuple[int, int, int, int]] = []
    for match in code_sites(text, _IF_RE, mask):
        try:
            first, last = paren_body(text, match.end() - 1, mask)
            _split_condition_on_and(text, first, last, mask)
            body_open, body_close = braced_body_after(text, last + 1, mask)
        except Declined:
            continue
        after = next_code(text, body_close + 1, mask)
        if after is not None and word_at(text, after + len("else") - 1) == "else":
            continue
        options.append((first, last, body_open, body_close))
    if not options:
        raise Declined("no else-free if with a top-level &&")
    first, last, body_open, body_close = options[rng.randrange(len(options))]
    head, tail = _split_condition_on_and(text, first, last, mask)
    body = text[body_open : body_close + 1]
    out = _replace(text, body_open, body_close + 1, f"{{ if ({tail}) {body} }}")
    return _replace(out, first, last, head)


def mutate_for_to_while(text: str, rng: random.Random) -> str:
    """Rewrite ``for (init; cond; step) body`` as ``init; while (cond) {...}``.

    Guarded twice, because the naive rewrite is *not* equivalent:

      * a ``continue`` in the body skips the step in the ``while`` form but
        runs it in the ``for`` form, so a body containing one is declined;
      * a declaration in the initializer has the loop's scope in C99, so an
        initializer that declares is declined.
    """
    mask = code_mask(text)
    options: list[tuple[int, int, int, int, str, str, str]] = []
    for match in code_sites(text, _FOR_RE, mask):
        try:
            first, last = paren_body(text, match.end() - 1, mask)
            body_open, body_close = braced_body_after(text, last + 1, mask)
        except Declined:
            continue
        inner = text[first:last]
        inner_mask = mask[first:last]
        parts = split_top_level(inner, inner_mask, 0, ";")
        if len(parts) != 3:
            continue
        init = inner[parts[0][0] : parts[0][1]].strip()
        condition = inner[parts[1][0] : parts[1][1]].strip()
        step = inner[parts[2][0] : parts[2][1]].strip()
        if init and _DECL_RE.match(init):
            continue
        body = text[body_open + 1 : body_close]
        if code_sites(body, re.compile(r"\bcontinue\b"), code_mask(body)):
            continue
        options.append(
            (
                match.start(),
                body_close + 1,
                body_open,
                body_close,
                init,
                condition,
                step,
            )
        )
    if not options:
        raise Declined(
            "no for loop with a braced, continue-free body and a non-declaring init"
        )
    start, end, body_open, body_close, init, condition, step = options[
        rng.randrange(len(options))
    ]
    body = text[body_open + 1 : body_close]
    guard = condition if condition else "1"
    prefix = f"{init};" if init else ""
    return _replace(
        text,
        start,
        end,
        f"{prefix} while ({guard}) {{ {body} {step + ';' if step else ''} }}",
    )


def mutate_goto_ify(text: str, rng: random.Random) -> str:
    """Rewrite ``while (C) { B }` as a label, a guarded ``goto``, and a back jump.

    The money case of `calibration.md` section 2.1: the control-flow graph is
    unchanged by construction, so every CFG metric must stay perfectly quiet,
    while the control *skeleton* -- the thing a reader and a tree metric see --
    is destroyed.

    Guarded on ``break``, ``continue``, ``goto`` and label definitions in the
    body: after the rewrite the enclosing ``while`` no longer exists, so a
    ``break`` would bind to a different construct or fail to compile, and a
    ``continue`` would skip the loop's own back edge.
    """
    mask = code_mask(text)
    options: list[tuple[int, int, int, int, int, int]] = []
    for match in code_sites(text, _WHILE_RE, mask):
        try:
            _reject_do_while(text, mask, match)
            first, last = paren_body(text, match.end() - 1, mask)
            body_open, body_close = braced_body_after(text, last + 1, mask)
        except Declined:
            continue
        body = text[body_open + 1 : body_close]
        body_mask = code_mask(body)
        if code_sites(body, re.compile(r"\b(break|continue|goto|switch)\b"), body_mask):
            continue
        if _LABEL_DEF_RE.search(body):
            continue
        options.append((match.start(), first, last, body_open, body_close, 0))
    if not options:
        raise Declined(
            "no while loop with a braced body free of break/continue/goto/switch/labels"
        )
    start, first, last, body_open, body_close, _ = options[rng.randrange(len(options))]
    tag = f"gm{rng.randrange(1 << 20):05x}"
    if has_code_word(text, mask, f"__gm_top_{tag}"):
        raise Declined("label name collision")
    condition = text[first:last]
    body = text[body_open : body_close + 1]
    replacement = (
        f"__gm_top_{tag}: if (!({condition})) goto __gm_end_{tag};\n"
        f"{body}\n"
        f"goto __gm_top_{tag};\n"
        f"__gm_end_{tag}: ;"
    )
    return _replace(text, start, body_close + 1, replacement)


def mutate_redundant_else(text: str, rng: random.Random) -> str:
    """Append an empty ``else { }`` to an ``if`` that has none.

    An empty else changes nothing at run time; a structuring pass that emits
    one is not wrong. Whether a CFG front end gives it a node is exactly the
    question this class asks.
    """
    mask = code_mask(text)
    options: list[int] = []
    for match in code_sites(text, _IF_RE, mask):
        try:
            _, last = paren_body(text, match.end() - 1, mask)
            _, body_close = braced_body_after(text, last + 1, mask)
        except Declined:
            continue
        after = next_code(text, body_close + 1, mask)
        if after is not None and word_at(text, after + len("else") - 1) == "else":
            continue
        options.append(body_close + 1)
    if not options:
        raise Declined("no braced if without an else")
    at = options[rng.randrange(len(options))]
    return _replace(text, at, at, " else { }")


def mutate_else_if_nest(text: str, rng: random.Random) -> str:
    """Rewrite a trailing ``else if (C) { B }`` as ``else { if (C) { B } }``.

    Chaining and nesting are the same program; only the last arm is rewritten
    so that no further ``else`` has to be moved inside the new block.
    """
    mask = code_mask(text)
    options: list[tuple[int, int, int]] = []
    for match in code_sites(text, _ELSE_RE, mask):
        after = next_code(text, match.end(), mask)
        if after is None or word_at(text, after + len("if") - 1) != "if":
            continue
        inner = _IF_RE.match(text, after)
        if inner is None:
            continue
        try:
            require_blank_gap(text, match.end(), after)
            _, last = paren_body(text, inner.end() - 1, mask)
            _, body_close = braced_body_after(text, last + 1, mask)
        except Declined:
            continue
        tail = next_code(text, body_close + 1, mask)
        if tail is not None and word_at(text, tail + len("else") - 1) == "else":
            continue
        options.append((match.end(), after, body_close + 1))
    if not options:
        raise Declined("no trailing else-if with a braced body")
    else_end, if_start, body_end = options[rng.randrange(len(options))]
    return _replace(text, else_end, body_end, " { " + text[if_start:body_end] + " }")


def _simple_statement_spans(text: str, mask: list[bool]) -> list[tuple[int, int]]:
    """Spans of statements that are safe to wrap or duplicate.

    A statement qualifies when it ends at a top-level ``;`` inside a block,
    starts right after ``;``, ``{`` or ``}``, contains no braces, and is not a
    declaration -- a declaration's scope would change if it were moved.
    """
    spans: list[tuple[int, int]] = []
    depth_brace = 0
    depth_paren = 0
    for index, char in enumerate(text):
        if not mask[index]:
            continue
        if char == "{":
            depth_brace += 1
        elif char == "}":
            depth_brace -= 1
        elif char == "(":
            depth_paren += 1
        elif char == ")":
            depth_paren -= 1
        elif char == ";" and depth_paren == 0 and depth_brace >= 1:
            # The boundary scan has to respect nesting: the previous `;` before
            # `ok &= f(x);` in `for (i = 0; i < n; i++) ok &= f(x);` is inside
            # the loop header, and splicing a brace there produces
            # `for (i = 0; i < n; { i++) ...`. Count parentheses backwards and
            # only accept a boundary seen at depth zero.
            boundary = None
            nesting = 0
            for position in range(index - 1, -1, -1):
                if not mask[position]:
                    continue
                here = text[position]
                if here in ")]":
                    nesting += 1
                elif here in "([":
                    nesting -= 1
                elif nesting == 0 and here in ";{}:":
                    boundary = position
                    break
            if boundary is None or text[boundary] not in ";{}":
                continue
            body = text[boundary + 1 : index + 1]
            if not body.strip(" \t\n;") or "{" in body or "}" in body:
                continue
            if _DECL_RE.match(body) or _LABEL_DEF_RE.search(body):
                continue
            # `while` at a statement start is the tail of a `do ... while`
            # often enough that the two cannot be told apart from the text
            # alone, and wrapping that tail destroys the loop.
            if re.match(r"\s*(case|default|else|do|while)\b", body):
                continue
            following = next_code(text, index + 1, mask)
            if (
                following is not None
                and word_at(text, following + len("else") - 1) == "else"
            ):
                # `{ if (c) s; } else t;` does not parse: the brace pair ends
                # the if-statement the else has to attach to.
                continue
            spans.append((boundary + 1, index + 1))
    return spans


def mutate_extra_braces(text: str, rng: random.Random) -> str:
    """Wrap one simple statement in an extra pair of braces.

    A compound statement containing a single non-declaration statement is that
    statement. Declarations are excluded because a brace pair would end their
    scope early.
    """
    mask = code_mask(text)
    spans = _simple_statement_spans(text, mask)
    if not spans:
        raise Declined("no wrappable simple statement")
    start, end = spans[rng.randrange(len(spans))]
    return _replace(text, start, end, " { " + text[start:end].strip() + " } ")


def mutate_incr_expand(text: str, rng: random.Random) -> str:
    """Rewrite ``x++;`` as ``x = x + 1;`` (and ``x--;`` as ``x = x - 1;``).

    As a full expression statement the result is discarded, so postfix and
    prefix agree and the two forms are the same program for a scalar object.
    """
    mask = code_mask(text)
    options = code_sites(text, _INC_STMT_RE, mask) + code_sites(
        text, _DEC_STMT_RE, mask
    )
    site = pick(rng, options, "increment or decrement statement")
    name = site.group(1)
    operator = "+" if "++" in site.group(0) else "-"
    return _replace(text, site.start(), site.end(), f"{name} = {name} {operator} 1;")


def mutate_duplicate_tail(text: str, rng: random.Random) -> str:
    """Copy the statement after an ``if``/``else`` into both of its arms.

    The tail-duplication a real structuring algorithm performs
    (`calibration.md` section 2.1). Whichever arm ran, the tail runs
    immediately after it, exactly as before; an arm that leaves early skipped
    the tail before the rewrite and still skips it after. Declined when a
    ``goto`` or a label is in play, because a jump into the region would then
    see one copy instead of the original.
    """
    mask = code_mask(text)
    if code_sites(text, re.compile(r"\bgoto\b"), mask) or _LABEL_DEF_RE.search(text):
        raise Declined("goto or label in unit")
    # Keyed by the span's first CODE position, which is what `next_code`
    # returns when the tail is looked up below; keying by the raw span start
    # would never match, because a span begins at the boundary delimiter.
    simple: dict[int, tuple[int, int]] = {}
    for span in _simple_statement_spans(text, mask):
        head = next_code(text, span[0], mask)
        if head is not None:
            simple[head] = span
    options: list[tuple[int, int, int, int, int, int]] = []
    for match in code_sites(text, _IF_RE, mask):
        try:
            _, last = paren_body(text, match.end() - 1, mask)
            then_open, then_close = braced_body_after(text, last + 1, mask)
        except Declined:
            continue
        after = next_code(text, then_close + 1, mask)
        if after is None or word_at(text, after + len("else") - 1) != "else":
            continue
        try:
            require_blank_gap(text, then_close + 1, after)
            else_open, else_close = braced_body_after(text, after + len("else"), mask)
        except Declined:
            continue
        tail = next_code(text, else_close + 1, mask)
        if tail is None or tail not in simple:
            continue
        options.append((then_close, else_close, *simple[tail]))
    if not options:
        raise Declined("no if/else followed by a duplicable simple statement")
    then_close, else_close, tail_start, tail_end = options[rng.randrange(len(options))]
    tail = text[tail_start:tail_end].strip()
    out = _replace(text, tail_start, tail_end, "")
    out = _replace(out, else_close, else_close, f" {tail} ")
    return _replace(out, then_close, then_close, f" {tail} ")


#: The versioned mutation catalogue. Order is the report order.
#:
#: Bump this whenever a class is added, removed, or its rewrite changes: the
#: detection rates of two runs are only comparable within one catalogue version
#: (`calibration.md` section 5, "the cache key covers the semantics").
CATALOGUE_VERSION = "1"

CATALOGUE: tuple[MutationClass, ...] = (
    # ---- sensitivity ------------------------------------------------------
    MutationClass(
        "negate-condition",
        True,
        mutate_negate_condition,
        "The branch taken is inverted for every input that reaches the test.",
        "No effect if the condition is a compile-time constant.",
    ),
    MutationClass(
        "equality-flip",
        True,
        mutate_equality_flip,
        "`==` and `!=` disagree on every input, by definition.",
    ),
    MutationClass(
        "relational-flip",
        True,
        mutate_relational_flip,
        "`a < b` and `a >= b` are complements: they disagree on every input.",
    ),
    MutationClass(
        "off-by-one",
        True,
        mutate_off_by_one,
        "`<` and `<=` disagree exactly at the boundary, which a loop bound reaches.",
        "Only observable on an input that hits the boundary value.",
    ),
    MutationClass(
        "logic-flip",
        True,
        mutate_logic_flip,
        "`&&` and `||` differ on any input where the operands disagree, and "
        "differ in which operand is evaluated.",
    ),
    MutationClass(
        "arith-flip",
        True,
        mutate_arith_flip,
        "`a + b` and `a - b` differ whenever `b` is non-zero.",
    ),
    MutationClass(
        "assign-op-flip",
        True,
        mutate_assign_op_flip,
        "`x += e` and `x -= e` differ whenever `e` is non-zero.",
    ),
    MutationClass(
        "constant-bump",
        True,
        mutate_constant_bump,
        "A different literal is a different value on every path that reads it.",
        "No effect if the literal sits on dead code.",
    ),
    MutationClass(
        "incr-to-decr",
        True,
        mutate_incr_to_decr,
        "The object moves in the opposite direction on every execution.",
    ),
    MutationClass(
        "drop-call",
        True,
        mutate_drop_call,
        "The callee's side effects are lost.",
        "No effect if the callee is pure; purity is not checked.",
    ),
    MutationClass(
        "swap-args",
        True,
        mutate_swap_args,
        "The callee receives its arguments in the other order.",
        "No effect if the callee is symmetric in those positions, or if the two "
        "values happen to be equal.",
    ),
    MutationClass(
        "drop-break",
        True,
        mutate_drop_break,
        "The loop or switch no longer leaves where it used to.",
    ),
    MutationClass(
        "while->if",
        True,
        mutate_while_to_if,
        "The loop body runs at most once instead of until the guard fails.",
    ),
    MutationClass(
        "else->if(0)",
        True,
        mutate_else_to_if_false,
        "The fallback arm becomes unreachable.",
    ),
    MutationClass(
        "null-body",
        True,
        mutate_null_body,
        "Every computation and side effect in the function is gone.",
        "No effect on a function that already did nothing but return 0.",
    ),
    # ---- specificity ------------------------------------------------------
    MutationClass(
        "ws-reflow",
        False,
        mutate_whitespace_reflow,
        "C is free-form outside directives, strings and character constants, "
        "all of which the code mask excludes from the insertion points.",
    ),
    MutationClass(
        "comment-insert",
        False,
        mutate_comment_insert,
        "A comment becomes one space in translation phase 3.",
    ),
    MutationClass(
        "rename-param",
        False,
        mutate_rename_parameter,
        "An identifier's spelling is not observable; the rewrite declines when "
        "the new name already occurs, so it cannot capture.",
        "A block-scope redeclaration of the same name would be renamed too; "
        "not detected.",
    ),
    MutationClass(
        "int-identity",
        False,
        mutate_int_literal_identity,
        "`(N + 0)` folds to `N` for an integer literal, and stays a constant "
        "expression, so it is legal in every context a literal is.",
    ),
    MutationClass(
        "extra-braces",
        False,
        mutate_extra_braces,
        "A compound statement holding one non-declaration statement is that statement.",
    ),
    MutationClass(
        "if-else-swap",
        False,
        mutate_if_else_swap,
        "`!(C)` evaluates C once, in place; swapping the arms swaps the "
        "inversion back.",
    ),
    MutationClass(
        "demorgan",
        False,
        mutate_demorgan,
        "`!(!(A) || !(B))` short-circuits on exactly the same inputs as "
        "`A && B`, and yields the same 0 or 1.",
    ),
    MutationClass(
        "and-to-nested-if",
        False,
        mutate_and_to_nested_if,
        "`if (A && B) X` runs X on exactly the inputs `if (A) if (B) X` does, "
        "with the same evaluation order; declined when an `else` is present.",
    ),
    MutationClass(
        "for-to-while",
        False,
        mutate_for_to_while,
        "The desugaring in the standard, guarded on the two cases where it is "
        "not one: a `continue` in the body and a declaring initializer.",
    ),
    MutationClass(
        "else-if-nest",
        False,
        mutate_else_if_nest,
        "`else if` is `else { if }`; only a trailing arm is rewritten so no "
        "further `else` has to move.",
    ),
    MutationClass(
        "redundant-else",
        False,
        mutate_redundant_else,
        "An empty `else` executes nothing on the path it adds.",
    ),
    MutationClass(
        "incr-expand",
        False,
        mutate_incr_expand,
        "As a full expression statement the result is discarded, so `x++;` and "
        "`x = x + 1;` are the same program for a scalar object.",
        "Not equivalent for a `volatile` object or where `x` is a macro; "
        "neither is checked.",
    ),
    MutationClass(
        "goto-ify",
        False,
        mutate_goto_ify,
        "The standard lowering of `while`, guarded on `break`, `continue`, "
        "`goto`, `switch` and labels in the body. The CFG is unchanged by "
        "construction; the control skeleton is destroyed.",
    ),
    MutationClass(
        "duplicate-tail",
        False,
        mutate_duplicate_tail,
        "Whichever arm ran, the tail ran next; after the copy it still does, "
        "and an arm that left early skipped it either way.",
    ),
)

BY_NAME: dict[str, MutationClass] = {cls.name: cls for cls in CATALOGUE}

#: Rewrites considered and deliberately left out, with the reason. Named here
#: rather than omitted silently, because "we did not test it" and "it is not
#: meaning-preserving" are different statements about a metric's specificity.
REJECTED: tuple[tuple[str, str], ...] = (
    (
        "statement reordering",
        "Two adjacent statements are independent only if they share no memory. "
        "That is a dataflow fact, and nothing here computes one; a syntactic "
        "swap of `*p = 1;` and `x = *q;` is a behaviour change whenever p and q "
        "alias. `calibration.md`'s row for this belongs to a semantic metric "
        "with an alias analysis behind it, not to a source rewriter.",
    ),
    (
        "x + 0 / x * 1 on a general expression",
        "Not identities in C. `-0.0 + 0.0` is `+0.0`, so the rewrite is "
        "observable for floating point; and `c * 1` on a narrow integer applies "
        "the integer promotions, which changes the argument type in a variadic "
        "call. Kept only in the type-safe form: an integer literal folded to "
        "`(N + 0)`, which is the `int-identity` class.",
    ),
    (
        "declaration hoisting to the top of the body",
        "Moving `T x = f();` changes when `f()` runs, and moving `T x;` past a "
        "same-named outer declaration changes which object later code names. "
        "Both need scope and effect analysis the front end does not expose.",
    ),
    (
        "goto-ification of a loop containing break or continue",
        "The rewrite deletes the enclosing `while`, so a `break` inside it "
        "binds to a different construct or fails to compile, and a `continue` "
        "no longer reaches the back edge. Only the guarded form ships, and the "
        "decline count for the guard is reported.",
    ),
    (
        "for-to-while with a declaring initializer, or a body containing continue",
        "`for (int i = 0; ...)` scopes `i` to the loop in C99; and `continue` "
        "runs the step in a `for` but skips it in the hand-desugared `while`. "
        "Both are declined rather than mislabelled as preserving.",
    ),
    (
        "De Morgan across a top-level ||",
        "`&&` binds tighter than `||`, so splitting `a || b && c` at its `&&` "
        "reassociates the expression. Declined; only conditions with no "
        "top-level `||` are rewritten.",
    ),
)


# --------------------------------------------------------------------------
# corpora
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Unit:
    """One function's text, standing alone as a translation unit.

    Attributes:
        key: A stable identifier, used to seed this unit's generators.
        name: The function's name, as the front end reports it.
        text: C text that parses to exactly this one function.
        origin: Where it came from, for the report.
    """

    key: str
    name: str
    text: str
    origin: str


def load_samples(path: Path) -> list[Unit]:
    """The 300 published benchmark functions, each with its real source.

    Args:
        path: `published_function_results.json`.

    Returns:
        One :class:`Unit` per sample, in file order.

    Raises:
        FileNotFoundError: If `path` does not exist.
        KeyError: If the file has no ``samples`` array.
    """
    payload = json.loads(path.read_text())
    units: list[Unit] = []
    for index, sample in enumerate(payload["samples"]):
        source = sample.get("source_code")
        name = sample.get("function")
        if not source or not name:
            continue
        units.append(
            Unit(
                key=f"samples/{sample.get('project')}/{sample.get('binary')}/{name}/{index}",
                name=name,
                text=source,
                origin="published sample",
            )
        )
    return units


def split_functions(text: str) -> Iterator[tuple[str, str]]:
    """Candidate ``(name, text)`` pairs for each definition in a C file.

    A definition is a top-level ``{`` whose header ends in a parenthesized
    list. The result is a *candidate*: :func:`tree_units` reparses each one and
    keeps it only when it round-trips to the same CFG it had in the whole file.

    Args:
        text: A whole C translation unit.

    Yields:
        ``(function name, the text of that definition)``.
    """
    mask = code_mask(text)
    index = 0
    start = 0
    while index < len(text):
        if not mask[index] or text[index] not in ";{":
            index += 1
            continue
        if text[index] == ";":
            start = index + 1
            index += 1
            continue
        try:
            close = match_forward(text, index, mask, "{", "}")
        except Declined:
            return
        header = text[start:index]
        opens = [i for i in range(len(header)) if mask[start + i] and header[i] == "("]
        if opens:
            before = header[: opens[-1]].rstrip()
            found = re.search(r"([A-Za-z_]\w*)\s*$", before)
            if found:
                yield found.group(1), text[start : close + 1]
        index = close + 1
        start = index


def load_tree(
    tree: Path, parity: Callable[[str], dict[str, dict]], limit: int | None
) -> tuple[list[Unit], Counter[str]]:
    """Functions carved out of the materialized tree's decompiled C.

    Every candidate is reparsed on its own and kept only if it yields exactly
    the function it claims and the identical CFG the whole file gave it. A
    candidate that fails either check is counted, not dropped silently.

    Args:
        tree: The materialized DecBench tree root.
        parity: `glaurung.source_cfg.parity_cfgs`.
        limit: Stop after this many accepted units, or None for all.

    Returns:
        The accepted units, and a counter of why candidates were rejected.
    """
    units: list[Unit] = []
    rejected: Counter[str] = Counter()
    for path in sorted(tree.glob("*/*/decompiled/*.c")):
        text = path.read_text(errors="replace")
        try:
            whole = parity(text)
        except Exception as exc:  # noqa: BLE001 - a front-end crash is a result
            rejected[f"file unparsed: {type(exc).__name__}"] += 1
            continue
        for name, piece in split_functions(text):
            if name not in whole:
                rejected["name not in file CFGs"] += 1
                continue
            try:
                alone = parity(piece)
            except Exception as exc:  # noqa: BLE001
                rejected[f"slice unparsed: {type(exc).__name__}"] += 1
                continue
            if name not in alone:
                rejected["slice lost the function"] += 1
                continue
            if Cfg.from_serialized(alone[name]) != Cfg.from_serialized(whole[name]):
                rejected["slice changed the CFG"] += 1
                continue
            units.append(
                Unit(
                    key=f"tree/{path.parts[-4]}/{path.parts[-3]}/{path.stem}/{name}",
                    name=name,
                    text=piece,
                    origin=str(path),
                )
            )
            if limit is not None and len(units) >= limit:
                return units, rejected
    return units, rejected


# --------------------------------------------------------------------------
# the run
# --------------------------------------------------------------------------


@dataclass
class ClassResult:
    """Everything one mutation class produced over one corpus.

    Attributes:
        name: The class name.
        changes: The ground-truth label (see :class:`MutationClass`).
        applied: Mutants that were produced and reparsed successfully.
        declined: Decline reasons, counted.
        unchanged: Mutants whose text came back identical to the original.
        unparsed: Mutants the front end could not turn back into this function.
        budget: Pairs on which the isomorphism search ran out of steps.
        flagged: Per metric, mutants the metric did not call perfect.
        quiet: Per metric, mutants the metric still called perfect.
        magnitudes: Per metric, the metric values of the flagged mutants that
            were cheap enough to compute.
    """

    name: str
    changes: bool
    applied: int = 0
    declined: Counter[str] = field(default_factory=Counter)
    unchanged: int = 0
    unparsed: int = 0
    budget: int = 0
    flagged: Counter[str] = field(default_factory=Counter)
    quiet: Counter[str] = field(default_factory=Counter)
    magnitudes: dict[str, list[float]] = field(default_factory=dict)

    def confusion(self, metric: str) -> dict[str, int]:
        """The four-cell confusion counts for one metric.

        For a behaviour-changing class the metric should flag, so a flag is a
        true positive; for a preserving class it should stay quiet, so a flag
        is a false alarm. Only two of the four cells can be non-zero for a
        given class, which is the point: sensitivity and specificity are
        measured on disjoint populations.

        Args:
            metric: The metric name.

        Returns:
            ``{"tp", "fn", "fp", "tn"}`` counts.
        """
        flagged = self.flagged[metric]
        quiet = self.quiet[metric]
        if self.changes:
            return {"tp": flagged, "fn": quiet, "fp": 0, "tn": 0}
        return {"tp": 0, "fn": 0, "fp": flagged, "tn": quiet}


@dataclass
class Report:
    """A whole run.

    Attributes:
        seed: The seed every site choice was drawn from.
        catalogue_version: :data:`CATALOGUE_VERSION` at run time.
        corpus: Which corpus was walked.
        units: Units that parsed, held their function, and were non-degenerate.
        skipped: Why units were dropped, counted.
        results: One :class:`ClassResult` per selected class.
    """

    seed: int
    catalogue_version: str
    corpus: str
    units: int = 0
    skipped: Counter[str] = field(default_factory=Counter)
    results: dict[str, ClassResult] = field(default_factory=dict)


def run(
    units: Sequence[Unit],
    classes: Sequence[MutationClass],
    parity: Callable[[str], dict[str, dict]],
    *,
    seed: int,
    corpus: str,
    magnitude_max_rows: int = DEFAULT_MAGNITUDE_MAX_ROWS,
) -> Report:
    """Mutate every unit with every class and score every mutant.

    Args:
        units: The corpus.
        classes: The mutation classes to apply.
        parity: `glaurung.source_cfg.parity_cfgs`.
        seed: The experiment seed; recorded in the report.
        corpus: A label for the corpus, recorded in the report.
        magnitude_max_rows: Passed through to the metric verdicts.

    Returns:
        The :class:`Report`.
    """
    report = Report(seed=seed, catalogue_version=CATALOGUE_VERSION, corpus=corpus)
    for mutation in classes:
        report.results[mutation.name] = ClassResult(mutation.name, mutation.changes)
        for metric in METRICS:
            report.results[mutation.name].magnitudes[metric] = []

    for unit in units:
        try:
            baseline = parity(unit.text)
        except Exception as exc:  # noqa: BLE001 - a front-end crash is a result
            report.skipped[f"unit unparsed: {type(exc).__name__}"] += 1
            continue
        if unit.name not in baseline:
            report.skipped["front end did not report the function"] += 1
            continue
        reference = Cfg.from_serialized(baseline[unit.name])
        if reference.degenerate:
            report.skipped["degenerate CFG (dropped from GED upstream too)"] += 1
            continue
        report.units += 1

        for mutation in classes:
            result = report.results[mutation.name]
            rng = random.Random(f"{seed}|{unit.key}|{mutation.name}")
            try:
                mutated = mutation.apply(unit.text, rng)
            except Declined as exc:
                result.declined[str(exc)] += 1
                continue
            if mutated == unit.text:
                result.unchanged += 1
                continue
            try:
                mutant_cfgs = parity(mutated)
            except Exception as exc:  # noqa: BLE001
                result.unparsed += 1
                del exc
                continue
            if unit.name not in mutant_cfgs:
                result.unparsed += 1
                continue
            mutant = Cfg.from_serialized(mutant_cfgs[unit.name])
            try:
                verdicts = {
                    metric: scorer(
                        reference, mutant, magnitude_max_rows=magnitude_max_rows
                    )
                    for metric, scorer in METRICS.items()
                }
            except IsomorphismBudgetExhausted:
                result.budget += 1
                continue
            result.applied += 1
            for metric, verdict in verdicts.items():
                if verdict.perfect:
                    result.quiet[metric] += 1
                else:
                    result.flagged[metric] += 1
                    if verdict.value is not None:
                        result.magnitudes[metric].append(verdict.value)
    return report


# --------------------------------------------------------------------------
# execution differential: is the "preserving" label true, not just argued?
# --------------------------------------------------------------------------


def preserves_behaviour(
    program: str, mutated: str, *, cc: str = "cc", timeout: int = 60
) -> tuple[bool, str]:
    """Compile and run two whole programs and compare what they print.

    This is what turns a specificity class's `rationale` from an argument into
    a measurement. It needs a self-contained program, so it is driven from
    tests over small programs rather than over the corpus, whose functions do
    not compile alone.

    Args:
        program: A complete C program with a `main`.
        mutated: The same program after a mutation.
        cc: The compiler to invoke.
        timeout: Per-step timeout in seconds.

    Returns:
        ``(behaviour is identical, an explanation when it is not)``.
    """
    with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as directory:
        root = Path(directory)
        outputs: list[str] = []
        for label, source in (("base", program), ("mutant", mutated)):
            path = root / f"{label}.c"
            path.write_text(source)
            binary = root / label
            build = subprocess.run(
                [cc, "-std=c11", "-O0", "-w", str(path), "-o", str(binary)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if build.returncode != 0:
                return False, f"{label} did not compile: {build.stderr.strip()[-300:]}"
            runner = subprocess.run(
                [str(binary)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            outputs.append(f"rc={runner.returncode}\n{runner.stdout}")
        if outputs[0] != outputs[1]:
            return False, f"base {outputs[0]!r} != mutant {outputs[1]!r}"
        return True, ""


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------


def _rate(numerator: int, denominator: int) -> str:
    return f"{100.0 * numerator / denominator:5.1f}%" if denominator else "    -"


def _median(values: Sequence[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def report_json(report: Report) -> dict[str, object]:
    """The whole run as JSON-serializable data.

    Args:
        report: The run.

    Returns:
        A mapping suitable for `json.dump`.
    """
    classes: dict[str, object] = {}
    for name, result in report.results.items():
        mutation = BY_NAME[name]
        classes[name] = {
            "changes_behaviour": result.changes,
            "rationale": mutation.rationale,
            "caveat": mutation.caveat,
            "applied": result.applied,
            "unchanged": result.unchanged,
            "unparsed": result.unparsed,
            "iso_budget_exhausted": result.budget,
            "declined": dict(sorted(result.declined.items())),
            "declined_total": sum(result.declined.values()),
            "metrics": {
                metric: {
                    **result.confusion(metric),
                    "rate": (
                        round(result.flagged[metric] / result.applied, 6)
                        if result.applied
                        else None
                    ),
                    "median_magnitude": _median(result.magnitudes[metric]),
                }
                for metric in METRICS
            },
        }
    totals: dict[str, object] = {}
    for metric in METRICS:
        cells = Counter()
        for result in report.results.values():
            for cell, count in result.confusion(metric).items():
                cells[cell] += count
        positives = cells["tp"] + cells["fn"]
        negatives = cells["fp"] + cells["tn"]
        totals[metric] = {
            **dict(cells),
            "sensitivity": round(cells["tp"] / positives, 6) if positives else None,
            "specificity": round(cells["tn"] / negatives, 6) if negatives else None,
        }
    return {
        "seed": report.seed,
        "catalogue_version": report.catalogue_version,
        "corpus": report.corpus,
        "units_scored": report.units,
        "units_skipped": dict(sorted(report.skipped.items())),
        "classes": classes,
        "totals": totals,
        "rejected_classes": [{"class": name, "why": why} for name, why in REJECTED],
    }


def print_report(report: Report, verbose: bool) -> None:
    """Print the confusion matrix, one block per half.

    Args:
        report: The run.
        verbose: Whether to print every decline reason.
    """
    print(f"corpus            {report.corpus}")
    print(f"seed              {report.seed}   catalogue v{report.catalogue_version}")
    print(f"units scored      {report.units}")
    for reason, count in sorted(report.skipped.items()):
        print(f"  skipped {count:6d}  {reason}")
    print()

    for changes, title, verdict_column, good, bad in (
        (
            True,
            "SENSITIVITY -- behaviour changed; a metric that stays perfect missed it",
            "detected",
            "TP",
            "FN",
        ),
        (
            False,
            "SPECIFICITY -- behaviour preserved; a metric that moves raised a false alarm",
            "false alarm",
            "TN",
            "FP",
        ),
    ):
        selected = [r for r in report.results.values() if r.changes == changes]
        if not selected:
            continue
        print(title)
        header = f"{'class':<18} {'applied':>7} {'declin':>7} {'unpar':>6}"
        for metric in METRICS:
            header += f" | {metric:>11} {good:>5} {bad:>5} {'med':>6}"
        print(header)
        print("-" * len(header))
        for result in selected:
            line = (
                f"{result.name:<18} {result.applied:>7} "
                f"{sum(result.declined.values()):>7} {result.unparsed:>6}"
            )
            for metric in METRICS:
                cells = result.confusion(metric)
                rate = _rate(result.flagged[metric], result.applied)
                right = cells["tp"] if changes else cells["tn"]
                wrong = cells["fn"] if changes else cells["fp"]
                magnitude = _median(result.magnitudes[metric])
                line += (
                    f" | {rate:>11} {right:>5} {wrong:>5} "
                    f"{('-' if magnitude is None else f'{magnitude:6.1f}'):>6}"
                )
            print(line)
            if result.budget:
                print(
                    f"{'':<18} !! {result.budget} pair(s) exhausted the isomorphism budget"
                )
        print()

    print("TOTALS (the pair, never their average)")
    for metric in METRICS:
        cells: Counter[str] = Counter()
        for result in report.results.values():
            for cell, count in result.confusion(metric).items():
                cells[cell] += count
        positives = cells["tp"] + cells["fn"]
        negatives = cells["fp"] + cells["tn"]
        print(
            f"  {metric:<12} sensitivity {_rate(cells['tp'], positives)} "
            f"({cells['tp']}/{positives})    "
            f"specificity {_rate(cells['tn'], negatives)} "
            f"({cells['tn']}/{negatives})"
        )
    print()

    if verbose:
        print("DECLINES (a class that declines everywhere has a rate over nothing)")
        for result in report.results.values():
            total = sum(result.declined.values())
            if not total:
                continue
            print(f"  {result.name} ({total} declined, {result.unchanged} no-op)")
            for reason, count in result.declined.most_common():
                print(f"      {count:6d}  {reason}")
        print()
        print("REJECTED as not meaning-preserving")
        for name, why in REJECTED:
            print(f"  {name}\n      {why}")


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point.

    Args:
        argv: Arguments, or None to read `sys.argv`.

    Returns:
        The process exit code.
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--corpus",
        choices=("samples", "tree"),
        default="samples",
        help="published benchmark sources, or Glaurung's own decompiled C",
    )
    parser.add_argument("--samples-path", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--tree", type=Path, default=DEFAULT_TREE)
    parser.add_argument("--limit", type=int, default=None, help="stop after N units")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument(
        "--classes",
        default=None,
        help="comma-separated class names; default is the whole catalogue",
    )
    parser.add_argument(
        "--magnitude-max-rows",
        type=int,
        default=DEFAULT_MAGNITUDE_MAX_ROWS,
        help="cost-matrix rows above which metric VALUES are skipped (never verdicts)",
    )
    parser.add_argument("--json", type=Path, default=None, help="also write JSON here")
    parser.add_argument("--verbose", action="store_true", help="print every decline")
    args = parser.parse_args(argv)

    try:
        from glaurung.source_cfg import parity_cfgs
    except ImportError as exc:
        print(f"glaurung extension not importable: {exc}", file=sys.stderr)
        return 2

    if args.classes:
        wanted = [name.strip() for name in args.classes.split(",") if name.strip()]
        unknown = [name for name in wanted if name not in BY_NAME]
        if unknown:
            print(f"unknown mutation class(es): {unknown}", file=sys.stderr)
            return 2
        classes = [BY_NAME[name] for name in wanted]
    else:
        classes = list(CATALOGUE)

    if args.corpus == "samples":
        if not args.samples_path.is_file():
            print(f"no samples file at {args.samples_path}", file=sys.stderr)
            return 2
        units = load_samples(args.samples_path)
        corpus = f"samples {args.samples_path}"
        carve: Counter[str] = Counter()
    else:
        if not args.tree.is_dir():
            print(f"no tree at {args.tree}", file=sys.stderr)
            return 2
        units, carve = load_tree(args.tree, parity_cfgs, args.limit)
        corpus = f"tree {args.tree}"
    if args.limit is not None:
        units = units[: args.limit]

    report = run(
        units,
        classes,
        parity_cfgs,
        seed=args.seed,
        corpus=corpus,
        magnitude_max_rows=args.magnitude_max_rows,
    )
    for reason, count in carve.items():
        report.skipped[f"carve: {reason}"] += count
    print_report(report, args.verbose)

    if args.json:
        args.json.write_text(json.dumps(report_json(report), indent=2) + "\n")
        print(f"wrote {args.json}")

    empty = sorted(
        name for name, result in report.results.items() if result.applied == 0
    )
    if empty:
        print(
            "no mutant was produced for: " + ", ".join(empty) + "\n"
            "An instrument that measured nothing must not read as a pass.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
