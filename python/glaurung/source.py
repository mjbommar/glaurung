"""Measure C source: how big, how branchy, how nested, what it calls.

Everything Glaurung measured about C before this module existed was a
*comparison* -- graph edit distance, tree edit distance, type match, byte match
-- four metrics that score a decompilation against a ground truth and mean
nothing with only one side. This is the other kind: a property of a single
piece of source, which is what a reviewer picking what to read first, a
researcher featurizing a corpus, a CI gate refusing a function above a
threshold, and a decompiler author asking whether today's output is more
structured than yesterday's all actually want.

The parser underneath is pure Rust and total: no JVM, no subprocess, and no
input raises. A file that is not C at all yields zero functions and the
diagnostics saying so, and a file whose third function is unparseable still
reports the other two -- a front end that lost one function must not look like
one that lost the file.

Quick start:

    >>> import glaurung
    >>> report = glaurung.source.analyze("int f(int a) { return a ? 1 : 0; }")
    >>> report.functions[0].name, report.functions[0].cyclomatic
    ('f', 2)

    >>> for f in report.hotspots(by="cognitive", limit=5):
    ...     print(f.name, f.cognitive, f.max_nesting)
    f 1 0

Definitions for every metric are in the Rust module documentation
(`src/csource/metrics/`) and summarized in `docs/reference/source-metrics.md`;
the ones people disagree about -- cognitive complexity's `else if` rule,
Halstead's operator split -- are written out there rather than left implied.
"""

from __future__ import annotations

import statistics
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from glaurung import _native

__all__ = [
    "COMPARED_METRICS",
    "Diagnostic",
    "FunctionMetrics",
    "SourceReport",
    "analyze",
    "analyze_path",
    "compare",
    "control_flow_graphs",
    "feature_names",
    "features",
    "functions",
    "normalize",
]

#: The metric names :meth:`SourceReport.hotspots` will sort by, mapped to the
#: attribute that holds each. Restricting the sort key to a known set turns a
#: typo into an error at the call rather than a silently unsorted list.
_RANKABLE = (
    "cyclomatic",
    "cognitive",
    "max_nesting",
    "max_loop_depth",
    "lines",
    "code_lines",
    "tokens",
    "statements",
    "calls",
    "parameters",
    "decision_points",
    "loops",
    "unreachable_statements",
    "halstead_volume",
    "halstead_difficulty",
    "halstead_effort",
)


#: What :func:`compare` reports by default: the metrics whose movement between
#: two builds is worth reading. Every one is an integer, so a delta is exact.
COMPARED_METRICS = (
    "cyclomatic",
    "cognitive",
    "max_nesting",
    "gotos",
    "unreachable_statements",
    "lines",
    "statements",
)


class Diagnostic:
    """One problem the parser reported, with the text that shows it.

    Attributes:
        severity: ``"error"`` or ``"warning"``.
        message: What went wrong.
        start: Start byte offset in the analyzed text.
        end: End byte offset, exclusive.
        text: The rendered excerpt, with a caret under the span.
    """

    __slots__ = ("severity", "message", "start", "end", "text")

    def __init__(self, raw: Mapping[str, Any]) -> None:
        """Wrap one diagnostic dict from the extension.

        Args:
            raw: The mapping the native layer produced.
        """
        self.severity: str = raw["severity"]
        self.message: str = raw["message"]
        self.start: int = raw["start"]
        self.end: int = raw["end"]
        self.text: str = raw["text"]

    def __repr__(self) -> str:
        """A one-line form naming the severity and message."""
        return f"<Diagnostic {self.severity}: {self.message}>"


class FunctionMetrics:
    """Everything measured about one function definition.

    The nested dicts the extension returns stay available as :attr:`raw`; the
    attributes below are the flattened names worth typing interactively. Both
    describe the same measurement, so neither is a summary of the other.
    """

    __slots__ = ("raw",)

    def __init__(self, raw: Mapping[str, Any]) -> None:
        """Wrap one function's measurement.

        Args:
            raw: The nested mapping the native layer produced.
        """
        self.raw = raw

    # --- identity ------------------------------------------------------------

    @property
    def name(self) -> str:
        """The declared name, empty when the declarator had none."""
        return self.raw["name"]

    @property
    def first_line(self) -> int:
        """1-based first line of the definition."""
        return self.raw["size"]["first_line"]

    @property
    def last_line(self) -> int:
        """1-based last line of the definition."""
        return self.raw["size"]["last_line"]

    @property
    def has_body(self) -> bool:
        """Whether the parser recovered a body for it."""
        return self.raw["has_body"]

    @property
    def parameters(self) -> int:
        """Declared parameters; ``(void)`` and ``()`` are both zero."""
        return self.raw["parameters"]

    # --- size ----------------------------------------------------------------

    @property
    def lines(self) -> int:
        """Physical lines the definition spans."""
        return self.raw["size"]["lines"]

    @property
    def code_lines(self) -> int:
        """Lines on which at least one token begins."""
        return self.raw["size"]["code_lines"]

    @property
    def tokens(self) -> int:
        """Tokens in the definition."""
        return self.raw["size"]["tokens"]

    # --- control flow --------------------------------------------------------

    @property
    def cyclomatic(self) -> int:
        """McCabe's number, ``E - N + 2`` over the reachable subgraph."""
        return self.raw["graph"]["cyclomatic"]

    @property
    def decision_points(self) -> int:
        """Branch points, as ``sum(max(0, out_degree - 1))``.

        Reported beside :attr:`cyclomatic` rather than folded into it: the two
        agree only when the graph has a single sink, and the gap is a count of
        constructs that never reach the function end.
        """
        return self.raw["graph"]["decision_points"]

    @property
    def loops(self) -> int:
        """Natural loops, counted as distinct back-edge destinations."""
        return self.raw["graph"]["loops"]

    @property
    def unreachable_statements(self) -> int:
        """Statements no path from the entry reaches. A lower bound."""
        return self.raw["unreachable_statements"]

    @property
    def node_kinds(self) -> Mapping[str, int]:
        """How many CFG nodes carry each kind: ``goto``, ``switch``, ...."""
        return self.raw["graph"]["node_kinds"]

    @property
    def gotos(self) -> int:
        """`goto` transfers in the function.

        The headline number for judging decompiler output: a structurer that
        gave up emits `goto` where a loop or an `if`/`else` belongs, and the
        count is how much it gave up.
        """
        return self.raw["graph"]["node_kinds"].get("goto", 0)

    @property
    def is_structured(self) -> bool:
        """Whether the function's control flow is expressible without `goto`.

        True when it contains no `goto` transfer. This is a statement about the
        *text*, not about what is possible: a function that could have been
        written with structured control flow but was not still reads False,
        which is the question a decompiler-output review is asking.
        """
        return self.gotos == 0

    # --- shape ---------------------------------------------------------------

    @property
    def cognitive(self) -> int:
        """Cognitive complexity, per the SonarSource specification."""
        return self.raw["shape"]["cognitive"]

    @property
    def max_nesting(self) -> int:
        """Deepest nesting of control structures, in levels."""
        return self.raw["shape"]["max_nesting"]

    @property
    def max_loop_depth(self) -> int:
        """Deepest nesting of loops specifically."""
        return self.raw["shape"]["max_loop_depth"]

    @property
    def statements(self) -> int:
        """Statement nodes of any kind."""
        return self.raw["shape"]["statements"]

    @property
    def calls(self) -> int:
        """Call expressions, one per argument list."""
        return self.raw["shape"]["calls"]

    @property
    def callees(self) -> Sequence[str]:
        """Distinct directly-named callees, sorted.

        A call through a function pointer or a struct member counts toward
        :attr:`calls` and appears here under no name, because there is none.
        """
        return self.raw["shape"]["callees"]

    @property
    def tag_counts(self) -> Mapping[str, int]:
        """How many AST nodes carry each C node tag."""
        return self.raw["shape"]["tag_counts"]

    # --- Halstead ------------------------------------------------------------

    @property
    def halstead(self) -> Mapping[str, float]:
        """Halstead's four counts and the three figures derived from them."""
        return self.raw["halstead"]

    @property
    def halstead_volume(self) -> float:
        """``N * log2(n)``."""
        return self.raw["halstead"]["volume"]

    @property
    def halstead_difficulty(self) -> float:
        """``(n1 / 2) * (N2 / n2)``."""
        return self.raw["halstead"]["difficulty"]

    @property
    def halstead_effort(self) -> float:
        """``difficulty * volume``."""
        return self.raw["halstead"]["effort"]

    # --- output --------------------------------------------------------------

    def to_dict(self) -> Mapping[str, Any]:
        """The measurement as plain nested data, ready for JSON."""
        return self.raw

    def __repr__(self) -> str:
        """A one-line form naming the function and its two complexities."""
        return (
            f"<FunctionMetrics {self.name!r} lines={self.lines} "
            f"cyclomatic={self.cyclomatic} cognitive={self.cognitive}>"
        )


class SourceReport:
    """Everything measured about one translation unit."""

    __slots__ = ("raw", "_functions", "source", "name")

    def __init__(
        self, raw: Mapping[str, Any], source: str, name: str | None = None
    ) -> None:
        """Wrap one file's measurement.

        Args:
            raw: The mapping the native layer produced.
            source: The exact text the offsets in `raw` refer to. When a
                dialect was applied this is the *normalized* text, not the
                caller's original.
            name: A display name for the unit, if the caller has one.
        """
        self.raw = raw
        self.source = source
        self.name = name
        self._functions = tuple(FunctionMetrics(f) for f in raw["functions"])

    @property
    def functions(self) -> tuple[FunctionMetrics, ...]:
        """Every function definition with a body, in source order."""
        return self._functions

    @property
    def diagnostics(self) -> tuple[Diagnostic, ...]:
        """Every problem the parser reported, in source order."""
        return tuple(Diagnostic(d) for d in self.raw["diagnostics"])

    @property
    def lines(self) -> int:
        """Physical lines in the file."""
        return self.raw["lines"]["lines"]

    @property
    def code_lines(self) -> int:
        """Lines on which at least one token begins."""
        return self.raw["lines"]["code_lines"]

    @property
    def blank_lines(self) -> int:
        """Lines with no non-whitespace byte."""
        return self.raw["lines"]["blank_lines"]

    @property
    def other_lines(self) -> int:
        """Non-blank lines carrying no token: comments, and the continuation
        lines of tokens that span several lines.

        Not called ``comment_lines``: the lexer stores no trivia, so the token
        buffer cannot tell a comment from a string literal's second line, and
        naming the bucket for its majority case would be a claim it cannot
        support.
        """
        return self.raw["lines"]["other_lines"]

    def hotspots(
        self, by: str = "cognitive", limit: int | None = 10
    ) -> tuple[FunctionMetrics, ...]:
        """The functions that score highest on one metric.

        Args:
            by: Any name in :data:`_RANKABLE` -- ``"cognitive"``,
                ``"cyclomatic"``, ``"max_nesting"``, ``"lines"``, and the rest.
            limit: How many to return, or `None` for all of them.

        Returns:
            Functions in descending order of `by`, with the name as a
            tie-break so the order is total and reproducible.

        Raises:
            ValueError: If `by` is not a rankable metric. A typo here would
                otherwise silently return the list in source order.
        """
        if by not in _RANKABLE:
            raise ValueError(
                f"cannot rank by {by!r}; expected one of {', '.join(_RANKABLE)}"
            )
        ranked = sorted(self._functions, key=lambda f: (-getattr(f, by), f.name))
        return tuple(ranked if limit is None else ranked[:limit])

    def summary(self) -> Mapping[str, Any]:
        """Whole-unit aggregates, for a dashboard row or a build-over-build diff.

        Returns:
            A mapping with the file's line counts, the function count, how many
            functions are :attr:`FunctionMetrics.is_structured`, the total
            `goto` and unreachable-statement counts, and ``min``/``median``/
            ``mean``/``max`` for each metric in :data:`_RANKABLE`.

            A unit with no functions returns the same keys with the
            distributions absent rather than zeroed: a mean of zero over no
            functions is a number that reads like a measurement and is not one.
        """
        base: dict[str, Any] = {
            "name": self.name,
            "lines": self.lines,
            "code_lines": self.code_lines,
            "blank_lines": self.blank_lines,
            "other_lines": self.other_lines,
            "functions": len(self._functions),
            "structured_functions": sum(1 for f in self._functions if f.is_structured),
            "gotos": sum(f.gotos for f in self._functions),
            "unreachable_statements": sum(
                f.unreachable_statements for f in self._functions
            ),
            "diagnostics": len(self.raw["diagnostics"]),
        }
        if not self._functions:
            base["distributions"] = {}
            return base

        distributions: dict[str, Mapping[str, float]] = {}
        for metric in _RANKABLE:
            values = [float(getattr(f, metric)) for f in self._functions]
            distributions[metric] = {
                "min": min(values),
                "median": statistics.median(values),
                "mean": statistics.fmean(values),
                "max": max(values),
            }
        base["distributions"] = distributions
        return base

    def call_graph(self) -> Mapping[str, tuple[str, ...]]:
        """Which function calls which, within this translation unit.

        Returns:
            ``{caller: (callee, ...)}`` over every measured function, with the
            callees sorted. Names not defined in this unit are included --
            a call to `malloc` is a real edge, and dropping it would make the
            graph claim the function calls nothing.

            Indirect calls contribute no edge, because there is no name to
            record; :attr:`FunctionMetrics.calls` counts them and this does
            not, so the two disagree exactly where a pointer was called.
        """
        return {f.name: tuple(f.callees) for f in self._functions}

    def defined_names(self) -> frozenset[str]:
        """The function names this unit defines.

        Intersect it with :meth:`call_graph` values to keep only the edges that
        stay inside the unit.
        """
        return frozenset(f.name for f in self._functions)

    def to_dict(self) -> Mapping[str, Any]:
        """The report as plain nested data, ready for JSON."""
        return self.raw

    def __len__(self) -> int:
        """How many functions were measured."""
        return len(self._functions)

    def __iter__(self) -> Iterator[FunctionMetrics]:
        """Iterate the functions in source order."""
        return iter(self._functions)

    def __repr__(self) -> str:
        """A one-line form naming the unit and its size."""
        where = f" {self.name!r}" if self.name else ""
        return (
            f"<SourceReport{where} functions={len(self._functions)} lines={self.lines}>"
        )


def normalize(code: str, dialect: str) -> str:
    """Apply the one text normalization pass a dialect is allowed to go through.

    Args:
        code: The source text.
        dialect: ``"preprocessed"`` for a gcc-preprocessed translation unit
            (`.i`), or ``"decompiled"`` for a decompiler backend's output.

    Returns:
        The normalized text. It is a *different string*, so any offset measured
        against it does not address the original.

    Raises:
        ValueError: If `dialect` is neither of the two names.
    """
    return _native.source.normalize(code, dialect)


def analyze(
    code: str, *, name: str | None = None, dialect: str | None = None
) -> SourceReport:
    """Measure one translation unit of C.

    Args:
        code: The source text. Any byte sequence is acceptable; this never
            raises on account of the input.
        name: A display name for the unit, used only in `repr`.
        dialect: When given, :func:`normalize` runs first and the report
            describes the normalized text, which :attr:`SourceReport.source`
            then holds. Pass ``"decompiled"`` for decompiler output and
            ``"preprocessed"`` for a `.i` file; omit it for ordinary C.

    Returns:
        The report. A file with no recoverable function yields an empty
        :attr:`SourceReport.functions` and the diagnostics explaining why --
        never an exception, because a caller cannot otherwise tell an empty
        file from a failed one.
    """
    text = normalize(code, dialect) if dialect is not None else code
    return SourceReport(_native.source.analyze(text), text, name)


def analyze_path(path: str | Path, *, dialect: str | None = None) -> SourceReport:
    """Measure one file of C.

    Args:
        path: The file to read. Invalid UTF-8 is replaced rather than raising,
            matching how the corpus tooling reads decompiler output.
        dialect: As :func:`analyze`.

    Returns:
        The report, named after the file.
    """
    path = Path(path)
    code = path.read_bytes().decode("utf-8", errors="replace")
    return analyze(code, name=str(path), dialect=dialect)


def functions(code: str) -> Sequence[Mapping[str, Any]]:
    """List a file's function definitions without measuring any of them.

    One parse and no graph construction, for deciding what to measure.

    Args:
        code: The source text.

    Returns:
        One mapping per definition with ``name``, ``start``, ``end``,
        ``first_line``, ``last_line`` and ``has_body``.
    """
    return _native.source.functions(code)


def control_flow_graphs(code: str) -> Sequence[Mapping[str, Any]]:
    """Every function's general control-flow graph.

    This is the graph a person would draw -- real successors, real join points,
    real loop back edges, typed nodes and edges. It is deliberately *not*
    :func:`glaurung.source_cfg.parity_cfgs`, which reproduces another tool's
    artifacts so that one similarity score can be compared against it.

    Args:
        code: The source text.

    Returns:
        One mapping per function with ``name``, ``start``, ``end``,
        ``short_circuits`` and a ``cfg`` holding ``nodes``, ``edges``,
        ``entry`` and ``exit``. A list rather than a name-keyed mapping,
        because two definitions in one file can carry the same name after
        recovery and a mapping would silently drop one.
    """
    return _native.source.control_flow_graphs(code)


def feature_names() -> Sequence[str]:
    """The column names :func:`features` returns, in order.

    Returns:
        A fixed, ordered, documented vector of column names. Stability is the
        point: rows stacked across files and across releases have to mean the
        same thing column by column.
    """
    return _native.source.feature_names()


def features(code: str) -> Sequence[tuple[str, Sequence[float]]]:
    """One fixed-width numeric row per function, for corpus-scale work.

    The same data :func:`analyze` reports, flattened.

    This is for the *stable column vector*, not for speed. Measured over
    ``tests/decompiler_fixtures/src`` (196 files, 900 functions, 0.78 MB) on a
    ``maturin develop --release`` build, best of five: ``analyze`` 43.8 ms,
    ``features`` 41.3 ms -- 0.94x. Parsing and graph construction dominate.
    What a row buys is a meaning fixed by :func:`feature_names` that does not
    move when the report's dict schema gains a key.

    Args:
        code: The source text.

    Returns:
        ``(name, row)`` pairs in source order, each row as long as
        :func:`feature_names`.
    """
    return _native.source.features(code)


def compare(
    before: SourceReport,
    after: SourceReport,
    *,
    metrics: Sequence[str] = COMPARED_METRICS,
) -> Mapping[str, Any]:
    """Per-function metric movement between two reports.

    The shape both build-over-build regression tracking and cross-decompiler
    comparison reduce to: measure two pieces of C, match their functions, and
    read what moved. `before` might be last release's output and `after` this
    one's, or one decompiler's output and another's, or the original source and
    the decompilation of it.

    Args:
        before: The baseline report.
        after: The report to compare against it.
        metrics: Which :class:`FunctionMetrics` attributes to difference.
            Defaults to :data:`COMPARED_METRICS`.

    Returns:
        A mapping with:

        * ``matched`` -- one entry per name present in both, each
          ``{"name", "before", "after", "deltas"}`` where ``deltas`` maps each
          metric to ``after - before``. Sorted by the largest absolute delta
          first, so the functions that moved most read first.
        * ``added`` / ``removed`` -- names present in only one side, sorted.
        * ``totals`` -- for each metric, the sum over *matched* functions on
          each side and the difference. Matched only, deliberately: a total
          that mixed in added and removed functions would attribute their whole
          weight to a regression.

    Raises:
        ValueError: If a name in `metrics` is not a rankable metric or
            ``gotos``. A typo would otherwise silently drop a column.

    Note:
        Functions are matched by name. A translation unit that defines the same
        name twice -- which recovery can produce -- keeps only the last of
        them on each side, and the pairing is then between those two. Check
        ``added``/``removed`` when the counts do not line up.
    """
    allowed = set(_RANKABLE) | {"gotos"}
    unknown = [m for m in metrics if m not in allowed]
    if unknown:
        raise ValueError(
            f"cannot compare on {', '.join(unknown)}; "
            f"expected names from {', '.join(sorted(allowed))}"
        )

    left = {f.name: f for f in before.functions}
    right = {f.name: f for f in after.functions}
    shared = sorted(set(left) & set(right))

    matched: list[Mapping[str, Any]] = []
    totals: dict[str, Mapping[str, float]] = {
        metric: {"before": 0.0, "after": 0.0, "delta": 0.0} for metric in metrics
    }
    for name in shared:
        deltas: dict[str, float] = {}
        values_before: dict[str, float] = {}
        values_after: dict[str, float] = {}
        for metric in metrics:
            a = float(getattr(left[name], metric))
            b = float(getattr(right[name], metric))
            values_before[metric] = a
            values_after[metric] = b
            deltas[metric] = b - a
            bucket = totals[metric]
            totals[metric] = {
                "before": bucket["before"] + a,
                "after": bucket["after"] + b,
                "delta": bucket["delta"] + (b - a),
            }
        matched.append(
            {
                "name": name,
                "before": values_before,
                "after": values_after,
                "deltas": deltas,
            }
        )

    # Largest movement first, name as the tie-break so the order is total.
    matched.sort(
        key=lambda entry: (
            -max((abs(v) for v in entry["deltas"].values()), default=0.0),
            entry["name"],
        )
    )
    return {
        "matched": matched,
        "added": sorted(set(right) - set(left)),
        "removed": sorted(set(left) - set(right)),
        "totals": totals,
    }
