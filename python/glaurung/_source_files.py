"""File-based C analysis behind the public glaurung.source API.

Change ``from pyjoern import fast_cfgs_from_source`` to
``from glaurung.source import fast_cfgs_from_source`` for graph-topology callers.
Install ``glaurung[graphs]`` for NetworkX. No Joern executable is invoked.

This implements a subset of pyjoern: nodes carry identity and entry/exit flags,
not JIL statements. ``parse_source`` defaults to skipping AST and DDG; requesting
those analyses raises. See ``docs/reference/source-python.md`` for the contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING
import warnings

from glaurung import source_cfg

if TYPE_CHECKING:
    from glaurung import source
    import networkx as nx

__all__ = [
    "Function",
    "SourceParseError",
    "SourceParseWarning",
    "fast_cfgs_from_source",
    "parse_source",
    "parse_callgraph",
]


class SourceParseWarning(UserWarning):
    """The parser reported problems while recovering a file."""


class SourceParseError(ValueError):
    """A strict parse failed, with its path and diagnostics attached."""

    def __init__(self, path: Path, diagnostics: tuple[source.Diagnostic, ...]) -> None:
        """Keep the diagnostic objects so callers can show source excerpts."""
        self.path = path
        self.diagnostics = diagnostics
        super().__init__(f"{path}: {len(diagnostics)} parser diagnostic(s)")


@dataclass(frozen=True)
class Function:
    """A recovered definition with metrics and an optional NetworkX CFG.

    Line numbers refer to normalized text when ``is_decompilation=True``.
    ``diagnostics`` covers the containing file, not only this function.
    Unsupported analyses raise rather than presenting an empty result.
    """

    name: str
    filename: Path
    start_line: int
    end_line: int
    callees: tuple[str, ...]
    cfg: nx.DiGraph | None
    metrics: source.FunctionMetrics
    diagnostics: tuple[source.Diagnostic, ...]

    @property
    def ddg(self) -> nx.DiGraph:
        """Reject access to an unimplemented data-dependence graph."""
        raise NotImplementedError("Glaurung's Joern adapter does not compute DDGs")

    @property
    def ast(self) -> nx.DiGraph:
        """Reject access to a Joern-compatible AST."""
        raise NotImplementedError("Glaurung's Joern adapter does not expose Joern ASTs")


def _networkx() -> ModuleType:
    try:
        import networkx as nx
    except ImportError as error:
        raise ImportError("Install glaurung[graphs] to use NetworkX graphs") from error
    return nx


def _read(path: Path, is_decompilation: bool, strict: bool) -> source.SourceReport:
    from glaurung import source

    report = source.analyze_path(
        path, dialect="decompiled" if is_decompilation else None
    )
    if report.diagnostics:
        error = SourceParseError(path, report.diagnostics)
        if strict:
            raise error
        warnings.warn(str(error), SourceParseWarning, stacklevel=3)
    return report


def _single_file(path: str | Path) -> Path:
    result = Path(path).expanduser().resolve()
    if result.is_dir():
        raise ValueError(
            "This call requires a single file; use parse_source for a directory"
        )
    return result


def _graphs(report: source.SourceReport) -> dict[str, nx.DiGraph]:
    _networkx()
    graphs = source_cfg.cfgs_from_decompiled(report.source)
    for name, graph in graphs.items():
        graph.name = name
        graph.graph.update(path=report.name, diagnostics=report.diagnostics)
        for node in graph:
            graph.nodes[node]["node"] = node
        for a, b in graph.edges:
            graph.edges[a, b].update(src=a, dst=b)
    return graphs


def fast_cfgs_from_source(
    filepath: str | Path,
    lift_cfgs: bool = True,
    supergraph: bool = True,
    timeout: float | None = None,
    *,
    is_decompilation: bool = False,
    strict: bool = False,
) -> dict[str, nx.DiGraph]:
    """Read a C file and return function-name-to-NetworkX-CFG mappings.

    Args:
        filepath: One source file, read as UTF-8 with replacement for bad bytes.
        lift_cfgs: Must be true; raw Joern DOT nodes are not available.
        supergraph: Must be true; only the coalesced comparison graph is exposed.
        timeout: Must be None. This in-process API has no cancellable deadline.
        is_decompilation: Normalize pseudocode in memory before parsing.
        strict: Raise on any parser diagnostic instead of warning and recovering.

    Returns:
        Recovered, scoreable function graphs. Nodes carry ``id``,
        ``is_entrypoint`` and ``is_exitpoint``; they have no JIL statements.
        Graph attributes include ``path`` and file-level ``diagnostics``.
        Duplicate names use the graph with more nodes, keeping the first tie.

    Raises:
        OSError: The file cannot be read.
        ValueError: The path is a directory.
        SourceParseError: Strict mode encountered diagnostics.
        NotImplementedError: A requested option has no supported implementation.
        ImportError: NetworkX is missing; install ``glaurung[graphs]``.
    """
    if not lift_cfgs or not supergraph:
        raise NotImplementedError("Only lift_cfgs=True, supergraph=True is supported")
    if timeout is not None:
        raise NotImplementedError(
            "No in-process timeout; run in a worker process to enforce a deadline"
        )
    return _graphs(_read(_single_file(filepath), is_decompilation, strict))


def parse_source(
    source_path: str | Path,
    no_metadata: bool = False,
    no_cfg: bool = False,
    no_ddg: bool = True,
    no_ast: bool = True,
    is_decompilation: bool = False,
    *,
    strict: bool = False,
) -> dict[str | tuple[str, str], Function]:
    """Read C definitions from a file or a recursively searched directory.

    Args:
        source_path: One file, or a directory searched for ``*.c`` and ``*.h``.
        no_metadata: Must be false; metadata is required to identify definitions.
        no_cfg: Omit NetworkX graphs. Metrics still build the general CFG.
        no_ddg: Must be true. Unlike pyjoern, the default skips this analysis.
        no_ast: Must be true. Unlike pyjoern, the default skips this analysis.
        is_decompilation: Normalize each file in memory, leaving it unchanged.
        strict: Raise on any parser diagnostic instead of warning and recovering.

    Returns:
        Name-keyed functions for a file; ``(name, absolute filename)`` keys for a
        directory. Callees are directly named targets; indirect calls may be absent.
        An empty file or directory returns an empty dict. Unreadable files raise.

    Raises:
        OSError: Any selected file cannot be read.
        SourceParseError: Strict mode encountered diagnostics.
        ValueError: Duplicate definitions prevent unambiguous metadata/CFG pairing.
        NotImplementedError: An unsupported analysis or metadata mode was requested.
        ImportError: Graphs were requested but NetworkX is missing.
    """
    if no_metadata or not no_ddg or not no_ast:
        raise NotImplementedError(
            "Use no_metadata=False, no_ddg=True, no_ast=True; Joern AST/DDG analysis is unsupported"
        )
    path = Path(source_path).expanduser().resolve()
    directory = path.is_dir()
    paths = sorted({*path.rglob("*.c"), *path.rglob("*.h")}) if directory else [path]
    result: dict[str | tuple[str, str], Function] = {}
    for file in paths:
        if directory and not file.is_file():
            continue
        report = _read(file, is_decompilation, strict)
        names = [f.name for f in report.functions]
        if len(names) != len(set(names)):
            raise ValueError(
                f"{file}: duplicate function definitions; use glaurung.source.analyze_path to inspect them"
            )
        graphs = {} if no_cfg else _graphs(report)
        for f in report.functions:
            function = Function(
                f.name,
                file,
                f.first_line,
                f.last_line,
                tuple(f.callees),
                graphs.get(f.name),
                f,
                report.diagnostics,
            )
            if directory:
                result[f.name, str(file)] = function
            else:
                result[f.name] = function
    return result


def parse_callgraph(
    source_path: str | Path, is_decompilation: bool = False, *, strict: bool = False
) -> nx.DiGraph:
    """Read one file and return a directed graph of directly named calls.

    Args:
        source_path: One C file. Directories are rejected because names alone
            cannot distinguish file-local functions with the same spelling.
        is_decompilation: Normalize pseudocode in memory before parsing.
        strict: Raise on any parser diagnostic instead of warning and recovering.

    Returns:
        A NetworkX graph with string nodes. Includes isolated definitions and
        named external callees. Does not resolve indirect calls or included files.
        ``graph['diagnostics']`` holds file-level diagnostics.

    Raises:
        OSError: The file cannot be read.
        ValueError: The path is a directory.
        SourceParseError: Strict mode encountered diagnostics.
        ImportError: NetworkX is missing.
    """
    nx = _networkx()
    report = _read(_single_file(source_path), is_decompilation, strict)
    graph = nx.DiGraph(path=report.name, diagnostics=report.diagnostics)
    graph.add_nodes_from(f.name for f in report.functions)
    graph.add_edges_from(
        (f.name, callee) for f in report.functions for callee in f.callees
    )
    return graph
