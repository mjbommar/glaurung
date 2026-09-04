#!/usr/bin/env python3
"""F-17: write DecBench-shaped source-CFG JSONs from Glaurung's own provider.

Every published ``<opt>/<project>/source_cfgs/<stem>.json`` in the DecBench
corpus was produced by ``decbench.publish.cfg_export.export_project_cfgs``:
one file per binary, resolved across the project's translation units through
``resolved_source_for_binary`` (``decbench/utils/cfg.py``). This tool runs the
same step with Glaurung's own C front end in place of pyjoern: it walks a
project's preprocessed translation units, extracts each one's function CFGs
with ``glaurung.source_cfg.parity_cfgs``, resolves name collisions across TUs
the way ``src/csource/joern/resolve.rs`` (F-16) does, and writes the DecBench
JSON shape (``REQ-OUT-1``) so a written file loads through
``decbench.pipeline.materialized.load_source_cfgs`` and
``decbench.publish.cfg_export.rebuild_cfg`` unmodified -- see that module's
docstring for the full shape (``opt``/``project``/``binary``/``generator``
plus a ``functions`` map of ``{"nodes","edges","labels","entry","exit",
"degenerate"}``). ``load_source_cfgs`` and ``rebuild_cfg`` read only the
``functions`` map and never touch ``labels``, so this tool omits it rather
than fabricate JIL statement text ``ParityCfg`` (``src/csource/joern/mod.rs``)
does not carry.

Layout convention, matching ``decbench.utils.results_tree.compiled_dir`` on
the input side and ``decbench.publish.cfg_export.cfg_json_path`` on the
output side::

    <root>/<opt>/<project>/compiled/*.i   (preprocessed; *.c as a fallback)
    <dest>/<opt>/<project>/source_cfgs/<tu-stem>.json

There is no DWARF-derived binary<->TU mapping here: that needs a compiled
binary plus ``decbench.utils.binfmt.source_function_owners``, which this tool
has no access to. So, like ``src/csource/joern/resolve.rs::resolve_project``,
every translation unit stands in for the binary built from it, per DecBench's
own binary-stem convention (``nologin`` binary <-> ``nologin.i``) -- the same
simplification the Rust module documents and the one real per-project data
was not available to test past.

    uv run python tools/source_cfg_export.py <root> <dest>
    uv run python tools/source_cfg_export.py <root> <dest> --overwrite --json

Exit codes: 0 on any successful walk (including zero TUs found, which is a
report, not a failure -- callers checking coverage read the summary); 2 when
``root`` does not exist or the ``glaurung`` extension is not importable, so an
unrunnable tool is never confused with one that found nothing to export.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

#: One function's serialized CFG, exactly what `glaurung.source_cfg.parity_cfgs`
#: returns per name: `{"nodes", "edges", "entry", "exit", "degenerate"}`.
CfgDict = dict[str, Any]

#: One project's parsed CFGs, per translation-unit stem.
ProjectCfgs = dict[str, dict[str, CfgDict]]

#: `decbench.utils.results_tree.OPT_LEVELS`, reproduced rather than imported --
#: this tool must run in Glaurung's own environment, where `decbench` is not
#: installed (see `tools/source_cfg_parity.py`'s `JoernProvider`, which needs
#: `$DECBENCH_DIR/.venv` for the same reason).
OPT_LEVELS: tuple[str, ...] = ("O0", "O2", "O2-noinline")


def parity_cfgs(text: str) -> dict[str, CfgDict]:
    """One translation unit's function CFGs, via Glaurung's own provider.

    Args:
        text: C source text for one translation unit (typically preprocessed).

    Returns:
        ``{function name: {"nodes", "edges", "entry", "exit", "degenerate"}}``.
    """
    from glaurung.source_cfg import parity_cfgs as _parity_cfgs

    return _parity_cfgs(text)


def _rank(cfg: CfgDict) -> tuple[bool, int]:
    """Sort key preferring a non-degenerate, then larger, CFG.

    Mirrors ``decbench.utils.cfg._source_rank`` and
    ``src/csource/joern/resolve.rs::rank`` exactly.

    Args:
        cfg: A serialized function CFG.

    Returns:
        A tuple comparable with ``>``: non-degenerate CFGs always outrank
        degenerate ones, and among CFGs of equal degeneracy the one with more
        nodes wins.
    """
    return (not cfg["degenerate"], len(cfg["nodes"]))


def best_by_name(by_tu: ProjectCfgs) -> dict[str, CfgDict]:
    """Collapse per-TU CFGs to one-per-name, preferring the real, larger body.

    The cross-TU fallback used when a binary's own TU doesn't define a name at
    all, or defines it only as an empty prototype. Mirrors
    ``decbench.utils.cfg.best_source_by_name`` and
    ``src/csource/joern/resolve.rs::best_by_name``.

    Args:
        by_tu: A project's CFGs, keyed by translation-unit stem then function
            name.

    Returns:
        ``{function name: CFG}``, the single highest-ranked candidate for
        each name across every TU.
    """
    best: dict[str, CfgDict] = {}
    for cfgs in by_tu.values():
        for name, cfg in cfgs.items():
            current = best.get(name)
            if current is None or _rank(cfg) > _rank(current):
                best[name] = cfg
    return best


def resolve_for_binary(
    binary_tu_stem: str, by_tu: ProjectCfgs, fallback: dict[str, CfgDict]
) -> dict[str, CfgDict]:
    """The function CFGs to score one binary against, TU-aware.

    Mirrors ``decbench.utils.cfg.resolved_source_for_binary`` without its
    DWARF ``function_owners`` step (see the module docstring) and
    ``src/csource/joern/resolve.rs::resolve_for_binary``: start from the
    cross-TU fallback, then let the binary's own TU override any name it
    defines non-degenerately. That override is unconditional -- a binary's
    own, smaller version of a name always wins over a larger same-named
    candidate pulled in from another TU of the same project; there is no
    node-count comparison at this step, only at :func:`best_by_name`.

    Args:
        binary_tu_stem: The translation-unit stem standing in for the binary
            (the binary-stem convention -- see the module docstring).
        by_tu: A project's CFGs, keyed by translation-unit stem then function
            name.
        fallback: The project-wide cross-TU map from :func:`best_by_name`.

    Returns:
        ``{function name: CFG}`` for this one binary.
    """
    resolved = dict(fallback)
    for name, cfg in by_tu.get(binary_tu_stem, {}).items():
        if not cfg["degenerate"]:
            resolved[name] = cfg
    return resolved


def resolve_project(by_tu: ProjectCfgs) -> ProjectCfgs:
    """Resolve every TU of a project as if it were its own binary.

    Args:
        by_tu: A project's CFGs, keyed by translation-unit stem then function
            name.

    Returns:
        ``{translation-unit stem: {function name: CFG}}``, one resolved map
        per TU, standing in for the binary built from it.
    """
    fallback = best_by_name(by_tu)
    return {stem: resolve_for_binary(stem, by_tu, fallback) for stem in by_tu}


def tu_files(compiled_dir: Path) -> list[Path]:
    """Translation units to parse in one project's compiled directory.

    Args:
        compiled_dir: A ``<root>/<opt>/<project>/compiled`` directory.

    Returns:
        Preprocessed ``*.i`` files, sorted by name, when any exist; otherwise
        raw ``*.c`` files, also sorted, as a fallback for a tree that never
        ran a preprocess step.
    """
    preprocessed = sorted(compiled_dir.glob("*.i"))
    if preprocessed:
        return preprocessed
    return sorted(compiled_dir.glob("*.c"))


def parse_project(compiled_dir: Path) -> ProjectCfgs:
    """Parse every translation unit in one project into per-TU CFGs.

    Args:
        compiled_dir: A ``<root>/<opt>/<project>/compiled`` directory.

    Returns:
        ``{translation-unit stem: {function name: CFG}}``.
    """
    by_tu: ProjectCfgs = {}
    for path in tu_files(compiled_dir):
        text = path.read_text(errors="replace")
        by_tu[path.stem] = parity_cfgs(text)
    return by_tu


def cfg_json_path(dest: Path, opt: str, project: str, stem: str) -> Path:
    """Path of a binary's source-CFG JSON under ``dest``.

    Matches ``decbench.publish.cfg_export.cfg_json_path`` exactly, which is
    also the path ``decbench.pipeline.materialized.load_source_cfgs`` reads.

    Args:
        dest: Destination tree root.
        opt: Optimization level (``O0``, ``O2``, ``O2-noinline``).
        project: Project name.
        stem: Binary (translation-unit) stem.

    Returns:
        The JSON path for this binary's resolved CFGs.
    """
    return dest / opt / project / "source_cfgs" / f"{stem}.json"


def write_cfg_json(
    path: Path,
    opt: str,
    project: str,
    stem: str,
    resolved: dict[str, CfgDict],
    generator: str,
) -> None:
    """Serialize one binary's resolved function CFGs (``REQ-OUT-1`` / F-17).

    Field order and content match
    ``decbench.publish.cfg_export._write_cfg_json`` exactly, minus ``labels``
    (see the module docstring: it is provenance-only and neither
    ``rebuild_cfg`` nor ``load_source_cfgs`` reads it).

    Args:
        path: Output JSON path (parent directories are created as needed).
        opt: Optimization level, recorded for provenance only.
        project: Project name, recorded for provenance only.
        stem: Binary stem, recorded for provenance only (the loader keys on
            the JSON filename, not this field).
        resolved: ``{function name: CFG}`` for this binary.
        generator: The ``generator`` field to record (e.g. ``"glaurung"``).
    """
    functions = {
        name: {
            "nodes": cfg["nodes"],
            "edges": cfg["edges"],
            "entry": cfg["entry"],
            "exit": cfg["exit"],
            "degenerate": cfg["degenerate"],
        }
        for name, cfg in resolved.items()
    }
    data = {
        "opt": opt,
        "project": project,
        "binary": stem,
        "generator": generator,
        "functions": functions,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def export_project(
    root: Path,
    dest: Path,
    opt: str,
    project: str,
    *,
    overwrite: bool,
    generator: str,
) -> list[Path]:
    """Write source-CFG JSONs for one project's translation units.

    Args:
        root: Input tree root (``<root>/<opt>/<project>/compiled/*.i``).
        dest: Output tree root.
        opt: Optimization level.
        project: Project name.
        overwrite: Rewrite a JSON that already exists at the target path.
        generator: The ``generator`` field to record in each written file.

    Returns:
        Paths actually written (existing files skipped when ``overwrite`` is
        false are not included).
    """
    compiled = root / opt / project / "compiled"
    if not compiled.is_dir():
        return []
    by_tu = parse_project(compiled)
    if not by_tu:
        return []
    resolved = resolve_project(by_tu)
    written: list[Path] = []
    for stem, functions in resolved.items():
        target = cfg_json_path(dest, opt, project, stem)
        if target.exists() and not overwrite:
            continue
        write_cfg_json(target, opt, project, stem, functions, generator)
        written.append(target)
    return written


def discover_projects(root: Path) -> list[tuple[str, str]]:
    """``(opt, project)`` pairs present under ``root``.

    Args:
        root: Input tree root.

    Returns:
        Sorted ``(opt, project)`` pairs whose ``compiled`` directory exists,
        matching ``decbench.utils.results_tree.compiled_dir``'s layout.
    """
    pairs: list[tuple[str, str]] = []
    for opt in OPT_LEVELS:
        opt_dir = root / opt
        if not opt_dir.is_dir():
            continue
        for project_dir in sorted(p for p in opt_dir.iterdir() if p.is_dir()):
            if (project_dir / "compiled").is_dir():
                pairs.append((opt, project_dir.name))
    return pairs


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0] if __doc__ else ""
    )
    parser.add_argument(
        "root", type=Path, help="tree with <opt>/<project>/compiled/*.i (or *.c)"
    )
    parser.add_argument("dest", type=Path, help="destination tree root")
    parser.add_argument(
        "--overwrite", action="store_true", help="rewrite existing JSONs"
    )
    parser.add_argument(
        "--generator", default="glaurung", help="the 'generator' field to record"
    )
    parser.add_argument("--json", action="store_true", help="emit a JSON summary")
    args = parser.parse_args()

    if not args.root.is_dir():
        print(f"no tree at {args.root}", file=sys.stderr)
        return 2

    try:
        import glaurung  # noqa: F401
    except ImportError as exc:
        print(f"glaurung extension not importable: {exc}", file=sys.stderr)
        return 2

    pairs = discover_projects(args.root)
    if not pairs:
        print(f"no <opt>/<project>/compiled dirs under {args.root}", file=sys.stderr)
        return 2

    summary: dict[str, int] = {}
    total = 0
    for opt, project in pairs:
        written = export_project(
            args.root,
            args.dest,
            opt,
            project,
            overwrite=args.overwrite,
            generator=args.generator,
        )
        summary[f"{opt}/{project}"] = len(written)
        total += len(written)

    if args.json:
        print(json.dumps({"total": total, "by_project": summary}, indent=2))
    else:
        print(f"wrote {total} source-CFG JSON(s) under {args.dest}")
        for key, count in summary.items():
            print(f"  {key}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
