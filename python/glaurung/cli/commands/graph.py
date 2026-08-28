"""Graph export command — DOT/GraphViz output for callgraphs and CFGs (#167)."""

from __future__ import annotations

import argparse
from typing import Iterable, List, Optional

import glaurung as g

from ..formatters.base import BaseFormatter, OutputFormat
from .base import BaseCommand
from ..kb_names import load_analyst_names


def _dot_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _plt_labels(path: str) -> dict[str, str]:
    """`sub_<hex>` → `strlen@plt` for every PLT stub in an ELF.

    The callgraph names a node after a discovered *function*, and a PLT stub is
    not one -- so every call to a library routine, and every intra-module call
    in a shared object, rendered as an anonymous `sub_1020`. A callgraph whose
    library edges are all unnamed hex is close to useless for the thing a
    callgraph is for, which is seeing at a glance what a function talks to.

    The decompiler has always resolved these (`ir::name_resolve` folds
    `elf_plt_map` into its address map); only this surface did not. Failure is
    silent and total: a non-ELF, or a parse error, yields no labels and the
    graph renders exactly as it did before.
    """
    try:
        entries = g.analysis.elf_plt_map_path(str(path))
    except Exception:  # noqa: BLE001 - a PE or a bad parse just gets no labels
        return {}
    return {f"sub_{int(va):x}": str(name) for va, name in entries or []}


def _emit_callgraph_dot(
    funcs: List,
    callgraph,
    analyst_names: dict[int, str] | None = None,
    plt_labels: dict[str, str] | None = None,
) -> str:
    """Render the callgraph as DOT. Maps the (potentially stale) callgraph
    node names back to the current Function names by entry VA — the
    callgraph is built before the symbol-rename / DWARF-override passes,
    so its node strings can be `sub_*` even when the discovered Function
    has a real name."""
    # Build sub_<hex> → real_name map.
    name_remap: dict[str, str] = {}
    # Old function name → analyst name, used to make `@`-qualified aliases
    # follow the rename (see below).
    renamed_bases: dict[str, str] = {}
    for f in funcs:
        va = int(f.entry_point.value)
        sub_label = f"sub_{va:x}"
        if f.name and f.name != sub_label:
            name_remap[sub_label] = f.name
        # An analyst rename outranks whatever the binary calls the function,
        # and has to be applied to BOTH spellings the callgraph might use --
        # the synthesised `sub_<hex>` and the discovered name -- because which
        # one a node carries depends on when the callgraph was built. Without
        # this a renamed function appears under its old name in the callgraph
        # while appearing under its new one in `decompile`, which is worse
        # than having no names at all.
        analyst = (analyst_names or {}).get(va)
        if analyst:
            name_remap[sub_label] = analyst
            if f.name:
                name_remap[f.name] = analyst
                renamed_bases[f.name] = analyst

    # PLT labels fill in nodes no discovered function covers, so they are
    # consulted only after the function remap -- a real function at a stub's
    # address (which does happen for IFUNC resolvers) keeps its own name.
    for label, name in (plt_labels or {}).items():
        # A call inside a shared object targets the callee's PLT stub, not the
        # callee, so a rename that stops at the function leaves every edge
        # reading the old name -- `driver -> validate@plt` next to a node
        # called `hdr_parse`. The `@` qualifier is kept because it is not
        # decoration: it says the edge goes through a stub. Only `@`-qualified
        # spellings are followed, so two static helpers that merely share a
        # name are untouched. This mirrors `ir::name_resolve::apply_analyst_names`.
        base, sep, qualifier = name.partition("@")
        if sep and base in renamed_bases:
            name = f"{renamed_bases[base]}@{qualifier}"
        name_remap.setdefault(label, name)

    def fix(n: str) -> str:
        return name_remap.get(n, n)

    nodes = list(getattr(callgraph, "nodes", []) or [])
    edges = list(getattr(callgraph, "edges", []) or [])

    lines: List[str] = ["digraph callgraph {"]
    lines.append("  rankdir=LR;")
    lines.append("  node [shape=box, fontname=monospace, fontsize=10];")

    # Style the entry-point function (if any) and library/external imports
    # so the graph reads at a glance.
    # Compared against post-remap node names, so a renamed function is still
    # recognised as discovered rather than styled as an external import.
    discovered_names: set[str] = {fix(f.name) for f in funcs if f.name}
    # Two distinct nodes can now resolve to one label -- `.plt` and `.plt.sec`
    # hold separate stubs for the same symbol, and both are `strlen@plt`. That
    # collapse is correct (they ARE the same callee) but the node line must
    # still be emitted once, and edges must still dedupe onto it.
    emitted: set[str] = set()
    for n in nodes:
        real = fix(n)
        if real in emitted:
            continue
        emitted.add(real)
        attrs: List[str] = []
        if real == "main" or real == "_start":
            attrs.append("style=filled")
            attrs.append("fillcolor=lightyellow")
        elif real not in discovered_names:
            # External / library symbol — drawn dashed.
            attrs.append("style=dashed")
            attrs.append('color="#888888"')
        attr_s = (" [" + ", ".join(attrs) + "]") if attrs else ""
        lines.append(f'  "{_dot_escape(real)}"{attr_s};')

    seen_edges: set[tuple[str, str]] = set()
    for e in edges:
        caller = fix(getattr(e, "caller", ""))
        callee = fix(getattr(e, "callee", ""))
        if not caller or not callee:
            continue
        if (caller, callee) in seen_edges:
            continue
        seen_edges.add((caller, callee))
        lines.append(f'  "{_dot_escape(caller)}" -> "{_dot_escape(callee)}";')

    lines.append("}")
    return "\n".join(lines) + "\n"


def _emit_cfg_dot(func) -> str:
    """Render a single function's basic-block CFG as DOT."""
    lines: List[str] = [f"digraph cfg_{int(func.entry_point.value):x} {{"]
    lines.append(f'  label="CFG of {_dot_escape(func.name)}";')
    lines.append("  labelloc=t;")
    lines.append("  node [shape=box, fontname=monospace, fontsize=9];")

    # Build VA → block-id map for edge target lookups.
    block_id_for: dict[int, str] = {}
    blocks: list[tuple[int, int, str]] = []
    for bb in func.basic_blocks:
        s = int(bb.start_address.value)
        e = int(bb.end_address.value)
        bid = bb.id
        block_id_for[s] = bid
        blocks.append((s, e, bid))

    for s, e, bid in blocks:
        label = f"{bid}\\n{s:#x}-{e:#x}"
        lines.append(f'  "{_dot_escape(bid)}" [label="{_dot_escape(label)}"];')

    # Edges come from each block's successor_ids — Function does not
    # expose a top-level edges getter on the Python side.
    for bb in func.basic_blocks:
        for succ_id in bb.successor_ids or []:
            lines.append(f'  "{_dot_escape(bb.id)}" -> "{_dot_escape(succ_id)}";')

    lines.append("}")
    return "\n".join(lines) + "\n"


def _resolve_function(funcs: Iterable, target: str):
    """Resolve `target` to a Function: accepts decimal/hex VA or function name."""
    if target.startswith("0x") or target.startswith("0X"):
        try:
            va = int(target, 16)
        except ValueError:
            va = None
    else:
        try:
            va = int(target)
        except ValueError:
            va = None
    for f in funcs:
        if va is not None and int(f.entry_point.value) == va:
            return f
        if f.name == target:
            return f
    return None


class GraphCommand(BaseCommand):
    """Export DOT/GraphViz for callgraph or per-function CFG."""

    def get_name(self) -> str:
        return "graph"

    def get_help(self) -> str:
        return "Export DOT/GraphViz for callgraph or function CFG"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", help="Path to binary")
        sub = parser.add_subparsers(dest="kind", required=True)

        cg = sub.add_parser("callgraph", help="Export the whole callgraph as DOT")
        cg.add_argument("--max-functions", type=int, default=128)
        cg.add_argument(
            "--db",
            default=None,
            help="Optional .glaurung project file. Function names recorded in "
            "the project are used for the graph's nodes, so a callgraph agrees "
            "with `decompile --db` instead of showing pre-rename names.",
        )

        cfg = sub.add_parser("cfg", help="Export one function's CFG as DOT")
        cfg.add_argument(
            "function",
            help="Target function: name (e.g. 'main') or entry VA ('0x1320'/'4896')",
        )
        cfg.add_argument("--max-functions", type=int, default=64)

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        try:
            path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        try:
            funcs, callgraph = g.analysis.analyze_functions_path(str(path))
        except Exception as e:
            formatter.output_plain(f"Error during analysis: {e}")
            return 3

        if args.kind == "callgraph":
            dot = _emit_callgraph_dot(
                funcs,
                callgraph,
                load_analyst_names(getattr(args, "db", None), str(path)),
                _plt_labels(str(path)),
            )
            formatter.output_plain(dot)
            return 0

        if args.kind == "cfg":
            target = _resolve_function(funcs, args.function)
            if target is None:
                formatter.output_plain(
                    f"Error: function {args.function!r} not found "
                    f"(saw {len(funcs)} functions)"
                )
                return 4
            if not target.basic_blocks:
                formatter.output_plain(
                    f"Error: {target.name} has no basic blocks (skipped during discovery)"
                )
                return 5
            dot = _emit_cfg_dot(target)
            formatter.output_plain(dot)
            return 0

        formatter.output_plain(f"Error: unknown graph kind {args.kind!r}")
        return 6
