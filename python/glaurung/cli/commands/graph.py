"""Graph export command — DOT/GraphViz output for callgraphs and CFGs (#167)."""

from __future__ import annotations

import argparse
from typing import Iterable, List, Optional

import glaurung as g

from ..formatters.base import BaseFormatter, OutputFormat
from .base import BaseCommand


def _dot_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _emit_callgraph_dot(funcs: List, callgraph) -> str:
    """Render the callgraph as DOT. Maps the (potentially stale) callgraph
    node names back to the current Function names by entry VA — the
    callgraph is built before the symbol-rename / DWARF-override passes,
    so its node strings can be `sub_*` even when the discovered Function
    has a real name."""
    # Build sub_<hex> → real_name map.
    name_remap: dict[str, str] = {}
    for f in funcs:
        sub_label = f"sub_{int(f.entry_point.value):x}"
        if f.name and f.name != sub_label:
            name_remap[sub_label] = f.name

    def fix(n: str) -> str:
        return name_remap.get(n, n)

    nodes = list(getattr(callgraph, "nodes", []) or [])
    edges = list(getattr(callgraph, "edges", []) or [])

    lines: List[str] = ["digraph callgraph {"]
    lines.append("  rankdir=LR;")
    lines.append("  node [shape=box, fontname=monospace, fontsize=10];")

    # Style the entry-point function (if any) and library/external imports
    # so the graph reads at a glance.
    discovered_names: set[str] = {f.name for f in funcs}
    for n in nodes:
        real = fix(n)
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

    for e in edges:
        caller = fix(getattr(e, "caller", ""))
        callee = fix(getattr(e, "callee", ""))
        if not caller or not callee:
            continue
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
            dot = _emit_callgraph_dot(funcs, callgraph)
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
