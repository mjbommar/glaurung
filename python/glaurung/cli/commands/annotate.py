"""Non-interactive analyst annotation: `rename`, `comment`, `label`, `proto`.

Every one of these already existed -- inside the interactive REPL. Nothing
outside it could rename a function, leave a comment, name a global, or record a
prototype, so an analyst workflow could not be scripted, driven from an editor,
replayed in CI, or handed to an agent. The only writable non-REPL surfaces were
`frame`, `bookmark`, `journal`, `undo` and `redo`.

That is the wrong half to expose. Renaming is the single most common thing a
reverse engineer does -- 14 of the 16 professionals observed in Votipka et al.
(USENIX Security 2020) renamed variables, and 14 annotated -- and it is exactly
the half a batch tool needs. The interactive REPL is the surface that can most
afford to be the only one; it is not.

The verb list here is not invented. Three parties converged on it
independently: Hex-Rays' own IDA Domain API, the cross-decompiler `libbs`
artifact set behind BinSync, and the de-facto agent-facing `ida-pro-mcp`. Where
they agree -- rename, set type, comment, set prototype -- is what an RE surface
is expected to have.

Two conventions, both taken from the commands already in the tree:

* the project file is the first positional, as in `xrefs`, `frame`, `bookmark`;
* an address argument accepts hex or decimal, AND accepts a function name
  already recorded in the project, so `rename p.glaurung validate parse_hdr`
  works without the analyst first looking an address up.

Writes go through the same setters the REPL uses, so provenance ranking
(`kb.provenance`) and the undo log apply identically. `--by` exists because a
tool driving these commands may legitimately be recording something other than
an analyst decision, and mislabelling automation as `manual` would let it
overwrite real analyst edits.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Optional

from .base import BaseCommand
from ..formatters.base import BaseFormatter


def _open_kb(args: argparse.Namespace, formatter: BaseFormatter):
    """Open the project, or report why not. Returns ``(kb, exit_code)``."""
    db_path = Path(args.db)
    if not db_path.exists():
        formatter.output_plain(f"Error: db not found: {db_path}")
        return None, 2
    from glaurung.llm.kb.persistent import PersistentKnowledgeBase

    try:
        return PersistentKnowledgeBase.open(db_path, binary_path=args.binary), 0
    except Exception as e:  # noqa: BLE001 - surfaced to the user, not swallowed
        formatter.output_plain(f"Error opening db: {e}")
        return None, 3


def resolve_va(kb, token: str) -> Optional[int]:
    """An address, or the entry address of a function already named in the project.

    Accepting a name matters more than it looks: without it every annotation
    command needs the analyst to go and find an address first, which is exactly
    the friction that keeps people in a GUI. Numbers are tried first so a
    function perversely named `0x1030` cannot shadow the address 0x1030.
    """
    try:
        return int(token, 0)
    except ValueError:
        pass
    from glaurung.llm.kb import xref_db

    for row in xref_db.list_function_names(kb):
        if row.canonical == token or token in (row.aliases or []):
            return int(row.entry_va)
    return None


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("db", help="Path to .glaurung project file")
    parser.add_argument(
        "--binary",
        type=Path,
        default=None,
        help="Optional: binary path the project was opened against",
    )
    parser.add_argument(
        "--by",
        default="manual",
        metavar="SOURCE",
        help="Provenance to record (default: manual). Use an automatic source "
        "name -- auto, dwarf, pdb, stdlib, flirt, propagated, borrowed -- when "
        "the write is not an analyst decision, so it cannot outrank one.",
    )


class RenameCommand(BaseCommand):
    """Name a function in the project, non-interactively."""

    def get_name(self) -> str:
        return "rename"

    def get_help(self) -> str:
        return "Name a function in a .glaurung project (reaches `decompile --db`)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        _add_common(parser)
        parser.add_argument(
            "func", help="Function entry VA (hex/decimal) or current name"
        )
        parser.add_argument("name", help="New name")

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        kb, code = _open_kb(args, formatter)
        if kb is None:
            return code
        from glaurung.llm.kb import xref_db

        try:
            va = resolve_va(kb, args.func)
            if va is None:
                formatter.output_plain(
                    f"Error: no function {args.func!r} in the project"
                )
                return 4
            if not args.name.strip():
                formatter.output_plain("Error: a name cannot be blank")
                return 2
            xref_db.set_function_name(kb, va, args.name, set_by=args.by)
            row = next(
                (r for r in xref_db.list_function_names(kb) if r.entry_va == va), None
            )
            if row is None or row.canonical != args.name:
                held = row.set_by if row else "?"
                formatter.output_plain(
                    f"  refused: 0x{va:x} is held by a stronger source "
                    f"({held}); pass --by manual to override"
                )
                return 5
            formatter.output_plain(f"  0x{va:x} -> {args.name}  [{args.by}]")
            return 0
        finally:
            kb.close()


class CommentCommand(BaseCommand):
    """Attach, show, or delete a comment at an address."""

    def get_name(self) -> str:
        return "comment"

    def get_help(self) -> str:
        return "Set / show / delete a comment at an address in a .glaurung project"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        _add_common(parser)
        parser.add_argument("va", help="Address (hex/decimal) or a function name")
        parser.add_argument("text", nargs="*", help="Comment body; omit to show")
        parser.add_argument(
            "--delete", action="store_true", help="Delete the comment at this address"
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        kb, code = _open_kb(args, formatter)
        if kb is None:
            return code
        from glaurung.llm.kb import xref_db

        try:
            va = resolve_va(kb, args.va)
            if va is None:
                formatter.output_plain(
                    f"Error: bad address or unknown name: {args.va!r}"
                )
                return 2
            if args.delete:
                # An empty body is how the schema spells "no comment"; there is
                # no delete_comment, and inventing one here would bypass the
                # precedence guard and the undo log that set_comment applies.
                xref_db.set_comment(kb, va, "", set_by=args.by)
                formatter.output_plain(f"  cleared comment at 0x{va:x}")
                return 0
            if not args.text:
                body = xref_db.get_comment(kb, va)
                formatter.output_plain(body if body else f"  (no comment at 0x{va:x})")
                return 0
            body = " ".join(args.text)
            xref_db.set_comment(kb, va, body, set_by=args.by)
            if xref_db.get_comment(kb, va) != body:
                formatter.output_plain(
                    f"  refused: a comment at 0x{va:x} is held by a stronger source"
                )
                return 5
            formatter.output_plain(f"  0x{va:x}: {body}  [{args.by}]")
            return 0
        finally:
            kb.close()


class LabelCommand(BaseCommand):
    """Name a data address (a global), optionally with a C type."""

    def get_name(self) -> str:
        return "label"

    def get_help(self) -> str:
        return "Name a data address in a .glaurung project, with an optional C type"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        _add_common(parser)
        parser.add_argument("va", help="Data address (hex/decimal)")
        parser.add_argument("name", nargs="?", help="Label name; omit to show")
        parser.add_argument("--type", dest="c_type", default=None, help="C type")
        parser.add_argument("--size", type=int, default=None, help="Size in bytes")
        parser.add_argument("--delete", action="store_true", help="Remove the label")

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        kb, code = _open_kb(args, formatter)
        if kb is None:
            return code
        from glaurung.llm.kb import xref_db

        try:
            try:
                va = int(args.va, 0)
            except ValueError:
                formatter.output_plain(f"Error: bad address: {args.va!r}")
                return 2
            if args.delete:
                if xref_db.get_data_label(kb, va) is None:
                    formatter.output_plain(f"  no label at 0x{va:x}")
                    return 4
                xref_db.remove_data_label(kb, va, set_by=args.by)
                if xref_db.get_data_label(kb, va) is not None:
                    formatter.output_plain(
                        f"  refused: the label at 0x{va:x} is held by a stronger source"
                    )
                    return 5
                formatter.output_plain(f"  removed label at 0x{va:x}")
                return 0
            if args.name is None:
                existing = xref_db.get_data_label(kb, va)
                if existing is None:
                    formatter.output_plain(f"  (no label at 0x{va:x})")
                    return 0
                shown = f"  0x{va:x}  {existing.name}"
                if existing.c_type:
                    shown += f"  {existing.c_type}"
                formatter.output_plain(f"{shown}  [{existing.set_by}]")
                return 0
            xref_db.set_data_label(
                kb,
                va,
                args.name,
                c_type=args.c_type,
                size=args.size,
                set_by=args.by,
            )
            stored = xref_db.get_data_label(kb, va)
            if stored is None or stored.name != args.name:
                formatter.output_plain(
                    f"  refused: the label at 0x{va:x} is held by a stronger source"
                )
                return 5
            formatter.output_plain(f"  0x{va:x} -> {args.name}  [{args.by}]")
            return 0
        finally:
            kb.close()


class ProtoCommand(BaseCommand):
    """Record a function prototype."""

    def get_name(self) -> str:
        return "proto"

    def get_help(self) -> str:
        return "Set / show a function prototype in a .glaurung project"

    # A declared prototype reaches `decompile --db` only when its parameter
    # COUNT matches the arity the decompiler recovered. On a mismatch the
    # renderer drops the whole declaration -- return type included -- and falls
    # back to the recovered signature. That gate is pre-existing and protects
    # DWARF the same way; it is why a wrong prototype cannot corrupt output.
    # It is also silent, which is why `--binary` exists below.

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        _add_common(parser)
        parser.add_argument("name", help="Function name (prototypes are keyed by name)")
        parser.add_argument(
            "ret", nargs="?", help="Return type; omit to show the current prototype"
        )
        parser.add_argument(
            "params",
            nargs="*",
            help="Parameters as name:type (e.g. buf:char* len:int)",
        )
        parser.add_argument(
            "--variadic", action="store_true", help="Mark the prototype variadic"
        )
        parser.add_argument(
            "--check-arity",
            action="store_true",
            help="With --binary, warn if the parameter count does not match the "
            "arity the decompiler recovered. A prototype whose arity differs is "
            "silently ignored by `decompile --db`, so this turns a no-op into a "
            "message.",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        kb, code = _open_kb(args, formatter)
        if kb is None:
            return code
        from glaurung.llm.kb import xref_db

        try:
            if args.ret is None:
                proto = xref_db.get_function_prototype(kb, args.name)
                if proto is None:
                    formatter.output_plain(f"  (no prototype for {args.name})")
                    return 0
                formatter.output_plain(f"  {_render_proto(args.name, proto)}")
                return 0
            params = []
            for spec in args.params:
                if ":" not in spec:
                    formatter.output_plain(
                        f"Error: parameter {spec!r} is not name:type"
                    )
                    return 2
                pname, _, ptype = spec.partition(":")
                if not pname or not ptype:
                    formatter.output_plain(
                        f"Error: parameter {spec!r} is not name:type"
                    )
                    return 2
                params.append(xref_db.FunctionParam(name=pname, c_type=ptype))
            xref_db.set_function_prototype(
                kb,
                args.name,
                args.ret,
                params,
                is_variadic=args.variadic,
                set_by=args.by,
            )
            stored = xref_db.get_function_prototype(kb, args.name)
            if stored is None or stored.return_type != args.ret:
                formatter.output_plain(
                    f"  refused: the prototype for {args.name} is held by a "
                    "stronger source"
                )
                return 5
            formatter.output_plain(f"  {_render_proto(args.name, stored)}  [{args.by}]")
            _warn_on_arity_mismatch(args, formatter, len(params))
            return 0
        finally:
            kb.close()


def _warn_on_arity_mismatch(
    args: argparse.Namespace, formatter: BaseFormatter, declared: int
) -> None:
    """Say so when this prototype will be ignored by `decompile --db`.

    The renderer applies a declared prototype only on an exact arity match and
    drops the whole declaration otherwise. That is the right conservative rule
    -- a wrong prototype cannot corrupt the output -- but an analyst who types a
    signature and sees nothing change deserves to know which of the two
    happened.

    Needs the binary, because only the decompiler knows the recovered arity, so
    it is opt-in via `--check-arity --binary <path>`.

    The function is resolved through the PROJECT first. Prototypes are keyed by
    name, and the name an analyst types is the one they just chose -- which the
    binary does not know. Resolving against the binary alone made this check
    fail silently for a renamed function, i.e. exactly when it was wanted.
    """
    if not getattr(args, "check_arity", False):
        return
    binary = getattr(args, "binary", None)
    if binary is None:
        formatter.output_plain(
            "  note: --check-arity needs --binary to compare against"
        )
        return

    from ..kb_names import load_analyst_names

    entry_va = None
    for va, name in load_analyst_names(str(args.db), str(binary)).items():
        if name == args.name:
            entry_va = va
            break
    try:
        import glaurung as g

        if entry_va is None:
            functions = g.analysis.analyze_functions_path(
                str(binary), max_functions=2000
            )[0]
            for function in functions:
                if function.name == args.name:
                    entry_va = int(function.entry_point.value)
                    break
        if entry_va is None:
            formatter.output_plain(
                f"  note: {args.name} is not a function in {binary}; arity unchecked"
            )
            return
        text = g.ir.decompile_at(str(binary), entry_va, style="decbench")
    except Exception as exc:  # noqa: BLE001
        formatter.output_plain(
            f"  note: could not analyse {binary} ({exc}); arity unchecked"
        )
        return

    # Matched by SHAPE, not by name: the rendered name is whatever the binary
    # calls the function, which after a rename is not what the analyst typed.
    match = re.search(r"^[A-Za-z_][\w \*]*\b\w+\(([^)]*)\)\s*\{", text, re.M)
    if not match:
        return
    inner = match.group(1).strip()
    recovered = 0 if inner in ("", "void") else inner.count(",") + 1
    if recovered != declared:
        formatter.output_plain(
            f"  note: {declared} parameter(s) declared but {recovered} "
            f"recovered. `decompile --db` applies a prototype only on an exact "
            f"arity match, so this one will be ignored."
        )


def _render_proto(name: str, proto) -> str:
    params = ", ".join(f"{p.c_type} {p.name}" for p in (proto.params or []))
    if proto.is_variadic:
        params = f"{params}, ..." if params else "..."
    return f"{proto.return_type or 'void'} {name}({params or 'void'})"
