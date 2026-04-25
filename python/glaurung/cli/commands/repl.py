"""Interactive analysis REPL — Tier-S #155.

The user-facing product on top of #152 (persistent KB), #153 (type
system), and #154 (xref database). Loads a binary, opens (or creates)
its ``.glaurung`` file, and exposes a navigation grammar an analyst
can drive interactively:

    glaurung repl <binary>

    > goto 0x10c0
    > rename 0x10c0 parse_config
    > comment 0x10cf "stack canary save"
    > xrefs 0x10c0
    > decomp 0x10c0
    > type request struct method:char* path:char* length:size_t
    > apply request 0x10c0
    > forward / back
    > ask "what does this function do?"
    > save / quit

State is persisted on every command (no save-on-exit fragility) so
``glaurung repl <binary>`` next morning resumes exactly where the
previous session ended.

Implementation philosophy: thin CLI grammar over the existing
PersistentKnowledgeBase / xref_db / type_db modules. The REPL is
*not* the place to add new analysis; it is the place to drive
analysis interactively and persist the analyst's decisions.
"""

from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path
from typing import List, Optional

from .base import BaseCommand
from ..formatters.base import BaseFormatter


class ReplCommand(BaseCommand):
    """``glaurung repl <binary>`` — interactive analysis session."""

    def get_name(self) -> str:
        return "repl"

    def get_help(self) -> str:
        return "Interactive analysis session with persistent KB"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "binary", help="Path to the binary (or existing .glaurung file)",
        )
        parser.add_argument(
            "--db",
            help="Path to the .glaurung database file. Defaults to "
                 "<binary>.glaurung next to the binary.",
        )
        parser.add_argument(
            "--session", default="main",
            help="Session name (default: 'main'). Different sessions on "
                 "the same binary keep their KB nodes separate.",
        )
        parser.add_argument(
            "--no-index", action="store_true",
            help="Skip the one-time callgraph indexing step.",
        )

    # ------------------------------------------------------------------

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        binary_path = self.validate_file_path(args.binary)
        db_path = Path(args.db) if args.db else binary_path.with_suffix(
            binary_path.suffix + ".glaurung"
        )

        # Lazy import — pulling pydantic-ai for `ask` is expensive and
        # not every REPL session uses AI.
        import glaurung as g
        from glaurung.llm.kb.persistent import PersistentKnowledgeBase
        from glaurung.llm.kb import xref_db, type_db

        sys.stdout.write(f"glaurung repl  binary={binary_path}\n")
        sys.stdout.write(f"               db={db_path}  session={args.session!r}\n")

        kb = PersistentKnowledgeBase.open(
            db_path, binary_path=binary_path, session=args.session,
            auto_load_stdlib=True,
        )

        # One-time indexing on first open. Cheap if already indexed.
        if not args.no_index and not xref_db.is_indexed(kb):
            sys.stdout.write("indexing callgraph (first time)…\n")
            n = xref_db.index_callgraph(kb, str(binary_path))
            sys.stdout.write(f"  {n} call edges indexed\n")

        # Navigation history for `forward` / `back`.
        history: List[int] = []
        cursor = -1   # index into history; -1 == no current position

        def _push(va: int) -> None:
            nonlocal cursor
            # Truncate any forward history when we navigate from middle.
            del history[cursor + 1 :]
            history.append(va)
            cursor = len(history) - 1

        def _here() -> Optional[int]:
            return history[cursor] if 0 <= cursor < len(history) else None

        # Cached function map (entry_va → Function), populated lazily so the
        # REPL stays cheap on cold open. Refresh when the user runs `goto`.
        _funcs_cache: dict[int, object] = {}

        def _ensure_funcs() -> dict[int, object]:
            if not _funcs_cache:
                import glaurung as g
                try:
                    funcs, _cg = g.analysis.analyze_functions_path(str(binary_path))
                except Exception:
                    return _funcs_cache
                for f in funcs:
                    _funcs_cache[int(f.entry_point.value)] = f
            return _funcs_cache

        def _enclosing_function_va(va: int) -> Optional[int]:
            """Map a VA to the entry of the function whose chunks cover it."""
            funcs = _ensure_funcs()
            for entry_va, f in funcs.items():
                # Use chunk-aware containment so cold splits resolve correctly.
                try:
                    if f.contains_va(int(va)):
                        return int(entry_va)
                except Exception:
                    pass
            return None

        # --------------------------------------------------------------
        # Command dispatch
        # --------------------------------------------------------------

        ctx = self._build_memory_context(binary_path, kb, db_path, args.session)
        agent = None  # constructed lazily on first `ask`

        def cmd_help(_argv: List[str]) -> None:
            sys.stdout.write(_HELP_TEXT)

        def cmd_quit(_argv: List[str]) -> None:
            raise EOFError

        def cmd_save(_argv: List[str]) -> None:
            kb.save()
            sys.stdout.write("saved.\n")

        def cmd_goto(argv: List[str]) -> None:
            if not argv:
                sys.stdout.write("goto <addr>\n")
                return
            try:
                va = int(argv[0], 0)
            except ValueError:
                sys.stdout.write(f"invalid address: {argv[0]!r}\n")
                return
            _push(va)
            name = xref_db.get_function_name(kb, va)
            if name:
                sys.stdout.write(f"  {va:#x}  {name.canonical}  (set_by={name.set_by})\n")
            else:
                sys.stdout.write(f"  {va:#x}\n")

        def cmd_back(_argv: List[str]) -> None:
            nonlocal cursor
            if cursor <= 0:
                sys.stdout.write("(at oldest history entry)\n")
                return
            cursor -= 1
            sys.stdout.write(f"  {_here():#x}\n")

        def cmd_forward(_argv: List[str]) -> None:
            nonlocal cursor
            if cursor + 1 >= len(history):
                sys.stdout.write("(at newest history entry)\n")
                return
            cursor += 1
            sys.stdout.write(f"  {_here():#x}\n")

        def cmd_rename(argv: List[str]) -> None:
            if len(argv) < 2:
                sys.stdout.write("rename <addr> <name> [--by manual|llm|...]\n")
                return
            try:
                va = int(argv[0], 0)
            except ValueError:
                sys.stdout.write(f"invalid address: {argv[0]!r}\n")
                return
            new_name = argv[1]
            set_by = "manual"
            if "--by" in argv:
                idx = argv.index("--by")
                if idx + 1 < len(argv):
                    set_by = argv[idx + 1]
            xref_db.set_function_name(kb, va, new_name, set_by=set_by)
            sys.stdout.write(f"  {va:#x} → {new_name}\n")

        def cmd_comment(argv: List[str]) -> None:
            if len(argv) < 2:
                sys.stdout.write("comment <addr> <text>\n")
                return
            try:
                va = int(argv[0], 0)
            except ValueError:
                sys.stdout.write(f"invalid address: {argv[0]!r}\n")
                return
            body = " ".join(argv[1:])
            xref_db.set_comment(kb, va, body)
            sys.stdout.write(f"  {va:#x}: {body}\n")

        def cmd_xrefs(argv: List[str]) -> None:
            target = self._resolve_va(argv, _here())
            if target is None:
                sys.stdout.write("xrefs [<addr>]\n")
                return
            into = xref_db.list_xrefs_to(kb, target)
            outof = xref_db.list_xrefs_from(kb, target)
            sys.stdout.write(f"  refs to {target:#x}: {len(into)}\n")
            for r in into[:8]:
                fn = xref_db.get_function_name(kb, r.src_va)
                tag = fn.canonical if fn else f"sub_{r.src_va:x}"
                sys.stdout.write(f"    {r.kind:8s}  {r.src_va:#x} ({tag})\n")
            sys.stdout.write(f"  refs from {target:#x}: {len(outof)}\n")
            for r in outof[:8]:
                fn = xref_db.get_function_name(kb, r.dst_va)
                tag = fn.canonical if fn else f"sub_{r.dst_va:x}"
                sys.stdout.write(f"    {r.kind:8s}  {r.dst_va:#x} ({tag})\n")

        def cmd_decomp(argv: List[str]) -> None:
            target = self._resolve_va(argv, _here())
            if target is None:
                sys.stdout.write("decomp [<addr>]\n")
                return
            try:
                text = g.ir.decompile_at(
                    str(binary_path), target,
                    timeout_ms=500, style="c",
                )
            except Exception as e:
                sys.stdout.write(f"decompile failed: {e}\n")
                return
            for ln in text.splitlines()[:80]:
                sys.stdout.write(f"  {ln}\n")
            if text.count("\n") > 80:
                sys.stdout.write(f"  ... ({text.count(chr(10)) - 80} more lines)\n")

        def cmd_functions(argv: List[str]) -> None:
            names = xref_db.list_function_names(kb)
            limit = 20
            if argv:
                try:
                    limit = int(argv[0])
                except ValueError:
                    pass
            sys.stdout.write(f"  {len(names)} functions, showing first {limit}:\n")
            for name in names[:limit]:
                # Prefer the demangled form when the canonical is mangled.
                pretty = name.demangled or name.canonical
                # If we did demangle, also show the raw name parenthesized.
                aux = (
                    f"  ({name.canonical})" if name.demangled else ""
                )
                sys.stdout.write(
                    f"    {name.entry_va:#x}  {pretty}{aux}  "
                    f"(set_by={name.set_by})\n"
                )

        def cmd_types(argv: List[str]) -> None:
            kind = argv[0] if argv else None
            recs = type_db.list_types(kb, kind=kind)  # type: ignore[arg-type]
            sys.stdout.write(f"  {len(recs)} types:\n")
            for rec in recs[:30]:
                sys.stdout.write(
                    f"    {rec.kind:14s} {rec.name:30s} "
                    f"(set_by={rec.set_by}, conf={rec.confidence:.2f})\n"
                )

        def cmd_struct(argv: List[str]) -> None:
            """struct <name> field=type[@offset] field=type[@offset] ..."""
            if not argv:
                sys.stdout.write(
                    "struct <name> <field>:<type>[@<offset>] ...\n"
                )
                return
            name = argv[0]
            fields: List[type_db.StructField] = []
            cursor_off = 0
            for spec in argv[1:]:
                if ":" not in spec:
                    continue
                fname, rest = spec.split(":", 1)
                if "@" in rest:
                    ty, off = rest.split("@", 1)
                    try:
                        cursor_off = int(off, 0)
                    except ValueError:
                        continue
                else:
                    ty = rest
                size = _guess_size(ty)
                fields.append(
                    type_db.StructField(
                        offset=cursor_off, name=fname, c_type=ty, size=size,
                    )
                )
                cursor_off += size
            type_db.add_struct(kb, name, fields, set_by="manual")
            sys.stdout.write(f"  struct {name} ({len(fields)} fields) saved\n")

        def cmd_label(argv: List[str]) -> None:
            """label                       — list all data labels
            label set <addr> <name> [<type>]
            label remove <addr>
            label import                 — pull non-function symbols from the binary"""
            if not argv:
                labels = xref_db.list_data_labels(kb)
                if not labels:
                    sys.stdout.write(
                        "(no data labels yet — `label import` to bootstrap from symbols)\n"
                    )
                    return
                sys.stdout.write(f"  {len(labels)} data labels:\n")
                for d in labels[:64]:
                    typ = f": {d.c_type}" if d.c_type else ""
                    sys.stdout.write(
                        f"    {d.va:#010x}  {d.name}{typ}  (set_by={d.set_by})\n"
                    )
                if len(labels) > 64:
                    sys.stdout.write(f"    … {len(labels) - 64} more\n")
                return

            sub = argv[0]
            if sub == "set":
                if len(argv) < 3:
                    sys.stdout.write("label set <addr> <name> [<type>]\n")
                    return
                try:
                    va = int(argv[1], 0)
                except ValueError:
                    sys.stdout.write(f"bad addr: {argv[1]!r}\n")
                    return
                name = argv[2]
                c_type = " ".join(argv[3:]) if len(argv) > 3 else None
                xref_db.set_data_label(
                    kb, va=va, name=name, c_type=c_type, set_by="manual",
                )
                sys.stdout.write(f"  labelled {va:#010x} -> {name}\n")
                kb.save()
                return
            if sub == "remove":
                if len(argv) < 2:
                    sys.stdout.write("label remove <addr>\n")
                    return
                try:
                    va = int(argv[1], 0)
                except ValueError:
                    sys.stdout.write(f"bad addr: {argv[1]!r}\n")
                    return
                xref_db.remove_data_label(kb, va)
                sys.stdout.write(f"  removed label at {va:#010x}\n")
                kb.save()
                return
            if sub == "import":
                n = xref_db.import_data_symbols_from_binary(
                    kb, str(ctx.file_path),
                )
                sys.stdout.write(f"  imported {n} data labels from binary symbols\n")
                kb.save()
                return
            sys.stdout.write(f"unknown label subcommand: {sub!r}\n")

        def cmd_locals(argv: List[str]) -> None:
            """locals               — list stack vars at current function
            locals discover       — auto-discover stack vars at current function
            locals rename <off> <name>  — rename a slot (manual)"""
            here_va = _here()
            if here_va is None:
                sys.stdout.write("(set position with `goto` first)\n")
                return
            # Resolve to function entry by looking up the containing function.
            func_va = _enclosing_function_va(here_va)
            if func_va is None:
                sys.stdout.write(f"no function contains {here_va:#x}\n")
                return

            if not argv:
                vars_ = xref_db.list_stack_vars(kb, function_va=func_va)
                if not vars_:
                    sys.stdout.write(
                        f"no stack vars yet for fn@{func_va:#x}; "
                        "run `locals discover`\n"
                    )
                    return
                sys.stdout.write(f"  {len(vars_)} vars in fn@{func_va:#x}:\n")
                for v in vars_:
                    typ = f": {v.c_type}" if v.c_type else ""
                    sys.stdout.write(
                        f"    {v.offset:+#06x}  {v.name}{typ}  "
                        f"(uses={v.use_count}, by={v.set_by})\n"
                    )
                return

            sub = argv[0]
            if sub == "discover":
                n = xref_db.discover_stack_vars(kb, str(ctx.file_path), func_va)
                sys.stdout.write(
                    f"  discovered {n} stack-frame slot(s) in fn@{func_va:#x}\n"
                )
                kb.save()
                return
            if sub == "rename":
                if len(argv) < 3:
                    sys.stdout.write("locals rename <offset> <name>\n")
                    return
                try:
                    off = int(argv[1], 0)  # accepts decimal, 0x-hex, signed
                except ValueError:
                    sys.stdout.write(f"bad offset: {argv[1]!r}\n")
                    return
                name = argv[2]
                xref_db.set_stack_var(
                    kb, function_va=func_va, offset=off, name=name,
                    set_by="manual",
                )
                sys.stdout.write(f"  renamed {off:+#06x} -> {name}\n")
                kb.save()
                return
            sys.stdout.write(f"unknown locals subcommand: {sub!r}\n")

        def cmd_show(argv: List[str]) -> None:
            """show <type-name>"""
            if not argv:
                sys.stdout.write("show <type-name>\n")
                return
            rec = type_db.get_type(kb, argv[0])
            if rec is None:
                sys.stdout.write(f"no type named {argv[0]!r}\n")
                return
            sys.stdout.write(type_db.render_c_definition(rec) + "\n")

        def cmd_strings(argv: List[str]) -> None:
            sample = list(ctx.artifact.strings.strings)
            limit = 20
            if argv:
                try:
                    limit = int(argv[0])
                except ValueError:
                    pass
            sys.stdout.write(f"  {len(sample)} strings, first {limit}:\n")
            for s in sample[:limit]:
                sys.stdout.write(
                    f"    @{s.offset:08x}  {s.text[:80]!r}\n"
                )

        def cmd_ask(argv: List[str]) -> None:
            nonlocal agent
            if not argv:
                sys.stdout.write("ask <question>\n")
                return
            if agent is None:
                from glaurung.llm.agents.memory_agent import create_memory_agent
                agent = create_memory_agent()
                sys.stdout.write("(loaded memory agent — 51 tools available)\n")
            question = " ".join(argv)
            try:
                result = agent.run_sync(question, deps=ctx)
                sys.stdout.write(str(result.output) + "\n")
            except Exception as e:
                sys.stdout.write(f"agent error: {e}\n")
            kb.save()  # persist any KB nodes the agent added

        commands = {
            "help": cmd_help, "?": cmd_help, "h": cmd_help,
            "quit": cmd_quit, "q": cmd_quit, "exit": cmd_quit,
            "save": cmd_save,
            "goto": cmd_goto, "g": cmd_goto,
            "back": cmd_back, "b": cmd_back,
            "forward": cmd_forward, "f": cmd_forward,
            "rename": cmd_rename, "n": cmd_rename,
            "comment": cmd_comment, "c": cmd_comment,
            "xrefs": cmd_xrefs, "x": cmd_xrefs,
            "decomp": cmd_decomp, "d": cmd_decomp,
            "functions": cmd_functions,
            "types": cmd_types,
            "struct": cmd_struct,
            "show": cmd_show,
            "locals": cmd_locals, "l": cmd_locals,
            "label": cmd_label,
            "strings": cmd_strings, "s": cmd_strings,
            "ask": cmd_ask,
        }

        # --------------------------------------------------------------
        # Main loop
        # --------------------------------------------------------------

        # Enable readline if available so up-arrow history works.
        try:
            import readline  # noqa: F401
        except ImportError:
            pass

        try:
            while True:
                try:
                    here_va = _here()
                    prompt = f"{here_va:#x}> " if here_va is not None else "> "
                    line = input(prompt)
                except EOFError:
                    break
                except KeyboardInterrupt:
                    sys.stdout.write("\n")
                    continue
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    argv = shlex.split(line)
                except ValueError as e:
                    sys.stdout.write(f"parse error: {e}\n")
                    continue
                cmd_name = argv[0]
                handler = commands.get(cmd_name)
                if handler is None:
                    sys.stdout.write(
                        f"unknown command: {cmd_name!r}  "
                        f"(try 'help')\n"
                    )
                    continue
                try:
                    handler(argv[1:])
                except EOFError:
                    raise
                except Exception as e:
                    sys.stdout.write(f"error: {e}\n")
                    continue
                # Persist after every state-changing command — REPL
                # crashes shouldn't lose work.
                if cmd_name in ("rename", "n", "comment", "c",
                                "struct", "ask"):
                    kb.save()
        except (EOFError, KeyboardInterrupt):
            pass

        sys.stdout.write("\nsaving and exiting…\n")
        kb.close()
        return 0

    # ------------------------------------------------------------------

    def _build_memory_context(
        self,
        binary_path: Path,
        kb,
        db_path: Path,
        session: str,
    ):
        """Construct a MemoryContext that reuses the already-open KB
        (so the REPL's writes go through the persistent layer instead
        of an ephemeral in-memory fork)."""
        import glaurung as g
        from glaurung.llm.context import MemoryContext, Budgets

        artifact = g.triage.analyze_path(
            str(binary_path),
            str_min_len=4, str_max_samples=1000, str_max_classify=1000,
        )
        ctx = MemoryContext(
            file_path=str(binary_path),
            artifact=artifact,
            kb=kb,
            budgets=Budgets(timeout_ms=3000),
            session_id=session,
            db_path=str(db_path),
        )
        return ctx

    @staticmethod
    def _resolve_va(argv: List[str], default: Optional[int]) -> Optional[int]:
        if argv:
            try:
                return int(argv[0], 0)
            except ValueError:
                return None
        return default


def _guess_size(c_type: str) -> int:
    """Conservative size guess for the REPL's `struct` shorthand."""
    t = c_type.replace(" ", "")
    if t.endswith("*"):
        return 8
    if t in ("char", "uint8_t", "int8_t", "bool", "_Bool"):
        return 1
    if t in ("short", "uint16_t", "int16_t"):
        return 2
    if t in ("int", "uint32_t", "int32_t", "float"):
        return 4
    if t in ("long", "uint64_t", "int64_t", "size_t", "ssize_t",
             "double", "ptrdiff_t"):
        return 8
    return 8  # default: pointer-sized


_HELP_TEXT = """\
glaurung repl commands

  Navigation
    goto <addr> | g <addr>      jump cursor to address
    back | b                    previous history position
    forward | f                 next history position

  Persistence (auto-saved)
    rename <addr> <name>        set canonical function name
    comment <addr> <text>       attach a comment to an address
    struct <n> a:int b:char* …  define a struct
    locals                      list stack-frame slots in current function
    locals discover             auto-discover stack-frame slots from disasm
    locals rename <off> <name>  rename one slot (offset accepts 0x-hex)
    label                       list global data labels
    label set <addr> <name> [<type>]   add or rename a data label
    label remove <addr>         drop a data label
    label import                bootstrap labels from binary symbols
    save                        force a save (also automatic on every edit)

  Inspection
    xrefs [<addr>]              calls/refs into and out of address
    decomp [<addr>] | d         show pseudocode for the function at address
    functions [<n>]             list functions (default 20)
    types [<kind>]              list types
    show <type-name>            print one type as C
    strings [<n>]               first N triage strings

  AI
    ask <question>              run the memory agent (51 tools) over the
                                binary; persists results to the KB

  Misc
    help | ? | h                this text
    quit | q | exit             save and exit
"""
