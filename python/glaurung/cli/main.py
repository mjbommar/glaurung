"""Main CLI entry point with modular command structure."""

import argparse
import sys
from importlib import import_module
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime
    from .commands.base import BaseCommand
    from .formatters.base import BaseFormatter

# Command and formatter classes are named here rather than imported, and loaded
# only for the subcommand actually being run.
#
# Importing all 35 eagerly meant every invocation paid for the most expensive
# one. `ask` reaches `glaurung.llm.agents.factory` -> `pydantic_ai` ->
# `pydantic_ai.mcp` / `pydantic_graph`, which `-X importtime` measured at
# 1417 ms of a 1467 ms `import glaurung.cli`. `glaurung --help` took 3.10 s
# while the PyO3 extension itself imports in 0.11 s.
#
# That cost is paid thousands of times per fixture-matrix run, because
# `tools/diff_decompile.py` shells out to `glaurung decompile` once per
# function. `python/tests/test_cli_startup_is_lazy.py` pins the contract.
#
#   name -> (command module, command class, formatter module, formatter class)
_REGISTRY: dict[str, tuple[str, str, str, str]] = {
    "triage": ("triage", "TriageCommand", "", "TriageFormatter"),
    "strings": ("strings", "StringsCommand", "strings", "StringsFormatter"),
    "symbols": ("symbols", "SymbolsCommand", "", "SymbolsFormatter"),
    "disasm": ("disasm", "DisasmCommand", "", "DisasmFormatter"),
    "cfg": ("cfg", "CFGCommand", "", "CFGFormatter"),
    "ask": ("ask", "AskCommand", "ask", "AskFormatter"),
    "decompile": ("decompile", "DecompileCommand", "decompile", "DecompileFormatter"),
    # `explain` emits its rewritten C body via output_plain (with a banner
    # comment) or a JSON payload it prints directly; the decompile formatter is
    # a pass-through that accepts both shapes cleanly.
    "explain": ("explain", "ExplainCommand", "decompile", "DecompileFormatter"),
    "name-func": ("name_func", "NameFuncCommand", "name_func", "NameFuncFormatter"),
    # The REPL is interactive and prints directly, so TriageFormatter is a
    # no-op placeholder that is never actually consulted. Likewise `graph`,
    # which emits raw DOT text via output_plain.
    "repl": ("repl", "ReplCommand", "", "TriageFormatter"),
    "graph": ("graph", "GraphCommand", "", "TriageFormatter"),
    "detect-packer": ("detect_packer", "DetectPackerCommand", "", "TriageFormatter"),
    "diff": ("binary_diff", "BinaryDiffCommand", "", "TriageFormatter"),
    "kickoff": ("kickoff", "KickoffCommand", "", "TriageFormatter"),
    "patch": ("patch", "PatchCommand", "", "TriageFormatter"),
    "verify-recovery": (
        "verify_recovery",
        "VerifyRecoveryCommand",
        "",
        "TriageFormatter",
    ),
    "export": ("export", "ExportCommand", "", "TriageFormatter"),
    "undo": ("undo", "UndoCommand", "", "TriageFormatter"),
    "redo": ("undo", "RedoCommand", "", "TriageFormatter"),
    "xrefs": ("xrefs", "XrefsCommand", "", "TriageFormatter"),
    "frame": ("frame", "FrameCommand", "", "TriageFormatter"),
    "strings-xrefs": ("string_xrefs", "StringsXrefsCommand", "", "TriageFormatter"),
    "view": ("view", "ViewCommand", "", "TriageFormatter"),
    "find": ("find", "FindCommand", "", "TriageFormatter"),
    "bookmark": ("bookmark", "BookmarkCommand", "", "TriageFormatter"),
    "journal": ("bookmark", "JournalCommand", "", "TriageFormatter"),
    "classfile": ("classfile", "ClassfileCommand", "", "TriageFormatter"),
    "java": ("java", "JavaCommand", "", "TriageFormatter"),
    "java-recovery-report": (
        "java_recovery_report",
        "JavaRecoveryReportCommand",
        "",
        "TriageFormatter",
    ),
    "luac": ("luac", "LuacCommand", "", "TriageFormatter"),
    "pe": ("pe", "PeCommand", "", "TriageFormatter"),
    "windows-risk": ("windows_risk", "WindowsRiskCommand", "", "TriageFormatter"),
    "types": ("types", "TypesCommand", "", "TriageFormatter"),
    "windows": ("windows", "WindowsCommand", "", "TriageFormatter"),
    "locks": ("locks", "LocksCommand", "", "TriageFormatter"),
    "group": ("group", "GroupCommand", "", "TriageFormatter"),
}


class GlaurungCLI:
    """Main CLI application."""

    def __init__(self):
        self._commands: dict[str, BaseCommand] = {}

    @property
    def command_names(self) -> tuple[str, ...]:
        """Every registered subcommand, without importing any of them."""
        return tuple(_REGISTRY)

    def command(self, name: str) -> "BaseCommand":
        """Instantiate one subcommand, importing its module on first use."""
        cached = self._commands.get(name)
        if cached is not None:
            return cached
        module_name, class_name, _, _ = _REGISTRY[name]
        module = import_module(f".commands.{module_name}", __package__)
        instance = getattr(module, class_name)()
        self._commands[name] = instance
        return instance

    def formatter_class(self, name: str) -> type["BaseFormatter"]:
        """Resolve one formatter class, importing its module on first use."""
        _, _, module_name, class_name = _REGISTRY[name]
        # An empty module name means the formatter lives in the package root,
        # which re-exports the four shared ones.
        target = f".formatters.{module_name}" if module_name else ".formatters"
        return getattr(import_module(target, __package__), class_name)

    def create_parser(self, only: str | None = None) -> argparse.ArgumentParser:
        """Create the argument parser.

        `only` restricts the registered subparsers to a single command, which is
        what keeps an invocation from importing the other thirty-four. Passing
        `None` registers all of them and therefore imports all of them; that is
        the correct behavior for `--help`, where the whole list is the output.
        """
        parser = argparse.ArgumentParser(
            prog="glaurung", description="Glaurung binary analysis CLI"
        )

        # Add global arguments
        parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")

        # Create subparsers for commands
        subparsers = parser.add_subparsers(
            dest="cmd", required=True, help="Available commands"
        )

        names = (only,) if only is not None else self.command_names
        for cmd_name in names:
            self.command(cmd_name).setup_parser(subparsers)

        return parser

    def _requested_command(self, argv: list[str] | None) -> str | None:
        """The subcommand named in `argv`, if it is one we know.

        The first bare token is the subcommand: the only global options are
        `--version` and `--help`, neither of which takes a value. Anything
        unrecognized returns `None` so the full parser is built and argparse can
        emit its own error listing every valid choice.
        """
        tokens = sys.argv[1:] if argv is None else argv
        for token in tokens:
            if token.startswith("-"):
                continue
            return token if token in _REGISTRY else None
        return None

    def run(self, argv: Optional[List[str]] = None) -> int:
        """Run the CLI application."""
        parser = self.create_parser(only=self._requested_command(argv))
        args = parser.parse_args(argv)

        # Get the command
        if args.cmd not in _REGISTRY:
            print(f"Unknown command: {args.cmd}", file=sys.stderr)
            return 1
        command = self.command(args.cmd)

        # Determine output format
        output_format = command.get_output_format(args)

        # Create the appropriate formatter
        formatter = self.formatter_class(args.cmd)(output_format)

        # Execute the command
        try:
            return command.execute(args, formatter)
        except KeyboardInterrupt:
            print("\nInterrupted by user", file=sys.stderr)
            return 130
        except Exception as e:
            if args.verbose:
                import traceback

                traceback.print_exc()
            else:
                print(f"Error: {e}", file=sys.stderr)
            return 1


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point for the CLI."""
    cli = GlaurungCLI()
    return cli.run(argv)


if __name__ == "__main__":
    sys.exit(main())
