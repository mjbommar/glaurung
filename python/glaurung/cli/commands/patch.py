"""Binary patch CLI subcommand (#185)."""

import argparse
from dataclasses import asdict
from pathlib import Path

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class PatchCommand(BaseCommand):
    """Write hex bytes at a given VA, producing a new binary file."""

    def get_name(self) -> str:
        return "patch"

    def get_help(self) -> str:
        return "Patch hex bytes at a VA to produce a new binary"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("input", help="Source binary")
        parser.add_argument("output", help="Output binary path")
        parser.add_argument(
            "--va", required=True,
            help="Virtual address to patch (hex with 0x or decimal)",
        )
        parser.add_argument(
            "--bytes", dest="payload", default=None,
            help='Hex byte payload, e.g. "90 90 90" or "488b45f8"',
        )
        parser.add_argument(
            "--nop", action="store_true",
            help="NOP out the instruction at --va (size-preserving)",
        )
        parser.add_argument(
            "--jmp", dest="jmp_target", default=None,
            help="Replace the instruction at --va with `jmp <target>` "
                 "(size-preserving, NOP-padded). Argument is target VA.",
        )
        parser.add_argument(
            "--force-branch", choices=("true", "false"), default=None,
            help="Force the conditional branch at --va: true = always "
                 "taken (JMP to original target); false = always not "
                 "taken (NOPs).",
        )
        parser.add_argument(
            "--verify", action="store_true",
            help="After patching, re-disassemble at --va and print "
                 "the resulting instruction so the analyst can confirm "
                 "the byte-level change decodes as intended.",
        )
        parser.add_argument(
            "--force", action="store_true",
            help="Overwrite output if it exists",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        try:
            self.validate_file_path(args.input)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        try:
            va = int(args.va, 0)
        except ValueError:
            formatter.output_plain(f"Error: bad --va: {args.va!r}")
            return 2

        # Mode dispatch: exactly one of --bytes / --nop / --jmp /
        # --force-branch must be set.
        modes = sum(
            1 for x in (
                args.payload, args.nop, args.jmp_target, args.force_branch,
            ) if x
        )
        if modes != 1:
            formatter.output_plain(
                "Error: pass exactly one of --bytes / --nop / --jmp / "
                "--force-branch"
            )
            return 2

        from glaurung.llm.kb.patch import (
            patch_at_va, patch_nop, patch_jmp, patch_force_branch,
            render_patch_markdown,
        )

        try:
            if args.nop:
                result = patch_nop(
                    str(args.input), str(args.output), va,
                    overwrite_output=args.force,
                )
            elif args.jmp_target is not None:
                try:
                    target = int(args.jmp_target, 0)
                except ValueError:
                    formatter.output_plain(
                        f"Error: bad --jmp target: {args.jmp_target!r}"
                    )
                    return 2
                result = patch_jmp(
                    str(args.input), str(args.output), va, target,
                    overwrite_output=args.force,
                )
            elif args.force_branch is not None:
                taken = (args.force_branch == "true")
                result = patch_force_branch(
                    str(args.input), str(args.output), va, taken,
                    overwrite_output=args.force,
                )
            else:
                result = patch_at_va(
                    str(args.input), str(args.output), va, args.payload,
                    overwrite_output=args.force,
                )
        except FileExistsError as e:
            formatter.output_plain(f"Error: {e}")
            return 3
        except (FileNotFoundError, ValueError, RuntimeError, NotImplementedError) as e:
            formatter.output_plain(f"Error: {e}")
            return 4

        verify_str = ""
        if args.verify:
            import glaurung as g
            try:
                ins = g.disasm.disassemble_window_at(
                    str(args.output), int(va),
                    window_bytes=16, max_instructions=1,
                )
                if ins:
                    head = ins[0]
                    ops = ", ".join(
                        str(o) for o in getattr(head, "operands", []) or []
                    )
                    verify_str = (
                        f"verify: {head.mnemonic} {ops}".strip()
                    )
                else:
                    verify_str = "verify: (no instruction decoded)"
            except Exception as e:
                verify_str = f"verify: (failed: {e})"

        if formatter.format_type == OutputFormat.JSON:
            payload_dict = asdict(result)
            if verify_str:
                payload_dict["verify"] = verify_str
            formatter.output_json(payload_dict)
            return 0
        formatter.output_plain(render_patch_markdown(result, input_path=args.input))
        if verify_str:
            formatter.output_plain(f"_{verify_str}_")
        return 0
