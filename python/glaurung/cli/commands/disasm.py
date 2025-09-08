"""Disassembly command implementation."""

import argparse
from pathlib import Path
from typing import Optional

import glaurung as g
from glaurung.disasm import PyDisassembler, disassemble_window_at
from glaurung import DisassemblerConfig, Architecture, Endianness, Address, AddressKind

from .base import BaseCommand
from ..formatters.disasm import DisasmFormatter


class DisasmCommand(BaseCommand):
    """Command for disassembling code from a binary."""

    def get_name(self) -> str:
        """Return the command name."""
        return "disasm"

    def get_help(self) -> str:
        """Return the command help text."""
        return "Disassemble a code window from a file"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add command-specific arguments."""
        parser.add_argument("path", help="Path to file")
        parser.add_argument(
            "--engine",
            choices=["auto", "iced", "capstone"],
            default="auto",
            help="Disassembler engine to use",
        )
        parser.add_argument(
            "--arch",
            choices=[
                "x86",
                "x86_64",
                "arm",
                "arm64",
                "mips",
                "mips64",
                "ppc",
                "ppc64",
                "riscv",
                "riscv64",
                "unknown",
            ],
            default=None,
            help="Target architecture",
        )
        parser.add_argument(
            "--window-bytes", type=int, default=256, help="Number of bytes to read"
        )
        parser.add_argument(
            "--max-instructions",
            type=int,
            default=32,
            help="Maximum instructions to disassemble",
        )
        parser.add_argument(
            "--max-time-ms", type=int, default=20, help="Maximum time in milliseconds"
        )
        parser.add_argument(
            "--addr",
            type=lambda x: int(x, 0),
            default=None,
            help="Starting virtual address (e.g., 0x1000)",
        )
        parser.add_argument(
            "--entry",
            dest="use_entry",
            action="store_true",
            help="Start at detected entrypoint if available (default)",
        )
        parser.add_argument(
            "--no-entry",
            dest="use_entry",
            action="store_false",
            help="Do not use entrypoint; start at VA 0 or --addr",
        )
        parser.set_defaults(use_entry=True)
        parser.add_argument(
            "--comments", action="store_true", help="Add comments for calls and strings"
        )

    def _get_architecture(self, path: Path, arch_str: Optional[str]) -> Architecture:
        """Determine the architecture for disassembly."""
        arch_map = {
            "x86": Architecture.X86,
            "x86_64": Architecture.X86_64,
            "arm": Architecture.ARM,
            "arm64": Architecture.ARM64,
            "mips": Architecture.MIPS,
            "mips64": Architecture.MIPS64,
            "ppc": Architecture.PPC,
            "ppc64": Architecture.PPC64,
            "riscv": Architecture.RISCV,
            "riscv64": Architecture.RISCV64,
            "unknown": Architecture.Unknown,
        }

        if arch_str and arch_str != "unknown":
            return arch_map.get(arch_str, Architecture.Unknown)

        # Auto-detect from triage
        try:
            art = g.triage.analyze_path(str(path), 10_485_760, 104_857_600, 1)
            if art.verdicts:
                arch = art.verdicts[0].arch
            else:
                arch = (
                    art.heuristic_arch[0][0] if art.heuristic_arch else g.Arch.Unknown
                )

            key = str(arch)
            mapping = {
                "x86": Architecture.X86,
                "x86_64": Architecture.X86_64,
                "arm": Architecture.ARM,
                "aarch64": Architecture.ARM64,
                "mips": Architecture.MIPS,
                "mips64": Architecture.MIPS64,
                "ppc": Architecture.PPC,
                "ppc64": Architecture.PPC64,
                "riscv": Architecture.RISCV,
                "riscv64": Architecture.RISCV64,
                "unknown": Architecture.Unknown,
            }
            return mapping.get(key, Architecture.Unknown)
        except Exception:
            return Architecture.Unknown

    def execute(self, args: argparse.Namespace, formatter: DisasmFormatter) -> int:
        """Execute the disassembly command."""
        # Validate file path
        try:
            path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        # Determine architecture
        arch = self._get_architecture(path, args.arch)

        # Determine starting address
        start_va = args.addr
        if start_va is None and args.use_entry:
            try:
                ent = g.analysis.detect_entry_path(str(path), 10_485_760, 104_857_600)
                if ent is not None:
                    _fmt, _archs, _end, entry_va, _fo = ent
                    start_va = int(entry_va)
            except Exception:
                start_va = None

        # Use disassemble_window_at for proper VA mapping
        if start_va is not None:
            try:
                instructions = disassemble_window_at(
                    str(path),
                    int(start_va),
                    window_bytes=args.window_bytes,
                    max_instructions=args.max_instructions,
                    max_time_ms=args.max_time_ms,
                )
            except Exception:
                # Fallback to simple disassembly from file start
                start_va = 0
                instructions = self._fallback_disasm(
                    path,
                    arch,
                    args.engine,
                    args.window_bytes,
                    args.max_instructions,
                    args.max_time_ms,
                )
        else:
            start_va = 0
            instructions = self._fallback_disasm(
                path,
                arch,
                args.engine,
                args.window_bytes,
                args.max_instructions,
                args.max_time_ms,
            )

        # Build output data
        data = {
            "engine": args.engine if args.engine != "auto" else "iced-x86",
            "arch": str(arch),
            "instructions": [],
            "metadata": {
                "start_address": start_va,
                "window_bytes": args.window_bytes,
                "max_instructions": args.max_instructions,
            },
        }

        # Convert instructions to dict format
        for inst in instructions:
            inst_dict = {
                "address": inst.address.value if hasattr(inst, "address") else 0,
                "bytes": inst.bytes.hex()
                if isinstance(inst.bytes, (bytes, bytearray))
                else bytes(inst.bytes).hex(),
                "mnemonic": inst.mnemonic,
                "operands": [str(op) for op in inst.operands],
                "length": inst.length,
            }

            # Add comments if requested
            if args.comments:
                comment = self._get_instruction_comment(inst, path)
                if comment:
                    inst_dict["comment"] = comment

            data["instructions"].append(inst_dict)

        # Check if output was truncated
        file_size = path.stat().st_size
        if file_size > args.window_bytes:
            data["metadata"]["truncated"] = True
            data["metadata"]["truncated_bytes"] = True
        if len(instructions) >= args.max_instructions:
            data["metadata"]["truncated"] = True
            data["metadata"]["truncated_instructions"] = True

        # Format and output results
        formatter.format_output(data)

        return 0

    def _fallback_disasm(
        self,
        path: Path,
        arch: Architecture,
        engine: str,
        window_bytes: int,
        max_instructions: int,
        max_time_ms: int,
    ):
        """Fallback disassembly from file start."""
        data = path.read_bytes()[:window_bytes]

        options = None
        if engine in ("iced", "capstone"):
            options = {"engine": engine}

        cfg = DisassemblerConfig(arch, Endianness.Little, options)
        try:
            d = PyDisassembler(cfg)
        except Exception:
            return []

        addr = Address(AddressKind.VA, 0, arch.address_bits())
        return d.disassemble_bytes(
            addr, data, max_instructions=max_instructions, max_time_ms=max_time_ms
        )

    def _get_instruction_comment(self, inst, path: Path) -> Optional[str]:
        """Generate comment for instruction (calls, strings, etc.)."""
        # This would analyze the instruction for interesting patterns
        # For now, return None
        return None
