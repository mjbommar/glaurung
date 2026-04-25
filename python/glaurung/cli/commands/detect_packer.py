"""Packer detection command (#187)."""

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class DetectPackerCommand(BaseCommand):
    """Quick `is-this-packed?` check for a binary."""

    def get_name(self) -> str:
        return "detect-packer"

    def get_help(self) -> str:
        return "Detect whether a binary is packed (UPX, Themida, VMProtect, ...)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", help="Path to binary")

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        try:
            path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        from glaurung.llm.kb.packer_detect import detect_packer

        verdict = detect_packer(str(path))

        if formatter.format_type == OutputFormat.JSON:
            formatter.output_json(asdict(verdict))
            return 0
        if formatter.format_type == OutputFormat.JSONL:
            formatter.output_jsonl(asdict(verdict))
            return 0

        # Plain / rich.
        lines = []
        if verdict.is_packed:
            label = verdict.packer_name or f"{verdict.family or 'unknown'} (generic)"
            lines.append(
                f"PACKED: {label}  (confidence {verdict.confidence:.0%})"
            )
            for ind in verdict.indicators:
                lines.append(f"  indicator: {ind}")
        else:
            lines.append("not packed")
        lines.append(f"  overall entropy: {verdict.overall_entropy:.3f} bits/byte")
        for n in verdict.notes:
            lines.append(f"  note: {n}")
        formatter.output_plain("\n".join(lines))
        return 0 if not verdict.is_packed else 1
