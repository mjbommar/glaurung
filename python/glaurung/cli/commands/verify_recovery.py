"""Verify recovered C/C++ source against a binary (#202 v0)."""

import argparse
import sys
from dataclasses import asdict
from pathlib import Path

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class VerifyRecoveryCommand(BaseCommand):
    """Compile-check (and optionally diff) recovered source."""

    def get_name(self) -> str:
        return "verify-recovery"

    def get_help(self) -> str:
        return "Compile-check rewritten source; optionally diff bytes against a target binary"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("source_file", help="Recovered C/C++ source file (or - for stdin)")
        parser.add_argument(
            "--language", default="c", choices=("c", "cpp"),
            help="Source language (default: c)",
        )
        parser.add_argument(
            "--compiler", default=None,
            help="Compiler to use (default: gcc → clang → cc)",
        )
        parser.add_argument(
            "--target", type=Path, default=None,
            help="Optional target binary; when set, also runs byte-similarity",
        )
        parser.add_argument(
            "--function", default=None,
            help="Function name to compare against in the target",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        if args.source_file == "-":
            source = sys.stdin.read()
        else:
            try:
                self.validate_file_path(args.source_file)
            except (FileNotFoundError, ValueError) as e:
                formatter.output_plain(f"Error: {e}")
                return 2
            source = Path(args.source_file).read_text()

        from glaurung.llm.kb.verify_recovery import (
            byte_similarity_against_target,
            compile_check,
        )

        result = compile_check(
            source, compiler=args.compiler, language=args.language,
        )
        payload: dict = {"compile": asdict(result)}

        if args.target and args.function:
            sim = byte_similarity_against_target(
                source, str(args.target), args.function,
                compiler=args.compiler, language=args.language,
            )
            payload["similarity"] = asdict(sim)

        if formatter.format_type == OutputFormat.JSON:
            formatter.output_json(payload)
            return 0 if result.ok else 1

        # Plain output.
        lines = []
        if result.ok:
            lines.append(f"compile: ✅ ({result.compiler})")
        else:
            lines.append(f"compile: ❌ ({result.compiler}, exit {result.exit_code})")
            for ln in (result.stderr or "").splitlines()[:8]:
                lines.append(f"  {ln}")
        sim = payload.get("similarity")
        if sim:
            lines.append(
                f"byte-similarity for `{sim['function_name']}`: "
                f"{sim['score']:.1%} "
                f"(target {sim['target_size']}b / recovered {sim['recovered_size']}b)"
            )
            for n in sim.get("notes", []):
                lines.append(f"  note: {n}")
        formatter.output_plain("\n".join(lines))
        return 0 if result.ok else 1
