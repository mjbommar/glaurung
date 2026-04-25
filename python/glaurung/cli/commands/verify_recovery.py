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
        parser.add_argument(
            "--run", action="store_true",
            help="Compile + run the source. Capture stdout/stderr/exit (#171).",
        )
        parser.add_argument(
            "--compare-runtime", action="store_true",
            help="Run both the recovered source AND the --target binary "
                 "with the same args/stdin; report whether outputs match.",
        )
        parser.add_argument(
            "--arg", dest="run_args", action="append", default=[],
            help="argv to pass to the executable (repeatable). e.g. --arg foo --arg bar",
        )
        parser.add_argument(
            "--stdin", default=None,
            help="String to feed on stdin to the executable.",
        )
        parser.add_argument(
            "--timeout", type=float, default=5.0,
            help="Per-execution timeout in seconds (default: 5.0)",
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
            build_and_run,
            byte_similarity_against_target,
            compare_runtime_to_target,
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

        if args.run:
            run_result = build_and_run(
                source, args=args.run_args, stdin=args.stdin,
                compiler=args.compiler, language=args.language,
                timeout_seconds=args.timeout,
            )
            payload["run"] = asdict(run_result)

        if args.compare_runtime:
            if not args.target:
                formatter.output_plain("Error: --compare-runtime requires --target")
                return 2
            cmp_result = compare_runtime_to_target(
                source, str(args.target),
                args=args.run_args, stdin=args.stdin,
                compiler=args.compiler, language=args.language,
                timeout_seconds=args.timeout,
            )
            payload["compare_runtime"] = asdict(cmp_result)

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
        run = payload.get("run")
        if run:
            lines.append(
                f"run: exit={run['exit_code']} runtime={run['runtime_ms']:.1f}ms "
                f"stdout={len(run['stdout'])}b stderr={len(run['stderr'])}b"
            )
            for n in run.get("notes", []):
                lines.append(f"  note: {n}")
        cmp_run = payload.get("compare_runtime")
        if cmp_run:
            agree = (
                cmp_run["same_exit_code"]
                and cmp_run["same_stdout"]
                and cmp_run["same_stderr"]
            )
            lines.append(
                f"runtime-vs-target: "
                f"exit {'✅' if cmp_run['same_exit_code'] else '❌'}  "
                f"stdout {'✅' if cmp_run['same_stdout'] else '❌'}  "
                f"stderr {'✅' if cmp_run['same_stderr'] else '❌'}"
            )
            if not agree:
                tgt = cmp_run["target_run"]
                rec = cmp_run["recovered_run"]
                lines.append(
                    f"  target:    exit={tgt['exit_code']} stdout={tgt['stdout']!r}"
                )
                lines.append(
                    f"  recovered: exit={rec['exit_code']} stdout={rec['stdout']!r}"
                )
        formatter.output_plain("\n".join(lines))
        return 0 if result.ok else 1
