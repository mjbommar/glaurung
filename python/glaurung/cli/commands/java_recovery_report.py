"""Daily-use Java recovery report CLI command."""

import argparse
import os
import re
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.tools.java_recovery_report import build_tool

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class JavaRecoveryReportCommand(BaseCommand):
    """Run Java project recovery and print a concise report."""

    def get_name(self) -> str:
        return "java-recovery-report"

    def get_help(self) -> str:
        return "Recover a Java archive and print a ranked daily-use report"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", help="JAR/ZIP archive to recover")
        parser.add_argument(
            "--output-root",
            help=(
                "Recovered project root. Defaults to "
                "tmp/glaurung-java-recovery/<archive-stem>."
            ),
        )
        parser.add_argument(
            "--include-package",
            action="append",
            default=[],
            help="Package prefix to include; may be supplied multiple times.",
        )
        parser.add_argument(
            "--include-class-glob",
            action="append",
            default=[],
            help="Class glob to include; may be supplied multiple times.",
        )
        parser.add_argument(
            "--classpath",
            action="append",
            default=[],
            help="Compile classpath entry or os.pathsep-separated entries.",
        )
        parser.add_argument(
            "--mapping-path",
            help="Optional ProGuard/Mojang/Tiny mapping file.",
        )
        parser.add_argument(
            "--decompiler-engine",
            choices=["auto", "cfr", "vineflower"],
            default="auto",
            help="Decompiler engine selection.",
        )
        parser.add_argument(
            "--resource-policy",
            choices=["none", "copy_runtime", "copy_all"],
            default="copy_runtime",
            help="Resource copy policy for the recovered project.",
        )
        parser.add_argument(
            "--inner-class-policy",
            choices=["skip", "companion", "merge"],
            default="merge",
            help="How to emit inner class source.",
        )
        parser.add_argument("--max-classes", type=int, default=64)
        parser.add_argument("--max-resources", type=int, default=2_000)
        parser.add_argument("--java-release", type=int, default=17)
        parser.add_argument(
            "--validate-profile",
            choices=["compile_only", "abi", "resources", "full_static"],
            default="full_static",
        )
        parser.add_argument("--max-blockers", type=int, default=8)
        parser.add_argument("--max-class-summaries", type=int, default=12)
        parser.add_argument("--max-repair-summaries", type=int, default=12)
        parser.add_argument("--helper-jar", help="Optional glaurung JVM helper JAR")
        parser.add_argument(
            "--force-redecompile",
            action="store_true",
            help="Ignore cached decompile/recovery state.",
        )
        parser.add_argument(
            "--extract-nested-archives",
            action="store_true",
            help="Extract nested JARs and feed them into the compile classpath.",
        )
        parser.add_argument(
            "--rewrite-mapped-sources",
            action="store_true",
            help="Rewrite source names with the supplied mapping file.",
        )
        parser.add_argument(
            "--allow-dependency-network",
            action="store_true",
            help="Allow Maven/Gradle/dependency repair to use online resolution.",
        )
        parser.add_argument(
            "--no-local-maven-cache",
            action="store_false",
            dest="include_local_maven_cache",
            help="Disable bounded local ~/.m2 repository scans for missing classes.",
        )
        parser.add_argument(
            "--local-maven-repository",
            help="Local Maven repository to scan for missing classpath entries.",
        )
        parser.add_argument(
            "--max-local-maven-cache-jars",
            type=int,
            default=2_048,
            help="Maximum local Maven cache JARs to inspect during repair.",
        )
        parser.add_argument(
            "--no-resume",
            action="store_false",
            dest="resume",
            help="Disable recovery cache/resume.",
        )
        parser.add_argument(
            "--no-repair",
            action="store_false",
            dest="run_repair",
            help="Skip compile-driven repair attempts.",
        )
        parser.add_argument(
            "--no-validate",
            action="store_false",
            dest="run_validate",
            help="Skip validation after compile/repair.",
        )
        parser.add_argument(
            "--no-compile-candidates",
            action="store_false",
            dest="compile_candidates",
            help="Skip compile scoring for decompiler candidates.",
        )
        parser.add_argument(
            "--no-report-files",
            action="store_false",
            dest="write_report_files",
            help="Do not write .glaurung/recovery-report files.",
        )
        parser.set_defaults(
            resume=True,
            run_repair=True,
            run_validate=True,
            compile_candidates=True,
            write_report_files=True,
            include_local_maven_cache=True,
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        path = self.validate_file_path(args.path)
        output_root = (
            Path(args.output_root) if args.output_root else _default_output_root(path)
        )
        artifact = g.triage.analyze_path(str(path), 700_000_000, 200_000_000, 1)
        ctx = MemoryContext(file_path=str(path), artifact=artifact)
        import_triage(ctx.kb, artifact, str(path))
        tool = build_tool()
        result = tool.run(
            ctx,
            ctx.kb,
            tool.input_model(
                path=str(path),
                output_root=str(output_root),
                resource_policy=args.resource_policy,
                decompiler_engine=args.decompiler_engine,
                helper_jar=args.helper_jar,
                mapping_path=args.mapping_path,
                rewrite_mapped_sources=args.rewrite_mapped_sources,
                include_packages=args.include_package,
                include_class_globs=args.include_class_glob,
                inner_class_policy=args.inner_class_policy,
                max_classes=args.max_classes,
                max_resources=args.max_resources,
                java_release=args.java_release,
                compile_candidates=args.compile_candidates,
                classpath=_split_path_values(args.classpath),
                extract_nested_archives=args.extract_nested_archives,
                allow_dependency_network=args.allow_dependency_network,
                include_local_maven_cache=args.include_local_maven_cache,
                local_maven_repository=args.local_maven_repository,
                max_local_maven_cache_jars=args.max_local_maven_cache_jars,
                resume=args.resume,
                force_redecompile=args.force_redecompile,
                run_repair=args.run_repair,
                run_validate=args.run_validate,
                validate_profile=args.validate_profile,
                max_blockers=args.max_blockers,
                max_class_summaries=args.max_class_summaries,
                max_repair_summaries=args.max_repair_summaries,
                write_report_files=args.write_report_files,
            ),
        )
        payload = result.model_dump(exclude={"recovery_result"})
        if formatter.format_type == OutputFormat.JSON:
            formatter.output_json(payload)
        elif formatter.format_type == OutputFormat.JSONL:
            formatter.output_jsonl(payload)
        elif formatter.format_type == OutputFormat.RICH:
            formatter.output_rich(formatter.create_markdown(result.markdown))
        else:
            formatter.output_plain(result.markdown)
        return 0


def _default_output_root(path: Path) -> Path:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", path.stem).strip("._")
    if not stem:
        stem = "archive"
    return Path("tmp") / "glaurung-java-recovery" / stem


def _split_path_values(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        for item in value.split(os.pathsep):
            if item:
                out.append(item)
    return out
