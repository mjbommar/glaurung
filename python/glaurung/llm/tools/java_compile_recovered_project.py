from __future__ import annotations

import hashlib
import re
import shlex
import shutil
import subprocess
import time
import zipfile
from collections.abc import Iterable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


JavaCompileTool = Literal["auto", "javac", "maven", "gradle"]
SelectedJavaCompileTool = Literal["unknown", "javac", "maven", "gradle"]
DiagnosticCategory = Literal[
    "missing_classpath_dependency",
    "bad_decompiler_syntax",
    "missing_import",
    "generic_signature_mismatch",
    "enum_record_sealed_reconstruction",
    "lambda_or_anonymous_reconstruction",
    "access_visibility_mismatch",
    "duplicate_class_or_package_conflict",
    "annotation_processor_or_module_path",
    "unknown",
]


class JavaCompileRecoveredProjectArgs(BaseModel):
    source_project_root: str | None = Field(
        None,
        description=(
            "Recovered Java project root. Defaults to the memory context file path "
            "so agent smoke/tool-probing calls can fail structurally instead of "
            "at schema validation time."
        ),
    )
    build_tool: JavaCompileTool = "auto"
    java_home: str | None = None
    java_release: int | None = Field(None, ge=1)
    javac_args_file: str = "javac.args"
    sources_file: str = "sources.txt"
    classpath: list[str] = Field(default_factory=list)
    update_sources_file: bool = True
    max_diagnostics: int = Field(64, ge=0)
    max_output_chars: int = Field(20_000, ge=0)
    timeout_seconds: int = Field(30, ge=1, le=600)
    allow_dependency_network: bool = False


class JavaCompilerDiagnostic(BaseModel):
    file: str | None = None
    line: int | None = None
    column: int | None = None
    severity: str = "error"
    category: DiagnosticCategory = "unknown"
    message: str
    symbol: str | None = None
    package_or_class: str | None = None
    raw_excerpt: str


class JavaCompileRecoveredProjectResult(BaseModel):
    source_project_root: str
    selected_build_tool: SelectedJavaCompileTool
    success: bool
    timed_out: bool = False
    exit_code: int | None = None
    duration_ms: int = 0
    command: list[str] = Field(default_factory=list)
    generated_classes_dir: str | None = None
    rebuilt_jar_path: str | None = None
    diagnostic_count: int = 0
    diagnostics: list[JavaCompilerDiagnostic] = Field(default_factory=list)
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    stop_reasons: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class JavaCompileRecoveredProjectTool(
    MemoryTool[JavaCompileRecoveredProjectArgs, JavaCompileRecoveredProjectResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_compile_recovered_project",
                description=(
                    "Compile a recovered Java source project with bounded javac, "
                    "Maven, or Gradle execution and structured diagnostics."
                ),
                tags=("java", "compile", "source-recovery", "diagnostics", "kb"),
            ),
            JavaCompileRecoveredProjectArgs,
            JavaCompileRecoveredProjectResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaCompileRecoveredProjectArgs,
    ) -> JavaCompileRecoveredProjectResult:
        root = Path(args.source_project_root or ctx.file_path)
        if not root.is_dir():
            return JavaCompileRecoveredProjectResult(
                source_project_root=str(root),
                selected_build_tool="unknown",
                success=False,
                stop_reasons=["source_project_root_missing"],
            )

        selected = _select_build_tool(root, args.build_tool)
        if selected == "javac":
            result = _run_javac(root, args)
        elif selected == "maven":
            result = _run_maven(root, args)
        elif selected == "gradle":
            result = _run_gradle(root, args)
        else:
            result = JavaCompileRecoveredProjectResult(
                source_project_root=str(root),
                selected_build_tool=selected,
                success=False,
                stop_reasons=["unsupported_build_tool"],
            )
        _add_compile_node(kb, result)
        return result


def _select_build_tool(
    root: Path, requested: JavaCompileTool
) -> SelectedJavaCompileTool:
    if requested != "auto":
        return requested
    if (root / "javac.args").is_file():
        return "javac"
    if (root / "pom.xml").is_file():
        return "maven"
    if (root / "build.gradle").is_file() or (root / "build.gradle.kts").is_file():
        return "gradle"
    return "javac"


def _run_javac(
    root: Path,
    args: JavaCompileRecoveredProjectArgs,
) -> JavaCompileRecoveredProjectResult:
    javac = _javac_path(args.java_home)
    if javac is None:
        return JavaCompileRecoveredProjectResult(
            source_project_root=str(root),
            selected_build_tool="javac",
            success=False,
            stop_reasons=["javac_missing"],
        )

    classes_dir = root / "build" / "classes"
    classes_dir.mkdir(parents=True, exist_ok=True)
    sources = _java_sources(root)
    warnings: list[str] = []
    if not sources:
        warnings.append("No Java source files were found under src/main/java.")
    sources_file = root / args.sources_file
    if args.update_sources_file and _sources_file_needs_update(sources_file):
        sources_file.write_text(
            "\n".join(_relative(root, source) for source in sources) + "\n",
            encoding="utf-8",
        )

    argfile = root / args.javac_args_file
    if argfile.is_file():
        command = [javac, *_expand_javac_argfile(root, argfile)]
    else:
        command = [
            javac,
            "--release",
            str(args.java_release or 17),
            "-d",
            _relative(root, classes_dir),
        ]
        if args.classpath:
            command.extend(["-classpath", ":".join(args.classpath)])
        command.extend(_relative(root, source) for source in sources)

    started = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=args.timeout_seconds,
            check=False,
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        combined = "\n".join(part for part in (proc.stderr, proc.stdout) if part)
        diagnostics = _parse_javac_diagnostics(combined, args.max_diagnostics)
        stop_reasons = []
        if len(diagnostics) >= args.max_diagnostics and args.max_diagnostics > 0:
            stop_reasons.append("max_diagnostics")
        rebuilt_jar = (
            _write_rebuilt_jar(root, classes_dir) if proc.returncode == 0 else None
        )
        result = JavaCompileRecoveredProjectResult(
            source_project_root=str(root),
            selected_build_tool="javac",
            success=proc.returncode == 0,
            timed_out=False,
            exit_code=proc.returncode,
            duration_ms=duration_ms,
            command=command,
            generated_classes_dir=str(classes_dir),
            rebuilt_jar_path=str(rebuilt_jar) if rebuilt_jar else None,
            diagnostic_count=len(diagnostics),
            diagnostics=diagnostics,
            stdout_excerpt=_excerpt(proc.stdout, args.max_output_chars),
            stderr_excerpt=_excerpt(proc.stderr, args.max_output_chars),
            stop_reasons=stop_reasons,
            warnings=warnings,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.monotonic() - started) * 1000)
        stdout = _coerce_output(exc.stdout)
        stderr = _coerce_output(exc.stderr)
        result = JavaCompileRecoveredProjectResult(
            source_project_root=str(root),
            selected_build_tool="javac",
            success=False,
            timed_out=True,
            exit_code=None,
            duration_ms=duration_ms,
            command=command,
            generated_classes_dir=str(classes_dir),
            diagnostic_count=0,
            diagnostics=[],
            stdout_excerpt=_excerpt(stdout, args.max_output_chars),
            stderr_excerpt=_excerpt(stderr, args.max_output_chars),
            stop_reasons=["timeout"],
            warnings=warnings,
        )
    return result


def _write_rebuilt_jar(root: Path, classes_dir: Path) -> Path | None:
    if not classes_dir.is_dir():
        return None
    jar_path = root / "build" / "libs" / "recovered.jar"
    jar_path.parent.mkdir(parents=True, exist_ok=True)
    resources_dir = root / "src" / "main" / "resources"
    with zipfile.ZipFile(jar_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(p for p in classes_dir.rglob("*") if p.is_file()):
            zf.write(path, path.relative_to(classes_dir).as_posix())
        if resources_dir.is_dir():
            for path in sorted(p for p in resources_dir.rglob("*") if p.is_file()):
                zf.write(path, path.relative_to(resources_dir).as_posix())
    return jar_path


def _run_maven(
    root: Path,
    args: JavaCompileRecoveredProjectArgs,
) -> JavaCompileRecoveredProjectResult:
    mvn = shutil.which("mvn")
    if mvn is None:
        return JavaCompileRecoveredProjectResult(
            source_project_root=str(root),
            selected_build_tool="maven",
            success=False,
            stop_reasons=["maven_missing"],
        )
    command = [mvn, "-q"]
    warnings: list[str] = []
    if not args.allow_dependency_network:
        command.append("-o")
        warnings.append(
            "Maven ran in offline mode because dependency network is disabled."
        )
    command.extend(["-DskipTests", "package"])
    return _run_build_process(
        root=root,
        args=args,
        selected_build_tool="maven",
        command=command,
        classes_dir=root / "target" / "classes",
        jar_glob="target/*.jar",
        warnings=warnings,
    )


def _run_gradle(
    root: Path,
    args: JavaCompileRecoveredProjectArgs,
) -> JavaCompileRecoveredProjectResult:
    gradle = _gradle_path(root)
    if gradle is None:
        return JavaCompileRecoveredProjectResult(
            source_project_root=str(root),
            selected_build_tool="gradle",
            success=False,
            stop_reasons=["gradle_missing"],
        )
    command = [gradle]
    warnings: list[str] = []
    if not args.allow_dependency_network:
        command.append("--offline")
        warnings.append(
            "Gradle ran in offline mode because dependency network is disabled."
        )
    command.extend(["-q", "build", "-x", "test"])
    return _run_build_process(
        root=root,
        args=args,
        selected_build_tool="gradle",
        command=command,
        classes_dir=root / "build" / "classes",
        jar_glob="build/libs/*.jar",
        warnings=warnings,
    )


def _run_build_process(
    *,
    root: Path,
    args: JavaCompileRecoveredProjectArgs,
    selected_build_tool: SelectedJavaCompileTool,
    command: list[str],
    classes_dir: Path,
    jar_glob: str,
    warnings: list[str],
) -> JavaCompileRecoveredProjectResult:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=args.timeout_seconds,
            check=False,
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        combined = "\n".join(part for part in (proc.stderr, proc.stdout) if part)
        diagnostics = _parse_javac_diagnostics(combined, args.max_diagnostics)
        stop_reasons = []
        if len(diagnostics) >= args.max_diagnostics and args.max_diagnostics > 0:
            stop_reasons.append("max_diagnostics")
        rebuilt_jar = _first_file(root.glob(jar_glob))
        return JavaCompileRecoveredProjectResult(
            source_project_root=str(root),
            selected_build_tool=selected_build_tool,
            success=proc.returncode == 0,
            timed_out=False,
            exit_code=proc.returncode,
            duration_ms=duration_ms,
            command=command,
            generated_classes_dir=str(classes_dir) if classes_dir.exists() else None,
            rebuilt_jar_path=str(rebuilt_jar) if rebuilt_jar else None,
            diagnostic_count=len(diagnostics),
            diagnostics=diagnostics,
            stdout_excerpt=_excerpt(proc.stdout, args.max_output_chars),
            stderr_excerpt=_excerpt(proc.stderr, args.max_output_chars),
            stop_reasons=stop_reasons,
            warnings=warnings,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.monotonic() - started) * 1000)
        return JavaCompileRecoveredProjectResult(
            source_project_root=str(root),
            selected_build_tool=selected_build_tool,
            success=False,
            timed_out=True,
            exit_code=None,
            duration_ms=duration_ms,
            command=command,
            generated_classes_dir=str(classes_dir) if classes_dir.exists() else None,
            diagnostic_count=0,
            diagnostics=[],
            stdout_excerpt=_excerpt(_coerce_output(exc.stdout), args.max_output_chars),
            stderr_excerpt=_excerpt(_coerce_output(exc.stderr), args.max_output_chars),
            stop_reasons=["timeout"],
            warnings=warnings,
        )


_JAVAC_DIAG_RE = re.compile(
    r"^(?P<file>.*?\.java):(?P<line>\d+):(?:(?P<column>\d+):)? "
    r"(?P<severity>error|warning): (?P<message>.*)$"
)


def _parse_javac_diagnostics(
    output: str,
    max_diagnostics: int,
) -> list[JavaCompilerDiagnostic]:
    if max_diagnostics == 0:
        return []
    lines = output.splitlines()
    diagnostics: list[JavaCompilerDiagnostic] = []
    i = 0
    while i < len(lines):
        match = _JAVAC_DIAG_RE.match(lines[i])
        if match is None:
            i += 1
            continue
        start = i
        i += 1
        while i < len(lines) and _JAVAC_DIAG_RE.match(lines[i]) is None:
            i += 1
        raw_lines = lines[start:i]
        message = match.group("message").strip()
        import_target = _import_target(raw_lines)
        if import_target and import_target not in message:
            message = f"{message} (from import {import_target})"
        symbol = _detail_value(raw_lines, "symbol")
        package_or_class = _package_or_class(message, symbol)
        diagnostics.append(
            JavaCompilerDiagnostic(
                file=match.group("file"),
                line=int(match.group("line")),
                column=int(match.group("column")) if match.group("column") else None,
                severity=match.group("severity"),
                category=_diagnostic_category(message, raw_lines),
                message=message,
                symbol=symbol,
                package_or_class=package_or_class,
                raw_excerpt="\n".join(raw_lines[:8]),
            )
        )
        if len(diagnostics) >= max_diagnostics:
            break
    return diagnostics


def _diagnostic_category(message: str, raw_lines: list[str]) -> DiagnosticCategory:
    lowered = message.lower()
    raw = "\n".join(raw_lines).lower()
    if "package " in lowered and " does not exist" in lowered:
        return "missing_classpath_dependency"
    if "cannot find symbol" in lowered:
        if "symbol:   class " in raw or "symbol:   variable " in raw:
            return "missing_classpath_dependency"
        return "missing_import"
    if (
        "expected" in lowered
        or "illegal start" in lowered
        or "not a statement" in lowered
    ):
        return "bad_decompiler_syntax"
    if "duplicate class" in lowered or "should be declared in a file named" in lowered:
        return "duplicate_class_or_package_conflict"
    if "is not public" in lowered or "has private access" in lowered:
        return "access_visibility_mismatch"
    if "incompatible types" in lowered or "cannot be applied" in lowered:
        return "generic_signature_mismatch"
    if "enum" in lowered or "record" in lowered or "sealed" in lowered:
        return "enum_record_sealed_reconstruction"
    if "lambda" in lowered or "anonymous" in lowered:
        return "lambda_or_anonymous_reconstruction"
    if "module" in lowered or "processor" in lowered:
        return "annotation_processor_or_module_path"
    return "unknown"


def _detail_value(raw_lines: list[str], key: str) -> str | None:
    prefix = f"{key}:"
    for line in raw_lines:
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped.removeprefix(prefix).strip()
    return None


def _import_target(raw_lines: list[str]) -> str | None:
    for line in raw_lines:
        stripped = line.strip()
        match = re.match(r"import\s+([A-Za-z0-9_.*]+);", stripped)
        if match is not None:
            return match.group(1)
    return None


def _package_or_class(message: str, symbol: str | None) -> str | None:
    package_match = re.search(r"package\s+([A-Za-z0-9_.]+)\s+does not exist", message)
    if package_match is not None:
        return package_match.group(1)
    if symbol:
        parts = symbol.split()
        if parts:
            return parts[-1]
    return None


def _javac_path(java_home: str | None) -> str | None:
    if java_home:
        candidate = Path(java_home) / "bin" / "javac"
        if candidate.is_file():
            return str(candidate)
    return shutil.which("javac")


def _gradle_path(root: Path) -> str | None:
    wrapper = root / "gradlew"
    if wrapper.is_file():
        return str(wrapper)
    return shutil.which("gradle")


def _first_file(paths: Iterable[Path]) -> Path | None:
    for path in sorted(paths):
        if path.is_file():
            return path
    return None


def _expand_javac_argfile(root: Path, argfile: Path, depth: int = 0) -> list[str]:
    if depth > 4:
        return [f"@{_relative(root, argfile)}"]
    tokens = shlex.split(argfile.read_text(encoding="utf-8", errors="replace"))
    expanded: list[str] = []
    for token in tokens:
        if token.startswith("@") and len(token) > 1:
            nested = root / token[1:]
            if nested.is_file():
                expanded.extend(_expand_javac_argfile(root, nested, depth + 1))
                continue
        expanded.append(token)
    return expanded


def _java_sources(root: Path) -> list[Path]:
    source_root = root / "src" / "main" / "java"
    if not source_root.is_dir():
        return []
    return sorted(path for path in source_root.rglob("*.java") if path.is_file())


def _sources_file_needs_update(path: Path) -> bool:
    if not path.exists():
        return True
    lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
    ]
    return not any(line and not line.startswith("#") for line in lines)


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _excerpt(text: str, max_chars: int) -> str:
    if max_chars == 0:
        return ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...[truncated]"


def _coerce_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _add_compile_node(
    kb: KnowledgeBase,
    result: JavaCompileRecoveredProjectResult,
) -> None:
    digest = hashlib.sha256(
        "|".join(
            [
                result.source_project_root,
                result.selected_build_tool,
                str(result.exit_code),
                str(result.diagnostic_count),
            ]
        ).encode("utf-8")
    ).hexdigest()[:16]
    kb.add_node(
        Node(
            kind=NodeKind.java_compile_result,
            label=f"{result.selected_build_tool}: {'pass' if result.success else 'fail'}",
            text=(
                f"Compile {'succeeded' if result.success else 'failed'} with "
                f"{result.diagnostic_count} diagnostic(s)."
            ),
            props={
                "tool": "java_compile_recovered_project",
                "compile_result_id": digest,
                **result.model_dump(),
            },
            tags=["java", "compile", result.selected_build_tool],
        )
    )


def build_tool() -> MemoryTool[
    JavaCompileRecoveredProjectArgs, JavaCompileRecoveredProjectResult
]:
    return JavaCompileRecoveredProjectTool()
