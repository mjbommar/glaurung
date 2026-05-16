from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


class JavaHelperError(RuntimeError):
    """Raised when the JVM helper cannot be built or executed."""


def ensure_helper_jar(
    helper_jar: str | None = None,
    *,
    build: bool = True,
    timeout_seconds: int = 120,
) -> Path:
    """Return the JVM helper fat JAR, building it with Maven if needed."""
    explicit = helper_jar or os.environ.get("GLAURUNG_JVM_TOOLS_JAR")
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return path
        raise JavaHelperError(f"JVM helper jar does not exist: {path}")

    project_root = _repo_root()
    helper_root = project_root / "java" / "glaurung-jvm-tools"
    jar = helper_root / "target" / "glaurung-jvm-tools-0.1.0-all.jar"
    if jar.is_file():
        return jar
    if not build:
        raise JavaHelperError(f"JVM helper jar is not built: {jar}")
    mvn = shutil.which("mvn")
    if mvn is None:
        raise JavaHelperError("mvn is required to build java/glaurung-jvm-tools")
    proc = subprocess.run(
        [mvn, "-q", "-DskipTests", "package"],
        cwd=helper_root,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    if proc.returncode != 0 or not jar.is_file():
        raise JavaHelperError(
            "failed to build JVM helper: "
            + _excerpt("\n".join([proc.stderr, proc.stdout]), 4000)
        )
    return jar


def run_jvm_tool(
    args: list[str],
    *,
    helper_jar: str | None = None,
    timeout_seconds: int = 60,
    build: bool = True,
) -> dict[str, Any]:
    """Run the JVM helper and return its JSON object."""
    jar = ensure_helper_jar(
        helper_jar,
        build=build,
        timeout_seconds=max(timeout_seconds, 30),
    )
    java = shutil.which("java")
    if java is None:
        raise JavaHelperError("java is required to run the JVM helper")
    try:
        proc = subprocess.run(
            [java, "-jar", str(jar), *args],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "success": False,
            "command": args[0] if args else None,
            "helper_jar": str(jar),
            "exit_code": None,
            "timed_out": True,
            "stdout_excerpt": _excerpt(_to_text(exc.stdout), 4000),
            "stderr_excerpt": _excerpt(_to_text(exc.stderr), 4000),
            "stop_reasons": ["helper_timeout"],
        }
    result = _parse_json_stdout(proc.stdout)
    if result is None:
        return {
            "success": False,
            "command": args[0] if args else None,
            "helper_jar": str(jar),
            "exit_code": proc.returncode,
            "timed_out": False,
            "stdout_excerpt": _excerpt(proc.stdout, 4000),
            "stderr_excerpt": _excerpt(proc.stderr, 4000),
            "stop_reasons": ["helper_json_parse_failed"],
        }
    result["helper_jar"] = str(jar)
    result["exit_code"] = proc.returncode
    result["timed_out"] = False
    if proc.stderr:
        result["stderr_excerpt"] = _excerpt(proc.stderr, 4000)
    return result


def _parse_json_stdout(stdout: str) -> dict[str, Any] | None:
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        return value if isinstance(value, dict) else None
    return None


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _excerpt(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...[truncated]"


def _to_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
