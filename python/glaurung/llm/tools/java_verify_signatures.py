from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


SignatureVerificationState = Literal[
    "not_zip",
    "unsigned",
    "tool_missing",
    "timeout",
    "verified",
    "verified_with_warnings",
    "invalid",
    "error",
]


class JavaVerifySignaturesArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    timeout_seconds: int = Field(30, ge=1, le=300)
    max_output_chars: int = Field(12_000, ge=1_000, le=100_000)


class JavaSignatureEntrySummary(BaseModel):
    entry_name: str
    size: int


class JavaVerifySignaturesResult(BaseModel):
    archive_path: str
    sha256: str
    state: SignatureVerificationState
    jarsigner_available: bool
    verification_attempted: bool
    signed_metadata_present: bool
    signature_entries: list[JavaSignatureEntrySummary] = Field(default_factory=list)
    signed_entry_count: int = 0
    unsigned_entry_count: int = 0
    warning_count: int = 0
    warnings: list[str] = Field(default_factory=list)
    error_count: int = 0
    errors: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    output_truncated: bool = False
    output_excerpt: str = ""


class JavaVerifySignaturesTool(
    MemoryTool[JavaVerifySignaturesArgs, JavaVerifySignaturesResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_verify_signatures",
                description=(
                    "Verify JAR signature metadata with jarsigner without executing "
                    "archive code. Reports signed/unsigned/invalid state, warnings, "
                    "and bounded output excerpts."
                ),
                tags=("java", "jar", "signature", "security", "kb"),
            ),
            JavaVerifySignaturesArgs,
            JavaVerifySignaturesResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaVerifySignaturesArgs,
    ) -> JavaVerifySignaturesResult:
        path = Path(args.path or ctx.file_path)
        digest = _sha256(path)
        if not zipfile.is_zipfile(path):
            result = JavaVerifySignaturesResult(
                archive_path=str(path),
                sha256=digest,
                state="not_zip",
                jarsigner_available=shutil.which("jarsigner") is not None,
                verification_attempted=False,
                signed_metadata_present=False,
            )
            _add_signature_node(kb, result)
            return result

        signature_entries = _signature_entries(path)
        signed_metadata_present = bool(signature_entries)
        jarsigner = shutil.which("jarsigner")
        if jarsigner is None:
            result = JavaVerifySignaturesResult(
                archive_path=str(path),
                sha256=digest,
                state="tool_missing",
                jarsigner_available=False,
                verification_attempted=False,
                signed_metadata_present=signed_metadata_present,
                signature_entries=signature_entries,
                warnings=["jarsigner not found on PATH"],
                warning_count=1,
            )
            _add_signature_node(kb, result)
            return result

        try:
            proc = subprocess.run(
                [
                    jarsigner,
                    "-verify",
                    "-certs",
                    "-verbose",
                    str(path),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=args.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            output = _join_output(exc.stdout, exc.stderr)
            result = JavaVerifySignaturesResult(
                archive_path=str(path),
                sha256=digest,
                state="timeout",
                jarsigner_available=True,
                verification_attempted=True,
                signed_metadata_present=signed_metadata_present,
                signature_entries=signature_entries,
                warnings=[f"jarsigner timed out after {args.timeout_seconds}s"],
                warning_count=1,
                output_excerpt=_truncate(output, args.max_output_chars)[0],
                output_truncated=_truncate(output, args.max_output_chars)[1],
            )
            _add_signature_node(kb, result)
            return result

        output = _join_output(proc.stdout, proc.stderr)
        excerpt, truncated = _truncate(output, args.max_output_chars)
        warnings = _extract_messages(output, "Warning:")
        errors = _extract_messages(output, "Error:")
        signed_entry_count, unsigned_entry_count = _entry_counts(output)
        state = _verification_state(
            output=output,
            exit_code=proc.returncode,
            signed_metadata_present=signed_metadata_present,
            warnings=warnings,
            errors=errors,
        )
        result = JavaVerifySignaturesResult(
            archive_path=str(path),
            sha256=digest,
            state=state,
            jarsigner_available=True,
            verification_attempted=True,
            signed_metadata_present=signed_metadata_present,
            signature_entries=signature_entries,
            signed_entry_count=signed_entry_count,
            unsigned_entry_count=unsigned_entry_count,
            warning_count=len(warnings),
            warnings=warnings,
            error_count=len(errors),
            errors=errors,
            exit_code=proc.returncode,
            output_truncated=truncated,
            output_excerpt=excerpt,
        )
        _add_signature_node(kb, result)
        return result


_SIGNATURE_ENTRY_RE = re.compile(
    r"^META-INF/[^/]+\.(?:SF|RSA|DSA|EC)$",
    re.IGNORECASE,
)
_ENTRY_LINE_RE = re.compile(r"^\s*([?a-zA-Z\s]+)\s+\d+\s+.+?\s+(.+)$")


def _signature_entries(path: Path) -> list[JavaSignatureEntrySummary]:
    out: list[JavaSignatureEntrySummary] = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            normalized = info.filename.replace("\\", "/")
            if _SIGNATURE_ENTRY_RE.fullmatch(normalized):
                out.append(
                    JavaSignatureEntrySummary(
                        entry_name=info.filename,
                        size=info.file_size,
                    )
                )
    return out


def _verification_state(
    *,
    output: str,
    exit_code: int,
    signed_metadata_present: bool,
    warnings: list[str],
    errors: list[str],
) -> SignatureVerificationState:
    lowered = output.lower()
    if "jar is unsigned" in lowered or (
        not signed_metadata_present and "jar verified" not in lowered
    ):
        return "unsigned"
    if exit_code == 0 and "jar verified" in lowered:
        return "verified_with_warnings" if warnings else "verified"
    if errors or "jar verified" not in lowered:
        return "invalid"
    return "error"


def _extract_messages(output: str, prefix: str) -> list[str]:
    messages: list[str] = []
    lines = output.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith(prefix):
            continue
        message = stripped.removeprefix(prefix).strip()
        next_index = index + 1
        while next_index < len(lines):
            continuation = lines[next_index].strip()
            if not continuation:
                break
            if continuation.startswith(("Warning:", "Error:")):
                break
            message = f"{message} {continuation}".strip()
            next_index += 1
        messages.append(message[:500])
    return messages


def _entry_counts(output: str) -> tuple[int, int]:
    signed = 0
    unsigned = 0
    for line in output.splitlines():
        match = _ENTRY_LINE_RE.match(line)
        if match is None:
            continue
        flags = match.group(1)
        entry_name = match.group(2).strip()
        if not entry_name or entry_name.startswith("["):
            continue
        compact_flags = flags.replace(" ", "")
        if "s" in compact_flags:
            signed += 1
        if "?" in compact_flags:
            unsigned += 1
    return signed, unsigned


def _join_output(stdout: str | bytes | None, stderr: str | bytes | None) -> str:
    def normalize(value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value

    return "\n".join(part for part in (normalize(stdout), normalize(stderr)) if part)


def _truncate(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) <= max_chars:
        return text, False
    return text[:max_chars], True


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
    except FileNotFoundError:
        return ""
    return h.hexdigest()


def _add_signature_node(kb: KnowledgeBase, result: JavaVerifySignaturesResult) -> None:
    kb.add_node(
        Node(
            kind=NodeKind.evidence,
            label=f"JAR signature verification: {Path(result.archive_path).name}",
            text=f"JAR signature verification state: {result.state}",
            props={
                "tool": "java_verify_signatures",
                **result.model_dump(exclude={"output_excerpt"}),
            },
            tags=["java", "jar", "signature", result.state],
        )
    )


def build_tool() -> MemoryTool[JavaVerifySignaturesArgs, JavaVerifySignaturesResult]:
    return JavaVerifySignaturesTool()
