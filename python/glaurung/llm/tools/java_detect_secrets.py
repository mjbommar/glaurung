from __future__ import annotations

import hashlib
import math
import re
import zipfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


SecretSourceType = Literal["class_string", "resource_text"]


class JavaDetectSecretsArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    include_class_constants: bool = True
    include_resources: bool = True
    max_classes: int = Field(50_000, ge=0)
    max_resources: int = Field(2_000, ge=0)
    max_resource_bytes: int = Field(2_000_000, ge=0)
    max_candidates: int = Field(512, ge=0)
    min_high_entropy_length: int = Field(32, ge=8)
    min_high_entropy: float = Field(4.0, ge=0.0)


class JavaSecretCandidate(BaseModel):
    candidate_id: str
    category: str
    severity: str
    confidence: float
    source_type: SecretSourceType
    path: str
    class_name: str | None = None
    method_name: str | None = None
    method_descriptor: str | None = None
    bci: int | None = None
    line_number: int | None = None
    value: str | None = None
    redacted_value_hash: str
    value_length: int
    context: str


class JavaDetectSecretsResult(BaseModel):
    archive_path: str
    sha256: str
    class_count: int
    resource_count: int
    candidate_count: int
    candidates: list[JavaSecretCandidate]
    summary_by_category: dict[str, int]
    truncated: bool = False
    stop_reasons: list[str] = Field(default_factory=list)


class JavaDetectSecretsTool(MemoryTool[JavaDetectSecretsArgs, JavaDetectSecretsResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_detect_secrets",
                description=(
                    "Scan Java archive string constants and text resources for "
                    "likely secrets or tokens. Candidate values are redacted and "
                    "represented only by stable hashes and metadata."
                ),
                tags=("java", "jar", "secrets", "audit", "kb"),
            ),
            JavaDetectSecretsArgs,
            JavaDetectSecretsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaDetectSecretsArgs,
    ) -> JavaDetectSecretsResult:
        path = Path(args.path or ctx.file_path)
        digest = _sha256(path)
        if not zipfile.is_zipfile(path):
            return JavaDetectSecretsResult(
                archive_path=str(path),
                sha256=digest,
                class_count=0,
                resource_count=0,
                candidate_count=0,
                candidates=[],
                summary_by_category={},
                stop_reasons=["input_not_zip"],
            )

        candidates: list[JavaSecretCandidate] = []
        class_count = 0
        resource_count = 0
        truncated = False
        java_analysis = getattr(g, "analysis")

        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if info.filename.endswith(".class"):
                    class_count += 1
                    if not args.include_class_constants:
                        continue
                    if class_count > args.max_classes:
                        truncated = True
                        continue
                    parsed = java_analysis.parse_java_class_bytes(zf.read(info))
                    if parsed is None:
                        continue
                    candidates.extend(
                        _class_candidates(
                            entry_name=info.filename,
                            parsed=parsed,
                            args=args,
                            remaining=max(args.max_candidates - len(candidates), 0),
                        )
                    )
                elif args.include_resources and _looks_like_text_resource(
                    info.filename
                ):
                    resource_count += 1
                    if resource_count > args.max_resources:
                        truncated = True
                        continue
                    if info.file_size > args.max_resource_bytes:
                        truncated = True
                        continue
                    candidates.extend(
                        _resource_candidates(
                            entry_name=info.filename,
                            text=zf.read(info).decode("utf-8", errors="replace"),
                            args=args,
                            remaining=max(args.max_candidates - len(candidates), 0),
                        )
                    )
                if len(candidates) >= args.max_candidates:
                    truncated = True
                    break

        for candidate in candidates:
            _add_secret_node(kb, path, candidate)

        summary_by_category: dict[str, int] = {}
        for candidate in candidates:
            summary_by_category[candidate.category] = (
                summary_by_category.get(candidate.category, 0) + 1
            )

        return JavaDetectSecretsResult(
            archive_path=str(path),
            sha256=digest,
            class_count=class_count,
            resource_count=resource_count,
            candidate_count=len(candidates),
            candidates=candidates,
            summary_by_category=summary_by_category,
            truncated=truncated,
        )


def _class_candidates(
    *,
    entry_name: str,
    parsed: dict[str, Any],
    args: JavaDetectSecretsArgs,
    remaining: int,
) -> list[JavaSecretCandidate]:
    if remaining <= 0:
        return []
    out: list[JavaSecretCandidate] = []
    class_name = str(parsed["class_name"])
    for method in parsed["methods"]:
        code = method.get("code")
        if not isinstance(code, dict):
            continue
        line_numbers = _line_numbers(code)
        for xref in code.get("xrefs", []):
            if not isinstance(xref, dict) or xref.get("kind") != "string":
                continue
            value = xref.get("string_value")
            if not isinstance(value, str):
                continue
            for match in _secret_matches(value, args=args):
                out.append(
                    _candidate(
                        source_type="class_string",
                        path=entry_name,
                        raw_value=match.value,
                        category=match.category,
                        severity=match.severity,
                        confidence=match.confidence,
                        context=_context_without_secret(value, match.value),
                        class_name=class_name,
                        method_name=str(method["name"]),
                        method_descriptor=str(method["descriptor"]),
                        bci=int(xref["bci"])
                        if isinstance(xref.get("bci"), int)
                        else None,
                        line_number=_line_number_for_bci(
                            line_numbers,
                            int(xref["bci"])
                            if isinstance(xref.get("bci"), int)
                            else None,
                        ),
                    )
                )
                if len(out) >= remaining:
                    return out
    return out


def _resource_candidates(
    *,
    entry_name: str,
    text: str,
    args: JavaDetectSecretsArgs,
    remaining: int,
) -> list[JavaSecretCandidate]:
    out: list[JavaSecretCandidate] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for match in _secret_matches(line, args=args):
            out.append(
                _candidate(
                    source_type="resource_text",
                    path=entry_name,
                    raw_value=match.value,
                    category=match.category,
                    severity=match.severity,
                    confidence=match.confidence,
                    context=_context_without_secret(line, match.value),
                    line_number=line_number,
                )
            )
            if len(out) >= remaining:
                return out
    return out


class _SecretMatch(BaseModel):
    value: str
    category: str
    severity: str
    confidence: float


_PATTERNS: tuple[tuple[str, str, str, float, re.Pattern[str]], ...] = (
    (
        "github_token",
        "high",
        "0.98",
        0.98,
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"),
    ),
    (
        "github_token",
        "high",
        "0.98",
        0.98,
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    ),
    (
        "openai_api_key",
        "high",
        "0.95",
        0.95,
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "google_api_key",
        "high",
        "0.95",
        0.95,
        re.compile(r"\bAIza[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "aws_access_key",
        "high",
        "0.95",
        0.95,
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
)

_KEY_VALUE_SECRET = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|password|passwd)\b"
    r"\s*[:=]\s*[\"']?([^\"'\s,;]{8,})"
)


def _secret_matches(
    value: str,
    *,
    args: JavaDetectSecretsArgs,
) -> list[_SecretMatch]:
    matches: list[_SecretMatch] = []
    seen: set[str] = set()
    for category, severity, _label, confidence, pattern in _PATTERNS:
        for match in pattern.finditer(value):
            secret = match.group(0)
            if secret not in seen:
                matches.append(
                    _SecretMatch(
                        value=secret,
                        category=category,
                        severity=severity,
                        confidence=confidence,
                    )
                )
                seen.add(secret)
    for match in _KEY_VALUE_SECRET.finditer(value):
        secret = match.group(1)
        if _looks_like_placeholder(secret) or secret in seen:
            continue
        matches.append(
            _SecretMatch(
                value=secret,
                category=_category_for_secret(secret),
                severity="medium",
                confidence=0.85,
            )
        )
        seen.add(secret)
    if (
        len(value) >= args.min_high_entropy_length
        and not _looks_like_placeholder(value)
        and not _looks_like_env_name(value)
        and _entropy(value) >= args.min_high_entropy
        and _has_mixed_secret_charset(value)
        and value not in seen
    ):
        matches.append(
            _SecretMatch(
                value=value,
                category="high_entropy_string",
                severity="medium",
                confidence=0.65,
            )
        )
    return matches


def _category_for_secret(value: str) -> str:
    if value.startswith(("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")):
        return "github_token"
    if value.startswith("sk-"):
        return "openai_api_key"
    if value.startswith("AIza"):
        return "google_api_key"
    if value.startswith("AKIA"):
        return "aws_access_key"
    return "key_value_secret"


def _candidate(
    *,
    source_type: SecretSourceType,
    path: str,
    raw_value: str,
    category: str,
    severity: str,
    confidence: float,
    context: str,
    class_name: str | None = None,
    method_name: str | None = None,
    method_descriptor: str | None = None,
    bci: int | None = None,
    line_number: int | None = None,
) -> JavaSecretCandidate:
    digest = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
    key = f"{source_type}:{path}:{class_name}:{method_name}:{method_descriptor}:{bci}:{line_number}:{category}:{digest}"
    return JavaSecretCandidate(
        candidate_id=hashlib.sha256(key.encode("utf-8")).hexdigest()[:16],
        category=category,
        severity=severity,
        confidence=confidence,
        source_type=source_type,
        path=path,
        class_name=class_name,
        method_name=method_name,
        method_descriptor=method_descriptor,
        bci=bci,
        line_number=line_number,
        value=None,
        redacted_value_hash=digest,
        value_length=len(raw_value),
        context=context,
    )


def _context_without_secret(text: str, secret: str) -> str:
    return text.replace(secret, "<redacted>")[:240]


def _line_numbers(code: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        line
        for line in code.get("line_numbers", [])
        if isinstance(line, dict)
        and isinstance(line.get("start_pc"), int)
        and isinstance(line.get("line_number"), int)
    ]


def _line_number_for_bci(
    line_numbers: list[dict[str, Any]],
    bci: int | None,
) -> int | None:
    if bci is None:
        return None
    current: int | None = None
    for item in sorted(line_numbers, key=lambda value: int(value["start_pc"])):
        if int(item["start_pc"]) > bci:
            break
        current = int(item["line_number"])
    return current


def _looks_like_text_resource(path: str) -> bool:
    lowered = path.lower()
    return lowered.endswith(
        (
            ".properties",
            ".props",
            ".json",
            ".toml",
            ".xml",
            ".yaml",
            ".yml",
            ".ini",
            ".cfg",
            ".conf",
            ".txt",
            ".mf",
        )
    )


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    return lowered in {
        "changeme",
        "change-me",
        "example",
        "not-secret",
        "password",
        "secret",
        "token",
    } or lowered.startswith(("your_", "example_", "dummy"))


def _looks_like_env_name(value: str) -> bool:
    return value.isupper() and "_" in value and "=" not in value


def _has_mixed_secret_charset(value: str) -> bool:
    return (
        any(ch.islower() for ch in value)
        and any(ch.isupper() for ch in value)
        and any(ch.isdigit() for ch in value)
    )


def _entropy(value: str) -> float:
    counts = {ch: value.count(ch) for ch in set(value)}
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _add_secret_node(
    kb: KnowledgeBase,
    archive_path: Path,
    candidate: JavaSecretCandidate,
) -> None:
    kb.add_node(
        Node(
            kind=NodeKind.java_secret,
            label=f"{candidate.category}: {candidate.path}",
            props={
                "tool": "java_detect_secrets",
                "archive_path": str(archive_path),
                **candidate.model_dump(),
            },
            tags=["java", "secret", candidate.category, candidate.source_type],
        )
    )


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def build_tool() -> MemoryTool[JavaDetectSecretsArgs, JavaDetectSecretsResult]:
    return JavaDetectSecretsTool()
