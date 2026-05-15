from __future__ import annotations

import base64
import binascii
import hashlib
import json
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


SuspiciousBlobState = Literal[
    "benign_resource_like",
    "encoded_constant",
    "compressed_blob",
    "encrypted_or_random_blob",
    "decoder_nearby",
    "decoded_to_file",
    "decoded_to_classloader",
    "decoded_to_native_load",
    "decoded_to_process_or_network",
]
SuspiciousBlobSourceType = Literal["class_string", "method_bytecode", "resource"]


class JavaDetectSuspiciousBlobsArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    include_class_constants: bool = True
    include_methods: bool = True
    include_resources: bool = True
    include_benign_resource_like: bool = False
    max_classes: int = Field(50_000, ge=0)
    max_resources: int = Field(5_000, ge=0)
    max_resource_bytes: int = Field(5_000_000, ge=0)
    max_findings: int = Field(512, ge=0)
    min_encoded_length: int = Field(24, ge=8)
    min_decoded_length: int = Field(8, ge=1)
    min_high_entropy_resource_bytes: int = Field(512, ge=1)
    high_entropy_threshold: float = Field(7.35, ge=0.0, le=8.0)


class JavaSuspiciousBlobFinding(BaseModel):
    finding_id: str
    state: SuspiciousBlobState
    category: str
    severity: str
    confidence: float
    source_type: SuspiciousBlobSourceType
    path: str
    class_name: str | None = None
    method_name: str | None = None
    method_descriptor: str | None = None
    bci: int | None = None
    line_number: int | None = None
    value: str | None = None
    redacted_value_hash: str | None = None
    value_length: int | None = None
    decoded_length: int | None = None
    entropy: float | None = None
    magic: str | None = None
    matched_apis: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    message: str


class JavaDetectSuspiciousBlobsResult(BaseModel):
    archive_path: str
    sha256: str
    class_count: int
    parsed_class_count: int
    resource_count: int
    finding_count: int
    findings: list[JavaSuspiciousBlobFinding]
    summary_by_state: dict[str, int]
    summary_by_category: dict[str, int]
    truncated: bool = False
    stop_reasons: list[str] = Field(default_factory=list)


class JavaDetectSuspiciousBlobsTool(
    MemoryTool[JavaDetectSuspiciousBlobsArgs, JavaDetectSuspiciousBlobsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_detect_suspicious_blobs",
                description=(
                    "Scan Java archives for encoded constants, compressed or "
                    "high-entropy payloads, hidden class/native resources, and "
                    "method-local decoder-to-sink correlations."
                ),
                tags=("java", "jar", "obfuscation", "blob", "security", "kb"),
            ),
            JavaDetectSuspiciousBlobsArgs,
            JavaDetectSuspiciousBlobsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaDetectSuspiciousBlobsArgs,
    ) -> JavaDetectSuspiciousBlobsResult:
        path = Path(args.path or ctx.file_path)
        digest = _sha256(path)
        if not zipfile.is_zipfile(path):
            return JavaDetectSuspiciousBlobsResult(
                archive_path=str(path),
                sha256=digest,
                class_count=0,
                parsed_class_count=0,
                resource_count=0,
                finding_count=0,
                findings=[],
                summary_by_state={},
                summary_by_category={},
                stop_reasons=["input_not_zip"],
            )

        findings: list[JavaSuspiciousBlobFinding] = []
        class_count = 0
        parsed_class_count = 0
        resource_count = 0
        truncated = False
        java_analysis = getattr(g, "analysis")

        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if info.filename.endswith(".class"):
                    class_count += 1
                    if not args.include_class_constants and not args.include_methods:
                        continue
                    if class_count > args.max_classes:
                        truncated = True
                        continue
                    parsed = java_analysis.parse_java_class_bytes(zf.read(info))
                    if parsed is None:
                        continue
                    parsed_class_count += 1
                    findings.extend(
                        _class_findings(
                            entry_name=info.filename,
                            parsed=parsed,
                            args=args,
                            remaining=max(args.max_findings - len(findings), 0),
                        )
                    )
                elif args.include_resources:
                    resource_count += 1
                    if resource_count > args.max_resources:
                        truncated = True
                        continue
                    if info.file_size > args.max_resource_bytes:
                        truncated = True
                        continue
                    findings.extend(
                        _resource_findings(
                            entry_name=info.filename,
                            data=zf.read(info),
                            args=args,
                            remaining=max(args.max_findings - len(findings), 0),
                        )
                    )
                if len(findings) >= args.max_findings:
                    truncated = True
                    break

        for finding in findings:
            _add_finding_node(kb, path, finding)

        return JavaDetectSuspiciousBlobsResult(
            archive_path=str(path),
            sha256=digest,
            class_count=class_count,
            parsed_class_count=parsed_class_count,
            resource_count=resource_count,
            finding_count=len(findings),
            findings=findings,
            summary_by_state=_count_by(findings, "state"),
            summary_by_category=_count_by(findings, "category"),
            truncated=truncated,
        )


def _class_findings(
    *,
    entry_name: str,
    parsed: dict[str, Any],
    args: JavaDetectSuspiciousBlobsArgs,
    remaining: int,
) -> list[JavaSuspiciousBlobFinding]:
    if remaining <= 0:
        return []
    out: list[JavaSuspiciousBlobFinding] = []
    class_name = str(parsed["class_name"])
    for method in parsed["methods"]:
        code = method.get("code")
        if not isinstance(code, dict):
            continue
        method_name = str(method["name"])
        method_descriptor = str(method["descriptor"])
        line_numbers = _line_numbers(code)
        xrefs = [xref for xref in code.get("xrefs", []) if isinstance(xref, dict)]
        if args.include_class_constants:
            for xref in xrefs:
                if xref.get("kind") != "string":
                    continue
                value = xref.get("string_value")
                if not isinstance(value, str):
                    continue
                decoded_candidates = _decoded_string_candidates(value, args=args)
                for candidate in decoded_candidates:
                    bci = int(xref["bci"]) if isinstance(xref.get("bci"), int) else None
                    out.append(
                        _finding(
                            state=candidate.state,
                            category=candidate.category,
                            severity=candidate.severity,
                            confidence=candidate.confidence,
                            source_type="class_string",
                            path=entry_name,
                            class_name=class_name,
                            method_name=method_name,
                            method_descriptor=method_descriptor,
                            bci=bci,
                            line_number=_line_number_for_bci(line_numbers, bci),
                            value_hash=_hash_text(value),
                            value_length=len(value),
                            decoded_length=len(candidate.decoded),
                            entropy=_entropy_bytes(candidate.decoded),
                            magic=candidate.magic,
                            matched_apis=[],
                            evidence=[
                                f"{candidate.encoding} string constant",
                                *candidate.evidence,
                            ],
                            message=(
                                f"{candidate.encoding} encoded constant in "
                                f"{class_name}#{method_name}{method_descriptor}: "
                                f"{candidate.message}"
                            ),
                        )
                    )
                    if len(out) >= remaining:
                        return out

        if args.include_methods:
            method_finding = _method_correlation_finding(
                entry_name=entry_name,
                class_name=class_name,
                method_name=method_name,
                method_descriptor=method_descriptor,
                xrefs=xrefs,
            )
            if method_finding is not None:
                out.append(method_finding)
                if len(out) >= remaining:
                    return out
    return out


def _resource_findings(
    *,
    entry_name: str,
    data: bytes,
    args: JavaDetectSuspiciousBlobsArgs,
    remaining: int,
) -> list[JavaSuspiciousBlobFinding]:
    if remaining <= 0 or not data:
        return []
    magic = _magic(data)
    lowered = entry_name.lower()
    entropy = _entropy_bytes(data[: min(len(data), 1_000_000)])
    if magic == "class" and not lowered.endswith(".class"):
        return [
            _finding(
                state="decoded_to_classloader",
                category="archive_resource_anomaly",
                severity="high",
                confidence=0.95,
                source_type="resource",
                path=entry_name,
                value_hash=_hash_bytes(data),
                value_length=len(data),
                decoded_length=len(data),
                entropy=entropy,
                magic=magic,
                evidence=["classfile magic under non-.class resource path"],
                message="Resource begins with Java classfile magic but is not a .class entry.",
            )
        ]
    if magic in {"elf", "pe", "macho"}:
        return [
            _finding(
                state="decoded_to_native_load",
                category="archive_resource_anomaly",
                severity="high",
                confidence=0.9,
                source_type="resource",
                path=entry_name,
                value_hash=_hash_bytes(data),
                value_length=len(data),
                decoded_length=len(data),
                entropy=entropy,
                magic=magic,
                evidence=["native executable/library magic in archive resource"],
                message="Resource looks like a platform-native binary payload.",
            )
        ]
    if magic in {"zip", "gzip", "zlib"}:
        if _is_named_compressed_archive(entry_name):
            if not args.include_benign_resource_like:
                return []
            return [
                _finding(
                    state="benign_resource_like",
                    category="archive_resource_anomaly",
                    severity="info",
                    confidence=0.5,
                    source_type="resource",
                    path=entry_name,
                    value_hash=_hash_bytes(data),
                    value_length=len(data),
                    decoded_length=len(data),
                    entropy=entropy,
                    magic=magic,
                    evidence=["named compressed/archive resource"],
                    message=(
                        "Resource is a named compressed/archive entry; this is "
                        "common for bundled dependencies and jar-in-jar loaders."
                    ),
                )
            ]
        return [
            _finding(
                state="compressed_blob",
                category="archive_resource_anomaly",
                severity="medium",
                confidence=0.85,
                source_type="resource",
                path=entry_name,
                value_hash=_hash_bytes(data),
                value_length=len(data),
                decoded_length=len(data),
                entropy=entropy,
                magic=magic,
                evidence=["compressed/archive magic in resource"],
                message="Resource looks like an embedded compressed/archive blob.",
            )
        ]
    if (
        len(data) >= args.min_high_entropy_resource_bytes
        and entropy >= args.high_entropy_threshold
    ):
        if _is_benign_resource_like(entry_name):
            if not args.include_benign_resource_like:
                return []
            return [
                _finding(
                    state="benign_resource_like",
                    category="archive_resource_anomaly",
                    severity="info",
                    confidence=0.5,
                    source_type="resource",
                    path=entry_name,
                    value_hash=_hash_bytes(data),
                    value_length=len(data),
                    decoded_length=len(data),
                    entropy=entropy,
                    magic=magic,
                    evidence=[
                        "high entropy but extension is normally compressed media/data"
                    ],
                    message="High entropy resource looks like a normal compressed asset.",
                )
            ]
        return [
            _finding(
                state="encrypted_or_random_blob",
                category="archive_resource_anomaly",
                severity="medium",
                confidence=0.75,
                source_type="resource",
                path=entry_name,
                value_hash=_hash_bytes(data),
                value_length=len(data),
                decoded_length=len(data),
                entropy=entropy,
                magic=magic,
                evidence=["high entropy resource bytes"],
                message="Resource has high entropy and does not look like a normal media asset.",
            )
        ]
    return _encoded_resource_findings(
        entry_name=entry_name,
        data=data,
        args=args,
        remaining=remaining,
    )


class _DecodedStringCandidate(BaseModel):
    encoding: str
    decoded: bytes
    state: SuspiciousBlobState
    category: str
    severity: str
    confidence: float
    magic: str | None = None
    evidence: list[str] = Field(default_factory=list)
    message: str


def _decoded_string_candidates(
    value: str,
    *,
    args: JavaDetectSuspiciousBlobsArgs,
) -> list[_DecodedStringCandidate]:
    out: list[_DecodedStringCandidate] = []
    for encoding, decoded in _decode_string(value, args=args):
        magic = _magic(decoded)
        entropy = _entropy_bytes(decoded)
        state: SuspiciousBlobState = "encoded_constant"
        category = "encoded_string"
        severity = "low"
        confidence = 0.7
        evidence = [f"decoded_length={len(decoded)}"]
        message = "encoded data decodes successfully"
        if magic == "class":
            state = "decoded_to_classloader"
            category = "encoded_class_blob"
            severity = "high"
            confidence = 0.95
            evidence.append("decoded Java classfile magic")
            message = "decoded bytes begin with Java classfile magic"
        elif magic in {"zip", "gzip", "zlib"}:
            state = "compressed_blob"
            category = "encoded_compressed_blob"
            severity = "medium"
            confidence = 0.85
            evidence.append(f"decoded {magic} magic")
            message = "decoded bytes look compressed or archive-like"
        elif magic in {"elf", "pe", "macho"}:
            state = "decoded_to_native_load"
            category = "encoded_native_blob"
            severity = "high"
            confidence = 0.9
            evidence.append(f"decoded native magic={magic}")
            message = "decoded bytes look like a native binary"
        elif len(decoded) >= args.min_high_entropy_resource_bytes and entropy >= 7.35:
            state = "encrypted_or_random_blob"
            category = "encoded_high_entropy_blob"
            severity = "medium"
            confidence = 0.8
            evidence.append(f"decoded_entropy={entropy:.3f}")
            message = "decoded bytes are high entropy"
        out.append(
            _DecodedStringCandidate(
                encoding=encoding,
                decoded=decoded,
                state=state,
                category=category,
                severity=severity,
                confidence=confidence,
                magic=magic,
                evidence=evidence,
                message=message,
            )
        )
    return out


def _decode_string(
    value: str,
    *,
    args: JavaDetectSuspiciousBlobsArgs,
) -> list[tuple[str, bytes]]:
    compact = "".join(value.split())
    if len(compact) < args.min_encoded_length:
        return []
    out: list[tuple[str, bytes]] = []
    if _looks_base64(compact):
        padded = compact + ("=" * ((4 - len(compact) % 4) % 4))
        for label, altchars in (("base64", None), ("base64url", b"-_")):
            try:
                decoded = base64.b64decode(
                    padded.encode("ascii"),
                    altchars=altchars,
                    validate=altchars is None,
                )
            except (binascii.Error, ValueError):
                continue
            if len(decoded) >= args.min_decoded_length and _plausible_decode(decoded):
                out.append((label, decoded))
                break
    if _looks_hex(compact):
        try:
            decoded = binascii.unhexlify(compact)
        except (binascii.Error, ValueError):
            decoded = b""
        if len(decoded) >= args.min_decoded_length and _plausible_decode(decoded):
            out.append(("hex", decoded))
    return out


def _encoded_resource_findings(
    *,
    entry_name: str,
    data: bytes,
    args: JavaDetectSuspiciousBlobsArgs,
    remaining: int,
) -> list[JavaSuspiciousBlobFinding]:
    if remaining <= 0 or not entry_name.lower().endswith(".json"):
        return []
    if _is_likely_localization_json(entry_name):
        return []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return []
    try:
        root = json.loads(text)
    except json.JSONDecodeError:
        return []

    out: list[JavaSuspiciousBlobFinding] = []
    for json_path, key, parent_keys, value in _json_string_values(root):
        if not _is_sensitive_encoded_resource_context(
            entry_name=entry_name,
            key=key,
            parent_keys=parent_keys,
            json_path=json_path,
        ):
            continue
        for encoding, decoded in _decode_string_relaxed(value, args=args):
            magic = _magic(decoded)
            decoded_entropy = _entropy_bytes(decoded)
            if magic == "class":
                state: SuspiciousBlobState = "decoded_to_classloader"
                category = "encoded_resource_class_blob"
                severity = "high"
                confidence = 0.95
                message = "Sensitive-looking JSON value decodes to Java classfile magic."
            elif magic in {"elf", "pe", "macho"}:
                state = "decoded_to_native_load"
                category = "encoded_resource_native_blob"
                severity = "high"
                confidence = 0.9
                message = "Sensitive-looking JSON value decodes to native binary magic."
            elif magic in {"zip", "gzip", "zlib"}:
                state = "compressed_blob"
                category = "encoded_resource_compressed_blob"
                severity = "medium"
                confidence = 0.85
                message = "Sensitive-looking JSON value decodes to compressed data."
            elif _binaryish_decoded_secret(decoded):
                state = "encrypted_or_random_blob"
                category = "encoded_resource_secret_blob"
                severity = "high" if _strong_secret_key_hint(key) else "medium"
                confidence = 0.82 if _strong_secret_key_hint(key) else 0.74
                message = (
                    "Sensitive-looking JSON value decodes to compact binary data "
                    "that looks encrypted or random."
                )
            else:
                continue
            line_number = _line_number_for_value(text, value)
            out.append(
                _finding(
                    state=state,
                    category=category,
                    severity=severity,
                    confidence=confidence,
                    source_type="resource",
                    path=entry_name,
                    line_number=line_number,
                    value_hash=_hash_text(value),
                    value_length=len(value),
                    decoded_length=len(decoded),
                    entropy=decoded_entropy,
                    magic=magic,
                    evidence=[
                        f"{encoding} JSON value",
                        f"json_path={json_path}",
                        f"decoded_length={len(decoded)}",
                        f"decoded_entropy={decoded_entropy:.3f}",
                    ],
                    message=message,
                )
            )
            if len(out) >= remaining:
                return out
    return out


def _json_string_values(
    value: Any,
    *,
    json_path: str = "$",
    key: str | None = None,
    parent_keys: frozenset[str] = frozenset(),
) -> list[tuple[str, str | None, frozenset[str], str]]:
    if isinstance(value, str):
        return [(json_path, key, parent_keys, value)]
    if isinstance(value, dict):
        keys = frozenset(str(item).lower() for item in value)
        out: list[tuple[str, str | None, frozenset[str], str]] = []
        for child_key, child_value in value.items():
            child_key_text = str(child_key)
            out.extend(
                _json_string_values(
                    child_value,
                    json_path=f"{json_path}.{child_key_text}",
                    key=child_key_text,
                    parent_keys=keys,
                )
            )
        return out
    if isinstance(value, list):
        out = []
        for index, child_value in enumerate(value):
            out.extend(
                _json_string_values(
                    child_value,
                    json_path=f"{json_path}[{index}]",
                    key=key,
                    parent_keys=parent_keys,
                )
            )
        return out
    return []


def _decode_string_relaxed(
    value: str,
    *,
    args: JavaDetectSuspiciousBlobsArgs,
) -> list[tuple[str, bytes]]:
    compact = "".join(value.split())
    if len(compact) < args.min_encoded_length:
        return []
    out: list[tuple[str, bytes]] = []
    if _looks_base64(compact):
        padded = compact + ("=" * ((4 - len(compact) % 4) % 4))
        for label, altchars in (("base64", None), ("base64url", b"-_")):
            try:
                decoded = base64.b64decode(
                    padded.encode("ascii"),
                    altchars=altchars,
                    validate=altchars is None,
                )
            except (binascii.Error, ValueError):
                continue
            if len(decoded) >= args.min_decoded_length:
                out.append((label, decoded))
                break
    if _looks_hex(compact):
        raw = compact[2:] if compact.startswith(("0x", "0X")) else compact
        try:
            decoded = binascii.unhexlify(raw)
        except (binascii.Error, ValueError):
            decoded = b""
        if len(decoded) >= args.min_decoded_length:
            out.append(("hex", decoded))
    return out


_RESOURCE_CONTEXT_HINTS = (
    "auth",
    "credential",
    "key",
    "oauth",
    "secret",
    "storage",
    "token",
)
_RESOURCE_SECRET_KEY_HINTS = (
    "access_token",
    "apikey",
    "api_key",
    "auth",
    "client_secret",
    "credential",
    "password",
    "passwd",
    "private_key",
    "secret",
    "stored",
    "token",
)
_EXACT_RESOURCE_SECRET_KEYS = frozenset({"auth", "key", "stored"})
_GENERIC_BLOB_KEYS = ("blob", "ciphertext", "data", "payload", "value")


def _is_sensitive_encoded_resource_context(
    *,
    entry_name: str,
    key: str | None,
    parent_keys: frozenset[str],
    json_path: str,
) -> bool:
    lowered_entry = entry_name.lower()
    lowered_key = (key or "").lower()
    lowered_json_path = json_path.lower()
    if _strong_secret_key_hint(key):
        return True
    has_contextual_path = any(
        hint in lowered_entry or hint in lowered_json_path
        for hint in _RESOURCE_CONTEXT_HINTS
    )
    if lowered_key in _GENERIC_BLOB_KEYS and has_contextual_path:
        return True
    if lowered_key in _GENERIC_BLOB_KEYS and (
        parent_keys.intersection(_RESOURCE_SECRET_KEY_HINTS)
        or parent_keys.intersection(_EXACT_RESOURCE_SECRET_KEYS)
    ):
        return True
    return lowered_key in _GENERIC_BLOB_KEYS and {"stored", "data"}.issubset(
        parent_keys
    )


def _strong_secret_key_hint(key: str | None) -> bool:
    lowered = (key or "").lower()
    return lowered in _EXACT_RESOURCE_SECRET_KEYS or any(
        hint in lowered for hint in _RESOURCE_SECRET_KEY_HINTS
    )


def _is_likely_localization_json(path: str) -> bool:
    lowered = path.lower()
    return (
        "/lang/" in lowered
        or lowered.startswith("lang/")
        or lowered.endswith("_localization/en_us.json")
        or "_localization/" in lowered
    )


def _binaryish_decoded_secret(data: bytes) -> bool:
    if not data:
        return False
    if _magic(data) is not None:
        return True
    printable = sum(1 for byte in data if byte in b"\r\n\t" or 32 <= byte <= 126)
    printable_ratio = printable / len(data)
    max_entropy = min(8.0, math.log2(len(data))) if len(data) > 1 else 1.0
    normalized_entropy = _entropy_bytes(data) / max_entropy
    return printable_ratio < 0.65 and normalized_entropy >= 0.65


def _line_number_for_value(text: str, value: str) -> int | None:
    offset = text.find(value)
    if offset < 0:
        return None
    return text.count("\n", 0, offset) + 1


_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")
_HEX_RE = re.compile(r"^(?:0x)?[A-Fa-f0-9]+$")


def _looks_base64(value: str) -> bool:
    if not _BASE64_RE.fullmatch(value):
        return False
    if len(value.rstrip("=")) < 16:
        return False
    return len(value) % 4 in {0, 2, 3}


def _looks_hex(value: str) -> bool:
    raw = value[2:] if value.startswith(("0x", "0X")) else value
    return len(raw) >= 32 and len(raw) % 2 == 0 and bool(_HEX_RE.fullmatch(value))


def _plausible_decode(data: bytes) -> bool:
    if not data:
        return False
    if _magic(data) is not None:
        return True
    printable = sum(1 for byte in data if byte in b"\r\n\t" or 32 <= byte <= 126)
    printable_ratio = printable / len(data)
    return printable_ratio >= 0.75 or _entropy_bytes(data) >= 6.0


_DECODER_APIS: tuple[tuple[str, str], ...] = (
    ("java/util/Base64", "getDecoder"),
    ("java/util/Base64", "getUrlDecoder"),
    ("java/util/Base64", "getMimeDecoder"),
    ("java/util/Base64$Decoder", "decode"),
    ("javax/xml/bind/DatatypeConverter", "parseBase64Binary"),
    ("javax/xml/bind/DatatypeConverter", "parseHexBinary"),
    ("java/util/HexFormat", "parseHex"),
    ("java/util/zip/Inflater", "<init>"),
    ("java/util/zip/Inflater", "inflate"),
    ("java/util/zip/Inflater", "setInput"),
    ("java/util/zip/GZIPInputStream", "<init>"),
    ("javax/crypto/Cipher", "getInstance"),
    ("javax/crypto/Cipher", "doFinal"),
    ("javax/crypto/spec/SecretKeySpec", "<init>"),
)

_SINK_APIS: tuple[tuple[str, str, SuspiciousBlobState, str], ...] = (
    ("java/lang/ClassLoader", "defineClass", "decoded_to_classloader", "classloader"),
    (
        "java/lang/invoke/MethodHandles$Lookup",
        "defineClass",
        "decoded_to_classloader",
        "classloader",
    ),
    ("java/net/URLClassLoader", "<init>", "decoded_to_classloader", "classloader"),
    ("java/lang/System", "load", "decoded_to_native_load", "native"),
    ("java/lang/System", "loadLibrary", "decoded_to_native_load", "native"),
    ("java/lang/ProcessBuilder", "<init>", "decoded_to_process_or_network", "process"),
    ("java/lang/ProcessBuilder", "start", "decoded_to_process_or_network", "process"),
    ("java/lang/Runtime", "exec", "decoded_to_process_or_network", "process"),
    ("java/net/URL", "openConnection", "decoded_to_process_or_network", "network"),
    ("java/net/URL", "openStream", "decoded_to_process_or_network", "network"),
    ("java/net/Socket", "<init>", "decoded_to_process_or_network", "network"),
    ("java/net/Socket", "connect", "decoded_to_process_or_network", "network"),
    ("java/nio/file/Files", "write", "decoded_to_file", "filesystem"),
    ("java/nio/file/Files", "writeString", "decoded_to_file", "filesystem"),
    ("java/nio/file/Files", "copy", "decoded_to_file", "filesystem"),
)


def _method_correlation_finding(
    *,
    entry_name: str,
    class_name: str,
    method_name: str,
    method_descriptor: str,
    xrefs: list[dict[str, Any]],
) -> JavaSuspiciousBlobFinding | None:
    method_refs = [
        xref for xref in xrefs if xref.get("kind") in {"method", "interface_method"}
    ]
    decoders = [
        _api_label(xref) for xref in method_refs if _matches_any(xref, _DECODER_APIS)
    ]
    if not decoders:
        return None
    sinks: list[tuple[str, SuspiciousBlobState, str]] = []
    for xref in method_refs:
        sink = _sink_for_xref(xref)
        if sink is not None:
            sinks.append((_api_label(xref), sink[0], sink[1]))
    if sinks:
        sink_label, state, sink_kind = sinks[0]
        severity = (
            "high"
            if state in {"decoded_to_classloader", "decoded_to_native_load"}
            else "medium"
        )
        return _finding(
            state=state,
            category=f"decoder_to_{sink_kind}",
            severity=severity,
            confidence=0.82,
            source_type="method_bytecode",
            path=entry_name,
            class_name=class_name,
            method_name=method_name,
            method_descriptor=method_descriptor,
            value_hash=_hash_text(
                f"{class_name}#{method_name}{method_descriptor}:{','.join(decoders)}:{sink_label}"
            ),
            matched_apis=[*sorted(set(decoders)), sink_label],
            evidence=[
                "decoder API and sensitive sink appear in the same method",
                f"decoder_count={len(set(decoders))}",
                f"sink={sink_label}",
            ],
            message=(
                f"Decoder/deobfuscation API is method-local to {sink_kind} sink "
                f"in {class_name}#{method_name}{method_descriptor}."
            ),
        )
    return _finding(
        state="decoder_nearby",
        category="decoder_pattern",
        severity="medium",
        confidence=0.65,
        source_type="method_bytecode",
        path=entry_name,
        class_name=class_name,
        method_name=method_name,
        method_descriptor=method_descriptor,
        value_hash=_hash_text(
            f"{class_name}#{method_name}{method_descriptor}:{','.join(decoders)}"
        ),
        matched_apis=sorted(set(decoders)),
        evidence=["decoder/deobfuscation API appears in method"],
        message=(
            "Method contains decoder/deobfuscation API calls but no same-method "
            "sensitive sink was detected."
        ),
    )


def _matches_any(xref: dict[str, Any], apis: tuple[tuple[str, str], ...]) -> bool:
    owner = str(xref.get("owner", ""))
    name = str(xref.get("name", ""))
    return any(owner == api_owner and name == api_name for api_owner, api_name in apis)


def _sink_for_xref(
    xref: dict[str, Any],
) -> tuple[SuspiciousBlobState, str] | None:
    owner = str(xref.get("owner", ""))
    name = str(xref.get("name", ""))
    for api_owner, api_name, state, sink_kind in _SINK_APIS:
        if owner == api_owner and name == api_name:
            return state, sink_kind
    return None


def _api_label(xref: dict[str, Any]) -> str:
    return f"{xref.get('owner', '')}#{xref.get('name', '')}{xref.get('descriptor', '')}"


def _finding(
    *,
    state: SuspiciousBlobState,
    category: str,
    severity: str,
    confidence: float,
    source_type: SuspiciousBlobSourceType,
    path: str,
    message: str,
    class_name: str | None = None,
    method_name: str | None = None,
    method_descriptor: str | None = None,
    bci: int | None = None,
    line_number: int | None = None,
    value_hash: str | None = None,
    value_length: int | None = None,
    decoded_length: int | None = None,
    entropy: float | None = None,
    magic: str | None = None,
    matched_apis: list[str] | None = None,
    evidence: list[str] | None = None,
) -> JavaSuspiciousBlobFinding:
    key = (
        f"{state}:{category}:{source_type}:{path}:{class_name}:{method_name}:"
        f"{method_descriptor}:{bci}:{value_hash}:{magic}:{message}"
    )
    return JavaSuspiciousBlobFinding(
        finding_id=hashlib.sha256(key.encode("utf-8")).hexdigest()[:16],
        state=state,
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
        redacted_value_hash=value_hash,
        value_length=value_length,
        decoded_length=decoded_length,
        entropy=round(entropy, 3) if entropy is not None else None,
        magic=magic,
        matched_apis=matched_apis or [],
        evidence=evidence or [],
        message=message,
    )


def _add_finding_node(
    kb: KnowledgeBase,
    archive_path: Path,
    finding: JavaSuspiciousBlobFinding,
) -> None:
    where = finding.path
    if finding.class_name:
        where = f"{finding.class_name}#{finding.method_name}{finding.method_descriptor}"
    kb.add_node(
        Node(
            kind=NodeKind.java_suspicious_blob,
            label=f"{finding.state}: {where}",
            text=finding.message,
            props={
                "tool": "java_detect_suspicious_blobs",
                "archive_path": str(archive_path),
                **finding.model_dump(),
            },
            tags=[
                "java",
                "suspicious-blob",
                finding.state,
                finding.category,
            ],
        )
    )


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


def _magic(data: bytes) -> str | None:
    if data.startswith(b"\xca\xfe\xba\xbe"):
        if len(data) >= 8:
            major = int.from_bytes(data[6:8], "big")
            if 45 <= major <= 100:
                return "class"
        return "macho"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if len(data) >= 2 and data[0] == 0x78 and data[1] in {0x01, 0x5E, 0x9C, 0xDA}:
        return "zlib"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(
        (
            b"\xfe\xed\xfa\xce",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe\x00\x00",
        )
    ):
        return "macho"
    return None


def _is_benign_resource_like(path: str) -> bool:
    lowered = path.lower()
    return lowered.endswith(
        (
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".webp",
            ".ogg",
            ".mp3",
            ".mp4",
            ".jar",
            ".zip",
            ".gz",
            ".gzip",
            ".nbt",
            ".schem",
            ".schematic",
            ".mcstructure",
            ".rsa",
            ".dsa",
            ".ec",
            ".sf",
            ".class",
        )
    )


def _is_named_compressed_archive(path: str) -> bool:
    lowered = path.lower()
    return lowered.endswith(
        (".jar", ".zip", ".gz", ".gzip", ".nbt", ".schem", ".schematic")
    )


def _entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except FileNotFoundError:
        return ""
    return h.hexdigest()


def _count_by(
    findings: list[JavaSuspiciousBlobFinding], field_name: str
) -> dict[str, int]:
    out: dict[str, int] = {}
    for finding in findings:
        value = str(getattr(finding, field_name))
        out[value] = out.get(value, 0) + 1
    return out


def build_tool() -> MemoryTool[
    JavaDetectSuspiciousBlobsArgs,
    JavaDetectSuspiciousBlobsResult,
]:
    return JavaDetectSuspiciousBlobsTool()
