from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_proguard_mappings import ProguardMappings, parse_proguard_mappings


class JavaDetectSensitiveBehaviorArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    mapping_path: str | None = Field(
        None,
        description="Optional ProGuard/Mojang mapping file for de-obfuscating class names",
    )
    max_classes: int = Field(50_000, ge=0)
    max_findings: int = Field(512, ge=0)


class JavaSensitiveFinding(BaseModel):
    finding_id: str
    rule_id: str
    category: str
    severity: str
    confidence: float
    class_name: str
    mapped_class_name: str | None = None
    method_name: str
    method_descriptor: str
    bci: int | None
    opcode: int | None
    xref_kind: str
    owner: str
    name: str
    descriptor: str
    target: str
    message: str


class JavaDetectSensitiveBehaviorResult(BaseModel):
    archive_path: str
    sha256: str
    class_count: int
    parsed_class_count: int
    parse_error_count: int
    finding_count: int
    findings: list[JavaSensitiveFinding]
    summary_by_category: dict[str, int]
    truncated: bool = False


@dataclass(frozen=True)
class SensitiveRule:
    rule_id: str
    category: str
    severity: str
    confidence: float
    owners: tuple[str, ...]
    names: tuple[str, ...] = ()
    kinds: tuple[str, ...] = ("method", "interface_method")
    message: str = ""

    def matches(self, xref: dict[str, Any]) -> bool:
        if str(xref.get("kind", "")) not in self.kinds:
            return False
        if str(xref.get("owner", "")) not in self.owners:
            return False
        if self.names and str(xref.get("name", "")) not in self.names:
            return False
        return True


_RULES: tuple[SensitiveRule, ...] = (
    SensitiveRule(
        rule_id="java.process.process_builder",
        category="process",
        severity="high",
        confidence=0.95,
        owners=("java/lang/ProcessBuilder",),
        names=("<init>", "start"),
        message="ProcessBuilder can launch operating-system processes.",
    ),
    SensitiveRule(
        rule_id="java.process.runtime_exec",
        category="process",
        severity="high",
        confidence=0.98,
        owners=("java/lang/Runtime",),
        names=("exec",),
        message="Runtime.exec can launch operating-system processes.",
    ),
    SensitiveRule(
        rule_id="java.filesystem.nio_files",
        category="filesystem",
        severity="medium",
        confidence=0.9,
        owners=("java/nio/file/Files",),
        names=(
            "copy",
            "createDirectories",
            "createDirectory",
            "createFile",
            "delete",
            "deleteIfExists",
            "move",
            "readAllBytes",
            "readString",
            "walk",
            "write",
            "writeString",
        ),
        message="java.nio.file.Files can read, write, delete, or walk local files.",
    ),
    SensitiveRule(
        rule_id="java.filesystem.file_delete",
        category="filesystem",
        severity="medium",
        confidence=0.85,
        owners=("java/io/File",),
        names=("delete", "deleteOnExit", "listFiles", "mkdir", "mkdirs", "renameTo"),
        message="java.io.File can inspect or mutate local filesystem state.",
    ),
    SensitiveRule(
        rule_id="java.network.http_client",
        category="network",
        severity="medium",
        confidence=0.9,
        owners=("java/net/http/HttpClient",),
        names=("newHttpClient", "send", "sendAsync"),
        message="HttpClient can create outbound HTTP requests.",
    ),
    SensitiveRule(
        rule_id="java.network.socket",
        category="network",
        severity="medium",
        confidence=0.95,
        owners=(
            "java/net/Socket",
            "java/net/ServerSocket",
            "java/net/DatagramSocket",
        ),
        names=("<init>", "connect", "bind", "send", "receive", "accept"),
        message="Socket APIs can open network connections or listeners.",
    ),
    SensitiveRule(
        rule_id="java.network.url_connection",
        category="network",
        severity="medium",
        confidence=0.9,
        owners=("java/net/URL", "java/net/URLConnection"),
        names=("openConnection", "openStream", "connect", "getInputStream"),
        message="URL connection APIs can perform outbound network access.",
    ),
    SensitiveRule(
        rule_id="java.reflection.class_lookup",
        category="reflection",
        severity="low",
        confidence=0.85,
        owners=("java/lang/Class",),
        names=(
            "forName",
            "getDeclaredField",
            "getDeclaredMethod",
            "getDeclaredMethods",
        ),
        message="Reflection can inspect or invoke code paths by name.",
    ),
    SensitiveRule(
        rule_id="java.reflection.access_override",
        category="reflection",
        severity="medium",
        confidence=0.9,
        owners=("java/lang/reflect/AccessibleObject", "java/lang/reflect/Method"),
        names=("setAccessible", "trySetAccessible", "invoke"),
        message="Reflection access override or invocation can bypass normal call structure.",
    ),
    SensitiveRule(
        rule_id="java.classloading.loader",
        category="classloading",
        severity="medium",
        confidence=0.85,
        owners=("java/lang/ClassLoader", "java/net/URLClassLoader"),
        names=("defineClass", "loadClass", "<init>"),
        message="ClassLoader APIs can load or define code dynamically.",
    ),
    SensitiveRule(
        rule_id="java.native.load",
        category="native",
        severity="high",
        confidence=0.95,
        owners=("java/lang/System",),
        names=("load", "loadLibrary"),
        message="Native library loading can execute platform-native code.",
    ),
    SensitiveRule(
        rule_id="java.serialization.object_input_stream",
        category="serialization",
        severity="medium",
        confidence=0.9,
        owners=("java/io/ObjectInputStream",),
        names=("<init>", "readObject", "readUnshared"),
        message="ObjectInputStream deserializes Java objects from input data.",
    ),
    SensitiveRule(
        rule_id="java.crypto.cipher",
        category="crypto",
        severity="info",
        confidence=0.85,
        owners=("javax/crypto/Cipher", "java/security/KeyStore"),
        names=("getInstance", "load", "store"),
        message="Cryptography or keystore APIs are present.",
    ),
    SensitiveRule(
        rule_id="java.scheduler.executor",
        category="scheduler",
        severity="low",
        confidence=0.85,
        owners=(
            "java/util/concurrent/ScheduledExecutorService",
            "java/util/Timer",
        ),
        names=("schedule", "scheduleAtFixedRate", "scheduleWithFixedDelay"),
        message="Scheduler APIs can run behavior later or repeatedly.",
    ),
    SensitiveRule(
        rule_id="java.environment.system",
        category="environment",
        severity="low",
        confidence=0.9,
        owners=("java/lang/System",),
        names=("getenv", "getProperty"),
        message="Environment variables or system properties can influence behavior.",
    ),
)


class JavaDetectSensitiveBehaviorTool(
    MemoryTool[JavaDetectSensitiveBehaviorArgs, JavaDetectSensitiveBehaviorResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_detect_security_sensitive_behavior",
                description=(
                    "Statically scan a Java archive for sensitive API sinks such as "
                    "process execution, filesystem mutation, networking, reflection, "
                    "native loading, serialization, crypto, scheduling, and environment reads."
                ),
                tags=("java", "jar", "security", "audit", "kb"),
            ),
            JavaDetectSensitiveBehaviorArgs,
            JavaDetectSensitiveBehaviorResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaDetectSensitiveBehaviorArgs,
    ) -> JavaDetectSensitiveBehaviorResult:
        path = Path(args.path or ctx.file_path)
        digest = _sha256(path)
        findings: list[JavaSensitiveFinding] = []
        class_count = 0
        parsed_class_count = 0
        parse_error_count = 0
        truncated = False
        java_analysis = getattr(g, "analysis")
        mappings = (
            parse_proguard_mappings(Path(args.mapping_path))
            if args.mapping_path is not None
            else None
        )

        if not zipfile.is_zipfile(path):
            return JavaDetectSensitiveBehaviorResult(
                archive_path=str(path),
                sha256=digest,
                class_count=0,
                parsed_class_count=0,
                parse_error_count=1,
                finding_count=0,
                findings=[],
                summary_by_category={},
                truncated=False,
            )

        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.endswith(".class"):
                    continue
                class_count += 1
                if class_count > args.max_classes:
                    truncated = True
                    continue
                try:
                    parsed = java_analysis.parse_java_class_bytes(zf.read(info))
                except RuntimeError:
                    parse_error_count += 1
                    continue
                if parsed is None:
                    parse_error_count += 1
                    continue
                parsed_class_count += 1
                for finding in _findings_for_class(
                    parsed=parsed,
                    mappings=mappings,
                    max_findings=max(0, args.max_findings - len(findings)),
                ):
                    findings.append(finding)
                    _add_finding_node(kb, path, finding)
                    if len(findings) >= args.max_findings:
                        truncated = True
                        break
                if len(findings) >= args.max_findings:
                    break

        summary_by_category: dict[str, int] = {}
        for finding in findings:
            summary_by_category[finding.category] = (
                summary_by_category.get(finding.category, 0) + 1
            )

        return JavaDetectSensitiveBehaviorResult(
            archive_path=str(path),
            sha256=digest,
            class_count=class_count,
            parsed_class_count=parsed_class_count,
            parse_error_count=parse_error_count,
            finding_count=len(findings),
            findings=findings,
            summary_by_category=summary_by_category,
            truncated=truncated,
        )


def _findings_for_class(
    *,
    parsed: dict[str, Any],
    mappings: ProguardMappings | None,
    max_findings: int,
) -> list[JavaSensitiveFinding]:
    if max_findings <= 0:
        return []
    class_name = str(parsed["class_name"])
    mapped_class_name = _mapped_class_name(mappings, class_name)
    out: list[JavaSensitiveFinding] = []
    for method in parsed["methods"]:
        code = method.get("code")
        if not isinstance(code, dict):
            continue
        for xref in code.get("xrefs", []):
            if not isinstance(xref, dict):
                continue
            for rule in _RULES:
                if not rule.matches(xref):
                    continue
                out.append(
                    _finding_from_rule(
                        rule=rule,
                        class_name=class_name,
                        mapped_class_name=mapped_class_name,
                        method=method,
                        xref=xref,
                    )
                )
                break
            if len(out) >= max_findings:
                return out
    return out


def _finding_from_rule(
    *,
    rule: SensitiveRule,
    class_name: str,
    mapped_class_name: str | None,
    method: dict[str, Any],
    xref: dict[str, Any],
) -> JavaSensitiveFinding:
    method_name = str(method["name"])
    method_descriptor = str(method["descriptor"])
    bci_raw = xref.get("bci")
    opcode_raw = xref.get("opcode")
    bci = int(bci_raw) if isinstance(bci_raw, int) else None
    opcode = int(opcode_raw) if isinstance(opcode_raw, int) else None
    owner = str(xref.get("owner", ""))
    name = str(xref.get("name", ""))
    descriptor = str(xref.get("descriptor", ""))
    finding_key = f"{rule.rule_id}:{class_name}:{method_name}:{method_descriptor}:{bci}:{owner}:{name}:{descriptor}"
    finding_id = hashlib.sha256(finding_key.encode("utf-8")).hexdigest()[:16]
    return JavaSensitiveFinding(
        finding_id=finding_id,
        rule_id=rule.rule_id,
        category=rule.category,
        severity=rule.severity,
        confidence=rule.confidence,
        class_name=class_name,
        mapped_class_name=mapped_class_name,
        method_name=method_name,
        method_descriptor=method_descriptor,
        bci=bci,
        opcode=opcode,
        xref_kind=str(xref.get("kind", "")),
        owner=owner,
        name=name,
        descriptor=descriptor,
        target=str(xref.get("target", "")),
        message=rule.message,
    )


def _add_finding_node(
    kb: KnowledgeBase,
    archive_path: Path,
    finding: JavaSensitiveFinding,
) -> None:
    kb.add_node(
        Node(
            kind=NodeKind.java_sensitive_sink,
            label=(
                f"{finding.category}: {finding.mapped_class_name or finding.class_name}#"
                f"{finding.method_name}{finding.method_descriptor}"
            ),
            props={
                "tool": "java_detect_security_sensitive_behavior",
                "archive_path": str(archive_path),
                **finding.model_dump(),
            },
            tags=["java", "security", "sensitive", finding.category],
        )
    )


def _mapped_class_name(
    mappings: ProguardMappings | None, class_name: str
) -> str | None:
    if mappings is None:
        return None
    mapping, match_kind = mappings.lookup_class(class_name)
    if mapping is None or match_kind == "none":
        return None
    return mapping.official_name


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def build_tool() -> MemoryTool[
    JavaDetectSensitiveBehaviorArgs, JavaDetectSensitiveBehaviorResult
]:
    return JavaDetectSensitiveBehaviorTool()
