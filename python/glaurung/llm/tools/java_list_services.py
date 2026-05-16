from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class JavaListServicesArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    service_filter: str | None = Field(None, description="Optional service substring")
    provider_filter: str | None = Field(None, description="Optional provider substring")
    limit: int = Field(256, ge=0)


class JavaServiceDescriptor(BaseModel):
    entry_name: str
    service: str
    dotted_service: str
    provider_count: int
    providers: list[str] = Field(default_factory=list)
    dotted_providers: list[str] = Field(default_factory=list)
    sha256: str


class JavaListServicesResult(BaseModel):
    archive_path: str
    descriptor_count_seen: int = 0
    matched_descriptor_count: int = 0
    services: list[JavaServiceDescriptor] = Field(default_factory=list)
    truncated: bool = False
    stop_reasons: list[str] = Field(default_factory=list)


class JavaListServicesTool(MemoryTool[JavaListServicesArgs, JavaListServicesResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_list_services",
                description=(
                    "List META-INF/services ServiceLoader descriptors and provider "
                    "classes from a Java archive with KB evidence."
                ),
                tags=("java", "jar", "service-loader", "kb"),
            ),
            JavaListServicesArgs,
            JavaListServicesResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaListServicesArgs,
    ) -> JavaListServicesResult:
        archive_path = Path(args.path or ctx.file_path)
        if not zipfile.is_zipfile(archive_path):
            return JavaListServicesResult(
                archive_path=str(archive_path),
                stop_reasons=["input_not_zip"],
            )
        result = JavaListServicesResult(archive_path=str(archive_path))
        with zipfile.ZipFile(archive_path) as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.startswith("META-INF/services/"):
                    continue
                result.descriptor_count_seen += 1
                data = zf.read(info)
                descriptor = _descriptor(info.filename, data)
                if not _matches(descriptor, args):
                    continue
                if len(result.services) >= args.limit:
                    result.truncated = True
                    result.stop_reasons.append("limit")
                    break
                result.services.append(descriptor)
                result.matched_descriptor_count += 1
                _add_service_node(kb, archive_path, descriptor)
        return result


def _descriptor(entry_name: str, data: bytes) -> JavaServiceDescriptor:
    service = entry_name.removeprefix("META-INF/services/")
    providers = _parse_providers(data)
    return JavaServiceDescriptor(
        entry_name=entry_name,
        service=service,
        dotted_service=service.replace("/", "."),
        provider_count=len(providers),
        providers=providers,
        dotted_providers=[provider.replace("/", ".") for provider in providers],
        sha256=hashlib.sha256(data).hexdigest(),
    )


def _parse_providers(data: bytes) -> list[str]:
    providers: list[str] = []
    text = data.decode("utf-8", errors="replace")
    for line in text.splitlines():
        provider = line.split("#", 1)[0].strip()
        if provider:
            providers.append(provider.replace(".", "/"))
    return list(dict.fromkeys(providers))


def _matches(
    descriptor: JavaServiceDescriptor,
    args: JavaListServicesArgs,
) -> bool:
    if args.service_filter:
        service_candidates = {descriptor.service, descriptor.dotted_service}
        if not any(args.service_filter in item for item in service_candidates):
            return False
    if args.provider_filter:
        provider_candidates = {*descriptor.providers, *descriptor.dotted_providers}
        if not any(args.provider_filter in item for item in provider_candidates):
            return False
    return True


def _add_service_node(
    kb: KnowledgeBase,
    archive_path: Path,
    descriptor: JavaServiceDescriptor,
) -> None:
    kb.add_node(
        Node(
            kind=NodeKind.java_resource,
            label=descriptor.entry_name,
            props={
                "tool": "java_list_services",
                "archive_path": str(archive_path),
                **descriptor.model_dump(),
            },
            tags=["java", "service-loader"],
        )
    )


def build_tool() -> MemoryTool[JavaListServicesArgs, JavaListServicesResult]:
    return JavaListServicesTool()
