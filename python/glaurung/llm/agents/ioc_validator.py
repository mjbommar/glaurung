"""IOC validation agent (memory-first compatible)."""

from typing import List, Optional, Literal
from enum import Enum
from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext

from ..config import get_config
from ..context import MemoryContext


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    EMAIL = "email"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry"


class IOCCandidate(BaseModel):
    value: str = Field(...)
    ioc_type: IOCType = Field(...)
    offset: Optional[int] = Field(None)
    context: Optional[str] = Field(None)
    encoding: Optional[str] = Field(None)


class ValidatedIOC(BaseModel):
    value: str
    ioc_type: IOCType
    is_valid: bool
    confidence: float
    reasoning: str
    risk_level: Optional[Literal["low", "medium", "high", "critical"]] = None
    category: Optional[str] = None


class IOCValidationBatch(BaseModel):
    candidates: List[IOCCandidate]
    binary_format: Optional[str] = None
    binary_type: Optional[str] = None


class IOCValidationResult(BaseModel):
    validated_iocs: List[ValidatedIOC]
    summary: str
    true_positive_count: int
    false_positive_count: int
    high_risk_iocs: List[str] = []


IOC_VALIDATOR_PROMPT = (
    "You are an expert cybersecurity analyst specializing in IOC validation.\n\n"
    "Consider binary context and filter out false positives."
)


def create_ioc_validator(
    model: Optional[str] = None,
) -> Agent[IOCValidationBatch, IOCValidationResult]:
    config = get_config()
    default_model = (
        (config.ioc_model or config.default_model)
        if any(config.available_models().values())
        else "test"
    )
    model = model or default_model
    return Agent(
        model=model,
        system_prompt=IOC_VALIDATOR_PROMPT,
        output_type=IOCValidationResult,
        deps_type=IOCValidationBatch,
    )


def validate_iocs(
    candidates: List[IOCCandidate],
    binary_format: Optional[str] = None,
    binary_type: Optional[str] = None,
    model: Optional[str] = None,
) -> IOCValidationResult:
    agent = create_ioc_validator(model)
    batch = IOCValidationBatch(
        candidates=candidates, binary_format=binary_format, binary_type=binary_type
    )
    result = agent.run_sync(
        f"Validate these {len(candidates)} IOC candidates and filter out false positives. Binary format: {binary_format or 'unknown'}",
        deps=batch,
    )
    return result.output


async def validate_iocs_async(
    candidates: List[IOCCandidate],
    binary_format: Optional[str] = None,
    binary_type: Optional[str] = None,
    model: Optional[str] = None,
) -> IOCValidationResult:
    agent = create_ioc_validator(model)
    batch = IOCValidationBatch(
        candidates=candidates, binary_format=binary_format, binary_type=binary_type
    )
    result = await agent.run(
        f"Validate these {len(candidates)} IOC candidates and filter out false positives. Binary format: {binary_format or 'unknown'}",
        deps=batch,
    )
    return result.output


def _format_artifact_context(ctx: MemoryContext) -> str:
    art = ctx.artifact
    fmt = arch = bits = None
    if getattr(art, "verdicts", None):
        try:
            v = art.verdicts[0]
            fmt, arch, bits = str(v.format), str(v.arch), getattr(v, "bits", None)
        except Exception:
            pass
    size = getattr(art, "size_bytes", None)
    return (
        f"File: {ctx.file_path}\n"
        + (f"Size: {size:,} bytes\n" if size is not None else "")
        + (f"Format: {fmt} Arch: {arch} Bits: {bits}\n" if fmt or arch or bits else "")
    )


def create_contextual_ioc_validator(
    artifact_context: MemoryContext, model: Optional[str] = None
) -> Agent[IOCValidationBatch, IOCValidationResult]:
    config = get_config()
    default_model = (
        (config.ioc_model or config.default_model)
        if any(config.available_models().values())
        else "test"
    )
    model = model or default_model
    agent = Agent(
        model=model,
        system_prompt=IOC_VALIDATOR_PROMPT,
        output_type=IOCValidationResult,
        deps_type=IOCValidationBatch,
    )

    @agent.system_prompt
    async def add_binary_context(_: RunContext[IOCValidationBatch]) -> str:
        return _format_artifact_context(artifact_context)

    return agent


def filter_iocs_from_artifact(
    artifact, model: Optional[str] = None, max_batch_size: int = 20
) -> List[ValidatedIOC]:
    if not artifact.strings or not artifact.strings.ioc_samples:
        return []
    ioc_type_map = {
        "ipv4": IOCType.IPV4,
        "ipv6": IOCType.IPV6,
        "domain": IOCType.DOMAIN,
        "hostname": IOCType.HOSTNAME,
        "url": IOCType.URL,
        "email": IOCType.EMAIL,
        "path_windows": IOCType.FILE_PATH,
        "path_posix": IOCType.FILE_PATH,
        "path_unc": IOCType.FILE_PATH,
        "registry": IOCType.REGISTRY_KEY,
    }
    candidates: List[IOCCandidate] = []
    for sample in artifact.strings.ioc_samples[:max_batch_size]:
        ioc_type = ioc_type_map.get(sample.kind, IOCType.HOSTNAME)
        candidates.append(
            IOCCandidate(
                value=sample.text,
                ioc_type=ioc_type,
                offset=getattr(sample, "offset", None),
            )
        )
    context = MemoryContext(
        artifact=artifact, file_path=getattr(artifact, "path", "unknown")
    )
    validator = create_contextual_ioc_validator(context, model)
    batch = IOCValidationBatch(
        candidates=candidates,
        binary_format=str(artifact.verdicts[0].format) if artifact.verdicts else None,
    )
    result = validator.run_sync(
        f"Validate {len(candidates)} IOC candidates from {artifact.path}", deps=batch
    )
    return [ioc for ioc in result.output.validated_iocs if ioc.is_valid]
