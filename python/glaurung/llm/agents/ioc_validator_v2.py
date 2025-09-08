"""IOC validation agent V2 (compat)."""

from typing import List, Dict, Optional, Literal, Tuple
from enum import Enum
from pydantic import BaseModel, model_validator
from pydantic_ai import Agent

from ..config import get_config


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
    value: str
    ioc_type: IOCType
    offset: Optional[int] = None
    context: Optional[str] = None
    encoding: Optional[str] = None


class IOCValidationDecision(BaseModel):
    candidate_index: int
    is_valid: bool
    confidence: float
    reasoning: str
    risk_level: Optional[Literal["low", "medium", "high", "critical"]] = None
    category: Optional[str] = None


class IOCValidationOutput(BaseModel):
    decisions: List[IOCValidationDecision]
    summary: str

    @model_validator(mode="after")
    def validate_decisions(self):
        seen = set()
        for d in self.decisions:
            if d.candidate_index in seen:
                raise ValueError(f"Duplicate validation for index {d.candidate_index}")
            seen.add(d.candidate_index)
        return self


class ValidatedIOC(BaseModel):
    value: str
    ioc_type: IOCType
    is_valid: bool
    confidence: float
    reasoning: str
    risk_level: Optional[Literal["low", "medium", "high", "critical"]]
    category: Optional[str]
    offset: Optional[int]
    context: Optional[str]


IOC_VALIDATOR_PROMPT_V2 = (
    "You are an expert cybersecurity analyst specializing in IOC validation.\n"
    "Your task is to validate a numbered list of IOC candidates and determine which are real threats vs false positives.\n\n"
    "CRITICAL RULES: Reference each IOC by its 0-based index only; do not create new IOCs."
)


def create_ioc_validator_v2(
    model: Optional[str] = None,
) -> Agent[Dict, IOCValidationOutput]:
    config = get_config()
    default_model = (
        (config.ioc_model or config.default_model)
        if any(config.available_models().values())
        else "test"
    )
    model = model or default_model
    return Agent(
        model=model,
        system_prompt=IOC_VALIDATOR_PROMPT_V2,
        output_type=IOCValidationOutput,
    )


def validate_iocs_v2(
    candidates: List[IOCCandidate],
    binary_format: Optional[str] = None,
    binary_type: Optional[str] = None,
    model: Optional[str] = None,
) -> Tuple[List[ValidatedIOC], int, int]:
    if not candidates:
        return [], 0, 0

    lst = "\n".join(
        f"{i}. [{c.ioc_type.value}] {c.value}"
        + (f" (context: {c.context})" if c.context else "")
        for i, c in enumerate(candidates)
    )
    prompt = (
        f"Validate these {len(candidates)} IOC candidates from a {binary_format or 'unknown'} binary:\n\n"
        f"{lst}\n\nFor each IOC, provide a validation decision referencing it by index."
    )
    agent = create_ioc_validator_v2(model)
    result = agent.run_sync(
        prompt,
        deps={
            "candidates": candidates,
            "binary_format": binary_format,
            "binary_type": binary_type,
        },
    )
    output = result.output

    decision_map = {d.candidate_index: d for d in output.decisions}
    validated: List[ValidatedIOC] = []
    tp = fp = 0
    for i, c in enumerate(candidates):
        d = decision_map.get(i)
        if not d:
            validated.append(
                ValidatedIOC(
                    value=c.value,
                    ioc_type=c.ioc_type,
                    is_valid=False,
                    confidence=0.5,
                    reasoning="No validation decision provided",
                    risk_level=None,
                    category=None,
                    offset=c.offset,
                    context=c.context,
                )
            )
            fp += 1
            continue
        if d.candidate_index != i:
            raise ValueError(f"Index mismatch: expected {i}, got {d.candidate_index}")
        v = ValidatedIOC(
            value=c.value,
            ioc_type=c.ioc_type,
            is_valid=d.is_valid,
            confidence=d.confidence,
            reasoning=d.reasoning,
            risk_level=d.risk_level,
            category=d.category,
            offset=c.offset,
            context=c.context,
        )
        validated.append(v)
        if d.is_valid:
            tp += 1
        else:
            fp += 1

    for v in validated:
        if v.value not in [c.value for c in candidates]:
            raise ValueError(f"Hallucinated IOC detected: {v.value}")
    return validated, tp, fp


def filter_iocs_from_artifact_v2(
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
    for s in artifact.strings.ioc_samples[:max_batch_size]:
        candidates.append(
            IOCCandidate(
                value=s.text,
                ioc_type=ioc_type_map.get(s.kind, IOCType.HOSTNAME),
                offset=getattr(s, "offset", None),
            )
        )
    validated, _, _ = validate_iocs_v2(
        candidates,
        binary_format=str(artifact.verdicts[0].format) if artifact.verdicts else None,
        model=model,
    )
    return [v for v in validated if v.is_valid]
