from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class JavaDescriptorSummary(BaseModel):
    kind: Literal["method", "field", "invalid"]
    parameter_types: list[str] = Field(default_factory=list)
    parameter_count: int = 0
    return_type: str | None = None
    field_type: str | None = None
    error: str | None = None


_PRIMITIVE_TYPES = {
    "B": "byte",
    "C": "char",
    "D": "double",
    "F": "float",
    "I": "int",
    "J": "long",
    "S": "short",
    "Z": "boolean",
    "V": "void",
}


def decode_method_descriptor(descriptor: str) -> JavaDescriptorSummary:
    try:
        if not descriptor.startswith("("):
            raise ValueError("method descriptor must start with '('")
        pos = 1
        parameter_types: list[str] = []
        while pos < len(descriptor) and descriptor[pos] != ")":
            java_type, pos = _parse_type(descriptor, pos, allow_void=False)
            parameter_types.append(java_type)
        if pos >= len(descriptor) or descriptor[pos] != ")":
            raise ValueError("method descriptor missing ')'")
        return_type, pos = _parse_type(descriptor, pos + 1, allow_void=True)
        if pos != len(descriptor):
            raise ValueError("method descriptor has trailing data")
        return JavaDescriptorSummary(
            kind="method",
            parameter_types=parameter_types,
            parameter_count=len(parameter_types),
            return_type=return_type,
        )
    except ValueError as exc:
        return JavaDescriptorSummary(kind="invalid", error=str(exc))


def decode_field_descriptor(descriptor: str) -> JavaDescriptorSummary:
    try:
        field_type, pos = _parse_type(descriptor, 0, allow_void=False)
        if pos != len(descriptor):
            raise ValueError("field descriptor has trailing data")
        return JavaDescriptorSummary(kind="field", field_type=field_type)
    except ValueError as exc:
        return JavaDescriptorSummary(kind="invalid", error=str(exc))


def _parse_type(
    descriptor: str,
    pos: int,
    *,
    allow_void: bool,
) -> tuple[str, int]:
    dimensions = 0
    while pos < len(descriptor) and descriptor[pos] == "[":
        dimensions += 1
        pos += 1
    if pos >= len(descriptor):
        raise ValueError("descriptor ended inside type")
    tag = descriptor[pos]
    if tag == "L":
        end = descriptor.find(";", pos)
        if end == -1:
            raise ValueError("object type missing ';'")
        java_type = descriptor[pos + 1 : end].replace("/", ".")
        pos = end + 1
    elif tag in _PRIMITIVE_TYPES:
        if tag == "V" and (dimensions or not allow_void):
            raise ValueError("void is only valid as a method return type")
        java_type = _PRIMITIVE_TYPES[tag]
        pos += 1
    else:
        raise ValueError(f"unknown descriptor tag {tag!r}")
    if dimensions:
        java_type += "[]" * dimensions
    return java_type, pos
