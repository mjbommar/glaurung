from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class JavaModuleRequireSummary(BaseModel):
    module: str
    flags: int
    version: str | None = None


class JavaModulePackageSummary(BaseModel):
    package: str
    flags: int
    targets: list[str] = Field(default_factory=list)


class JavaModuleProvideSummary(BaseModel):
    service: str
    implementations: list[str] = Field(default_factory=list)


class JavaModuleSummary(BaseModel):
    name: str
    flags: int
    version: str | None = None
    requires: list[JavaModuleRequireSummary] = Field(default_factory=list)
    exports: list[JavaModulePackageSummary] = Field(default_factory=list)
    opens: list[JavaModulePackageSummary] = Field(default_factory=list)
    uses: list[str] = Field(default_factory=list)
    provides: list[JavaModuleProvideSummary] = Field(default_factory=list)


def module_summary(value: Any) -> JavaModuleSummary | None:
    """Return a normalized JPMS module summary from parsed classfile data."""
    if not isinstance(value, dict):
        return None
    return JavaModuleSummary.model_validate(value)
