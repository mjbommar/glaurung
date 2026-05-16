from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


ClassfileSizeCategory = Literal[
    "unknown", "empty", "tiny", "normal", "large", "very_large"
]

MIN_CLASSFILE_MAJOR_VERSION = 45
MAX_KNOWN_CLASSFILE_MAJOR_VERSION = 70
MAX_KNOWN_JAVA_RELEASE_LABEL = "Java SE 26"
PREVIEW_MINOR_VERSION = 65535
LARGE_CLASSFILE_BYTES = 1 * 1024 * 1024
VERY_LARGE_CLASSFILE_BYTES = 10 * 1024 * 1024


class JavaClassfilePolicySummary(BaseModel):
    major_version: int
    minor_version: int
    java_release: int | None = None
    java_release_label: str | None = None
    classfile_version_label: str
    is_preview_classfile: bool = False
    classfile_size: int | None = None
    classfile_size_category: ClassfileSizeCategory = "unknown"
    classfile_warnings: list[str] = Field(default_factory=list)


def java_release_for_major(major_version: int) -> int | None:
    """Return the Java SE release number for classfile majors with one."""
    if major_version >= 49:
        return major_version - 44
    return None


def java_release_label_for_major(major_version: int) -> str | None:
    """Return a human-readable Java release label for a classfile major version."""
    legacy_labels = {
        45: "Java 1.1",
        46: "Java 1.2",
        47: "Java 1.3",
        48: "Java 1.4",
    }
    if major_version in legacy_labels:
        return legacy_labels[major_version]
    release = java_release_for_major(major_version)
    if release is not None:
        return f"Java {release}"
    return None


def classfile_version_label(major_version: int, minor_version: int) -> str:
    """Return a readable JVM classfile version label."""
    release_label = java_release_label_for_major(major_version)
    version = f"classfile {major_version}.{minor_version}"
    if release_label is None:
        return version
    return f"{release_label} ({version})"


def classfile_policy(
    major_version: int,
    minor_version: int,
    *,
    size_bytes: int | None = None,
) -> JavaClassfilePolicySummary:
    """Summarize classfile version and size policy for parser-facing tools."""
    warnings: list[str] = []
    is_preview = minor_version == PREVIEW_MINOR_VERSION
    if major_version < MIN_CLASSFILE_MAJOR_VERSION:
        warnings.append(
            "Classfile major version is below the standard JVM classfile range."
        )
    if major_version > MAX_KNOWN_CLASSFILE_MAJOR_VERSION:
        warnings.append(
            f"Classfile major version is newer than {MAX_KNOWN_JAVA_RELEASE_LABEL}; "
            "analysis may need a newer JVM/toolchain."
        )
    if minor_version not in {0, PREVIEW_MINOR_VERSION}:
        warnings.append("Classfile minor version is unusual; expected 0 or 65535.")
    if is_preview:
        if major_version >= 56:
            warnings.append("Classfile uses Java preview features.")
        else:
            warnings.append(
                "Classfile uses preview minor version before Java 12 standardized it."
            )

    size_category = _size_category(size_bytes)
    if size_category == "empty":
        warnings.append("Classfile entry is empty.")
    elif size_category == "tiny":
        warnings.append("Classfile entry is too small to contain a valid classfile.")
    elif size_category == "large":
        warnings.append(
            "Classfile entry is large; generated or packed code is possible."
        )
    elif size_category == "very_large":
        warnings.append(
            "Classfile entry is very large; generated, packed, or adversarial code is possible."
        )

    return JavaClassfilePolicySummary(
        major_version=major_version,
        minor_version=minor_version,
        java_release=java_release_for_major(major_version),
        java_release_label=java_release_label_for_major(major_version),
        classfile_version_label=classfile_version_label(major_version, minor_version),
        is_preview_classfile=is_preview,
        classfile_size=size_bytes,
        classfile_size_category=size_category,
        classfile_warnings=warnings,
    )


def _size_category(size_bytes: int | None) -> ClassfileSizeCategory:
    if size_bytes is None:
        return "unknown"
    if size_bytes == 0:
        return "empty"
    if size_bytes < 10:
        return "tiny"
    if size_bytes >= VERY_LARGE_CLASSFILE_BYTES:
        return "very_large"
    if size_bytes >= LARGE_CLASSFILE_BYTES:
        return "large"
    return "normal"
