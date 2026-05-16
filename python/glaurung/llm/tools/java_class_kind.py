from __future__ import annotations

from typing import Any, Literal


JavaClassKind = Literal["module", "annotation", "interface", "enum", "record", "class"]


def class_kind(
    *,
    class_name: str,
    access_flags: int,
    super_class: str | None,
    record_components: Any,
    module_info: Any,
) -> JavaClassKind:
    """Return a normalized Java class declaration kind."""
    if access_flags & 0x8000 or class_name == "module-info" or module_info is not None:
        return "module"
    if access_flags & 0x2000:
        return "annotation"
    if access_flags & 0x0200:
        return "interface"
    if access_flags & 0x4000:
        return "enum"
    if super_class == "java/lang/Record" or _list_count(record_components) > 0:
        return "record"
    return "class"


def _list_count(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0
