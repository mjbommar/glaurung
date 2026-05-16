from __future__ import annotations

from collections import Counter
from typing import Any


def code_xref_counts(code: Any) -> dict[str, int]:
    """Return stable bytecode xref count buckets for parsed Code data."""
    if not isinstance(code, dict):
        return _empty_counts()
    xrefs = [xref for xref in code.get("xrefs", []) if isinstance(xref, dict)]
    kinds = Counter(str(xref.get("kind", "")) for xref in xrefs)
    method_count = kinds["method"] + kinds["interface_method"]
    dynamic_count = kinds["dynamic"] + kinds["invokedynamic"]
    return {
        "xref_count": len(xrefs),
        "method_xref_count": method_count,
        "field_xref_count": kinds["field"],
        "class_xref_count": kinds["class"],
        "string_xref_count": kinds["string"],
        "dynamic_xref_count": dynamic_count,
    }


def _empty_counts() -> dict[str, int]:
    return {
        "xref_count": 0,
        "method_xref_count": 0,
        "field_xref_count": 0,
        "class_xref_count": 0,
        "string_xref_count": 0,
        "dynamic_xref_count": 0,
    }
