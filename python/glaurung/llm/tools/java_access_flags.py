from __future__ import annotations

from typing import Literal


JavaAccessFlagKind = Literal["class", "field", "method", "inner_class", "parameter"]


_FLAGS: dict[JavaAccessFlagKind, tuple[tuple[int, str], ...]] = {
    "class": (
        (0x0001, "public"),
        (0x0010, "final"),
        (0x0020, "super"),
        (0x0200, "interface"),
        (0x0400, "abstract"),
        (0x1000, "synthetic"),
        (0x2000, "annotation"),
        (0x4000, "enum"),
        (0x8000, "module"),
    ),
    "field": (
        (0x0001, "public"),
        (0x0002, "private"),
        (0x0004, "protected"),
        (0x0008, "static"),
        (0x0010, "final"),
        (0x0040, "volatile"),
        (0x0080, "transient"),
        (0x1000, "synthetic"),
        (0x4000, "enum"),
    ),
    "method": (
        (0x0001, "public"),
        (0x0002, "private"),
        (0x0004, "protected"),
        (0x0008, "static"),
        (0x0010, "final"),
        (0x0020, "synchronized"),
        (0x0040, "bridge"),
        (0x0080, "varargs"),
        (0x0100, "native"),
        (0x0400, "abstract"),
        (0x0800, "strict"),
        (0x1000, "synthetic"),
    ),
    "inner_class": (
        (0x0001, "public"),
        (0x0002, "private"),
        (0x0004, "protected"),
        (0x0008, "static"),
        (0x0010, "final"),
        (0x0200, "interface"),
        (0x0400, "abstract"),
        (0x1000, "synthetic"),
        (0x2000, "annotation"),
        (0x4000, "enum"),
    ),
    "parameter": (
        (0x0010, "final"),
        (0x1000, "synthetic"),
        (0x8000, "mandated"),
    ),
}


def access_flag_names(flags: int, kind: JavaAccessFlagKind) -> list[str]:
    """Return JVM access flag names for the supplied access-flag context."""
    return [name for bit, name in _FLAGS[kind] if flags & bit]
