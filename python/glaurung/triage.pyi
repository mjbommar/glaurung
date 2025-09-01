from __future__ import annotations
from typing import List, Optional

class SnifferSource:
    Infer: SnifferSource
    MimeGuess: SnifferSource
    Other: SnifferSource
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...

class TriageHint:
    source: SnifferSource
    mime: Optional[str]
    extension: Optional[str]
    label: Optional[str]
    def __init__(
        self,
        source: SnifferSource,
        mime: Optional[str] = ...,
        extension: Optional[str] = ...,
        label: Optional[str] = ...,
    ) -> None: ...
    def __repr__(self) -> str: ...

class TriageErrorKind:
    ShortRead: TriageErrorKind
    BadMagic: TriageErrorKind
    IncoherentFields: TriageErrorKind
    UnsupportedVariant: TriageErrorKind
    Truncated: TriageErrorKind
    BudgetExceeded: TriageErrorKind
    ParserMismatch: TriageErrorKind
    SnifferMismatch: TriageErrorKind
    Other: TriageErrorKind
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...

class TriageError:
    kind: TriageErrorKind
    message: Optional[str]
    def __init__(self, kind: TriageErrorKind, message: Optional[str] = ...) -> None: ...
    def __repr__(self) -> str: ...

class ConfidenceSignal:
    name: str
    score: float
    notes: Optional[str]
    def __init__(self, name: str, score: float, notes: Optional[str] = ...) -> None: ...

class ParserKind:
    Object: ParserKind
    Goblin: ParserKind
    PELite: ParserKind
    Nom: ParserKind
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...

class ParserResult:
    parser: ParserKind
    ok: bool
    error: Optional[TriageError]
    def __init__(
        self, parser: ParserKind, ok: bool, error: Optional[TriageError] = ...
    ) -> None: ...

class EntropySummary:
    overall: Optional[float]
    window_size: Optional[int]
    windows: Optional[List[float]]
    def __init__(
        self,
        overall: Optional[float] = ...,
        window_size: Optional[int] = ...,
        windows: Optional[List[float]] = ...,
    ) -> None: ...

class StringsSummary:
    ascii_count: int
    utf16le_count: int
    utf16be_count: int
    samples: Optional[List[str]]
    def __init__(
        self,
        ascii_count: int,
        utf16le_count: int,
        utf16be_count: int,
        samples: Optional[List[str]] = ...,
    ) -> None: ...

class PackerMatch:
    name: str
    confidence: float
    def __init__(self, name: str, confidence: float) -> None: ...

class ContainerChild:
    type_name: str
    offset: int
    size: int
    def __init__(self, type_name: str, offset: int, size: int) -> None: ...

class Budgets:
    bytes_read: int
    time_ms: int
    recursion_depth: int
    def __init__(self, bytes_read: int, time_ms: int, recursion_depth: int) -> None: ...

class TriageVerdict:
    from glaurung import Format, Arch, Endianness

    format: Format
    arch: Arch
    bits: int
    endianness: Endianness
    confidence: float
    signals: Optional[List[ConfidenceSignal]]
    def __init__(
        self,
        format: Format,
        arch: Arch,
        bits: int,
        endianness: Endianness,
        confidence: float,
        signals: Optional[List[ConfidenceSignal]] = ...,
    ) -> None: ...

class TriagedArtifact:
    id: str
    path: str
    size_bytes: int
    sha256: Optional[str]
    hints: List[TriageHint]
    verdicts: List[TriageVerdict]
    entropy: Optional[EntropySummary]
    strings: Optional[StringsSummary]
    packers: Optional[List[PackerMatch]]
    containers: Optional[List[ContainerChild]]
    parse_status: Optional[List[ParserResult]]
    budgets: Optional[Budgets]
    errors: Optional[List[TriageError]]
    def __init__(
        self,
        id: str,
        path: str,
        size_bytes: int,
        sha256: Optional[str] = ...,
        hints: list[TriageHint] = ...,
        verdicts: list[TriageVerdict] = ...,
        entropy: Optional[EntropySummary] = ...,
        strings: Optional[StringsSummary] = ...,
        packers: Optional[list[PackerMatch]] = ...,
        containers: Optional[list[ContainerChild]] = ...,
        parse_status: Optional[list[ParserResult]] = ...,
        budgets: Optional[Budgets] = ...,
        errors: Optional[list[TriageError]] = ...,
    ) -> None: ...
    def to_json(self) -> str: ...
    @staticmethod
    def from_json(json_str: str) -> TriagedArtifact: ...
