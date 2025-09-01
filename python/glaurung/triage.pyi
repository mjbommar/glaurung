from __future__ import annotations
from typing import List, Optional, Dict, Any

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
    mean: Optional[float]
    std_dev: Optional[float]
    min: Optional[float]
    max: Optional[float]
    def __init__(
        self,
        overall: Optional[float] = ...,
        window_size: Optional[int] = ...,
        windows: Optional[List[float]] = ...,
    ) -> None: ...

class EntropyClass:
    def value(self) -> float: ...

class EntropyAnomaly:
    index: int
    from_value: float  # Renamed from 'from' to avoid Python keyword conflict
    to_value: float    # Renamed for consistency
    to: float          # Also available for backward compatibility
    delta: float

class PackedIndicators:
    has_low_entropy_header: bool
    has_high_entropy_body: bool
    entropy_cliff: Optional[int]
    verdict: float

def entropy_of_bytes(data: bytes) -> float: ...
def compute_entropy(
    data: bytes,
    window_size: int = ...,
    step: int = ...,
    max_windows: int = ...,
    overall: bool = ...,
    header_size: int = ...,
) -> EntropySummary: ...
def analyze_entropy_bytes(
    data: bytes,
    window_size: int = ...,
    step: int = ...,
    max_windows: int = ...,
    header_size: int = ...,
) -> EntropyAnalysis: ...

class EntropyAnalysis:
    summary: EntropySummary
    classification: EntropyClass
    packed_indicators: PackedIndicators
    anomalies: list[EntropyAnomaly]
    def __init__(self) -> None: ...

class StringsSummary:
    ascii_count: int
    utf16le_count: int
    utf16be_count: int
    strings: Optional[List[DetectedString]]
    language_counts: Optional[Dict[str, int]]
    script_counts: Optional[Dict[str, int]]
    samples: Optional[List[str]]
    def __init__(
        self,
        ascii_count: int,
        utf16le_count: int,
        utf16be_count: int,
        strings: Optional[List[DetectedString]] = ...,
        language_counts: Optional[Dict[str, int]] = ...,
        script_counts: Optional[Dict[str, int]] = ...,
    ) -> None: ...

class DetectedString:
    text: str
    encoding: str
    language: Optional[str]
    script: Optional[str]
    confidence: Optional[float]
    offset: Optional[int]

class PackerMatch:
    name: str
    confidence: float
    def __init__(self, name: str, confidence: float) -> None: ...

class ContainerChild:
    type_name: str
    offset: int
    size: int
    def __init__(self, type_name: str, offset: int, size: int) -> None: ...

class ContainerMetadata:
    """Metadata about container contents."""
    file_count: Optional[int]
    total_uncompressed_size: Optional[int]
    total_compressed_size: Optional[int]
    def __init__(
        self,
        file_count: Optional[int] = None,
        total_uncompressed_size: Optional[int] = None,
        total_compressed_size: Optional[int] = None,
    ) -> None: ...

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
    entropy_analysis: Optional[EntropyAnalysis]
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
        entropy_analysis: Optional[EntropyAnalysis] = ...,
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

# Triage analysis functions
def analyze_path(path: str, _max_read_bytes: int = ..., _max_file_size: int = ..., _max_recursion_depth: int = ...) -> TriagedArtifact: ...(
    path: str,
    max_read_bytes: int = 10_485_760,
    max_file_size: int = 104_857_600,
) -> TriagedArtifact:
    """
    Analyze a file at the given path.
    
    Args:
        path: Path to the file to analyze
        max_read_bytes: Maximum bytes to read for analysis (default 10MB)
        max_file_size: Maximum file size to analyze (default 100MB)
    
    Returns:
        TriagedArtifact containing analysis results
    """
    ...

def analyze_bytes(data: bytes, _max_read_bytes: int = ..., _max_recursion_depth: int = ...) -> TriagedArtifact: ...(
    data: bytes,
    max_read_bytes: int = 10_485_760,
) -> TriagedArtifact:
    """
    Analyze raw bytes.
    
    Args:
        data: Bytes to analyze
        max_read_bytes: Maximum bytes to read for analysis (default 10MB)
    
    Returns:
        TriagedArtifact containing analysis results
    """
    ...
