"""
Python-friendly re-exports for triage types.

These map directly to the Rust types in `glaurung._native.triage`.
"""

import glaurung._native as _native  # type: ignore

# Import triage types from the triage attribute
SnifferSource = _native.triage.SnifferSource
TriageHint = _native.triage.TriageHint
TriageErrorKind = _native.triage.TriageErrorKind
TriageError = _native.triage.TriageError
ConfidenceSignal = _native.triage.ConfidenceSignal
ParserKind = _native.triage.ParserKind
ParserResult = _native.triage.ParserResult
EntropySummary = _native.triage.EntropySummary
DetectedString = _native.triage.DetectedString
StringsSummary = _native.triage.StringsSummary
IocSample = _native.triage.IocSample
try:
    SymbolSummary = _native.triage.SymbolSummary  # type: ignore[attr-defined]
except AttributeError:  # Backward-compatible with older native modules
    SymbolSummary = None  # type: ignore[assignment]
PackerMatch = _native.triage.PackerMatch
ContainerChild = _native.triage.ContainerChild
Budgets = _native.triage.Budgets
TriageVerdict = _native.triage.TriageVerdict
TriagedArtifact = _native.triage.TriagedArtifact
# Overlay detection types
OverlayAnalysis = _native.triage.OverlayAnalysis
OverlayFormat = _native.triage.OverlayFormat

IOConfig = _native.triage.IOConfig
EntropyConfig = _native.triage.EntropyConfig
EntropyThresholds = _native.triage.EntropyThresholds
EntropyWeights = _native.triage.EntropyWeights
HeuristicsConfig = _native.triage.HeuristicsConfig
ScoringConfig = _native.triage.ScoringConfig
PackerConfig = _native.triage.PackerConfig
HeaderConfig = _native.triage.HeaderConfig
ParserConfig = _native.triage.ParserConfig
SimilarityConfig = _native.triage.SimilarityConfig


class _IOProxy:
    __slots__ = ("_owner", "_native")

    def __init__(self, owner, native):
        self._owner = owner
        self._native = native

    def __getattr__(self, name):  # pragma: no cover - simple delegation
        return getattr(self._native, name)

    def __setattr__(self, name, value):
        if name in {"_owner", "_native"}:
            object.__setattr__(self, name, value)
            return
        setattr(self._native, name, value)
        # Commit back to owner via property setter
        self._owner._native.io = self._native


class _ThresholdsProxy:
    __slots__ = ("_entropy", "_native")

    def __init__(self, entropy_proxy, native):
        self._entropy = entropy_proxy
        self._native = native

    def __getattr__(self, name):  # pragma: no cover - simple delegation
        return getattr(self._native, name)

    def __setattr__(self, name, value):
        if name in {"_entropy", "_native"}:
            object.__setattr__(self, name, value)
            return
        setattr(self._native, name, value)
        # Update parent entropy config then commit to owner
        self._entropy._native.thresholds = self._native
        self._entropy._owner._native.entropy = self._entropy._native


class _WeightsProxy:
    __slots__ = ("_entropy", "_native")

    def __init__(self, entropy_proxy, native):
        self._entropy = entropy_proxy
        self._native = native

    def __getattr__(self, name):  # pragma: no cover - simple delegation
        return getattr(self._native, name)

    def __setattr__(self, name, value):
        if name in {"_entropy", "_native"}:
            object.__setattr__(self, name, value)
            return
        setattr(self._native, name, value)
        self._entropy._native.weights = self._native
        self._entropy._owner._native.entropy = self._entropy._native


class _EntropyProxy:
    __slots__ = ("_owner", "_native")

    def __init__(self, owner, native):
        self._owner = owner
        self._native = native

    def __getattr__(self, name):  # pragma: no cover - simple delegation
        if name == "thresholds":
            return _ThresholdsProxy(self, self._native.thresholds)
        if name == "weights":
            return _WeightsProxy(self, self._native.weights)
        return getattr(self._native, name)

    def __setattr__(self, name, value):
        if name in {"_owner", "_native"}:
            object.__setattr__(self, name, value)
            return
        setattr(self._native, name, value)
        self._owner._native.entropy = self._native


class _ScoringProxy:
    __slots__ = ("_owner", "_native")

    def __init__(self, owner, native):
        self._owner = owner
        self._native = native

    def __getattr__(self, name):  # pragma: no cover - simple delegation
        return getattr(self._native, name)

    def __setattr__(self, name, value):
        if name in {"_owner", "_native"}:
            object.__setattr__(self, name, value)
            return
        setattr(self._native, name, value)
        self._owner._native.scoring = self._native


class TriageConfig:
    """Python wrapper around native TriageConfig that keeps nested changes in sync."""

    __slots__ = ("_native",)

    def __init__(self):
        self._native = _native.triage.TriageConfig()

    @property
    def io(self) -> _IOProxy:
        return _IOProxy(self, self._native.io)

    @property
    def entropy(self) -> _EntropyProxy:
        return _EntropyProxy(self, self._native.entropy)

    @property
    def scoring(self) -> _ScoringProxy:
        return _ScoringProxy(self, self._native.scoring)

    @property
    def packers(self) -> PackerConfig:
        """Direct access to PackerConfig (mutable)."""
        return self._native.packers

    @packers.setter
    def packers(self, cfg: PackerConfig) -> None:  # pragma: no cover - trivial setter
        self._native.packers = cfg

    @property
    def similarity(self) -> SimilarityConfig:
        """Direct access to SimilarityConfig (mutable)."""
        return self._native.similarity

    @similarity.setter
    def similarity(self, cfg: SimilarityConfig) -> None:  # pragma: no cover
        self._native.similarity = cfg

# Import triage functions
analyze_bytes = _native.triage.analyze_bytes
analyze_path = _native.triage.analyze_path

__all__ = [
    "SnifferSource",
    "TriageHint",
    "TriageErrorKind",
    "TriageError",
    "ConfidenceSignal",
    "ParserKind",
    "ParserResult",
    "EntropySummary",
    "DetectedString",
    "StringsSummary",
    "IocSample",
    "SymbolSummary",
    "PackerMatch",
    "ContainerChild",
    "Budgets",
    "TriageVerdict",
    "TriagedArtifact",
    "OverlayAnalysis",
    "OverlayFormat",
    # Configs
    "TriageConfig",
    "IOConfig",
    "EntropyConfig",
    "EntropyThresholds",
    "EntropyWeights",
    "HeuristicsConfig",
    "ScoringConfig",
    "PackerConfig",
    "SimilarityConfig",
    "HeaderConfig",
    "ParserConfig",
    "analyze_bytes",
    "analyze_path",
]
