"""
Python-friendly re-exports for triage types.

These map directly to the Rust types in `glaurung._native.triage`.
"""

import glaurung._native as _native  # type: ignore
from typing import Any

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
# Keep the Python wrapper's runtime surface aligned with ``triage.pyi`` and
# the native module.  Importing ``glaurung.triage`` replaces the package's
# initial native-module alias with this file; without these passthroughs,
# callers such as ``windows-risk`` lose symbol enumeration depending solely
# on import order.
list_symbols = _native.triage.list_symbols
list_symbols_demangled = _native.triage.list_symbols_demangled


class _StringsProxy:
    __slots__ = ("_ss", "_path")

    def __init__(self, native_ss: Any, path: str):
        self._ss = native_ss
        self._path = path

    def __getattr__(self, name):  # pragma: no cover - simple delegation/augmentation
        if name == "ioc_counts":
            base = dict(getattr(self._ss, "ioc_counts", {}) or {})
            if base.get("ipv4", 0) == 0:
                texts: list[str] = []
                try:
                    if getattr(self._ss, "strings", None):
                        texts.extend(
                            [
                                getattr(s, "text", "")
                                for s in self._ss.strings
                                if getattr(s, "text", None)
                            ]
                        )
                    if getattr(self._ss, "samples", None):
                        texts.extend(
                            [t for t in self._ss.samples if isinstance(t, str)]
                        )
                    if not texts and self._path:
                        with open(
                            self._path, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            texts.append(f.read())
                    import re

                    ipv4_re = re.compile(
                        r"\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b"
                    )
                    base["ipv4"] = sum(len(ipv4_re.findall(t)) for t in texts)
                except Exception:
                    pass
            return base
        return getattr(self._ss, name)


class _ArtifactProxy:
    __slots__ = ("_art",)

    def __init__(self, art: Any):
        self._art = art

    def __getattr__(self, name):  # pragma: no cover - simple delegation
        if name == "strings":
            ss = getattr(self._art, "strings", None)
            return (
                _StringsProxy(ss, getattr(self._art, "path", ""))
                if ss is not None
                else None
            )
        return getattr(self._art, name)


def analyze_path(
    path: str,
    max_read_bytes: int = 10_485_760,
    max_file_size: int = 104_857_600,
    max_depth: int = 1,
    str_min_len: int = 4,
    str_max_samples: int = 40,
    str_lang: bool = True,
    str_max_lang_detect: int = 100,
    str_classify: bool = True,
    str_max_classify: int = 200,
    str_max_ioc_per_string: int = 16,
):
    """Wrapper around native analyze_path with stable defaults.

    Falls back to older signatures if the native extension doesn't support
    extended string-analysis parameters.
    """
    art = _native.triage.analyze_path(
        path,
        max_read_bytes,
        max_file_size,
        max_depth,
        str_min_len,
        str_max_samples,
        str_lang,
        str_max_lang_detect,
        str_classify,
        str_max_classify,
        str_max_ioc_per_string,
    )
    return _ArtifactProxy(art)


def triage(
    path: str,
    max_read_bytes: int = 10_485_760,
    max_file_size: int = 104_857_600,
    max_depth: int = 1,
    str_min_len: int = 4,
    str_max_samples: int = 40,
    str_lang: bool = True,
    str_max_lang_detect: int = 100,
    str_classify: bool = True,
    str_max_classify: int = 200,
    str_max_ioc_per_string: int = 16,
):
    """Convenience wrapper around analyze_path with sane defaults.

    Provides a stable signature for tests and examples. Falls back to older native
    extension signatures if needed for compatibility.
    """
    art = analyze_path(
        path,
        max_read_bytes,
        max_file_size,
        max_depth,
        str_min_len,
        str_max_samples,
        str_lang,
        str_max_lang_detect,
        str_classify,
        str_max_classify,
        str_max_ioc_per_string,
    )
    return art


def _augment_ioc_counts(art: TriagedArtifact) -> None:
    """Augment missing IOC counts for common types using Python-level regex.

    This provides a consistent surface when some engines omit certain counters.
    """
    try:
        ss = getattr(art, "strings", None)
        if not ss:
            return
        counts = getattr(ss, "ioc_counts", None)
        # Only augment when missing or clearly zero
        need_ipv4 = counts is None or counts.get("ipv4", 0) == 0
        if not need_ipv4:
            return
        texts: list[str] = []
        if getattr(ss, "strings", None):
            texts.extend(
                [getattr(s, "text", "") for s in ss.strings if getattr(s, "text", None)]
            )
        if getattr(ss, "samples", None):
            texts.extend([t for t in ss.samples if isinstance(t, str)])
        if not texts:
            # Fallback: read the file content for text IOCs (small files)
            try:
                with open(
                    getattr(art, "path", ""), "r", encoding="utf-8", errors="ignore"
                ) as f:
                    texts.append(f.read())
            except Exception:
                return
        import re

        ipv4_re = re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
        )
        ipv4_total = 0
        for t in texts:
            ipv4_total += len(ipv4_re.findall(t))
        if ipv4_total > 0:
            if counts is None:
                counts = {"ipv4": ipv4_total}
                setattr(ss, "ioc_counts", counts)
            else:
                counts["ipv4"] = counts.get("ipv4", 0) + ipv4_total
    except Exception:
        # Best-effort augmentation only
        return


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
    "list_symbols",
    "list_symbols_demangled",
    "triage",
]

# Every name in `__all__` is bound unconditionally above, so a native module
# that stops exporting one fails at import rather than silently shrinking the
# public surface.  This replaces three `try: ... except AttributeError: pass`
# blocks that named 59 PE/ELF/Mach-O types: 52 of them were never Rust types at
# all, and the remaining 7 (PeTriageInfo, ElfTriageInfo, MachOTriageInfo,
# ElfType, ElfMachine, RichHeader, RichHeaderEntry) exist in Rust but are not
# registered on `_native.triage`.  Each block therefore died on its own first
# line and `__all__` never gained a single one of the 59 names -- 59 failures
# hidden behind three silent `pass` statements.
_missing = sorted(name for name in __all__ if name not in globals())
if _missing:  # pragma: no cover - only reachable against a mismatched build
    raise ImportError(
        "glaurung.triage exports names the native module does not provide: "
        + ", ".join(_missing)
    )
del _missing
