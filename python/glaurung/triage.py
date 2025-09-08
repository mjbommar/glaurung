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
    "triage",
]


try:
    # PE-specific types
    PeTriageInfo = _native.triage.PeTriageInfo
    PeSubsystem = _native.triage.PeSubsystem
    PeMachine = _native.triage.PeMachine
    PeCharacteristics = _native.triage.PeCharacteristics
    PeDllCharacteristics = _native.triage.PeDllCharacteristics
    PeDebugInfo = _native.triage.PeDebugInfo
    PePdbInfo = _native.triage.PePdbInfo
    PeImport = _native.triage.PeImport
    PeExport = _native.triage.PeExport
    PeResource = _native.triage.PeResource
    PeResourceType = _native.triage.PeResourceType
    PeVersionInfo = _native.triage.PeVersionInfo
    PeTlsInfo = _native.triage.PeTlsInfo
    PeLoadConfig = _native.triage.PeLoadConfig
    PeRelocation = _native.triage.PeRelocation
    PeSection = _native.triage.PeSection
    PeRichHeader = _native.triage.RichHeader
    PeRichHeaderEntry = _native.triage.RichHeaderEntry

    __all__ += [
        "PeTriageInfo",
        "PeSubsystem",
        "PeMachine",
        "PeCharacteristics",
        "PeDllCharacteristics",
        "PeDebugInfo",
        "PePdbInfo",
        "PeImport",
        "PeExport",
        "PeResource",
        "PeResourceType",
        "PeVersionInfo",
        "PeTlsInfo",
        "PeLoadConfig",
        "PeRelocation",
        "PeSection",
        "PeRichHeader",
        "PeRichHeaderEntry",
    ]
except AttributeError:
    # PE types not available in this build
    pass

try:
    # ELF-specific types
    ElfTriageInfo = _native.triage.ElfTriageInfo
    ElfType = _native.triage.ElfType
    ElfMachine = _native.triage.ElfMachine
    ElfOsAbi = _native.triage.ElfOsAbi
    ElfHeaderFlags = _native.triage.ElfHeaderFlags
    ElfSegment = _native.triage.ElfSegment
    ElfSegmentType = _native.triage.ElfSegmentType
    ElfSegmentFlags = _native.triage.ElfSegmentFlags
    ElfSection = _native.triage.ElfSection
    ElfSectionType = _native.triage.ElfSectionType
    ElfSectionFlags = _native.triage.ElfSectionFlags
    ElfSymbol = _native.triage.ElfSymbol
    ElfSymbolType = _native.triage.ElfSymbolType
    ElfSymbolBind = _native.triage.ElfSymbolBind
    ElfSymbolVisibility = _native.triage.ElfSymbolVisibility
    ElfRelocation = _native.triage.ElfRelocation
    ElfDynamicEntry = _native.triage.ElfDynamicEntry
    ElfDynamicTag = _native.triage.ElfDynamicTag
    ElfNote = _native.triage.ElfNote
    ElfGnuInfo = _native.triage.ElfGnuInfo

    __all__ += [
        "ElfTriageInfo",
        "ElfType",
        "ElfMachine",
        "ElfOsAbi",
        "ElfHeaderFlags",
        "ElfSegment",
        "ElfSegmentType",
        "ElfSegmentFlags",
        "ElfSection",
        "ElfSectionType",
        "ElfSectionFlags",
        "ElfSymbol",
        "ElfSymbolType",
        "ElfSymbolBind",
        "ElfSymbolVisibility",
        "ElfRelocation",
        "ElfDynamicEntry",
        "ElfDynamicTag",
        "ElfNote",
        "ElfGnuInfo",
    ]
except AttributeError:
    # ELF types not available in this build
    pass

try:
    # Mach-O specific types
    MachOTriageInfo = _native.triage.MachOTriageInfo
    MachOHeader = _native.triage.MachOHeader
    MachOFileType = _native.triage.MachOFileType
    MachOHeaderFlags = _native.triage.MachOHeaderFlags
    MachOLoadCommand = _native.triage.MachOLoadCommand
    MachOSegment = _native.triage.MachOSegment
    MachOSection = _native.triage.MachOSection
    MachOSymbol = _native.triage.MachOSymbol
    MachODynamicLib = _native.triage.MachODynamicLib
    MachOChainedFixup = _native.triage.MachOChainedFixup
    MachOCodeSignature = _native.triage.MachOCodeSignature
    MachOEncryptionInfo = _native.triage.MachOEncryptionInfo
    MachOFunctionStarts = _native.triage.MachOFunctionStarts
    MachODataInCode = _native.triage.MachODataInCode
    MachOLinkerOption = _native.triage.MachOLinkerOption
    MachOSourceVersion = _native.triage.MachOSourceVersion
    MachOVersionMin = _native.triage.MachOVersionMin
    MachOEntryPoint = _native.triage.MachOEntryPoint
    MachOUuid = _native.triage.MachOUuid
    MachOBuildVersion = _native.triage.MachOBuildVersion
    MachOBuildToolVersion = _native.triage.MachOBuildToolVersion

    __all__ += [
        "MachOTriageInfo",
        "MachOHeader",
        "MachOFileType",
        "MachOHeaderFlags",
        "MachOLoadCommand",
        "MachOSegment",
        "MachOSection",
        "MachOSymbol",
        "MachODynamicLib",
        "MachOChainedFixup",
        "MachOCodeSignature",
        "MachOEncryptionInfo",
        "MachOFunctionStarts",
        "MachODataInCode",
        "MachOLinkerOption",
        "MachOSourceVersion",
        "MachOVersionMin",
        "MachOEntryPoint",
        "MachOUuid",
        "MachOBuildVersion",
        "MachOBuildToolVersion",
    ]
except AttributeError:
    # Mach-O types not available in this build
    pass
