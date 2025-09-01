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
StringsSummary = _native.triage.StringsSummary
PackerMatch = _native.triage.PackerMatch
ContainerChild = _native.triage.ContainerChild
Budgets = _native.triage.Budgets
TriageVerdict = _native.triage.TriageVerdict
TriagedArtifact = _native.triage.TriagedArtifact

__all__ = [
    "SnifferSource",
    "TriageHint",
    "TriageErrorKind",
    "TriageError",
    "ConfidenceSignal",
    "ParserKind",
    "ParserResult",
    "EntropySummary",
    "StringsSummary",
    "PackerMatch",
    "ContainerChild",
    "Budgets",
    "TriageVerdict",
    "TriagedArtifact",
]
