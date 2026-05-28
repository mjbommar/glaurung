"""Structured vulnerability-finding schema for Glaurung's LLM agents.

Free-text answers from ``glaurung ask`` force every downstream consumer
(ASB, the CWE sweep, the self-critic pass, the cite-or-discard verifier)
to regex-parse English. This module pins a Pydantic schema that all
finding-shaped LLM outputs round-trip through, so:

* The CLI ``--format json`` emits parseable JSON.
* The L2 self-critique pass takes structured input.
* The L3 CWE sweep can merge per-class results into one corpus report.
* The L4 verifier can resolve cited VAs against the project DB.

The schema is intentionally narrow and validation-friendly: every
finding carries at least one piece of cited evidence and an explicit
confidence label. Helpers for normalising CWE ids and resolving function
references round out the module.
"""

from __future__ import annotations

import re
from typing import Iterable, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


ConfidenceLevel = Literal["low", "medium", "high"]
EvidenceKind = Literal[
    "import",      # PE import-table entry (caller named a function from a DLL)
    "string",      # an embedded string adjacent to the bug site
    "disasm",      # a specific instruction at a VA
    "decompile",   # a specific decompiler line / pseudocode snippet
    "fact_bundle", # a row from the Lane-4 fact-bundle (per-function evidence)
    "xref",        # an xref edge (caller -> callee or read/write site)
]
EvidenceSupport = Literal["true", "partial", "false"]


# Common CWE ids the demo corpus + Windows research substrate cover. The
# list is non-exhaustive; new ids are accepted as long as they match the
# canonical "CWE-<number>" pattern, but having the well-known ones named
# helps the LLM stay on-vocabulary and lets reports group by class.
WELL_KNOWN_CWES: dict[str, str] = {
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-191": "Integer Underflow",
    "CWE-401": "Missing Release of Memory after Effective Lifetime",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-457": "Use of Uninitialized Variable",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-787": "Out-of-bounds Write",
    "CWE-822": "Untrusted Pointer Dereference",
    "CWE-823": "Use of Out-of-range Pointer Offset",
}


_CWE_RE = re.compile(r"^CWE-\d{1,5}$")


def normalize_cwe(raw: str) -> str:
    """Coerce a CWE id from the model to the canonical 'CWE-<n>' form.

    Accepts: 'cwe-121', 'CWE 121', '121', 'CWE-0121',
    'CWE-121 (Stack...)' etc. Raises ValueError on unrecoverable input.
    """
    if not raw:
        raise ValueError("empty CWE id")
    # Pull the first digit run out of the string regardless of separators.
    m = re.search(r"\d+", raw)
    if not m:
        raise ValueError(f"unrecognised CWE id (no digits): {raw!r}")
    n = int(m.group(0))
    return f"CWE-{n}"


def lookup_cwe_name(cwe: str) -> Optional[str]:
    """Return the canonical human-readable CWE name when known, else None."""
    return WELL_KNOWN_CWES.get(cwe)


# ---------------------------------------------------------------------------


class FunctionRef(BaseModel):
    """A reference to a specific function inside the analysed binary.

    Either ``va`` or ``name`` must be present (preferably both). The L4
    verifier resolves names against the analysis result and demotes
    findings whose function refs don't resolve.
    """

    name: Optional[str] = Field(
        default=None,
        description="Function name as recovered by analysis (or PDB).",
    )
    va: Optional[int] = Field(
        default=None,
        description="Function entry VA. Decimal int; serialise via hex_va.",
    )

    @model_validator(mode="after")
    def _at_least_one(self) -> "FunctionRef":
        if self.name is None and self.va is None:
            raise ValueError("FunctionRef needs at least name or va")
        return self

    @property
    def hex_va(self) -> Optional[str]:
        return None if self.va is None else f"0x{self.va:x}"

    def __str__(self) -> str:
        if self.name and self.va is not None:
            return f"{self.name} @ 0x{self.va:x}"
        return self.name or f"0x{self.va:x}"


class AddressRef(BaseModel):
    """A specific instruction VA inside a function (or close-enough)."""

    va: int = Field(..., description="Virtual address")

    @property
    def hex_va(self) -> str:
        return f"0x{self.va:x}"


class Evidence(BaseModel):
    """One piece of grounding for a finding.

    ``location`` is a textual locator: hex VA for ``disasm``/``xref``,
    ``"imports[name]"`` or just the import symbol for ``import``,
    ``"<file>:<line>"`` for ``decompile``, etc. The L4 verifier inspects
    this field to confirm the reference is real.
    """

    kind: EvidenceKind = Field(
        ..., description="What kind of artifact this evidence cites."
    )
    location: str = Field(
        ..., description="Locator: VA hex, import symbol, decompile line ref."
    )
    text: str = Field(
        ..., description="Human-readable snippet (the actual evidence content)."
    )


class VulnerabilityFinding(BaseModel):
    """A single candidate vulnerability the agent claims to have found.

    Findings round-trip through this model on the way out of every LLM
    call. The CLI emits ``list[VulnerabilityFinding]`` as JSON when
    ``--format json`` is passed.

    Constraints (enforced by validators):
      * ``cwe`` matches ``CWE-<number>`` after normalization.
      * ``evidence`` is non-empty.
      * ``function`` carries at least a name or a VA.
    """

    cwe: str = Field(
        ..., description="Canonical CWE id, e.g. 'CWE-121'."
    )
    cwe_name: Optional[str] = Field(
        default=None,
        description=(
            "Human-readable CWE name. Auto-filled from WELL_KNOWN_CWES "
            "when omitted and the id is in the table."
        ),
    )
    function: FunctionRef = Field(
        ..., description="The function where the bug lives."
    )
    bug_site: Optional[AddressRef] = Field(
        default=None,
        description="VA of the specific instruction implementing the bug.",
    )
    root_cause: str = Field(
        ...,
        min_length=8,
        description="One sentence: why this is a bug and what is controlled.",
    )
    evidence: list[Evidence] = Field(
        default_factory=list,
        description="At least one piece of cited evidence required.",
    )
    confidence: ConfidenceLevel = Field(
        default="medium", description="low / medium / high"
    )
    alternates: list["VulnerabilityFinding"] = Field(
        default_factory=list,
        description="Other CWE classes the agent considered for the same site.",
    )
    # L2 / L4 outputs are stored here; absent on first emission.
    evidence_supports_claim: Optional[EvidenceSupport] = Field(
        default=None,
        description="Set by the L2 self-critique pass.",
    )
    critique: Optional[str] = Field(
        default=None,
        description="One-line critic note set by the L2 self-critique pass.",
    )
    verification_issues: list[str] = Field(
        default_factory=list,
        description="Set by the L4 cite-or-discard verifier when references fail.",
    )

    @field_validator("cwe", mode="before")
    @classmethod
    def _normalize_cwe(cls, v):
        return normalize_cwe(v)

    @field_validator("evidence")
    @classmethod
    def _evidence_nonempty(cls, v: list[Evidence]) -> list[Evidence]:
        if not v:
            raise ValueError(
                "VulnerabilityFinding.evidence must contain at least one Evidence "
                "entry (cite-or-discard policy)."
            )
        return v

    @model_validator(mode="after")
    def _fill_cwe_name(self) -> "VulnerabilityFinding":
        if self.cwe_name is None:
            known = lookup_cwe_name(self.cwe)
            if known:
                # Pydantic v2: bypass frozen check via __dict__ since we just
                # validated the model; mutating after-validation is allowed.
                object.__setattr__(self, "cwe_name", known)
        return self


VulnerabilityFinding.model_rebuild()


class FindingsReport(BaseModel):
    """Container the CLI emits for a single binary analysis call.

    The agent may return zero findings (clean binary or low-confidence
    pass). ``binary_path`` is recorded so corpus-level merges (L3) can
    group findings by source.
    """

    binary_path: str = Field(
        ..., description="Path of the analysed binary."
    )
    findings: list[VulnerabilityFinding] = Field(
        default_factory=list,
        description="Zero or more candidate findings.",
    )
    notes: Optional[str] = Field(
        default=None,
        description="Free-text caveats from the agent (e.g. 'no bug found').",
    )

    def by_cwe(self) -> dict[str, list[VulnerabilityFinding]]:
        """Group findings by CWE id."""
        out: dict[str, list[VulnerabilityFinding]] = {}
        for f in self.findings:
            out.setdefault(f.cwe, []).append(f)
        return out

    @classmethod
    def merge(cls, reports: Iterable["FindingsReport"]) -> "FindingsReport":
        """Merge several reports (e.g. one per CWE-class pass) into one,
        deduplicating by (cwe, function.va or function.name, bug_site.va)."""
        seen: set[tuple] = set()
        merged: list[VulnerabilityFinding] = []
        binary_path = ""
        notes_parts: list[str] = []
        for r in reports:
            binary_path = binary_path or r.binary_path
            if r.notes:
                notes_parts.append(r.notes)
            for f in r.findings:
                key = (
                    f.cwe,
                    f.function.va if f.function.va is not None else f.function.name,
                    f.bug_site.va if f.bug_site else None,
                )
                if key in seen:
                    continue
                seen.add(key)
                merged.append(f)
        return cls(
            binary_path=binary_path,
            findings=merged,
            notes="\n".join(notes_parts) if notes_parts else None,
        )
