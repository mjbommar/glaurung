"""Cite-or-discard finding verifier (L4).

After an agent produces a :class:`VulnerabilityFinding`, this module
resolves the cited evidence against the analysed binary and demotes
findings whose references don't survive verification.

What it catches:

* Function VAs that aren't in the discovered function set (hallucinated).
* Bug-site VAs that lie outside the named function's extent.
* ``import`` evidence pointing to a symbol that isn't in the PE imports.
* ``disasm`` evidence whose cited VA doesn't lie inside any function
  Glaurung analyzed.
* ``decompile`` evidence whose snippet text doesn't appear when we
  decompile the function we claim it lives in.

What it intentionally does NOT do:

* Re-litigate the CWE class (that's L2's self-critic).
* Run the LLM (verification is pure deterministic resolution).
* Drop findings outright (caller decides; default policy is to demote
  confidence and record ``verification_issues``).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Iterable, Optional

import glaurung as g

from .findings import (
    AddressRef,
    Evidence,
    FindingsReport,
    FunctionRef,
    VulnerabilityFinding,
)


logger = logging.getLogger(__name__)


@dataclass
class _AnalysedFunction:
    """The verifier's view of a discovered function."""

    name: str
    entry_va: int
    end_va: int  # exclusive: entry + total_size or entry + 1 if size unknown
    function_class: str = "application"

    def contains(self, va: int) -> bool:
        return self.entry_va <= va < self.end_va


@dataclass
class _BinaryContext:
    """Cached analysis snapshot used to verify a batch of findings.

    Owning a single _BinaryContext per binary path keeps repeated
    `analyze_functions_path` + `triage` calls from re-running for each
    finding in a report.
    """

    binary_path: str
    functions_by_va: dict[int, _AnalysedFunction]
    functions_by_name: dict[str, list[_AnalysedFunction]]
    imports: set[str]
    decompile_cache: dict[int, str]

    @classmethod
    def build(cls, binary_path: str) -> "_BinaryContext":
        result = g.analysis.analyze_functions_path(
            binary_path, max_functions=2000,
        )
        # analyze_functions_path returns (functions, callgraph) or
        # (functions, callgraph, stats) depending on the build. We only
        # need the first element.
        analyzed = result[0]

        # First pass: collect entry VAs + sizes. Many functions report
        # total_size=0 (size discovery not always populated); fall back
        # to the gap-to-next-function entry to bound the extent.
        raw: list[tuple[str, int, int]] = []  # (name, va, declared_size)
        for fn in analyzed:
            va = int(fn.entry_point.value)
            try:
                size = int(fn.total_size or 0)
            except Exception:
                size = 0
            raw.append((fn.name, va, size))
        raw.sort(key=lambda r: r[1])

        # Compute an end-VA per entry, using:
        #   1. declared total_size when >0
        #   2. the next entry's VA otherwise
        #   3. entry + 0x400 as a last resort (single-function binaries)
        from .runtime_classifier import classify_function

        functions_by_va: dict[int, _AnalysedFunction] = {}
        functions_by_name: dict[str, list[_AnalysedFunction]] = {}
        for i, (name, va, size) in enumerate(raw):
            if size > 0:
                end = va + size
            elif i + 1 < len(raw):
                end = raw[i + 1][1]
            else:
                end = va + 0x400
            # Pathological case: next entry happens to be the same VA
            # (overlapping symbol). Keep at least a 1-byte extent so
            # downstream containment checks don't degenerate.
            if end <= va:
                end = va + 1
            af = _AnalysedFunction(
                name=name, entry_va=va, end_va=end,
                function_class=classify_function(name),
            )
            functions_by_va[va] = af
            functions_by_name.setdefault(name, []).append(af)

        imports = _collect_imports(binary_path)
        return cls(
            binary_path=binary_path,
            functions_by_va=functions_by_va,
            functions_by_name=functions_by_name,
            imports=imports,
            decompile_cache={},
        )

    def decompile(self, va: int) -> Optional[str]:
        if va in self.decompile_cache:
            return self.decompile_cache[va]
        try:
            text = g.ir.decompile_at(
                self.binary_path, va,
                timeout_ms=5_000, max_blocks=256, max_instructions=2_000,
                types=True, style="",
            )
        except Exception as e:
            logger.debug("decompile_at(%s, 0x%x) failed: %s", self.binary_path, va, e)
            text = None
        if text is not None:
            self.decompile_cache[va] = text
        return text

    def function_for(self, ref: FunctionRef) -> Optional[_AnalysedFunction]:
        if ref.va is not None and ref.va in self.functions_by_va:
            return self.functions_by_va[ref.va]
        if ref.name:
            matches = self.functions_by_name.get(ref.name, [])
            if len(matches) == 1:
                return matches[0]
        return None


def _collect_imports(binary_path: str) -> set[str]:
    """Best-effort extraction of PE/ELF import symbols. Returns the set
    of symbol names; empty set if extraction fails."""
    out: set[str] = set()
    # Try the new triage shape first.
    try:
        artifact = g.triage.analyze_path(binary_path, max_recursion_depth=1)
        # Triage exposes imports under artifact.imports / symbols.imports on
        # different schema versions; try a couple of shapes.
        for attr in ("imports", "all_imports"):
            obj = getattr(artifact, attr, None)
            if obj:
                for item in obj:
                    name = getattr(item, "name", None) or str(item)
                    if name:
                        out.add(name)
                if out:
                    return out
        syms = getattr(artifact, "symbols", None)
        if syms is not None:
            obj = getattr(syms, "imports", None)
            if obj:
                for item in obj:
                    name = getattr(item, "name", None) or str(item)
                    if name:
                        out.add(name)
    except Exception as e:
        logger.debug("triage import extraction failed: %s", e)
    return out


# ---------------------------------------------------------------------------


_VA_RE = re.compile(r"0x[0-9a-fA-F]+|[0-9]+")


def _parse_va(text: str) -> Optional[int]:
    """Pick the first int literal (hex or decimal) out of a location string."""
    m = _VA_RE.search(text or "")
    if not m:
        return None
    try:
        return int(m.group(0), 0)
    except ValueError:
        return None


def verify_finding(
    finding: VulnerabilityFinding,
    binary_ctx: _BinaryContext,
    *,
    demote_on_issue: bool = True,
) -> VulnerabilityFinding:
    """Resolve every reference inside ``finding`` against ``binary_ctx``.

    Mutates the finding in place (Pydantic models allow assignment by
    default) and returns it. Verification issues are appended to
    ``finding.verification_issues``; when ``demote_on_issue`` is True
    (the default), any non-empty issue list lowers confidence one level
    down to ``low``.
    """
    issues: list[str] = list(finding.verification_issues)

    # 1. Function reference: must resolve to a discovered function.
    fn = binary_ctx.function_for(finding.function)
    if fn is None:
        ref_text = finding.function.name or f"0x{finding.function.va:x}" \
            if finding.function.va is not None else "<unspecified>"
        issues.append(f"function {ref_text!r} not found in analysis")
    elif fn.function_class in ("runtime_helper", "library_import_stub"):
        # D3: a finding pointing at compiler-runtime / import-stub code is
        # almost always a mis-attribution. Flag it loudly.
        issues.append(
            f"function {fn.name!r} is classified as {fn.function_class} "
            "(compiler runtime / import stub), not application code"
        )

    # 2. Bug site (when set): must lie inside the function's extent.
    if finding.bug_site is not None and fn is not None:
        if not fn.contains(finding.bug_site.va):
            issues.append(
                f"bug_site 0x{finding.bug_site.va:x} outside function "
                f"{fn.name} [0x{fn.entry_va:x}, 0x{fn.end_va:x})"
            )

    # 3. Per-evidence resolution.
    for ev in finding.evidence:
        ev_issue = _verify_evidence(ev, binary_ctx, fn)
        if ev_issue:
            issues.append(ev_issue)

    finding.verification_issues = issues
    if demote_on_issue and issues:
        finding.confidence = "low"
    return finding


def _verify_evidence(
    ev: Evidence,
    binary_ctx: _BinaryContext,
    fn: Optional[_AnalysedFunction],
) -> Optional[str]:
    """Return a one-line issue description or None if the evidence resolves."""
    kind = ev.kind
    loc = ev.location or ""

    if kind == "import":
        # location is either bare symbol name or "imports[name]".
        m = re.match(r"imports?\[(?P<name>[^\]]+)\]", loc)
        sym = m.group("name") if m else loc.strip()
        if not sym:
            return f"import evidence has empty symbol locator: {loc!r}"
        if binary_ctx.imports and sym not in binary_ctx.imports:
            # Imports set may be empty if extraction failed; only flag
            # when we actually have a populated set to compare against.
            return (
                f"import evidence cites '{sym}' but symbol is not in the "
                f"PE import table"
            )
        return None

    if kind == "disasm":
        va = _parse_va(loc)
        if va is None:
            return f"disasm evidence has no parseable VA in location: {loc!r}"
        # Disasm VA must lie inside SOME analyzed function.
        for af in binary_ctx.functions_by_va.values():
            if af.contains(va):
                return None
        return (
            f"disasm evidence at 0x{va:x} is not inside any analyzed function"
        )

    if kind == "xref":
        va = _parse_va(loc)
        if va is None:
            return f"xref evidence has no parseable VA in location: {loc!r}"
        for af in binary_ctx.functions_by_va.values():
            if af.contains(va):
                return None
        return f"xref evidence at 0x{va:x} not inside any analyzed function"

    if kind == "decompile":
        # location may be "function:label" or "function:line" -- we
        # verify by asking the decompiler whether the cited snippet
        # appears in the named function's pseudocode.
        if fn is None:
            return (
                "decompile evidence with no resolved function to check "
                f"against (location={loc!r})"
            )
        text = binary_ctx.decompile(fn.entry_va)
        if text is None:
            return (
                f"decompile evidence for {fn.name} could not be verified: "
                "decompiler returned no output"
            )
        # Loose match: pick the longest "interesting" word from the
        # snippet and verify it appears in the pseudocode.
        sample = ev.text or loc
        salient = max(
            (w for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", sample)),
            key=len, default="",
        )
        if salient and salient not in text:
            return (
                f"decompile evidence snippet ('{salient}…') not found in "
                f"pseudocode for {fn.name}"
            )
        return None

    if kind == "string":
        # We don't keep an extracted-strings index in the verifier yet;
        # accept the citation but note it for future tightening.
        return None

    if kind == "fact_bundle":
        # Fact-bundle verification requires the ASB project DB; out of
        # scope for the in-Glaurung verifier. Accept.
        return None

    return f"unknown evidence kind: {kind!r}"


def verify_report(
    report: FindingsReport,
    *,
    binary_ctx: Optional[_BinaryContext] = None,
    demote_on_issue: bool = True,
) -> FindingsReport:
    """Verify every finding in ``report`` against the named binary.

    Builds a fresh :class:`_BinaryContext` if one is not provided.
    Mutates the report's findings in place and returns the report for
    chaining.
    """
    ctx = binary_ctx or _BinaryContext.build(report.binary_path)
    for finding in report.findings:
        verify_finding(finding, ctx, demote_on_issue=demote_on_issue)
    return report
