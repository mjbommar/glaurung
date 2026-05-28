"""Self-critique pass for VulnerabilityFinding (L2).

After the L4 verifier resolves cited references, the critic asks a second
LLM call: given the finding + the actual evidence content, does the
evidence support the claim? This catches the v2 corpus failure modes:

* "the cited evidence is actually a bounded copy" -- india.exe miss
* "the cited function is mingw __pei386_runtime_relocator (CRT)" -- kilo.exe miss
* "two different VAs for the same function" -- mike.dll contradiction

The critic emits one of ``true``/``partial``/``false`` per finding and a
one-line critique. Findings that don't pass critique get
``confidence='low'``.

Unlike the L4 verifier, the critic is allowed to be wrong -- but its
disagreement is information the operator should see. The critique is
attached to the finding under ``critique``; the support verdict lands
in ``evidence_supports_claim``.
"""

from __future__ import annotations

import logging
from typing import Optional

from pydantic import BaseModel, Field

from .findings import FindingsReport, VulnerabilityFinding


logger = logging.getLogger(__name__)


_CRITIC_SYSTEM_PROMPT = """\
You are a skeptical security-review critic. You are given:

  1. A VulnerabilityFinding the discovery agent emitted.
  2. The actual content of every Evidence entry the finding cited
     (disassembly text, decompile snippets, import-table membership,
     etc. -- the *resolved* artifacts, not just locator strings).

Your job: judge whether the evidence supports the claim.

* Answer `true` ONLY when the cited evidence *directly* implies the
  named CWE at the named site. "strcpy of caller-controlled buffer
  into a fixed-size stack array" supports CWE-121. A bare "strcpy
  import exists" alone DOES NOT.
* Answer `partial` when the evidence supports a related-but-not-
  identical claim (e.g. a stack overflow story whose cited copy turns
  out to be a *bounded* strncpy; an integer-overflow story cited in
  the CRT's vfprintf width parser instead of the application's own
  arithmetic; a UAF story whose freed-pointer is never re-published).
* Answer `false` when the evidence flat-out contradicts the claim
  or points at compiler runtime / CRT internals instead of application
  code.

Your critique field MUST be one short sentence (<= 200 chars) naming
the specific reason. Do not list multiple reasons; pick the most
important.
"""


class _CriticVerdict(BaseModel):
    """Structured output for the critic agent."""

    evidence_supports_claim: str = Field(
        ..., description="One of: true, partial, false"
    )
    critique: str = Field(
        ..., min_length=4, max_length=400,
        description="One short sentence naming the most important issue.",
    )


def _resolve_evidence_for_prompt(
    finding: VulnerabilityFinding,
    binary_ctx,
) -> str:
    """Build a compact "what the citations actually contain" block for
    the critic prompt by re-fetching each evidence reference through the
    same _BinaryContext the L4 verifier uses."""
    lines: list[str] = []
    for i, ev in enumerate(finding.evidence, 1):
        lines.append(f"[{i}] kind={ev.kind} location={ev.location}")
        lines.append(f"    agent_quote: {ev.text}")
        if ev.kind == "disasm":
            from .finding_verifier import _parse_va
            va = _parse_va(ev.location) or _parse_va(ev.text)
            if va is not None:
                for af in binary_ctx.functions_by_va.values():
                    if af.contains(va):
                        lines.append(
                            f"    resolved: inside function {af.name} "
                            f"[0x{af.entry_va:x}, 0x{af.end_va:x})"
                        )
                        break
                else:
                    lines.append(
                        f"    resolved: VA 0x{va:x} NOT inside any "
                        "analyzed function"
                    )
        elif ev.kind == "import":
            import re
            m = re.match(r"imports?\[(?P<n>[^\]]+)\]", ev.location)
            sym = m.group("n") if m else ev.location.strip()
            in_table = sym in binary_ctx.imports if binary_ctx.imports else None
            if in_table is True:
                lines.append(f"    resolved: '{sym}' present in PE import table")
            elif in_table is False:
                lines.append(f"    resolved: '{sym}' NOT in PE import table")
        elif ev.kind == "decompile":
            fn = binary_ctx.function_for(finding.function)
            if fn is not None:
                text = binary_ctx.decompile(fn.entry_va) or ""
                if text and ev.text and ev.text in text:
                    lines.append("    resolved: snippet text appears in pseudocode")
                else:
                    lines.append("    resolved: snippet text NOT visible in pseudocode")
        lines.append("")
    if finding.verification_issues:
        lines.append("verifier_issues:")
        for issue in finding.verification_issues:
            lines.append(f"  - {issue}")
    return "\n".join(lines)


async def critique_finding(
    finding: VulnerabilityFinding,
    binary_ctx,
    *,
    model_name: str,
) -> VulnerabilityFinding:
    """Run a single critic LLM call and stamp the verdict onto the finding."""
    pydantic_ai = __import__("pydantic_ai")  # noqa: F841
    from pydantic_ai import Agent
    from pydantic_ai.settings import ModelSettings

    critic = Agent(
        model=model_name,
        system_prompt=_CRITIC_SYSTEM_PROMPT,
        output_type=_CriticVerdict,
    )

    evidence_block = _resolve_evidence_for_prompt(finding, binary_ctx)
    user_prompt = (
        "FINDING:\n"
        f"  cwe: {finding.cwe} ({finding.cwe_name or ''})\n"
        f"  function: {finding.function}\n"
        f"  bug_site: {finding.bug_site.hex_va if finding.bug_site else '(none)'}\n"
        f"  root_cause: {finding.root_cause}\n"
        f"  confidence: {finding.confidence}\n"
        "\n"
        "RESOLVED EVIDENCE:\n"
        f"{evidence_block}\n"
        "\n"
        "Verdict?"
    )

    # OpenAI service_tier=flex handoff for the critic too.
    # F3: bump max_tokens from 512 -> 4096 (Opus 4.7 with extended
    # thinking burns 2-8K just on thinking before emitting the small
    # _CriticVerdict JSON; 512 truncates inside reasoning).
    critic_settings: dict[str, object] = {
        "temperature": 0.0, "max_tokens": 4_096,
    }
    if model_name and model_name.startswith("openai:"):
        from .config import get_config
        tier = get_config().openai_service_tier
        if tier and tier != "default":
            critic_settings["extra_body"] = {"service_tier": tier}
    # F2: the critic doesn't use tools -- one round-trip is enough.
    # request_limit=2 leaves slack for a single retry on validation
    # failure. tool_calls_limit=0 forbids tool use entirely (defensive
    # if a future critic prompt accidentally tempts the agent).
    from .usage_limits import build_usage_limits
    critic_usage_limits = build_usage_limits(
        model_name=model_name,
        request_limit=2,
        tool_calls_limit=0,
        total_tokens_limit=50_000,
    )
    result = await critic.run(
        user_prompt,
        model_settings=ModelSettings(**critic_settings),
        usage_limits=critic_usage_limits,
    )
    # F4: cost telemetry.
    try:
        from .usage_tracker import get_tracker
        get_tracker().record(
            result, model=model_name, source="finding_critic",
        )
    except Exception:  # pragma: no cover
        pass
    verdict: _CriticVerdict = result.output if hasattr(result, "output") else result
    raw = (verdict.evidence_supports_claim or "").strip().lower()
    if raw in ("true", "yes"):
        finding.evidence_supports_claim = "true"
    elif raw in ("partial", "mixed", "maybe"):
        finding.evidence_supports_claim = "partial"
    elif raw in ("false", "no"):
        finding.evidence_supports_claim = "false"
    else:
        finding.evidence_supports_claim = "partial"
    finding.critique = verdict.critique.strip()

    # Demote confidence when the critic disagrees.
    if finding.evidence_supports_claim == "false":
        finding.confidence = "low"
    elif finding.evidence_supports_claim == "partial":
        if finding.confidence == "high":
            finding.confidence = "medium"

    return finding


async def critique_report(
    report: FindingsReport,
    *,
    model_name: str,
    binary_ctx: Optional[object] = None,
    force_critique: bool = False,
) -> FindingsReport:
    """Critique every finding in ``report``. Uses one ``_BinaryContext``
    for all of them so the resolver doesn't re-analyze the same binary
    per finding.

    F6: by default, findings already demoted by L4 (confidence='low' AND
    non-empty verification_issues) skip the critic LLM call -- the
    verifier's evidence-grounded demotion is treated as a 'false'
    verdict, the critique is set to a synthesized 'L4 says X' line,
    and no critic API spend is incurred. Pass ``force_critique=True``
    to override and run the critic on every finding regardless.
    """
    if binary_ctx is None:
        from .finding_verifier import _BinaryContext
        binary_ctx = _BinaryContext.build(report.binary_path)

    for finding in report.findings:
        # F6: short-circuit when L4 already failed verification.
        if (
            not force_critique
            and finding.confidence == "low"
            and finding.verification_issues
        ):
            first_issue = finding.verification_issues[0]
            finding.evidence_supports_claim = "false"
            finding.critique = (
                f"skipped (L4 verifier already flagged): {first_issue}"
            )
            continue
        try:
            await critique_finding(finding, binary_ctx, model_name=model_name)
        except Exception as e:
            logger.warning("critique failed for %s: %s", finding, e)
            finding.critique = f"[critic-error] {type(e).__name__}: {e}"
            finding.evidence_supports_claim = None

    return report
