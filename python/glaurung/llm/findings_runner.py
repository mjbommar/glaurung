"""Drive an LLM agent through a vuln-discovery pass that returns a
structured ``FindingsReport`` instead of free-text.

Wired into ``glaurung ask --findings-json PATH``. Used by L3's CWE-class
sweep as the per-class pass entry point.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

from .config import get_config
from .findings import FindingsReport, VulnerabilityFinding


# The system prompt is intentionally small. It pins:
#  * what counts as a finding (application code only, not CRT)
#  * the structured output contract
#  * cite-or-discard discipline (every finding must cite at least one piece
#    of evidence the L4 verifier can resolve)
_FINDINGS_SYSTEM_PROMPT = """\
You are Glaurung's vulnerability-discovery agent. Output a FindingsReport
listing security defects found in the binary's OWN code -- never in CRT,
libc, or compiler runtime helpers (mingw __pei386_*, msvcrt vfprintf
width parsers, libgcc unwind glue, etc).

For every finding:

* `cwe`: canonical 'CWE-<n>' id from the WELL_KNOWN_CWES table where
  possible.
* `function.name` and/or `function.va`: the function in which the bug
  lives, exactly as the analysis tools reported it. If you only know
  the VA, set `name=null`.
* `bug_site.va`: VA of the specific instruction implementing the bug.
* `root_cause`: ONE sentence. Say what the attacker controls and why
  it leads to memory unsafety, control-flow corruption, etc.
* `evidence`: AT LEAST ONE entry. Pick the kind that grounds your claim:
  `import` (PE import-table entry), `string` (embedded ASCII/UTF-16),
  `disasm` (a specific VA's instruction), `decompile` (a line of
  pseudocode), `fact_bundle` (Lane-4 row), `xref` (caller->callee or
  read/write site). Set `location` to a locator the host can verify
  (hex VA, import symbol, decompile line snippet).
* `confidence`: low / medium / high. Be honest: 'high' requires
  instruction-level evidence, not just a suspicious import.

If you cannot find a bug, return an empty `findings` list and set
`notes` to one sentence explaining what you looked at and why nothing
stood out. Do NOT invent findings.
"""


_FINDINGS_QUESTION = """\
Find security vulnerabilities in this binary's own code. Use the
analysis tools to inspect imports, strings, and the decompiled bodies
of functions that are NOT compiler-runtime helpers. Report results as
a FindingsReport (list of VulnerabilityFinding) per the system prompt.

Focus on these CWE families:
  * CWE-121/120/787: unbounded copies, OOB writes, stack/heap overflows
  * CWE-134: format strings with caller-controlled first argument
  * CWE-190/191: arithmetic overflow before allocator / size check
  * CWE-401/415/416: leaks, double-free, use-after-free
  * CWE-476/822: NULL or untrusted pointer dereference (especially
    inside Windows IRP-handling code without ProbeForRead/Write).

If multiple sites look plausible, return up to three findings ordered
by confidence (highest first).
"""


async def run_findings_pass(
    binary_path: str,
    args: Any,
) -> FindingsReport:
    """Run a single structured-output discovery pass over ``binary_path``.

    Uses the same factory + context setup as the regular ``ask`` flow,
    but installs ``output_type=FindingsReport`` on the pydantic-ai agent
    so the model returns validated JSON instead of prose.
    """
    pydantic_ai = __import__("pydantic_ai")  # noqa: F841 -- import-only guard
    import glaurung as g
    from .context import MemoryContext, Budgets
    from .kb.adapters import import_triage as kb_import_triage
    from .agents.memory_agent import register_analysis_tools
    from .agents.memory_foundation import create_foundation_agent
    from .agents.base import ModelHyperparameters

    cfg = get_config()
    model_name = getattr(args, "model", None) or cfg.default_model

    # L5: when --route is on, derive the per-question tool filter from
    # the prompt we'll actually send (sweep-class prompt when present,
    # else the default discovery question). This keeps the structured
    # pass under OpenAI's 128-tool cap even on the default model.
    tool_filter: set[str] | None = None
    if getattr(args, "all_tools", False):
        tool_filter = None
    elif getattr(args, "route", False):
        from .tool_routing import select_tools_for_question
        routing_prompt = getattr(args, "cwe_class_prompt", None) or _FINDINGS_QUESTION
        tool_filter = set(select_tools_for_question(routing_prompt))
    # Always route the findings pass under the default OpenAI model:
    # gpt-5.4-mini's 128 tool cap is hard, and the broad-discovery
    # subset (~17 tools) is enough for vuln hunting.
    if tool_filter is None and model_name.startswith("openai:"):
        from .tool_routing import select_tools_for_question
        tool_filter = set(select_tools_for_question(
            getattr(args, "cwe_class_prompt", None) or _FINDINGS_QUESTION
        ))

    # Build a structured-output agent: same tool surface as create_memory_agent
    # but with output_type=FindingsReport so the validation happens server-side.
    foundation = create_foundation_agent(
        model=model_name,
        output_type=FindingsReport,
        system_prompt=_FINDINGS_SYSTEM_PROMPT,
    )
    agent = register_analysis_tools(
        foundation, model_name=model_name, tool_filter=tool_filter,
    )

    # Triage + minimal MemoryContext so the agent has KB content to chew on.
    max_read_bytes = getattr(args, "max_read_bytes", 10_485_760)
    max_file_size = getattr(args, "max_file_size", 104_857_600)
    artifact = g.triage.analyze_path(
        binary_path,
        max_read_bytes=max_read_bytes,
        max_file_size=max_file_size,
        max_recursion_depth=1,
    )
    context = MemoryContext(
        file_path=binary_path,
        artifact=artifact,
        session_id="cli_ask_findings",
        allow_expensive=True,
        budgets=Budgets(
            max_read_bytes=max_read_bytes,
            max_file_size=max_file_size,
            max_functions=getattr(args, "max_functions", 5),
            max_instructions=getattr(args, "max_instructions", 50_000),
            max_disasm_window=getattr(args, "disasm_window", 4096),
        ),
    )
    try:
        kb_import_triage(context.kb, artifact, binary_path)
    except Exception:
        # Triage import is best-effort; the agent can still call tools.
        pass

    # F3: max_tokens=4096 was anachronistic -- May-2026 models do 64K+
    # output comfortably, and a FindingsReport with multiple findings +
    # multi-entry evidence arrays can easily exceed 4K and force
    # pydantic-ai's structured-output retry path (which re-bills the
    # full conversation). Use the LLMConfig default (32_768) so the cap
    # is generous AND tracked centrally.
    from .usage_limits import default_max_output_tokens
    params = ModelHyperparameters(
        temperature=0.2,
        max_tokens=default_max_output_tokens(),
    )

    # pydantic-ai >=1.x: sampling params via ModelSettings. The
    # model_name arg drives OpenAI service_tier=flex handoff.
    from pydantic_ai.settings import ModelSettings
    settings = ModelSettings(**params.to_model_kwargs(model_name=model_name))

    # L3 hook: the CWE sweep passes a class-scoped prompt via
    # args.cwe_class_prompt. Use it when set; otherwise fall back to the
    # broad discovery question.
    user_prompt = getattr(args, "cwe_class_prompt", None) or _FINDINGS_QUESTION

    # F2: cap discovery at 8 tool-turns. Per-class structured-output
    # discovery rarely needs more than 5 tools (triage preloaded,
    # decompile one or two, then emit final_result). 8 leaves a small
    # buffer; ~5x cheaper than pydantic-ai's 50 default.
    from .usage_limits import build_usage_limits
    usage_limits = build_usage_limits(model_name=model_name, request_limit=8)

    result = await agent.run(
        user_prompt,
        deps=context,
        model_settings=settings,
        usage_limits=usage_limits,
    )

    # F4: cost telemetry. Wrapped in try/except so telemetry never
    # masks a real LLM error.
    try:
        from .usage_tracker import get_tracker
        get_tracker().record(
            result, model=model_name, source="findings_runner",
        )
    except Exception:  # pragma: no cover
        pass

    # pydantic-ai 1.x returns AgentRunResult; the parsed structured output
    # lives on .output.
    report: FindingsReport = result.output if hasattr(result, "output") else result
    if not isinstance(report, FindingsReport):
        # Defensive: some backends return a dict-shaped output object.
        report = FindingsReport.model_validate(report)
    # Always pin the binary_path; agents sometimes leave it empty.
    if not report.binary_path:
        object.__setattr__(report, "binary_path", binary_path)

    # L4: run the cite-or-discard verifier over every finding before the
    # report leaves the runner. This populates verification_issues and
    # demotes confidence on hallucinated references.
    binary_ctx = None
    try:
        from .finding_verifier import _BinaryContext, verify_report
        binary_ctx = _BinaryContext.build(binary_path)
        verify_report(report, binary_ctx=binary_ctx)
    except Exception as e:
        existing = report.notes or ""
        sep = "\n" if existing else ""
        object.__setattr__(
            report, "notes",
            f"{existing}{sep}[verifier-error] {type(e).__name__}: {e}",
        )

    # L2: self-critique pass -- ask the critic whether the resolved
    # evidence actually supports the claim. Only runs when we have a
    # working binary context (skip on verifier failure to avoid
    # cascading errors).
    if binary_ctx is not None and report.findings:
        if not getattr(args, "skip_critique", False):
            try:
                from .finding_critic import critique_report
                await critique_report(
                    report,
                    model_name=model_name,
                    binary_ctx=binary_ctx,
                )
            except Exception as e:
                existing = report.notes or ""
                sep = "\n" if existing else ""
                object.__setattr__(
                    report, "notes",
                    f"{existing}{sep}[critic-error] {type(e).__name__}: {e}",
                )

    return report


def write_findings_report(report: FindingsReport, path: str) -> None:
    """Emit the report as JSON to ``path`` (use '-' for stdout)."""
    text = report.model_dump_json(indent=2)
    if path == "-":
        sys.stdout.write(text)
        sys.stdout.write("\n")
        sys.stdout.flush()
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
