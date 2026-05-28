"""Per-question tool routing for the memory agent (L5).

The memory agent registers ~163 tools globally; that exceeds both
Anthropic's 20-strict-tool cap and OpenAI's 128-total-tool cap, and
(more importantly) drowns the model in irrelevant tool descriptions
for any given question.

This module maps a free-text question to a focused "intent" -- and
each intent has a curated <=30-tool subset. Intents are detected via
keyword/regex matching; this is a deterministic router, NOT another
LLM call. Operators can override per-invocation with ``--tools t1 t2``
or escape with ``--all-tools``.

Intents:

* ``vuln_discovery``  -- "find a bug", "what's vulnerable", CWE family
                         keywords. Includes imports, strings, decompile,
                         CFG, xrefs, fact bundles.
* ``triage_summary``  -- "what is this", "summary", "format/platform".
                         Light: triage, strings, format detection.
* ``function_walk``   -- "explain X", "decompile X", "what does Y do".
                         decompile + xrefs + CFG.
* ``import_audit``    -- "list imports", "what APIs", "dangerous calls".
* ``string_audit``    -- "find strings", IOC extraction.
* ``broad_discovery`` -- fallback. The 25-tool baseline that covers
                         the union of vuln + triage + function_walk
                         (still well under the strict cap).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Intent:
    name: str
    tools: tuple[str, ...]
    keywords: tuple[str, ...]
    keyword_re: re.Pattern[str] | None = None


# Canonical tool names registered by glaurung.llm.agents.memory_agent
# .register_analysis_tools. Names listed here MUST match the actual
# `@agent.tool(name=...)` or `Tool(name=...)` strings; on mismatch the
# router silently no-ops (the agent will just have fewer tools, but
# nothing breaks).
#
# Subsets are chosen so that the largest intent (broad_discovery) sits
# comfortably under 30 tools, the Anthropic strict cap stays under 20
# for vuln_discovery, and every intent contains the lightweight
# triage/strings/imports trio so the model can always orient itself.
_CORE_TRIAGE_TOOLS: tuple[str, ...] = (
    "hash_file",
    "annotate_binary",
    "extract_strings",
    "list_imports",
    "list_exports",
    "list_functions",
    "detect_packer",
)

_DECOMPILE_TOOLS: tuple[str, ...] = (
    "decompile_function",
    "describe_call_site",
    "analyze_recursively",
)

_GRAPH_TOOLS: tuple[str, ...] = (
    "list_basic_blocks",
    "list_callers",
    "list_callees",
    "map_pe_iat",
    "map_elf_plt",
    "map_elf_got",
    "map_symbol_addresses",
)

_VULN_FACT_TOOLS: tuple[str, ...] = (
    # These tools require a .glaurung project SQLite DB; they fail with
    # "file is not a database" when called on a raw binary path. Kept
    # in a separate group so callers with a project DB available (the
    # ASB Lane-5 runner does have one) can opt them in via --all-tools
    # or an explicit tool list. The default vuln_discovery intent below
    # uses ONLY binary-path tools.
    "windows_project_callsite_facts",
    "windows_project_call_argument_snapshot",
    "windows_project_callgraph_slice",
    "windows_project_xref_query",
    "windows_project_memory_access_query",
    "windows_project_onehop_sink_chains",
)


_INTENTS: tuple[Intent, ...] = (
    Intent(
        name="vuln_discovery",
        tools=(
            _CORE_TRIAGE_TOOLS
            + _DECOMPILE_TOOLS
            + ("list_basic_blocks", "list_callers", "list_callees",
               "map_pe_iat", "map_symbol_addresses")
            # NB: windows_project_* tools are NOT included by default --
            # they require a .glaurung project DB the raw-binary `ask`
            # flow doesn't open. Use `--all-tools` when running against
            # a project DB.
        ),
        keywords=(
            "vuln", "vulnerab", "bug", "cwe-", "cwe ",
            "overflow", "use-after-free", "uaf", "double free",
            "format string", "off by one", "off-by-one",
            "integer overflow", "null deref", "null pointer",
            "out of bound", "out-of-bound", "memory corrupt",
            "race", "toctou", "double-fetch", "double fetch",
            "find any bug", "find a bug", "audit",
        ),
    ),
    Intent(
        name="triage_summary",
        tools=_CORE_TRIAGE_TOOLS,
        keywords=(
            "what is this", "what kind", "summary", "summarise",
            "summarize", "what format", "format", "platform",
            "pe or elf", "windows or linux", "is this pe",
            "is this elf", "metadata",
        ),
    ),
    Intent(
        name="function_walk",
        tools=_CORE_TRIAGE_TOOLS + _DECOMPILE_TOOLS + ("list_callers", "list_callees"),
        keywords=(
            "explain", "walk through", "what does", "describe function",
            "decompile", "pseudocode", "show me ",
        ),
    ),
    Intent(
        name="import_audit",
        tools=("list_imports", "list_exports", "annotate_binary",
               "map_pe_iat"),
        keywords=(
            "list imports", "what apis", "what api", "import table",
            "dangerous calls", "imported function",
        ),
    ),
    Intent(
        name="string_audit",
        tools=("extract_strings", "annotate_binary"),
        keywords=(
            "find strings", "extract strings", "ioc", "indicators of",
            "embedded urls", "what strings",
        ),
    ),
    Intent(
        name="broad_discovery",
        # Fallback: small enough to fit Anthropic's strict cap once
        # strict=False is in play, broad enough to handle anything.
        tools=(
            _CORE_TRIAGE_TOOLS
            + _DECOMPILE_TOOLS
            + ("list_basic_blocks", "list_callers", "list_callees",
               "map_pe_iat", "map_symbol_addresses")
        ),
        keywords=(),
    ),
)


def _normalize(text: str) -> str:
    return (text or "").lower().strip()


def route_for_question(question: str) -> Intent:
    """Pick the best-matching intent for ``question``.

    Resolution order: the first intent in :data:`_INTENTS` whose keyword
    list contains a token present in ``question`` wins. Ties resolve in
    declaration order (vuln_discovery > triage_summary > function_walk
    > …). Falls back to ``broad_discovery``.
    """
    q = _normalize(question)
    for intent in _INTENTS:
        for kw in intent.keywords:
            if kw and kw in q:
                return intent
        if intent.keyword_re and intent.keyword_re.search(q):
            return intent
    # Last entry is broad_discovery by construction.
    return _INTENTS[-1]


def select_tools_for_question(question: str) -> tuple[str, ...]:
    """Return the curated tool-name subset for the given question."""
    return route_for_question(question).tools


def list_intents() -> Iterable[Intent]:
    return _INTENTS


def intent_summary() -> str:
    """Human-readable summary, for --show-routing diagnostics."""
    lines = []
    for it in _INTENTS:
        lines.append(f"  {it.name}: {len(it.tools)} tools")
        if it.keywords:
            sample = ", ".join(it.keywords[:5])
            more = "" if len(it.keywords) <= 5 else f" (+{len(it.keywords) - 5} more)"
            lines.append(f"      keywords: {sample}{more}")
    return "\n".join(lines)
