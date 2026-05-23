"""Tests for L5: per-question tool routing."""

from __future__ import annotations

import pytest

from glaurung.llm.tool_routing import (
    Intent,
    list_intents,
    route_for_question,
    select_tools_for_question,
)


# ---- intent catalog sanity ----

def test_at_least_six_intents_in_catalog():
    names = {it.name for it in list_intents()}
    assert {"vuln_discovery", "triage_summary", "function_walk",
            "import_audit", "string_audit", "broad_discovery"} <= names


def test_no_intent_exceeds_strict_anthropic_cap_after_filter():
    """Each intent's tool count should fit Anthropic's 20-strict cap
    comfortably (we set strict=False on Anthropic via D2, but keeping
    intents under 30 keeps the model's tool-list digestible)."""
    for it in list_intents():
        assert len(it.tools) <= 30, (
            f"intent {it.name} has {len(it.tools)} tools (over the "
            "30-tool routing budget); split into a narrower intent."
        )


def test_every_intent_includes_at_least_one_triage_tool():
    """An intent that doesn't let the agent identify the file gracefully
    will fail in practice. Each intent should keep at least one of
    {annotate_binary, hash_file, list_imports, extract_strings}."""
    light = {"annotate_binary", "hash_file", "list_imports",
             "extract_strings", "list_exports", "list_functions"}
    for it in list_intents():
        assert light & set(it.tools), (
            f"intent {it.name} has none of {light} -- agent can't "
            "even orient itself."
        )


# ---- routing decisions ----

@pytest.mark.parametrize("question,expected_intent", [
    ("Find any obvious bug in the application's own code.", "vuln_discovery"),
    ("Is there a CWE-121 stack buffer overflow somewhere?", "vuln_discovery"),
    ("Look for a use-after-free in the session handler", "vuln_discovery"),
    ("Could this binary have an integer overflow before alloc?", "vuln_discovery"),
    ("Find a format string bug", "vuln_discovery"),
    ("Find a double-fetch race", "vuln_discovery"),
])
def test_vuln_questions_route_to_vuln_intent(question, expected_intent):
    assert route_for_question(question).name == expected_intent


@pytest.mark.parametrize("question", [
    "What is this binary?",
    "What format is this file?",
    "Give me a summary of the file",
    "Is this PE or ELF?",
])
def test_triage_questions_route_to_triage(question):
    assert route_for_question(question).name == "triage_summary"


@pytest.mark.parametrize("question", [
    "Decompile main",
    "Explain function 0x140001480",
    "What does sub_140001480 do?",
])
def test_function_walk_routing(question):
    intent = route_for_question(question)
    assert intent.name in ("function_walk", "vuln_discovery"), (
        # 'Explain X' may legitimately route to either; only fail if
        # we hit a totally unexpected intent.
        f"expected function_walk-ish, got {intent.name}"
    )


def test_unrelated_question_falls_back_to_broad_discovery():
    intent = route_for_question("What's the answer to the universe?")
    assert intent.name == "broad_discovery"


def test_empty_question_falls_back_to_broad_discovery():
    assert route_for_question("").name == "broad_discovery"
    assert route_for_question("   ").name == "broad_discovery"


def test_select_tools_for_question_returns_tuple_of_names():
    tools = select_tools_for_question("find any vulnerability")
    assert isinstance(tools, tuple)
    assert all(isinstance(t, str) for t in tools)
    assert len(tools) >= 5
    assert "annotate_binary" in tools or "extract_strings" in tools


# ---- register_analysis_tools filter wiring ----

def test_tool_filter_excludes_named_tools_when_applied():
    """``register_analysis_tools(agent, tool_filter={'list_imports'})``
    should leave only that tool in the agent's toolset (or empty if the
    name doesn't match; pre-filter ensures it does)."""
    pytest.importorskip("pydantic_ai")

    from glaurung.llm.agents.memory_foundation import create_foundation_agent
    from glaurung.llm.agents.memory_agent import register_analysis_tools

    cfg_model = "test"  # avoid hitting any real backend
    agent = create_foundation_agent(model=cfg_model)
    register_analysis_tools(agent, model_name=cfg_model,
                            tool_filter={"list_imports", "annotate_binary"})

    toolset = getattr(agent, "_function_toolset", None)
    assert toolset is not None, "expected pydantic-ai _function_toolset"
    tools = getattr(toolset, "_tools", None) or getattr(toolset, "tools", None)
    assert isinstance(tools, dict)
    # Of the ~163 tools normally registered, only our two should survive.
    surviving = set(tools.keys())
    assert surviving <= {"list_imports", "annotate_binary"}, (
        f"filter let through unexpected tools: "
        f"{surviving - {'list_imports', 'annotate_binary'}}"
    )
    assert surviving, "filter removed everything; check tool name match"


def test_tool_filter_silently_ignores_unknown_names():
    """Passing a filter with names that don't match any tool should not
    crash -- just yield an empty toolset."""
    pytest.importorskip("pydantic_ai")

    from glaurung.llm.agents.memory_foundation import create_foundation_agent
    from glaurung.llm.agents.memory_agent import register_analysis_tools

    agent = create_foundation_agent(model="test")
    register_analysis_tools(agent, model_name="test",
                            tool_filter={"this_tool_does_not_exist_at_all"})
    toolset = agent._function_toolset
    tools = getattr(toolset, "_tools", None) or getattr(toolset, "tools", {})
    assert tools == {}
