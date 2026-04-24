"""Live-API smoke tests for the LLM-backed function naming.

These tests actually hit the configured LLM provider (Anthropic by
preference, OpenAI as fallback). They are gated by the
``GLAURUNG_LIVE_LLM`` environment variable — unset by default, so `pytest`
skips them during normal development and CI. Set ``GLAURUNG_LIVE_LLM=1``
(and ensure ``ANTHROPIC_API_KEY`` or ``OPENAI_API_KEY`` is exported) to
run them.

The assertions are deliberately soft: LLM output is stochastic, so we
check for *semantic overlap* with the ground truth (the suggested name
mentions at least one of the expected keywords) rather than a strict
equality. If the model veers wildly off-topic this still catches it; if
it produces e.g. `dump_config_info` instead of `print_config`, that's a
pass.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import glaurung as g


LIVE = os.environ.get("GLAURUNG_LIVE_LLM") == "1"


def _has_credentials() -> bool:
    return bool(
        os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
    )


pytestmark = pytest.mark.skipif(
    not (LIVE and _has_credentials()),
    reason="live LLM test — set GLAURUNG_LIVE_LLM=1 and provide a model key",
)


C2_SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/c2_demo-gcc-O2"
)
HELLO_SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
)


def _name_func(path: Path, va: int) -> tuple[str, float, str, str]:
    from glaurung.llm.context import MemoryContext, Budgets
    from glaurung.llm.kb.adapters import import_triage
    from glaurung.llm.tools.suggest_function_name import (
        SuggestFunctionNameArgs,
        SuggestFunctionNameTool,
    )

    art = g.triage.analyze_path(str(path))
    ctx = MemoryContext(
        file_path=str(path),
        artifact=art,
        budgets=Budgets(timeout_ms=5000),
    )
    import_triage(ctx.kb, art, str(path))
    tool = SuggestFunctionNameTool()
    result = tool.run(
        ctx,
        ctx.kb,
        SuggestFunctionNameArgs(
            va=va, original_name=None, use_llm=True, add_to_kb=False
        ),
    )
    s = result.suggestion
    return s.name, s.confidence, s.summary, s.rationale


@pytest.mark.skipif(not C2_SAMPLE.exists(), reason="c2_demo sample missing")
def test_c2_demo_main_is_named_something_print_or_config_related():
    # c2_demo's main is a fprintf-heavy configuration dumper. The LLM
    # should pick a name that mentions at least one of: print, config,
    # dump, display.
    name, conf, summary, rationale = _name_func(C2_SAMPLE, 0x10C0)
    text = " ".join([name, summary, rationale]).lower()
    assert any(
        kw in text for kw in ("print", "config", "dump", "display", "log")
    ), f"unexpected naming output: name={name!r} summary={summary!r}"
    assert conf >= 0.2, "model returned very low confidence"


@pytest.mark.skipif(not HELLO_SAMPLE.exists(), reason="hello sample missing")
def test_hello_start_is_named_as_entry_point():
    # hello-gcc-O2's _start is the ELF entry stub. Expected keywords:
    # start, entry, init, libc, main.
    name, conf, summary, rationale = _name_func(HELLO_SAMPLE, 0x1840)
    text = " ".join([name, summary, rationale]).lower()
    assert any(
        kw in text for kw in ("start", "entry", "init", "libc", "main")
    ), f"unexpected naming output: name={name!r} summary={summary!r}"
