"""`glaurung name-func` — LLM-backed function naming CLI shim.

Thin wrapper around :mod:`glaurung.llm.tools.suggest_function_name` that
takes a binary and a function VA, assembles the pseudocode + symbol
context, and returns the suggested name. Requires an API key to be
present in the environment (either ``ANTHROPIC_API_KEY`` or
``OPENAI_API_KEY``). Without either, prints a helpful error.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Optional

import glaurung as g

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class NameFuncCommand(BaseCommand):
    """Suggest an LLM-derived name for a single function."""

    def get_name(self) -> str:
        return "name-func"

    def get_help(self) -> str:
        return "Suggest a name for a function via LLM + decompiled pseudocode"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", help="Path to binary")
        parser.add_argument(
            "--func",
            dest="func",
            type=lambda x: int(x, 0),
            default=None,
            help="Function entry VA (hex or decimal). Defaults to the "
                 "binary's detected entry point.",
        )
        parser.add_argument(
            "--original",
            dest="original_name",
            default=None,
            help="Original / mangled name if known (given to the model as "
                 "soft context).",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        try:
            path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        # Credential check up-front — failing fast here gives a much better
        # error than watching pydantic-ai raise deep inside an agent call.
        from glaurung.llm.config import LLMConfig

        cfg = LLMConfig()
        avail = cfg.available_models()
        if not (avail.get("anthropic") or avail.get("openai")):
            formatter.output_plain(
                "Error: no LLM API key found. Set ANTHROPIC_API_KEY (preferred) "
                "or OPENAI_API_KEY in your environment."
            )
            return 2

        func_va: Optional[int] = args.func
        if func_va is None:
            got = g.analysis.detect_entry_path(str(path))
            if got is None:
                formatter.output_plain(
                    "Error: could not detect entry point; pass --func 0xVA"
                )
                return 2
            func_va = int(got[3])

        # Build a minimal MemoryContext — the suggest tool only needs
        # file_path + an artifact + budgets.
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
        try:
            result = tool.run(
                ctx,
                ctx.kb,
                SuggestFunctionNameArgs(
                    va=int(func_va),
                    original_name=args.original_name,
                    use_llm=True,
                    add_to_kb=False,
                ),
            )
        except Exception as e:  # pragma: no cover — surfaces as CLI error
            formatter.output_plain(f"Error: {e}")
            return 1

        s = result.suggestion
        as_json = formatter.format_type in (OutputFormat.JSON, OutputFormat.JSONL)
        if as_json:
            payload = {
                "entry_va": int(func_va),
                "suggested_name": s.name,
                "confidence": s.confidence,
                "summary": s.summary,
                "rationale": s.rationale,
                "model": cfg.preferred_model(),
            }
            print(json.dumps(payload, indent=2))
        else:
            formatter.output_plain(f"suggested name: {s.name}")
            formatter.output_plain(f"confidence:     {s.confidence:.2f}")
            if s.summary:
                formatter.output_plain(f"summary:        {s.summary}")
            if s.rationale:
                formatter.output_plain(f"rationale:      {s.rationale}")
            formatter.output_plain(f"model:          {cfg.preferred_model()}")
        return 0
