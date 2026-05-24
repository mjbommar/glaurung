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
import logging
import os
from pathlib import Path
from typing import Optional

import glaurung as g

from .base import BaseCommand
from .. import cache as _cache
from ..formatters.base import BaseFormatter, OutputFormat

log = logging.getLogger(__name__)


def _build_name_func_cache_paths(
    *,
    cache_dir_arg: Optional[str],
    binary_path: str,
    func_va: int,
    model_name: str,
    original_name: Optional[str],
):
    """Resolve cache paths for a name-func invocation.

    Returns a :class:`_cache.CachePaths` on success, ``None`` if the
    cache is disabled or any setup step fails. Errors are swallowed
    so the caller can degrade gracefully.
    """

    cache_dir = _cache.resolve_cache_dir(cache_dir_arg)
    if cache_dir is None:
        return None
    try:
        binary_sha = _cache.sha256_file(Path(binary_path))
        flags = _cache.canonical_flag_dict(
            [
                ("model", model_name),
                # The user-provided original-name hint is fed verbatim
                # into the LLM prompt, so it materially affects output.
                ("original_name", original_name or ""),
                # Temperature is fixed at the default for name-func
                # today (no --temperature flag); pin it explicitly so
                # introducing one later naturally invalidates entries.
                ("temperature", "default"),
                ("schema", 1),
            ]
        )
        return _cache.build_paths(
            cache_dir,
            namespace="name-func",
            binary_sha256=binary_sha,
            va=func_va,
            flags=flags,
            suffix=".json",
        )
    except OSError as exc:
        log.warning("name-func cache: setup failed (%s); falling back to live run", exc)
        return None


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
        parser.add_argument(
            "--cache-dir",
            default=None,
            help="Optional persistent cache directory for name-func output. "
            "Entries are keyed by (glaurung version, sha256(binary), VA, "
            "model + original-name hint). Falls back to "
            "$GLAURUNG_CACHE_DIR when unset. Append-only — clear the "
            "directory manually if disk fills up.",
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

        model_name = cfg.preferred_model()

        # Cache check — if we already have an entry for this
        # (binary, va, model, original-name hint), skip the LLM call.
        cache_paths = _build_name_func_cache_paths(
            cache_dir_arg=args.cache_dir,
            binary_path=str(path),
            func_va=int(func_va),
            model_name=model_name,
            original_name=args.original_name,
        )
        cached_payload: Optional[dict] = None
        if cache_paths is not None:
            hit = _cache.read_text(cache_paths)
            if hit is not None:
                try:
                    cached_payload = json.loads(hit)
                    log.debug("name-func cache HIT %s", cache_paths.file)
                except ValueError as exc:
                    log.warning(
                        "name-func cache: corrupt entry %s (%s); recomputing",
                        cache_paths.file,
                        exc,
                    )
                    cached_payload = None
            else:
                log.debug("name-func cache MISS %s", cache_paths.file)

        if cached_payload is not None:
            payload = cached_payload
        else:
            # Build a minimal MemoryContext — the suggest tool only
            # needs file_path + an artifact + budgets.
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
            payload = {
                "entry_va": int(func_va),
                "suggested_name": s.name,
                "confidence": s.confidence,
                "summary": s.summary,
                "rationale": s.rationale,
                "model": model_name,
            }
            if cache_paths is not None:
                _cache.write_text(cache_paths, json.dumps(payload, indent=2))

        as_json = formatter.format_type in (OutputFormat.JSON, OutputFormat.JSONL)
        if as_json:
            print(json.dumps(payload, indent=2))
        else:
            formatter.output_plain(f"suggested name: {payload['suggested_name']}")
            formatter.output_plain(
                f"confidence:     {float(payload['confidence']):.2f}"
            )
            if payload.get("summary"):
                formatter.output_plain(f"summary:        {payload['summary']}")
            if payload.get("rationale"):
                formatter.output_plain(f"rationale:      {payload['rationale']}")
            formatter.output_plain(
                f"model:          {payload.get('model', model_name)}"
            )
        return 0
