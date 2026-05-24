"""`glaurung explain` -- rewrite one function into idiomatic source.

Two-stage Layer-1 -> Layer-2 pipeline driving the previously-unreachable
``rewrite_function_idiomatic`` tool (Tool #14):

  1. Tool #10 (``infer_function_signature``) recovers a C prototype with
     per-parameter direction / nullability / ownership annotations.
  2. Tool #14 (``rewrite_function_idiomatic``) rewrites the raw lifter
     pseudocode into idiomatic C (or Rust / Go) using that prototype.

For MVP the Layer-0 atomic-labeler tables (``variable_names``,
``constant_labels``, ``string_names``, ``loop_idioms``, structs / enums
/ error codes) are all left empty -- they are scoped to F4. The
rewriter still benefits from the prototype + role label + auto-fetched
pseudocode and produces noticeably cleaner C than raw decompile.

Flag matrix:

  --no-types     Skip Tool #10; pass a placeholder ``int sub_<va>(void *)``
                 prototype. Cheap-but-rough -- one fewer LLM call.
  --no-roles     Skip Tool #13 (role classifier).
  --no-layer0    (default behaviour for MVP -- explicit toggle for
                 callers that want to assert it). Always passes empty
                 Layer-0 dicts; here for symmetry with future F4.

The intended downstream consumer is agentic-security-bot's
``diff_explain.py``, which feeds the rewritten C body to a discriminator
LLM instead of the raw IR.
"""

from __future__ import annotations

import argparse
import json
import logging
from typing import Any, Optional

import glaurung as g

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat

log = logging.getLogger(__name__)


def _placeholder_prototype(va: int) -> str:
    """Return a minimal stand-in prototype when --no-types is requested."""
    return f"int sub_{va:x}(void *arg0);"


def _infer_prototype(
    *,
    file_path: str,
    artifact: Any,
    va: int,
    timeout_ms: int,
) -> tuple[str, str, float]:
    """Run Tool #10 against ``va``. Returns (c_prototype, source, confidence).

    ``source`` is ``"llm"`` or ``"heuristic"`` (matching the tool's own
    bookkeeping). On any unexpected exception, falls through to the
    placeholder prototype with ``source="error"`` so the rewrite stage
    can still proceed.
    """
    from glaurung.llm.context import Budgets, MemoryContext
    from glaurung.llm.tools.infer_function_signature import (
        InferFunctionSignatureArgs,
        InferFunctionSignatureTool,
    )

    ctx = MemoryContext(
        file_path=file_path,
        artifact=artifact,
        budgets=Budgets(timeout_ms=max(timeout_ms, 2000)),
    )
    tool = InferFunctionSignatureTool()
    try:
        result = tool.run(
            ctx,
            ctx.kb,
            InferFunctionSignatureArgs(
                va=int(va),
                timeout_ms=int(timeout_ms),
                use_llm=True,
            ),
        )
    except Exception as exc:  # pragma: no cover - surfaces as a fallback
        log.warning("infer_function_signature failed: %s", exc)
        return _placeholder_prototype(va), "error", 0.0
    sig = result.signature
    return sig.c_prototype, result.source, float(sig.confidence)


def _classify_role(
    *,
    file_path: str,
    artifact: Any,
    va: int,
    c_prototype: str,
    pseudocode: str,
    timeout_ms: int,
) -> tuple[Optional[str], str]:
    """Run Tool #13. Returns (role_label, source) or (None, "skipped")."""
    from glaurung.llm.context import Budgets, MemoryContext
    from glaurung.llm.tools.classify_function_role import (
        ClassifyFunctionRoleArgs,
        ClassifyFunctionRoleTool,
    )

    ctx = MemoryContext(
        file_path=file_path,
        artifact=artifact,
        budgets=Budgets(timeout_ms=max(timeout_ms, 2000)),
    )
    tool = ClassifyFunctionRoleTool()
    try:
        result = tool.run(
            ctx,
            ctx.kb,
            ClassifyFunctionRoleArgs(
                pseudocode=pseudocode,
                c_prototype=c_prototype,
                use_llm=True,
            ),
        )
    except Exception as exc:  # pragma: no cover - surfaces as None role
        log.warning("classify_function_role failed: %s", exc)
        return None, "error"
    return result.label.role, result.source


def _rewrite_idiomatic(
    *,
    file_path: str,
    artifact: Any,
    va: int,
    c_prototype: str,
    role: Optional[str],
    target_language: str,
    timeout_ms: int,
) -> dict[str, Any]:
    """Run Tool #14 with empty Layer-0 inputs (MVP)."""
    from glaurung.llm.context import Budgets, MemoryContext
    from glaurung.llm.tools.rewrite_function_idiomatic import (
        RewriteFunctionArgs,
        RewriteFunctionIdiomaticTool,
    )

    ctx = MemoryContext(
        file_path=file_path,
        artifact=artifact,
        budgets=Budgets(timeout_ms=max(timeout_ms, 2000)),
    )
    tool = RewriteFunctionIdiomaticTool()
    result = tool.run(
        ctx,
        ctx.kb,
        RewriteFunctionArgs(
            entry_va=int(va),
            c_prototype=c_prototype,
            role=role,
            # Layer-0 inputs intentionally empty for F3 (MVP); F4 wires
            # the atomic labelers and populates these tables.
            variable_names={},
            constant_labels={},
            string_names={},
            loop_idioms=[],
            structs=[],
            enums=[],
            error_codes=[],
            target_language=target_language,  # type: ignore[arg-type]
            timeout_ms=int(timeout_ms),
        ),
    )
    return {
        "source": result.rewrite.source,
        "language": result.rewrite.language,
        "assumptions": list(result.rewrite.assumptions),
        "confidence": float(result.rewrite.confidence),
        "rationale": result.rewrite.rationale,
        "rewrite_source": result.source,  # 'llm' | 'heuristic'
    }


class ExplainCommand(BaseCommand):
    """Rewrite a single function from raw IR into idiomatic source."""

    def get_name(self) -> str:
        return "explain"

    def get_help(self) -> str:
        return (
            "Rewrite one function via Tool #14 (rewrite_function_idiomatic). "
            "Inputs are auto-fetched (pseudocode) or recovered (prototype)."
        )

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", help="Path to file")
        parser.add_argument(
            "--func",
            dest="func",
            type=lambda x: int(x, 0),
            default=None,
            help="Entry VA of the function to explain (hex or decimal). "
            "If omitted, the detected entry point is used.",
        )
        parser.add_argument(
            "--style",
            choices=["c", "rust", "go"],
            default="c",
            help="Target language for the rewritten source (default: c).",
        )
        parser.add_argument(
            "--no-types",
            dest="use_types",
            action="store_false",
            default=True,
            help="Skip Tool #10 (signature inference); use a minimal "
            "placeholder prototype like 'int sub_<va>(void *)'.",
        )
        parser.add_argument(
            "--no-roles",
            dest="use_roles",
            action="store_false",
            default=True,
            help="Skip Tool #13 (role classification) -- the rewriter still "
            "runs, just without a role hint.",
        )
        parser.add_argument(
            "--no-layer0",
            dest="use_layer0",
            action="store_false",
            default=False,
            help="Layer-0 atomic labelers are not yet wired (F4 ticket). "
            "Flag is accepted for forward-compat / explicit MVP toggling.",
        )
        parser.add_argument(
            "--timeout-ms",
            type=int,
            default=2000,
            help="Per-stage analysis / LLM timeout in milliseconds "
            "(default: 2000).",
        )
        parser.add_argument(
            "--pdb-cache",
            default="",
            help="Optional Microsoft-style PDB cache directory used by the "
            "underlying decompile pass for call-target name resolution.",
        )
        parser.add_argument(
            "--cache-dir",
            default=None,
            help="Optional persistent cache directory. Reserved for future "
            "use -- the explain pipeline does not yet cache its own output. "
            "Tool #10 / Tool #14 themselves remain uncached.",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        try:
            path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        as_json = formatter.format_type in (OutputFormat.JSON, OutputFormat.JSONL)
        quiet = getattr(args, "quiet", False)

        # Resolve --func or fall back to entry detection (matches decompile).
        func_va: Optional[int] = args.func
        if func_va is None:
            got = g.analysis.detect_entry_path(str(path))
            if got is None:
                formatter.output_plain(
                    "Error: could not detect entry point; pass --func 0xVA"
                )
                return 2
            func_va = int(got[3])

        try:
            artifact = g.triage.analyze_path(str(path))
        except Exception as exc:
            formatter.output_plain(f"Error: triage failed: {exc}")
            return 1

        # Auto-fetch pseudocode once; we feed it to both Tool #13 and
        # (via the tool itself) Tool #14. Tool #14 will re-fetch if we
        # don't pass it explicitly, but doing it here lets us share with
        # the role classifier and lets --pdb-cache flow through.
        try:
            pseudocode = g.ir.decompile_at(
                str(path),
                int(func_va),
                timeout_ms=max(int(args.timeout_ms), 500),
                style="",
                pdb_cache=args.pdb_cache or "",
            )
        except Exception as exc:
            formatter.output_plain(f"Error: decompile failed: {exc}")
            return 1

        # Stage 1: signature inference (Tool #10).
        if args.use_types:
            c_prototype, proto_source, proto_conf = _infer_prototype(
                file_path=str(path),
                artifact=artifact,
                va=int(func_va),
                timeout_ms=int(args.timeout_ms),
            )
        else:
            c_prototype = _placeholder_prototype(int(func_va))
            proto_source = "skipped"
            proto_conf = 0.0

        # Stage 2: role classification (Tool #13). Cheap pre-pass.
        role: Optional[str] = None
        role_source = "skipped"
        if args.use_roles:
            role, role_source = _classify_role(
                file_path=str(path),
                artifact=artifact,
                va=int(func_va),
                c_prototype=c_prototype,
                pseudocode=pseudocode,
                timeout_ms=int(args.timeout_ms),
            )

        # Stage 3: idiomatic rewrite (Tool #14).
        try:
            rewrite = _rewrite_idiomatic(
                file_path=str(path),
                artifact=artifact,
                va=int(func_va),
                c_prototype=c_prototype,
                role=role,
                target_language=args.style,
                timeout_ms=int(args.timeout_ms),
            )
        except Exception as exc:  # pragma: no cover - surfaces as CLI error
            formatter.output_plain(f"Error: rewrite failed: {exc}")
            return 1

        if as_json:
            payload: dict[str, Any] = {
                "entry_va": int(func_va),
                "c_prototype": c_prototype,
                "role": role,
                "language": rewrite["language"],
                "source": rewrite["source"],
                "assumptions": rewrite["assumptions"],
                "confidence": rewrite["confidence"],
                "rationale": rewrite["rationale"],
                "stages": {
                    "infer_function_signature": {
                        "source": proto_source,
                        "confidence": proto_conf,
                    },
                    "classify_function_role": {
                        "source": role_source,
                    },
                    "rewrite_function_idiomatic": {
                        "source": rewrite["rewrite_source"],
                    },
                },
            }
            print(json.dumps(payload, indent=2))
            return 0

        # Plain text output: prototype banner + rewritten source.
        if not quiet:
            formatter.output_plain(f"// entry_va: {func_va:#x}")
            formatter.output_plain(f"// prototype-source: {proto_source}")
            if role is not None:
                formatter.output_plain(f"// role: {role} ({role_source})")
            formatter.output_plain(
                f"// rewrite-source: {rewrite['rewrite_source']} "
                f"(confidence {rewrite['confidence']:.2f})"
            )
            formatter.output_plain("")
        formatter.output_plain(rewrite["source"])
        if not quiet and rewrite["assumptions"]:
            formatter.output_plain("")
            formatter.output_plain("// assumptions:")
            for a in rewrite["assumptions"]:
                formatter.output_plain(f"//   - {a}")
        return 0
