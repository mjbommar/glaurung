"""`glaurung explain` -- rewrite one function into idiomatic source.

Multi-stage Layer-0 -> Layer-1 -> Layer-2 pipeline driving the
previously-unreachable ``rewrite_function_idiomatic`` tool (Tool #14):

  0. (optional, ``--with-layer0``) F4 atomic labelers:
     - Tool #5 ``name_local_variable``  -> ``variable_names``
     - Tool #3 ``name_string_literal``  -> ``string_names``
     - Tool #2 ``classify_constant``    -> ``constant_labels``
  1. Tool #10 (``infer_function_signature``) recovers a C prototype with
     per-parameter direction / nullability / ownership annotations.
  2. Tool #13 (``classify_function_role``) labels the function with a
     coarse role tag (``parser`` / ``network_handler`` / ...).
  3. Tool #14 (``rewrite_function_idiomatic``) rewrites the raw lifter
     pseudocode into idiomatic C (or Rust / Go) using prototype +
     role + (when enabled) the Layer-0 substitution tables.

The Layer-0 pre-pass is OFF by default because it adds 10-30 LLM
calls per function (~$0.20-$0.50 at gpt-5.4-mini-flex). Operators
opt in with ``--with-layer0`` once they care about the readability
delta. Each Layer-0 call is keyed against the A7 cache via
``--cache-dir`` / ``$GLAURUNG_CACHE_DIR`` so the same call across
CVE months hits the cache for free.

Flag matrix:

  --no-types       Skip Tool #10; pass a placeholder
                   ``int sub_<va>(void *)`` prototype.
  --no-roles       Skip Tool #13 (role classifier).
  --with-layer0    Enable the F4 Layer-0 pre-pass. Off by default.
  --no-layer0      Force-disable. Default behaviour; kept for symmetry.
  --cache-dir DIR  A7 cache directory; feeds the Layer-0 prepass and
                   (in the future) the rewrite output cache.

JSON output extension: when --with-layer0 is set, the payload grows
a ``"layer0"`` block recording every (input, output) pair the
pre-pass resolved -- the audit log that proves which ``var0`` got
renamed to what.
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
    variable_names: Optional[dict[str, str]] = None,
    string_names: Optional[dict[str, str]] = None,
    constant_labels: Optional[dict[str, str]] = None,
    fidelity: str = "tldr",
    suspicious_vas: Optional[list[int]] = None,
    struct_pack: Optional[list[Any]] = None,
) -> dict[str, Any]:
    """Run Tool #14. Layer-0 dicts populated by F4 prepass when enabled.

    Returns one of two dict shapes depending on ``fidelity``:
      - fidelity='tldr' (default): keys source / language / assumptions /
        confidence / rationale / rewrite_source. Single source string,
        idiomatic compressed rewrite.
      - fidelity='annotated': keys prototype / blocks / assumptions /
        confidence / rationale / rewrite_source. blocks is a list of
        CodeBlock dicts (start_va / end_va / lifted_c / calls /
        mem_accesses / branches / block_confidence). For bug-hunting.
    """
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
            fidelity=fidelity,  # type: ignore[arg-type]
            suspicious_vas=suspicious_vas or [],
            # Layer-0 tables: populated by F4 prepass when
            # --with-layer0 is set, else empty (F3 behaviour).
            variable_names=variable_names or {},
            constant_labels=constant_labels or {},
            string_names=string_names or {},
            loop_idioms=[],
            structs=list(struct_pack) if struct_pack else [],
            enums=[],
            error_codes=[],
            target_language=target_language,  # type: ignore[arg-type]
            timeout_ms=int(timeout_ms),
        ),
    )

    if fidelity == "annotated" and result.annotated is not None:
        ann = result.annotated
        return {
            "fidelity": "annotated",
            "prototype": ann.prototype,
            "blocks": [b.model_dump() for b in ann.blocks],
            "assumptions": list(ann.assumptions),
            "confidence": float(ann.overall_confidence),
            "rationale": ann.rationale,
            "rewrite_source": result.source,
        }

    rw = result.rewrite
    return {
        "fidelity": "tldr",
        "source": rw.source,
        "language": rw.language,
        "assumptions": list(rw.assumptions),
        "confidence": float(rw.confidence),
        "rationale": rw.rationale,
        "rewrite_source": result.source,
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
            "--with-layer0",
            dest="use_layer0",
            action="store_true",
            default=False,
            help="Enable the F4 Layer-0 atomic-labeler pre-pass: runs "
            "Tools #5 / #3 / #2 to populate variable_names / "
            "string_names / constant_labels before Tool #14. Adds "
            "10-30 LLM calls per function (~$0.20-$0.50). Off by "
            "default. A7 cache via --cache-dir / GLAURUNG_CACHE_DIR "
            "amortizes cost across CVE months.",
        )
        parser.add_argument(
            "--no-layer0",
            dest="use_layer0",
            action="store_false",
            help="Force-disable the F4 Layer-0 pre-pass (default).",
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
            help="Optional A7 persistent cache directory. With "
            "--with-layer0 each Layer-0 call (Tool #5 / #3 / #2) is "
            "cached by (binary sha, va, kind, input). Falls back to "
            "$GLAURUNG_CACHE_DIR when unset. Tool #10 / Tool #14 "
            "themselves remain uncached for now.",
        )
        parser.add_argument(
            "--fidelity",
            choices=["tldr", "annotated"],
            default="tldr",
            help="Rewrite preset. 'tldr' (default) = idiomatic compressed "
            "rewrite for source recovery / readability. 'annotated' = "
            "per-basic-block faithful for bug-hunting triage; emits a "
            "block list with start_va/end_va/lifted_c plus enumerated "
            "calls/mem_accesses/branches per block. Use 'annotated' when "
            "feeding the output to a vulnerability reviewer.",
        )
        parser.add_argument(
            "--suspicious-va",
            dest="suspicious_vas",
            action="append",
            type=lambda x: int(x, 0),
            default=[],
            help="VA (hex/decimal) of a region a static rule fired on. "
            "Repeatable. The annotated rewriter biases attention here -- "
            "blocks containing these VAs are emitted with extra fidelity.",
        )
        parser.add_argument(
            "--require-llm",
            action="store_true",
            default=False,
            help="Hard-fail (non-zero exit) when the LLM is unreachable "
            "instead of silently degrading to the heuristic fallback. "
            "Recommended for automation/batch pipelines where heuristic "
            "output downstream would be mistaken for an LLM lift. Same "
            "effect as GLAURUNG_REQUIRE_LLM=1.",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        try:
            path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        # --require-llm sets the env var that run_structured_llm
        # checks; this propagates through every Tool #14/Tool #10/etc.
        # call inside the rewrite stack without needing to thread a
        # kwarg through every layer.
        if getattr(args, "require_llm", False):
            import os
            os.environ["GLAURUNG_REQUIRE_LLM"] = "1"

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

        # Stage 2.5: Layer-0 atomic labelers (F4, opt-in).
        layer0_result = None
        layer0_source = "skipped"
        if args.use_layer0:
            try:
                from ._layer0_prepass import run_layer0_prepass

                layer0_result = run_layer0_prepass(
                    file_path=str(path),
                    va=int(func_va),
                    pseudocode=pseudocode,
                    artifact=artifact,
                    timeout_ms=int(args.timeout_ms),
                    use_llm=True,
                    cache_dir_arg=args.cache_dir,
                )
                layer0_source = "enabled"
            except Exception as exc:  # pragma: no cover - surfaces as CLI warning
                log.warning("layer0 prepass failed: %s", exc)
                layer0_source = "error"

        # Stage 3: idiomatic rewrite (Tool #14).
        # For annotated mode, inject the curated Windows-kernel struct
        # pack when the role classifier says kernel. Lets Tool #14
        # resolve raw `[arg1 + 0x18]` offsets to `irp->AssociatedIrp.SystemBuffer`.
        struct_pack: list[Any] = []
        if args.fidelity == "annotated":
            from ._kernel_struct_pack import kernel_struct_pack_for_role
            struct_pack = kernel_struct_pack_for_role(role)
        try:
            rewrite = _rewrite_idiomatic(
                file_path=str(path),
                artifact=artifact,
                va=int(func_va),
                c_prototype=c_prototype,
                role=role,
                target_language=args.style,
                timeout_ms=int(args.timeout_ms),
                variable_names=(
                    layer0_result.variable_names if layer0_result else None
                ),
                string_names=(
                    layer0_result.string_names if layer0_result else None
                ),
                constant_labels=(
                    layer0_result.constant_labels if layer0_result else None
                ),
                fidelity=args.fidelity,
                suspicious_vas=list(args.suspicious_vas),
                struct_pack=struct_pack,
            )
        except Exception as exc:  # pragma: no cover - surfaces as CLI error
            formatter.output_plain(f"Error: rewrite failed: {exc}")
            return 1

        if as_json:
            payload: dict[str, Any] = {
                "entry_va": int(func_va),
                "c_prototype": c_prototype,
                "role": role,
                "fidelity": rewrite.get("fidelity", "tldr"),
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
                    "layer0_prepass": {
                        "source": layer0_source,
                    },
                    "rewrite_function_idiomatic": {
                        "source": rewrite["rewrite_source"],
                    },
                },
            }
            if rewrite.get("fidelity") == "annotated":
                payload["prototype"] = rewrite["prototype"]
                payload["blocks"] = rewrite["blocks"]
            else:
                payload["language"] = rewrite["language"]
                payload["source"] = rewrite["source"]
            if layer0_result is not None:
                payload["layer0"] = layer0_result.to_json()
            print(json.dumps(payload, indent=2))
            return 0

        # Plain text output: prototype banner + rewritten source.
        if not quiet:
            formatter.output_plain(f"// entry_va: {func_va:#x}")
            formatter.output_plain(f"// prototype-source: {proto_source}")
            if role is not None:
                formatter.output_plain(f"// role: {role} ({role_source})")
            if layer0_result is not None:
                formatter.output_plain(
                    f"// layer0: vars={len(layer0_result.variable_names)} "
                    f"strs={len(layer0_result.string_names)} "
                    f"consts={len(layer0_result.constant_labels)} "
                    f"(llm={layer0_result.llm_calls} "
                    f"cache={layer0_result.cache_hits})"
                )
            formatter.output_plain(
                f"// rewrite-source: {rewrite['rewrite_source']} "
                f"(fidelity={rewrite.get('fidelity', 'tldr')}, "
                f"confidence {rewrite['confidence']:.2f})"
            )
            formatter.output_plain("")
        if rewrite.get("fidelity") == "annotated":
            # Render each CodeBlock as a labelled chunk so the output is
            # still human-readable in plain text mode.
            formatter.output_plain(
                f"// prototype: {rewrite.get('prototype', c_prototype)}"
            )
            if args.suspicious_vas:
                sv = ", ".join(f"0x{v:x}" for v in args.suspicious_vas)
                formatter.output_plain(f"// suspicious VAs: {sv}")
            formatter.output_plain("")
            for i, blk in enumerate(rewrite["blocks"]):
                formatter.output_plain(
                    f"// ---- block {i}: {blk['start_va']}..{blk['end_va']} "
                    f"(confidence {blk['block_confidence']:.2f}) ----"
                )
                formatter.output_plain(blk["lifted_c"])
                if blk.get("calls"):
                    formatter.output_plain("// calls in this block:")
                    for c in blk["calls"]:
                        notable = " (notable)" if c.get("notable") else ""
                        formatter.output_plain(
                            f"//   {c['call_va']} -> {c['callee']} "
                            f"[{c.get('kind', 'direct')}]{notable}"
                        )
                if blk.get("mem_accesses"):
                    formatter.output_plain("// mem accesses in this block:")
                    for m in blk["mem_accesses"]:
                        formatter.output_plain(
                            f"//   {m['va']} {m['kind']} "
                            f"w={m['width']} {m['addr_expr']}"
                        )
                if blk.get("branches"):
                    formatter.output_plain("// branches in this block:")
                    for b in blk["branches"]:
                        tgt = b.get("target_va") or "-"
                        pred = b.get("predicate") or ""
                        formatter.output_plain(
                            f"//   {b['va']} {b['kind']} -> {tgt}"
                            + (f"  ({pred})" if pred else "")
                        )
                formatter.output_plain("")
        else:
            formatter.output_plain(rewrite["source"])
        if not quiet and rewrite["assumptions"]:
            formatter.output_plain("")
            formatter.output_plain("// assumptions:")
            for a in rewrite["assumptions"]:
                formatter.output_plain(f"//   - {a}")
        return 0
