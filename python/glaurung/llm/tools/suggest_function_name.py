"""Tool for suggesting function names using LLM and KB context."""

from __future__ import annotations

from pydantic import BaseModel, Field
from pydantic_ai import Agent

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class SuggestFunctionNameArgs(BaseModel):
    va: int = Field(..., description="Virtual address of the function")
    original_name: str | None = Field(
        None, description="Original/mangled name if available"
    )
    max_instructions: int = Field(64, description="Max instructions to analyze")
    use_llm: bool = Field(
        True, description="Use LLM for suggestions (vs heuristics only)"
    )
    add_to_kb: bool = Field(True, description="Add result to KB")


class SuggestedFunctionName(BaseModel):
    name: str = Field(..., description="Suggested function name")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in suggestion")
    summary: str = Field("", description="Brief description of function purpose")
    rationale: str = Field("", description="Why this name was chosen")


class SuggestFunctionNameResult(BaseModel):
    suggestion: SuggestedFunctionName
    evidence_node_id: str | None = None


class SuggestFunctionNameTool(
    MemoryTool[SuggestFunctionNameArgs, SuggestFunctionNameResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="name_function",
                description="Suggest a meaningful name for a function based on calls/strings/disasm.",
                tags=("analysis", "llm", "kb"),
            ),
            SuggestFunctionNameArgs,
            SuggestFunctionNameResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: SuggestFunctionNameArgs
    ) -> SuggestFunctionNameResult:
        # First try to demangle if we have an original name
        demangled_name = None
        if args.original_name:
            try:
                result = g.strings.demangle_text(args.original_name)
                if result:
                    demangled_name, _flavor = result
            except Exception:
                pass

        # Do not blindly trust original or demangled names; treat as context only.

        # Gather context from disassembly
        instructions = []
        calls = []
        strings = []

        try:
            instrs = g.disasm.disassemble_window_at(
                ctx.file_path,
                int(args.va),
                window_bytes=1024,
                max_instructions=args.max_instructions,
                max_time_ms=ctx.budgets.timeout_ms,
            )

            # Try to get symbol maps for call resolution
            sym_map = {}
            plt_map = {}
            try:
                sym_list = g.symbols.symbol_address_map(ctx.file_path)
                sym_map = {int(a): s for (a, s) in sym_list}
            except Exception:
                pass
            try:
                plt_list = g.analysis.elf_plt_map_path(ctx.file_path)
                plt_map = {int(a): s for (a, s) in plt_list}
            except Exception:
                pass

            # Analyze instructions
            for ins in instrs:
                # Look for calls
                try:
                    if hasattr(ins, "is_call") and ins.is_call():
                        for op in ins.operands:
                            if str(getattr(op, "kind", "")).lower() == "immediate":
                                try:
                                    target = int(str(getattr(op, "text", "")), 16)
                                    name = sym_map.get(target) or plt_map.get(target)
                                    if name:
                                        calls.append(name)
                                except Exception:
                                    pass
                except Exception:
                    pass

                # Look for string references (simplified)
                # This would need more sophisticated analysis for real string extraction
                instructions.append(
                    f"{ins.mnemonic} "
                    + ", ".join(str(o) for o in getattr(ins, "operands", []))
                )
        except Exception:
            pass

        # Search KB for relevant strings near this address
        try:
            string_nodes = [n for n in kb.nodes() if n.kind == NodeKind.string]
            for sn in string_nodes[:10]:  # Limit to first 10
                if sn.label and len(sn.label) > 3:
                    strings.append(sn.label)
        except Exception:
            pass

        if args.use_llm:
            # Use LLM to suggest name based on context
            suggestion = self._suggest_with_llm(
                original_name=args.original_name or f"sub_{args.va:x}",
                demangled_name=demangled_name,
                instructions=instructions[:24],  # First 24 instructions
                calls=calls,
                strings=strings,
                ctx=ctx,
                va=int(args.va),
            )
        else:
            # Use heuristics only
            suggestion = self._suggest_with_heuristics(
                original_name=args.original_name or f"sub_{args.va:x}",
                demangled_name=demangled_name,
                calls=calls,
                strings=strings,
                va=args.va,
            )

        # Ensure uniqueness: append VA suffix and normalize
        suffix = f"_{int(args.va):x}"
        base = suggestion.name or f"sub{suffix}"
        import re as _re

        def _slugify(n: str) -> str:
            n = n.strip()
            n = _re.sub(r"\(.*\)$", "", n)
            n = _re.sub(r"[<>]", "", n)
            n = _re.sub(r"[\s:/\\\-]+", "_", n)
            n = _re.sub(r"[^A-Za-z0-9_]", "", n)
            n = _re.sub(r"_+", "_", n)
            return n.strip("_").lower() or "func"

        final_name = _slugify(base) + suffix
        suggestion = SuggestedFunctionName(
            name=final_name,
            confidence=suggestion.confidence,
            summary=suggestion.summary,
            rationale=suggestion.rationale,
        )

        # Add to KB if requested
        ev_id = None
        if args.add_to_kb:
            ev = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="function_name_suggestion",
                    props={
                        "va": args.va,
                        "suggested_name": suggestion.name,
                        "confidence": suggestion.confidence,
                    },
                )
            )
            ev_id = ev.id
            # Link to file node
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))

        return SuggestFunctionNameResult(suggestion=suggestion, evidence_node_id=ev_id)

    def _suggest_with_llm(
        self,
        original_name: str,
        demangled_name: str | None,
        instructions: list[str],
        calls: list[str],
        strings: list[str],
        ctx: MemoryContext,
        va: int | None = None,
    ) -> SuggestedFunctionName:
        """Use LLM to suggest a function name based on decompiled pseudocode.

        Richer prompt than the legacy path: when a VA is known, we ask the
        glaurung decompiler for a C-style rendering of the function and
        include that as the primary evidence. Falls back to the raw
        instruction / call / string context when decompilation fails.
        """
        import asyncio

        from ..config import get_config

        cfg = get_config()
        avail = cfg.available_models()

        # If no LLM available, fall back to heuristics
        if not any(avail.values()):
            return self._suggest_with_heuristics(
                original_name, demangled_name, calls, strings, 0
            )

        # If called from within a running event loop (e.g. as a tool inside
        # another pydantic-ai Agent), Agent.run_sync cannot drive a nested
        # loop — it will raise and orphan the inner coroutine. Detect this
        # and use heuristics instead of creating an unawaitable coroutine.
        try:
            asyncio.get_running_loop()
            return self._suggest_with_heuristics(
                original_name, demangled_name, calls, strings, 0
            )
        except RuntimeError:
            pass

        prompt = build_naming_prompt(
            ctx=ctx,
            va=va,
            original_name=original_name,
            demangled_name=demangled_name,
            instructions=instructions,
            calls=calls,
            strings=strings,
        )

        # Use the best available model — Claude Opus 4.7 preferred, GPT-5.5
        # fallback. See llm/config.py::preferred_model().
        agent = Agent[str, SuggestedFunctionName](
            model=cfg.preferred_model(),
            output_type=SuggestedFunctionName,
            system_prompt=(
                "You are a reverse engineering assistant. You will be shown "
                "glaurung-decompiled pseudocode for one function. Your task "
                "is to suggest a concise, descriptive name for that function "
                "in snake_case. Consider the function's behavior: which "
                "library functions it calls, which string literals it uses, "
                "what control flow it performs, and what data it touches. "
                "Original / mangled names are unreliable — weigh them "
                "lightly and prefer evidence from the code."
            ),
        )

        try:
            result = agent.run_sync(prompt)
            return result.output
        except Exception:
            # Fallback to heuristics if LLM fails
            return self._suggest_with_heuristics(
                original_name, demangled_name, calls, strings, 0
            )

    def _suggest_with_heuristics(
        self,
        original_name: str,
        demangled_name: str | None,
        calls: list[str],
        strings: list[str],
        va: int,
    ) -> SuggestedFunctionName:
        """Simple heuristic-based name suggestion."""
        # If we have a good demangled name, use it
        if demangled_name and demangled_name != original_name:
            return SuggestedFunctionName(
                name=demangled_name,
                confidence=0.85,
                summary="Demangled C++ name",
                rationale="Successfully demangled from mangled name",
            )

        # Check for common patterns in calls
        name = None
        confidence = 0.5
        summary = ""
        rationale = ""

        if any("print" in c.lower() or "puts" in c.lower() for c in calls):
            name = "print_message"
            confidence = 0.7
            summary = "Prints output to console"
            rationale = "Calls printing functions"
        elif any("socket" in c.lower() or "connect" in c.lower() for c in calls):
            name = "network_handler"
            confidence = 0.7
            summary = "Network-related functionality"
            rationale = "Calls network APIs"
        elif any("createfile" in c.lower() or "open" in c.lower() for c in calls):
            name = "file_handler"
            confidence = 0.7
            summary = "File operations"
            rationale = "Calls file APIs"
        elif any("malloc" in c.lower() or "alloc" in c.lower() for c in calls):
            name = "memory_allocator"
            confidence = 0.65
            summary = "Memory allocation"
            rationale = "Calls memory allocation functions"

        # Check strings for hints
        if not name and strings:
            if any("error" in s.lower() for s in strings):
                name = "error_handler"
                confidence = 0.6
                summary = "Error handling"
                rationale = "Contains error strings"
            elif any("http" in s.lower() or "https" in s.lower() for s in strings):
                name = "web_handler"
                confidence = 0.65
                summary = "Web-related functionality"
                rationale = "Contains URLs"

        # Fallback
        if not name:
            if original_name.startswith("_Z"):
                name = original_name  # Keep mangled name if we couldn't demangle
                confidence = 0.3
                summary = "Mangled C++ function"
                rationale = "Unable to demangle or analyze"
            elif original_name == "main":
                name = "main"
                confidence = 1.0
                summary = "Program entry point"
                rationale = "Standard main function"
            else:
                name = f"sub_{va:x}" if va else original_name
                confidence = 0.2
                summary = "Unknown function"
                rationale = "No identifying characteristics found"

        return SuggestedFunctionName(
            name=name, confidence=confidence, summary=summary, rationale=rationale
        )


def build_naming_prompt(
    ctx: MemoryContext,
    va: int | None,
    original_name: str,
    demangled_name: str | None,
    instructions: list[str],
    calls: list[str],
    strings: list[str],
) -> str:
    """Build a naming prompt using decompiled pseudocode as primary evidence.

    Also exposed as a module-level helper so the `glaurung ask name-func`
    CLI shim can reuse the exact same context-assembly logic.
    """
    pseudocode: str | None = None
    if va is not None and getattr(ctx, "file_path", None):
        try:
            pseudocode = g.ir.decompile_at(
                str(ctx.file_path),
                int(va),
                timeout_ms=max(200, int(getattr(ctx.budgets, "timeout_ms", 500) or 500)),
                style="c",
            )
        except Exception:
            pseudocode = None

    parts: list[str] = []
    parts.append(f"Original (likely unreliable): {original_name}")
    if demangled_name and demangled_name != original_name:
        parts.append(f"Demangled: {demangled_name}")

    if pseudocode:
        # Cap at ~120 lines to stay within a reasonable prompt budget.
        lines = pseudocode.splitlines()
        if len(lines) > 120:
            lines = lines[:120] + [f"... ({len(pseudocode.splitlines()) - 120} more lines truncated)"]
        parts.append("Pseudocode (glaurung --style c):\n```\n" + "\n".join(lines) + "\n```")
    else:
        # Fall back to the old context shape when decompilation is
        # unavailable (e.g. unsupported arch, or timeout).
        if calls:
            parts.append(f"Calls (resolved): {', '.join(calls[:8])}")
        if strings:
            parts.append("Strings:\n" + "\n".join(f"  {s!r}" for s in strings[:5]))
        if instructions:
            parts.append(
                "First instructions:\n" + "\n".join(instructions[:16])
            )

    prompt = (
        "Suggest a meaningful snake_case name for the function below.\n\n"
        + "\n\n".join(parts)
        + "\n\nReturn the suggested name, a confidence in [0, 1], a one-"
        "sentence summary, and a short rationale citing specific evidence "
        "(string literals, called functions, control-flow shape) you used."
    )
    return prompt


def build_tool() -> MemoryTool[SuggestFunctionNameArgs, SuggestFunctionNameResult]:
    return SuggestFunctionNameTool()


def suggest_name_sync(
    snippet: str, context: str | None = None
) -> SuggestedFunctionName:
    """Legacy synchronous interface for compatibility."""
    # This is a simplified version for backward compatibility
    # Just return a basic heuristic result
    name = "unknown_function"
    confidence = 0.5
    summary = ""

    if context:
        if "main" in context.lower():
            name = "main"
            confidence = 0.9
            summary = "Main entry point"
        elif "print" in context.lower():
            name = "print_handler"
            confidence = 0.7
            summary = "Output function"

    return SuggestedFunctionName(
        name=name,
        confidence=confidence,
        summary=summary,
        rationale="Legacy heuristic analysis",
    )
