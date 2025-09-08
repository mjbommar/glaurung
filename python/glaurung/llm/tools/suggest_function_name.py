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
    ) -> SuggestedFunctionName:
        """Use LLM to suggest a function name based on context."""
        from ..config import get_config

        cfg = get_config()
        avail = cfg.available_models()

        # If no LLM available, fall back to heuristics
        if not any(avail.values()):
            return self._suggest_with_heuristics(
                original_name, demangled_name, calls, strings, 0
            )

        # Create a simple agent for this task
        agent = Agent[str, SuggestedFunctionName](
            model=cfg.default_model,
            output_type=SuggestedFunctionName,
            system_prompt=(
                "You are a reverse engineering assistant that suggests meaningful function names "
                "based on disassembly analysis. Provide concise, descriptive names that follow "
                "common naming conventions (snake_case for C, camelCase for Java/JS, etc.). "
                "Consider the function's behavior, API calls, and string references."
            ),
        )

        # Build context string
        context_parts = []
        if demangled_name:
            context_parts.append(f"Demangled: {demangled_name}")
        if calls:
            context_parts.append(f"Calls: {', '.join(calls[:5])}")
        if strings:
            context_parts.append(f"Strings: {', '.join(repr(s) for s in strings[:3])}")
        if instructions:
            context_parts.append("First instructions:\n" + "\n".join(instructions[:10]))

        context = "\n".join(context_parts) if context_parts else "No additional context"

        prompt = (
            "Suggest a meaningful function name based on behavior.\n"
            "Original/mangled names may be misleading; consider them lightly.\n"
            f"Original: {original_name}\n"
            f"{context}\n\n"
            "Return a succinct identifier (snake_case), confidence (0-1), brief summary, and rationale."
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
