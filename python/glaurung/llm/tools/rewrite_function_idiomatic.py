"""Tool #14: rewrite one function into idiomatic source.

Layer 2 workhorse. Every earlier tool exists to feed this one:

- Layer-0 labelers give it named variables, symbolic constants, named
  string literals, classified loops.
- Layer-1 recoverers give it the struct/enum/error-model tables, a
  full function signature with direction/ownership/nullability, and
  protocol/CLI anchors.

With all of that in hand the LLM rewrites the pseudocode body into
source that reads like something a human wrote — no register names,
no synthetic ``var3`` locals, no bare numeric constants. The
``assumptions`` list tracks every rewrite decision that is not
mechanically provable from the input so #17
``verify_semantic_equivalence`` can later challenge them.
"""

from __future__ import annotations

import re
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


Language = Literal["c", "cpp", "rust", "go", "python"]

# Two rewrite presets:
#
# "tldr"      -- original behavior. Idiomatic, compressed, "as if a human
#                wrote it before compilation". For source recovery,
#                publishing, casual reading.
# "annotated" -- bug-hunting triage mode. Per-basic-block, faithful, no
#                dead-store removal, no branch collapse, no loop-to-memcpy
#                replacement. Preserves VA labels and call/access metadata
#                so a vulnerability researcher can map output back to the
#                binary. Output is verbose by design.
RewriteFidelity = Literal["tldr", "annotated"]


class StructDef(BaseModel):
    name: str
    c_definition: str


class EnumDef(BaseModel):
    name: str
    c_definition: str


class ErrorCodeRef(BaseModel):
    canonical_name: str = Field(..., description="e.g. 'ERR_NOMEM'")
    numeric_value: int


class RewriteFunctionArgs(BaseModel):
    entry_va: int = Field(..., description="Entry VA of the function")
    pseudocode: Optional[str] = Field(
        None,
        description="Function pseudocode. When omitted, the tool calls "
                    "g.ir.decompile_at itself.",
    )
    fidelity: RewriteFidelity = Field(
        default="tldr",
        description="Rewrite preset. 'tldr' = idiomatic-source recovery "
                    "(default; existing behavior). 'annotated' = per-block "
                    "faithful for bug-hunting triage; emits an "
                    "AnnotatedFunction with one CodeBlock per basic block.",
    )
    suspicious_vas: List[int] = Field(
        default_factory=list,
        description="Optional list of VAs the caller wants extra fidelity "
                    "around (e.g. a static-rule sink_va). Used by the "
                    "'annotated' preset to bias prompt attention.",
    )
    c_prototype: str = Field(
        ..., description="Recovered prototype from #10"
    )
    role: Optional[str] = Field(
        None, description="Role label from #13"
    )
    variable_names: Dict[str, str] = Field(
        default_factory=dict,
        description="Mapping from raw identifier (var3, arg0, t7) to the "
                    "name picked by #5. The rewriter substitutes these.",
    )
    constant_labels: Dict[str, str] = Field(
        default_factory=dict,
        description="Mapping from string-rendered constant value ('0x4002') "
                    "to its symbolic form ('O_RDWR | O_DIRECT') from #2.",
    )
    string_names: Dict[str, str] = Field(
        default_factory=dict,
        description="Mapping from raw string literal to SCREAMING_SNAKE_CASE "
                    "name from #3.",
    )
    loop_idioms: List[str] = Field(
        default_factory=list,
        description="Human-readable descriptions of loop replacements from "
                    "#4 — e.g. 'line 12 loop replaced with memcpy(dst, src, len)'.",
    )
    structs: List[StructDef] = Field(default_factory=list)
    enums: List[EnumDef] = Field(default_factory=list)
    error_codes: List[ErrorCodeRef] = Field(default_factory=list)
    target_language: Language = "c"
    timeout_ms: int = 500


class RewrittenFunction(BaseModel):
    source: str = Field(..., description="Final source for this function")
    language: Language
    assumptions: List[str] = Field(
        default_factory=list,
        description="Every non-mechanical rewrite decision — dropped dead "
                    "stores, idiom replacements, renamed variables whose "
                    "intent the LLM inferred. Feeds #17.",
    )
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


# Annotated-mode (bug-hunting fidelity) schemas. The point of the per-block
# structure is to make compression impossible: the LLM cannot collapse two
# basic blocks into one without violating the type contract.

class AnnotatedCallSite(BaseModel):
    call_va: str = Field(..., description="VA of the call instruction, hex")
    callee: str = Field(..., description="Callee symbol or expression")
    kind: Literal["direct", "indirect", "thunk", "tail_call"] = "direct"
    notable: bool = Field(
        False,
        description="True if this call is security-relevant for review "
                    "(ObReferenceObjectByHandle, ExAllocatePool*, "
                    "ProbeForRead/Write, IofCompleteRequest, etc).",
    )


class AnnotatedMemAccess(BaseModel):
    va: str = Field(..., description="VA of the load/store instruction, hex")
    kind: Literal["read", "write", "read_write"]
    width: int = Field(ge=1, description="Access width in bytes")
    addr_expr: str = Field(
        ...,
        description="Symbolic address expression -- "
                    "'SystemBuffer + 0x28', 'caller_arg0->Endpoint', "
                    "'[rsp + 0x40]'. Preserved verbatim from input fact-bundle "
                    "where present; otherwise reconstructed from disasm.",
    )


class AnnotatedBranch(BaseModel):
    va: str
    kind: Literal["cond", "uncond", "switch", "return", "tail_call"]
    predicate: Optional[str] = None
    target_va: Optional[str] = None


class CodeBlock(BaseModel):
    start_va: str = Field(..., description="VA of the first instruction, hex")
    end_va: str = Field(..., description="VA of the last instruction, hex")
    lifted_c: str = Field(
        ...,
        description="Faithful C-line equivalent for every instruction in "
                    "this block. NO dead-store removal. NO branch collapse. "
                    "NO loop-to-memcpy replacement unless the body is "
                    "exactly that idiom. Variable renames from Layer-0 ARE "
                    "applied. Symbolic addr_exprs from the fact-bundle ARE "
                    "applied. Out-of-block calls show as // call <callee> "
                    "comments with their VA.",
    )
    calls: List[AnnotatedCallSite] = Field(default_factory=list)
    mem_accesses: List[AnnotatedMemAccess] = Field(default_factory=list)
    branches: List[AnnotatedBranch] = Field(default_factory=list)
    block_confidence: float = Field(
        ge=0.0, le=1.0,
        description="Per-block self-rated confidence. Use < 0.5 for any "
                    "block where the LLM had to guess at struct fields, "
                    "type widths, or branch direction.",
    )


class AnnotatedFunction(BaseModel):
    prototype: str = Field(..., description="C prototype, as used")
    blocks: List[CodeBlock] = Field(
        ...,
        description="ONE entry per basic block in the input. The list MUST "
                    "cover every block; do not collapse, dedupe, or skip. "
                    "An empty list is invalid output.",
    )
    assumptions: List[str] = Field(default_factory=list)
    overall_confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class RewriteFunctionResult(BaseModel):
    entry_va: int
    rewrite: Optional[RewrittenFunction] = Field(
        None,
        description="Populated when fidelity='tldr'.",
    )
    annotated: Optional[AnnotatedFunction] = Field(
        None,
        description="Populated when fidelity='annotated'.",
    )
    source: str = Field(..., description="'llm' | 'heuristic'")
    fidelity: RewriteFidelity = "tldr"


def _apply_substitutions(text: str, mappings: Dict[str, str]) -> str:
    """Simple textual substitution used by the heuristic fallback.

    Not safe for real rewrites (substrings, identifier collisions) but
    produces a cosmetically-cleaner fallback for offline mode.
    """
    out = text
    # Longest first so "arg10" isn't eaten by "arg1".
    for k in sorted(mappings, key=len, reverse=True):
        out = out.replace(k, mappings[k])
    return out


def _heuristic(
    args: RewriteFunctionArgs, pseudocode: str
) -> RewrittenFunction:
    text = pseudocode
    text = _apply_substitutions(text, args.variable_names)
    text = _apply_substitutions(text, args.constant_labels)
    # String literal substitution uses the *content* as the key and the
    # symbolic name as the value, but we only want to substitute quoted
    # occurrences — the simplest safe match is the full quoted form.
    for raw, symbolic in args.string_names.items():
        quoted = f'"{raw}"'
        text = text.replace(quoted, symbolic)

    source = (
        f"// auto-rewritten (heuristic) — {args.c_prototype}\n"
        f"{args.c_prototype.rstrip(';')}\n"
        f"{{\n"
        f"    /* {pseudocode.count(chr(10))} lines of pseudocode below */\n"
        f"{text}\n"
        f"}}"
    )
    return RewrittenFunction(
        source=source,
        language=args.target_language,
        assumptions=[
            "Heuristic rewrite — LLM not consulted; treat output as "
            "lightly-substituted pseudocode, not real source."
        ],
        confidence=0.2,
        rationale="offline fallback — no semantic transformation performed",
    )


_SYSTEM_PROMPT = (
    "You are a reverse engineer rewriting one decompiled function into "
    "idiomatic source in the requested language. You will be given:\n"
    "  - the pseudocode body\n"
    "  - the recovered C prototype\n"
    "  - the function's role label\n"
    "  - renaming tables for variables, constants, and string literals\n"
    "  - loop-idiom replacements (e.g. 'lines 8–12 = memcpy')\n"
    "  - recovered struct/enum/error definitions available for use\n\n"
    "Rewrite the body so it reads as if a human wrote it before "
    "compilation. Apply all renamings. Replace loops with library "
    "calls when the idiom table says so. Use recovered error "
    "constants in `return` statements. Remove optimizer artefacts "
    "(obvious strength reductions, loop unrolling, dead-store chains). "
    "Any non-mechanical decision you make — replacing a loop with "
    "`memcpy`, collapsing two branches, inferring a cast — goes in "
    "the `assumptions` list so a reviewer can audit it. Do not "
    "invent code that has no binary backing."
)


_SYSTEM_PROMPT_ANNOTATED = (
    "You are annotating a Windows kernel driver function for security "
    "review. The reader is a vulnerability researcher hunting for "
    "CWE-416 (UAF), CWE-822 (untrusted pointer deref), CWE-787 (OOB "
    "write), CWE-200 (info disclosure), CWE-269 (priv esc), CWE-362 "
    "(race), and similar shapes. Faithfulness BEATS readability.\n\n"

    "For EVERY basic block in the input pseudocode, emit one CodeBlock "
    "entry with:\n"
    "  - start_va / end_va: the VA range this block covers\n"
    "  - lifted_c: a C-line equivalent for EVERY instruction in the "
    "    block.\n"
    "  - calls / mem_accesses / branches: enumerate every observable "
    "    side effect in this block, with VAs.\n"
    "  - block_confidence: < 0.5 if you had to guess at types, struct "
    "    layouts, or branch direction.\n\n"

    "RENAMING IS MANDATORY. When the user supplies variable_names, "
    "constant_labels, or string_names tables, you MUST substitute "
    "those names into the `lifted_c` body. A `%var0` in the input that "
    "maps to `request_state` in the table MUST appear as "
    "`request_state` in your output -- not as `var0`, not as `%var0`, "
    "not as `var_0`. The same rule applies to `arg0`/`arg1`/`tN`/"
    "`stack_N`. If a name from the table is ambiguous because two raw "
    "identifiers happen to share a name, disambiguate with a numeric "
    "suffix; do NOT silently drop the rename. Variables not in the "
    "table keep their raw form (`var3`, `arg2`) -- do not invent names.\n\n"

    "STRUCT FIELDS. When you have a struct definition available (Irp, "
    "IO_STACK_LOCATION, AFD_ENDPOINT, IO_STATUS_BLOCK, etc) use field "
    "names: `irp->AssociatedIrp.SystemBuffer` instead of `*(u64 *)&"
    "[irp + 0x18]`. If the struct is NOT in the supplied definitions, "
    "leave the raw offset (`*(unsigned char *)(arg0 + 0x40)`) -- DO "
    "NOT invent a field name.\n\n"

    "DO NOT collapse blocks. DO NOT merge two basic blocks into one "
    "CodeBlock even if they look alike. DO NOT remove 'dead stores' -- "
    "they may be security-relevant (e.g. zeroing a buffer before "
    "completion, fencing a pointer write). DO NOT replace loops with "
    "library calls unless the body matches memcpy/memset EXACTLY. "
    "DO NOT shorten the function. If you are uncertain about a region, "
    "transcribe it MORE verbosely, not less.\n\n"

    "When the caller flags `suspicious_vas`, give those blocks extra "
    "attention -- a static rule fired in that region and the human "
    "reviewer needs to see every load/store/call clearly to decide "
    "TP vs FP. Mark such blocks with `block_confidence` >= 0.5 ONLY "
    "if every instruction is unambiguous -- if you had to guess, "
    "say so.\n\n"

    "Output an AnnotatedFunction. The `blocks` list MUST be non-empty "
    "and MUST cover every basic block visible in the input. Empty "
    "output is treated as a refusal and will trigger the fallback."
)


def _build_prompt_annotated(args: "RewriteFunctionArgs", pseudocode: str) -> str:
    parts = [
        f"Target language: {args.target_language}",
        f"Prototype: {args.c_prototype}",
    ]
    if args.role:
        parts.append(f"Role: {args.role}")
    if args.suspicious_vas:
        sv = ", ".join(f"0x{v:x}" for v in args.suspicious_vas)
        parts.append(
            "SUSPICIOUS VAs (a static rule fired here -- preserve every "
            f"load/store/call exactly): {sv}"
        )
    parts.append(f"Pseudocode:\n```\n{pseudocode}\n```")
    if args.variable_names:
        parts.append(
            "Variable renames (apply these):\n"
            + "\n".join(f"  {k} -> {v}" for k, v in args.variable_names.items())
        )
    if args.constant_labels:
        parts.append(
            "Constant rewrites (apply these):\n"
            + "\n".join(
                f"  {k} -> {v}" for k, v in args.constant_labels.items()
            )
        )
    if args.string_names:
        parts.append(
            "String literal names:\n"
            + "\n".join(
                f"  {k!r} -> {v}" for k, v in list(args.string_names.items())[:12]
            )
        )
    if args.structs:
        parts.append(
            "Available struct definitions:\n"
            + "\n\n".join(s.c_definition for s in args.structs)
        )
    if args.enums:
        parts.append(
            "Available enum definitions:\n"
            + "\n\n".join(e.c_definition for e in args.enums)
        )
    if args.error_codes:
        parts.append(
            "Error codes available:\n"
            + "\n".join(
                f"  {e.canonical_name} = {e.numeric_value}"
                for e in args.error_codes
            )
        )
    parts.append(
        "Return AnnotatedFunction with prototype, the full list of "
        "blocks (one per basic block in the input -- do not skip any), "
        "assumptions, overall_confidence, and rationale."
    )
    return "\n\n".join(parts)


_STORE_PATTERN_RE = re.compile(
    # Matches lines whose left-hand side looks like a memory store:
    #   *ptr = ...                       (any pointer dereference write)
    #   *(type *)addr = ...              (cast-deref write)
    #   *(u64 *)node = expr              (the AfdRestartBufferSend hallucination shape)
    #   obj->field = ...                 (struct-field write via pointer)
    #   ptr[idx] = ...                   (indexed write)
    # Excludes comparisons (== / !=), compound expressions in parens,
    # and r-h-s contexts. The match is conservative: false negatives are
    # fine (we just don't ground them) but false positives would yank
    # legit code into "synthesized" flags.
    r"""^(?P<indent>\s*)              # leading whitespace
        (?:                            # left-hand side, one of:
          \*\([^)]+\)\s*\w+            #   *(type *)name
        | \*[A-Za-z_][\w.]*            #   *ident
        | [A-Za-z_]\w*\s*->\s*\w+      #   obj->field
        | [A-Za-z_]\w*\s*\[[^\]]+\]    #   ident[expr]
        )
        \s*=(?!=)                      # single '=' not '=='
    """,
    re.VERBOSE,
)


def _block_has_disasm_write(block: "CodeBlock") -> bool:
    """True if the block's own mem_accesses claim any write."""
    for ma in block.mem_accesses:
        if ma.kind in ("write", "read_write"):
            return True
    return False


def _ground_annotated_lift(annotated: "AnnotatedFunction") -> "AnnotatedFunction":
    """Self-consistency grounding pass over each block's lifted_c.

    For every line in lifted_c that looks like a memory store, confirm
    that the block's structured mem_accesses list contains at least one
    write/read_write entry. If not, prefix the line with
    ``// SYNTHESIZED -- unverified store``.

    This catches the AfdRestartBufferSend-class hallucination shape
    (P0-E in BACKLOG-2026-05-26.md) where the LLM renders a register
    clobber (``mov reg, [mem]``) as a memory store ``*node = ...`` but
    does NOT include any write entry in mem_accesses for that block.

    A future iteration can add capstone-driven disasm grounding to
    catch the fully-consistent-hallucination case (lift agrees with
    structured mem_accesses but both disagree with the binary).
    """
    if annotated is None or not annotated.blocks:
        return annotated
    new_blocks = []
    flagged_any = False
    for block in annotated.blocks:
        if _block_has_disasm_write(block):
            # Block legitimately has at least one write; trust the
            # LLM's store-shaped lines in this block. (Per-line
            # store-to-mem_access pairing is a tighter check we can
            # add when capstone-grounded; this version operates at
            # the block level to avoid false positives on legit code.)
            new_blocks.append(block)
            continue
        # Block has no claimed writes. Any store-shaped line in
        # lifted_c is suspect.
        lines = block.lifted_c.split("\n")
        out_lines: list[str] = []
        block_flagged = False
        for line in lines:
            if _STORE_PATTERN_RE.match(line):
                out_lines.append(
                    f"// SYNTHESIZED -- unverified store (no matching "
                    f"mem_access in this block); next line may be "
                    f"hallucinated"
                )
                out_lines.append(line)
                block_flagged = True
                flagged_any = True
            else:
                out_lines.append(line)
        if block_flagged:
            new_blocks.append(block.model_copy(update={"lifted_c": "\n".join(out_lines)}))
        else:
            new_blocks.append(block)
    if not flagged_any:
        return annotated
    # Add a top-level assumption so downstream triage sees the flag.
    new_assumptions = list(annotated.assumptions) + [
        "GROUNDING: One or more blocks contain store-shaped lines in "
        "lifted_c without a matching write entry in mem_accesses; those "
        "lines are prefixed `// SYNTHESIZED -- unverified store`. Verify "
        "against raw disasm before triaging UAF/race/store-based bugs.",
    ]
    return annotated.model_copy(update={
        "blocks": new_blocks,
        "assumptions": new_assumptions,
    })


def _annotated_heuristic_fallback(
    args: "RewriteFunctionArgs", pseudocode: str
) -> "AnnotatedFunction":
    """Offline / failure-path fallback: emit a single block containing
    the raw pseudocode so callers always get a typed result.

    This is intentionally degenerate -- it preserves the input verbatim
    inside one CodeBlock so the reader can fall through to manual
    review, but it does NOT split into basic blocks.
    """
    return AnnotatedFunction(
        prototype=args.c_prototype,
        blocks=[
            CodeBlock(
                start_va=f"0x{int(args.entry_va):x}",
                end_va=f"0x{int(args.entry_va):x}",
                lifted_c=pseudocode,
                calls=[],
                mem_accesses=[],
                branches=[],
                block_confidence=0.10,
            )
        ],
        assumptions=[
            "annotated_heuristic_fallback: LLM unavailable or refused; "
            "entire function is in a single block as raw pseudocode."
        ],
        overall_confidence=0.10,
        rationale="offline fallback",
    )


def _build_prompt(args: RewriteFunctionArgs, pseudocode: str) -> str:
    parts = []
    parts.append(f"Target language: {args.target_language}")
    parts.append(f"Prototype: {args.c_prototype}")
    if args.role:
        parts.append(f"Role: {args.role}")
    parts.append(f"Pseudocode:\n```\n{pseudocode}\n```")
    if args.variable_names:
        parts.append(
            "Variable renames:\n"
            + "\n".join(f"  {k} -> {v}" for k, v in args.variable_names.items())
        )
    if args.constant_labels:
        parts.append(
            "Constant rewrites:\n"
            + "\n".join(f"  {k} -> {v}" for k, v in args.constant_labels.items())
        )
    if args.string_names:
        parts.append(
            "String literal names:\n"
            + "\n".join(
                f"  {k!r} -> {v}" for k, v in list(args.string_names.items())[:12]
            )
        )
    if args.loop_idioms:
        parts.append("Loop idiom replacements:\n" + "\n".join(
            f"  - {entry}" for entry in args.loop_idioms
        ))
    if args.structs:
        parts.append("Available struct definitions:\n" + "\n\n".join(
            s.c_definition for s in args.structs
        ))
    if args.enums:
        parts.append("Available enum definitions:\n" + "\n\n".join(
            e.c_definition for e in args.enums
        ))
    if args.error_codes:
        parts.append(
            "Error codes available:\n"
            + "\n".join(
                f"  {e.canonical_name} = {e.numeric_value}"
                for e in args.error_codes
            )
        )
    parts.append(
        "Return RewrittenFunction with source, language, assumptions "
        "list (critical), confidence, and rationale."
    )
    return "\n\n".join(parts)


class RewriteFunctionIdiomaticTool(
    MemoryTool[RewriteFunctionArgs, RewriteFunctionResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="rewrite_function_idiomatic",
                description="Rewrite one function from pseudocode to idiomatic "
                            "source in C/Rust/Go/Python, consuming all "
                            "Layer-0/Layer-1 evidence. The central creative "
                            "step of source recovery.",
                tags=("llm", "rewrite", "layer2"),
            ),
            RewriteFunctionArgs,
            RewriteFunctionResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: RewriteFunctionArgs,
    ) -> RewriteFunctionResult:
        pseudocode = args.pseudocode
        if pseudocode is None:
            try:
                pseudocode = g.ir.decompile_at(
                    str(ctx.file_path),
                    int(args.entry_va),
                    timeout_ms=max(200, int(args.timeout_ms)),
                    style="",
                )
            except Exception as e:
                pseudocode = f"// decompile failed: {e}"

        if args.fidelity == "annotated":
            heur = _annotated_heuristic_fallback(args, pseudocode)
            prompt = _build_prompt_annotated(args, pseudocode)
            annotated = run_structured_llm(
                prompt=prompt,
                output_type=AnnotatedFunction,
                system_prompt=_SYSTEM_PROMPT_ANNOTATED,
                fallback=lambda: heur,
            )
            source = "heuristic" if annotated is heur else "llm"
            # Sanity guard: a successful LLM response with an empty
            # blocks list is the "soft refusal" pattern (the LLM gave
            # up but didn't throw). Treat as fallback so callers see
            # the raw pseudocode rather than zero blocks.
            if annotated is not heur and not annotated.blocks:
                annotated = heur
                source = "heuristic"
            # Grounding pass: flag store-shaped lines in lifted_c that
            # have no corresponding mem_access write in the same block.
            # Catches the AfdRestartBufferSend-class hallucination where
            # the LLM renders a register clobber as a memory store.
            # Only runs on LLM output; heuristic fallback already
            # mirrors the disasm structure.
            if source == "llm":
                annotated = _ground_annotated_lift(annotated)
            return RewriteFunctionResult(
                entry_va=int(args.entry_va),
                annotated=annotated,
                source=source,
                fidelity="annotated",
            )

        # fidelity == "tldr" (default; existing behavior)
        heur = _heuristic(args, pseudocode)
        prompt = _build_prompt(args, pseudocode)
        rewrite = run_structured_llm(
            prompt=prompt,
            output_type=RewrittenFunction,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if rewrite is heur else "llm"
        return RewriteFunctionResult(
            entry_va=int(args.entry_va),
            rewrite=rewrite,
            source=source,
            fidelity="tldr",
        )


def build_tool() -> MemoryTool[RewriteFunctionArgs, RewriteFunctionResult]:
    return RewriteFunctionIdiomaticTool()
