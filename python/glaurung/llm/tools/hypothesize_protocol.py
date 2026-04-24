"""Tool #11: hypothesize the wire protocol a function speaks.

Layer 1 structural recovery. Deterministic analysis can detect that
a function assembles the strings ``"GET "``, ``" HTTP/1.1\\r\\n"``,
``"Content-Length: "``, but it cannot tell HTTP from SMTP from IRC
without looking at the *sequence* in which those strings are written
— that's protocol-level reasoning, squarely in LLM territory.

The output anchors the module naming in Layer 3 (this function goes
into ``net/http_client.c``, not ``net/smtp_client.c``) and feeds the
CLI / README synthesis as well.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


# Well-known protocol stems that appear verbatim in string literals.
# Heuristic matches claim MEDIUM confidence; the LLM is needed when
# multiple stems appear or none does.
_KNOWN_STEMS = [
    ("HTTP", [b"HTTP/1.", b"HTTP/2", b"GET ", b"POST ", b"Content-Length:"]),
    ("SMTP", [b"EHLO", b"MAIL FROM:", b"RCPT TO:", b"250 "]),
    ("IRC",  [b"PRIVMSG ", b"JOIN #", b"NICK ", b"001 ", b"PING :"]),
    ("FTP",  [b"USER ", b"PASS ", b"PASV", b"RETR ", b"STOR "]),
    ("POP3", [b"+OK", b"RETR ", b"USER ", b"PASS "]),
    ("DNS",  [b"QTYPE", b"A record", b"AXFR"]),
    ("MQTT", [b"MQTT", b"CONNECT", b"PUBLISH"]),
    ("TLS",  [b"TLSv", b"ClientHello", b"ServerHello"]),
    ("JSON-RPC", [b"jsonrpc", b"\"jsonrpc\":\"2.0\""]),
]


class ProtocolStringEvidence(BaseModel):
    text: str
    position: int = Field(
        0,
        description="Approximate ordering index — how early this string is "
                    "assembled in the function (0 = first). Sequencing is "
                    "the main signal.",
    )


class HypothesizeProtocolArgs(BaseModel):
    strings: List[ProtocolStringEvidence] = Field(
        ..., description="Protocol-looking strings in assembly order"
    )
    assembly_pseudocode: str = Field(
        "",
        description="Pseudocode excerpt showing how the strings are "
                    "concatenated / sent. Critical for sequencing.",
    )
    use_llm: bool = True


class ProtocolHypothesis(BaseModel):
    protocol: str = Field(..., description="Protocol name, e.g. 'HTTP/1.1' or 'unknown'")
    version: Optional[str] = None
    framing: str = Field(
        "",
        description="How messages are framed: 'CRLF-delimited headers + body', "
                    "'length-prefixed', 'newline-separated', 'binary TLV', …",
    )
    observed_fields: List[str] = Field(
        default_factory=list,
        description="Structural field names the LLM can extract from the "
                    "strings — 'User-Agent', 'Content-Length', 'method'.",
    )
    notes: str = ""
    confidence: float = Field(ge=0.0, le=1.0)


class HypothesizeProtocolResult(BaseModel):
    hypothesis: ProtocolHypothesis
    source: str = Field(..., description="'heuristic' | 'llm'")


def _heuristic(args: HypothesizeProtocolArgs) -> ProtocolHypothesis:
    blob = "\n".join(s.text for s in args.strings).encode("latin-1", "ignore")
    best_proto = "unknown"
    best_hits = 0
    for name, stems in _KNOWN_STEMS:
        hits = sum(1 for s in stems if s in blob)
        if hits > best_hits:
            best_proto = name
            best_hits = hits
    if best_hits >= 2:
        return ProtocolHypothesis(
            protocol=best_proto,
            framing=(
                "CRLF-delimited headers + body"
                if best_proto in ("HTTP", "SMTP", "POP3", "IRC", "FTP")
                else ""
            ),
            observed_fields=[],
            notes=f"matched {best_hits} known stems",
            confidence=0.7,
        )
    if best_hits == 1:
        return ProtocolHypothesis(
            protocol=best_proto,
            framing="",
            observed_fields=[],
            notes="single stem match — LLM review suggested",
            confidence=0.45,
        )
    return ProtocolHypothesis(
        protocol="unknown",
        framing="",
        observed_fields=[],
        notes="no well-known protocol stem matched",
        confidence=0.2,
    )


_SYSTEM_PROMPT = (
    "You are a reverse engineer identifying the wire protocol a "
    "function speaks. You will be given protocol-looking string "
    "literals in the order they appear during message assembly, plus "
    "a pseudocode excerpt showing how they are concatenated. Identify "
    "the protocol and version (HTTP/1.1, SMTP, IRC, MQTT 3.1, …) from "
    "the *sequencing*, not just the presence of keywords. Explain the "
    "framing (CRLF-delimited headers, length-prefixed, binary TLV, …) "
    "and list the structural fields you can extract. If the evidence "
    "is insufficient, say so honestly and set protocol='unknown'."
)


def _build_prompt(args: HypothesizeProtocolArgs) -> str:
    parts = []
    parts.append("String evidence in assembly order:")
    for s in sorted(args.strings, key=lambda s: s.position):
        parts.append(f"  [{s.position}] {s.text!r}")
    if args.assembly_pseudocode:
        parts.append(
            "Assembly pseudocode:\n```\n" + args.assembly_pseudocode + "\n```"
        )
    parts.append(
        "Identify protocol + version, framing, and observed fields. "
        "Return confidence honestly."
    )
    return "\n\n".join(parts)


class HypothesizeProtocolTool(
    MemoryTool[HypothesizeProtocolArgs, HypothesizeProtocolResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="hypothesize_protocol",
                description="Identify the wire protocol a function speaks "
                            "from protocol-looking strings and the pseudocode "
                            "that assembles them.",
                tags=("llm", "protocol", "layer1"),
            ),
            HypothesizeProtocolArgs,
            HypothesizeProtocolResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: HypothesizeProtocolArgs,
    ) -> HypothesizeProtocolResult:
        heur = _heuristic(args)
        if not args.use_llm or heur.confidence >= 0.7:
            return HypothesizeProtocolResult(hypothesis=heur, source="heuristic")

        prompt = _build_prompt(args)
        hyp = run_structured_llm(
            prompt=prompt,
            output_type=ProtocolHypothesis,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if hyp is heur else "llm"
        return HypothesizeProtocolResult(hypothesis=hyp, source=source)


def build_tool() -> MemoryTool[HypothesizeProtocolArgs, HypothesizeProtocolResult]:
    return HypothesizeProtocolTool()
