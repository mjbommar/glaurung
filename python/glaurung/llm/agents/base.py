"""Base protocol and shared functionality for analysis agents."""

from __future__ import annotations

from typing import Protocol, Optional, Any, Dict, List, runtime_checkable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib

from pydantic import BaseModel, Field


class TerminationReason(Enum):
    """Reasons why agent execution terminated."""

    SINGLE_PASS_COMPLETE = "single_pass_complete"
    CONFIDENCE_MET = "confidence_met"
    MAX_ITERATIONS = "max_iterations"
    TIMEOUT = "timeout"
    TOKEN_LIMIT = "token_limit"
    LOOP_DETECTED = "loop_detected"
    NO_PROGRESS = "no_progress"
    ERROR = "error"
    USER_CANCELLED = "user_cancelled"


class ModelHyperparameters(BaseModel):
    """Model generation hyperparameters for LLM calls."""

    temperature: float = Field(
        default=0.3, ge=0.0, le=2.0, description="Sampling temperature"
    )
    top_p: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="Nucleus sampling threshold"
    )
    top_k: Optional[int] = Field(default=None, ge=1, description="Top-k sampling")
    max_tokens: Optional[int] = Field(
        default=None, ge=1, description="Maximum output tokens"
    )
    presence_penalty: Optional[float] = Field(
        default=None, ge=-2.0, le=2.0, description="Presence penalty"
    )
    frequency_penalty: Optional[float] = Field(
        default=None, ge=-2.0, le=2.0, description="Frequency penalty"
    )
    seed: Optional[int] = Field(
        default=None, description="Random seed for deterministic output"
    )

    def to_model_kwargs(self) -> Dict[str, Any]:
        """Convert to kwargs for pydantic-ai model calls."""
        kwargs = {}
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        if self.top_p is not None:
            kwargs["top_p"] = self.top_p
        if self.top_k is not None:
            kwargs["top_k"] = self.top_k
        if self.max_tokens is not None:
            kwargs["max_output_tokens"] = self.max_tokens
        if self.presence_penalty is not None:
            kwargs["presence_penalty"] = self.presence_penalty
        if self.frequency_penalty is not None:
            kwargs["frequency_penalty"] = self.frequency_penalty
        if self.seed is not None:
            kwargs["seed"] = self.seed
        return kwargs


class AnalysisResult(BaseModel):
    """Result from agent analysis with metrics and metadata."""

    answer: str = Field(description="The agent's response")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in the answer")
    iterations_used: int = Field(ge=1, description="Number of iterations executed")
    total_tokens: int = Field(ge=0, description="Total tokens consumed")
    execution_time: float = Field(ge=0.0, description="Total execution time in seconds")
    evidence_count: int = Field(ge=0, description="Number of evidence pieces gathered")
    tools_used: List[str] = Field(
        default_factory=list, description="Tools invoked during analysis"
    )
    terminated_reason: TerminationReason = Field(description="Why execution stopped")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata"
    )

    def is_successful(self) -> bool:
        """Check if the analysis completed successfully."""
        return self.terminated_reason in [
            TerminationReason.SINGLE_PASS_COMPLETE,
            TerminationReason.CONFIDENCE_MET,
        ]


@dataclass
class ExecutionState:
    """Track execution state for monitoring and loop detection."""

    iteration: int = 0
    tool_sequence: List[str] = field(default_factory=list)
    tool_call_signatures: List[str] = field(default_factory=list)  # Hash of tool + args
    evidence_hashes: set = field(default_factory=set)
    confidence_history: List[float] = field(default_factory=list)
    tokens_used: int = 0
    start_time: datetime = field(default_factory=datetime.now)
    last_error: Optional[str] = None

    def add_tool_call(self, tool_name: str, args: Dict[str, Any]) -> bool:
        """
        Add a tool call and check for exact duplicates.
        Returns True if this exact call was made before.
        """
        self.tool_sequence.append(tool_name)

        # Create deterministic signature for tool + args
        args_str = repr(sorted(args.items())) if args else ""
        signature = hashlib.md5(f"{tool_name}:{args_str}".encode()).hexdigest()[:16]

        is_duplicate = signature in self.tool_call_signatures
        self.tool_call_signatures.append(signature)

        return is_duplicate

    def add_evidence(self, evidence: str) -> bool:
        """
        Add evidence and check if it's new.
        Returns True if the evidence is novel.
        """
        if not evidence:
            return False

        evidence_hash = hashlib.md5(evidence.encode()).hexdigest()[:16]
        if evidence_hash in self.evidence_hashes:
            return False

        self.evidence_hashes.add(evidence_hash)
        return True

    def update_confidence(self, confidence: float):
        """Track confidence progression."""
        self.confidence_history.append(confidence)

    def elapsed_seconds(self) -> float:
        """Get elapsed time in seconds."""
        return (datetime.now() - self.start_time).total_seconds()

    def get_repeat_count(self, tool_name: str, args: Dict[str, Any]) -> int:
        """Count how many times this exact tool+args combination was called."""
        args_str = repr(sorted(args.items())) if args else ""
        signature = hashlib.md5(f"{tool_name}:{args_str}".encode()).hexdigest()[:16]
        return self.tool_call_signatures.count(signature)

    def has_pattern_loop(self, pattern_length: int = 3) -> bool:
        """Check if the last N tools form a repeating pattern."""
        if len(self.tool_sequence) < pattern_length * 2:
            return False

        recent = self.tool_sequence[-pattern_length:]
        previous = self.tool_sequence[-pattern_length * 2 : -pattern_length]

        return recent == previous

    def is_making_progress(self) -> bool:
        """Check if the agent is making progress."""
        # No new evidence in last 3 iterations
        if self.iteration >= 3 and len(self.evidence_hashes) == 0:
            return False

        # Confidence not improving
        if len(self.confidence_history) >= 3:
            recent_confidence = self.confidence_history[-3:]
            if max(recent_confidence) - min(recent_confidence) < 0.05:
                return False

        return True


@runtime_checkable
class BaseAnalysisAgent(Protocol):
    """Protocol defining the interface for analysis agents."""

    async def analyze(
        self,
        question: str,
        context: Any,
        hyperparameters: Optional[ModelHyperparameters] = None,
    ) -> AnalysisResult:
        """
        Analyze a question with the given context.

        Args:
            question: The question to analyze
            context: Analysis context (e.g., MemoryContext)
            hyperparameters: Optional model generation parameters

        Returns:
            AnalysisResult with answer and metadata
        """
        ...

    def analyze_sync(
        self,
        question: str,
        context: Any,
        hyperparameters: Optional[ModelHyperparameters] = None,
    ) -> AnalysisResult:
        """
        Synchronous version of analyze.

        Args:
            question: The question to analyze
            context: Analysis context
            hyperparameters: Optional model generation parameters

        Returns:
            AnalysisResult with answer and metadata
        """
        ...


class AgentMetrics:
    """Helper class for extracting metrics from agent results."""

    @staticmethod
    def extract_confidence(result: Any, context: Any) -> float:
        """Extract or calculate confidence from result."""
        # Check for explicit confidence
        if hasattr(result, "output"):
            if hasattr(result.output, "confidence"):
                return float(result.output.confidence)

        # Heuristic based on context and result quality
        confidence = 0.2  # Base confidence (increased from 0.1)

        # Factor: KB nodes (more exploration = higher confidence)
        if hasattr(context, "kb"):
            node_count = sum(1 for _ in context.kb.nodes())
            if node_count > 0:
                # More generous scaling: 10 nodes = 0.5 confidence contribution
                kb_confidence = min(node_count / 20, 1.0) * 0.5
                confidence = max(confidence, confidence + kb_confidence)

        # Factor: Result completeness for structured outputs
        if hasattr(result, "output") and hasattr(result.output, "__dict__"):
            fields = result.output.__dict__
            if fields:
                filled = sum(1 for v in fields.values() if v not in [None, [], ""])
                completeness = filled / len(fields)
                confidence = max(confidence, confidence + completeness * 0.3)

        # Factor: String output quality (for memory agent)
        elif hasattr(result, "output") and isinstance(result.output, str):
            output_str = str(result.output)
            # Higher confidence for longer, detailed responses
            if len(output_str) > 500:
                confidence += 0.3
            elif len(output_str) > 200:
                confidence += 0.2
            elif len(output_str) > 50:
                confidence += 0.1

            # Look for indicators of successful analysis
            success_indicators = [
                "function",
                "address",
                "0x",
                "prints",
                "calls",
                "string",
                "found",
                "located",
                "identified",
            ]
            matches = sum(
                1 for word in success_indicators if word.lower() in output_str.lower()
            )
            if matches >= 3:
                confidence += 0.3
            elif matches >= 2:
                confidence += 0.2

        return min(confidence, 1.0)

    @staticmethod
    def extract_tools(result: Any) -> List[str]:
        """Extract tool names from agent result."""
        tools = []

        if hasattr(result, "all_messages"):
            try:
                messages = result.all_messages
                if callable(messages):
                    messages = messages()

                for msg in messages:
                    if hasattr(msg, "parts"):
                        parts = msg.parts
                        if callable(parts):
                            parts = parts()

                        for part in parts:
                            if hasattr(part, "tool_name"):
                                tools.append(part.tool_name)
            except Exception:
                pass

        return list(set(tools))

    @staticmethod
    def extract_tools_with_args(result: Any) -> List[tuple]:
        """Extract tool calls with their arguments."""
        tool_calls = []

        if hasattr(result, "all_messages"):
            try:
                messages = result.all_messages
                if callable(messages):
                    messages = messages()

                for msg in messages:
                    if hasattr(msg, "parts"):
                        parts = msg.parts
                        if callable(parts):
                            parts = parts()

                        for part in parts:
                            if hasattr(part, "tool_name"):
                                args = {}
                                if hasattr(part, "args"):
                                    try:
                                        args = dict(part.args)
                                    except Exception:
                                        args = {}
                                tool_calls.append((part.tool_name, args))
            except Exception:
                pass

        return tool_calls

    @staticmethod
    def count_tokens(result: Any) -> int:
        """
        Estimate token count from result.
        Note: This is an approximation. Real implementation should use tiktoken or model tokenizer.
        """
        total = 0

        # Count output tokens (rough estimate: 1 token ≈ 4 chars)
        if hasattr(result, "output"):
            try:
                output_str = (
                    result.output
                    if isinstance(result.output, str)
                    else str(result.output)
                )
            except Exception:
                output_str = ""
            total += len(output_str) // 4

        # Try to get usage from result if available
        if hasattr(result, "usage"):
            try:
                if hasattr(result.usage, "total_tokens"):
                    val = result.usage.total_tokens
                    return int(val) if isinstance(val, (int, float)) else total
                elif hasattr(result.usage, "prompt_tokens") and hasattr(
                    result.usage, "completion_tokens"
                ):
                    pt = result.usage.prompt_tokens
                    ct = result.usage.completion_tokens
                    if isinstance(pt, (int, float)) and isinstance(ct, (int, float)):
                        return int(pt) + int(ct)
            except Exception:
                pass

        # Estimate from messages
        if hasattr(result, "all_messages"):
            try:
                messages = result.all_messages
                if callable(messages):
                    messages = messages()

                for msg in messages:
                    if hasattr(msg, "content"):
                        total += len(str(msg.content)) // 4
            except Exception:
                pass

        return max(int(total), 1)  # At least 1 token, ensure int

    @staticmethod
    def count_evidence(context: Any) -> int:
        """Count evidence pieces in context."""
        if hasattr(context, "kb"):
            # Count non-metadata nodes
            count = 0
            for node in context.kb.nodes():
                # Handle different node types
                if hasattr(node, "type"):
                    if node.type not in ["metadata", "feedback", "system"]:
                        count += 1
                elif isinstance(node, dict) and node.get("type"):
                    if node.get("type") not in ["metadata", "feedback", "system"]:
                        count += 1
                else:
                    count += 1  # Count if we can't determine type
            return count
        return 0
