"""Iterative refinement wrapper for agents."""

from __future__ import annotations

from typing import Optional, Any, List, Dict
from dataclasses import dataclass, field
from enum import Enum
import asyncio

from pydantic import BaseModel, Field
from pydantic_ai import Agent

from ..context import MemoryContext


class ConfidenceLevel(Enum):
    """Confidence levels for agent responses."""

    VERY_LOW = 0.2
    LOW = 0.4
    MEDIUM = 0.6
    HIGH = 0.8
    VERY_HIGH = 0.95


@dataclass
class IterationState:
    """State tracking for iterative refinement."""

    iteration: int = 0
    confidence: float = 0.0
    evidence_gathered: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    failed_attempts: List[str] = field(default_factory=list)
    findings: Dict[str, Any] = field(default_factory=dict)


class RefinementStrategy(BaseModel):
    """Strategy for iterative refinement."""

    max_iterations: int = Field(default=5, ge=1, le=10)
    min_confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    backoff_factor: float = Field(default=1.5, ge=1.0, le=3.0)
    require_evidence: bool = Field(default=True)
    allow_partial_results: bool = Field(default=True)


class IterativeAnalysisResult(BaseModel):
    """Result from iterative analysis."""

    answer: str
    confidence: float
    iterations_used: int
    evidence_count: int
    tools_used: List[str]
    refinement_path: List[str]


class IterativeAgent:
    """Wrapper for agents that provides iterative refinement capabilities."""

    def __init__(
        self, base_agent: Agent, strategy: Optional[RefinementStrategy] = None
    ):
        """Initialize iterative agent.

        Args:
            base_agent: The underlying pydantic-ai agent
            strategy: Refinement strategy configuration
        """
        self.agent = base_agent
        self.strategy = strategy or RefinementStrategy()

    async def run_with_refinement(
        self,
        question: str,
        context: MemoryContext,
        initial_confidence: Optional[float] = None,
    ) -> IterativeAnalysisResult:
        """Run agent with iterative refinement.

        Args:
            question: The question to answer
            context: Memory context with KB and file info
            initial_confidence: Optional initial confidence estimate

        Returns:
            Analysis result with confidence and evidence
        """
        state = IterationState(confidence=initial_confidence or 0.0)
        best_result = None
        refinement_path = []

        while state.iteration < self.strategy.max_iterations:
            state.iteration += 1

            # Build prompt with context from previous iterations
            prompt = self._build_iterative_prompt(question, state)
            refinement_path.append(f"Iteration {state.iteration}: {prompt[:100]}...")

            try:
                # Run agent with current context
                result = await self.agent.run(prompt, deps=context)

                # Evaluate result quality
                confidence = await self._evaluate_confidence(result, context, state)
                state.confidence = confidence

                # Track evidence and tools
                self._update_state_from_result(result, state)

                # Keep best result so far
                if best_result is None or confidence > best_result.confidence:
                    best_result = IterativeAnalysisResult(
                        answer=str(result.output),
                        confidence=confidence,
                        iterations_used=state.iteration,
                        evidence_count=len(state.evidence_gathered),
                        tools_used=list(set(state.tools_used)),
                        refinement_path=refinement_path.copy(),
                    )

                # Check if we've reached sufficient confidence
                if confidence >= self.strategy.min_confidence:
                    return best_result

                # Add feedback for next iteration
                self._add_refinement_feedback(context, state, confidence)

                # Exponential backoff on wait time
                await asyncio.sleep(
                    0.1 * (self.strategy.backoff_factor**state.iteration)
                )

            except Exception as e:
                state.failed_attempts.append(str(e))
                if not self.strategy.allow_partial_results:
                    raise

        # Return best effort after max iterations
        if best_result and self.strategy.allow_partial_results:
            return best_result
        else:
            raise RuntimeError(
                f"Failed to achieve confidence {self.strategy.min_confidence} "
                f"after {self.strategy.max_iterations} iterations. "
                f"Best confidence: {state.confidence:.2f}"
            )

    def _build_iterative_prompt(self, question: str, state: IterationState) -> str:
        """Build prompt incorporating previous iteration context."""
        prompt_parts = [question]

        if state.iteration > 1:
            prompt_parts.append(f"\n\nThis is iteration {state.iteration}.")

            if state.evidence_gathered:
                prompt_parts.append(
                    f"So far, {len(state.evidence_gathered)} pieces of evidence have been found."
                )

            if state.failed_attempts:
                prompt_parts.append(
                    f"Previous attempts encountered issues: {', '.join(state.failed_attempts[-2:])}"
                )

            if state.confidence > 0:
                prompt_parts.append(
                    f"Current confidence level: {state.confidence:.1%}. "
                    f"Need to reach {self.strategy.min_confidence:.1%}."
                )

            prompt_parts.append(
                "Please explore different approaches or gather more evidence to improve confidence."
            )

        return "\n".join(prompt_parts)

    async def _evaluate_confidence(
        self, result: Any, context: MemoryContext, state: IterationState
    ) -> float:
        """Evaluate confidence in the result.

        Confidence factors:
        - Number of successful tool calls
        - Amount of evidence in KB
        - Consistency of findings
        - Explicit confidence if provided
        """
        confidence = 0.0
        factors = []

        # Check for explicit confidence in result
        if hasattr(result.output, "confidence"):
            confidence = max(confidence, float(result.output.confidence))
            factors.append(("explicit", result.output.confidence))

        # Factor: Evidence gathered
        if state.evidence_gathered:
            evidence_score = min(len(state.evidence_gathered) / 10, 1.0) * 0.3
            confidence = max(confidence, evidence_score)
            factors.append(("evidence", evidence_score))

        # Factor: Tool usage
        if state.tools_used:
            tool_score = min(len(set(state.tools_used)) / 5, 1.0) * 0.2
            confidence = max(confidence, confidence + tool_score)
            factors.append(("tools", tool_score))

        # Factor: KB node count (more exploration = higher confidence)
        kb_nodes = sum(1 for _ in context.kb.nodes())
        if kb_nodes > 10:
            kb_score = min(kb_nodes / 50, 1.0) * 0.2
            confidence = max(confidence, confidence + kb_score)
            factors.append(("kb_nodes", kb_score))

        # Factor: Result completeness
        if hasattr(result.output, "__dict__"):
            fields = result.output.__dict__
            filled = sum(1 for v in fields.values() if v is not None)
            completeness = filled / len(fields) if fields else 0
            confidence = max(confidence, confidence + completeness * 0.3)
            factors.append(("completeness", completeness))

        # Penalty for failures
        if state.failed_attempts:
            penalty = min(len(state.failed_attempts) * 0.1, 0.3)
            confidence = max(0.1, confidence - penalty)
            factors.append(("failures", -penalty))

        return min(confidence, 1.0)

    def _update_state_from_result(self, result: Any, state: IterationState):
        """Extract evidence and tool usage from result."""
        # Try to extract tool calls from result
        if hasattr(result, "all_messages"):
            try:
                messages = result.all_messages()
                for msg in messages:
                    if hasattr(msg, "parts"):
                        for part in msg.parts():
                            if hasattr(part, "tool_name"):
                                state.tools_used.append(part.tool_name)

                            # Track evidence from tool results
                            if hasattr(part, "content"):
                                content_str = str(part.content)
                                if len(content_str) > 50:  # Substantial content
                                    state.evidence_gathered.append(
                                        content_str[:200] + "..."
                                    )
            except Exception:
                pass  # Best effort extraction

    def _add_refinement_feedback(
        self, context: MemoryContext, state: IterationState, confidence: float
    ):
        """Add feedback to context for next iteration."""
        feedback = f"Iteration {state.iteration} confidence: {confidence:.1%}. "

        if confidence < 0.3:
            feedback += "Need much more evidence. Try different analysis approaches."
        elif confidence < 0.5:
            feedback += "Making progress but need deeper investigation."
        elif confidence < self.strategy.min_confidence:
            feedback += "Close to target. Focus on filling gaps in analysis."

        # Add as note in KB for context
        context.kb.add_node(
            id=f"feedback_{state.iteration}",
            type="refinement_feedback",
            properties={
                "iteration": state.iteration,
                "confidence": confidence,
                "message": feedback,
                "tools_used": state.tools_used.copy(),
                "evidence_count": len(state.evidence_gathered),
            },
        )


async def create_iterative_memory_agent(
    model: Optional[str] = None, strategy: Optional[RefinementStrategy] = None
) -> IterativeAgent:
    """Create an iterative memory agent.

    Args:
        model: Optional model name
        strategy: Refinement strategy

    Returns:
        Configured iterative agent
    """
    from .memory_agent import create_memory_agent

    base_agent = create_memory_agent(model=model)
    return IterativeAgent(base_agent, strategy=strategy)
