"""Iterative refinement agent with safety mechanisms and progressive strategies."""

from __future__ import annotations

import asyncio
from typing import Optional, Any

from pydantic import BaseModel, Field
from pydantic_ai import Agent, ModelRetry

from .base import (
    AnalysisResult,
    ModelHyperparameters,
    ExecutionState,
    TerminationReason,
    AgentMetrics,
)


class IterativeConfig(BaseModel):
    """Configuration for iterative agent execution with safety mechanisms."""

    # Iteration control
    max_iterations: int = Field(
        default=5, ge=1, le=20, description="Maximum number of refinement iterations"
    )
    min_confidence: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Minimum confidence threshold to consider answer sufficient",
    )

    # Safety mechanisms - Time and resource limits
    max_total_seconds: float = Field(
        default=120.0,
        gt=0.0,
        le=600.0,
        description="Maximum total execution time in seconds",
    )
    max_total_tokens: Optional[int] = Field(
        default=100_000,
        ge=100,
        description="Maximum total tokens across all iterations",
    )

    # Loop detection
    allow_repeated_tools: int = Field(
        default=1,
        ge=0,
        le=5,
        description="How many times the same tool+args can be called (0=no repeats)",
    )
    detect_state_loops: bool = Field(
        default=True, description="Detect when agent is stuck in behavioral loops"
    )
    pattern_detection_length: int = Field(
        default=3, ge=2, le=5, description="Length of tool sequence patterns to detect"
    )

    # Progressive strategies
    progressive_temperature: bool = Field(
        default=True,
        description="Increase temperature when stuck to encourage exploration",
    )
    temperature_increase_factor: float = Field(
        default=1.2,
        ge=1.0,
        le=2.0,
        description="Factor to increase temperature by when stuck",
    )
    max_temperature: float = Field(
        default=1.5,
        ge=0.5,
        le=2.0,
        description="Maximum temperature to reach during progression",
    )

    # Behavioral settings
    require_evidence: bool = Field(
        default=True, description="Require gathering evidence before accepting answer"
    )
    min_evidence_pieces: int = Field(
        default=2, ge=0, description="Minimum evidence pieces required"
    )
    allow_partial_results: bool = Field(
        default=True, description="Return best partial result if iterations exhausted"
    )
    backoff_factor: float = Field(
        default=1.5,
        ge=1.0,
        le=3.0,
        description="Exponential backoff factor between iterations",
    )
    max_backoff_seconds: float = Field(
        default=5.0,
        ge=0.1,
        le=30.0,
        description="Maximum backoff time between iterations",
    )

    # Progress requirements
    require_progress: bool = Field(
        default=False, description="Terminate if no progress is being made"
    )
    no_progress_iterations: int = Field(
        default=2,
        ge=1,
        le=5,
        description="Iterations without progress before terminating",
    )


class IterativeRefinementAgent:
    """
    Agent that iteratively refines its analysis with safety mechanisms.

    This agent can make multiple passes to improve its answer quality,
    with comprehensive safety features including:
    - Time and token budgets
    - Loop detection and prevention
    - Progressive temperature adjustment
    - Evidence requirements
    - State tracking
    """

    def __init__(
        self,
        base_agent: Agent,
        config: Optional[IterativeConfig] = None,
        model: Optional[str] = None,
    ):
        """
        Initialize iterative refinement agent.

        Args:
            base_agent: The underlying pydantic-ai agent
            config: Configuration for iterative execution
            model: Optional model override
        """
        self.agent = base_agent
        self.config = config or IterativeConfig()
        self.model = model
        self.metrics = AgentMetrics()

    async def analyze(
        self,
        question: str,
        context: Any,
        hyperparameters: Optional[ModelHyperparameters] = None,
    ) -> AnalysisResult:
        """
        Iteratively refine analysis with safety mechanisms.

        Args:
            question: The question to analyze
            context: Analysis context (e.g., MemoryContext)
            hyperparameters: Optional model generation parameters

        Returns:
            AnalysisResult with best answer and metadata
        """
        import sys

        print("DEBUG: Starting iterative analysis", file=sys.stderr)
        state = ExecutionState()
        base_params = hyperparameters or ModelHyperparameters()
        best_result = None
        best_confidence = 0.0
        iterations_without_progress = 0

        for iteration in range(1, self.config.max_iterations + 1):
            print(f"DEBUG: Iteration {iteration}", file=sys.stderr)
            state.iteration = iteration

            # Check safety conditions before iteration
            termination_reason = self._check_termination_conditions(state)
            if termination_reason:
                return self._create_result(
                    best_result, state, termination_reason, best_confidence
                )

            # Adjust hyperparameters based on progress
            current_params = self._adjust_hyperparameters(base_params, state, iteration)

            # Build iteration-aware prompt
            iteration_prompt = self._build_iteration_prompt(question, state, iteration)

            try:
                # Calculate timeout for this iteration
                remaining_time = self.config.max_total_seconds - state.elapsed_seconds()
                # Use longer timeout for first iteration, shorter for subsequent ones
                base_timeout = 60.0 if iteration == 1 else 30.0
                iteration_timeout = min(base_timeout, remaining_time)

                # Execute iteration with monitoring
                result = await asyncio.wait_for(
                    self._execute_iteration(
                        iteration_prompt,
                        context,
                        current_params,
                        state,
                    ),
                    timeout=iteration_timeout,
                )

                # Evaluate iteration quality FIRST (before loop detection)
                confidence = self.metrics.extract_confidence(result, context)
                state.update_confidence(confidence)

                # Check for behavioral loops AFTER evaluating confidence
                if self._detect_loops(result, state):
                    # Use the current confidence, not the old best_confidence
                    return self._create_result(
                        result,  # Use current result which might be good
                        state,
                        TerminationReason.LOOP_DETECTED,
                        max(confidence, best_confidence),  # Use better of the two
                    )

                # Check for progress
                if not self._is_making_progress(state, confidence):
                    iterations_without_progress += 1
                    if (
                        iterations_without_progress
                        >= self.config.no_progress_iterations
                    ):
                        return self._create_result(
                            best_result or result,
                            state,
                            TerminationReason.NO_PROGRESS,
                            max(best_confidence, confidence),
                        )
                else:
                    iterations_without_progress = 0

                # Update best result
                if confidence > best_confidence:
                    best_result = result
                    best_confidence = confidence

                # Check if confidence target met
                if confidence >= self.config.min_confidence:
                    if self._meets_evidence_requirements(state):
                        return self._create_result(
                            result, state, TerminationReason.CONFIDENCE_MET, confidence
                        )

                # Add feedback to context for next iteration
                self._inject_iteration_feedback(context, state, confidence, iteration)

                # Backoff between iterations (with exponential increase)
                if iteration < self.config.max_iterations:
                    backoff_time = min(
                        0.1 * (self.config.backoff_factor**iteration),
                        self.config.max_backoff_seconds,
                    )
                    await asyncio.sleep(backoff_time)

            except asyncio.TimeoutError:
                if best_result and self.config.allow_partial_results:
                    return self._create_result(
                        best_result, state, TerminationReason.TIMEOUT, best_confidence
                    )
                raise

            except ModelRetry as retry_error:
                # Handle pydantic-ai retry exceptions
                state.last_error = str(retry_error)
                # Continue to next iteration with feedback

            except Exception as e:
                state.last_error = str(e)
                if not self.config.allow_partial_results:
                    raise

        # Max iterations reached
        if best_result:
            return self._create_result(
                best_result, state, TerminationReason.MAX_ITERATIONS, best_confidence
            )
        else:
            raise RuntimeError(
                f"Failed to obtain results after {self.config.max_iterations} iterations. "
                f"Last error: {state.last_error}"
            )

    def analyze_sync(
        self,
        question: str,
        context: Any,
        hyperparameters: Optional[ModelHyperparameters] = None,
    ) -> AnalysisResult:
        """Synchronous version of analyze."""
        return asyncio.run(self.analyze(question, context, hyperparameters))

    def _check_termination_conditions(
        self, state: ExecutionState
    ) -> Optional[TerminationReason]:
        """Check if any termination conditions are met."""
        # Time limit
        if state.elapsed_seconds() > self.config.max_total_seconds:
            return TerminationReason.TIMEOUT

        # Token limit
        if (
            self.config.max_total_tokens
            and state.tokens_used > self.config.max_total_tokens
        ):
            return TerminationReason.TOKEN_LIMIT

        return None

    def _adjust_hyperparameters(
        self, base_params: ModelHyperparameters, state: ExecutionState, iteration: int
    ) -> ModelHyperparameters:
        """Adjust hyperparameters based on iteration state."""
        params = base_params.model_copy()

        if not self.config.progressive_temperature:
            return params

        # Increase temperature if stuck (low confidence or no progress)
        if iteration > 2:
            avg_confidence = (
                sum(state.confidence_history[-3:]) / len(state.confidence_history[-3:])
                if len(state.confidence_history) >= 3
                else 0.0
            )

            if avg_confidence < 0.4:  # Very stuck
                temp_increase = self.config.temperature_increase_factor ** (
                    iteration - 2
                )
                params.temperature = min(
                    base_params.temperature * temp_increase, self.config.max_temperature
                )

        return params

    def _build_iteration_prompt(
        self, question: str, state: ExecutionState, iteration: int
    ) -> str:
        """Build iteration-aware prompt with context."""
        parts = [question]

        if iteration == 1:
            return question

        # Add iteration context
        parts.append(f"\n[Iteration {iteration}/{self.config.max_iterations}]")

        # Add progress indicators
        if state.confidence_history:
            current = state.confidence_history[-1]
            target = self.config.min_confidence
            parts.append(f"Current confidence: {current:.0%} (target: {target:.0%})")

        # Add evidence status
        evidence_count = len(state.evidence_hashes)
        if self.config.require_evidence:
            parts.append(
                f"Evidence gathered: {evidence_count}/{self.config.min_evidence_pieces} pieces"
            )

        # Add guidance based on state
        if state.last_error:
            parts.append(f"Previous attempt encountered: {state.last_error}")
            parts.append("Please try a different approach.")

        elif len(state.confidence_history) >= 2:
            last_conf = state.confidence_history[-1]
            prev_conf = state.confidence_history[-2]

            if last_conf > prev_conf:
                parts.append("Good progress! Continue refining the analysis.")
            elif last_conf == prev_conf:
                parts.append("No improvement. Try exploring different aspects.")
            else:
                parts.append("Confidence decreased. Reconsider the approach.")

        # Warn about repeated tools
        if state.tool_sequence:
            unique_tools = set(state.tool_sequence)
            if len(state.tool_sequence) > len(unique_tools) * 2:
                parts.append(
                    "Note: Some tools have been used multiple times. "
                    "Consider using different tools or parameters."
                )

        return "\n".join(parts)

    async def _execute_iteration(
        self,
        prompt: str,
        context: Any,
        params: ModelHyperparameters,
        state: ExecutionState,
    ) -> Any:
        """Execute a single iteration with monitoring."""
        # Note: pydantic-ai doesn't accept hyperparameters directly in run()
        # Would need to configure at agent creation or use model-specific settings

        # Run agent
        model_kwargs = params.to_model_kwargs()
        if self.model:
            model_kwargs["model"] = self.model
        result = await self.agent.run(
            prompt,
            deps=context,
            **model_kwargs,
        )

        # Update state with metrics
        state.tokens_used += self.metrics.count_tokens(result)

        # Track tool usage
        for tool_name, args in self.metrics.extract_tools_with_args(result):
            state.add_tool_call(tool_name, args)

        # Track evidence
        if hasattr(result, "output"):
            try:
                state.add_evidence(str(result.output))
            except Exception:
                # Be robust to broken __str__ on mocks
                try:
                    state.add_evidence(repr(result.output))
                except Exception:
                    pass

        return result

    def _detect_loops(self, result: Any, state: ExecutionState) -> bool:
        """Detect behavioral loops in execution."""
        if not self.config.detect_state_loops:
            return False

        # Check for exact tool+args repetition
        for tool_name, args in self.metrics.extract_tools_with_args(result):
            repeat_count = state.get_repeat_count(tool_name, args)
            if repeat_count > self.config.allow_repeated_tools + 1:
                return True

        # Check for pattern loops in tool sequence
        if state.has_pattern_loop(self.config.pattern_detection_length):
            return True

        return False

    def _is_making_progress(
        self, state: ExecutionState, current_confidence: float
    ) -> bool:
        """Check if the agent is making meaningful progress."""
        if not self.config.require_progress:
            return True

        # First iteration always counts as progress
        if state.iteration == 1:
            return True

        # Check confidence improvement
        if len(state.confidence_history) >= 2:
            if current_confidence > state.confidence_history[-2] + 0.05:
                return True

        # Check evidence growth
        if state.iteration >= 2 and len(state.evidence_hashes) > state.iteration:
            return True

        # Check tool diversity (trying new things)
        if state.tool_sequence:
            recent_tools = (
                state.tool_sequence[-5:]
                if len(state.tool_sequence) >= 5
                else state.tool_sequence
            )
            if len(set(recent_tools)) >= 3:  # Using diverse tools
                return True

        return False

    def _meets_evidence_requirements(self, state: ExecutionState) -> bool:
        """Check if evidence requirements are met."""
        if not self.config.require_evidence:
            return True

        return len(state.evidence_hashes) >= self.config.min_evidence_pieces

    def _inject_iteration_feedback(
        self, context: Any, state: ExecutionState, confidence: float, iteration: int
    ):
        """Inject feedback into context for next iteration."""
        if not hasattr(context, "kb"):
            return

        feedback = {
            "iteration": iteration,
            "confidence": confidence,
            "evidence_count": len(state.evidence_hashes),
            "tools_used": list(set(state.tool_sequence)),
            "improving": confidence
            > (
                state.confidence_history[-2]
                if len(state.confidence_history) >= 2
                else 0
            ),
        }

        # Add guidance based on confidence
        if confidence < 0.3:
            feedback["guidance"] = (
                "Need much more investigation. Try broader search strategies."
            )
        elif confidence < 0.5:
            feedback["guidance"] = (
                "Making progress. Focus on gathering specific evidence."
            )
        elif confidence < self.config.min_confidence:
            feedback["guidance"] = (
                f"Close to target. Need {(self.config.min_confidence - confidence):.0%} more confidence."
            )

        # Add as KB node for context
        try:
            context.kb.add_node(
                id=f"iteration_feedback_{iteration}",
                type="iteration_feedback",
                properties=feedback,
            )
        except Exception:
            pass  # Soft fail on feedback injection

    def _create_result(
        self,
        best_result: Any,
        state: ExecutionState,
        reason: TerminationReason,
        confidence: float,
    ) -> AnalysisResult:
        """Create final analysis result."""
        if best_result is None:
            answer = "Unable to complete analysis"
        else:
            try:
                out = best_result.output
                answer = out if isinstance(out, str) else str(out)
            except Exception:
                answer = "Analysis complete"

        metadata = {
            "iterations": state.iteration,
            "confidence_history": state.confidence_history,
            "unique_tools": len(set(state.tool_sequence)),
            "evidence_pieces": len(state.evidence_hashes),
            "final_confidence": confidence,
        }

        if state.last_error:
            metadata["last_error"] = state.last_error

        return AnalysisResult(
            answer=answer,
            confidence=confidence,
            iterations_used=state.iteration,
            total_tokens=state.tokens_used,
            execution_time=state.elapsed_seconds(),
            evidence_count=len(state.evidence_hashes),
            tools_used=list(set(state.tool_sequence)),
            terminated_reason=reason,
            metadata=metadata,
        )


def create_iterative_agent(
    base_agent: Agent,
    config: Optional[IterativeConfig] = None,
    model: Optional[str] = None,
) -> IterativeRefinementAgent:
    """
    Create an iterative refinement agent with safety mechanisms.

    Args:
        base_agent: The underlying pydantic-ai agent
        config: Configuration for iterative execution
        model: Optional model override

    Returns:
        Configured IterativeRefinementAgent instance
    """
    return IterativeRefinementAgent(base_agent, config, model)
