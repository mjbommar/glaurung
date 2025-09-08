"""Optimized single-pass agent implementation."""

from __future__ import annotations

import asyncio
from typing import Optional, Any

from pydantic import BaseModel, Field
from pydantic_ai import Agent

from .base import (
    AnalysisResult,
    ModelHyperparameters,
    ExecutionState,
    TerminationReason,
    AgentMetrics,
)


class SinglePassConfig(BaseModel):
    """Configuration for single-pass agent execution."""

    optimize_context: bool = Field(
        default=True, description="Pre-load likely needed context before execution"
    )
    fail_fast: bool = Field(
        default=False,
        description="Fail immediately on tool errors instead of returning partial results",
    )
    pre_populate_kb: bool = Field(
        default=True, description="Pre-populate KB with high-value data"
    )
    include_metadata: bool = Field(
        default=True, description="Include detailed metadata in results"
    )
    timeout_seconds: float = Field(
        default=60.0, gt=0.0, description="Maximum time for single execution"
    )


class SinglePassAgent:
    """
    Optimized agent for single-pass execution.

    This agent is designed for straightforward queries that can be answered
    in a single LLM call with tool executions. It includes optimizations like
    context pre-loading and fast failure modes.
    """

    def __init__(
        self,
        base_agent: Agent,
        config: Optional[SinglePassConfig] = None,
        model: Optional[str] = None,
    ):
        """
        Initialize single-pass agent.

        Args:
            base_agent: The underlying pydantic-ai agent
            config: Configuration for single-pass execution
            model: Optional model override
        """
        self.agent = base_agent
        self.config = config or SinglePassConfig()
        self.model = model
        self.metrics = AgentMetrics()

    async def analyze(
        self,
        question: str,
        context: Any,
        hyperparameters: Optional[ModelHyperparameters] = None,
    ) -> AnalysisResult:
        """
        Execute single-pass analysis with optimizations.

        Args:
            question: The question to analyze
            context: Analysis context (e.g., MemoryContext)
            hyperparameters: Optional model generation parameters

        Returns:
            AnalysisResult with answer and metadata
        """
        state = ExecutionState()
        params = hyperparameters or ModelHyperparameters()

        # Pre-load context if configured
        if self.config.optimize_context and self.config.pre_populate_kb:
            await self._preload_context(context)

        try:
            # Execute with timeout
            result = await asyncio.wait_for(
                self._execute_with_monitoring(question, context, state, params),
                timeout=self.config.timeout_seconds,
            )

            # Extract metrics
            confidence = self.metrics.extract_confidence(result, context)
            evidence_count = self.metrics.count_evidence(context)
            tools_used = self.metrics.extract_tools(result)
            tokens = self.metrics.count_tokens(result)

            # Build detailed metadata if configured
            metadata = {}
            if self.config.include_metadata:
                metadata = {
                    "model": self.model or "default",
                    "hyperparameters": params.model_dump(exclude_none=True),
                    "kb_nodes": sum(1 for _ in context.kb.nodes())
                    if hasattr(context, "kb")
                    else 0,
                    "kb_edges": sum(1 for _ in context.kb.edges())
                    if hasattr(context, "kb")
                    else 0,
                    "context_optimized": self.config.optimize_context,
                }

            return AnalysisResult(
                answer=str(result.output),
                confidence=confidence,
                iterations_used=1,
                total_tokens=tokens,
                execution_time=state.elapsed_seconds(),
                evidence_count=evidence_count,
                tools_used=tools_used,
                terminated_reason=TerminationReason.SINGLE_PASS_COMPLETE,
                metadata=metadata,
            )

        except asyncio.TimeoutError:
            return self._create_error_result(
                f"Single-pass execution timed out after {self.config.timeout_seconds}s",
                state,
                TerminationReason.TIMEOUT,
            )

        except Exception as e:
            if self.config.fail_fast:
                raise

            return self._create_error_result(
                f"Analysis failed: {str(e)}", state, TerminationReason.ERROR
            )

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
        return asyncio.run(self.analyze(question, context, hyperparameters))

    async def _execute_with_monitoring(
        self,
        question: str,
        context: Any,
        state: ExecutionState,
        params: ModelHyperparameters,
    ) -> Any:
        """Execute agent with monitoring and state tracking."""
        # Track tool calls if possible
        original_kb_add = None
        if hasattr(context, "kb") and hasattr(context.kb, "add_node"):
            original_kb_add = context.kb.add_node

            def monitored_add_node(*args, **kwargs):
                # Track evidence addition
                if args:
                    state.add_evidence(str(args[0]))
                elif "properties" in kwargs:
                    state.add_evidence(str(kwargs["properties"]))
                return original_kb_add(*args, **kwargs)

            context.kb.add_node = monitored_add_node

        try:
            # Run the agent, passing model + hyperparameters as kwargs
            model_kwargs = params.to_model_kwargs()
            if self.model:
                model_kwargs["model"] = self.model
            result = await self.agent.run(
                question,
                deps=context,
                **model_kwargs,
            )

            # Track tools used
            for tool_name, args in self.metrics.extract_tools_with_args(result):
                state.add_tool_call(tool_name, args)

            return result

        finally:
            # Restore original method
            if original_kb_add and hasattr(context, "kb"):
                context.kb.add_node = original_kb_add

    async def _preload_context(self, context: Any):
        """
        Pre-load high-value context before execution.

        This method pre-populates the KB with data that's likely to be needed,
        reducing the number of tool calls during the main execution.
        """
        if not hasattr(context, "kb"):
            return

        # Pre-load function list if binary analysis
        if hasattr(context, "artifact"):
            try:
                # Import tools for pre-loading
                from ..tools.list_functions import build_tool as build_list_functions
                from ..tools.map_symbol_addresses import (
                    build_tool as build_map_addresses,
                )

                # Pre-load function list (limited)
                list_tool = build_list_functions()
                list_tool.run(
                    context, context.kb, list_tool.input_model(max_functions=10)
                )

                # Pre-load symbol address map
                map_tool = build_map_addresses()
                map_tool.run(context, context.kb, map_tool.input_model())

            except ImportError:
                pass  # Tools not available
            except Exception:
                pass  # Soft fail on pre-loading

    def _create_error_result(
        self, error_message: str, state: ExecutionState, reason: TerminationReason
    ) -> AnalysisResult:
        """Create an error result."""
        return AnalysisResult(
            answer=error_message,
            confidence=0.0,
            iterations_used=1,
            total_tokens=state.tokens_used,
            execution_time=state.elapsed_seconds(),
            evidence_count=len(state.evidence_hashes),
            tools_used=list(set(state.tool_sequence)),
            terminated_reason=reason,
            metadata={"error": error_message},
        )


def create_single_pass_agent(
    base_agent: Agent,
    config: Optional[SinglePassConfig] = None,
    model: Optional[str] = None,
) -> SinglePassAgent:
    """
    Create an optimized single-pass agent.

    Args:
        base_agent: The underlying pydantic-ai agent
        config: Configuration for single-pass execution
        model: Optional model override

    Returns:
        Configured SinglePassAgent instance
    """
    return SinglePassAgent(base_agent, config, model)
