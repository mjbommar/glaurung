"""Factory module for creating analysis agents with different strategies."""

from __future__ import annotations

from typing import Optional, Union, Literal
from enum import Enum

from pydantic import BaseModel, Field
from pydantic_ai import Agent

from .base import ModelHyperparameters, AnalysisResult
from .single_pass import SinglePassAgent, SinglePassConfig, create_single_pass_agent
from .iterative_refinement import (
    IterativeRefinementAgent,
    IterativeConfig,
    create_iterative_agent,
)
from .memory_agent import create_memory_agent


class AgentStrategy(str, Enum):
    """Available agent execution strategies."""

    SINGLE_PASS = "single_pass"
    ITERATIVE = "iterative"
    AUTO = "auto"  # Automatically choose based on question complexity


class UnifiedAgentConfig(BaseModel):
    """Unified configuration for agent creation."""

    strategy: AgentStrategy = Field(
        default=AgentStrategy.AUTO, description="Execution strategy to use"
    )

    # Model configuration
    model: Optional[str] = Field(
        default=None, description="Model to use (e.g., 'openai:gpt-4')"
    )
    hyperparameters: Optional[ModelHyperparameters] = Field(
        default=None, description="Model generation hyperparameters"
    )

    # Strategy-specific configs
    single_pass_config: Optional[SinglePassConfig] = Field(
        default=None, description="Configuration for single-pass execution"
    )
    iterative_config: Optional[IterativeConfig] = Field(
        default=None, description="Configuration for iterative execution"
    )

    # Auto-strategy heuristics
    auto_complexity_threshold: int = Field(
        default=3,
        ge=1,
        description="Number of expected tool calls to trigger iterative mode",
    )
    auto_confidence_requirement: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Required confidence to trigger iterative mode",
    )


class AnalysisAgentFactory:
    """Factory for creating analysis agents with appropriate strategies."""

    @staticmethod
    def create_agent(
        config: Optional[UnifiedAgentConfig] = None,
        base_agent: Optional[Agent] = None,
    ) -> Union[SinglePassAgent, IterativeRefinementAgent]:
        """
        Create an analysis agent with the specified strategy.

        Args:
            config: Unified configuration for agent creation
            base_agent: Optional pre-configured base agent

        Returns:
            Configured agent instance
        """
        config = config or UnifiedAgentConfig()

        # Create base agent if not provided
        if base_agent is None:
            base_agent = create_memory_agent(model=config.model)

        # Create agent based on strategy
        if config.strategy == AgentStrategy.SINGLE_PASS:
            return create_single_pass_agent(
                base_agent, config.single_pass_config, config.model
            )

        elif config.strategy == AgentStrategy.ITERATIVE:
            return create_iterative_agent(
                base_agent, config.iterative_config, config.model
            )

        else:  # AUTO strategy
            # This would be enhanced with actual complexity detection
            # For now, return iterative as it's more robust
            return create_iterative_agent(
                base_agent,
                config.iterative_config
                or IterativeConfig(
                    max_iterations=3,  # Fewer iterations for auto mode
                    min_confidence=config.auto_confidence_requirement,
                ),
                config.model,
            )

    @staticmethod
    def create_safe_iterative_agent(
        model: Optional[str] = None,
        max_time_seconds: float = 120.0,
        max_tokens: int = 100_000,
    ) -> IterativeRefinementAgent:
        """
        Create an iterative agent with safe default settings.

        Args:
            model: Optional model name
            max_time_seconds: Maximum execution time
            max_tokens: Maximum token budget

        Returns:
            Safely configured iterative agent
        """
        config = IterativeConfig(
            max_iterations=5,
            min_confidence=0.7,
            max_total_seconds=max_time_seconds,
            max_total_tokens=max_tokens,
            allow_repeated_tools=1,
            detect_state_loops=True,
            progressive_temperature=True,
            require_evidence=True,
            min_evidence_pieces=2,
            allow_partial_results=True,
            require_progress=True,
            no_progress_iterations=2,
        )

        base_agent = create_memory_agent(model=model)
        return create_iterative_agent(base_agent, config, model)

    @staticmethod
    def create_fast_single_pass_agent(
        model: Optional[str] = None,
        timeout: float = 60.0,
    ) -> SinglePassAgent:
        """
        Create a fast single-pass agent optimized for speed.

        Args:
            model: Optional model name
            timeout: Execution timeout

        Returns:
            Speed-optimized single-pass agent
        """
        config = SinglePassConfig(
            optimize_context=True,
            fail_fast=False,
            pre_populate_kb=True,
            include_metadata=False,  # Skip metadata for speed
            timeout_seconds=timeout,
        )

        base_agent = create_memory_agent(model=model)
        return create_single_pass_agent(base_agent, config, model)

    @staticmethod
    async def analyze_with_best_strategy(
        question: str,
        context: Any,
        prefer_speed: bool = False,
        require_high_confidence: bool = False,
        model: Optional[str] = None,
        hyperparameters: Optional[ModelHyperparameters] = None,
    ) -> AnalysisResult:
        """
        Analyze using the most appropriate strategy.

        This method heuristically chooses between single-pass and iterative
        based on the question characteristics and requirements.

        Args:
            question: The question to analyze
            context: Analysis context
            prefer_speed: Prefer faster single-pass when possible
            require_high_confidence: Force iterative for high confidence
            model: Optional model name
            hyperparameters: Optional generation parameters

        Returns:
            Analysis result
        """
        # Simple heuristics for strategy selection
        question_lower = question.lower()

        # Indicators that suggest complex analysis needed
        complex_indicators = [
            "analyze" in question_lower,
            "explain" in question_lower,
            "compare" in question_lower,
            "malicious" in question_lower,
            "suspicious" in question_lower,
            "?" in question and len(question) > 100,  # Long questions
        ]

        # Count complexity score
        complexity_score = sum(complex_indicators)

        # Decide on strategy
        use_iterative = (
            require_high_confidence
            or complexity_score >= 3
            or (complexity_score >= 2 and not prefer_speed)
        )

        if use_iterative:
            agent = AnalysisAgentFactory.create_safe_iterative_agent(model=model)
        else:
            agent = AnalysisAgentFactory.create_fast_single_pass_agent(model=model)

        return await agent.analyze(question, context, hyperparameters)


# Convenience functions for backward compatibility
def create_analysis_agent(
    strategy: Literal["single_pass", "iterative", "auto"] = "auto",
    model: Optional[str] = None,
    **kwargs,
) -> Union[SinglePassAgent, IterativeRefinementAgent]:
    """
    Create an analysis agent with the specified strategy.

    Args:
        strategy: Execution strategy
        model: Optional model name
        **kwargs: Additional configuration options

    Returns:
        Configured agent instance
    """
    config = UnifiedAgentConfig(strategy=AgentStrategy(strategy), model=model, **kwargs)

    return AnalysisAgentFactory.create_agent(config)
