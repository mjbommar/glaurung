"""Tests for refactored agent infrastructure."""

import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock


from glaurung.llm.agents.base import (
    ModelHyperparameters,
    AnalysisResult,
    ExecutionState,
    TerminationReason,
    AgentMetrics,
)
from glaurung.llm.agents.single_pass import (
    SinglePassAgent,
    SinglePassConfig,
)
from glaurung.llm.agents.iterative_refinement import (
    IterativeRefinementAgent,
    IterativeConfig,
)
from glaurung.llm.agents.factory import (
    AnalysisAgentFactory,
    UnifiedAgentConfig,
    AgentStrategy,
)


class TestModelHyperparameters:
    """Test ModelHyperparameters configuration."""

    def test_default_values(self):
        """Test default hyperparameter values."""
        params = ModelHyperparameters()
        assert params.temperature == 0.3
        assert params.top_p is None
        assert params.max_tokens is None

    def test_to_model_kwargs(self):
        """Test conversion to model kwargs."""
        params = ModelHyperparameters(
            temperature=0.7, top_p=0.9, max_tokens=2048, seed=42
        )

        kwargs = params.to_model_kwargs()
        assert kwargs["temperature"] == 0.7
        assert kwargs["top_p"] == 0.9
        assert kwargs["max_output_tokens"] == 2048
        assert kwargs["seed"] == 42

    def test_validation_bounds(self):
        """Test parameter validation bounds."""
        # Temperature must be between 0 and 2
        with pytest.raises(ValueError):
            ModelHyperparameters(temperature=-0.1)

        with pytest.raises(ValueError):
            ModelHyperparameters(temperature=2.1)

        # top_p must be between 0 and 1
        with pytest.raises(ValueError):
            ModelHyperparameters(top_p=1.1)


class TestExecutionState:
    """Test ExecutionState tracking."""

    def test_tool_tracking(self):
        """Test tool call tracking and duplicate detection."""
        state = ExecutionState()

        # First call should not be duplicate
        assert not state.add_tool_call("search", {"query": "test"})

        # Same call should be duplicate
        assert state.add_tool_call("search", {"query": "test"})

        # Different args should not be duplicate
        assert not state.add_tool_call("search", {"query": "other"})

        # Check repeat count
        assert state.get_repeat_count("search", {"query": "test"}) == 2
        assert state.get_repeat_count("search", {"query": "other"}) == 1

    def test_evidence_tracking(self):
        """Test evidence deduplication."""
        state = ExecutionState()

        # New evidence should return True
        assert state.add_evidence("Evidence 1")
        assert state.add_evidence("Evidence 2")

        # Duplicate evidence should return False
        assert not state.add_evidence("Evidence 1")

        assert len(state.evidence_hashes) == 2

    def test_pattern_detection(self):
        """Test loop pattern detection."""
        state = ExecutionState()

        # Add pattern
        state.tool_sequence = ["tool1", "tool2", "tool3", "tool1", "tool2", "tool3"]

        # Should detect pattern of length 3
        assert state.has_pattern_loop(3)

        # Should not detect pattern of length 4
        assert not state.has_pattern_loop(4)

    def test_progress_tracking(self):
        """Test progress detection."""
        state = ExecutionState()
        state.iteration = 3

        # No evidence = no progress
        assert not state.is_making_progress()

        # Add evidence
        state.add_evidence("evidence")
        assert state.is_making_progress()

        # Stuck confidence = no progress
        state.confidence_history = [0.5, 0.5, 0.5]
        assert not state.is_making_progress()


class TestSinglePassAgent:
    """Test SinglePassAgent implementation."""

    @pytest.fixture
    def mock_base_agent(self):
        """Create mock base agent."""
        agent = MagicMock()
        agent.run = AsyncMock()
        return agent

    @pytest.fixture
    def mock_context(self):
        """Create mock context."""
        context = MagicMock()
        context.kb = MagicMock()
        context.kb.nodes = MagicMock(return_value=iter([{"id": "1"}, {"id": "2"}]))
        context.kb.edges = MagicMock(return_value=iter([]))
        context.kb.add_node = MagicMock()
        context.artifact = MagicMock()
        return context

    @pytest.mark.asyncio
    async def test_single_pass_execution(self, mock_base_agent, mock_context):
        """Test basic single-pass execution."""
        # Setup mock result
        mock_result = MagicMock()
        mock_result.output = "Test answer"
        mock_base_agent.run.return_value = mock_result

        # Create agent
        config = SinglePassConfig(
            optimize_context=False
        )  # Disable optimization for test
        agent = SinglePassAgent(mock_base_agent, config)

        # Run analysis
        result = await agent.analyze("Test question?", mock_context)

        # Verify result
        assert isinstance(result, AnalysisResult)
        assert result.answer == "Test answer"
        assert result.iterations_used == 1
        assert result.terminated_reason == TerminationReason.SINGLE_PASS_COMPLETE

        # Verify agent was called
        mock_base_agent.run.assert_called_once()

    @pytest.mark.asyncio
    async def test_hyperparameter_passing(self, mock_base_agent, mock_context):
        """Test hyperparameters are passed to model."""
        mock_result = MagicMock()
        mock_result.output = "Answer"
        mock_base_agent.run.return_value = mock_result

        agent = SinglePassAgent(mock_base_agent, SinglePassConfig())

        # Run with custom hyperparameters
        params = ModelHyperparameters(temperature=0.9, max_tokens=1000)
        await agent.analyze("Question?", mock_context, params)

        # Check kwargs passed to agent
        call_kwargs = mock_base_agent.run.call_args[1]
        assert call_kwargs.get("temperature") == 0.9
        assert call_kwargs.get("max_output_tokens") == 1000

    @pytest.mark.asyncio
    async def test_timeout_handling(self, mock_base_agent, mock_context):
        """Test timeout handling."""

        # Make agent.run hang
        async def slow_run(*args, **kwargs):
            await asyncio.sleep(10)

        mock_base_agent.run = slow_run

        # Create agent with short timeout
        config = SinglePassConfig(timeout_seconds=0.1)
        agent = SinglePassAgent(mock_base_agent, config)

        # Should timeout
        result = await agent.analyze("Question?", mock_context)
        assert result.terminated_reason == TerminationReason.TIMEOUT
        assert "timed out" in result.answer

    @pytest.mark.asyncio
    async def test_fail_fast_mode(self, mock_base_agent, mock_context):
        """Test fail-fast behavior."""
        # Make agent raise error
        mock_base_agent.run.side_effect = RuntimeError("Test error")

        # With fail_fast=True, should raise
        config = SinglePassConfig(fail_fast=True)
        agent = SinglePassAgent(mock_base_agent, config)

        with pytest.raises(RuntimeError):
            await agent.analyze("Question?", mock_context)

        # With fail_fast=False, should return error result
        config = SinglePassConfig(fail_fast=False)
        agent = SinglePassAgent(mock_base_agent, config)

        result = await agent.analyze("Question?", mock_context)
        assert result.terminated_reason == TerminationReason.ERROR
        assert "Test error" in result.answer


class TestIterativeRefinementAgent:
    """Test IterativeRefinementAgent implementation."""

    @pytest.fixture
    def mock_base_agent(self):
        """Create mock base agent."""
        agent = MagicMock()
        agent.run = AsyncMock()
        return agent

    @pytest.fixture
    def mock_context(self):
        """Create mock context."""
        context = MagicMock()
        context.kb = MagicMock()
        context.kb.nodes = MagicMock(return_value=iter([{"id": "1"}, {"id": "2"}]))
        context.kb.add_node = MagicMock()
        return context

    @pytest.mark.asyncio
    async def test_iterative_refinement(self, mock_base_agent, mock_context):
        """Test iterative refinement until confidence met."""
        # Setup progressive confidence improvement
        confidences = [0.3, 0.5, 0.8]
        results = []

        for conf in confidences:
            mock_result = MagicMock()
            mock_result.output = MagicMock()
            mock_result.output.confidence = conf
            mock_result.output.__str__ = lambda: f"Answer with confidence {conf}"
            results.append(mock_result)

        mock_base_agent.run.side_effect = results

        # Create agent with confidence threshold
        config = IterativeConfig(
            max_iterations=5,
            min_confidence=0.7,
            require_evidence=False,  # Simplify for test
        )
        agent = IterativeRefinementAgent(mock_base_agent, config)

        # Run analysis
        result = await agent.analyze("Complex question?", mock_context)

        # Should have made 3 iterations
        assert result.iterations_used == 3
        assert result.confidence == 0.8
        assert result.terminated_reason == TerminationReason.CONFIDENCE_MET
        assert mock_base_agent.run.call_count == 3

    @pytest.mark.asyncio
    async def test_max_iterations_limit(self, mock_base_agent, mock_context):
        """Test max iterations termination."""
        # Always return low confidence
        mock_result = MagicMock()
        mock_result.output = MagicMock()
        mock_result.output.confidence = 0.3
        mock_result.output.__str__ = lambda: "Low confidence answer"
        mock_base_agent.run.return_value = mock_result

        # Create agent with low iteration limit
        config = IterativeConfig(
            max_iterations=2,
            min_confidence=0.9,
            require_evidence=False,
        )
        agent = IterativeRefinementAgent(mock_base_agent, config)

        # Run analysis
        result = await agent.analyze("Question?", mock_context)

        # Should stop at max iterations
        assert result.iterations_used == 2
        assert result.terminated_reason == TerminationReason.MAX_ITERATIONS
        assert mock_base_agent.run.call_count == 2

    @pytest.mark.asyncio
    async def test_loop_detection(self, mock_base_agent, mock_context):
        """Test loop detection mechanism."""
        # Create result that simulates repeated tool calls
        mock_result = MagicMock()
        mock_result.output = "Answer"
        mock_result.all_messages = MagicMock(
            return_value=[
                MagicMock(
                    parts=MagicMock(
                        return_value=[
                            MagicMock(tool_name="search", args={"query": "test"})
                        ]
                    )
                )
            ]
        )
        mock_base_agent.run.return_value = mock_result

        # Create agent with strict loop detection
        config = IterativeConfig(
            max_iterations=10,
            allow_repeated_tools=0,  # No repeats allowed
            detect_state_loops=True,
        )
        agent = IterativeRefinementAgent(mock_base_agent, config)

        # Run analysis
        result = await agent.analyze("Question?", mock_context)

        # Should detect loop after 2 calls with same tool+args
        assert result.terminated_reason == TerminationReason.LOOP_DETECTED

    @pytest.mark.asyncio
    async def test_time_budget(self, mock_base_agent, mock_context):
        """Test time budget enforcement."""

        # Simulate slow iterations
        async def slow_run(*args, **kwargs):
            await asyncio.sleep(0.5)
            mock_result = MagicMock()
            mock_result.output = "Answer"
            return mock_result

        mock_base_agent.run = slow_run

        # Create agent with tight time budget
        config = IterativeConfig(
            max_iterations=10,
            max_total_seconds=0.7,  # Less than 2 iterations
        )
        agent = IterativeRefinementAgent(mock_base_agent, config)

        # Run analysis
        result = await agent.analyze("Question?", mock_context)

        # Should timeout after 1-2 iterations
        assert result.terminated_reason == TerminationReason.TIMEOUT
        assert result.iterations_used <= 2

    @pytest.mark.asyncio
    async def test_progressive_temperature(self, mock_base_agent, mock_context):
        """Test progressive temperature adjustment."""
        # Track temperatures used
        temperatures_used = []

        async def track_temp(*args, **kwargs):
            temperatures_used.append(kwargs.get("temperature", 0.3))
            mock_result = MagicMock()
            mock_result.output = MagicMock()
            mock_result.output.confidence = 0.2  # Stay low to trigger progression
            mock_result.output.__str__ = lambda: "Answer"
            return mock_result

        mock_base_agent.run = track_temp

        # Create agent with progressive temperature
        config = IterativeConfig(
            max_iterations=4,
            progressive_temperature=True,
            temperature_increase_factor=1.5,
        )
        agent = IterativeRefinementAgent(mock_base_agent, config)

        # Run with base temperature
        params = ModelHyperparameters(temperature=0.3)
        await agent.analyze("Question?", mock_context, params)

        # Temperature should increase after iteration 2
        assert len(temperatures_used) == 4
        assert temperatures_used[0] == 0.3  # Base
        assert temperatures_used[1] == 0.3  # Still base
        assert temperatures_used[2] > 0.3  # Increased
        assert temperatures_used[3] > temperatures_used[2]  # Further increased


class TestAgentFactory:
    """Test agent factory functionality."""

    def test_create_single_pass(self):
        """Test creating single-pass agent."""
        config = UnifiedAgentConfig(strategy=AgentStrategy.SINGLE_PASS)
        agent = AnalysisAgentFactory.create_agent(config)

        assert isinstance(agent, SinglePassAgent)

    def test_create_iterative(self):
        """Test creating iterative agent."""
        config = UnifiedAgentConfig(strategy=AgentStrategy.ITERATIVE)
        agent = AnalysisAgentFactory.create_agent(config)

        assert isinstance(agent, IterativeRefinementAgent)

    def test_create_safe_iterative(self):
        """Test creating safe iterative agent."""
        agent = AnalysisAgentFactory.create_safe_iterative_agent(
            max_time_seconds=60, max_tokens=50000
        )

        assert isinstance(agent, IterativeRefinementAgent)
        assert agent.config.max_total_seconds == 60
        assert agent.config.max_total_tokens == 50000
        assert agent.config.detect_state_loops is True

    def test_create_fast_single_pass(self):
        """Test creating fast single-pass agent."""
        agent = AnalysisAgentFactory.create_fast_single_pass_agent(timeout=30)

        assert isinstance(agent, SinglePassAgent)
        assert agent.config.timeout_seconds == 30
        assert agent.config.optimize_context is True
        assert agent.config.include_metadata is False


class TestAgentMetrics:
    """Test AgentMetrics helper class."""

    def test_extract_confidence(self):
        """Test confidence extraction."""
        metrics = AgentMetrics()

        # Test explicit confidence
        result = MagicMock()
        result.output = MagicMock()
        result.output.confidence = 0.85

        context = MagicMock()
        confidence = metrics.extract_confidence(result, context)
        assert confidence == 0.85

    def test_extract_tools(self):
        """Test tool extraction."""
        metrics = AgentMetrics()

        # Create mock result with tool calls
        result = MagicMock()
        result.all_messages = MagicMock(
            return_value=[
                MagicMock(
                    parts=MagicMock(
                        return_value=[
                            MagicMock(tool_name="search"),
                            MagicMock(tool_name="analyze"),
                            MagicMock(tool_name="search"),  # Duplicate
                        ]
                    )
                )
            ]
        )

        tools = metrics.extract_tools(result)
        assert set(tools) == {"search", "analyze"}
        assert len(tools) == 2  # Deduplicated

    def test_count_tokens(self):
        """Test token counting estimation."""
        metrics = AgentMetrics()

        result = MagicMock()
        result.output = "This is a test response with several words."
        result.usage = None  # No usage data

        # Should estimate based on output
        tokens = metrics.count_tokens(result)
        assert tokens > 0  # Some reasonable estimate


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
