"""Tests for LLM integration (memory-first)."""

from unittest.mock import MagicMock
from pydantic_ai.models.test import TestModel

from glaurung.llm import LLMConfig
from glaurung.llm.context import MemoryContext
from glaurung.llm.agents.memory_foundation import inject_kb_context
from glaurung.llm.agents.summary_memory import BinarySummary, create_summarizer_agent


def test_llm_config():
    """Test LLM configuration."""
    config = LLMConfig()
    assert config.default_model == "openai:gpt-4.1-mini"
    assert config.temperature == 0.3

    # Test available models detection
    models = config.available_models()
    # Should detect at least one model from environment
    assert isinstance(models, dict)


def test_llm_config_env_override(monkeypatch):
    """Test environment variable overrides."""
    monkeypatch.setenv("GLAURUNG_LLM_MODEL", "anthropic:claude-sonnet-4-20250514")
    monkeypatch.setenv("GLAURUNG_LLM_TEMPERATURE", "0.7")

    config = LLMConfig()
    assert config.default_model == "anthropic:claude-sonnet-4-20250514"
    assert config.temperature == 0.7


def test_memory_context_basic():
    """Test MemoryContext creation and fields."""
    artifact = MagicMock()
    artifact.size_bytes = 1024
    artifact.verdicts = [MagicMock(format="ELF", arch="x86_64", bits=64)]
    ctx = MemoryContext(file_path="/test/binary", artifact=artifact)
    assert ctx.file_path == "/test/binary"
    assert ctx.artifact.size_bytes == 1024


def test_inject_kb_context_uses_memory():
    """Test KB context injection string."""
    artifact = MagicMock()
    artifact.size_bytes = 2048
    artifact.verdicts = [MagicMock(format="PE", arch="x86", bits=32)]
    ctx = MemoryContext(file_path="/test.exe", artifact=artifact)

    # Build a minimal RunContext-like object
    class RC:
        def __init__(self, deps):
            self.deps = deps

    context_str = inject_kb_context(RC(ctx))
    assert "file=/test.exe" in context_str
    assert "kb_nodes=" in context_str


def test_binary_summary_model():
    """Test BinarySummary pydantic model."""
    summary = BinarySummary(
        summary="Test binary for testing",
        purpose="Testing",
        risk_level="benign",
        key_behaviors=["Reads files", "Writes output"],
        recommendation="Safe to run",
    )

    # Test serialization
    data = summary.model_dump()
    assert data["summary"] == "Test binary for testing"
    assert data["risk_level"] == "benign"
    assert len(data["key_behaviors"]) == 2

    # Test validation
    assert summary.risk_level in [
        "benign",
        "low",
        "medium",
        "high",
        "critical",
        "unknown",
    ]


def test_summarizer_agent_with_test_model():
    """Test summarizer agent with TestModel."""

    # Create test response
    test_response = BinarySummary(
        summary="This is a system utility for listing files.",
        purpose="File management",
        risk_level="benign",
        key_behaviors=["Lists directory contents"],
        recommendation="Safe system utility",
    )

    # Create test model that returns our response
    test_model = TestModel(custom_output_args=test_response)

    # Create agent with test model
    agent = create_summarizer_agent()

    # Create mock context
    artifact = MagicMock()
    artifact.size_bytes = 1024
    artifact.verdicts = []
    artifact.entropy = None
    artifact.symbols = None
    artifact.strings = None
    artifact.similarity = None

    context = MemoryContext(artifact=artifact, file_path="/bin/ls")

    # Run agent with test model (sync)
    result = agent.run_sync("Analyze this binary", model=test_model, deps=context)

    assert result.output.summary == "This is a system utility for listing files."
    assert result.output.risk_level == "benign"


def test_logging_integration():
    """Test logging functionality."""
    from glaurung.llm.logging import LLMLogger

    logger = LLMLogger(enable_logging=True, log_level="INFO")

    # Test request logging
    logger.log_request("openai:gpt-4", "Test prompt", "System prompt")
    assert logger.total_requests == 1

    # Test response logging
    logger.log_response("openai:gpt-4", "Test response", duration=1.5)

    # Test error logging
    logger.log_error("openai:gpt-4", Exception("Test error"))

    # Test stats
    stats = logger.get_stats()
    assert stats["total_requests"] == 1
    assert stats["total_tokens"] == 0  # No usage provided

    # Test reset
    logger.reset_stats()
    assert logger.total_requests == 0
