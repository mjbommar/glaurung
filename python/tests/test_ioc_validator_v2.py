"""Tests for IOC validation V2 with hallucination prevention."""

import pytest
from unittest.mock import MagicMock

from glaurung.llm.agents.ioc_validator_v2 import (
    IOCCandidate,
    IOCType,
    IOCValidationDecision,
    IOCValidationOutput,
    validate_iocs_v2,
    filter_iocs_from_artifact_v2,
)


def test_no_hallucination_possible():
    """Test that the validator cannot hallucinate new IOCs."""

    # Input candidates
    candidates = [
        IOCCandidate(value="192.168.1.1", ioc_type=IOCType.IPV4, context="private IP"),
        IOCCandidate(
            value="google.com", ioc_type=IOCType.DOMAIN, context="legitimate domain"
        ),
        IOCCandidate(value="1.2.3.4", ioc_type=IOCType.IPV4, context="version string"),
    ]

    # Create test response with decisions
    test_response = IOCValidationOutput(
        decisions=[
            IOCValidationDecision(
                candidate_index=0,
                is_valid=False,
                confidence=1.0,
                reasoning="Private IP, not a real IOC",
            ),
            IOCValidationDecision(
                candidate_index=1,
                is_valid=True,
                confidence=0.9,
                reasoning="Legitimate service",
                risk_level="low",
            ),
            IOCValidationDecision(
                candidate_index=2,
                is_valid=False,
                confidence=0.95,
                reasoning="Sequential pattern",
            ),
        ],
        summary="3 IOCs validated",
    )

    # Mock the agent
    from unittest.mock import patch, MagicMock

    mock_agent = MagicMock()
    mock_agent.run_sync.return_value = MagicMock(output=test_response)

    with patch(
        "glaurung.llm.agents.ioc_validator_v2.create_ioc_validator_v2",
        return_value=mock_agent,
    ):
        validated, tp, fp = validate_iocs_v2(candidates)

    # Verify results
    assert len(validated) == 3
    assert tp == 1
    assert fp == 2

    # CRITICAL: Verify all values are from original candidates
    validated_values = [v.value for v in validated]
    original_values = [c.value for c in candidates]

    for val in validated_values:
        assert val in original_values, (
            f"Hallucinated value {val} not in original candidates!"
        )

    # Verify specific validations
    assert validated[0].value == "192.168.1.1"
    assert validated[0].is_valid == False

    assert validated[1].value == "google.com"
    assert validated[1].is_valid == True

    assert validated[2].value == "1.2.3.4"
    assert validated[2].is_valid == False


def test_hallucination_detection_raises_error():
    """Test that hallucination is detected and raises an error."""

    candidates = [
        IOCCandidate(value="test.com", ioc_type=IOCType.DOMAIN),
    ]

    # Try to return a decision with wrong index
    bad_response = IOCValidationOutput(
        decisions=[
            IOCValidationDecision(
                candidate_index=5,  # Invalid index!
                is_valid=True,
                confidence=0.9,
                reasoning="Test",
            ),
        ],
        summary="Test",
    )

    mock_agent = MagicMock()
    mock_agent.run_sync.return_value = MagicMock(output=bad_response)

    from unittest.mock import patch

    with patch(
        "glaurung.llm.agents.ioc_validator_v2.create_ioc_validator_v2",
        return_value=mock_agent,
    ):
        # This should handle the invalid index gracefully
        validated, tp, fp = validate_iocs_v2(candidates)

        # Should treat missing validation as false positive
        assert len(validated) == 1
        assert validated[0].value == "test.com"
        assert validated[0].is_valid == False  # No decision = false positive


def test_duplicate_index_validation():
    """Test that duplicate indices in decisions are rejected."""

    with pytest.raises(ValueError, match="Duplicate validation"):
        IOCValidationOutput(
            decisions=[
                IOCValidationDecision(
                    candidate_index=0, is_valid=True, confidence=0.9, reasoning="First"
                ),
                IOCValidationDecision(
                    candidate_index=0,  # Duplicate!
                    is_valid=False,
                    confidence=0.8,
                    reasoning="Second",
                ),
            ],
            summary="Test",
        )


def test_filter_from_artifact_v2():
    """Test filtering from artifact with V2."""

    # Create mock artifact
    artifact = MagicMock()
    artifact.path = "/test/binary.exe"
    artifact.verdicts = [MagicMock(format="PE")]

    # Create mock IOC samples
    ioc_sample1 = MagicMock()
    ioc_sample1.kind = "ipv4"
    ioc_sample1.text = "8.8.8.8"

    ioc_sample2 = MagicMock()
    ioc_sample2.kind = "domain"
    ioc_sample2.text = "google.com"

    artifact.strings = MagicMock()
    artifact.strings.ioc_samples = [ioc_sample1, ioc_sample2]

    # Mock validation
    test_response = IOCValidationOutput(
        decisions=[
            IOCValidationDecision(
                candidate_index=0,
                is_valid=True,
                confidence=0.9,
                reasoning="Public DNS",
                risk_level="low",
            ),
            IOCValidationDecision(
                candidate_index=1,
                is_valid=True,
                confidence=1.0,
                reasoning="Legitimate service",
                risk_level="low",
            ),
        ],
        summary="2 valid IOCs",
    )

    mock_agent = MagicMock()
    mock_agent.run_sync.return_value = MagicMock(output=test_response)

    from unittest.mock import patch

    with patch(
        "glaurung.llm.agents.ioc_validator_v2.create_ioc_validator_v2",
        return_value=mock_agent,
    ):
        validated = filter_iocs_from_artifact_v2(artifact)

    # Should return only true positives
    assert len(validated) == 2
    assert all(ioc.is_valid for ioc in validated)

    # CRITICAL: Verify values match originals
    assert validated[0].value == "8.8.8.8"
    assert validated[1].value == "google.com"


def test_empty_candidates():
    """Test handling of empty candidate list."""
    validated, tp, fp = validate_iocs_v2([])
    assert validated == []
    assert tp == 0
    assert fp == 0


def test_missing_decision_treated_as_false_positive():
    """Test that candidates without decisions are treated as false positives."""

    candidates = [
        IOCCandidate(value="test1.com", ioc_type=IOCType.DOMAIN),
        IOCCandidate(value="test2.com", ioc_type=IOCType.DOMAIN),
        IOCCandidate(value="test3.com", ioc_type=IOCType.DOMAIN),
    ]

    # Only provide decision for first one
    response = IOCValidationOutput(
        decisions=[
            IOCValidationDecision(
                candidate_index=0, is_valid=True, confidence=0.9, reasoning="Valid"
            ),
        ],
        summary="Partial validation",
    )

    mock_agent = MagicMock()
    mock_agent.run_sync.return_value = MagicMock(output=response)

    from unittest.mock import patch

    with patch(
        "glaurung.llm.agents.ioc_validator_v2.create_ioc_validator_v2",
        return_value=mock_agent,
    ):
        validated, tp, fp = validate_iocs_v2(candidates)

    assert len(validated) == 3
    assert tp == 1
    assert fp == 2

    # First should be valid
    assert validated[0].is_valid == True
    # Others should be false positives
    assert validated[1].is_valid == False
    assert validated[2].is_valid == False
