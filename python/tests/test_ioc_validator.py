"""Tests for IOC validation agent."""

from unittest.mock import MagicMock
from pydantic_ai.models.test import TestModel

from glaurung.llm.agents.ioc_validator import (
    IOCCandidate,
    IOCType,
    ValidatedIOC,
    IOCValidationResult,
    create_ioc_validator,
    filter_iocs_from_artifact,
)


def test_ioc_candidate_model():
    """Test IOCCandidate model."""
    candidate = IOCCandidate(
        value="192.168.1.1",
        ioc_type=IOCType.IPV4,
        offset=1024,
        context="Found in .data section",
        encoding="ascii",
    )

    assert candidate.value == "192.168.1.1"
    assert candidate.ioc_type == IOCType.IPV4
    assert candidate.offset == 1024


def test_validated_ioc_model():
    """Test ValidatedIOC model."""
    validated = ValidatedIOC(
        value="evil.malware.com",
        ioc_type=IOCType.DOMAIN,
        is_valid=True,
        confidence=0.95,
        reasoning="Suspicious domain with random subdomain pattern",
        risk_level="high",
        category="malware-c2",
    )

    assert validated.is_valid
    assert validated.confidence == 0.95
    assert validated.risk_level == "high"


def test_ioc_validation_result_model():
    """Test IOCValidationResult model."""
    result = IOCValidationResult(
        validated_iocs=[
            ValidatedIOC(
                value="1.1.1.1",
                ioc_type=IOCType.IPV4,
                is_valid=True,
                confidence=0.9,
                reasoning="Public DNS server",
                risk_level="low",
            ),
            ValidatedIOC(
                value="1.0.0.0",
                ioc_type=IOCType.IPV4,
                is_valid=False,
                confidence=0.95,
                reasoning="Version number pattern",
            ),
        ],
        summary="Validated 2 IOCs: 1 true positive, 1 false positive filtered",
        true_positive_count=1,
        false_positive_count=1,
        high_risk_iocs=[],
    )

    assert result.true_positive_count == 1
    assert result.false_positive_count == 1
    assert len(result.validated_iocs) == 2


def test_create_ioc_validator():
    """Test creating IOC validator agent."""
    agent = create_ioc_validator()

    assert agent is not None
    assert agent.output_type == IOCValidationResult


def test_validate_iocs_with_test_model():
    """Test IOC validation with TestModel."""

    # Create test candidates
    candidates = [
        IOCCandidate(
            value="192.168.1.1", ioc_type=IOCType.IPV4, context="private IP in config"
        ),
        IOCCandidate(
            value="evil-c2.tk", ioc_type=IOCType.DOMAIN, context="suspicious domain"
        ),
        IOCCandidate(value="1.2.3.4", ioc_type=IOCType.IPV4, context="version string"),
    ]

    # Create expected response
    expected_result = IOCValidationResult(
        validated_iocs=[
            ValidatedIOC(
                value="192.168.1.1",
                ioc_type=IOCType.IPV4,
                is_valid=False,
                confidence=1.0,
                reasoning="Private IP address, not a real IOC",
            ),
            ValidatedIOC(
                value="evil-c2.tk",
                ioc_type=IOCType.DOMAIN,
                is_valid=True,
                confidence=0.9,
                reasoning="Suspicious domain with commonly abused TLD",
                risk_level="high",
                category="malware-c2",
            ),
            ValidatedIOC(
                value="1.2.3.4",
                ioc_type=IOCType.IPV4,
                is_valid=False,
                confidence=0.95,
                reasoning="Sequential pattern indicates version or test data",
            ),
        ],
        summary="3 IOCs validated: 1 true positive (high risk), 2 false positives filtered",
        true_positive_count=1,
        false_positive_count=2,
        high_risk_iocs=["evil-c2.tk"],
    )

    # Create test model with expected output
    test_model = TestModel(custom_output_args=expected_result)

    # Create agent with test model
    agent = create_ioc_validator()

    # Run validation
    from glaurung.llm.agents.ioc_validator import IOCValidationBatch

    batch = IOCValidationBatch(candidates=candidates, binary_format="PE")

    result = agent.run_sync("Validate IOCs", model=test_model, deps=batch)

    assert result.output.true_positive_count == 1
    assert result.output.false_positive_count == 2
    assert len(result.output.high_risk_iocs) == 1
    assert result.output.high_risk_iocs[0] == "evil-c2.tk"


def test_filter_iocs_from_artifact():
    """Test filtering IOCs from a triaged artifact."""

    # Create mock artifact with IOC samples
    artifact = MagicMock()
    artifact.path = "/test/binary.exe"
    artifact.verdicts = [MagicMock(format="PE")]

    # Create mock IOC samples
    ioc_sample1 = MagicMock()
    ioc_sample1.kind = "ipv4"
    ioc_sample1.text = "8.8.8.8"
    ioc_sample1.offset = 1000

    ioc_sample2 = MagicMock()
    ioc_sample2.kind = "domain"
    ioc_sample2.text = "google.com"
    ioc_sample2.offset = 2000

    ioc_sample3 = MagicMock()
    ioc_sample3.kind = "ipv4"
    ioc_sample3.text = "192.168.1.1"
    ioc_sample3.offset = 3000

    artifact.strings = MagicMock()
    artifact.strings.ioc_samples = [ioc_sample1, ioc_sample2, ioc_sample3]

    # Other required artifact attributes
    artifact.size_bytes = 10000
    artifact.entropy = None
    artifact.symbols = None
    artifact.similarity = None

    # Create expected validation result
    expected_result = IOCValidationResult(
        validated_iocs=[
            ValidatedIOC(
                value="8.8.8.8",
                ioc_type=IOCType.IPV4,
                is_valid=True,
                confidence=0.95,
                reasoning="Public DNS server, legitimate",
                risk_level="low",
            ),
            ValidatedIOC(
                value="google.com",
                ioc_type=IOCType.DOMAIN,
                is_valid=True,
                confidence=1.0,
                reasoning="Legitimate service domain",
                risk_level="low",
            ),
            ValidatedIOC(
                value="192.168.1.1",
                ioc_type=IOCType.IPV4,
                is_valid=False,
                confidence=1.0,
                reasoning="Private IP address",
            ),
        ],
        summary="Validated 3 IOCs: 2 legitimate services, 1 false positive",
        true_positive_count=2,
        false_positive_count=1,
        high_risk_iocs=[],
    )

    # Use test model
    TestModel(custom_output_args=expected_result)

    # Mock the validator creation to use test model
    from unittest.mock import patch

    with patch(
        "glaurung.llm.agents.ioc_validator.create_contextual_ioc_validator"
    ) as mock_create:
        mock_agent = MagicMock()
        mock_agent.run_sync.return_value = MagicMock(output=expected_result)
        mock_create.return_value = mock_agent

        # Filter IOCs
        validated = filter_iocs_from_artifact(artifact, model="test")

        # Should return only the true positives
        assert len(validated) == 2
        assert all(ioc.is_valid for ioc in validated)
        assert validated[0].value == "8.8.8.8"
        assert validated[1].value == "google.com"


def test_ioc_type_enum():
    """Test IOCType enum values."""
    assert IOCType.IPV4 == "ipv4"
    assert IOCType.IPV6 == "ipv6"
    assert IOCType.DOMAIN == "domain"
    assert IOCType.HOSTNAME == "hostname"
    assert IOCType.URL == "url"
    assert IOCType.EMAIL == "email"
    assert IOCType.FILE_PATH == "file_path"
    assert IOCType.REGISTRY_KEY == "registry"


def test_validate_iocs_with_context():
    """Test validation with binary format context."""
    candidates = [
        IOCCandidate(
            value="notepad.exe", ioc_type=IOCType.FILE_PATH, context="Found in imports"
        ),
    ]

    expected_result = IOCValidationResult(
        validated_iocs=[
            ValidatedIOC(
                value="notepad.exe",
                ioc_type=IOCType.FILE_PATH,
                is_valid=False,
                confidence=1.0,
                reasoning="System binary reference, not an IOC",
            ),
        ],
        summary="1 false positive filtered (system binary)",
        true_positive_count=0,
        false_positive_count=1,
        high_risk_iocs=[],
    )

    test_model = TestModel(custom_output_args=expected_result)
    agent = create_ioc_validator()

    from glaurung.llm.agents.ioc_validator import IOCValidationBatch

    batch = IOCValidationBatch(
        candidates=candidates, binary_format="PE", binary_type="System Utility"
    )

    result = agent.run_sync("Validate IOCs", model=test_model, deps=batch)

    assert result.output.false_positive_count == 1
    assert result.output.true_positive_count == 0
