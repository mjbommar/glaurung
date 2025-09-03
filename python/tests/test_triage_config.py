"""Tests for triage configuration Python bindings."""

import pytest


def test_triage_config_creation():
    """Test that triage configuration can be created and accessed from Python."""
    try:
        import glaurung.triage as triage

        # Create a new triage configuration
        config = triage.TriageConfig()

        # Test accessing nested configurations
        io_config = config.io
        entropy_config = config.entropy

        # Test accessing specific values
        assert io_config.max_sniff_size == 4096
        assert entropy_config.window_size == 8192

        # Test modification
        io_config.max_sniff_size = 8192
        assert io_config.max_sniff_size == 8192

    except ImportError:
        # Skip test if python-ext feature is not enabled
        pytest.skip("Python extension not built with python-ext feature")


def test_entropy_configuration():
    """Test entropy-specific configuration options."""
    try:
        import glaurung.triage as triage

        # Create entropy config
        entropy_config = triage.EntropyConfig()

        # Test thresholds
        thresholds = entropy_config.thresholds
        assert thresholds.text == 3.0
        assert thresholds.code == 5.0
        assert thresholds.encrypted == 7.8

        # Test weights
        weights = entropy_config.weights
        assert weights.header_body_mismatch == 0.6
        assert weights.cliff_detected == 0.2

        # Test modification
        thresholds.text = 2.5
        assert thresholds.text == 2.5

    except ImportError:
        pytest.skip("Python extension not built with python-ext feature")


def test_io_configuration():
    """Test I/O configuration options."""
    try:
        import glaurung.triage as triage

        # Create IO config
        io_config = triage.IOConfig()

        # Test default values
        assert io_config.max_sniff_size == 4096
        assert io_config.max_header_size == 65536
        assert io_config.max_file_size == 104857600  # 100MB

        # Test modification
        io_config.max_file_size = 52428800  # 50MB
        assert io_config.max_file_size == 52428800

    except ImportError:
        pytest.skip("Python extension not built with python-ext feature")


def test_customized_triage_config():
    """Test creating a customized triage configuration."""
    try:
        import glaurung.triage as triage

        # Create base config
        config = triage.TriageConfig()

        # Customize I/O settings
        config.io.max_file_size = 52428800  # 50MB
        config.io.max_read_bytes = 5242880  # 5MB

        # Customize entropy settings
        config.entropy.window_size = 4096
        config.entropy.thresholds.text = 2.5
        config.entropy.weights.high_entropy = 0.15

        # Customize scoring
        config.scoring.infer_weight = 0.20
        config.scoring.parser_success_confidence = 0.35

        # Verify changes
        assert config.io.max_file_size == 52428800
        assert config.entropy.window_size == 4096
        assert config.entropy.thresholds.text == 2.5
        assert config.scoring.infer_weight == 0.20

    except ImportError:
        pytest.skip("Python extension not built with python-ext feature")


if __name__ == "__main__":
    # Simple manual test
    test_triage_config_creation()
    test_entropy_configuration()
    test_io_configuration()
    test_customized_triage_config()
    print("All tests passed!")
