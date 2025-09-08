#!/usr/bin/env python3
"""Test overlay detection functionality."""

from glaurung import triage


def test_overlay_analysis_creation():
    """Test that OverlayAnalysis can be created and accessed."""
    # Create a TriagedArtifact with overlay field
    artifact = triage.TriagedArtifact(
        id="test",
        path="/test/path",
        size_bytes=1024,
        schema_version="1.0.0",
        overlay=None,  # Test that None is accepted
    )

    # Verify the overlay field is accessible
    assert artifact.overlay is None

    # Test that we can access the overlay-related classes
    assert hasattr(triage, "OverlayAnalysis")
    assert hasattr(triage, "OverlayFormat")


def test_overlay_format_enum():
    """Test that OverlayFormat enum values are accessible."""
    # Check that we can access OverlayFormat enum values
    assert hasattr(triage.OverlayFormat, "ZIP")
    assert hasattr(triage.OverlayFormat, "CAB")
    assert hasattr(triage.OverlayFormat, "SevenZip")
    assert hasattr(triage.OverlayFormat, "RAR")
    assert hasattr(triage.OverlayFormat, "NSIS")
    assert hasattr(triage.OverlayFormat, "InnoSetup")
    assert hasattr(triage.OverlayFormat, "Certificate")
    assert hasattr(triage.OverlayFormat, "Unknown")


if __name__ == "__main__":
    test_overlay_analysis_creation()
    test_overlay_format_enum()
    print("All overlay tests passed!")
