#!/usr/bin/env python3
"""Test overlay detection integration."""

import os
from glaurung import triage


def test_pe_with_zip_overlay():
    """
    Test triage on a PE file with a ZIP overlay.
    """
    # Get the path to the test sample
    test_file_path = os.path.join(
        os.path.dirname(__file__), "samples", "pe_with_overlay.exe"
    )

    # Triage the file
    artifact = triage.triage(test_file_path)

    # Verify the overlay analysis
    assert artifact.overlay is not None, "Overlay should be detected"
    overlay = artifact.overlay

    # Get file sizes for verification
    pe_size = os.path.getsize(
        "/home/mjbommar/src/glaurung/samples/binaries/platforms/windows/amd64/export/windows/x86_64/release/hello-c-mingw64-release.exe"
    )
    zip_size = os.path.getsize(
        "/home/mjbommar/src/glaurung/samples/containers/zip/hello-cpp-g++-O0.zip"
    )

    # Check overlay properties
    assert overlay.offset == pe_size, f"Overlay offset should be {pe_size}"
    assert overlay.size == zip_size, f"Overlay size should be {zip_size}"
    assert repr(overlay.detected_format) == repr(triage.OverlayFormat.ZIP), (
        "Detected format should be ZIP"
    )
    assert overlay.is_archive, "is_archive should be True for ZIP"
    assert not overlay.has_signature, "has_signature should be False"
    assert overlay.entropy > 7.5, "Entropy of a ZIP file should be high"


if __name__ == "__main__":
    test_pe_with_zip_overlay()
    print("All overlay integration tests passed!")
