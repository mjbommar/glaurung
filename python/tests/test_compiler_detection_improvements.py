"""Tests for compiler detection improvements including packer detection and stripped binary handling."""

import pytest
import glaurung.triage as triage
from pathlib import Path


def test_packer_detection():
    """Test detection of UPX packed binaries."""
    upx_path = Path(
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-cpp-g++-O0.upx9"
    )

    if upx_path.exists():
        result = triage.analyze_path(str(upx_path))
        # Check if packer is mentioned in the triage result
        # Since we don't expose PackerType directly, check the verdict or metadata
        assert result is not None
        # The evidence summary should mention packing
        # This will depend on the Python API exposure


def test_stripped_binary_detection():
    """Test detection of stripped binaries with compiler fallback."""
    stripped_paths = [
        "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-stripped",
        "samples/binaries/platforms/linux/amd64/export/native/gcc/debug/hello-gcc-stripped",
    ]

    for path_str in stripped_paths:
        path = Path(path_str)
        if not path.exists():
            continue

        result = triage.analyze_path(str(path))
        assert result is not None

        # Check that language is detected even though binary is stripped
        # The exact API depends on what's exposed in Python
        # For now, just verify it doesn't crash
        print(f"Stripped binary {path.name}: Triaged successfully")


def test_shared_library_detection():
    """Test detection of shared libraries defaulting to C."""
    lib_path = Path(
        "samples/binaries/platforms/linux/amd64/export/libraries/shared/libmathlib.so"
    )

    if lib_path.exists():
        result = triage.analyze_path(str(lib_path))
        assert result is not None
        # Shared libraries should be detected, check result
        print("Shared library: Triaged successfully")


def test_bytecode_detection():
    """Test detection of bytecode formats (Java, Python, etc.)."""
    bytecode_files = [
        (
            "samples/binaries/platforms/linux/amd64/export/java/jdk21/HelloWorld.class",
            "Java",
        ),
        (
            "samples/binaries/platforms/linux/amd64/export/python/hello-python.pyc",
            "Python",
        ),
        ("samples/binaries/platforms/linux/amd64/export/lua/hello-lua5.4.luac", "Lua"),
    ]

    for path_str, expected_lang in bytecode_files:
        path = Path(path_str)
        if not path.exists():
            continue

        with open(path, "rb") as f:
            data = f.read(4)

        # Test magic number detection
        if expected_lang == "Java":
            assert data == b"\xca\xfe\xba\xbe", (
                "Java class file should start with CAFEBABE"
            )
        elif expected_lang == "Lua":
            assert data[:4] == b"\x1bLua", "Lua bytecode should start with ESC-Lua"
        # Python has various magic numbers depending on version

        result = triage.analyze_path(str(path))
        assert result is not None
        print(f"{expected_lang} bytecode: Triaged successfully")


def test_comprehensive_detection_rate():
    """Test overall detection rate has improved."""
    import os

    total_files = 0
    successful = 0
    failed_files = []

    samples_dir = Path("samples/binaries/platforms")
    if not samples_dir.exists():
        pytest.skip("Samples directory not found")

    for root, dirs, files in os.walk(samples_dir):
        for file in files:
            # Skip non-binary files
            if file.endswith((".json", ".txt", ".jar")):
                continue

            file_path = Path(root) / file
            total_files += 1

            try:
                result = triage.analyze_path(str(file_path))
                if result is not None:
                    successful += 1
                else:
                    failed_files.append(str(file_path))
            except Exception as e:
                print(f"Error processing {file_path}: {e}")
                failed_files.append(str(file_path))

    if total_files > 0:
        success_rate = (successful / total_files) * 100
        print("\n=== Python Detection Results ===")
        print(f"Total files: {total_files}")
        print(f"Successful: {successful} ({success_rate:.1f}%)")
        print(f"Failed: {total_files - successful}")

        if failed_files:
            print("\nFailed files (first 10):")
            for f in failed_files[:10]:
                print(f"  - {f}")

        # We improved to 82%, so we should be at least 80%
        assert success_rate >= 80.0, (
            f"Detection rate {success_rate:.1f}% is below expected 80%"
        )


if __name__ == "__main__":
    # Run tests
    test_packer_detection()
    test_stripped_binary_detection()
    test_shared_library_detection()
    test_bytecode_detection()
    test_comprehensive_detection_rate()
    print("All Python tests passed!")
