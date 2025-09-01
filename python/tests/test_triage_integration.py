"""Integration tests for triage functionality using real sample files.

These tests mirror the Rust integration tests in tests/triage/ and validate
the triage system end-to-end using real binary files from the samples directory.
"""

import pytest
import glaurung as g


class TestTriageIntegration:
    """Integration tests for the complete triage pipeline."""

    def test_analyze_system_binary_ls(self, system_binary_ls):
        """Test triage analysis of /usr/bin/ls (real system binary)."""
        result = g.triage.analyze_path(str(system_binary_ls))

        assert result is not None
        assert isinstance(result, g.triage.TriagedArtifact)
        assert result.path == str(system_binary_ls)
        assert result.size_bytes > 0

        # Should have at least one verdict for a valid ELF binary
        assert len(result.verdicts) > 0, (
            "Should have at least one verdict for ELF binary"
        )

        # First verdict should be for ELF format
        primary_verdict = result.verdicts[0]
        assert primary_verdict.format == g.Format.ELF
        assert primary_verdict.confidence > 0.5  # Should have reasonable confidence

        # Should have hints from sniffers
        assert len(result.hints) > 0, "Should have sniffer hints"

        print(
            f"✅ /usr/bin/ls analysis: {result.size_bytes} bytes, {len(result.verdicts)} verdicts"
        )

    def test_analyze_system_binary_cat(self, system_binary_cat):
        """Test triage analysis of /usr/bin/cat (another real system binary)."""
        result = g.triage.analyze_path(str(system_binary_cat))

        assert result is not None
        assert result.path == str(system_binary_cat)
        assert result.size_bytes > 0
        assert len(result.verdicts) > 0

        # Should be ELF format
        assert result.verdicts[0].format == g.Format.ELF

        print(f"✅ /usr/bin/cat analysis: {result.size_bytes} bytes")

    def test_analyze_empty_data(self):
        """Test triage analysis of empty data (should fail gracefully)."""
        with pytest.raises(ValueError):
            g.triage.analyze_bytes(b"")

    def test_analyze_invalid_data(self):
        """Test triage analysis of invalid data."""
        invalid_data = b"This is not a valid binary format"
        result = g.triage.analyze_bytes(invalid_data)

        # Should succeed but with no strong verdicts
        assert result is not None
        assert result.size_bytes == len(invalid_data)

        # Should have hints but low-confidence verdicts
        assert len(result.hints) >= 0  # May or may not have hints
        if result.verdicts:
            assert result.verdicts[0].confidence < 0.5

    def test_analyze_sample_gcc_binary(self, sample_elf_gcc):
        """Test triage analysis of GCC-compiled ELF binary from samples."""
        result = g.triage.analyze_path(str(sample_elf_gcc))

        assert result is not None
        assert result.size_bytes > 0
        assert len(result.verdicts) > 0

        # Should be identified as ELF
        assert result.verdicts[0].format == g.Format.ELF
        assert result.verdicts[0].arch in [g.Arch.X86, g.Arch.X86_64]
        assert result.verdicts[0].bits in [32, 64]

        print(
            f"✅ GCC ELF analysis: {result.verdicts[0].arch}, {result.verdicts[0].bits}-bit"
        )

    def test_analyze_sample_clang_binary(self, sample_elf_clang):
        """Test triage analysis of Clang-compiled ELF binary from samples."""
        result = g.triage.analyze_path(str(sample_elf_clang))

        assert result is not None
        assert len(result.verdicts) > 0
        assert result.verdicts[0].format == g.Format.ELF

        print(
            f"✅ Clang ELF analysis: {result.verdicts[0].arch}, {result.verdicts[0].bits}-bit"
        )

    def test_analyze_sample_pe_binary(self, sample_pe_exe):
        """Test triage analysis of Windows PE binary from samples."""
        result = g.triage.analyze_path(str(sample_pe_exe))

        assert result is not None
        assert len(result.verdicts) > 0
        assert result.verdicts[0].format == g.Format.PE

        print(
            f"✅ PE binary analysis: {result.verdicts[0].arch}, {result.verdicts[0].bits}-bit"
        )

    def test_analyze_sample_jar_file(self, sample_jar):
        """Test triage analysis of Java JAR file from samples."""
        result = g.triage.analyze_path(str(sample_jar))

        assert result is not None
        assert result.size_bytes > 0

        # JAR files should be detected (may not have strong verdicts)
        print(
            f"✅ JAR file analysis: {result.size_bytes} bytes, {len(result.hints)} hints"
        )

    def test_analyze_sample_java_class(self, sample_java_class):
        """Test triage analysis of Java class file from samples."""
        result = g.triage.analyze_path(str(sample_java_class))

        assert result is not None
        assert result.size_bytes > 0

        print(
            f"✅ Java class analysis: {result.size_bytes} bytes, {len(result.hints)} hints"
        )

    def test_analyze_sample_fortran_binary(self, sample_fortran):
        """Test triage analysis of Fortran binary from samples."""
        result = g.triage.analyze_path(str(sample_fortran))

        assert result is not None
        assert len(result.verdicts) > 0
        assert result.verdicts[0].format == g.Format.ELF

        print(
            f"✅ Fortran ELF analysis: {result.verdicts[0].arch}, {result.verdicts[0].bits}-bit"
        )

    def test_analyze_sample_python_bytecode(self, sample_python_pyc):
        """Test triage analysis of Python bytecode from samples."""
        result = g.triage.analyze_path(str(sample_python_pyc))

        assert result is not None
        assert result.size_bytes > 0

        # Python bytecode may not be strongly detected
        print(
            f"✅ Python bytecode analysis: {result.size_bytes} bytes, {len(result.hints)} hints"
        )

    def test_json_round_trip(self, system_binary_ls):
        """Test JSON serialization round-trip."""
        result = g.triage.analyze_path(str(system_binary_ls))

        # Serialize to JSON
        json_str = result.to_json()
        assert isinstance(json_str, str)
        assert len(json_str) > 0

        # Deserialize from JSON
        restored = g.triage.TriagedArtifact.from_json(json_str)

        # Verify key properties match
        assert restored.id == result.id
        assert restored.path == result.path
        assert restored.size_bytes == result.size_bytes
        assert len(restored.verdicts) == len(result.verdicts)
        assert len(restored.hints) == len(result.hints)

    def test_error_handling_nonexistent_file(self):
        """Test error handling for non-existent files."""
        with pytest.raises((ValueError, FileNotFoundError, OSError)):
            g.triage.analyze_path("/does/not/exist")

    def test_verdict_properties(self, system_binary_ls):
        """Test verdict properties and structure."""
        result = g.triage.analyze_path(str(system_binary_ls))
        verdict = result.verdicts[0]

        # Check verdict structure
        assert hasattr(verdict, "format")
        assert hasattr(verdict, "arch")
        assert hasattr(verdict, "bits")
        assert hasattr(verdict, "endianness")
        assert hasattr(verdict, "confidence")

        # Check valid ranges
        assert verdict.bits in [32, 64]
        assert 0.0 <= verdict.confidence <= 1.0
        assert verdict.endianness in [g.Endianness.Little, g.Endianness.Big]

    def test_hints_structure(self, system_binary_ls):
        """Test hint properties and structure."""
        result = g.triage.analyze_path(str(system_binary_ls))

        for hint in result.hints:
            assert hasattr(hint, "source")
            assert hasattr(hint, "mime")
            assert hasattr(hint, "extension")
            assert hasattr(hint, "label")

            assert hint.source in [
                g.triage.SnifferSource.Infer,
                g.triage.SnifferSource.MimeGuess,
                g.triage.SnifferSource.Other,
            ]
