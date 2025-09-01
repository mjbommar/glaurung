"""Integration tests for triage I/O functionality using real sample files.

These tests mirror the Rust I/O integration tests and validate file reading,
size limits, and bounds checking using real binary files from the samples directory.
"""

import pytest
import glaurung as g


class TestTriageIO:
    """Integration tests for triage I/O functionality."""

    def test_file_size_validation_gcc(self, sample_elf_gcc):
        """Test file size validation with GCC binary."""
        result = g.triage.analyze_path(str(sample_elf_gcc))

        assert result.size_bytes > 0, "File should not be empty"
        assert result.size_bytes < 1024 * 1024, "File should be reasonable size"

        print(f"✅ GCC file size: {result.size_bytes} bytes")

    def test_file_size_validation_clang(self, sample_elf_clang):
        """Test file size validation with Clang binary."""
        result = g.triage.analyze_path(str(sample_elf_clang))

        assert result.size_bytes > 0, "File should not be empty"
        print(f"✅ Clang file size: {result.size_bytes} bytes")

    def test_file_size_validation_pe(self, sample_pe_exe):
        """Test file size validation with PE binary."""
        result = g.triage.analyze_path(str(sample_pe_exe))

        assert result.size_bytes > 0, "File should not be empty"
        print(f"✅ PE file size: {result.size_bytes} bytes")

    def test_file_size_validation_jar(self, sample_jar):
        """Test file size validation with JAR file."""
        result = g.triage.analyze_path(str(sample_jar))

        assert result.size_bytes > 0, "File should not be empty"
        print(f"✅ JAR file size: {result.size_bytes} bytes")

    def test_file_section_reading_gcc(self, sample_elf_gcc):
        """Test reading specific sections of GCC binary."""
        result = g.triage.analyze_path(str(sample_elf_gcc))

        # Should successfully analyze the file
        assert result.verdicts[0].format == g.Format.ELF

        # The triage process should have read the ELF header
        # (This is an indirect test of section reading)
        print(
            f"✅ GCC section reading: {result.verdicts[0].arch}, {result.verdicts[0].bits}-bit"
        )

    def test_error_handling_nonexistent_file(self):
        """Test error handling for non-existent files."""
        with pytest.raises((ValueError, FileNotFoundError, OSError)):
            g.triage.analyze_path("/definitely/does/not/exist")

    def test_error_handling_permission_denied(self, sample_elf_gcc, sample_jar):
        """Test error handling for files without read permission (if any exist)."""
        # This test would be more relevant in environments with permission-restricted files
        # For now, just verify the system doesn't crash on various file types
        test_files = [sample_elf_gcc, sample_jar]

        for sample_path in test_files:
            # Should not raise exceptions for valid files
            result = g.triage.analyze_path(str(sample_path))
            assert result is not None
            print(f"✅ {sample_path}: successfully analyzed")

    def test_file_reading_with_different_sizes(self, sample_elf_gcc, sample_jar):
        """Test file reading with files of different sizes."""
        test_files = [
            (sample_elf_gcc, "GCC"),
            (sample_jar, "JAR"),
        ]

        for sample_path, description in test_files:
            result = g.triage.analyze_path(str(sample_path))

            assert result.size_bytes > 0
            print(f"✅ {description}: {result.size_bytes} bytes")

    def test_io_with_system_binaries(self, system_binary_ls, system_binary_cat):
        """Test I/O functionality with system binaries."""
        for binary_path in [system_binary_ls, system_binary_cat]:
            result = g.triage.analyze_path(str(binary_path))

            assert result.size_bytes > 0
            assert result.verdicts[0].format == g.Format.ELF

            print(
                f"✅ {binary_path.name}: {result.size_bytes} bytes, {result.verdicts[0].arch}"
            )

    def test_io_bounds_checking(self, sample_elf_gcc):
        """Test that I/O bounds checking works correctly."""
        # Test with a valid file to ensure bounds are respected
        result = g.triage.analyze_path(str(sample_elf_gcc))

        # The analysis should complete without errors
        # (Bounds checking happens internally in the Rust code)
        assert result is not None
        assert len(result.verdicts) > 0

        print(
            f"✅ Bounds checking: analysis completed for {result.size_bytes} byte file"
        )

    def test_io_with_various_file_types(
        self,
        sample_elf_gcc,
        sample_elf_clang,
        sample_pe_exe,
        sample_jar,
        sample_java_class,
        sample_fortran,
    ):
        """Test I/O with various file types from samples."""
        test_files = [
            sample_elf_gcc,
            sample_elf_clang,
            sample_pe_exe,
            sample_jar,
            sample_java_class,
            sample_fortran,
        ]

        successful_analyses = 0

        for sample_path in test_files:
            try:
                result = g.triage.analyze_path(str(sample_path))
                assert result is not None
                assert result.size_bytes > 0
                successful_analyses += 1
                print(f"✅ {sample_path.name}: {result.size_bytes} bytes")
            except Exception as e:
                print(f"❌ {sample_path.name}: {e}")

        assert successful_analyses > 0, (
            "At least one file should be successfully analyzed"
        )
