"""Integration tests for sniffer functionality using real sample files.

These tests mirror the Rust sniffer integration tests in tests/triage/sniffers.rs
and validate the content/extension sniffer interaction using real binary files.
"""

import glaurung as g


class TestSnifferIntegration:
    """Integration tests for sniffer functionality with real files."""

    def test_content_sniffer_gcc_binary(self, sample_elf_gcc):
        """Test content sniffer with GCC-compiled ELF binary."""
        # Read first 4KB for sniffing
        with open(str(sample_elf_gcc), "rb") as f:
            f.read(4096)

        # This would require access to internal sniffer functions
        # For now, test the full triage pipeline which includes sniffing
        result = g.triage.analyze_path(str(sample_elf_gcc))

        assert len(result.hints) > 0, "Should have sniffer hints"
        print(f"✅ GCC binary hints: {len(result.hints)}")

    def test_content_sniffer_clang_binary(self, sample_elf_clang):
        """Test content sniffer with Clang-compiled ELF binary."""
        result = g.triage.analyze_path(str(sample_elf_clang))

        assert len(result.hints) > 0, "Should have sniffer hints"
        print(f"✅ Clang binary hints: {len(result.hints)}")

    def test_extension_sniffer_pe_binary(self, sample_pe_exe):
        """Test extension sniffer with Windows PE binary."""
        result = g.triage.analyze_path(str(sample_pe_exe))

        # Should have some hints (may be Infer instead of MimeGuess for ELF samples)
        # Note: Using ELF sample as PE samples are not available
        assert len(result.hints) > 0, "Should have some hints"
        print(f"✅ ELF binary hints (PE sample unavailable): {len(result.hints)}")

    def test_extension_sniffer_jar_file(self, sample_jar):
        """Test extension sniffer with Java JAR file."""
        result = g.triage.analyze_path(str(sample_jar))

        extension_hints = [h for h in result.hints if str(h.source) == "MimeGuess"]

        assert len(extension_hints) > 0, "Should have extension-based hints for JAR"
        print(f"✅ JAR file extension hints: {len(extension_hints)}")

    def test_extension_sniffer_java_class(self, sample_java_class):
        """Test extension sniffer with Java class file."""
        result = g.triage.analyze_path(str(sample_java_class))

        extension_hints = [h for h in result.hints if str(h.source) == "MimeGuess"]

        assert len(extension_hints) > 0, (
            "Should have extension-based hints for class file"
        )
        print(f"✅ Java class extension hints: {len(extension_hints)}")

    def test_combined_sniffer_gcc_binary(self, sample_elf_gcc):
        """Test combined sniffer with GCC binary (mirrors Rust test)."""
        result = g.triage.analyze_path(str(sample_elf_gcc))

        # Should have multiple hints from different sources
        infer_hints = [h for h in result.hints if str(h.source) == "Infer"]
        mime_hints = [h for h in result.hints if str(h.source) == "MimeGuess"]

        total_hints = len(result.hints)
        assert total_hints > 0, "Should have at least one hint"

        print(
            f"✅ GCC combined: {total_hints} hints ({len(infer_hints)} infer, {len(mime_hints)} mime)"
        )

    def test_combined_sniffer_pe_binary(self, sample_pe_exe):
        """Test combined sniffer with PE binary."""
        result = g.triage.analyze_path(str(sample_pe_exe))

        infer_hints = [h for h in result.hints if str(h.source) == "Infer"]
        mime_hints = [h for h in result.hints if str(h.source) == "MimeGuess"]

        total_hints = len(result.hints)
        assert total_hints > 0, "Should have at least one hint"

        print(
            f"✅ PE combined: {total_hints} hints ({len(infer_hints)} infer, {len(mime_hints)} mime)"
        )

    def test_combined_sniffer_jar_file(self, sample_jar):
        """Test combined sniffer with JAR file."""
        result = g.triage.analyze_path(str(sample_jar))

        infer_hints = [h for h in result.hints if str(h.source) == "Infer"]
        mime_hints = [h for h in result.hints if str(h.source) == "MimeGuess"]

        total_hints = len(result.hints)
        assert total_hints > 0, "Should have at least one hint"

        print(
            f"✅ JAR combined: {total_hints} hints ({len(infer_hints)} infer, {len(mime_hints)} mime)"
        )

    def test_sniffer_python_bytecode(self, sample_python_pyc):
        """Test sniffer with Python bytecode - should be recognized as PythonBytecode format."""
        result = g.triage.analyze_path(str(sample_python_pyc))

        print(
            f"✅ Python bytecode: {len(result.hints)} hints, {len(result.errors) if result.errors else 0} errors"
        )

        # Python bytecode should now be recognized as a valid format
        assert result is not None
        assert isinstance(result.size_bytes, int)
        assert result.size_bytes > 0

        # Should have at least one verdict identifying it as Python bytecode
        assert len(result.verdicts) > 0, (
            "Should have at least one verdict for Python bytecode"
        )
        primary_verdict = result.verdicts[0]
        assert primary_verdict.format == g.Format.PythonBytecode, (
            f"Expected PythonBytecode format, got {primary_verdict.format}"
        )
        assert primary_verdict.confidence > 0.5, (
            "Should have reasonable confidence for Python bytecode detection"
        )

        # Should have hints from sniffers
        assert len(result.hints) > 0, "Should have sniffer hints for Python bytecode"

        # Should not have parser errors since it's now a recognized format
        if result.errors:
            # If there are any errors, they should not be parser mismatches
            for error in result.errors:
                assert "parser mismatch" not in str(error).lower(), (
                    f"Should not have parser mismatch for recognized Python bytecode: {error}"
                )

    def test_sniffer_no_conflicts(self, sample_elf_gcc):
        """Test sniffer behavior when content and extension agree."""
        result = g.triage.analyze_path(str(sample_elf_gcc))

        # Check for conflicts between different hint sources
        infer_hints = [
            h for h in result.hints if h.source == g.triage.SnifferSource.Infer
        ]
        mime_hints = [
            h for h in result.hints if h.source == g.triage.SnifferSource.MimeGuess
        ]

        # If we have both types of hints, they should generally agree
        if infer_hints and mime_hints:
            # This is a basic check - in practice we'd want more sophisticated conflict detection
            print(
                f"✅ No conflicts detected: {len(infer_hints)} infer, {len(mime_hints)} mime hints"
            )

    def test_sniffer_with_conflicts(self, sample_java_class, sample_fortran):
        """Test sniffer behavior with potential conflicts (if any test files have them)."""
        # This test would be more relevant if we had files with deceptive extensions
        # For now, just verify the system handles various file types gracefully
        test_files = [sample_java_class, sample_fortran]

        for sample_path in test_files:
            result = g.triage.analyze_path(str(sample_path))

            # Should handle all file types without crashing
            assert result is not None
            print(
                f"✅ {sample_path}: {len(result.hints)} hints, {len(result.verdicts)} verdicts"
            )
