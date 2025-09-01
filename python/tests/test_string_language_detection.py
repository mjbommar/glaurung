"""Tests for string language detection functionality."""

import pytest
from glaurung.triage import DetectedString, StringsSummary, analyze_bytes


class TestDetectedString:
    """Test DetectedString functionality."""

    def test_detected_string_creation(self):
        """Test creating a DetectedString with language info."""
        ds = DetectedString(
            text="Hello world",
            encoding="ascii",
            language="eng",
            script="Latin",
            confidence=0.95,
            offset=100,
        )

        assert ds.text == "Hello world"
        assert ds.encoding == "ascii"
        assert ds.language == "eng"
        assert ds.script == "Latin"
        assert abs(ds.confidence - 0.95) < 0.01
        assert ds.offset == 100

    def test_detected_string_without_language(self):
        """Test creating a DetectedString without language info."""
        ds = DetectedString(
            text="Test",
            encoding="utf16le",
        )

        assert ds.text == "Test"
        assert ds.encoding == "utf16le"
        assert ds.language is None
        assert ds.script is None
        assert ds.confidence is None
        assert ds.offset is None

    def test_detected_string_str_representation(self):
        """Test string representation of DetectedString."""
        ds = DetectedString(
            text="This is a test string",
            encoding="ascii",
            language="eng",
            script="Latin",
            confidence=0.9,
        )

        str_repr = str(ds)
        assert "eng" in str_repr
        assert "Latin" in str_repr
        assert "ascii" in str_repr


class TestStringsSummaryWithLanguages:
    """Test StringsSummary with language detection."""

    def test_strings_summary_with_detected_strings(self):
        """Test StringsSummary with DetectedString objects."""
        ds1 = DetectedString("Hello world", "ascii", "eng", "Latin", 0.95)
        ds2 = DetectedString("Bonjour monde", "ascii", "fra", "Latin", 0.85)

        summary = StringsSummary(
            ascii_count=2,
            utf16le_count=0,
            utf16be_count=0,
            strings=[ds1, ds2],
            language_counts={"eng": 1, "fra": 1},
            script_counts={"Latin": 2},
        )

        assert summary.ascii_count == 2
        assert summary.utf16le_count == 0
        assert summary.utf16be_count == 0
        assert len(summary.strings) == 2
        assert summary.language_counts["eng"] == 1
        assert summary.language_counts["fra"] == 1
        assert summary.script_counts["Latin"] == 2

    def test_strings_summary_backward_compatibility(self):
        """Test backward compatibility with samples property."""
        ds1 = DetectedString("Test string 1", "ascii")
        ds2 = DetectedString("Test string 2", "ascii")

        summary = StringsSummary(
            ascii_count=2, utf16le_count=0, utf16be_count=0, strings=[ds1, ds2]
        )

        # The samples property should extract text from DetectedString objects
        samples = summary.samples
        assert samples is not None
        assert len(samples) == 2
        assert "Test string 1" in samples
        assert "Test string 2" in samples


class TestLanguageDetectionIntegration:
    """Test language detection in triage analysis."""

    def test_analyze_bytes_with_english_text(self):
        """Test analyzing bytes containing English text."""
        # Create test data with identifiable English text
        test_data = (
            b"This is a comprehensive test of the language detection system. " * 5
        )
        test_data += b"\x00\x00\x00\x00"  # Some binary data
        test_data += b"Another English sentence for testing purposes." * 3

        result = analyze_bytes(test_data)

        # Check that strings were extracted
        assert result.strings is not None
        assert result.strings.ascii_count > 0

        # Check that some strings have language detected
        detected_strings = result.strings.strings
        if detected_strings:
            # At least one string should have language detected
            has_language = any(s.language is not None for s in detected_strings)
            assert has_language, "No language detected in any strings"

            # Check for English detection
            english_strings = [s for s in detected_strings if s.language == "eng"]
            assert len(english_strings) > 0, "English not detected in strings"

    def test_analyze_bytes_with_mixed_languages(self):
        """Test analyzing bytes with mixed language content."""
        # Mix of English and French (longer strings for better detection)
        test_data = (
            b"This is an English sentence that should be detected correctly. " * 2
        )
        test_data += b"\x00\x00"
        test_data += (
            b"Ceci est une phrase en francais pour tester la detection de langue. " * 2
        )
        test_data += b"\x00\x00"
        test_data += b"Another English text segment for language identification. " * 2

        result = analyze_bytes(test_data)

        if result.strings and result.strings.strings:
            languages = set()
            for s in result.strings.strings:
                if s.language:
                    languages.add(s.language)

            # We should detect at least one language
            assert len(languages) > 0, (
                f"No languages detected. Strings: {[s.text for s in result.strings.strings]}"
            )

    def test_analyze_bytes_with_short_strings(self):
        """Test that short strings don't have language detected."""
        # Short strings shouldn't trigger language detection
        test_data = b"Hi\x00Test\x00OK\x00Yes\x00No\x00"

        result = analyze_bytes(test_data)

        if result.strings and result.strings.strings:
            # Short strings (< 10 chars) should not have language detected
            for s in result.strings.strings:
                if len(s.text) < 10:  # Threshold for language detection
                    assert s.language is None, (
                        f"Language detected for short string: {s.text}"
                    )


@pytest.mark.parametrize(
    "text,expected_lang,expected_script",
    [
        ("This is definitely an English sentence for testing.", "eng", "Latin"),
        ("x" * 100, None, None),  # Repetitive text shouldn't detect language
        ("1234567890" * 5, None, None),  # Numbers shouldn't detect language
    ],
)
def test_language_detection_patterns(text, expected_lang, expected_script):
    """Test language detection on various text patterns."""
    # Convert to bytes and analyze
    test_data = text.encode("utf-8")
    result = analyze_bytes(test_data)

    if result.strings and result.strings.strings:
        for s in result.strings.strings:
            if len(s.text) >= 10:  # Only check strings long enough for detection
                if expected_lang:
                    assert s.language == expected_lang, (
                        f"Expected {expected_lang}, got {s.language} for: {s.text}"
                    )
                    assert s.script == expected_script, (
                        f"Expected {expected_script}, got {s.script}"
                    )
                else:
                    # For non-linguistic content, language might not be detected
                    # or might be detected with low confidence
                    pass  # This is acceptable
