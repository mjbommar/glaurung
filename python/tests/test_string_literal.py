"""Tests for the StringLiteral type."""

import pytest
from glaurung import (
    StringLiteral, StringEncoding, StringClassification,
    Address, AddressKind
)


class TestStringEncoding:
    """Test the StringEncoding enum."""

    def test_string_encoding_values(self):
        """Test all StringEncoding enum values."""
        assert StringEncoding.Ascii
        assert StringEncoding.Utf8
        assert StringEncoding.Utf16
        assert StringEncoding.Utf32
        assert StringEncoding.Unknown
        assert StringEncoding.Base64

    def test_string_encoding_display(self):
        """Test string representation of encodings."""
        assert str(StringEncoding.Ascii) == "Ascii"
        assert str(StringEncoding.Utf8) == "Utf8"
        assert str(StringEncoding.Utf16) == "Utf16"
        assert str(StringEncoding.Utf32) == "Utf32"
        assert str(StringEncoding.Unknown) == "Unknown"
        assert str(StringEncoding.Base64) == "Base64"


class TestStringClassification:
    """Test the StringClassification enum."""

    def test_string_classification_values(self):
        """Test all StringClassification enum values."""
        assert StringClassification.Url
        assert StringClassification.Path
        assert StringClassification.Email
        assert StringClassification.Key
        assert StringClassification.Other

    def test_string_classification_display(self):
        """Test string representation of classifications."""
        assert str(StringClassification.Url) == "Url"
        assert str(StringClassification.Path) == "Path"
        assert str(StringClassification.Email) == "Email"
        assert str(StringClassification.Key) == "Key"
        assert str(StringClassification.Other) == "Other"


class TestStringLiteralCreation:
    """Test StringLiteral creation and basic functionality."""

    def test_string_literal_creation_minimal(self):
        """Test creating a minimal StringLiteral."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        string_lit = StringLiteral(
            "str_1",
            address,
            "Hello World",
            StringEncoding.Ascii,
            11
        )

        assert string_lit.id == "str_1"
        assert string_lit.value == "Hello World"
        assert str(string_lit.encoding) == "Ascii"
        assert string_lit.length_bytes == 11
        assert string_lit.raw_bytes is None
        assert string_lit.referenced_by is None
        assert string_lit.language_hint is None
        assert string_lit.classification is None
        assert string_lit.entropy is None

    def test_string_literal_creation_full(self):
        """Test creating a StringLiteral with all fields."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        raw_bytes = b"Hello World"
        referenced_by = [Address(AddressKind.VA, 0x401000, bits=64)]

        string_lit = StringLiteral(
            "str_2",
            address,
            "Hello World",
            StringEncoding.Utf8,
            11,
            raw_bytes=raw_bytes,
            referenced_by=referenced_by,
            language_hint="en",
            classification=StringClassification.Other,
            entropy=3.5
        )

        assert string_lit.id == "str_2"
        assert string_lit.value == "Hello World"
        assert str(string_lit.encoding) == "Utf8"
        assert string_lit.length_bytes == 11
        assert string_lit.raw_bytes == raw_bytes
        assert len(string_lit.referenced_by) == 1
        assert string_lit.language_hint == "en"
        assert str(string_lit.classification) == "Other"
        assert string_lit.entropy == 3.5

    def test_string_literal_with_different_encodings(self):
        """Test StringLiteral with different encodings."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        # Test UTF-16
        utf16_string = StringLiteral(
            "str_utf16",
            address,
            "Hello",
            StringEncoding.Utf16,
            10  # 5 chars * 2 bytes
        )
        assert str(utf16_string.encoding) == "Utf16"

        # Test Base64
        b64_string = StringLiteral(
            "str_b64",
            address,
            "SGVsbG8=",
            StringEncoding.Base64,
            8
        )
        assert str(b64_string.encoding) == "Base64"


class TestStringLiteralProperties:
    """Test StringLiteral properties and methods."""

    def test_string_literal_len(self):
        """Test string length calculation."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        empty_string = StringLiteral("empty", address, "", StringEncoding.Ascii, 0)
        assert empty_string.len() == 0
        assert empty_string.is_empty()

        normal_string = StringLiteral("normal", address, "Hello", StringEncoding.Ascii, 5)
        assert normal_string.len() == 5
        assert not normal_string.is_empty()

    def test_string_literal_classification_methods(self):
        """Test classification checking methods."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        url_string = StringLiteral(
            "url",
            address,
            "http://example.com",
            StringEncoding.Ascii,
            18,
            classification=StringClassification.Url
        )

        path_string = StringLiteral(
            "path",
            address,
            "/usr/bin/ls",
            StringEncoding.Ascii,
            11,
            classification=StringClassification.Path
        )

        email_string = StringLiteral(
            "email",
            address,
            "user@example.com",
            StringEncoding.Ascii,
            15,
            classification=StringClassification.Email
        )

        key_string = StringLiteral(
            "key",
            address,
            "secret_key_123",
            StringEncoding.Ascii,
            13,
            classification=StringClassification.Key
        )

        other_string = StringLiteral(
            "other",
            address,
            "some string",
            StringEncoding.Ascii,
            11,
            classification=StringClassification.Other
        )

        # Test positive cases
        assert url_string.is_url()
        assert path_string.is_path()
        assert email_string.is_email()
        assert key_string.is_key()

        # Test negative cases
        assert not url_string.is_path()
        assert not path_string.is_url()
        assert not email_string.is_key()
        assert not key_string.is_email()

        # Test None classification
        no_class_string = StringLiteral("no_class", address, "test", StringEncoding.Ascii, 4)
        assert not no_class_string.is_url()
        assert not no_class_string.is_path()
        assert not no_class_string.is_email()
        assert not no_class_string.is_key()

    def test_string_literal_description(self):
        """Test string description generation."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        simple_string = StringLiteral(
            "simple",
            address,
            "Hello",
            StringEncoding.Ascii,
            5
        )
        desc = simple_string.description()
        assert "Hello" in desc
        assert "Ascii" in desc
        assert "5 bytes" in desc

        classified_string = StringLiteral(
            "classified",
            address,
            "http://test.com",
            StringEncoding.Utf8,
            15,
            classification=StringClassification.Url
        )
        desc = classified_string.description()
        assert "http://test.com" in desc
        assert "Url" in desc
        assert "Utf8" in desc

    def test_string_literal_display(self):
        """Test string representation."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        string_lit = StringLiteral(
            "test_id",
            address,
            "Test String",
            StringEncoding.Ascii,
            11
        )

        assert str(string_lit) == "String 'Test String' (test_id)"


class TestStringLiteralEdgeCases:
    """Test edge cases and error conditions."""

    def test_string_literal_empty_string(self):
        """Test StringLiteral with empty string."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        empty = StringLiteral("empty", address, "", StringEncoding.Ascii, 0)
        assert empty.value == ""
        assert empty.len() == 0
        assert empty.is_empty()

    def test_string_literal_unicode_content(self):
        """Test StringLiteral with Unicode content."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        unicode_string = StringLiteral(
            "unicode",
            address,
            "Hello 世界 🌍",
            StringEncoding.Utf8,
            18  # Approximate byte length
        )

        assert unicode_string.value == "Hello 世界 🌍"
        assert str(unicode_string.encoding) == "Utf8"

    def test_string_literal_with_raw_bytes(self):
        """Test StringLiteral with raw byte data."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        raw_data = b"\x00\x01\x02\x03Hello\x04\x05"

        string_lit = StringLiteral(
            "with_bytes",
            address,
            "Hello",
            StringEncoding.Ascii,
            5,
            raw_bytes=raw_data
        )

        assert string_lit.raw_bytes == raw_data
        assert string_lit.value == "Hello"

    def test_string_literal_with_references(self):
        """Test StringLiteral with reference addresses."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        ref1 = Address(AddressKind.VA, 0x401000, bits=64)
        ref2 = Address(AddressKind.VA, 0x402000, bits=64)

        string_lit = StringLiteral(
            "with_refs",
            address,
            "Referenced String",
            StringEncoding.Ascii,
            16,
            referenced_by=[ref1, ref2]
        )

        assert len(string_lit.referenced_by) == 2
        assert string_lit.referenced_by[0].value == 0x401000
        assert string_lit.referenced_by[1].value == 0x402000

    def test_string_literal_large_entropy(self):
        """Test StringLiteral with high entropy value."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        high_entropy = StringLiteral(
            "high_entropy",
            address,
            "random_data_12345",
            StringEncoding.Ascii,
            17,
            entropy=7.8
        )

        assert high_entropy.entropy == 7.8