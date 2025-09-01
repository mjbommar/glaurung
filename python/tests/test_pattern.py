"""Tests for the Pattern type."""

import pytest
from glaurung import (
    Pattern,
    PatternType,
    PatternDefinition,
    YaraMatch,
    MetadataValue,
    Address,
    AddressKind,
)


class TestPatternType:
    """Test the PatternType enum."""

    def test_pattern_type_values(self):
        """Test all PatternType enum values."""
        assert PatternType.Signature
        assert PatternType.Heuristic
        assert PatternType.Yara
        assert PatternType.Behavior
        assert PatternType.Statistical

    def test_pattern_type_display(self):
        """Test string representation of PatternType."""
        assert str(PatternType.Signature) == "Signature"
        assert str(PatternType.Heuristic) == "Heuristic"
        assert str(PatternType.Yara) == "Yara"
        assert str(PatternType.Behavior) == "Behavior"
        assert str(PatternType.Statistical) == "Statistical"


class TestMetadataValue:
    """Test the MetadataValue enum."""

    def test_metadata_value_variants(self):
        """Test all MetadataValue variants."""
        string_val = MetadataValue.String("test")
        int_val = MetadataValue.Integer(42)
        float_val = MetadataValue.Float(3.14)
        bool_val = MetadataValue.Boolean(True)
        array_val = MetadataValue.Array(
            [MetadataValue.String("item1"), MetadataValue.Integer(2)]
        )

        assert str(string_val) == "test"
        assert str(int_val) == "42"
        assert str(float_val) == "3.14"
        assert str(bool_val) == "true"
        assert "item1" in str(array_val)
        assert "2" in str(array_val)


class TestYaraMatch:
    """Test the YaraMatch struct."""

    def test_yara_match_creation(self):
        """Test creating a YaraMatch."""
        yara_match = YaraMatch(0x1000, "$string1")

        assert yara_match.offset == 0x1000
        assert yara_match.identifier == "$string1"
        assert str(yara_match) == "$string1@4096"

    def test_yara_match_with_different_values(self):
        """Test YaraMatch with different values."""
        match1 = YaraMatch(0x2000, "$malware_sig")
        match2 = YaraMatch(0x0, "$header")

        assert match1.offset == 0x2000
        assert match1.identifier == "$malware_sig"
        assert str(match1) == "$malware_sig@8192"

        assert match2.offset == 0x0
        assert match2.identifier == "$header"
        assert str(match2) == "$header@0"


class TestPatternDefinition:
    """Test the PatternDefinition enum."""

    def test_signature_definition(self):
        """Test Signature pattern definition."""
        sig_def = PatternDefinition.Signature("DEADBEEF", "FF00FF00")

        assert str(sig_def.pattern_type) == "Signature"
        desc = str(sig_def)
        assert "DEADBEEF" in desc
        assert "FF00FF00" in desc

    def test_signature_definition_no_mask(self):
        """Test Signature pattern definition without mask."""
        sig_def = PatternDefinition.Signature("DEADBEEF", None)

        assert str(sig_def.pattern_type) == "Signature"
        desc = str(sig_def)
        assert "DEADBEEF" in desc
        assert "mask" not in desc

    def test_yara_definition(self):
        """Test YARA pattern definition."""
        matches = [YaraMatch(0x1000, "$string1"), YaraMatch(0x2000, "$string2")]
        yara_def = PatternDefinition.Yara("malware_rule", matches)

        assert yara_def.pattern_type == PatternType.Yara
        desc = str(yara_def)
        assert "malware_rule" in desc
        assert "2 matches" in desc

    def test_heuristic_definition(self):
        """Test Heuristic pattern definition."""
        conditions = ["condition1", "condition2", "condition3"]
        heur_def = PatternDefinition.Heuristic(conditions)

        assert heur_def.pattern_type == PatternType.Heuristic
        desc = str(heur_def)
        assert "3 conditions" in desc

    def test_behavior_definition_full(self):
        """Test Behavior pattern definition with all fields."""
        api_calls = ["VirtualAlloc", "WriteProcessMemory"]
        sequences = ["push ebp", "mov ebp, esp"]
        beh_def = PatternDefinition.Behavior(api_calls, sequences)

        assert beh_def.pattern_type == PatternType.Behavior
        desc = str(beh_def)
        assert "2 APIs" in desc
        assert "2 sequences" in desc

    def test_behavior_definition_partial(self):
        """Test Behavior pattern definition with partial fields."""
        api_calls = ["VirtualAlloc"]
        beh_def = PatternDefinition.Behavior(api_calls, None)

        assert beh_def.pattern_type == PatternType.Behavior
        desc = str(beh_def)
        assert "1 APIs" in desc
        assert "0 sequences" in desc

    def test_statistical_definition_full(self):
        """Test Statistical pattern definition with all fields."""
        entropy = 7.5
        metrics = {
            "mean": MetadataValue.Float(3.14),
            "count": MetadataValue.Integer(100),
        }
        stat_def = PatternDefinition.Statistical(entropy, metrics)

        assert stat_def.pattern_type == PatternType.Statistical
        desc = str(stat_def)
        assert "7.500" in desc
        assert "2 metrics" in desc

    def test_statistical_definition_partial(self):
        """Test Statistical pattern definition with partial fields."""
        entropy = 6.2
        stat_def = PatternDefinition.Statistical(entropy, None)

        assert stat_def.pattern_type == PatternType.Statistical
        desc = str(stat_def)
        assert "6.200" in desc
        assert "0 metrics" in desc


class TestPatternCreation:
    """Test Pattern creation and basic functionality."""

    def test_pattern_creation_signature_minimal(self):
        """Test creating a minimal Signature pattern."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        pattern_def = PatternDefinition.Signature("DEADBEEF", None)

        pattern = Pattern(
            "sig_1",
            PatternType.Signature,
            "Deadbeef Signature",
            [address],
            0.9,
            pattern_def,
            "A signature for deadbeef pattern",
        )

        assert pattern.id == "sig_1"
        assert str(pattern.pattern_type) == "Signature"
        assert pattern.name == "Deadbeef Signature"
        assert pattern.address_count() == 1
        assert pattern.confidence == 0.9
        assert pattern.description == "A signature for deadbeef pattern"
        assert pattern.references == []
        assert pattern.metadata is None

    def test_pattern_creation_signature_full(self):
        """Test creating a full Signature pattern."""
        address1 = Address(AddressKind.VA, 0x400000, bits=64)
        address2 = Address(AddressKind.VA, 0x401000, bits=64)
        pattern_def = PatternDefinition.Signature("DEADBEEF", "FF00FF00")

        metadata = {
            "author": MetadataValue.String("security_researcher"),
            "version": MetadataValue.Integer(1),
            "severity": MetadataValue.Float(8.5),
        }

        pattern = Pattern(
            "sig_2",
            PatternType.Signature,
            "Advanced Deadbeef Signature",
            [address1, address2],
            0.95,
            pattern_def,
            "An advanced signature for deadbeef pattern",
            ["https://example.com/sig2", "CVE-2023-12345"],
            metadata,
        )

        assert pattern.id == "sig_2"
        assert pattern.address_count() == 2
        assert pattern.confidence == 0.95
        assert len(pattern.references) == 2
        assert pattern.metadata is not None
        assert pattern.has_references()
        assert pattern.has_metadata()

    def test_pattern_creation_yara(self):
        """Test creating a YARA pattern."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        matches = [YaraMatch(0x1000, "$string1"), YaraMatch(0x2000, "$string2")]
        pattern_def = PatternDefinition.Yara("malware_rule", matches)

        pattern = Pattern(
            "yara_1",
            PatternType.Yara,
            "Malware YARA Rule",
            [address],
            0.8,
            pattern_def,
            "YARA rule for malware detection",
        )

        assert str(pattern.pattern_type) == "Yara"
        assert pattern.name == "Malware YARA Rule"
        assert pattern.confidence == 0.8

    def test_pattern_creation_heuristic(self):
        """Test creating a Heuristic pattern."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        conditions = ["contains suspicious API calls", "has high entropy sections"]
        pattern_def = PatternDefinition.Heuristic(conditions)

        pattern = Pattern(
            "heur_1",
            PatternType.Heuristic,
            "Suspicious Behavior Pattern",
            [address],
            0.6,
            pattern_def,
            "Heuristic pattern for suspicious behavior",
        )

        assert str(pattern.pattern_type) == "Heuristic"
        assert pattern.name == "Suspicious Behavior Pattern"
        assert pattern.confidence == 0.6

    def test_pattern_creation_behavior(self):
        """Test creating a Behavior pattern."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        api_calls = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"]
        sequences = ["push ebp", "mov ebp, esp", "sub esp, 0x100"]
        pattern_def = PatternDefinition.Behavior(api_calls, sequences)

        pattern = Pattern(
            "beh_1",
            PatternType.Behavior,
            "Injection Behavior Pattern",
            [address],
            0.85,
            pattern_def,
            "Pattern for code injection behavior",
        )

        assert str(pattern.pattern_type) == "Behavior"
        assert pattern.name == "Injection Behavior Pattern"
        assert pattern.confidence == 0.85

    def test_pattern_creation_statistical(self):
        """Test creating a Statistical pattern."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        entropy = 7.8
        metrics = {
            "mean_entropy": MetadataValue.Float(7.8),
            "std_dev": MetadataValue.Float(1.2),
            "anomaly_score": MetadataValue.Integer(95),
        }
        pattern_def = PatternDefinition.Statistical(entropy, metrics)

        pattern = Pattern(
            "stat_1",
            PatternType.Statistical,
            "High Entropy Anomaly",
            [address],
            0.7,
            pattern_def,
            "Statistical pattern for high entropy anomalies",
        )

        assert str(pattern.pattern_type) == "Statistical"
        assert pattern.name == "High Entropy Anomaly"
        assert pattern.confidence == 0.7


class TestPatternValidation:
    """Test Pattern validation."""

    def test_pattern_confidence_validation(self):
        """Test confidence value validation."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        pattern_def = PatternDefinition.Signature("DEADBEEF", None)

        # Test invalid confidence (too high)
        with pytest.raises(ValueError, match="confidence must be between 0.0 and 1.0"):
            Pattern(
                "test",
                PatternType.Signature,
                "Test",
                [address],
                1.5,
                pattern_def,
                "Test",
            )

        # Test invalid confidence (negative)
        with pytest.raises(ValueError, match="confidence must be between 0.0 and 1.0"):
            Pattern(
                "test",
                PatternType.Signature,
                "Test",
                [address],
                -0.1,
                pattern_def,
                "Test",
            )

    def test_pattern_type_mismatch(self):
        """Test pattern type and definition mismatch validation."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        pattern_def = PatternDefinition.Signature("DEADBEEF", None)

        # Try to create pattern with mismatched type
        with pytest.raises(
            ValueError, match="pattern_type must match pattern_definition type"
        ):
            Pattern(
                "test",
                PatternType.Heuristic,  # Wrong type
                "Test",
                [address],
                0.8,
                pattern_def,  # Signature definition
                "Test",
            )


class TestPatternProperties:
    """Test Pattern properties and methods."""

    def test_pattern_confidence_levels(self):
        """Test confidence level classification."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        pattern_def = PatternDefinition.Signature("DEADBEEF", None)

        high_conf = Pattern(
            "high",
            PatternType.Signature,
            "High Confidence",
            [Address(AddressKind.VA, 0x400000, bits=64)],
            0.9,
            PatternDefinition.Signature("DEADBEEF", None),
            "High confidence pattern",
        )

        medium_conf = Pattern(
            "medium",
            PatternType.Signature,
            "Medium Confidence",
            [Address(AddressKind.VA, 0x400000, bits=64)],
            0.65,
            PatternDefinition.Signature("DEADBEEF", None),
            "Medium confidence pattern",
        )

        low_conf = Pattern(
            "low",
            PatternType.Signature,
            "Low Confidence",
            [Address(AddressKind.VA, 0x400000, bits=64)],
            0.3,
            PatternDefinition.Signature("DEADBEEF", None),
            "Low confidence pattern",
        )

        assert high_conf.is_high_confidence()
        assert high_conf.confidence_level() == "high"

        assert medium_conf.is_medium_confidence()
        assert medium_conf.confidence_level() == "medium"

        assert low_conf.is_low_confidence()
        assert low_conf.confidence_level() == "low"

    def test_pattern_address_operations(self):
        """Test address-related operations."""
        address1 = Address(AddressKind.VA, 0x400000, bits=64)
        address2 = Address(AddressKind.VA, 0x401000, bits=64)
        address3 = Address(AddressKind.VA, 0x402000, bits=64)
        pattern_def = PatternDefinition.Signature("DEADBEEF", None)

        pattern = Pattern(
            "multi_addr",
            PatternType.Signature,
            "Multi-address Pattern",
            [address1, address2, address3],
            0.8,
            pattern_def,
            "Pattern found at multiple addresses",
        )

        assert pattern.address_count() == 3
        assert len(pattern.addresses) == 3

    def test_pattern_summary(self):
        """Test pattern summary generation."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        pattern_def = PatternDefinition.Signature("DEADBEEF", None)

        pattern = Pattern(
            "summary_test",
            PatternType.Signature,
            "Test Pattern",
            [address],
            0.75,
            pattern_def,
            "A test pattern",
        )

        summary = pattern.summary()
        assert "Test Pattern" in summary
        assert "Signature" in summary
        assert "1 locations" in summary
        assert "0.75" in summary

    def test_pattern_display(self):
        """Test pattern string representation."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        pattern_def = PatternDefinition.Signature("DEADBEEF", None)

        pattern = Pattern(
            "display_test",
            PatternType.Signature,
            "Display Test Pattern",
            [address],
            0.8,
            pattern_def,
            "A pattern for display testing",
        )

        display_str = str(pattern)
        assert "Display Test Pattern" in display_str
        assert "Signature" in display_str
        assert "1 addresses" in display_str
        assert "0.80" in display_str

    def test_pattern_with_references(self):
        """Test pattern with references."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        pattern_def = PatternDefinition.Signature("DEADBEEF", None)
        references = ["https://example.com", "CVE-2023-12345", "MITRE ATT&CK T1055"]

        pattern = Pattern(
            "ref_test",
            PatternType.Signature,
            "Referenced Pattern",
            [address],
            0.9,
            pattern_def,
            "Pattern with references",
            references,
            None,
        )

        assert pattern.has_references()
        assert len(pattern.references) == 3
        assert "CVE-2023-12345" in pattern.references

    def test_pattern_with_metadata(self):
        """Test pattern with metadata."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        pattern_def = PatternDefinition.Signature("DEADBEEF", None)

        metadata = {
            "category": MetadataValue.String("malware"),
            "family": MetadataValue.String("trojan"),
            "confidence_score": MetadataValue.Float(0.95),
            "detection_count": MetadataValue.Integer(150),
        }

        pattern = Pattern(
            "meta_test",
            PatternType.Signature,
            "Metadata Pattern",
            [address],
            0.9,
            pattern_def,
            "Pattern with metadata",
            None,
            metadata,
        )

        assert pattern.has_metadata()
        assert pattern.metadata is not None
        # Note: We can't easily test the contents of the metadata dict from Python
        # since it's a Rust HashMap, but we can test that it exists and has_metadata() works


class TestPatternEdgeCases:
    """Test edge cases and special scenarios."""

    def test_pattern_empty_addresses(self):
        """Test pattern with empty address list."""
        pattern_def = PatternDefinition.Signature("DEADBEEF", None)

        # This should work but might not be very useful
        pattern = Pattern(
            "empty_addr",
            PatternType.Signature,
            "Empty Address Pattern",
            [],
            0.5,
            pattern_def,
            "Pattern with no addresses",
        )

        assert pattern.address_count() == 0
        assert len(pattern.addresses) == 0

    def test_pattern_single_address(self):
        """Test pattern with single address."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        pattern_def = PatternDefinition.Signature("DEADBEEF", None)

        pattern = Pattern(
            "single_addr",
            PatternType.Signature,
            "Single Address Pattern",
            [address],
            0.7,
            pattern_def,
            "Pattern with single address",
        )

        assert pattern.address_count() == 1
        assert len(pattern.addresses) == 1

    def test_pattern_boundary_confidence_values(self):
        """Test pattern with boundary confidence values."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        pattern_def = PatternDefinition.Signature("DEADBEEF", None)

        # Test minimum confidence
        min_conf = Pattern(
            "min_conf",
            PatternType.Signature,
            "Minimum Confidence",
            [Address(AddressKind.VA, 0x400000, bits=64)],
            0.0,
            PatternDefinition.Signature("DEADBEEF", None),
            "Minimum confidence pattern",
        )
        assert min_conf.confidence == 0.0
        assert min_conf.is_low_confidence()

        # Test maximum confidence
        max_conf = Pattern(
            "max_conf",
            PatternType.Signature,
            "Maximum Confidence",
            [Address(AddressKind.VA, 0x400000, bits=64)],
            1.0,
            PatternDefinition.Signature("DEADBEEF", None),
            "Maximum confidence pattern",
        )
        assert max_conf.confidence == 1.0
        assert max_conf.is_high_confidence()

    def test_pattern_long_name_and_description(self):
        """Test pattern with long name and description."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        pattern_def = PatternDefinition.Signature("DEADBEEF", None)

        long_name = "A" * 200
        long_description = "B" * 500

        pattern = Pattern(
            "long_fields",
            PatternType.Signature,
            long_name,
            [address],
            0.8,
            pattern_def,
            long_description,
        )

        assert len(pattern.name) == 200
        assert len(pattern.description) == 500
        assert pattern.name == long_name
        assert pattern.description == long_description

    def test_pattern_complex_metadata(self):
        """Test pattern with complex metadata structure."""
        address = Address(AddressKind.VA, 0x400000, bits=64)
        pattern_def = PatternDefinition.Signature("DEADBEEF", None)

        # Create complex metadata with nested structures
        metadata = {
            "analysis": MetadataValue.String("static"),
            "platform": MetadataValue.String("windows"),
            "architecture": MetadataValue.String("x64"),
            "file_size": MetadataValue.Integer(1024000),
            "entropy": MetadataValue.Float(6.78),
            "is_packed": MetadataValue.Boolean(True),
            "tags": MetadataValue.Array(
                [
                    MetadataValue.String("malware"),
                    MetadataValue.String("trojan"),
                    MetadataValue.String("dropper"),
                ]
            ),
        }

        pattern = Pattern(
            "complex_meta",
            PatternType.Signature,
            "Complex Metadata Pattern",
            [address],
            0.85,
            pattern_def,
            "Pattern with complex metadata",
            None,
            metadata,
        )

        assert pattern.has_metadata()
        # The metadata contents are validated in Rust, so we just ensure it was set
