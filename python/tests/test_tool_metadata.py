import pytest
from glaurung import ToolMetadata, SourceKind


class TestToolMetadataCreation:
    """Test ToolMetadata creation and validation."""

    def test_create_basic_tool_metadata(self):
        """Test creating a basic tool metadata."""
        metadata = ToolMetadata("disasm.capstone", "5.0.1")
        assert metadata.name == "disasm.capstone"
        assert metadata.version == "5.0.1"
        assert metadata.parameters is None
        assert metadata.source_kind is None
        assert metadata.is_valid()

    def test_create_tool_metadata_with_source_kind(self):
        """Test creating tool metadata with source kind."""
        metadata = ToolMetadata("loader.lief", "0.14.0", source_kind=SourceKind.Static)
        assert metadata.name == "loader.lief"
        assert metadata.version == "0.14.0"
        assert metadata.source_kind == SourceKind.Static

    def test_create_tool_metadata_with_parameters(self):
        """Test creating tool metadata with parameters."""
        params = {"arch": "x86_64", "syntax": "intel"}
        metadata = ToolMetadata("disasm.capstone", "5.0.1", parameters=params)
        assert metadata.name == "disasm.capstone"
        assert metadata.version == "5.0.1"
        assert metadata.parameters == params
        assert metadata.parameter_count() == 2

    def test_create_tool_metadata_full(self):
        """Test creating tool metadata with all fields."""
        params = {"arch": "x86_64", "mode": "64"}
        metadata = ToolMetadata(
            "disasm.capstone", "5.0.1", parameters=params, source_kind=SourceKind.Static
        )
        assert metadata.name == "disasm.capstone"
        assert metadata.version == "5.0.1"
        assert metadata.parameters == params
        assert metadata.source_kind == SourceKind.Static
        assert metadata.is_valid()

    def test_invalid_empty_name(self):
        """Test that empty name is rejected."""
        with pytest.raises(ValueError, match="Tool name cannot be empty"):
            ToolMetadata("", "1.0.0")

    def test_invalid_empty_version(self):
        """Test that empty version is rejected."""
        with pytest.raises(ValueError, match="Tool version cannot be empty"):
            ToolMetadata("test.tool", "")

    def test_invalid_whitespace_name(self):
        """Test that whitespace-only name is rejected."""
        with pytest.raises(ValueError, match="Tool name cannot be empty"):
            ToolMetadata("   ", "1.0.0")

    def test_invalid_whitespace_version(self):
        """Test that whitespace-only version is rejected."""
        with pytest.raises(ValueError, match="Tool version cannot be empty"):
            ToolMetadata("test.tool", "   ")


class TestToolMetadataParameters:
    """Test ToolMetadata parameter operations."""

    def test_parameter_operations(self):
        """Test parameter getter/setter operations."""
        metadata = ToolMetadata("test.tool", "1.0.0")

        # Initially no parameters
        assert not metadata.has_parameters()
        assert metadata.parameter_count() == 0
        assert metadata.get_parameter("arch") is None

        # Set parameters via method
        params = {"arch": "x86_64", "syntax": "intel"}
        metadata.set_parameters_py(params)

        assert metadata.has_parameters()
        assert metadata.parameter_count() == 2
        assert metadata.get_parameter("arch") == "x86_64"
        assert metadata.get_parameter("syntax") == "intel"
        assert metadata.get_parameter("nonexistent") is None

    def test_parameter_modification(self):
        """Test modifying parameters after creation."""
        metadata = ToolMetadata("test.tool", "1.0.0")

        # Add parameters individually
        metadata.set_parameter("arch", "x86_64")
        metadata.set_parameter("syntax", "intel")

        assert metadata.parameter_count() == 2
        assert metadata.get_parameter("arch") == "x86_64"

        # Remove parameter
        removed = metadata.remove_parameter("arch")
        assert removed == "x86_64"
        assert metadata.parameter_count() == 1
        assert metadata.get_parameter("arch") is None

        # Remove non-existent parameter
        removed = metadata.remove_parameter("nonexistent")
        assert removed is None


class TestToolMetadataSourceKind:
    """Test ToolMetadata source kind operations."""

    def test_source_kind_modification(self):
        """Test modifying source kind after creation."""
        metadata = ToolMetadata("test.tool", "1.0.0")

        # Initially no source kind
        assert metadata.source_kind is None

        # Set source kind
        metadata.set_source_kind_py(SourceKind.Dynamic)
        assert metadata.source_kind == SourceKind.Dynamic

        # Change source kind
        metadata.set_source_kind_py(SourceKind.Heuristic)
        assert metadata.source_kind == SourceKind.Heuristic

        # Clear source kind
        metadata.source_kind = None
        assert metadata.source_kind is None


class TestToolMetadataRepresentation:
    """Test ToolMetadata string representations."""

    def test_str_representation_basic(self):
        """Test string representation of basic tool metadata."""
        metadata = ToolMetadata("disasm.capstone", "5.0.1")
        assert str(metadata) == "disasm.capstone@5.0.1"

    def test_str_representation_with_source_kind(self):
        """Test string representation with source kind."""
        metadata = ToolMetadata("loader.lief", "0.14.0", source_kind=SourceKind.Static)
        assert str(metadata) == "loader.lief@0.14.0 (Static)"

    def test_repr_representation(self):
        """Test repr representation of tool metadata."""
        metadata = ToolMetadata("test.tool", "1.0.0")
        repr_str = repr(metadata)
        assert "ToolMetadata" in repr_str
        assert "test.tool" in repr_str
        assert "1.0.0" in repr_str

    def test_repr_with_parameters(self):
        """Test repr representation with parameters."""
        params = {"arch": "x86_64"}
        metadata = ToolMetadata("test.tool", "1.0.0", parameters=params)
        repr_str = repr(metadata)
        assert "parameters=" in repr_str

    def test_repr_with_source_kind(self):
        """Test repr representation with source kind."""
        metadata = ToolMetadata("test.tool", "1.0.0", source_kind=SourceKind.Dynamic)
        repr_str = repr(metadata)
        assert "source_kind=" in repr_str


class TestSourceKind:
    """Test SourceKind enum."""

    def test_source_kind_str(self):
        """Test string representation of SourceKind."""
        assert str(SourceKind.Static) == "Static"
        assert str(SourceKind.Dynamic) == "Dynamic"
        assert str(SourceKind.Heuristic) == "Heuristic"
        assert str(SourceKind.External) == "External"

    def test_source_kind_repr(self):
        """Test repr representation of SourceKind."""
        assert repr(SourceKind.Static) == "SourceKind.Static"
        assert repr(SourceKind.Dynamic) == "SourceKind.Dynamic"
        assert repr(SourceKind.Heuristic) == "SourceKind.Heuristic"
        assert repr(SourceKind.External) == "SourceKind.External"


class TestToolMetadataSerialization:
    """Test ToolMetadata serialization features."""

    def test_json_serialization_basic(self):
        """Test JSON serialization of basic tool metadata."""
        metadata = ToolMetadata("disasm.capstone", "5.0.1")
        json_str = metadata.to_json()
        assert isinstance(json_str, str)

        # Deserialize
        restored = ToolMetadata.from_json(json_str)
        assert restored.name == metadata.name
        assert restored.version == metadata.version
        assert restored.parameters == metadata.parameters
        assert restored.source_kind == metadata.source_kind

    def test_json_serialization_full(self):
        """Test JSON serialization with all fields."""
        params = {"arch": "x86_64", "syntax": "intel"}
        metadata = ToolMetadata(
            "disasm.capstone", "5.0.1", parameters=params, source_kind=SourceKind.Static
        )

        json_str = metadata.to_json()
        restored = ToolMetadata.from_json(json_str)

        assert restored == metadata
        assert restored.name == "disasm.capstone"
        assert restored.version == "5.0.1"
        assert restored.parameters == params
        assert restored.source_kind == SourceKind.Static

    def test_binary_serialization(self):
        """Test binary serialization and deserialization."""
        params = {"arch": "x86_64"}
        metadata = ToolMetadata(
            "disasm.capstone", "5.0.1", parameters=params, source_kind=SourceKind.Static
        )

        binary_data = metadata.to_binary()
        assert isinstance(binary_data, bytes)

        # Deserialize
        restored = ToolMetadata.from_binary(binary_data)
        assert restored == metadata

    def test_serialization_round_trip(self):
        """Test that serialization preserves all data."""
        test_cases = [
            ToolMetadata("basic.tool", "1.0.0"),
            ToolMetadata("tool.with.kind", "2.0.0", source_kind=SourceKind.Dynamic),
            ToolMetadata("tool.with.params", "3.0.0", parameters={"key": "value"}),
            ToolMetadata(
                "full.tool",
                "4.0.0",
                parameters={"arch": "x86_64", "mode": "64"},
                source_kind=SourceKind.Heuristic,
            ),
        ]

        for metadata in test_cases:
            # JSON round trip
            json_str = metadata.to_json()
            json_restored = ToolMetadata.from_json(json_str)
            assert json_restored == metadata

            # Binary round trip
            binary_data = metadata.to_binary()
            binary_restored = ToolMetadata.from_binary(binary_data)
            assert binary_restored == metadata


class TestToolMetadataValidation:
    """Test ToolMetadata validation."""

    def test_valid_metadata(self):
        """Test that valid metadata passes validation."""
        test_cases = [
            ToolMetadata("disasm.capstone", "5.0.1"),
            ToolMetadata("loader.lief", "0.14.0", source_kind=SourceKind.Static),
            ToolMetadata("analyzer.yara", "4.2.0", parameters={"rules": "malware.yar"}),
            ToolMetadata(
                "tracer.dynamic",
                "1.0.0-beta",
                parameters={"timeout": "30", "depth": "10"},
                source_kind=SourceKind.Dynamic,
            ),
        ]

        for metadata in test_cases:
            assert metadata.is_valid(), f"Metadata should be valid: {metadata}"

    def test_constructor_validation(self):
        """Test that the constructor properly validates inputs."""
        # This is already tested in other test methods
        # The constructor prevents creating invalid metadata
        pass


class TestToolMetadataEdgeCases:
    """Test ToolMetadata edge cases."""

    def test_git_sha_version(self):
        """Test using git SHA as version."""
        sha = "a1b2c3d4e5f6789012345678901234567890abcd"
        metadata = ToolMetadata("disasm.capstone", sha)
        assert metadata.version == sha
        assert metadata.is_valid()

    def test_semantic_version(self):
        """Test semantic versioning."""
        versions = ["1.0.0", "2.1.3", "0.1.0-alpha", "3.0.0-rc.1"]
        for version in versions:
            metadata = ToolMetadata("test.tool", version)
            assert metadata.version == version
            assert metadata.is_valid()

    def test_complex_tool_names(self):
        """Test complex tool names."""
        names = [
            "disasm.capstone",
            "loader.lief",
            "analyzer.yara",
            "tracer.dynamic",
            "identify.magic",
            "unpack.upx",
        ]
        for name in names:
            metadata = ToolMetadata(name, "1.0.0")
            assert metadata.name == name
            assert metadata.is_valid()

    def test_empty_parameters_dict(self):
        """Test empty parameters dictionary."""
        metadata = ToolMetadata("test.tool", "1.0.0", parameters={})
        assert not metadata.has_parameters()
        assert metadata.parameter_count() == 0
        assert metadata.is_valid()

    def test_parameter_modification_preserves_validation(self):
        """Test that parameter modifications preserve validation."""
        metadata = ToolMetadata("test.tool", "1.0.0")

        # Add valid parameters
        metadata.set_parameter("key1", "value1")
        metadata.set_parameter("key2", "value2")
        assert metadata.is_valid()

        # Try to add invalid parameter (empty key) - should work at runtime
        # (validation is only at construction time for parameters)
        metadata.set_parameter("", "value")
        # Note: This doesn't fail at runtime, only at construction
        assert metadata.parameter_count() == 3
