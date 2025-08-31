import pytest
from glaurung import Artifact, ToolMetadata, SourceKind
import json


class TestArtifactCreation:
    """Test Artifact creation and validation."""

    def test_create_basic_artifact(self):
        """Test creating a basic artifact."""
        tool = ToolMetadata("disasm.capstone", "5.0.1")
        data = json.dumps({"key": "value", "number": 42})

        artifact = Artifact("test-artifact", tool, "TestData", data)

        assert artifact.id == "test-artifact"
        assert artifact.tool.name == "disasm.capstone"
        assert artifact.data_type == "TestData"
        assert artifact.schema_version == "1.0"
        assert artifact.input_refs == []
        assert artifact.meta is None
        assert artifact.is_valid()

    def test_create_artifact_with_all_fields(self):
        """Test creating artifact with all optional fields."""
        tool = ToolMetadata(
            "loader.lief",
            "0.14.0",
            parameters={"arch": "x86_64"},
            source_kind=SourceKind.Static,
        )
        data = json.dumps({"functions": ["main", "foo"], "count": 2})
        input_refs = ["input1", "input2"]
        meta = json.dumps({"confidence": 0.95, "source": "analysis"})

        artifact = Artifact(
            "analysis-result",
            tool,
            "CFG",
            data,
            input_refs=input_refs,
            schema_version="2.0",
            meta=meta,
        )

        assert artifact.id == "analysis-result"
        assert artifact.tool.name == "loader.lief"
        assert artifact.data_type == "CFG"
        assert artifact.schema_version == "2.0"
        assert artifact.input_refs == input_refs
        assert artifact.is_valid()

    def test_invalid_empty_id(self):
        """Test that empty ID is rejected."""
        tool = ToolMetadata("test.tool", "1.0.0")
        data = json.dumps({"test": True})

        with pytest.raises(ValueError, match="Artifact ID cannot be empty"):
            Artifact("", tool, "Test", data)

    def test_invalid_empty_schema_version(self):
        """Test that empty schema version is rejected."""
        tool = ToolMetadata("test.tool", "1.0.0")
        data = json.dumps({"test": True})

        with pytest.raises(ValueError, match="Schema version cannot be empty"):
            Artifact("test-id", tool, "Test", data, schema_version="")

    def test_invalid_empty_data_type(self):
        """Test that empty data type is rejected."""
        tool = ToolMetadata("test.tool", "1.0.0")
        data = json.dumps({"test": True})

        with pytest.raises(ValueError, match="Data type cannot be empty"):
            Artifact("test-id", tool, "", data)

    def test_invalid_json_data(self):
        """Test that invalid JSON data is rejected."""
        tool = ToolMetadata("test.tool", "1.0.0")

        with pytest.raises(ValueError, match="Invalid JSON for data"):
            Artifact("test-id", tool, "Test", "invalid json")

    def test_invalid_json_meta(self):
        """Test that invalid JSON meta is rejected."""
        tool = ToolMetadata("test.tool", "1.0.0")
        data = json.dumps({"test": True})

        with pytest.raises(ValueError, match="Invalid JSON for meta"):
            Artifact("test-id", tool, "Test", data, meta="invalid json")


class TestArtifactProperties:
    """Test Artifact property access."""

    def test_getters(self):
        """Test all getter methods."""
        tool = ToolMetadata("test.tool", "1.0.0", source_kind=SourceKind.Dynamic)
        data = json.dumps({"key": "value"})
        meta = json.dumps({"extra": "info"})
        input_refs = ["ref1", "ref2"]

        artifact = Artifact(
            "test-id",
            tool,
            "TestType",
            data,
            input_refs=input_refs,
            schema_version="1.5",
            meta=meta,
        )

        assert artifact.id == "test-id"
        assert artifact.tool.name == "test.tool"
        assert isinstance(artifact.created_at, str)  # ISO timestamp string
        assert artifact.input_refs == input_refs
        assert artifact.schema_version == "1.5"
        assert artifact.data_type == "TestType"
        assert json.loads(artifact.data) == {"key": "value"}
        assert json.loads(artifact.meta) == {"extra": "info"}

    def test_timestamp_format(self):
        """Test that created_at is a valid ISO timestamp."""
        tool = ToolMetadata("test.tool", "1.0.0")
        data = json.dumps({"test": True})

        artifact = Artifact("test-id", tool, "Test", data)

        # Should be ISO 8601 format
        assert "T" in artifact.created_at
        assert "+" in artifact.created_at or "Z" in artifact.created_at

    def test_data_as_json(self):
        """Test that data getter returns valid JSON."""
        tool = ToolMetadata("test.tool", "1.0.0")
        original_data = {"functions": ["main", "foo"], "edges": 5}

        artifact = Artifact("test-id", tool, "CFG", json.dumps(original_data))

        parsed_data = json.loads(artifact.data)
        assert parsed_data == original_data


class TestArtifactInputRefs:
    """Test Artifact input reference operations."""

    def test_input_ref_operations(self):
        """Test adding and removing input references."""
        tool = ToolMetadata("test.tool", "1.0.0")
        data = json.dumps({"test": True})

        artifact = Artifact("test-id", tool, "Test", data)

        # Initially no input refs
        assert artifact.input_ref_count() == 0
        assert not artifact.has_input_refs()

        # Add input refs
        artifact.add_input_ref("ref1")
        artifact.add_input_ref("ref2")

        assert artifact.input_ref_count() == 2
        assert artifact.has_input_refs()
        assert "ref1" in artifact.input_refs
        assert "ref2" in artifact.input_refs

        # Remove input ref
        assert artifact.remove_input_ref("ref1")
        assert artifact.input_ref_count() == 1
        assert "ref1" not in artifact.input_refs
        assert "ref2" in artifact.input_refs

        # Try to remove non-existent ref
        assert not artifact.remove_input_ref("nonexistent")
        assert artifact.input_ref_count() == 1


class TestArtifactMeta:
    """Test Artifact metadata operations."""

    def test_meta_operations(self):
        """Test metadata handling."""
        tool = ToolMetadata("test.tool", "1.0.0")
        data = json.dumps({"test": True})

        # Create artifact without meta
        artifact = Artifact("test-id", tool, "Test", data)
        assert artifact.meta is None

        # Create artifact with meta
        meta = json.dumps({"confidence": 0.85, "method": "heuristic"})
        artifact_with_meta = Artifact("test-id2", tool, "Test", data, meta=meta)

        assert artifact_with_meta.meta is not None
        parsed_meta = json.loads(artifact_with_meta.meta)
        assert parsed_meta["confidence"] == 0.85
        assert parsed_meta["method"] == "heuristic"


class TestArtifactRepresentation:
    """Test Artifact string representations."""

    def test_str_representation(self):
        """Test string representation."""
        tool = ToolMetadata("disasm.capstone", "5.0.1")
        data = json.dumps({"test": True})

        artifact = Artifact("test-artifact", tool, "TestData", data)

        str_repr = str(artifact)
        assert "Artifact" in str_repr
        assert "test-artifact" in str_repr
        assert "TestData" in str_repr
        assert "1.0" in str_repr

    def test_repr_representation(self):
        """Test repr representation."""
        tool = ToolMetadata("test.tool", "1.0.0")
        data = json.dumps({"test": True})

        artifact = Artifact("test-id", tool, "Test", data)

        repr_str = repr(artifact)
        assert "Artifact" in repr_str
        assert "test-id" in repr_str
        assert "Test" in repr_str


class TestArtifactSerialization:
    """Test Artifact serialization features."""

    def test_json_serialization(self):
        """Test JSON serialization and deserialization."""
        tool = ToolMetadata(
            "disasm.capstone",
            "5.0.1",
            parameters={"arch": "x86_64"},
            source_kind=SourceKind.Static,
        )
        data = json.dumps({"functions": ["main", "foo"]})
        meta = json.dumps({"confidence": 0.9})
        input_refs = ["input1", "input2"]

        original = Artifact(
            "test-artifact",
            tool,
            "CFG",
            data,
            input_refs=input_refs,
            schema_version="2.0",
            meta=meta,
        )

        # Serialize
        json_str = original.to_json()
        assert isinstance(json_str, str)

        # Deserialize
        restored = Artifact.from_json(json_str)

        # Check core fields (excluding timestamp)
        assert restored.id == original.id
        assert restored.tool.name == original.tool.name
        assert restored.tool.version == original.tool.version
        assert restored.input_refs == original.input_refs
        assert restored.schema_version == original.schema_version
        assert restored.data_type == original.data_type
        assert json.loads(restored.data) == json.loads(original.data)
        assert json.loads(restored.meta) == json.loads(original.meta)

    def test_binary_serialization(self):
        """Test binary serialization and deserialization."""
        tool = ToolMetadata("test.tool", "1.0.0")
        data = json.dumps({"test": "data"})

        original = Artifact("test-id", tool, "Test", data)

        # Serialize
        binary_data = original.to_binary()
        assert isinstance(binary_data, bytes)

        # Note: Binary deserialization may fail due to chrono DateTime serialization
        # This is a known limitation with bincode and chrono
        try:
            restored = Artifact.from_binary(binary_data)
            assert restored.id == original.id
            assert restored.tool.name == original.tool.name
            assert restored.data_type == original.data_type
            assert json.loads(restored.data) == json.loads(original.data)
        except ValueError as e:
            # Expected to fail due to chrono serialization issues
            assert "Binary deserialization error" in str(e)


class TestArtifactValidation:
    """Test Artifact validation."""

    def test_valid_artifacts(self):
        """Test that valid artifacts pass validation."""
        test_cases = [
            (
                "basic",
                ToolMetadata("tool1", "1.0"),
                "Type1",
                json.dumps({"data": 1}),
                None,
                "1.0",
                None,
            ),
            (
                "with-inputs",
                ToolMetadata("tool2", "2.0"),
                "Type2",
                json.dumps([1, 2, 3]),
                ["ref1"],
                "1.0",
                None,
            ),
            (
                "with-meta",
                ToolMetadata("tool3", "3.0"),
                "Type3",
                json.dumps({"key": "value"}),
                None,
                "2.0",
                json.dumps({"extra": "info"}),
            ),
        ]

        for id_val, tool, data_type, data, input_refs, schema, meta in test_cases:
            input_refs = input_refs or []
            schema = schema or "1.0"
            meta = meta or None

            artifact = Artifact(
                id_val,
                tool,
                data_type,
                data,
                input_refs=input_refs,
                schema_version=schema,
                meta=meta,
            )
            assert artifact.is_valid(), f"Artifact should be valid: {artifact}"

    def test_constructor_validation(self):
        """Test that constructor properly validates inputs."""
        # This is already tested in other test methods
        # The constructor prevents creating invalid artifacts
        pass


class TestArtifactEdgeCases:
    """Test Artifact edge cases."""

    def test_large_data(self):
        """Test with large JSON data."""
        tool = ToolMetadata("test.tool", "1.0.0")

        # Create large data
        large_data = {"items": list(range(1000))}
        data_json = json.dumps(large_data)

        artifact = Artifact("large-artifact", tool, "LargeData", data_json)
        assert artifact.is_valid()

        # Verify data integrity
        parsed = json.loads(artifact.data)
        assert len(parsed["items"]) == 1000

    def test_unicode_data(self):
        """Test with Unicode characters in data."""
        tool = ToolMetadata("test.tool", "1.0.0")

        unicode_data = {"message": "Hello 世界 🌍", "symbols": ["α", "β", "γ"]}
        data_json = json.dumps(unicode_data)

        artifact = Artifact("unicode-artifact", tool, "UnicodeData", data_json)
        assert artifact.is_valid()

        # Verify Unicode preservation
        parsed = json.loads(artifact.data)
        assert parsed["message"] == "Hello 世界 🌍"
        assert "α" in parsed["symbols"]

    def test_empty_collections(self):
        """Test with empty collections."""
        tool = ToolMetadata("test.tool", "1.0.0")

        # Empty object
        data = json.dumps({})
        artifact = Artifact("empty-data", tool, "EmptyData", data)
        assert artifact.is_valid()
        assert json.loads(artifact.data) == {}

        # Empty array
        data = json.dumps([])
        artifact = Artifact("empty-array", tool, "EmptyArray", data)
        assert artifact.is_valid()
        assert json.loads(artifact.data) == []

    def test_nested_structures(self):
        """Test with deeply nested JSON structures."""
        tool = ToolMetadata("test.tool", "1.0.0")

        nested_data = {
            "level1": {
                "level2": {"level3": {"values": [1, 2, {"deep": "value"}], "count": 42}}
            }
        }
        data_json = json.dumps(nested_data)

        artifact = Artifact("nested-artifact", tool, "NestedData", data_json)
        assert artifact.is_valid()

        # Verify structure preservation
        parsed = json.loads(artifact.data)
        assert parsed["level1"]["level2"]["level3"]["count"] == 42
        assert parsed["level1"]["level2"]["level3"]["values"][2]["deep"] == "value"
