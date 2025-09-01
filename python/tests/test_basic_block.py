"""Tests for the BasicBlock type."""

from glaurung import (
    BasicBlock,
    Address,
    AddressKind,
)


class TestBasicBlockCreation:
    """Test BasicBlock creation and basic functionality."""

    def test_basic_block_creation_minimal(self):
        """Test creating a minimal basic block."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.VA, 0x1020, bits=64)

        block = BasicBlock("bb_1000", start_addr, end_addr, 5)

        assert block.id == "bb_1000"
        assert block.start_address.value == 0x1000
        assert block.end_address.value == 0x1020
        assert block.instruction_count == 5
        assert block.successor_ids == []
        assert block.predecessor_ids == []
        assert not block.is_entry_block()
        assert not block.is_exit_block()

    def test_basic_block_creation_with_relationships(self):
        """Test creating a basic block with successor and predecessor relationships."""
        start_addr = Address(AddressKind.VA, 0x2000, bits=64)
        end_addr = Address(AddressKind.VA, 0x2020, bits=64)

        successors = ["bb_2020", "bb_2030"]
        predecessors = ["bb_1ff0"]

        block = BasicBlock(
            "bb_2000",
            start_addr,
            end_addr,
            3,
            successors,
            predecessors,
        )

        assert block.id == "bb_2000"
        assert block.instruction_count == 3
        assert block.successor_ids == successors
        assert block.predecessor_ids == predecessors
        assert not block.is_entry_block()
        assert not block.is_exit_block()

    def test_basic_block_creation_entry_block(self):
        """Test creating an entry block (no predecessors)."""
        start_addr = Address(AddressKind.VA, 0x400000, bits=64)
        end_addr = Address(AddressKind.VA, 0x400010, bits=64)

        block = BasicBlock("entry", start_addr, end_addr, 2, ["bb_main"], [])

        assert block.is_entry_block()
        assert not block.is_exit_block()
        assert block.successor_count() == 1
        assert block.predecessor_count() == 0

    def test_basic_block_creation_exit_block(self):
        """Test creating an exit block (no successors)."""
        start_addr = Address(AddressKind.VA, 0x500000, bits=64)
        end_addr = Address(AddressKind.VA, 0x500020, bits=64)

        block = BasicBlock("exit", start_addr, end_addr, 4, [], ["bb_last"])

        assert not block.is_entry_block()
        assert block.is_exit_block()
        assert block.successor_count() == 0
        assert block.predecessor_count() == 1


class TestBasicBlockProperties:
    """Test BasicBlock properties and methods."""

    def test_basic_block_size_bytes(self):
        """Test calculating basic block size in bytes."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.VA, 0x1020, bits=64)

        block = BasicBlock("test", start_addr, end_addr, 5)

        assert block.size_bytes() == 0x20  # 32 bytes

    def test_basic_block_size_bytes_different_spaces(self):
        """Test size calculation with different address spaces."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.FileOffset, 0x1020, bits=64)

        block = BasicBlock("test", start_addr, end_addr, 5)

        assert block.size_bytes() == 0  # Cannot calculate size for different spaces

    def test_basic_block_contains_address(self):
        """Test address containment checking."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.VA, 0x1020, bits=64)

        block = BasicBlock("test", start_addr, end_addr, 5)

        # Address within the block
        inside_addr = Address(AddressKind.VA, 0x1010, bits=64)
        assert block.contains_address(inside_addr)

        # Address at the start (inclusive)
        assert block.contains_address(start_addr)

        # Address at the end (exclusive - should not contain)
        end_addr_test = Address(AddressKind.VA, 0x1020, bits=64)
        assert not block.contains_address(end_addr_test)

        # Address before the block
        before_addr = Address(AddressKind.VA, 0x0FF0, bits=64)
        assert not block.contains_address(before_addr)

        # Address after the block
        after_addr = Address(AddressKind.VA, 0x1030, bits=64)
        assert not block.contains_address(after_addr)

        # Address with different kind
        file_addr = Address(AddressKind.FileOffset, 0x1010, bits=64)
        assert not block.contains_address(file_addr)

    def test_basic_block_single_instruction(self):
        """Test single instruction block detection."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.VA, 0x1005, bits=64)

        single_instr_block = BasicBlock("single", start_addr, end_addr, 1)
        multi_instr_block = BasicBlock("multi", start_addr, end_addr, 3)

        assert single_instr_block.is_single_instruction()
        assert not multi_instr_block.is_single_instruction()


class TestBasicBlockRelationships:
    """Test BasicBlock successor and predecessor management."""

    def test_basic_block_successor_management(self):
        """Test adding and removing successors."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.VA, 0x1020, bits=64)

        block = BasicBlock("test", start_addr, end_addr, 5)

        # Initially no successors
        assert block.successor_count() == 0
        assert not block.has_successor("bb1")

        # Add successors
        block.add_successor("bb1")
        block.add_successor("bb2")
        block.add_successor("bb1")  # Duplicate should be ignored

        assert block.successor_count() == 2
        assert block.has_successor("bb1")
        assert block.has_successor("bb2")
        assert not block.has_successor("bb3")

        # Remove successor
        block.remove_successor("bb1")
        assert block.successor_count() == 1
        assert not block.has_successor("bb1")
        assert block.has_successor("bb2")

    def test_basic_block_predecessor_management(self):
        """Test adding and removing predecessors."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.VA, 0x1020, bits=64)

        block = BasicBlock("test", start_addr, end_addr, 5)

        # Initially no predecessors
        assert block.predecessor_count() == 0
        assert not block.has_predecessor("pred1")

        # Add predecessors
        block.add_predecessor("pred1")
        block.add_predecessor("pred2")

        assert block.predecessor_count() == 2
        assert block.has_predecessor("pred1")
        assert block.has_predecessor("pred2")
        assert not block.has_predecessor("pred3")

        # Remove predecessor
        block.remove_predecessor("pred1")
        assert block.predecessor_count() == 1
        assert not block.has_predecessor("pred1")
        assert block.has_predecessor("pred2")


class TestBasicBlockDisplay:
    """Test BasicBlock display and string representation."""

    def test_basic_block_display(self):
        """Test basic block string representation."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.VA, 0x1020, bits=64)

        block = BasicBlock(
            "test_bb", start_addr, end_addr, 3, ["succ1"], ["pred1", "pred2"]
        )

        display_str = str(block)
        assert "BasicBlock" in display_str
        assert "test_bb" in display_str
        assert "1000" in display_str
        assert "1020" in display_str
        assert "3" in display_str
        assert "2" in display_str  # 2 predecessors
        assert "1" in display_str  # 1 successor

    def test_basic_block_summary(self):
        """Test basic block summary generation."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.VA, 0x1020, bits=64)

        # Regular block
        regular_block = BasicBlock(
            "regular", start_addr, end_addr, 3, ["succ1"], ["pred1"]
        )
        summary = regular_block.summary()
        assert "BB:regular" in summary
        assert "1000-1020" in summary
        assert "3 instrs" in summary
        assert "1 preds" in summary
        assert "1 succs" in summary

        # Entry block
        entry_block = BasicBlock("entry", start_addr, end_addr, 1, ["main"], [])
        summary = entry_block.summary()
        assert "ENTRY" in summary

        # Exit block
        exit_block = BasicBlock("exit", start_addr, end_addr, 2, [], ["last"])
        summary = exit_block.summary()
        assert "EXIT" in summary


class TestBasicBlockValidation:
    """Test BasicBlock validation."""

    def test_basic_block_validation_valid(self):
        """Test validation of a valid basic block."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.VA, 0x1020, bits=64)

        block = BasicBlock("valid", start_addr, end_addr, 5, ["succ1"], ["pred1"])

        # Validation should pass
        assert block.validate() is None  # PyO3 converts Ok(()) to None

    def test_basic_block_validation_invalid_start_end(self):
        """Test validation with invalid start/end addresses."""
        start_addr = Address(AddressKind.VA, 0x1020, bits=64)  # Start after end
        end_addr = Address(AddressKind.VA, 0x1000, bits=64)

        block = BasicBlock("invalid", start_addr, end_addr, 5)

        # Validation should fail
        try:
            block.validate()
            assert False, "Validation should have failed"
        except Exception as e:
            assert "start address" in str(e) and "end address" in str(e)

    def test_basic_block_validation_different_kinds(self):
        """Test validation with different address kinds."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.FileOffset, 0x1020, bits=64)

        block = BasicBlock("invalid", start_addr, end_addr, 5)

        # Validation should fail
        try:
            block.validate()
            assert False, "Validation should have failed"
        except Exception as e:
            assert "address" in str(e) and "kind" in str(e)

    def test_basic_block_validation_zero_instructions(self):
        """Test validation with zero instructions."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.VA, 0x1020, bits=64)

        block = BasicBlock("invalid", start_addr, end_addr, 0)

        # Validation should fail
        try:
            block.validate()
            assert False, "Validation should have failed"
        except Exception as e:
            assert "instruction" in str(e)

    def test_basic_block_validation_duplicate_successors(self):
        """Test validation with duplicate successor IDs."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.VA, 0x1020, bits=64)

        block = BasicBlock("invalid", start_addr, end_addr, 5, ["succ1", "succ1"], [])

        # Validation should fail
        try:
            block.validate()
            assert False, "Validation should have failed"
        except Exception as e:
            assert "duplicate" in str(e) and "successor" in str(e)


class TestBasicBlockEdgeCases:
    """Test edge cases and special scenarios."""

    def test_basic_block_minimal_size(self):
        """Test basic block with minimal size."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.VA, 0x1001, bits=64)  # Only 1 byte

        block = BasicBlock("minimal", start_addr, end_addr, 1)

        assert block.size_bytes() == 1
        assert block.is_single_instruction()

    def test_basic_block_large_size(self):
        """Test basic block with large size."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.VA, 0x100000, bits=64)  # 1MB - 1 byte

        block = BasicBlock("large", start_addr, end_addr, 1000)

        # Library uses half-open intervals [start, end), so size = end - start
        assert block.size_bytes() == 0xFF000  # 1MB - 4KB
        assert not block.is_single_instruction()

    def test_basic_block_many_relationships(self):
        """Test basic block with many successors and predecessors."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.VA, 0x1020, bits=64)

        successors = [f"bb_{i}" for i in range(10)]
        predecessors = [f"pred_{i}" for i in range(5)]

        block = BasicBlock(
            "many_relations", start_addr, end_addr, 5, successors, predecessors
        )

        assert block.successor_count() == 10
        assert block.predecessor_count() == 5

        for i in range(10):
            assert block.has_successor(f"bb_{i}")

        for i in range(5):
            assert block.has_predecessor(f"pred_{i}")

    def test_basic_block_empty_relationships(self):
        """Test basic block with empty successor/predecessor lists."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.VA, 0x1020, bits=64)

        block = BasicBlock("empty_relations", start_addr, end_addr, 3, [], [])

        assert block.successor_count() == 0
        assert block.predecessor_count() == 0
        assert block.is_entry_block()
        assert block.is_exit_block()

    def test_basic_block_different_address_spaces(self):
        """Test basic block with addresses in different spaces."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64, space="ram")
        end_addr = Address(AddressKind.VA, 0x1020, bits=64, space="ram")

        block = BasicBlock("spaced", start_addr, end_addr, 5)

        assert block.size_bytes() == 0x20  # Should still work with same space

    def test_basic_block_remove_nonexistent(self):
        """Test removing non-existent successors/predecessors."""
        start_addr = Address(AddressKind.VA, 0x1000, bits=64)
        end_addr = Address(AddressKind.VA, 0x1020, bits=64)

        block = BasicBlock(
            "test", start_addr, end_addr, 5, ["existing"], ["existing_pred"]
        )

        # Try to remove non-existent relationships
        block.remove_successor("nonexistent")
        block.remove_predecessor("nonexistent")

        # Should still have the original relationships
        assert block.has_successor("existing")
        assert block.has_predecessor("existing_pred")
        assert block.successor_count() == 1
        assert block.predecessor_count() == 1
