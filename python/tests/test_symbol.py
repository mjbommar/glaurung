"""Tests for the Symbol type."""

import pytest
from glaurung import (
    Symbol, SymbolKind, SymbolBinding, SymbolVisibility, SymbolSource,
    Address, AddressKind
)


class TestSymbolEnums:
    """Test all Symbol-related enums."""

    def test_symbol_kind_values(self):
        """Test all SymbolKind enum values."""
        assert SymbolKind.Function
        assert SymbolKind.Object
        assert SymbolKind.Section
        assert SymbolKind.Import
        assert SymbolKind.Export
        assert SymbolKind.Thunk
        assert SymbolKind.Debug
        assert SymbolKind.Synthetic
        assert SymbolKind.Other

    def test_symbol_kind_display(self):
        """Test string representation of SymbolKind."""
        assert str(SymbolKind.Function) == "Function"
        assert str(SymbolKind.Object) == "Object"
        assert str(SymbolKind.Import) == "Import"
        assert str(SymbolKind.Export) == "Export"
        assert str(SymbolKind.Other) == "Other"

    def test_symbol_binding_values(self):
        """Test all SymbolBinding enum values."""
        assert SymbolBinding.Local
        assert SymbolBinding.Global
        assert SymbolBinding.Weak

    def test_symbol_binding_display(self):
        """Test string representation of SymbolBinding."""
        assert str(SymbolBinding.Local) == "Local"
        assert str(SymbolBinding.Global) == "Global"
        assert str(SymbolBinding.Weak) == "Weak"

    def test_symbol_visibility_values(self):
        """Test all SymbolVisibility enum values."""
        assert SymbolVisibility.Public
        assert SymbolVisibility.Private
        assert SymbolVisibility.Protected
        assert SymbolVisibility.Hidden

    def test_symbol_visibility_display(self):
        """Test string representation of SymbolVisibility."""
        assert str(SymbolVisibility.Public) == "Public"
        assert str(SymbolVisibility.Private) == "Private"
        assert str(SymbolVisibility.Protected) == "Protected"
        assert str(SymbolVisibility.Hidden) == "Hidden"

    def test_symbol_source_values(self):
        """Test all SymbolSource enum values."""
        assert SymbolSource.DebugInfo
        assert SymbolSource.ImportTable
        assert SymbolSource.ExportTable
        assert SymbolSource.Heuristic
        assert SymbolSource.Pdb
        assert SymbolSource.Dwarf
        assert SymbolSource.Ai

    def test_symbol_source_display(self):
        """Test string representation of SymbolSource."""
        assert str(SymbolSource.DebugInfo) == "DebugInfo"
        assert str(SymbolSource.ImportTable) == "ImportTable"
        assert str(SymbolSource.ExportTable) == "ExportTable"
        assert str(SymbolSource.Heuristic) == "Heuristic"
        assert str(SymbolSource.Ai) == "Ai"


class TestSymbolCreation:
    """Test Symbol creation and basic functionality."""

    def test_symbol_creation_minimal(self):
        """Test creating a minimal Symbol."""
        symbol = Symbol(
            "sym_1",
            "main",
            SymbolKind.Function,
            SymbolSource.DebugInfo
        )

        assert symbol.id == "sym_1"
        assert symbol.name == "main"
        assert symbol.demangled is None
        assert str(symbol.kind) == "Function"
        assert symbol.address is None
        assert symbol.size is None
        assert symbol.binding is None
        assert symbol.module is None
        assert symbol.visibility is None
        assert str(symbol.source) == "DebugInfo"

    def test_symbol_creation_full(self):
        """Test creating a Symbol with all fields."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        symbol = Symbol(
            "sym_2",
            "_ZN4test7exampleEv",
            SymbolKind.Function,
            SymbolSource.DebugInfo,
            demangled="test::example()",
            address=address,
            size=42,
            binding=SymbolBinding.Global,
            module="test.so",
            visibility=SymbolVisibility.Public
        )

        assert symbol.id == "sym_2"
        assert symbol.name == "_ZN4test7exampleEv"
        assert symbol.demangled == "test::example()"
        assert str(symbol.kind) == "Function"
        assert symbol.address.value == 0x400000
        assert symbol.size == 42
        assert str(symbol.binding) == "Global"
        assert symbol.module == "test.so"
        assert str(symbol.visibility) == "Public"
        assert str(symbol.source) == "DebugInfo"

    def test_symbol_creation_import(self):
        """Test creating an import symbol."""
        symbol = Symbol(
            "import_1",
            "printf",
            SymbolKind.Import,
            SymbolSource.ImportTable,
            module="libc.so.6"
        )

        assert str(symbol.kind) == "Import"
        assert str(symbol.source) == "ImportTable"
        assert symbol.module == "libc.so.6"

    def test_symbol_creation_export(self):
        """Test creating an export symbol."""
        address = Address(AddressKind.VA, 0x400100, bits=64)

        symbol = Symbol(
            "export_1",
            "my_function",
            SymbolKind.Export,
            SymbolSource.ExportTable,
            address=address,
            binding=SymbolBinding.Global,
            visibility=SymbolVisibility.Public
        )

        assert str(symbol.kind) == "Export"
        assert str(symbol.source) == "ExportTable"
        assert symbol.address.value == 0x400100
        assert str(symbol.binding) == "Global"
        assert str(symbol.visibility) == "Public"


class TestSymbolProperties:
    """Test Symbol properties and methods."""

    def test_symbol_display_name(self):
        """Test display name resolution."""
        # Test with demangled name
        symbol_with_demangled = Symbol(
            "sym_1",
            "_ZN4test7exampleEv",
            SymbolKind.Function,
            SymbolSource.DebugInfo,
            demangled="test::example()"
        )
        assert symbol_with_demangled.display_name() == "test::example()"

        # Test without demangled name
        symbol_without_demangled = Symbol(
            "sym_2",
            "simple_function",
            SymbolKind.Function,
            SymbolSource.Heuristic
        )
        assert symbol_without_demangled.display_name() == "simple_function"
        assert symbol_without_demangled.demangled is None

    def test_symbol_type_checks(self):
        """Test symbol type checking methods."""
        function_symbol = Symbol(
            "func",
            "main",
            SymbolKind.Function,
            SymbolSource.DebugInfo
        )

        object_symbol = Symbol(
            "obj",
            "global_var",
            SymbolKind.Object,
            SymbolSource.DebugInfo
        )

        import_symbol = Symbol(
            "imp",
            "printf",
            SymbolKind.Import,
            SymbolSource.ImportTable
        )

        export_symbol = Symbol(
            "exp",
            "my_func",
            SymbolKind.Export,
            SymbolSource.ExportTable
        )

        # Test positive cases
        assert function_symbol.is_function()
        assert object_symbol.is_object()
        assert import_symbol.is_import()
        assert export_symbol.is_export()

        # Test negative cases
        assert not function_symbol.is_object()
        assert not object_symbol.is_function()
        assert not import_symbol.is_export()
        assert not export_symbol.is_import()

    def test_symbol_binding_checks(self):
        """Test symbol binding checking methods."""
        local_symbol = Symbol(
            "local",
            "var",
            SymbolKind.Object,
            SymbolSource.DebugInfo,
            binding=SymbolBinding.Local
        )

        global_symbol = Symbol(
            "global",
            "var",
            SymbolKind.Object,
            SymbolSource.DebugInfo,
            binding=SymbolBinding.Global
        )

        weak_symbol = Symbol(
            "weak",
            "var",
            SymbolKind.Object,
            SymbolSource.DebugInfo,
            binding=SymbolBinding.Weak
        )

        no_binding_symbol = Symbol(
            "no_binding",
            "var",
            SymbolKind.Object,
            SymbolSource.Heuristic
        )

        # Test positive cases
        assert local_symbol.is_local()
        assert global_symbol.is_global()
        assert weak_symbol.is_weak()

        # Test negative cases
        assert not local_symbol.is_global()
        assert not global_symbol.is_local()
        assert not weak_symbol.is_global()

        # Test None binding
        assert not no_binding_symbol.is_local()
        assert not no_binding_symbol.is_global()
        assert not no_binding_symbol.is_weak()

    def test_symbol_description(self):
        """Test symbol description generation."""
        address = Address(AddressKind.VA, 0x400000, bits=64)

        simple_symbol = Symbol(
            "simple",
            "main",
            SymbolKind.Function,
            SymbolSource.DebugInfo
        )
        desc = simple_symbol.description()
        assert "main" in desc
        assert "Function" in desc

        complex_symbol = Symbol(
            "complex",
            "_ZN4test7exampleEv",
            SymbolKind.Function,
            SymbolSource.DebugInfo,
            demangled="test::example()",
            address=address,
            binding=SymbolBinding.Global
        )
        desc = complex_symbol.description()
        assert "test::example()" in desc
        assert "Function" in desc
        assert "Global" in desc
        assert "at" in desc

    def test_symbol_display(self):
        """Test symbol string representation."""
        symbol = Symbol(
            "test_id",
            "test_function",
            SymbolKind.Function,
            SymbolSource.DebugInfo
        )

        assert str(symbol) == "Symbol 'test_function' (test_id)"

        symbol_with_demangled = Symbol(
            "test_id2",
            "mangled_name",
            SymbolKind.Function,
            SymbolSource.DebugInfo,
            demangled="demangled::name()"
        )

        assert str(symbol_with_demangled) == "Symbol 'demangled::name()' (test_id2)"


class TestSymbolEdgeCases:
    """Test edge cases and special scenarios."""

    def test_symbol_empty_name(self):
        """Test Symbol with empty name."""
        symbol = Symbol(
            "empty_name",
            "",
            SymbolKind.Object,
            SymbolSource.Heuristic
        )

        assert symbol.name == ""
        assert symbol.display_name() == ""
        assert symbol.is_object()

    def test_symbol_very_long_name(self):
        """Test Symbol with very long name."""
        long_name = "a" * 1000
        symbol = Symbol(
            "long_name",
            long_name,
            SymbolKind.Function,
            SymbolSource.DebugInfo
        )

        assert symbol.name == long_name
        assert symbol.display_name() == long_name
        assert len(symbol.name) == 1000

    def test_symbol_zero_size(self):
        """Test Symbol with zero size."""
        symbol = Symbol(
            "zero_size",
            "empty_func",
            SymbolKind.Function,
            SymbolSource.DebugInfo,
            size=0
        )

        assert symbol.size == 0

    def test_symbol_large_size(self):
        """Test Symbol with large size."""
        symbol = Symbol(
            "large_size",
            "big_array",
            SymbolKind.Object,
            SymbolSource.DebugInfo,
            size=0x1000000  # 16MB
        )

        assert symbol.size == 0x1000000

    def test_symbol_all_sources(self):
        """Test Symbol with all different source types."""
        sources = [
            SymbolSource.DebugInfo,
            SymbolSource.ImportTable,
            SymbolSource.ExportTable,
            SymbolSource.Heuristic,
            SymbolSource.Pdb,
            SymbolSource.Dwarf,
            SymbolSource.Ai,
        ]

        for i, source in enumerate(sources):
            symbol = Symbol(
                f"sym_{i}",
                f"func_{i}",
                SymbolKind.Function,
                source
            )
            assert str(symbol.source) == str(source)

    def test_symbol_all_visibilities(self):
        """Test Symbol with all visibility types."""
        visibilities = [
            SymbolVisibility.Public,
            SymbolVisibility.Private,
            SymbolVisibility.Protected,
            SymbolVisibility.Hidden,
        ]

        for i, visibility in enumerate(visibilities):
            symbol = Symbol(
                f"sym_{i}",
                f"func_{i}",
                SymbolKind.Function,
                SymbolSource.DebugInfo,
                visibility=visibility
            )
            assert str(symbol.visibility) == str(visibility)

    def test_symbol_mixed_address_kinds(self):
        """Test Symbol with different address kinds."""
        va_address = Address(AddressKind.VA, 0x400000, bits=64)
        rva_address = Address(AddressKind.RVA, 0x1000, bits=32)
        file_address = Address(AddressKind.FileOffset, 0x2000, bits=64)

        va_symbol = Symbol(
            "va_sym",
            "func",
            SymbolKind.Function,
            SymbolSource.DebugInfo,
            address=va_address
        )

        rva_symbol = Symbol(
            "rva_sym",
            "func",
            SymbolKind.Function,
            SymbolSource.DebugInfo,
            address=rva_address
        )

        file_symbol = Symbol(
            "file_sym",
            "func",
            SymbolKind.Function,
            SymbolSource.DebugInfo,
            address=file_address
        )

        assert va_symbol.address.kind == AddressKind.VA
        assert rva_symbol.address.kind == AddressKind.RVA
        assert file_symbol.address.kind == AddressKind.FileOffset