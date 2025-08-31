"""Python package entry for the glaurung extension.

Exports core Rust-backed types for convenient import in Python.
"""

from typing import Any, TYPE_CHECKING
from importlib import import_module

if not TYPE_CHECKING:
    try:
        _ext: Any = import_module(f"{__name__}.glaurung")
        Address = _ext.Address
        AddressKind = _ext.AddressKind
        AddressRange = _ext.AddressRange
        AddressSpace = _ext.AddressSpace
        AddressSpaceKind = _ext.AddressSpaceKind
        Artifact = _ext.Artifact
        Binary = _ext.Binary
        Format = _ext.Format
        Arch = _ext.Arch
        Endianness = _ext.Endianness
        Hashes = _ext.Hashes
        Id = _ext.Id
        IdKind = _ext.IdKind
        IdGenerator = _ext.IdGenerator
        Perms = _ext.Perms
        Section = _ext.Section
        SectionPerms = _ext.SectionPerms
        Segment = _ext.Segment
        StringEncoding = _ext.StringEncoding
        StringClassification = _ext.StringClassification
        StringLiteral = _ext.StringLiteral
        Symbol = _ext.Symbol
        SymbolKind = _ext.SymbolKind
        SymbolBinding = _ext.SymbolBinding
        SymbolVisibility = _ext.SymbolVisibility
        SymbolSource = _ext.SymbolSource
        MetadataValue = _ext.MetadataValue
        PatternType = _ext.PatternType
        YaraMatch = _ext.YaraMatch
        PatternDefinition = _ext.PatternDefinition
        Pattern = _ext.Pattern
        RelocationType = _ext.RelocationType
        Relocation = _ext.Relocation
        OperandKind = _ext.OperandKind
        Access = _ext.Access
        SideEffect = _ext.SideEffect
        Operand = _ext.Operand
        Instruction = _ext.Instruction
        ToolMetadata = _ext.ToolMetadata
        SourceKind = _ext.SourceKind

        __all__ = [
            "Address",
            "AddressKind",
            "AddressRange",
            "AddressSpace",
            "AddressSpaceKind",
            "Artifact",
            "Binary",
            "Format",
            "Arch",
            "Endianness",
            "Hashes",
            "Id",
            "IdKind",
            "IdGenerator",
            "Perms",
            "Section",
            "SectionPerms",
            "Segment",
            "StringEncoding",
            "StringClassification",
            "StringLiteral",
            "Symbol",
            "SymbolKind",
            "SymbolBinding",
            "SymbolVisibility",
            "SymbolSource",
            "MetadataValue",
            "PatternType",
            "YaraMatch",
            "PatternDefinition",
            "Pattern",
            "RelocationType",
            "Relocation",
            "OperandKind",
            "Access",
            "SideEffect",
            "Operand",
            "Instruction",
            "ToolMetadata",
            "SourceKind",
        ]
    except Exception:
        # Extension not built yet
        __doc__ = "Glaurung binary analysis framework"
        __all__ = []
