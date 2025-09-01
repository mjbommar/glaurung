"""
Glaurung Python package.

This package wraps the Rust extension module `glaurung._native` and provides
Python-friendly entry points. Rust types remain available under
`glaurung._native` and `glaurung._native.triage`.
"""

from . import _native as _native  # type: ignore

# Re-export all core types at the package root for convenience
# Address types
Address = _native.Address
AddressKind = _native.AddressKind
AddressRange = _native.AddressRange
AddressSpace = _native.AddressSpace
AddressSpaceKind = _native.AddressSpaceKind

# Binary and format types
Format = _native.Format
Arch = _native.Arch
Binary = _native.Binary
Hashes = _native.Hashes

# ID and identification types
Id = _native.Id
IdKind = _native.IdKind
IdGenerator = _native.IdGenerator

# Tool and metadata types
ToolMetadata = _native.ToolMetadata
SourceKind = _native.SourceKind
Artifact = _native.Artifact

# Binary analysis types
Section = _native.Section
SectionPerms = _native.SectionPerms
Segment = _native.Segment
Perms = _native.Perms
Symbol = _native.Symbol
SymbolKind = _native.SymbolKind
SymbolBinding = _native.SymbolBinding
SymbolVisibility = _native.SymbolVisibility
SymbolSource = _native.SymbolSource
Relocation = _native.Relocation
RelocationType = _native.RelocationType
Instruction = _native.Instruction
Operand = _native.Operand
OperandKind = _native.OperandKind
Access = _native.Access
SideEffect = _native.SideEffect
Register = _native.Register
RegisterKind = _native.RegisterKind
DisassemblerError = _native.DisassemblerError
Architecture = _native.Architecture
Endianness = _native.Endianness
DisassemblerConfig = _native.DisassemblerConfig
# TODO: Fix BasicBlock compilation
# BasicBlock = _native.BasicBlock
StringLiteral = _native.StringLiteral
StringEncoding = _native.StringEncoding
StringClassification = _native.StringClassification

# Pattern matching types
Pattern = _native.Pattern
PatternDefinition = _native.PatternDefinition
PatternType = _native.PatternType
YaraMatch = _native.YaraMatch
MetadataValue = _native.MetadataValue

# Expose triage submodule from the native extension
triage = _native.triage

__all__ = [
    # Address types
    "Address",
    "AddressKind",
    "AddressRange",
    "AddressSpace",
    "AddressSpaceKind",
    # Binary and format types
    "Format",
    "Arch",
    "Endianness",
    "Binary",
    "Hashes",
    # ID and identification types
    "Id",
    "IdKind",
    "IdGenerator",
    # Tool and metadata types
    "ToolMetadata",
    "SourceKind",
    "Artifact",
    # Binary analysis types
    "Section",
    "SectionPerms",
    "Segment",
    "Perms",
    "Symbol",
    "SymbolKind",
    "SymbolBinding",
    "SymbolVisibility",
    "SymbolSource",
    "Relocation",
    "RelocationType",
    "Instruction",
    "Operand",
    "OperandKind",
    "Access",
    "SideEffect",
    "Register",
    "RegisterKind",
    "DisassemblerError",
    "Architecture",
    "Endianness",
    "DisassemblerConfig",
    "StringLiteral",
    "StringEncoding",
    "StringClassification",
    # Pattern matching types
    "Pattern",
    "PatternDefinition",
    "PatternType",
    "YaraMatch",
    "MetadataValue",
    # Triage submodule
    "triage",
]
