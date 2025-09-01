from typing import Any as _Any

# Coarse stubs for runtime-provided native symbols to aid static type checking.
# The actual implementations are provided by the compiled extension.
# Address types
Address: _Any
AddressKind: _Any
AddressRange: _Any
AddressSpace: _Any
AddressSpaceKind: _Any
# Binary and format types
Format: _Any
Arch: _Any
Binary: _Any
Hashes: _Any
# ID and identification types
Id: _Any
IdKind: _Any
IdGenerator: _Any
# Tool and metadata types
ToolMetadata: _Any
SourceKind: _Any
Artifact: _Any
# Binary analysis types
Section: _Any
SectionPerms: _Any
Segment: _Any
Perms: _Any
Symbol: _Any
SymbolKind: _Any
SymbolBinding: _Any
SymbolVisibility: _Any
SymbolSource: _Any
Relocation: _Any
RelocationType: _Any
Instruction: _Any
Operand: _Any
OperandKind: _Any
Access: _Any
SideEffect: _Any
Register: _Any
RegisterKind: _Any
DisassemblerError: _Any
Architecture: _Any
Endianness: _Any
DisassemblerConfig: _Any
StringLiteral: _Any
StringEncoding: _Any
StringClassification: _Any
# Pattern matching types
Pattern: _Any
PatternDefinition: _Any
PatternType: _Any
YaraMatch: _Any
MetadataValue: _Any
# Triage submodule
triage: _Any

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
