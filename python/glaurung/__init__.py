"""
Glaurung Python package.

This package wraps the Rust extension module `glaurung._native` and provides
Python-friendly entry points. Rust types remain available under
`glaurung._native` and `glaurung._native.triage`.
"""

from enum import Enum

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
# Provide a thin Python Enum wrapper for DisassemblerError to get nicer str()


class DisassemblerError(Enum):
    InvalidInstruction = _native.DisassemblerError.InvalidInstruction
    InvalidAddress = _native.DisassemblerError.InvalidAddress
    InsufficientBytes = _native.DisassemblerError.InsufficientBytes
    UnsupportedInstruction = _native.DisassemblerError.UnsupportedInstruction

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


Architecture = _native.Architecture
Endianness = _native.Endianness
DisassemblerConfig = _native.DisassemblerConfig
BasicBlock = _native.BasicBlock
StringLiteral = _native.StringLiteral
StringEncoding = _native.StringEncoding
StringClassification = _native.StringClassification

# Pattern matching types
Pattern = _native.Pattern
PatternDefinition = _native.PatternDefinition
PatternType = _native.PatternType
YaraMatch = _native.YaraMatch
MetadataValue = _native.MetadataValue

# Data types and variables
DataType = _native.DataType
DataTypeKind = _native.DataTypeKind
Field = _native.Field
EnumMember = _native.EnumMember
TypeData = _native.TypeData
Variable = _native.Variable
StorageLocation = _native.StorageLocation

# Expose triage submodule from the native extension
triage = _native.triage

# Expose a top-level symbols package provided by the native extension
symbols = _native.symbols
strings = _native.strings
from . import similarity as similarity

# Graph types (CFG and CallGraph)
ControlFlowGraph = _native.ControlFlowGraph
ControlFlowEdge = _native.ControlFlowEdge
ControlFlowEdgeKind = _native.ControlFlowEdgeKind
CallGraph = _native.CallGraph
CallGraphEdge = _native.CallGraphEdge
CallType = _native.CallType
CallGraphStats = _native.CallGraphStats
ControlFlowGraphStats = _native.ControlFlowGraphStats
Function = _native.Function
FunctionKind = _native.FunctionKind
FunctionFlags = _native.FunctionFlagsPy
Reference = _native.Reference
ReferenceKind = _native.ReferenceKind
UnresolvedReferenceKind = _native.UnresolvedReferenceKind
ReferenceTarget = _native.ReferenceTarget

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
    "BasicBlock",
    "StringLiteral",
    "StringEncoding",
    "StringClassification",
    # Pattern matching types
    "Pattern",
    "PatternDefinition",
    "PatternType",
    "YaraMatch",
    "MetadataValue",
    # Data types and variables
    "DataType",
    "DataTypeKind",
    "Field",
    "EnumMember",
    "TypeData",
    "Variable",
    "StorageLocation",
    # Graphs
    "ControlFlowGraph",
    "ControlFlowEdge",
    "ControlFlowEdgeKind",
    "ControlFlowGraphStats",
    "CallGraph",
    "CallGraphEdge",
    "CallType",
    "CallGraphStats",
    "Function",
    "FunctionKind",
    "FunctionFlags",
    "Reference",
    "ReferenceKind",
    "UnresolvedReferenceKind",
    "ReferenceTarget",
    # Triage submodule
    "triage",
    # Top-level symbols module
    "symbols",
    # Top-level strings module
    "strings",
    # Top-level similarity module
    "similarity",
]

# Expose logging config from native and Python wrapper
LogLevel = _native.LogLevel
init_logging = _native.init_logging
log_message = _native.log_message

__all__ += [
    "LogLevel",
    "init_logging",
    "log_message",
]
