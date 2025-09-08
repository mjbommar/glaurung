"""
Glaurung Python package.

This package wraps the Rust extension module `glaurung._native` and provides
Python-friendly entry points. Rust types remain available under
`glaurung._native` and `glaurung._native.triage`.
"""

from enum import Enum

from . import _native as _native  # type: ignore
import sys as _sys
from . import similarity as similarity

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

# Expose a top-level symbols and strings from native extension
symbols = _native.symbols
strings = _native.strings
# Disassembly submodule
disasm = _native.disasm
# Ensure `import glaurung.disasm` works by aliasing the native submodule
_sys.modules[__name__ + ".disasm"] = disasm

# Analysis submodule
analysis = _native.analysis
_sys.modules[__name__ + ".analysis"] = analysis

# Triage module: use native triage, but attach a convenience triage()/analyze_path() wrapper
_triage_mod = _native.triage
# Preserve the original native function to avoid recursion when we override attributes
_triage_analyze_native = _triage_mod.analyze_path


class _StringsProxy:
    __slots__ = ("_ss", "_path")

    def __init__(self, native_ss, path: str):
        self._ss = native_ss
        self._path = path

    def __getattr__(self, name):
        if name == "ioc_counts":
            base = dict(getattr(self._ss, "ioc_counts", {}) or {})
            if base.get("ipv4", 0) == 0:
                texts: list[str] = []
                try:
                    if getattr(self._ss, "strings", None):
                        texts.extend(
                            [
                                getattr(s, "text", "")
                                for s in self._ss.strings
                                if getattr(s, "text", None)
                            ]
                        )
                    if getattr(self._ss, "samples", None):
                        texts.extend(
                            [t for t in self._ss.samples if isinstance(t, str)]
                        )
                    if not texts and self._path:
                        with open(
                            self._path, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            texts.append(f.read())
                    import re

                    ipv4_re = re.compile(
                        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
                    )
                    base["ipv4"] = sum(len(ipv4_re.findall(t)) for t in texts)
                except Exception:
                    pass
            return base
        return getattr(self._ss, name)


class _ArtifactProxy:
    __slots__ = ("_art",)

    def __init__(self, art):
        self._art = art

    def __getattr__(self, name):
        if name == "strings":
            ss = getattr(self._art, "strings", None)
            return (
                _StringsProxy(ss, getattr(self._art, "path", ""))
                if ss is not None
                else None
            )
        return getattr(self._art, name)


def _triage_wrapper(
    path: str,
    max_read_bytes: int = 10_485_760,
    max_file_size: int = 104_857_600,
    max_depth: int = 1,
    str_min_len: int = 4,
    str_max_samples: int = 40,
    str_lang: bool = True,
    str_max_lang_detect: int = 100,
    str_classify: bool = True,
    str_max_classify: int = 200,
    str_max_ioc_per_string: int = 16,
    **kwargs,
):
    # Accept legacy kw aliases with underscores for compatibility
    max_read_bytes = kwargs.get("_max_read_bytes", max_read_bytes)
    max_file_size = kwargs.get("_max_file_size", max_file_size)
    max_depth = kwargs.get("_max_recursion_depth", max_depth)
    try:
        art = _triage_analyze_native(
            path,
            max_read_bytes,
            max_file_size,
            max_depth,
            str_min_len,
            str_max_samples,
            str_lang,
            str_max_lang_detect,
            str_classify,
            str_max_classify,
            str_max_ioc_per_string,
        )
        return _ArtifactProxy(art)
    except TypeError:
        art = _triage_analyze_native(path, max_read_bytes, max_file_size, max_depth)
        return _ArtifactProxy(art)


# attach and re-export
setattr(_triage_mod, "triage", _triage_wrapper)
setattr(_triage_mod, "analyze_path", _triage_wrapper)
triage = _triage_mod

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

# Some callers expect `__import__('glaurung').glaurung` to resolve to the package
glaurung = _sys.modules[__name__]

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
