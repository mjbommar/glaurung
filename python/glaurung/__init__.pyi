"""
Python type stubs for the glaurung binary analysis library.

This module provides comprehensive binary analysis capabilities including
triage, disassembly, control flow analysis, and more.
"""

from __future__ import annotations
from typing import Any, Optional, List, Dict, Union
import enum

# Re-export triage submodule
from . import triage

# Top-level symbols module (alias to triage.symbols)
class _SymbolsModule:
    def list_symbols(
        self,
        path: str,
        max_read_bytes: int = 10_485_760,
        max_file_size: int = 104_857_600,
    ) -> tuple[list[str], list[str], list[str], list[str], list[str]]: ...
    def imphash(
        self,
        path: str,
        max_read_bytes: int = 10_485_760,
        max_file_size: int = 104_857_600,
    ) -> Optional[str]: ...
    def analyze_exports(
        self,
        path: str,
        max_read_bytes: int = 10_485_760,
        max_file_size: int = 104_857_600,
    ) -> Optional[tuple[int, int, int]]: ...
    def analyze_env(
        self,
        path: str,
        max_read_bytes: int = 10_485_760,
        max_file_size: int = 104_857_600,
    ) -> dict[str, object]: ...

symbols: _SymbolsModule

# ============================================================================
# Enumerations
# ============================================================================

class AddressKind(enum.Enum):
    """Type of address representation."""

    VA: AddressKind  # Virtual Address
    FileOffset: AddressKind  # File offset
    RVA: AddressKind  # Relative Virtual Address
    Physical: AddressKind  # Physical memory address
    Relative: AddressKind  # Relative to some base
    Symbolic: AddressKind  # Symbolic reference

class AddressSpaceKind(enum.Enum):
    """Type of address space."""

    Default: AddressSpaceKind
    Overlay: AddressSpaceKind
    Stack: AddressSpaceKind
    Heap: AddressSpaceKind
    MMIO: AddressSpaceKind  # Memory-mapped I/O
    Other: AddressSpaceKind

class Format(enum.Enum):
    """Binary file format."""

    Unknown: Format
    ELF: Format
    PE: Format
    MachO: Format
    Wasm: Format
    COFF: Format
    Archive: Format
    Raw: Format
    PythonBytecode: Format

class Arch(enum.Enum):
    """Processor architecture."""

    Unknown: Arch
    X86: Arch
    X86_64: Arch
    ARM: Arch
    ARM64: Arch
    AArch64: Arch
    MIPS: Arch
    MIPS64: Arch
    PPC: Arch
    PPC64: Arch
    SPARC: Arch
    RISCV: Arch
    RISCV64: Arch
    def bits(self) -> int: ...
    def is_64_bit(self) -> bool: ...

class Endianness(enum.Enum):
    """Byte order."""

    Little: Endianness
    Big: Endianness
    Native: Endianness

class IdKind(enum.Enum):
    """Type of identifier."""

    Binary: IdKind
    Function: IdKind
    BasicBlock: IdKind
    Symbol: IdKind
    Section: IdKind
    Segment: IdKind
    Instruction: IdKind
    Variable: IdKind
    DataType: IdKind
    Entity: IdKind

class SourceKind(enum.Enum):
    """Source of analysis information."""

    Static: SourceKind
    Dynamic: SourceKind
    Heuristic: SourceKind
    External: SourceKind

class SectionPerms(enum.Enum):
    """Section permissions."""

    NONE: int
    READ: int
    WRITE: int
    EXECUTE: int

class Perms(enum.Enum):
    """Segment permissions."""

    NONE: int
    READ: int
    WRITE: int
    EXECUTE: int

class SymbolKind(enum.Enum):
    """Type of symbol."""

    Unknown: SymbolKind
    Function: SymbolKind
    Data: SymbolKind
    Section: SymbolKind
    File: SymbolKind
    Object: SymbolKind
    Common: SymbolKind
    TLS: SymbolKind

class SymbolBinding(enum.Enum):
    """Symbol binding/linkage."""

    Local: SymbolBinding
    Global: SymbolBinding
    Weak: SymbolBinding
    Unique: SymbolBinding

class SymbolVisibility(enum.Enum):
    """Symbol visibility."""

    Default: SymbolVisibility
    Public: SymbolVisibility
    Private: SymbolVisibility
    Internal: SymbolVisibility
    Hidden: SymbolVisibility
    Protected: SymbolVisibility

class SymbolSource(enum.Enum):
    """Source of symbol information."""

    Binary: SymbolSource
    Debug: SymbolSource
    DebugInfo: SymbolSource
    Import: SymbolSource
    ImportTable: SymbolSource
    Export: SymbolSource
    ExportTable: SymbolSource
    Heuristic: SymbolSource
    Dynamic: SymbolSource
    Pdb: SymbolSource
    Dwarf: SymbolSource
    Ai: SymbolSource

class OperandKind(enum.Enum):
    """Type of instruction operand."""

    Register: OperandKind
    Immediate: OperandKind
    Memory: OperandKind
    Displacement: OperandKind

class Access(enum.Enum):
    """Memory access type."""

    Read: Access
    Write: Access
    Execute: Access

class SideEffect(enum.Enum):
    """Instruction side effects."""

    NONE: int
    MODIFIES_FLAGS: int
    MODIFIES_STACK: int
    MODIFIES_MEMORY: int
    SYSTEM_CALL: int

class RegisterKind(enum.Enum):
    """Type of register."""

    GeneralPurpose: RegisterKind
    FloatingPoint: RegisterKind
    Vector: RegisterKind
    Flag: RegisterKind
    Control: RegisterKind
    Debug: RegisterKind
    Segment: RegisterKind

class Architecture(enum.Enum):
    """Disassembler architecture."""

    X86: Architecture
    X86_64: Architecture
    ARM: Architecture
    ARM64: Architecture
    MIPS: Architecture
    MIPS64: Architecture
    PPC: Architecture
    PPC64: Architecture
    RISCV: Architecture
    RISCV64: Architecture
    Unknown: Architecture
    def address_bits(self) -> int: ...
    def is_64_bit(self) -> bool: ...

class StringEncoding(enum.Enum):
    """String encoding type."""

    ASCII: StringEncoding
    UTF8: StringEncoding
    UTF16LE: StringEncoding
    UTF16BE: StringEncoding
    UTF32LE: StringEncoding
    UTF32BE: StringEncoding

class StringClassification(enum.Enum):
    """String content classification."""

    Unknown: StringClassification
    Code: StringClassification
    Path: StringClassification
    URL: StringClassification
    Email: StringClassification
    Registry: StringClassification
    GUID: StringClassification
    Version: StringClassification
    Error: StringClassification
    Debug: StringClassification

class PatternType(enum.Enum):
    """Pattern matching type."""

    Yara: PatternType
    Regex: PatternType
    Binary: PatternType
    Fuzzy: PatternType

class RelocationType(enum.Enum):
    """Type of relocation."""

    Absolute: RelocationType
    Relative: RelocationType
    HighLow: RelocationType
    Dir64: RelocationType
    ThumbCall: RelocationType
    ARMCall: RelocationType

class FunctionKind(enum.Enum):
    """Type of function."""

    Normal: FunctionKind
    Imported: FunctionKind
    Exported: FunctionKind
    External: FunctionKind
    Library: FunctionKind
    Thunk: FunctionKind
    Unknown: FunctionKind

class ControlFlowEdgeKind(enum.Enum):
    """Type of control flow edge."""

    Fallthrough: ControlFlowEdgeKind
    Branch: ControlFlowEdgeKind
    Call: ControlFlowEdgeKind
    Return: ControlFlowEdgeKind

class CallType(enum.Enum):
    """Type of function call."""

    Direct: CallType
    Indirect: CallType
    Virtual: CallType
    Tail: CallType
    Recursive: CallType
    External: CallType

class ReferenceKind(enum.Enum):
    """Type of reference."""

    Call: ReferenceKind
    Jump: ReferenceKind
    Branch: ReferenceKind
    Return: ReferenceKind
    Read: ReferenceKind
    Write: ReferenceKind
    DataRef: ReferenceKind
    Unknown: ReferenceKind

class UnresolvedReferenceKind(enum.Enum):
    """Type of unresolved reference."""

    External: UnresolvedReferenceKind
    Dynamic: UnresolvedReferenceKind
    Virtual: UnresolvedReferenceKind
    Computed: UnresolvedReferenceKind

class LogLevel(enum.Enum):
    """Logging level."""

    Trace: LogLevel
    Debug: LogLevel
    Info: LogLevel
    Warn: LogLevel
    Error: LogLevel

class DataTypeKind(enum.Enum):
    """Type of data type."""

    Primitive: DataTypeKind
    Pointer: DataTypeKind
    Array: DataTypeKind
    Struct: DataTypeKind
    Union: DataTypeKind
    Enum: DataTypeKind
    Function: DataTypeKind
    Typedef: DataTypeKind

    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...

class StorageLocation:
    """Storage location of a variable."""

    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    @staticmethod
    def register(name: str) -> StorageLocation: ...
    @staticmethod
    def stack(offset: int, frame_base: Optional[str] = None) -> StorageLocation: ...
    @staticmethod
    def heap(address: Address) -> StorageLocation: ...
    @staticmethod
    def global_(address: Address) -> StorageLocation: ...

# ============================================================================
# Core Types
# ============================================================================

class Address:
    """Represents an address in binary analysis."""

    kind: AddressKind
    value: int
    bits: int
    space: Optional[str]
    symbol_ref: Optional[str]

    def __init__(
        self,
        kind: AddressKind,
        value: int,
        bits: int,
        space: Optional[str] = None,
        symbol_ref: Optional[str] = None,
    ) -> None: ...
    def is_valid(self) -> bool: ...
    def __add__(self, offset: int) -> Address: ...
    def __sub__(self, offset: int) -> Address: ...
    def __eq__(self, other: object) -> bool: ...
    def __lt__(self, other: Address) -> bool: ...
    def __le__(self, other: Address) -> bool: ...
    def __gt__(self, other: Address) -> bool: ...
    def __ge__(self, other: Address) -> bool: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    def __hash__(self) -> int: ...
    # Python-only helpers
    def is_valid_py(self) -> bool: ...
    def to_rva_py(self, image_base: int) -> Optional[Address]: ...
    def to_va_py(self, image_base: int) -> Optional[Address]: ...
    def file_offset_to_va_py(
        self, section_rva: int, image_base: int
    ) -> Optional[Address]: ...
    def va_to_file_offset_py(
        self, section_va: int, section_file_offset: int
    ) -> Optional[Address]: ...
    def to_json_py(self) -> str: ...
    @staticmethod
    def from_json_py(json_str: str) -> Address: ...
    def to_binary_py(self) -> bytes: ...
    @staticmethod
    def from_binary_py(data: bytes) -> Address: ...

class AddressRange:
    """Represents a range of addresses."""

    start: Address
    size: int
    alignment: Optional[int]

    def __init__(
        self,
        start: Address,
        size: int,
        alignment: Optional[int] = None,
    ) -> None: ...
    @property
    def end(self) -> Address: ...
    def contains_address(self, address: Address) -> bool: ...
    def contains_range(self, other: AddressRange) -> bool: ...
    def overlaps(self, other: AddressRange) -> bool: ...
    def intersection(self, other: AddressRange) -> Optional[AddressRange]: ...
    def is_valid_py(self) -> bool: ...
    def contains_range_py(self, other: AddressRange) -> bool: ...
    def overlaps_py(self, other: AddressRange) -> bool: ...
    def intersection_py(self, other: AddressRange) -> Optional[AddressRange]: ...
    def is_empty(self) -> bool: ...
    def size_bytes(self) -> int: ...

class AddressSpace:
    """Represents an address space."""

    name: str
    kind: AddressSpaceKind
    size: Optional[int]
    base_space: Optional[str]

    def __init__(
        self,
        name: str,
        kind: AddressSpaceKind,
        size: Optional[int] = None,
        base_space: Optional[str] = None,
    ) -> None: ...
    def is_valid(self) -> bool: ...
    # Python-only helpers
    def is_valid_py(self) -> bool: ...
    @property
    def effective_size(self) -> Optional[int]: ...
    def is_overlay(self) -> bool: ...
    def has_base_space(self) -> bool: ...

class Id:
    """Unique identifier for binary analysis entities."""

    value: str
    kind: IdKind

    def __init__(self, value: str, kind: IdKind) -> None: ...
    def is_valid(self) -> bool: ...
    def __str__(self) -> str: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class IdGenerator:
    """Generator for unique identifiers."""
    @staticmethod
    def binary_from_content(content: bytes, path: Optional[str] = None) -> Id: ...
    @staticmethod
    def binary_from_uuid(uuid: str) -> Id: ...
    @staticmethod
    def function(binary_id: str, address: str) -> Id: ...
    @staticmethod
    def basic_block(binary_id: str, address: str) -> Id: ...
    @staticmethod
    def symbol(name: str, address: Optional[str] = None) -> Id: ...

class Hashes:
    """Cryptographic hashes of binary content."""

    sha256: Optional[str]
    md5: Optional[str]
    sha1: Optional[str]
    additional: Optional[Dict[str, str]]

    def __init__(
        self,
        sha256: Optional[str] = None,
        md5: Optional[str] = None,
        sha1: Optional[str] = None,
        additional: Optional[Dict[str, str]] = None,
    ) -> None: ...
    def has_sha256(self) -> bool: ...
    def has_any_hash(self) -> bool: ...
    def is_valid_py(self) -> bool: ...
    def get_hash(self, name: str) -> Optional[str]: ...
    def set_hash(self, name: str, value: str) -> None: ...

class Binary:
    """Represents a binary file."""

    id: str
    path: str
    format: Format
    arch: Arch
    bits: int
    endianness: Endianness
    entry_points: List[Address]
    size_bytes: int
    hashes: Optional[Hashes]
    uuid: Optional[str]
    timestamps: Optional[Dict[str, int]]

    def __init__(
        self,
        id: str,
        path: str,
        format: Format,
        arch: Arch,
        bits: int,
        endianness: Endianness,
        entry_points: List[Address],
        size_bytes: int,
        hashes: Optional[Hashes] = None,
        uuid: Optional[str] = None,
        timestamps: Optional[Dict[str, int]] = None,
    ) -> None: ...
    def is_valid_py(self) -> bool: ...
    def is_64_bit(self) -> bool: ...
    def has_entry_points(self) -> bool: ...
    def entry_point_count(self) -> int: ...
    def primary_entry_point(self) -> Optional[Address]: ...
    def has_hashes(self) -> bool: ...
    def get_timestamp(self, key: str) -> Optional[int]: ...
    def set_timestamp(self, key: str, value: int) -> None: ...
    def to_json_py(self) -> str: ...
    @staticmethod
    def from_json_py(s: str) -> Binary: ...

class ToolMetadata:
    """Metadata about analysis tools."""

    name: str
    version: str
    parameters: Optional[Dict[str, str]]
    source_kind: Optional[SourceKind]

    def __init__(
        self,
        name: str,
        version: str,
        parameters: Optional[Dict[str, str]] = None,
        source_kind: Optional[SourceKind] = None,
    ) -> None: ...
    # Python helpers
    def has_parameters(self) -> bool: ...
    def parameter_count(self) -> int: ...
    def set_parameter(self, key: str, value: str) -> None: ...
    def remove_parameter(self, key: str) -> Optional[str]: ...
    def set_parameters(self, params: Dict[str, str]) -> None: ...
    def set_parameters_py(self, params: Dict[str, str]) -> None: ...
    def set_source_kind_py(self, kind: SourceKind) -> None: ...
    def is_valid(self) -> bool: ...
    def get_parameter(self, key: str) -> Optional[str]: ...
    def to_json(self) -> str: ...
    @staticmethod
    def from_json(s: str) -> ToolMetadata: ...
    def to_binary(self) -> bytes: ...
    @staticmethod
    def from_binary(data: bytes) -> ToolMetadata: ...

class Artifact:
    """Analysis artifact container."""

    id: str
    tool: ToolMetadata
    created_at: str
    input_refs: List[str]
    schema_version: str
    data_type: str
    data: str
    meta: str

    def __init__(
        self,
        id: str,
        tool: ToolMetadata,
        data_type: str,
        data: str,
        input_refs: Optional[List[str]] = None,
        schema_version: str = "1.0.0",
        meta: Optional[str] = None,
    ) -> None: ...
    def is_valid(self) -> bool: ...
    def input_ref_count(self) -> int: ...
    def has_input_refs(self) -> bool: ...
    def add_input_ref(self, ref: str) -> None: ...
    def remove_input_ref(self, ref: str) -> bool: ...
    def to_json(self) -> str: ...
    @staticmethod
    def from_json(s: str) -> Artifact: ...
    def to_binary(self) -> bytes: ...
    @staticmethod
    def from_binary(data: bytes) -> Artifact: ...

class Section:
    """Binary section."""

    id: str
    name: Optional[str]
    range: AddressRange
    file_offset: int
    perms: Optional[SectionPerms]
    flags: int
    section_type: Optional[str]

    def __init__(
        self,
        id: str,
        name: Optional[str],
        range: AddressRange,
        file_offset: int,
        perms: Optional[SectionPerms] = None,
        flags: int = 0,
        section_type: Optional[str] = None,
    ) -> None: ...

class Segment:
    """Binary segment."""

    id: str
    name: Optional[str]
    virtual_range: AddressRange
    file_range: Optional[AddressRange]
    perms: Perms
    flags: int
    segment_type: Optional[str]

    def __init__(
        self,
        id: str,
        name: Optional[str],
        virtual_range: AddressRange,
        file_range: Optional[AddressRange],
        perms: Perms,
        flags: int = 0,
        segment_type: Optional[str] = None,
    ) -> None: ...

class Symbol:
    """Binary symbol."""

    id: str
    name: str
    address: Optional[Address]
    size: Optional[int]
    kind: SymbolKind
    binding: SymbolBinding
    visibility: SymbolVisibility
    source: SymbolSource

    def __init__(
        self,
        id: str,
        name: str,
        kind: SymbolKind,
        source: SymbolSource,
        address: Optional[Address] = None,
        size: Optional[int] = None,
        binding: SymbolBinding = SymbolBinding.Local,
        visibility: SymbolVisibility = SymbolVisibility.Default,
    ) -> None: ...
    def display_name(self) -> str: ...
    def is_object(self) -> bool: ...

class Relocation:
    """Binary relocation."""

    id: str
    address: Address
    relocation_type: RelocationType
    symbol: Optional[str]
    addend: Optional[int]

    def __init__(
        self,
        id: str,
        address: Address,
        relocation_type: RelocationType,
        symbol: Optional[str] = None,
        addend: Optional[int] = None,
    ) -> None: ...

class Instruction:
    """Disassembled instruction."""

    address: Address
    size: int
    mnemonic: str
    operands: List[Operand]
    bytes: bytes
    prefix: Optional[str]
    side_effects: int

    def __init__(
        self,
        address: Address,
        size: int,
        mnemonic: str,
        operands: List[Operand],
        bytes: bytes,
        prefix: Optional[str] = None,
        side_effects: int = 0,
    ) -> None: ...

class Operand:
    """Instruction operand."""

    kind: OperandKind
    value: Union[str, int, Address]
    size: Optional[int]
    access: Optional[Access]

    def __init__(
        self,
        kind: OperandKind,
        value: Union[str, int, Address],
        size: Optional[int] = None,
        access: Optional[Access] = None,
    ) -> None: ...

class Register:
    """Processor register."""

    name: str
    kind: RegisterKind
    size: int
    parent: Optional[str]

    def __init__(
        self,
        name: str,
        kind: RegisterKind,
        size: int,
        parent: Optional[str] = None,
    ) -> None: ...

class DisassemblerError(enum.Enum):
    """Disassembler error kinds."""

    InvalidInstruction: DisassemblerError
    InvalidAddress: DisassemblerError
    InsufficientBytes: DisassemblerError
    UnsupportedInstruction: DisassemblerError
    InternalError: DisassemblerError

class DisassemblerConfig:
    """Disassembler configuration."""

    architecture: Architecture
    endianness: Endianness
    options: Dict[str, Any]

    def __init__(
        self,
        architecture: Architecture,
        endianness: Endianness = Endianness.Little,
        options: Optional[Dict[str, Any]] = None,
    ) -> None: ...

class StringLiteral:
    """String literal found in binary."""

    id: str
    value: str
    address: Address
    encoding: StringEncoding
    length: int
    classification: Optional[StringClassification]

    def __init__(
        self,
        id: str,
        value: str,
        address: Address,
        encoding: StringEncoding,
        length: int,
        classification: Optional[StringClassification] = None,
    ) -> None: ...

class Pattern:
    """Pattern match result."""

    id: str
    definition: PatternDefinition
    matches: List[YaraMatch]

    def __init__(
        self,
        id: str,
        definition: PatternDefinition,
        matches: List[YaraMatch],
    ) -> None: ...

class PatternDefinition:
    """Pattern definition."""

    name: str
    pattern_type: PatternType
    pattern: str
    metadata: Optional[Dict[str, MetadataValue]]

    def __init__(
        self,
        name: str,
        pattern_type: PatternType,
        pattern: str,
        metadata: Optional[Dict[str, MetadataValue]] = None,
    ) -> None: ...

class YaraMatch:
    """YARA pattern match."""

    offset: int
    length: int
    identifier: str

    def __init__(
        self,
        offset: int,
        length: int,
        identifier: str,
    ) -> None: ...

class MetadataValue:
    """Pattern metadata value."""

    value: Union[str, int, bool]

    def __init__(self, value: Union[str, int, bool]) -> None: ...

class BasicBlock:
    """Basic block in control flow."""

    id: str
    start_address: Address
    end_address: Address
    instruction_count: int
    successor_ids: List[str]
    predecessor_ids: List[str]
    relationships_known: bool

    def __init__(
        self,
        id: str,
        start_address: Address,
        end_address: Address,
        instruction_count: int,
        successor_ids: Optional[List[str]] = None,
        predecessor_ids: Optional[List[str]] = None,
    ) -> None: ...
    def size_bytes(self) -> int: ...
    # Python-only helpers
    def is_valid_py(self) -> bool: ...
    @property
    def effective_size(self) -> Optional[int]: ...
    def contains_address(self, addr: Address) -> bool: ...
    def is_entry_block(self) -> bool: ...
    def is_exit_block(self) -> bool: ...
    def successor_count(self) -> int: ...
    def predecessor_count(self) -> int: ...
    def has_successor(self, id: str) -> bool: ...
    def has_predecessor(self, id: str) -> bool: ...
    def is_single_instruction(self) -> bool: ...
    def add_successor(self, id: str) -> None: ...
    def remove_successor(self, id: str) -> None: ...
    def add_predecessor(self, id: str) -> None: ...
    def remove_predecessor(self, id: str) -> None: ...
    def summary(self) -> str: ...
    def validate(self) -> None: ...

class Function:
    """Function in binary."""

    id: str
    name: str
    entry_point: Address
    kind: FunctionKind
    size: Optional[int]
    range: Optional[AddressRange]
    flags: int
    module: Optional[str]
    ordinal: Optional[int]
    signature: Optional[str]
    calling_convention: Optional[str]
    stack_frame_size: Optional[int]
    local_var_count: Optional[int]
    local_vars_size: Optional[int]
    saved_regs_size: Optional[int]
    max_call_depth: Optional[int]
    basic_block_count: Optional[int]
    instruction_count: Optional[int]
    cyclomatic_complexity: Optional[int]
    cross_references_to: Optional[List[Address]]
    cross_references_from: Optional[List[Address]]
    is_thunk: bool
    thunk_target: Optional[Address]

    def __init__(
        self,
        name: str,
        entry_point: Address,
        kind: FunctionKind = FunctionKind.Unknown,
        range: Optional[AddressRange] = None,
        flags: int = 0,
        module: Optional[str] = None,
        ordinal: Optional[int] = None,
        calling_convention: Optional[str] = None,
        signature: Optional[str] = None,
        stack_frame_size: Optional[int] = None,
        local_vars_size: Optional[int] = None,
        saved_regs_size: Optional[int] = None,
        max_call_depth: Optional[int] = None,
        thunk_target: Optional[Address] = None,
    ) -> None: ...
    def has_flag(self, flag: int) -> bool: ...
    def to_json(self) -> str: ...
    @staticmethod
    def from_json(s: str) -> Function: ...

class FunctionFlags:
    """Function flags constants."""

    NONE: int
    NO_RETURN: int
    HAS_SEH: int
    HAS_EH: int
    IS_VARIADIC: int
    IS_INLINE: int
    IS_NAKED: int
    IS_CONSTRUCTOR: int
    IS_DESTRUCTOR: int

class Reference:
    """Cross-reference between addresses."""

    id: str
    from_address: Address
    to_target: ReferenceTarget
    kind: ReferenceKind

    def __init__(
        self,
        id: str,
        from_address: Address,
        to_target: ReferenceTarget,
        kind: ReferenceKind,
    ) -> None: ...

class ReferenceTarget:
    """Target of a reference."""

    address: Optional[Address]
    symbol: Optional[str]
    unresolved: Optional[UnresolvedReferenceKind]

    def __init__(
        self,
        address: Optional[Address] = None,
        symbol: Optional[str] = None,
        unresolved: Optional[UnresolvedReferenceKind] = None,
    ) -> None: ...

class ControlFlowEdge:
    """Edge in control flow graph."""

    from_block_id: str
    to_block_id: str
    kind: ControlFlowEdgeKind
    confidence: float

    def __init__(
        self,
        from_block_id: str,
        to_block_id: str,
        kind: ControlFlowEdgeKind,
        confidence: Optional[float] = None,
    ) -> None: ...

class ControlFlowGraph:
    """Control flow graph for a function."""

    function_id: Optional[str]
    block_ids: List[str]
    edges: List[ControlFlowEdge]

    def __init__(self, function_id: Optional[str] = None) -> None: ...
    def add_block(self, block_id: str) -> None: ...
    def add_blocks(self, block_ids: List[str]) -> None: ...
    def add_edge(self, edge: ControlFlowEdge) -> None: ...
    def get_block_ids(self) -> List[str]: ...
    def get_edges(self) -> List[ControlFlowEdge]: ...
    def compute_stats(self) -> ControlFlowGraphStats: ...
    def block_count(self) -> int: ...
    def edge_count(self) -> int: ...

class ControlFlowGraphStats:
    """Statistics for control flow graph."""

    block_count: int
    edge_count: int
    entry_blocks: int
    exit_blocks: int
    cyclomatic_complexity: int
    has_cycles: bool
    edge_kind_counts: Dict[str, int]

    def __init__(
        self,
        block_count: int,
        edge_count: int,
        entry_blocks: int,
        exit_blocks: int,
        cyclomatic_complexity: int,
        has_cycles: bool,
        edge_kind_counts: Dict[str, int],
    ) -> None: ...

class CallGraphEdge:
    """Edge in call graph."""

    caller: str  # Caller function ID
    callee: str  # Callee function ID
    call_sites: List[Address]
    call_type: CallType
    confidence: Optional[float]

    def __init__(
        self,
        caller: str,
        callee: str,
        call_sites: List[Address],
        call_type: CallType,
        confidence: Optional[float] = None,
    ) -> None: ...

class CallGraph:
    """Call graph for binary."""

    nodes: List[str]  # Function IDs
    edges: List[CallGraphEdge]

    def __init__(self) -> None: ...
    def add_node(self, node_id: str) -> None: ...
    def add_edge(self, edge: CallGraphEdge) -> None: ...
    def get_nodes(self) -> List[str]: ...
    def get_edges(self) -> List[CallGraphEdge]: ...
    def get_callees(self, function_id: str) -> List[str]: ...
    def get_callers(self, function_id: str) -> List[str]: ...
    def compute_stats(self) -> CallGraphStats: ...
    def function_count(self) -> int: ...
    def edge_count(self) -> int: ...

class CallGraphStats:
    """Statistics for call graph."""

    function_count: int
    edge_count: int
    max_in_degree: int
    max_out_degree: int
    has_cycles: bool
    strongly_connected_components: int

    def __init__(
        self,
        function_count: int,
        edge_count: int,
        max_in_degree: int,
        max_out_degree: int,
        has_cycles: bool,
        strongly_connected_components: int,
    ) -> None: ...

class Variable:
    """Variable in binary analysis."""

    id: str
    name: Optional[str]
    type_id: str
    storage: StorageLocation
    liveness_range: Optional[AddressRange]
    source: Optional[str]

    def __init__(
        self,
        id: str,
        type_id: str,
        storage: StorageLocation,
        name: Optional[str] = None,
        liveness_range: Optional[AddressRange] = None,
        source: Optional[str] = None,
    ) -> None: ...
    @staticmethod
    def register(
        id: str,
        name: Optional[str],
        type_id: str,
        register_name: str,
        liveness_range: Optional[AddressRange] = None,
        source: Optional[str] = None,
    ) -> Variable: ...
    @staticmethod
    def stack(
        id: str,
        name: Optional[str],
        type_id: str,
        offset: int,
        frame_base: Optional[str] = None,
        liveness_range: Optional[AddressRange] = None,
        source: Optional[str] = None,
    ) -> Variable: ...
    @staticmethod
    def heap(
        id: str,
        name: Optional[str],
        type_id: str,
        address: Address,
        liveness_range: Optional[AddressRange] = None,
        source: Optional[str] = None,
    ) -> Variable: ...
    @staticmethod
    def global_(
        id: str,
        name: Optional[str],
        type_id: str,
        address: Address,
        liveness_range: Optional[AddressRange] = None,
        source: Optional[str] = None,
    ) -> Variable: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

    # Property getters
    @property
    def get_id(self) -> str: ...
    @property
    def get_name(self) -> Optional[str]: ...
    @property
    def get_type_id(self) -> str: ...
    @property
    def get_storage(self) -> StorageLocation: ...
    @property
    def get_liveness_range(self) -> Optional[AddressRange]: ...
    @property
    def get_source(self) -> Optional[str]: ...

    # Methods
    def is_valid_py(self) -> bool: ...
    def is_register_py(self) -> bool: ...
    def is_stack_py(self) -> bool: ...
    def is_heap_py(self) -> bool: ...
    def is_global_py(self) -> bool: ...
    def register_name_py(self) -> Optional[str]: ...
    def stack_offset_py(self) -> Optional[int]: ...
    def frame_base_py(self) -> Optional[str]: ...
    def address_py(self) -> Optional[Address]: ...
    def is_live_at_py(self, address: Address) -> bool: ...
    def liveness_size_py(self) -> Optional[int]: ...
    def to_json(self) -> str: ...
    @staticmethod
    def from_json(json_str: str) -> Variable: ...

class DataType:
    """Data type definition."""

    id: str
    name: str
    kind: DataTypeKind
    size: int
    alignment: Optional[int]
    type_data: TypeData
    source: Optional[str]

    def __init__(
        self,
        id: str,
        name: str,
        kind: DataTypeKind,
        size: int,
        alignment: Optional[int] = None,
        source: Optional[str] = None,
    ) -> None: ...
    @staticmethod
    def primitive(
        id: str,
        name: str,
        size: int,
        alignment: Optional[int] = None,
        source: Optional[str] = None,
    ) -> DataType: ...
    @staticmethod
    def pointer(
        id: str,
        name: str,
        size: int,
        alignment: Optional[int],
        base_type_id: str,
        attributes: List[str],
        source: Optional[str] = None,
    ) -> DataType: ...
    @staticmethod
    def array(
        id: str,
        name: str,
        size: int,
        alignment: Optional[int],
        base_type_id: str,
        count: int,
        source: Optional[str] = None,
    ) -> DataType: ...
    @staticmethod
    def struct_(
        id: str,
        name: str,
        size: int,
        alignment: Optional[int],
        fields: List[Field],
        source: Optional[str] = None,
    ) -> DataType: ...
    @staticmethod
    def union(
        id: str,
        name: str,
        size: int,
        alignment: Optional[int],
        fields: List[Field],
        source: Optional[str] = None,
    ) -> DataType: ...
    @staticmethod
    def enum_(
        id: str,
        name: str,
        size: int,
        alignment: Optional[int],
        underlying_type_id: str,
        members: List[EnumMember],
        source: Optional[str] = None,
    ) -> DataType: ...
    @staticmethod
    def function(
        id: str,
        name: str,
        size: int,
        alignment: Optional[int],
        return_type_id: Optional[str],
        parameter_type_ids: List[str],
        variadic: bool,
        source: Optional[str] = None,
    ) -> DataType: ...
    @staticmethod
    def typedef(
        id: str,
        name: str,
        size: int,
        alignment: Optional[int],
        base_type_id: str,
        source: Optional[str] = None,
    ) -> DataType: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

    # Property getters
    @property
    def get_id(self) -> str: ...
    @property
    def get_name(self) -> str: ...
    @property
    def get_kind(self) -> DataTypeKind: ...
    @property
    def get_size(self) -> int: ...
    @property
    def get_alignment(self) -> Optional[int]: ...
    @property
    def get_source(self) -> Optional[str]: ...

    # Methods
    def is_valid_py(self) -> bool: ...
    def is_pointer_py(self) -> bool: ...
    def is_array_py(self) -> bool: ...
    def is_function_py(self) -> bool: ...
    def is_composite_py(self) -> bool: ...
    def base_type_id_py(self) -> Optional[str]: ...
    def return_type_py(self) -> Optional[str]: ...
    def to_json(self) -> str: ...
    @staticmethod
    def from_json(json_str: str) -> DataType: ...

class TypeData(enum.Enum):
    """Type-specific data for DataType."""

    Primitive: TypeData
    Pointer: TypeData
    Array: TypeData
    Struct: TypeData
    Union: TypeData
    Enum: TypeData
    Function: TypeData
    Typedef: TypeData

class Field:
    """Field in struct/union."""

    name: str
    type_id: str
    offset: int

    def __init__(
        self,
        name: str,
        type_id: str,
        offset: int,
    ) -> None: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    @property
    def get_name(self) -> str: ...
    @property
    def get_type_id(self) -> str: ...
    @property
    def get_offset(self) -> int: ...

class EnumMember:
    """Enum member."""

    name: str
    value: int

    def __init__(
        self,
        name: str,
        value: int,
    ) -> None: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    @property
    def get_name(self) -> str: ...
    @property
    def get_value(self) -> int: ...

# ============================================================================
# Logging Functions
# ============================================================================

def init_logging(json: bool = False) -> None:
    """Initialize the logging system.

    Args:
        json: If True, use JSON format for logs. If False, use regular format.
    """
    ...

def log_message(level: LogLevel, message: str) -> None:
    """Log a message at the specified level."""
    ...

# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    # Submodules
    "triage",
    # Enumerations
    "AddressKind",
    "AddressSpaceKind",
    "Format",
    "Arch",
    "Endianness",
    "IdKind",
    "SourceKind",
    "SectionPerms",
    "Perms",
    "SymbolKind",
    "SymbolBinding",
    "SymbolVisibility",
    "SymbolSource",
    "OperandKind",
    "Access",
    "SideEffect",
    "RegisterKind",
    "Architecture",
    "StringEncoding",
    "StringClassification",
    "PatternType",
    "RelocationType",
    "FunctionKind",
    "ControlFlowEdgeKind",
    "CallType",
    "ReferenceKind",
    "UnresolvedReferenceKind",
    "LogLevel",
    "DataTypeKind",
    "StorageLocation",
    # Core Types
    "Address",
    "AddressRange",
    "AddressSpace",
    "Id",
    "IdGenerator",
    "Hashes",
    "Binary",
    "ToolMetadata",
    "Artifact",
    "Section",
    "Segment",
    "Symbol",
    "Relocation",
    "Instruction",
    "Operand",
    "Register",
    "DisassemblerError",
    "DisassemblerConfig",
    "StringLiteral",
    "Pattern",
    "PatternDefinition",
    "YaraMatch",
    "MetadataValue",
    "BasicBlock",
    "Function",
    "Reference",
    "ReferenceTarget",
    "ControlFlowEdge",
    "ControlFlowGraph",
    "ControlFlowGraphStats",
    "CallGraphEdge",
    "CallGraph",
    "CallGraphStats",
    "Variable",
    "DataType",
    "TypeData",
    "Field",
    "EnumMember",
    # Functions
    "init_logging",
    "log_message",
]
