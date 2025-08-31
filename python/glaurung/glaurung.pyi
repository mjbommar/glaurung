from __future__ import annotations

import enum
from typing import Optional, Dict, List, Any


class AddressKind(enum.Enum):
    VA: AddressKind
    FileOffset: AddressKind
    RVA: AddressKind
    Physical: AddressKind
    Relative: AddressKind
    Symbolic: AddressKind


class Address:
    kind: AddressKind
    value: int
    space: Optional[str]
    bits: int
    symbol_ref: Optional[str]

    def __init__(
        self,
        kind: AddressKind,
        value: int,
        bits: int,
        space: Optional[str] = ...,
        symbol_ref: Optional[str] = ...,
    ) -> None: ...

    def is_valid_py(self) -> bool: ...

    def add_py(self, other: int) -> Address: ...
    def sub_py(self, other: int) -> Address: ...
    def __add__(self, other: int) -> Address: ...
    def __sub__(self, other: int) -> Address: ...

    def to_rva_py(self, image_base: int) -> Optional[Address]: ...
    def to_va_py(self, image_base: int) -> Optional[Address]: ...
    def file_offset_to_va_py(self, section_rva: int, image_base: int) -> Optional[Address]: ...
    def va_to_file_offset_py(self, section_va: int, section_file_offset: int) -> Optional[Address]: ...

    def to_json_py(self) -> str: ...
    @staticmethod
    def from_json_py(json_str: str) -> Address: ...
    def to_binary_py(self) -> bytes: ...
    @staticmethod
    def from_binary_py(data: bytes) -> Address: ...

    def __lt__(self, other: Address) -> bool: ...
    def __le__(self, other: Address) -> bool: ...
    def __gt__(self, other: Address) -> bool: ...
    def __ge__(self, other: Address) -> bool: ...
    def __eq__(self, other: object) -> bool: ...


class AddressRange:
    start: Address
    size: int
    alignment: Optional[int]

    def __init__(self, start: Address, size: int, alignment: Optional[int] = ...) -> None: ...

    @property
    def end(self) -> Address: ...

    def contains_address(self, address: Address) -> bool: ...
    def is_valid_py(self) -> bool: ...
    def contains_range_py(self, other: AddressRange) -> bool: ...
    def overlaps_py(self, other: AddressRange) -> bool: ...
    def intersection_py(self, other: AddressRange) -> Optional[AddressRange]: ...

    # Alternate names also exported by the extension
    def overlaps(self, other: AddressRange) -> bool: ...
    def intersection(self, other: AddressRange) -> Optional[AddressRange]: ...

    @property
    def size_bytes(self) -> int: ...


class AddressSpaceKind(enum.Enum):
    Default: AddressSpaceKind
    Overlay: AddressSpaceKind
    Stack: AddressSpaceKind
    Heap: AddressSpaceKind
    MMIO: AddressSpaceKind
    Other: AddressSpaceKind


class AddressSpace:
    name: str
    kind: AddressSpaceKind
    size: Optional[int]
    base_space: Optional[str]

    def __init__(
        self,
        name: str,
        kind: AddressSpaceKind,
        size: Optional[int] = ...,
        base_space: Optional[str] = ...,
    ) -> None: ...

    def is_valid_py(self) -> bool: ...
    def is_overlay(self) -> bool: ...
    def has_base_space(self) -> bool: ...

    @property
    def effective_size(self) -> Optional[int]: ...


class IdKind(enum.Enum):
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


class Id:
    value: str
    kind: IdKind

    def __init__(self, value: str, kind: IdKind) -> None: ...
    def is_valid(self) -> bool: ...
    def __str__(self) -> str: ...


class IdGenerator:
    @staticmethod
    def binary_from_content(content: bytes, path: Optional[str]) -> Id: ...

    @staticmethod
    def binary_from_uuid(uuid: str) -> Id: ...

    @staticmethod
    def function(binary_id: str, address: str) -> Id: ...

    @staticmethod
    def basic_block(binary_id: str, address: str) -> Id: ...

    @staticmethod
    def symbol(name: str, address: Optional[str]) -> Id: ...

    @staticmethod
    def section(name: Optional[str], index: Optional[int]) -> Id: ...

    @staticmethod
    def segment(name: Optional[str], index: Optional[int]) -> Id: ...

    @staticmethod
    def instruction(address: str) -> Id: ...

    @staticmethod
    def variable(context: str, name: Optional[str], offset: Optional[int]) -> Id: ...

    @staticmethod
    def data_type(name: Optional[str], content_hash: Optional[str]) -> Id: ...

    @staticmethod
    def entity(entity_type: str, identifier: str) -> Id: ...

    @staticmethod
    def uuid(kind: IdKind) -> Id: ...

    @staticmethod
    def hash(kind: IdKind, content: str) -> Id: ...


class SourceKind(enum.Enum):
    Static: SourceKind
    Dynamic: SourceKind
    Heuristic: SourceKind
    External: SourceKind


class ToolMetadata:
    name: str
    version: str
    parameters: Optional[Dict[str, str]]
    source_kind: Optional[SourceKind]

    def __init__(
        self,
        name: str,
        version: str,
        parameters: Optional[Dict[str, str]] = ...,
        source_kind: Optional[SourceKind] = ...,
    ) -> None: ...

    # Validation
    def is_valid(self) -> bool: ...

    # Parameter helpers
    def get_parameter(self, key: str) -> Optional[str]: ...
    def set_parameter(self, key: str, value: str) -> None: ...
    def remove_parameter(self, key: str) -> Optional[str]: ...
    def parameter_count(self) -> int: ...
    def has_parameters(self) -> bool: ...
    def set_parameters_py(self, parameters: Dict[str, str]) -> None: ...

    # Source kind helper
    def set_source_kind_py(self, source_kind: SourceKind) -> None: ...

    # Serialization
    def to_json(self) -> str: ...
    @staticmethod
    def from_json(json_str: str) -> ToolMetadata: ...
    def to_binary(self) -> bytes: ...
    @staticmethod
    def from_binary(data: bytes) -> ToolMetadata: ...


class Artifact:
    id: str
    tool: ToolMetadata
    created_at: str
    input_refs: List[str]
    schema_version: str
    data_type: str
    data: str
    meta: Any

    def __init__(
        self,
        id: str,
        tool: ToolMetadata,
        data_type: str,
        data: str,
        input_refs: Optional[List[str]] = ...,
        schema_version: str = ...,
        meta: Optional[str] = ...,
    ) -> None: ...

    def is_valid(self) -> bool: ...

    # Input refs operations
    def input_ref_count(self) -> int: ...
    def has_input_refs(self) -> bool: ...
    def add_input_ref(self, input_ref: str) -> None: ...
    def remove_input_ref(self, input_ref: str) -> bool: ...

    # Serialization helpers
    def to_json(self) -> str: ...
    @staticmethod
    def from_json(json_str: str) -> Artifact: ...
    def to_binary(self) -> bytes: ...
    @staticmethod
    def from_binary(data: bytes) -> Artifact: ...
    def data_as_json(self) -> str: ...
    def meta_as_json(self) -> Optional[str]: ...
