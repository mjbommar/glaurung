# GLAURUNG Data Model Proposal - GROK4

## Address
## Purpose
Represents a memory address in the binary, supporting virtual, physical, and overlay spaces.

## Fields
- `value`: Numeric address value (u64)
- `space`: Address space identifier (string, e.g., "ram", "overlay")
- `offset`: Offset within the space (u64)
- `is_virtual`: Boolean indicating if virtual address

---

## AddressSpace
## Purpose
Defines an address space in the program, such as default, overlay, or special spaces like stack/heap.

## Fields
- `name`: Unique name of the space (string)
- `type`: Type enum (default, overlay, stack, heap, etc.)
- `size`: Maximum size (u64)
- `base_space`: Reference to base space for overlays (AddressSpace)

---

## MemoryBlock
## Purpose
Represents a contiguous block of memory (section/segment) in the binary.

## Fields
- `name`: Block name (string)
- `start`: Starting Address
- `size`: Size in bytes (u64)
- `permissions`: Flags for read/write/execute (u32)
- `type`: Block type (code, data, bss, etc.)
- `initialized`: Boolean if block has initial data

---

## Symbol
## Purpose
Represents a symbol from symbol table or debug info.

## Fields
- `name`: Symbol name (string)
- `address`: Address of the symbol
- `type`: Enum (function, variable, label, etc.)
- `size`: Size in bytes (u64)
- `namespace`: Containing namespace (string)
- `binding`: Enum (local, global, weak)

---

## Function
## Purpose
Represents a function with its metadata and structure.

## Fields
- `name`: Function name (string)
- `entry_point`: Entry Address
- `basic_blocks`: List of BasicBlock
- `parameters`: List of Variable (parameters)
- `local_vars`: List of Variable (locals)
- `calling_convention`: String (e.g., "cdecl")
- `return_type`: DataType

---

## BasicBlock
## Purpose
A fundamental unit of a Control Flow Graph. It represents a straight-line sequence of code with no jumps in or out, except at the very beginning and very end.

## Fields
- `start_address`: The `Address` of the first instruction in the block.
- `end_address`: The `Address` of the last instruction in the block.
- `instructions`: A list of `Instruction` objects that make up the block.
- `successors`: A list of `Address`es pointing to the start of subsequent basic blocks.
- `predecessors`: A list of `Address`es of the blocks that can branch to this one.

---

## Instruction
## Purpose
Represents a single disassembled instruction.

## Fields
- `address`: Address of the instruction
- `mnemonic`: Instruction mnemonic (string)
- `operands`: List of Operand
- `bytes`: Raw byte array
- `size`: Instruction length (u32)
- `flow_type`: Enum (unconditional, conditional, call, etc.)

---

## Operand
## Purpose
Represents an operand in an instruction.

## Fields
- `type`: Enum (register, immediate, memory, etc.)
- `value`: Variant value based on type
- `size`: Size in bits (u32)
- `access`: Enum (read, write, read_write)

---

## Register
## Purpose
Represents a CPU register.

## Fields
- `name`: Register name (string)
- `size`: Size in bits (u32)
- `type`: Enum (general, float, vector, etc.)
- `address`: Optional Address for memory-mapped registers

---

## Variable
## Purpose
Represents a variable (local, parameter, global).

## Fields
- `name`: Variable name (string)
- `data_type`: DataType
- `storage`: Storage location (Register, StackOffset, Address)
- `scope`: Enum (local, parameter, global)

---

## DataType
## Purpose
Represents type information for data and variables.

## Fields
- `name`: Type name (string)
- `kind`: Enum (primitive, struct, pointer, array, etc.)
- `size`: Size in bytes (u32)
- `fields`: For composites, list of field names and types

---

## Reference
## Purpose
Represents a cross-reference (xref) between addresses.

## Fields
- `from`: Source Address
- `to`: Target Address
- `type`: Enum (call, jump, data_read, data_write)
- `operand_index`: Index of operand in instruction (i32)

---

## Relocation
## Purpose
Represents a relocation entry in the binary.

## Fields
- `address`: Address to relocate
- `type`: Relocation type enum
- `value`: Relocation value (u64)
- `symbol`: Optional associated Symbol

---

## Program
## Purpose
Top-level object representing the entire analyzed binary.

## Fields
- `name`: Program name (string)
- `format`: Binary format (elf, pe, macho)
- `architecture`: Target architecture (string)
- `entry_point`: Entry Address
- `memory_blocks`: List of MemoryBlock
- `functions`: List of Function
- `symbols`: List of Symbol
- `relocations`: List of Relocation
- `data_types`: List of DataType

---