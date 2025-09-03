# Project

## Purpose
The `Project` object is the top-level container for a complete analysis session. It holds the binary being analyzed, the analysis results, and any user-defined metadata. It is the primary object that will be serialized to and deserialized from a file to save and load analysis progress.

## Fields
- `binary`: The core `Binary` object being analyzed.
- `address_space`: The `AddressSpace` representing the loaded binary's memory.
- `functions`: A collection of identified `Function` objects.
- `symbols`: A table of all known `Symbol` objects.
- `metadata`: A key-value store for project-level information (e.g., analysis date, user notes).

---

# Binary

## Purpose
The `Binary` object represents the raw, un-analyzed executable file. It provides access to the file's format-specific information, such as headers, sections, and segments.

## Fields
- `file_path`: The absolute path to the binary file on disk.
- `raw_bytes`: The complete content of the file.
- `file_format`: An enum indicating the format (e.g., ELF, PE, Mach-O).
- `architecture`: The CPU architecture of the binary (e.g., x86_64, AArch64).
- `entry_point`: The `Address` of the program's entry point.
- `segments`: A list of `Segment` objects parsed from the file.
- `sections`: A list of `Section` objects parsed from the file.

---

# Address

## Purpose
The `Address` object is a universal, unambiguous representation of a location within a virtual address space. It is a simple but critical data type used throughout the entire system.

## Fields
- `value`: A 64-bit unsigned integer representing the virtual address.

---

# AddressSpace

## Purpose
The `AddressSpace` object is the abstract model of the program's memory. It manages memory mappings from the binary's segments and provides a unified interface for reading, writing, and querying memory permissions.

## Fields
- `mappings`: A collection of memory regions, each associated with a `Segment` and its permissions (read, write, execute).
- `base_address`: The base address where the binary is loaded in the virtual address space.

---

# Segment

## Purpose
A `Segment` represents a region of memory that is mapped from the binary file, as defined by the loader (e.g., an ELF Program Header). It defines the size, location, and permissions of a memory region.

## Fields
- `virtual_address`: The starting `Address` of the segment in memory.
- `virtual_size`: The size of the segment in memory.
- `file_offset`: The offset within the binary file where the segment's data begins.
- `file_size`: The size of the data in the file to be mapped.
- `permissions`: The memory permissions (Read, Write, Execute).

---

# Section

## Purpose
A `Section` represents a contiguous region of the binary file with a specific purpose, as defined by the file format (e.g., `.text`, `.data`, `.rodata` from an ELF Section Header).

## Fields
- `name`: The name of the section (e.g., `.text`).
- `virtual_address`: The starting `Address` of the section in memory.
- `size`: The size of the section.
- `file_offset`: The offset within the binary file where the section's data begins.

---

# Symbol

## Purpose
A `Symbol` represents a named location in the binary, typically a function or a global variable.

## Fields
- `name`: The name of the symbol (e.g., `main`, `printf`).
- `address`: The `Address` the symbol points to.
- `size`: The size of the data or function associated with the symbol, if known.
- `type`: The type of symbol (e.g., Function, Object, Notype).

---

# Instruction

## Purpose
An `Instruction` object represents a single, disassembled machine instruction.

## Fields
- `address`: The `Address` of the instruction.
- `size`: The length of the instruction in bytes.
- `mnemonic`: The instruction's mnemonic (e.g., `MOV`, `JMP`, `CALL`).
- `operands`: A list of strings or structured objects representing the instruction's operands.
- `bytes`: The raw bytes of the instruction.

---

# BasicBlock

## Purpose
A `BasicBlock` is a fundamental unit of a Control Flow Graph. It represents a straight-line sequence of code with no jumps in or out, except at the very beginning and very end.

## Fields
- `start_address`: The `Address` of the first instruction in the block.
- `end_address`: The `Address` of the last instruction in the block.
- `instructions`: A list of `Instruction` objects that make up the block.
- `successors`: A list of `Address`es pointing to the start of subsequent basic blocks.
- `predecessors`: A list of `Address`es of the blocks that can branch to this one.

---

# ControlFlowGraph (CFG)

## Purpose
The `ControlFlowGraph` is a directed graph that represents the flow of control within a function. Nodes in the graph are `BasicBlock`s, and edges represent jumps, calls, or fall-throughs between them.

## Fields
- `nodes`: A collection of `BasicBlock` objects.
- `edges`: A list of tuples representing the connections between basic blocks, defining the flow of control.
- `entry_node`: The `BasicBlock` that serves as the entry point to the function.

---

# Function

## Purpose
A `Function` is a high-level representation of a subroutine identified in the binary. It is a primary unit of analysis.

## Fields
- `entry_address`: The `Address` where the function begins.
- `name`: The name of the function, if known from a symbol.
- `basic_blocks`: A collection of `BasicBlock`s belonging to this function.
- `cfg`: The `ControlFlowGraph` for this function.
- `return_type`: The inferred return type of the function.
- `arguments`: A list of inferred arguments for the function.
