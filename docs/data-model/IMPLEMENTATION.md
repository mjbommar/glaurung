# Data Model Implementation Plan

## Phase 0: Core Foundation Types

### 1. Address Type - FIRST IMPLEMENTATION

**Purpose:** The fundamental building block for all location references in binary analysis. Every instruction, function, reference, and data element needs addresses.

#### Design Details

```rust
// src/core/address.rs

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass]
pub enum AddressKind {
    VA,         // Virtual Address (runtime memory address)
    RVA,        // Relative Virtual Address (offset from image base)
    FileOffset, // Offset within the file on disk
    Physical,   // Physical memory address (rare, for kernel/embedded)
    Relative,   // Relative to some other address
    Symbolic,   // Symbolic reference that needs resolution
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass]
pub struct Address {
    pub kind: AddressKind,
    pub value: u64,
    pub space: Option<String>,     // Address space identifier
    pub bits: u8,                  // 16, 32, or 64
    pub symbol_ref: Option<String>, // Required when kind=Symbolic
}
```

#### Implementation Tasks

1. **Core Rust Implementation**
    - [x] Create `src/core/mod.rs` to organize core types
    - [x] Implement `Address` struct with all fields
    - [x] Implement `AddressKind` enum
    - [x] Add display traits for human-readable output
    - [x] Add arithmetic operations (add, sub, offset)
    - [x] Add comparison traits (Ord, PartialOrd)
    - [x] Add conversion methods between address kinds
    - [x] Add validation (bits must be 16/32/64)
    - [x] Add range checking based on bits

2. **PyO3 Python Bindings**
    - [x] Add `#[pyclass]` to Address and AddressKind
    - [x] Implement `#[pymethods]` for:
      - `__new__` constructor
      - `__str__` and `__repr__`
      - `__eq__` and `__hash__`
      - `__add__` and `__sub__` for arithmetic
      - Property getters/setters for all fields
    - [x] Add conversion to/from Python int for value
    - [x] Add pickle support for serialization

3. **Serialization**
    - [x] Implement serde Serialize/Deserialize
    - [x] Add JSON representation
    - [x] Add binary serialization (bincode)
    - [x] Ensure round-trip preservation

4. **Testing**
    - [x] Unit tests in Rust (`src/core/address.rs` #[cfg(test)])
    - [x] Property-based tests with proptest
    - [x] Python integration tests (`python/tests/test_address.py`)
    - [x] Serialization round-trip tests
    - [x] Edge cases (overflow, invalid bits, etc.)

5. **Documentation**
    - [x] Rust doc comments with examples
    - [x] Python docstrings via PyO3
    - [x] Type stubs (.pyi file) for Python
    - [x] Usage examples in docs/

#### Key Design Decisions

1. **Why AddressKind?**
   - Different address types need different handling
   - VA ↔ RVA conversion needs image base
   - FileOffset ↔ VA conversion needs section mapping
   - Symbolic addresses need resolution pass

2. **Why Optional Space?**
   - Most addresses use default space
   - Overlays, segments, and MMIO need distinct spaces
   - Enables embedded systems support

3. **Why Symbol Reference?**
   - When kind=Symbolic, must reference a symbol
   - Enables late binding and dynamic resolution
   - Critical for imports/exports

4. **Why Bits Field?**
   - 16-bit for DOS/embedded
   - 32-bit for x86, ARM32
   - 64-bit for x64, ARM64
   - Affects overflow behavior and display

#### Dependencies Added

```bash
# Rust dependencies (COMPLETED)
cargo add serde --features derive
cargo add pyo3
cargo add bincode         # For binary serialization
cargo add hex             # For hex display
cargo add uuid            # For ID generation
cargo add sha2            # For hashing
cargo add chrono          # For timestamps

# Python dev dependencies (COMPLETED)
uv add --group dev pytest
uv add --group dev pytest-benchmark
uv add --group dev hypothesis  # Property-based testing
```

#### File Structure (COMPLETED)

```
src/
├── lib.rs          # Module registration
├── core/
│   ├── mod.rs      # Core module exports
│   ├── address.rs  # Address implementation (✅ COMPLETE)
│   ├── address_range.rs  # AddressRange implementation (✅ COMPLETE)
│   ├── address_space.rs  # AddressSpace implementation (✅ COMPLETE)
│   ├── artifact.rs  # Artifact implementation (✅ COMPLETE)
│   ├── binary.rs   # Binary implementation (✅ COMPLETE)
│   ├── id.rs       # ID generation implementation (✅ COMPLETE)
│   ├── segment.rs  # Segment implementation (✅ COMPLETE)
│   ├── section.rs  # Section implementation (✅ COMPLETE)
│   └── tool_metadata.rs  # ToolMetadata implementation (✅ COMPLETE)
└── (other modules pending)

python/
├── glaurung/
│   ├── __init__.py
│   ├── __init__.pyi  # Type stubs
│   └── core.py       # Python wrappers if needed
└── tests/
    ├── test_address.py        # ✅ COMPLETE
    ├── test_address_range.py  # ✅ COMPLETE
    ├── test_address_space.py  # ✅ COMPLETE
    ├── test_artifact.py       # ✅ COMPLETE
    ├── test_binary.py         # ✅ COMPLETE
    ├── test_id.py             # ✅ COMPLETE
    ├── test_segment.py        # ✅ COMPLETE
    ├── test_section.py        # ✅ COMPLETE
    ├── test_tool_metadata.py  # ✅ COMPLETE
    └── conftest.py   # Pytest fixtures
```

#### Example Usage (After Implementation)

```python
from glaurung import Address, AddressKind

# Create a virtual address
va = Address(AddressKind.VA, 0x401000, bits=32)

# Create a file offset
offset = Address(AddressKind.FileOffset, 0x1000, bits=32)

# Arithmetic
next_addr = va + 0x10
assert next_addr.value == 0x401010

# Symbolic address
sym = Address(AddressKind.Symbolic, 0, symbol_ref="kernel32.dll!CreateFileW")

# Serialization
import json
data = va.to_json()
restored = Address.from_json(data)
assert va == restored
```

#### Success Criteria

1. **Correctness**
   - All address types properly represented
   - Arithmetic operations preserve kind and space
   - Symbol references validated

2. **Performance**
   - Creation: < 100ns
   - Arithmetic: < 50ns
   - Serialization: < 1μs

3. **Usability**
   - Intuitive Python API
   - Clear error messages
   - Good IDE support via type stubs

4. **Compatibility**
   - Works with 32-bit and 64-bit addresses
   - Handles all major executable formats
   - Serialization format stable

---

## Implementation Order

### Phase 0: Foundation (Week 1) - **100% COMPLETE** ✅
1. **Address** ✅ **COMPLETE**
2. **AddressRange** ✅ **COMPLETE**
3. **ID Generation** ✅ **COMPLETE**
4. **ToolMetadata** ✅ **COMPLETE**
5. **Artifact** ✅ **COMPLETE**

### Phase 1: Structure (Week 2)
6. **Binary** ✅ **COMPLETE**
7. **Segment** ✅ **COMPLETE**
8. **Section** ✅ **COMPLETE**
9. **Format** enum ✅ **COMPLETE**
10. **Hashes** ✅ **COMPLETE**

### Phase 2: Symbols & Strings (Week 3)
11. **Symbol**
12. **StringLiteral**
13. **Pattern** (basic)
14. **Relocation**

### Phase 3: Instructions (Week 4)
15. **Instruction**
16. **Operand**
17. **Register**
18. **Disassembler trait**

### Phase 4: Analysis (Week 5-6)
19. **BasicBlock**
20. **Function**
21. **Reference**
22. **ControlFlowGraph**
23. **CallGraph**

### Phase 5: Types (Week 7)
24. **DataType**
25. **Variable**
26. **TypeInference**

### Phase 6: Storage (Week 8)
27. **Storage abstraction**
28. **SQLite backend**
29. **Caching layer**
30. **Query interface**

---

## Testing Strategy

### Unit Tests
- Each type has comprehensive unit tests
- Property-based testing for invariants
- Fuzzing for parsers

### Integration Tests
- Python ↔ Rust round-trips
- Serialization formats
- Cross-type interactions

### Performance Tests
- Benchmarks for critical paths
- Memory usage monitoring
- Scaling tests with large binaries

### Example-Driven Tests
- Real binary formats (PE, ELF, MachO)
- Known malware samples
- Edge cases from bug reports

---

## Development Workflow

1. **TDD Approach**
   ```bash
   # Write test first
   touch python/tests/test_address.py
   
   # Run test (should fail)
   uvx pytest python/tests/test_address.py
   
   # Implement in Rust
   edit src/core/address.rs
   
   # Build and test
   maturin develop
   uvx pytest python/tests/test_address.py
   ```

2. **Continuous Integration**
   ```bash
   # Run Rust tests
   cargo test
   
   # Run Python tests
   maturin develop
   uvx pytest
   
   # Check types
   uvx mypy python/
   
   # Benchmark
   uvx pytest --benchmark-only
   ```

3. **Documentation**
   ```bash
   # Generate Rust docs
   cargo doc --open
   
   # Test Python docstrings
   uvx pytest --doctest-modules
   ```

---

## Notes for Address Implementation

### Critical Invariants
- If kind=Symbolic, symbol_ref MUST be Some
- bits MUST be one of: 16, 32, 64
- value MUST fit within bits range
- space defaults to "default" if None

### Performance Considerations
- Address is Copy type in Rust (cheap to pass)
- Use u64 for value (covers all cases)
- String fields make it non-Copy in Python
- Consider interning common space strings

### Future Extensions
- Segment:Offset representation for x86 real mode
- ARM Thumb bit handling
- GPU address spaces
- Virtualization guest/host addresses

### Common Patterns
```rust
// VA to RVA conversion
impl Address {
    pub fn to_rva(&self, image_base: u64) -> Option<Address> {
        match self.kind {
            AddressKind::VA => Some(Address {
                kind: AddressKind::RVA,
                value: self.value - image_base,
                ..self.clone()
            }),
            _ => None,
        }
    }
}

// Range checking
impl Address {
    pub fn is_valid(&self) -> bool {
        match self.bits {
            16 => self.value <= 0xFFFF,
            32 => self.value <= 0xFFFF_FFFF,
            64 => true,
            _ => false,
        }
    }
}
```

---

## Next Steps

**Phase 0 Foundation - 100% Complete** ✅

✅ **ALL PHASE 0 TYPES COMPLETED:**
- Address type with full feature set
- AddressRange type with advanced operations
- ID generation system with multiple strategies
- ToolMetadata type with parameter management
- Artifact type with provenance tracking
- PyO3 Python bindings for all types
- Comprehensive testing (Rust + Python)
- Serialization support (JSON + binary)
- Documentation and examples

**Phase 1 Progress:**
✅ **COMPLETED:**
- Binary type with comprehensive metadata support
- Format enum (ELF, PE, MachO, Wasm, COFF, Raw, Unknown)
- Arch enum (x86, x86_64, ARM, AArch64, MIPS, PPC, RISC-V, etc.)
- Endianness enum (Little, Big)
- Hashes type with SHA-256, MD5, SHA-1, and custom hash support

⏳ **REMAINING (Phase 1):**
1. ✅ Segment type for load-time memory mapping - **COMPLETE**
2. ✅ Section type for file-format organization - **COMPLETE**
3. Build streaming instruction decoder
4. Add Symbol and StringLiteral types

**Ready for Phase 2:**
5. Add Relocation type
6. Implement Pattern type for signatures/anomalies

This iterative approach ensures each component is solid before building on it.

---

## AddressRange Type - IMPLEMENTATION COMPLETE ✅

**Purpose:** Represents contiguous memory regions for segments, sections, functions, and other binary constructs.

### Implementation Status

**✅ COMPLETED** - AddressRange is fully implemented with advanced features beyond the original plan:

#### Core Features
- Half-open range representation `[start, end)`
- Size and optional alignment support
- Full PyO3 Python bindings
- Comprehensive validation and error handling

#### Advanced Operations
- **Containment checking**: `contains_address()`, `contains_range()`
- **Overlap detection**: `overlaps_with()`
- **Range intersection**: `intersection_with()`
- **Address space validation**: Ensures compatible address kinds/spaces/bits

#### Implementation Highlights
- **Robust validation**: Prevents invalid ranges, overflow, and incompatible operations
- **Cross-language consistency**: Identical behavior in Rust and Python
- **Performance optimized**: Efficient range operations for large binary analysis
- **Extensive testing**: 100+ test cases covering edge cases and error conditions

#### Example Usage
```python
from glaurung import Address, AddressKind, AddressRange

# Create a memory segment
start = Address(AddressKind.VA, 0x401000, 32)
segment = AddressRange(start, 0x1000, alignment=0x1000)

# Check if address is within segment
test_addr = Address(AddressKind.VA, 0x401500, 32)
assert segment.contains_address(test_addr)

# Range operations
assert segment.overlaps_with(other_range)
intersection = segment.intersection_py(other_range)
```

---

## Current Project Status

### Phase 0: Foundation (Week 1) - **100% COMPLETE** ✅

**Completed:**
- ✅ Address type with full feature set
- ✅ AddressRange type with advanced operations
- ✅ ID generation system with multiple strategies
- ✅ ToolMetadata type with parameter management
- ✅ Artifact type with provenance tracking
- ✅ PyO3 Python bindings for all types
- ✅ Comprehensive testing (Rust + Python)
- ✅ Serialization support (JSON + binary)
- ✅ Documentation and examples

**Next Steps:**
1. Begin Phase 1: Binary structure types
2. Begin Phase 1: Binary structure types
3. Update testing infrastructure for integration tests

### Implementation Quality Notes

**Exceeds Original Plan:**
- Advanced AddressRange operations (intersection, overlap detection)
- Binary serialization support
- Comprehensive error handling and validation
- Cross-language consistency guarantees
- Performance optimizations for large-scale analysis

**Production Ready:**
- Robust error handling prevents invalid states
- Extensive test coverage ensures reliability
- Clean API design supports future extensions
- Proper separation of concerns (Rust core, Python bindings)