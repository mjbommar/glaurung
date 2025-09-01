# Python Bytecode Parser Documentation

## Overview

Python bytecode (.pyc, .pyo) files contain compiled Python code that runs on the Python Virtual Machine (PVM). These files are crucial for malware analysis as Python is increasingly used in malicious scripts, ransomware, and info-stealers. GLAURUNG's Python bytecode parser handles all major Python versions from 2.7 through 3.13+.

## Format Specifications

### File Structure

```
┌─────────────────┐
│   Magic Number  │  2 bytes + 2 bytes \r\n (version-specific)
├─────────────────┤
│    Bit Field    │  4 bytes (Python 3.7+, PEP 552)
├─────────────────┤
│    Timestamp   │  4 bytes (if not hash-based)
│       OR        │
│   Source Hash   │  8 bytes (if hash-based, 3.7+)
├─────────────────┤
│   Source Size   │  4 bytes (Python 3.3+)
├─────────────────┤
│  Marshal Data   │  Serialized code object
└─────────────────┘
```

### Python Version Magic Numbers

| Python Version | Magic Number | Decimal | Notes |
|---------------|--------------|---------|-------|
| 3.13          | 0x0D0D      | 3531    | Latest stable |
| 3.12          | 0x0D0C      | 3531    | |
| 3.11          | 0x0D0A      | 3495    | Adaptive bytecode |
| 3.10          | 0x0D09      | 3439    | Pattern matching |
| 3.9           | 0x0D08      | 3425    | |
| 3.8           | 0x0D05      | 3413    | |
| 3.7           | 0x0D0F      | 3394    | PEP 552 |
| 3.6           | 0x0D0D      | 3379    | |
| 2.7           | 0x03F3      | 62211   | Legacy |

## Parser Implementation

### Phase 1: Header Validation
- [ ] Magic number identification
- [ ] Python version detection
- [ ] Bit field parsing (hash-based vs timestamp)
- [ ] Source file metadata extraction

### Phase 2: Marshal Decoding
- [ ] Marshal format version detection
- [ ] Type byte decoding
- [ ] Reference tracking (for circular references)
- [ ] String interning handling

### Phase 3: Code Object Parsing
- [ ] Bytecode extraction
- [ ] Constant pool parsing
- [ ] Variable names (locals, globals, free vars)
- [ ] Argument specifications
- [ ] Flags and metadata

### Phase 4: Bytecode Disassembly
- [ ] Opcode mapping for version
- [ ] Argument decoding
- [ ] Jump target resolution
- [ ] Exception table parsing (3.11+)

### Phase 5: Advanced Analysis
- [ ] String extraction and decryption
- [ ] Import analysis
- [ ] Control flow reconstruction
- [ ] Obfuscation detection
- [ ] Packed/encrypted payload detection

## Data Model

```rust
pub struct PycFile {
    pub magic: u32,
    pub python_version: PythonVersion,
    pub bit_field: u32,
    pub timestamp: Option<u32>,
    pub source_hash: Option<[u8; 8]>,
    pub source_size: u32,
    pub code_object: CodeObject,
}

pub struct CodeObject {
    pub arg_count: u32,
    pub pos_only_arg_count: u32,  // 3.8+
    pub kw_only_arg_count: u32,
    pub locals_count: u32,
    pub stack_size: u32,
    pub flags: CodeFlags,
    pub bytecode: Vec<u8>,
    pub constants: Vec<PyConstant>,
    pub names: Vec<String>,
    pub var_names: Vec<String>,
    pub free_vars: Vec<String>,
    pub cell_vars: Vec<String>,
    pub filename: String,
    pub name: String,
    pub first_line_no: u32,
    pub line_table: Vec<u8>,      // 3.10+ compact format
    pub exception_table: Vec<u8>,  // 3.11+
}

pub enum PyConstant {
    None,
    Integer(i64),
    Float(f64),
    Complex(f64, f64),
    String(Vec<u8>),
    Bytes(Vec<u8>),
    Tuple(Vec<PyConstant>),
    CodeObject(Box<CodeObject>),
}
```

## Bytecode Instruction Sets

### Major Instruction Categories
- **Stack manipulation**: LOAD_*, STORE_*, POP_*, DUP_*
- **Control flow**: JUMP_*, POP_JUMP_IF_*, FOR_ITER
- **Function calls**: CALL_*, MAKE_FUNCTION, RETURN_VALUE
- **Binary operations**: BINARY_*, INPLACE_*
- **Import system**: IMPORT_*, LOAD_BUILD_CLASS
- **Exception handling**: SETUP_*, RAISE_VARARGS

### Version-Specific Changes
- **3.11+**: Adaptive/specialized bytecode
- **3.10+**: Pattern matching opcodes
- **3.9+**: Dict merge operators
- **3.8+**: Positional-only parameters
- **3.7+**: Method call optimizations
- **3.6+**: Format string opcodes

## Security Considerations

### Common Obfuscation Techniques
- **Marshal manipulation**: Custom marshal encoders
- **Opcode remapping**: Modified Python interpreters
- **String encryption**: XOR, AES, custom algorithms
- **Code object packing**: Compressed/encrypted payloads
- **Import hooking**: Dynamic code loading
- **Anti-debugging**: sys.settrace detection

### Malware Patterns
- **Droppers**: Embedded executables in constants
- **Stealers**: Browser/wallet data theft code
- **RATs**: Remote access implementations
- **Cryptominers**: CPU/GPU mining code
- **Ransomware**: File encryption routines

### Defensive Parsing
- Limit recursion depth for nested code objects
- Validate marshal object sizes
- Detect impossible bytecode sequences
- Flag suspicious constant patterns
- Monitor for known malicious signatures

## Testing Coverage

### Test Samples
- Standard .pyc files: All Python versions
- Optimized files: -O and -OO flags
- Hash-based files: PEP 552 format
- Obfuscated samples: PyArmor, pyobfuscate
- Malware samples: Real-world threats

### Validation Tests
- [ ] Magic number detection across versions
- [ ] Marshal format compatibility
- [ ] Bytecode disassembly accuracy
- [ ] String extraction completeness
- [ ] Code object hierarchy

## Python Distribution Formats

### Frozen Modules
- py2exe executables
- PyInstaller bundles
- cx_Freeze archives
- Nuitka compiled binaries

### Package Formats
- .egg files (setuptools)
- .whl files (wheel)
- .pyz files (zipapp)

## Optimization Levels

| Flag | Extension | Description |
|------|-----------|-------------|
| None | .pyc | Standard bytecode |
| -O | .pyo/.pyc | Optimized, no assert |
| -OO | .pyo/.pyc | Optimized, no docstrings |

## Integration Points

### With Triage Pipeline
- Magic number detection
- Python version identification
- Optimization level detection

### With String Extractor
- Constant pool strings
- Module docstrings
- Variable names

### With Import Analyzer
- Import statements
- Dynamic imports
- Module dependencies

## Anti-Analysis Techniques

### Detection Methods
- [ ] Opcode frequency analysis
- [ ] Entropy measurement
- [ ] String pattern matching
- [ ] Control flow complexity
- [ ] Import chain analysis

### Deobfuscation Strategies
- Constant folding
- Dead code elimination
- String decryption
- Control flow restoration
- Import resolution

## Future Enhancements

- [ ] Full bytecode decompilation
- [ ] Python 3.14+ support
- [ ] Cython extension support
- [ ] MicroPython bytecode
- [ ] Stackless Python support
- [ ] PyPy bytecode format
- [ ] Automatic deobfuscation
- [ ] Machine learning-based classification

## References

- [Python Bytecode Documentation](https://docs.python.org/3/library/dis.html)
- [PEP 552 - Deterministic pycs](https://www.python.org/dev/peps/pep-0552/)
- [Marshal Format](https://github.com/python/cpython/blob/main/Python/marshal.c)
- [PyInstaller Extractor](https://github.com/extremecoders-re/pyinstxtractor)
- [uncompyle6 Decompiler](https://github.com/rocky/python-uncompyle6)
- [Decompyle++ (pycdc)](https://github.com/zrax/pycdc)