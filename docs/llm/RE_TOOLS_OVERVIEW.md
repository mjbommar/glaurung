# Glaurung LLM Tool System Overview

## What We Built

We've created a comprehensive tool system for pydantic-ai agents that enables LLMs to perform reverse engineering and binary analysis tasks through function calling. The system is inspired by professional RE tools like IDA Pro, Ghidra, and gdb.

## Tool Categories

### 1. **Basic Analysis Tools** (`tools.py`)
- **File Operations**: `get_file_hash` - Calculate hashes (MD5, SHA256)
- **String Extraction**: `extract_strings` - Extract strings with encoding options
- **Symbol Analysis**: `check_import` - Check for specific imports
- **Disassembly**: `disassemble_at_address` - Disassemble at specific addresses
- **Control Flow**: `analyze_control_flow` - Analyze CFG (placeholder for future)

### 2. **Reverse Engineering Tools** (`re_tools_simple.py`)

#### Navigation Tools (IDA Pro style)
- `goto_address` - Navigate to specific address (like 'g' in IDA)
- `list_functions` - List all detected functions

#### Search Tools (Ghidra style)
- `search_strings` - Search for text patterns in strings
- `search_bytes` - Search for byte patterns (hex)

#### Analysis Tools
- `analyze_function` - Analyze function structure (calls, jumps, complexity)
- `list_imports` - List imported functions with suspicious detection
- `check_entropy` - Detect packing/encryption via entropy
- `find_iocs` - Extract indicators of compromise (URLs, IPs, domains)

#### Memory Tools (GDB style)
- `examine_bytes` - Examine raw bytes at address (like 'x' in gdb)

## Architecture

### Context System
```python
@dataclass
class REContext:
    file_path: str                    # Binary file path
    artifact: TriagedArtifact        # Analysis results from Rust
    session_id: str                  # Session identifier
    current_address: int            # Current navigation position
    allow_expensive: bool          # Permission for expensive ops
    max_results: int               # Result limiting
    _functions: Optional[List]    # Cached function list
    _symbol_map: Optional[Dict]  # Cached symbol map
```

### Tool Registration
Tools are registered with agents using the `agent.tool()` method:
```python
agent = Agent(model="openai:gpt-4.1-mini", deps_type=REContext)
agent.tool(goto_address)
agent.tool(search_strings)
agent.tool(analyze_function)
```

### Async vs Sync
- **Async tools**: For I/O operations (file reading, network)
- **Sync tools**: For CPU-bound operations (calculations)
- pydantic-ai runs multiple tools concurrently for performance

## Integration with Rust Backend

The tools leverage Glaurung's Rust implementation for:

1. **Triage** (`g.triage`)
   - `analyze_path` - Full binary analysis
   - `entropy_of_bytes` - Entropy calculation

2. **Disassembly** (`g.disasm`)
   - `disassemble_window_at` - Disassemble at virtual address
   - Proper VA to file offset mapping

3. **Analysis** (`g.analysis`)
   - `analyze_functions_path` - Function detection and CFG
   - `va_to_file_offset_path` - VA to offset mapping
   - `symbol_address_map` - Symbol resolution
   - `elf_plt_map_path` - PLT resolution

4. **Search** (`g.search`)
   - `search_bytes` - Byte pattern search
   - `search_text` - Text search

5. **Symbols** (`g.symbols`)
   - Import/export analysis
   - Suspicious import detection
   - Demangling support

## Usage Examples

### Basic Tool Usage
```python
from glaurung.llm.re_tools_simple import create_simple_re_agent, REContext

# Analyze a binary
artifact = g.triage.analyze_path("/path/to/binary", 10_000_000, 100_000_000, 1)

# Create context
context = REContext(
    file_path="/path/to/binary",
    artifact=artifact,
    session_id="analysis_001",
    allow_expensive=True
)

# Create agent with tools
agent = create_simple_re_agent(model="openai:gpt-4.1-mini")

# Run analysis
result = agent.run_sync(
    "Find all suspicious imports and check if this binary is packed",
    deps=context
)
```

### Example Queries
```python
# Navigation
"Navigate to address 0x401000 and show the disassembly"
"List all functions and find the main function"

# Search
"Search for all URLs and IP addresses in this binary"
"Find all strings containing 'password' or 'key'"
"Search for byte pattern 48 8B 45 (mov rax, [rbp+...])"

# Analysis
"Analyze the function at the entry point"
"Check if this binary is packed or encrypted"
"List all suspicious imports and explain why they're suspicious"
"Find all IOCs and categorize them"

# Memory
"Examine 64 bytes at address 0x401000"
"Show the hex dump of the .text section"
```

## Key Features

### 1. **Hallucination Prevention**
- Tools work with actual data from the binary
- Results are grounded in real analysis
- No fabrication of addresses or values

### 2. **Performance Optimization**
- Caching of expensive operations (function analysis, symbol maps)
- Concurrent tool execution
- Result limiting to prevent overwhelming responses

### 3. **Security Focus**
- Suspicious import detection
- IOC extraction and validation
- Entropy-based packing detection
- Call graph analysis for behavior understanding

### 4. **Compatibility**
- Works with PE, ELF, Mach-O formats
- Multiple architectures (x86, x64, ARM, etc.)
- Handles packed and obfuscated binaries

## Testing

All tools have been tested and confirmed working:

1. **Basic functionality**: Hash calculation, string extraction
2. **Navigation**: Address navigation, function listing
3. **Search**: String and byte pattern searching
4. **Analysis**: Function analysis, import checking, entropy
5. **IOC extraction**: URL, IP, domain detection

## Future Enhancements

Potential additions based on RE tool capabilities:

1. **Advanced Navigation**
   - Cross-reference graphs
   - Call/jump following
   - Bookmark management

2. **Enhanced Search**
   - Regex pattern support
   - Instruction pattern matching
   - Yara rule integration

3. **Deep Analysis**
   - Data flow analysis
   - Taint tracking
   - Symbolic execution hints

4. **Visualization**
   - ASCII CFG generation
   - Function relationship graphs
   - Memory layout diagrams

5. **Integration**
   - MITRE ATT&CK mapping
   - CAPA rule matching
   - VirusTotal integration

## Performance Considerations

- Tools are designed to be fast (< 100ms for most operations)
- Expensive operations (full CFG analysis) are gated behind permissions
- Results are limited to prevent token overflow
- Caching reduces redundant analysis

## Security Notes

- All file operations are read-only
- No execution of analyzed binaries
- Sandboxed analysis environment
- Careful handling of malicious samples

## Conclusion

The Glaurung LLM tool system provides comprehensive binary analysis capabilities through pydantic-ai's tool calling mechanism. It bridges the gap between traditional RE tools and LLM-based analysis, enabling natural language interaction with binary analysis tasks while maintaining accuracy and performance.