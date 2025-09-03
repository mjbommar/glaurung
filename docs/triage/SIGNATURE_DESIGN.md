# High-Performance Scriptable Signature Design

## Executive Summary

A three-tier signature system balancing performance and flexibility:
1. **Compiled signatures** (0ms overhead) - Critical patterns built into binary
2. **Runtime patterns** (1-10ms) - Fast pattern matching with Aho-Corasick
3. **Script logic** (10-50ms) - Complex detection via sandboxed WASM

## Core Design Principles

### Performance First
- 90% of detections should complete in < 10ms
- Use tiered approach: fast filters before expensive checks
- Aggressive caching at every level
- SIMD acceleration where available

### Safety & Determinism
- Sandboxed script execution (WASM)
- Resource limits (time, memory, fuel)
- No network access from signatures
- Reproducible results

### Extensibility
- Runtime signature loading without recompilation
- Community contribution friendly
- Version compatibility guarantees

## Architecture Overview

```rust
pub struct SignatureEngine {
    // Tier 1: Zero-cost compiled signatures
    compiled: &'static [CompiledSignature],
    
    // Tier 2: Fast runtime pattern matching
    patterns: PatternMatcher,
    
    // Tier 3: Flexible scripted logic
    scripts: Option<ScriptEngine>,
    
    // Performance optimization
    cache: SignatureCache,
    bloom: BloomFilter,
}
```

## Tier 1: Compiled Signatures (Fastest)

### Approach
Embed critical signatures directly in the binary using Rust's const evaluation.

```rust
// signatures/compiled.rs
const UPX_SIGNATURE: CompiledSig = CompiledSig {
    id: "upx_core",
    patterns: &[
        Pattern::exact(0x1C8, b"UPX!"),
        Pattern::exact(0x1CC, &[0x00, 0x00, 0x00]),
    ],
    format: Format::PE,
};

pub const COMPILED_SIGS: &[CompiledSig] = &[
    UPX_SIGNATURE,
    ASPACK_SIGNATURE,
    // ... ~100-200 essential signatures
];
```

### Benefits
- Zero runtime parsing overhead
- No allocation needed
- Can't be corrupted/modified
- Always available

## Tier 2: Runtime Patterns (Fast)

### Pattern Matching Algorithm: Aho-Corasick

Why Aho-Corasick?
- O(n + m) complexity for multiple patterns
- Single pass through data
- Predictable performance
- Well-tested (used in grep, ClamAV)

```rust
pub struct PatternMatcher {
    // Multi-pattern search
    ac_automaton: AhoCorasick,
    
    // Offset-specific patterns (fast lookup)
    offset_patterns: BTreeMap<u64, Vec<Pattern>>,
    
    // Section-relative patterns
    section_patterns: HashMap<String, Vec<Pattern>>,
    
    // Entry-point relative
    entry_patterns: Vec<(i64, Pattern)>,
}
```

### Signature Format: TOML

TOML chosen over JSON/YAML because:
- Native Rust support (serde)
- Clean hex string representation
- No escaping nightmares
- Comments for documentation
- Array of tables perfect for signatures

```toml
# signatures/packers/upx.toml
[[signature]]
id = "upx_3_96"
name = "UPX 3.96"
format = "pe"  # pe, elf, macho, any
confidence = 0.95
priority = 100  # Higher runs first

# Multiple patterns with different match types
[[signature.pattern]]
offset = 0x1C8
bytes = "55 50 58 21"  # Human-readable hex
match = "exact"

[[signature.pattern]]
# Wildcard matching (? = any byte, ?? = any word)
offset = "entry_point"  
bytes = "60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ??"
match = "wildcard"

[[signature.pattern]]
# Regex for strings section
section = ".rdata"
regex = "UPX[0-9]\\.[0-9]{2}"
match = "regex"

# Optional conditions (only if patterns match)
[signature.condition]
# Rhai script for complex logic
script = '''
has_section(".UPX0") && 
has_section(".UPX1") &&
section_count() == 3
'''
```

### Binary Data Representation

**Hex Strings** (Recommended):
```toml
bytes = "4D 5A 90 00 03"  # Clear, unambiguous
bytes = "4D5A900003"      # Also valid
```

**Base64** (For large sequences):
```toml
bytes_base64 = "TVqQAAMAAAAEAAAA"
```

**Escape Sequences** (For mixed text/binary):
```toml
bytes = "MZ\x90\x00\x03"
```

## Tier 3: Script Logic (Flexible)

### Script Engine: WebAssembly

Why WASM over Lua/Rhai/JavaScript?
- **Superior sandboxing** - Memory isolation by design
- **Predictable performance** - Fuel-based limits
- **Language agnostic** - Write in Rust, C, AssemblyScript
- **No GC pauses** - Deterministic timing
- **Growing ecosystem** - Wasmtime, Wasmer mature

```rust
pub struct ScriptEngine {
    engine: wasmtime::Engine,
    module_cache: HashMap<String, Module>,
    
    // Resource limits
    config: ScriptConfig,
}

pub struct ScriptConfig {
    max_memory: usize,      // 10MB default
    max_fuel: u64,          // 1_000_000 default
    max_time: Duration,     // 50ms default
    enable_imports: bool,   // false default
}
```

### Script Interface

```rust
// Exposed to WASM scripts
#[wasm_bindgen]
pub struct BinaryContext {
    size: u32,
    format: Format,
    entry_point: u32,
}

#[wasm_bindgen]
impl BinaryContext {
    pub fn read_bytes(&self, offset: u32, length: u32) -> Vec<u8> { }
    pub fn has_section(&self, name: &str) -> bool { }
    pub fn get_imports(&self) -> Vec<String> { }
    pub fn get_exports(&self) -> Vec<String> { }
    pub fn section_entropy(&self, name: &str) -> f32 { }
}
```

## Performance Optimizations

### 1. Multi-Stage Pipeline

```rust
impl SignatureEngine {
    pub fn analyze(&self, data: &[u8]) -> Vec<Detection> {
        let mut detections = Vec::new();
        
        // Stage 1: Format detection (< 0.1ms)
        let format = detect_format_quick(data);
        
        // Stage 2: Bloom filter (< 0.1ms)
        // Quick negative check - if bloom says no, skip
        if !self.bloom.might_contain(&data[..512]) {
            return detections;
        }
        
        // Stage 3: Compiled signatures (< 1ms)
        detections.extend(self.check_compiled(data, format));
        
        // Stage 4: Pattern matching (< 10ms)
        if detections.is_empty() {  // Only if needed
            detections.extend(self.check_patterns(data, format));
        }
        
        // Stage 5: Script evaluation (< 50ms)
        // Only for signatures with scripts, only if patterns matched
        for detection in &mut detections {
            if let Some(script) = self.get_script(detection.id) {
                detection.verified = self.run_script(script, data);
            }
        }
        
        detections
    }
}
```

### 2. Caching Strategy

```rust
pub struct SignatureCache {
    // L1: Hash -> Results (LRU, 1000 entries)
    results: LruCache<Blake3Hash, Vec<Detection>>,
    
    // L2: Compiled patterns (never evicted)
    patterns: HashMap<String, CompiledPattern>,
    
    // L3: WASM modules (LRU, 100 entries)
    modules: LruCache<String, Module>,
}
```

### 3. SIMD Acceleration

```rust
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

// Find 4-byte pattern using AVX2
unsafe fn find_bytes_avx2(haystack: &[u8], needle: [u8; 4]) -> Option<usize> {
    let needle_vec = _mm256_set1_epi32(i32::from_le_bytes(needle));
    
    for (i, chunk) in haystack.chunks_exact(32).enumerate() {
        let hay_vec = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);
        let cmp = _mm256_cmpeq_epi32(hay_vec, needle_vec);
        let mask = _mm256_movemask_epi8(cmp);
        
        if mask != 0 {
            // Found match, calculate exact position
            return Some(i * 32 + mask.trailing_zeros() as usize / 4);
        }
    }
    None
}
```

### 4. Lazy Evaluation

```rust
pub struct LazySignature {
    id: String,
    toml: String,
    compiled: OnceCell<CompiledSig>,
}

impl LazySignature {
    fn get_compiled(&self) -> Result<&CompiledSig> {
        self.compiled.get_or_try_init(|| {
            parse_signature_toml(&self.toml)
        })
    }
}
```

## Configuration

### Runtime Configuration

```rust
pub struct SignatureConfig {
    // Signature loading
    pub signature_dirs: Vec<PathBuf>,
    pub enable_runtime_sigs: bool,
    pub enable_scripts: bool,
    
    // Performance tuning
    pub pattern_cache_size: usize,     // 10,000 default
    pub script_timeout: Duration,      // 50ms default
    pub enable_simd: bool,             // true if available
    pub parallel_analysis: bool,       // true default
    
    // Sandboxing
    pub script_memory_limit: usize,    // 10MB default
    pub script_fuel_limit: u64,        // 1M default
    
    // Embedded signatures
    pub use_compiled_sigs: bool,       // true default
}
```

### Directory Structure

```
signatures/
├── compiled/           # Built into binary
│   ├── critical.rs    # Must-have detections
│   └── mod.rs
├── runtime/           # Loaded at startup
│   ├── packers/
│   │   ├── upx.toml
│   │   ├── aspack.toml
│   │   └── themida.toml
│   ├── compilers/
│   │   ├── gcc.toml
│   │   ├── msvc.toml
│   │   └── clang.toml
│   └── malware/       # Known families
│       ├── ransomware.toml
│       └── apt.toml
└── scripts/           # WASM modules
    ├── complex_packer.wasm
    └── heuristic.wasm
```

## Default Signatures

### Embedding Strategy

```rust
// build.rs - Compile signatures at build time
fn main() {
    // Read all TOML files from signatures/compiled/
    let sig_dir = Path::new("signatures/compiled");
    let mut signatures = Vec::new();
    
    for entry in fs::read_dir(sig_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension() == Some("toml") {
            let content = fs::read_to_string(&path).unwrap();
            let sig: Signature = toml::from_str(&content).unwrap();
            signatures.push(sig);
        }
    }
    
    // Generate Rust code
    let out_path = Path::new(&env::var("OUT_DIR").unwrap())
        .join("compiled_sigs.rs");
    let code = generate_signature_code(&signatures);
    fs::write(out_path, code).unwrap();
}
```

### Critical Default Signatures (~200)

**Packers** (50):
- UPX (all versions)
- ASPack, PECompact, Petite
- Themida, VMProtect, Obsidium
- MPRESS, MEW, FSG

**Compilers** (50):
- GCC (major versions)
- MSVC (2015-2025)
- Clang/LLVM
- Go, Rust, MinGW

**Frameworks** (50):
- .NET (2.0-8.0)
- Java/JVM bytecode
- Python bytecode
- Node.js/Electron

**Malware** (50):
- Known ransomware families
- Common RAT signatures
- Exploit kit artifacts

## Performance Benchmarks

### Target Performance

| Operation | Target | Current DIE | Notes |
|-----------|--------|-------------|-------|
| Format detection | < 0.1ms | 0.5ms | Using magic bytes |
| Simple pattern | < 1ms | 2ms | Aho-Corasick |
| Complex pattern | < 10ms | 20ms | With wildcards |
| Script execution | < 50ms | 100ms | WASM sandboxed |
| Full analysis | < 100ms | 500ms | All signatures |

### Memory Usage

| Component | Memory | Notes |
|-----------|--------|-------|
| Compiled sigs | 2MB | Static in binary |
| Pattern matcher | 10MB | AC automaton |
| Script engine | 20MB | WASM runtime |
| Cache | 50MB | Configurable |
| **Total** | ~82MB | For typical usage |

## Security Considerations

### Sandboxing
- WASM provides memory isolation
- No filesystem access from scripts
- No network access
- Resource limits enforced

### Input Validation
- Size limits on patterns
- Regex complexity limits
- Script fuel consumption
- Timeout enforcement

### Signature Verification
- Optional signature signing
- Checksum verification
- Source attribution

## Migration Path

### Phase 1: Foundation (Week 1)
- Implement pattern matcher with Aho-Corasick
- TOML parser for signatures
- Basic caching

### Phase 2: Optimization (Week 2)
- Add SIMD acceleration
- Implement bloom filters
- Parallel analysis

### Phase 3: Scripting (Week 3)
- Integrate Wasmtime
- Define script API
- Sandboxing setup

### Phase 4: Production (Week 4)
- Port existing signatures
- Performance tuning
- Documentation

## Conclusion

This design achieves:
- ✅ **High Performance**: Sub-10ms for 90% of detections
- ✅ **Flexibility**: Full scripting when needed
- ✅ **Safety**: Sandboxed execution
- ✅ **Extensibility**: Runtime signature loading
- ✅ **Compatibility**: Works with existing formats

The three-tier architecture ensures we never sacrifice performance for flexibility, while the TOML format and WASM scripting provide a powerful and safe extension mechanism.