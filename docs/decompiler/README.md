# Glaurung Decompiler Architecture

## Overview

Glaurung's decompiler transforms low-level machine code, bytecode, and intermediate representations into high-level source code. This document details our multi-stage decompilation pipeline, supported languages, and integration strategies.

## Decompilation Philosophy

1. **Correctness over Readability**: Preserve semantics first, optimize for human readability second
2. **Multi-Level IR**: Progressive lifting through increasingly abstract representations
3. **Pattern Recognition**: Identify and reconstruct high-level constructs
4. **AI-Assisted Recovery**: Leverage LLMs for variable naming and structure inference
5. **Incremental Refinement**: Support iterative improvement of decompiled code

## Decompilation Pipeline

```
┌──────────────┐
│ Binary/Bytecode │
└──────┬───────┘
       ▼
┌──────────────┐
│ Disassembly  │ ← Stage 1: Instruction Decoding
└──────┬───────┘
       ▼
┌──────────────┐
│ Low-Level IR │ ← Stage 2: Initial Lifting
└──────┬───────┘
       ▼
┌──────────────┐
│ Mid-Level IR │ ← Stage 3: SSA Form
└──────┬───────┘
       ▼
┌──────────────┐
│ High-Level IR│ ← Stage 4: Type Recovery
└──────┬───────┘
       ▼
┌──────────────┐
│Control Flow  │ ← Stage 5: Structure Recovery
└──────┬───────┘
       ▼
┌──────────────┐
│ AST Generation│ ← Stage 6: Syntax Tree
└──────┬───────┘
       ▼
┌──────────────┐
│Source Code   │ ← Stage 7: Code Generation
└──────────────┘
```

## Supported Decompilation Targets

### Tier 1: Production-Ready Native Code

| Source | Target Language | Decompiler | Quality | Notes |
|--------|----------------|------------|---------|-------|
| **x86/x64** | C/C++ | Ghidra, Reko, B2R2 | ⭐⭐⭐⭐ | Full support, type recovery |
| **ARM/AArch64** | C/C++ | Ghidra, RetDec | ⭐⭐⭐⭐ | Good struct reconstruction |
| **MIPS** | C | Ghidra, Reko | ⭐⭐⭐ | Basic flow recovery |
| **PowerPC** | C | Ghidra | ⭐⭐⭐ | Limited type inference |
| **RISC-V** | C | Ghidra | ⭐⭐ | Experimental |
| **WebAssembly** | C/Rust | wasm-decompile | ⭐⭐⭐⭐ | Excellent recovery |

### Tier 2: Bytecode Languages

| Platform | Target | Decompiler | Quality | Features |
|----------|--------|------------|---------|----------|
| **Java** | Java | Fernflower, CFR, Procyon | ⭐⭐⭐⭐⭐ | Near-perfect recovery |
| **.NET/C#** | C#, VB.NET, F# | ILSpy, dnSpy | ⭐⭐⭐⭐⭐ | Source-level debugging |
| **Python** | Python | uncompyle6, pycdc, decompyle3 | ⭐⭐⭐⭐ | Good for 3.8+ |
| **Lua** | Lua | luadec, unluac | ⭐⭐⭐ | Version-specific |
| **Flash** | ActionScript | JPEXS, RABCDAsm | ⭐⭐⭐ | AS2/AS3 support |
| **Dalvik** | Java | jadx, dex2jar | ⭐⭐⭐⭐ | Android APK support |

### Tier 3: Specialized Formats

| Format | Target | Tool | Quality | Use Case |
|--------|--------|------|---------|----------|
| **LLVM IR** | C/C++ | llvm-cbe | ⭐⭐⭐ | Compiler research |
| **SPIR-V** | GLSL/HLSL | SPIRV-Cross | ⭐⭐⭐⭐ | Shader analysis |
| **CUDA PTX** | CUDA C | - | ⭐⭐ | GPU kernel recovery |
| **Verilog** | C | Verilator | ⭐⭐⭐ | Hardware → Software |

## Core Components

### 1. Intermediate Representations (IR)

#### Low-Level IR (LLIR)
```rust
pub enum LowLevelIR {
    Load { dst: Reg, src: Mem },
    Store { dst: Mem, src: Reg },
    BinOp { op: Op, dst: Reg, lhs: Val, rhs: Val },
    Jump { target: Label },
    Call { func: Addr, args: Vec<Val> },
}
```

#### Mid-Level IR (MLIR) - SSA Form
```rust
pub struct SSAValue {
    id: ValueId,
    ty: Type,
    def: Definition,
    uses: Vec<UseRef>,
}

pub enum Definition {
    Phi(Vec<(BlockId, ValueId)>),
    Operation(OpCode, Vec<ValueId>),
    Constant(Value),
}
```

#### High-Level IR (HLIR) - Typed
```rust
pub enum HighLevelExpr {
    Variable { name: String, ty: Type },
    FieldAccess { obj: Box<Expr>, field: String },
    ArrayIndex { arr: Box<Expr>, idx: Box<Expr> },
    FunctionCall { name: String, args: Vec<Expr> },
    Cast { expr: Box<Expr>, to: Type },
}
```

### 2. Type Recovery System

```rust
pub struct TypeInference {
    constraints: Vec<TypeConstraint>,
    solutions: HashMap<VarId, Type>,
}

pub enum TypeConstraint {
    Equal(TypeVar, TypeVar),
    Subtype(TypeVar, TypeVar),
    HasField(TypeVar, String, TypeVar),
    Callable(TypeVar, Vec<TypeVar>, TypeVar),
}
```

### 3. Control Flow Reconstruction

#### Pattern Matching for High-Level Constructs

| Pattern | Assembly Signature | Recovered Construct |
|---------|-------------------|-------------------|
| **If-Then** | `cmp; jz label` | `if (condition) { ... }` |
| **If-Else** | `cmp; jz else; ...; jmp end; else:` | `if (...) { ... } else { ... }` |
| **While** | `loop: cmp; jz end; ...; jmp loop` | `while (condition) { ... }` |
| **For** | `init; loop: cmp; jz end; ...; inc; jmp loop` | `for (init; cond; inc) { ... }` |
| **Switch** | `jmp table[reg]` | `switch (expr) { case ...: }` |
| **Try-Catch** | Exception handler tables | `try { ... } catch { ... }` |

### 4. Data Structure Recovery

#### Struct Identification
```rust
// Heuristics for struct recovery
pub struct StructRecovery {
    access_patterns: Vec<MemoryAccess>,
    field_offsets: BTreeMap<i64, FieldInfo>,
    vtable_refs: Option<Address>,
}

impl StructRecovery {
    fn infer_struct(&self) -> RecoveredStruct {
        // 1. Group by base pointer
        // 2. Identify consistent offsets
        // 3. Infer field types from usage
        // 4. Detect inheritance via vtables
    }
}
```

#### Array and String Detection
- Constant stride access → Array
- Null-terminated reads → C string
- Length-prefixed → Pascal string
- UTF-16 patterns → Wide string

### 5. AI-Assisted Enhancement

```python
class AIDecompilerEnhancer:
    def suggest_variable_names(self, context):
        """Use LLM to suggest meaningful variable names"""
        prompt = f"Given this decompiled function: {context}, suggest variable names"
        return self.llm.complete(prompt)
    
    def identify_algorithms(self, ast):
        """Recognize common algorithms and patterns"""
        # MD5, SHA, sorting, searching, etc.
        pass
    
    def recover_comments(self, code):
        """Generate explanatory comments"""
        pass
```

## Decompiler Comparison

### Native Code Decompilers

| Tool | Languages | Strengths | Weaknesses | License |
|------|-----------|-----------|------------|---------|
| **Ghidra** | C/C++ | Extensive arch support, scriptable | Java-based, slow | Apache 2.0 |
| **IDA Pro + Hex-Rays** | C/C++ | Industry standard, excellent output | Expensive, closed-source | Commercial |
| **Reko** | C | Open-source, extensible | Limited arch support | GPL |
| **RetDec** | C | Good LLVM integration | Incomplete type recovery | MIT |
| **B2R2** | F# IR | Formal methods backing | Academic, less mature | MIT |
| **Snowman** | C++ | Clean code output | Limited maintenance | GPL |

### Bytecode Decompilers

| Platform | Best Tool | Runner-ups | Notes |
|----------|-----------|------------|-------|
| **Java** | Fernflower | CFR, Procyon | IntelliJ uses Fernflower |
| **.NET** | ILSpy | dnSpy, dotPeek | ILSpy most active |
| **Python** | uncompyle6 | decompyle3, pycdc | Version-specific |
| **Android** | JADX | dex2jar + JD-GUI | JADX is all-in-one |

## Implementation Strategy

### Phase 1: Foundation
```rust
// Core decompiler trait
pub trait Decompiler {
    type IR;
    type AST;
    
    fn lift_to_ir(&self, asm: &[Instruction]) -> Self::IR;
    fn analyze_ir(&mut self, ir: &Self::IR) -> AnalysisResults;
    fn generate_ast(&self, ir: &Self::IR, analysis: &AnalysisResults) -> Self::AST;
    fn emit_code(&self, ast: &Self::AST, lang: Language) -> String;
}
```

### Phase 2: Multi-Engine Integration
```rust
pub struct UnifiedDecompiler {
    engines: HashMap<Architecture, Box<dyn Decompiler>>,
    config: DecompilerConfig,
}

impl UnifiedDecompiler {
    pub fn decompile(&self, binary: &Binary) -> DecompiledProgram {
        let engine = self.select_engine(&binary.architecture);
        let ir = engine.lift_to_ir(&binary.instructions);
        let enhanced_ir = self.apply_optimizations(ir);
        engine.emit_code(enhanced_ir, self.config.target_language)
    }
}
```

### Phase 3: AI Integration
```python
class HybridDecompiler:
    def __init__(self, traditional_engine, ai_model):
        self.engine = traditional_engine
        self.ai = ai_model
    
    def decompile(self, binary):
        # Traditional decompilation
        base_code = self.engine.decompile(binary)
        
        # AI enhancement
        enhanced = self.ai.enhance(base_code, {
            'suggest_names': True,
            'add_comments': True,
            'identify_patterns': True,
            'recover_types': True
        })
        
        return enhanced
```

## Advanced Features

### 1. Incremental Decompilation
- Decompile on-demand
- Cache results
- Update only changed regions

### 2. Interactive Refinement
- User-guided type hints
- Manual struct definitions
- Custom naming rules

### 3. Cross-Reference Integration
- Import/export tracking
- Call graph analysis
- Data flow visualization

### 4. Optimization Detection
```rust
pub enum CompilerOptimization {
    TailCallElimination,
    LoopUnrolling,
    InlinedFunction,
    DeadCodeElimination,
    StrengthReduction,
}

pub fn detect_optimizations(ir: &IR) -> Vec<CompilerOptimization> {
    // Pattern matching for common optimizations
}
```

### 5. Obfuscation Handling
- Control flow flattening reversal
- Opaque predicate removal
- String decryption
- VM-based protection unpacking

## Output Formats

### C/C++ Output
```c
// Decompiled function with recovered types
struct user_data {
    int id;           // offset: 0x00
    char name[256];   // offset: 0x04
    float score;      // offset: 0x104
};

int process_user(struct user_data* user) {
    if (user->id < 0) {
        return -1;  // Error: invalid ID
    }
    
    user->score = calculate_score(user->name);
    return 0;  // Success
}
```

### Python Output
```python
# Decompiled from bytecode
def process_data(input_list):
    """Recovered function processing data list"""
    result = []
    for item in input_list:
        if isinstance(item, int):
            result.append(item * 2)
        else:
            result.append(str(item).upper())
    return result
```

### Pseudocode Output
```
FUNCTION process_packet(buffer, length):
    IF length < HEADER_SIZE:
        RETURN ERROR_TOO_SHORT
    
    header = CAST<PacketHeader>(buffer)
    IF header.magic != EXPECTED_MAGIC:
        RETURN ERROR_INVALID_MAGIC
    
    payload = buffer + HEADER_SIZE
    RETURN handle_payload(payload, header.type)
```

## Quality Metrics

### Decompilation Quality Assessment
1. **Syntactic Correctness**: Does it compile?
2. **Semantic Preservation**: Same behavior?
3. **Readability Score**: Human assessment
4. **Type Recovery Rate**: % of types recovered
5. **Structure Recovery**: Loops, conditions identified

### Benchmarks
| Metric | Target | Current |
|--------|--------|---------|
| Compilation Rate | 95% | 87% |
| Semantic Accuracy | 99% | 94% |
| Type Recovery | 80% | 72% |
| Readability (1-10) | 7+ | 6.3 |

## Configuration

### Global Settings
```toml
[decompiler]
default_language = "c"
optimization_level = 2
type_inference = true
ai_enhancement = true
comment_generation = true

[decompiler.naming]
style = "snake_case"  # or "camelCase"
prefix_globals = "g_"
prefix_locals = "l_"
```

### Per-Architecture Settings
```toml
[decompiler.x86]
engine = "ghidra"
calling_conventions = ["cdecl", "stdcall", "fastcall"]

[decompiler.java]
engine = "fernflower"
deobfuscate = true
```

## Testing and Validation

### Round-Trip Testing
```
Source → Compile → Binary → Decompile → Source'
Compare: Source ≈ Source'
```

### Differential Testing
- Compare outputs from multiple decompilers
- Identify consensus vs. divergence
- Flag suspicious differences

### Corpus Testing
- Known binaries with source
- Malware samples with reports
- Obfuscated challenges

## Integration Examples

### Rust API
```rust
use glaurung::decompiler::{Decompiler, Language};

let decompiler = Decompiler::new()
    .architecture(Architecture::X86_64)
    .language(Language::C)
    .enable_type_recovery()
    .build()?;

let source = decompiler.decompile_function(&binary, function_addr)?;
println!("{}", source);
```

### Python API
```python
import glaurung

# Decompile entire binary
decompiler = glaurung.Decompiler(
    engine="ghidra",
    target_language="c",
    ai_enhance=True
)

program = decompiler.decompile_binary(binary_path)
for function in program.functions:
    print(f"// Function: {function.name}")
    print(function.source_code)
```

### CLI Usage
```bash
# Basic decompilation
glaurung decompile binary.exe -o source.c

# With options
glaurung decompile \
    --engine ghidra \
    --language cpp \
    --types auto \
    --ai-enhance \
    --comments \
    binary.exe
```

## Future Roadmap

### 2025 Q1-Q2
- [ ] Integrate Ghidra decompiler
- [ ] Implement type inference engine
- [ ] Add Rust output support

### 2025 Q3-Q4
- [ ] AI-powered variable naming
- [ ] Automated algorithm recognition
- [ ] Decompiler fuzzing framework

### 2026+
- [ ] Neural decompilation models
- [ ] Quantum algorithm recovery
- [ ] Cross-language translation

## Research and References

### Key Papers
1. "A Principled Approach to Decompilation" (Cifuentes, 1994)
2. "TIE: Principled Reverse Engineering of Types in Binary Programs" (Lee et al., 2011)
3. "Decompilation of Binary Programs" (Van Emmerik, 1994)
4. "Using Recurrent Neural Networks for Decompilation" (Katz et al., 2018)
5. "Phoenix: Towards Ultra-Low Overhead, Recoverable, and Correct Decompilation" (Chen et al., 2023)

### Books
- "Reversing: Secrets of Reverse Engineering" by Eldad Eilam
- "The IDA Pro Book" by Chris Eagle
- "Practical Binary Analysis" by Dennis Andriesse

### Tools and Resources
- [Ghidra Documentation](https://ghidra-sre.org/)
- [RetDec Wiki](https://github.com/avast/retdec/wiki)
- [Compiler Explorer](https://godbolt.org/) - Understanding compiler output
- [Decompiler Explorer](https://dogbolt.org/) - Compare decompilers

## Contributing

### Areas Needing Work
1. **RISC-V Decompilation**: Needs lifting rules
2. **Go Binary Support**: Unique calling conventions
3. **Rust Binary Support**: Trait recovery
4. **Swift Support**: Objective-C bridge handling
5. **Obfuscation Removal**: Advanced techniques

### How to Contribute
1. Implement new architecture support
2. Improve type inference algorithms
3. Add pattern recognition rules
4. Contribute test cases
5. Document decompilation techniques