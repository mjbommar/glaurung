# Glaurung Binary Lifting Architecture

## Overview

Binary lifting (also called binary translation or binary raising) transforms low-level machine code into higher-level intermediate representations (IR) suitable for program analysis, optimization, and transformation. Unlike decompilation which targets human-readable source code, lifting preserves precise semantics in a machine-analyzable form.

Glaurung uses binary lifting as a foundation for multiple analysis techniques:
- **Static Analysis**: Dataflow, taint analysis, symbolic execution
- **Optimization**: Binary optimization and hardening
- **Recompilation**: Cross-architecture translation
- **Decompilation**: IR serves as input to decompiler pipeline
- **Verification**: Formal methods and equivalence checking

## Core Design Principles

1. **Semantic Preservation**: Lifting must maintain exact program semantics
2. **IR Agnostic**: Support multiple target IRs (LLVM, VEX, REIL, etc.)
3. **Pluggable Lifters**: Multiple lifting engines per architecture
4. **Validation**: Automated correctness checking of lifted code
5. **Hybrid Approach**: Combine static and dynamic lifting techniques

## Target Intermediate Representations

### LLVM IR (Primary Target)

LLVM IR is Glaurung's primary lifting target for several reasons:
- **Rich Ecosystem**: Extensive optimization passes, analysis tools, backends
- **SSA Form**: Single Static Assignment simplifies dataflow analysis
- **Type System**: Strong typing aids in type recovery
- **Toolchain Integration**: Can recompile to native code via LLVM
- **Industry Support**: Widely used in compilers and binary analysis tools

**Trade-offs**:
- ✅ High-level, optimizable, well-documented
- ✅ Large ecosystem of analysis passes
- ❌ Originally designed for compilers, not binary analysis
- ❌ Can be verbose for low-level operations

### VEX IR (Secondary Target)

VEX IR (from Valgrind) is used by angr and other binary analysis frameworks:
- **Design**: Purpose-built for binary instrumentation and analysis
- **Performance**: Optimized for fast interpretation
- **Completeness**: Handles edge cases and undefined behavior explicitly

**Trade-offs**:
- ✅ Designed for binary analysis
- ✅ Fast interpretation
- ❌ Hundreds of instruction types (complexity)
- ❌ Smaller ecosystem than LLVM

### Other IR Targets (Future)

- **REIL** (Reverse Engineering Intermediate Language) - Simple, architecture-agnostic
- **BIL** (Binary Analysis IR) - Used by BAP framework
- **ESIL** (Evaluable Strings Intermediate Language) - radare2's IR
- **Microcode** - IDA Pro's internal IR

## LLVM IR Lifting Tools: State of the Art

### Static Binary Lifters

#### 1. llvm-mctoll (Microsoft) ⭐ Recommended for Clean IR

**Status**: Production-ready
**Architecture Support**: x86-64, ARM32
**Repository**: `github.com/microsoft/llvm-mctoll` → `reference/llvm-mctoll` (planned)

**Strengths**:
- Produces cleanest, most readable LLVM IR
- Closest to forward-compiled LLVM output
- Leverages LLVM optimization infrastructure
- Good for recompilation and optimization

**Limitations**:
- No SIMD support (SSE, AVX, Neon)
- Requires manual function annotations
- Limited to x86-64 and ARM32 (no 32-bit x86)
- Static analysis limitations with indirect calls

**Use Cases**:
- Binary optimization and hardening
- Cross-architecture recompilation
- When readable IR is critical
- Academic research on binary translation

**Quality Assessment**:
```
IR Quality:     ⭐⭐⭐⭐⭐ (closest to compiled LLVM)
Readability:    ⭐⭐⭐⭐⭐ (very clean, minimal artifacts)
Completeness:   ⭐⭐⭐   (function annotation required)
Speed:          ⭐⭐⭐⭐ (fast static analysis)
```

#### 2. RetDec (Avast) ⭐ Currently Integrated

**Status**: Maintenance mode, stable
**Architecture Support**: x86, x86-64, ARM, ARM64, MIPS, PowerPC
**Repository**: `github.com/avast/retdec` → `reference/retdec`

**Strengths**:
- Full decompiler with LLVM IR as intermediate output
- Multi-architecture support
- Produces both IR (.ll/.bc) and C code
- Good compiler/packer detection
- Handles obfuscation reasonably well

**Limitations**:
- Primary focus is decompilation, not lifting
- "Curved" lifting path (optimized for C output)
- Generates artifacts (bit masking, type confusion)
- Symbol resolution can be incomplete

**Outputs**:
- `.ll` - LLVM IR text format
- `.bc` - LLVM bitcode binary
- `.c` - Decompiled C code
- `.dsm` - Annotated disassembly
- `.config.json` - Metadata and analysis results

**Use Cases**:
- Reverse engineering binaries
- When both IR and C output are needed
- Multi-architecture support required
- Packer/obfuscation analysis

**Quality Assessment**:
```
IR Quality:     ⭐⭐⭐⭐ (good, but decompiler-optimized)
Readability:    ⭐⭐⭐⭐ (readable with some artifacts)
Completeness:   ⭐⭐⭐⭐⭐ (lifts entire programs)
Speed:          ⭐⭐⭐   (slower due to full pipeline)
```

**Experimental Results**: See [experiments/retdec-test-2025-10-20.md](experiments/retdec-test-2025-10-20.md)

#### 3. rev.ng

**Status**: Active development
**Architecture Support**: x86, x86-64, ARM, AArch64, MIPS, SystemZ
**Repository**: `github.com/revng/revng` (not yet in reference/)

**Strengths**:
- Modern static lifter design
- Good correctness guarantees
- Control flow graph recovery
- Support for position-independent code

**Limitations**:
- Less mature than RetDec/McSema
- Smaller community
- Documentation can be sparse

**Use Cases**:
- Academic research
- When correctness is paramount
- Modern binary formats

### Dynamic Binary Lifters

#### 4. BinRec (Trail of Bits) ⭐ Recommended for Accuracy

**Status**: Research tool, production-capable
**Architecture Support**: x86-64
**Repository**: `github.com/trailofbits/binrec-tob` (not yet in reference/)

**Strengths**:
- Uses dynamic tracing for accuracy
- Handles obfuscation and self-modification
- Produces correct IR even for complex code
- Can optimize lifted code
- Recompilation capability

**Limitations**:
- Requires execution (test inputs needed)
- Slower than static lifting
- Limited architecture support
- May miss cold code paths

**Use Cases**:
- Obfuscated or packed binaries
- When static analysis fails
- Binary optimization projects
- Security-critical applications

**Quality Assessment**:
```
IR Quality:     ⭐⭐⭐⭐⭐ (excellent, execution-validated)
Readability:    ⭐⭐⭐⭐ (clean, optimized)
Completeness:   ⭐⭐⭐⭐⭐ (captures actual execution)
Speed:          ⭐⭐     (dynamic overhead)
```

### Instruction-Level Lifters (Building Blocks)

#### 5. Remill (Trail of Bits) ⭐ Foundation Library

**Status**: Production-ready library
**Architecture Support**: x86, x86-64, AArch64, SPARC32, SPARC64
**Repository**: `github.com/lifting-bits/remill` → `reference/remill` (planned)

**Strengths**:
- Precise instruction semantics
- Used by McSema and other tools
- Clean, modular design
- Well-documented instruction semantics
- Handles edge cases correctly

**Limitations**:
- Only lifts instructions, not whole programs
- Requires additional tooling for CFG recovery
- No built-in optimization passes

**Use Cases**:
- Building custom lifters
- Instruction-level analysis
- When precise semantics are critical
- Foundation for other tools

**Quality Assessment**:
```
IR Quality:     ⭐⭐⭐⭐⭐ (instruction-perfect)
Readability:    ⭐⭐⭐⭐⭐ (clean semantics)
Completeness:   ⭐⭐     (instruction-only)
Speed:          ⭐⭐⭐⭐⭐ (very fast)
```

**Integration Strategy**: Use Remill as the semantic foundation, build program-level lifter on top.

#### 6. McSema (Trail of Bits)

**Status**: Production-ready
**Architecture Support**: x86, x86-64, AArch64
**Repository**: `github.com/lifting-bits/mcsema` → `reference/mcsema` (planned)

**Strengths**:
- Lifts whole programs
- Uses Remill for instruction semantics
- Mature, well-tested
- Good CFG recovery

**Limitations**:
- Uses `struct.State` virtual machine approach
- Produces verbose, hard-to-read IR
- Larger instruction counts than other lifters
- Indirection through state struct

**IR Characteristics**:
```c
// McSema uses a virtual machine approach:
struct State {
    uint64_t RAX;
    uint64_t RBX;
    // ... all registers ...
};

void function_lifted(struct State *state) {
    state->RAX = state->RBX + 5;  // Indirect through struct
    // vs direct LLVM: %result = add i64 %rbx, 5
}
```

**Use Cases**:
- When program-level lifting is needed
- Complex control flow recovery
- Can tolerate verbose IR

**Quality Assessment**:
```
IR Quality:     ⭐⭐⭐   (correct but verbose)
Readability:    ⭐⭐     (struct.State indirection)
Completeness:   ⭐⭐⭐⭐⭐ (whole programs)
Speed:          ⭐⭐⭐⭐ (fast static)
```

## Emerging Tools (2024-2025)

### Neural/ML-Based Lifters

#### Forklift (April 2024)

**Status**: Research prototype
**Approach**: Neural network-based lifting

**Performance**:
- 2.5× more accurate than Lasagne
- 4.4× more accurate than GPT-4
- No manual engineering required

**Implications**: Future of lifting may be learned rather than hand-coded.

#### LEARNT (September 2024)

**Status**: Research prototype
**Approach**: Neural machine translation for binary lifting

**Significance**: Shows promise for handling optimization and obfuscation.

#### SLaDe (March 2024)

**Status**: Research prototype
**Approach**: Small language model decompiler for optimized assembly

**Focus**: Specialized models for binary code understanding.

## Tool Comparison Matrix

| Tool | Approach | IR Quality | Readability | Arch Support | Speed | Maturity | Artifacts |
|------|----------|------------|-------------|--------------|-------|----------|-----------|
| **llvm-mctoll** | Static | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | x64, ARM32 | ⭐⭐⭐⭐ | Stable | Minimal |
| **RetDec** | Static | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | Multi-arch | ⭐⭐⭐ | Stable | Moderate |
| **BinRec** | Dynamic | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | x64 | ⭐⭐ | Research | Minimal |
| **McSema** | Static | ⭐⭐⭐ | ⭐⭐ | x86/x64/ARM | ⭐⭐⭐⭐ | Stable | High (struct) |
| **Remill** | Instruction | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Multi-arch | ⭐⭐⭐⭐⭐ | Stable | None |
| **rev.ng** | Static | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | Multi-arch | ⭐⭐⭐⭐ | Active | Low |

### Lifting Quality Characteristics

**IR Quality**: Semantic accuracy, optimization potential
**Readability**: How close to forward-compiled LLVM
**Arch Support**: Number of supported architectures
**Speed**: Lifting performance
**Maturity**: Production-readiness and stability
**Artifacts**: Unnecessary instructions, type confusion, indirection

## Recommendations for Glaurung

### Tier 1: Core Integration

1. **Remill** - Foundation for instruction semantics
   - Integrate as library dependency
   - Use for accurate instruction lifting
   - Build program-level analysis on top

2. **llvm-mctoll** - Primary static lifter
   - Best IR quality for x86-64 and ARM
   - Use for optimization and recompilation
   - Fallback when clean IR is needed

3. **RetDec** - Current integration
   - Keep for multi-architecture support
   - Use when both IR and C output needed
   - Good for decompilation pipeline

### Tier 2: Specialized Tools

4. **BinRec** - Dynamic lifting fallback
   - Add for obfuscated binaries
   - Use when static lifting fails
   - Requires test harness infrastructure

5. **McSema** - Consider for specific use cases
   - May be useful for complex CFG recovery
   - Accept verbose IR as trade-off
   - Primarily for compatibility

### Integration Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Glaurung Binary                      │
└────────────────────────┬────────────────────────────────┘
                         ▼
              ┌──────────────────────┐
              │  Triage & Detection  │
              └──────────┬───────────┘
                         ▼
         ┌───────────────────────────────┐
         │   Architecture Detection      │
         └───────────┬───────────────────┘
                     ▼
    ┌────────────────────────────────────────┐
    │        Lifter Selection Layer          │
    │  (Choose best lifter for binary type)  │
    └────┬────────────┬───────────┬──────────┘
         │            │           │
         ▼            ▼           ▼
    ┌────────┐  ┌─────────┐  ┌─────────┐
    │ Remill │  │ mctoll  │  │ RetDec  │
    │(Instr) │  │(Static) │  │(Decomp) │
    └────┬───┘  └────┬────┘  └────┬────┘
         │           │            │
         └───────────┴────────────┘
                     ▼
         ┌───────────────────────┐
         │    LLVM IR (.ll/.bc)  │
         └───────────┬───────────┘
                     ▼
         ┌───────────────────────┐
         │  LLVM Optimization    │
         │      Passes           │
         └───────────┬───────────┘
                     ▼
    ┌────────────────────────────────────┐
    │         Analysis Pipelines         │
    │  • Dataflow Analysis               │
    │  • Taint Tracking                  │
    │  • Symbolic Execution              │
    │  • Decompilation                   │
    │  • Recompilation                   │
    └────────────────────────────────────┘
```

### Implementation Phases

**Phase 1: Foundation (Current)**
- ✅ RetDec integration via git submodule
- ✅ LLVM IR output capability
- ✅ Basic lifting pipeline

**Phase 2: Enhancement (Next)**
- ⬜ Integrate Remill as library
- ⬜ Build program-level lifter on Remill
- ⬜ LLVM IR analysis pass infrastructure
- ⬜ Lifting validation framework

**Phase 3: Expansion**
- ⬜ Add llvm-mctoll integration
- ⬜ BinRec for dynamic lifting
- ⬜ Multi-lifter comparison mode
- ⬜ Automated lifter selection

**Phase 4: Advanced**
- ⬜ Custom hybrid lifter
- ⬜ ML-based lifting experiments
- ⬜ Cross-validation between lifters
- ⬜ Lifting quality metrics

## Validation and Testing

### Correctness Validation

Ensuring lifted IR preserves semantics:

1. **Round-trip Testing**: Compile → Lift → Recompile → Compare
2. **Differential Testing**: Compare multiple lifters on same binary
3. **Dynamic Validation**: Execute original vs lifted code
4. **Formal Verification**: Prove semantic equivalence (research)

### Quality Metrics

Measuring lifting quality:

- **Instruction Count**: Lower is better (less verbosity)
- **SSA Form**: Proper phi nodes and dominance
- **Type Recovery**: Accurate type inference
- **Control Flow**: Correct CFG reconstruction
- **Optimization Potential**: Can LLVM optimize it?

### Test Suite

Build comprehensive test suite:
- Simple functions (factorial, fibonacci)
- Complex control flow (switches, exceptions)
- Optimized code (-O2, -O3)
- Obfuscated code (commercial packers)
- Real-world binaries (coreutils, libraries)

## Research Directions

### Active Research Areas

1. **Neural Lifting**: ML-based instruction semantics
2. **Hybrid Approaches**: Combining static + dynamic
3. **Type Recovery**: Better inference of high-level types
4. **Cross-Architecture**: Universal lifter for all ISAs
5. **Obfuscation Handling**: Specialized lifting for protected code

### Open Problems

- **Indirect Calls**: Resolving function pointers statically
- **Self-Modifying Code**: Handling runtime code generation
- **Exception Handling**: Preserving exception semantics
- **Floating Point**: Precise FP semantics in IR
- **SIMD Instructions**: Lifting vector operations correctly

## References

### Papers and Publications

- **BinRec** (EuroSys 2020): "BinRec: Dynamic Binary Lifting and Recompilation"
- **MCTOLL** (LCTES 2019): "Raising Binaries to LLVM IR with MCTOLL"
- **Forklift** (April 2024): "An Extensible Neural Lifter"
- **LEARNT** (September 2024): "Neural Machine Translation for Binary Lifting"
- **Validation** (PLDI 2020): "Scalable Validation of Binary Lifters"

### Related Documentation

- [Decompiler Architecture](../decompiler/README.md) - IR to source code
- [Disassembly Architecture](../disassembly/README.md) - Binary to assembly
- [Data Model](../../architecture/data-model/README.md) - IR representation

### External Resources

- [LLVM Language Reference](https://llvm.org/docs/LangRef.html)
- [Remill Documentation](https://github.com/lifting-bits/remill/tree/master/docs)
- [McSema Documentation](https://github.com/lifting-bits/mcsema/tree/master/docs)
- [RetDec Wiki](https://github.com/avast/retdec/wiki)
- [Binary Lifting Survey](https://alastairreid.github.io/RelatedWork/notes/binary-lifter/)

### Reference Implementations

All reference implementations are available as git submodules in `reference/`:
- `reference/retdec` - RetDec decompiler
- `reference/remill` - Instruction lifter (planned)
- `reference/mcsema` - Program lifter (planned)
- `reference/llvm-mctoll` - Static binary raiser (planned)

## Experimental Results

See `experiments/` directory for detailed lifting tests and comparisons:
- [RetDec Test (2025-10-20)](experiments/retdec-test-2025-10-20.md) - Simple C program lifting

---

**Document Status**: Active Development
**Last Updated**: 2025-10-20
**Contributors**: Initial research and implementation planning
