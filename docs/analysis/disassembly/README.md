# Glaurung Disassembly Architecture

> **Status:** This document began as a broad architecture proposal. Sections
> describing engines, benchmarks, and future architecture tiers are design
> context, not a promise that every listed backend is shipped. For current
> user-facing behavior, use `uv run glaurung disasm --help` and the source under
> `src/disasm/`.

## Overview

Glaurung provides a comprehensive, multi-tiered disassembly architecture supporting native machine code, bytecode, and specialized instruction sets. This document outlines our disassembly capabilities, implementation strategy, and integration approach.

## Core Design Principles

1. **Unified Interface**: Single trait-based API for all disassemblers
2. **Pluggable Backends**: Support multiple disassembly engines per architecture
3. **Performance-First**: Zero-copy operations where possible
4. **Safety**: Memory-safe Rust implementations with controlled FFI
5. **Completeness**: Support for all major architectures and bytecode formats

## Architecture Support Matrix

### Tier 1: Production-Ready Native Architectures

| Architecture | Primary Engine | Fallback Engines | Status | Notes |
|-------------|---------------|------------------|--------|-------|
| **x86/x86-64** | Zydis | XED, iced-x86, bddisasm, Capstone | ✅ Ready | Full AVX-512, APX support |
| **ARM/AArch64** | Capstone | iced-arm, B2R2 | ✅ Ready | ARMv9, SVE2 support |
| **RISC-V** | Capstone | riscv-decode | ✅ Ready | RV32/64IMAFDC |
| **MIPS** | Capstone | B2R2 | ✅ Ready | MIPS I-V, microMIPS |
| **PowerPC** | Capstone | B2R2 | ✅ Ready | PPC32/64, Altivec |
| **SPARC** | Capstone | - | ⚠️ Limited | V8/V9 |
| **SystemZ** | Capstone | - | ⚠️ Limited | z/Architecture |
| **WebAssembly** | WABT | wasm3, wasmer | ✅ Ready | Full 1.0 spec |

### Tier 2: Bytecode and Virtual Machines

| Platform | Engine | Format | Status | Coverage |
|----------|--------|--------|--------|----------|
| **Java/JVM** | javap, ASM | .class, .jar | ✅ Ready | Java 8-21 |
| **.NET/CLR** | ILSpy, dnlib | .dll, .exe | ✅ Ready | .NET Framework, Core, 5+ |
| **Python** | dis, uncompyle6 | .pyc, .pyo | ✅ Ready | 2.7, 3.6-3.12 |
| **Ruby** | RubyVM::InstructionSequence | .rb | 🚧 Planned | YARV bytecode |
| **Lua** | luadec | .luac | ✅ Ready | Lua 5.1-5.4 |
| **Erlang/BEAM** | beam_disasm | .beam | 🚧 Planned | OTP 24+ |
| **Dalvik/ART** | baksmali | .dex, .odex | ✅ Ready | Android 4.0+ |
| **Flash/ActionScript** | RABCDAsm | .swf | ⚠️ Limited | AS2/AS3 |

### Tier 3: GPU and Specialized Processors

| Platform | Engine | ISA | Status | Notes |
|----------|--------|-----|--------|-------|
| **NVIDIA GPU** | nvdisasm, cuobjdump | PTX, SASS | ✅ Ready | CUDA 11+ |
| **AMD GPU** | rocm-objdump | GCN, RDNA | ⚠️ Limited | ROCm support |
| **Intel GPU** | iga | Gen ISA | ⚠️ Limited | Gen9+ |
| **SPIR-V** | spirv-dis, spirv-cross | SPIR-V | ✅ Ready | Vulkan, OpenCL |
| **DirectX Shaders** | dxc, fxdis | DXIL, DXBC | ✅ Ready | SM 5.0+ |
| **OpenGL Shaders** | glslang | GLSL | ✅ Ready | OpenGL 3.3+ |
| **Metal Shaders** | metal-dis | Metal IR | 🚧 Planned | iOS/macOS |

### Tier 4: Embedded and Legacy

| Architecture | Engine | Status | Notes |
|-------------|--------|--------|-------|
| **AVR** | avr-objdump, vAVRdisasm | ✅ Ready | Arduino, ATmega |
| **PIC** | gpdasm | ⚠️ Limited | PIC16/18/24 |
| **8051** | dis51 | ⚠️ Limited | 8051 variants |
| **MSP430** | msp430-objdump | ✅ Ready | TI MSP430 |
| **Xtensa** | xtensa-objdump | ⚠️ Limited | ESP32 |
| **Z80** | z80dasm | ✅ Ready | Z80, Z180 |
| **6502** | da65 | ✅ Ready | 6502, 65C02 |
| **68000** | m68k-objdump | ✅ Ready | 68000-68060 |

## Implementation Architecture

### 1. Core Trait System

```rust
// src/core/disassembler.rs
pub trait Disassembler {
    fn disassemble_instruction(&self, address: &Address, bytes: &[u8]) 
        -> DisassemblerResult<Instruction>;
    fn max_instruction_length(&self) -> usize;
    fn architecture(&self) -> Architecture;
    fn endianness(&self) -> Endianness;
}
```

### 2. Engine Selection Strategy

```
Priority Order:
1. User-specified engine (if provided)
2. Performance-optimized engine (Zydis for x86, etc.)
3. Feature-complete engine (Capstone)
4. Fallback engine (for validation/comparison)
```

### 3. Layered Architecture

```
┌─────────────────────────────────────┐
│         Python/CLI Interface        │
├─────────────────────────────────────┤
│      Unified Disassembler API       │
├─────────────────────────────────────┤
│        Engine Selector/Router       │
├──────┬──────┬──────┬──────┬────────┤
│Zydis │ XED  │Cpstn │iced  │ WABT   │
├──────┴──────┴──────┴──────┴────────┤
│        Safe FFI Layer               │
├─────────────────────────────────────┤
│     Native Libraries (C/C++)        │
└─────────────────────────────────────┘
```

## Engine Comparison and Selection

### x86/x64 Disassemblers

| Engine | Speed | Memory | Features | License | When to Use |
|--------|-------|--------|----------|---------|------------|
| **Zydis** | 200+ MB/s | Zero alloc | Full Intel SDM | MIT | Default, performance-critical |
| **Intel XED** | 150 MB/s | Low | Official Intel | Apache 2.0 | Latest ISA, validation |
| **iced-x86** | 250+ MB/s | Zero alloc | Pure Rust | MIT | Rust ecosystem integration |
| **bddisasm** | 180 MB/s | Zero alloc | Hypervisor-ready | Apache 2.0 | Security applications |
| **Capstone** | 100 MB/s | Moderate | Multi-arch | BSD | Fallback, multi-arch needs |

### Selection Criteria

1. **Accuracy**: Correctness of disassembly
2. **Performance**: Instructions per second
3. **Memory Usage**: Allocation patterns
4. **Feature Coverage**: Instruction set completeness
5. **Maintenance**: Active development status
6. **Integration**: Ease of FFI/binding

## Advanced Features

### 1. Linear Sweep Disassembly
- Start-to-end continuous disassembly
- Gap detection and handling
- Invalid instruction recovery

### 2. Recursive Descent Disassembly
- Control flow following
- Function boundary detection
- Cross-reference generation

### 3. Speculative Disassembly
- Multiple interpretation paths
- Confidence scoring
- Heuristic-based selection

### 4. Parallel Disassembly
- Thread-safe engine instances
- Work-stealing queue
- Chunked processing

### 5. Streaming Disassembly
- Large file handling
- Memory-mapped I/O
- Progressive loading

## Integration Examples

### Rust Integration

```rust
use glaurung::disasm::{DisassemblerBuilder, Architecture};

// Create x86-64 disassembler with Zydis backend
let disasm = DisassemblerBuilder::new()
    .architecture(Architecture::X86_64)
    .engine("zydis")
    .syntax("intel")
    .build()?;

// Disassemble bytes
let instruction = disasm.disassemble(&address, &bytes)?;
println!("{}", instruction);
```

### Python Integration

```python
import glaurung

# Create disassembler
disasm = glaurung.Disassembler(
    arch=glaurung.Architecture.X86_64,
    engine="zydis"
)

# Disassemble function
for insn in disasm.disassemble_function(binary, address):
    print(f"{insn.address:08x}: {insn.mnemonic} {insn.operands}")
```

## Performance Benchmarks

### x86-64 Disassembly (1GB Binary)

| Engine | Time | Throughput | Memory |
|--------|------|------------|--------|
| iced-x86 | 3.8s | 263 MB/s | 12 MB |
| Zydis | 4.9s | 204 MB/s | 8 MB |
| bddisasm | 5.5s | 181 MB/s | 6 MB |
| XED | 6.7s | 149 MB/s | 18 MB |
| Capstone | 10.2s | 98 MB/s | 45 MB |

## Configuration Options

Glaurung does not currently load the proposed `[disassembly]` TOML tables from
earlier versions of this document. Configure a CLI invocation directly:

```bash
uv run glaurung disasm BINARY \
  --engine auto \
  --arch x86_64 \
  --addr 0x401000 \
  --window-bytes 4096 \
  --max-instructions 200 \
  --max-time-ms 1000
```

`--engine` accepts `auto`, `iced`, or `capstone`. Architecture, address/window,
instruction-count, and time bounds are also per-invocation flags. KB-aware
function disassembly uses `--db PROJECT.glaurung --function NAME_OR_VA`.
Run `uv run glaurung disasm --help` for the current choices and defaults.

## Error Handling

### Error Types
1. **InvalidInstruction**: Unrecognized opcode
2. **InsufficientBytes**: Truncated instruction
3. **UnsupportedArchitecture**: No engine available
4. **EngineError**: Backend-specific failure

### Recovery Strategies
- Fallback to alternative engine
- Skip and continue
- Heuristic resynchronization
- User-defined handlers

## Testing Strategy

### 1. Correctness Testing
- Cross-validation between engines
- Known instruction corpus
- Fuzzing with random bytes

### 2. Performance Testing
- Benchmark suite
- Memory profiling
- Stress testing

### 3. Integration Testing
- FFI boundary testing
- Multi-threaded scenarios
- Error injection

## Future Roadmap

### Phase 1 (Q1 2025)
- [ ] Complete Zydis integration
- [ ] Implement engine selection logic
- [ ] Add streaming disassembly

### Phase 2 (Q2 2025)
- [ ] GPU disassembly support
- [ ] Custom architecture plugins
- [ ] ML-based instruction recovery

### Phase 3 (Q3 2025)
- [ ] Quantum computing ISAs
- [ ] Neural processor units
- [ ] Homomorphic encryption support

## References

### Specifications
- Intel® 64 and IA-32 Architectures Software Developer's Manual
- ARM Architecture Reference Manual
- RISC-V ISA Specification
- WebAssembly Core Specification
- SPIR-V Specification

### Academic Papers
- "A Retargetable Machine Code Decompiler" (Van Emmerik, 2007)
- "Native x86 Decompilation Using Semantics-Preserving Structural Analysis" (Schwartz et al., 2013)
- "Probabilistic Disassembly" (Miller et al., 2019)

### Tools and Libraries
- [Capstone](https://www.capstone-engine.org/)
- [Zydis](https://zydis.re/)
- [Intel XED](https://intelxed.github.io/)
- [WABT](https://github.com/WebAssembly/wabt)
- [ILSpy](https://github.com/icsharpcode/ILSpy)
