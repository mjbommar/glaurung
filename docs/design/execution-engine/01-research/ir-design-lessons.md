# IR Design Lessons — Making an IR Executable

How VEX (angr), Ghidra P-code, BAP BIL, Binary Ninja LLIL, radare2 ESIL, Miasm,
and Triton solve the problems that turn a *lossy* IR into a *total, typed,
executable* one. Mapped onto our LLIR.

## Headline: three properties every executor-grade IR has (and ours lacks)

1. **Totality** — no "unknown instruction" hole. Unmodeled instructions lift to a
   *typed, side-effect-declaring* opaque op, never nothing. (VEX dirty calls,
   P-code `CALLOTHER`, BIL typed `Unknown`, LLIL intrinsics, ESIL `TRAP`.)
2. **Per-value bit width** — every operand of every op has a known width. (P-code
   varnode = `(space, offset, size)`; VEX strongly-typed temps; BIL typed imms;
   Miasm size on every `Expr`.)
3. **One semantic core, multiple value backends** — write the interpreter once,
   parameterize the value type. (angr/claripy backends; Triton concolic AST;
   BINSEC DBA; Miasm `SymbolicExecutionEngine` over the same IR.)

## 1. Totality / unmodeled instructions

**Pattern:** emit an opaque, **named, typed** op that *declares its read/write
footprint*, not a bare "unknown".

- **VEX "dirty calls" (`Ist_Dirty`)** — for `cpuid`/`rdtsc`/x87: a call to a
  helper that declares which guest-state ranges it reads/writes and whether it
  touches memory, so dataflow stays sound over an opaque body.
- **P-code `CALLOTHER`** — placeholder for unmodeled behavior, **incrementally
  refinable**: start as a black box, later inject real p-code without changing IR
  shape. This is the model to copy.
- **BIL `Unknown`** — carries a *type annotation*, so it composes in a typed tree
  instead of poisoning downstream.
- **BNIL `LLIL_INTRINSIC`** — named op with explicit input/output operand lists →
  def/use preserved even when the math is opaque.

**Tradeoff:** a black box that declares its footprint keeps taint/dataflow sound
and lets a symbolic engine mint fresh symbols for outputs; a bare trap is sound
only by halting. **Recommendation:** replace `Op::Unknown { mnemonic }` with
`Op::Intrinsic { name, ins, outs, reads_mem, writes_mem }`, refinable into real
ops later. → [`../02-architecture/helpers-and-intrinsics.md`](../02-architecture/helpers-and-intrinsics.md)

## 2. Bit-width / typing

**Pattern:** width is a property of every value; width changes are explicit total
ops; arithmetic is modular at the operand width by definition.

- P-code width ops: `INT_ZEXT`, `INT_SEXT`, `SUBPIECE` (truncate/extract),
  `PIECE` (concat, endianness-aware).
- BIL casts: `UNSIGNED`/`SIGNED` (extend), `HIGH`/`LOW` (narrow, *which* half
  explicit).
- Overflow as **separate predicate ops**, not a side effect: P-code `INT_CARRY`
  (unsigned), `INT_SCARRY` (signed add), `INT_SBORROW` (signed sub) → 1-bit
  results. This is exactly how to define flags soundly.

**Why it's mandatory:** a bit-vector SMT solver (Z3/Bitwuzla) *requires* widths;
an untyped `i64` cannot be lowered to SMT without guessing, and concrete
wraparound is undefined. **Recommendation:** typed `Const { value, width }`;
width on every `Bin`/`Un`/`Cmp`/`Load`/`Store`; explicit `ZExt`/`SExt`/`Trunc`/
`Extract`/`Concat`. → [`../02-architecture/executable-llir.md`](../02-architecture/executable-llir.md)

## 3. Flags / condition codes

The sharpest speed-vs-precision split:

- **Lazy thunk (VEX `cc_op`/`cc_dep`, QEMU `CC_OP`)** — store the op + operands,
  compute the flag only when read. Fast for concrete (most flags never read), but
  a **symbolic `cc_op` blows up** the solver. Avoid.
- **Producer/consumer + roles (Binary Ninja)** — only generate a flag's
  computation when a consumer exists; each live flag is a concrete, solver-friendly
  expression. Best of both. **Adopt this.**
- **Eager per-flag (P-code/BIL/ESIL/Miasm)** — each flag a 1-bit var via an
  explicit predicate. Maximally solver-friendly; compute some you never read
  (DCE mitigates).

**Recommendation:** keep our existing condition-code flag VRegs (already the right
abstraction), define each via an explicit width-typed predicate op, and only
materialize when consumed. We already have a DCE pass for dead flag writes
(`src/ir/dce.rs`) — extend it.

## 4. Sub-register / partial-register writes

**Pattern:** a **flat, byte-offset register file** with `(offset, size)` get/put
makes aliasing structural and automatic (VEX guest-state offsets; P-code register
address space). The x86-64 quirk — *write `eax` zeroes upper `rax`, write `al`
does not* — is encoded **by the lifter** (32-bit write emits an explicit
zero-extend), not by an IR rule. Miasm/BIL alternative: algebraic slice/compose
(`AH = EAX[8:16]`, `AX = AH.AL`) — cleaner for symbolic algebra but pushes
correctness onto the lifter.

**Recommendation:** flat guest-state byte array for the machine's register file
(→ [`../02-architecture/machine-state.md`](../02-architecture/machine-state.md));
lifter emits explicit ext on 32-bit writes. Our current `ioctl_taint`
"sub-register canonicalization" is an approximation that the real register file
replaces.

## 5. Memory & endianness

**Pattern:** load/store carry explicit access width **and** endianness; the engine
stays endian-agnostic, the lifter decides. (VEX `LDle:I32`; BIL endianness as a
Load/Store parameter; P-code endianness as an address-space property.)

**Recommendation:** add an `endian` field to `MemOp` (it already has `size`); make
access width authoritative.

## 6. One semantic core for concrete AND symbolic

The architecture decision. Every dual-mode framework reuses **one interpreter
parameterized by the value/abstract-value type**:

- **angr/claripy** — values are claripy ASTs dispatched to backends:
  `BackendConcrete` (ints), `BackendZ3` (symbolic), `BackendVSA` (intervals). The
  VEX interpreter is written once.
- **Triton** — synchronized concrete + symbolic state over the *same* semantics.
- **BINSEC** — one DBA consumed by both simulator and symbolic engine.

**Recommendation — the keystone:** a Rust `trait Domain` providing bit-vector
primitives (`add(w)`, `zext`, `sext`, `extract`, `concat`, `ite`, `eq/ult/slt`,
`load`, `store`); implement `Concrete` (wrapping `u128`+width), `Symbolic`
(SMT terms), later `Interval`/`VSA`. **Validated by prototype** (see
[`../02-architecture/value-domain-trait.md`](../02-architecture/value-domain-trait.md)).

## 7. Cross-architecture

A single typed IR lets you write the engine **once**; ISA-specificity is confined
to (a) the lifter/decoder, (b) the register-file/guest-state layout *as data*,
(c) intrinsic/helper handlers, (d) ABI/syscall conventions. Proven by VEX (angr:
x86/ARM/MIPS/PPC/RISC-V), P-code (Ghidra: dozens of arches), BINSEC (x86/ARM/
RISC-V). Per-arch quirks (ARM IT-blocks, MIPS delay slots, bi-endianness, lazy
x86 flags) live in the lifter only.

## Prioritized recommendations (→ Phase 0)

- **P0-a** Width on every value & op; modular arithmetic by width.
- **P0-b** Explicit `ZExt`/`SExt`/`Trunc`/`Extract`/`Concat`.
- **P0-c** Replace `Op::Unknown` with footprint-declaring `Op::Intrinsic`.
- **P0-d** Flat byte-offset register file; lifter encodes x86-64 32-bit
  zero-extend rule.
- **P0-e** Flags via explicit predicate ops, producer/consumer materialization.
- **P0-f** `endian` on `MemOp`; width authoritative.
- **P1**  The `Domain` trait + interpreter written once over it.

## Sources

- [angr — VEX IR](https://docs.angr.io/advanced-topics/ir), [claripy backends](https://docs.angr.io/en/latest/advanced-topics/claripy.html)
- [Ghidra P-code Reference](https://ghidra.re/ghidra_docs/languages/html/pcoderef.html), [P-code Operations](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html), [CALLOTHER injection](https://swarm.ptsecurity.com/guide-to-p-code-injection/)
- [BAP BIL API](http://binaryanalysisplatform.github.io/bap/api/master/bap/Bap/Std/Bil/index.html)
- [Binary Ninja — Flags](https://docs.binary.ninja/dev/flags.html), [BNIL](https://docs.binary.ninja/dev/bnil-overview.html), [ToB: Breaking Down LLIL](https://blog.trailofbits.com/2017/01/31/breaking-down-binary-ninjas-low-level-il/)
- [radare2 ESIL](https://github.com/radareorg/radare2/blob/master/doc/esil.md)
- [Miasm expressions](https://github.com/cea-sec/miasm/blob/master/doc/expression/expression.ipynb), [SymbolicExecutionEngine](https://miasm.re/miasm_doxygen/classmiasm_1_1ir_1_1symbexec_1_1_symbolic_execution_engine.html)
- [Triton](https://triton-library.github.io/), [BINSEC/SE (DBA)](http://sebastien.bardin.free.fr/2016-saner.pdf)
