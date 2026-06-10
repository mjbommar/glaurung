# Helpers & Intrinsics — Total Coverage with a Small Core

QEMU's lesson: keep the interpreter's op set small; push everything exotic
(SIMD, FP, `DIV`, `CPUID`, `RDTSC`, syscalls, system registers) into **helpers**.
This is also how we achieve **totality** — `Op::Unknown` is gone; an unmodeled
instruction lifts to `Op::Intrinsic`, which dispatches to a helper (or, if no
helper is registered, to a sound fallback).

## Two related concepts

- **`Op::Intrinsic`** (IR-level) — a typed, footprint-declaring opaque op produced
  by the lifter (replaces `Unknown`). It names an operation and declares its
  inputs, outputs, and whether it touches memory.
- **Helper** (engine-level) — the Rust function that *implements* an intrinsic for
  a given `Domain`. Registered in a `HelperRegistry`.

```rust
pub struct Intrinsic { name: String, ins: Vec<Value>, outs: Vec<(VReg, Width)>,
                       reads_mem: bool, writes_mem: bool }

pub trait Helper<D: Domain> {
    fn call(&self, m: &mut Machine<D>, ins: &[D::Val], outs: &[(VReg, Width)]) -> Result<(), ExecError>;
}
pub struct HelperRegistry<D: Domain> { map: HashMap<&'static str, Box<dyn Helper<D>>> }
```

## The calling contract (from QEMU's global-sync rule)

Before dispatching a helper, the interpreter **flushes** any dirty register
operands to the canonical register file; after, it **reloads**. Helpers operate
only on `&mut Machine<D>` (register file + memory), never on interpreter-internal
temporaries. This keeps helpers simple and correct regardless of how the
interpreter caches values.

## Behavior per domain

| Intrinsic | Concrete helper | Symbolic helper |
|---|---|---|
| `div`/`idiv` | compute quotient/remainder, raise on div-by-zero | build `bvudiv`/`bvsdiv` terms; add div-by-zero path constraint |
| `cpuid` | return a **fixed, configured** feature set | same fixed concrete values (deterministic) |
| `rdtsc` | virtual monotonic counter (instruction count) | same |
| `rdrand`/`rdseed` | **seeded deterministic PRNG** | fresh symbol or seeded value |
| `pshufb`/SSE/AVX | scalar-loop over lanes on the vector cell | per-lane `bvextract`/`concat` terms, or **fresh symbol** if too complex |
| `fadd`/x87/VFP | software FP (correctness-first) | fresh symbol (FP-SMT deferred; N6 non-goal) |
| `syscall`/`svc` | dispatch to OS layer ([`os-abi-layer.md`](os-abi-layer.md)) | model/concretize per OS stub |

## The sound fallback (when no helper is registered)

If an `Intrinsic` has no registered helper, the engine must stay **sound**, not
silently wrong:

- **Concrete mode:** halt with `Halt::UnsupportedIntrinsic { name }`. The caller
  sees exactly where coverage ran out (never a wrong result). This is the
  emulator analog of P-code halting on an un-injected `CALLOTHER`.
- **Symbolic mode:** havoc the declared outputs — assign each `out` a **fresh
  symbol** — and, if `writes_mem`, mark the declared memory footprint symbolic.
  Execution continues soundly (over-approximate), which is exactly what a symbolic
  engine wants for an unmodeled op (VEX dirty-call semantics).

The footprint declaration (`ins`/`outs`/`reads_mem`/`writes_mem`) is what makes
the fallback sound for dataflow/taint even with an opaque body.

## Coverage roadmap

- **Phase 0**: lifters emit `Intrinsic` for everything they don't model (replacing
  `Unknown`); the conservative footprint is "reads+writes mem, no typed outs"
  until refined.
- **Phase 1**: helpers for the common scalar intrinsics needed to run real x86-64
  functions to completion — `div`/`idiv`, `mul`/`imul` high part, `cpuid`,
  `rdtsc`, `bswap`, `rol`/`ror`, `bt`/`bts`, `cmpxchg`, `xchg`.
- **Phase 2**: SIMD/x87 helpers (scalar-loop SSE/AVX, software FP) + ARM64 NEON,
  so the differential corpus has zero `UnsupportedIntrinsic` halts.
- **Later**: promote hot SIMD helpers to real vector IR ops if profiling demands
  (P-code-style incremental refinement — no IR shape change).

## Refinement path (intrinsic → real IR)

Because an `Intrinsic` is just a named op with declared footprint, we can later
*lower* common ones into real hardened-LLIR sequences (e.g., `bswap` → byte
`extract`/`concat`), gaining symbolic precision for free. The IR shape never
changes; only the lifter/lowering improves. This mirrors Ghidra's `CALLOTHER`
p-code injection.

## References
- [`../01-research/emulator-engineering.md`](../01-research/emulator-engineering.md) §5
- [`../01-research/ir-design-lessons.md`](../01-research/ir-design-lessons.md) §1
- [`executable-llir.md`](executable-llir.md), [`determinism.md`](determinism.md)
