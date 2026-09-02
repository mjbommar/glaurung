# Decompiler test strategy: what to build next

> **Kind:** record · **Date:** 2026-08-13

> **Status: ranked working plan.** Written after the corpus reached 131 fixtures
> / 524 lanes / 1,763 recorded outcomes. Counts are revision-bound; rerun before
> quoting them.

The corpus has been grown along one axis — *source constructs, hand-written in
C*. That axis is now well covered. Everything else has been held fixed:

| axis | coverage before this plan |
|---|---|
| source language | C (130 files), C++ (1 file) |
| producer | gcc + clang, `-O0` / `-O2` only |
| architecture | x86-64, i386, AArch64, ARMv7 — all little-endian |
| container | ELF only |
| authoring | 100% hand-written |

The list below is ordered by impact divided by effort, not by intellectual
interest. Items 1-5 are buildable with the toolchain already on this machine;
items 6-8 are blocked on tooling and are scaffolded rather than guessed at.

## 1. C++ runtime shapes (fixtures 132-139)

The single largest language gap: one `.cpp` fixture against 130 C ones. C++
generates machinery that has no C analogue at all — vtables and vtable
thunks, RTTI records consumed by `dynamic_cast`, `.eh_frame`/`.gcc_except_table`
unwinding with landing pads, template monomorphization producing many near-clone
bodies, deterministic destructor ordering including on the throw path, and
`this`-pointer adjustment under multiple and virtual inheritance.

Glaurung already ships an Itanium demangler; nothing currently exercises it
against real mangled symbols in a behavioural test.

Wrapped in `extern "C"` entry points taking and returning plain ints, following
the convention `10_cpp_runtime_shapes.cpp` established, so the existing
execution differential drives them unchanged.

## 2. Thread-local storage and atomics (fixtures 140-141)

`__thread` / `_Thread_local` uses an addressing mode that appears nowhere else:
a GOT-relative TLS offset resolved through `%fs`-relative access or a
`__tls_get_addr` call, depending on the TLS model (`initial-exec` vs
`global-dynamic`). A decompiler that treats it as an ordinary global is wrong in
a way no existing fixture can catch.

C11 atomics add lock-prefixed read-modify-write instructions, compare-exchange
loops with their retry edge, and memory-ordering fences that constrain
reordering without computing anything.

## 3. Non-local control flow (fixtures 142-143)

`setjmp`/`longjmp` transfers control across frames that are already gone, so the
CFG has an edge no call graph shows. `alloca` and dynamically-sized frames move
the stack pointer at runtime, breaking any fixed frame-layout assumption.
Cleanup attributes (`__attribute__((cleanup))`) generate destructor-like calls
on every exit path including early returns.

## 4. Inline assembly and intrinsics (fixture 144)

Inline `asm` is a region the compiler does not model semantically; the
decompiler sees instructions with no source-level intent, and the operand
constraints determine which registers are clobbered. Compiler builtins
(`__builtin_clz`, `popcount`, `bswap`, overflow-checked arithmetic) lower to
single instructions whose recovery must reproduce their exact edge-case
behaviour, including the zero input where `clz` is undefined and must be guarded.

## 5. Metamorphic invariants (a test lane, not fixtures)

Properties that hold **without any ground truth**, so they apply to every binary
in the corpus and to real-world binaries with no source at all:

- **Convergence** — decompile, recompile, decompile again. The second recovery
  must be behaviourally identical to the first. Divergence is unambiguously a
  bug and needs no oracle to detect.
- **Strip invariance** — `decompile(strip(b))` must behave like `decompile(b)`.
  Symbols may improve naming; they must not change semantics.
- **Optimization invariance** — the `-O0` and `-O2` builds of one source must
  recover to behaviourally equivalent C.

This is the highest-leverage item per line of code written: it reuses every
fixture already in the corpus and turns each into several additional assertions.

## Outcome of items 1-5

Built and recorded. Yield per fixture is dramatically higher than the C batches,
which is the point of moving off the "more C constructs" axis.

| item | fixtures | pass | fail | failure rate |
|---|---:|---:|---:|---:|
| 1. C++ runtime shapes (132-139) | 8 | 46 | 58 | **56%** |
| 2-4. systems / ABI (140-144) | 5 | 39 | 29 | **43%** |
| for comparison: C edge cases (82-131) | 50 | 525 | 71 | 12% |
| for comparison: algorithms (31-80) | 50 | 395 | 29 | 7% |

Thirteen fixtures produced 87 recorded defects; the preceding fifty produced 71.

**Failing in all four lanes** — systematic, not lane-specific:

- RTTI in full: `dynamic_cast` up and down, `typeid` comparison
- Exception unwinding in full: catch-by-type, destructors during unwind, rethrow
- Virtual dispatch: `cpp_vtable_area`, `cpp_vtable_inherited_slot`, and the
  virtual-inheritance final overrider
- Thread-local storage: three of four exports — the `%fs`-relative / TLS-offset
  addressing mode appears to be recovered as an ordinary global
- `alloca`: both exports — dynamically sized frames

**Item 5 (metamorphic) is live** as `python/tests/test_decompiler_metamorphic.py`
and found a defect immediately, with no oracle: `20_graph_bfs:graph_bfs` renders
10 conditionals on the second round-trip pass and 11 on the third, so the
recovery is still adding control flow after two rebuilds. It is recorded in
`KNOWN_NON_CONVERGENT` and asserted to *still* fail, so a fix cannot be absorbed
silently.

One design note worth keeping: the first version of the convergence check
compared recovered text exactly and failed all six cases. The cause was
commutative operand reordering (`a & (a - 1)` coming back as `(a - 1) & a`),
which is rendering noise rather than recovery drift. The assertion now compares
the control-flow skeleton — branch, loop, return, and `goto` counts — so it
measures the property that actually matters.

## 6. Producer matrix expansion (blocked only by runtime, not tooling)

Every fixture recompiles for free under flags never yet tested: `-O1`, `-O3`,
`-Os`, `-Og`, LTO (cross-module inlining produces shapes nothing else does),
and the hardening set — stack protector, `_FORTIFY_SOURCE`, CET `endbr64`,
stack-clash probing. Same sources, materially different binaries, zero new
fixtures.

Deferred here because it multiplies baseline size and matrix runtime rather than
because it is hard; it should be staged as an opt-in lane before becoming
required.

## 7. Generative fuzzing (blocked: `csmith` not installed)

Csmith generates random C programs that are **free of undefined behaviour by
construction** — precisely the constraint this corpus keeps running into by
hand. The pipeline is generate → compile → decompile → recompile → execute both
→ diff, and every step after generation already exists here.

This converts the corpus from "constructs someone thought of" to "constructs a
generator found", with no authoring cost per case. YARPGen is a second generator
with different biases.

## 8. Coverage-guided gap analysis (blocked: needs an instrumented build)

Run `llvm-cov` over the Rust decompiler while executing the corpus. Whatever
passes and branches 131 fixtures never reach are the measured blind spots. This
replaces imagination with evidence for choosing what to write next, and is worth
doing before another hand-authored batch.

## Explicitly out of scope for now

- **Cross-architecture expansion** (RISC-V, big-endian s390x/MIPS) — no
  cross-compilers installed. Note that every architecture currently tested is
  little-endian, so the byte-order fixtures (`91`, `99`) cannot fail the way they
  are designed to.
- **Rust and Go fixtures** — both are high value (Glaurung demangles Rust
  already; Go's itab interfaces and register ABI are an industry-wide decompiler
  weak spot) but need their toolchains and a different differential entry point.
- **Obfuscated / adversarial samples** — tests robustness rather than fidelity,
  and wants its own verdict vocabulary: "refused to guess" is a pass there and a
  failure everywhere else.
