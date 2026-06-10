# Motivation, Goals, and Non-Goals

## Context

Glaurung is an AI-native reverse-engineering framework with a custom Rust
analysis core. It currently performs **static** analysis only: disassembly
(`iced-x86` + `capstone`), a custom LLIR with x86/x64/arm64 lifters
(`src/ir/`), CFG and function discovery (`src/analysis/cfg.rs`), SSA/dataflow,
a decompiler, and a bespoke static taint pass for Windows drivers
(`src/analysis/ioctl_taint.rs`).

There is **no emulation and no symbolic execution** today. The `ioctl_taint`
design doc explicitly chose cheap static dataflow over the angr/Unicorn/Z3 stack
("…pays a ~30s/driver startup cost, brings in z3 / unicorn / claripy…"). That
was the right call for that problem. But a growing set of problems genuinely
*need* execution semantics, and the philosophy is "what Ghidra would look like if
built today" — which means owning this capability natively, in Rust, not bolting
on a Python framework.

## What execution unlocks (the use cases that justify the cost)

Ranked roughly by value-to-effort:

1. **Concrete string / payload decryption.** Malware routinely decrypts strings,
   config, and stage-2 payloads in small self-contained stubs. Emulate the stub
   over the encrypted bytes → recover plaintext. *Needs: concrete emulator.*
2. **Indirect control-flow resolution.** Jump tables, `call rax`, vtable
   dispatch, tail-call thunks. Concrete (or concolic) emulation resolves targets
   that static analysis leaves as "indirect". Feeds CFG completeness directly.
   *Needs: concrete emulator (+ light concolic).*
3. **Computed-constant recovery.** Stack cookies, hash seeds, API-hashing
   resolution (resolve hashed imports by emulating the resolver).
   *Needs: concrete emulator.*
4. **Opaque-predicate / dead-code detection** for deobfuscation.
   *Needs: symbolic or concolic.*
5. **Directed sink-finding for Windows drivers** — the symbolic successor to
   `ioctl_taint`: instead of statically tracing taint to a dangerous sink,
   *concolically drive toward the sink* from a symbolic IRP/IOCTL buffer and emit
   a **concrete input witness** that reaches it. *Needs: concolic + SMT + directed search.*
6. **LLM vuln-discovery substrate (L1–L5).** Give the agent tools like "emulate
   this function with these args", "what inputs reach this block", "what does this
   decode routine produce". *Needs: all of the above, behind cost guards.*

## Goals

- **G1 — One semantic core.** A single IR interpreter parameterized by an
  abstract value domain; concrete and symbolic are backends, not separate engines.
- **G2 — Multi-arch from day one.** x86-64 first, ARM64 close behind, with the
  engine arch-agnostic over the typed IR. (32-bit x86 and others later via lifter
  + descriptor only.)
- **G3 — Total, sound execution.** No silent divergence. Unmodeled instructions
  become *declared* intrinsics, not holes; the executor stays sound.
- **G4 — Tractable, not complete.** For real malware/drivers, favor concolic +
  concretization + directed search over sound-but-exploding pure symbolic
  execution. Witnesses over proofs.
- **G5 — Deterministic & reproducible.** Identical inputs → identical output,
  always (a production-tool requirement and a Glaurung house rule).
- **G6 — Optional heavyweight deps.** Base wheel builds with no SMT/C++ deps;
  solver and dev-oracle are opt-in Cargo features.
- **G7 — Agent-ready.** Surfaced to Python and to the LLM tool layer with cost
  guards, deterministic output, and KB writeback.

## Non-goals (explicitly out of scope, at least initially)

- **N1 — Full-system / OS-boot emulation.** We emulate *slices* (functions,
  stubs, handlers), not whole kernels. No device emulation, no real scheduler.
- **N2 — A JIT.** Start with a cached IR interpreter. A JIT is a possible later
  backend behind the same IR; not v1. See ADR-0003.
- **N3 — Soundness/verification guarantees.** This is a bug-finding /
  analysis tool, not a verifier. We will deliberately concretize and merge,
  losing completeness for tractability (KLEE/Mayhem/QSYM lineage).
- **N4 — Cycle-accurate timing or microarchitectural fidelity.** No pipeline,
  cache, or speculative modeling.
- **N5 — Shipping angr/Unicorn/Triton.** Not as runtime deps. Unicorn is a
  dev-only differential oracle (Cargo feature), never in the wheel.
- **N6 — Floating-point bit-exactness in v1.** FP via helpers, correctness-first,
  exotic rounding modes deferred.

## Success criteria (how we know each phase worked)

| Phase | Concrete success signal |
|---|---|
| 0 | Hardened IR round-trips; every lifted op has an explicit width; `Op::Unknown` replaced by `Op::Intrinsic`; existing decompiler/dataflow tests still pass |
| 1 | x86-64 emulator matches Unicorn register+memory state on ≥95% of a generated instruction corpus + a set of `samples/` function slices |
| 2 | ARM64 emulator reaches parity on its corpus; SIMD/x87/div covered by helpers (no `Intrinsic`-halts on the corpus) |
| 3 | Snapshot/restore is O(dirty-pages); hooks fire with Unicorn-equivalent semantics; libc/Win32 stubs let real functions run to completion |
| 4 | Concolic run of a real string-decrypt stub recovers plaintext; SMT pipe solves a branch constraint and produces a reaching input |
| 5 | Directed search reaches a target block in a real IOCTL handler and emits a concrete witness; bounded, deterministic, no state explosion on the test corpus |
| 6 | `glaurung` Python API + agent tools drive the engine; results land in the `.glaurung` KB with provenance |
| 7 | End-to-end: automatic string decryption + indirect-jump resolution on a real malware sample improves CFG/KB coverage measurably |

## Effort & risk framing

This is a multi-quarter effort. The conceptual risk is front-loaded in Phases 0–1
(IR hardening + the domain-generic core). Once those land, Phases 2–7 are
largely additive and independently testable. The biggest *ongoing* risks are
(a) instruction-semantics correctness (mitigated by the differential oracle) and
(b) symbolic state explosion (mitigated by the concolic-first, concretize-by-
default memory model — see ADR-0004, ADR-0006).
