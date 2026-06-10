# Glaurung Execution Engine — Native Emulation & Symbolic Execution

> Status: **design / planning** (2026-06). No code yet. This tree is the
> top-down implementation plan for building concrete emulation **and** symbolic
> execution natively on Glaurung's own Rust stack, on top of the existing LLIR —
> no angr, no Unicorn, no Triton as runtime dependencies.

## The one-sentence thesis

Build **one IR interpreter, parameterized by an abstract value domain**, so that
the *concrete emulator* and the *symbolic executor* are two instantiations of the
**same** semantic core. The only architecture-specific code is the lifter (which
already exists for x86/x64/arm64). Everything else — the engine, the memory
model, the solver layer, the OS/ABI layer — is written once and shared.

This is the design every mature framework converged on independently: angr
(claripy backends over one VEX `SimEngine`), Triton (concolic over one AST),
BINSEC (one DBA core for sim + symbolic), Miasm (`SymbolicExecutionEngine` over
the same IR the jitter runs). See [`01-research/`](01-research/).

## Why this, why now

Glaurung already has a custom LLIR (`src/ir/`), per-arch lifters
(`lift_x86.rs`, `lift_arm64.rs`), a CFG/function-discovery layer
(`src/analysis/cfg.rs`), and a dataflow pass that already does abstract
interpretation over the IR (`src/analysis/ioctl_taint.rs`). What's missing is a
*machine* — a thing that holds state and executes the IR. Adding it unlocks:

- **String/payload decryption** by emulating decode stubs.
- **Indirect jump / jump-table / vtable resolution** by concrete emulation.
- **Opaque-predicate and dead-code detection.**
- **Directed sink-finding** for the Windows driver work — a symbolic successor to
  the static `ioctl_taint` pass that emits a concrete input witness.
- A substrate for the **L1–L5 LLM vuln-discovery** pipeline.

See [`00-motivation-and-goals.md`](00-motivation-and-goals.md).

## The hard part (read this before anything else)

It is **not** the SMT solver or the emulator loop. It is that **today's LLIR is a
*lossy static-analysis* IR, not an *executable* one.** Three gaps make it
non-executable as-is (all three confirmed by reading `src/ir/types.rs`):

1. **`Op::Unknown { mnemonic }` is a semantic hole.** A decompiler can render an
   unknown instruction as a comment; an emulator that hits one diverges from the
   real CPU forever. SIMD/x87/atomics all fall here today.
2. **No per-operation bit width.** `Value::Const(i64)` is sign-extended; `Op::Bin`
   carries no width. An SMT bit-vector backend *requires* exact widths; concrete
   wraparound is undefined without them.
3. **No machine-state model at all** — no register file contents, no memory bytes,
   no flag values exist anywhere yet.

So **Phase 0 is IR hardening**, and it is the load-bearing phase. See
[`02-architecture/executable-llir.md`](02-architecture/executable-llir.md).

What's already *right* in the IR and must be preserved: flags are modeled as
**condition-code** virtual registers (`Z`, `C`, `Slt`, `Sle`, …) rather than raw
x86 EFLAGS bits — this is exactly what gives cross-arch (x86 ↔ ARM `NZCV`) flag
parity for free.

## Start / restart here

| File | Use it to |
|---|---|
| **[`STATUS.md`](STATUS.md)** | **Read first.** Where the project is, what's next, blockers, restart procedure. Update it every session. |
| **[`PLAN.md`](PLAN.md)** | The canonical ordered task checklist for all phases (with `[ ]/[~]/[x]` boxes). Find the first unchecked task. |

`STATUS.md` is the narrative ("we are here, do this next"); `PLAN.md` is the
checklist; this `README.md` is the orientation. Keep the checkboxes in `PLAN.md`
in sync with the phase table in `STATUS.md`.

## How to navigate this plan

| Folder | What's in it |
|---|---|
| [`00-motivation-and-goals.md`](00-motivation-and-goals.md) | Use cases, non-goals, success criteria, scope guardrails |
| [`01-research/`](01-research/) | Synthesized findings from the literature (IR design, symbolic execution, emulator engineering, SMT backends) with sources |
| [`02-architecture/`](02-architecture/) | The system design: executable LLIR, the `Domain` trait, machine state, arch abstraction, helpers, OS/ABI layer, determinism |
| [`03-phases/`](03-phases/) | The phased implementation plan — one file per phase, each with tasks, deliverables, tests, and exit criteria |
| [`04-testing/`](04-testing/) | TDD strategy, the Unicorn dev-only differential oracle, fixture/corpus policy |
| [`05-decisions/`](05-decisions/) | Architecture Decision Records (the load-bearing choices, with rejected alternatives) |

## Phase map (top-down)

```
Phase 0  IR hardening ............ make LLIR total + typed + executable     [FOUNDATION]
Phase 1  Concrete emulator (x64) . Domain trait + Concrete backend + step() [KEYSTONE]
Phase 2  Coverage + ARM64 ........ helpers for SIMD/x87/etc.; arm64 parity
Phase 3  Snapshots/hooks/OS ...... COW memory, Unicorn-style hooks, SimProcedures
Phase 4  Concolic + SMT .......... Solver trait, easy-smt pipe, symbolic Domain
Phase 5  Symbolic exploration .... state forking, path constraints, directed search
Phase 6  PyO3 + agent tools ...... Python surface, L1–L5 tool registration, KB writeback
Phase 7  Applications ............ string-decrypt, indirect-jump resolve, IOCTL sink-finding
```

Phases 0→1 are strictly sequential and are the bulk of the conceptual risk.
Phases 2 and 3 can overlap. Phase 4 gates 5. Phases 6–7 ride on whatever exists.
Detailed sequencing and dependencies: [`03-phases/README.md`](03-phases/README.md).

## Guardrails (Glaurung house rules that constrain this design)

- **TDD, real fixtures only.** Every instruction-semantics claim is backed by a
  differential test against an oracle on a real binary from `samples/`/`tests/`.
  No mock CPU state. See [`04-testing/`](04-testing/).
- **Determinism is mandatory.** No `Date::now`/`Math.random` in execution paths.
  `RDTSC`/`CPUID`/`RDRAND` read virtual state; worklists are ordered; solver seeds
  are pinned. See [`02-architecture/determinism.md`](02-architecture/determinism.md).
- **The SMT solver is optional.** The base PyO3/maturin wheel must build with no
  C/C++ solver dependency. See [`05-decisions/adr-0005-smt-pipe-then-native-optional.md`](05-decisions/adr-0005-smt-pipe-then-native-optional.md).
- **Rust core, `Result<T,E>` + `?`, no `.unwrap()` in library paths.**
- **Don't swap in angr/Unicorn/Triton at runtime.** Unicorn is allowed **only** as
  a dev-test oracle behind a Cargo feature, never shipped.
