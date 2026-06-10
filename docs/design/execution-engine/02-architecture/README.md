# Architecture

The system design for Glaurung's execution engine. Read in order; each file is a
component spec referenced by the phase plan.

| File | Component | Phase |
|---|---|---|
| [`executable-llir.md`](executable-llir.md) | Hardening the LLIR into a total, typed, executable IR | 0 |
| [`value-domain-trait.md`](value-domain-trait.md) | **The keystone** — one interpreter over a `Domain` trait | 1 |
| [`machine-state.md`](machine-state.md) | Register file, softmmu memory, COW snapshots, hooks | 1, 3 |
| [`arch-abstraction.md`](arch-abstraction.md) | `CpuModel` trait; x86-64 + arm64 descriptors | 1, 2 |
| [`helpers-and-intrinsics.md`](helpers-and-intrinsics.md) | Helper registry replacing `Op::Unknown` (SIMD/FP/div/cpuid) | 0, 2 |
| [`os-abi-layer.md`](os-abi-layer.md) | SimProcedures, syscalls, library stubs, Windows kernel surface | 3 |
| [`symbolic-engine.md`](symbolic-engine.md) | Symbolic state, forking, path constraints, solver, search | 4, 5 |
| [`determinism.md`](determinism.md) | Reproducibility rules that constrain everything | all |

## Proposed crate / module layout

A single new top-level Rust module tree under `src/`, mirroring the existing
`src/ir/` + `src/analysis/` convention (Glaurung is one crate, feature-gated —
**not** a workspace). Nothing here is built unless its feature is on.

```
src/
├── ir/                     # EXISTING — hardened in Phase 0
│   ├── types.rs            #   + width fields, Op::Intrinsic, ext/trunc ops
│   ├── lift_x86.rs         #   + emit widths, intrinsics, explicit zero-extend
│   ├── lift_arm64.rs       #   + same, Phase 2
│   └── verify.rs           #   NEW: IR well-formedness / type checker
├── exec/                   # NEW — the execution engine (feature: "exec")
│   ├── mod.rs
│   ├── domain.rs           # trait Domain (the keystone)
│   ├── concrete.rs         # Concrete: Domain (the emulator's value backend)
│   ├── interp.rs           # the ONE step()/run() interpreter, generic over Domain
│   ├── state.rs            # CpuState: register file + flags + pc
│   ├── memory.rs           # softmmu: paged, perms, sparse, dirty-page COW
│   ├── hooks.rs            # Unicorn-style hook taxonomy + dispatch
│   ├── helpers/            # helper registry (SIMD, FP, div, cpuid, rdtsc, …)
│   │   ├── mod.rs
│   │   ├── x86.rs
│   │   └── arm64.rs
│   ├── arch/               # CpuModel descriptors (register layout, ABI, syscalls)
│   │   ├── mod.rs
│   │   ├── x86_64.rs
│   │   └── arm64.rs
│   ├── liftcache.rs        # lift-once block cache + software block chaining
│   └── budget.rs           # instruction/loop/region budgets (reuse cfg::Budgets style)
├── os/                     # NEW — OS/ABI layer (feature: "exec")
│   ├── mod.rs
│   ├── simproc.rs          # function-summary registry (SimProcedures)
│   ├── linux.rs            # libc stubs + syscall table
│   └── windows.rs          # Win32/ntoskrnl stubs + IRP/IOCTL model
├── symbolic/               # NEW — symbolic/concolic layer (feature: "symbolic")
│   ├── mod.rs
│   ├── expr.rs             # hash-consed bitvector AST (the symbolic Val)
│   ├── symdomain.rs        # Symbolic: Domain (builds Expr / SMT terms)
│   ├── solver/             # Solver trait + backends
│   │   ├── mod.rs
│   │   ├── pipe.rs         # easy-smt SMT-LIB2 pipe (default)
│   │   ├── z3.rs           # optional feature "solver-z3"
│   │   └── bitwuzla.rs     # optional feature "solver-bitwuzla"
│   ├── symstate.rs         # symbolic State: regs/mem/constraints/solver/taint
│   ├── symmem.rs           # symbolic memory (concretize-with-threshold)
│   ├── explore.rs          # worklist, forking, search strategies, stashes
│   └── cache.rs            # constraint independence + counterexample cache
├── analysis/
│   └── ioctl_taint.rs      # EXISTING — eventually a symbolic-backed successor
└── python_bindings/
    └── exec.rs             # NEW — PyO3 surface (feature: "python-ext")
```

## Cargo features (additive, all optional)

```toml
[features]
exec            = []                      # concrete emulator (pure Rust, no C deps)
symbolic        = ["exec"]               # concolic/symbolic over the emulator
solver-z3       = ["symbolic", "dep:z3"] # optional native Z3
solver-bitwuzla = ["symbolic", "dep:bitwuzla-sys"]  # optional native Bitwuzla (UNIX)
dev-oracle      = ["dep:unicorn-engine"] # DEV ONLY differential test oracle, never shipped
```

`exec` is pure Rust — no new C/C++ dependency, builds into the wheel cleanly.
`symbolic` adds the pipe solver (still no compiled dep; needs a solver *binary* at
runtime). Native solvers and the Unicorn oracle are strictly opt-in.

## Data flow (concrete emulation)

```
binary bytes ──(existing)──► CFG/function discovery ──► lift_function ──► LlirFunction (hardened)
                                                                              │
                                                          liftcache (Arc<LiftedBlock>)
                                                                              │
   CpuState + Memory ◄──── interp::run::<Concrete>(block, &mut machine) ◄─────┘
        │                         │ (hooks fire; helpers dispatch; OS stubs on sentinel fetch)
        └── results: regs, memory writes, resolved targets, decrypted bytes ──► KB / agent tools
```

## Data flow (concolic / symbolic) — same interpreter, symbolic Domain

```
seed input ──► interp::run::<Symbolic>(…) building Expr terms alongside concrete values
                    │ at input-dependent branch: fork state, push constraint, solver.check_assuming
                    ▼
        explore worklist (priority = dist_to_sink) ──► found state ──► solver.get_model ──► concrete witness
```
