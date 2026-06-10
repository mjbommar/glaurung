# Phase 1 — Concrete Emulator (x86-64), The Keystone

**Goal:** the `Domain` trait + a `Concrete` backend + the single generic
interpreter, executing hardened x86-64 LLIR over a real register file and softmmu
memory, validated against Unicorn. Specs:
[`../02-architecture/value-domain-trait.md`](../02-architecture/value-domain-trait.md),
[`machine-state.md`](../02-architecture/machine-state.md),
[`arch-abstraction.md`](../02-architecture/arch-abstraction.md).

**Feature gate:** `exec` (pure Rust, no new C deps).

## Tasks

- **1.1 `exec/domain.rs`** — the `Domain` trait (incl. `type Mem`, `as_branch`,
  `concretize_addr`). *Test:* compiles; doc-tested signatures.
- **1.2 `exec/concrete.rs`** — `Concrete: Domain`, `Val=(u128,Width)` masked to
  width; wrapping arithmetic; `as_branch` always `Taken/NotTaken`. *Test:*
  exhaustive small-width arithmetic/ext/trunc tables vs hand-computed values.
- **1.3 `exec/state.rs` + `exec/arch/x86_64.rs`** — flat byte-offset `RegFile`
  with x86-64 `RegLayout` (GPR aliases, `ah`-style, flags, xmm); `CpuModel` impl.
  *Test:* sub-register read/write aliasing (write `eax` zeroes upper `rax`; write
  `al` doesn't).
- **1.4 `exec/memory.rs`** — paged sparse softmmu, perms, little-endian load/store
  honoring width. (COW snapshots arrive in Phase 3; Phase 1 has plain pages.)
  *Test:* map/read/write/perm-violation; endianness.
- **1.5 `exec/interp.rs`** — the ONE `step()` + block `run()` over `Domain`;
  `Flow::{Next,Jump,Fork,Call,Return,Halt}`. *Test:* run hand-written LLIR blocks.
- **1.6 `exec/liftcache.rs`** — lift-once block cache + successor caching. *Test:*
  cache hit on re-entry; correctness unchanged.
- **1.7 `exec/budget.rs`** — instruction budget + loop guard → `Halt`. *Test:*
  infinite loop halts at the budget.
- **1.8 Common scalar helpers** (in `exec/helpers/x86.rs`, minimal set):
  `div`/`idiv`, high-half `mul`/`imul`, `cpuid` (fixed), `rdtsc` (virtual),
  `bswap`, `rol`/`ror`, `cmpxchg`, `xchg`. *Test:* per-helper unit tests.
- **1.9 Differential oracle harness** (`dev-oracle` feature) — single-step our
  interpreter and `unicorn-engine` on identical pre-state; diff full regs+flags+
  memory writes. Spec:
  [`../04-testing/differential-oracle.md`](../04-testing/differential-oracle.md).
  *Test:* a generated x86-64 instruction corpus + a handful of real `samples/`
  function slices.
- **1.10 Determinism test** — run a fixed program twice; assert identical final
  state.

## Deliverables

- `src/exec/` with the modules above; `exec` feature wired into `Cargo.toml`.
- A `dev-oracle` test harness (not shipped).
- A minimal `emulate_function(binary, va, args)` internal entry point returning
  final registers + memory writes + resolved indirect targets.

## Exit criteria

- The emulator matches Unicorn register+memory state on **≥95%** of the generated
  x86-64 corpus and on the chosen `samples/` slices; every divergence is filed as
  a fixture-backed regression test (per the TDD rule).
- Zero `UnsupportedIntrinsic` halts on the corpus (the Phase-1 helper set covers
  it; broader SIMD/FP is Phase 2).
- Determinism test passes; `cargo test --features exec,dev-oracle` green.

## <a name="prototype"></a>Validated prototype (the keystone, already compiled)

A standalone `rustc -O` prototype proved the architecture: one `step()` drove both
a concrete run and a symbolic-term-building run. Abridged:

```rust
trait Domain { type Val: Clone;
    fn constant(&mut self,w:u16,b:u128)->Self::Val;
    fn add(&mut self,a:&Self::Val,b:&Self::Val,w:u16)->Self::Val;
    fn eq (&mut self,a:&Self::Val,b:&Self::Val,w:u16)->Self::Val; /* … */ }

// Concrete backend (the emulator): Val = u128 masked to width
impl Domain for Concrete { type Val=u128;
    fn add(&mut self,a:&u128,b:&u128,w:u16)->u128 { a.wrapping_add(*b) & mask(w) }
    fn eq (&mut self,a:&u128,b:&u128,_:u16)->u128 { (a==b) as u128 } /* … */ }

// Symbolic backend (Phase 4 preview): Val = SMT-LIB2 term string
impl Domain for Symbolic { type Val=String;
    fn add(&mut self,a:&String,b:&String,_:u16)->String { format!("(bvadd {a} {b})") }
    fn eq (&mut self,a:&String,b:&String,_:u16)->String { format!("(ite (= {a} {b}) (_ bv1 1) (_ bv0 1))") } }

// ONE interpreter, generic over Domain — never duplicated.
fn step<D:Domain>(m:&mut Machine<D>, op:&Op) { /* match op { … } */ }
```

Output:
```
CONCRETE: ebx=0x100 zf=1
SYMBOLIC zf term: (ite (= (bvadd rax_sym (_ bv1 32)) (_ bv256 32)) (_ bv1 1) (_ bv0 1))
```

The full prototype lives in design history; reimplement it as the real
`exec/domain.rs` + `exec/concrete.rs` + `exec/interp.rs` against the hardened IR.
