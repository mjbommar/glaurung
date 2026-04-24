//! Low-Level Intermediate Representation (LLIR) — Phase 2 kickoff.
//!
//! This is the first, deliberately small IR in Glaurung's lifting pipeline.
//! It exists to turn machine instructions into a machine-analysable,
//! architecture-agnostic three-address form that downstream passes (data-flow,
//! xref recovery, a future mid-IR/SSA lifter) can consume without knowing the
//! source ISA.
//!
//! Design principles:
//! 1. **Semantic preservation first.** When we cannot lift an instruction
//!    faithfully, emit [`Op::Unknown`] carrying the source mnemonic instead
//!    of silently dropping it.
//! 2. **Three-address, non-SSA.** SSA comes at the next layer. Keeping this
//!    layer non-SSA lets the lifter stay tiny (~200 LoC per arch) and keeps
//!    the output readable for unit tests.
//! 3. **Flags are virtual registers.** x86 `cmp`/`add` side-effects go into
//!    explicit [`VReg::Flag`] writes so condition-code consumers can read
//!    them as ordinary values.
//! 4. **Tiny scope.** v1 supports a handful of x86-64 mnemonics
//!    (mov, add, sub, cmp, test, push, pop, call, ret, jmp, jcc, nop, lea).
//!    Anything else becomes [`Op::Unknown`] and is reported to the caller.
//!
//! This file defines the IR; [`lift_x86`] contains the lifter.

pub mod arm64_prologue;
pub mod ast;
pub mod call_args;
pub mod canary;
pub mod const_fold;
pub mod dce;
pub mod dead_stores;
pub mod expr_reconstruct;
pub mod label_prune;
pub mod lift_arm64;
pub mod lift_function;
pub mod lift_x86;
pub mod name_resolve;
pub mod naming;
pub mod ssa;
pub mod stack_idiom;
pub mod stack_locals;
pub mod strings_fold;
pub mod structure;
pub mod types;
pub mod types_recover;
pub mod use_def;
pub mod x86_prologue;

pub use types::*;
