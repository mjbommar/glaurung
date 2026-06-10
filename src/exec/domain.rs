//! The `Domain` trait — the keystone of the execution engine.
//!
//! One interpreter, parameterized by an abstract value domain. The concrete
//! emulator and the symbolic executor are two `impl Domain`; the interpreter's
//! `step()` is written once over this trait. See
//! `docs/design/execution-engine/02-architecture/value-domain-trait.md`.
//!
//! All arithmetic is **modular at an explicit [`Width`]**. The only places where
//! concrete and symbolic semantics legitimately diverge are [`Domain::as_branch`]
//! (concrete always decides; symbolic may fork) and the concretization hooks
//! ([`Domain::as_u64`]).

use crate::ir::types::{BinOp, CmpOp, UnOp, Width};

/// The decision the interpreter makes at a conditional branch given a 1-bit
/// condition value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchDecision {
    /// The condition is (provably) true — take the branch.
    Taken,
    /// The condition is (provably) false — fall through.
    NotTaken,
    /// Both successors are feasible — the caller must fork (symbolic only).
    Fork,
}

/// A typed bit-vector value domain.
///
/// Implementors define what a "value" is (`Val`) and how the bit-vector
/// primitives behave. `Concrete` uses a masked `u128`; the symbolic backend
/// (Phase 4) will build an interned expression term.
///
/// Every operation that has a result width takes it explicitly, so the domain
/// never has to guess. Predicate operations ([`Domain::cmp`]) return a 1-bit
/// value (the engine's representation of a flag / boolean).
pub trait Domain {
    /// The value representation. `Clone` because values flow into multiple
    /// register/memory cells; `Debug` for test/assertion ergonomics.
    type Val: Clone + std::fmt::Debug;

    /// A constant of the given width (the raw `bits` are reduced to `width`).
    fn constant(&mut self, width: Width, bits: u128) -> Self::Val;

    /// Binary arithmetic/logic, modular at `w`.
    fn binop(&mut self, op: BinOp, a: &Self::Val, b: &Self::Val, w: Width) -> Self::Val;

    /// Unary arithmetic/logic, modular at `w`.
    fn unop(&mut self, op: UnOp, a: &Self::Val, w: Width) -> Self::Val;

    /// Comparison predicate → a 1-bit value (`0`/`1`). `w` is the operand width.
    fn cmp(&mut self, op: CmpOp, a: &Self::Val, b: &Self::Val, w: Width) -> Self::Val;

    /// Zero-extend `a` from `from` bits to `to` bits (`to >= from`).
    fn zext(&mut self, a: &Self::Val, from: Width, to: Width) -> Self::Val;

    /// Sign-extend `a` from `from` bits to `to` bits (`to >= from`).
    fn sext(&mut self, a: &Self::Val, from: Width, to: Width) -> Self::Val;

    /// Truncate `a` to its low `to` bits.
    fn trunc(&mut self, a: &Self::Val, to: Width) -> Self::Val;

    /// Extract bits `[lo, hi)` of `a` (result width is `hi - lo`).
    fn extract(&mut self, a: &Self::Val, hi: u16, lo: u16) -> Self::Val;

    /// Concatenate: `(hi << width(lo)) | lo`, most-significant part first.
    fn concat(&mut self, hi: &Self::Val, lo: &Self::Val, hi_w: Width, lo_w: Width) -> Self::Val;

    /// Pure select: `cond ? t : e`, where `cond` is a 1-bit value.
    fn ite(&mut self, cond: &Self::Val, t: &Self::Val, e: &Self::Val, w: Width) -> Self::Val;

    /// Decide a branch from a 1-bit condition. `Concrete` returns `Taken` or
    /// `NotTaken`; a symbolic domain may return `Fork`.
    fn as_branch(&mut self, cond: &Self::Val) -> BranchDecision;

    /// Best-effort concretization to a `u64` (jump/call targets, addresses).
    /// `Concrete` always returns `Some`; a symbolic domain may concretize per a
    /// strategy or return `None` when undecidable.
    fn as_u64(&mut self, v: &Self::Val) -> Option<u64>;
}
