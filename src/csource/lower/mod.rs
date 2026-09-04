//! `S4` --- lowering the S1 C syntax tree to [`LlirFunction`].
//!
//! Plan: `docs/design/static-c-analysis/roadmap.md` section 6. The point of
//! reaching LLIR is that [`crate::exec::interp`] is *the one* interpreter: a
//! front end that produces an `LlirFunction` inherits concrete execution,
//! symbolic execution and every solver behind the `Solver` trait without a line
//! of new engine code. Stage S5 --- bounded equivalence between a source
//! function and its decompilation --- is unreachable without it, and every
//! metric the project has today is structural and therefore blind to the
//! defect classes that matter (`docs/design/metrics-research/`).
//!
//! # What this is not
//!
//! Not a C compiler. The roadmap's scope discipline is quoted verbatim:
//! "Lowering only needs to cover what the fixtures and the corpus contain. It
//! is not a C compiler: no linking, no ABI lowering beyond what `ir::abi`
//! already models, no preprocessor." A construct outside the covered set costs
//! a [`LowerError`] naming it, never a silently wrong lowering --- an
//! approximate answer here would be indistinguishable from a decompiler defect
//! at the point where S5 reports one.
//!
//! # The value representation, stated once
//!
//! Every lowered C value of scalar type `T` lives in a [`VReg::Temp`] holding
//! the value **reduced mod 2^width(T) and then extended to 64 bits according to
//! `T`'s signedness** --- sign-extended when `T` is signed, zero-extended when
//! it is not.
//!
//! This one invariant is what makes the lowering correct on an interpreter that
//! cannot tell it the width of a temporary. [`crate::exec::interp`]'s
//! `op_width` takes the destination register's width and a `Temp` has none, so
//! every `Op::Bin` over temporaries executes at 64 bits whatever the C types
//! were. Rather than fight that, the lowering computes at 64 bits and then
//! *renormalizes* --- `Trunc` to `width(T)`, then `SExt`/`ZExt` back to 64 ---
//! after every operation that can overflow the C type. `int` addition therefore
//! wraps at 32 bits, as C says it does, and a signed comparison of two
//! sign-extended 64-bit values agrees with the same comparison at 32.
//!
//! It also makes conversion trivial and, importantly, *source-type
//! independent*: converting a canonical value to type `C` is `Trunc` to
//! `width(C)` followed by the extension `C`'s signedness asks for, regardless of
//! what type the value had before. That is why a `?:` whose arms have different
//! types can convert once in the join block, after the arms have already
//! written their results.
//!
//! # Block layout
//!
//! `LlirFunction` is addressed by VA because it was built for lifted code.
//! Synthetic blocks get synthetic VAs from [`build::BLOCK_BASE`], and a block's
//! `end_va` is set to **the start VA of its intended fall-through successor**,
//! which is exactly the contract `Machine::run_function` reads it under ("a
//! block's `end_va` is the start of its fall-through successor"). A block with
//! no fall-through gets [`build::NO_FALLTHROUGH_VA`], which no block starts at,
//! so a lowering bug surfaces as a loud `Outcome::NoBlock(0)` instead of
//! silently running the next block.
//!
//! # No recursion over user input
//!
//! Both the expression and the statement lowering walk an explicit job stack.
//! The reason is recorded in `roadmap.md` section 0: a recursive scan in the
//! sibling workspace overflowed the stack and aborted the process, so no
//! per-function result could be reported and the harness read the exit as a
//! crash. Decompiler C nests exactly that deeply.

pub mod build;
pub mod ctype;
#[cfg(feature = "exec")]
pub mod differential;
pub mod expr;
pub mod func;
pub mod literal;
pub mod stmt;

#[cfg(test)]
mod census_tests;
#[cfg(all(test, feature = "exec"))]
mod differential_tests;
#[cfg(test)]
mod tests;

pub use ctype::CType;
pub use func::{lower_function, lower_named_function, LoweredFunction, ParamSlot};

use crate::syntax::ids::NodeId;

/// Why a function could not be lowered.
///
/// One variant, carrying the construct's own name and the byte offset it starts
/// at, because the only useful thing a caller can do with a refusal is report
/// *which* construct is missing. A census over the fixture corpus is then a
/// frequency table over `what`, which is how the coverage question in
/// `roadmap.md` section 6 gets a number instead of an opinion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowerError {
    /// The construct that is not covered, named the way the report should read
    /// it (e.g. `"pointer type"`, `"call expression"`, `"switch statement"`).
    pub what: String,
    /// Byte offset into the source text where the construct starts, or 0 when
    /// the construct has no token of its own.
    pub offset: u32,
}

impl LowerError {
    /// Refuse `what`, locating it at `offset`.
    pub fn new(what: impl Into<String>, offset: u32) -> Self {
        Self {
            what: what.into(),
            offset,
        }
    }
}

impl std::fmt::Display for LowerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsupported at byte {}: {}", self.offset, self.what)
    }
}

impl std::error::Error for LowerError {}

/// A node the lowering reached but does not model.
pub(crate) fn unsupported<T>(
    what: impl Into<String>,
    node: NodeId,
    ctx: &func::Ctx<'_>,
) -> Result<T, LowerError> {
    Err(LowerError::new(what, ctx.offset_of(node)))
}
