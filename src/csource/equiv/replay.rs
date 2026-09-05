//! The concrete half: separating two functions without a solver, and confirming
//! that a model the solver returned is real.
//!
//! # Why the probes run first
//!
//! A defect that changes what a function computes usually changes it on an
//! ordinary input. Running both sides concretely on a fixed vector set costs no
//! solver call, and a disagreement it finds is a witness already reproduced ---
//! there is nothing left to confirm. The vectors are
//! [`crate::csource::lower::differential`]'s, reused rather than reinvented,
//! with one addition: every value is **canonicalized to the parameter's declared
//! type** first. `0xffff_ffff_ffff_ffff` is a fine probe for a `long` and is not
//! a value any caller can pass for an `unsigned int`, and a difference found
//! only at an uncallable input is not a difference.
//!
//! # Why a model is replayed
//!
//! The symbolic domain and the concrete domain do not agree everywhere.
//! `BinOp::Div` by zero is `0` in `src/exec/concrete.rs` and all-ones under
//! SMT-LIB's `bvudiv`; a shift amount at or above the operand width is reduced
//! **modulo** the width concretely and saturates to zero under `bvshl`. Where a
//! query's satisfying assignment depends on one of those, the model is an
//! artefact of the encoding rather than a fact about the two functions. So every
//! model is re-run concretely, and a model that does not reproduce a difference
//! downgrades the verdict to `unknown` instead of being reported as a defect.

use crate::ir::types::{LlirFunction, Width};

use crate::csource::lower::differential::{run_with_args, vectors};

use super::{Bounds, IoSpec, Witness};

/// Run both functions on the probe vector set, returning the first reproduced
/// disagreement.
///
/// A vector on which either side fails to return is skipped rather than
/// reported: "one side did not finish" is not evidence that they compute
/// different things.
pub fn probe_sweep(
    left: &LlirFunction,
    right: &LlirFunction,
    io: &IoSpec,
    result_width: Width,
    bounds: &Bounds,
) -> Option<Witness> {
    for raw in vectors(io.inputs.len()) {
        let args: Vec<u64> = raw
            .iter()
            .zip(&io.inputs)
            .map(|(value, slot)| slot.canonicalize(*value))
            .collect();
        if let Some(witness) = confirm(left, right, &args, result_width, bounds) {
            return Some(witness);
        }
    }
    None
}

/// Run both functions on one argument vector and report a difference only when
/// both returned.
pub fn confirm(
    left: &LlirFunction,
    right: &LlirFunction,
    args: &[u64],
    result_width: Width,
    bounds: &Bounds,
) -> Option<Witness> {
    let width = Some(result_width);
    let ours = run_with_args(left, args, width, bounds.stack_pointer, bounds.probe_steps);
    let theirs = run_with_args(right, args, width, bounds.stack_pointer, bounds.probe_steps);
    match (ours.result, theirs.result) {
        (Some(a), Some(b)) if a != b => Some(Witness {
            args: args.to_vec(),
            left: a,
            right: b,
        }),
        _ => None,
    }
}
