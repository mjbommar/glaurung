//! The explorer's contract with the solver layer.
//!
//! Warm-solver path ownership (who may reuse retained backend state),
//! the two traced query forms every caller goes through, and the
//! backend-independent canonical model choice with its process-wide
//! accounting.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::exec::domain::Domain;
use crate::ir::types::CmpOp;
use crate::symbolic::concretization::{
    active_concretization_policy, ConcretizationPolicy, UnsignedExtremum,
};
use crate::symbolic::expr::ExprId;
use crate::symbolic::ordered_trace::WarmReplayCheck;
use crate::symbolic::solver::{last_solve_timing, solve_for_path_delta, Assert, SolveResult};

use super::State;

static CANONICAL_MODEL_CHOICE_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_COMPLETED: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_INFEASIBLE: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_PROBES: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_INCONCLUSIVE: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_UNSUPPORTED_WIDTH: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_UNKNOWN: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_NO_SOLVER: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_ERROR: AtomicU64 = AtomicU64::new(0);
static CANONICAL_MODEL_CHOICE_FINAL_UNSAT: AtomicU64 = AtomicU64::new(0);

/// Process-wide accounting for backend-independent model choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalModelChoiceStats {
    /// Active model-selection policy.
    pub policy: &'static str,
    /// Expressions for which an unsigned extremum was requested.
    pub attempts: u64,
    /// Attempts that produced and rechecked an extremum.
    pub completed: u64,
    /// Attempts made on a path that was already infeasible.
    pub infeasible: u64,
    /// Temporary solver checks issued by the minimizer.
    pub probes: u64,
    /// Attempts that failed closed because no checked minimum was available.
    pub inconclusive: u64,
    /// Attempts whose expression exceeded the concrete-value representation.
    pub unsupported_width: u64,
    /// Attempts stopped by a solver `unknown` result.
    pub unknown: u64,
    /// Attempts stopped because no solver was available.
    pub no_solver: u64,
    /// Attempts stopped by a backend error.
    pub error: u64,
    /// Attempts whose final equality unexpectedly returned UNSAT.
    pub final_unsat: u64,
}

/// Return the active canonical-model policy and its process-wide counters.
pub fn canonical_model_choice_stats() -> CanonicalModelChoiceStats {
    CanonicalModelChoiceStats {
        policy: active_concretization_policy().policy_id(),
        attempts: CANONICAL_MODEL_CHOICE_ATTEMPTS.load(Ordering::Relaxed),
        completed: CANONICAL_MODEL_CHOICE_COMPLETED.load(Ordering::Relaxed),
        infeasible: CANONICAL_MODEL_CHOICE_INFEASIBLE.load(Ordering::Relaxed),
        probes: CANONICAL_MODEL_CHOICE_PROBES.load(Ordering::Relaxed),
        inconclusive: CANONICAL_MODEL_CHOICE_INCONCLUSIVE.load(Ordering::Relaxed),
        unsupported_width: CANONICAL_MODEL_CHOICE_UNSUPPORTED_WIDTH.load(Ordering::Relaxed),
        unknown: CANONICAL_MODEL_CHOICE_UNKNOWN.load(Ordering::Relaxed),
        no_solver: CANONICAL_MODEL_CHOICE_NO_SOLVER.load(Ordering::Relaxed),
        error: CANONICAL_MODEL_CHOICE_ERROR.load(Ordering::Relaxed),
        final_unsat: CANONICAL_MODEL_CHOICE_FINAL_UNSAT.load(Ordering::Relaxed),
    }
}

/// Process-local identity for explicit warm-solver ownership. It never enters
/// formulas or evidence; ordered trace paths retain their separate stable IDs.
static NEXT_WARM_PATH_ID: AtomicU64 = AtomicU64::new(1);

pub(super) fn next_warm_path_id() -> u64 {
    NEXT_WARM_PATH_ID.fetch_add(1, Ordering::Relaxed)
}

pub(super) fn warm_owner_transfer_enabled() -> bool {
    if crate::symbolic::solver::fair_shadow_enabled() {
        return true;
    }
    #[cfg(feature = "solver-axeyum")]
    {
        crate::symbolic::solver::axeyum_backend::warm_owner_transfer_enabled()
    }
    #[cfg(not(feature = "solver-axeyum"))]
    {
        false
    }
}

pub(super) fn warm_serial_sibling_reuse_enabled() -> bool {
    if crate::symbolic::solver::fair_shadow_enabled() {
        return true;
    }
    #[cfg(feature = "solver-axeyum")]
    {
        effective_serial_sibling_reuse(
            crate::symbolic::solver::axeyum_backend::warm_serial_sibling_reuse_enabled(),
            crate::symbolic::solver::axeyum_backend::direct_delta_enabled(),
        )
    }
    #[cfg(not(feature = "solver-axeyum"))]
    {
        false
    }
}

pub(super) fn effective_serial_sibling_reuse(configured: bool, _direct_delta: bool) -> bool {
    configured
}

pub(super) fn share_serial_warm_owner_with_children(path_id: u64, children: u64) {
    crate::symbolic::ordered_trace::warm_owner_share(path_id, children);
    #[cfg(feature = "solver-axeyum")]
    crate::symbolic::solver::axeyum_backend::share_serial_warm_owner_with_children(
        path_id, children,
    );
    #[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
    if crate::symbolic::solver::fair_shadow_enabled() {
        crate::symbolic::solver::z3_backend::share_serial_warm_owner_with_children(
            path_id, children,
        );
    }
    #[cfg(all(
        feature = "solver-z3",
        feature = "solver-axeyum",
        feature = "solver-bitwuzla"
    ))]
    if crate::symbolic::solver::fair_shadow_enabled() {
        crate::symbolic::solver::bitwuzla_backend::share_serial_warm_owner_with_children(
            path_id, children,
        );
    }
    #[cfg(not(feature = "solver-axeyum"))]
    let _ = (path_id, children);
}

pub(super) fn close_warm_owner(path_id: u64) {
    crate::symbolic::ordered_trace::warm_owner_release(path_id);
    #[cfg(feature = "solver-axeyum")]
    if crate::symbolic::solver::fair_shadow_enabled() {
        crate::symbolic::solver::axeyum_backend::close_fair_warm_path(path_id);
    } else {
        crate::symbolic::solver::axeyum_backend::close_warm_path(path_id);
    }
    #[cfg(all(feature = "solver-z3", feature = "solver-axeyum"))]
    if crate::symbolic::solver::fair_shadow_enabled() {
        crate::symbolic::solver::z3_backend::close_warm_path(path_id);
    }
    #[cfg(all(
        feature = "solver-z3",
        feature = "solver-axeyum",
        feature = "solver-bitwuzla"
    ))]
    if crate::symbolic::solver::fair_shadow_enabled() {
        crate::symbolic::solver::bitwuzla_backend::close_warm_path(path_id);
    }
}

/// Solve the current path condition and record the exact query occurrence.
pub(super) fn solve_traced(st: &mut State, purpose: &str, location: u64) -> SolveResult {
    let persistent = st.constraints.len();
    let requested_retain_assertions = st.warm_retain_assertions;
    let (result, synced) = solve_for_path_delta(
        &st.machine.dom.pool,
        &st.constraints,
        st.warm_path_id,
        st.warm_retain_assertions,
        persistent,
        &st.warm_assertion_prefix,
    );
    if synced {
        st.warm_retain_assertions = persistent;
    }
    let timing = last_solve_timing();
    if let Some(trace) = &mut st.trace {
        let warm_replay = WarmReplayCheck {
            owner_id: st.warm_path_id,
            requested_retain_assertions,
            persistent_assertions: persistent,
            synchronized: synced,
        };
        trace.check(
            &st.machine.dom.pool,
            &st.constraints,
            &result,
            purpose,
            timing,
            Some(&warm_replay),
            location,
        );
    }
    result
}

/// Solve with one temporary assertion, preserving explicit push/check/pop
/// history while leaving the path condition unchanged.
pub(super) fn solve_probe_traced(
    st: &mut State,
    assertion: Assert,
    purpose: &str,
    role: &str,
    location: u64,
) -> SolveResult {
    if let Some(trace) = &mut st.trace {
        trace.push_temporary(&st.machine.dom.pool, assertion, role, location);
    }
    let mut probe = st.constraints.clone();
    probe.push(assertion);
    let persistent = st.constraints.len();
    let requested_retain_assertions = st.warm_retain_assertions;
    let (result, synced) = solve_for_path_delta(
        &st.machine.dom.pool,
        &probe,
        st.warm_path_id,
        st.warm_retain_assertions,
        persistent,
        &st.warm_assertion_prefix,
    );
    if synced {
        st.warm_retain_assertions = persistent;
    }
    let timing = last_solve_timing();
    if let Some(trace) = &mut st.trace {
        let warm_replay = WarmReplayCheck {
            owner_id: st.warm_path_id,
            requested_retain_assertions,
            persistent_assertions: persistent,
            synchronized: synced,
        };
        trace.check(
            &st.machine.dom.pool,
            &probe,
            &result,
            purpose,
            timing,
            Some(&warm_replay),
            location,
        );
        trace.pop(location);
    }
    result
}

/// Select an unsigned extremum of `value` under the current path condition.
///
/// Every bound is a temporary assertion, so the search cannot mutate the path.
/// The final equality probe both rechecks the selected value and leaves an
/// immediately preceding SAT event for ordered model-choice tracing. Widths
/// above 128 bits cannot be represented by this engine's concrete value type
/// and therefore fail closed.
pub(super) fn select_unsigned_extremum(
    st: &mut State,
    value: ExprId,
    purpose: &str,
    location: u64,
    extremum: UnsignedExtremum,
) -> Option<u128> {
    CANONICAL_MODEL_CHOICE_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    let width = st.machine.dom.pool.width_of(value);
    let bits = width.bits();
    if bits == 0 || bits > 128 {
        CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
        CANONICAL_MODEL_CHOICE_UNSUPPORTED_WIDTH.fetch_add(1, Ordering::Relaxed);
        return None;
    }

    CANONICAL_MODEL_CHOICE_PROBES.fetch_add(1, Ordering::Relaxed);
    match solve_traced(st, "canonical-model-choice-feasibility", location) {
        SolveResult::Sat(_) => {}
        SolveResult::Unsat => {
            CANONICAL_MODEL_CHOICE_INFEASIBLE.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        SolveResult::Unknown(_) => {
            CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
            CANONICAL_MODEL_CHOICE_UNKNOWN.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        SolveResult::NoSolver => {
            CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
            CANONICAL_MODEL_CHOICE_NO_SOLVER.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        SolveResult::Error(_) => {
            CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
            CANONICAL_MODEL_CHOICE_ERROR.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    }

    let mut low = 0u128;
    let mut high = if bits == 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    };
    while low < high {
        let distance = high - low;
        let midpoint = match extremum {
            UnsignedExtremum::Minimum => low + (distance >> 1),
            UnsignedExtremum::Maximum => low + (distance >> 1) + (distance & 1),
        };
        let bound = st.machine.dom.constant(width, midpoint);
        let probe = match extremum {
            UnsignedExtremum::Minimum => st.machine.dom.cmp(CmpOp::Ule, &value, &bound, width),
            UnsignedExtremum::Maximum => st.machine.dom.cmp(CmpOp::Ule, &bound, &value, width),
        };
        CANONICAL_MODEL_CHOICE_PROBES.fetch_add(1, Ordering::Relaxed);
        match solve_probe_traced(
            st,
            (probe, true),
            purpose,
            "canonical-model-choice-bound",
            location,
        ) {
            SolveResult::Sat(_) => match extremum {
                UnsignedExtremum::Minimum => high = midpoint,
                UnsignedExtremum::Maximum => low = midpoint,
            },
            SolveResult::Unsat => match extremum {
                UnsignedExtremum::Minimum => low = midpoint + 1,
                UnsignedExtremum::Maximum => high = midpoint - 1,
            },
            SolveResult::Unknown(_) => {
                CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
                CANONICAL_MODEL_CHOICE_UNKNOWN.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            SolveResult::NoSolver => {
                CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
                CANONICAL_MODEL_CHOICE_NO_SOLVER.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            SolveResult::Error(_) => {
                CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
                CANONICAL_MODEL_CHOICE_ERROR.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
    }

    let selected = st.machine.dom.constant(width, low);
    let equal = st.machine.dom.cmp(CmpOp::Eq, &value, &selected, width);
    CANONICAL_MODEL_CHOICE_PROBES.fetch_add(1, Ordering::Relaxed);
    match solve_probe_traced(
        st,
        (equal, true),
        purpose,
        "canonical-model-choice-final",
        location,
    ) {
        SolveResult::Sat(_) => {
            CANONICAL_MODEL_CHOICE_COMPLETED.fetch_add(1, Ordering::Relaxed);
            Some(low)
        }
        SolveResult::Unsat => {
            CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
            CANONICAL_MODEL_CHOICE_FINAL_UNSAT.fetch_add(1, Ordering::Relaxed);
            None
        }
        SolveResult::Unknown(_) => {
            CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
            CANONICAL_MODEL_CHOICE_UNKNOWN.fetch_add(1, Ordering::Relaxed);
            None
        }
        SolveResult::NoSolver => {
            CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
            CANONICAL_MODEL_CHOICE_NO_SOLVER.fetch_add(1, Ordering::Relaxed);
            None
        }
        SolveResult::Error(_) => {
            CANONICAL_MODEL_CHOICE_INCONCLUSIVE.fetch_add(1, Ordering::Relaxed);
            CANONICAL_MODEL_CHOICE_ERROR.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

#[cfg(test)]
pub(super) fn minimize_unsigned_value(
    st: &mut State,
    value: ExprId,
    purpose: &str,
    location: u64,
) -> Option<u128> {
    select_unsigned_extremum(st, value, purpose, location, UnsignedExtremum::Minimum)
}

#[cfg(test)]
pub(super) fn maximize_unsigned_value(
    st: &mut State,
    value: ExprId,
    purpose: &str,
    location: u64,
) -> Option<u128> {
    select_unsigned_extremum(st, value, purpose, location, UnsignedExtremum::Maximum)
}
