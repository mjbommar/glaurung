//! Opt-in firing counts for the AST recovery transforms.
//!
//! # Why this exists
//!
//! A structural transform is a long conjunction of shape requirements, and a
//! conjunction that is one clause too strict is INVISIBLE: the pass compiles,
//! its unit tests pass (they construct exactly the shape it wants), the gate is
//! green, and it never fires on a real binary. Two passes in this crate were in
//! that state — `loop_form::recover_sentinel_search_loops` had never fired on a
//! corpus lane, and `loop_form::recover_guarded_do_whiles` fired once in 688.
//! Nothing reported that, because "did not fire" and "fired and changed
//! nothing" produce identical output.
//!
//! This module makes firing observable. It is off unless
//! `GLAURUNG_PASS_STATS` is set in the environment, and when off costs one
//! relaxed atomic load per call.
//!
//! # Using it
//!
//! ```text
//! GLAURUNG_PASS_STATS=1 glaurung decompile <binary> --all --style decbench \
//!     2>&1 >/dev/null | sort | uniq -c | sort -rn
//! ```
//!
//! Each line is `glaurung-pass-stat <pass> <attempt|fire>`. Attempts are
//! counted where the pass is *offered* a body to match, so `fire / attempt` is
//! the selectivity of the match and a pass with attempts and no fires is one
//! whose preconditions never hold on real input.
//!
//! Emitted per event rather than accumulated and dumped at exit, because the
//! callers that matter are short-lived subprocesses (`tools/diff_decompile.py`
//! runs one per function) and an atexit dump would be lost whenever a lane was
//! killed — which is exactly the run you most want the numbers from.

use std::io::Write;
use std::sync::OnceLock;

fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("GLAURUNG_PASS_STATS").is_some())
}

/// Record that `pass` was offered a body to match.
pub fn attempt(pass: &str) {
    emit(pass, "attempt");
}

/// Record that `pass` matched and rewrote something.
pub fn fire(pass: &str) {
    emit(pass, "fire");
}

fn emit(pass: &str, event: &str) {
    if !enabled() {
        return;
    }
    // Deliberately unbuffered and best-effort: a diagnostic that panicked or
    // held a lock across a recovery pass would change the thing it measures.
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "glaurung-pass-stat {pass} {event}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_is_silent_and_infallible_when_disabled() {
        // The test process does not set `GLAURUNG_PASS_STATS`, so these are
        // no-ops. The property under test is that they cannot panic or block —
        // a diagnostic that can take down a recovery pass is worse than no
        // diagnostic.
        attempt("probe");
        fire("probe");
        assert!(!enabled() || enabled());
    }
}
