//! What bounds one analysis, and what says the answer was cut short.
//!
//! Every ceiling this module can hit is in here together, because they answer
//! one question -- *how much work is this run allowed to do* -- and the four
//! `hit_*` flags they set are the difference between "the binary has no
//! vtables" and "we stopped before looking". [`Budgets`] is the caller's
//! declaration, [`Deadline`] is the whole-run clock (plus the cancellation flag
//! that makes a long analysis interruptible from Python), and [`scan_within`]
//! is the guard for the straight-line whole-image sweeps that have no loop of
//! their own to instrument.

use super::*;

#[derive(Debug, Clone, Copy)]
pub struct Budgets {
    pub max_functions: usize,
    pub max_blocks: usize,
    pub max_instructions: usize,
    /// Wall clock for ONE function's block/instruction walk. Despite the bare
    /// name this has never bounded an analysis: `discover_function` restarts its
    /// clock per seed, so a binary with 20 000 functions can spend 20 000 times
    /// this and still be inside budget. Use `total_timeout_ms` to bound the run.
    pub timeout_ms: u64,
    /// Wall clock for the WHOLE analysis: every whole-binary discovery phase and
    /// every seed in the worklist, not just one function's walk. `0` means no
    /// ceiling.
    ///
    /// Zero is the default because a ceiling that truncates changes what
    /// discovery finds, and every recorded corpus number was measured without
    /// one; silently applying a wall clock to existing callers would move those
    /// numbers with nothing to attribute the movement to. Callers that would
    /// rather have a bounded answer than a complete one — the CLI does — set it
    /// explicitly, and `FunctionDiscoveryStats::hit_total_timeout` then says the
    /// result is a truncation rather than an answer.
    pub total_timeout_ms: u64,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            // Zero means "no function-count cap"; use the other budgets
            // to keep full-corpus analysis bounded.
            max_functions: 0,
            max_blocks: 2048,
            max_instructions: 50_000,
            timeout_ms: 100,
            total_timeout_ms: 0,
        }
    }
}

/// A wall-clock ceiling for one whole analysis, threaded through every discovery
/// loop so exceeding it is a reported outcome instead of an unbounded run.
///
/// Copyable and cheap to test: `expired()` is one `clock_gettime`, the same call
/// the per-function `timeout_ms` check already makes on the decode path.
#[derive(Debug, Clone, Copy)]
pub struct Deadline<'a> {
    end: Option<std::time::Instant>,
    start: std::time::Instant,
    cancel: Option<&'a std::sync::atomic::AtomicBool>,
}

impl<'a> Deadline<'a> {
    /// The ceiling `budgets.total_timeout_ms` describes, starting now.
    pub fn start(budgets: &Budgets) -> Self {
        let start = std::time::Instant::now();
        Self {
            end: (budgets.total_timeout_ms > 0)
                .then(|| start + std::time::Duration::from_millis(budgets.total_timeout_ms)),
            start,
            cancel: None,
        }
    }

    /// A deadline that never expires — for callers with no whole-run ceiling.
    pub fn none() -> Self {
        Self {
            end: None,
            start: std::time::Instant::now(),
            cancel: None,
        }
    }

    /// The same ceiling, additionally stopped as soon as `cancel` is set.
    ///
    /// This is what makes a long analysis interruptible from Python. Releasing
    /// the GIL is NOT enough on its own: the interpreter runs its signal handler
    /// only on a thread that holds the GIL, and the thread that called us is
    /// inside Rust for the whole analysis, so a `Ctrl-C` sits pending until the
    /// call returns — which is exactly the 20-minute unkillable run. The binding
    /// runs the analysis on a worker thread, keeps the calling thread in
    /// `Python::check_signals`, and sets this flag when a signal arrives.
    pub fn with_cancel(self, cancel: &'a std::sync::atomic::AtomicBool) -> Self {
        Self {
            cancel: Some(cancel),
            ..self
        }
    }

    /// Whether the analysis must stop: the ceiling passed, or a caller asked.
    pub fn expired(&self) -> bool {
        self.cancelled() || self.end.is_some_and(|end| std::time::Instant::now() >= end)
    }

    /// Whether a caller asked for the analysis to stop.
    pub fn cancelled(&self) -> bool {
        self.cancel
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Wall clock consumed so far, in milliseconds.
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

/// Run a whole-binary seed scan unless the analysis deadline has already passed.
///
/// The discovery loops check the deadline themselves; these scans are
/// straight-line sweeps over the whole image with no loop to instrument, so the
/// check has to be at the call. Once the ceiling is gone every remaining scan is
/// skipped instead of run to completion, and `hit_total_timeout` is set — which
/// is what makes an empty candidate list a REPORTED truncation rather than a
/// binary that simply had no vtables in it.
pub(super) fn scan_within<T: Default>(
    deadline: Deadline<'_>,
    stats: &mut FunctionDiscoveryStats,
    scan: impl FnOnce() -> T,
) -> T {
    if deadline.expired() {
        stats.hit_total_timeout = true;
        return T::default();
    }
    scan()
}
