//! Bounded-execution budget for the interpreter.
//!
//! Forensic/analysis execution must terminate. The budget counts **instructions
//! retired** (deterministic — no wall-clock; see
//! `docs/design/execution-engine/02-architecture/determinism.md`) and trips when
//! the limit is reached. A fuller budget (loop detection, region fencing) can
//! grow here later.

/// An instruction budget. Construct with [`Budget::new`]; the engine calls
/// [`Budget::tick`] once per executed instruction.
#[derive(Debug, Clone)]
pub struct Budget {
    max_steps: u64,
    steps: u64,
}

impl Budget {
    /// A budget allowing `max_steps` instructions.
    pub fn new(max_steps: u64) -> Self {
        Self {
            max_steps,
            steps: 0,
        }
    }

    /// Count one instruction. Returns `false` once the budget is exhausted (the
    /// just-counted step is the one over the limit).
    pub fn tick(&mut self) -> bool {
        self.steps += 1;
        self.steps <= self.max_steps
    }

    /// Instructions retired so far.
    pub fn spent(&self) -> u64 {
        self.steps
    }

    /// Whether the budget has been exhausted.
    pub fn exhausted(&self) -> bool {
        self.steps > self.max_steps
    }
}

impl Default for Budget {
    /// A generous default for one-shot function execution.
    fn default() -> Self {
        Self::new(100_000)
    }
}
