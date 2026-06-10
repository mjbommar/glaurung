//! SimProcedures — function-call summaries (Phase 3, initial).
//!
//! Following angr's model, a call to a modeled address is *replaced* by a Rust
//! summary that applies its effect to machine state and "returns" — rather than
//! executing into the callee. This lets a function run past library/OS calls
//! (`malloc`, `strlen`, `memcpy`, …) instead of stopping at the call. Summaries
//! read arguments via the calling convention and write the return register.
//!
//! Summaries are plain `fn` pointers (like helpers), looked up by target VA, so
//! the registry can be consulted and then the summary called with `&mut Machine`
//! without aliasing. The libc/Win32 stub *sets* (Phase 3.5/3.6) register
//! concrete summaries here.

use std::collections::HashMap;

use crate::exec::domain::Domain;
use crate::exec::interp::{Halt, Machine};

/// A call summary: apply the call's effect to the machine and return. `Err(halt)`
/// stops execution.
pub type SimProcFn<D> = fn(&mut Machine<D>) -> Result<(), Halt>;

/// A registry of call summaries keyed by target virtual address.
pub struct SimProcRegistry<D: Domain> {
    by_addr: HashMap<u64, SimProcFn<D>>,
}

impl<D: Domain> Default for SimProcRegistry<D> {
    fn default() -> Self {
        Self {
            by_addr: HashMap::new(),
        }
    }
}

impl<D: Domain> Clone for SimProcRegistry<D> {
    fn clone(&self) -> Self {
        Self {
            by_addr: self.by_addr.clone(),
        }
    }
}

impl<D: Domain> SimProcRegistry<D> {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Register a summary for calls to `addr`.
    pub fn register(&mut self, addr: u64, proc_fn: SimProcFn<D>) {
        self.by_addr.insert(addr, proc_fn);
    }

    /// Look up a summary for a call target.
    pub fn get(&self, addr: u64) -> Option<SimProcFn<D>> {
        self.by_addr.get(&addr).copied()
    }

    /// Whether any summaries are registered (hot-path gate).
    pub fn is_empty(&self) -> bool {
        self.by_addr.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::concrete::Concrete;
    use crate::exec::{Budget, Flow, Outcome};
    use crate::ir::types::{CallTarget, LlirBlock, LlirFunction, LlirInstr, Op, VReg, Width};

    /// A summary that sets rax = 42 (a stand-in for a modeled callee).
    fn ret42(m: &mut Machine<Concrete>) -> Result<(), Halt> {
        let v = m.dom.constant(Width::W64, 42);
        m.regs.write(&mut m.dom, &VReg::phys("rax"), v);
        Ok(())
    }

    #[test]
    fn call_to_registered_simproc_runs_and_continues() {
        let mut m = Machine::new(Concrete);
        m.simprocs.register(0x4000, ret42);

        // call 0x4000 ; (falls through) — the call is replaced by the summary,
        // and execution continues to the next instruction.
        let f = m.step(&Op::Call {
            target: CallTarget::Direct(0x4000),
        });
        assert_eq!(f, Flow::Next, "modeled call continues instead of CalledOut");
        assert_eq!(m.regs.read(&mut m.dom, &VReg::phys("rax")), 42);
    }

    #[test]
    fn unmodeled_call_still_yields_calledout() {
        let mut m = Machine::new(Concrete);
        let f = m.step(&Op::Call {
            target: CallTarget::Direct(0x9999),
        });
        assert_eq!(f, Flow::Call(Some(0x9999)));
    }

    #[test]
    fn run_function_proceeds_through_a_modeled_call() {
        // B0: call 0x4000 ; ret    — with a simproc for 0x4000, the whole
        // function runs to Return (rax = 42), instead of stopping at the call.
        let mut m = Machine::new(Concrete);
        m.simprocs.register(0x4000, ret42);
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1008,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::Call {
                            target: CallTarget::Direct(0x4000),
                        },
                    },
                    LlirInstr {
                        va: 0x1004,
                        op: Op::Return,
                    },
                ],
                succs: vec![],
            }],
        };
        let mut budget = Budget::new(100);
        assert_eq!(m.run_function(&lf, &mut budget), Outcome::Returned);
        assert_eq!(m.regs.read(&mut m.dom, &VReg::phys("rax")), 42);
    }
}
