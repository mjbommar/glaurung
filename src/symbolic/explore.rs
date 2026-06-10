//! Symbolic path exploration (Phase 5, initial).
//!
//! Forks execution at *symbolic* conditional branches, accumulates the path
//! condition, prunes infeasible paths with the solver, and searches for an input
//! that drives control to a target address. Built on the same interpreter and
//! the `Symbolic` domain; state forking is a `Machine<Symbolic>` clone (each
//! fork carries its own expression pool — a shared copy-on-write pool is a
//! future optimization).
//!
//! Scope (initial): DFS worklist, bounded by a max-state cap; concrete branches
//! follow deterministically, symbolic branches fork and are feasibility-checked.
//! Concretize-with-threshold symbolic *memory*, directed search ordering, and
//! witness concrete-replay are later Phase-5 increments
//! (`docs/design/execution-engine/02-architecture/symbolic-engine.md`).

use std::collections::HashMap;

use crate::exec::domain::{BranchDecision, Domain};
use crate::exec::{Flow, Machine};
use crate::ir::types::{LlirBlock, LlirFunction, Op};
use crate::symbolic::solver::{solve, Assert, SolveResult};
use crate::symbolic::Symbolic;

/// One in-flight path: a machine snapshot, its program counter, and the path
/// condition collected so far.
struct State {
    machine: Machine<Symbolic>,
    pc: u64,
    constraints: Vec<Assert>,
}

/// Search for an input that reaches `target`, starting from `lf`'s entry with the
/// machine seeded by `seed` (e.g. marking argument registers symbolic). Returns
/// the solver result for the first path that reaches `target`:
/// `Sat(model)` is a reaching witness; `Unsat` means no explored path reached it;
/// `Unknown` means the state cap was hit first; `NoSolver` propagates.
pub fn find_input_reaching(
    lf: &LlirFunction,
    target: u64,
    seed: impl FnOnce(&mut Machine<Symbolic>),
    max_states: usize,
) -> SolveResult {
    let blocks: HashMap<u64, LlirBlock> =
        lf.blocks.iter().map(|b| (b.start_va, b.clone())).collect();

    let mut machine = Machine::new(Symbolic::new());
    seed(&mut machine);

    let mut work = vec![State {
        machine,
        pc: lf.entry_va,
        constraints: Vec::new(),
    }];
    let mut explored = 0usize;

    while let Some(st) = work.pop() {
        if explored >= max_states {
            return SolveResult::Unknown;
        }
        explored += 1;

        if st.pc == target {
            // Reached the target: solve the accumulated path condition for a
            // concrete input that drives execution here.
            return solve(&st.machine.dom.pool, &st.constraints);
        }

        for s in process_block(&blocks, st) {
            work.push(s);
        }
    }
    SolveResult::Unsat
}

/// Execute the block at `st.pc`, returning the feasible successor states.
fn process_block(blocks: &HashMap<u64, LlirBlock>, mut st: State) -> Vec<State> {
    let Some(block) = blocks.get(&st.pc).cloned() else {
        return Vec::new(); // ran off the known CFG
    };

    for ins in &block.instrs {
        match &ins.op {
            Op::CondJump {
                cond,
                target,
                inverted,
            } => {
                let c = st.machine.regs.read(&mut st.machine.dom, cond);
                match st.machine.dom.as_branch(&c) {
                    // Constant conditions follow deterministically.
                    BranchDecision::Taken => {
                        st.pc = if !*inverted { *target } else { block.end_va };
                        return vec![st];
                    }
                    BranchDecision::NotTaken => {
                        st.pc = if *inverted { *target } else { block.end_va };
                        return vec![st];
                    }
                    // Symbolic condition: fork both ways, keep the feasible ones.
                    BranchDecision::Fork => {
                        let pc_if_true = if !*inverted { *target } else { block.end_va };
                        let pc_if_false = if *inverted { *target } else { block.end_va };
                        let mut out = Vec::new();
                        for (bit, npc) in [(true, pc_if_true), (false, pc_if_false)] {
                            let mut child = State {
                                machine: st.machine.clone(),
                                pc: npc,
                                constraints: st.constraints.clone(),
                            };
                            child.constraints.push((c, bit));
                            // Prune only when provably infeasible; keep on
                            // Sat / Unknown / NoSolver.
                            if !matches!(
                                solve(&child.machine.dom.pool, &child.constraints),
                                SolveResult::Unsat
                            ) {
                                out.push(child);
                            }
                        }
                        return out;
                    }
                }
            }
            Op::Jump { target } => {
                st.pc = *target;
                return vec![st];
            }
            // No call/return handling yet (Phase 3 SimProcedures); end the path.
            Op::Return | Op::Call { .. } => return Vec::new(),
            other => match st.machine.step(other) {
                Flow::Next => continue,
                Flow::Jump(t) => {
                    st.pc = t;
                    return vec![st];
                }
                // Branch shouldn't occur (CondJump handled above); halt/return/
                // call end the path.
                _ => return Vec::new(),
            },
        }
    }

    // Fell off the end with no terminator → fall through to the next block.
    st.pc = block.end_va;
    vec![st]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{CmpOp, Flag, LlirInstr, Op, VReg, Value, Width};

    fn func(blocks: Vec<(u64, Vec<Op>, u64)>) -> LlirFunction {
        let mut out = Vec::new();
        for (start, ops, end) in blocks {
            out.push(LlirBlock {
                start_va: start,
                end_va: end,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(i, op)| LlirInstr {
                        va: start + i as u64 * 4,
                        op,
                    })
                    .collect(),
                succs: vec![],
            });
        }
        LlirFunction {
            entry_va: out[0].start_va,
            blocks: out,
        }
    }

    #[test]
    fn finds_input_that_reaches_target_block() {
        // B0: zf = (rdi == 42) ; if zf jump WIN else fall through
        // WIN @0x2000: ret      ← target, reachable iff rdi == 42
        // FALL @0x1008: ret
        let lf = func(vec![
            (
                0x1000,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("rdi")),
                        rhs: Value::Const(42),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x2000,
                        inverted: false,
                    },
                ],
                0x1008,
            ),
            (0x2000, vec![Op::Return], 0x2004),
            (0x1008, vec![Op::Return], 0x100c),
        ]);

        let result = find_input_reaching(
            &lf,
            0x2000,
            |m| {
                let sym = m.dom.fresh(Width::W64); // sym0 = rdi
                m.regs.write(&mut m.dom, &VReg::phys("rdi"), sym);
            },
            1000,
        );

        match result {
            SolveResult::Sat(model) => {
                assert_eq!(
                    model.values.get(&0).copied(),
                    Some(42),
                    "the reaching input must be rdi = 42"
                );
            }
            other => panic!("expected a reaching witness, got {:?}", other),
        }
    }

    #[test]
    fn unreachable_target_is_unsat_or_exhausted() {
        // Single block that just returns; target 0x9999 is never reached.
        let lf = func(vec![(0x1000, vec![Op::Return], 0x1004)]);
        let result = find_input_reaching(&lf, 0x9999, |_| {}, 1000);
        assert!(
            matches!(result, SolveResult::Unsat | SolveResult::Unknown),
            "got {:?}",
            result
        );
    }
}
