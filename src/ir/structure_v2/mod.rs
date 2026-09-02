//! Shadow-mode control-flow structuring.
//!
//! This module observes the same typed CFG as the production structurer but
//! cannot select rendered output. Its contract is evidence first: every run
//! returns a deterministic candidate or a typed refusal, plus exact graph
//! coverage. Production authority remains [`crate::ir::structure`].

mod conditions;

pub use conditions::{ConditionDag, ConditionId, ConditionNode};

use crate::ir::ssa::SsaInfo;
use crate::ir::types::LlirFunction;

/// Why the shadow structurer deliberately declined a graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The first vertical slice supports acyclic condition graphs only.
    CyclicGraph,
}

/// Result of observing one function without changing production output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowReport {
    pub block_count: usize,
    pub edge_count: usize,
    pub covered_blocks: usize,
    pub represented_edges: usize,
    pub conditions: Option<ConditionDag>,
    pub refusal: Option<Refusal>,
}

/// Analyze one function beside v1 without influencing its selected region.
pub fn observe(lf: &LlirFunction, ssa: &SsaInfo) -> ShadowReport {
    let cfg = crate::ir::structure::Cfg::from(lf, ssa);
    observe_cfg(&cfg)
}

/// Observe the exact typed graph already built for production v1.
pub(crate) fn observe_cfg(cfg: &crate::ir::structure::Cfg) -> ShadowReport {
    let block_count = cfg.succs.len();
    let edge_count = cfg.edges.iter().map(Vec::len).sum();
    match ConditionDag::from_cfg(cfg) {
        Ok(conditions) => ShadowReport {
            block_count,
            edge_count,
            covered_blocks: block_count,
            represented_edges: edge_count,
            conditions: Some(conditions),
            refusal: None,
        },
        Err(refusal) => ShadowReport {
            block_count,
            edge_count,
            covered_blocks: 0,
            represented_edges: 0,
            conditions: None,
            refusal: Some(refusal),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::types::{Flag, LlirBlock, LlirFunction, LlirInstr, Op, VReg};

    fn condition(target: u64) -> Op {
        Op::CondJump {
            cond: VReg::Flag(Flag::Z),
            target,
            inverted: false,
        }
    }

    fn block(start_va: u64, op: Op, succs: Vec<u64>) -> LlirBlock {
        LlirBlock {
            start_va,
            end_va: start_va + 4,
            instrs: vec![LlirInstr { va: start_va, op }],
            succs,
        }
    }

    fn mixed_short_circuit_cfg() -> LlirFunction {
        // Machine CFG for `(a && b) || c`: the individual comparisons are
        // intentionally abstract. The structurer consumes branch identity and
        // polarity, not source spelling.
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                block(0x1000, condition(0x1100), vec![0x1100, 0x1200]),
                block(0x1100, condition(0x1300), vec![0x1300, 0x1200]),
                block(0x1200, condition(0x1300), vec![0x1300, 0x1400]),
                block(0x1300, Op::Return, vec![]),
                block(0x1400, Op::Return, vec![]),
            ],
        }
    }

    #[test]
    fn mixed_short_circuit_condition_dag_is_total_and_deterministic() {
        let function = mixed_short_circuit_cfg();
        let ssa = compute_ssa(&function);

        let first = observe(&function, &ssa);
        let second = observe(&function, &ssa);

        assert_eq!(first, second);
        assert_eq!(first.refusal, None);
        assert_eq!(first.block_count, 5);
        assert_eq!(first.covered_blocks, first.block_count);
        assert_eq!(first.edge_count, 6);
        assert_eq!(first.represented_edges, first.edge_count);
        let dag = first.conditions.expect("acyclic CFG has a condition DAG");
        assert_eq!(dag.reaching_conditions().len(), first.block_count);
        assert!(dag.node_count() < 32, "shared conditions must be interned");

        fn evaluate(dag: &ConditionDag, id: ConditionId, branches: &[bool; 3]) -> bool {
            match &dag.nodes[id.0] {
                ConditionNode::False => false,
                ConditionNode::True => true,
                ConditionNode::Branch { block } => branches[*block],
                ConditionNode::Not(inner) => !evaluate(dag, *inner, branches),
                ConditionNode::And(terms) => {
                    terms.iter().all(|term| evaluate(dag, *term, branches))
                }
                ConditionNode::Or(terms) => terms.iter().any(|term| evaluate(dag, *term, branches)),
            }
        }

        for bits in 0u8..8 {
            let branches = [bits & 1 != 0, bits & 2 != 0, bits & 4 != 0];
            let expected_true = (branches[0] && branches[1]) || branches[2];
            assert_eq!(
                evaluate(&dag, dag.reaching_conditions()[3], &branches),
                expected_true,
                "true return under {branches:?}"
            );
            assert_eq!(
                evaluate(&dag, dag.reaching_conditions()[4], &branches),
                !expected_true,
                "false return under {branches:?}"
            );
        }
    }

    #[test]
    fn a_cycle_is_a_typed_refusal_not_partial_coverage() {
        let function = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                block(0x1000, Op::Nop, vec![0x1100]),
                block(0x1100, Op::Nop, vec![0x1000]),
            ],
        };
        let report = observe(&function, &compute_ssa(&function));

        assert_eq!(report.refusal, Some(Refusal::CyclicGraph));
        assert_eq!(report.covered_blocks, 0);
        assert_eq!(report.represented_edges, 0);
        assert_eq!(report.conditions, None);
    }

    #[test]
    fn real_sc_mixed_fixture_runs_in_shadow_mode_with_total_coverage() {
        let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/decompiler_fixtures/build/01_conditional_polarity-gcc-O0.so");
        let session = crate::program::session::ProgramSession::from_path(&binary)
            .expect("checked-in conditional-polarity fixture parses");
        let image = session.image();
        let entry = image
            .defined_text_symbol_address("sc_mixed")
            .expect("fixture exports sc_mixed");
        let discovered = session.discover_functions(
            &crate::analysis::cfg::Budgets {
                max_functions: 1,
                max_blocks: 128,
                max_instructions: 4096,
                timeout_ms: 5000,
                total_timeout_ms: 0,
            },
            &[entry],
        );
        let function = discovered
            .iter()
            .find(|function| function.entry_point.value == entry)
            .expect("sc_mixed is discovered");
        let lifted = crate::ir::lift_function::lift_function_from_image(image, function)
            .expect("sc_mixed lifts");
        let report = observe(&lifted, &compute_ssa(&lifted));

        assert_eq!(report.refusal, None, "{report:#?}");
        assert_eq!(report.covered_blocks, report.block_count);
        assert_eq!(report.represented_edges, report.edge_count);
        assert!(
            report.block_count >= 5,
            "real short-circuit CFG is nontrivial"
        );
        assert!(report.conditions.is_some());
    }
}
