//! Shadow-mode control-flow structuring.
//!
//! This module observes the same typed CFG as the production structurer but
//! cannot select rendered output. Its contract is evidence first: every run
//! returns a deterministic candidate or a typed refusal, plus exact graph
//! coverage. Production authority remains [`crate::ir::structure`].

mod conditions;
mod dominators;
mod region;
mod verify;

pub use conditions::{ConditionDag, ConditionId, ConditionNode};
pub use dominators::{LoopForest, LoopInfo, LoopKind};
pub use region::{BlockRegion, RegionCandidate, Terminal, Transfer};
pub use verify::CandidateError;

use crate::ir::ssa::SsaInfo;
use crate::ir::types::LlirFunction;

/// Why the shadow structurer deliberately declined a graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A cycle remains after removing every dominance-proved natural back edge.
    CyclicGraph,
    /// The independently verified candidate did not preserve the typed CFG.
    CandidateInvalid,
}

/// Result of observing one function without changing production output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowReport {
    pub block_count: usize,
    pub edge_count: usize,
    pub covered_blocks: usize,
    pub represented_edges: usize,
    pub conditions: Option<ConditionDag>,
    pub loops: LoopForest,
    pub candidate: Option<RegionCandidate>,
    pub verification_errors: Vec<CandidateError>,
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
    let loops = LoopForest::from_cfg(cfg);
    match ConditionDag::from_cfg(cfg, &loops) {
        Ok(conditions) => {
            let candidate = RegionCandidate::from_cfg(cfg, &loops);
            let verification_errors = candidate.as_ref().map_or_else(Vec::new, |candidate| {
                verify::verify_candidate(cfg, &loops, candidate)
            });
            if verification_errors.is_empty() {
                ShadowReport {
                    block_count,
                    edge_count,
                    covered_blocks: block_count,
                    represented_edges: edge_count,
                    conditions: Some(conditions),
                    candidate,
                    loops,
                    verification_errors,
                    refusal: None,
                }
            } else {
                ShadowReport {
                    block_count,
                    edge_count,
                    covered_blocks: 0,
                    represented_edges: 0,
                    conditions: Some(conditions),
                    candidate: None,
                    loops,
                    verification_errors,
                    refusal: Some(Refusal::CandidateInvalid),
                }
            }
        }
        Err(refusal) => ShadowReport {
            block_count,
            edge_count,
            covered_blocks: 0,
            represented_edges: 0,
            conditions: None,
            candidate: None,
            loops,
            verification_errors: Vec::new(),
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
        assert!(first.verification_errors.is_empty());
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
    fn an_irreducible_two_entry_cycle_is_a_typed_refusal_not_partial_coverage() {
        let function = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                block(0x1000, condition(0x1200), vec![0x1200, 0x1100]),
                block(0x1100, Op::Nop, vec![0x1200]),
                block(0x1200, Op::Nop, vec![0x1100]),
            ],
        };
        let report = observe(&function, &compute_ssa(&function));

        assert_eq!(report.refusal, Some(Refusal::CyclicGraph));
        assert_eq!(report.covered_blocks, 0);
        assert_eq!(report.represented_edges, 0);
        assert_eq!(report.conditions, None);
        assert!(report.verification_errors.is_empty());
    }

    #[test]
    fn real_sc_mixed_fixture_runs_in_shadow_mode_with_total_coverage() {
        let lifted = lift_real_fixture("01_conditional_polarity-gcc-O0.so", "sc_mixed");
        let report = observe(&lifted, &compute_ssa(&lifted));

        assert_eq!(report.refusal, None, "{report:#?}");
        assert_eq!(report.covered_blocks, report.block_count);
        assert_eq!(report.represented_edges, report.edge_count);
        assert!(
            report.block_count >= 5,
            "real short-circuit CFG is nontrivial"
        );
        assert!(report.conditions.is_some());
        assert!(report.loops.is_empty());
        let candidate = report.candidate.expect("acyclic candidate");
        assert_eq!(candidate.blocks().len(), report.block_count);
        assert_eq!(candidate.transfer_count(), report.edge_count);
    }

    fn lift_real_fixture(binary_name: &str, function_name: &str) -> LlirFunction {
        let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/decompiler_fixtures/build")
            .join(binary_name);
        let session = crate::program::session::ProgramSession::from_path(&binary)
            .expect("checked-in decompiler fixture parses");
        let image = session.image();
        let entry = image
            .defined_text_symbol_address(function_name)
            .unwrap_or_else(|| panic!("fixture exports {function_name}"));
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
            .unwrap_or_else(|| panic!("{function_name} is discovered"));
        crate::ir::lift_function::lift_function_from_image(image, function)
            .unwrap_or_else(|error| panic!("{function_name} lifts: {error}"))
    }

    #[test]
    fn real_dowhile_fixture_has_a_post_tested_loop_with_explicit_exits() {
        let lifted = lift_real_fixture("03_loop_shapes-gcc-O0.so", "dowhile_atleastonce");
        let report = observe(&lifted, &compute_ssa(&lifted));

        assert_eq!(report.loops.len(), 1, "{report:#?}");
        let loop_info = &report.loops.loops()[0];
        assert_eq!(loop_info.kind, LoopKind::PostTested);
        assert!(!loop_info.latches.is_empty());
        assert!(!loop_info.exits.is_empty());
        assert!(loop_info.blocks.len() >= 2);
        let candidate = report.candidate.expect("reducible loop candidate");
        assert_eq!(candidate.blocks().len(), report.block_count);
        assert_eq!(candidate.transfer_count(), report.edge_count);
        assert!(candidate
            .transfers()
            .any(|edge| matches!(edge, Transfer::Continue { .. })));
        assert!(candidate
            .transfers()
            .any(|edge| matches!(edge, Transfer::Break { .. })));
    }

    #[test]
    fn real_loop_return_fixture_records_loop_exits_without_losing_blocks() {
        let lifted = lift_real_fixture("03_loop_shapes-gcc-O0.so", "loop_return_on_neg");
        let report = observe(&lifted, &compute_ssa(&lifted));

        assert!(!report.loops.is_empty(), "{report:#?}");
        assert!(
            report
                .loops
                .loops()
                .iter()
                .any(|loop_info| loop_info.exits.len() >= 2),
            "early-return and normal-exit paths must remain distinct: {report:#?}"
        );
        let candidate = report.candidate.expect("reducible loop candidate");
        assert_eq!(candidate.blocks().len(), report.block_count);
        assert_eq!(candidate.transfer_count(), report.edge_count);
        let return_blocks: Vec<_> = candidate
            .blocks()
            .iter()
            .filter(|block| block.terminal == Some(Terminal::Return))
            .map(|block| block.block)
            .collect();
        assert_eq!(
            return_blocks.len(),
            1,
            "the shared terminal tail is owned once: {candidate:#?}"
        );
        let shared_return = return_blocks[0];
        let incoming = candidate
            .transfers()
            .filter(|transfer| match transfer {
                Transfer::Flow { to }
                | Transfer::Branch { to, .. }
                | Transfer::Break { to, .. } => *to == shared_return,
                Transfer::Continue { .. } => false,
            })
            .count();
        assert!(
            incoming >= 2,
            "early and normal exits must both reach the shared terminal: {candidate:#?}"
        );
    }
}
