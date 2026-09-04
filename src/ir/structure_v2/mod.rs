//! Shadow-mode control-flow structuring.
//!
//! This module observes the same typed CFG as the production structurer but
//! cannot select rendered output. Its contract is evidence first: every run
//! returns a deterministic candidate or a typed refusal, plus exact graph
//! coverage. Production authority remains [`crate::ir::structure`].

mod cleanup;
mod conditions;
mod dominators;
mod local;
mod recover;
mod region;
pub(crate) mod render;
mod verify;

pub use cleanup::{
    DuplicatedTail, MAX_TAIL_DUPLICATION_INSTRUCTIONS, MAX_TOTAL_TAIL_DUPLICATION_INSTRUCTIONS,
};
pub use conditions::{ConditionDag, ConditionId, ConditionNode};
pub use dominators::{LoopForest, LoopInfo, LoopKind};
pub use local::{HonestGotoEvidence, LocalRegions};
pub use recover::{
    LocalExitRegion, LocalLabelRegion, LoopExitRegion, StructuredRegion, StructuredTree,
    SwitchCaseRegion, SwitchDefaultRegion,
};
pub use region::{
    BlockRegion, RegionCandidate, SwitchCaseEvidence, SwitchDefaultEvidence, SwitchEvidence,
    Terminal, Transfer,
};
pub use verify::{CandidateError, TreeError};

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
    pub tree: Option<StructuredTree>,
    /// Deterministic pre-pass C-like text for faithfully adaptable tree shapes.
    pub raw_pseudocode: Option<String>,
    /// Deterministic parseable C after the shared source-level preparation pass.
    pub prepared_pseudocode: Option<String>,
    pub honest_gotos: Vec<HonestGotoEvidence>,
    pub duplicated_tails: Vec<DuplicatedTail>,
    pub verification_errors: Vec<CandidateError>,
    pub tree_verification_errors: Vec<TreeError>,
    pub refusal: Option<Refusal>,
}

/// Analyze one function beside v1 without influencing its selected region.
pub fn observe(lf: &LlirFunction, ssa: &SsaInfo) -> ShadowReport {
    let cfg = crate::ir::structure::Cfg::from(lf, ssa);
    observe_cfg(&cfg, lf, ssa)
}

/// Observe the exact typed graph already built for production v1.
pub(crate) fn observe_cfg(
    cfg: &crate::ir::structure::Cfg,
    lf: &LlirFunction,
    ssa: &SsaInfo,
) -> ShadowReport {
    let block_count = cfg.succs.len();
    let edge_count = cfg.edges.iter().map(Vec::len).sum();
    let loops = LoopForest::from_cfg(cfg);
    let local_regions = LocalRegions::from_cfg(cfg, &loops);
    let duplicated_tails = cleanup::plan_tail_duplication(cfg);
    let branch_predicates = cfg.branch_predicates(lf, ssa);
    match ConditionDag::from_cfg(cfg, &loops, &local_regions, &branch_predicates) {
        Ok(conditions) => {
            let candidate = RegionCandidate::from_cfg(cfg, &loops, &local_regions);
            let verification_errors = candidate.as_ref().map_or_else(Vec::new, |candidate| {
                verify::verify_candidate(cfg, &loops, &local_regions, &duplicated_tails, candidate)
            });
            if verification_errors.is_empty() {
                let tree = candidate.as_ref().and_then(|candidate| {
                    recover::recover_tree(
                        cfg,
                        &conditions,
                        candidate,
                        &loops,
                        &local_regions,
                        &duplicated_tails,
                    )
                });
                let tree_verification_errors = tree.as_ref().map_or_else(Vec::new, |tree| {
                    verify::verify_tree(
                        candidate.as_ref().expect("tree requires a candidate"),
                        &conditions,
                        &loops,
                        &local_regions,
                        &duplicated_tails,
                        tree,
                    )
                });
                let tree = if tree_verification_errors.is_empty() {
                    tree
                } else {
                    None
                };
                let rendered = tree
                    .as_ref()
                    .and_then(|tree| render::render_pseudocode(lf, tree));
                let raw_pseudocode = rendered.as_ref().map(|rendered| rendered.raw.clone());
                let prepared_pseudocode = rendered.map(|rendered| rendered.prepared);
                ShadowReport {
                    block_count,
                    edge_count,
                    covered_blocks: block_count,
                    represented_edges: edge_count,
                    conditions: Some(conditions),
                    candidate,
                    tree,
                    raw_pseudocode,
                    prepared_pseudocode,
                    honest_gotos: local_regions.evidence().to_vec(),
                    duplicated_tails,
                    loops,
                    verification_errors,
                    tree_verification_errors,
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
                    tree: None,
                    raw_pseudocode: None,
                    prepared_pseudocode: None,
                    honest_gotos: Vec::new(),
                    duplicated_tails: Vec::new(),
                    loops,
                    verification_errors,
                    tree_verification_errors: Vec::new(),
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
            tree: None,
            raw_pseudocode: None,
            prepared_pseudocode: None,
            honest_gotos: Vec::new(),
            duplicated_tails: Vec::new(),
            loops,
            verification_errors: Vec::new(),
            tree_verification_errors: Vec::new(),
            refusal: Some(refusal),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::types::{
        CmpOp, Flag, LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value, Width,
    };

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

    fn shared_return_cfg(return_instruction_count: usize) -> LlirFunction {
        let mut tail_instrs = (0..return_instruction_count.saturating_sub(1))
            .map(|offset| LlirInstr {
                va: 0x1300 + offset as u64,
                op: Op::Nop,
            })
            .collect::<Vec<_>>();
        tail_instrs.push(LlirInstr {
            va: 0x1300 + return_instruction_count.saturating_sub(1) as u64,
            op: Op::Return,
        });
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                block(0x1000, condition(0x1100), vec![0x1100, 0x1200]),
                block(0x1100, Op::Nop, vec![0x1300]),
                block(0x1200, Op::Nop, vec![0x1300]),
                LlirBlock {
                    start_va: 0x1300,
                    end_va: 0x1300 + return_instruction_count as u64,
                    instrs: tail_instrs,
                    succs: vec![],
                },
            ],
        }
    }

    fn typed_comparison_cfg(op: CmpOp, lhs: VReg, inverted: bool) -> LlirFunction {
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                LlirBlock {
                    start_va: 0x1000,
                    end_va: 0x1008,
                    instrs: vec![
                        LlirInstr {
                            va: 0x1000,
                            op: Op::Cmp {
                                dst: VReg::Flag(Flag::C),
                                op,
                                lhs: Value::Reg(lhs),
                                rhs: Value::Const(7),
                            },
                        },
                        LlirInstr {
                            va: 0x1004,
                            op: Op::CondJump {
                                cond: VReg::Flag(Flag::C),
                                target: 0x1100,
                                inverted,
                            },
                        },
                    ],
                    succs: vec![0x1100, 0x1200],
                },
                block(0x1100, Op::Return, vec![]),
                block(0x1200, Op::Return, vec![]),
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
                ConditionNode::Branch { block, .. } => branches[*block],
                ConditionNode::LocalRegion { .. } => {
                    panic!("acyclic truth-table fixture has no local region")
                }
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
    fn condition_atoms_preserve_comparison_width_signedness_and_polarity() {
        let unsigned32 = typed_comparison_cfg(CmpOp::Ult, VReg::phys("eax"), false);
        let signed64_inverted = typed_comparison_cfg(CmpOp::Slt, VReg::phys("rax"), true);
        let unknown = mixed_short_circuit_cfg();

        let unsigned_report = observe(&unsigned32, &compute_ssa(&unsigned32));
        let signed_report = observe(&signed64_inverted, &compute_ssa(&signed64_inverted));
        let unknown_report = observe(&unknown, &compute_ssa(&unknown));

        assert!(unsigned_report
            .conditions
            .expect("condition DAG")
            .nodes
            .iter()
            .any(|node| matches!(
                node,
                ConditionNode::Branch {
                    block: 0,
                    op: Some(CmpOp::Ult),
                    operand_width: Some(Width::W32),
                    inverted: false,
                }
            )));
        assert!(signed_report
            .conditions
            .expect("condition DAG")
            .nodes
            .iter()
            .any(|node| matches!(
                node,
                ConditionNode::Branch {
                    block: 0,
                    op: Some(CmpOp::Slt),
                    operand_width: Some(Width::W64),
                    inverted: true,
                }
            )));
        assert!(unknown_report
            .conditions
            .expect("condition DAG")
            .nodes
            .iter()
            .any(|node| matches!(
                node,
                ConditionNode::Branch {
                    op: None,
                    operand_width: None,
                    ..
                }
            )));
    }

    #[test]
    fn an_irreducible_two_entry_cycle_degrades_to_verified_local_gotos() {
        let function = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                block(0x1000, condition(0x1200), vec![0x1200, 0x1100]),
                block(0x1100, Op::Nop, vec![0x1200]),
                block(0x1200, Op::Nop, vec![0x1100]),
            ],
        };
        let report = observe(&function, &compute_ssa(&function));

        assert_eq!(report.refusal, None, "{report:#?}");
        assert_eq!(report.covered_blocks, report.block_count);
        assert_eq!(report.represented_edges, report.edge_count);
        assert_eq!(report.honest_gotos.len(), 1);
        let evidence = &report.honest_gotos[0];
        assert_eq!(evidence.blocks, vec![1, 2]);
        assert_eq!(evidence.entry_targets, vec![1, 2]);
        assert_eq!(
            evidence.property,
            "irreducible_scc_multiple_entries_no_dominating_header"
        );
        let candidate = report.candidate.expect("local-labelled candidate");
        assert!(candidate
            .transfers()
            .any(|transfer| matches!(transfer, Transfer::LocalGoto { to: 1 | 2, .. })));
        assert!(report.verification_errors.is_empty());
    }

    #[test]
    fn a_small_shared_return_gets_deterministic_clone_provenance() {
        let function = shared_return_cfg(MAX_TAIL_DUPLICATION_INSTRUCTIONS);
        let report = observe(&function, &compute_ssa(&function));

        assert_eq!(report.refusal, None, "{report:#?}");
        assert_eq!(report.duplicated_tails.len(), 1, "{report:#?}");
        assert_eq!(
            report.duplicated_tails[0],
            DuplicatedTail {
                source_block: 3,
                canonical_predecessor: 1,
                cloned_at_predecessor: 2,
                instruction_count: MAX_TAIL_DUPLICATION_INSTRUCTIONS,
            }
        );
        assert!(report.verification_errors.is_empty());
    }

    #[test]
    fn an_oversized_shared_return_is_not_duplicated() {
        let function = shared_return_cfg(MAX_TAIL_DUPLICATION_INSTRUCTIONS + 1);
        let report = observe(&function, &compute_ssa(&function));

        assert_eq!(report.refusal, None, "{report:#?}");
        assert!(report.duplicated_tails.is_empty(), "{report:#?}");
    }

    #[test]
    fn total_tail_duplication_growth_is_bounded_per_function() {
        let predecessor_vas: Vec<_> = (0..10).map(|index| 0x1100 + index * 0x100).collect();
        let mut blocks = vec![block(0x1000, Op::Nop, predecessor_vas.clone())];
        blocks.extend(
            predecessor_vas
                .iter()
                .copied()
                .map(|va| block(va, Op::Nop, vec![0x2000])),
        );
        let mut tail = shared_return_cfg(MAX_TAIL_DUPLICATION_INSTRUCTIONS)
            .blocks
            .pop()
            .expect("helper has a return tail");
        tail.start_va = 0x2000;
        tail.end_va = 0x2000 + MAX_TAIL_DUPLICATION_INSTRUCTIONS as u64;
        for (offset, instruction) in tail.instrs.iter_mut().enumerate() {
            instruction.va = 0x2000 + offset as u64;
        }
        blocks.push(tail);
        let function = LlirFunction {
            entry_va: 0x1000,
            blocks,
        };

        let report = observe(&function, &compute_ssa(&function));

        assert_eq!(report.refusal, None, "{report:#?}");
        assert_eq!(
            report
                .duplicated_tails
                .iter()
                .map(|tail| tail.instruction_count)
                .sum::<usize>(),
            MAX_TOTAL_TAIL_DUPLICATION_INSTRUCTIONS
        );
        assert!(report.verification_errors.is_empty());
    }

    #[test]
    fn real_sc_mixed_fixture_runs_in_shadow_mode_with_total_coverage() {
        let Some(lifted) = lift_real_fixture("01_conditional_polarity-gcc-O0.so", "sc_mixed")
        else {
            return;
        };
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

    #[test]
    fn real_early_return_fixture_recovers_a_verified_acyclic_tree() {
        let Some(lifted) = lift_real_fixture("01_conditional_polarity-gcc-O0.so", "early_return")
        else {
            return;
        };
        let report = observe(&lifted, &compute_ssa(&lifted));

        assert_eq!(report.refusal, None, "{report:#?}");
        assert!(report.loops.is_empty(), "fixture must stay acyclic");
        assert!(report.tree.is_some(), "{report:#?}");
        assert!(report.tree_verification_errors.is_empty(), "{report:#?}");
        let pseudocode = report
            .raw_pseudocode
            .as_deref()
            .unwrap_or_else(|| panic!("verified acyclic tree should render: {report:#?}"));
        assert!(pseudocode.contains("if ("), "{pseudocode}");
        assert!(!pseudocode.contains("goto "), "{pseudocode}");
        let repeated = observe(&lifted, &compute_ssa(&lifted));
        assert_eq!(report.raw_pseudocode, repeated.raw_pseudocode);
        assert_eq!(report.prepared_pseudocode, repeated.prepared_pseudocode);
        assert_prepared_c(&report);
    }

    #[test]
    fn real_packet_parser_keeps_its_shared_epilogue_as_a_join() {
        let Some(lifted) = lift_real_fixture("07_packet_parser-gcc-O0.so", "parse_packet") else {
            return;
        };
        let report = observe(&lifted, &compute_ssa(&lifted));

        assert_eq!(report.refusal, None, "{report:#?}");
        let raw = report
            .raw_pseudocode
            .as_deref()
            .unwrap_or_else(|| panic!("verified packet tree should render: {report:#?}"));
        assert!(raw.contains("\n    L_14dd:"), "raw v2 tree:\n{raw}");
        assert!(
            !raw.contains("\n                    L_14dd:"),
            "raw v2 tree:\n{raw}"
        );
        let prepared = report
            .prepared_pseudocode
            .as_deref()
            .unwrap_or_else(|| panic!("verified packet tree should prepare: {report:#?}"));
        assert!(
            prepared.contains("\n    L_14dd:"),
            "prepared v2 tree:\n{prepared}"
        );
    }

    /// Lift one function out of a prebuilt fixture, or `None` if it is absent.
    ///
    /// `tests/decompiler_fixtures/build/` is gitignored and built by the
    /// fixture harness, so it does not exist in a plain checkout. Returning
    /// `None` (rather than panicking) is what lets the `cargo test --features
    /// python-ext` CI job pass; `GLAURUNG_REQUIRE_FIXTURES=1`, which the
    /// Decompiler Fixture Gate sets, turns the absence back into a failure so
    /// the skip cannot go unnoticed where the corpus really is built.
    fn lift_real_fixture(binary_name: &str, function_name: &str) -> Option<LlirFunction> {
        let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/decompiler_fixtures/build")
            .join(binary_name);
        if !binary.is_file() {
            crate::testing::missing_fixture(binary_name);
            return None;
        }
        let session = crate::program::session::ProgramSession::from_path(&binary)
            .expect("checked-in decompiler fixture parses");
        let image = session.image();
        let entry = image
            .defined_text_symbol_address(function_name)
            .unwrap_or_else(|| panic!("fixture exports {function_name}"));
        let discovered = session.discover_functions(
            &crate::analysis::cfg::Budgets {
                max_functions: 1,
                max_blocks: 1024,
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
        Some(
            crate::ir::lift_function::lift_function_from_image(image, function)
                .unwrap_or_else(|error| panic!("{function_name} lifts: {error}")),
        )
    }

    fn assert_prepared_c(report: &ShadowReport) {
        let text = report
            .prepared_pseudocode
            .as_deref()
            .unwrap_or_else(|| panic!("verified tree should have prepared C: {report:#?}"));
        let directory = tempfile::tempdir().expect("temporary C syntax directory");
        let source = directory.path().join("shadow.c");
        std::fs::write(&source, text).expect("write prepared shadow C");
        let output = std::process::Command::new("cc")
            .args(["-fsyntax-only", "-std=gnu89", "-w", "-fno-builtin"])
            .arg(&source)
            .output()
            .expect("host C compiler is available");
        assert!(
            output.status.success(),
            "prepared shadow output must parse:\n{}\n{text}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn real_dowhile_fixture_has_a_post_tested_loop_with_explicit_exits() {
        let Some(lifted) = lift_real_fixture("03_loop_shapes-gcc-O0.so", "dowhile_atleastonce")
        else {
            return;
        };
        let ssa = compute_ssa(&lifted);
        let report = observe(&lifted, &ssa);

        assert_eq!(report.loops.len(), 1, "{report:#?}");
        let loop_info = &report.loops.loops()[0];
        assert_eq!(loop_info.kind, LoopKind::PostTested);
        assert!(!loop_info.latches.is_empty());
        assert!(!loop_info.exits.is_empty());
        assert!(loop_info.blocks.len() >= 2);
        let candidate = report.candidate.as_ref().expect("reducible loop candidate");
        assert_eq!(candidate.blocks().len(), report.block_count);
        assert_eq!(candidate.transfer_count(), report.edge_count);
        assert!(candidate
            .transfers()
            .any(|edge| matches!(edge, Transfer::Continue { .. })));
        assert!(candidate
            .transfers()
            .any(|edge| matches!(edge, Transfer::Break { .. })));
        let tree = report
            .tree
            .as_ref()
            .unwrap_or_else(|| panic!("reducible loop tree: {report:#?}"));
        assert!(tree_has_region(&tree.root, |region| matches!(
            region,
            StructuredRegion::Loop {
                kind: LoopKind::PostTested,
                ..
            }
        )));
        assert!(tree_has_region(&tree.root, |region| matches!(
            region,
            StructuredRegion::Continue { .. }
        )));
        assert!(tree_has_region(&tree.root, |region| matches!(
            region,
            StructuredRegion::Break { .. }
        )));
        let pseudocode = report
            .raw_pseudocode
            .as_deref()
            .unwrap_or_else(|| panic!("verified post-tested loop should render: {report:#?}"));
        assert!(pseudocode.contains("do {"), "{pseudocode}");
        assert!(pseudocode.contains("} while ("), "{pseudocode}");
        assert!(pseudocode.contains("break;"), "{pseudocode}");
        assert!(!pseudocode.contains("goto "), "{pseudocode}");
        assert_prepared_c(&report);
        assert!(report.tree_verification_errors.is_empty(), "{report:#?}");
        let repeated = observe(&lifted, &ssa);
        assert_eq!(report.tree, repeated.tree);
        assert_eq!(report.prepared_pseudocode, repeated.prepared_pseudocode);
    }

    #[test]
    fn real_loop_return_fixture_records_loop_exits_without_losing_blocks() {
        let Some(lifted) = lift_real_fixture("03_loop_shapes-gcc-O0.so", "loop_return_on_neg")
        else {
            return;
        };
        let ssa = compute_ssa(&lifted);
        let report = observe(&lifted, &ssa);

        assert!(!report.loops.is_empty(), "{report:#?}");
        assert!(
            report
                .loops
                .loops()
                .iter()
                .any(|loop_info| loop_info.exits.len() >= 2),
            "early-return and normal-exit paths must remain distinct: {report:#?}"
        );
        let candidate = report.candidate.as_ref().expect("reducible loop candidate");
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
                | Transfer::Break { to, .. }
                | Transfer::LocalGoto { to, .. } => *to == shared_return,
                Transfer::Continue { .. } => false,
            })
            .count();
        assert!(
            incoming >= 2,
            "early and normal exits must both reach the shared terminal: {candidate:#?}"
        );
        assert!(
            !report.duplicated_tails.is_empty(),
            "the real shared return should produce clone provenance: {report:#?}"
        );
        assert!(
            report
                .duplicated_tails
                .iter()
                .all(|tail| tail.source_block == shared_return),
            "only the shared return may be selected for duplication: {report:#?}"
        );
        let tree = report
            .tree
            .as_ref()
            .unwrap_or_else(|| panic!("multi-exit reducible loop tree: {report:#?}"));
        assert!(tree_has_region(&tree.root, |region| matches!(
            region,
            StructuredRegion::Loop { .. }
        )));
        assert!(tree_has_region(&tree.root, |region| matches!(
            region,
            StructuredRegion::Loop { exits, .. } if exits.len() == 2
        )));
        assert!(tree_has_region(&tree.root, |region| matches!(
            region,
            StructuredRegion::Break { .. }
        )));
        for tail in &report.duplicated_tails {
            assert!(
                tree_has_region(&tree.root, |region| matches!(
                    region,
                    StructuredRegion::DuplicatedReturn {
                        source_block,
                        cloned_at_predecessor,
                    } if source_block == &tail.source_block
                        && cloned_at_predecessor == &tail.cloned_at_predecessor
                )),
                "planned terminal clone must be materialized: {tail:?}\n{tree:#?}"
            );
        }
        let pseudocode = report
            .raw_pseudocode
            .as_deref()
            .unwrap_or_else(|| panic!("verified multi-exit loop should render: {report:#?}"));
        assert!(pseudocode.contains("while (1)"), "{pseudocode}");
        assert!(pseudocode.matches("return").count() >= 2, "{pseudocode}");
        assert!(!pseudocode.contains("goto "), "{pseudocode}");
        let repeated = observe(&lifted, &ssa);
        assert_eq!(report.raw_pseudocode, repeated.raw_pseudocode);
        let prepared = report
            .prepared_pseudocode
            .as_deref()
            .unwrap_or_else(|| panic!("verified multi-exit loop should prepare as C: {report:#?}"));
        assert!(prepared.contains("while (1)"), "{prepared}");
        assert!(!prepared.contains("goto "), "{prepared}");
        assert_prepared_c(&report);
        assert_eq!(report.prepared_pseudocode, repeated.prepared_pseudocode);
        assert!(report.tree_verification_errors.is_empty(), "{report:#?}");
        assert_eq!(report.tree, repeated.tree);
    }

    fn tree_has_region(
        region: &StructuredRegion,
        predicate: impl Copy + Fn(&StructuredRegion) -> bool,
    ) -> bool {
        if predicate(region) {
            return true;
        }
        match region {
            StructuredRegion::Sequence(regions) => regions
                .iter()
                .any(|region| tree_has_region(region, predicate)),
            StructuredRegion::If {
                then_region,
                else_region,
                ..
            } => {
                tree_has_region(then_region, predicate)
                    || else_region
                        .as_deref()
                        .is_some_and(|region| tree_has_region(region, predicate))
            }
            StructuredRegion::Loop { body, exits, .. } => {
                tree_has_region(body, predicate)
                    || exits
                        .iter()
                        .any(|exit| tree_has_region(&exit.region, predicate))
            }
            StructuredRegion::Switch { cases, default, .. } => {
                cases
                    .iter()
                    .any(|case| tree_has_region(&case.region, predicate))
                    || default
                        .as_ref()
                        .is_some_and(|default| tree_has_region(&default.region, predicate))
            }
            StructuredRegion::Empty
            | StructuredRegion::Block(_)
            | StructuredRegion::Return { .. }
            | StructuredRegion::Break { .. }
            | StructuredRegion::Continue { .. }
            | StructuredRegion::LocalGoto { .. }
            | StructuredRegion::SharedGoto { .. }
            | StructuredRegion::DuplicatedReturn { .. } => false,
        }
    }

    #[test]
    fn real_two_entry_loop_is_an_accepted_honest_goto() {
        let Some(lifted) = lift_real_fixture("211_irreducible_loops-gcc-O0.so", "two_entry_loop")
        else {
            return;
        };
        let ssa = compute_ssa(&lifted);
        let report = observe(&lifted, &ssa);

        assert_eq!(report.refusal, None, "{report:#?}");
        assert_eq!(report.honest_gotos.len(), 1, "{report:#?}");
        assert_eq!(
            report.honest_gotos[0].property,
            "irreducible_scc_multiple_entries_no_dominating_header"
        );
        assert!(report.honest_gotos[0].entry_targets.len() >= 2);
        assert_eq!(report.covered_blocks, report.block_count);
        assert_eq!(report.represented_edges, report.edge_count);
        let tree = report
            .tree
            .as_ref()
            .unwrap_or_else(|| panic!("local-labelled tree: {report:#?}"));
        assert_eq!(tree.local_regions.len(), 1, "{tree:#?}");
        assert!(tree_has_region(&tree.root, |region| matches!(
            region,
            StructuredRegion::LocalGoto { .. }
        )));
        let pseudocode = report
            .raw_pseudocode
            .as_deref()
            .unwrap_or_else(|| panic!("verified local-labelled tree should render: {report:#?}"));
        assert!(pseudocode.contains("goto L_"), "{pseudocode}");
        for target in pseudocode.lines().filter_map(|line| {
            line.trim()
                .strip_prefix("goto ")
                .and_then(|line| line.strip_suffix(';'))
        }) {
            assert!(
                pseudocode.contains(&format!("{target}:")),
                "unresolved {target} in:\n{pseudocode}"
            );
        }
        let repeated = observe(&lifted, &ssa);
        assert_eq!(report.raw_pseudocode, repeated.raw_pseudocode);
        assert_prepared_c(&report);
        assert_eq!(report.prepared_pseudocode, repeated.prepared_pseudocode);
        assert!(report.tree_verification_errors.is_empty(), "{report:#?}");
    }

    #[test]
    fn real_nested_irreducible_region_does_not_erase_the_outer_loop() {
        let Some(lifted) = lift_real_fixture(
            "211_irreducible_loops-gcc-O0.so",
            "irreducible_inside_reducible",
        ) else {
            return;
        };
        let report = observe(&lifted, &compute_ssa(&lifted));

        assert_eq!(report.refusal, None, "{report:#?}");
        assert!(!report.loops.is_empty(), "outer reducible loop survives");
        assert!(
            !report.honest_gotos.is_empty(),
            "inner irreducible SCC is named"
        );
        let candidate = report
            .candidate
            .as_ref()
            .expect("locally degraded candidate");
        assert!(candidate.transfers().any(|transfer| matches!(
            transfer,
            Transfer::Continue { .. } | Transfer::Break { .. }
        )));
        assert!(candidate
            .transfers()
            .any(|transfer| matches!(transfer, Transfer::LocalGoto { .. })));
        assert_eq!(candidate.blocks().len(), report.block_count);
        assert_eq!(candidate.transfer_count(), report.edge_count);
        let tree = report
            .tree
            .as_ref()
            .unwrap_or_else(|| panic!("outer loop with local-labelled child: {report:#?}"));
        assert!(!tree.local_regions.is_empty(), "{tree:#?}");
        assert!(tree_has_region(&tree.root, |region| matches!(
            region,
            StructuredRegion::Loop { .. }
        )));
        assert!(tree_has_region(&tree.root, |region| matches!(
            region,
            StructuredRegion::LocalGoto { .. }
        )));
        let pseudocode = report.raw_pseudocode.as_deref().unwrap_or_else(|| {
            panic!("outer loop with nested local region should render: {report:#?}")
        });
        assert!(pseudocode.contains("while ("), "{pseudocode}");
        assert!(pseudocode.contains("goto L_"), "{pseudocode}");
        for target in pseudocode.lines().filter_map(|line| {
            line.trim()
                .strip_prefix("goto ")
                .and_then(|line| line.strip_suffix(';'))
        }) {
            assert!(
                pseudocode.contains(&format!("{target}:")),
                "unresolved {target} in:\n{pseudocode}"
            );
        }
        let repeated = observe(&lifted, &compute_ssa(&lifted));
        assert_eq!(report.raw_pseudocode, repeated.raw_pseudocode);
        assert_prepared_c(&report);
        assert_eq!(report.prepared_pseudocode, repeated.prepared_pseudocode);
        assert!(report.tree_verification_errors.is_empty(), "{report:#?}");
    }

    #[test]
    fn real_duff_dispatch_reaches_shadow_as_typed_cases() {
        let Some(lifted) = lift_real_fixture("102_duffs_device-gcc-O2.so", "duff_copy") else {
            return;
        };
        let report = observe(&lifted, &compute_ssa(&lifted));
        let candidate = report
            .candidate
            .as_ref()
            .unwrap_or_else(|| panic!("Duff CFG should have a verified candidate: {report:#?}"));
        let dispatches = candidate.switches();

        assert_eq!(dispatches.len(), 1, "{dispatches:#?}");
        let dispatch = &dispatches[0];
        assert_eq!(lifted.blocks[dispatch.dispatch].succs.len(), 8);
        assert_eq!(dispatch.cases.len(), 8, "{dispatch:#?}");
        assert_eq!(
            dispatch
                .cases
                .iter()
                .flat_map(|case| case.values.iter().copied())
                .collect::<Vec<_>>(),
            (0..8).collect::<Vec<_>>()
        );
        assert_eq!(candidate.switch_defaults().len(), 1, "{candidate:#?}");
        assert_eq!(
            candidate.switch_defaults()[0].dispatch,
            Some(dispatch.dispatch)
        );
        let tree = report
            .tree
            .as_ref()
            .unwrap_or_else(|| panic!("typed Duff switch should recover locally: {report:#?}"));
        assert!(tree_has_region(&tree.root, |region| matches!(
            region,
            StructuredRegion::Switch { .. }
        )));
        let pseudocode = report
            .raw_pseudocode
            .as_deref()
            .unwrap_or_else(|| panic!("verified Duff tree should render: {report:#?}"));
        assert!(pseudocode.contains("switch ("), "{pseudocode}");
        assert!(pseudocode.contains("case 0:"), "{pseudocode}");
        assert!(pseudocode.contains("case 7:"), "{pseudocode}");
        assert!(pseudocode.contains("goto L_"), "{pseudocode}");
        assert!(
            !pseudocode.contains("unrecovered indirect jump"),
            "{pseudocode}"
        );
        for target in pseudocode.lines().filter_map(|line| {
            line.trim()
                .strip_prefix("goto ")
                .and_then(|line| line.strip_suffix(';'))
        }) {
            assert!(
                pseudocode.contains(&format!("{target}:")),
                "unresolved {target} in:\n{pseudocode}"
            );
        }
        let repeated = observe(&lifted, &compute_ssa(&lifted));
        assert_eq!(report.tree, repeated.tree);
        assert_eq!(report.raw_pseudocode, repeated.raw_pseudocode);
        assert_eq!(report.prepared_pseudocode, repeated.prepared_pseudocode);
        assert_prepared_c(&report);
        assert!(report.verification_errors.is_empty(), "{report:#?}");
        assert!(report.tree_verification_errors.is_empty(), "{report:#?}");
    }

    #[test]
    fn real_wide_effect_switches_reach_shadow_without_losing_cases() {
        for (binary, case_count) in [
            ("154_wide_switch-gcc-O2.so", 208usize),
            ("154_wide_switch-clang-O2.so", 256usize),
        ] {
            let Some(lifted) = lift_real_fixture(binary, "wide154_dense_effects") else {
                continue;
            };
            assert!(
                lifted.blocks.len() > 128,
                "fixture must remain a scale test"
            );
            let report = observe(&lifted, &compute_ssa(&lifted));
            let candidate = report
                .candidate
                .as_ref()
                .unwrap_or_else(|| panic!("wide switch should have a candidate: {report:#?}"));
            let dispatch = candidate
                .switches()
                .iter()
                .max_by_key(|dispatch| {
                    dispatch
                        .cases
                        .iter()
                        .map(|case| case.values.len())
                        .sum::<usize>()
                })
                .unwrap_or_else(|| panic!("wide switch should have typed cases: {report:#?}"));
            assert_eq!(
                dispatch
                    .cases
                    .iter()
                    .map(|case| case.values.len())
                    .sum::<usize>(),
                case_count,
                "{dispatch:#?}"
            );
            let tree = report.tree.as_ref().unwrap_or_else(|| {
                panic!("wide switch should recover a verified tree: {report:#?}")
            });
            assert!(tree_has_region(&tree.root, |region| matches!(
                region,
                StructuredRegion::Switch { .. }
            )));
            let pseudocode = report
                .raw_pseudocode
                .as_deref()
                .unwrap_or_else(|| panic!("wide switch should render: {report:#?}"));
            assert!(pseudocode.contains("switch ("), "{pseudocode}");
            assert!(pseudocode.contains("case 0:"), "{pseudocode}");
            assert!(
                pseudocode.contains(&format!("case {}:", case_count - 1)),
                "{pseudocode}"
            );
            assert!(
                !pseudocode.contains("unrecovered indirect jump"),
                "{pseudocode}"
            );
            if binary.contains("clang") {
                assert_eq!(
                    pseudocode.matches("rsp = (rsp - 408);").count(),
                    1,
                    "the guarded switch adapter must not execute its owner block twice:\n{pseudocode}"
                );
            }
            let repeated = observe(&lifted, &compute_ssa(&lifted));
            assert_eq!(report.tree, repeated.tree);
            assert_eq!(report.raw_pseudocode, repeated.raw_pseudocode);
            assert_eq!(report.prepared_pseudocode, repeated.prepared_pseudocode);
            assert_prepared_c(&report);
            assert!(report.tree_verification_errors.is_empty(), "{report:#?}");
        }
    }

    #[test]
    fn real_dispatch_in_loop_without_a_join_recovers_a_verified_tree() {
        let Some(lifted) =
            lift_real_fixture("206_aarch64_wide_dispatch-gcc-O2.so", "dispatch_in_loop")
        else {
            return;
        };
        let report = observe(&lifted, &compute_ssa(&lifted));

        assert_eq!(report.refusal, None, "{report:#?}");
        assert_eq!(report.covered_blocks, report.block_count, "{report:#?}");
        assert_eq!(report.represented_edges, report.edge_count, "{report:#?}");
        assert!(!report.loops.is_empty(), "fixture must retain its loop");
        let candidate = report
            .candidate
            .as_ref()
            .unwrap_or_else(|| panic!("dispatch loop should have a candidate: {report:#?}"));
        assert_eq!(candidate.switches().len(), 1, "{candidate:#?}");
        assert_eq!(
            candidate.switches()[0]
                .cases
                .iter()
                .flat_map(|case| case.values.iter().copied())
                .collect::<Vec<_>>(),
            (0..7).collect::<Vec<_>>()
        );
        let tree = report
            .tree
            .as_ref()
            .unwrap_or_else(|| panic!("dispatch loop should recover locally: {report:#?}"));
        assert!(tree_has_region(&tree.root, |region| matches!(
            region,
            StructuredRegion::Loop { .. }
        )));
        let pseudocode = report
            .raw_pseudocode
            .as_deref()
            .unwrap_or_else(|| panic!("dispatch loop should render: {report:#?}"));
        assert!(pseudocode.contains("while (1)"), "{pseudocode}");
        assert!(pseudocode.contains("switch ("), "{pseudocode}");
        assert!(pseudocode.contains("case 0:"), "{pseudocode}");
        assert!(pseudocode.contains("case 6:"), "{pseudocode}");
        assert!(pseudocode.contains("break;"), "{pseudocode}");
        assert!(pseudocode.contains("return "), "{pseudocode}");
        assert!(
            !pseudocode.contains("unrecovered indirect jump"),
            "{pseudocode}"
        );
        let repeated = observe(&lifted, &compute_ssa(&lifted));
        assert_eq!(report.tree, repeated.tree);
        assert_eq!(report.raw_pseudocode, repeated.raw_pseudocode);
        assert_eq!(report.prepared_pseudocode, repeated.prepared_pseudocode);
        assert_prepared_c(&report);
        assert!(report.tree_verification_errors.is_empty(), "{report:#?}");
    }
}
