//! Cleanup applied only after exact region recovery: bounded tail-duplication
//! plans, and provenance-preserving lexical cleanup of verified output.

use super::LocalRegions;
use crate::ir::ast::{Function, Stmt};
use crate::ir::structure::Cfg;

/// Ceiling for cloning one straight-line tail ending in return.
pub const MAX_TAIL_DUPLICATION_INSTRUCTIONS: usize = 8;

/// A cleanup tail stays local rather than becoming a second structurer.
pub const MAX_TAIL_DUPLICATION_BLOCKS: usize = 4;

/// Maximum total cloned instructions planned for one function.
pub const MAX_TOTAL_TAIL_DUPLICATION_INSTRUCTIONS: usize = 64;

/// Provenance for one planned clone of an input straight-line return tail.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DuplicatedTail {
    pub source_block: usize,
    pub blocks: Vec<usize>,
    pub canonical_predecessor: usize,
    pub cloned_at_predecessor: usize,
    pub instruction_count: usize,
}

fn linear_return_tail(cfg: &Cfg, source_block: usize) -> Option<(Vec<usize>, usize)> {
    let mut blocks = Vec::new();
    let mut instruction_count = 0usize;
    let mut block = source_block;
    loop {
        if blocks.contains(&block) || blocks.len() == MAX_TAIL_DUPLICATION_BLOCKS {
            return None;
        }
        blocks.push(block);
        instruction_count = instruction_count.saturating_add(cfg.block_instruction_counts[block]);
        if instruction_count > MAX_TAIL_DUPLICATION_INSTRUCTIONS {
            return None;
        }
        match cfg.succs[block].as_slice() {
            [] if cfg.ends_in_return[block] => return Some((blocks, instruction_count)),
            [successor] => block = *successor,
            _ => return None,
        }
    }
}

/// Plan deterministic clones for small shared straight-line tails ending in
/// return. Every cloned block and the complete instruction budget are recorded
/// so verification can reject a forged branch, cycle, or oversized chain.
pub(super) fn plan_tail_duplication(cfg: &Cfg, locals: &LocalRegions) -> Vec<DuplicatedTail> {
    let mut duplicated = Vec::new();
    let mut planned_instructions = 0usize;
    for source_block in 0..cfg.succs.len() {
        let predecessors = &cfg.preds[source_block];
        if predecessors.len() < 2 {
            continue;
        }
        let Some((blocks, instruction_count)) = linear_return_tail(cfg, source_block) else {
            continue;
        };
        let canonical_predecessor = predecessors[0];
        for cloned_at_predecessor in predecessors[1..].iter().copied() {
            // Local labelled regions retain their input blocks and exits as a
            // separate definition. Their transfers are not tree-builder clone
            // sites, so never promise a materialization there.
            if locals
                .evidence()
                .iter()
                .any(|region| region.blocks.contains(&cloned_at_predecessor))
            {
                continue;
            }
            if planned_instructions.saturating_add(instruction_count)
                > MAX_TOTAL_TAIL_DUPLICATION_INSTRUCTIONS
            {
                break;
            }
            duplicated.push(DuplicatedTail {
                source_block,
                blocks: blocks.clone(),
                canonical_predecessor,
                cloned_at_predecessor,
                instruction_count,
            });
            planned_instructions += instruction_count;
        }
    }
    duplicated
}

// --- lexical cleanup of verified structure-v2 output ---------------------

/// Remove lexical `else` nesting after an arm that exits on every path.
///
/// This runs only for selected structure-v2 output and only after region
/// adaptation has fixed block ownership and joins. It changes no condition,
/// transfer, or statement order: `if (c) return; else body` becomes
/// `if (c) return; body`.
pub(crate) fn flatten_terminal_elses(function: &mut Function) {
    flatten_in_body(&mut function.body);
}

fn exits_on_all_paths(body: &[Stmt]) -> bool {
    let Some(last) = body.last() else {
        return false;
    };
    match last.semantic() {
        Stmt::Return { .. }
        | Stmt::Throw { .. }
        | Stmt::Goto { .. }
        | Stmt::IndirectGoto { .. }
        | Stmt::Continue
        | Stmt::Break => true,
        Stmt::If {
            then_body,
            else_body: Some(else_body),
            ..
        } => exits_on_all_paths(then_body) && exits_on_all_paths(else_body),
        _ => false,
    }
}

fn flatten_in_body(body: &mut Vec<Stmt>) {
    for statement in body.iter_mut() {
        match statement.semantic_mut() {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                flatten_in_body(then_body);
                if let Some(else_body) = else_body {
                    flatten_in_body(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::For { body, .. } | Stmt::DoWhile { body, .. } => {
                flatten_in_body(body)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    flatten_in_body(case);
                }
                if let Some(default) = default {
                    flatten_in_body(default);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                flatten_in_body(try_body);
                for catch in catches {
                    flatten_in_body(&mut catch.body);
                }
            }
            Stmt::Origin { .. }
            | Stmt::Assign { .. }
            | Stmt::Store { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::Throw { .. }
            | Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::Continue
            | Stmt::IndirectGoto { .. }
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Push { .. }
            | Stmt::Pop { .. } => {}
        }
    }

    let mut index = 0;
    while index < body.len() {
        let qualifies = matches!(
            body[index].semantic(),
            Stmt::If {
                then_body,
                else_body: Some(_),
                ..
            } if exits_on_all_paths(then_body)
        );
        if !qualifies {
            index += 1;
            continue;
        }
        let statement = std::mem::replace(&mut body[index], Stmt::Nop);
        let (semantic, origins) = statement.into_semantic_with_origins();
        let Stmt::If {
            cond,
            then_body,
            else_body: Some(else_body),
        } = semantic
        else {
            unreachable!("shape checked above")
        };
        body[index] = Stmt::If {
            cond,
            then_body,
            else_body: None,
        }
        .with_optional_origins(origins);
        let inserted = else_body.len();
        body.splice(index + 1..index + 1, else_body);
        index += inserted + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Expr, OriginSet};

    #[test]
    fn terminal_then_arm_becomes_an_attributed_early_return() {
        let owner = OriginSet::one(0x1010);
        let mut function = Function {
            name: "early".into(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![Stmt::Return {
                    value: Some(Expr::Const(1)),
                }],
                else_body: Some(vec![Stmt::Assign {
                    dst: crate::ir::types::VReg::phys("result"),
                    src: Expr::Const(2),
                }]),
            }
            .with_origins(owner.clone())],
        };

        flatten_terminal_elses(&mut function);

        assert_eq!(function.body.len(), 2);
        assert_eq!(function.body[0].origins(), Some(&owner));
        assert!(matches!(
            function.body[0].semantic(),
            Stmt::If {
                else_body: None,
                ..
            }
        ));
        assert!(matches!(function.body[1].semantic(), Stmt::Assign { .. }));
    }

    #[test]
    fn partially_returning_then_arm_keeps_its_else() {
        let mut function = Function {
            name: "partial".into(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![Stmt::If {
                    cond: Expr::Const(2),
                    then_body: vec![Stmt::Return { value: None }],
                    else_body: None,
                }],
                else_body: Some(vec![Stmt::Return { value: None }]),
            }],
        };

        flatten_terminal_elses(&mut function);

        assert!(matches!(
            function.body[0].semantic(),
            Stmt::If {
                else_body: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn terminal_goto_arm_becomes_an_attributed_early_exit() {
        let owner = OriginSet::one(0x1020);
        let mut function = Function {
            name: "goto_exit".into(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![Stmt::Goto { target: 0x2000 }],
                else_body: Some(vec![Stmt::Assign {
                    dst: crate::ir::types::VReg::phys("result"),
                    src: Expr::Const(2),
                }]),
            }
            .with_origins(owner.clone())],
        };

        flatten_terminal_elses(&mut function);

        assert_eq!(function.body.len(), 2);
        assert_eq!(function.body[0].origins(), Some(&owner));
        assert!(matches!(
            function.body[0].semantic(),
            Stmt::If {
                then_body,
                else_body: None,
                ..
            } if matches!(then_body.as_slice(), [Stmt::Goto { target: 0x2000 }])
        ));
        assert!(matches!(function.body[1].semantic(), Stmt::Assign { .. }));
    }
}
