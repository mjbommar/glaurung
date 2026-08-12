//! Sink a labelled block to its unique `goto`, removing both.
//!
//! # NOT WIRED INTO THE PIPELINE — measured, and it lost
//!
//! This pass is correct and does what it claims: it removed 11% of emitted
//! gotos. It is compiled and tested but deliberately not called, because when
//! it was called it cost `statemachine:gcc:O0.ged` 10 → 35 plus five
//! `byte_match` cells. Fewer gotos is not the same as a control-flow graph
//! closer to the source's, and this is the counterexample: moving a block to
//! its jump site changes where that block sits in the region tree, which is
//! exactly what GED measures.
//!
//! Keep the code — the analysis below is the expensive part and it stays true —
//! but do not wire it back in without a metric that says goto density is worth
//! paying GED for. See task #63.
//!
//! Goto density is the second-largest readability gap after declaration count:
//! 8.63 per 100 lines against Ghidra's 3.18 and angr's 1.99, measured
//! function-weighted over 93 ground-truth functions. Over 409 gotos in that
//! corpus:
//!
//! ```text
//! 316  (77.3%)  target a label reached by exactly ONE goto
//! 102  of those also have NO fallthrough into the label
//!   0  are at the same nesting level as their goto
//! ```
//!
//! That last line is why this pass sinks rather than inlines. Every one of the
//! 102 has its `goto` nested *deeper* than the label — the label sits at
//! function level and the jump comes from inside an `if`. A same-level inliner
//! fires on nothing at all.
//!
//! # Why sinking is sound
//!
//! When exactly one `goto` targets a label and nothing falls into it, that goto
//! is the block's ONLY predecessor: the block executes exactly when the goto is
//! taken, and never otherwise. Moving it to the goto site therefore preserves
//! the execution set, wherever that site is nested — including inside a loop,
//! because "when the goto fires" is the same condition either way.
//!
//! The one thing that must not be lost is the block's own exit. A block that
//! ended by falling through into the *next* label depended on its position; so
//! this pass only moves a block that ends in an unconditional transfer, which is
//! self-contained by construction. (Appending a synthetic `goto next` would
//! widen the pass, but it would also manufacture a jump the reader did not have,
//! which is the opposite of the goal.)

use std::collections::HashMap;

use crate::ir::ast::{Function, Stmt};

/// Remove a `goto`/label pair by moving the labelled block to the jump.
pub fn sink_single_predecessor_labels(f: &mut Function) {
    // Bounded: each round removes at least one label, and sinking can expose a
    // fresh single-predecessor label underneath the one just moved.
    for _ in 0..8 {
        let mut targets: HashMap<u64, usize> = HashMap::new();
        count_goto_targets(&f.body, &mut targets);
        let sinkable: Vec<u64> = targets
            .into_iter()
            .filter(|(_, count)| *count == 1)
            .map(|(target, _)| target)
            .collect();
        if sinkable.is_empty() {
            return;
        }
        let mut moved = false;
        for target in sinkable {
            if let Some(block) = take_labelled_block(&mut f.body, target) {
                if replace_goto_with_block(&mut f.body, target, &block) {
                    moved = true;
                } else {
                    // The jump was not found after all — put the block back
                    // rather than dropping code on the floor.
                    restore_labelled_block(&mut f.body, target, block);
                }
            }
        }
        if !moved {
            return;
        }
    }
}

fn count_goto_targets(body: &[Stmt], counts: &mut HashMap<u64, usize>) {
    for statement in body {
        match statement {
            Stmt::Goto { target } => *counts.entry(*target).or_insert(0) += 1,
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                count_goto_targets(then_body, counts);
                if let Some(else_body) = else_body {
                    count_goto_targets(else_body, counts);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                count_goto_targets(body, counts)
            }
            Stmt::For {
                init, step, body, ..
            } => {
                count_goto_targets(std::slice::from_ref(init.as_ref()), counts);
                count_goto_targets(body, counts);
                count_goto_targets(std::slice::from_ref(step.as_ref()), counts);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    count_goto_targets(case_body, counts);
                }
                if let Some(default_body) = default {
                    count_goto_targets(default_body, counts);
                }
            }
            _ => {}
        }
    }
}

/// True for a statement after which control cannot fall through.
fn is_unconditional_transfer(statement: &Stmt) -> bool {
    matches!(
        statement,
        Stmt::Goto { .. } | Stmt::Return { .. } | Stmt::Break | Stmt::IndirectGoto { .. }
    )
}

/// Detach `label:` and the statements up to the next label, when that block is
/// entered only by a jump and leaves only by a transfer.
fn take_labelled_block(body: &mut Vec<Stmt>, target: u64) -> Option<Vec<Stmt>> {
    let at = body
        .iter()
        .position(|s| matches!(s, Stmt::Label(va) if *va == target))?;

    // Nothing may fall into the label: the statement before it must transfer
    // away, or the label must open the block.
    if at > 0 && !is_unconditional_transfer(&body[at - 1]) {
        return None;
    }

    let mut end = at + 1;
    while end < body.len() && !matches!(body[end], Stmt::Label(_)) {
        if is_unconditional_transfer(&body[end]) {
            end += 1;
            // Self-contained: it ends by transferring, so its position carries
            // no meaning and it can be moved.
            let block: Vec<Stmt> = body.drain(at..end).skip(1).collect();
            return (!block.is_empty()).then_some(block);
        }
        end += 1;
    }
    // Fell through into the next label (or the end of the body) — its position
    // is load-bearing, so leave it alone.
    None
}

fn restore_labelled_block(body: &mut Vec<Stmt>, target: u64, block: Vec<Stmt>) {
    body.push(Stmt::Label(target));
    body.extend(block);
}

/// Replace the single `goto target;` with the block, anywhere in the tree.
fn replace_goto_with_block(body: &mut Vec<Stmt>, target: u64, block: &[Stmt]) -> bool {
    if let Some(at) = body
        .iter()
        .position(|s| matches!(s, Stmt::Goto { target: va } if *va == target))
    {
        body.splice(at..=at, block.iter().cloned());
        return true;
    }
    for statement in body.iter_mut() {
        let replaced = match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                replace_goto_with_block(then_body, target, block)
                    || else_body
                        .as_mut()
                        .is_some_and(|b| replace_goto_with_block(b, target, block))
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                replace_goto_with_block(body, target, block)
            }
            Stmt::For { body, .. } => replace_goto_with_block(body, target, block),
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter_mut()
                    .any(|(_, case_body)| replace_goto_with_block(case_body, target, block))
                    || default
                        .as_mut()
                        .is_some_and(|b| replace_goto_with_block(b, target, block))
            }
            _ => false,
        };
        if replaced {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::Expr;
    use crate::ir::types::VReg;

    fn assign(name: &str, value: i64) -> Stmt {
        Stmt::Assign {
            dst: VReg::phys(name),
            src: Expr::Const(value),
        }
    }

    /// The shape all 102 corpus candidates have: the jump is nested inside an
    /// `if`, the label sits at function level.
    #[test]
    fn a_block_entered_only_from_a_nested_goto_is_sunk_to_it() {
        let mut f = Function {
            name: "sink".into(),
            entry_va: 0,
            body: vec![
                Stmt::If {
                    cond: Expr::Const(1),
                    then_body: vec![Stmt::Goto { target: 0x40 }],
                    else_body: None,
                },
                Stmt::Return { value: None },
                Stmt::Label(0x40),
                assign("a", 7),
                Stmt::Return { value: None },
            ],
        };
        sink_single_predecessor_labels(&mut f);

        assert!(
            !f.body.iter().any(|s| matches!(s, Stmt::Label(0x40))),
            "label should be gone: {:#?}",
            f.body
        );
        let Stmt::If { then_body, .. } = &f.body[0] else {
            panic!("expected the if to survive: {:#?}", f.body);
        };
        assert!(
            matches!(then_body[0], Stmt::Assign { .. }),
            "block should have moved into the jump site: {then_body:#?}"
        );
        assert!(matches!(then_body[1], Stmt::Return { .. }));
    }

    /// Two jumps means the block is shared; moving it would duplicate or strand
    /// one of them.
    #[test]
    fn a_block_with_two_predecessors_is_left_alone() {
        let body = vec![
            Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![Stmt::Goto { target: 0x40 }],
                else_body: Some(vec![Stmt::Goto { target: 0x40 }]),
            },
            Stmt::Label(0x40),
            assign("a", 7),
            Stmt::Return { value: None },
        ];
        let mut f = Function {
            name: "shared".into(),
            entry_va: 0,
            body: body.clone(),
        };
        sink_single_predecessor_labels(&mut f);
        assert_eq!(f.body, body);
    }

    /// If control can FALL into the label, the block has a second predecessor
    /// that no goto count can see.
    #[test]
    fn a_block_that_can_be_fallen_into_is_left_alone() {
        let body = vec![
            Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![Stmt::Goto { target: 0x40 }],
                else_body: None,
            },
            assign("b", 1), // no transfer: control falls into the label below
            Stmt::Label(0x40),
            assign("a", 7),
            Stmt::Return { value: None },
        ];
        let mut f = Function {
            name: "fallthrough".into(),
            entry_va: 0,
            body: body.clone(),
        };
        sink_single_predecessor_labels(&mut f);
        assert_eq!(f.body, body);
    }

    /// A block that leaves by falling through to the NEXT label depends on
    /// where it sits, so moving it would lose that edge.
    #[test]
    fn a_block_that_falls_out_to_the_next_label_is_left_alone() {
        let body = vec![
            Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![Stmt::Goto { target: 0x40 }],
                else_body: None,
            },
            Stmt::Return { value: None },
            Stmt::Label(0x40),
            assign("a", 7),
            Stmt::Label(0x50), // fallthrough exit, not a transfer
            Stmt::Return { value: None },
        ];
        let mut f = Function {
            name: "fallout".into(),
            entry_va: 0,
            body: body.clone(),
        };
        sink_single_predecessor_labels(&mut f);
        assert_eq!(f.body, body);
    }
}
