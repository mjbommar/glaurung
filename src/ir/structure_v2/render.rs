//! Conservative shadow-tree adapter into the existing AST and printer.

use super::{LoopKind, StructuredRegion, StructuredTree};
use crate::ir::structure::Region;
use crate::ir::types::LlirFunction;

/// Two deterministic views derived from one faithfully adapted shadow AST.
pub(super) struct RenderedPseudocode {
    pub raw: String,
    pub prepared: String,
}

/// Render a verified tree through the production AST lowerer and the shared
/// source-level preparation pass when every shape has a faithful region
/// spelling.
pub(super) fn render_pseudocode(
    lf: &LlirFunction,
    tree: &StructuredTree,
) -> Option<RenderedPseudocode> {
    let region = adapt_tree(tree)?;
    let function = crate::ir::ast::lower(lf, &region, format!("sub_{:x}", lf.entry_va));
    let raw = crate::ir::ast::render_c(&function);
    let prepared = crate::ir::ast::prepare_for_decbench(&function);
    Some(RenderedPseudocode {
        raw,
        prepared: crate::ir::ast::render_decbench(&prepared),
    })
}

/// Adapt an independently verified v2 tree into the production AST boundary.
pub(crate) fn adapt_tree(tree: &StructuredTree) -> Option<Region> {
    let mut regions = vec![adapt_region(&tree.root)?];
    for local in &tree.local_regions {
        regions.push(Region::Unstructured(
            local.blocks.iter().map(|block| block.block).collect(),
        ));
        for exit in &local.exits {
            regions.push(adapt_region(&exit.region)?);
        }
    }
    Some(Region::Seq(regions))
}

fn adapt_region(region: &StructuredRegion) -> Option<Region> {
    match region {
        StructuredRegion::Empty => Some(Region::Seq(Vec::new())),
        StructuredRegion::Block(block) => Some(Region::Block(block.block)),
        StructuredRegion::Return { block } => Some(Region::Block(*block)),
        StructuredRegion::DuplicatedReturn { source_block, .. } => {
            Some(Region::Block(*source_block))
        }
        StructuredRegion::Sequence(regions) => adapt_sequence(regions),
        StructuredRegion::If {
            source_block,
            then_region,
            else_region,
            ..
        } => adapt_if(*source_block, then_region, else_region.as_deref(), None),
        StructuredRegion::Switch {
            guard,
            dispatch,
            cases,
            default,
        } => {
            let formal_default = if let Some(default) = default {
                Some(Box::new(adapt_region(&default.region)?))
            } else {
                None
            };
            Some(Region::Switch {
                guard: *guard,
                dispatch: *dispatch,
                case_labels: cases.iter().map(|case| case.values.clone()).collect(),
                arms: cases
                    .iter()
                    .map(|case| adapt_region(&case.region))
                    .collect::<Option<Vec<_>>>()?,
                formal_default,
                join: None,
            })
        }
        StructuredRegion::Loop {
            header,
            kind,
            body,
            exits,
        } => adapt_loop(*header, *kind, body, exits, None),
        StructuredRegion::LocalGoto { to, .. } | StructuredRegion::SharedGoto { to, .. } => {
            Some(Region::Goto(*to))
        }
        StructuredRegion::Break { .. } | StructuredRegion::Continue { .. } => None,
    }
}

fn adapt_loop(
    header: usize,
    kind: LoopKind,
    body: &StructuredRegion,
    exits: &[super::LoopExitRegion],
    continuation: Option<usize>,
) -> Option<Region> {
    if !exits.is_empty() {
        let exits = exits
            .iter()
            .map(|exit| Some((exit.target, adapt_region(&exit.region)?)))
            .collect::<Option<Vec<_>>>()?;
        return Some(Region::MultiExitLoop {
            header,
            body: Box::new(adapt_loop_body(body, header)?),
            exits,
            continuation,
        });
    }
    if tree_has_switch(body) {
        let continuation = continuation.or_else(|| unique_loop_break_target(body, header))?;
        let mut saw_break = false;
        if !all_loop_breaks_target(body, header, continuation, &mut saw_break) || !saw_break {
            return None;
        }
        return Some(Region::MultiExitLoop {
            header,
            body: Box::new(adapt_loop_body(body, header)?),
            exits: vec![(continuation, Region::Seq(Vec::new()))],
            continuation: Some(continuation),
        });
    }
    if kind == LoopKind::PreTested {
        let continuation = continuation?;
        let mut saw_break = false;
        if !all_loop_breaks_target(body, header, continuation, &mut saw_break) || !saw_break {
            return None;
        }
        return Some(Region::MultiExitLoop {
            header,
            body: Box::new(adapt_loop_body(body, header)?),
            exits: vec![(continuation, Region::Seq(Vec::new()))],
            continuation: Some(continuation),
        });
    }
    if kind != LoopKind::PostTested {
        return None;
    }
    let mut facts = PostTestedFacts::default();
    collect_post_tested_facts(body, header, &mut facts)?;
    let latch = facts.latch?;
    let exit = facts.exit?;
    if facts.break_targets.iter().any(|target| *target != exit) {
        return None;
    }
    facts.blocks.retain(|block| *block != latch);
    if facts.blocks.is_empty() {
        return None;
    }
    Some(Region::DoWhile {
        body: Box::new(Region::Seq(
            facts.blocks.into_iter().map(Region::Block).collect(),
        )),
        cond: latch,
        exit: Some(exit),
    })
}

fn unique_loop_break_target(region: &StructuredRegion, header: usize) -> Option<usize> {
    let mut target = None;
    fn collect(region: &StructuredRegion, header: usize, target: &mut Option<usize>) -> bool {
        match region {
            StructuredRegion::Sequence(regions) => {
                regions.iter().all(|region| collect(region, header, target))
            }
            StructuredRegion::If {
                then_region,
                else_region,
                ..
            } => {
                collect(then_region, header, target)
                    && else_region
                        .as_deref()
                        .is_none_or(|region| collect(region, header, target))
            }
            StructuredRegion::Switch { cases, default, .. } => {
                cases
                    .iter()
                    .all(|case| collect(&case.region, header, target))
                    && default
                        .as_ref()
                        .is_none_or(|default| collect(&default.region, header, target))
            }
            StructuredRegion::Break {
                header: seen, to, ..
            } if *seen == header => match target {
                Some(expected) => *expected == *to,
                None => {
                    *target = Some(*to);
                    true
                }
            },
            StructuredRegion::Continue { header: seen, .. } => *seen == header,
            StructuredRegion::Loop { .. } | StructuredRegion::Break { .. } => false,
            StructuredRegion::Empty
            | StructuredRegion::Block(_)
            | StructuredRegion::Return { .. }
            | StructuredRegion::DuplicatedReturn { .. }
            | StructuredRegion::LocalGoto { .. }
            | StructuredRegion::SharedGoto { .. } => true,
        }
    }
    collect(region, header, &mut target)
        .then_some(target)
        .flatten()
}

/// Confirm that a single-exit loop's typed breaks all reach the lexical
/// continuation before spelling those transfers as C `break` statements.
fn all_loop_breaks_target(
    region: &StructuredRegion,
    header: usize,
    continuation: usize,
    saw_break: &mut bool,
) -> bool {
    match region {
        StructuredRegion::Empty
        | StructuredRegion::Block(_)
        | StructuredRegion::Return { .. }
        | StructuredRegion::DuplicatedReturn { .. }
        | StructuredRegion::LocalGoto { .. }
        | StructuredRegion::SharedGoto { .. } => true,
        StructuredRegion::Sequence(regions) => regions
            .iter()
            .all(|region| all_loop_breaks_target(region, header, continuation, saw_break)),
        StructuredRegion::If {
            then_region,
            else_region,
            ..
        } => {
            all_loop_breaks_target(then_region, header, continuation, saw_break)
                && else_region.as_deref().is_none_or(|region| {
                    all_loop_breaks_target(region, header, continuation, saw_break)
                })
        }
        StructuredRegion::Switch { cases, default, .. } => {
            cases
                .iter()
                .all(|case| all_loop_breaks_target(&case.region, header, continuation, saw_break))
                && default.as_ref().is_none_or(|default| {
                    all_loop_breaks_target(&default.region, header, continuation, saw_break)
                })
        }
        StructuredRegion::Break {
            header: seen, to, ..
        } => {
            *saw_break = true;
            *seen == header && *to == continuation
        }
        StructuredRegion::Continue { header: seen, .. } => *seen == header,
        StructuredRegion::Loop { .. } => false,
    }
}

fn adapt_loop_body(region: &StructuredRegion, header: usize) -> Option<Region> {
    match region {
        StructuredRegion::Empty => Some(Region::Seq(Vec::new())),
        StructuredRegion::Block(block) => Some(Region::Block(block.block)),
        StructuredRegion::Return { block } => Some(Region::Block(*block)),
        StructuredRegion::DuplicatedReturn { source_block, .. } => {
            Some(Region::Block(*source_block))
        }
        StructuredRegion::Sequence(regions) => adapt_loop_sequence(regions, header),
        StructuredRegion::If {
            source_block,
            then_region,
            else_region,
            ..
        } => adapt_loop_if(
            *source_block,
            then_region,
            else_region.as_deref(),
            None,
            header,
        ),
        StructuredRegion::Switch {
            guard,
            dispatch,
            cases,
            default,
        } => {
            let formal_default = if let Some(default) = default {
                Some(Box::new(adapt_loop_body(&default.region, header)?))
            } else {
                None
            };
            Some(Region::Switch {
                guard: *guard,
                dispatch: *dispatch,
                case_labels: cases.iter().map(|case| case.values.clone()).collect(),
                arms: cases
                    .iter()
                    .map(|case| adapt_loop_body(&case.region, header))
                    .collect::<Option<Vec<_>>>()?,
                formal_default,
                join: None,
            })
        }
        StructuredRegion::Break {
            header: seen, to, ..
        } if *seen == header => Some(Region::Goto(*to)),
        StructuredRegion::Continue { header: seen, .. } if *seen == header => {
            Some(Region::Goto(header))
        }
        StructuredRegion::LocalGoto { to, .. } | StructuredRegion::SharedGoto { to, .. } => {
            Some(Region::Goto(*to))
        }
        StructuredRegion::Loop { .. }
        | StructuredRegion::Break { .. }
        | StructuredRegion::Continue { .. } => None,
    }
}

fn tree_has_switch(region: &StructuredRegion) -> bool {
    match region {
        StructuredRegion::Switch { .. } => true,
        StructuredRegion::Sequence(regions) => regions.iter().any(tree_has_switch),
        StructuredRegion::If {
            then_region,
            else_region,
            ..
        } => tree_has_switch(then_region) || else_region.as_deref().is_some_and(tree_has_switch),
        StructuredRegion::Loop { body, exits, .. } => {
            tree_has_switch(body) || exits.iter().any(|exit| tree_has_switch(&exit.region))
        }
        StructuredRegion::Empty
        | StructuredRegion::Block(_)
        | StructuredRegion::Return { .. }
        | StructuredRegion::DuplicatedReturn { .. }
        | StructuredRegion::Break { .. }
        | StructuredRegion::Continue { .. }
        | StructuredRegion::LocalGoto { .. }
        | StructuredRegion::SharedGoto { .. } => false,
    }
}

fn adapt_loop_sequence(regions: &[StructuredRegion], header: usize) -> Option<Region> {
    let mut adapted = Vec::new();
    let mut index = 0usize;
    while index < regions.len() {
        if matches!(
            (&regions[index], regions.get(index + 1)),
            (
                StructuredRegion::Block(block),
                Some(StructuredRegion::If { source_block, .. })
            ) if block.block == *source_block
        ) {
            index += 1;
        }
        let adapted_region = match &regions[index] {
            StructuredRegion::If {
                source_block,
                then_region,
                else_region,
                ..
            } => adapt_loop_if(
                *source_block,
                then_region,
                else_region.as_deref(),
                regions.get(index + 1).and_then(entry_block),
                header,
            )?,
            region => adapt_loop_body(region, header)?,
        };
        adapted.push(adapted_region);
        index += 1;
    }
    Some(Region::Seq(adapted))
}

fn adapt_loop_if(
    source_block: usize,
    then_region: &StructuredRegion,
    else_region: Option<&StructuredRegion>,
    join: Option<usize>,
    header: usize,
) -> Option<Region> {
    let then_r = Box::new(adapt_loop_body(then_region, header)?);
    match else_region {
        None | Some(StructuredRegion::Empty) => Some(Region::IfThen {
            cond: source_block,
            then_r,
            join,
            invert: false,
        }),
        Some(else_region) => Some(Region::IfThenElse {
            cond: source_block,
            then_r,
            else_r: Box::new(adapt_loop_body(else_region, header)?),
            join,
            invert: false,
        }),
    }
}

#[derive(Default)]
struct PostTestedFacts {
    blocks: Vec<usize>,
    latch: Option<usize>,
    exit: Option<usize>,
    break_targets: Vec<usize>,
}

fn collect_post_tested_facts(
    region: &StructuredRegion,
    header: usize,
    facts: &mut PostTestedFacts,
) -> Option<()> {
    match region {
        StructuredRegion::Empty => Some(()),
        StructuredRegion::Block(block) => {
            facts.blocks.push(block.block);
            Some(())
        }
        StructuredRegion::Sequence(regions) => {
            for region in regions {
                collect_post_tested_facts(region, header, facts)?;
            }
            Some(())
        }
        StructuredRegion::If {
            source_block,
            then_region,
            else_region: Some(else_region),
            ..
        } if latch_exit(then_region, else_region, header).is_some() => {
            let exit = latch_exit(then_region, else_region, header)?;
            if facts.latch.replace(*source_block).is_some() || facts.exit.replace(exit).is_some() {
                return None;
            }
            Some(())
        }
        StructuredRegion::If {
            then_region,
            else_region,
            ..
        } => {
            collect_post_tested_facts(then_region, header, facts)?;
            if let Some(else_region) = else_region {
                collect_post_tested_facts(else_region, header, facts)?;
            }
            Some(())
        }
        StructuredRegion::Break { to, .. } => {
            facts.break_targets.push(*to);
            Some(())
        }
        StructuredRegion::Return { .. }
        | StructuredRegion::DuplicatedReturn { .. }
        | StructuredRegion::Loop { .. }
        | StructuredRegion::Switch { .. }
        | StructuredRegion::Continue { .. }
        | StructuredRegion::LocalGoto { .. }
        | StructuredRegion::SharedGoto { .. } => None,
    }
}

fn latch_exit(
    then_region: &StructuredRegion,
    else_region: &StructuredRegion,
    header: usize,
) -> Option<usize> {
    match (then_region, else_region) {
        (StructuredRegion::Continue { header: seen, .. }, StructuredRegion::Break { to, .. })
        | (StructuredRegion::Break { to, .. }, StructuredRegion::Continue { header: seen, .. })
            if *seen == header =>
        {
            Some(*to)
        }
        _ => None,
    }
}

fn adapt_sequence(regions: &[StructuredRegion]) -> Option<Region> {
    let mut adapted = Vec::new();
    let mut index = 0usize;
    while index < regions.len() {
        if matches!(
            (&regions[index], regions.get(index + 1)),
            (
                StructuredRegion::Block(block),
                Some(StructuredRegion::If { source_block, .. })
            ) if block.block == *source_block
        ) {
            // The shadow algebra keeps the condition-owner leaf separately for
            // exact ownership. v1's `If*` node owns and lowers that same block.
            index += 1;
        }
        let adapted_region = match &regions[index] {
            StructuredRegion::If {
                source_block,
                then_region,
                else_region,
                ..
            } => adapt_if(
                *source_block,
                then_region,
                else_region.as_deref(),
                regions.get(index + 1).and_then(entry_block),
            )?,
            StructuredRegion::Loop {
                header,
                kind,
                body,
                exits,
            } => adapt_loop(
                *header,
                *kind,
                body,
                exits,
                regions.get(index + 1).and_then(entry_block),
            )?,
            region => adapt_region(region)?,
        };
        adapted.push(adapted_region);
        index += 1;
    }
    Some(Region::Seq(adapted))
}

fn adapt_if(
    source_block: usize,
    then_region: &StructuredRegion,
    else_region: Option<&StructuredRegion>,
    join: Option<usize>,
) -> Option<Region> {
    let then_r = Box::new(adapt_region(then_region)?);
    match else_region {
        None | Some(StructuredRegion::Empty) => Some(Region::IfThen {
            cond: source_block,
            then_r,
            join,
            invert: false,
        }),
        Some(else_region) => Some(Region::IfThenElse {
            cond: source_block,
            then_r,
            else_r: Box::new(adapt_region(else_region)?),
            join,
            invert: false,
        }),
    }
}

fn entry_block(region: &StructuredRegion) -> Option<usize> {
    match region {
        StructuredRegion::Empty => None,
        StructuredRegion::Block(block) => Some(block.block),
        StructuredRegion::Return { block } => Some(*block),
        StructuredRegion::DuplicatedReturn { source_block, .. } => Some(*source_block),
        StructuredRegion::Sequence(regions) => regions.iter().find_map(entry_block),
        StructuredRegion::If { source_block, .. } => Some(*source_block),
        StructuredRegion::Loop { header, .. } => Some(*header),
        StructuredRegion::Switch {
            guard, dispatch, ..
        } => Some(guard.unwrap_or(*dispatch)),
        StructuredRegion::Break { to, .. }
        | StructuredRegion::LocalGoto { to, .. }
        | StructuredRegion::SharedGoto { to, .. } => Some(*to),
        StructuredRegion::Continue { header, .. } => Some(*header),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::structure_v2::BlockRegion;

    #[test]
    fn adapter_consumes_the_separate_condition_owner_leaf_once() {
        let tree = StructuredRegion::Sequence(vec![
            StructuredRegion::Block(BlockRegion {
                block: 0,
                transfers: Vec::new(),
                terminal: None,
            }),
            StructuredRegion::If {
                source_block: 0,
                condition: crate::ir::structure_v2::ConditionId(2),
                then_region: Box::new(StructuredRegion::Return { block: 1 }),
                else_region: Some(Box::new(StructuredRegion::Return { block: 2 })),
            },
        ]);

        assert_eq!(
            adapt_region(&tree),
            Some(Region::Seq(vec![Region::IfThenElse {
                cond: 0,
                then_r: Box::new(Region::Block(1)),
                else_r: Box::new(Region::Block(2)),
                join: None,
                invert: false,
            }]))
        );
    }

    #[test]
    fn pretested_loop_adapter_requires_every_break_to_reach_the_continuation() {
        let body = StructuredRegion::Sequence(vec![
            StructuredRegion::Break {
                from: 0,
                header: 0,
                to: 2,
                taken: Some(false),
            },
            StructuredRegion::Break {
                from: 1,
                header: 0,
                to: 3,
                taken: Some(true),
            },
        ]);

        assert_eq!(
            adapt_loop(0, LoopKind::PreTested, &body, &[], Some(2)),
            None
        );
    }

    #[test]
    fn pretested_loop_adapter_retains_a_verified_single_exit() {
        let body = StructuredRegion::Sequence(vec![
            StructuredRegion::Break {
                from: 0,
                header: 0,
                to: 2,
                taken: Some(false),
            },
            StructuredRegion::Continue {
                from: 1,
                header: 0,
                taken: None,
            },
        ]);

        assert_eq!(
            adapt_loop(0, LoopKind::PreTested, &body, &[], Some(2)),
            Some(Region::MultiExitLoop {
                header: 0,
                body: Box::new(Region::Seq(vec![Region::Goto(2), Region::Goto(0)])),
                exits: vec![(2, Region::Seq(Vec::new()))],
                continuation: Some(2),
            })
        );
    }
}
