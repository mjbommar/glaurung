//! Conservative shadow-tree adapter into the existing AST and printer.

use super::{LocalLabelRegion, LoopKind, StructuredRegion, StructuredTree};
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
    let mut root = adapt_region(&tree.root)?;
    let mut embedded = std::collections::BTreeSet::new();
    embed_switch_local_regions(&mut root, &tree.local_regions, &mut embedded)?;
    let mut regions = vec![root];
    for local in &tree.local_regions {
        if embedded.contains(&local.region) {
            continue;
        }
        regions.push(Region::Unstructured(
            local.blocks.iter().map(|block| block.block).collect(),
        ));
        for exit in &local.exits {
            regions.push(adapt_region(&exit.region)?);
        }
    }
    Some(Region::Seq(regions))
}

/// Place a verified multi-entry local region inside a switch when at least two
/// distinct arms enter it. This is the region relationship required by Duff's
/// device: case labels belong inside the loop body, even though the loop is
/// irreducible when viewed without the dispatch. The region remains owned
/// exactly once; only its lexical placement changes.
fn embed_switch_local_regions(
    region: &mut Region,
    locals: &[LocalLabelRegion],
    embedded: &mut std::collections::BTreeSet<usize>,
) -> Option<()> {
    match region {
        Region::Seq(parts) => {
            for part in parts {
                embed_switch_local_regions(part, locals, embedded)?;
            }
        }
        Region::IfThen { then_r, .. } => {
            embed_switch_local_regions(then_r, locals, embedded)?;
        }
        Region::IfThenElse { then_r, else_r, .. } => {
            embed_switch_local_regions(then_r, locals, embedded)?;
            embed_switch_local_regions(else_r, locals, embedded)?;
        }
        Region::While { body, .. } | Region::DoWhile { body, .. } => {
            embed_switch_local_regions(body, locals, embedded)?;
        }
        Region::MultiExitLoop { body, exits, .. } => {
            embed_switch_local_regions(body, locals, embedded)?;
            for (_, exit) in exits {
                embed_switch_local_regions(exit, locals, embedded)?;
            }
        }
        Region::Switch {
            arms,
            formal_default,
            ..
        } => {
            for arm in arms.iter_mut() {
                embed_switch_local_regions(arm, locals, embedded)?;
            }
            if let Some(default) = formal_default {
                embed_switch_local_regions(default, locals, embedded)?;
            }

            let candidates: Vec<_> = locals
                .iter()
                .filter(|local| !embedded.contains(&local.region))
                .filter_map(|local| {
                    let blocks: std::collections::BTreeSet<_> =
                        local.blocks.iter().map(|block| block.block).collect();
                    let entering_arms: Vec<_> = arms
                        .iter()
                        .enumerate()
                        .filter_map(|(index, arm)| {
                            region_goto_targets(arm)
                                .iter()
                                .any(|target| blocks.contains(target))
                                .then_some(index)
                        })
                        .collect();
                    (entering_arms.len() >= 2).then_some((local, entering_arms[0]))
                })
                .collect();
            if let [(local, owner)] = candidates.as_slice() {
                let local_blocks: std::collections::BTreeSet<_> =
                    local.blocks.iter().map(|block| block.block).collect();
                let entry = region_goto_targets(&arms[*owner])
                    .into_iter()
                    .find(|target| local_blocks.contains(target))?;
                let mut ordered_blocks: Vec<_> =
                    local.blocks.iter().map(|block| block.block).collect();
                let entry_position = ordered_blocks.iter().position(|block| *block == entry)?;
                // The SCC inventory is block-id ordered, not execution ordered.
                // Start its lexical spelling at the owning case's real entry.
                // Any displaced internal fallthrough becomes an explicit goto
                // in `Region::Unstructured`, so rotating cannot hide an edge.
                ordered_blocks.rotate_left(entry_position);
                let mut body = vec![std::mem::replace(
                    &mut arms[*owner],
                    Region::Seq(Vec::new()),
                )];
                body.push(Region::Unstructured(ordered_blocks));
                for exit in &local.exits {
                    body.push(adapt_region(&exit.region)?);
                }
                arms[*owner] = Region::Seq(body);
                embedded.insert(local.region);
            }
        }
        Region::Block(_) | Region::RawLoop { .. } | Region::Goto(_) | Region::Unstructured(_) => {}
    }
    Some(())
}

fn region_goto_targets(region: &Region) -> Vec<usize> {
    match region {
        Region::Goto(target) => vec![*target],
        Region::Seq(parts) => parts.iter().flat_map(region_goto_targets).collect(),
        Region::IfThen { then_r, .. } => region_goto_targets(then_r),
        Region::IfThenElse { then_r, else_r, .. } => {
            let mut targets = region_goto_targets(then_r);
            targets.extend(region_goto_targets(else_r));
            targets
        }
        Region::While { body, .. } | Region::DoWhile { body, .. } => region_goto_targets(body),
        Region::MultiExitLoop { body, exits, .. } => {
            let mut targets = region_goto_targets(body);
            targets.extend(exits.iter().flat_map(|(_, exit)| region_goto_targets(exit)));
            targets
        }
        Region::Switch {
            arms,
            formal_default,
            ..
        } => {
            let mut targets: Vec<_> = arms.iter().flat_map(region_goto_targets).collect();
            if let Some(default) = formal_default {
                targets.extend(region_goto_targets(default));
            }
            targets
        }
        Region::Block(_) | Region::RawLoop { .. } | Region::Unstructured(_) => Vec::new(),
    }
}

fn adapt_region(region: &StructuredRegion) -> Option<Region> {
    match region {
        StructuredRegion::Empty => Some(Region::Seq(Vec::new())),
        StructuredRegion::Block(block) => Some(Region::Block(block.block)),
        StructuredRegion::Return { block } => Some(Region::Block(*block)),
        StructuredRegion::DuplicatedReturn { blocks, .. } => Some(Region::Seq(
            blocks.iter().copied().map(Region::Block).collect(),
        )),
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
        StructuredRegion::DuplicatedReturn { blocks, .. } => Some(Region::Seq(
            blocks.iter().copied().map(Region::Block).collect(),
        )),
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
        if control_node_consumes_owner_leaf(&regions[index], regions.get(index + 1)) {
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
        if control_node_consumes_owner_leaf(&regions[index], regions.get(index + 1)) {
            // The shadow algebra keeps a control-owner leaf separately for
            // exact ownership. v1's `If*` and guarded `Switch` nodes own and
            // lower that same block, so adapting both would execute it twice.
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

fn control_node_consumes_owner_leaf(
    region: &StructuredRegion,
    next: Option<&StructuredRegion>,
) -> bool {
    matches!(
        (region, next),
        (
            StructuredRegion::Block(block),
            Some(StructuredRegion::If { source_block, .. })
        ) if block.block == *source_block
    ) || matches!(
        (region, next),
        (
            StructuredRegion::Block(block),
            Some(StructuredRegion::Switch {
                guard: Some(guard),
                ..
            })
        ) if block.block == *guard
    )
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
    fn adapter_consumes_the_separate_switch_guard_leaf_once() {
        let tree = StructuredRegion::Sequence(vec![
            StructuredRegion::Block(BlockRegion {
                block: 0,
                transfers: Vec::new(),
                terminal: None,
            }),
            StructuredRegion::Switch {
                guard: Some(0),
                dispatch: 1,
                cases: vec![crate::ir::structure_v2::SwitchCaseRegion {
                    target: 2,
                    values: vec![0],
                    region: Box::new(StructuredRegion::Return { block: 2 }),
                }],
                default: None,
            },
        ]);

        assert_eq!(
            adapt_region(&tree),
            Some(Region::Seq(vec![Region::Switch {
                guard: Some(0),
                dispatch: 1,
                case_labels: vec![vec![0]],
                arms: vec![Region::Block(2)],
                formal_default: None,
                join: None,
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
