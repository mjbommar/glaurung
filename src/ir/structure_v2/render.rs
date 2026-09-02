//! Conservative shadow-tree adapter into the existing AST and printer.

use super::{StructuredRegion, StructuredTree};
use crate::ir::structure::Region;
use crate::ir::types::LlirFunction;

/// Render a verified tree through the production AST lowerer when every shape
/// has a faithful v1-region spelling.
pub(super) fn render_raw_pseudocode(lf: &LlirFunction, tree: &StructuredTree) -> Option<String> {
    if !tree.local_regions.is_empty() {
        return None;
    }
    let region = adapt_region(&tree.root)?;
    let function = crate::ir::ast::lower(lf, &region, format!("sub_{:x}", lf.entry_va));
    Some(crate::ir::ast::render_c(&function))
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
        StructuredRegion::SharedGoto { to, .. } => Some(Region::Goto(*to)),
        StructuredRegion::Loop { .. }
        | StructuredRegion::Break { .. }
        | StructuredRegion::Continue { .. }
        | StructuredRegion::LocalGoto { .. } => None,
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
}
