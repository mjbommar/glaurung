//! The region walk: loop and dispatch shapes, label repair, and the front door.
//!
//! [`lower`] is the entry point for the whole LLIR -> AST pipeline and the only
//! item here the rest of the crate names. It runs [`lower_on_this_stack`] on a
//! thread with [`LOWERING_STACK_BYTES`] of stack, because `lower_region` and
//! [`lower_region_inner`] recurse in lockstep over the recovered region tree
//! with no depth budget.
//!
//! `lower_region_inner` is the large `match` that turns each [`Region`] variant
//! into C control flow, delegating per-block work to
//! [`super::lower_conds::lower_block`] and per-op work to
//! [`super::lower_ops`]. The raw-shape helpers (`lower_raw_loop_block`,
//! `raw_dispatch_default_target`) handle the cases CFG recovery could not
//! structure, and `collect_goto_targets`/`deduplicate_labels` repair the labels
//! that survive.

use super::float_gate::scalar_float_semantics_are_closed;
use super::fold_returns;
use super::lower_conds::{
    exit_is_taken_branch, extract_cond_and_strip, hoisting_the_header_is_safe, lower_block,
    negate_cmp_expr, strip_back_edge,
};
use super::lower_ops::{lower_value, switch_index_of};
use super::{Expr, Function, Stmt};
use crate::ir::structure::Region;
use crate::ir::types::{LlirFunction, Op, VReg};

/// Drop a trailing `goto <target_va>` from a lowered arm — control already
/// falls through to that block, so the jump is redundant (and, if it targets a
/// join emitted after the `if`, actively harmful: it skips the join's body).
fn strip_trailing_goto(stmts: &mut Vec<Stmt>, target_va: u64) {
    if matches!(stmts.last(), Some(Stmt::Goto { target }) if *target == target_va) {
        stmts.pop();
    }
}

/// Spell a direct edge from the current loop body to its distinguished exit as
/// `break`. Recurse through conditionals only: inside a nested loop or switch,
/// a C `break` would target that inner construct rather than this loop.
fn recover_direct_loop_breaks(stmts: &mut [Stmt], exit_va: u64) {
    for statement in stmts {
        match statement {
            Stmt::Goto { target } if *target == exit_va => *statement = Stmt::Break,
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                recover_direct_loop_breaks(then_body, exit_va);
                if let Some(else_body) = else_body {
                    recover_direct_loop_breaks(else_body, exit_va);
                }
            }
            _ => {}
        }
    }
}

/// The successor reached by source-order fallthrough rather than an explicit
/// transfer in `block`'s final instruction.
fn implicit_successor(block: &crate::ir::types::LlirBlock) -> Option<u64> {
    match block.instrs.last().map(|instruction| &instruction.op) {
        Some(Op::CondJump { target, .. }) => block
            .succs
            .iter()
            .copied()
            .find(|successor| successor != target),
        Some(Op::Jump { .. } | Op::IndirectJump { .. }) => None,
        Some(op) if op.is_unconditional_return() => None,
        _ if block.succs.len() == 1 => block.succs.first().copied(),
        _ => None,
    }
}

/// Lower one block owned by [`Region::RawLoop`], preserving a resolved table
/// dispatch as an explicit low-level switch.
///
/// A raw loop deliberately keeps labelled CFG rather than claiming that its
/// cases form source-level structured arms. The indirect machine transfer must
/// still become valid C, though: `goto *expr` is not portable C and the normal
/// renderer cannot recompile it safely. A typed `IndirectJump` with a proven
/// index and ordered CFG successors is exactly a positional switch whose case
/// bodies jump to the original block labels.
fn lower_raw_loop_block(
    block: &crate::ir::types::LlirBlock,
    default_target: Option<u64>,
    lower_scalar_float: bool,
) -> Vec<Stmt> {
    let explicit_index = block
        .instrs
        .iter()
        .rev()
        .find_map(|instruction| match &instruction.op {
            Op::IndirectJump {
                index: Some(index), ..
            } => Some(lower_value(index)),
            _ => None,
        });
    let mut statements = lower_block(block, lower_scalar_float);
    let Some(discriminant) = explicit_index else {
        return statements;
    };
    if block.succs.len() < 2 {
        return statements;
    }
    let Some(indirect_position) = statements
        .iter()
        .rposition(|statement| matches!(statement, Stmt::IndirectGoto { .. }))
    else {
        return statements;
    };
    statements.remove(indirect_position);
    let cases = block
        .succs
        .iter()
        .enumerate()
        .filter(|(_, target)| default_target != Some(**target))
        .map(|(case, target)| (Some(case as i64), vec![Stmt::Goto { target: *target }]))
        .collect();
    statements.push(Stmt::Switch {
        discriminant,
        cases,
        default: default_target.map(|target| vec![Stmt::Goto { target }]),
    });
    statements
}

/// Recover the bounds guard's out-of-range edge for one raw table dispatch.
///
/// The dispatch target list is positional and may contain the guard's default
/// target in many unused slots. A conditional predecessor with exactly two
/// successors proves which edge bypasses the table. Conflicting predecessors
/// fail closed instead of guessing a C `default` arm.
fn raw_dispatch_default_target(
    lf: &LlirFunction,
    raw_blocks: &[usize],
    dispatch: usize,
) -> Option<u64> {
    let dispatch_va = lf.blocks[dispatch].start_va;
    let mut candidates = raw_blocks.iter().copied().filter_map(|block_index| {
        let block = &lf.blocks[block_index];
        if block.succs.len() != 2
            || !block.succs.contains(&dispatch_va)
            || !matches!(
                block.instrs.last().map(|instruction| &instruction.op),
                Some(Op::CondJump { .. })
            )
        {
            return None;
        }
        block
            .succs
            .iter()
            .copied()
            .find(|successor| *successor != dispatch_va)
    });
    let candidate = candidates.next()?;
    if candidates.all(|other| other == candidate) && lf.blocks[dispatch].succs.contains(&candidate)
    {
        Some(candidate)
    } else {
        None
    }
}

fn lower_region(
    r: &Region,
    lf: &LlirFunction,
    targets: &std::collections::HashSet<u64>,
    lower_scalar_float: bool,
) -> Vec<Stmt> {
    let mut out = lower_region_inner(r, lf, targets, lower_scalar_float);
    // A region that *emits* a goto-target block (any shape — a plain block or a
    // structured `if`/`while` that begins at the target) gets a label at the
    // start of its statements so the jump resolves. The block's statements render
    // exactly once, here. A `Region::Goto` is a *reference*, not an emission —
    // labelling it would produce `L: goto L;` self-loops and duplicate labels.
    if !matches!(r, Region::Goto(_)) {
        if let Some(e) = crate::ir::structure::entry_block(r) {
            let va = lf.blocks[e].start_va;
            if targets.contains(&va) && !matches!(out.first(), Some(Stmt::Label(l)) if *l == va) {
                out.insert(0, Stmt::Label(va));
            }
        }
    }
    out
}

fn lower_region_inner(
    r: &Region,
    lf: &LlirFunction,
    targets: &std::collections::HashSet<u64>,
    lower_scalar_float: bool,
) -> Vec<Stmt> {
    match r {
        Region::Block(bi) => lower_block(&lf.blocks[*bi], lower_scalar_float),
        Region::Goto(bi) => vec![Stmt::Goto {
            target: lf.blocks[*bi].start_va,
        }],
        Region::Seq(parts) => {
            // `out` adopts the first non-empty part's vector rather than copying
            // into a fresh one. A `Stmt` is 320 bytes, so `Vec::new()` + `extend`
            // paid a full re-copy of the largest part plus the doubling reallocs
            // that got the accumulator up to its size. Extending an EMPTY vector
            // and assigning it are the same value, so this is the same statement
            // list either way.
            let mut out: Vec<Stmt> = Vec::new();
            for (idx, p) in parts.iter().enumerate() {
                let mut lowered = lower_region(p, lf, targets, lower_scalar_float);
                // A sequence emits its next region immediately after this one,
                // so an unconditional jump to that region is ordinary
                // fallthrough and must disappear. This includes entry jumps to
                // a recovered loop and zero-distance bridge blocks between a
                // nested-loop exit and its outer latch. Keeping the latter goto
                // makes the following latch statements unreachable.
                let next_entry = parts
                    .get(idx + 1)
                    .and_then(crate::ir::structure::entry_block);
                if let Some(entry) = next_entry {
                    let next_va = lf.blocks[entry].start_va;
                    if matches!(lowered.last(), Some(Stmt::Goto { target }) if *target == next_va) {
                        lowered.pop();
                    }
                }
                if out.is_empty() {
                    out = lowered;
                } else {
                    out.extend(lowered);
                }
            }
            out
        }
        Region::IfThen {
            cond,
            then_r,
            join,
            invert,
        } => {
            let cond_stmts = lower_block(&lf.blocks[*cond], lower_scalar_float);
            let (cond_expr, mut pre) = extract_cond_and_strip(&lf.blocks[*cond], cond_stmts);
            // The raw condition is true when the branch is taken; if `then_r` is
            // the fall-through arm the structurer flagged `invert`, so negate.
            let cond_expr = if *invert {
                negate_cmp_expr(cond_expr)
            } else {
                cond_expr
            };
            let mut then_stmts = lower_region(then_r, lf, targets, lower_scalar_float);
            // The arm's trailing `goto <join>` is redundant — control falls
            // through to the join right after the `if`. Leaving it makes the arm
            // jump *past* the join's body (e.g. the epilogue's `return`) to a
            // dangling label, dropping the return value.
            if let Some(j) = join {
                strip_trailing_goto(&mut then_stmts, lf.blocks[*j].start_va);
            }
            pre.push(Stmt::If {
                cond: cond_expr,
                then_body: then_stmts,
                else_body: None,
            });
            pre
        }
        Region::IfThenElse {
            cond,
            then_r,
            else_r,
            join,
            invert,
        } => {
            let cond_stmts = lower_block(&lf.blocks[*cond], lower_scalar_float);
            let (cond_expr, mut pre) = extract_cond_and_strip(&lf.blocks[*cond], cond_stmts);
            let cond_expr = if *invert {
                negate_cmp_expr(cond_expr)
            } else {
                cond_expr
            };
            let mut then_stmts = lower_region(then_r, lf, targets, lower_scalar_float);
            let mut else_stmts = lower_region(else_r, lf, targets, lower_scalar_float);
            if let Some(j) = join {
                let jva = lf.blocks[*j].start_va;
                strip_trailing_goto(&mut then_stmts, jva);
                strip_trailing_goto(&mut else_stmts, jva);
            }
            pre.push(Stmt::If {
                cond: cond_expr,
                then_body: then_stmts,
                else_body: Some(else_stmts),
            });
            pre
        }
        Region::While { header, body, exit } => {
            let cond_stmts = lower_block(&lf.blocks[*header], lower_scalar_float);
            let (cond_expr, pre) = extract_cond_and_strip(&lf.blocks[*header], cond_stmts);
            // `cond_expr` is the branch-TAKEN condition. Whether that is the
            // loop's CONTINUE condition depends on where the taken edge goes, and
            // the two mainstream layouts disagree:
            //
            //   gcc -O0   test at the BOTTOM, taken edge re-enters the body
            //             -> the condition already is the continue test
            //   clang -O0 test at the TOP, taken edge LEAVES the loop (a rotated
            //   gcc -O2   loop) -> the condition is the EXIT test
            //
            // Emitting it verbatim in the second case states the opposite of the
            // source: `while (n > 1)` came out as `while (n <= 1)`.
            let continue_cond = if exit_is_taken_branch(lf, *header, *exit) {
                negate_cmp_expr(cond_expr)
            } else {
                cond_expr
            };
            let cond_expr = continue_cond;
            let mut body_stmts = lower_region(body, lf, targets, lower_scalar_float);
            if let Some(exit) = exit {
                recover_direct_loop_breaks(&mut body_stmts, lf.blocks[*exit].start_va);
            }
            // The back-edge is what `while` MEANS. Left as an explicit `goto` to
            // the header it jumps OUT of the loop body to a label the renderer
            // pins wherever that block was emitted — after the `return`, in a
            // rotated loop — so the body cannot repeat.
            strip_back_edge(&mut body_stmts, lf.blocks[*header].start_va);
            if body_stmts.is_empty() && !pre.is_empty() {
                // Do-while: the whole loop body sits in the self-looping header,
                // so the `While` body is empty and `pre` is the body itself. The
                // condition is *post*-tested. Emitting `pre; while (cond) {}` (the
                // previous behaviour) is a semantic bug — the body runs once and
                // the loop becomes an empty infinite/stale test. Lower to
                //     while (1) { body; if (!cond) break; }
                // so the body runs each iteration and the post-test exits.
                let mut loop_body = pre;
                loop_body.push(Stmt::If {
                    cond: negate_cmp_expr(cond_expr),
                    then_body: vec![Stmt::Break],
                    else_body: None,
                });
                vec![Stmt::While {
                    cond: Expr::Const(1),
                    body: loop_body,
                }]
            } else if pre.is_empty() {
                vec![Stmt::While {
                    cond: cond_expr,
                    body: body_stmts,
                }]
            } else if hoisting_the_header_is_safe(&pre, &body_stmts) {
                // The header's leftover work is a plain copy chain — no memory read,
                // no register updating itself — so `copy_prop` folds it into the
                // condition downstream and hoisting it once is equivalent.
                let mut out = pre;
                out.push(Stmt::While {
                    cond: cond_expr,
                    body: body_stmts,
                });
                out
            } else {
                // The header does PER-ITERATION work that cannot be folded into the
                // condition, so hoisting it leaves the condition reading a value
                // nothing updates — an infinite loop. `while ((c = *s++))` is the
                // shape: gcc -O0 puts the pointer bump, the load and the test all in
                // the header because all three run every iteration.
                //
                //     var0 = p; p = p + 1;          <- hoisted
                //     c = *(char *)var0;            <- hoisted
                //     while ((c != 0)) { h = ...; } <- c never changes
                //
                // `strops::hash_djb2` and `str_len` both spun until the time budget
                // on inputs the original returned on. Keep the work where it runs:
                //     while (1) { <header work>; if (!cond) break; <body> }
                let mut loop_body = pre;
                loop_body.push(Stmt::If {
                    cond: negate_cmp_expr(cond_expr),
                    then_body: vec![Stmt::Break],
                    else_body: None,
                });
                loop_body.extend(body_stmts);
                vec![Stmt::While {
                    cond: Expr::Const(1),
                    body: loop_body,
                }]
            }
        }
        Region::DoWhile { body, cond, exit } => {
            let mut body_stmts = lower_region(body, lf, targets, lower_scalar_float);
            let cond_stmts = lower_block(&lf.blocks[*cond], lower_scalar_float);
            let (cond_expr, mut latch_stmts) =
                extract_cond_and_strip(&lf.blocks[*cond], cond_stmts);
            // A shared arm can explicitly jump to the bottom test (source-level
            // `continue`). The condition block is otherwise absorbed into the
            // DoWhile node and never emitted as a region of its own, so retain
            // its label at the precise in-loop point where its non-branch
            // statements execute. Without this, label repair can only append an
            // empty target after the function return and the jump skips the
            // latch and result path entirely.
            let latch_va = lf.blocks[*cond].start_va;
            if targets.contains(&latch_va) {
                body_stmts.push(Stmt::Label(latch_va));
            }
            body_stmts.append(&mut latch_stmts);
            let continue_cond = if exit_is_taken_branch(lf, *cond, *exit) {
                negate_cmp_expr(cond_expr)
            } else {
                cond_expr
            };
            vec![Stmt::DoWhile {
                body: body_stmts,
                cond: continue_cond,
            }]
        }
        Region::RawLoop {
            header,
            blocks,
            exits: _,
        } => {
            let header_va = lf.blocks[*header].start_va;
            let mut loop_body = Vec::new();
            for (position, block_index) in blocks.iter().copied().enumerate() {
                let block = &lf.blocks[block_index];
                let default_target = raw_dispatch_default_target(lf, blocks, block_index);
                loop_body.push(Stmt::Label(block.start_va));
                loop_body.extend(lower_raw_loop_block(
                    block,
                    default_target,
                    lower_scalar_float,
                ));

                // Raw blocks normally rely on source order for fallthrough. The
                // loop owns a non-contiguous subset and starts at its header, so
                // make every displaced fallthrough explicit. Falling off the
                // final block naturally starts the next `while (1)` iteration.
                let lexical_next = blocks
                    .get(position + 1)
                    .map(|next| lf.blocks[*next].start_va)
                    .unwrap_or(header_va);
                if let Some(successor) = implicit_successor(block) {
                    if successor != lexical_next {
                        loop_body.push(Stmt::Goto { target: successor });
                    }
                }
            }
            vec![Stmt::While {
                cond: Expr::Const(1),
                body: loop_body,
            }]
        }
        Region::Switch {
            guard,
            dispatch,
            case_labels,
            arms,
            formal_default,
            join,
        } => {
            // Lower the dispatch block as the prefix; the last
            // instruction is the indirect jump itself which we replace
            // with the structured `switch` statement. v0 emits each
            // arm with its case index (positional) and an implicit
            // break at the end.
            let mut prefix = guard
                .map(|guard| lower_block(&lf.blocks[guard], lower_scalar_float))
                .unwrap_or_default();
            // The range branch is now represented by the switch's formal
            // default. Keep normalization/dataflow statements from the guard,
            // but remove its compiler-level conditional transfer.
            while matches!(
                prefix.last(),
                Some(Stmt::Goto { .. }) | Some(Stmt::If { .. })
            ) {
                prefix.pop();
            }
            prefix.extend(lower_block(&lf.blocks[*dispatch], lower_scalar_float));
            let explicit_index = lf.blocks[*dispatch]
                .instrs
                .iter()
                .rev()
                .find_map(|instruction| match &instruction.op {
                    Op::IndirectJump {
                        index: Some(index), ..
                    } => Some(lower_value(index)),
                    _ => None,
                });
            // The switch statement IS the dispatch, so its terminator must not
            // also appear inside it. `IndirectGoto` belongs in this list for the
            // same reason `Goto` does; while the indirect jump lifted to a call
            // it was neither, so the dispatch survived as a phantom call
            // statement *within* the recovered switch.
            let mut discriminant = None;
            if let Some(position) = prefix
                .iter()
                .rposition(|stmt| matches!(stmt, Stmt::IndirectGoto { .. }))
            {
                if let Stmt::IndirectGoto { target } = &prefix[position] {
                    discriminant = switch_index_of(target);
                }
                prefix.remove(position);
            }
            while matches!(
                prefix.last(),
                Some(Stmt::Goto { .. }) | Some(Stmt::If { .. }) | Some(Stmt::IndirectGoto { .. })
            ) {
                if let Some(Stmt::IndirectGoto { target }) = prefix.last() {
                    discriminant = switch_index_of(target);
                }
                let _ = &discriminant;
                prefix.pop();
            }
            let mut cases: Vec<(Option<i64>, Vec<Stmt>)> = Vec::new();
            for (arm_index, arm) in arms.iter().enumerate() {
                let mut body = lower_region(arm, lf, targets, lower_scalar_float);
                if let Some(join) = join {
                    // The renderer supplies the case `break`; a jump to the
                    // block emitted immediately after this switch is plain
                    // structured fallthrough, not a C goto.
                    strip_trailing_goto(&mut body, lf.blocks[*join].start_va);
                }
                let labels = case_labels
                    .get(arm_index)
                    .filter(|labels| !labels.is_empty())
                    .cloned()
                    .unwrap_or_else(|| vec![arm_index as i64]);
                for label in labels {
                    cases.push((Some(label), body.clone()));
                }
            }
            let default = formal_default.as_deref().map(|region| {
                let mut body = lower_region(region, lf, targets, lower_scalar_float);
                if let Some(join) = join {
                    strip_trailing_goto(&mut body, lf.blocks[*join].start_va);
                }
                body
            });
            // The switched value, recovered from the dispatch's own target
            // expression: the table read indexes by exactly the value the
            // source switched on. The placeholder this replaces
            // (`dispatch_<va>`) named nothing and rendered as an undeclared
            // variable, so the recovered switch read as `switch (var6)` with
            // `var6` defined nowhere. Falls back to the placeholder when the
            // index is not recognisable, rather than inventing one.
            let discriminant = explicit_index.or(discriminant).or_else(|| {
                prefix.iter().rev().find_map(|st| match st {
                    Stmt::Assign { src, .. } => switch_index_of(src),
                    _ => None,
                })
            });
            prefix.push(Stmt::Switch {
                discriminant: discriminant.unwrap_or_else(|| {
                    Expr::Reg(VReg::Phys(format!(
                        "dispatch_{:x}",
                        lf.blocks[*dispatch].start_va
                    )))
                }),
                cases,
                default,
            });
            prefix
        }
        Region::Unstructured(blocks) => {
            let mut out = Vec::new();
            for (position, &bi) in blocks.iter().enumerate() {
                out.push(Stmt::Label(lf.blocks[bi].start_va));
                let block = &lf.blocks[bi];
                out.extend(lower_block(block, lower_scalar_float));
                // A partial labelled-CFG fallback need not own every block
                // between two addresses. Preserve a displaced machine
                // fallthrough explicitly instead of relying on vector order.
                let lexical_next = blocks
                    .get(position + 1)
                    .map(|next| lf.blocks[*next].start_va);
                if let Some(successor) = implicit_successor(block) {
                    if Some(successor) != lexical_next {
                        out.push(Stmt::Goto { target: successor });
                    }
                }
            }
            out
        }
    }
}

/// Collect the VAs of blocks referenced by a [`Region::Goto`] anywhere in the
/// tree — these blocks must render a leading `Stmt::Label` so the jumps resolve.
fn collect_goto_targets(r: &Region, lf: &LlirFunction, out: &mut std::collections::HashSet<u64>) {
    match r {
        Region::Goto(bi) => {
            out.insert(lf.blocks[*bi].start_va);
        }
        Region::Seq(parts) => parts.iter().for_each(|p| collect_goto_targets(p, lf, out)),
        Region::IfThen { then_r, .. } => collect_goto_targets(then_r, lf, out),
        Region::IfThenElse { then_r, else_r, .. } => {
            collect_goto_targets(then_r, lf, out);
            collect_goto_targets(else_r, lf, out);
        }
        Region::While { body, .. } | Region::DoWhile { body, .. } => {
            collect_goto_targets(body, lf, out)
        }
        Region::RawLoop { exits, .. } => {
            out.extend(exits.iter().map(|exit| lf.blocks[*exit].start_va));
        }
        Region::Switch {
            arms,
            formal_default,
            ..
        } => {
            arms.iter().for_each(|a| collect_goto_targets(a, lf, out));
            if let Some(default) = formal_default {
                collect_goto_targets(default, lf, out);
            }
        }
        Region::Block(_) | Region::Unstructured(_) => {}
    }
}

/// Keep exactly one C label for each CFG block, preferring the least-nested
/// emission when the region tree references a shared block from more than one
/// structured path.
///
/// Region joins are references as well as ownership boundaries, so lowering a
/// switch arm and the function tail can clone the same epilogue block. That is
/// harmless while it is plain statements, but once a surviving goto requires a
/// label both clones would spell the same `L_x:` and the C translation unit no
/// longer compiles. The shallowest copy is the natural shared destination.
pub(super) fn deduplicate_labels(body: &mut Vec<Stmt>) {
    fn collect_min_depth(
        body: &[Stmt],
        depth: usize,
        minimum: &mut std::collections::HashMap<u64, usize>,
    ) {
        for stmt in body {
            match stmt {
                Stmt::Label(va) => {
                    minimum
                        .entry(*va)
                        .and_modify(|old| *old = (*old).min(depth))
                        .or_insert(depth);
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    collect_min_depth(then_body, depth + 1, minimum);
                    if let Some(else_body) = else_body {
                        collect_min_depth(else_body, depth + 1, minimum);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                    collect_min_depth(body, depth + 1, minimum)
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        collect_min_depth(case_body, depth + 1, minimum);
                    }
                    if let Some(default_body) = default {
                        collect_min_depth(default_body, depth + 1, minimum);
                    }
                }
                _ => {}
            }
        }
    }

    fn retain_at_min_depth(
        body: &mut Vec<Stmt>,
        depth: usize,
        minimum: &std::collections::HashMap<u64, usize>,
        kept: &mut std::collections::HashSet<u64>,
    ) {
        body.retain_mut(|stmt| match stmt {
            Stmt::Label(va) => minimum.get(va) == Some(&depth) && kept.insert(*va),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                retain_at_min_depth(then_body, depth + 1, minimum, kept);
                if let Some(else_body) = else_body {
                    retain_at_min_depth(else_body, depth + 1, minimum, kept);
                }
                true
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                retain_at_min_depth(body, depth + 1, minimum, kept);
                true
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    retain_at_min_depth(case_body, depth + 1, minimum, kept);
                }
                if let Some(default_body) = default {
                    retain_at_min_depth(default_body, depth + 1, minimum, kept);
                }
                true
            }
            _ => true,
        });
    }

    let mut minimum = std::collections::HashMap::new();
    collect_min_depth(body, 0, &mut minimum);
    retain_at_min_depth(body, 0, &minimum, &mut std::collections::HashSet::new());
}

/// Stack reserved for one function's lowering.
///
/// `lower_region` and `lower_region_inner` recurse in lockstep over the region
/// tree, and `lower_region_inner` is one large `match` whose frame holds the
/// union of every arm's locals — measured at roughly 18 KB per level. A 256
/// case switch built for aarch64 at `-O0` by gcc 15 does not become a jump
/// table; the structurer recovers a comparison ladder 442 levels deep, which is
/// about 8 MB and therefore exactly the default thread stack. It did not fail
/// gracefully: the process took SIGSEGV in a function prologue, so there was no
/// panic message, no stdout, and no stderr, and `tools/arch_roundtrip.py` could
/// only report `gate-crashed: ` with an empty reason.
///
/// This reserves address space, not memory; untouched pages are never
/// committed. At the measured frame size it admits roughly 14,000 levels, about
/// thirty times the case that failed.
const LOWERING_STACK_BYTES: usize = 256 * 1024 * 1024;

/// Lower an entire function given its region tree.
///
/// The work runs on a thread with [`LOWERING_STACK_BYTES`] of stack rather than
/// whatever `ulimit -s` happens to be, so a deep region tree cannot turn into a
/// silent SIGSEGV. Every pass below recurses over the same deep structure — the
/// region tree in `lower_region`, then the resulting statement tree in
/// `collect_goto_targets` and `deduplicate_labels` — so the whole body needs the
/// headroom, not just the first pass.
pub fn lower(lf: &LlirFunction, region: &Region, name: impl Into<String>) -> Function {
    let name = name.into();
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("glaurung-lower".to_string())
            .stack_size(LOWERING_STACK_BYTES)
            .spawn_scoped(scope, move || lower_on_this_stack(lf, region, name))
            .expect("spawn the lowering thread")
            .join()
            // Preserve panic behavior exactly: a panic inside lowering must
            // still unwind to the original caller, not become a join error.
            .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
    })
}

fn lower_on_this_stack(lf: &LlirFunction, region: &Region, name: String) -> Function {
    let lower_scalar_float = scalar_float_semantics_are_closed(lf);
    let mut targets = std::collections::HashSet::new();
    collect_goto_targets(region, lf, &mut targets);
    // Region::Goto is not the only source of an explicit edge. A raw direct
    // jump can survive inside a recovered switch arm when several cases share
    // a latch but one case exits the loop. Discover those statements from the
    // first lowered body, then lower once more with their targets known so the
    // emitted destination block receives its real label. Without this pass the
    // renderer can only append an empty label at function end, changing where
    // the case actually transfers control.
    let mut body = lower_region(region, lf, &targets, lower_scalar_float);
    let known_target_count = targets.len();
    crate::ir::label_prune::collect_goto_targets(&body, &mut targets);
    if targets.len() != known_target_count {
        body = lower_region(region, lf, &targets, lower_scalar_float);
    }
    deduplicate_labels(&mut body);
    let mut f = Function {
        name,
        entry_va: lf.entry_va,
        body,
    };
    fold_returns(&mut f.body);
    f
}
