//! The semantic pass schedule that runs before DecBench rendering.
//!
//! Everything here changes definitions, uses, value identities, or control-flow
//! representation. The passes used to run *inside* `render_decbench_typed`,
//! which made that renderer impure: the AST that was checked or dumped was not
//! the AST that was printed, so def-before-use verification against it produced
//! false positives on correct functions and had to be reverted. Running them as
//! a named pass whose output is the thing rendered is what makes the emitted C
//! verifiable — see [`crate::ir::verify_defs`].
//!
//! This module is the schedule, not the transformations: with the exception of
//! parameter-spill coalescing (`super::param_spills`) and the return folds that
//! remain in `super`, every step is a call into a sibling `crate::ir::*` pass.
//! What lives here is the *order*, the bounded fixpoints, and the comments
//! recording why a pass has to run before or after another one.

use super::param_spills::{coalesce_named_param_spills, coalesce_param_spills, drop_self_stores};
use super::{
    fold_exhaustive_if_returns, fold_exhaustive_switch_returns, fold_returns,
    remove_redundant_return_constant_assignments, Function,
};

/// The explicit AST transformation that precedes DecBench rendering.
///
/// These nineteen steps change *definitions, uses, value identities, or control-flow
/// representation* — they are
/// semantic pipeline operations, not formatting:
///
/// 1. `default_return_to_reg` gives a bare `return` its ABI return register, so
///    an always-non-void rendering emits `return ret;` instead of the
///    value-losing `return 0;`;
/// 2. `coalesce_param_spills` folds a parameter's spill slot back into the
///    parameter, so the emitted C uses `argN` directly instead of a redundant
///    `local_X = argN` copy (which recompiles to stack traffic the original never
///    emits);
/// 3. `copy_prop::propagate_copies` and `const_fold::fold_constants` run to a
///    small local fixpoint: mask folding can turn a twice-read partial-register
///    parent into a one-use copy, and propagating that copy exposes the final
///    comparison identity.
/// 4. `select_fold::collapse_assignment_diamonds` turns a proven two-arm,
///    same-destination diamond into one pure select expression, then the narrow
///    promoted-select propagator removes an adjacent one-use stack temporary.
/// 5. `guarded_call::materialize_false_edges` makes the zero-valued
///    false edge of an exact `value != 0` guarded call overwrite explicit,
///    preserving lazy evaluation while recovering both reaching values.
/// 6. `lazy_call_select::collapse_lazy_call_diamonds` moves a proven
///    value-producing call into its original lazy assignment arm without
///    duplicating or speculating the call.
/// 7. `select_fold::recover_guarded_select_returns` turns an initialized result,
///    one guarded select overwrite, and its joined return back into terminating
///    nested returns when the initializer is a pure register view.
/// 8. `select_fold::fold_boolean_masks` renders an exact comparison-derived
///    `0`/`-1` select as arithmetic negation, avoiding fake source-level control
///    flow without changing the mask value.
/// 9. `copy_prop::propagate_adjacent_guard_values` folds a physical scratch's
///    immediately adjacent, sole eager guard use without claiming that physical
///    role is globally SSA.
/// 10. `copy_prop::propagate_adjacent_overwritten_values` carries one pure,
///    immediately consumed value into the assignment that overwrites the same
///    physical scratch without treating that scratch as globally SSA.
/// 11. `terminal_loop::recover_terminal_self_loops` turns an exact terminal
///    machine `label; goto label` into a source-level infinite loop while
///    retaining the label for any incoming structured edge.
/// 12. `label_prune::recover_forward_exit_regions` turns exact forward skips to
///    an adjacent join into guarded continuations, including a tail loop exit
///    that is provably the source-level `break`.
/// 13. `loop_form::recover_linear_latched_do_whiles` turns a uniquely owned
///    `label; body; if (condition) goto label` into the exact source-level
///    `do { body } while (condition)` form.
/// 14. `loop_form::recover_head_tested_whiles` turns the conservative constant-bound
///    countdown `while (1) { if (exit) break; body }` into
///    `while (!exit) { body }` only when folding has made the exit guard first.
/// 15. `label_prune::inline_terminal_goto_tails` duplicates only straight-line,
///    uniquely labelled return tails at their goto sites, recovering ordinary
///    early returns without inventing or reordering an effect.
/// 16. `switch_ladder::recover_switches` runs before select formation and again
///    after loop/copy recovery, converting proven comparison ladders into
///    `switch` nodes without losing a two-case tail to a ternary expression.
/// 17. `guarded_switch::collapse_range_guards` removes a compiler range-check
///    wrapper only when its unsigned domain and every switch label prove that
///    the wrapper cannot select a case the switch would not select itself.
/// 18. `loop_form::promote_for_loops` combines an adjacent initializer, exact head
///    guard, and unconditional same-variable unit increment into a `for` node.
/// 19. `fold_exhaustive_if_returns` and `fold_exhaustive_switch_returns` move an
///    immediately joined result return into proven terminating arms. Exhaustive
///    `if`/`switch` regions lose the join entirely; a one-sided `if` becomes an
///    early return followed by the original false-path fallthrough.
///
/// They used to run *inside* `render_decbench_typed`, which made that renderer
/// impure: the AST that was checked or dumped was not the AST that was printed,
/// so def-before-use verification against it produced false positives on correct
/// functions and had to be reverted. Running them here, as a named pass whose
/// output is the thing rendered, makes the emitted C verifiable — see
/// [`crate::ir::verify_defs`].
pub fn prepare_for_decbench(f: &Function) -> Function {
    prepare_for_decbench_with_output(f, crate::ir::types_recover::RecoveredOutputKind::Unknown)
}

/// Prepare DecBench output with the recovered source-level output contract.
/// Unknown/direct outputs retain the compatibility behavior; proven void
/// outputs erase incidental return-register residue before any source-level
/// folding runs.
pub fn prepare_for_decbench_with_output(
    f: &Function,
    output_kind: crate::ir::types_recover::RecoveredOutputKind,
) -> Function {
    prepare_for_decbench_with_output_and_protected_locals(
        f,
        output_kind,
        &std::collections::HashSet::new(),
        8,
    )
}

/// Prepare output while preserving debug-proven source-local identities.
///
/// Source locals may be initialized from a parameter without being that
/// parameter's home storage. The protected set is deliberately internal-slot
/// names: semantic passes retain those names until the final presentation
/// boundary, where authoritative source spellings are applied.
pub(crate) fn prepare_for_decbench_with_output_and_protected_locals(
    f: &Function,
    output_kind: crate::ir::types_recover::RecoveredOutputKind,
    protected_locals: &std::collections::HashSet<String>,
    pointer_width: u8,
) -> Function {
    let mut owned = f.clone();
    if output_kind == crate::ir::types_recover::RecoveredOutputKind::Void {
        crate::ir::direct_output::clear_return_values(&mut owned);
    } else {
        crate::ir::direct_output::materialize_direct_output(&mut owned);
    }
    coalesce_param_spills(&mut owned.body, protected_locals);
    crate::ir::label_prune::prune_unreachable_tails(&mut owned);
    // Copy propagation exposes algebraic flag identities, while folding those
    // identities changes use counts and exposes new one-use copies. Iterate the
    // monotone pair to a small bounded fixpoint: x86 partial-register returns
    // need three rounds (fold the observed mask, inline the parent, delete the
    // now-dead pre-loop copy). Four is a defensive bound, not an unbounded
    // optimiser loop; all transformations strictly remove a copy or expression
    // layer and ordinary functions settle after one round.
    for _ in 0..4 {
        let before = owned.clone();
        crate::ir::copy_prop::propagate_copies(&mut owned);
        crate::ir::const_fold::fold_constants(&mut owned);
        if owned == before {
            break;
        }
    }
    // Folding can prove that an initially composite narrow-register rebuild is
    // exactly its incoming argument (`(arg & ~255) | (arg & 255) == arg`). Run
    // the same guarded home analysis again so byte/halfword parameter spills
    // exposed only at the fixpoint do not survive as fake source locals.
    coalesce_named_param_spills(&mut owned.body, protected_locals);
    // A spill carried through a scratch can become `arg0 = arg0` only after
    // the copy fixpoint. The earlier coalescing cleanup cannot see it yet.
    drop_self_stores(&mut owned.body);
    // Propagation can expose a casted result copy directly before its return.
    // Collapse it before exhaustive-switch joining so the lossless cast chain
    // can be carried into each arm instead of blocking source-level returns.
    fold_returns(&mut owned.body);
    // Copy propagation and the second constant fold can replace a flag read in
    // a condition with its recovered comparison. Prune the now-dead definition
    // before shape recovery: otherwise a redundant `sf_N = ...` remains before
    // an exit guard and blocks exact while/for/select recognition.
    crate::ir::dce::prune_overwritten_flags(&mut owned);
    crate::ir::dce::prune_dead_flags(&mut owned);
    crate::ir::copy_prop::propagate_adjacent_promoted_values(&mut owned);
    crate::ir::copy_prop::propagate_adjacent_guard_values(&mut owned);
    // The run-local propagators above clear their environment at every
    // control-flow boundary, so an ABI copy made in the entry block and read
    // inside a loop survives as a declared local no matter how few reads it
    // has. That is the ordinary shape of -O2 output. This pass folds only the
    // provably free case: a name assigned exactly once, from a cast chain over
    // a never-written parameter.
    crate::ir::guard_chain::collapse_shared_exit_guard_ladders(&mut owned);
    crate::ir::guard_chain::collapse_shared_assignment_guards(&mut owned);
    crate::ir::guard_chain::collapse_redundant_copy_nested_guards(&mut owned);
    crate::ir::guard_chain::collapse_nested_terminal_return_guards(&mut owned);
    // Region recovery may clone a comparison tree's shared default into
    // sequential terminal guards. Recover that switch before two-case tails
    // become `Select` expressions and erase the final equality arms. The
    // second invocation below remains necessary because select/copy folding can
    // expose ladders whose discriminant was not yet syntactically uniform.
    crate::ir::switch_ladder::recover_switches(&mut owned);
    crate::ir::select_fold::collapse_assignment_diamonds(&mut owned);
    crate::ir::guarded_call::materialize_false_edges(&mut owned);
    crate::ir::lazy_call_select::collapse_lazy_call_diamonds_with_pointer_width(
        &mut owned,
        pointer_width,
    );
    crate::ir::select_fold::recover_guarded_select_returns(&mut owned);
    crate::ir::select_fold::fold_boolean_masks(&mut owned);
    // Runs after every producer of `Select`, including the lifters. ARM32
    // predicated execution emits the guard twice — `(C ? (C ? x : prior) : y)` —
    // and the inner alternative is unreachable because the enclosing arm already
    // decided `C`. Dominance, not definedness: the arm being dropped may well be
    // a defined value, it simply cannot be selected.
    crate::ir::copy_prop::propagate_adjacent_promoted_values(&mut owned);
    crate::ir::copy_prop::propagate_adjacent_guard_values(&mut owned);
    crate::ir::copy_prop::propagate_adjacent_overwritten_values(&mut owned);
    crate::ir::terminal_loop::recover_terminal_self_loops(&mut owned);
    // Recover shared return epilogues before general forward joins. Otherwise a
    // goto from a loop to `return -1` is faithfully but less clearly rendered
    // as `break; ... return -1` instead of the exact early return.
    crate::ir::label_prune::inline_terminal_goto_tails(&mut owned);
    // A forward join may contain a still-linearised inner loop, while removing
    // that join can in turn expose the enclosing linear latch. Two bounded
    // rounds recover inner loop -> forward join -> outer loop without relaxing
    // either pass's internal-label rejection.
    for _ in 0..2 {
        crate::ir::label_prune::recover_forward_exit_regions(&mut owned);
        crate::ir::loop_form::recover_linear_latched_do_whiles(&mut owned);
    }
    // Forward-region recovery can be the step that finally turns a linear
    // call/constant join into an ordinary two-arm assignment. Form the lazy
    // select now, then MOVE its effectful scratch value into an adjacent sole
    // consumer. Ordinary copy propagation may duplicate pure expressions, but
    // an Expr::Call must retain exactly one evaluation.
    crate::ir::select_fold::collapse_assignment_diamonds(&mut owned);
    crate::ir::copy_prop::move_adjacent_effectful_scratch_values(&mut owned);
    // Inlining a shared terminal epilogue can leave its old fallthrough
    // assignment after an explicit return. Remove that newly unreachable tail
    // before exact sentinel-loop matching; it is not an effect the candidate
    // should have to tolerate, but it also must not block a faithful rewrite.
    crate::ir::label_prune::prune_unreachable_tails(&mut owned);
    crate::ir::loop_form::recover_head_tested_whiles(&mut owned);
    crate::ir::loop_form::recover_guarded_do_whiles(&mut owned);
    crate::ir::loop_form::recover_sentinel_search_loops(&mut owned);
    crate::ir::guard_chain::collapse_adjacent_break_guards(&mut owned);
    crate::ir::guard_chain::collapse_nested_terminal_return_guards(&mut owned);
    // Before rendering and before widening (which already understands `Switch`):
    // a gcc -O0 comparison ladder is a `switch`, not a nest of `if`s and `goto`s.
    crate::ir::switch_ladder::recover_switches(&mut owned);
    crate::ir::guarded_switch::collapse_range_guards(&mut owned);
    // Removing a proven range guard can make a prefix copy dominate the switch
    // directly. Carry only those aliases into the switch arms. A general late
    // copy-propagation rerun is unsound here: loops have already been recovered,
    // and a pre-loop snapshot may depend on a value changed by the loop body.
    crate::ir::copy_prop::propagate_switch_entry_copies(&mut owned);
    fold_exhaustive_if_returns(&mut owned);
    fold_exhaustive_switch_returns(&mut owned);
    crate::ir::loop_form::promote_for_loops(&mut owned);
    // Loop promotion can expose sequential terminal guards that were nested in
    // the recovered CFG during the earlier pass. Fuse that final exact shape
    // as well; the transformation is adjacency-checked and idempotent.
    crate::ir::guard_chain::collapse_adjacent_break_guards(&mut owned);
    crate::ir::guard_chain::collapse_redundant_copy_nested_guards(&mut owned);
    crate::ir::guard_chain::collapse_matching_terminal_return_guard(&mut owned);
    // Late copy/guard folding can make an entry-owned do-while's initial and
    // latch predicates structurally identical only after the first loop-form
    // pass. The recovery is exact and idempotent; rerun it on the final AST so
    // phi-coalesced cursors retain their source-level pre-test.
    crate::ir::loop_form::recover_guarded_do_whiles(&mut owned);
    crate::ir::latch_predicate::fold_latched_predicates(&mut owned);
    remove_redundant_return_constant_assignments(&mut owned.body);
    owned
}
