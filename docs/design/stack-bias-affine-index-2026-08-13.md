# The stack-bias affine-index work, and why it was not merged

*Recorded 2026-08-13, during the branch audit that emptied every other branch
onto master. This is the one piece of real work that could not be moved
mechanically. It is written down here so the branch holding it can go without
the idea going with it.*

## Where it lives

`agent/stack-bias` @ `4ac7657` — "snapshot: preserve uncommitted work in
wt-stackbias". A single file, `src/ir/stack_locals.rs`, +640/-80.

Its own commit message says the contents are "the state left in that worktree,
not a reviewed change", and that is the accurate description: it is a
mid-refactor snapshot, not a finished change.

## What it does

Two things, one small and one pervasive.

**The idea worth keeping** is an affine-index analysis: `affine_of`,
`affine_of_expr`, `collect_affine_index_defs`, and the test
`a_constant_bias_folded_into_the_index_still_reaches_the_displacement`. It
records, per register, a definition of the form `root * scale + bias`, with two
guards that are the interesting part:

* both ends must be version-stable, so a later redefinition cannot invalidate
  the fact and the fold names the same value at every use;
* a self-rooted definition is rejected outright, because it is a
  read-modify-write of a non-SSA register and folding it would silently shift
  every later use.

The payoff is in the test's name: a constant bias folded into an array index
currently stops the index from being matched against the frame displacement, so
the slot is not recognised as the local it is.

**The part that blocks a mechanical merge** is `StackAddressDefs`, a context
struct threaded through eleven function signatures across the file —
`collect_label_stack_deltas`, its inner `update_stack_assignment` and `walk`,
and eight more. It is not a feature that can be lifted out; it is a change to
how the whole module passes its facts around.

## Why it was not merged

Master's `stack_locals.rs` has 1,241 substantive lines; the branch's has 1,072.
Measured line-wise, master holds **339** the branch does not, against **170** the
branch holds that master does not. Taking the branch wholesale would lose about
twice what it gained.

Nor can the two be textually reconciled. The signatures the branch rewrites are
in the region master rewrote independently, which is the precise hazard
[`master-integration-2026-08-12.md`](master-integration-2026-08-12.md) records:
a textual resolution compiles, silently keeps one side's fix, drops the other's,
and the merged behaviour matches neither side's recorded baseline — so no
baseline can catch it.

There is also no gate that isolates the change. The branch carries one unit test
for the affine helpers and nothing that demonstrates the end-to-end effect, so
"did this improve recovery?" has no answer on the branch as it stands.

## What doing it properly looks like

1. Port ONLY the affine analysis — `affine_of`, `affine_of_expr`,
   `collect_affine_index_defs`, `is_version_stable` and the two guards above —
   against master's current model, leaving `StackAddressDefs` behind. The guards
   are the expensive part of the thinking and they transfer unchanged.
2. Bring its unit test with it; it is written against the helpers, not against
   the threading.
3. Add a fixture that exercises the shape end to end: an array indexed with a
   constant bias (`a[i + 3]`) in a frame whose slot recognition currently fails.
   Without one, step 1 is unfalsifiable.
4. Only then consider whether anything still wants `StackAddressDefs`. It may
   turn out that master's model already carries those facts by another route, in
   which case the refactor was a means to an end that no longer exists.

Do not resurrect the branch and merge it. Re-derive the 170 lines against
master, with the test in front.
