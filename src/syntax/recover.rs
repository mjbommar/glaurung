//! `SB-8` --- error-recovery primitives: synchronizing sets and bounded depth.
//!
//! Spec: `docs/design/source-front-ends/substrate.md` sections 6 and 7.
//!
//! This is what makes "parsing never fails" (`REQ-SYN-2`) a real property
//! rather than a slogan. A grammar module above this one still has to *use*
//! these pieces correctly at every recovery point, but the primitives are
//! built so that the classic ways to get that wrong -- an infinite recovery
//! loop, an unbounded recursive descent, an unbounded token walk -- are hard
//! to write by accident rather than merely discouraged in a comment.
//!
//! # Why a sync set is a sorted slice, not a 65536-bit bitset
//!
//! A synchronizing set answers one question, over and over, in a parser's
//! hottest loop: "is this token kind one of the handful I should stop
//! skipping at?" A token kind is an opaque `u16` (`REQ-SYN-1`), so the
//! textbook representation is a bitset over the whole `u16` space -- 8 KiB,
//! tested in true O(1) with one shift and one mask.
//!
//! That is the wrong trade here, and the reason is the *count* of sync
//! points a real grammar has, not the cost of any one lookup. A recovery
//! point exists at roughly every statement-level and declaration-level
//! production, and each one wants its own set (a statement recovers to a
//! different set of kinds than a parameter list does). A C-family grammar
//! plausibly declares several dozen of these as `const`s. At 8 KiB apiece
//! that is hundreds of kilobytes of mostly-zero static data for sets whose
//! *combined* membership -- summed across every sync point in the grammar --
//! is a few hundred kinds at most, because [`docs/design/source-front-ends/
//! substrate.md`] section 6 gives the representative case directly: a
//! statement parser syncs on a statement terminator, a block-closing
//! delimiter, and a few statement-introducing keywords -- single digits to
//! perhaps two dozen members, not thousands.
//!
//! A sorted `&'static [u16]` costs `2 * members` bytes, tests membership with
//! a binary search that is `O(log members)` and in practice a handful of
//! comparisons over data already resident in one cache line, and -- the
//! requirement this module states explicitly -- builds trivially as a
//! `const fn` over a literal array, where a bitset would need either a
//! `while`-loop const-evaluation for every declared set or a build script.
//! `O(log n)` is not the textbook `O(1)` of a bitset, but at the `n` real
//! grammars use the two are indistinguishable at the machine level, and the
//! representation this module ships is a small `struct` wrapping a slice, so
//! nothing about the public API forecloses swapping the internals for a
//! bitset later if a consumer ever measures a set large enough for the
//! asymptotics to matter. `REQ-SYN-10` applies: build the piece today's two
//! consumers need, not the one a hypothetical third might.
//!
//! [`docs/design/source-front-ends/substrate.md`]: ../../../docs/design/source-front-ends/substrate.md
//!
//! # Language neutrality
//!
//! `REQ-SYN-1`. Nothing below names a token kind, keyword or punctuation mark
//! of any language; every example in these docs is described by role
//! ("a block-closing kind", "a statement terminator") rather than by the
//! literal character or word a language happens to spell it with.

use std::cell::Cell;

use crate::syntax::diag::{Diagnostic, Diagnostics};
use crate::syntax::ids::Span;
use crate::syntax::token::Cursor;

/// A synchronizing set of token kinds: the answer to "which tokens is it safe
/// to resume parsing at?"
///
/// Built once, from a sorted `&'static [u16]`, and reused at every recovery
/// point that shares the same recovery strategy. See the module docs for why
/// this is a sorted slice rather than a bitset.
///
/// # Invariant
///
/// The backing slice must be sorted and free of duplicates for
/// [`SyncSet::contains`]'s binary search to be correct. [`SyncSet::new`]
/// cannot enforce this itself and stay a `const fn` (sorting is not
/// available in const context on stable Rust), so it is a caller obligation,
/// exactly like declaring a lookup table by hand. A grammar's sync sets are a
/// handful of short, hand-written literals, so this is easy to get right and
/// [`SyncSet::from_unsorted`] is provided as a non-`const` fallback for the
/// rare case where sortedness cannot be guaranteed by inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncSet {
    /// Sorted, deduplicated member kinds.
    kinds: &'static [u16],
}

impl SyncSet {
    /// A sync set over exactly `kinds`, which must already be sorted and
    /// free of duplicates.
    ///
    /// `const fn`, so a grammar declares its sync sets as `const`s next to
    /// the productions that use them (`static SYNC_STMT: SyncSet =
    /// SyncSet::new(&[3, 9, 40]);`), with no runtime construction cost and no
    /// allocation (`REQ-SYN-6`).
    pub const fn new(kinds: &'static [u16]) -> Self {
        Self { kinds }
    }

    /// A sync set over `kinds`, sorting a caller-provided copy first.
    ///
    /// Not `const` -- sorting needs a runtime slice -- so prefer
    /// [`SyncSet::new`] with a literal written in order wherever the sync
    /// set is a compile-time constant, which is the overwhelmingly common
    /// case. This exists for the rare set assembled at runtime (e.g. unioned
    /// from two grammar fragments) where sortedness by construction is not
    /// free to guarantee.
    pub fn from_unsorted(mut kinds: Vec<u16>) -> Self {
        kinds.sort_unstable();
        kinds.dedup();
        Self {
            kinds: Vec::leak(kinds),
        }
    }

    /// The empty sync set, which matches no kind. Skipping to it always runs
    /// to end of input; useful as a placeholder before a real set is known,
    /// or as a deliberate "there is no safe resume point here".
    pub const EMPTY: SyncSet = SyncSet::new(&[]);

    /// Whether `kind` is a member of this set.
    ///
    /// Binary search over the sorted backing slice -- see the module docs
    /// for why this beats a bitset at the sizes a real grammar's sync sets
    /// reach.
    pub fn contains(&self, kind: u16) -> bool {
        self.kinds.binary_search(&kind).is_ok()
    }

    /// How many kinds this set contains.
    pub const fn len(&self) -> usize {
        self.kinds.len()
    }

    /// Whether this set has no members.
    pub const fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }
}

/// What [`skip_to_sync`] accomplished: how much input it skipped, and whether
/// it actually landed on a synchronizing token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkipOutcome {
    /// The span of the tokens skipped, from where the cursor started to
    /// where it now sits. Every token, including one lost to recovery, keeps
    /// a real span (`REQ-SYN-7`), so this is what a caller attaches to the
    /// diagnostic explaining what was discarded. Empty when the cursor was
    /// already sitting on a synchronizing token, or already at end of input
    /// -- a zero-length skip is a valid, reportable outcome, not a
    /// degenerate one.
    pub skipped: Span,
    /// Whether the cursor now sits on a token that is a member of the sync
    /// set. `false` means input ran out before any member was seen: the
    /// caller has no safe resume point left in this token stream, not merely
    /// a distant one.
    pub found: bool,
}

/// Advance `cursor` until its current token is a member of `set`, or input is
/// exhausted; report what happened as a [`SkipOutcome`].
///
/// This is the whole of "recovery" in the mechanical sense: everything a
/// parser does after reporting an error is discard tokens until it reaches
/// ground it recognizes again. `skip_to_sync` is the one place that walk
/// happens, so every recovery point in a grammar shares its termination
/// argument instead of re-proving it locally.
///
/// # Termination
///
/// [`Cursor::bump`] strictly advances the cursor's position while it is not
/// already at end of input, and the loop here only calls `bump` under that
/// same condition, so each iteration either advances or exits -- bounded by
/// [`crate::syntax::token::Tokens::len`], which is finite for any input
/// (`REQ-SYN-4`). No native recursion is used to get there (`REQ-SYN-3`).
///
/// # Zero-length skips are not a failure
///
/// If the cursor is already on a synchronizing token, the loop body never
/// runs and `skipped` is the empty span at the cursor's current position,
/// with `found: true`. This is correct -- there was nothing to skip -- but
/// it is also exactly the shape of a recovery loop that calls
/// `skip_to_sync` and then loops without re-checking whether it moved.
/// Pairing this call with [`ProgressMark`] turns that silent stall into a
/// reported one; `skip_to_sync` alone does not protect a caller from it,
/// because whether "no progress" is even an error depends on what the
/// caller does next.
pub fn skip_to_sync(cursor: &mut Cursor<'_>, set: &SyncSet) -> SkipOutcome {
    let lo = cursor.span().lo;
    while !cursor.is_eof() && !set.contains(cursor.peek()) {
        cursor.bump();
    }
    let hi = cursor.span().lo;
    SkipOutcome {
        skipped: Span::new(lo, hi),
        found: set.contains(cursor.peek()),
    }
}

/// A limit on how deeply a parser may nest, and the live count of how deep it
/// currently is (`REQ-SYN-4`).
///
/// The substrate itself never recurses natively (`REQ-SYN-3`): its own walks
/// use an explicit stack. This guard exists for the layer above it. A
/// language grammar may still be *structured* as recursive descent -- one
/// Rust function per production, calling into the next -- even when the
/// substrate underneath is not, and that structure's nesting is driven by
/// the input: a decompiler's output routinely contains deeply nested casts,
/// parenthesised expression spines and chained boolean operators, all of it
/// attacker- or corruption-controlled rather than authored. `DepthBudget` is
/// what turns that native call stack's depth into a bounded, reported
/// quantity instead of a process abort.
/// # Why the guard holds a `Cell`, not an exclusive borrow
///
/// The obvious first draft ties `DepthGuard`'s lifetime to `&mut
/// DepthBudget`, the way a mutex guard ties itself to `&Mutex`. It is wrong
/// here: a recursive-descent parser must hold an *outer* guard alive while
/// calling back into the same budget for every inner production, and an
/// exclusive borrow makes that second call a compile error -- the outer
/// guard is still live, so the budget is not free to lend out again. The
/// budget needs many simultaneous readers of the same depth, exactly the
/// shape `Cell` (single-threaded interior mutability, no allocation, no new
/// dependency) exists for: [`DepthBudget::enter`] takes `&self`, so nesting
/// to any depth just re-borrows the same shared reference the caller already
/// has.
#[derive(Debug)]
pub struct DepthBudget {
    /// The deepest nesting permitted before [`DepthBudget::enter`] refuses.
    limit: u32,
    /// How many [`DepthGuard`]s are currently alive.
    depth: Cell<u32>,
}

impl DepthBudget {
    /// A budget that permits nesting up to `limit` levels deep.
    pub const fn new(limit: u32) -> Self {
        Self {
            limit,
            depth: Cell::new(0),
        }
    }

    /// The configured limit.
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// The current live nesting depth -- how many [`DepthGuard`]s are
    /// currently held.
    pub fn depth(&self) -> u32 {
        self.depth.get()
    }

    /// Enter one more level of nesting, or refuse with a diagnostic if that
    /// would exceed [`DepthBudget::limit`].
    ///
    /// On success, the live depth increases by one and the returned
    /// [`DepthGuard`] is what decreases it again -- there is no separate
    /// "leave" call to forget. `span` is attached to the diagnostic when the
    /// guard is refused, and should be the caller's current position so the
    /// diagnostic points at where nesting became too deep.
    ///
    /// Refusal does not increment the depth: a rejected `enter` produces no
    /// guard, so there is nothing to balance and no drop to run. Takes
    /// `&self`, not `&mut self` -- see the struct docs for why an exclusive
    /// borrow is the wrong shape for a value nested calls must keep
    /// re-entering.
    pub fn enter(&self, span: Span) -> Result<DepthGuard<'_>, Diagnostic> {
        let current = self.depth.get();
        if current >= self.limit {
            return Err(Diagnostic::error(
                span,
                format!("nesting depth exceeded the limit of {}", self.limit),
            ));
        }
        self.depth.set(current + 1);
        Ok(DepthGuard { depth: &self.depth })
    }
}

/// Proof that one level of [`DepthBudget`] nesting is held, and the sole way
/// to release it.
///
/// Dropping the guard is the only way its budget's depth decreases, so a
/// forgotten decrement is not an available bug: every path out of the scope
/// that produced this guard -- a normal return, an early `return`, the `?`
/// operator, a `break` out of an enclosing loop -- runs `Drop::drop` before
/// the guard's storage goes away, exactly like a mutex guard. This is the
/// RAII shape `REQ-SYN-4` calls for, applied to depth instead of a lock.
#[derive(Debug)]
pub struct DepthGuard<'a> {
    depth: &'a Cell<u32>,
}

impl Drop for DepthGuard<'_> {
    fn drop(&mut self) {
        self.depth.set(self.depth.get().saturating_sub(1));
    }
}

/// A monotonically decreasing count of parsing steps still available
/// (`REQ-SYN-4`).
///
/// Depth bounds unbounded *nesting*; this bounds unbounded *breadth* -- a
/// loop that keeps making small, individually-legal forward steps (a long
/// flat statement list, a pathological token stream that resyncs and
/// immediately errors again) rather than recursing. A parser charges this
/// for every token it consumes or every recovery step it takes; once it
/// reaches zero the parser is expected to stop rather than keep working,
/// and [`WorkBudget::is_exhausted`] is how a caller distinguishes "finished
/// the input" from "ran out of budget and gave up partway through" --
/// exactly the distinction `REQ-SYN-2` needs so a partial result is never
/// silently mistaken for a complete one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkBudget {
    /// Units of work still available. Charging saturates at zero rather than
    /// underflowing, so exhaustion is a stable state a caller can keep
    /// checking rather than a one-time event it must not miss.
    remaining: u32,
}

impl WorkBudget {
    /// A budget with `steps` units of work available before it is
    /// exhausted.
    pub const fn new(steps: u32) -> Self {
        Self { remaining: steps }
    }

    /// Units of work still available.
    pub const fn remaining(&self) -> u32 {
        self.remaining
    }

    /// Whether the budget has run out.
    ///
    /// This is the observable half of `REQ-SYN-4`'s "produces a diagnostic
    /// and a partial result, never a hang": a caller that finishes a parse
    /// checks this once at the end to tell a clean completion from a
    /// budget-forced stop, independent of whether any individual `charge`
    /// call happened to be the one that crossed zero.
    pub const fn is_exhausted(&self) -> bool {
        self.remaining == 0
    }

    /// Charge `cost` units of work against the budget; returns whether any
    /// budget remains afterward.
    ///
    /// Saturates at zero rather than underflowing (no panic on any input,
    /// per the module's hard rule), so overcharging an already-exhausted
    /// budget is harmless and idempotent -- `charge` keeps returning `false`.
    /// The usual call shape is `if !budget.charge(1) { report and stop; }`.
    pub fn charge(&mut self, cost: u32) -> bool {
        self.remaining = self.remaining.saturating_sub(cost);
        !self.is_exhausted()
    }
}

/// A recorded cursor position, checked later to prove a recovery step
/// actually moved forward.
///
/// The canonical recovery bug is a loop that reports an error, "recovers",
/// and lands back on the same token -- forever, since nothing about the
/// state changed. `ProgressMark` is the primitive that makes writing that
/// bug by accident hard: capture one before a recovery step, then call
/// [`ProgressMark::ensure`] after it. If the cursor did not move,
/// `ensure` pushes a diagnostic and force-advances by one token itself, so
/// the *next* iteration is guaranteed to start from new ground even if the
/// recovery logic that ran in between was a complete no-op.
///
/// `ensure` alone cannot guarantee a loop terminates when the cursor is
/// already at end of input -- there is nowhere left to force it to -- so a
/// recovery loop built on this still needs its own `is_eof` check as the
/// outer stop condition; what `ProgressMark` removes is every *other* way
/// the loop could fail to advance.
#[derive(Debug, Clone, Copy)]
pub struct ProgressMark {
    /// The cursor position at the time this mark was taken.
    pos: u32,
}

impl ProgressMark {
    /// Record `cursor`'s current position.
    pub fn here(cursor: &Cursor<'_>) -> Self {
        Self { pos: cursor.pos() }
    }

    /// Confirm `cursor` advanced since [`ProgressMark::here`]; if it did
    /// not, record a diagnostic at its current span and force it one token
    /// forward.
    ///
    /// Returns `true` if the cursor had already advanced on its own (the
    /// common case -- nothing more to do), or `false` if this call had to
    /// force it (the recovery step was a no-op and a diagnostic was just
    /// pushed to `diagnostics` to say so). Either way, the caller's next
    /// loop iteration starts from a cursor position strictly greater than
    /// `self.pos`, unless the cursor was already at end of input, in which
    /// case [`Cursor::bump`] itself has nowhere left to advance to and the
    /// caller's own `is_eof` check is what must end the loop.
    pub fn ensure(self, cursor: &mut Cursor<'_>, diagnostics: &mut Diagnostics) -> bool {
        if cursor.pos() != self.pos {
            return true;
        }
        let span = cursor.span();
        diagnostics.push(Diagnostic::error(
            span,
            "recovery made no progress; forcing the cursor forward",
        ));
        cursor.bump();
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::token::{Tokens, TokensBuilder};

    /// Five tokens with kinds `[10, 20, 30, 20, 99]`, at increasing offsets,
    /// so a sync set over `{20}` has two members to find and `{99}` has one
    /// at the very end.
    fn sample() -> Tokens {
        let mut b = TokensBuilder::new();
        b.push(10, 0);
        b.push(20, 2);
        b.push(30, 4);
        b.push(20, 6);
        b.push(99, 8);
        b.finish(10)
    }

    fn span(lo: u32, hi: u32) -> Span {
        Span::new(lo, hi)
    }

    #[test]
    fn skip_to_sync_stops_at_the_first_member_partway_through() {
        let tokens = sample();
        let mut cursor = tokens.cursor();
        let sync = SyncSet::new(&[30]);

        let outcome = skip_to_sync(&mut cursor, &sync);

        assert!(outcome.found);
        assert_eq!(
            outcome.skipped,
            span(0, 4),
            "skipped the two kind-10/20 tokens"
        );
        assert_eq!(
            cursor.peek(),
            30,
            "cursor lands on the sync token, not past it"
        );
        assert_eq!(cursor.pos(), 2);
    }

    #[test]
    fn skip_to_sync_with_no_matching_kind_runs_to_end_and_reports_it() {
        let tokens = sample();
        let mut cursor = tokens.cursor();
        let sync = SyncSet::new(&[123]); // not a kind present anywhere

        let outcome = skip_to_sync(&mut cursor, &sync);

        assert!(!outcome.found, "no member of the set ever appeared");
        assert!(cursor.is_eof());
        assert_eq!(
            outcome.skipped,
            span(0, tokens.end_of_input()),
            "the whole input was consumed searching"
        );
    }

    #[test]
    fn skip_to_sync_already_on_a_sync_token_is_a_zero_length_skip() {
        let tokens = sample();
        let mut cursor = tokens.cursor();
        let sync = SyncSet::new(&[10]); // the very first token's kind

        let outcome = skip_to_sync(&mut cursor, &sync);

        assert!(outcome.found);
        assert!(outcome.skipped.is_empty(), "nothing needed skipping");
        assert_eq!(cursor.pos(), 0, "the cursor never moved");
    }

    #[test]
    fn a_zero_length_skip_makes_the_progress_check_fail_loudly_instead_of_looping() {
        // The scenario `skip_to_sync`'s own docs warn about: recovery finds
        // it is already on a sync token, does nothing, and a caller that
        // trusted that alone would spin forever re-running the same
        // no-op step. Pairing it with `ProgressMark` turns the silent stall
        // into a reported, forced advance instead.
        let tokens = sample();
        let mut cursor = tokens.cursor();
        let sync = SyncSet::new(&[10]);
        let mut diagnostics = Diagnostics::new();

        let mark = ProgressMark::here(&cursor);
        let outcome = skip_to_sync(&mut cursor, &sync);
        assert!(outcome.skipped.is_empty());

        assert!(diagnostics.is_empty(), "nothing reported until ensure runs");
        let advanced_on_its_own = mark.ensure(&mut cursor, &mut diagnostics);

        assert!(!advanced_on_its_own, "ensure had to force it");
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics
            .iter()
            .next()
            .unwrap()
            .message
            .contains("no progress"));
        assert_eq!(cursor.pos(), 1, "ensure forced exactly one token forward");
    }

    #[test]
    fn sync_set_contains_only_its_declared_members() {
        let sync = SyncSet::new(&[5, 10, 200]);
        assert!(sync.contains(5));
        assert!(sync.contains(10));
        assert!(sync.contains(200));
        assert!(!sync.contains(6));
        assert_eq!(sync.len(), 3);
        assert!(!sync.is_empty());
    }

    #[test]
    fn the_empty_sync_set_matches_nothing() {
        assert!(SyncSet::EMPTY.is_empty());
        assert!(!SyncSet::EMPTY.contains(0));
        assert!(!SyncSet::EMPTY.contains(Tokens::EOF));
    }

    #[test]
    fn from_unsorted_sorts_and_dedups_before_it_can_be_searched() {
        let sync = SyncSet::from_unsorted(vec![9, 1, 5, 1, 9]);
        assert_eq!(sync.len(), 3, "duplicates were removed");
        assert!(sync.contains(1));
        assert!(sync.contains(5));
        assert!(sync.contains(9));
        assert!(!sync.contains(2));
    }

    #[test]
    fn a_sync_set_can_be_declared_as_a_compile_time_constant() {
        const STMT_SYNC: SyncSet = SyncSet::new(&[1, 2, 3]);
        assert!(STMT_SYNC.contains(2));
    }

    #[test]
    fn depth_budget_refuses_past_its_limit_without_incrementing() {
        let budget = DepthBudget::new(2);
        let first = budget.enter(span(0, 0));
        let second = budget.enter(span(0, 0));
        assert!(first.is_ok());
        assert!(second.is_ok());
        assert_eq!(budget.depth(), 2);

        let refused = budget.enter(span(4, 5));
        assert!(refused.is_err());
        assert_eq!(
            budget.depth(),
            2,
            "a refusal must not still increment depth"
        );
        let diag = refused.unwrap_err();
        assert_eq!(diag.span, span(4, 5));
        assert!(diag.message.contains('2'), "the message names the limit");
    }

    #[test]
    fn depth_guards_restore_depth_on_drop_in_nesting_order() {
        let budget = DepthBudget::new(3);
        assert_eq!(budget.depth(), 0);
        {
            let _outer = budget.enter(span(0, 0)).expect("first level fits");
            assert_eq!(budget.depth(), 1);
            {
                let _inner = budget.enter(span(0, 0)).expect("second level fits");
                assert_eq!(budget.depth(), 2);
            }
            assert_eq!(budget.depth(), 1, "the inner guard's drop restored depth");
        }
        assert_eq!(budget.depth(), 0, "the outer guard's drop restored depth");
    }

    #[test]
    fn a_depth_guard_is_released_even_on_an_early_return() {
        // The failure mode an RAII guard exists to rule out: a bail-out path
        // that skips a hand-written decrement. `?` runs `Drop` on every local
        // in scope, including the guard, before the function returns.
        fn enter_then_bail(budget: &DepthBudget) -> Result<(), Diagnostic> {
            let _guard = budget.enter(span(0, 0))?;
            assert_eq!(budget.depth(), 1);
            Err(Diagnostic::error(span(1, 2), "bail out early"))
        }

        let budget = DepthBudget::new(1);
        let result = enter_then_bail(&budget);
        assert!(result.is_err());
        assert_eq!(
            budget.depth(),
            0,
            "the guard dropped on the early return path"
        );

        // And the budget is usable again -- nothing was left stuck at 1.
        assert!(budget.enter(span(0, 0)).is_ok());
    }

    #[test]
    fn work_budget_exhausts_and_the_exhausted_state_is_observable() {
        let mut budget = WorkBudget::new(3);
        assert!(!budget.is_exhausted());

        assert!(budget.charge(1));
        assert!(budget.charge(1));
        assert_eq!(budget.remaining(), 1);
        assert!(!budget.is_exhausted());

        let has_more = budget.charge(1);
        assert!(!has_more, "the third charge exhausted it");
        assert!(budget.is_exhausted());

        // Overcharging an exhausted budget saturates rather than
        // underflowing or panicking, and stays observably exhausted.
        assert!(!budget.charge(5));
        assert_eq!(budget.remaining(), 0);
        assert!(budget.is_exhausted());
    }

    #[test]
    fn the_no_progress_detector_catches_a_stalled_recovery_loop() {
        let tokens = sample();
        let mut cursor = tokens.cursor();
        let mut diagnostics = Diagnostics::new();

        // A pathological "recovery" step that never moves the cursor,
        // looped a bounded number of times. Without `ProgressMark` this
        // would spin forever; with it, every iteration is forced forward.
        let mut iterations = 0;
        while !cursor.is_eof() && iterations < 100 {
            let mark = ProgressMark::here(&cursor);
            // (a broken recovery step would go here and do nothing)
            mark.ensure(&mut cursor, &mut diagnostics);
            iterations += 1;
        }

        assert!(
            cursor.is_eof(),
            "forced advances eventually exhaust the input"
        );
        assert_eq!(
            iterations,
            tokens.len(),
            "one forced step per real token, not the 100-iteration cap"
        );
        assert_eq!(diagnostics.len(), tokens.len());
        assert!(diagnostics
            .iter()
            .all(|d| d.message.contains("no progress")));
    }

    #[test]
    fn ensure_returns_true_and_reports_nothing_when_the_cursor_already_moved() {
        let tokens = sample();
        let mut cursor = tokens.cursor();
        let mut diagnostics = Diagnostics::new();

        let mark = ProgressMark::here(&cursor);
        cursor.bump();
        let advanced_on_its_own = mark.ensure(&mut cursor, &mut diagnostics);

        assert!(advanced_on_its_own);
        assert!(diagnostics.is_empty());
    }
}
