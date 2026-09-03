//! `T-4`, `T-5` --- stack-offset calibration between two frame conventions.
//!
//! Spec: `docs/design/static-c-analysis/implementation-inventory.md` section 5.
//!
//! DWARF reports a local's address as a displacement from the canonical frame
//! address (in practice, rbp-relative and negative); a decompiler reports the
//! same slot in whatever convention its own frame model uses. IDA's Hex-Rays
//! numbers slots from the *bottom* of the frame, so its offsets differ from
//! DWARF's by a per-function constant of roughly the frame size --- routinely
//! far more than the ±32 a fixed window would cover. Without calibration every
//! such slot is scored as a miss and the backend's `type_match` collapses to
//! near zero for reasons that have nothing to do with type recovery.
//!
//! Calibration is the fix: find the single additive `k` such that shifting
//! every decompiled offset by `k` puts the most of them onto ground-truth
//! offsets. [`calibrate_shift`] does it per function with an adaptive,
//! uncapped candidate set; [`calibrate_shift_multi`] does it once for a whole
//! binary with a deliberately *capped* one. The two differ on purpose --- see
//! each function's doc --- and the difference is load-bearing, so this module
//! reproduces both exactly rather than unifying them.
//!
//! **Faithfulness over cleverness.** This is a port of `_candidate_shifts`,
//! `_calibrate_shift` and `_calibrate_shift_multi` from DecBench's
//! `decbench/metrics/type_match.py`. The point is to reproduce the reference's
//! shift, not to improve on it: the fallback chains, the tie-breaks, and the
//! places where the reference is arguably wrong (see [`calibrate_shift`]'s
//! "Reference quirk") are all preserved. `src/metrics/type_name.rs` states the
//! same house attitude for the neighbouring component, and
//! `implementation-inventory.md` section 9 states it generally.
//!
//! **Determinism** (`REQ-SYN-5`, and `K-4` in [`crate::metrics`]). The
//! reference iterates a Python `set` that it sorts first, so its tie-break is
//! well defined; a port that iterated an unordered map and took "the first
//! maximum" would agree on any corpus whose insertion order happened to match
//! and disagree on a reordering of the same input. Nothing here relies on
//! iteration order: every winner is chosen by `Better::beats`, a *strict
//! total order* on `(count, |k|, k)` in which no two distinct candidates are
//! ever equal, so the argmax is the same value whatever order the candidates
//! arrive in. That is why the `HashMap` in [`calibrate_shift`] is legitimate
//! under `K-4`: it is looked up and discarded, and its iteration order cannot
//! reach output.
//!
//! **Arithmetic width.** The reference runs on Python integers, which do not
//! overflow; offsets here are `i64` and `g - d` does not fit in one. See
//! [`Shift`].

use std::collections::HashMap;
use std::collections::HashSet;

/// An additive stack-offset shift, in bytes, as `i128` rather than `i64`.
///
/// A shift is a *difference* of two offsets, and the difference of two `i64`s
/// needs 65 bits: `calibrate_shift(&[i64::MAX], &[i64::MIN])` is `2^64 - 1` in
/// the reference, which has arbitrary-precision integers, and would wrap to
/// `-1` in `i64`. Wrapping would be a silent wrong answer, saturating would be
/// a different silent wrong answer, and returning an error would turn a
/// perfectly well-defined calibration into a non-answer. `i128` simply holds
/// the value: every quantity this module computes is either `g - d` (bounded
/// by `2^64 - 1` in magnitude) or `d + k` (bounded by `2^64 + 2^63`), both far
/// inside `i128`, so **no arithmetic in this module can overflow at all** and
/// there is no saturation, wrapping or panic to reason about.
///
/// Applying a shift to an offset is therefore also an `i128` operation: see
/// `shifted_hits`, which treats a shifted offset outside `i64`'s range as
/// "not a ground-truth offset". That is what the reference does too, since a
/// ground-truth offset set drawn from DWARF only ever contains values that fit
/// in `i64`.
pub type Shift = i128;

/// Better than the incumbent: the strict total order that decides which
/// candidate shift wins.
///
/// A candidate is `(count, k)`: how many decompiled offsets `k` aligns, and
/// the shift itself. The reference picks its winner by walking the candidates
/// in `sorted(key=lambda x: (abs(x), x))` order and replacing the incumbent
/// only on a *strictly greater* count --- so a higher count always wins, and a
/// tie is kept by whichever candidate the sort put first, which is the one
/// with the smaller `|k|` and, between `-m` and `+m`, the negative one.
///
/// Encoding that as an order rather than as an iteration makes the result
/// independent of the order candidates are visited in, which is what lets
/// `calibrate_shift` build its candidates in a `HashMap` (`REQ-SYN-5`; see
/// the module doc). The order is total on distinct `k`, because `(|k|, k)`
/// distinguishes every pair of distinct integers.
trait Better {
    /// Whether `self` beats `other` under the reference's tie-break.
    fn beats(&self, other: &Self) -> bool;
}

impl Better for (u64, Shift) {
    fn beats(&self, other: &Self) -> bool {
        let (count, k) = *self;
        let (other_count, other_k) = *other;
        if count != other_count {
            return count > other_count;
        }
        // `abs()` is total here: `k` is a difference of `i64`s or a member of
        // `-32..=32`, never `i128::MIN`.
        (k.abs(), k) < (other_k.abs(), other_k)
    }
}

/// Whether `offset` shifted by `shift` hits one of the ground-truth offsets
/// in `gt`.
///
/// The addition is done in [`Shift`] width and the result is converted back to
/// `i64` to be looked up, so a shift that carries an offset outside `i64`'s
/// range simply misses. That matches the reference exactly: its `d + k` is an
/// arbitrary-precision integer, and a ground-truth set built from DWARF
/// contains only `i64`-representable values, so an out-of-range sum is never a
/// member there either.
fn shifted_hits(gt: &HashSet<i64>, offset: i64, shift: Shift) -> bool {
    match i64::try_from(Shift::from(offset) + shift) {
        Ok(shifted) => gt.contains(&shifted),
        Err(_) => false,
    }
}

/// The `offsets` made unique and sorted into ascending order.
///
/// Every count in this module is over a *set* of shifted offsets, because the
/// reference counts `len({d + k for d in decomp_offsets} & gt_set)` --- a set
/// comprehension, so two decompiled variables sharing an offset contribute one
/// match, not two. Deduplicating once up front is both what makes the counts
/// right and what makes the difference-multiset identity in [`calibrate_shift`]
/// hold. Sorting is not needed for correctness (the winner is chosen by a
/// total order) but it costs nothing and makes any debug print stable.
fn unique_sorted(offsets: &[i64]) -> Vec<i64> {
    let mut out = offsets.to_vec();
    out.sort_unstable();
    out.dedup();
    out
}

/// Counts how many distinct decompiled offsets align with a ground-truth
/// offset when shifted by `shift`.
///
/// This is the score every candidate shift is ranked by, and it is also the
/// `_aligned` helper the reference's caller uses to decide whether a
/// per-function shift should override the binary-wide one --- so it is public:
/// a caller that has a shift from either calibrator needs the same count to
/// make that decision, and recomputing it by hand is how the two drift apart.
///
/// Duplicates on either side are collapsed. Returns `0` when either side is
/// empty, which is the reference's behaviour for an empty `decomp_offsets`
/// and falls out of the set intersection for an empty `gt_offsets`.
pub fn aligned_count(gt_offsets: &[i64], decomp_offsets: &[i64], shift: Shift) -> u64 {
    let gt: HashSet<i64> = gt_offsets.iter().copied().collect();
    let decomp = unique_sorted(decomp_offsets);
    decomp
        .iter()
        .filter(|&&d| shifted_hits(&gt, d, shift))
        .count() as u64
}

/// Calibrate one additive shift aligning one function's decompiled stack
/// offsets to its ground-truth offsets, or `None` if nothing aligns.
///
/// The candidate set is *adaptive and uncapped*, which is the whole point of
/// the per-function calibrator: a shift `k` can align a slot only when
/// `k = g - d` for some ground-truth `g` and decompiled `d`, so the exact set
/// worth testing is that difference set plus `0`, and it therefore covers any
/// frame size. IDA's Hex-Rays offsets are frame-bottom relative and differ
/// from DWARF's by roughly the frame size, which a fixed window would never
/// reach; [`calibrate_shift_multi`] uses a fixed window instead, for a reason
/// given there.
///
/// The winner is the `k` maximizing [`aligned_count`], with ties resolved to
/// the smallest `|k|` (and, between `-m` and `+m`, to `-m`).
///
/// **The two-alignment guard.** A large `k` can always be found that aligns
/// exactly one slot --- pick any `g` and any `d` and you have one. Crediting
/// that would let a function with one decompiled variable claim a perfect
/// frame calibration by coincidence. So: if the winner is nonzero *and* there
/// are at least two decompiled offsets, it must align at least two of them;
/// otherwise fall back to `k = 0` when zero aligns at least one, and to `None`
/// when it does not. With a single decompiled offset there is nothing to
/// corroborate against, so the guard does not apply and a lone alignment is
/// accepted.
///
/// **Reference quirk, reproduced deliberately.** The guard's "at least two
/// decompiled offsets" test is `len(decomp_offsets)` in the reference --- the
/// *list* length, duplicates included --- while the count it is compared
/// against is over the deduplicated set. So `gt = [-16]`, `decomp = [-8, -8]`
/// is one distinct slot described twice, but the guard treats it as two
/// variables, demands two alignments, gets one, and returns `None`; the same
/// input written as `decomp = [-8]` returns `Some(-8)`. This is a bug in the
/// reference and it is preserved here, because a metric port that disagrees
/// with the metric is not a port. `calibrate_duplicate_decompiled_offsets_
/// trip_the_guard` in this module's tests pins it.
///
/// **Second reference finding: the guard's own zero fallback is dead code.**
/// The guard fires only when the winner is nonzero and aligns exactly one
/// offset. But `k = 0` is always a candidate, so if it aligned one offset too
/// it would tie the winner on count and take the tie-break on `|k|` --- a
/// nonzero winner at count one therefore *implies* that zero aligns nothing,
/// which is exactly the `zero_count` the fallback goes on to test. So
/// `return 0 if zero_count >= 1` can never fire, and the guard always yields
/// `None`. Every `Some(0)` this function returns comes from zero winning the
/// argmax outright, never from the fallback. The branch is kept here anyway,
/// verbatim, because removing it would be an edit to the reference rather
/// than a port of it; `calibrate_guard_never_reaches_its_own_zero_fallback`
/// in this module's tests pins the reasoning.
///
/// # Complexity
///
/// `O(|G| · |D|)` time and space, over the deduplicated inputs, via the
/// **mode of the difference multiset** --- not the naive `O(|G| · |D|²)` of
/// enumerating the `|G| · |D|` candidates and rescoring all `|D|` offsets
/// against each.
///
/// The two are equivalent, and the reason is that `d ↦ d + k` is injective.
/// Write `Ĝ` and `D̂` for the deduplicated inputs. For a fixed `k`,
///
/// ```text
///   count(k) = |{d + k : d ∈ D̂} ∩ Ĝ|
///            = |{d ∈ D̂ : d + k ∈ Ĝ}|          (injectivity: no two d collide)
///            = |{(g, d) ∈ Ĝ × D̂ : g - d = k}| (each such d pairs with one g)
/// ```
///
/// --- the last line being precisely the multiplicity of `k` in the multiset
/// of differences `{g - d}`. So a single pass over `Ĝ × D̂` incrementing
/// `counts[g - d]` computes `count(k)` for *every* candidate `k`
/// simultaneously. The keys with nonzero count are exactly the reference's
/// candidate set minus the shifts that align nothing, and a shift that aligns
/// nothing can never win (the reference's incumbent starts at count zero and
/// is replaced only on a strictly greater count, so `k = 0` with `count(0) = 0`
/// never becomes the winner either --- which is why `0` needs no special
/// insertion here, only the `None` result it produces).
///
/// Space is the same bound: at most `|Ĝ| · |D̂|` map entries. For the sizes
/// this metric sees --- stack slots in one function, tens at most --- that is
/// nothing; a pathological ten-thousand-offset function would cost on the
/// order of a gigabyte, which is a bound worth knowing but not one worth
/// capping against the reference's behaviour.
pub fn calibrate_shift(gt_offsets: &[i64], decomp_offsets: &[i64]) -> Option<Shift> {
    if gt_offsets.is_empty() || decomp_offsets.is_empty() {
        return None;
    }

    let gt_unique = unique_sorted(gt_offsets);
    let decomp_unique = unique_sorted(decomp_offsets);

    // Mode of the difference multiset: one pass, every candidate scored. See
    // the "Complexity" section above for why this equals the reference's
    // per-candidate rescan.
    let mut counts: HashMap<Shift, u64> = HashMap::new();
    for &g in &gt_unique {
        for &d in &decomp_unique {
            *counts
                .entry(Shift::from(g) - Shift::from(d))
                .or_insert(0_u64) += 1;
        }
    }

    // Chosen by a strict total order, so the `HashMap`'s iteration order is
    // irrelevant to the answer (`REQ-SYN-5`).
    let mut best: Option<(u64, Shift)> = None;
    for (&k, &count) in counts.iter() {
        let candidate = (count, k);
        if best.is_none_or(|incumbent| candidate.beats(&incumbent)) {
            best = Some(candidate);
        }
    }

    let (best_count, best_k) = best?;
    if best_count == 0 {
        return None;
    }

    // The two-alignment guard. `decomp_offsets.len()` is the raw list length,
    // duplicates included, exactly as the reference has it -- see "Reference
    // quirk" above.
    if best_k != 0 && decomp_offsets.len() >= 2 && best_count < 2 {
        let zero_count = aligned_count(gt_offsets, decomp_offsets, 0);
        return if zero_count >= 1 { Some(0) } else { None };
    }

    Some(best_k)
}

/// The candidate shifts the binary-wide calibrator votes over: `-32..=32`,
/// ordered by increasing `|k|` and, within a magnitude, negative first.
///
/// The window is fixed *on purpose*, and it is the one place the binary-wide
/// calibrator deliberately differs from [`calibrate_shift`]'s uncapped search.
/// A binary-wide shift is a claim about a decompiler's whole frame convention,
/// so it should only ever be a small ABI-scale constant; leaving the candidate
/// set adaptive would let one large coincidental difference from one function
/// win a vote it has no business winning. A genuinely large per-function gap
/// --- IDA's frame-bottom numbering --- is handled per function instead, by
/// the caller overriding the binary-wide shift when the per-function one
/// aligns strictly more.
///
/// The order matches the reference's `sorted(range(-32, 33), key=(abs, x))`.
/// It does not affect which candidate wins (that is [`Better::beats`]) but it
/// is kept because the reference's fallback chain reads in terms of it.
fn multi_candidates() -> Vec<Shift> {
    let mut out: Vec<Shift> = Vec::with_capacity(65);
    out.push(0);
    for magnitude in 1..=32_i128 {
        out.push(-magnitude);
        out.push(magnitude);
    }
    out
}

/// One function's contribution to the binary-wide vote, prepared once.
///
/// Holds the ground-truth offsets as a lookup set and the decompiled offsets
/// deduplicated, so that scoring all sixty-five candidate shifts costs one
/// pass over the offsets each rather than rebuilding both collections
/// sixty-five times as the reference does.
struct VotingFunction {
    /// Ground-truth stack offsets for this function, as a membership set.
    gt_offsets: HashSet<i64>,
    /// Decompiled stack offsets for this function, deduplicated and sorted.
    decomp_offsets: Vec<i64>,
}

impl VotingFunction {
    /// How many distinct decompiled offsets match a ground-truth offset for
    /// this function under `shift`.
    fn matches(&self, shift: Shift) -> u64 {
        self.decomp_offsets
            .iter()
            .filter(|&&d| shifted_hits(&self.gt_offsets, d, shift))
            .count() as u64
    }
}

/// Calibrate one additive shift across many functions of a binary, or `None`
/// if nothing aligns anywhere.
///
/// Each pair is one function's `(ground_truth_offsets, decompiled_offsets)`.
/// Pairs with an empty side are dropped first, as they carry no information
/// and the reference drops them too. Generic over anything slice-like so a
/// caller can pass `&[(Vec<i64>, Vec<i64>)]` (the shape named in the component
/// inventory) or borrowed slices without copying.
///
/// Two things differ from [`calibrate_shift`], both deliberate:
///
/// * **The candidate window is fixed at ±32** rather than adaptive --- see
///   `multi_candidates` for why a binary-wide claim must not be allowed to
///   ride on one function's coincidental large difference.
/// * **Each function votes `max(0, matches - 1)`**, not `matches`. The
///   discount is the binary-wide analogue of the per-function two-alignment
///   guard: a lone slot that happens to line up under some shift contributes
///   nothing, while a function whose several slots all line up --- which is
///   what a real ABI-constant shift looks like --- contributes for each one
///   past the first. Summed over a binary, the real shift pulls away from the
///   coincidences.
///
/// **The fallback chain, which is load-bearing.** Discounted voting says
/// nothing at all about a binary whose every function has exactly one stack
/// variable: every function votes zero, no shift is chosen, and abstaining
/// there would throw away real signal. So:
///
/// 1. Take the shift with the most discounted votes. If any shift scored a
///    discounted vote at all, return it, full stop --- no further checks.
/// 2. Otherwise re-vote with plain match counts.
/// 3. If that also finds nothing (or a best of zero), return `None`.
/// 4. If the plain-count winner is nonzero, prefer `0` whenever `0` aligns at
///    least one offset anywhere, and otherwise require the winner to have at
///    least two plain matches. Only a winner clearing both hurdles is
///    returned.
///
/// Step 4's preference for `0` is strong: it applies even when a nonzero shift
/// scored strictly more plain matches. That is intentional in the reference
/// --- in the fallback regime the evidence is by construction one slot per
/// function, and "the decompiler agrees with DWARF" is a better explanation of
/// a single coincidence than "the decompiler is shifted by seven".
pub fn calibrate_shift_multi<G, D>(pairs: &[(G, D)]) -> Option<Shift>
where
    G: AsRef<[i64]>,
    D: AsRef<[i64]>,
{
    let functions: Vec<VotingFunction> = pairs
        .iter()
        .filter_map(|(gt, decomp)| {
            let gt = gt.as_ref();
            let decomp = decomp.as_ref();
            if gt.is_empty() || decomp.is_empty() {
                return None;
            }
            Some(VotingFunction {
                gt_offsets: gt.iter().copied().collect(),
                decomp_offsets: unique_sorted(decomp),
            })
        })
        .collect();
    if functions.is_empty() {
        return None;
    }

    let candidates = multi_candidates();

    // Step 1: discounted voting. `saturating_sub` is the `max(0, ...)`; the
    // sum cannot overflow `u64` because it is bounded by the total number of
    // decompiled offsets.
    let mut best: Option<(u64, Shift)> = None;
    for &k in &candidates {
        let votes: u64 = functions
            .iter()
            .map(|f| f.matches(k).saturating_sub(1))
            .sum();
        if votes > 0 && best.is_none_or(|incumbent| (votes, k).beats(&incumbent)) {
            best = Some((votes, k));
        }
    }
    if let Some((_, best_k)) = best {
        return Some(best_k);
    }

    // Step 2: plain-count fallback, for the binary whose functions each have a
    // single stack variable.
    let mut best: Option<(u64, Shift)> = None;
    for &k in &candidates {
        let votes: u64 = functions.iter().map(|f| f.matches(k)).sum();
        if votes > 0 && best.is_none_or(|incumbent| (votes, k).beats(&incumbent)) {
            best = Some((votes, k));
        }
    }

    // Step 3.
    let (best_votes, best_k) = best?;
    if best_votes == 0 {
        return None;
    }

    // Step 4.
    if best_k != 0 {
        let zero_votes: u64 = functions.iter().map(|f| f.matches(0)).sum();
        if zero_votes >= 1 {
            return Some(0);
        }
        if best_votes < 2 {
            return None;
        }
    }

    Some(best_k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligned_count_collapses_duplicates_on_both_sides() {
        assert_eq!(aligned_count(&[-8, -8, -16], &[-8, -8], 0), 1);
        assert_eq!(aligned_count(&[-8, -16], &[-8, -16], 0), 2);
        assert_eq!(aligned_count(&[], &[-8], 0), 0);
        assert_eq!(aligned_count(&[-8], &[], 0), 0);
    }

    #[test]
    fn aligned_count_shift_out_of_i64_range_misses() {
        assert_eq!(aligned_count(&[0], &[i64::MAX], 1), 0);
        assert_eq!(aligned_count(&[0], &[i64::MIN], -1), 0);
    }

    #[test]
    fn calibrate_exact_zero_shift() {
        let gt = [-8_i64, -16, -24, -32];
        assert_eq!(calibrate_shift(&gt, &gt), Some(0));
    }

    #[test]
    fn calibrate_constant_nonzero_shift() {
        let gt = [-8_i64, -16, -24, -32];
        let decomp: Vec<i64> = gt.iter().map(|o| o + 96).collect();
        assert_eq!(calibrate_shift(&gt, &decomp), Some(-96));
    }

    #[test]
    fn calibrate_shift_is_uncapped() {
        // A frame-bottom-relative convention, far outside any fixed window.
        let gt = [-8_i64, -16, -24];
        let decomp: Vec<i64> = gt.iter().map(|o| o + 4096).collect();
        assert_eq!(calibrate_shift(&gt, &decomp), Some(-4096));
    }

    #[test]
    fn calibrate_two_alignment_guard_rejects_a_spurious_single_match() {
        // -100 is nowhere near the ground truth; the only shift that aligns
        // anything aligns exactly one of the two decompiled offsets, and with
        // two decompiled offsets present that is not enough.
        let gt = [-8_i64, -16];
        let decomp = [-100_i64, -200];
        // k = 92 aligns -100 -> -8; k = 192 aligns -200 -> -8; none aligns two.
        assert_eq!(calibrate_shift(&gt, &decomp), None);
    }

    #[test]
    fn calibrate_falls_back_to_zero_when_nothing_beats_it() {
        // The observable "fall back to zero" behaviour: several candidates all
        // align exactly one offset, and the tie-break hands it to k = 0, which
        // is a real alignment. The guard never fires because the winner is 0.
        let gt = [-8_i64, -4096];
        let decomp = [-8_i64, -12];
        // k = 0 aligns -8; k = -4084 aligns -12 -> -4096; k = 4 aligns
        // -12 -> -8. All score 1, so the smallest |k| (0) wins.
        assert_eq!(calibrate_shift(&gt, &decomp), Some(0));

        let gt = [-8_i64, -16];
        let decomp = [-8_i64, -1000];
        assert_eq!(calibrate_shift(&gt, &decomp), Some(0));

        let gt = [-16_i64];
        let decomp = [-16_i64, -1000];
        assert_eq!(calibrate_shift(&gt, &decomp), Some(0));
    }

    #[test]
    fn calibrate_guard_never_reaches_its_own_zero_fallback() {
        // A second reference finding, pinned rather than fixed: the guard's
        // `return 0 if zero_count >= 1 else None` can only ever return None.
        //
        // The guard fires when the winner is nonzero and aligns exactly one
        // offset. But k = 0 is always a candidate, and if it too aligned one
        // offset it would tie the winner on count and win the tie-break on
        // |k|. So a nonzero winner at count 1 *implies* count(0) == 0, which
        // is exactly the zero_count the fallback then tests. The branch that
        // returns Some(0) is therefore dead code in the reference.
        //
        // This sweeps a wide space of two-offset inputs and asserts the guard
        // never produces Some(0): whenever the result is Some(0), zero was the
        // outright winner and the guard was not entered at all.
        for g0 in -64_i64..=64 {
            for d0 in [-1000_i64, -33, -8, 0, 7, 4096] {
                let gt = [g0, g0 - 8];
                let decomp = [d0, d0 - 1000];
                let k = calibrate_shift(&gt, &decomp);
                if let Some(k) = k {
                    let count = aligned_count(&gt, &decomp, k);
                    // Either the winner aligned two, or it is zero (which the
                    // guard exempts), or there was a single decompiled offset.
                    assert!(
                        count >= 2 || k == 0,
                        "guard admitted k={k} at count {count} for gt={gt:?} decomp={decomp:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn calibrate_duplicate_decompiled_offsets_trip_the_guard() {
        // The reference quirk, pinned. One distinct decompiled slot, listed
        // twice: `len(decomp_offsets) >= 2` is satisfied by the duplicate, the
        // count is over the deduplicated set and so is 1, the guard demands 2,
        // and zero aligns nothing -- so a calibration that plainly exists is
        // reported as no alignment.
        assert_eq!(calibrate_shift(&[-16], &[-8, -8]), None);
        // The same input without the duplicate calibrates fine.
        assert_eq!(calibrate_shift(&[-16], &[-8]), Some(-8));
    }

    #[test]
    fn calibrate_no_alignment_at_all() {
        // A single decompiled offset always has *some* aligning shift, so "no
        // alignment" needs the guard: two offsets, no shift aligning two, and
        // zero aligning none.
        assert_eq!(calibrate_shift(&[100, 200], &[-8, -1000]), None);
    }

    #[test]
    fn calibrate_empty_inputs_on_either_side() {
        assert_eq!(calibrate_shift(&[], &[]), None);
        assert_eq!(calibrate_shift(&[-8], &[]), None);
        assert_eq!(calibrate_shift(&[], &[-8]), None);
    }

    #[test]
    fn calibrate_single_offset_each_side() {
        // One offset each: the guard does not apply, so the exact difference
        // is accepted however large it is.
        assert_eq!(calibrate_shift(&[-8], &[-8]), Some(0));
        assert_eq!(calibrate_shift(&[-8], &[120]), Some(-128));
        assert_eq!(
            calibrate_shift(&[1_000_000], &[-1_000_000]),
            Some(2_000_000)
        );
    }

    #[test]
    fn calibrate_at_the_integer_extremes_does_not_overflow() {
        // `g - d` here is 2^64 - 1, which does not fit in i64. The reference
        // has bignums and returns it; so do we.
        assert_eq!(
            calibrate_shift(&[i64::MAX], &[i64::MIN]),
            Some(Shift::from(i64::MAX) - Shift::from(i64::MIN))
        );
        assert_eq!(
            calibrate_shift(&[i64::MIN], &[i64::MAX]),
            Some(Shift::from(i64::MIN) - Shift::from(i64::MAX))
        );
        assert_eq!(calibrate_shift(&[i64::MIN], &[i64::MIN]), Some(0));
        assert_eq!(calibrate_shift(&[i64::MAX], &[i64::MAX]), Some(0));
        // Two extremes on each side: zero aligns both, and beats everything.
        assert_eq!(
            calibrate_shift(&[i64::MIN, i64::MAX], &[i64::MIN, i64::MAX]),
            Some(0)
        );
    }

    #[test]
    fn calibrate_ties_resolve_to_the_smallest_magnitude_then_negative() {
        // Smallest magnitude: -4 and 96 both align two offsets; -4 wins.
        assert_eq!(calibrate_shift(&[0, 8, 100, 108], &[4, 12]), Some(-4));
        // Equal magnitude: -5 and +5 both align three offsets; -5 wins,
        // matching the reference's `sorted(key=(abs(x), x))`.
        assert_eq!(calibrate_shift(&[0, 10, 20, 30], &[5, 15, 25]), Some(-5));
        // Single decompiled offset: the guard does not apply, so the tie
        // between -4 and +4 is decided on sign alone.
        assert_eq!(calibrate_shift(&[0, 8], &[4]), Some(-4));
    }

    #[test]
    fn calibrate_thousands_of_offsets() {
        // The difference multiset is |G| * |D| entries, so this allocates on
        // the order of a million map slots. That is the documented space
        // bound, exercised here to prove it terminates rather than panics.
        let gt: Vec<i64> = (0..1_000).map(|i| -8 * i).collect();
        let decomp: Vec<i64> = gt.iter().map(|o| o + 512).collect();
        assert_eq!(calibrate_shift(&gt, &decomp), Some(-512));
    }

    #[test]
    fn multi_empty_and_degenerate_inputs() {
        let empty: [(Vec<i64>, Vec<i64>); 0] = [];
        assert_eq!(calibrate_shift_multi(&empty), None);
        assert_eq!(calibrate_shift_multi(&[(vec![], vec![-8_i64])]), None);
        assert_eq!(calibrate_shift_multi(&[(vec![-8_i64], vec![])]), None);
    }

    #[test]
    fn multi_finds_a_constant_shift_inside_the_window() {
        let pairs = vec![
            (vec![-8_i64, -16, -24], vec![0_i64, -8, -16]),
            (vec![-8_i64, -16], vec![0_i64, -8]),
        ];
        assert_eq!(calibrate_shift_multi(&pairs), Some(-8));
    }

    #[test]
    fn multi_window_excludes_a_larger_true_shift() {
        // The true shift is -96, well outside +-32. Nothing inside the window
        // aligns anything, so the binary-wide calibrator abstains rather than
        // inventing a small shift -- the per-function calibrator is what
        // recovers this case.
        let pairs = vec![
            (vec![-8_i64, -16, -24], vec![88_i64, 80, 72]),
            (vec![-8_i64, -16], vec![88_i64, 80]),
        ];
        assert_eq!(calibrate_shift(&[-8, -16, -24], &[88, 80, 72]), Some(-96));
        assert_eq!(calibrate_shift_multi(&pairs), None);
    }

    #[test]
    fn multi_discounted_vote_ignores_single_slot_functions() {
        // Three functions with one slot each, all aligning at k = 5, plus one
        // two-slot function aligning at k = 0. Discounted voting sees only the
        // two-slot function (the singletons vote max(0, 1 - 1) = 0), so 0 wins
        // even though 5 has more plain matches.
        let pairs = vec![
            (vec![0_i64], vec![-5_i64]),
            (vec![8_i64], vec![3_i64]),
            (vec![16_i64], vec![11_i64]),
            (vec![-100_i64, -108], vec![-100_i64, -108]),
        ];
        assert_eq!(calibrate_shift_multi(&pairs), Some(0));
    }

    #[test]
    fn multi_falls_back_to_plain_counting_then_prefers_zero() {
        // Every function has one slot, so no shift earns a discounted vote.
        // Plain counting gives k = 5 three matches and k = 0 one; step 4's
        // preference for zero returns 0 anyway.
        let pairs = vec![
            (vec![0_i64], vec![-5_i64]),
            (vec![8_i64], vec![3_i64]),
            (vec![16_i64], vec![11_i64]),
            (vec![-64_i64], vec![-64_i64]),
        ];
        assert_eq!(calibrate_shift_multi(&pairs), Some(0));
    }

    #[test]
    fn multi_plain_fallback_returns_a_nonzero_shift_when_zero_aligns_nothing() {
        // Single-slot functions only, zero aligns none, and k = 5 aligns two
        // -- clearing step 4's "at least two plain matches" hurdle.
        let pairs = vec![(vec![0_i64], vec![-5_i64]), (vec![8_i64], vec![3_i64])];
        assert_eq!(calibrate_shift_multi(&pairs), Some(5));
    }

    #[test]
    fn multi_plain_fallback_abstains_on_a_lone_nonzero_match() {
        // One single-slot function, aligning only at k = 5: one plain match,
        // zero aligns nothing, `best_votes < 2` -- abstain.
        let pairs = vec![(vec![0_i64], vec![-5_i64])];
        assert_eq!(calibrate_shift_multi(&pairs), None);
    }

    #[test]
    fn multi_at_the_integer_extremes_does_not_overflow() {
        let pairs = vec![
            (vec![i64::MAX, i64::MIN], vec![i64::MAX, i64::MIN]),
            (vec![i64::MIN], vec![i64::MAX]),
        ];
        assert_eq!(calibrate_shift_multi(&pairs), Some(0));

        // Every shift in the window carries i64::MAX out of range; nothing
        // aligns, and no panic.
        let pairs = vec![(vec![i64::MIN], vec![i64::MAX])];
        assert_eq!(calibrate_shift_multi(&pairs), None);
    }

    #[test]
    fn multi_accepts_borrowed_slices() {
        let gt: &[i64] = &[-8, -16];
        let decomp: &[i64] = &[0, -8];
        assert_eq!(calibrate_shift_multi(&[(gt, decomp)]), Some(-8));
    }

    /// Runs the reference Python (`_calibrate_shift` and
    /// `_calibrate_shift_multi`) over a seeded random corpus and asserts this
    /// module agrees with it on every case. Requires the DecBench checkout;
    /// skips cleanly (passing) when it is not present, per this repo's rule
    /// against depending on an out-of-repo checkout in a committed test.
    #[test]
    fn differential_against_live_decbench_python() {
        differential::run();
    }

    /// Isolated so `differential_against_live_decbench_python` stays short;
    /// see its doc for what this proves.
    mod differential {
        use super::super::{calibrate_shift, calibrate_shift_multi, Shift};
        use std::path::PathBuf;
        use std::process::Command;

        /// Number of single-function cases the differential generates.
        const SINGLE_CASES: usize = 3_000;
        /// Number of binary-wide (multi-function) cases the differential
        /// generates.
        const MULTI_CASES: usize = 800;

        /// SplitMix64, so the corpus is reproducible without a dependency.
        ///
        /// A fixed seed is the point: a differential that regenerates a
        /// different corpus each run cannot be bisected when it fails.
        struct SplitMix64(u64);

        impl SplitMix64 {
            fn next_u64(&mut self) -> u64 {
                self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^ (z >> 31)
            }

            /// A value strictly below `bound`, or `0` when `bound` is `0`.
            fn below(&mut self, bound: u64) -> u64 {
                if bound == 0 {
                    0
                } else {
                    self.next_u64() % bound
                }
            }
        }

        fn decbench_dir() -> PathBuf {
            std::env::var("DECBENCH_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/nas4/data/workspace-infosec/decbench"))
        }

        fn scratch_dir() -> PathBuf {
            let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
            let dir = PathBuf::from(base).join("glaurung-calibrate-differential");
            let _ = std::fs::create_dir_all(&dir);
            dir
        }

        /// Generates one function's `(ground_truth_offsets,
        /// decompiled_offsets)` pair, drawn from the shapes calibration
        /// actually meets plus the degenerate ones that break naive ports.
        ///
        /// The realistic shape is the common case: a handful of negative
        /// offsets a few bytes apart, the decompiled side the same set under a
        /// constant shift, with some slots dropped, some invented, and some
        /// perturbed. The rest are the edges --- empty sides, singletons,
        /// duplicates (which trip the reference's guard quirk), and values at
        /// `i64::MIN`/`i64::MAX` where `g - d` leaves `i64`.
        fn generate_pair(rng: &mut SplitMix64) -> (Vec<i64>, Vec<i64>) {
            match rng.below(10) {
                0 => (Vec::new(), Vec::new()),
                1 => {
                    // One side empty.
                    if rng.below(2) == 0 {
                        (Vec::new(), vec![-(8 * (1 + rng.below(8) as i64))])
                    } else {
                        (vec![-(8 * (1 + rng.below(8) as i64))], Vec::new())
                    }
                }
                2 => {
                    // Singletons.
                    let g = -(8 * (1 + rng.below(16) as i64));
                    let d = g + rng.below(200) as i64 - 100;
                    (vec![g], vec![d])
                }
                3 => {
                    // Integer extremes.
                    let pool = [
                        i64::MIN,
                        i64::MIN + 1,
                        i64::MIN + 8,
                        -1,
                        0,
                        1,
                        i64::MAX - 8,
                        i64::MAX - 1,
                        i64::MAX,
                    ];
                    fn take(rng: &mut SplitMix64, pool: &[i64]) -> Vec<i64> {
                        let n = 1 + rng.below(3) as usize;
                        (0..n)
                            .map(|_| pool[rng.below(pool.len() as u64) as usize])
                            .collect()
                    }
                    let gt = take(rng, &pool);
                    let decomp = take(rng, &pool);
                    (gt, decomp)
                }
                4 => {
                    // Heavy duplicates, to exercise the list-length guard.
                    let base = -(8 * (1 + rng.below(8) as i64));
                    let n = 1 + rng.below(4) as usize;
                    let gt = vec![base; n];
                    let shift = rng.below(64) as i64 - 32;
                    let m = 1 + rng.below(4) as usize;
                    (gt, vec![base - shift; m])
                }
                _ => {
                    // The realistic shape.
                    let count = 1 + rng.below(8) as usize;
                    let mut gt: Vec<i64> = Vec::with_capacity(count);
                    let mut next = -(rng.below(4) as i64 * 8) - 4;
                    for _ in 0..count {
                        gt.push(next);
                        next -= 1 + rng.below(24) as i64;
                    }
                    // Small window shifts most of the time; a frame-bottom
                    // sized one sometimes, to exercise the uncapped search.
                    let shift: i64 = match rng.below(4) {
                        0 => 0,
                        1 => rng.below(65) as i64 - 32,
                        2 => rng.below(4096) as i64,
                        _ => rng.below(9) as i64 - 4,
                    };
                    let mut decomp: Vec<i64> = Vec::new();
                    for &g in &gt {
                        match rng.below(8) {
                            0 => {}                                                // dropped slot
                            1 => decomp.push(g - shift + 1 + rng.below(3) as i64), // perturbed
                            _ => decomp.push(g - shift),
                        }
                    }
                    // Noise the decompiler invented.
                    for _ in 0..rng.below(3) {
                        decomp.push(rng.below(512) as i64 - 256);
                    }
                    (gt, decomp)
                }
            }
        }

        /// A binary in which every function has exactly one stack slot.
        ///
        /// This shape is what forces `calibrate_shift_multi` past discounted
        /// voting (every function votes `max(0, 1 - 1) = 0`) and into the
        /// plain-count fallback and its tie-break against zero. A corpus of
        /// only mixed-arity binaries never reaches that branch, so the
        /// differential would be blind to it -- measured: patching step 4's
        /// `zero_votes >= 1` to `zero_votes >= best_votes` changed nothing
        /// until this shape was added.
        fn generate_single_slot_binary(rng: &mut SplitMix64) -> Vec<(Vec<i64>, Vec<i64>)> {
            let n = 1 + rng.below(6) as usize;
            // One shared small shift most functions obey, plus stragglers, so
            // that zero and the shared shift genuinely compete.
            let shared = rng.below(9) as i64 - 4;
            (0..n)
                .map(|_| {
                    let g = -(8 * (1 + rng.below(12) as i64));
                    let k = match rng.below(4) {
                        0 => 0,
                        1 => rng.below(9) as i64 - 4,
                        _ => shared,
                    };
                    (vec![g], vec![g - k])
                })
                .collect()
        }

        /// A binary whose functions all share one shift, drawn from a range
        /// that straddles the +-32 window.
        ///
        /// This shape probes the window boundary directly: the same corpus
        /// then contains binaries whose true shift the binary-wide calibrator
        /// must find and binaries whose true shift it must refuse to find.
        /// Measured: widening the window to +-64 disagreed on 1 case without
        /// this shape and on many more with it.
        fn generate_shared_shift_binary(rng: &mut SplitMix64) -> Vec<(Vec<i64>, Vec<i64>)> {
            let shift = rng.below(161) as i64 - 80;
            let n = 1 + rng.below(5) as usize;
            (0..n)
                .map(|_| {
                    let slots = 1 + rng.below(5) as usize;
                    let mut gt: Vec<i64> = Vec::with_capacity(slots);
                    let mut next = -8_i64;
                    for _ in 0..slots {
                        gt.push(next);
                        next -= 1 + rng.below(16) as i64;
                    }
                    let decomp: Vec<i64> = gt.iter().map(|g| g - shift).collect();
                    (gt, decomp)
                })
                .collect()
        }

        /// The corpus: single-function cases and binary-wide cases, from one
        /// fixed seed.
        #[allow(clippy::type_complexity)]
        fn generate_corpus() -> (Vec<(Vec<i64>, Vec<i64>)>, Vec<Vec<(Vec<i64>, Vec<i64>)>>) {
            let mut rng = SplitMix64(0x5EED_CA11_B4A7_E000);
            let singles: Vec<(Vec<i64>, Vec<i64>)> =
                (0..SINGLE_CASES).map(|_| generate_pair(&mut rng)).collect();
            let multis: Vec<Vec<(Vec<i64>, Vec<i64>)>> = (0..MULTI_CASES)
                .map(|_| {
                    if rng.below(3) == 0 {
                        generate_single_slot_binary(&mut rng)
                    } else if rng.below(2) == 0 {
                        generate_shared_shift_binary(&mut rng)
                    } else {
                        let n = rng.below(7) as usize;
                        (0..n).map(|_| generate_pair(&mut rng)).collect()
                    }
                })
                .collect();
            (singles, multis)
        }

        /// The reference Python's results for the whole corpus, or `None`
        /// when the DecBench checkout/venv is not available.
        ///
        /// Shifts cross the process boundary as decimal *strings*, not JSON
        /// numbers: a shift can exceed `i64` (see [`Shift`]) and JSON numbers
        /// of that magnitude are not portable across the two parsers.
        fn python_results(
            singles: &[(Vec<i64>, Vec<i64>)],
            multis: &[Vec<(Vec<i64>, Vec<i64>)>],
        ) -> Option<(Vec<Option<Shift>>, Vec<Option<Shift>>)> {
            let decbench_dir = decbench_dir();
            let python = decbench_dir.join(".venv").join("bin").join("python");
            if !python.is_file() {
                return None;
            }

            let dir = scratch_dir();
            let input_path = dir.join("cases.json");
            let output_path = dir.join("results.json");

            let input = serde_json::json!({ "singles": singles, "multis": multis });
            std::fs::write(&input_path, serde_json::to_string(&input).ok()?).ok()?;

            let script = r#"
import json
import sys

from decbench.metrics.type_match import _calibrate_shift, _calibrate_shift_multi

with open(sys.argv[1]) as f:
    cases = json.load(f)

singles = [
    None if _calibrate_shift(g, d) is None else str(_calibrate_shift(g, d))
    for g, d in cases["singles"]
]
multis = []
for group in cases["multis"]:
    pairs = [(g, d) for g, d in group]
    k = _calibrate_shift_multi(pairs)
    multis.append(None if k is None else str(k))

with open(sys.argv[2], "w") as f:
    json.dump({"singles": singles, "multis": multis}, f)
"#;

            let output = Command::new(&python)
                .arg("-c")
                .arg(script)
                .arg(&input_path)
                .arg(&output_path)
                .env("PYTHONPATH", &decbench_dir)
                .output();

            let output = match output {
                Ok(o) => o,
                Err(_) => return None,
            };
            if !output.status.success() {
                eprintln!(
                    "reference python invocation failed: stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                return None;
            }

            let raw = std::fs::read_to_string(&output_path).ok()?;
            let parsed: std::collections::BTreeMap<String, Vec<Option<String>>> =
                serde_json::from_str(&raw).ok()?;
            let decode = |v: &Vec<Option<String>>| -> Vec<Option<Shift>> {
                v.iter()
                    .map(|s| {
                        s.as_ref()
                            .map(|s| s.parse::<Shift>().expect("shift parses"))
                    })
                    .collect()
            };
            Some((
                decode(parsed.get("singles")?),
                decode(parsed.get("multis")?),
            ))
        }

        pub(super) fn run() {
            let (singles, multis) = generate_corpus();
            let Some((python_singles, python_multis)) = python_results(&singles, &multis) else {
                eprintln!(
                    "SKIP differential_against_live_decbench_python: DecBench checkout not \
                     found (looked for {:?}); this is expected outside the environment that \
                     has /nas4 mounted",
                    decbench_dir().join(".venv").join("bin").join("python")
                );
                return;
            };

            assert_eq!(python_singles.len(), singles.len());
            assert_eq!(python_multis.len(), multis.len());

            let mut compared: u64 = 0;
            let mut agreeing: u64 = 0;
            let mut mismatches: Vec<String> = Vec::new();
            // Outcome breakdown, so that "N agreeing" cannot be satisfied by a
            // corpus on which both sides trivially abstain everywhere.
            let mut abstained: u64 = 0;
            let mut zero: u64 = 0;
            let mut nonzero_small: u64 = 0;
            let mut nonzero_large: u64 = 0;
            let mut tally = |k: Option<Shift>| match k {
                None => abstained += 1,
                Some(0) => zero += 1,
                Some(k) if k.abs() <= 32 => nonzero_small += 1,
                Some(_) => nonzero_large += 1,
            };

            for (case, expected) in singles.iter().zip(&python_singles) {
                let (gt, decomp) = case;
                let rust = calibrate_shift(gt, decomp);
                tally(rust);
                compared += 1;
                if rust == *expected {
                    agreeing += 1;
                } else if mismatches.len() < 20 {
                    mismatches.push(format!(
                        "calibrate_shift(gt={gt:?}, decomp={decomp:?}): \
                         rust={rust:?} python={expected:?}"
                    ));
                }
            }

            for (case, expected) in multis.iter().zip(&python_multis) {
                let rust = calibrate_shift_multi(case);
                tally(rust);
                compared += 1;
                if rust == *expected {
                    agreeing += 1;
                } else if mismatches.len() < 20 {
                    mismatches.push(format!(
                        "calibrate_shift_multi({case:?}): rust={rust:?} python={expected:?}"
                    ));
                }
            }

            drop(tally);
            println!(
                "calibrate differential: {} cases compared ({} single-function, \
                 {} binary-wide), {} agreeing, {} disagreeing; outcomes: \
                 {} abstain, {} zero, {} nonzero |k| <= 32, {} nonzero |k| > 32",
                compared,
                singles.len(),
                multis.len(),
                agreeing,
                compared - agreeing,
                abstained,
                zero,
                nonzero_small,
                nonzero_large,
            );

            // The corpus must actually exercise the interesting outcomes; a
            // differential that only ever compares `None` proves nothing.
            assert!(abstained > 100, "corpus produced too few abstentions");
            assert!(zero > 100, "corpus produced too few zero shifts");
            assert!(
                nonzero_small > 100,
                "corpus produced too few small nonzero shifts"
            );
            assert!(
                nonzero_large > 100,
                "corpus produced too few frame-sized shifts"
            );

            for line in &mismatches {
                eprintln!("mismatch: {line}");
            }

            assert!(
                mismatches.is_empty() && agreeing == compared,
                "{} of {} cases disagreed with the live reference",
                compared - agreeing,
                compared
            );
        }
    }
}
