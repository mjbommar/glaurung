//! `T-3`, `T-6`, `T-7` --- width-only matching, three-pass greedy assignment,
//! and the type-recovery score.
//!
//! Spec: `docs/design/static-c-analysis/implementation-inventory.md` section 5.
//!
//! This is the decision half of DecBench's `type_match`: given a function's
//! ground-truth variables and a decompiler's recovered variables, decide which
//! recovered variable stands for which ground-truth variable, decide whether
//! each such pair agrees on the type, and turn the resulting counts into a
//! score. It ports `_match_structured`, `_uncommitted_size`'s consumer side,
//! `_effective_offset`, `_build_result`'s arithmetic and
//! `_calibrate_binary_shift` from DecBench's `decbench/metrics/type_match.py`.
//!
//! It sits on top of the two components that already landed:
//!
//! * [`crate::metrics::type_name`] (`T-2`, and `T-3`'s tables) turns a type
//!   spelling into the set of spellings it is equivalent to, and knows which
//!   spellings are "uncommitted" --- width-only placeholders like
//!   `undefined4`, `_DWORD` or `int4`.
//! * [`crate::metrics::calibrate`] (`T-4`, `T-5`) finds the additive constant
//!   that reconciles a decompiler's stack-offset convention with DWARF's.
//!
//! # What this module deliberately does not do
//!
//! **`T-1`, the DWARF walk, is not here and is not a prerequisite for
//! trusting what is.** Ground truth arrives as a plain `[GroundTruthVar]`
//! slice, so this module has no dependency on `gimli`, on a loaded image, or
//! on any particular debug format; `T-1` layers on top by producing that
//! slice, and can be written, tested and replaced without touching a line
//! below. The same is true on the other side: a [`DecompiledVar`] is whatever
//! the caller's front end recovered. `T-8`, the signature-text fallback that
//! parses variables out of emitted C when a backend exposes no structured
//! ones, is likewise a *producer* of `DecompiledVar`s and is not implemented
//! here.
//!
//! Nor is the aggregation layer (`S-1`..`S-4`): this module scores one
//! function and reports the counts it scored from. In particular a function
//! with no ground-truth variables is not scored at all by the reference ---
//! its binary-level loop skips it before the denominator is formed --- so
//! [`FunctionTypeMatch::score`] returning `0.0` for that case is a
//! placeholder the caller is expected to never ask for, not an abstention
//! policy. See [`crate::metrics`] on why an abstention must not collapse into
//! a zero.
//!
//! # Faithfulness over cleverness
//!
//! `implementation-inventory.md` section 9, landmine 2, is about this file:
//! the matching is **greedy and must stay greedy**. Three passes in a fixed
//! order, each consuming what it matches, and within a bucket "prefer a
//! type-matching candidate, otherwise consume the first and score a false
//! positive". Replacing that with the optimal assignment --- which is the
//! obvious improvement, and for which `crate::syntax::ged::solve_assignment`
//! is already sitting right there --- produces different `(tp, fp, fn)`
//! triples and therefore different scores. The point of this module is to reproduce the
//! reference's number, not to improve on it.
//!
//! # Determinism
//!
//! `K-4` in [`crate::metrics`]: nothing that iterates a `HashMap` may reach
//! output. The three lookup indexes here are `BTreeMap`s and the claimed-set
//! is a `Vec<bool>` indexed by position, so every intermediate this module
//! builds has one iteration order. That is stronger than the reference needs
//! --- it only ever *looks up* in its dicts --- but it costs nothing at these
//! sizes and removes the question.
//!
//! # Arithmetic width
//!
//! Shifted offsets are [`Shift`] (`i128`), for the reason
//! [`crate::metrics::calibrate::Shift`] gives: a shift is a difference of two
//! `i64`s and does not fit in one. A shifted decompiled offset is used only
//! as a lookup key against ground-truth offsets, which are `i64` by
//! construction, so an out-of-range key is simply a key nothing matches ---
//! exactly what happens in the reference, where the arithmetic is
//! arbitrary-precision but the ground-truth set still only holds `i64`
//! values.

use std::collections::BTreeMap;

use crate::metrics::calibrate::{aligned_count, calibrate_shift, calibrate_shift_multi, Shift};
use crate::metrics::type_name::{normalize_type, size_scalars, uncommitted_size, TypeForms};

/// One ground-truth variable: what the debug information says the source
/// really declared.
///
/// This is `T-1`'s output type, defined here so that `T-3`/`T-6`/`T-7` can be
/// written and tested without a DWARF reader (see the module doc). The field
/// set is exactly the reference's ground-truth dict, minus its `is_arg` flag
/// --- see [`GroundTruthVar::arg_index`] for why that flag is redundant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroundTruthVar {
    /// The source-level name, or empty when the debug entry carried none.
    ///
    /// Empty is meaningful: the name pass skips a ground-truth variable with
    /// no name rather than matching it against decompiled variables that also
    /// have none, which is what the reference's `if not gt_name: continue`
    /// does. An anonymous variable is therefore only ever matched by argument
    /// position or by stack offset.
    pub name: String,

    /// The spellings this variable's type is equivalent to, **already
    /// normalized** --- build it with [`ground_truth_forms`].
    ///
    /// A `Vec<String>` rather than a [`TypeForms`] on purpose, and it is the
    /// reference's own choice for the same two reasons. First, ground truth
    /// is normalized *once, by the producer*, over possibly several DWARF
    /// spellings of one type (a typedef chain reports both `__int32_t` and
    /// `int`), and the result is their union --- which is not the output of
    /// any single [`normalize_type`] call, so it is not a value `TypeForms`
    /// can be constructed to hold. Second, the reference is explicit that
    /// this list must be **sorted, not a set's iteration order**: it feeds a
    /// cache key, and an unstable order there once cost it 77% of its disk
    /// cache. Only the decompiled side is normalized at match time.
    ///
    /// Matching is set intersection against the decompiled side's
    /// [`TypeForms`], so duplicates here are harmless but pointless.
    pub types: Vec<String>,

    /// Frame-relative stack offsets this variable occupies, deduplicated.
    ///
    /// A `Vec` rather than an `Option<i64>` because DWARF can report a
    /// variable at more than one location over its lifetime; the reference
    /// keeps every `DW_OP_fbreg` displacement it saw and lets the offset pass
    /// try all of them. Empty means the variable had a location but not a
    /// stack one --- a register-resident local, the common case at `-O2` ---
    /// which is precisely the case the argument and name passes exist to
    /// cover.
    pub rbp_offsets: Vec<i64>,

    /// The type's size in bytes, from the debug information.
    ///
    /// Carried for completeness and for the caller's own reporting. The
    /// matching below never reads it: the width-only rule of `T-3` is about
    /// the *decompiled* side's width, and it is checked against the
    /// ground-truth *spelling*, not its size, so that a ground-truth pointer
    /// or aggregate of the same width stays a miss.
    pub size: u64,

    /// `Some(i)` iff this is the function's `i`th formal parameter in
    /// declaration order.
    ///
    /// The reference carries a separate `is_arg` boolean beside this, and its
    /// argument pass tests both (`if not gv["is_arg"] or arg_index is None`).
    /// The two can never disagree: the only place `is_arg=True` is set also
    /// passes an integer index, and every other construction sets both to
    /// false/`None`. Collapsing them into one `Option` is therefore exact,
    /// and it makes the impossible state unrepresentable rather than merely
    /// unreached.
    ///
    /// Note that a formal parameter of an *inlined* subroutine or a lexical
    /// block is not an argument of the enclosing function, and the reference
    /// records it with no index. Producers must preserve that.
    pub arg_index: Option<u32>,
}

/// One variable a decompiler claims to have recovered.
///
/// Deliberately holds the type as a **raw, un-normalized spelling** rather
/// than a [`TypeForms`]: `T-3`'s width-only rule inspects the spelling itself
/// (is it `undefined4`? does it contain a `*`?), and normalization is lossy
/// for that question --- `normalize_type("undefined4")` already contains
/// `"int"`, so a pre-normalized form set could not tell a decompiler that
/// committed to `int` apart from one that only recovered four bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompiledVar {
    /// The decompiler's name for the variable, or empty if it has none.
    ///
    /// Also an input to [`effective_offset`]: Ghidra and IDA encode a stack
    /// slot's frame displacement in names like `local_1c`, and the reference
    /// mines it when the structured offset is absent.
    pub name: String,

    /// The type spelling exactly as the decompiler emitted it.
    pub type_spelling: String,

    /// The decompiler's own frame-relative offset for the slot, if it
    /// reported one.
    ///
    /// `None` covers both "not a stack variable" (a register-resident SSA
    /// value) and "a stack variable whose offset only survives in the name";
    /// [`effective_offset`] separates those two.
    pub stack_offset: Option<i64>,

    /// The decompiler's own size for the variable in bytes, if it reported
    /// one.
    ///
    /// Load-bearing for `T-3`: when this is 1, 2, 4 or 8 it *overrides* the
    /// width implied by the type spelling. See [`prepared_width`].
    pub size: Option<u64>,

    /// `Some(i)` iff the decompiler placed this variable at ABI argument
    /// position `i`.
    pub arg_index: Option<u32>,
}

/// The counts and provenance of one function's type-match scoring.
///
/// Everything the reference puts in its `MetricValue.metadata`, minus the two
/// fields that describe which code path ran (it always has structured
/// variables here) and the cache bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FunctionTypeMatch {
    /// Ground-truth variables that were matched to a decompiled variable
    /// whose type agreed.
    pub true_positives: u32,

    /// Ground-truth variables that were matched to a decompiled variable
    /// whose type did **not** agree.
    ///
    /// Named "false positive" by the reference because it is the decompiler
    /// asserting a type that is wrong, not merely failing to assert one.
    pub false_positives: u32,

    /// Ground-truth variables no pass could match to any unclaimed decompiled
    /// variable.
    ///
    /// See [`FunctionTypeMatch::score`] on what this does *not* count.
    pub false_negatives: u32,

    /// The offset shift that the stack pass actually used.
    ///
    /// `Some` for every scored function, including `Some(0)`: the reference's
    /// structured path always resolves to a concrete integer, falling back to
    /// `0` rather than to "no shift". The `Option` exists because the
    /// reference's *other* scoring path, the name-only regex fallback (`T-8`
    /// territory), reports no shift at all, and a consumer that renders this
    /// metadata should be able to say so.
    pub shift: Option<Shift>,

    /// How many ground-truth variables the argument-position pass decided.
    pub matched_by_arg: u32,

    /// How many the stack-offset pass decided.
    pub matched_by_offset: u32,

    /// How many the exact-name pass decided.
    pub matched_by_name: u32,

    /// How many ground-truth variables the function had in total.
    pub gt_vars: u32,

    /// How many decompiled variables were offered.
    ///
    /// Reported, but --- see [`FunctionTypeMatch::score`] --- it does not
    /// enter the score.
    pub decomp_vars: u32,

    /// How many ground-truth variables had at least one stack offset.
    pub gt_stack_vars: u32,

    /// How many decompiled variables had an [`effective_offset`].
    pub decomp_stack_vars: u32,

    /// How many ground-truth variables were formal parameters.
    pub gt_arg_vars: u32,
}

impl FunctionTypeMatch {
    /// The type-recovery score: `tp / (tp + fp + fn)`.
    ///
    /// # This is not a Jaccard, and the difference matters
    ///
    /// `implementation-inventory.md` describes `T-7` as "a Jaccard over
    /// variables, so spurious extra variables cost you". **The reference does
    /// not do that.** Its `fn` is `sum(1 for d in decided if not d)` --- a
    /// count over *ground-truth* variables that no pass decided --- so every
    /// ground-truth variable lands in exactly one of the three buckets and
    /// the denominator is identically `gt_vars`. A decompiled variable that
    /// corresponds to nothing in the ground truth is never counted anywhere.
    /// The score is therefore **recall over ground-truth variables**, and
    /// inventing extra variables is free.
    ///
    /// It is not *quite* free in one indirect way, which is worth knowing
    /// before anyone concludes the metric is blind to invention: a spurious
    /// variable can *shadow* a real one. The argument index is claimed by the
    /// first decompiled variable carrying it, and the offset and name buckets
    /// are consumed by [`claim`], so a spurious variable sitting on a real
    /// one's argument position turns a true positive into a false positive.
    /// That is a second-order effect of collision, not a cost of the extra
    /// variable as such: put the spurious variable anywhere unoccupied and
    /// the score does not move.
    ///
    /// The formula is written out rather than simplified to `tp / gt_vars`
    /// because it is the reference's, and because a future producer that
    /// leaves a ground-truth variable in none of the three buckets would make
    /// them differ --- at which point this is the one that is right.
    ///
    /// # Empty ground truth
    ///
    /// Returns `0.0` when the denominator is zero, as the reference's
    /// `accuracy = tp / total if total > 0 else 0.0` does. As the module doc
    /// says, the reference never actually scores such a function; treat this
    /// as an unreachable placeholder rather than as a claim that a function
    /// with no variables recovers types badly.
    #[must_use]
    pub fn score(&self) -> f64 {
        let total = self.true_positives + self.false_positives + self.false_negatives;
        if total == 0 {
            return 0.0;
        }
        f64::from(self.true_positives) / f64::from(total)
    }
}

/// The stack offset to treat a decompiled variable as living at, or `None` if
/// it does not appear to be a stack variable at all.
///
/// Ports `_effective_offset`. A structured `stack_offset` wins outright; when
/// there is none, a Ghidra/IDA-style `local_1c` or `var_20` name is mined for
/// the hexadecimal displacement it encodes, which is by convention *negative*
/// (the slot is below the frame pointer). Anything else --- including
/// `Stack_...` spellings, which the reference excludes by name because their
/// sign convention is not consistent across tools --- yields `None`.
///
/// # Why mine the name at all
///
/// Because a decompiler that emits a variable list without offsets still puts
/// the offset in the identifier, and without this the stack pass would have
/// nothing to work with for two of the three major backends. It is a
/// concession to reality, and the reference is explicit that Ghidra's
/// register-SSA variables (`uVar1` and friends) correctly stay `None`.
///
/// # Overflow
///
/// The reference parses the hex digits as an arbitrary-precision integer. A
/// name with more than fifteen hex digits would exceed `i64` here and yields
/// `None` instead of an enormous offset. Such an offset could never equal a
/// DWARF offset, which is `i64` by construction, so the difference is
/// confined to the calibration candidate set and to the `decomp_stack_vars`
/// tally; no realistic frame produces one.
#[must_use]
pub fn effective_offset(var: &DecompiledVar) -> Option<i64> {
    if let Some(offset) = var.stack_offset {
        return Some(offset);
    }

    let digits = var
        .name
        .strip_prefix("local_")
        .or_else(|| var.name.strip_prefix("var_"))?;

    // `^(?:local|var)_([0-9a-fA-F]+)$`: at least one digit, all hexadecimal,
    // nothing after them. `from_str_radix` rejects an empty string and any
    // non-hex character, but it also accepts a leading `+`/`-` sign that the
    // reference's character class does not, so the sign is excluded first.
    if digits.starts_with('+') || digits.starts_with('-') {
        return None;
    }
    i64::from_str_radix(digits, 16).ok().map(|value| -value)
}

/// The width a decompiled variable's type recovers *without* committing to a
/// C type, or `None` when the type is committed (or unrecognized).
///
/// This is `T-3`'s first half, and it is [`uncommitted_size`] with the
/// argument order this module's callers have. Split out and public because
/// the rule it encodes is easy to get subtly wrong in a producer: the *size*
/// field, when it is one of the four scalar widths, beats the width implied
/// by the spelling. A variable typed `undefined8` but sized 4 is four bytes
/// of unknown, not eight.
#[must_use]
pub fn prepared_width(var: &DecompiledVar) -> Option<u64> {
    uncommitted_size(&var.type_spelling, var.size)
}

/// The normalized form list to store in [`GroundTruthVar::types`], given
/// every spelling the debug information used for one type.
///
/// This is the ground-truth half of `T-2`, and it is the only place a
/// producer should build that field: it unions [`normalize_type`] over each
/// spelling, deduplicates, and **sorts**. The sort is not cosmetic --- the
/// reference sorts for a documented reason (its cache key is a JSON dump of
/// this list, and a Python set's iteration order varies with
/// `PYTHONHASHSEED`, which silently cost it most of its disk cache) --- and
/// the same argument applies here to any caller that hashes or diffs a
/// ground-truth payload. Determinism is a public promise (`K-4` in
/// [`crate::metrics`]), and a producer that skipped this and pushed forms in
/// discovery order would break it without failing anything locally.
///
/// Sorting cannot change a match: matching is set intersection, which does
/// not depend on order.
#[must_use]
pub fn ground_truth_forms(spellings: &[&str]) -> Vec<String> {
    let mut forms: Vec<String> = Vec::new();
    for spelling in spellings {
        for form in normalize_type(spelling).as_slice() {
            if !forms.iter().any(|existing| existing == form) {
                forms.push(form.clone());
            }
        }
    }
    forms.sort_unstable();
    forms
}

/// A decompiled variable with its per-variable derived facts computed once.
///
/// The reference builds `var_types`, `var_unc` and `var_offsets` as three
/// parallel lists before matching starts, because each is consulted many
/// times across the three passes and normalization is not free. Holding them
/// in one struct keeps the three from drifting out of alignment, which is the
/// failure mode parallel arrays invite.
#[derive(Debug)]
struct PreparedVar {
    /// The spellings this variable's declared type is equivalent to.
    forms: TypeForms,

    /// The width from `T-3`'s uncommitted-type rule, if any.
    uncommitted_width: Option<u64>,

    /// The offset from [`effective_offset`], if any.
    offset: Option<i64>,
}

/// Whether decompiled variable `dec` type-matches a ground-truth variable
/// whose normalized spellings are `gt_forms`.
///
/// Ports the reference's inner `_matches`, and is the whole of `T-3`'s
/// decision. Two independent ways to agree:
///
/// 1. **Exact agreement after normalization** --- the two form sets
///    intersect. This is `T-2`'s job and covers the overwhelming majority.
/// 2. **Width-only credit** --- the decompiled type is uncommitted, and the
///    ground truth is a *scalar* of that width.
///
/// Rule 2 is the one that has to be stated carefully, because the generous
/// reading of it is wrong. [`size_scalars`] holds integers and `bool` and
/// nothing else: no `float`, no `double`, no pointer, no aggregate. So
/// `undefined8` is credited against `long` and refused against `char *`,
/// `double`, or a struct --- a decompiler that recovered only "eight bytes"
/// has demonstrably not recovered a pointer, and crediting it would make the
/// metric unable to distinguish the two things it exists to distinguish. The
/// asymmetry is deliberate: rule 2 tests the ground truth's *spelling*, never
/// its size, so a ground-truth `char *` on a 64-bit target --- eight bytes,
/// like `long long` --- still fails.
fn type_matches(gt_forms: &[String], dec: &PreparedVar) -> bool {
    if gt_forms.iter().any(|form| dec.forms.contains(form)) {
        return true;
    }
    match dec.uncommitted_width {
        Some(width) => size_scalars(width)
            .iter()
            .any(|scalar| gt_forms.iter().any(|form| form == scalar)),
        None => false,
    }
}

/// The greedy bucket claim: take the best unclaimed candidate, and say what
/// happened.
///
/// Ports the reference's inner `claim`, which is where landmine 2 lives.
/// Given the decompiled-variable indexes that could stand for one
/// ground-truth variable:
///
/// * `None` --- every candidate is already claimed (or there were none). The
///   ground-truth variable is left **undecided** and falls through to the
///   next pass; it is not yet a miss.
/// * `Some(true)` --- some unclaimed candidate type-matches. Claim *that*
///   one, in candidate order, and score a true positive.
/// * `Some(false)` --- none does. Claim the **first** unclaimed candidate
///   anyway and score a false positive.
///
/// The last branch is the counter-intuitive one and it is not an accident:
/// having found a decompiled variable at the right offset (or with the right
/// name) with the wrong type, the metric records that the decompiler *did*
/// see this variable and got its type wrong --- a false positive --- rather
/// than letting it fall through to the name pass and be recorded as never
/// recovered. Consuming the candidate is what stops one wrong-typed variable
/// from absorbing several ground-truth ones.
///
/// Preferring a type-matching candidate over the first is what makes this
/// greedy rather than arbitrary, and it is also why the assignment is not
/// optimal: the variable claimed here may have been the only match for some
/// later ground-truth variable in the same bucket. That is the reference's
/// behaviour and must stay (landmine 2).
fn claim(
    candidates: &[usize],
    gt_forms: &[String],
    prepared: &[PreparedVar],
    claimed: &mut [bool],
) -> Option<bool> {
    let mut first_available: Option<usize> = None;
    for &i in candidates {
        if claimed[i] {
            continue;
        }
        if first_available.is_none() {
            first_available = Some(i);
        }
        if type_matches(gt_forms, &prepared[i]) {
            claimed[i] = true;
            return Some(true);
        }
    }

    let first = first_available?;
    claimed[first] = true;
    Some(false)
}

/// Scores one function's recovered variables against its ground truth:
/// `T-6`'s three-pass greedy matching and `T-7`'s score.
///
/// `calibration_shift` is the binary-wide shift from
/// [`binary_calibration_shift`] (`T-5`), or `None` to start from zero. Either
/// way this function may override it with a per-function shift (`T-4`) ---
/// see "Calibration" below.
///
/// # The three passes, and why the order is load-bearing
///
/// Each pass considers only ground-truth variables no earlier pass decided,
/// and each decompiled variable is claimed at most once across all three.
///
/// 1. **Arguments, by ABI position.** A formal parameter is matched to the
///    decompiled variable at the same argument index. Position is the one
///    identity that survives everything: at `-O2` an argument lives in a
///    register and has no stack offset, and backends like angr invent names,
///    so neither of the other two passes could find it. This pass does not go
///    through [`claim`] --- there is exactly one candidate per index --- so
///    an argument whose index is missing or already claimed stays undecided
///    and falls through rather than scoring a false positive.
/// 2. **Stack variables, by calibrated offset.** A ground-truth variable is
///    matched against the decompiled variables whose shifted offset equals
///    one of its own.
/// 3. **Everything else, by exact name.** This picks up register-resident
///    locals when the decompiler imported debug names, and stack slots the
///    decompiler promoted out of memory.
///
/// Running names *last* is the load-bearing part. Names are the weakest
/// evidence --- a decompiler is free to invent them, and two unrelated
/// variables can share one --- so anything positional or structural must get
/// first refusal on a decompiled variable. Reordering the passes changes the
/// triple, and therefore the score, on any function where the evidence
/// disagrees.
///
/// # Calibration
///
/// The stack pass needs the decompiler's offsets in DWARF's frame convention.
/// The binary-wide shift is the default because it is estimated from far more
/// evidence than one function provides. It is overridden by the per-function
/// shift only when the binary-wide one aligns **nothing at all** and the
/// per-function one aligns something --- a deliberately narrow escape hatch
/// for IDA's frame-bottom-relative numbering, where the gap to DWARF is a
/// per-function constant of roughly the frame size that no single binary-wide
/// constant can fit. Widening it would let a coincidental per-function
/// alignment overrule a well-attested binary-wide one.
///
/// # Empty ground truth
///
/// Returns an all-zero result whose [`FunctionTypeMatch::score`] is `0.0`.
/// The reference never scores such a function; see the module doc.
#[must_use]
pub fn match_structured(
    ground_truth: &[GroundTruthVar],
    decompiled: &[DecompiledVar],
    calibration_shift: Option<Shift>,
) -> FunctionTypeMatch {
    let prepared: Vec<PreparedVar> = decompiled
        .iter()
        .map(|var| PreparedVar {
            forms: normalize_type(&var.type_spelling),
            uncommitted_width: prepared_width(var),
            offset: effective_offset(var),
        })
        .collect();

    let gt_offsets: Vec<i64> = ground_truth
        .iter()
        .flat_map(|gv| gv.rbp_offsets.iter().copied())
        .collect();
    let decomp_offsets: Vec<i64> = prepared.iter().filter_map(|p| p.offset).collect();

    // The reference's `shift = calibration_shift if ... is not None else 0`:
    // in the structured path the shift is always a concrete integer, never
    // absent, and `0` is the identity rather than a refusal to calibrate.
    let mut shift: Shift = calibration_shift.unwrap_or(0);
    if let Some(func_shift) = calibrate_shift(&gt_offsets, &decomp_offsets) {
        if aligned_count(&gt_offsets, &decomp_offsets, shift) == 0
            && aligned_count(&gt_offsets, &decomp_offsets, func_shift) > 0
        {
            shift = func_shift;
        }
    }

    // Three lookup indexes, built in decompiled-variable order so that "the
    // first" in `claim` and in the argument pass means the same thing it does
    // in the reference. `BTreeMap` rather than `HashMap` per `K-4`.
    let mut by_arg_index: BTreeMap<u32, usize> = BTreeMap::new();
    let mut by_offset: BTreeMap<Shift, Vec<usize>> = BTreeMap::new();
    let mut by_name: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, var) in decompiled.iter().enumerate() {
        if let Some(index) = var.arg_index {
            // First writer wins: `if v.arg_index not in by_arg_index`.
            by_arg_index.entry(index).or_insert(i);
        }
        if let Some(offset) = prepared[i].offset {
            by_offset
                .entry(Shift::from(offset) + shift)
                .or_default()
                .push(i);
        }
        if !var.name.is_empty() {
            by_name.entry(var.name.as_str()).or_default().push(i);
        }
    }

    let mut claimed = vec![false; decompiled.len()];
    // `decided[gi]` records that some pass reached a verdict on ground-truth
    // variable `gi`; `verdicts[gi]` is that verdict. They are separate
    // because "undecided" and "decided as a miss" are different outcomes and
    // only the former falls through to the next pass.
    let mut decided = vec![false; ground_truth.len()];
    let mut verdicts = vec![false; ground_truth.len()];
    let mut matched_by_arg = 0_u32;
    let mut matched_by_offset = 0_u32;
    let mut matched_by_name = 0_u32;

    // Pass 1: arguments by ABI position.
    for (gi, gv) in ground_truth.iter().enumerate() {
        let Some(arg_index) = gv.arg_index else {
            continue;
        };
        let Some(&di) = by_arg_index.get(&arg_index) else {
            continue;
        };
        if claimed[di] {
            continue;
        }
        claimed[di] = true;
        decided[gi] = true;
        verdicts[gi] = type_matches(&gv.types, &prepared[di]);
        matched_by_arg += 1;
    }

    // Pass 2: stack variables by calibrated offset.
    for (gi, gv) in ground_truth.iter().enumerate() {
        if decided[gi] {
            continue;
        }
        let mut candidates: Vec<usize> = Vec::new();
        for &offset in &gv.rbp_offsets {
            if let Some(bucket) = by_offset.get(&Shift::from(offset)) {
                candidates.extend_from_slice(bucket);
            }
        }
        if candidates.is_empty() {
            continue;
        }
        if let Some(verdict) = claim(&candidates, &gv.types, &prepared, &mut claimed) {
            decided[gi] = true;
            verdicts[gi] = verdict;
            matched_by_offset += 1;
        }
    }

    // Pass 3: everything else by exact name. The `is_empty` half of the
    // guard is the reference's `if not gt_name: continue`, and it is
    // deliberately redundant: `by_name` never holds an empty key, because the
    // index above skips unnamed decompiled variables, so an anonymous
    // ground-truth variable would find an empty bucket anyway. It is kept
    // because it is the reference's, and because the redundancy depends on an
    // invariant two hundred lines away -- a mutation removing it changes no
    // observable behaviour today and would change it the moment the index
    // did.
    for (gi, gv) in ground_truth.iter().enumerate() {
        if decided[gi] || gv.name.is_empty() {
            continue;
        }
        let candidates: &[usize] = by_name.get(gv.name.as_str()).map_or(&[], Vec::as_slice);
        if let Some(verdict) = claim(candidates, &gv.types, &prepared, &mut claimed) {
            decided[gi] = true;
            verdicts[gi] = verdict;
            matched_by_name += 1;
        }
    }

    let true_positives = decided
        .iter()
        .zip(&verdicts)
        .filter(|&(&d, &v)| d && v)
        .count() as u32;
    let false_positives = decided
        .iter()
        .zip(&verdicts)
        .filter(|&(&d, &v)| d && !v)
        .count() as u32;
    let false_negatives = decided.iter().filter(|&&d| !d).count() as u32;

    FunctionTypeMatch {
        true_positives,
        false_positives,
        false_negatives,
        shift: Some(shift),
        matched_by_arg,
        matched_by_offset,
        matched_by_name,
        gt_vars: ground_truth.len() as u32,
        decomp_vars: decompiled.len() as u32,
        gt_stack_vars: ground_truth
            .iter()
            .filter(|gv| !gv.rbp_offsets.is_empty())
            .count() as u32,
        decomp_stack_vars: prepared.iter().filter(|p| p.offset.is_some()).count() as u32,
        gt_arg_vars: ground_truth
            .iter()
            .filter(|gv| gv.arg_index.is_some())
            .count() as u32,
    }
}

/// The single offset shift that best reconciles a whole binary's decompiled
/// stack offsets with DWARF's, or `None` when there is nothing to calibrate.
///
/// Ports `_calibrate_binary_shift`: gather each function's `(ground-truth
/// offsets, decompiled offsets)` pair, drop the functions where either side
/// is empty, and hand the rest to `T-5`'s discounted vote
/// ([`calibrate_shift_multi`]). Functions with no ground truth are the
/// caller's to exclude, exactly as the reference excludes them --- they are
/// not scored either.
///
/// This exists here, rather than being left to each caller, because getting
/// the *input* to `T-5` wrong is the easy mistake: the decompiled offsets
/// must come from [`effective_offset`] (so that name-encoded slots
/// participate) and the ground-truth offsets must be the flattened union
/// across all of a function's variables, duplicates and all.
#[must_use]
pub fn binary_calibration_shift(
    functions: &[(&[GroundTruthVar], &[DecompiledVar])],
) -> Option<Shift> {
    let pairs: Vec<(Vec<i64>, Vec<i64>)> = functions
        .iter()
        .map(|(ground_truth, decompiled)| {
            let gt: Vec<i64> = ground_truth
                .iter()
                .flat_map(|gv| gv.rbp_offsets.iter().copied())
                .collect();
            let dec: Vec<i64> = decompiled.iter().filter_map(effective_offset).collect();
            (gt, dec)
        })
        .filter(|(gt, dec)| !gt.is_empty() && !dec.is_empty())
        .collect();

    calibrate_shift_multi(&pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // Unit tests: T-3, the width-only rule.
    //
    // Every expectation below is the reference's, checked by calling
    // `TypeMatchMetric._match_structured` on the same input (see the
    // differential corpus at the bottom of this module for the mechanised
    // form of the same check).
    // ---------------------------------------------------------------------

    /// A ground-truth variable, with its type spelling normalized the way
    /// `T-1` would normalize it.
    fn gt(
        name: &str,
        spellings: &[&str],
        offsets: &[i64],
        size: u64,
        arg: Option<u32>,
    ) -> GroundTruthVar {
        GroundTruthVar {
            name: name.to_string(),
            types: ground_truth_forms(spellings),
            rbp_offsets: offsets.to_vec(),
            size,
            arg_index: arg,
        }
    }

    /// A decompiled variable.
    fn dv(
        name: &str,
        spelling: &str,
        offset: Option<i64>,
        size: Option<u64>,
        arg: Option<u32>,
    ) -> DecompiledVar {
        DecompiledVar {
            name: name.to_string(),
            type_spelling: spelling.to_string(),
            stack_offset: offset,
            size,
            arg_index: arg,
        }
    }

    /// Wraps a decompiled variable in the form [`type_matches`] wants.
    fn prepared(var: &DecompiledVar) -> PreparedVar {
        PreparedVar {
            forms: normalize_type(&var.type_spelling),
            uncommitted_width: prepared_width(var),
            offset: effective_offset(var),
        }
    }

    /// Whether a decompiled spelling of the given size type-matches a
    /// ground-truth spelling, the whole of `T-3`'s decision in one call.
    fn matches(gt_spelling: &str, dec_spelling: &str, dec_size: Option<u64>) -> bool {
        let forms = ground_truth_forms(&[gt_spelling]);
        let var = dv("v", dec_spelling, None, dec_size, None);
        type_matches(&forms, &prepared(&var))
    }

    #[test]
    fn t3_width_only_matches_a_same_width_scalar() {
        // The inventory's own acceptance test for T-3: "`undefined8` matches
        // `long`, does not match `char *`".
        assert!(matches("long", "undefined8", None));
        assert!(!matches("char *", "undefined8", None));
    }

    #[test]
    fn t3_width_only_refuses_pointers_of_the_same_width() {
        // The generosity is about SCALARS. A pointer is 8 bytes on LP64, so a
        // width-only rule that looked at the ground truth's SIZE rather than
        // its SPELLING would credit every one of these. `_SIZE_SCALARS` holds
        // no pointer spelling, which is what makes them misses.
        for pointer in ["char *", "int *", "void *", "struct Node *", "char **"] {
            assert!(
                !matches(pointer, "undefined8", None),
                "undefined8 must not match the pointer {pointer}"
            );
            assert!(
                !matches(pointer, "_QWORD", None),
                "_QWORD must not match the pointer {pointer}"
            );
        }
    }

    #[test]
    fn t3_width_only_refuses_aggregates_and_floats() {
        // A struct of eight bytes and a `double` are both types the
        // decompiler demonstrably failed to recover when it emitted a width.
        assert!(!matches("struct Pair", "undefined8", None));
        assert!(!matches("double", "undefined8", None));
        assert!(!matches("float", "undefined4", None));
    }

    #[test]
    fn t3_width_one_admits_bool_which_normalization_alone_would_miss() {
        // This is the case that shows the width rule is not redundant with
        // T-2. `normalize_type("undefined1")` contains "char" (TYPE_MAP) but
        // never "bool", so an exact-intersection-only matcher would score a
        // ground-truth `_Bool` as a miss. `_SIZE_SCALARS[1] == {"char",
        // "bool"}` is what credits it.
        let forms = ground_truth_forms(&["_Bool"]);
        assert!(forms.iter().any(|f| f == "bool"));
        let plain = dv("v", "undefined1", None, None, None);
        assert!(!normalize_type("undefined1").contains("bool"));
        assert!(type_matches(&forms, &prepared(&plain)));
    }

    #[test]
    fn t3_spellings_outside_the_alias_table_only_match_by_width() {
        // `byte`, `word`, `dword`, `qword` are in `_UNCOMMITTED_WIDTH` but
        // NOT in `TYPE_MAP`, so normalization leaves them alone and the width
        // rule is the only thing that can match them at all.
        assert!(!normalize_type("dword").contains("int"));
        assert!(matches("int", "dword", None));
        assert!(matches("long long", "qword", None));
        assert!(!matches("int *", "dword", None));
    }

    #[test]
    fn t3_declared_size_overrides_the_spelling_width() {
        // `_uncommitted_size` checks `size in _SIZE_SCALARS` BEFORE consulting
        // `_UNCOMMITTED_WIDTH`, so a decompiler that says "eight bytes" but
        // reports a 4-byte slot has recovered four bytes of unknown.
        //
        // The override is only OBSERVABLE through a spelling that `TYPE_MAP`
        // does not alias, which is a real subtlety and the reason this test
        // uses `qword` rather than the obvious `undefined8`: `undefined8`
        // normalizes to `long long` outright, so it exact-matches a
        // ground-truth `long long` by rule 1 no matter what the size says.
        // Checked against the reference, which reports `("exact", True)` for
        // `undefined8`/`long long`/size 4 and `("width", 4, False)` for
        // `qword`/`long long`/size 4.
        assert!(!normalize_type("qword").contains("long long"));
        assert_eq!(
            prepared_width(&dv("v", "qword", None, Some(4), None)),
            Some(4)
        );
        assert!(matches("int", "qword", Some(4)));
        assert!(!matches("long long", "qword", Some(4)));
        // With no size, the spelling's own width is used.
        assert!(matches("long long", "qword", None));
        // A size that is not one of the four scalar widths is ignored and the
        // spelling wins, per the same reference ordering.
        assert!(matches("long long", "qword", Some(3)));
        assert!(matches("long long", "qword", Some(16)));
        // The alias route is independent of all of this, and dominates.
        assert!(matches("long long", "undefined8", Some(4)));
    }

    #[test]
    fn t3_a_pointer_spelling_is_never_uncommitted() {
        // `_uncommitted_size` returns None the moment the spelling contains a
        // `*`, before the regex is even consulted: `undefined8 *` is a
        // COMMITTED type (a pointer), just to something unresolved. So it
        // cannot borrow the width rule to match a scalar.
        assert_eq!(
            prepared_width(&dv("v", "undefined8 *", None, Some(8), None)),
            None
        );
        assert!(!matches("long long", "undefined8 *", Some(8)));
        // And normalization keeps it a miss against a committed pointer too:
        // `_POINTEE_MAP` deliberately excludes the placeholder spellings, so
        // `undefined8 *` does not become `long long*`.
        assert!(!matches("size_t *", "undefined8 *", None));
    }

    #[test]
    fn t3_a_committed_type_never_uses_the_width_rule() {
        // `int` is not an uncommitted spelling, so it matches `long long`
        // through neither route even though the caller claims 8 bytes.
        assert_eq!(prepared_width(&dv("v", "int", None, Some(8), None)), None);
        assert!(!matches("long long", "int", Some(8)));
    }

    #[test]
    fn t3_unknown_width_spellings_fall_through_without_a_size() {
        // `int3` matches `_UNCOMMITTED_TYPES` but has no `_UNCOMMITTED_WIDTH`
        // entry, so with no size it recovers no width at all.
        assert_eq!(prepared_width(&dv("v", "int3", None, None, None)), None);
        assert!(!matches("int", "int3", None));
        // ...and with a size it does.
        assert!(matches("int", "int3", Some(4)));
    }

    // ---------------------------------------------------------------------
    // Unit tests: `effective_offset`.
    // ---------------------------------------------------------------------

    #[test]
    fn effective_offset_prefers_the_structured_offset() {
        // The structured offset wins outright, even when the name encodes a
        // different one -- `_effective_offset` returns before looking at the
        // name.
        let var = dv("local_10", "int", Some(-4), Some(4), None);
        assert_eq!(effective_offset(&var), Some(-4));
    }

    #[test]
    fn effective_offset_mines_ghidra_and_ida_names() {
        // `^(?:local|var)_([0-9a-fA-F]+)$`, negated: the convention is that
        // the name's hex is the slot's distance BELOW the frame pointer.
        assert_eq!(
            effective_offset(&dv("local_1c", "int", None, None, None)),
            Some(-0x1c)
        );
        assert_eq!(
            effective_offset(&dv("var_20", "int", None, None, None)),
            Some(-0x20)
        );
        assert_eq!(
            effective_offset(&dv("local_A", "int", None, None, None)),
            Some(-0xa)
        );
    }

    #[test]
    fn effective_offset_rejects_everything_else() {
        // Ghidra's register-SSA variables stay None, which is what keeps them
        // out of the stack pass and out of calibration.
        assert_eq!(
            effective_offset(&dv("uVar1", "int", None, None, None)),
            None
        );
        // `Stack_...` is excluded by the reference by name: its sign
        // convention is not consistent across tools.
        assert_eq!(
            effective_offset(&dv("Stack_20", "int", None, None, None)),
            None
        );
        assert_eq!(
            effective_offset(&dv("aStack_20", "int", None, None, None)),
            None
        );
        // Non-hex, empty, and sign characters all fail the character class.
        assert_eq!(
            effective_offset(&dv("local_", "int", None, None, None)),
            None
        );
        assert_eq!(
            effective_offset(&dv("local_xyz", "int", None, None, None)),
            None
        );
        assert_eq!(
            effective_offset(&dv("local_-4", "int", None, None, None)),
            None
        );
        assert_eq!(
            effective_offset(&dv("local_10_1", "int", None, None, None)),
            None
        );
        assert_eq!(effective_offset(&dv("", "int", None, None, None)), None);
    }

    // ---------------------------------------------------------------------
    // Unit tests: T-6, the three passes and their order.
    // ---------------------------------------------------------------------

    #[test]
    fn t6_argument_pass_beats_a_conflicting_name() {
        // GT arg 0 is named `a`; the decompiled variable at ABI position 0 is
        // named `b` and typed `int`, and a DIFFERENT decompiled variable is
        // named `a` and typed `char`. Position wins: the argument pass claims
        // index 0 first, so `a` is scored against `int`-typed `b` -- a true
        // positive -- and never reaches the name pass.
        let ground_truth = [gt("a", &["int"], &[], 4, Some(0))];
        let decompiled = [
            dv("b", "int", None, Some(4), Some(0)),
            dv("a", "char", None, Some(1), None),
        ];
        let result = match_structured(&ground_truth, &decompiled, None);
        assert_eq!(
            (
                result.true_positives,
                result.false_positives,
                result.false_negatives
            ),
            (1, 0, 0)
        );
        assert_eq!((result.matched_by_arg, result.matched_by_name), (1, 0));
    }

    #[test]
    fn t6_offset_pass_beats_a_conflicting_name() {
        // Same shape one pass down: the offset bucket claims the variable
        // before the name pass can.
        let ground_truth = [gt("total", &["int"], &[-8], 4, None)];
        let decompiled = [
            dv("local_8", "int", Some(-8), Some(4), None),
            dv("total", "char", None, Some(1), None),
        ];
        let result = match_structured(&ground_truth, &decompiled, None);
        assert_eq!((result.matched_by_offset, result.matched_by_name), (1, 0));
        assert_eq!(result.true_positives, 1);
    }

    #[test]
    fn t6_an_unmatched_argument_falls_through_rather_than_scoring() {
        // The argument pass does NOT go through `claim`: when the index is
        // absent it leaves the ground-truth variable undecided so a later pass
        // can try, instead of consuming something and scoring a false
        // positive. Here the name pass then finds it.
        let ground_truth = [gt("n", &["int"], &[], 4, Some(3))];
        let decompiled = [dv("n", "int", None, Some(4), None)];
        let result = match_structured(&ground_truth, &decompiled, None);
        assert_eq!((result.matched_by_arg, result.matched_by_name), (0, 1));
        assert_eq!(result.true_positives, 1);
    }

    #[test]
    fn t6_a_bucket_prefers_a_type_matching_candidate_over_the_first() {
        // Two decompiled variables share the offset. The one that type-matches
        // is claimed even though it is second -- this is the "prefer a
        // type-matching candidate" half of `claim`.
        let ground_truth = [gt("x", &["int"], &[-4], 4, None)];
        let decompiled = [
            dv("wrong", "char *", Some(-4), Some(8), None),
            dv("right", "int", Some(-4), Some(4), None),
        ];
        let result = match_structured(&ground_truth, &decompiled, None);
        assert_eq!(result.true_positives, 1);
        assert_eq!(result.false_positives, 0);
    }

    #[test]
    fn t6_a_bucket_with_no_match_consumes_the_first_and_scores_a_false_positive() {
        // The other half of `claim`, and the counter-intuitive one: having
        // found a variable at the right offset with the wrong type, the metric
        // records that the decompiler saw this slot and got it wrong.
        // Consuming it is what stops one wrong variable absorbing two
        // ground-truth ones.
        let ground_truth = [
            gt("x", &["int"], &[-4], 4, None),
            gt("y", &["int"], &[-4], 4, None),
        ];
        let decompiled = [dv("slot", "char *", Some(-4), Some(8), None)];
        let result = match_structured(&ground_truth, &decompiled, None);
        assert_eq!(
            (
                result.true_positives,
                result.false_positives,
                result.false_negatives
            ),
            (0, 1, 1)
        );
        // The second ground-truth variable found the bucket empty, so `claim`
        // returned None and it stayed undecided -- a miss, not a second false
        // positive.
        assert_eq!(result.matched_by_offset, 1);
    }

    #[test]
    fn t6_greedy_is_not_optimal_and_must_stay_that_way() {
        // Landmine 2 in one test. Ground truth: `a: int` then `b: char` at the
        // same offset. Decompiled: `p: char` then `q: int` at that offset.
        // The OPTIMAL assignment is a<->q and b<->p: two true positives.
        // Greedy takes `a` first, prefers the type-matching `q`, then leaves
        // `b` only `p`... which happens to match. Shift the types so it does
        // not: ground truth `a: int`, `b: int`; decompiled `p: int`, `q: int`
        // is trivial, so use `a: int`, `b: long long` against `p: long long`,
        // `q: int`.
        let ground_truth = [
            gt("a", &["int"], &[-4], 4, None),
            gt("b", &["long long"], &[-4], 8, None),
        ];
        let decompiled = [
            dv("p", "long long", Some(-4), Some(8), None),
            dv("q", "int", Some(-4), Some(4), None),
        ];
        let result = match_structured(&ground_truth, &decompiled, None);
        // Optimal would be (2, 0, 0). Greedy gives `a` the type-matching `q`,
        // leaving `b` with `p` -- which also matches, so this particular
        // shape is still (2, 0, 0). The asymmetric one below is the real
        // demonstration.
        assert_eq!(result.true_positives, 2);

        // Now the asymmetric shape: only ONE decompiled variable can satisfy
        // `b`, and `a` is happy with either. Greedy hands `a` the first
        // type-matching candidate it sees, which is the one `b` needed.
        let ground_truth = [
            gt("a", &["long long"], &[-4], 8, None),
            gt("b", &["long long"], &[-4], 8, None),
        ];
        let decompiled = [
            dv("p", "long long", Some(-4), Some(8), None),
            dv("q", "char *", Some(-4), Some(8), None),
        ];
        let result = match_structured(&ground_truth, &decompiled, None);
        assert_eq!(
            (
                result.true_positives,
                result.false_positives,
                result.false_negatives
            ),
            (1, 1, 0)
        );
    }

    #[test]
    fn t6_a_decompiled_variable_is_claimed_at_most_once_across_passes() {
        // One decompiled variable that could serve as the argument, as the
        // offset match, and as the name match. It serves once; the other two
        // ground-truth variables miss.
        let ground_truth = [
            gt("shared", &["int"], &[-4], 4, Some(0)),
            gt("other", &["int"], &[-4], 4, None),
            gt("shared", &["int"], &[], 4, None),
        ];
        let decompiled = [dv("shared", "int", Some(-4), Some(4), Some(0))];
        let result = match_structured(&ground_truth, &decompiled, None);
        assert_eq!(
            (
                result.true_positives,
                result.false_positives,
                result.false_negatives
            ),
            (1, 0, 2)
        );
        assert_eq!(result.matched_by_arg, 1);
    }

    #[test]
    fn t6_an_anonymous_ground_truth_variable_skips_the_name_pass() {
        // `if not gt_name: continue`. An unnamed ground-truth variable with no
        // offset and no argument index cannot be matched at all -- it is not
        // paired with an unnamed decompiled variable.
        let ground_truth = [gt("", &["int"], &[], 4, None)];
        let decompiled = [dv("", "int", None, Some(4), None)];
        let result = match_structured(&ground_truth, &decompiled, None);
        assert_eq!(result.false_negatives, 1);
        assert_eq!(result.matched_by_name, 0);
    }

    #[test]
    fn t6_an_unnamed_decompiled_variable_never_enters_the_name_index() {
        // `if v.name:` -- the empty name is not a bucket key, so a
        // ground-truth variable named "" could not find it even if the name
        // pass ran.
        let ground_truth = [gt("x", &["int"], &[], 4, None)];
        let decompiled = [dv("", "int", None, Some(4), None)];
        let result = match_structured(&ground_truth, &decompiled, None);
        assert_eq!(result.false_negatives, 1);
    }

    #[test]
    fn t6_a_second_ground_truth_argument_at_the_same_index_falls_through() {
        // The argument pass's `if claimed[di] { continue; }` guard. Two
        // ground-truth formal parameters sharing an ABI index cannot both be
        // matched to the one decompiled variable there: the first claims it,
        // the second is left undecided and, with no offset and no distinct
        // name match, becomes a miss rather than a second verdict on the same
        // variable.
        //
        // `T-1` will not produce this shape (its index is a counter), but
        // `match_structured` takes ground truth as an input and the guard is
        // what makes the input safe. Checked against the reference, which
        // returns `tp=1, fp=0, fn=1, matched_by_arg=1` for exactly this.
        let ground_truth = [
            gt("a", &["int"], &[], 4, Some(0)),
            gt("b", &["int"], &[], 4, Some(0)),
        ];
        let decompiled = [dv("p", "int", None, Some(4), Some(0))];
        let result = match_structured(&ground_truth, &decompiled, None);
        assert_eq!(
            (
                result.true_positives,
                result.false_positives,
                result.false_negatives
            ),
            (1, 0, 1)
        );
        assert_eq!(result.matched_by_arg, 1);
        assert_eq!(result.gt_arg_vars, 2);
    }

    #[test]
    fn t6_the_first_variable_wins_a_duplicated_argument_index() {
        // `if v.arg_index not in by_arg_index` -- first writer wins, so a
        // spurious variable inserted ahead of the real one at the same ABI
        // position shadows it. This is the ONE way an extra variable can cost
        // a decompiler anything under T-7 (see `t7_spurious_variables_are_free`).
        let ground_truth = [gt("a", &["int"], &[], 4, Some(0))];
        let decompiled = [
            dv("shadow", "char *", None, Some(8), Some(0)),
            dv("a", "int", None, Some(4), Some(0)),
        ];
        let result = match_structured(&ground_truth, &decompiled, None);
        assert_eq!(result.false_positives, 1);
        assert_eq!(result.true_positives, 0);
    }

    // ---------------------------------------------------------------------
    // Unit tests: calibration hand-off (T-4/T-5 consumed by T-6).
    // ---------------------------------------------------------------------

    #[test]
    fn calibration_override_only_fires_when_the_binary_shift_aligns_nothing() {
        // IDA's frame-bottom offsets: the decompiled slots sit +96 from
        // DWARF's. A binary-wide shift of 0 aligns nothing, so the
        // per-function shift takes over.
        let ground_truth = [
            gt("a", &["int"], &[-8], 4, None),
            gt("b", &["int"], &[-12], 4, None),
        ];
        let decompiled = [
            dv("v1", "int", Some(88), Some(4), None),
            dv("v2", "int", Some(84), Some(4), None),
        ];
        let result = match_structured(&ground_truth, &decompiled, Some(0));
        assert_eq!(result.shift, Some(-96));
        assert_eq!(result.matched_by_offset, 2);
        assert_eq!(result.true_positives, 2);
    }

    #[test]
    fn calibration_override_does_not_fire_when_the_binary_shift_aligns_something() {
        // The escape hatch is deliberately narrow: a binary-wide shift that
        // aligns even ONE offset is kept, even if a per-function shift would
        // align more. Here `0` aligns `a`; a per-function `-96` would align
        // `b` too, and is refused.
        let ground_truth = [
            gt("a", &["int"], &[-8], 4, None),
            gt("b", &["int"], &[-12], 4, None),
            gt("c", &["int"], &[-16], 4, None),
        ];
        let decompiled = [
            dv("v1", "int", Some(-8), Some(4), None),
            dv("v2", "int", Some(84), Some(4), None),
            dv("v3", "int", Some(80), Some(4), None),
        ];
        let result = match_structured(&ground_truth, &decompiled, Some(0));
        assert_eq!(result.shift, Some(0));
        assert_eq!(result.matched_by_offset, 1);
    }

    #[test]
    fn binary_calibration_drops_functions_with_an_empty_side() {
        // `_calibrate_binary_shift` only contributes a pair when BOTH sides
        // have offsets; a function whose decompiled variables are all
        // register-resident votes on nothing.
        let with_offsets = [
            gt("a", &["int"], &[-8], 4, None),
            gt("b", &["int"], &[-16], 4, None),
        ];
        let registers = [gt("r", &["int"], &[], 4, None)];
        let shifted = [
            dv("v1", "int", Some(-12), Some(4), None),
            dv("v2", "int", Some(-20), Some(4), None),
        ];
        let regs = [dv("uVar1", "int", None, Some(4), None)];
        let shift = binary_calibration_shift(&[(&with_offsets, &shifted), (&registers, &regs)]);
        assert_eq!(shift, Some(4));
    }

    // ---------------------------------------------------------------------
    // Unit tests: T-7, the score -- and what it does not measure.
    // ---------------------------------------------------------------------

    #[test]
    fn t7_score_is_tp_over_the_three_counts() {
        let with_false_positives = FunctionTypeMatch {
            true_positives: 3,
            false_positives: 1,
            false_negatives: 0,
            ..FunctionTypeMatch::default()
        };
        assert!((with_false_positives.score() - 0.75).abs() < 1e-12);

        // Misses must be in the denominator too. Without this case the score
        // is indistinguishable from precision, `tp / (tp + fp)`, which is
        // what a decompiler that simply omits every variable it is unsure of
        // would be scored on -- and it would score 1.0.
        let with_misses = FunctionTypeMatch {
            true_positives: 3,
            false_positives: 0,
            false_negatives: 1,
            ..FunctionTypeMatch::default()
        };
        assert!((with_misses.score() - 0.75).abs() < 1e-12);

        let with_both = FunctionTypeMatch {
            true_positives: 1,
            false_positives: 1,
            false_negatives: 2,
            ..FunctionTypeMatch::default()
        };
        assert!((with_both.score() - 0.25).abs() < 1e-12);

        // The abstaining decompiler, end to end: it recovers one variable
        // correctly and says nothing about three more. Precision would call
        // that perfect; the reference calls it 0.25.
        let ground_truth = [
            gt("a", &["int"], &[-4], 4, None),
            gt("b", &["int"], &[-8], 4, None),
            gt("c", &["int"], &[-12], 4, None),
            gt("d", &["int"], &[-16], 4, None),
        ];
        let decompiled = [dv("a", "int", Some(-4), Some(4), None)];
        let result = match_structured(&ground_truth, &decompiled, None);
        assert_eq!(
            (
                result.true_positives,
                result.false_positives,
                result.false_negatives
            ),
            (1, 0, 3)
        );
        assert!((result.score() - 0.25).abs() < 1e-12);
    }

    #[test]
    fn t7_an_empty_denominator_scores_zero() {
        assert_eq!(FunctionTypeMatch::default().score(), 0.0);
    }

    #[test]
    fn t7_the_denominator_is_always_the_ground_truth_count() {
        // The finding this module documents: the reference's `fn` counts
        // UNDECIDED GROUND-TRUTH variables, so tp + fp + fn is identically the
        // number of ground-truth variables and the score is recall, not a
        // Jaccard. Verified here on a shape with a miss, a false positive, a
        // hit and four unmatched decompiled variables; verified on all 10,272
        // differential cases by `differential_corpus_reproduces_the_reference`.
        let ground_truth = [
            gt("a", &["int"], &[-4], 4, None),
            gt("b", &["int"], &[-8], 4, None),
            gt("c", &["int"], &[], 4, None),
        ];
        let decompiled = [
            dv("a", "int", Some(-4), Some(4), None),
            dv("b", "char *", Some(-8), Some(8), None),
            dv("j1", "int", Some(-100), Some(4), None),
            dv("j2", "int", Some(-104), Some(4), None),
            dv("j3", "int", Some(-108), Some(4), None),
            dv("j4", "int", Some(-112), Some(4), None),
        ];
        let result = match_structured(&ground_truth, &decompiled, None);
        assert_eq!(
            result.true_positives + result.false_positives + result.false_negatives,
            result.gt_vars
        );
        assert_eq!(result.decomp_vars, 6);
        assert_eq!(
            (
                result.true_positives,
                result.false_positives,
                result.false_negatives
            ),
            (1, 1, 1)
        );
    }

    #[test]
    fn t7_spurious_variables_are_free() {
        // A decompiler that invents variables corresponding to nothing pays
        // nothing, as long as they do not collide with a real one. This is
        // the metric's blind spot, and it is the reference's behaviour, so it
        // is asserted rather than fixed.
        let ground_truth = [gt("a", &["int"], &[-4], 4, Some(0))];
        let honest = [dv("a", "int", Some(-4), Some(4), Some(0))];
        let inflated = [
            dv("a", "int", Some(-4), Some(4), Some(0)),
            dv("junk0", "double", Some(-1000), Some(8), None),
            dv("junk1", "double", Some(-1008), Some(8), None),
            dv("junk2", "double", Some(-1016), Some(8), None),
        ];
        let honest_result = match_structured(&ground_truth, &honest, None);
        let inflated_result = match_structured(&ground_truth, &inflated, None);
        assert_eq!(honest_result.score(), 1.0);
        assert_eq!(inflated_result.score(), 1.0);
        assert_eq!(honest_result.decomp_vars, 1);
        assert_eq!(inflated_result.decomp_vars, 4);
    }

    #[test]
    fn t7_a_null_backend_that_echoes_widths_scores_well() {
        // The analogue of the `ged` audit's finding about trivial functions.
        // A "decompiler" that recovers nothing but each slot's WIDTH -- no
        // types, no names, just `undefinedN` at the right offsets -- scores a
        // perfect 1.0 on a function whose locals are all integers, which is
        // most of them. The metric is measuring width recovery there, not
        // type recovery.
        let ground_truth = [
            gt("count", &["int"], &[-4], 4, None),
            gt("total", &["long int", "long"], &[-16], 8, None),
            gt("flag", &["_Bool"], &[-17], 1, None),
            gt("code", &["short int", "short"], &[-20], 2, None),
        ];
        let width_only = [
            dv("local_4", "undefined4", None, Some(4), None),
            dv("local_10", "undefined8", None, Some(8), None),
            dv("local_11", "undefined1", None, Some(1), None),
            dv("local_14", "undefined2", None, Some(2), None),
        ];
        let result = match_structured(&ground_truth, &width_only, None);
        assert_eq!(result.score(), 1.0);
        assert_eq!(result.matched_by_offset, 4);
        // And the same backend scores 0 the moment a local is a pointer or a
        // float -- which is the discrimination the rule preserves.
        let pointers = [
            gt("p", &["char *"], &[-8], 8, None),
            gt("d", &["double"], &[-16], 8, None),
        ];
        let widths = [
            dv("local_8", "undefined8", None, Some(8), None),
            dv("local_10", "undefined8", None, Some(8), None),
        ];
        assert_eq!(match_structured(&pointers, &widths, None).score(), 0.0);
    }

    // ---------------------------------------------------------------------
    // The differential corpus.
    // ---------------------------------------------------------------------

    /// 440 differential cases, each an input and the reference's answer to it.
    ///
    /// Embedded rather than kept in a fixture file so the gate is
    /// self-contained: this module's brief is one file, and a corpus that
    /// lives beside the code cannot go stale relative to it or be lost in a
    /// move.
    ///
    /// **Provenance.** The ground-truth half of every case is real DWARF,
    /// extracted by DecBench's own `extract_ground_truth_types` from
    /// `tests/decompiler_fixtures/build/*.so` (gcc and clang, `-O0` and
    /// `-O2`) --- 321 functions in all. The decompiled half is that ground
    /// truth perturbed under a fixed seed the way real backends perturb it:
    /// `echo` (a perfect recovery), `ghidra` (`local_1c` names with the
    /// structured offset dropped and types widened to `undefinedN`), `ida`
    /// (frame-bottom `var_20` offsets, `+96` from DWARF's, and `__int64` /
    /// `_QWORD` spellings), `degraded` (same-width uncommitted types),
    /// `wrong` (a committed but incorrect type), `noisy` (dropped variables,
    /// perturbed offsets, cleared argument indexes, resized slots),
    /// `spurious` (extra variables corresponding to nothing) and `shadow` (an
    /// extra variable colliding with a real one's argument index, offset and
    /// name, inserted first). Each is scored under four calibration shifts:
    /// none, 0, +96 and -8.
    ///
    /// **Expectations.** Every `EXPECT` line is the output of
    /// `TypeMatchMetric._match_structured` on the inputs above it --- ten
    /// fields: `tp fp fn shift matched_by_arg matched_by_offset
    /// matched_by_name decomp_stack_vars gt_stack_vars gt_arg_vars`.
    ///
    /// **Selection.** A stratified subsample of a 10,272-case run, one case
    /// per distinct behaviour signature (mode x input shift x which passes
    /// fired x whether there were false positives, misses, a shift override,
    /// a zero score, a perfect score, and more decompiled variables than
    /// ground-truth ones), plus the twenty smallest shift-override cases and
    /// the twelve widest functions. 153 of the 440 exercise the per-function
    /// shift override. The full 10,272 also reproduced the reference exactly;
    /// this subset is what stays in the gate.
    const DIFFERENTIAL_CORPUS: &str = r##"CASE 01_conditional_polarity-clang-O0.so:cmp_unsigned|noisy|0
SHIFT 0
GT a|4|0|8|int;unsigned int
GT b|4|1|4|int;unsigned int
DEC b|int|4|4|-
EXPECT 1 0 1 0 0 1 0 1 2 2
CASE 01_conditional_polarity-clang-O0.so:cmp_unsigned|noisy|None
SHIFT -
GT a|4|0|8|int;unsigned int
GT b|4|1|4|int;unsigned int
DEC b|int|4|4|-
EXPECT 1 0 1 0 0 1 0 1 2 2
CASE 01_conditional_polarity-gcc-O0.so:classify|shadow|-8
SHIFT -8
GT a|4|0|-4|int
GT b|4|1|-8|int
DEC b|char *|-8|4|1
DEC a|int|-4|4|0
DEC b|int|-8|4|1
EXPECT 1 1 0 0 2 0 0 3 2 2
CASE 01_conditional_polarity-gcc-O0.so:classify|shadow|0
SHIFT 0
GT a|4|0|-4|int
GT b|4|1|-8|int
DEC b|char *|-8|4|1
DEC a|int|-4|4|0
DEC b|int|-8|4|1
EXPECT 1 1 0 0 2 0 0 3 2 2
CASE 01_conditional_polarity-gcc-O0.so:classify|shadow|96
SHIFT 96
GT a|4|0|-4|int
GT b|4|1|-8|int
DEC b|char *|-8|4|1
DEC a|int|-4|4|0
DEC b|int|-8|4|1
EXPECT 1 1 0 0 2 0 0 3 2 2
CASE 01_conditional_polarity-gcc-O0.so:classify|shadow|None
SHIFT -
GT a|4|0|-4|int
GT b|4|1|-8|int
DEC b|char *|-8|4|1
DEC a|int|-4|4|0
DEC b|int|-8|4|1
EXPECT 1 1 0 0 2 0 0 3 2 2
CASE 01_conditional_polarity-gcc-O0.so:classify|wrong|-8
SHIFT -8
GT a|4|0|-4|int
GT b|4|1|-8|int
DEC a|int|-4|4|0
DEC b|bool|-8|4|1
EXPECT 1 1 0 0 2 0 0 2 2 2
CASE 01_conditional_polarity-gcc-O0.so:classify|wrong|0
SHIFT 0
GT a|4|0|-4|int
GT b|4|1|-8|int
DEC a|int|-4|4|0
DEC b|bool|-8|4|1
EXPECT 1 1 0 0 2 0 0 2 2 2
CASE 01_conditional_polarity-gcc-O0.so:classify|wrong|96
SHIFT 96
GT a|4|0|-4|int
GT b|4|1|-8|int
DEC a|int|-4|4|0
DEC b|bool|-8|4|1
EXPECT 1 1 0 0 2 0 0 2 2 2
CASE 01_conditional_polarity-gcc-O0.so:classify|wrong|None
SHIFT -
GT a|4|0|-4|int
GT b|4|1|-8|int
DEC a|int|-4|4|0
DEC b|bool|-8|4|1
EXPECT 1 1 0 0 2 0 0 2 2 2
CASE 01_conditional_polarity-gcc-O0.so:cmp_unsigned|noisy|0
SHIFT 0
GT a|4|0|-4|int;unsigned int
GT b|4|1|-8|int;unsigned int
DEC a|int|-12|1|-
DEC v14|int|-8|4|-
EXPECT 2 0 0 0 0 1 1 2 2 2
CASE 01_conditional_polarity-gcc-O0.so:cmp_unsigned|noisy|None
SHIFT -
GT a|4|0|-4|int;unsigned int
GT b|4|1|-8|int;unsigned int
DEC a|int|-12|1|-
DEC v14|int|-8|4|-
EXPECT 2 0 0 0 0 1 1 2 2 2
CASE 01_conditional_polarity-gcc-O0.so:early_return_ge|echo|-8
SHIFT -8
GT x|4|0|-4|int
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return_ge|echo|96
SHIFT 96
GT x|4|0|-4|int
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return_ge|ghidra|-8
SHIFT -8
GT x|4|0|-4|int
DEC local_4|undefined4|-|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return_ge|ghidra|96
SHIFT 96
GT x|4|0|-4|int
DEC local_4|undefined4|-|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return_ge|ida|None
SHIFT -
GT x|4|0|-4|int
DEC var_4|int|92|4|0
EXPECT 1 0 0 -96 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return_ge|noisy|-8
SHIFT -8
GT x|4|0|-4|int
DEC v10|long long|0|16|-
EXPECT 0 1 0 -4 0 1 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return_ge|noisy|0
SHIFT 0
GT x|4|0|-4|int
DEC v10|long long|0|16|-
EXPECT 0 1 0 -4 0 1 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return_ge|noisy|96
SHIFT 96
GT x|4|0|-4|int
DEC v10|long long|0|16|-
EXPECT 0 1 0 -4 0 1 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return_ge|noisy|None
SHIFT -
GT x|4|0|-4|int
DEC v10|long long|0|16|-
EXPECT 0 1 0 -4 0 1 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|degraded|-8
SHIFT -8
GT x|4|0|-4|int
DEC x|__int32|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|degraded|0
SHIFT 0
GT x|4|0|-4|int
DEC x|__int32|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|degraded|96
SHIFT 96
GT x|4|0|-4|int
DEC x|__int32|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|degraded|None
SHIFT -
GT x|4|0|-4|int
DEC x|__int32|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|echo|-8
SHIFT -8
GT x|4|0|-4|int
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|echo|0
SHIFT 0
GT x|4|0|-4|int
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|echo|96
SHIFT 96
GT x|4|0|-4|int
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|echo|None
SHIFT -
GT x|4|0|-4|int
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|ghidra|-8
SHIFT -8
GT x|4|0|-4|int
DEC local_4|int|-|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|ghidra|0
SHIFT 0
GT x|4|0|-4|int
DEC local_4|int|-|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|ghidra|96
SHIFT 96
GT x|4|0|-4|int
DEC local_4|int|-|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|ghidra|None
SHIFT -
GT x|4|0|-4|int
DEC local_4|int|-|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|ida|-8
SHIFT -8
GT x|4|0|-4|int
DEC var_4|__int32|92|4|0
EXPECT 1 0 0 -96 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|ida|0
SHIFT 0
GT x|4|0|-4|int
DEC var_4|__int32|92|4|0
EXPECT 1 0 0 -96 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|ida|96
SHIFT 96
GT x|4|0|-4|int
DEC var_4|__int32|92|4|0
EXPECT 1 0 0 -96 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|ida|None
SHIFT -
GT x|4|0|-4|int
DEC var_4|__int32|92|4|0
EXPECT 1 0 0 -96 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|noisy|-8
SHIFT -8
GT x|4|0|-4|int
DEC x|int|4|4|-
EXPECT 1 0 0 -8 0 1 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|noisy|0
SHIFT 0
GT x|4|0|-4|int
DEC x|int|4|4|-
EXPECT 1 0 0 -8 0 1 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|noisy|96
SHIFT 96
GT x|4|0|-4|int
DEC x|int|4|4|-
EXPECT 1 0 0 -8 0 1 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|noisy|None
SHIFT -
GT x|4|0|-4|int
DEC x|int|4|4|-
EXPECT 1 0 0 -8 0 1 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|shadow|-8
SHIFT -8
GT x|4|0|-4|int
DEC x|char *|-4|4|0
DEC x|int|-4|4|0
EXPECT 0 1 0 0 1 0 0 2 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|shadow|0
SHIFT 0
GT x|4|0|-4|int
DEC x|char *|-4|4|0
DEC x|int|-4|4|0
EXPECT 0 1 0 0 1 0 0 2 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|shadow|96
SHIFT 96
GT x|4|0|-4|int
DEC x|char *|-4|4|0
DEC x|int|-4|4|0
EXPECT 0 1 0 0 1 0 0 2 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|shadow|None
SHIFT -
GT x|4|0|-4|int
DEC x|char *|-4|4|0
DEC x|int|-4|4|0
EXPECT 0 1 0 0 1 0 0 2 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|wrong|-8
SHIFT -8
GT x|4|0|-4|int
DEC x|struct Node *|-4|4|0
EXPECT 0 1 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|wrong|0
SHIFT 0
GT x|4|0|-4|int
DEC x|struct Node *|-4|4|0
EXPECT 0 1 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|wrong|96
SHIFT 96
GT x|4|0|-4|int
DEC x|struct Node *|-4|4|0
EXPECT 0 1 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:early_return|wrong|None
SHIFT -
GT x|4|0|-4|int
DEC x|struct Node *|-4|4|0
EXPECT 0 1 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:elseif|noisy|-8
SHIFT -8
GT x|4|0|-4|int
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:elseif|noisy|0
SHIFT 0
GT x|4|0|-4|int
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:elseif|noisy|96
SHIFT 96
GT x|4|0|-4|int
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:elseif|noisy|None
SHIFT -
GT x|4|0|-4|int
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:sc_and|noisy|-8
SHIFT -8
GT x|4|0|-4|int
GT y|4|1|-8|int
DEC v0|uint8|-12|4|-
EXPECT 1 0 1 4 0 1 0 1 2 2
CASE 01_conditional_polarity-gcc-O0.so:sc_and|noisy|0
SHIFT 0
GT x|4|0|-4|int
GT y|4|1|-8|int
DEC v0|uint8|-12|4|-
EXPECT 1 0 1 4 0 1 0 1 2 2
CASE 01_conditional_polarity-gcc-O0.so:sc_and|noisy|96
SHIFT 96
GT x|4|0|-4|int
GT y|4|1|-8|int
DEC v0|uint8|-12|4|-
EXPECT 1 0 1 4 0 1 0 1 2 2
CASE 01_conditional_polarity-gcc-O0.so:sc_and|noisy|None
SHIFT -
GT x|4|0|-4|int
GT y|4|1|-8|int
DEC v0|uint8|-12|4|-
EXPECT 1 0 1 4 0 1 0 1 2 2
CASE 01_conditional_polarity-gcc-O0.so:ternary|noisy|-8
SHIFT -8
GT x|4|0|-4|int
DEC x|int|-4|4|-
EXPECT 1 0 0 0 0 1 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:ternary|noisy|0
SHIFT 0
GT x|4|0|-4|int
DEC x|int|-4|4|-
EXPECT 1 0 0 0 0 1 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:ternary|noisy|None
SHIFT -
GT x|4|0|-4|int
DEC x|int|-4|4|-
EXPECT 1 0 0 0 0 1 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:ternary|shadow|-8
SHIFT -8
GT x|4|0|-4|int
DEC x|unsigned int|-4|4|0
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 2 1 1
CASE 01_conditional_polarity-gcc-O0.so:ternary|shadow|0
SHIFT 0
GT x|4|0|-4|int
DEC x|unsigned int|-4|4|0
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 2 1 1
CASE 01_conditional_polarity-gcc-O0.so:ternary|shadow|96
SHIFT 96
GT x|4|0|-4|int
DEC x|unsigned int|-4|4|0
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 2 1 1
CASE 01_conditional_polarity-gcc-O0.so:ternary|shadow|None
SHIFT -
GT x|4|0|-4|int
DEC x|unsigned int|-4|4|0
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 2 1 1
CASE 01_conditional_polarity-gcc-O0.so:ternary|wrong|-8
SHIFT -8
GT x|4|0|-4|int
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:ternary|wrong|0
SHIFT 0
GT x|4|0|-4|int
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:ternary|wrong|96
SHIFT 96
GT x|4|0|-4|int
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O0.so:ternary|wrong|None
SHIFT -
GT x|4|0|-4|int
DEC x|int|-4|4|0
EXPECT 1 0 0 0 1 0 0 1 1 1
CASE 01_conditional_polarity-gcc-O2.so:classify|shadow|96
SHIFT 96
GT a|4|0|-|int
GT b|4|1|-|int
DEC b|char *|-|4|1
DEC a|int|-|4|0
DEC b|int|-|4|1
EXPECT 1 1 0 96 2 0 0 0 0 2
CASE 01_conditional_polarity-gcc-O2.so:cmp_signed|noisy|96
SHIFT 96
GT a|4|0|-|int
GT b|4|1|-|int
DEC a|int|-|3|-
DEC b|int|-|4|1
EXPECT 2 0 0 96 1 0 1 0 0 2
CASE 01_conditional_polarity-gcc-O2.so:cmp_signed|wrong|96
SHIFT 96
GT a|4|0|-|int
GT b|4|1|-|int
DEC a|struct Node *|-|4|0
DEC b|int|-|4|1
EXPECT 1 1 0 96 2 0 0 0 0 2
CASE 01_conditional_polarity-gcc-O2.so:early_return|degraded|-8
SHIFT -8
GT x|4|0|-|int
DEC x|undefined4|-|4|0
EXPECT 1 0 0 -8 1 0 0 0 0 1
CASE 01_conditional_polarity-gcc-O2.so:early_return|degraded|96
SHIFT 96
GT x|4|0|-|int
DEC x|undefined4|-|4|0
EXPECT 1 0 0 96 1 0 0 0 0 1
CASE 01_conditional_polarity-gcc-O2.so:early_return|echo|-8
SHIFT -8
GT x|4|0|-|int
DEC x|int|-|4|0
EXPECT 1 0 0 -8 1 0 0 0 0 1
CASE 01_conditional_polarity-gcc-O2.so:early_return|echo|96
SHIFT 96
GT x|4|0|-|int
DEC x|int|-|4|0
EXPECT 1 0 0 96 1 0 0 0 0 1
CASE 01_conditional_polarity-gcc-O2.so:early_return|ghidra|-8
SHIFT -8
GT x|4|0|-|int
DEC x|int|-|4|0
EXPECT 1 0 0 -8 1 0 0 0 0 1
CASE 01_conditional_polarity-gcc-O2.so:early_return|ghidra|96
SHIFT 96
GT x|4|0|-|int
DEC x|int|-|4|0
EXPECT 1 0 0 96 1 0 0 0 0 1
CASE 01_conditional_polarity-gcc-O2.so:early_return|ida|-8
SHIFT -8
GT x|4|0|-|int
DEC x|int|-|4|0
EXPECT 1 0 0 -8 1 0 0 0 0 1
CASE 01_conditional_polarity-gcc-O2.so:early_return|ida|0
SHIFT 0
GT x|4|0|-|int
DEC x|int|-|4|0
EXPECT 1 0 0 0 1 0 0 0 0 1
CASE 01_conditional_polarity-gcc-O2.so:early_return|ida|96
SHIFT 96
GT x|4|0|-|int
DEC x|int|-|4|0
EXPECT 1 0 0 96 1 0 0 0 0 1
CASE 01_conditional_polarity-gcc-O2.so:early_return|ida|None
SHIFT -
GT x|4|0|-|int
DEC x|int|-|4|0
EXPECT 1 0 0 0 1 0 0 0 0 1
CASE 01_conditional_polarity-gcc-O2.so:early_return|shadow|-8
SHIFT -8
GT x|4|0|-|int
DEC x|struct Node *|-|4|0
DEC x|int|-|4|0
EXPECT 0 1 0 -8 1 0 0 0 0 1
CASE 01_conditional_polarity-gcc-O2.so:early_return|shadow|96
SHIFT 96
GT x|4|0|-|int
DEC x|struct Node *|-|4|0
DEC x|int|-|4|0
EXPECT 0 1 0 96 1 0 0 0 0 1
CASE 01_conditional_polarity-gcc-O2.so:early_return|wrong|-8
SHIFT -8
GT x|4|0|-|int
DEC x|bool|-|4|0
EXPECT 0 1 0 -8 1 0 0 0 0 1
CASE 01_conditional_polarity-gcc-O2.so:early_return|wrong|96
SHIFT 96
GT x|4|0|-|int
DEC x|bool|-|4|0
EXPECT 0 1 0 96 1 0 0 0 0 1
CASE 01_conditional_polarity-gcc-O2.so:sc_or|noisy|-8
SHIFT -8
GT x|4|0|-|int
GT y|4|1|-|int
DEC y|int|-|4|1
EXPECT 1 0 1 -8 1 0 0 0 0 2
CASE 01_conditional_polarity-gcc-O2.so:sc_or|noisy|96
SHIFT 96
GT x|4|0|-|int
GT y|4|1|-|int
DEC y|int|-|4|1
EXPECT 1 0 1 96 1 0 0 0 0 2
CASE 01_conditional_polarity-gcc-O2.so:ternary|noisy|-8
SHIFT -8
GT x|4|0|-|int
DEC x|int|-|4|0
EXPECT 1 0 0 -8 1 0 0 0 0 1
CASE 01_conditional_polarity-gcc-O2.so:ternary|noisy|96
SHIFT 96
GT x|4|0|-|int
DEC x|int|-|4|0
EXPECT 1 0 0 96 1 0 0 0 0 1
CASE 02_integer_widths-clang-O0.so:add_wrap32|shadow|-8
SHIFT -8
GT a|4|0|12|int
GT b|4|1|8|int
GT r|4|-|4|__uint32_t;int;unsigned int
DEC a|unsigned int|12|4|0
DEC a|int|12|4|0
DEC b|int|8|4|1
DEC r|__uint32_t|4|4|-
EXPECT 3 0 0 -8 2 1 0 4 3 2
CASE 02_integer_widths-clang-O0.so:deposit_byte1|noisy|0
SHIFT 0
GT x|4|0|12|int;unsigned int
GT b|4|1|8|int;unsigned int
GT v|4|-|4|__uint32_t;int;unsigned int
DEC x|int|16|16|-
DEC b|int|8|4|1
DEC v|__uint32_t|4|4|-
EXPECT 3 0 0 0 1 1 1 3 3 2
CASE 02_integer_widths-clang-O0.so:deposit_byte1|noisy|96
SHIFT 96
GT x|4|0|12|int;unsigned int
GT b|4|1|8|int;unsigned int
GT v|4|-|4|__uint32_t;int;unsigned int
DEC x|int|16|16|-
DEC b|int|8|4|1
DEC v|__uint32_t|4|4|-
EXPECT 3 0 0 0 1 1 1 3 3 2
CASE 02_integer_widths-clang-O0.so:deposit_byte1|noisy|None
SHIFT -
GT x|4|0|12|int;unsigned int
GT b|4|1|8|int;unsigned int
GT v|4|-|4|__uint32_t;int;unsigned int
DEC x|int|16|16|-
DEC b|int|8|4|1
DEC v|__uint32_t|4|4|-
EXPECT 3 0 0 0 1 1 1 3 3 2
CASE 02_integer_widths-clang-O0.so:rt_u64|noisy|-8
SHIFT -8
GT x|4|0|12|int;unsigned int
GT v|8|-|0|__uint64_t;long;long long;unsigned long
DEC x|int|4|4|-
DEC v0|__int16|0|3|-
EXPECT 1 1 0 0 0 1 1 2 2 1
CASE 02_integer_widths-clang-O0.so:rt_u64|noisy|0
SHIFT 0
GT x|4|0|12|int;unsigned int
GT v|8|-|0|__uint64_t;long;long long;unsigned long
DEC x|int|4|4|-
DEC v0|__int16|0|3|-
EXPECT 1 1 0 0 0 1 1 2 2 1
CASE 02_integer_widths-clang-O0.so:rt_u64|noisy|96
SHIFT 96
GT x|4|0|12|int;unsigned int
GT v|8|-|0|__uint64_t;long;long long;unsigned long
DEC x|int|4|4|-
DEC v0|__int16|0|3|-
EXPECT 1 1 0 0 0 1 1 2 2 1
CASE 02_integer_widths-clang-O0.so:rt_u64|noisy|None
SHIFT -
GT x|4|0|12|int;unsigned int
GT v|8|-|0|__uint64_t;long;long long;unsigned long
DEC x|int|4|4|-
DEC v0|__int16|0|3|-
EXPECT 1 1 0 0 0 1 1 2 2 1
CASE 02_integer_widths-clang-O0.so:smul_high64|noisy|-8
SHIFT -8
GT a|8|0|8|__int64_t;long long
GT b|8|1|0|__int64_t;long long
DEC a|__int64_t|8|8|0
DEC b|__int64_t|0|2|-
EXPECT 2 0 0 -8 1 0 1 2 2 2
CASE 02_integer_widths-clang-O0.so:wrap_sub_u32|noisy|-8
SHIFT -8
GT a|4|0|12|__uint32_t;int;unsigned int
GT b|4|1|8|__uint32_t;int;unsigned int
GT r|4|-|4|__uint32_t;int;unsigned int
DEC v16|__uint32_t|4|8|-
DEC b|__uint32_t|8|4|1
EXPECT 2 0 1 0 1 1 0 2 3 2
CASE 02_integer_widths-clang-O0.so:wrap_sub_u32|noisy|0
SHIFT 0
GT a|4|0|12|__uint32_t;int;unsigned int
GT b|4|1|8|__uint32_t;int;unsigned int
GT r|4|-|4|__uint32_t;int;unsigned int
DEC v16|__uint32_t|4|8|-
DEC b|__uint32_t|8|4|1
EXPECT 2 0 1 0 1 1 0 2 3 2
CASE 02_integer_widths-clang-O0.so:wrap_sub_u32|noisy|96
SHIFT 96
GT a|4|0|12|__uint32_t;int;unsigned int
GT b|4|1|8|__uint32_t;int;unsigned int
GT r|4|-|4|__uint32_t;int;unsigned int
DEC v16|__uint32_t|4|8|-
DEC b|__uint32_t|8|4|1
EXPECT 2 0 1 0 1 1 0 2 3 2
CASE 02_integer_widths-clang-O0.so:wrap_sub_u32|noisy|None
SHIFT -
GT a|4|0|12|__uint32_t;int;unsigned int
GT b|4|1|8|__uint32_t;int;unsigned int
GT r|4|-|4|__uint32_t;int;unsigned int
DEC v16|__uint32_t|4|8|-
DEC b|__uint32_t|8|4|1
EXPECT 2 0 1 0 1 1 0 2 3 2
CASE 02_integer_widths-gcc-O0.so:extract_byte1|spurious|-8
SHIFT -8
GT x|4|0|-4|int;unsigned int
DEC x|int|-4|4|0
DEC junk0|struct Node *|-1000|4|-
EXPECT 1 0 0 0 1 0 0 2 1 1
CASE 02_integer_widths-gcc-O0.so:extract_byte1|spurious|0
SHIFT 0
GT x|4|0|-4|int;unsigned int
DEC x|int|-4|4|0
DEC junk0|struct Node *|-1000|4|-
EXPECT 1 0 0 0 1 0 0 2 1 1
CASE 02_integer_widths-gcc-O0.so:extract_byte1|spurious|96
SHIFT 96
GT x|4|0|-4|int;unsigned int
DEC x|int|-4|4|0
DEC junk0|struct Node *|-1000|4|-
EXPECT 1 0 0 0 1 0 0 2 1 1
CASE 02_integer_widths-gcc-O0.so:extract_byte1|spurious|None
SHIFT -
GT x|4|0|-4|int;unsigned int
DEC x|int|-4|4|0
DEC junk0|struct Node *|-1000|4|-
EXPECT 1 0 0 0 1 0 0 2 1 1
CASE 02_integer_widths-gcc-O0.so:extract_byte3|noisy|-8
SHIFT -8
GT x|4|0|-4|int;unsigned int
EXPECT 0 0 1 -8 0 0 0 0 1 1
CASE 02_integer_widths-gcc-O0.so:extract_byte3|noisy|0
SHIFT 0
GT x|4|0|-4|int;unsigned int
EXPECT 0 0 1 0 0 0 0 0 1 1
CASE 02_integer_widths-gcc-O0.so:extract_byte3|noisy|96
SHIFT 96
GT x|4|0|-4|int;unsigned int
EXPECT 0 0 1 96 0 0 0 0 1 1
CASE 02_integer_widths-gcc-O0.so:extract_byte3|noisy|None
SHIFT -
GT x|4|0|-4|int;unsigned int
EXPECT 0 0 1 0 0 0 0 0 1 1
CASE 02_integer_widths-gcc-O0.so:reconstruct_64|noisy|-8
SHIFT -8
GT hi|4|0|-20|__uint32_t;int;unsigned int
GT lo|4|1|-24|__uint32_t;int;unsigned int
GT v|8|-|-8|__uint64_t;long int;long long;long unsigned int
DEC v3|char|-20|4|-
EXPECT 0 1 2 0 0 1 0 1 3 2
CASE 02_integer_widths-gcc-O0.so:reconstruct_64|noisy|0
SHIFT 0
GT hi|4|0|-20|__uint32_t;int;unsigned int
GT lo|4|1|-24|__uint32_t;int;unsigned int
GT v|8|-|-8|__uint64_t;long int;long long;long unsigned int
DEC v3|char|-20|4|-
EXPECT 0 1 2 0 0 1 0 1 3 2
CASE 02_integer_widths-gcc-O0.so:reconstruct_64|noisy|None
SHIFT -
GT hi|4|0|-20|__uint32_t;int;unsigned int
GT lo|4|1|-24|__uint32_t;int;unsigned int
GT v|8|-|-8|__uint64_t;long int;long long;long unsigned int
DEC v3|char|-20|4|-
EXPECT 0 1 2 0 0 1 0 1 3 2
CASE 02_integer_widths-gcc-O0.so:rotl16_3|noisy|-8
SHIFT -8
GT x|4|0|-20|int;unsigned int
GT v|2|-|-4|__uint16_t;short;short int;short unsigned int
GT r|2|-|-2|__uint16_t;short;short int;short unsigned int
DEC v|__uint16_t|-4|8|-
DEC v9|__int8|-6|16|-
EXPECT 1 1 1 2 0 2 0 2 3 1
CASE 02_integer_widths-gcc-O0.so:rotl16_3|noisy|96
SHIFT 96
GT x|4|0|-20|int;unsigned int
GT v|2|-|-4|__uint16_t;short;short int;short unsigned int
GT r|2|-|-2|__uint16_t;short;short int;short unsigned int
DEC v|__uint16_t|-4|8|-
DEC v9|__int8|-6|16|-
EXPECT 1 1 1 2 0 2 0 2 3 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|degraded|-8
SHIFT -8
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC x|dword|-20|4|0
DEC r|_DWORD|-4|4|-
EXPECT 2 0 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|degraded|0
SHIFT 0
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC x|dword|-20|4|0
DEC r|_DWORD|-4|4|-
EXPECT 2 0 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|degraded|96
SHIFT 96
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC x|dword|-20|4|0
DEC r|_DWORD|-4|4|-
EXPECT 2 0 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|degraded|None
SHIFT -
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC x|dword|-20|4|0
DEC r|_DWORD|-4|4|-
EXPECT 2 0 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|echo|-8
SHIFT -8
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC x|__uint32_t|-20|4|0
DEC r|__uint32_t|-4|4|-
EXPECT 2 0 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|echo|0
SHIFT 0
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC x|__uint32_t|-20|4|0
DEC r|__uint32_t|-4|4|-
EXPECT 2 0 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|echo|96
SHIFT 96
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC x|__uint32_t|-20|4|0
DEC r|__uint32_t|-4|4|-
EXPECT 2 0 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|echo|None
SHIFT -
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC x|__uint32_t|-20|4|0
DEC r|__uint32_t|-4|4|-
EXPECT 2 0 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|ghidra|-8
SHIFT -8
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC local_14|undefined4|-|4|0
DEC local_4|undefined4|-|4|-
EXPECT 2 0 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|ghidra|0
SHIFT 0
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC local_14|undefined4|-|4|0
DEC local_4|undefined4|-|4|-
EXPECT 2 0 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|ghidra|96
SHIFT 96
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC local_14|undefined4|-|4|0
DEC local_4|undefined4|-|4|-
EXPECT 2 0 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|ghidra|None
SHIFT -
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC local_14|undefined4|-|4|0
DEC local_4|undefined4|-|4|-
EXPECT 2 0 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|ida|-8
SHIFT -8
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC var_14|_QWORD|76|4|0
DEC var_4|__uint32_t|92|4|-
EXPECT 2 0 0 -96 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|ida|0
SHIFT 0
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC var_14|_QWORD|76|4|0
DEC var_4|__uint32_t|92|4|-
EXPECT 2 0 0 -96 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|ida|96
SHIFT 96
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC var_14|_QWORD|76|4|0
DEC var_4|__uint32_t|92|4|-
EXPECT 2 0 0 -96 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|ida|None
SHIFT -
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC var_14|_QWORD|76|4|0
DEC var_4|__uint32_t|92|4|-
EXPECT 2 0 0 -96 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|shadow|-8
SHIFT -8
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC x|int|-20|4|0
DEC x|__uint32_t|-20|4|0
DEC r|__uint32_t|-4|4|-
EXPECT 2 0 0 0 1 1 0 3 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|shadow|0
SHIFT 0
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC x|int|-20|4|0
DEC x|__uint32_t|-20|4|0
DEC r|__uint32_t|-4|4|-
EXPECT 2 0 0 0 1 1 0 3 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|shadow|96
SHIFT 96
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC x|int|-20|4|0
DEC x|__uint32_t|-20|4|0
DEC r|__uint32_t|-4|4|-
EXPECT 2 0 0 0 1 1 0 3 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|shadow|None
SHIFT -
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC x|int|-20|4|0
DEC x|__uint32_t|-20|4|0
DEC r|__uint32_t|-4|4|-
EXPECT 2 0 0 0 1 1 0 3 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|wrong|-8
SHIFT -8
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC x|void *|-20|4|0
DEC r|struct Node *|-4|4|-
EXPECT 0 2 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|wrong|0
SHIFT 0
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC x|void *|-20|4|0
DEC r|struct Node *|-4|4|-
EXPECT 0 2 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|wrong|96
SHIFT 96
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC x|void *|-20|4|0
DEC r|struct Node *|-4|4|-
EXPECT 0 2 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rotl32_7|wrong|None
SHIFT -
GT x|4|0|-20|__uint32_t;int;unsigned int
GT r|4|-|-4|__uint32_t;int;unsigned int
DEC x|void *|-20|4|0
DEC r|struct Node *|-4|4|-
EXPECT 0 2 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u16|noisy|-8
SHIFT -8
GT x|4|0|-20|int;unsigned int
GT v|2|-|-2|__uint16_t;short;short int;short unsigned int
DEC x|int|-20|4|0
DEC v11|struct Node *|-2|16|-
EXPECT 1 1 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u16|noisy|0
SHIFT 0
GT x|4|0|-20|int;unsigned int
GT v|2|-|-2|__uint16_t;short;short int;short unsigned int
DEC x|int|-20|4|0
DEC v11|struct Node *|-2|16|-
EXPECT 1 1 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u16|noisy|96
SHIFT 96
GT x|4|0|-20|int;unsigned int
GT v|2|-|-2|__uint16_t;short;short int;short unsigned int
DEC x|int|-20|4|0
DEC v11|struct Node *|-2|16|-
EXPECT 1 1 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u16|noisy|None
SHIFT -
GT x|4|0|-20|int;unsigned int
GT v|2|-|-2|__uint16_t;short;short int;short unsigned int
DEC x|int|-20|4|0
DEC v11|struct Node *|-2|16|-
EXPECT 1 1 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u16|spurious|-8
SHIFT -8
GT x|4|0|-20|int;unsigned int
GT v|2|-|-2|__uint16_t;short;short int;short unsigned int
DEC x|int|-20|4|0
DEC v|__uint16_t|-2|2|-
DEC junk0|int|-1000|1|-
EXPECT 2 0 0 0 1 1 0 3 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u16|spurious|0
SHIFT 0
GT x|4|0|-20|int;unsigned int
GT v|2|-|-2|__uint16_t;short;short int;short unsigned int
DEC x|int|-20|4|0
DEC v|__uint16_t|-2|2|-
DEC junk0|int|-1000|1|-
EXPECT 2 0 0 0 1 1 0 3 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u16|spurious|96
SHIFT 96
GT x|4|0|-20|int;unsigned int
GT v|2|-|-2|__uint16_t;short;short int;short unsigned int
DEC x|int|-20|4|0
DEC v|__uint16_t|-2|2|-
DEC junk0|int|-1000|1|-
EXPECT 2 0 0 0 1 1 0 3 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u16|spurious|None
SHIFT -
GT x|4|0|-20|int;unsigned int
GT v|2|-|-2|__uint16_t;short;short int;short unsigned int
DEC x|int|-20|4|0
DEC v|__uint16_t|-2|2|-
DEC junk0|int|-1000|1|-
EXPECT 2 0 0 0 1 1 0 3 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u32|noisy|-8
SHIFT -8
GT x|4|0|-20|int;unsigned int
GT v|4|-|-4|__uint32_t;int;unsigned int
DEC v16|uint8|-24|16|-
DEC v|__uint32_t|-8|4|-
EXPECT 1 1 0 4 0 2 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u32|noisy|0
SHIFT 0
GT x|4|0|-20|int;unsigned int
GT v|4|-|-4|__uint32_t;int;unsigned int
DEC v16|uint8|-24|16|-
DEC v|__uint32_t|-8|4|-
EXPECT 1 1 0 4 0 2 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u32|noisy|96
SHIFT 96
GT x|4|0|-20|int;unsigned int
GT v|4|-|-4|__uint32_t;int;unsigned int
DEC v16|uint8|-24|16|-
DEC v|__uint32_t|-8|4|-
EXPECT 1 1 0 4 0 2 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u32|noisy|None
SHIFT -
GT x|4|0|-20|int;unsigned int
GT v|4|-|-4|__uint32_t;int;unsigned int
DEC v16|uint8|-24|16|-
DEC v|__uint32_t|-8|4|-
EXPECT 1 1 0 4 0 2 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u32|shadow|-8
SHIFT -8
GT x|4|0|-20|int;unsigned int
GT v|4|-|-4|__uint32_t;int;unsigned int
DEC x|void *|-20|4|0
DEC x|int|-20|4|0
DEC v|__uint32_t|-4|4|-
EXPECT 1 1 0 0 1 1 0 3 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u32|shadow|0
SHIFT 0
GT x|4|0|-20|int;unsigned int
GT v|4|-|-4|__uint32_t;int;unsigned int
DEC x|void *|-20|4|0
DEC x|int|-20|4|0
DEC v|__uint32_t|-4|4|-
EXPECT 1 1 0 0 1 1 0 3 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u32|shadow|96
SHIFT 96
GT x|4|0|-20|int;unsigned int
GT v|4|-|-4|__uint32_t;int;unsigned int
DEC x|void *|-20|4|0
DEC x|int|-20|4|0
DEC v|__uint32_t|-4|4|-
EXPECT 1 1 0 0 1 1 0 3 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u32|shadow|None
SHIFT -
GT x|4|0|-20|int;unsigned int
GT v|4|-|-4|__uint32_t;int;unsigned int
DEC x|void *|-20|4|0
DEC x|int|-20|4|0
DEC v|__uint32_t|-4|4|-
EXPECT 1 1 0 0 1 1 0 3 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u64|noisy|-8
SHIFT -8
GT x|4|0|-20|int;unsigned int
GT v|8|-|-8|__uint64_t;long int;long long;long unsigned int
DEC x|int|-20|4|0
DEC v1|long|-8|8|-
EXPECT 2 0 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u64|noisy|0
SHIFT 0
GT x|4|0|-20|int;unsigned int
GT v|8|-|-8|__uint64_t;long int;long long;long unsigned int
DEC x|int|-20|4|0
DEC v1|long|-8|8|-
EXPECT 2 0 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u64|noisy|96
SHIFT 96
GT x|4|0|-20|int;unsigned int
GT v|8|-|-8|__uint64_t;long int;long long;long unsigned int
DEC x|int|-20|4|0
DEC v1|long|-8|8|-
EXPECT 2 0 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u64|noisy|None
SHIFT -
GT x|4|0|-20|int;unsigned int
GT v|8|-|-8|__uint64_t;long int;long long;long unsigned int
DEC x|int|-20|4|0
DEC v1|long|-8|8|-
EXPECT 2 0 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u8|noisy|-8
SHIFT -8
GT x|4|0|-20|int;unsigned int
GT v|1|-|-1|__uint8_t;char;unsigned char
DEC x|int|-20|4|0
DEC v|__uint8_t|3|4|-
EXPECT 2 0 0 0 1 0 1 2 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u8|noisy|0
SHIFT 0
GT x|4|0|-20|int;unsigned int
GT v|1|-|-1|__uint8_t;char;unsigned char
DEC x|int|-20|4|0
DEC v|__uint8_t|3|4|-
EXPECT 2 0 0 0 1 0 1 2 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u8|noisy|96
SHIFT 96
GT x|4|0|-20|int;unsigned int
GT v|1|-|-1|__uint8_t;char;unsigned char
DEC x|int|-20|4|0
DEC v|__uint8_t|3|4|-
EXPECT 2 0 0 0 1 0 1 2 2 1
CASE 02_integer_widths-gcc-O0.so:rt_u8|noisy|None
SHIFT -
GT x|4|0|-20|int;unsigned int
GT v|1|-|-1|__uint8_t;char;unsigned char
DEC x|int|-20|4|0
DEC v|__uint8_t|3|4|-
EXPECT 2 0 0 0 1 0 1 2 2 1
CASE 02_integer_widths-gcc-O0.so:sext_i16|wrong|-8
SHIFT -8
GT x|4|0|-20|int
GT v|2|-|-2|__int16_t;short;short int
DEC x|unsigned int|-20|4|0
DEC v|int|-2|2|-
EXPECT 1 1 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:sext_i16|wrong|0
SHIFT 0
GT x|4|0|-20|int
GT v|2|-|-2|__int16_t;short;short int
DEC x|unsigned int|-20|4|0
DEC v|int|-2|2|-
EXPECT 1 1 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:sext_i16|wrong|96
SHIFT 96
GT x|4|0|-20|int
GT v|2|-|-2|__int16_t;short;short int
DEC x|unsigned int|-20|4|0
DEC v|int|-2|2|-
EXPECT 1 1 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:sext_i16|wrong|None
SHIFT -
GT x|4|0|-20|int
GT v|2|-|-2|__int16_t;short;short int
DEC x|unsigned int|-20|4|0
DEC v|int|-2|2|-
EXPECT 1 1 0 0 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O0.so:sext_i8|noisy|-8
SHIFT -8
GT x|4|0|-20|int
GT v|1|-|-1|__int8_t;char;signed char
DEC x|int|-16|4|-
DEC v|__int8_t|-1|1|-
EXPECT 2 0 0 0 0 1 1 2 2 1
CASE 02_integer_widths-gcc-O0.so:sext_i8|noisy|96
SHIFT 96
GT x|4|0|-20|int
GT v|1|-|-1|__int8_t;char;signed char
DEC x|int|-16|4|-
DEC v|__int8_t|-1|1|-
EXPECT 2 0 0 0 0 1 1 2 2 1
CASE 02_integer_widths-gcc-O0.so:smul_high64|shadow|-8
SHIFT -8
GT a|8|0|-24|__int64_t;long int;long long
GT b|8|1|-32|__int64_t;long int;long long
DEC b|struct Node *|-32|8|1
DEC a|__int64_t|-24|8|0
DEC b|__int64_t|-32|8|1
EXPECT 1 1 0 -8 2 0 0 3 2 2
CASE 02_integer_widths-gcc-O0.so:smul_high64|wrong|-8
SHIFT -8
GT a|8|0|-24|__int64_t;long int;long long
GT b|8|1|-32|__int64_t;long int;long long
DEC a|double|-24|8|0
DEC b|long|-32|8|1
EXPECT 1 1 0 -8 2 0 0 2 2 2
CASE 02_integer_widths-gcc-O0.so:trunc_u16_after_mul|noisy|-8
SHIFT -8
GT x|4|0|-20|int;unsigned int
GT v|2|-|-2|__uint16_t;short;short int;short unsigned int
DEC x|int|-20|4|0
DEC v7|float|6|2|-
EXPECT 1 1 0 -8 1 1 0 2 2 1
CASE 02_integer_widths-gcc-O2.so:extract_byte1|spurious|-8
SHIFT -8
GT x|4|0|-|int;unsigned int
DEC x|int|-|4|0
DEC junk0|int *|-1000|8|-
EXPECT 1 0 0 -8 1 0 0 1 0 1
CASE 02_integer_widths-gcc-O2.so:extract_byte1|spurious|96
SHIFT 96
GT x|4|0|-|int;unsigned int
DEC x|int|-|4|0
DEC junk0|int *|-1000|8|-
EXPECT 1 0 0 96 1 0 0 1 0 1
CASE 02_integer_widths-gcc-O2.so:rotl32_7|degraded|-8
SHIFT -8
GT x|4|0|-|__uint32_t;int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|int4|-|4|0
DEC r|uint4|-|4|-
EXPECT 2 0 0 -8 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rotl32_7|degraded|96
SHIFT 96
GT x|4|0|-|__uint32_t;int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|int4|-|4|0
DEC r|uint4|-|4|-
EXPECT 2 0 0 96 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rotl32_7|echo|-8
SHIFT -8
GT x|4|0|-|__uint32_t;int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|__uint32_t|-|4|0
DEC r|__uint32_t|-|4|-
EXPECT 2 0 0 -8 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rotl32_7|echo|96
SHIFT 96
GT x|4|0|-|__uint32_t;int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|__uint32_t|-|4|0
DEC r|__uint32_t|-|4|-
EXPECT 2 0 0 96 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rotl32_7|ghidra|-8
SHIFT -8
GT x|4|0|-|__uint32_t;int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|__uint32_t|-|4|0
DEC r|__uint32_t|-|4|-
EXPECT 2 0 0 -8 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rotl32_7|ghidra|96
SHIFT 96
GT x|4|0|-|__uint32_t;int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|__uint32_t|-|4|0
DEC r|__uint32_t|-|4|-
EXPECT 2 0 0 96 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rotl32_7|ida|-8
SHIFT -8
GT x|4|0|-|__uint32_t;int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|__int64|-|4|0
DEC r|__uint32_t|-|4|-
EXPECT 2 0 0 -8 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rotl32_7|ida|0
SHIFT 0
GT x|4|0|-|__uint32_t;int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|__int64|-|4|0
DEC r|__uint32_t|-|4|-
EXPECT 2 0 0 0 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rotl32_7|ida|96
SHIFT 96
GT x|4|0|-|__uint32_t;int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|__int64|-|4|0
DEC r|__uint32_t|-|4|-
EXPECT 2 0 0 96 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rotl32_7|ida|None
SHIFT -
GT x|4|0|-|__uint32_t;int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|__int64|-|4|0
DEC r|__uint32_t|-|4|-
EXPECT 2 0 0 0 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rotl32_7|shadow|-8
SHIFT -8
GT x|4|0|-|__uint32_t;int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|long|-|4|0
DEC x|__uint32_t|-|4|0
DEC r|__uint32_t|-|4|-
EXPECT 1 1 0 -8 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rotl32_7|shadow|96
SHIFT 96
GT x|4|0|-|__uint32_t;int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|long|-|4|0
DEC x|__uint32_t|-|4|0
DEC r|__uint32_t|-|4|-
EXPECT 1 1 0 96 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rotl32_7|wrong|-8
SHIFT -8
GT x|4|0|-|__uint32_t;int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|float|-|4|0
DEC r|long long|-|4|-
EXPECT 0 2 0 -8 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rotl32_7|wrong|96
SHIFT 96
GT x|4|0|-|__uint32_t;int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|float|-|4|0
DEC r|long long|-|4|-
EXPECT 0 2 0 96 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rotr32|noisy|-8
SHIFT -8
GT x|4|0|-|__uint32_t;int;unsigned int
GT n|4|1|-|int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|__uint32_t|-|4|0
DEC r|__uint32_t|-|16|-
EXPECT 2 0 1 -8 1 0 1 0 0 2
CASE 02_integer_widths-gcc-O2.so:rotr32|noisy|0
SHIFT 0
GT x|4|0|-|__uint32_t;int;unsigned int
GT n|4|1|-|int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|__uint32_t|-|4|0
DEC r|__uint32_t|-|16|-
EXPECT 2 0 1 0 1 0 1 0 0 2
CASE 02_integer_widths-gcc-O2.so:rotr32|noisy|96
SHIFT 96
GT x|4|0|-|__uint32_t;int;unsigned int
GT n|4|1|-|int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|__uint32_t|-|4|0
DEC r|__uint32_t|-|16|-
EXPECT 2 0 1 96 1 0 1 0 0 2
CASE 02_integer_widths-gcc-O2.so:rotr32|noisy|None
SHIFT -
GT x|4|0|-|__uint32_t;int;unsigned int
GT n|4|1|-|int;unsigned int
GT r|4|-|-|__uint32_t;int;unsigned int
DEC x|__uint32_t|-|4|0
DEC r|__uint32_t|-|16|-
EXPECT 2 0 1 0 1 0 1 0 0 2
CASE 02_integer_widths-gcc-O2.so:rt_u16|noisy|-8
SHIFT -8
GT x|4|0|-|int;unsigned int
GT v|2|-|-|__uint16_t;short;short int;short unsigned int
DEC v|__uint16_t|-|2|-
EXPECT 1 0 1 -8 0 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rt_u16|noisy|0
SHIFT 0
GT x|4|0|-|int;unsigned int
GT v|2|-|-|__uint16_t;short;short int;short unsigned int
DEC v|__uint16_t|-|2|-
EXPECT 1 0 1 0 0 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rt_u16|noisy|96
SHIFT 96
GT x|4|0|-|int;unsigned int
GT v|2|-|-|__uint16_t;short;short int;short unsigned int
DEC v|__uint16_t|-|2|-
EXPECT 1 0 1 96 0 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rt_u16|noisy|None
SHIFT -
GT x|4|0|-|int;unsigned int
GT v|2|-|-|__uint16_t;short;short int;short unsigned int
DEC v|__uint16_t|-|2|-
EXPECT 1 0 1 0 0 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rt_u16|spurious|-8
SHIFT -8
GT x|4|0|-|int;unsigned int
GT v|2|-|-|__uint16_t;short;short int;short unsigned int
DEC x|int|-|4|0
DEC v|__uint16_t|-|2|-
DEC junk0|struct Node *|-1000|2|-
EXPECT 2 0 0 -8 1 0 1 1 0 1
CASE 02_integer_widths-gcc-O2.so:rt_u16|spurious|0
SHIFT 0
GT x|4|0|-|int;unsigned int
GT v|2|-|-|__uint16_t;short;short int;short unsigned int
DEC x|int|-|4|0
DEC v|__uint16_t|-|2|-
DEC junk0|struct Node *|-1000|2|-
EXPECT 2 0 0 0 1 0 1 1 0 1
CASE 02_integer_widths-gcc-O2.so:rt_u16|spurious|96
SHIFT 96
GT x|4|0|-|int;unsigned int
GT v|2|-|-|__uint16_t;short;short int;short unsigned int
DEC x|int|-|4|0
DEC v|__uint16_t|-|2|-
DEC junk0|struct Node *|-1000|2|-
EXPECT 2 0 0 96 1 0 1 1 0 1
CASE 02_integer_widths-gcc-O2.so:rt_u16|spurious|None
SHIFT -
GT x|4|0|-|int;unsigned int
GT v|2|-|-|__uint16_t;short;short int;short unsigned int
DEC x|int|-|4|0
DEC v|__uint16_t|-|2|-
DEC junk0|struct Node *|-1000|2|-
EXPECT 2 0 0 0 1 0 1 1 0 1
CASE 02_integer_widths-gcc-O2.so:rt_u32|shadow|-8
SHIFT -8
GT x|4|0|-|int;unsigned int
GT v|4|-|-|__uint32_t;int;unsigned int
DEC v|char *|-|4|-
DEC x|int|-|4|0
DEC v|__uint32_t|-|4|-
EXPECT 2 0 0 -8 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rt_u32|shadow|96
SHIFT 96
GT x|4|0|-|int;unsigned int
GT v|4|-|-|__uint32_t;int;unsigned int
DEC v|char *|-|4|-
DEC x|int|-|4|0
DEC v|__uint32_t|-|4|-
EXPECT 2 0 0 96 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rt_u64|wrong|-8
SHIFT -8
GT x|4|0|-|int;unsigned int
GT v|8|-|-|__uint64_t;long int;long long;long unsigned int
DEC x|unsigned int|-|4|0
DEC v|float|-|8|-
EXPECT 1 1 0 -8 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:rt_u64|wrong|96
SHIFT 96
GT x|4|0|-|int;unsigned int
GT v|8|-|-|__uint64_t;long int;long long;long unsigned int
DEC x|unsigned int|-|4|0
DEC v|float|-|8|-
EXPECT 1 1 0 96 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:sar_signed|wrong|-8
SHIFT -8
GT x|4|0|-|int
DEC x|unsigned int|-|4|0
EXPECT 1 0 0 -8 1 0 0 0 0 1
CASE 02_integer_widths-gcc-O2.so:sar_signed|wrong|96
SHIFT 96
GT x|4|0|-|int
DEC x|unsigned int|-|4|0
EXPECT 1 0 0 96 1 0 0 0 0 1
CASE 02_integer_widths-gcc-O2.so:sext_i8|wrong|-8
SHIFT -8
GT x|4|0|-|int
GT v|1|-|-|__int8_t;char;signed char
DEC x|unsigned int|-|4|0
DEC v|char|-|1|-
EXPECT 2 0 0 -8 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:sext_i8|wrong|0
SHIFT 0
GT x|4|0|-|int
GT v|1|-|-|__int8_t;char;signed char
DEC x|unsigned int|-|4|0
DEC v|char|-|1|-
EXPECT 2 0 0 0 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:sext_i8|wrong|96
SHIFT 96
GT x|4|0|-|int
GT v|1|-|-|__int8_t;char;signed char
DEC x|unsigned int|-|4|0
DEC v|char|-|1|-
EXPECT 2 0 0 96 1 0 1 0 0 1
CASE 02_integer_widths-gcc-O2.so:sext_i8|wrong|None
SHIFT -
GT x|4|0|-|int
GT v|1|-|-|__int8_t;char;signed char
DEC x|unsigned int|-|4|0
DEC v|char|-|1|-
EXPECT 2 0 0 0 1 0 1 0 0 1
CASE 03_loop_shapes-clang-O0.so:cond_reload_and_transform|noisy|-8
SHIFT -8
GT p|8|0|8|int*
GT s|4|-|4|int
GT i|4|-|0|int
DEC p|int*|8|8|0
DEC v18|__int16|12|4|-
EXPECT 2 0 1 -8 1 1 0 2 3 1
CASE 03_loop_shapes-clang-O0.so:dowhile_atleastonce|noisy|-8
SHIFT -8
GT p|8|0|8|int*
GT i|4|-|4|int
GT s|4|-|0|int
DEC v12|byte|16|4|-
DEC i|int|0|4|-
DEC s|int|0|1|-
EXPECT 2 1 0 -8 0 1 2 3 3 1
CASE 03_loop_shapes-clang-O0.so:dowhile_atleastonce|shadow|-8
SHIFT -8
GT p|8|0|8|int*
GT i|4|-|4|int
GT s|4|-|0|int
DEC p|void *|8|8|0
DEC p|int*|8|8|0
DEC i|int|4|4|-
DEC s|int|0|4|-
EXPECT 1 2 0 -8 1 1 1 4 3 1
CASE 03_loop_shapes-clang-O0.so:for_sum|noisy|0
SHIFT 0
GT p|8|0|8|int*
GT s|4|-|4|int
GT i|4|-|0|int
DEC v2|byte|4|16|-
DEC v14|undefined4|-4|4|-
DEC i|int|-4|4|-
EXPECT 1 1 1 0 0 1 1 3 3 1
CASE 03_loop_shapes-clang-O0.so:for_sum|noisy|None
SHIFT -
GT p|8|0|8|int*
GT s|4|-|4|int
GT i|4|-|0|int
DEC v2|byte|4|16|-
DEC v14|undefined4|-4|4|-
DEC i|int|-4|4|-
EXPECT 1 1 1 0 0 1 1 3 3 1
CASE 03_loop_shapes-clang-O0.so:loop_early_return|ghidra|-8
SHIFT -8
GT p|8|0|0|int*
GT i|4|-|-4|int
DEC p|undefined8|0|8|0
DEC local_4|undefined4|-|4|-
EXPECT 1 1 0 0 1 1 0 2 2 1
CASE 03_loop_shapes-clang-O0.so:loop_early_return|ghidra|0
SHIFT 0
GT p|8|0|0|int*
GT i|4|-|-4|int
DEC p|undefined8|0|8|0
DEC local_4|undefined4|-|4|-
EXPECT 1 1 0 0 1 1 0 2 2 1
CASE 03_loop_shapes-clang-O0.so:loop_early_return|ghidra|96
SHIFT 96
GT p|8|0|0|int*
GT i|4|-|-4|int
DEC p|undefined8|0|8|0
DEC local_4|undefined4|-|4|-
EXPECT 1 1 0 0 1 1 0 2 2 1
CASE 03_loop_shapes-clang-O0.so:loop_early_return|ghidra|None
SHIFT -
GT p|8|0|0|int*
GT i|4|-|-4|int
DEC p|undefined8|0|8|0
DEC local_4|undefined4|-|4|-
EXPECT 1 1 0 0 1 1 0 2 2 1
CASE 03_loop_shapes-clang-O0.so:loop_return_on_neg|ghidra|-8
SHIFT -8
GT p|8|0|0|int*
GT s|4|-|-4|int
GT i|4|-|-8|int
DEC p|undefined8|0|8|0
DEC local_4|int|-|4|-
DEC local_8|undefined4|-|4|-
EXPECT 0 1 2 -8 1 0 0 3 3 1
CASE 03_loop_shapes-clang-O0.so:mutate_prefix|ghidra|-8
SHIFT -8
GT p|8|0|8|int*
GT carry|4|-|4|int
GT i|4|-|0|int
GT v|4|-|-4|int
DEC p|undefined8|8|8|0
DEC carry|undefined4|4|4|-
DEC i|undefined4|0|4|-
DEC local_4|undefined4|-|4|-
EXPECT 2 1 1 -8 1 1 1 4 4 1
CASE 03_loop_shapes-clang-O0.so:mutate_prefix|spurious|-8
SHIFT -8
GT p|8|0|8|int*
GT carry|4|-|4|int
GT i|4|-|0|int
GT v|4|-|-4|int
DEC p|int*|8|8|0
DEC carry|int|4|4|-
DEC i|int|0|4|-
DEC v|int|-4|4|-
DEC junk0|char|-1000|2|-
EXPECT 3 0 1 -8 1 1 1 5 4 1
CASE 03_loop_shapes-clang-O0.so:mutate_reverse|ghidra|-8
SHIFT -8
GT p|8|0|8|int*
GT i|4|-|4|int
GT j|4|-|0|int
GT t|4|-|-4|int
DEC p|int*|8|8|0
DEC i|undefined4|4|4|-
DEC j|int|0|4|-
DEC local_4|int|-|4|-
EXPECT 3 0 1 -8 1 1 1 4 4 1
CASE 03_loop_shapes-clang-O0.so:mutate_reverse|wrong|-8
SHIFT -8
GT p|8|0|8|int*
GT i|4|-|4|int
GT j|4|-|0|int
GT t|4|-|-4|int
DEC p|long|8|8|0
DEC i|int|4|4|-
DEC j|unsigned int|0|4|-
DEC t|unsigned int|-4|4|-
EXPECT 2 1 1 -8 1 1 1 4 4 1
CASE 03_loop_shapes-clang-O0.so:while_reload_header|ida|-8
SHIFT -8
GT p|8|0|8|int*
GT i|4|-|4|int
DEC p|_DWORD|104|8|0
DEC i|_DWORD|100|4|-
EXPECT 1 1 0 -96 1 1 0 2 2 1
CASE 03_loop_shapes-clang-O0.so:while_reload_header|ida|0
SHIFT 0
GT p|8|0|8|int*
GT i|4|-|4|int
DEC p|_DWORD|104|8|0
DEC i|_DWORD|100|4|-
EXPECT 1 1 0 -96 1 1 0 2 2 1
CASE 03_loop_shapes-clang-O0.so:while_reload_header|ida|96
SHIFT 96
GT p|8|0|8|int*
GT i|4|-|4|int
DEC p|_DWORD|104|8|0
DEC i|_DWORD|100|4|-
EXPECT 1 1 0 -96 1 1 0 2 2 1
CASE 03_loop_shapes-clang-O0.so:while_reload_header|ida|None
SHIFT -
GT p|8|0|8|int*
GT i|4|-|4|int
DEC p|_DWORD|104|8|0
DEC i|_DWORD|100|4|-
EXPECT 1 1 0 -96 1 1 0 2 2 1
CASE 03_loop_shapes-gcc-O0.so:dowhile_recompute|noisy|-8
SHIFT -8
GT x|4|0|-20|int
GT s|4|-|-8|int
GT t|4|-|-4|int;unsigned int
DEC x|int|-20|4|0
DEC s|int|-8|4|-
DEC v7|int|4|4|-
EXPECT 3 0 0 -8 1 1 1 3 3 1
CASE 03_loop_shapes-gcc-O0.so:loop_continue|noisy|-8
SHIFT -8
GT p|8|0|-24|int*
GT s|4|-|-8|int
GT i|4|-|-4|int
DEC p|int*|-24|-|-
DEC v4|int|0|4|-
EXPECT 2 0 1 -8 0 1 1 2 3 1
CASE 03_loop_shapes-gcc-O0.so:loop_early_return|degraded|-8
SHIFT -8
GT p|8|0|-24|int*
GT i|4|-|-4|int
DEC p|int8|-24|8|0
DEC i|undefined4|-4|4|-
EXPECT 1 1 0 0 1 1 0 2 2 1
CASE 03_loop_shapes-gcc-O0.so:loop_early_return|degraded|0
SHIFT 0
GT p|8|0|-24|int*
GT i|4|-|-4|int
DEC p|int8|-24|8|0
DEC i|undefined4|-4|4|-
EXPECT 1 1 0 0 1 1 0 2 2 1
CASE 03_loop_shapes-gcc-O0.so:loop_early_return|degraded|96
SHIFT 96
GT p|8|0|-24|int*
GT i|4|-|-4|int
DEC p|int8|-24|8|0
DEC i|undefined4|-4|4|-
EXPECT 1 1 0 0 1 1 0 2 2 1
CASE 03_loop_shapes-gcc-O0.so:loop_early_return|degraded|None
SHIFT -
GT p|8|0|-24|int*
GT i|4|-|-4|int
DEC p|int8|-24|8|0
DEC i|undefined4|-4|4|-
EXPECT 1 1 0 0 1 1 0 2 2 1
CASE 03_loop_shapes-gcc-O0.so:loop_return_on_neg|noisy|-8
SHIFT -8
GT p|8|0|-24|int*
GT s|4|-|-8|int
GT i|4|-|-4|int
DEC s|int|-16|3|-
DEC i|int|-4|4|-
EXPECT 1 1 1 -8 0 1 1 2 3 1
CASE 03_loop_shapes-gcc-O0.so:loop_return_on_neg|noisy|0
SHIFT 0
GT p|8|0|-24|int*
GT s|4|-|-8|int
GT i|4|-|-4|int
DEC s|int|-16|3|-
DEC i|int|-4|4|-
EXPECT 2 0 1 0 0 1 1 2 3 1
CASE 03_loop_shapes-gcc-O0.so:loop_return_on_neg|noisy|96
SHIFT 96
GT p|8|0|-24|int*
GT s|4|-|-8|int
GT i|4|-|-4|int
DEC s|int|-16|3|-
DEC i|int|-4|4|-
EXPECT 2 0 1 0 0 1 1 2 3 1
CASE 03_loop_shapes-gcc-O0.so:loop_return_on_neg|noisy|None
SHIFT -
GT p|8|0|-24|int*
GT s|4|-|-8|int
GT i|4|-|-4|int
DEC s|int|-16|3|-
DEC i|int|-4|4|-
EXPECT 2 0 1 0 0 1 1 2 3 1
CASE 03_loop_shapes-gcc-O0.so:mutate_prefix|degraded|-8
SHIFT -8
GT p|8|0|-24|int*
GT carry|4|-|-12|int
GT i|4|-|-8|int
GT v|4|-|-4|int
DEC p|qword|-24|8|0
DEC carry|int4|-12|4|-
DEC i|undefined4|-8|4|-
DEC v|undefined4|-4|4|-
EXPECT 2 1 1 -8 1 1 1 4 4 1
CASE 03_loop_shapes-gcc-O0.so:mutate_prefix|echo|-8
SHIFT -8
GT p|8|0|-24|int*
GT carry|4|-|-12|int
GT i|4|-|-8|int
GT v|4|-|-4|int
DEC p|int*|-24|8|0
DEC carry|int|-12|4|-
DEC i|int|-8|4|-
DEC v|int|-4|4|-
EXPECT 3 0 1 -8 1 1 1 4 4 1
CASE 03_loop_shapes-gcc-O0.so:mutate_prefix|ghidra|-8
SHIFT -8
GT p|8|0|-24|int*
GT carry|4|-|-12|int
GT i|4|-|-8|int
GT v|4|-|-4|int
DEC local_18|undefined8|-|8|0
DEC local_c|undefined4|-|4|-
DEC local_8|undefined4|-|4|-
DEC local_4|int|-|4|-
EXPECT 1 1 2 -8 1 1 0 4 4 1
CASE 03_loop_shapes-gcc-O0.so:mutate_prefix|shadow|-8
SHIFT -8
GT p|8|0|-24|int*
GT carry|4|-|-12|int
GT i|4|-|-8|int
GT v|4|-|-4|int
DEC carry|void *|-12|4|-
DEC p|int*|-24|8|0
DEC carry|int|-12|4|-
DEC i|int|-8|4|-
DEC v|int|-4|4|-
EXPECT 3 0 1 -8 1 1 1 5 4 1
CASE 03_loop_shapes-gcc-O0.so:mutate_prefix|wrong|-8
SHIFT -8
GT p|8|0|-24|int*
GT carry|4|-|-12|int
GT i|4|-|-8|int
GT v|4|-|-4|int
DEC p|struct Node *|-24|8|0
DEC carry|void *|-12|4|-
DEC i|char *|-8|4|-
DEC v|float|-4|4|-
EXPECT 0 3 1 -8 1 1 1 4 4 1
CASE 03_loop_shapes-gcc-O0.so:mutate_reverse|shadow|-8
SHIFT -8
GT p|8|0|-24|int*
GT i|4|-|-12|int
GT j|4|-|-8|int
GT t|4|-|-4|int
DEC p|short|-24|8|0
DEC p|int*|-24|8|0
DEC i|int|-12|4|-
DEC j|int|-8|4|-
DEC t|int|-4|4|-
EXPECT 2 1 1 -8 1 1 1 5 4 1
CASE 03_loop_shapes-gcc-O0.so:nested_carry|ghidra|-8
SHIFT -8
GT p|8|0|-24|int*
GT acc|4|-|-12|int
GT i|4|-|-8|int
GT j|4|-|-4|int
DEC local_18|int*|-|8|0
DEC local_c|undefined4|-|4|-
DEC local_8|undefined4|-|4|-
DEC local_4|undefined4|-|4|-
EXPECT 2 0 2 -8 1 1 0 4 4 1
CASE 03_loop_shapes-gcc-O0.so:while_reload_header|noisy|-8
SHIFT -8
GT p|8|0|-24|int*
GT i|4|-|-4|int
DEC v17|__int64|-16|4|-
EXPECT 0 1 1 -8 0 1 0 1 2 1
CASE 03_loop_shapes-gcc-O0.so:while_reload_header|noisy|0
SHIFT 0
GT p|8|0|-24|int*
GT i|4|-|-4|int
DEC v17|__int64|-16|4|-
EXPECT 0 1 1 -8 0 1 0 1 2 1
CASE 03_loop_shapes-gcc-O0.so:while_reload_header|noisy|96
SHIFT 96
GT p|8|0|-24|int*
GT i|4|-|-4|int
DEC v17|__int64|-16|4|-
EXPECT 0 1 1 -8 0 1 0 1 2 1
CASE 03_loop_shapes-gcc-O0.so:while_reload_header|noisy|None
SHIFT -
GT p|8|0|-24|int*
GT i|4|-|-4|int
DEC v17|__int64|-16|4|-
EXPECT 0 1 1 -8 0 1 0 1 2 1
CASE 03_loop_shapes-gcc-O2.so:loop_early_return|degraded|-8
SHIFT -8
GT p|8|0|-|int*
GT i|4|-|-|int
DEC p|__int64|-|8|0
DEC i|dword|-|4|-
EXPECT 1 1 0 -8 1 0 1 0 0 1
CASE 03_loop_shapes-gcc-O2.so:loop_early_return|degraded|0
SHIFT 0
GT p|8|0|-|int*
GT i|4|-|-|int
DEC p|__int64|-|8|0
DEC i|dword|-|4|-
EXPECT 1 1 0 0 1 0 1 0 0 1
CASE 03_loop_shapes-gcc-O2.so:loop_early_return|degraded|96
SHIFT 96
GT p|8|0|-|int*
GT i|4|-|-|int
DEC p|__int64|-|8|0
DEC i|dword|-|4|-
EXPECT 1 1 0 96 1 0 1 0 0 1
CASE 03_loop_shapes-gcc-O2.so:loop_early_return|degraded|None
SHIFT -
GT p|8|0|-|int*
GT i|4|-|-|int
DEC p|__int64|-|8|0
DEC i|dword|-|4|-
EXPECT 1 1 0 0 1 0 1 0 0 1
CASE 03_loop_shapes-gcc-O2.so:loop_early_return|ghidra|-8
SHIFT -8
GT p|8|0|-|int*
GT i|4|-|-|int
DEC p|undefined8|-|8|0
DEC i|undefined4|-|4|-
EXPECT 1 1 0 -8 1 0 1 0 0 1
CASE 03_loop_shapes-gcc-O2.so:loop_early_return|ghidra|0
SHIFT 0
GT p|8|0|-|int*
GT i|4|-|-|int
DEC p|undefined8|-|8|0
DEC i|undefined4|-|4|-
EXPECT 1 1 0 0 1 0 1 0 0 1
CASE 03_loop_shapes-gcc-O2.so:loop_early_return|ghidra|96
SHIFT 96
GT p|8|0|-|int*
GT i|4|-|-|int
DEC p|undefined8|-|8|0
DEC i|undefined4|-|4|-
EXPECT 1 1 0 96 1 0 1 0 0 1
CASE 03_loop_shapes-gcc-O2.so:loop_early_return|ghidra|None
SHIFT -
GT p|8|0|-|int*
GT i|4|-|-|int
DEC p|undefined8|-|8|0
DEC i|undefined4|-|4|-
EXPECT 1 1 0 0 1 0 1 0 0 1
CASE 03_loop_shapes-gcc-O2.so:loop_early_return|ida|-8
SHIFT -8
GT p|8|0|-|int*
GT i|4|-|-|int
DEC p|_QWORD|-|8|0
DEC i|_QWORD|-|4|-
EXPECT 1 1 0 -8 1 0 1 0 0 1
CASE 03_loop_shapes-gcc-O2.so:loop_early_return|ida|0
SHIFT 0
GT p|8|0|-|int*
GT i|4|-|-|int
DEC p|_QWORD|-|8|0
DEC i|_QWORD|-|4|-
EXPECT 1 1 0 0 1 0 1 0 0 1
CASE 03_loop_shapes-gcc-O2.so:loop_early_return|ida|96
SHIFT 96
GT p|8|0|-|int*
GT i|4|-|-|int
DEC p|_QWORD|-|8|0
DEC i|_QWORD|-|4|-
EXPECT 1 1 0 96 1 0 1 0 0 1
CASE 03_loop_shapes-gcc-O2.so:loop_early_return|ida|None
SHIFT -
GT p|8|0|-|int*
GT i|4|-|-|int
DEC p|_QWORD|-|8|0
DEC i|_QWORD|-|4|-
EXPECT 1 1 0 0 1 0 1 0 0 1
CASE 04_switch_shapes-clang-O0.so:dense_compute|shadow|-8
SHIFT -8
GT x|4|0|12|int;unsigned int
GT y|4|1|8|int
GT r|4|-|4|int
DEC x|long long|12|4|0
DEC x|int|12|4|0
DEC y|int|8|4|1
DEC r|int|4|4|-
EXPECT 2 1 0 -8 2 1 0 4 3 2
CASE 04_switch_shapes-gcc-O0.so:negative_sparse|noisy|-8
SHIFT -8
GT x|4|0|-4|int
DEC v8|double|4|4|-
EXPECT 0 1 0 -8 0 1 0 1 1 1
CASE 04_switch_shapes-gcc-O0.so:nested_switch|noisy|-8
SHIFT -8
GT x|4|0|-4|int;unsigned int
GT y|4|1|-8|int;unsigned int
DEC v5|int2|4|4|-
DEC y|int|-8|4|1
EXPECT 2 0 0 -8 1 1 0 2 2 2
CASE 04_switch_shapes-gcc-O0.so:switch_loop_break|noisy|-8
SHIFT -8
GT p|8|0|-24|int*
GT s|4|-|-8|int
GT i|4|-|-4|int
DEC v19|int4|-16|8|-
DEC v12|int1|0|4|-
EXPECT 1 1 1 -8 0 2 0 2 3 1
CASE 04_switch_shapes-gcc-O0.so:switch_loop_break|noisy|0
SHIFT 0
GT p|8|0|-24|int*
GT s|4|-|-8|int
GT i|4|-|-4|int
DEC v19|int4|-16|8|-
DEC v12|int1|0|4|-
EXPECT 1 1 1 -8 0 2 0 2 3 1
CASE 04_switch_shapes-gcc-O0.so:switch_loop_break|noisy|None
SHIFT -
GT p|8|0|-24|int*
GT s|4|-|-8|int
GT i|4|-|-4|int
DEC v19|int4|-16|8|-
DEC v12|int1|0|4|-
EXPECT 1 1 1 -8 0 2 0 2 3 1
CASE 04_switch_shapes-gcc-O2.so:dense_jumptable|shadow|-8
SHIFT -8
GT x|4|0|-|int;unsigned int
DEC x|unsigned int|-|4|0
DEC x|int|-|4|0
EXPECT 1 0 0 -8 1 0 0 0 0 1
CASE 04_switch_shapes-gcc-O2.so:dense_jumptable|shadow|96
SHIFT 96
GT x|4|0|-|int;unsigned int
DEC x|unsigned int|-|4|0
DEC x|int|-|4|0
EXPECT 1 0 0 96 1 0 0 0 0 1
CASE 05_cleanup_and_state_machine-clang-O0.so:process|noisy|-8
SHIFT -8
GT in|8|0|0|__uint8_t*;char*;uint8_t*;unsigned char*
GT n|4|1|-4|int
GT acc|4|-|-8|int
GT stage|4|-|-12|int
GT attempts|4|-|-16|int
GT sum|4|-|-20|int
DEC in|__uint8_t*|0|8|0
DEC n|int|-4|4|-
DEC v16|char|0|1|-
DEC stage|int|-12|4|-
DEC attempts|int|-16|4|-
DEC v13|int|-20|4|-
EXPECT 4 1 1 -8 1 3 1 6 6 2
CASE 05_cleanup_and_state_machine-gcc-O0.so:process|degraded|-8
SHIFT -8
GT in|8|0|-24|__uint8_t*;char*;uint8_t*;unsigned char*
GT n|4|1|-28|int
GT acc|4|-|-16|int
GT stage|4|-|-12|int
GT attempts|4|-|-8|int
GT sum|4|-|-4|int
DEC in|qword|-24|8|0
DEC n|_DWORD|-28|4|1
DEC acc|undefined4|-16|4|-
DEC stage|__int32|-12|4|-
DEC attempts|int4|-8|4|-
DEC sum|uint4|-4|4|-
EXPECT 3 1 2 -8 2 2 0 6 6 2
CASE 05_cleanup_and_state_machine-gcc-O0.so:process|echo|-8
SHIFT -8
GT in|8|0|-24|__uint8_t*;char*;uint8_t*;unsigned char*
GT n|4|1|-28|int
GT acc|4|-|-16|int
GT stage|4|-|-12|int
GT attempts|4|-|-8|int
GT sum|4|-|-4|int
DEC in|__uint8_t*|-24|8|0
DEC n|int|-28|4|1
DEC acc|int|-16|4|-
DEC stage|int|-12|4|-
DEC attempts|int|-8|4|-
DEC sum|int|-4|4|-
EXPECT 4 0 2 -8 2 2 0 6 6 2
CASE 05_cleanup_and_state_machine-gcc-O0.so:process|shadow|-8
SHIFT -8
GT in|8|0|-24|__uint8_t*;char*;uint8_t*;unsigned char*
GT n|4|1|-28|int
GT acc|4|-|-16|int
GT stage|4|-|-12|int
GT attempts|4|-|-8|int
GT sum|4|-|-4|int
DEC n|long|-28|4|1
DEC in|__uint8_t*|-24|8|0
DEC n|int|-28|4|1
DEC acc|int|-16|4|-
DEC stage|int|-12|4|-
DEC attempts|int|-8|4|-
DEC sum|int|-4|4|-
EXPECT 3 1 2 -8 2 2 0 7 6 2
CASE 05_cleanup_and_state_machine-gcc-O0.so:process|spurious|-8
SHIFT -8
GT in|8|0|-24|__uint8_t*;char*;uint8_t*;unsigned char*
GT n|4|1|-28|int
GT acc|4|-|-16|int
GT stage|4|-|-12|int
GT attempts|4|-|-8|int
GT sum|4|-|-4|int
DEC in|__uint8_t*|-24|8|0
DEC n|int|-28|4|1
DEC acc|int|-16|4|-
DEC stage|int|-12|4|-
DEC attempts|int|-8|4|-
DEC sum|int|-4|4|-
DEC junk0|int *|-1000|1|-
EXPECT 4 0 2 -8 2 2 0 7 6 2
CASE 05_cleanup_and_state_machine-gcc-O0.so:process|wrong|-8
SHIFT -8
GT in|8|0|-24|__uint8_t*;char*;uint8_t*;unsigned char*
GT n|4|1|-28|int
GT acc|4|-|-16|int
GT stage|4|-|-12|int
GT attempts|4|-|-8|int
GT sum|4|-|-4|int
DEC in|int *|-24|8|0
DEC n|long long|-28|4|1
DEC acc|struct Node *|-16|4|-
DEC stage|long|-12|4|-
DEC attempts|char *|-8|4|-
DEC sum|float|-4|4|-
EXPECT 0 4 2 -8 2 2 0 6 6 2
CASE 06_calling_conventions-gcc-O0.so:sum_arg3|noisy|-8
SHIFT -8
GT a0|4|0|-4|int
GT a1|4|1|-8|int
GT a2|4|2|-12|int
DEC v14|bool|-12|16|-
DEC a1|int|-8|4|1
EXPECT 1 1 1 0 1 1 0 2 3 3
CASE 06_calling_conventions-gcc-O0.so:sum_arg3|noisy|0
SHIFT 0
GT a0|4|0|-4|int
GT a1|4|1|-8|int
GT a2|4|2|-12|int
DEC v14|bool|-12|16|-
DEC a1|int|-8|4|1
EXPECT 1 1 1 0 1 1 0 2 3 3
CASE 06_calling_conventions-gcc-O0.so:sum_arg3|noisy|96
SHIFT 96
GT a0|4|0|-4|int
GT a1|4|1|-8|int
GT a2|4|2|-12|int
DEC v14|bool|-12|16|-
DEC a1|int|-8|4|1
EXPECT 1 1 1 0 1 1 0 2 3 3
CASE 06_calling_conventions-gcc-O0.so:sum_arg3|noisy|None
SHIFT -
GT a0|4|0|-4|int
GT a1|4|1|-8|int
GT a2|4|2|-12|int
DEC v14|bool|-12|16|-
DEC a1|int|-8|4|1
EXPECT 1 1 1 0 1 1 0 2 3 3
CASE 06_calling_conventions-gcc-O0.so:sum_arg6|noisy|-8
SHIFT -8
GT a0|4|0|-4|int
GT a1|4|1|-8|int
GT a2|4|2|-12|int
GT a3|4|3|-16|int
GT a4|4|4|-20|int
GT a5|4|5|-24|int
DEC a0|int|0|2|-
DEC a2|int|-12|4|2
DEC v12|int8|-20|4|-
DEC a4|int|-20|4|4
DEC a5|int|-32|4|-
EXPECT 4 0 2 -8 2 1 1 5 6 6
CASE 06_calling_conventions-gcc-O0.so:sum_arg8|noisy|0
SHIFT 0
GT a0|4|0|-4|int
GT a1|4|1|-8|int
GT a2|4|2|-12|int
GT a3|4|3|-16|int
GT a4|4|4|-20|int
GT a5|4|5|-24|int
GT a6|4|6|16|int
GT a7|4|7|24|int
DEC v5|int|0|4|-
DEC v4|int|0|4|-
DEC v14|undefined2|-12|1|-
DEC a4|int|-24|16|-
DEC a5|int|-24|4|5
DEC a6|int|16|4|6
DEC a7|int|24|4|7
EXPECT 4 1 3 0 3 1 1 7 8 8
CASE 06_calling_conventions-gcc-O0.so:sum_arg8|noisy|96
SHIFT 96
GT a0|4|0|-4|int
GT a1|4|1|-8|int
GT a2|4|2|-12|int
GT a3|4|3|-16|int
GT a4|4|4|-20|int
GT a5|4|5|-24|int
GT a6|4|6|16|int
GT a7|4|7|24|int
DEC v5|int|0|4|-
DEC v4|int|0|4|-
DEC v14|undefined2|-12|1|-
DEC a4|int|-24|16|-
DEC a5|int|-24|4|5
DEC a6|int|16|4|6
DEC a7|int|24|4|7
EXPECT 4 1 3 0 3 1 1 7 8 8
CASE 06_calling_conventions-gcc-O0.so:sum_arg8|noisy|None
SHIFT -
GT a0|4|0|-4|int
GT a1|4|1|-8|int
GT a2|4|2|-12|int
GT a3|4|3|-16|int
GT a4|4|4|-20|int
GT a5|4|5|-24|int
GT a6|4|6|16|int
GT a7|4|7|24|int
DEC v5|int|0|4|-
DEC v4|int|0|4|-
DEC v14|undefined2|-12|1|-
DEC a4|int|-24|16|-
DEC a5|int|-24|4|5
DEC a6|int|16|4|6
DEC a7|int|24|4|7
EXPECT 4 1 3 0 3 1 1 7 8 8
CASE 06_calling_conventions-gcc-O2.so:sum_arg7|noisy|-8
SHIFT -8
GT a0|4|0|-|int
GT a1|4|1|-|int
GT a2|4|2|-|int
GT a3|4|3|-|int
GT a4|4|4|-|int
GT a5|4|5|-|int
GT a6|4|6|16|int
DEC a0|int|-|4|-
DEC a1|int|-|4|1
DEC v19|int1|-|4|-
DEC a3|int|-|4|3
DEC v4|unsigned int|-|4|-
DEC a5|int|-|4|5
DEC a6|int|16|4|6
EXPECT 5 0 2 0 4 0 1 1 1 7
CASE 06_calling_conventions-gcc-O2.so:sum_arg7|noisy|96
SHIFT 96
GT a0|4|0|-|int
GT a1|4|1|-|int
GT a2|4|2|-|int
GT a3|4|3|-|int
GT a4|4|4|-|int
GT a5|4|5|-|int
GT a6|4|6|16|int
DEC a0|int|-|4|-
DEC a1|int|-|4|1
DEC v19|int1|-|4|-
DEC a3|int|-|4|3
DEC v4|unsigned int|-|4|-
DEC a5|int|-|4|5
DEC a6|int|16|4|6
EXPECT 5 0 2 0 4 0 1 1 1 7
CASE 07_packet_parser-clang-O0.so:parse_packet|spurious|-8
SHIFT -8
GT buf|8|0|0|__uint8_t*;char*;uint8_t*;unsigned char*
GT len|4|1|-4|int
GT hdr|12|-|-16|decoded_header
GT rc|4|-|-20|int
GT cursor|8|-|-32|__uint8_t*;char*;uint8_t*;unsigned char*
GT remaining|4|-|-36|int
GT declared|2|-|-38|__uint16_t;short;unsigned short
GT head_word|4|-|-44|__uint32_t;int;unsigned int
GT sum|4|-|-52|__uint32_t;int;unsigned int
GT summary|4|-|-64|int
GT ph|4|-|-48|payload_head
GT i|4|-|-56|int
GT last|1|-|-57|__uint8_t;char;unsigned char
DEC buf|__uint8_t*|0|8|0
DEC len|int|-4|4|1
DEC hdr|decoded_header|-16|12|-
DEC rc|int|-20|4|-
DEC cursor|__uint8_t*|-32|8|-
DEC remaining|int|-36|4|-
DEC declared|__uint16_t|-38|2|-
DEC head_word|__uint32_t|-44|4|-
DEC sum|__uint32_t|-52|4|-
DEC summary|int|-64|4|-
DEC ph|payload_head|-48|4|-
DEC i|int|-56|4|-
DEC last|__uint8_t|-57|1|-
DEC junk0|int *|-1000|2|-
EXPECT 10 1 2 -8 2 4 5 14 13 2
CASE 07_packet_parser-clang-O0.so:read_be32|ida|-8
SHIFT -8
GT p|8|0|8|__uint8_t*;char*;uint8_t*;unsigned char*
DEC p|_DWORD|104|8|0
EXPECT 0 1 0 -96 1 0 0 1 1 1
CASE 07_packet_parser-clang-O0.so:read_be32|ida|0
SHIFT 0
GT p|8|0|8|__uint8_t*;char*;uint8_t*;unsigned char*
DEC p|_DWORD|104|8|0
EXPECT 0 1 0 -96 1 0 0 1 1 1
CASE 07_packet_parser-clang-O0.so:read_be32|ida|96
SHIFT 96
GT p|8|0|8|__uint8_t*;char*;uint8_t*;unsigned char*
DEC p|_DWORD|104|8|0
EXPECT 0 1 0 -96 1 0 0 1 1 1
CASE 07_packet_parser-clang-O0.so:read_be32|ida|None
SHIFT -
GT p|8|0|8|__uint8_t*;char*;uint8_t*;unsigned char*
DEC p|_DWORD|104|8|0
EXPECT 0 1 0 -96 1 0 0 1 1 1
CASE 07_packet_parser-gcc-O0.so:parse_packet|echo|-8
SHIFT -8
GT buf|8|0|-72|__uint8_t*;char*;uint8_t*;unsigned char*
GT len|4|1|-76|int
GT hdr|12|-|-24|decoded_header
GT rc|4|-|-44|int
GT cursor|8|-|-32|__uint8_t*;char*;uint8_t*;unsigned char*
GT remaining|4|-|-40|int
GT declared|2|-|-58|__uint16_t;short;short int;short unsigned int
GT head_word|4|-|-56|__uint32_t;int;unsigned int
GT sum|4|-|-52|__uint32_t;int;unsigned int
GT summary|4|-|-36|int
GT ph|4|-|-12|payload_head
GT i|4|-|-48|int
GT last|1|-|-59|__uint8_t;char;unsigned char
DEC buf|__uint8_t*|-72|8|0
DEC len|int|-76|4|1
DEC hdr|decoded_header|-24|12|-
DEC rc|int|-44|4|-
DEC cursor|__uint8_t*|-32|8|-
DEC remaining|int|-40|4|-
DEC declared|__uint16_t|-58|2|-
DEC head_word|__uint32_t|-56|4|-
DEC sum|__uint32_t|-52|4|-
DEC summary|int|-36|4|-
DEC ph|payload_head|-12|4|-
DEC i|int|-48|4|-
DEC last|__uint8_t|-59|1|-
EXPECT 9 2 2 -8 2 6 3 13 13 2
CASE 07_packet_parser-gcc-O0.so:parse_packet|spurious|-8
SHIFT -8
GT buf|8|0|-72|__uint8_t*;char*;uint8_t*;unsigned char*
GT len|4|1|-76|int
GT hdr|12|-|-24|decoded_header
GT rc|4|-|-44|int
GT cursor|8|-|-32|__uint8_t*;char*;uint8_t*;unsigned char*
GT remaining|4|-|-40|int
GT declared|2|-|-58|__uint16_t;short;short int;short unsigned int
GT head_word|4|-|-56|__uint32_t;int;unsigned int
GT sum|4|-|-52|__uint32_t;int;unsigned int
GT summary|4|-|-36|int
GT ph|4|-|-12|payload_head
GT i|4|-|-48|int
GT last|1|-|-59|__uint8_t;char;unsigned char
DEC buf|__uint8_t*|-72|8|0
DEC len|int|-76|4|1
DEC hdr|decoded_header|-24|12|-
DEC rc|int|-44|4|-
DEC cursor|__uint8_t*|-32|8|-
DEC remaining|int|-40|4|-
DEC declared|__uint16_t|-58|2|-
DEC head_word|__uint32_t|-56|4|-
DEC sum|__uint32_t|-52|4|-
DEC summary|int|-36|4|-
DEC ph|payload_head|-12|4|-
DEC i|int|-48|4|-
DEC last|__uint8_t|-59|1|-
DEC junk0|float|-1000|8|-
DEC junk1|long long|-1008|8|-
DEC junk2|float|-1016|8|-
DEC junk3|float|-1024|1|-
EXPECT 9 2 2 -8 2 6 3 17 13 2
CASE 07_packet_parser-gcc-O0.so:parse_packet|spurious|0
SHIFT 0
GT buf|8|0|-72|__uint8_t*;char*;uint8_t*;unsigned char*
GT len|4|1|-76|int
GT hdr|12|-|-24|decoded_header
GT rc|4|-|-44|int
GT cursor|8|-|-32|__uint8_t*;char*;uint8_t*;unsigned char*
GT remaining|4|-|-40|int
GT declared|2|-|-58|__uint16_t;short;short int;short unsigned int
GT head_word|4|-|-56|__uint32_t;int;unsigned int
GT sum|4|-|-52|__uint32_t;int;unsigned int
GT summary|4|-|-36|int
GT ph|4|-|-12|payload_head
GT i|4|-|-48|int
GT last|1|-|-59|__uint8_t;char;unsigned char
DEC buf|__uint8_t*|-72|8|0
DEC len|int|-76|4|1
DEC hdr|decoded_header|-24|12|-
DEC rc|int|-44|4|-
DEC cursor|__uint8_t*|-32|8|-
DEC remaining|int|-40|4|-
DEC declared|__uint16_t|-58|2|-
DEC head_word|__uint32_t|-56|4|-
DEC sum|__uint32_t|-52|4|-
DEC summary|int|-36|4|-
DEC ph|payload_head|-12|4|-
DEC i|int|-48|4|-
DEC last|__uint8_t|-59|1|-
DEC junk0|float|-1000|8|-
DEC junk1|long long|-1008|8|-
DEC junk2|float|-1016|8|-
DEC junk3|float|-1024|1|-
EXPECT 13 0 0 0 2 11 0 17 13 2
CASE 07_packet_parser-gcc-O0.so:parse_packet|spurious|96
SHIFT 96
GT buf|8|0|-72|__uint8_t*;char*;uint8_t*;unsigned char*
GT len|4|1|-76|int
GT hdr|12|-|-24|decoded_header
GT rc|4|-|-44|int
GT cursor|8|-|-32|__uint8_t*;char*;uint8_t*;unsigned char*
GT remaining|4|-|-40|int
GT declared|2|-|-58|__uint16_t;short;short int;short unsigned int
GT head_word|4|-|-56|__uint32_t;int;unsigned int
GT sum|4|-|-52|__uint32_t;int;unsigned int
GT summary|4|-|-36|int
GT ph|4|-|-12|payload_head
GT i|4|-|-48|int
GT last|1|-|-59|__uint8_t;char;unsigned char
DEC buf|__uint8_t*|-72|8|0
DEC len|int|-76|4|1
DEC hdr|decoded_header|-24|12|-
DEC rc|int|-44|4|-
DEC cursor|__uint8_t*|-32|8|-
DEC remaining|int|-40|4|-
DEC declared|__uint16_t|-58|2|-
DEC head_word|__uint32_t|-56|4|-
DEC sum|__uint32_t|-52|4|-
DEC summary|int|-36|4|-
DEC ph|payload_head|-12|4|-
DEC i|int|-48|4|-
DEC last|__uint8_t|-59|1|-
DEC junk0|float|-1000|8|-
DEC junk1|long long|-1008|8|-
DEC junk2|float|-1016|8|-
DEC junk3|float|-1024|1|-
EXPECT 13 0 0 0 2 11 0 17 13 2
CASE 07_packet_parser-gcc-O0.so:parse_packet|spurious|None
SHIFT -
GT buf|8|0|-72|__uint8_t*;char*;uint8_t*;unsigned char*
GT len|4|1|-76|int
GT hdr|12|-|-24|decoded_header
GT rc|4|-|-44|int
GT cursor|8|-|-32|__uint8_t*;char*;uint8_t*;unsigned char*
GT remaining|4|-|-40|int
GT declared|2|-|-58|__uint16_t;short;short int;short unsigned int
GT head_word|4|-|-56|__uint32_t;int;unsigned int
GT sum|4|-|-52|__uint32_t;int;unsigned int
GT summary|4|-|-36|int
GT ph|4|-|-12|payload_head
GT i|4|-|-48|int
GT last|1|-|-59|__uint8_t;char;unsigned char
DEC buf|__uint8_t*|-72|8|0
DEC len|int|-76|4|1
DEC hdr|decoded_header|-24|12|-
DEC rc|int|-44|4|-
DEC cursor|__uint8_t*|-32|8|-
DEC remaining|int|-40|4|-
DEC declared|__uint16_t|-58|2|-
DEC head_word|__uint32_t|-56|4|-
DEC sum|__uint32_t|-52|4|-
DEC summary|int|-36|4|-
DEC ph|payload_head|-12|4|-
DEC i|int|-48|4|-
DEC last|__uint8_t|-59|1|-
DEC junk0|float|-1000|8|-
DEC junk1|long long|-1008|8|-
DEC junk2|float|-1016|8|-
DEC junk3|float|-1024|1|-
EXPECT 13 0 0 0 2 11 0 17 13 2
CASE 07_packet_parser-gcc-O0.so:read_be16|degraded|-8
SHIFT -8
GT p|8|0|-8|__uint8_t*;char*;uint8_t*;unsigned char*
DEC p|int8|-8|8|0
EXPECT 0 1 0 0 1 0 0 1 1 1
CASE 07_packet_parser-gcc-O0.so:read_be16|degraded|0
SHIFT 0
GT p|8|0|-8|__uint8_t*;char*;uint8_t*;unsigned char*
DEC p|int8|-8|8|0
EXPECT 0 1 0 0 1 0 0 1 1 1
CASE 07_packet_parser-gcc-O0.so:read_be16|degraded|96
SHIFT 96
GT p|8|0|-8|__uint8_t*;char*;uint8_t*;unsigned char*
DEC p|int8|-8|8|0
EXPECT 0 1 0 0 1 0 0 1 1 1
CASE 07_packet_parser-gcc-O0.so:read_be16|degraded|None
SHIFT -
GT p|8|0|-8|__uint8_t*;char*;uint8_t*;unsigned char*
DEC p|int8|-8|8|0
EXPECT 0 1 0 0 1 0 0 1 1 1
CASE 07_packet_parser-gcc-O0.so:read_be16|ghidra|-8
SHIFT -8
GT p|8|0|-8|__uint8_t*;char*;uint8_t*;unsigned char*
DEC local_8|undefined8|-|8|0
EXPECT 0 1 0 0 1 0 0 1 1 1
CASE 07_packet_parser-gcc-O0.so:read_be16|ghidra|0
SHIFT 0
GT p|8|0|-8|__uint8_t*;char*;uint8_t*;unsigned char*
DEC local_8|undefined8|-|8|0
EXPECT 0 1 0 0 1 0 0 1 1 1
CASE 07_packet_parser-gcc-O0.so:read_be16|ghidra|96
SHIFT 96
GT p|8|0|-8|__uint8_t*;char*;uint8_t*;unsigned char*
DEC local_8|undefined8|-|8|0
EXPECT 0 1 0 0 1 0 0 1 1 1
CASE 07_packet_parser-gcc-O0.so:read_be16|ghidra|None
SHIFT -
GT p|8|0|-8|__uint8_t*;char*;uint8_t*;unsigned char*
DEC local_8|undefined8|-|8|0
EXPECT 0 1 0 0 1 0 0 1 1 1
CASE 07_packet_parser-gcc-O0.so:validate_header|noisy|-8
SHIFT -8
GT buf|8|0|-24|__uint8_t*;char*;uint8_t*;unsigned char*
GT len|4|1|-28|int
GT magic|2|-|-4|__uint16_t;short;short int;short unsigned int
GT ver_type|1|-|-7|__uint8_t;char;unsigned char
GT version|1|-|-6|__uint8_t;char;unsigned char
GT type|1|-|-5|__uint8_t;char;unsigned char
GT length|2|-|-2|__uint16_t;short;short int;short unsigned int
DEC len|int|-28|4|1
DEC magic|__uint16_t|-8|16|-
DEC ver_type|__uint8_t|-7|1|-
DEC v15|__uint8_t|-2|1|-
DEC v4|undefined2|-5|1|-
DEC length|__uint16_t|-2|2|-
EXPECT 5 0 2 0 1 3 1 6 7 2
CASE 07_packet_parser-gcc-O2.so:parse_packet|shadow|-8
SHIFT -8
GT buf|8|0|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT len|4|1|-|int
GT hdr|12|-|-|decoded_header
GT rc|4|-|-|int
GT cursor|8|-|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT declared|2|-|-|__uint16_t;short;short int;short unsigned int
GT head_word|4|-|-|__uint32_t;int;unsigned int
GT sum|4|-|-|__uint32_t;int;unsigned int
GT summary|4|-|-|int
GT i|4|-|-|int
GT last|1|-|-|__uint8_t;char;unsigned char
GT out|8|-|-|decoded_header*
GT len|4|-|-|int
GT buf|8|-|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT rc|4|-|-|int
DEC len|int|-|4|-
DEC buf|__uint8_t*|-|8|0
DEC len|int|-|4|1
DEC hdr|decoded_header|-|12|-
DEC rc|int|-|4|-
DEC cursor|__uint8_t*|-|8|-
DEC declared|__uint16_t|-|2|-
DEC head_word|__uint32_t|-|4|-
DEC sum|__uint32_t|-|4|-
DEC summary|int|-|4|-
DEC i|int|-|4|-
DEC last|__uint8_t|-|1|-
DEC out|decoded_header*|-|8|-
DEC len|int|-|4|-
DEC buf|__uint8_t*|-|8|-
DEC rc|int|-|4|-
EXPECT 15 0 0 -8 2 0 13 0 0 2
CASE 07_packet_parser-gcc-O2.so:parse_packet|shadow|0
SHIFT 0
GT buf|8|0|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT len|4|1|-|int
GT hdr|12|-|-|decoded_header
GT rc|4|-|-|int
GT cursor|8|-|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT declared|2|-|-|__uint16_t;short;short int;short unsigned int
GT head_word|4|-|-|__uint32_t;int;unsigned int
GT sum|4|-|-|__uint32_t;int;unsigned int
GT summary|4|-|-|int
GT i|4|-|-|int
GT last|1|-|-|__uint8_t;char;unsigned char
GT out|8|-|-|decoded_header*
GT len|4|-|-|int
GT buf|8|-|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT rc|4|-|-|int
DEC len|int|-|4|-
DEC buf|__uint8_t*|-|8|0
DEC len|int|-|4|1
DEC hdr|decoded_header|-|12|-
DEC rc|int|-|4|-
DEC cursor|__uint8_t*|-|8|-
DEC declared|__uint16_t|-|2|-
DEC head_word|__uint32_t|-|4|-
DEC sum|__uint32_t|-|4|-
DEC summary|int|-|4|-
DEC i|int|-|4|-
DEC last|__uint8_t|-|1|-
DEC out|decoded_header*|-|8|-
DEC len|int|-|4|-
DEC buf|__uint8_t*|-|8|-
DEC rc|int|-|4|-
EXPECT 15 0 0 0 2 0 13 0 0 2
CASE 07_packet_parser-gcc-O2.so:parse_packet|shadow|96
SHIFT 96
GT buf|8|0|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT len|4|1|-|int
GT hdr|12|-|-|decoded_header
GT rc|4|-|-|int
GT cursor|8|-|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT declared|2|-|-|__uint16_t;short;short int;short unsigned int
GT head_word|4|-|-|__uint32_t;int;unsigned int
GT sum|4|-|-|__uint32_t;int;unsigned int
GT summary|4|-|-|int
GT i|4|-|-|int
GT last|1|-|-|__uint8_t;char;unsigned char
GT out|8|-|-|decoded_header*
GT len|4|-|-|int
GT buf|8|-|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT rc|4|-|-|int
DEC len|int|-|4|-
DEC buf|__uint8_t*|-|8|0
DEC len|int|-|4|1
DEC hdr|decoded_header|-|12|-
DEC rc|int|-|4|-
DEC cursor|__uint8_t*|-|8|-
DEC declared|__uint16_t|-|2|-
DEC head_word|__uint32_t|-|4|-
DEC sum|__uint32_t|-|4|-
DEC summary|int|-|4|-
DEC i|int|-|4|-
DEC last|__uint8_t|-|1|-
DEC out|decoded_header*|-|8|-
DEC len|int|-|4|-
DEC buf|__uint8_t*|-|8|-
DEC rc|int|-|4|-
EXPECT 15 0 0 96 2 0 13 0 0 2
CASE 07_packet_parser-gcc-O2.so:parse_packet|shadow|None
SHIFT -
GT buf|8|0|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT len|4|1|-|int
GT hdr|12|-|-|decoded_header
GT rc|4|-|-|int
GT cursor|8|-|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT declared|2|-|-|__uint16_t;short;short int;short unsigned int
GT head_word|4|-|-|__uint32_t;int;unsigned int
GT sum|4|-|-|__uint32_t;int;unsigned int
GT summary|4|-|-|int
GT i|4|-|-|int
GT last|1|-|-|__uint8_t;char;unsigned char
GT out|8|-|-|decoded_header*
GT len|4|-|-|int
GT buf|8|-|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT rc|4|-|-|int
DEC len|int|-|4|-
DEC buf|__uint8_t*|-|8|0
DEC len|int|-|4|1
DEC hdr|decoded_header|-|12|-
DEC rc|int|-|4|-
DEC cursor|__uint8_t*|-|8|-
DEC declared|__uint16_t|-|2|-
DEC head_word|__uint32_t|-|4|-
DEC sum|__uint32_t|-|4|-
DEC summary|int|-|4|-
DEC i|int|-|4|-
DEC last|__uint8_t|-|1|-
DEC out|decoded_header*|-|8|-
DEC len|int|-|4|-
DEC buf|__uint8_t*|-|8|-
DEC rc|int|-|4|-
EXPECT 15 0 0 0 2 0 13 0 0 2
CASE 07_packet_parser-gcc-O2.so:parse_packet|spurious|-8
SHIFT -8
GT buf|8|0|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT len|4|1|-|int
GT hdr|12|-|-|decoded_header
GT rc|4|-|-|int
GT cursor|8|-|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT declared|2|-|-|__uint16_t;short;short int;short unsigned int
GT head_word|4|-|-|__uint32_t;int;unsigned int
GT sum|4|-|-|__uint32_t;int;unsigned int
GT summary|4|-|-|int
GT i|4|-|-|int
GT last|1|-|-|__uint8_t;char;unsigned char
GT out|8|-|-|decoded_header*
GT len|4|-|-|int
GT buf|8|-|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT rc|4|-|-|int
DEC buf|__uint8_t*|-|8|0
DEC len|int|-|4|1
DEC hdr|decoded_header|-|12|-
DEC rc|int|-|4|-
DEC cursor|__uint8_t*|-|8|-
DEC declared|__uint16_t|-|2|-
DEC head_word|__uint32_t|-|4|-
DEC sum|__uint32_t|-|4|-
DEC summary|int|-|4|-
DEC i|int|-|4|-
DEC last|__uint8_t|-|1|-
DEC out|decoded_header*|-|8|-
DEC len|int|-|4|-
DEC buf|__uint8_t*|-|8|-
DEC rc|int|-|4|-
DEC junk0|struct Node *|-1000|8|-
DEC junk1|int|-1008|1|-
DEC junk2|long|-1016|2|-
DEC junk3|char *|-1024|2|-
EXPECT 15 0 0 -8 2 0 13 4 0 2
CASE 07_packet_parser-gcc-O2.so:parse_packet|spurious|0
SHIFT 0
GT buf|8|0|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT len|4|1|-|int
GT hdr|12|-|-|decoded_header
GT rc|4|-|-|int
GT cursor|8|-|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT declared|2|-|-|__uint16_t;short;short int;short unsigned int
GT head_word|4|-|-|__uint32_t;int;unsigned int
GT sum|4|-|-|__uint32_t;int;unsigned int
GT summary|4|-|-|int
GT i|4|-|-|int
GT last|1|-|-|__uint8_t;char;unsigned char
GT out|8|-|-|decoded_header*
GT len|4|-|-|int
GT buf|8|-|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT rc|4|-|-|int
DEC buf|__uint8_t*|-|8|0
DEC len|int|-|4|1
DEC hdr|decoded_header|-|12|-
DEC rc|int|-|4|-
DEC cursor|__uint8_t*|-|8|-
DEC declared|__uint16_t|-|2|-
DEC head_word|__uint32_t|-|4|-
DEC sum|__uint32_t|-|4|-
DEC summary|int|-|4|-
DEC i|int|-|4|-
DEC last|__uint8_t|-|1|-
DEC out|decoded_header*|-|8|-
DEC len|int|-|4|-
DEC buf|__uint8_t*|-|8|-
DEC rc|int|-|4|-
DEC junk0|struct Node *|-1000|8|-
DEC junk1|int|-1008|1|-
DEC junk2|long|-1016|2|-
DEC junk3|char *|-1024|2|-
EXPECT 15 0 0 0 2 0 13 4 0 2
CASE 07_packet_parser-gcc-O2.so:parse_packet|spurious|96
SHIFT 96
GT buf|8|0|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT len|4|1|-|int
GT hdr|12|-|-|decoded_header
GT rc|4|-|-|int
GT cursor|8|-|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT declared|2|-|-|__uint16_t;short;short int;short unsigned int
GT head_word|4|-|-|__uint32_t;int;unsigned int
GT sum|4|-|-|__uint32_t;int;unsigned int
GT summary|4|-|-|int
GT i|4|-|-|int
GT last|1|-|-|__uint8_t;char;unsigned char
GT out|8|-|-|decoded_header*
GT len|4|-|-|int
GT buf|8|-|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT rc|4|-|-|int
DEC buf|__uint8_t*|-|8|0
DEC len|int|-|4|1
DEC hdr|decoded_header|-|12|-
DEC rc|int|-|4|-
DEC cursor|__uint8_t*|-|8|-
DEC declared|__uint16_t|-|2|-
DEC head_word|__uint32_t|-|4|-
DEC sum|__uint32_t|-|4|-
DEC summary|int|-|4|-
DEC i|int|-|4|-
DEC last|__uint8_t|-|1|-
DEC out|decoded_header*|-|8|-
DEC len|int|-|4|-
DEC buf|__uint8_t*|-|8|-
DEC rc|int|-|4|-
DEC junk0|struct Node *|-1000|8|-
DEC junk1|int|-1008|1|-
DEC junk2|long|-1016|2|-
DEC junk3|char *|-1024|2|-
EXPECT 15 0 0 96 2 0 13 4 0 2
CASE 07_packet_parser-gcc-O2.so:parse_packet|spurious|None
SHIFT -
GT buf|8|0|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT len|4|1|-|int
GT hdr|12|-|-|decoded_header
GT rc|4|-|-|int
GT cursor|8|-|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT declared|2|-|-|__uint16_t;short;short int;short unsigned int
GT head_word|4|-|-|__uint32_t;int;unsigned int
GT sum|4|-|-|__uint32_t;int;unsigned int
GT summary|4|-|-|int
GT i|4|-|-|int
GT last|1|-|-|__uint8_t;char;unsigned char
GT out|8|-|-|decoded_header*
GT len|4|-|-|int
GT buf|8|-|-|__uint8_t*;char*;uint8_t*;unsigned char*
GT rc|4|-|-|int
DEC buf|__uint8_t*|-|8|0
DEC len|int|-|4|1
DEC hdr|decoded_header|-|12|-
DEC rc|int|-|4|-
DEC cursor|__uint8_t*|-|8|-
DEC declared|__uint16_t|-|2|-
DEC head_word|__uint32_t|-|4|-
DEC sum|__uint32_t|-|4|-
DEC summary|int|-|4|-
DEC i|int|-|4|-
DEC last|__uint8_t|-|1|-
DEC out|decoded_header*|-|8|-
DEC len|int|-|4|-
DEC buf|__uint8_t*|-|8|-
DEC rc|int|-|4|-
DEC junk0|struct Node *|-1000|8|-
DEC junk1|int|-1008|1|-
DEC junk2|long|-1016|2|-
DEC junk3|char *|-1024|2|-
EXPECT 15 0 0 0 2 0 13 4 0 2
CASE 08_indirect_dispatch-clang-O0.so:h_mul|noisy|-8
SHIFT -8
GT a|4|0|12|int
GT b|4|1|8|int
DEC v7|int|16|16|-
EXPECT 1 0 1 -8 0 1 0 1 2 2
CASE 08_indirect_dispatch-gcc-O0.so:apply|degraded|-8
SHIFT -8
GT cb|8|0|-8|FUNCTION*
GT x|4|1|-12|int
DEC cb|uint8|-8|8|0
DEC x|uint4|-12|4|1
EXPECT 1 1 0 0 2 0 0 2 2 2
CASE 08_indirect_dispatch-gcc-O0.so:apply|degraded|0
SHIFT 0
GT cb|8|0|-8|FUNCTION*
GT x|4|1|-12|int
DEC cb|uint8|-8|8|0
DEC x|uint4|-12|4|1
EXPECT 1 1 0 0 2 0 0 2 2 2
CASE 08_indirect_dispatch-gcc-O0.so:apply|degraded|96
SHIFT 96
GT cb|8|0|-8|FUNCTION*
GT x|4|1|-12|int
DEC cb|uint8|-8|8|0
DEC x|uint4|-12|4|1
EXPECT 1 1 0 0 2 0 0 2 2 2
CASE 08_indirect_dispatch-gcc-O0.so:apply|degraded|None
SHIFT -
GT cb|8|0|-8|FUNCTION*
GT x|4|1|-12|int
DEC cb|uint8|-8|8|0
DEC x|uint4|-12|4|1
EXPECT 1 1 0 0 2 0 0 2 2 2
CASE 08_indirect_dispatch-gcc-O0.so:apply|ghidra|-8
SHIFT -8
GT cb|8|0|-8|FUNCTION*
GT x|4|1|-12|int
DEC local_8|undefined8|-|8|0
DEC local_c|undefined4|-|4|1
EXPECT 1 1 0 0 2 0 0 2 2 2
CASE 08_indirect_dispatch-gcc-O0.so:apply|ghidra|0
SHIFT 0
GT cb|8|0|-8|FUNCTION*
GT x|4|1|-12|int
DEC local_8|undefined8|-|8|0
DEC local_c|undefined4|-|4|1
EXPECT 1 1 0 0 2 0 0 2 2 2
CASE 08_indirect_dispatch-gcc-O0.so:apply|ghidra|96
SHIFT 96
GT cb|8|0|-8|FUNCTION*
GT x|4|1|-12|int
DEC local_8|undefined8|-|8|0
DEC local_c|undefined4|-|4|1
EXPECT 1 1 0 0 2 0 0 2 2 2
CASE 08_indirect_dispatch-gcc-O0.so:apply|ghidra|None
SHIFT -
GT cb|8|0|-8|FUNCTION*
GT x|4|1|-12|int
DEC local_8|undefined8|-|8|0
DEC local_c|undefined4|-|4|1
EXPECT 1 1 0 0 2 0 0 2 2 2
CASE 08_indirect_dispatch-gcc-O0.so:apply|ida|-8
SHIFT -8
GT cb|8|0|-8|FUNCTION*
GT x|4|1|-12|int
DEC var_8|_DWORD|88|8|0
DEC var_c|__int32|84|4|1
EXPECT 1 1 0 -96 2 0 0 2 2 2
CASE 08_indirect_dispatch-gcc-O0.so:apply|ida|0
SHIFT 0
GT cb|8|0|-8|FUNCTION*
GT x|4|1|-12|int
DEC var_8|_DWORD|88|8|0
DEC var_c|__int32|84|4|1
EXPECT 1 1 0 -96 2 0 0 2 2 2
CASE 08_indirect_dispatch-gcc-O0.so:apply|ida|96
SHIFT 96
GT cb|8|0|-8|FUNCTION*
GT x|4|1|-12|int
DEC var_8|_DWORD|88|8|0
DEC var_c|__int32|84|4|1
EXPECT 1 1 0 -96 2 0 0 2 2 2
CASE 08_indirect_dispatch-gcc-O0.so:apply|ida|None
SHIFT -
GT cb|8|0|-8|FUNCTION*
GT x|4|1|-12|int
DEC var_8|_DWORD|88|8|0
DEC var_c|__int32|84|4|1
EXPECT 1 1 0 -96 2 0 0 2 2 2
CASE 08_indirect_dispatch-gcc-O0.so:dispatch_switch|noisy|-8
SHIFT -8
GT tag|4|0|-4|int
GT a|4|1|-8|int
GT b|4|2|-12|int
DEC v4|uint8|0|1|-
DEC b|int|-12|-|2
EXPECT 1 1 1 -8 1 1 0 2 3 3
CASE 08_indirect_dispatch-gcc-O0.so:h_mul|noisy|-8
SHIFT -8
GT a|4|0|-4|int
GT b|4|1|-8|int
DEC a|int|-4|4|0
EXPECT 1 0 1 0 1 0 0 1 2 2
CASE 08_indirect_dispatch-gcc-O0.so:h_mul|noisy|0
SHIFT 0
GT a|4|0|-4|int
GT b|4|1|-8|int
DEC a|int|-4|4|0
EXPECT 1 0 1 0 1 0 0 1 2 2
CASE 08_indirect_dispatch-gcc-O0.so:h_mul|noisy|96
SHIFT 96
GT a|4|0|-4|int
GT b|4|1|-8|int
DEC a|int|-4|4|0
EXPECT 1 0 1 0 1 0 0 1 2 2
CASE 08_indirect_dispatch-gcc-O0.so:h_mul|noisy|None
SHIFT -
GT a|4|0|-4|int
GT b|4|1|-8|int
DEC a|int|-4|4|0
EXPECT 1 0 1 0 1 0 0 1 2 2
CASE 08_indirect_dispatch-gcc-O2.so:apply|degraded|-8
SHIFT -8
GT cb|8|0|-|FUNCTION*
GT x|4|1|-|int
DEC cb|qword|-|8|0
DEC x|undefined4|-|4|1
EXPECT 1 1 0 -8 2 0 0 0 0 2
CASE 08_indirect_dispatch-gcc-O2.so:apply|degraded|96
SHIFT 96
GT cb|8|0|-|FUNCTION*
GT x|4|1|-|int
DEC cb|qword|-|8|0
DEC x|undefined4|-|4|1
EXPECT 1 1 0 96 2 0 0 0 0 2
CASE 08_indirect_dispatch-gcc-O2.so:apply|ghidra|-8
SHIFT -8
GT cb|8|0|-|FUNCTION*
GT x|4|1|-|int
DEC cb|undefined8|-|8|0
DEC x|undefined4|-|4|1
EXPECT 1 1 0 -8 2 0 0 0 0 2
CASE 08_indirect_dispatch-gcc-O2.so:apply|ghidra|96
SHIFT 96
GT cb|8|0|-|FUNCTION*
GT x|4|1|-|int
DEC cb|undefined8|-|8|0
DEC x|undefined4|-|4|1
EXPECT 1 1 0 96 2 0 0 0 0 2
CASE 08_indirect_dispatch-gcc-O2.so:apply|ida|-8
SHIFT -8
GT cb|8|0|-|FUNCTION*
GT x|4|1|-|int
DEC cb|__int32|-|8|0
DEC x|__int64|-|4|1
EXPECT 1 1 0 -8 2 0 0 0 0 2
CASE 08_indirect_dispatch-gcc-O2.so:apply|ida|0
SHIFT 0
GT cb|8|0|-|FUNCTION*
GT x|4|1|-|int
DEC cb|__int32|-|8|0
DEC x|__int64|-|4|1
EXPECT 1 1 0 0 2 0 0 0 0 2
CASE 08_indirect_dispatch-gcc-O2.so:apply|ida|96
SHIFT 96
GT cb|8|0|-|FUNCTION*
GT x|4|1|-|int
DEC cb|__int32|-|8|0
DEC x|__int64|-|4|1
EXPECT 1 1 0 96 2 0 0 0 0 2
CASE 08_indirect_dispatch-gcc-O2.so:apply|ida|None
SHIFT -
GT cb|8|0|-|FUNCTION*
GT x|4|1|-|int
DEC cb|__int32|-|8|0
DEC x|__int64|-|4|1
EXPECT 1 1 0 0 2 0 0 0 0 2
CASE 09_memory_effects-gcc-O0.so:mem_copy|ghidra|-8
SHIFT -8
GT dst|8|0|-24|int*
GT src|8|1|-32|int*
GT n|4|2|-36|int
GT i|4|-|-4|int
DEC local_18|int*|-|8|0
DEC local_20|int*|-|8|1
DEC local_24|undefined4|-|4|2
DEC local_4|undefined4|-|4|-
EXPECT 3 0 1 -8 3 0 0 4 4 3
CASE 09_memory_effects-gcc-O0.so:mem_set|ghidra|-8
SHIFT -8
GT dst|8|0|-24|int*
GT val|4|1|-28|int
GT n|4|2|-32|int
GT i|4|-|-4|int
DEC local_18|undefined8|-|8|0
DEC local_1c|undefined4|-|4|1
DEC local_20|undefined4|-|4|2
DEC local_4|undefined4|-|4|-
EXPECT 2 1 1 -8 3 0 0 4 4 3
CASE 09_memory_effects-gcc-O0.so:mem_set|noisy|0
SHIFT 0
GT dst|8|0|-24|int*
GT val|4|1|-28|int
GT n|4|2|-32|int
GT i|4|-|-4|int
DEC dst|int*|-20|8|-
DEC val|int|-28|4|1
DEC i|int|-4|4|-
EXPECT 3 0 1 0 1 1 1 3 4 3
CASE 09_memory_effects-gcc-O0.so:mem_set|noisy|96
SHIFT 96
GT dst|8|0|-24|int*
GT val|4|1|-28|int
GT n|4|2|-32|int
GT i|4|-|-4|int
DEC dst|int*|-20|8|-
DEC val|int|-28|4|1
DEC i|int|-4|4|-
EXPECT 3 0 1 0 1 1 1 3 4 3
CASE 09_memory_effects-gcc-O0.so:mem_set|noisy|None
SHIFT -
GT dst|8|0|-24|int*
GT val|4|1|-28|int
GT n|4|2|-32|int
GT i|4|-|-4|int
DEC dst|int*|-20|8|-
DEC val|int|-28|4|1
DEC i|int|-4|4|-
EXPECT 3 0 1 0 1 1 1 3 4 3
CASE 09_memory_effects-gcc-O0.so:tick_n|noisy|0
SHIFT 0
GT n|4|0|-20|int
GT i|4|-|-4|int
DEC v1|double|-20|1|-
DEC i|int|-4|4|-
EXPECT 1 1 0 0 0 2 0 2 2 1
CASE 09_memory_effects-gcc-O0.so:tick_n|noisy|None
SHIFT -
GT n|4|0|-20|int
GT i|4|-|-4|int
DEC v1|double|-20|1|-
DEC i|int|-4|4|-
EXPECT 1 1 0 0 0 2 0 2 2 1
CASE 100_struct_layout-gcc-O0.so:struct_assignment_copies|noisy|0
SHIFT 0
GT tag|4|0|-36|__int32_t;int
GT value|4|1|-40|__int32_t;int
GT source|12|-|-24|Tight
GT destination|12|-|-12|Tight
DEC v16|__int16|-28|4|-
DEC source|Tight|-24|12|-
DEC v19|int2|-12|-|-
EXPECT 1 1 2 0 0 2 0 3 4 2
CASE 100_struct_layout-gcc-O0.so:struct_assignment_copies|noisy|None
SHIFT -
GT tag|4|0|-36|__int32_t;int
GT value|4|1|-40|__int32_t;int
GT source|12|-|-24|Tight
GT destination|12|-|-12|Tight
DEC v16|__int16|-28|4|-
DEC source|Tight|-24|12|-
DEC v19|int2|-12|-|-
EXPECT 1 1 2 0 0 2 0 3 4 2
CASE 101_static_locals-gcc-O0.so:counter_next|degraded|-8
SHIFT -8
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC increment|uint4|-4|4|0
DEC counter|_DWORD|-|4|-
EXPECT 2 0 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|degraded|0
SHIFT 0
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC increment|uint4|-4|4|0
DEC counter|_DWORD|-|4|-
EXPECT 2 0 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|degraded|96
SHIFT 96
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC increment|uint4|-4|4|0
DEC counter|_DWORD|-|4|-
EXPECT 2 0 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|degraded|None
SHIFT -
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC increment|uint4|-4|4|0
DEC counter|_DWORD|-|4|-
EXPECT 2 0 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|echo|-8
SHIFT -8
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC increment|__int32_t|-4|4|0
DEC counter|__int32_t|-|4|-
EXPECT 2 0 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|echo|0
SHIFT 0
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC increment|__int32_t|-4|4|0
DEC counter|__int32_t|-|4|-
EXPECT 2 0 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|echo|96
SHIFT 96
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC increment|__int32_t|-4|4|0
DEC counter|__int32_t|-|4|-
EXPECT 2 0 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|echo|None
SHIFT -
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC increment|__int32_t|-4|4|0
DEC counter|__int32_t|-|4|-
EXPECT 2 0 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|ghidra|-8
SHIFT -8
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC local_4|__int32_t|-|4|0
DEC counter|undefined4|-|4|-
EXPECT 2 0 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|ghidra|0
SHIFT 0
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC local_4|__int32_t|-|4|0
DEC counter|undefined4|-|4|-
EXPECT 2 0 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|ghidra|96
SHIFT 96
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC local_4|__int32_t|-|4|0
DEC counter|undefined4|-|4|-
EXPECT 2 0 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|ghidra|None
SHIFT -
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC local_4|__int32_t|-|4|0
DEC counter|undefined4|-|4|-
EXPECT 2 0 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|ida|-8
SHIFT -8
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC var_4|__int32|92|4|0
DEC counter|__int32_t|-|4|-
EXPECT 2 0 0 -96 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|ida|0
SHIFT 0
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC var_4|__int32|92|4|0
DEC counter|__int32_t|-|4|-
EXPECT 2 0 0 -96 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|ida|96
SHIFT 96
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC var_4|__int32|92|4|0
DEC counter|__int32_t|-|4|-
EXPECT 2 0 0 -96 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|ida|None
SHIFT -
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC var_4|__int32|92|4|0
DEC counter|__int32_t|-|4|-
EXPECT 2 0 0 -96 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|shadow|-8
SHIFT -8
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC increment|char|-4|4|0
DEC increment|__int32_t|-4|4|0
DEC counter|__int32_t|-|4|-
EXPECT 1 1 0 0 1 0 1 2 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|shadow|0
SHIFT 0
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC increment|char|-4|4|0
DEC increment|__int32_t|-4|4|0
DEC counter|__int32_t|-|4|-
EXPECT 1 1 0 0 1 0 1 2 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|shadow|96
SHIFT 96
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC increment|char|-4|4|0
DEC increment|__int32_t|-4|4|0
DEC counter|__int32_t|-|4|-
EXPECT 1 1 0 0 1 0 1 2 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|shadow|None
SHIFT -
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC increment|char|-4|4|0
DEC increment|__int32_t|-4|4|0
DEC counter|__int32_t|-|4|-
EXPECT 1 1 0 0 1 0 1 2 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|wrong|-8
SHIFT -8
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC increment|void *|-4|4|0
DEC counter|int *|-|4|-
EXPECT 0 2 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|wrong|0
SHIFT 0
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC increment|void *|-4|4|0
DEC counter|int *|-|4|-
EXPECT 0 2 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|wrong|96
SHIFT 96
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC increment|void *|-4|4|0
DEC counter|int *|-|4|-
EXPECT 0 2 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_next|wrong|None
SHIFT -
GT increment|4|0|-4|__int32_t;int
GT counter|4|-|-|__int32_t;int
DEC increment|void *|-4|4|0
DEC counter|int *|-|4|-
EXPECT 0 2 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:counter_reset|degraded|-8
SHIFT -8
GT generation|4|-|-|__int32_t;int
DEC generation|uint4|-|4|-
EXPECT 1 0 0 -8 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|degraded|0
SHIFT 0
GT generation|4|-|-|__int32_t;int
DEC generation|uint4|-|4|-
EXPECT 1 0 0 0 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|degraded|96
SHIFT 96
GT generation|4|-|-|__int32_t;int
DEC generation|uint4|-|4|-
EXPECT 1 0 0 96 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|degraded|None
SHIFT -
GT generation|4|-|-|__int32_t;int
DEC generation|uint4|-|4|-
EXPECT 1 0 0 0 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|echo|-8
SHIFT -8
GT generation|4|-|-|__int32_t;int
DEC generation|__int32_t|-|4|-
EXPECT 1 0 0 -8 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|echo|0
SHIFT 0
GT generation|4|-|-|__int32_t;int
DEC generation|__int32_t|-|4|-
EXPECT 1 0 0 0 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|echo|96
SHIFT 96
GT generation|4|-|-|__int32_t;int
DEC generation|__int32_t|-|4|-
EXPECT 1 0 0 96 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|echo|None
SHIFT -
GT generation|4|-|-|__int32_t;int
DEC generation|__int32_t|-|4|-
EXPECT 1 0 0 0 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|ghidra|-8
SHIFT -8
GT generation|4|-|-|__int32_t;int
DEC generation|undefined4|-|4|-
EXPECT 1 0 0 -8 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|ghidra|0
SHIFT 0
GT generation|4|-|-|__int32_t;int
DEC generation|undefined4|-|4|-
EXPECT 1 0 0 0 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|ghidra|96
SHIFT 96
GT generation|4|-|-|__int32_t;int
DEC generation|undefined4|-|4|-
EXPECT 1 0 0 96 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|ghidra|None
SHIFT -
GT generation|4|-|-|__int32_t;int
DEC generation|undefined4|-|4|-
EXPECT 1 0 0 0 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|ida|-8
SHIFT -8
GT generation|4|-|-|__int32_t;int
DEC generation|__int32_t|-|4|-
EXPECT 1 0 0 -8 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|ida|0
SHIFT 0
GT generation|4|-|-|__int32_t;int
DEC generation|__int32_t|-|4|-
EXPECT 1 0 0 0 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|ida|96
SHIFT 96
GT generation|4|-|-|__int32_t;int
DEC generation|__int32_t|-|4|-
EXPECT 1 0 0 96 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|ida|None
SHIFT -
GT generation|4|-|-|__int32_t;int
DEC generation|__int32_t|-|4|-
EXPECT 1 0 0 0 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|noisy|-8
SHIFT -8
GT generation|4|-|-|__int32_t;int
DEC generation|__int32_t|-|4|-
EXPECT 1 0 0 -8 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|noisy|0
SHIFT 0
GT generation|4|-|-|__int32_t;int
DEC generation|__int32_t|-|4|-
EXPECT 1 0 0 0 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|noisy|96
SHIFT 96
GT generation|4|-|-|__int32_t;int
DEC generation|__int32_t|-|4|-
EXPECT 1 0 0 96 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|noisy|None
SHIFT -
GT generation|4|-|-|__int32_t;int
DEC generation|__int32_t|-|4|-
EXPECT 1 0 0 0 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|shadow|-8
SHIFT -8
GT generation|4|-|-|__int32_t;int
DEC generation|long long|-|4|-
DEC generation|__int32_t|-|4|-
EXPECT 1 0 0 -8 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|shadow|0
SHIFT 0
GT generation|4|-|-|__int32_t;int
DEC generation|long long|-|4|-
DEC generation|__int32_t|-|4|-
EXPECT 1 0 0 0 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|shadow|96
SHIFT 96
GT generation|4|-|-|__int32_t;int
DEC generation|long long|-|4|-
DEC generation|__int32_t|-|4|-
EXPECT 1 0 0 96 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|shadow|None
SHIFT -
GT generation|4|-|-|__int32_t;int
DEC generation|long long|-|4|-
DEC generation|__int32_t|-|4|-
EXPECT 1 0 0 0 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|spurious|-8
SHIFT -8
GT generation|4|-|-|__int32_t;int
DEC generation|__int32_t|-|4|-
DEC junk0|int *|-1000|2|-
DEC junk1|char|-1008|1|-
DEC junk2|bool|-1016|4|-
EXPECT 1 0 0 -8 0 0 1 3 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|spurious|0
SHIFT 0
GT generation|4|-|-|__int32_t;int
DEC generation|__int32_t|-|4|-
DEC junk0|int *|-1000|2|-
DEC junk1|char|-1008|1|-
DEC junk2|bool|-1016|4|-
EXPECT 1 0 0 0 0 0 1 3 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|spurious|96
SHIFT 96
GT generation|4|-|-|__int32_t;int
DEC generation|__int32_t|-|4|-
DEC junk0|int *|-1000|2|-
DEC junk1|char|-1008|1|-
DEC junk2|bool|-1016|4|-
EXPECT 1 0 0 96 0 0 1 3 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|spurious|None
SHIFT -
GT generation|4|-|-|__int32_t;int
DEC generation|__int32_t|-|4|-
DEC junk0|int *|-1000|2|-
DEC junk1|char|-1008|1|-
DEC junk2|bool|-1016|4|-
EXPECT 1 0 0 0 0 0 1 3 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|wrong|-8
SHIFT -8
GT generation|4|-|-|__int32_t;int
DEC generation|long|-|4|-
EXPECT 0 1 0 -8 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|wrong|0
SHIFT 0
GT generation|4|-|-|__int32_t;int
DEC generation|long|-|4|-
EXPECT 0 1 0 0 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|wrong|96
SHIFT 96
GT generation|4|-|-|__int32_t;int
DEC generation|long|-|4|-
EXPECT 0 1 0 96 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:counter_reset|wrong|None
SHIFT -
GT generation|4|-|-|__int32_t;int
DEC generation|long|-|4|-
EXPECT 0 1 0 0 0 0 1 0 0 0
CASE 101_static_locals-gcc-O0.so:static_table_lookup|shadow|-8
SHIFT -8
GT index|4|0|-4|__int32_t;int
GT squares|32|-|-|__int32_t;__int32_t[8];int;int32_t[8];int[8]
DEC squares|int|-|32|-
DEC index|__int32_t|-4|4|0
DEC squares|__int32_t|-|32|-
EXPECT 2 0 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:static_table_lookup|shadow|0
SHIFT 0
GT index|4|0|-4|__int32_t;int
GT squares|32|-|-|__int32_t;__int32_t[8];int;int32_t[8];int[8]
DEC squares|int|-|32|-
DEC index|__int32_t|-4|4|0
DEC squares|__int32_t|-|32|-
EXPECT 2 0 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:static_table_lookup|shadow|96
SHIFT 96
GT index|4|0|-4|__int32_t;int
GT squares|32|-|-|__int32_t;__int32_t[8];int;int32_t[8];int[8]
DEC squares|int|-|32|-
DEC index|__int32_t|-4|4|0
DEC squares|__int32_t|-|32|-
EXPECT 2 0 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:static_table_lookup|shadow|None
SHIFT -
GT index|4|0|-4|__int32_t;int
GT squares|32|-|-|__int32_t;__int32_t[8];int;int32_t[8];int[8]
DEC squares|int|-|32|-
DEC index|__int32_t|-4|4|0
DEC squares|__int32_t|-|32|-
EXPECT 2 0 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:static_table_lookup|spurious|-8
SHIFT -8
GT index|4|0|-4|__int32_t;int
GT squares|32|-|-|__int32_t;__int32_t[8];int;int32_t[8];int[8]
DEC index|__int32_t|-4|4|0
DEC squares|__int32_t|-|32|-
DEC junk0|int|-1000|4|-
DEC junk1|int|-1008|8|-
DEC junk2|char *|-1016|8|-
EXPECT 2 0 0 0 1 0 1 4 1 1
CASE 101_static_locals-gcc-O0.so:static_table_lookup|spurious|96
SHIFT 96
GT index|4|0|-4|__int32_t;int
GT squares|32|-|-|__int32_t;__int32_t[8];int;int32_t[8];int[8]
DEC index|__int32_t|-4|4|0
DEC squares|__int32_t|-|32|-
DEC junk0|int|-1000|4|-
DEC junk1|int|-1008|8|-
DEC junk2|char *|-1016|8|-
EXPECT 2 0 0 0 1 0 1 4 1 1
CASE 101_static_locals-gcc-O0.so:static_table_lookup|wrong|-8
SHIFT -8
GT index|4|0|-4|__int32_t;int
GT squares|32|-|-|__int32_t;__int32_t[8];int;int32_t[8];int[8]
DEC index|int|-4|4|0
DEC squares|short|-|32|-
EXPECT 1 1 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:static_table_lookup|wrong|0
SHIFT 0
GT index|4|0|-4|__int32_t;int
GT squares|32|-|-|__int32_t;__int32_t[8];int;int32_t[8];int[8]
DEC index|int|-4|4|0
DEC squares|short|-|32|-
EXPECT 1 1 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:static_table_lookup|wrong|96
SHIFT 96
GT index|4|0|-4|__int32_t;int
GT squares|32|-|-|__int32_t;__int32_t[8];int;int32_t[8];int[8]
DEC index|int|-4|4|0
DEC squares|short|-|32|-
EXPECT 1 1 0 0 1 0 1 1 1 1
CASE 101_static_locals-gcc-O0.so:static_table_lookup|wrong|None
SHIFT -
GT index|4|0|-4|__int32_t;int
GT squares|32|-|-|__int32_t;__int32_t[8];int;int32_t[8];int[8]
DEC index|int|-4|4|0
DEC squares|short|-|32|-
EXPECT 1 1 0 0 1 0 1 1 1 1
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|degraded|0
SHIFT 0
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC program|qword|-24|8|0
DEC length|_DWORD|-28|4|1
DEC seed|dword|-32|4|2
DEC targets|void*|-|32|-
DEC accumulator|_DWORD|-12|4|-
DEC position|undefined4|-8|4|-
DEC opcode|uint4|-4|4|-
EXPECT 6 1 0 0 3 3 1 6 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|degraded|96
SHIFT 96
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC program|qword|-24|8|0
DEC length|_DWORD|-28|4|1
DEC seed|dword|-32|4|2
DEC targets|void*|-|32|-
DEC accumulator|_DWORD|-12|4|-
DEC position|undefined4|-8|4|-
DEC opcode|uint4|-4|4|-
EXPECT 6 1 0 0 3 3 1 6 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|degraded|None
SHIFT -
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC program|qword|-24|8|0
DEC length|_DWORD|-28|4|1
DEC seed|dword|-32|4|2
DEC targets|void*|-|32|-
DEC accumulator|_DWORD|-12|4|-
DEC position|undefined4|-8|4|-
DEC opcode|uint4|-4|4|-
EXPECT 6 1 0 0 3 3 1 6 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|echo|0
SHIFT 0
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC program|__int32_t*|-24|8|0
DEC length|__int32_t|-28|4|1
DEC seed|__int32_t|-32|4|2
DEC targets|void*|-|32|-
DEC accumulator|__int32_t|-12|4|-
DEC position|__int32_t|-8|4|-
DEC opcode|__int32_t|-4|4|-
EXPECT 7 0 0 0 3 3 1 6 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|echo|96
SHIFT 96
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC program|__int32_t*|-24|8|0
DEC length|__int32_t|-28|4|1
DEC seed|__int32_t|-32|4|2
DEC targets|void*|-|32|-
DEC accumulator|__int32_t|-12|4|-
DEC position|__int32_t|-8|4|-
DEC opcode|__int32_t|-4|4|-
EXPECT 7 0 0 0 3 3 1 6 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|echo|None
SHIFT -
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC program|__int32_t*|-24|8|0
DEC length|__int32_t|-28|4|1
DEC seed|__int32_t|-32|4|2
DEC targets|void*|-|32|-
DEC accumulator|__int32_t|-12|4|-
DEC position|__int32_t|-8|4|-
DEC opcode|__int32_t|-4|4|-
EXPECT 7 0 0 0 3 3 1 6 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|ghidra|0
SHIFT 0
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC local_18|undefined8|-|8|0
DEC local_1c|undefined4|-|4|1
DEC local_20|undefined4|-|4|2
DEC targets|void*|-|32|-
DEC local_c|undefined4|-|4|-
DEC local_8|undefined4|-|4|-
DEC local_4|undefined4|-|4|-
EXPECT 6 1 0 0 3 3 1 6 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|ghidra|96
SHIFT 96
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC local_18|undefined8|-|8|0
DEC local_1c|undefined4|-|4|1
DEC local_20|undefined4|-|4|2
DEC targets|void*|-|32|-
DEC local_c|undefined4|-|4|-
DEC local_8|undefined4|-|4|-
DEC local_4|undefined4|-|4|-
EXPECT 6 1 0 0 3 3 1 6 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|ghidra|None
SHIFT -
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC local_18|undefined8|-|8|0
DEC local_1c|undefined4|-|4|1
DEC local_20|undefined4|-|4|2
DEC targets|void*|-|32|-
DEC local_c|undefined4|-|4|-
DEC local_8|undefined4|-|4|-
DEC local_4|undefined4|-|4|-
EXPECT 6 1 0 0 3 3 1 6 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|ida|-8
SHIFT -8
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC var_18|__int32_t*|72|8|0
DEC var_1c|__int32|68|4|1
DEC var_20|__int32|64|4|2
DEC targets|__int32|-|32|-
DEC var_c|__int32_t|84|4|-
DEC var_8|__int32|88|4|-
DEC var_4|_QWORD|92|4|-
EXPECT 6 1 0 -96 3 3 1 6 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|ida|0
SHIFT 0
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC var_18|__int32_t*|72|8|0
DEC var_1c|__int32|68|4|1
DEC var_20|__int32|64|4|2
DEC targets|__int32|-|32|-
DEC var_c|__int32_t|84|4|-
DEC var_8|__int32|88|4|-
DEC var_4|_QWORD|92|4|-
EXPECT 6 1 0 -96 3 3 1 6 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|ida|96
SHIFT 96
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC var_18|__int32_t*|72|8|0
DEC var_1c|__int32|68|4|1
DEC var_20|__int32|64|4|2
DEC targets|__int32|-|32|-
DEC var_c|__int32_t|84|4|-
DEC var_8|__int32|88|4|-
DEC var_4|_QWORD|92|4|-
EXPECT 6 1 0 -96 3 3 1 6 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|ida|None
SHIFT -
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC var_18|__int32_t*|72|8|0
DEC var_1c|__int32|68|4|1
DEC var_20|__int32|64|4|2
DEC targets|__int32|-|32|-
DEC var_c|__int32_t|84|4|-
DEC var_8|__int32|88|4|-
DEC var_4|_QWORD|92|4|-
EXPECT 6 1 0 -96 3 3 1 6 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|shadow|0
SHIFT 0
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC program|char *|-24|8|0
DEC program|__int32_t*|-24|8|0
DEC length|__int32_t|-28|4|1
DEC seed|__int32_t|-32|4|2
DEC targets|void*|-|32|-
DEC accumulator|__int32_t|-12|4|-
DEC position|__int32_t|-8|4|-
DEC opcode|__int32_t|-4|4|-
EXPECT 6 1 0 0 3 3 1 7 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|shadow|96
SHIFT 96
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC program|char *|-24|8|0
DEC program|__int32_t*|-24|8|0
DEC length|__int32_t|-28|4|1
DEC seed|__int32_t|-32|4|2
DEC targets|void*|-|32|-
DEC accumulator|__int32_t|-12|4|-
DEC position|__int32_t|-8|4|-
DEC opcode|__int32_t|-4|4|-
EXPECT 6 1 0 0 3 3 1 7 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|shadow|None
SHIFT -
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC program|char *|-24|8|0
DEC program|__int32_t*|-24|8|0
DEC length|__int32_t|-28|4|1
DEC seed|__int32_t|-32|4|2
DEC targets|void*|-|32|-
DEC accumulator|__int32_t|-12|4|-
DEC position|__int32_t|-8|4|-
DEC opcode|__int32_t|-4|4|-
EXPECT 6 1 0 0 3 3 1 7 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|spurious|0
SHIFT 0
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC program|__int32_t*|-24|8|0
DEC length|__int32_t|-28|4|1
DEC seed|__int32_t|-32|4|2
DEC targets|void*|-|32|-
DEC accumulator|__int32_t|-12|4|-
DEC position|__int32_t|-8|4|-
DEC opcode|__int32_t|-4|4|-
DEC junk0|bool|-1000|2|-
DEC junk1|int|-1008|1|-
DEC junk2|short|-1016|8|-
EXPECT 7 0 0 0 3 3 1 9 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|spurious|96
SHIFT 96
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC program|__int32_t*|-24|8|0
DEC length|__int32_t|-28|4|1
DEC seed|__int32_t|-32|4|2
DEC targets|void*|-|32|-
DEC accumulator|__int32_t|-12|4|-
DEC position|__int32_t|-8|4|-
DEC opcode|__int32_t|-4|4|-
DEC junk0|bool|-1000|2|-
DEC junk1|int|-1008|1|-
DEC junk2|short|-1016|8|-
EXPECT 7 0 0 0 3 3 1 9 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|spurious|None
SHIFT -
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC program|__int32_t*|-24|8|0
DEC length|__int32_t|-28|4|1
DEC seed|__int32_t|-32|4|2
DEC targets|void*|-|32|-
DEC accumulator|__int32_t|-12|4|-
DEC position|__int32_t|-8|4|-
DEC opcode|__int32_t|-4|4|-
DEC junk0|bool|-1000|2|-
DEC junk1|int|-1008|1|-
DEC junk2|short|-1016|8|-
EXPECT 7 0 0 0 3 3 1 9 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|wrong|0
SHIFT 0
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC program|int *|-24|8|0
DEC length|long|-28|4|1
DEC seed|unsigned int|-32|4|2
DEC targets|float|-|32|-
DEC accumulator|char *|-12|4|-
DEC position|float|-8|4|-
DEC opcode|long long|-4|4|-
EXPECT 2 5 0 0 3 3 1 6 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|wrong|96
SHIFT 96
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC program|int *|-24|8|0
DEC length|long|-28|4|1
DEC seed|unsigned int|-32|4|2
DEC targets|float|-|32|-
DEC accumulator|char *|-12|4|-
DEC position|float|-8|4|-
DEC opcode|long long|-4|4|-
EXPECT 2 5 0 0 3 3 1 6 6 3
CASE 103_computed_goto-gcc-O0.so:threaded_interpreter|wrong|None
SHIFT -
GT program|8|0|-24|__int32_t*;int*;int32_t*
GT length|4|1|-28|__int32_t;int
GT seed|4|2|-32|__int32_t;int
GT targets|32|-|-|void*;void*[4]
GT accumulator|4|-|-12|__int32_t;int
GT position|4|-|-8|__int32_t;int
GT opcode|4|-|-4|__int32_t;int
DEC program|int *|-24|8|0
DEC length|long|-28|4|1
DEC seed|unsigned int|-32|4|2
DEC targets|float|-|32|-
DEC accumulator|char *|-12|4|-
DEC position|float|-8|4|-
DEC opcode|long long|-4|4|-
EXPECT 2 5 0 0 3 3 1 6 6 3
CASE 104_statement_expression-gcc-O0.so:statement_expression_max|degraded|-8
SHIFT -8
GT a|4|0|-20|__int32_t;int
GT b|4|1|-24|__int32_t;int
GT c|4|2|-28|__int32_t;int
GT _a|4|-|-8|__int32_t;int
GT _b|4|-|-4|__int32_t;int
GT _a|4|-|-16|__int32_t;int
GT _b|4|-|-12|__int32_t;int
DEC a|__int32|-20|4|0
DEC b|uint4|-24|4|1
DEC c|undefined4|-28|4|2
DEC _a|int4|-8|4|-
DEC _b|dword|-4|4|-
DEC _a|__int32|-16|4|-
DEC _b|uint4|-12|4|-
EXPECT 7 0 0 -8 3 2 2 7 7 3
CASE 104_statement_expression-gcc-O0.so:statement_expression_max|echo|-8
SHIFT -8
GT a|4|0|-20|__int32_t;int
GT b|4|1|-24|__int32_t;int
GT c|4|2|-28|__int32_t;int
GT _a|4|-|-8|__int32_t;int
GT _b|4|-|-4|__int32_t;int
GT _a|4|-|-16|__int32_t;int
GT _b|4|-|-12|__int32_t;int
DEC a|__int32_t|-20|4|0
DEC b|__int32_t|-24|4|1
DEC c|__int32_t|-28|4|2
DEC _a|__int32_t|-8|4|-
DEC _b|__int32_t|-4|4|-
DEC _a|__int32_t|-16|4|-
DEC _b|__int32_t|-12|4|-
EXPECT 7 0 0 -8 3 2 2 7 7 3
CASE 104_statement_expression-gcc-O0.so:statement_expression_max|shadow|-8
SHIFT -8
GT a|4|0|-20|__int32_t;int
GT b|4|1|-24|__int32_t;int
GT c|4|2|-28|__int32_t;int
GT _a|4|-|-8|__int32_t;int
GT _b|4|-|-4|__int32_t;int
GT _a|4|-|-16|__int32_t;int
GT _b|4|-|-12|__int32_t;int
DEC _a|void *|-16|4|-
DEC a|__int32_t|-20|4|0
DEC b|__int32_t|-24|4|1
DEC c|__int32_t|-28|4|2
DEC _a|__int32_t|-8|4|-
DEC _b|__int32_t|-4|4|-
DEC _a|__int32_t|-16|4|-
DEC _b|__int32_t|-12|4|-
EXPECT 7 0 0 -8 3 2 2 8 7 3
CASE 104_statement_expression-gcc-O0.so:statement_expression_max|spurious|-8
SHIFT -8
GT a|4|0|-20|__int32_t;int
GT b|4|1|-24|__int32_t;int
GT c|4|2|-28|__int32_t;int
GT _a|4|-|-8|__int32_t;int
GT _b|4|-|-4|__int32_t;int
GT _a|4|-|-16|__int32_t;int
GT _b|4|-|-12|__int32_t;int
DEC a|__int32_t|-20|4|0
DEC b|__int32_t|-24|4|1
DEC c|__int32_t|-28|4|2
DEC _a|__int32_t|-8|4|-
DEC _b|__int32_t|-4|4|-
DEC _a|__int32_t|-16|4|-
DEC _b|__int32_t|-12|4|-
DEC junk0|char *|-1000|2|-
DEC junk1|short|-1008|4|-
DEC junk2|unsigned int|-1016|8|-
DEC junk3|char *|-1024|4|-
EXPECT 7 0 0 -8 3 2 2 11 7 3
CASE 104_statement_expression-gcc-O0.so:statement_expression_max|wrong|-8
SHIFT -8
GT a|4|0|-20|__int32_t;int
GT b|4|1|-24|__int32_t;int
GT c|4|2|-28|__int32_t;int
GT _a|4|-|-8|__int32_t;int
GT _b|4|-|-4|__int32_t;int
GT _a|4|-|-16|__int32_t;int
GT _b|4|-|-12|__int32_t;int
DEC a|struct Node *|-20|4|0
DEC b|int|-24|4|1
DEC c|struct Node *|-28|4|2
DEC _a|struct Node *|-8|4|-
DEC _b|char|-4|4|-
DEC _a|char *|-16|4|-
DEC _b|struct Node *|-12|4|-
EXPECT 1 6 0 -8 3 2 2 7 7 3
"##;

    /// One case parsed out of [`DIFFERENTIAL_CORPUS`].
    struct Case {
        id: String,
        shift: Option<Shift>,
        ground_truth: Vec<GroundTruthVar>,
        decompiled: Vec<DecompiledVar>,
        expected: [i64; 10],
    }

    /// Parses the corpus text into cases.
    ///
    /// The format is one `CASE`/`SHIFT`/`GT`*/`DEC`*/`EXPECT` block per case,
    /// `|`-separated fields, `;`-separated type forms, `-` for absent. It is
    /// a text format rather than JSON because it is generated once, read
    /// once, and diffed by eye when a case changes.
    fn parse_corpus(text: &str) -> Vec<Case> {
        let mut cases: Vec<Case> = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (tag, rest) = line.split_once(' ').unwrap_or((line, ""));
            match tag {
                "CASE" => cases.push(Case {
                    id: rest.to_string(),
                    shift: None,
                    ground_truth: Vec::new(),
                    decompiled: Vec::new(),
                    expected: [0; 10],
                }),
                "SHIFT" => {
                    let case = cases.last_mut().expect("SHIFT before CASE");
                    case.shift = if rest == "-" {
                        None
                    } else {
                        Some(rest.parse::<Shift>().expect("shift"))
                    };
                }
                "GT" => {
                    let fields: Vec<&str> = rest.split('|').collect();
                    assert_eq!(fields.len(), 5, "GT line: {rest}");
                    let offsets = if fields[3] == "-" {
                        Vec::new()
                    } else {
                        fields[3]
                            .split(',')
                            .map(|o| o.parse::<i64>().expect("offset"))
                            .collect()
                    };
                    let forms: Vec<String> = if fields[4].is_empty() {
                        Vec::new()
                    } else {
                        fields[4].split(';').map(str::to_string).collect()
                    };
                    cases
                        .last_mut()
                        .expect("GT before CASE")
                        .ground_truth
                        .push(GroundTruthVar {
                            name: fields[0].to_string(),
                            types: forms,
                            rbp_offsets: offsets,
                            size: fields[1].parse().expect("size"),
                            arg_index: (fields[2] != "-").then(|| fields[2].parse().expect("arg")),
                        });
                }
                "DEC" => {
                    let fields: Vec<&str> = rest.split('|').collect();
                    assert_eq!(fields.len(), 5, "DEC line: {rest}");
                    cases
                        .last_mut()
                        .expect("DEC before CASE")
                        .decompiled
                        .push(DecompiledVar {
                            name: fields[0].to_string(),
                            type_spelling: fields[1].to_string(),
                            stack_offset: (fields[2] != "-")
                                .then(|| fields[2].parse().expect("offset")),
                            size: (fields[3] != "-").then(|| fields[3].parse().expect("size")),
                            arg_index: (fields[4] != "-").then(|| fields[4].parse().expect("arg")),
                        });
                }
                "EXPECT" => {
                    let values: Vec<i64> = rest
                        .split_whitespace()
                        .map(|v| v.parse().expect("expect field"))
                        .collect();
                    assert_eq!(values.len(), 10, "EXPECT line: {rest}");
                    let case = cases.last_mut().expect("EXPECT before CASE");
                    case.expected.copy_from_slice(&values);
                }
                other => panic!("unknown corpus tag {other:?}"),
            }
        }
        cases
    }

    #[test]
    fn differential_corpus_reproduces_the_reference() {
        // Every expectation in DIFFERENTIAL_CORPUS is the output of
        // DecBench's own `TypeMatchMetric._match_structured`, called on the
        // inputs recorded beside it. The ground-truth halves are REAL: they
        // were extracted by the reference's `extract_ground_truth_types` from
        // Glaurung's fixture binaries under
        // `tests/decompiler_fixtures/build/` (gcc and clang, -O0 and -O2), so
        // the type spellings, sizes, offsets, names and argument indices are
        // whatever DWARF actually recorded, not invented. The decompiled
        // halves are those ground truths perturbed the way the three real
        // backends perturb them -- Ghidra's `local_1c`/`undefinedN` with the
        // structured offset dropped, IDA's frame-bottom `var_20` offsets,
        // width degradation, wrong types, dropped variables, spurious extra
        // variables, and bucket collisions -- under a fixed seed.
        //
        // The embedded corpus is a stratified subsample; the generator ran
        // 10,272 cases over 321 real functions and this implementation
        // reproduced the reference's (tp, fp, fn, shift, per-pass counts) on
        // all of them.
        let cases = parse_corpus(DIFFERENTIAL_CORPUS);
        assert_eq!(cases.len(), 440, "corpus changed size");

        let mut disagreements: Vec<String> = Vec::new();
        for case in &cases {
            let got = match_structured(&case.ground_truth, &case.decompiled, case.shift);
            let actual = [
                i64::from(got.true_positives),
                i64::from(got.false_positives),
                i64::from(got.false_negatives),
                got.shift.expect("structured path always resolves a shift") as i64,
                i64::from(got.matched_by_arg),
                i64::from(got.matched_by_offset),
                i64::from(got.matched_by_name),
                i64::from(got.decomp_stack_vars),
                i64::from(got.gt_stack_vars),
                i64::from(got.gt_arg_vars),
            ];
            if actual != case.expected {
                disagreements.push(format!(
                    "{}: expected {:?}, got {:?}",
                    case.id, case.expected, actual
                ));
            }
        }
        assert!(
            disagreements.is_empty(),
            "{} of {} cases disagree with the reference:\n{}",
            disagreements.len(),
            cases.len(),
            disagreements
                .iter()
                .take(20)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    #[test]
    fn differential_corpus_confirms_the_denominator_is_the_ground_truth_count() {
        // The T-7 finding, restated over the corpus rather than over one
        // hand-built shape: in every one of these real-ground-truth cases the
        // three counts sum to the number of ground-truth variables, which is
        // exactly the claim that a spurious decompiled variable never enters
        // the denominator. Holds on all 10,272 generated cases too.
        for case in parse_corpus(DIFFERENTIAL_CORPUS) {
            let got = match_structured(&case.ground_truth, &case.decompiled, case.shift);
            assert_eq!(
                got.true_positives + got.false_positives + got.false_negatives,
                case.ground_truth.len() as u32,
                "{}",
                case.id
            );
        }
    }

    #[test]
    fn matching_is_independent_of_ground_truth_form_order() {
        // Matching is a set intersection, so `ground_truth_forms`' sort
        // (which exists for cache-key stability, not for matching) cannot
        // change a verdict. Reversing every form list must not move a single
        // count -- if it does, something is reading the list positionally.
        for case in parse_corpus(DIFFERENTIAL_CORPUS) {
            let reversed: Vec<GroundTruthVar> = case
                .ground_truth
                .iter()
                .map(|gv| {
                    let mut copy = gv.clone();
                    copy.types.reverse();
                    copy
                })
                .collect();
            assert_eq!(
                match_structured(&case.ground_truth, &case.decompiled, case.shift),
                match_structured(&reversed, &case.decompiled, case.shift),
                "{}",
                case.id
            );
        }
    }

    #[test]
    fn ground_truth_forms_unions_sorts_and_deduplicates() {
        // A typedef chain: DWARF names both spellings, and the stored list is
        // their union, sorted. Taken from a real row of
        // `43_base64-gcc-O0.so`, where `produced` is recorded as
        // `["__int32_t", "int"]`.
        let forms = ground_truth_forms(&["__int32_t", "int"]);
        assert_eq!(forms, vec!["__int32_t".to_string(), "int".to_string()]);
        // Sorted, not insertion-ordered.
        assert_eq!(
            ground_truth_forms(&["int", "__int32_t"]),
            vec!["__int32_t".to_string(), "int".to_string()]
        );
        // And deduplicated across spellings that normalize together.
        let unsigned = ground_truth_forms(&["__uint32_t", "unsigned int"]);
        assert_eq!(
            unsigned,
            vec![
                "__uint32_t".to_string(),
                "int".to_string(),
                "unsigned int".to_string()
            ]
        );
    }
}
