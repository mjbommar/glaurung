//! The metric: BSim's merge-join cosine, and the distance it induces.
//!
//! # The kernel
//!
//! Each feature `f` gets a coefficient `c_f = idf(f) * (1 + log2(tf_f))`, and
//!
//! ```text
//! k(A, B) = sum over f in A and B of min(c_A(f), c_B(f))^2
//! ```
//!
//! which is BSim's formula verbatim. It is computed by walking two sorted lists
//! at once, in `O(n + m)`.
//!
//! # Why that is a metric and approximate graph edit distance is not
//!
//! `min(x, y)` is a positive semi-definite kernel on the non-negative reals
//! (it is Brownian motion's covariance), and the Schur product theorem says a
//! product of PSD kernels is PSD, so `min(x, y)^2` is PSD; a sum of PSD kernels
//! over features is PSD. Therefore
//!
//! ```text
//! d(A, B) = sqrt(k(A,A) + k(B,B) - 2 k(A,B))
//! ```
//!
//! is the distance induced by an inner product in some feature space, and
//! satisfies symmetry, non-negativity, the identity of indiscernibles *on the
//! quotient*, and the triangle inequality -- exactly, not approximately. It is a
//! pseudo-metric on functions and a metric on their CFR-feature classes, which
//! is precisely the object an index can be built over. Approximate graph edit
//! distance has none of these; exact GED is APX-hard.
//!
//! `d(A, B) = 0` therefore does **not** say the two functions are the same. It
//! says they have the same canonical form, which is the claim this module is
//! entitled to make.
//!
//! # Weights
//!
//! [`UniformWeights`] -- `idf(f) = 1` for every feature -- is the no-table
//! fallback, and it is what the *unweighted* numbers in
//! `docs/reference/function-identity-cfr.md` were measured under. The corpus
//! TF-IDF table that replaces it is [`super::weights::CorpusWeights`].
//!
//! # Confidence
//!
//! The cosine says "how alike". It does not say "is this a coincidence", and it
//! cannot: two four-feature functions that share three features score 0.75
//! whether those features are `mov`-shaped and in every function on earth or
//! unique to one library. [`significance`] is the second number, next to the
//! cosine exactly as BSim reports `sim` and `sig` together. See its
//! documentation for the null model, the formula, and what it does and does not
//! share with BSim's.

use super::signature::CfrSignature;

/// Inverse-document-frequency weighting over feature hashes.
///
/// A corpus table implements this as `log(N / df(f))`, quantised into a fixed
/// number of buckets the way BSim quantises the thousand commonest hashes into
/// 512 weights. Implementations must be pure and deterministic: a weight that
/// varies between calls varies the distance, and an index cannot survive that.
pub trait Weights {
    /// The weight of one feature. Must be finite and non-negative.
    fn idf(&self, feature: u32) -> f64;

    /// The largest weight this table can return, which is the weight of the
    /// rarest feature it can express.
    ///
    /// [`cosine`] never needs it -- a cosine is scale-invariant, so multiplying
    /// every weight by a constant leaves it untouched. [`significance`] does:
    /// BSim's penalty rates are quoted per occurrence in units where the rarest
    /// feature has coefficient 1, and BSim reaches those units by folding
    /// `sqrt(scale)` into every loaded weight. This is the same normalisation,
    /// asked of the table rather than baked into it.
    ///
    /// The default is `1.0`, which is exactly right for [`UniformWeights`] and
    /// which makes an unnormalised table's significance the unweighted one
    /// rather than a silently rescaled one.
    fn max_idf(&self) -> f64 {
        1.0
    }
}

/// Every feature weighted equally.
#[derive(Debug, Clone, Copy, Default)]
pub struct UniformWeights;

impl Weights for UniformWeights {
    fn idf(&self, _feature: u32) -> f64 {
        1.0
    }
}

/// The coefficient of one feature: its weight times its sublinear term
/// frequency.
///
/// `1 + log2(tf)` rather than `tf`, so a loop body repeated eight times counts
/// four rather than eight. BSim's term.
fn coefficient(weights: &dyn Weights, feature: u32, count: u16) -> f64 {
    let tf = f64::from(count.max(1));
    weights.idf(feature) * (1.0 + tf.log2())
}

fn weights_or_uniform(weights: Option<&dyn Weights>) -> &dyn Weights {
    const UNIFORM: UniformWeights = UniformWeights;
    weights.unwrap_or(&UNIFORM)
}

/// `k(A, B)`: the unnormalised kernel, by merge join over two sorted lists.
///
/// Returns `0.0` for signatures computed under incomparable versions rather
/// than a number that looks like a low similarity. A different mask list is not
/// a distant function; it is an unanswerable question.
pub fn kernel(a: &CfrSignature, b: &CfrSignature, weights: Option<&dyn Weights>) -> f64 {
    if !a.version.is_comparable_with(b.version) {
        return 0.0;
    }
    let weights = weights_or_uniform(weights);
    let mut total = 0.0;
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.features.len() && j < b.features.len() {
        let (left, left_count) = a.features[i];
        let (right, right_count) = b.features[j];
        match left.cmp(&right) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                let shared = coefficient(weights, left, left_count).min(coefficient(
                    weights,
                    right,
                    right_count,
                ));
                total += shared * shared;
                i += 1;
                j += 1;
            }
        }
    }
    total
}

/// `k(A, A)`: the squared norm.
pub fn self_kernel(a: &CfrSignature, weights: Option<&dyn Weights>) -> f64 {
    let weights = weights_or_uniform(weights);
    a.features
        .iter()
        .map(|(feature, count)| {
            let coefficient = coefficient(weights, *feature, *count);
            coefficient * coefficient
        })
        .sum()
}

/// The weighted cosine similarity in `[0, 1]`.
///
/// `0.0` when either signature is empty or the two are not comparable: an
/// empty vector has no direction, and BSim's own failure mode -- small
/// functions producing sparse vectors -- is best surfaced as "no answer"
/// rather than as a confident one.
pub fn cosine(a: &CfrSignature, b: &CfrSignature, weights: Option<&dyn Weights>) -> f64 {
    let numerator = kernel(a, b, weights);
    if numerator == 0.0 {
        return 0.0;
    }
    let norm = (self_kernel(a, weights) * self_kernel(b, weights)).sqrt();
    if norm <= 0.0 {
        return 0.0;
    }
    (numerator / norm).clamp(0.0, 1.0)
}

/// The distance induced by [`kernel`]: `sqrt(k(a,a) + k(b,b) - 2 k(a,b))`.
///
/// Clamped at zero before the square root. The kernel is PSD, so the quantity
/// is non-negative in exact arithmetic; the clamp is against the last bit of a
/// floating-point subtraction of two nearly equal sums, not against a modelling
/// error.
pub fn distance(a: &CfrSignature, b: &CfrSignature, weights: Option<&dyn Weights>) -> f64 {
    let squared = self_kernel(a, weights) + self_kernel(b, weights) - 2.0 * kernel(a, b, weights);
    squared.max(0.0).sqrt()
}

// ---------------------------------------------------------------------------
// Confidence: BSim's log-likelihood-ratio significance
// ---------------------------------------------------------------------------

/// BSim's causal-model coefficients, read out of Ghidra's shipped
/// `Ghidra/Features/BSim/data/lshweights_64.xml` and divided through by that
/// file's `scale`, so they apply to a coefficient normalised to
/// "one rarest feature = 1".
///
/// The generative model is stated in Ghidra's own `VectorCompare` doc comment:
/// *"Assume small vector is produced by flipping and removing hashes from big
/// vector."* Two penalties fall out of it, and both are per-occurrence rates
/// with a constant part and a part that decays as the larger vector grows:
///
/// * **flip** -- an occurrence the smaller vector has that the larger does not:
///   the same computation spelled differently. `numflip` of them.
/// * **diff** -- the size gap itself: the larger function does more. `diff` of
///   them.
///
/// The five numbers were fitted by the National Security Agency to *their*
/// p-code features over *their* corpus. They are used here unchanged because a
/// refit needs a labelled corpus of the size BSim was fitted on, and because
/// using them unchanged is what puts the output on the scale
/// [`BSIM_CALIBRATION`] describes. That they are borrowed rather than measured
/// is the single largest caveat on any confidence number this module produces,
/// and `docs/reference/function-identity-cfr.md` says so where the numbers are
/// reported.
mod bsim {
    /// `WeightFactory.scale` in `lshweights_64.xml`. Not used directly: it is
    /// the divisor that turns the file's `probflip*`/`probdiff*`/`addend` into
    /// the normalised constants below, and it is recorded so the derivation can
    /// be checked. (BSim folds `sqrt(scale)` into every loaded weight and
    /// `scale` into every penalty rate, so a coefficient normalised to
    /// "rarest feature = 1" needs the penalties divided by `scale`.)
    pub const SCALE: f64 = 1.512_759_76;
    /// `WeightFactory.probflip0`, normalised.
    pub const FLIP0: f64 = 0.202_671_876;
    /// `WeightFactory.probflip1`, normalised: the part that decays with size.
    pub const FLIP1: f64 = 0.540_692_533;
    /// `WeightFactory.probdiff0`, normalised.
    pub const DIFF0: f64 = 0.051_970_135_6;
    /// `WeightFactory.probdiff1`, normalised: the part that decays with size.
    pub const DIFF1: f64 = 0.852_635_318;
    /// `WeightFactory.addend / WeightFactory.scale`.
    ///
    /// The file stores `addend = 6.255_976_01` in scaled units; every other
    /// term here is normalised, so it is divided through once, here, rather
    /// than at every call site.
    pub const ADDEND: f64 = 6.255_976_01 / SCALE;
}

/// Ghidra's published correspondence between a confidence score and a
/// false-positive rate, from `help/topics/BSim/FeatureWeight.html`.
///
/// `(confidence, one-in-N)`. The help page is explicit that it holds "for
/// scores of 10.0 and greater", that the rate drops by a factor of two every
/// four to five points, and that small wrapper functions skew the low end --
/// which is why [`false_positive_one_in`] answers `None` below 10 rather than
/// extrapolating into the region the source itself calls unreliable.
pub const BSIM_CALIBRATION: [(f64, f64); 4] = [
    (10.0, 4_000.0),
    (26.0, 100_000.0),
    (43.0, 1_000_000.0),
    (93.0, 1_000_000_000.0),
];

/// Confidence at or above which a match is reported as significant.
///
/// BSim's middle published anchor: about one false positive in 100,000. It is a
/// *reporting* threshold and not a floor anything enforces -- BSim's own query
/// paths gate on the self-significance pre-filter instead, which is
/// [`self_significance`] here.
pub const CONFIDENT_SIGNIFICANCE: f64 = 26.0;

/// The two numbers a match is reported as, which is how BSim reports one:
/// `sim` says how alike, `sig` says whether it is a coincidence.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MatchConfidence {
    /// Weighted cosine in `[0, 1]` -- [`cosine`].
    pub cosine: f64,
    /// BSim's significance, which Ghidra's UI calls **Confidence** --
    /// [`significance`]. Open-ended, and negative for a poor match, exactly as
    /// BSim's is.
    pub significance: f64,
    /// `min(self_significance(a), self_significance(b))`: the largest
    /// significance these two signatures could possibly produce.
    pub self_significance: f64,
}

impl MatchConfidence {
    /// The false-positive rate as "one in N", interpolated log-linearly between
    /// the [`BSIM_CALIBRATION`] anchors. `None` below the lowest anchor.
    pub fn false_positive_one_in(&self) -> Option<f64> {
        false_positive_one_in(self.significance)
    }

    /// Whether the match clears [`CONFIDENT_SIGNIFICANCE`].
    pub fn is_confident(&self) -> bool {
        self.significance >= CONFIDENT_SIGNIFICANCE
    }

    /// What fraction of the available significance this match used, in
    /// `[0, 1]`, or `0.0` when there was none available.
    ///
    /// A three-block function can reach `1.0` here -- a perfect match on
    /// everything it has -- while its [`MatchConfidence::significance`] stays
    /// far below [`CONFIDENT_SIGNIFICANCE`]. That is exactly the property
    /// Ghidra's help page names: "Self significance is roughly proportional to
    /// the size of the function. So its impossible to achieve a high confidence
    /// for a small function".
    pub fn saturation(&self) -> f64 {
        if self.self_significance <= 0.0 {
            0.0
        } else {
            (self.significance / self.self_significance).clamp(0.0, 1.0)
        }
    }
}

/// The false-positive rate of a significance score, as "one in N", by
/// log-linear interpolation between the [`BSIM_CALIBRATION`] anchors.
///
/// Below the lowest anchor Ghidra's help page says the correspondence does not
/// hold -- "A general correspondence between low confidence scores and false
/// positive rates can be somewhat skewed by wrappers and other small
/// functions" -- so this answers "no rate" rather than extrapolating one.
/// Above the top anchor the last segment's slope is extended, which is the
/// halving-every-four-to-five-points the same page describes.
pub fn false_positive_one_in(significance: f64) -> Option<f64> {
    let (first_score, first_rate) = BSIM_CALIBRATION[0];
    if !(significance >= first_score) {
        // Written as a negated `>=` so a NaN significance answers `None` too.
        return None;
    }
    let mut lower = (first_score, first_rate);
    for &(score, rate) in &BSIM_CALIBRATION[1..] {
        if significance <= score {
            let position = (significance - lower.0) / (score - lower.0);
            return Some((lower.1.ln() + position * (rate.ln() - lower.1.ln())).exp());
        }
        lower = (score, rate);
    }
    let (before_score, before_rate) = BSIM_CALIBRATION[BSIM_CALIBRATION.len() - 2];
    let (last_score, last_rate) = BSIM_CALIBRATION[BSIM_CALIBRATION.len() - 1];
    let slope = (last_rate.ln() - before_rate.ln()) / (last_score - before_score);
    Some((last_rate.ln() + slope * (significance - last_score)).exp())
}

/// The scale a weight table's rarest feature sits at, used to normalise a
/// coefficient so that "one rarest feature" weighs 1 -- the units BSim's
/// penalty rates are quoted in.
///
/// Never zero or non-finite: a degenerate table falls back to 1.0, which makes
/// the significance the unweighted one rather than an infinity.
fn significance_unit(weights: &dyn Weights) -> f64 {
    let max = weights.max_idf();
    if max.is_finite() && max > 0.0 {
        max
    } else {
        1.0
    }
}

/// Total feature occurrences two signatures share: BSim's
/// `VectorCompare.intersectcount`, `sum over shared f of min(tf_A, tf_B)`.
fn intersect_count(a: &CfrSignature, b: &CfrSignature) -> u64 {
    let mut total = 0u64;
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.features.len() && j < b.features.len() {
        let (left, left_count) = a.features[i];
        let (right, right_count) = b.features[j];
        match left.cmp(&right) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                total += u64::from(left_count.min(right_count));
                i += 1;
                j += 1;
            }
        }
    }
    total
}

/// A signature's self-significance: the largest confidence any match to it can
/// reach.
///
/// BSim's `LSHVectorFactory.getSelfSignificance`, which is
/// `vector.getLength()^2 + addend` -- exactly [`significance`] specialised to
/// comparing a vector with itself, where the intersection is everything so both
/// penalties vanish. Ghidra's query paths use it as a pre-filter and skip any
/// stored vector whose self-significance is already below the caller's
/// threshold, because such a vector *cannot* produce a passing match:
///
/// ```text
/// // Self significance should be bigger than the significance threshold
/// // (or its impossible our result can exceed the threshold)
/// if (len2 < query.signifthresh) { continue; }
/// ```
///
/// It grows with the function, which is the whole mechanism by which a small
/// function cannot reach a confident match.
pub fn self_significance(a: &CfrSignature, weights: Option<&dyn Weights>) -> f64 {
    let weights = weights_or_uniform(weights);
    let unit = significance_unit(weights);
    let squared: f64 = a
        .features
        .iter()
        .map(|(feature, count)| {
            let coefficient = coefficient(weights, *feature, *count) / unit;
            coefficient * coefficient
        })
        .sum();
    squared + bsim::ADDEND
}

/// BSim's log-likelihood-ratio significance, the number Ghidra's UI calls
/// **Confidence**.
///
/// # The formula
///
/// This is `LSHVectorFactory.calculateSignificance` (Ghidra,
/// `Ghidra/Framework/Generic/src/main/java/generic/lsh/vector/`), whose C twin
/// is `lsh_compare_internal` in `Ghidra/Features/BSim/src/lshvector/c/weights.c`:
///
/// ```text
/// sig = dotproduct
///     - numflip * (probflip0 + probflip1 / max)
///     - diff    * (probdiff0 + probdiff1 / max)
///     + addend
/// ```
///
/// with, from `VectorCompare.fillOut()`:
///
/// ```text
/// acount, bcount   total feature occurrences (WITH multiplicity) on each side
/// min, max         min and max of those two
/// intersectcount   sum over shared features of min(tf_A, tf_B)
/// numflip          min - intersectcount
/// diff             max - min
/// ```
///
/// The model behind the two penalties is stated in Ghidra's own doc comment:
/// *"Assume small vector is produced by flipping and removing hashes from big
/// vector."* `numflip` counts occurrences the smaller function has that the
/// larger does not -- the same computation spelled differently -- and `diff`
/// counts the extra work the larger function does. Both are charged at a rate
/// with a constant part and a part that decays as `max` grows, because a longer
/// function has more chances to differ by accident.
///
/// **`acount` and `bcount` are occurrences with multiplicity**, not distinct
/// features: BSim's `hashcount` is the sum of the term frequencies, not
/// `numEntries()`. Getting that wrong changes `max`, `numflip` and `diff` at
/// once, so [`CfrSignature::total_count`] is what feeds them here.
///
/// # What is BSim's here, and what is ours
///
/// **BSim's, verbatim:** the shape of the formula, the definitions of
/// `numflip`/`diff`/`max`, the five fitted constants in [`bsim`], the
/// self-significance bound, and therefore the calibration in
/// [`BSIM_CALIBRATION`].
///
/// **Ours:** the features being counted, and the coefficient. BSim's is
/// `idfweight[bucket] * sqrt(1 + log2(tf))`, with `idfweight[0] = 1` for any
/// feature outside its thousand-entry lookup table; this module's is
/// `idf(f) * (1 + log2(tf))` from [`super::weights`], divided here by
/// [`Weights::max_idf`] so that the rarest feature the table can express again
/// has coefficient 1 -- the normalisation BSim performs by folding
/// `sqrt(scale)` into its loaded weights. The two agree exactly at `tf = 1`,
/// which is the overwhelming majority of features, and diverge for repeated
/// ones: BSim's `coeff^2` is linear in `1 + log2(tf)` where this module's is
/// quadratic. That difference is inherited from the kernel in [`cosine`], which
/// was measured and published before this function existed and which changing
/// would move every number in `docs/reference/function-identity-cfr.md`.
///
/// **The consequence, stated plainly:** the five constants were fitted to a
/// feature distribution that is not this one. The score is on BSim's scale by
/// construction and on BSim's calibration only by assumption. Read
/// [`BSIM_CALIBRATION`] as an order of magnitude for this representation, not
/// as a measured false-positive rate for it.
///
/// # Bounded by self-significance, as a theorem
///
/// `min(cA, cB)^2 <= cA^2` and `<= cB^2` termwise, and both penalties are
/// non-negative, so
///
/// ```text
/// significance(A, B) <= min(self_significance(A), self_significance(B))
/// ```
///
/// with no clamp anywhere. A four-feature function cannot produce more evidence
/// than four features carry, however well it matches.
/// `significance_is_bounded_by_self_significance` asserts it on constructed
/// vectors and the retrieval harness asserts it over the corpus.
///
/// # Incomparable versions
///
/// Returns [`f64::NEG_INFINITY`], which is "no answer" in the same way
/// [`cosine`] returns `0.0`. A finite negative number would read as a bad match
/// rather than as an unanswerable question, and `addend` alone would read as a
/// mediocre one.
pub fn significance(a: &CfrSignature, b: &CfrSignature, weights: Option<&dyn Weights>) -> f64 {
    if !a.version.is_comparable_with(b.version) {
        return f64::NEG_INFINITY;
    }
    let weights = weights_or_uniform(weights);
    let unit = significance_unit(weights);

    let mut dot = 0.0;
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.features.len() && j < b.features.len() {
        let (left, left_count) = a.features[i];
        let (right, right_count) = b.features[j];
        match left.cmp(&right) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                let shared = (coefficient(weights, left, left_count) / unit)
                    .min(coefficient(weights, right, right_count) / unit);
                dot += shared * shared;
                i += 1;
                j += 1;
            }
        }
    }

    let acount = a.total_count();
    let bcount = b.total_count();
    let (low, high) = (acount.min(bcount), acount.max(bcount));
    let numflip = low.saturating_sub(intersect_count(a, b)) as f64;
    let difference = (high - low) as f64;
    // `max` is a divisor in both penalty rates. An empty pair reaches here with
    // `high == 0`, where both counts are zero anyway, so the decaying part is
    // simply dropped rather than divided by nothing.
    let decay = if high == 0 { 0.0 } else { 1.0 / high as f64 };

    dot - numflip * (bsim::FLIP0 + bsim::FLIP1 * decay)
        - difference * (bsim::DIFF0 + bsim::DIFF1 * decay)
        + bsim::ADDEND
}

/// [`cosine`] and [`significance`] together, which is how a match should be
/// reported: BSim returns both from one comparison and neither answers the
/// question alone.
pub fn confidence(
    a: &CfrSignature,
    b: &CfrSignature,
    weights: Option<&dyn Weights>,
) -> MatchConfidence {
    MatchConfidence {
        cosine: cosine(a, b, weights),
        significance: significance(a, b, weights),
        self_significance: self_significance(a, weights).min(self_significance(b, weights)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::cfr::signature::{CfrSettings, CfrVersion};
    use crate::identity::cfr::weights::{CorpusWeights, WeightsBuilder};

    fn signature(raw: &[u32]) -> CfrSignature {
        CfrSignature::from_features(CfrVersion::current(CfrSettings::default()), raw)
    }

    #[test]
    fn a_signature_is_its_own_nearest_neighbour() {
        let a = signature(&[1, 2, 2, 3]);
        assert!((cosine(&a, &a, None) - 1.0).abs() < 1e-12);
        assert!(distance(&a, &a, None) < 1e-9);
    }

    #[test]
    fn disjoint_signatures_score_zero_and_sit_at_the_norm_distance() {
        let a = signature(&[1, 2]);
        let b = signature(&[3, 4]);
        assert_eq!(cosine(&a, &b, None), 0.0);
        let expected = (self_kernel(&a, None) + self_kernel(&b, None)).sqrt();
        assert!((distance(&a, &b, None) - expected).abs() < 1e-12);
    }

    #[test]
    fn the_distance_is_symmetric() {
        let a = signature(&[1, 2, 2, 5]);
        let b = signature(&[2, 3, 5, 5, 5]);
        assert!((distance(&a, &b, None) - distance(&b, &a, None)).abs() < 1e-12);
    }

    #[test]
    fn incomparable_versions_answer_zero_rather_than_a_low_score() {
        let plain = signature(&[1, 2, 3]);
        let nosize = CfrSignature::from_features(
            CfrVersion::current(CfrSettings {
                nosize: true,
                ..CfrSettings::default()
            }),
            &[1, 2, 3],
        );
        assert_eq!(cosine(&plain, &nosize, None), 0.0);
    }

    /// The property the whole design exists for, on hand-built vectors.
    #[test]
    fn the_triangle_inequality_holds_on_constructed_vectors() {
        let vectors = [
            signature(&[1, 2, 3]),
            signature(&[2, 3, 4, 4]),
            signature(&[4, 5]),
            signature(&[1, 1, 1, 5, 6]),
            signature(&[]),
        ];
        for a in &vectors {
            for b in &vectors {
                for c in &vectors {
                    let direct = distance(a, c, None);
                    let detour = distance(a, b, None) + distance(b, c, None);
                    assert!(
                        direct <= detour + 1e-9,
                        "d(a,c)={direct} > d(a,b)+d(b,c)={detour}"
                    );
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // Confidence
    // -----------------------------------------------------------------

    fn corpus_weights(corpus: &[&[u32]]) -> CorpusWeights {
        let version = CfrVersion::current(CfrSettings::default());
        let signatures: Vec<CfrSignature> = corpus
            .iter()
            .map(|raw| CfrSignature::from_features(version, raw))
            .collect();
        let mut builder = WeightsBuilder::new(version);
        builder.observe_all(&signatures);
        builder.build(1)
    }

    /// The bound is a consequence of `min(cA, cB)^2 <= cA^2` and non-negative
    /// penalties, so it must hold on every pair without anyone clamping.
    #[test]
    fn significance_is_bounded_by_self_significance() {
        let weights = corpus_weights(&[&[1, 2, 3], &[1, 4], &[1, 2, 5, 6], &[7], &[1, 3, 8]]);
        let vectors = [
            signature(&[1, 2, 3]),
            signature(&[1, 2, 3, 5, 6, 7, 8]),
            signature(&[7]),
            signature(&[]),
            signature(&[2, 2, 2, 3]),
        ];
        for a in &vectors {
            for b in &vectors {
                let confidence = confidence(a, b, Some(&weights));
                assert!(
                    confidence.significance <= confidence.self_significance + 1e-9,
                    "{} > {}",
                    confidence.significance,
                    confidence.self_significance
                );
                assert!((0.0..=1.0).contains(&confidence.saturation()));
                // Unweighted must obey the same bound.
                let uniform = super::confidence(a, b, None);
                assert!(uniform.significance <= uniform.self_significance + 1e-9);
            }
        }
    }

    /// Self-significance is `length^2 + addend`, which is `significance(a, a)`
    /// with both penalties vanishing. Ghidra relies on that identity directly
    /// (`ExecutableScorerSingle` substitutes one for the other), so it is worth
    /// pinning rather than assuming.
    #[test]
    fn a_self_comparison_reaches_exactly_the_self_significance() {
        let weights = corpus_weights(&[&[1, 2], &[1, 3], &[2, 3, 4], &[5, 6]]);
        for raw in [&[1u32, 2, 2, 4][..], &[5, 6][..], &[1][..]] {
            let a = signature(raw);
            let confidence = confidence(&a, &a, Some(&weights));
            assert!(
                (confidence.significance - confidence.self_significance).abs() < 1e-9,
                "{:?}: {} != {}",
                raw,
                confidence.significance,
                confidence.self_significance
            );
            assert!((confidence.saturation() - 1.0).abs() < 1e-9);
        }
    }

    /// The property the confidence number exists for, and the one Ghidra's help
    /// page states: a tiny function that matches *perfectly* still must not
    /// read as confident, while a large one matching equally well does.
    #[test]
    fn a_small_function_cannot_reach_a_confident_match_however_well_it_matches() {
        // 400 documents in which features 1 and 2 are rare enough to sit at the
        // top of the weight range.
        let mut corpus: Vec<Vec<u32>> = vec![vec![1, 2]];
        for filler in 0..400u32 {
            corpus.push(vec![1000 + filler]);
        }
        let borrowed: Vec<&[u32]> = corpus.iter().map(|v| v.as_slice()).collect();
        let weights = corpus_weights(&borrowed);

        let small = signature(&[1, 2]);
        let perfect = confidence(&small, &small, Some(&weights));
        assert!(
            (perfect.cosine - 1.0).abs() < 1e-12,
            "a self-match is a perfect cosine"
        );
        assert!(
            (perfect.saturation() - 1.0).abs() < 1e-9,
            "and it saturates its own evidence"
        );
        assert!(
            !perfect.is_confident(),
            "two features must not reach {CONFIDENT_SIGNIFICANCE}: got {}",
            perfect.significance
        );
        assert!(
            perfect.false_positive_one_in().is_none(),
            "and below the lowest published anchor there is no rate to quote"
        );

        // The same corpus and the same perfect match, on a function with enough
        // rare features to clear the threshold. Only the size changed.
        let large_features: Vec<u32> = (0..40u32).map(|i| 5000 + i).collect();
        let large = signature(&large_features);
        let large_match = confidence(&large, &large, Some(&weights));
        assert!(
            large_match.is_confident(),
            "forty rare features should clear {CONFIDENT_SIGNIFICANCE}: got {}",
            large_match.significance
        );
        let rate = large_match
            .false_positive_one_in()
            .expect("a confident match has a quotable rate");
        assert!(rate >= 100_000.0, "one in {rate}");
    }

    /// BSim's penalties are what make a partial match cost something. Two
    /// functions of the same size sharing half their features must score below
    /// two that share all of them, and a size mismatch must cost on top.
    #[test]
    fn the_flip_and_diff_penalties_both_bite() {
        let corpus: Vec<Vec<u32>> = (0..200u32).map(|i| vec![i]).collect();
        let borrowed: Vec<&[u32]> = corpus.iter().map(|v| v.as_slice()).collect();
        let weights = corpus_weights(&borrowed);

        let base: Vec<u32> = (0..20u32).collect();
        let a = signature(&base);
        let identical = signature(&base);
        // Same size, half the features replaced: pure `numflip`, no `diff`.
        let flipped: Vec<u32> = (0..10u32).chain(100..110u32).collect();
        let flipped = signature(&flipped);
        // A strict subset: no flips at all, pure `diff`.
        let shorter = signature(&base[..10]);

        let full = significance(&a, &identical, Some(&weights));
        let flip = significance(&a, &flipped, Some(&weights));
        let diff = significance(&a, &shorter, Some(&weights));
        assert!(flip < full, "flipping must cost: {flip} !< {full}");
        assert!(diff < full, "a size gap must cost: {diff} !< {full}");
    }

    #[test]
    fn the_published_calibration_interpolates_and_refuses_to_extrapolate_downward() {
        for (score, one_in) in BSIM_CALIBRATION {
            let got = false_positive_one_in(score).expect("an anchor has a rate");
            assert!((got - one_in).abs() / one_in < 1e-9, "{score} -> {got}");
        }
        // Between two anchors, monotone and bracketed.
        let middle = false_positive_one_in(35.0).expect("between anchors");
        assert!(middle > 100_000.0 && middle < 1_000_000.0, "{middle}");
        // Past the top anchor the last slope continues.
        assert!(false_positive_one_in(120.0).expect("above the top") > 1e9);
        // Below the lowest anchor Ghidra's page says the correspondence does
        // not hold, so there is no number to give.
        assert!(false_positive_one_in(9.99).is_none());
        assert!(false_positive_one_in(f64::NAN).is_none());
        // ...and the halving rate the help page quotes falls out of the table.
        let at_43 = false_positive_one_in(43.0).expect("anchor");
        let at_47_5 = false_positive_one_in(47.5).expect("anchor + 4.5");
        assert!(
            (at_47_5 / at_43 - 2.0).abs() < 0.15,
            "should roughly double every 4.5 points: {}",
            at_47_5 / at_43
        );
    }

    #[test]
    fn incomparable_versions_answer_no_significance_at_all() {
        let plain = signature(&[1, 2, 3]);
        let nosize = CfrSignature::from_features(
            CfrVersion::current(CfrSettings {
                nosize: true,
                ..Default::default()
            }),
            &[1, 2, 3],
        );
        assert_eq!(significance(&plain, &nosize, None), f64::NEG_INFINITY);
        assert!(!confidence(&plain, &nosize, None).is_confident());
        assert!(confidence(&plain, &nosize, None)
            .false_positive_one_in()
            .is_none());
    }

    #[test]
    fn significance_is_symmetric() {
        let weights = corpus_weights(&[&[1, 2], &[2, 3], &[3, 4, 5], &[1, 5]]);
        let a = signature(&[1, 2, 3, 3]);
        let b = signature(&[2, 3, 5]);
        assert!(
            (significance(&a, &b, Some(&weights)) - significance(&b, &a, Some(&weights))).abs()
                < 1e-12
        );
    }

    /// `acount`/`bcount` are occurrences WITH multiplicity, not distinct
    /// features -- BSim's `hashcount` sums the term frequencies. Getting it
    /// wrong changes `max`, `numflip` and `diff` at once, and the error is
    /// invisible on any corpus where every feature occurs once.
    #[test]
    fn the_penalty_counts_use_occurrences_and_not_distinct_features() {
        let weights = corpus_weights(&[&[1, 2], &[2, 3], &[3, 4]]);
        // Same distinct features, different multiplicities.
        let once = signature(&[1, 2]);
        let many = signature(&[1, 1, 1, 1, 2, 2]);
        assert_eq!(once.features.len(), many.features.len());
        assert_ne!(once.total_count(), many.total_count());
        // A `diff` penalty must appear even though no feature differs.
        assert!(
            significance(&once, &many, Some(&weights)) < significance(&once, &once, Some(&weights)),
            "a multiplicity gap is a size gap"
        );
    }

    #[test]
    fn a_weight_table_changes_the_score_it_is_asked_about() {
        struct RareOnly;
        impl Weights for RareOnly {
            fn idf(&self, feature: u32) -> f64 {
                if feature == 2 {
                    10.0
                } else {
                    0.1
                }
            }
        }
        let a = signature(&[1, 2]);
        let b = signature(&[2, 3]);
        let uniform = cosine(&a, &b, None);
        let weighted = cosine(&a, &b, Some(&RareOnly));
        assert!(weighted > uniform, "{weighted} !> {uniform}");
    }
}
