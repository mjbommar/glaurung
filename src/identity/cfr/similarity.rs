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
//! The TF-IDF corpus table is a later lane. The trait is defined now so the
//! call sites do not have to change when it lands, and
//! [`UniformWeights`] -- `idf(f) = 1` for every feature -- is what the
//! unweighted numbers in `docs/analysis/function-identity-cfr.md` were measured
//! under.

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::cfr::signature::{CfrSettings, CfrVersion};

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
            CfrVersion::current(CfrSettings { nosize: true }),
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
