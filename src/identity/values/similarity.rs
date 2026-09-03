//! The metric: weighted Jaccard over two value multisets.
//!
//! # The formula
//!
//! vSim compares fingerprints with
//!
//! ```text
//! J_w(A, B) = sum over v in A and B of W(v)
//!             ------------------------------
//!             sum over v in A or  B of W(v)
//! ```
//!
//! over *sets* of values, weighting each by its distinguishability
//! `W(v) = 1 / ln(Occ(v) + 1)`. [`weighted_jaccard_set`] is that expression
//! verbatim. [`weighted_jaccard`] is its standard multiset generalisation,
//!
//! ```text
//! J_w(A, B) = sum_v W(v) * min(c_A(v), c_B(v)) / sum_v W(v) * max(c_A(v), c_B(v))
//! ```
//!
//! which reduces to the set form exactly when every count is capped at one.
//! Both are here because which one is right is a measurement, not an argument:
//! the counts carry real information (a function that stores `0` eleven times
//! is not the function that stores it once) and they also carry real noise (an
//! unrolled loop stores it eleven times because the optimiser said so).
//!
//! # Why this is a metric and cosine over the same sets would not be
//!
//! `1 - J_w` is a metric on the weighted multisets for any non-negative weight
//! function: the weighted Jaccard distance is the Ruzicka distance, and its
//! triangle inequality is a theorem (it is the `L1`-normalised form of the
//! min-max kernel, which is positive semi-definite; Ioffe, ICDM 2010, uses
//! exactly that fact to build consistent weighted sampling). So it can index a
//! corpus, and `distance` below is a genuine pseudo-metric on functions --
//! `d(a, b) = 0` says the two have the same fingerprint, not that they are the
//! same function.
//!
//! # Weights
//!
//! [`UniformWeights`] -- `W(v) = 1` -- is the floor every unweighted number in
//! `docs/reference/function-identity-values.md` was measured under. A corpus
//! document-frequency table implements [`Weights`] with vSim's
//! `1 / ln(Occ(v) + 1)`; the harness builds one per slice
//! (`tests/identity_retrieval/scheme.rs`), which is where a corpus exists.

use super::fingerprint::ValueFingerprint;

/// Distinguishability weighting over fingerprint elements.
///
/// Implementations must be pure and deterministic: a weight that varies
/// between calls varies the distance, and an index cannot survive that.
pub trait Weights {
    /// The weight of one element. Must be finite and non-negative.
    fn weight(&self, element: u64) -> f64;
}

/// Every element weighted equally.
#[derive(Debug, Clone, Copy, Default)]
pub struct UniformWeights;

impl Weights for UniformWeights {
    fn weight(&self, _element: u64) -> f64 {
        1.0
    }
}

/// vSim's distinguishability weight, `W(v) = 1 / ln(Occ(v) + 1)`, over a
/// document-frequency table.
///
/// `Occ(v)` is how many functions in the corpus carry `v`. The `+ 1` avoids a
/// division by zero for an element seen once and the logarithm keeps the
/// penalty on a common element gentle -- vSim's stated reasoning, kept because
/// the alternative (`log(N / df)`, BSim's and the CFR's IDF) is a different
/// weighting whose behaviour on this representation has not been measured.
#[derive(Debug, Clone, Default)]
pub struct OccurrenceWeights {
    occurrences: std::collections::HashMap<u64, u32>,
}

impl OccurrenceWeights {
    /// Build a table by counting, for each element, how many fingerprints
    /// carry it. An element absent from the table is treated as seen once.
    pub fn from_fingerprints<'a>(corpus: impl IntoIterator<Item = &'a ValueFingerprint>) -> Self {
        let mut occurrences: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
        for fingerprint in corpus {
            for (element, _) in &fingerprint.values {
                *occurrences.entry(*element).or_insert(0) += 1;
            }
        }
        OccurrenceWeights { occurrences }
    }

    /// How many fingerprints the table was built from an element in.
    pub fn occurrences(&self, element: u64) -> u32 {
        self.occurrences.get(&element).copied().unwrap_or(1).max(1)
    }

    /// Distinct elements in the table.
    pub fn len(&self) -> usize {
        self.occurrences.len()
    }

    /// Whether the table is empty (no corpus was supplied).
    pub fn is_empty(&self) -> bool {
        self.occurrences.is_empty()
    }
}

impl Weights for OccurrenceWeights {
    fn weight(&self, element: u64) -> f64 {
        1.0 / f64::from(self.occurrences(element) + 1).ln()
    }
}

fn weights_or_uniform(weights: Option<&dyn Weights>) -> &dyn Weights {
    const UNIFORM: UniformWeights = UniformWeights;
    weights.unwrap_or(&UNIFORM)
}

/// Walk two sorted element lists at once, calling `visit(element, count_a,
/// count_b)` for every element in either.
fn merge<F: FnMut(u64, u32, u32)>(a: &ValueFingerprint, b: &ValueFingerprint, mut visit: F) {
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.values.len() && j < b.values.len() {
        let (left, left_count) = a.values[i];
        let (right, right_count) = b.values[j];
        match left.cmp(&right) {
            std::cmp::Ordering::Less => {
                visit(left, left_count, 0);
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                visit(right, 0, right_count);
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                visit(left, left_count, right_count);
                i += 1;
                j += 1;
            }
        }
    }
    for &(element, count) in &a.values[i..] {
        visit(element, count, 0);
    }
    for &(element, count) in &b.values[j..] {
        visit(element, 0, count);
    }
}

fn jaccard(
    a: &ValueFingerprint,
    b: &ValueFingerprint,
    weights: Option<&dyn Weights>,
    cap_counts: bool,
) -> f64 {
    // Incomparable versions answer 0.0 rather than a number that looks like a
    // low similarity: a different filter set is not a distant function, it is
    // an unanswerable question.
    if !a.version.is_comparable_with(b.version) {
        return 0.0;
    }
    let weights = weights_or_uniform(weights);
    let mut numerator = 0.0f64;
    let mut denominator = 0.0f64;
    merge(a, b, |element, count_a, count_b| {
        let (count_a, count_b) = if cap_counts {
            (u32::from(count_a > 0), u32::from(count_b > 0))
        } else {
            (count_a, count_b)
        };
        let weight = weights.weight(element);
        numerator += weight * f64::from(count_a.min(count_b));
        denominator += weight * f64::from(count_a.max(count_b));
    });
    if denominator <= 0.0 {
        return 0.0;
    }
    (numerator / denominator).clamp(0.0, 1.0)
}

/// Weighted Jaccard over the two multisets, counts included.
pub fn weighted_jaccard(
    a: &ValueFingerprint,
    b: &ValueFingerprint,
    weights: Option<&dyn Weights>,
) -> f64 {
    jaccard(a, b, weights, false)
}

/// vSim's Equation 2 verbatim: weighted Jaccard over the two element *sets*.
pub fn weighted_jaccard_set(
    a: &ValueFingerprint,
    b: &ValueFingerprint,
    weights: Option<&dyn Weights>,
) -> f64 {
    jaccard(a, b, weights, true)
}

/// The metric distance `1 - J_w`, over the multiset form.
pub fn distance(a: &ValueFingerprint, b: &ValueFingerprint, weights: Option<&dyn Weights>) -> f64 {
    1.0 - weighted_jaccard(a, b, weights)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::values::settings::{ValueSettings, ValueVersion};

    fn fingerprint(raw: &[u64]) -> ValueFingerprint {
        ValueFingerprint::from_elements(ValueVersion::current(ValueSettings::default()), raw)
    }

    #[test]
    fn a_fingerprint_is_its_own_nearest_neighbour() {
        let a = fingerprint(&[1, 2, 2, 3]);
        assert!((weighted_jaccard(&a, &a, None) - 1.0).abs() < 1e-12);
        assert!((weighted_jaccard_set(&a, &a, None) - 1.0).abs() < 1e-12);
        assert!(distance(&a, &a, None) < 1e-12);
    }

    #[test]
    fn disjoint_fingerprints_score_zero() {
        let a = fingerprint(&[1, 2]);
        let b = fingerprint(&[3, 4]);
        assert_eq!(weighted_jaccard(&a, &b, None), 0.0);
        assert_eq!(weighted_jaccard_set(&a, &b, None), 0.0);
    }

    #[test]
    fn the_set_form_is_the_multiset_form_with_the_counts_flattened() {
        let a = fingerprint(&[1, 1, 1, 2]);
        let b = fingerprint(&[1, 2, 2, 2]);
        // Sets: {1,2} vs {1,2}, so 1.0. Multiset: min 1+1 over max 3+3.
        assert!((weighted_jaccard_set(&a, &b, None) - 1.0).abs() < 1e-12);
        assert!((weighted_jaccard(&a, &b, None) - (2.0 / 6.0)).abs() < 1e-12);
    }

    #[test]
    fn similarity_is_symmetric_and_in_range() {
        let vectors = [
            fingerprint(&[1, 2, 3]),
            fingerprint(&[2, 3, 4, 4]),
            fingerprint(&[]),
            fingerprint(&[9]),
        ];
        for a in &vectors {
            for b in &vectors {
                let forward = weighted_jaccard(a, b, None);
                let backward = weighted_jaccard(b, a, None);
                assert!((forward - backward).abs() < 1e-12);
                assert!((0.0..=1.0).contains(&forward));
            }
        }
    }

    /// The property the choice of metric exists for.
    #[test]
    fn the_triangle_inequality_holds_on_constructed_multisets() {
        let vectors = [
            fingerprint(&[1, 2, 3]),
            fingerprint(&[2, 3, 4, 4]),
            fingerprint(&[4, 5]),
            fingerprint(&[1, 1, 1, 5, 6]),
            fingerprint(&[]),
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
    fn incomparable_versions_answer_zero_rather_than_a_low_score() {
        let plain = fingerprint(&[1, 2, 3]);
        let unfiltered = ValueFingerprint::from_elements(
            ValueVersion::current(ValueSettings {
                filter: false,
                ..ValueSettings::default()
            }),
            &[1, 2, 3],
        );
        assert_eq!(weighted_jaccard(&plain, &unfiltered, None), 0.0);
    }

    #[test]
    fn a_common_element_is_worth_less_than_a_rare_one() {
        let corpus: Vec<ValueFingerprint> = (0..20).map(|_| fingerprint(&[0])).collect();
        let mut with_rare = corpus.clone();
        with_rare.push(fingerprint(&[0, 0xdead_beef]));
        let weights = OccurrenceWeights::from_fingerprints(with_rare.iter());
        assert!(
            weights.weight(0xdead_beef) > weights.weight(0),
            "rare {} !> common {}",
            weights.weight(0xdead_beef),
            weights.weight(0)
        );

        // Two functions sharing only the rare element must beat two sharing
        // only the common one.
        let rare_pair = (
            fingerprint(&[0xdead_beef, 1]),
            fingerprint(&[0xdead_beef, 2]),
        );
        let common_pair = (fingerprint(&[0, 1]), fingerprint(&[0, 2]));
        assert!(
            weighted_jaccard(&rare_pair.0, &rare_pair.1, Some(&weights))
                > weighted_jaccard(&common_pair.0, &common_pair.1, Some(&weights))
        );
    }
}
