//! The corpus-derived TF-IDF table that turns the uniform kernel into a
//! weighted one.
//!
//! [`super::similarity`] defines the [`Weights`] trait and ships
//! [`super::similarity::UniformWeights`] as the no-table fallback, where every
//! feature counts the same and a `mov` between two registers weighs as much as
//! a call to `pthread_mutex_lock`. This module is the other implementation: an
//! inverse-document-frequency table counted over a corpus of
//! [`CfrSignature`]s.
//!
//! # The weight
//!
//! A feature's document frequency `df(f)` is the number of *functions* that
//! carry it at least once -- not the number of occurrences, which is the term
//! frequency and is handled separately by the `1 + log2(tf)` term inside the
//! kernel. Over a corpus of `N` functions,
//!
//! ```text
//! idf(f) = ln((N + 1) / (df(f) + 1))          [nats]
//! ```
//!
//! The `+1` on both sides is add-one smoothing, and it is doing two jobs. It
//! keeps the weight finite for a feature the corpus has never seen (`df = 0`),
//! which is the ordinary case at query time and which plain `ln(N / df)` sends
//! to infinity. And it keeps the weight non-negative for a feature *every*
//! function carries (`df = N`), where plain `ln(N / df)` is exactly zero and
//! one rounding error below it is negative -- a negative weight would make the
//! kernel indefinite and take the triangle inequality with it.
//!
//! So the table's range is `[0, ln(N + 1)]`: a universal feature contributes
//! nothing, and a feature seen once in a million-function corpus contributes
//! about 13.
//!
//! # Quantisation
//!
//! BSim quantises its weights, storing a `u16` per feature rather than a
//! double (`LSH_ITEM{uint32 hash; uint16 tf; uint16 idf; double coeff;}`), and
//! its shipped weight files cover the commonest hashes with a fixed number of
//! levels. This table does the same with [`IDF_BUCKETS`] = 512 levels evenly
//! spaced over `[0, IDF_MAX]` nats:
//!
//! ```text
//! bucket(f)  = round(clamp(idf(f), 0, IDF_MAX) * (IDF_BUCKETS - 1) / IDF_MAX)
//! weight(f)  = bucket(f) * IDF_MAX / (IDF_BUCKETS - 1)
//! ```
//!
//! [`IDF_MAX`] is 16 nats, which is `ln` of about 8.9 million: the ceiling only
//! binds on a corpus larger than any this project indexes, and fixing it as a
//! constant rather than deriving it from `N` is what makes two tables built
//! over differently sized corpora carry weights on the same scale. The step is
//! `16 / 511 = 0.0313` nats, i.e. a 3.2% resolution on the frequency ratio a
//! weight encodes -- far finer than the difference between two adjacent
//! document counts anywhere the weight matters.
//!
//! Quantising is not only a storage saving. A weight table is part of a score
//! that gets stored, compared and ratcheted, and a full-precision `f64`
//! recomputed on a different corpus ordering can differ in its last bits; a
//! bucket index cannot. Two tables that agree on every bucket produce
//! bit-identical scores.
//!
//! # `weights_id`
//!
//! Every stored vector's score depends on the table it was scored under, so the
//! table needs a name that changes whenever anything about it changes. BSim
//! freezes its weight scheme at database creation and documents that it "cannot
//! be changed without reingesting"; [`CorpusWeights::weights_id`] makes that
//! explicit rather than implicit -- a reweight is a new `weights_id`, not a
//! silent corruption of the old scores.
//!
//! The id covers the CFR scheme name, the full `(major, minor, settings)`
//! version triple, the quantisation parameters, the corpus size, and every
//! `(feature, bucket)` pair. Anything that could change a weight changes the
//! id.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::signature::{CfrSignature, CfrVersion};
use super::similarity::Weights;

/// Quantisation levels in the IDF table. BSim's own count.
pub const IDF_BUCKETS: u16 = 512;

/// Top of the quantised IDF range, in nats.
///
/// `ln(8.9e6)`, so the ceiling binds only on a corpus larger than anything this
/// project indexes. Fixed rather than derived from the corpus size so that two
/// tables built over different corpora put their weights on the same scale.
pub const IDF_MAX: f64 = 16.0;

/// Nats per bucket step: `IDF_MAX / (IDF_BUCKETS - 1)`.
pub fn bucket_step() -> f64 {
    IDF_MAX / f64::from(IDF_BUCKETS - 1)
}

/// The smoothed inverse document frequency of a feature, unquantised.
///
/// `ln((documents + 1) / (doc_count + 1))`, clamped into `[0, IDF_MAX]`. See
/// the module documentation for why the smoothing is on both sides.
pub fn raw_idf(documents: u64, doc_count: u64) -> f64 {
    let numerator = (documents as f64) + 1.0;
    let denominator = (doc_count as f64) + 1.0;
    (numerator / denominator).ln().clamp(0.0, IDF_MAX)
}

/// Quantise an unquantised IDF into `[0, IDF_BUCKETS - 1]`.
pub fn quantise(idf: f64) -> u16 {
    let scaled = idf.clamp(0.0, IDF_MAX) / bucket_step();
    // `round` then clamp: the division can land a hair above the top bucket
    // when `idf` is exactly `IDF_MAX`.
    (scaled.round() as i64).clamp(0, i64::from(IDF_BUCKETS - 1)) as u16
}

/// Recover the weight one bucket stands for, in nats.
pub fn dequantise(bucket: u16) -> f64 {
    f64::from(bucket.min(IDF_BUCKETS - 1)) * bucket_step()
}

/// One feature's row in the table.
///
/// `doc_count` is kept beside the bucket because it is what the
/// `feature_weight` KB table stores and what a later merge of two corpora
/// needs; the bucket alone cannot be un-quantised back into a count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureWeight {
    /// Functions in the corpus carrying this feature at least once.
    pub doc_count: u64,
    /// Quantised IDF, in `[0, IDF_BUCKETS - 1]`.
    pub bucket: u16,
}

impl FeatureWeight {
    /// The weight this row stands for, in nats.
    pub fn weight(self) -> f64 {
        dequantise(self.bucket)
    }
}

/// Counts a corpus of signatures into a [`CorpusWeights`].
///
/// The builder holds only `(feature -> document count)` and the number of
/// documents, so it is `O(distinct features)` in memory and can be fed a corpus
/// far larger than fits in RAM as signatures.
///
/// # Version discipline
///
/// A builder is pinned to one [`CfrVersion`] and [`WeightsBuilder::observe`]
/// **refuses** a signature computed under an incomparable one, returning
/// `false` rather than counting it. Features from two different mask lists are
/// two different alphabets that happen to share a hash space; mixing them
/// produces a table whose weights are wrong for both.
#[derive(Debug, Clone)]
pub struct WeightsBuilder {
    version: CfrVersion,
    documents: u64,
    doc_counts: BTreeMap<u32, u64>,
    rejected: u64,
}

impl WeightsBuilder {
    /// A builder for signatures under `version`.
    pub fn new(version: CfrVersion) -> Self {
        WeightsBuilder {
            version,
            documents: 0,
            doc_counts: BTreeMap::new(),
            rejected: 0,
        }
    }

    /// Count one function into the table.
    ///
    /// Returns `false` -- and counts nothing -- when the signature's version is
    /// not comparable with the builder's. An empty signature *is* counted as a
    /// document: it is a function the corpus contains, and leaving it out would
    /// make `N` disagree with the population the corpus actually holds.
    pub fn observe(&mut self, signature: &CfrSignature) -> bool {
        if !self.version.is_comparable_with(signature.version) {
            self.rejected += 1;
            return false;
        }
        self.documents += 1;
        for (feature, _count) in &signature.features {
            *self.doc_counts.entry(*feature).or_insert(0) += 1;
        }
        true
    }

    /// Count a whole slice.
    ///
    /// Returns how many were counted; the rest were refused for their version.
    pub fn observe_all<'a, I>(&mut self, signatures: I) -> usize
    where
        I: IntoIterator<Item = &'a CfrSignature>,
    {
        signatures
            .into_iter()
            .filter(|signature| self.observe(signature))
            .count()
    }

    /// Functions counted so far. This is the `N` in `ln((N + 1) / (df + 1))`.
    pub fn documents(&self) -> u64 {
        self.documents
    }

    /// Distinct features seen so far.
    pub fn distinct_features(&self) -> usize {
        self.doc_counts.len()
    }

    /// Signatures refused for an incomparable version.
    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// Freeze the counts into a weight table.
    ///
    /// Features whose document count is below `min_doc_count` are **left out**
    /// of the table rather than given a weight. Leaving one out is not the same
    /// as giving it zero: an absent feature falls through to the corpus's
    /// maximum weight (see [`CorpusWeights::idf`]), which is the right answer
    /// for a feature so rare the corpus saw it once. Pass `1` to keep
    /// everything, which is what the harness does.
    pub fn build(self, min_doc_count: u64) -> CorpusWeights {
        let entries: BTreeMap<u32, FeatureWeight> = self
            .doc_counts
            .into_iter()
            .filter(|(_, doc_count)| *doc_count >= min_doc_count)
            .map(|(feature, doc_count)| {
                (
                    feature,
                    FeatureWeight {
                        doc_count,
                        bucket: quantise(raw_idf(self.documents, doc_count)),
                    },
                )
            })
            .collect();
        CorpusWeights::from_parts(self.version, self.documents, entries)
    }
}

/// A frozen corpus IDF table: the [`Weights`] implementation the weighted
/// kernel consumes.
///
/// Construct one with [`WeightsBuilder`], or rebuild a stored one with
/// [`CorpusWeights::from_parts`]. Both routes recompute the `weights_id`, so a
/// table read back from a database and a table rebuilt from a corpus carry the
/// same id iff they are the same table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusWeights {
    version: CfrVersion,
    documents: u64,
    entries: BTreeMap<u32, FeatureWeight>,
    weights_id: String,
}

impl CorpusWeights {
    /// Rebuild a table from its parts, recomputing the id.
    pub fn from_parts(
        version: CfrVersion,
        documents: u64,
        entries: BTreeMap<u32, FeatureWeight>,
    ) -> Self {
        let weights_id = compute_weights_id(version, documents, &entries);
        CorpusWeights {
            version,
            documents,
            entries,
            weights_id,
        }
    }

    /// The version the counted signatures were computed under.
    ///
    /// A table may only weight signatures whose version is comparable with
    /// this; [`CorpusWeights::is_applicable_to`] is the check.
    pub fn version(&self) -> CfrVersion {
        self.version
    }

    /// Functions counted into the table.
    pub fn documents(&self) -> u64 {
        self.documents
    }

    /// Distinct features the table carries a weight for.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table carries no features at all. Such a table weights
    /// every feature at the corpus maximum and is not useful; it is reachable
    /// only from an empty corpus.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The stable name of this table.
    ///
    /// Changes whenever the CFR version, the quantisation parameters, the
    /// corpus size or any single weight changes. It is what the `feature_weight`
    /// and `feature_vector` KB tables key on, so that a reweight is a new
    /// `weights_id` rather than a silent rescoring of stored vectors.
    pub fn weights_id(&self) -> &str {
        &self.weights_id
    }

    /// Whether a signature may be scored under this table.
    pub fn is_applicable_to(&self, signature: &CfrSignature) -> bool {
        self.version.is_comparable_with(signature.version)
    }

    /// The stored row for one feature, if the table has one.
    pub fn entry(&self, feature: u32) -> Option<FeatureWeight> {
        self.entries.get(&feature).copied()
    }

    /// Every `(feature, row)` pair, ascending by feature hash.
    ///
    /// This is the order the `feature_weight` table wants and the order
    /// [`CorpusWeights::weights_id`] hashes in.
    pub fn iter(&self) -> impl Iterator<Item = (u32, FeatureWeight)> + '_ {
        self.entries.iter().map(|(hash, row)| (*hash, *row))
    }

    /// The weight an unlisted feature gets, in nats.
    ///
    /// A feature the corpus never saw has `df = 0`, so its smoothed IDF is
    /// `ln(N + 1)` -- the largest weight this corpus can express. That is the
    /// honest answer rather than a conservative one: the table's whole claim is
    /// that rarity is evidence, and a feature it has never seen is as rare as
    /// its evidence goes. It only affects the norms, because a feature absent
    /// from the table can still be shared by two functions and then it is
    /// shared *rarely*.
    pub fn unlisted_weight(&self) -> f64 {
        dequantise(quantise(raw_idf(self.documents, 0)))
    }
}

impl Weights for CorpusWeights {
    fn idf(&self, feature: u32) -> f64 {
        match self.entries.get(&feature) {
            Some(row) => row.weight(),
            None => self.unlisted_weight(),
        }
    }

    /// The corpus's own maximum, `ln(N + 1)` quantised -- the same value
    /// [`CorpusWeights::unlisted_weight`] returns, because the rarest feature a
    /// table can express is one it has never seen.
    ///
    /// Never zero: a table built from an empty corpus would put every weight at
    /// `ln(1) = 0`, and `super::similarity::significance` would then divide by
    /// it. `1.0` is the fallback, which makes such a table's significance the
    /// unweighted one.
    fn max_idf(&self) -> f64 {
        let max = self.unlisted_weight();
        if max > 0.0 {
            max
        } else {
            1.0
        }
    }
}

/// BLAKE3 over everything that could change a weight, hex-truncated to 16
/// characters and prefixed with the human-readable version triple.
fn compute_weights_id(
    version: CfrVersion,
    documents: u64,
    entries: &BTreeMap<u32, FeatureWeight>,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(super::CFR_SCHEME.as_bytes());
    hasher.update(&version.major.to_le_bytes());
    hasher.update(&version.minor.to_le_bytes());
    hasher.update(&version.settings.to_le_bytes());
    hasher.update(&IDF_BUCKETS.to_le_bytes());
    hasher.update(&IDF_MAX.to_le_bytes());
    hasher.update(&documents.to_le_bytes());
    for (feature, row) in entries {
        hasher.update(&feature.to_le_bytes());
        hasher.update(&row.bucket.to_le_bytes());
    }
    let digest = hasher.finalize();
    let mut short = String::with_capacity(16);
    for byte in &digest.as_bytes()[..8] {
        short.push_str(&format!("{byte:02x}"));
    }
    format!(
        "cfr-{}.{}-s{}-idf{}-{}",
        version.major, version.minor, version.settings, IDF_BUCKETS, short
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::cfr::signature::CfrSettings;
    use crate::identity::cfr::similarity::cosine;

    fn version() -> CfrVersion {
        CfrVersion::current(CfrSettings::default())
    }

    fn signature(raw: &[u32]) -> CfrSignature {
        CfrSignature::from_features(version(), raw)
    }

    fn table(corpus: &[&[u32]]) -> CorpusWeights {
        let signatures: Vec<CfrSignature> = corpus.iter().map(|raw| signature(raw)).collect();
        let mut builder = WeightsBuilder::new(version());
        builder.observe_all(&signatures);
        builder.build(1)
    }

    #[test]
    fn a_universal_feature_weighs_nothing_and_a_rare_one_weighs_a_lot() {
        // `1` is in every document; `9` is in one of five.
        let weights = table(&[&[1, 2], &[1, 3], &[1, 4], &[1, 5], &[1, 9]]);
        assert_eq!(weights.documents(), 5);
        assert_eq!(weights.idf(1), 0.0);
        assert!(weights.idf(9) > 1.0, "{}", weights.idf(9));
    }

    #[test]
    fn no_weight_is_ever_negative() {
        // The `df == N` case, which unsmoothed `ln(N / df)` puts at exactly
        // zero and one rounding error can put below it. A negative weight
        // makes the kernel indefinite.
        for documents in [1u64, 2, 10, 1_000, 1_000_000] {
            for doc_count in [0u64, 1, documents / 2, documents] {
                assert!(
                    raw_idf(documents, doc_count) >= 0.0,
                    "N={documents} df={doc_count}"
                );
            }
        }
    }

    #[test]
    fn quantisation_round_trips_within_half_a_step() {
        let step = bucket_step();
        for idf in [0.0f64, 0.01, 0.5, 1.0, 3.7, 9.9, IDF_MAX] {
            let back = dequantise(quantise(idf));
            assert!(
                (back - idf).abs() <= step / 2.0 + 1e-12,
                "idf={idf} -> {back}, step={step}"
            );
        }
    }

    #[test]
    fn an_idf_above_the_ceiling_saturates_rather_than_wrapping() {
        assert_eq!(quantise(1e9), IDF_BUCKETS - 1);
        assert_eq!(quantise(-1.0), 0);
        assert!((dequantise(IDF_BUCKETS - 1) - IDF_MAX).abs() < 1e-12);
        // A bucket past the top is clamped, not wrapped, so a table written by
        // a future build with more buckets reads as saturated rather than as
        // an arbitrary small weight.
        assert_eq!(dequantise(u16::MAX), dequantise(IDF_BUCKETS - 1));
    }

    #[test]
    fn an_unlisted_feature_gets_the_corpus_maximum() {
        let weights = table(&[&[1, 2], &[1, 3]]);
        let listed = weights.idf(1);
        let unlisted = weights.idf(0xdead_beef);
        assert!(unlisted > listed, "{unlisted} !> {listed}");
        assert_eq!(unlisted, weights.unlisted_weight());
    }

    #[test]
    fn the_id_changes_with_the_table_and_not_with_the_ordering() {
        let a = table(&[&[1, 2], &[1, 3]]);
        let b = table(&[&[1, 3], &[1, 2]]);
        assert_eq!(a.weights_id(), b.weights_id());
        let c = table(&[&[1, 2], &[1, 3], &[4]]);
        assert_ne!(a.weights_id(), c.weights_id());
    }

    #[test]
    fn the_id_changes_with_the_cfr_settings() {
        let plain = CorpusWeights::from_parts(
            CfrVersion::current(CfrSettings::default()),
            3,
            BTreeMap::new(),
        );
        let nosize = CorpusWeights::from_parts(
            CfrVersion::current(CfrSettings { nosize: true }),
            3,
            BTreeMap::new(),
        );
        assert_ne!(plain.weights_id(), nosize.weights_id());
    }

    #[test]
    fn a_builder_refuses_a_signature_from_another_quotient() {
        let mut builder = WeightsBuilder::new(version());
        let foreign = CfrSignature::from_features(
            CfrVersion::current(CfrSettings { nosize: true }),
            &[1, 2, 3],
        );
        assert!(!builder.observe(&foreign));
        assert_eq!(builder.documents(), 0);
        assert_eq!(builder.rejected(), 1);
        assert!(builder.observe(&signature(&[1, 2, 3])));
        assert_eq!(builder.documents(), 1);
    }

    #[test]
    fn a_min_doc_count_leaves_a_rare_feature_out_rather_than_zeroing_it() {
        let signatures: Vec<CfrSignature> = [&[1u32, 2][..], &[1, 3][..], &[1, 2][..]]
            .iter()
            .map(|raw| signature(raw))
            .collect();
        let mut builder = WeightsBuilder::new(version());
        builder.observe_all(&signatures);
        let weights = builder.build(2);
        assert!(weights.entry(3).is_none());
        // Left out, so it falls through to the maximum -- not to zero.
        assert_eq!(weights.idf(3), weights.unlisted_weight());
        assert!(weights.idf(3) > weights.idf(1));
    }

    #[test]
    fn a_table_round_trips_through_serde_with_its_id() {
        let weights = table(&[&[1, 2, 2], &[1, 3], &[4, 5]]);
        let json = serde_json::to_string(&weights).expect("serialize");
        let back: CorpusWeights = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(weights, back);
        assert_eq!(weights.weights_id(), back.weights_id());
    }

    /// The property the whole lane exists for: sharing a *rare* feature must
    /// score higher than sharing a common one, and the uniform table cannot
    /// tell the two apart.
    #[test]
    fn sharing_a_rare_feature_beats_sharing_a_common_one_only_once_weighted() {
        // `1` is in all six documents; `7` is in two.
        let corpus: [&[u32]; 6] = [&[1, 7], &[1, 7], &[1, 2], &[1, 3], &[1, 4], &[1, 5]];
        let weights = table(&corpus);

        let common_pair = (signature(&[1, 2]), signature(&[1, 3]));
        let rare_pair = (signature(&[7, 2]), signature(&[7, 3]));

        let uniform_common = cosine(&common_pair.0, &common_pair.1, None);
        let uniform_rare = cosine(&rare_pair.0, &rare_pair.1, None);
        assert!(
            (uniform_common - uniform_rare).abs() < 1e-12,
            "unweighted must be blind to rarity: {uniform_common} vs {uniform_rare}"
        );

        let weighted_common = cosine(&common_pair.0, &common_pair.1, Some(&weights));
        let weighted_rare = cosine(&rare_pair.0, &rare_pair.1, Some(&weights));
        assert!(
            weighted_rare > weighted_common,
            "rare {weighted_rare} !> common {weighted_common}"
        );
    }

    #[test]
    fn a_weighted_signature_is_still_its_own_nearest_neighbour() {
        let weights = table(&[&[1, 2], &[1, 3], &[2, 3, 4]]);
        let a = signature(&[1, 2, 2, 4]);
        assert!((cosine(&a, &a, Some(&weights)) - 1.0).abs() < 1e-12);
    }
}
