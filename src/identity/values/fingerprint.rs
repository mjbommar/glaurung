//! The stored artifact: a version triple, a sorted element multiset, a digest.
//!
//! The multiset is a `(u64 element, u32 count)` list sorted by element, which
//! makes [`super::similarity`]'s weighted Jaccard an `O(n + m)` merge join
//! rather than a hash-set intersection -- the same encoding and the same
//! reason as `crate::identity::cfr::signature`.
//!
//! # What a u64 element is
//!
//! Two classes share one key space.
//!
//! * **E1, a computed value.** The key *is* the normalised value: a 64-bit
//!   two's-complement number, sign-extended from the width the machine
//!   produced it at. Not a hash. vSim's fingerprints are human-readable on
//!   purpose and so are these -- an element that reads `0xffffffffffffffff` is
//!   the integer -1, and `card_read` in a diff can be read directly.
//! * **E2, a branch condition.** `(comparison, constant)` mixed into the same
//!   key space by [`branch_element`], in a band no small integer reaches.
//!
//! The two classes can in principle collide. The probability is a 2^-64 event
//! per pair and the consequence is one spurious shared element out of
//! hundreds, which is strictly smaller than the cost of hashing E1 and losing
//! the ability to read a fingerprint.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::settings::{ValueVersion, VALUE_SCHEME};
use crate::ir::types::Width;

/// Sign-extend `raw` from `width` to 64 bits, the normal form for class E1.
///
/// vSim's rule: "discard the size field and treat the value as signed by
/// default". A 32-bit `-1` and a 64-bit `-1` are the same number afterwards,
/// which is what lets a 32-bit build match its 64-bit sibling on a value that
/// is the same integer in both.
pub fn normalize(raw: u64, width: Width) -> u64 {
    let bits = u32::from(width.bits()).clamp(1, 64);
    if bits >= 64 {
        return raw;
    }
    let shift = 64 - bits;
    (((raw << shift) as i64) >> shift) as u64
}

/// The canonical comparison kinds a branch condition normalises to.
///
/// Strict forms are folded into non-strict ones over the integers
/// (`x > k` is `x >= k+1`), which is a *sound* rewrite and does the job vSim
/// does with a table of optimisation patterns learned from a held-out project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BranchKind {
    Eq,
    Ne,
    /// Unsigned `<=`.
    Ule,
    /// Unsigned `>=`.
    Uge,
    /// Signed `<=`.
    Sle,
    /// Signed `>=`.
    Sge,
}

impl BranchKind {
    fn tag(self) -> u64 {
        match self {
            BranchKind::Eq => 0,
            BranchKind::Ne => 1,
            BranchKind::Ule => 2,
            BranchKind::Uge => 3,
            BranchKind::Sle => 4,
            BranchKind::Sge => 5,
        }
    }
}

/// The element key for one branch condition.
pub fn branch_element(kind: BranchKind, constant: u64) -> u64 {
    const BAND: u64 = 0x00B4_0000_0000_0000;
    BAND | (super::seeds::mix64(constant ^ super::seeds::mix64(kind.tag() | 0x100)) >> 16)
}

/// One function's value fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueFingerprint {
    pub version: ValueVersion,
    /// `(element, occurrence count)`, sorted ascending by element.
    pub values: Vec<(u64, u32)>,
    /// BLAKE3 over the scheme name, the version triple and the element list.
    /// This is what the `function_identity` table stores, hex-encoded.
    pub digest: [u8; 32],
}

impl ValueFingerprint {
    /// Build a fingerprint from a raw element multiset.
    pub fn from_elements(version: ValueVersion, raw: &[u64]) -> Self {
        let mut counts: BTreeMap<u64, u32> = BTreeMap::new();
        for element in raw {
            *counts.entry(*element).or_insert(0) += 1;
        }
        let values: Vec<(u64, u32)> = counts.into_iter().collect();
        let digest = digest_of(version, &values);
        ValueFingerprint {
            version,
            values,
            digest,
        }
    }

    /// The hex digest, which is what the `function_identity` table stores.
    pub fn identity(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.digest {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// Distinct elements. This is the cardinality vSim's Jaccard is over.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether this fingerprint carries no elements at all.
    ///
    /// An empty fingerprint compares as "no answer" to everything, which is
    /// indistinguishable from a genuinely featureless function; callers are
    /// expected to say so rather than score it.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Total element occurrences, counts included.
    pub fn total_count(&self) -> u64 {
        self.values.iter().map(|(_, count)| u64::from(*count)).sum()
    }
}

/// BLAKE3 over the scheme name, the version triple, then the sorted elements.
fn digest_of(version: ValueVersion, values: &[(u64, u32)]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(VALUE_SCHEME.as_bytes());
    hasher.update(&version.major.to_le_bytes());
    hasher.update(&version.minor.to_le_bytes());
    hasher.update(&version.settings.to_le_bytes());
    for (element, count) in values {
        hasher.update(&element.to_le_bytes());
        hasher.update(&count.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::values::settings::ValueSettings;

    fn version() -> ValueVersion {
        ValueVersion::current(ValueSettings::default())
    }

    #[test]
    fn normalisation_makes_minus_one_the_same_number_at_every_width() {
        assert_eq!(normalize(0xffff_ffff, Width::W32), u64::MAX);
        assert_eq!(normalize(0xffff, Width::W16), u64::MAX);
        assert_eq!(normalize(0xff, Width::W8), u64::MAX);
        assert_eq!(normalize(u64::MAX, Width::W64), u64::MAX);
    }

    #[test]
    fn normalisation_leaves_small_positives_alone() {
        for width in [Width::W8, Width::W16, Width::W32, Width::W64] {
            assert_eq!(normalize(7, width), 7);
        }
        assert_eq!(normalize(0xdead_beef, Width::W32), (-559_038_737i64) as u64);
        assert_eq!(normalize(0xdead_beef, Width::W64), 0xdead_beef);
    }

    #[test]
    fn elements_are_sorted_and_counted() {
        let fingerprint = ValueFingerprint::from_elements(version(), &[7, 3, 7, 9, 3, 7]);
        assert_eq!(fingerprint.values, vec![(3, 2), (7, 3), (9, 1)]);
        assert_eq!(fingerprint.total_count(), 6);
        assert_eq!(fingerprint.len(), 3);
    }

    #[test]
    fn the_digest_depends_on_the_settings() {
        let plain = ValueFingerprint::from_elements(version(), &[1, 2, 3]);
        let unfiltered = ValueFingerprint::from_elements(
            ValueVersion::current(ValueSettings {
                filter: false,
                ..ValueSettings::default()
            }),
            &[1, 2, 3],
        );
        assert_eq!(plain.values, unfiltered.values);
        assert_ne!(plain.digest, unfiltered.digest);
    }

    #[test]
    fn branch_elements_are_distinct_per_comparison_and_per_constant() {
        let kinds = [
            BranchKind::Eq,
            BranchKind::Ne,
            BranchKind::Ule,
            BranchKind::Uge,
            BranchKind::Sle,
            BranchKind::Sge,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for kind in kinds {
            for constant in [0u64, 1, 8, u64::MAX] {
                assert!(
                    seen.insert(branch_element(kind, constant)),
                    "{kind:?}/{constant} collided"
                );
            }
        }
    }

    #[test]
    fn a_branch_element_cannot_be_mistaken_for_a_small_integer() {
        for kind in [BranchKind::Eq, BranchKind::Sge] {
            for constant in 0..64u64 {
                assert!(branch_element(kind, constant) > 1 << 40);
            }
        }
    }

    #[test]
    fn a_fingerprint_round_trips_through_serde() {
        let fingerprint = ValueFingerprint::from_elements(version(), &[5, 5, 1]);
        let json = serde_json::to_string(&fingerprint).expect("serialize");
        let back: ValueFingerprint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(fingerprint, back);
    }
}
