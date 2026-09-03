//! The stored artifact: a version triple, a sorted feature multiset, a digest.
//!
//! The multiset is serialised as a `(u32 hash, u16 count)` list sorted by hash,
//! which is BSim's `1:545c6155` encoding and which makes the comparison in
//! [`super::similarity`] an `O(n + m)` merge join rather than a hash-set
//! intersection.
//!
//! # Why the version triple is not optional
//!
//! Any change to the mask list -- one more masked constant, one fewer dropped
//! shadow node, a different width class -- changes every feature of every
//! function, so a stored vector computed under the old rules is not comparable
//! with one computed under the new. BSim carries `major`/`minor`/`settings` in
//! its database for exactly this reason. A vector without its version is a
//! number nobody can safely compare, and the moment a corpus exists it is
//! painful to add.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Settings that change what the canonical form keeps.
///
/// A settings value is part of the identity triple: two signatures computed
/// under different settings describe different quotients and must not be
/// compared.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CfrSettings {
    /// Collapse every width class of four bytes and up into one.
    ///
    /// BSim's `medium_nosize`. It is the single switch that buys 32-to-64-bit
    /// matching, at the cost of the discrimination a width carries, and it is
    /// present from day one because retrofitting a setting to a populated
    /// corpus means recomputing the corpus.
    pub nosize: bool,

    /// Run [`super::normalize`], the unsound local peephole normaliser, over a
    /// copy of the lifted function before the graph is built.
    ///
    /// **Off by default, and it must stay off by default.** The normaliser is
    /// a deliberately unsound canonicaliser for similarity; its output is a
    /// different quotient, which is why it is a settings bit rather than an
    /// unconditional stage. Two signatures whose `normalize` differs are not
    /// comparable, exactly as for `nosize`.
    pub normalize: bool,
}

impl CfrSettings {
    /// Bit position of [`CfrSettings::nosize`] in the packed settings word.
    pub const NOSIZE_BIT: u32 = 1 << 0;

    /// Bit position of [`CfrSettings::normalize`] in the packed settings word.
    pub const NORMALIZE_BIT: u32 = 1 << 1;

    /// The packed settings word stored in the version triple.
    pub fn bits(self) -> u32 {
        let mut bits = 0;
        if self.nosize {
            bits |= Self::NOSIZE_BIT;
        }
        if self.normalize {
            bits |= Self::NORMALIZE_BIT;
        }
        bits
    }

    /// Recover settings from a packed word. Unknown bits are ignored, which is
    /// deliberate: a newer writer's setting must not silently read as `false`
    /// on an older reader without the version comparison catching it first.
    pub fn from_bits(bits: u32) -> Self {
        CfrSettings {
            nosize: bits & Self::NOSIZE_BIT != 0,
            normalize: bits & Self::NORMALIZE_BIT != 0,
        }
    }
}

/// Major version of the canonical form.
///
/// Bumped when the mask list changes, which invalidates every stored vector.
pub const CFR_MAJOR: u16 = 1;

/// Minor version of the canonical form.
///
/// Bumped for a change that adds features without changing the meaning of the
/// existing ones. Vectors across a minor bump are comparable but not equal.
pub const CFR_MINOR: u16 = 0;

/// The scheme name written into the `function_identity` table.
pub const CFR_SCHEME: &str = "glaurung-cfr-v1";

/// The `(major, minor, settings)` triple every signature carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CfrVersion {
    pub major: u16,
    pub minor: u16,
    /// Packed [`CfrSettings`]; see [`CfrSettings::bits`].
    pub settings: u32,
}

impl CfrVersion {
    /// The current version under `settings`.
    pub fn current(settings: CfrSettings) -> Self {
        CfrVersion {
            major: CFR_MAJOR,
            minor: CFR_MINOR,
            settings: settings.bits(),
        }
    }

    /// Whether two signatures under these versions may be compared at all.
    ///
    /// A major difference means a different mask list and a different quotient;
    /// a settings difference means a different projection. Both make a
    /// similarity number meaningless rather than merely imprecise.
    pub fn is_comparable_with(self, other: Self) -> bool {
        self.major == other.major && self.settings == other.settings
    }
}

/// One function's canonical representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfrSignature {
    pub version: CfrVersion,
    /// `(feature hash, occurrence count)`, sorted ascending by hash.
    pub features: Vec<(u32, u16)>,
    /// BLAKE3 over the version triple and the feature list. This is the value
    /// the `function_identity` table stores, hex-encoded.
    pub digest: [u8; 32],
}

impl CfrSignature {
    /// Build a signature from a raw feature multiset.
    ///
    /// Counts saturate at [`u16::MAX`]: a function with 65,536 copies of one
    /// feature has told us everything it is going to.
    pub fn from_features(version: CfrVersion, raw: &[u32]) -> Self {
        let mut counts: BTreeMap<u32, u32> = BTreeMap::new();
        for feature in raw {
            *counts.entry(*feature).or_insert(0) += 1;
        }
        let features: Vec<(u32, u16)> = counts
            .into_iter()
            .map(|(hash, count)| (hash, count.min(u32::from(u16::MAX)) as u16))
            .collect();
        let digest = digest_of(version, &features);
        CfrSignature {
            version,
            features,
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

    /// Total feature occurrences. A proxy for function size, and the reason a
    /// three-node function cannot reach a confident match.
    pub fn total_count(&self) -> u64 {
        self.features
            .iter()
            .map(|(_, count)| u64::from(*count))
            .sum()
    }

    /// Whether this signature carries no features at all.
    pub fn is_empty(&self) -> bool {
        self.features.is_empty()
    }
}

/// BLAKE3 over the version triple followed by the sorted feature list.
///
/// The version is hashed *first* and inside the same digest, so two signatures
/// that happen to share a feature list under different mask lists do not share
/// an identity.
fn digest_of(version: CfrVersion, features: &[(u32, u16)]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(super::CFR_SCHEME.as_bytes());
    hasher.update(&version.major.to_le_bytes());
    hasher.update(&version.minor.to_le_bytes());
    hasher.update(&version.settings.to_le_bytes());
    for (hash, count) in features {
        hasher.update(&hash.to_le_bytes());
        hasher.update(&count.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn features_are_sorted_and_counted() {
        let version = CfrVersion::current(CfrSettings::default());
        let signature = CfrSignature::from_features(version, &[7, 3, 7, 9, 3, 7]);
        assert_eq!(signature.features, vec![(3, 2), (7, 3), (9, 1)]);
        assert_eq!(signature.total_count(), 6);
    }

    #[test]
    fn the_digest_depends_on_the_settings() {
        let plain =
            CfrSignature::from_features(CfrVersion::current(CfrSettings::default()), &[1, 2, 3]);
        let nosize = CfrSignature::from_features(
            CfrVersion::current(CfrSettings {
                nosize: true,
                ..CfrSettings::default()
            }),
            &[1, 2, 3],
        );
        assert_eq!(plain.features, nosize.features);
        assert_ne!(plain.digest, nosize.digest);
    }

    #[test]
    fn versions_across_a_settings_change_are_not_comparable() {
        let plain = CfrVersion::current(CfrSettings::default());
        let nosize = CfrVersion::current(CfrSettings {
            nosize: true,
            ..CfrSettings::default()
        });
        assert!(plain.is_comparable_with(plain));
        assert!(!plain.is_comparable_with(nosize));
    }

    #[test]
    fn a_signature_round_trips_through_serde() {
        let signature =
            CfrSignature::from_features(CfrVersion::current(CfrSettings::default()), &[5, 5, 1]);
        let json = serde_json::to_string(&signature).expect("serialize");
        let back: CfrSignature = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(signature, back);
    }
}
