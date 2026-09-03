//! What a value fingerprint keeps, and the version triple that says so.
//!
//! Every knob here changes the multiset a function produces, so every knob is
//! part of the identity triple. Two fingerprints computed under different
//! settings describe different quotients and must not be compared -- the same
//! discipline `crate::identity::cfr::signature` applies, for the same reason.

use serde::{Deserialize, Serialize};

/// The `scheme` string a value fingerprint is stored under.
pub const VALUE_SCHEME: &str = "glaurung-values-v1";

/// Major version. Bumped when a filter rule or the normal form changes, which
/// invalidates every stored fingerprint.
pub const VALUE_MAJOR: u16 = 1;

/// Minor version. Bumped for an addition that does not change the meaning of
/// the elements already emitted.
pub const VALUE_MINOR: u16 = 0;

/// Upper bound on [`ValueSettings::seeds`]; the packed settings word has four
/// bits for it.
pub const MAX_SEEDS: u8 = 15;

/// Upper bound on [`ValueSettings::site_cap`]; four bits in the packed word.
pub const MAX_SITE_CAP: u8 = 15;

/// Settings that change what the fingerprint keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValueSettings {
    /// How many fixed initial states to run.
    ///
    /// vSim evaluates each symbolic expression against a five-element array of
    /// trial values; running the concrete interpreter from N fixed initial
    /// states is the same idea with the substitution done during execution
    /// rather than after it. Three is the default. Clamped to
    /// `1..=MAX_SEEDS` by [`ValueSettings::seed_count`].
    pub seeds: u8,

    /// Instruction budget for **one** seed's run, in retired LLIR
    /// instructions. [`crate::exec::Budget`] counts these; there is no wall
    /// clock anywhere in this scheme, so a fingerprint does not depend on how
    /// busy the machine was.
    pub max_steps: u32,

    /// Distinct values recorded per instruction site per run.
    ///
    /// vSim executes one basic block at a time and so never sees a loop
    /// unrolled; we execute whole functions, so a ten-thousand-iteration loop
    /// would otherwise contribute ten thousand induction values and drown
    /// everything else the function computes. Clamped to `1..=MAX_SITE_CAP`.
    pub site_cap: u8,

    /// Apply the address filters (rules F1 to F3 in
    /// `docs/reference/function-identity-values.md`).
    ///
    /// vSim's ablation puts the whole filter at 0.09 Recall@1; this bit is
    /// what makes that measurable here.
    pub filter: bool,

    /// Emit the branch-condition elements (element class E2).
    pub branch_conditions: bool,

    /// Give each uninitialised **register** its own seed scalar instead of the
    /// one scalar the whole run shares.
    ///
    /// Off by default. vSim substitutes trial values by symbolic-variable
    /// position, which has no stable meaning across two builds; the uniform
    /// policy sidesteps the question by giving every fresh value in one run
    /// the same number. Keying by register name recovers the ability to tell
    /// `a - b` from `0`, at the cost of depending on two builds agreeing about
    /// register allocation.
    pub role_seeds: bool,
}

impl Default for ValueSettings {
    fn default() -> Self {
        ValueSettings {
            seeds: 3,
            max_steps: 20_000,
            site_cap: 4,
            filter: true,
            branch_conditions: true,
            role_seeds: false,
        }
    }
}

impl ValueSettings {
    /// Bit position of [`ValueSettings::filter`] in the packed settings word.
    pub const FILTER_BIT: u32 = 1 << 0;
    /// Bit position of [`ValueSettings::branch_conditions`].
    pub const BRANCH_BIT: u32 = 1 << 1;
    /// Bit position of [`ValueSettings::role_seeds`].
    pub const ROLE_SEEDS_BIT: u32 = 1 << 2;

    /// The seed count actually used, clamped into range.
    pub fn seed_count(self) -> u8 {
        self.seeds.clamp(1, MAX_SEEDS)
    }

    /// The per-site cap actually used, clamped into range.
    pub fn site_cap_used(self) -> u8 {
        self.site_cap.clamp(1, MAX_SITE_CAP)
    }

    /// The packed settings word stored in the version triple.
    ///
    /// Layout, low bit first: three flag bits, four bits of seed count, four
    /// bits of site cap, then the step budget in kibi-instructions saturated
    /// into the remaining twenty bits. Every knob is in there because every
    /// knob moves the multiset, and a stored vector whose version does not
    /// record the knob it was computed under is a number nobody can safely
    /// compare.
    pub fn bits(self) -> u32 {
        let mut bits = 0u32;
        if self.filter {
            bits |= Self::FILTER_BIT;
        }
        if self.branch_conditions {
            bits |= Self::BRANCH_BIT;
        }
        if self.role_seeds {
            bits |= Self::ROLE_SEEDS_BIT;
        }
        bits |= u32::from(self.seed_count()) << 4;
        bits |= u32::from(self.site_cap_used()) << 8;
        let steps_kib = (self.max_steps / 1024).min(0x000F_FFFF);
        bits |= steps_kib << 12;
        bits
    }
}

/// The `(major, minor, settings)` triple every fingerprint carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValueVersion {
    pub major: u16,
    pub minor: u16,
    /// Packed [`ValueSettings`]; see [`ValueSettings::bits`].
    pub settings: u32,
}

impl ValueVersion {
    /// The current version under `settings`.
    pub fn current(settings: ValueSettings) -> Self {
        ValueVersion {
            major: VALUE_MAJOR,
            minor: VALUE_MINOR,
            settings: settings.bits(),
        }
    }

    /// Whether two fingerprints under these versions may be compared at all.
    pub fn is_comparable_with(self, other: Self) -> bool {
        self.major == other.major && self.settings == other.settings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_knob_lands_in_the_packed_word() {
        let base = ValueSettings::default();
        let changed = [
            ValueSettings {
                filter: false,
                ..base
            },
            ValueSettings {
                branch_conditions: false,
                ..base
            },
            ValueSettings {
                role_seeds: true,
                ..base
            },
            ValueSettings { seeds: 5, ..base },
            ValueSettings {
                site_cap: 8,
                ..base
            },
            ValueSettings {
                max_steps: 40_960,
                ..base
            },
        ];
        for settings in changed {
            assert_ne!(
                settings.bits(),
                base.bits(),
                "{settings:?} packs the same as the default"
            );
        }
    }

    #[test]
    fn versions_across_a_settings_change_are_not_comparable() {
        let plain = ValueVersion::current(ValueSettings::default());
        let unfiltered = ValueVersion::current(ValueSettings {
            filter: false,
            ..ValueSettings::default()
        });
        assert!(plain.is_comparable_with(plain));
        assert!(!plain.is_comparable_with(unfiltered));
    }

    #[test]
    fn out_of_range_counts_clamp_rather_than_wrap_into_another_field() {
        let wild = ValueSettings {
            seeds: 200,
            site_cap: 200,
            ..ValueSettings::default()
        };
        assert_eq!(wild.seed_count(), MAX_SEEDS);
        assert_eq!(wild.site_cap_used(), MAX_SITE_CAP);
        // The seed and site-cap fields must not bleed into the step budget.
        assert_eq!(wild.bits() >> 12, ValueSettings::default().bits() >> 12);
    }
}
