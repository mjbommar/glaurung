//! Which harvested values are semantics-aware, and which are addresses.
//!
//! vSim's Algorithm 1 is subtractive: rather than trying to say what a
//! semantically significant value *is*, it removes what a value clearly is
//! not -- pointers and memory addresses -- and keeps the rest. Its ablation
//! puts the whole filter at 0.09 Recall@1 and a 2.8x comparison cost, so this
//! is load-bearing rather than tidying.
//!
//! # The rules, and what each one is a simplification of
//!
//! | Rule | vSim | Here |
//! |---|---|---|
//! | F1 | HC1: `v` inside a data section | `v >= ADDRESS_FLOOR` and `v` inside any mapped image range |
//! | F2 | HC2: `v` inside an executable section | folded into F1 -- `memory_kind_at` covers both, and the distinction never changes the verdict |
//! | F3 | HC3: `abs(v - bp) <= eps`, `eps` ~ 1 GiB | `abs(v - STACK_BASE) <= 1 MiB`, because we chose the stack pointer |
//! | F4 | `v in A`: used as an address | identical, over the addresses the concrete run actually formed |
//! | F5 | HS1/HS2/HS3, over expression trees | **not implemented**: concrete execution has no expression trees. F4 subsumes the case that fires most (a pointer, because something dereferenced it) |
//! | F6 | -- | width-1 values (flags) are dropped; a boolean is 0 or 1 and carries nothing |
//! | F7 | -- | at most `site_cap` distinct values per instruction site per run |
//!
//! F6 and F7 have no vSim counterpart because vSim does not need one. It
//! records branch conditions separately from values (so flags never enter the
//! value set) and it executes one basic block at a time (so no loop is ever
//! unrolled). We execute whole functions, so a loop that runs ten thousand
//! times would otherwise contribute ten thousand induction values.

use std::collections::{BTreeSet, HashMap};

use super::fingerprint::normalize;
use super::harvest::{Harvest, ValueContext};
use super::seeds::{ADDRESS_FLOOR, STACK_BASE, STACK_EPSILON};

/// Why values were dropped, so a measurement can say how much the filter did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FilterCounts {
    /// Observations seen.
    pub seen: usize,
    /// F6: width-1 (flag) values.
    pub flags: usize,
    /// F4: the value is an address the run formed.
    pub address_set: usize,
    /// F1/F2: the value lies inside the image's mapped memory.
    pub mapped: usize,
    /// F3: the value is within `STACK_EPSILON` of the stack pointer.
    pub stack: usize,
    /// F7: the instruction site had already contributed its quota.
    pub site_cap: usize,
    /// Values that survived every rule.
    pub kept: usize,
}

impl FilterCounts {
    /// Add another run's counts.
    pub fn merge(&mut self, other: FilterCounts) {
        self.seen += other.seen;
        self.flags += other.flags;
        self.address_set += other.address_set;
        self.mapped += other.mapped;
        self.stack += other.stack;
        self.site_cap += other.site_cap;
        self.kept += other.kept;
    }

    /// Values removed by the three address rules the `filter` setting gates.
    pub fn addresses_removed(&self) -> usize {
        self.address_set + self.mapped + self.stack
    }
}

/// Is `value` inside the image's mapped memory, above the low-address guard?
///
/// The guard is the whole reason this is a function rather than a call to
/// `memory_kind_at`; see [`ADDRESS_FLOOR`] for why a shared object makes the
/// unguarded rule delete every small constant.
pub fn is_image_address(context: &ValueContext<'_>, value: u64) -> bool {
    value >= ADDRESS_FLOOR && (context.is_mapped_address)(value)
}

/// Is `value` within the stack window?
pub fn is_stack_address(value: u64) -> bool {
    value.abs_diff(STACK_BASE) <= STACK_EPSILON
}

/// Apply every rule to one run's observations, returning the surviving
/// normalised values in the order they were produced.
pub fn filter_run(harvest: &Harvest, context: &ValueContext<'_>) -> (Vec<u64>, FilterCounts) {
    let settings = context.settings;
    let cap = usize::from(settings.site_cap_used());
    let mut counts = FilterCounts::default();
    let mut per_site: HashMap<u64, BTreeSet<u64>> = HashMap::new();
    let mut kept = Vec::with_capacity(harvest.observations.len());

    for observation in &harvest.observations {
        counts.seen += 1;

        // F6: a flag is 0 or 1 and says nothing on its own. Branch conditions
        // are a separate element class; see `super::branch`.
        if observation.width.bits() <= 1 {
            counts.flags += 1;
            continue;
        }

        if settings.filter {
            if harvest.addresses.contains(&observation.raw) {
                counts.address_set += 1;
                continue;
            }
            if is_image_address(context, observation.raw) {
                counts.mapped += 1;
                continue;
            }
            if is_stack_address(observation.raw) {
                counts.stack += 1;
                continue;
            }
        }

        let value = normalize(observation.raw, observation.width);
        let seen_here = per_site.entry(observation.site).or_default();
        if !seen_here.contains(&value) && seen_here.len() >= cap {
            counts.site_cap += 1;
            continue;
        }
        seen_here.insert(value);
        counts.kept += 1;
        kept.push(value);
    }

    (kept, counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::values::harvest::{bare_context, Observation, RunOutcome};
    use crate::identity::values::settings::ValueSettings;
    use crate::ir::types::Width;

    fn harvest_of(observations: Vec<Observation>, addresses: &[u64]) -> Harvest {
        Harvest {
            observations,
            addresses: addresses.iter().copied().collect(),
            outcome: RunOutcome::Returned,
            steps: 0,
        }
    }

    fn observation(site: u64, raw: u64, width: Width) -> Observation {
        Observation { site, raw, width }
    }

    #[test]
    fn a_value_used_as_an_address_is_dropped() {
        let context = bare_context(ValueSettings::default());
        let harvest = harvest_of(
            vec![
                observation(0x10, 0x4_2000, Width::W64),
                observation(0x14, 99, Width::W64),
            ],
            &[0x4_2000],
        );
        let (kept, counts) = filter_run(&harvest, &context);
        assert_eq!(kept, vec![99]);
        assert_eq!(counts.address_set, 1);
    }

    #[test]
    fn a_stack_address_is_dropped_and_a_far_value_is_not() {
        let context = bare_context(ValueSettings::default());
        let harvest = harvest_of(
            vec![
                observation(0x10, STACK_BASE - 0x18, Width::W64),
                observation(0x14, STACK_BASE - (STACK_EPSILON * 4), Width::W64),
            ],
            &[],
        );
        let (kept, counts) = filter_run(&harvest, &context);
        assert_eq!(counts.stack, 1);
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn the_low_address_guard_saves_small_constants_from_a_shared_object() {
        let mapped = |address: u64| address < 0x5000;
        let mut context = bare_context(ValueSettings::default());
        context.is_mapped_address = &mapped;
        let harvest = harvest_of(
            vec![
                observation(0x10, 0, Width::W32),
                observation(0x14, 1, Width::W32),
                observation(0x18, 0x2000, Width::W64),
            ],
            &[],
        );
        let (kept, counts) = filter_run(&harvest, &context);
        // Every one of these lies inside the "image", and none of them reaches
        // ADDRESS_FLOOR, so none is filtered.
        assert_eq!(counts.mapped, 0);
        assert_eq!(kept, vec![0, 1, 0x2000]);
    }

    #[test]
    fn a_high_mapped_address_is_still_filtered() {
        let mapped = |address: u64| (0x40_0000..0x50_0000).contains(&address);
        let mut context = bare_context(ValueSettings::default());
        context.is_mapped_address = &mapped;
        let harvest = harvest_of(vec![observation(0x10, 0x40_1234, Width::W64)], &[]);
        let (kept, counts) = filter_run(&harvest, &context);
        assert_eq!(counts.mapped, 1);
        assert!(kept.is_empty());
    }

    #[test]
    fn turning_the_filter_off_keeps_what_it_would_have_removed() {
        let mut settings = ValueSettings::default();
        settings.filter = false;
        let context = bare_context(settings);
        let harvest = harvest_of(
            vec![
                observation(0x10, 0x4_2000, Width::W64),
                observation(0x14, STACK_BASE - 0x18, Width::W64),
            ],
            &[0x4_2000],
        );
        let (kept, counts) = filter_run(&harvest, &context);
        assert_eq!(kept.len(), 2);
        assert_eq!(counts.addresses_removed(), 0);
    }

    #[test]
    fn flags_never_reach_the_value_set() {
        let context = bare_context(ValueSettings::default());
        let harvest = harvest_of(
            vec![
                observation(0x10, 1, Width::W1),
                observation(0x14, 0, Width::W1),
            ],
            &[],
        );
        let (kept, counts) = filter_run(&harvest, &context);
        assert!(kept.is_empty());
        assert_eq!(counts.flags, 2);
    }

    #[test]
    fn one_site_contributes_at_most_the_cap_distinct_values() {
        let settings = ValueSettings {
            site_cap: 2,
            ..ValueSettings::default()
        };
        let context = bare_context(settings);
        let harvest = harvest_of(
            (0..10)
                .map(|i| observation(0x100, 1000 + i, Width::W64))
                .collect(),
            &[],
        );
        let (kept, counts) = filter_run(&harvest, &context);
        assert_eq!(kept, vec![1000, 1001]);
        assert_eq!(counts.site_cap, 8);
    }

    #[test]
    fn the_cap_counts_distinct_values_not_occurrences() {
        let settings = ValueSettings {
            site_cap: 2,
            ..ValueSettings::default()
        };
        let context = bare_context(settings);
        let harvest = harvest_of(
            (0..6).map(|_| observation(0x100, 7, Width::W64)).collect(),
            &[],
        );
        let (kept, _) = filter_run(&harvest, &context);
        assert_eq!(kept, vec![7; 6], "a repeated value is not capped away");
    }
}
