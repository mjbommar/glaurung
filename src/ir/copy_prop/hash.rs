//! The hasher this pass's register-keyed maps use.
//!
//! Every map and set in `copy_prop` is keyed by a [`VReg`], and a
//! `VReg::Phys` is a short ISA or slot name — `"rax"`, `"local_18"`, `"t41"`.
//! Hashing those with the standard library's default (SipHash-1-3 under a
//! per-process random key) was **a third of the pass's instruction count on an
//! ordinary function**: measured on the `112_nontail_depth` fixture through
//! `benches/ir_dataflow.rs`, `sip::Hasher::write` plus the two `VReg` hashing
//! shims came to 282M of 852M instructions. The environment is looked up once
//! per register occurrence and rebuilt several times per call, so the hash is
//! the pass's inner loop.
//!
//! [`FxHasher`] is the multiply-xor-rotate hash `rustc` uses for its own
//! name-keyed tables. It is not collision-resistant and must never be reached
//! by attacker-chosen keys; these keys are register names produced by our own
//! lifter, and the maps live and die inside one call.
//!
//! # This cannot change the recovered output
//!
//! Swapping a hasher changes map *iteration order*, so it would matter if any
//! decision in this pass read one. None does — every map here is consulted by
//! `get`/`contains`, and the two sets that are iterated
//! (`prune_unobservable_scratch_dataflow`'s liveness frontier and
//! `copies_stable_across_loop`'s write set) compute an order-independent
//! closure and an order-independent union. The property is also *tested*
//! rather than argued: the standard library's `RandomState` is seeded per
//! process, so an iteration order that reached the output would already make
//! separate runs disagree, and
//! `python/tests/test_decompile_determinism.py` asserts byte-identical
//! decompilation across separate sequential processes.

use std::hash::{BuildHasherDefault, Hasher};

use crate::ir::types::VReg;

/// A [`std::collections::HashMap`] keyed by a register name.
pub(super) type RegMap<V> = std::collections::HashMap<VReg, V, BuildHasherDefault<FxHasher>>;

/// A [`std::collections::HashSet`] of register names.
pub(super) type RegSet = std::collections::HashSet<VReg, BuildHasherDefault<FxHasher>>;

/// The odd 64-bit constant `rustc-hash` multiplies by; the fractional bits of
/// the golden ratio.
const SEED: u64 = 0x517c_c1b7_2722_0a95;

/// `rustc`'s `FxHasher`: rotate, xor in the next word, multiply.
#[derive(Default, Clone, Copy)]
pub(super) struct FxHasher {
    hash: u64,
}

impl FxHasher {
    #[inline]
    fn add_to_hash(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(SEED);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut rest = bytes;
        while let Some((head, tail)) = rest.split_first_chunk::<8>() {
            self.add_to_hash(u64::from_ne_bytes(*head));
            rest = tail;
        }
        if let Some((head, tail)) = rest.split_first_chunk::<4>() {
            self.add_to_hash(u64::from(u32::from_ne_bytes(*head)));
            rest = tail;
        }
        if let Some((head, tail)) = rest.split_first_chunk::<2>() {
            self.add_to_hash(u64::from(u16::from_ne_bytes(*head)));
            rest = tail;
        }
        if let Some(byte) = rest.first() {
            self.add_to_hash(u64::from(*byte));
        }
    }

    #[inline]
    fn write_u8(&mut self, value: u8) {
        self.add_to_hash(u64::from(value));
    }

    #[inline]
    fn write_u16(&mut self, value: u16) {
        self.add_to_hash(u64::from(value));
    }

    #[inline]
    fn write_u32(&mut self, value: u32) {
        self.add_to_hash(u64::from(value));
    }

    #[inline]
    fn write_u64(&mut self, value: u64) {
        self.add_to_hash(value);
    }

    #[inline]
    fn write_usize(&mut self, value: usize) {
        self.add_to_hash(value as u64);
    }

    /// A final avalanche, which plain `rustc-hash` v1 does not do.
    ///
    /// `hashbrown` indexes its buckets with the LOW bits of the hash, and the
    /// multiply-xor-rotate loop leaves those weaker than the high ones: over
    /// 256 names of the form `local_N` the raw hash reached 176 of 512 buckets
    /// where a uniform hash reaches ~201. `splitmix64`'s finalizer costs three
    /// instructions and closes the gap; see the test below, which is what
    /// caught it.
    #[inline]
    fn finish(&self) -> u64 {
        let mut hash = self.hash;
        hash ^= hash >> 32;
        hash = hash.wrapping_mul(0xd6e8_feb8_6659_fd93);
        hash ^= hash >> 32;
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Equal keys must hash equally; the maps below would otherwise lose
    /// entries rather than merely slow down.
    #[test]
    fn equal_registers_hash_equally() {
        let mut map: RegMap<usize> = RegMap::default();
        map.insert(VReg::phys("local_18"), 7);
        assert_eq!(map.get(&VReg::phys("local_18")).copied(), Some(7));
        assert_eq!(map.get(&VReg::phys("local_19")).copied(), None);
        assert_eq!(map.get(&VReg::Temp(18)).copied(), None);
    }

    /// A weak hash is still a hash: distinct short register names must not all
    /// land in one bucket, or every lookup degrades to a linear scan.
    #[test]
    fn short_register_names_spread_across_buckets() {
        let names: Vec<VReg> = (0..256).map(|i| VReg::phys(format!("local_{i}"))).collect();
        let mut buckets = std::collections::HashSet::new();
        for name in &names {
            let mut hasher = FxHasher::default();
            std::hash::Hash::hash(name, &mut hasher);
            buckets.insert(hasher.finish() % 512);
        }
        // A uniform hash reaches ~201 of 512 buckets with 256 keys
        // (512 * (1 - (1 - 1/512)^256)); this asserts we are near that, not at
        // the pile-up a bad low-bit distribution produces.
        assert!(
            buckets.len() > 190,
            "256 distinct names collapsed into {} of 512 buckets",
            buckets.len()
        );
    }
}
