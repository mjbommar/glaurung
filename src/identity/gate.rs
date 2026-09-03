//! A BinaryFuse8 membership gate over known function identities.
//!
//! Item 7 of the identity ladder's execution plan
//! (`docs/history/program-measures-2026-09-02.md`): "is this identity in
//! ANY known library?" -- answered in ~3 ns with ~1.1 bytes/key, so a
//! negative can be returned before any exact-equality or masked-prefix
//! lookup runs. `docs/history/program-measures-2026-09-02/03-schema.sql`
//! section 7's `identity_filter` table holds exactly the serialized bytes
//! this module produces, one row per `(scheme, architecture)`.
//!
//! A binary fuse filter is a probabilistic set: **no false negatives, ever**
//! (the two schemes producing identities today, WARP GUIDs and FLIRT masked
//! patterns, are both correct to reject on a gate miss), and a small,
//! measured false-positive rate on a gate hit -- a hit means "go do the real
//! lookup", not "this is a match".
//!
//! # The determinism trap this module exists to avoid
//!
//! `xorf`'s default features include `uniform-random`, which fills the
//! filter's unused fingerprint slots from `rand::thread_rng()` rather than
//! zero. That is a real design choice upstream (a zero-filled slot raises
//! the false-positive rate for any key whose fingerprint happens to hash to
//! zero) -- but it means two builds over the *same* key set produce
//! *different bytes*, which is fatal to committing a filter to a project
//! file and diffing it, or to the "two builds are byte-identical" property
//! this module's tests assert. `Cargo.toml` disables `uniform-random`
//! (`default-features = false, features = ["binary-fuse", "serde"]`), which
//! zero-fills instead. The filter's own construction (`splitmix64` seeded
//! from a fixed `rng = 1`) was already deterministic; this was the one
//! non-deterministic input left.
//!
//! # Zero-copy loads
//!
//! [`IdentityGate::to_bytes`] and [`IdentityGateRef::from_bytes`] use xorf's
//! `DmaSerializable`/`FilterRef` split: a small fixed-length descriptor
//! (20 bytes: an 8-byte seed and three `u32`s) is copied, and the
//! fingerprint bytes -- the part that scales with key count, ~9 bits/key --
//! are referenced directly from the caller's buffer (an `mmap`, a `BLOB`
//! read into a `Vec<u8>` the caller keeps alive). No fingerprint byte is
//! copied or re-parsed on load.

use xorf::{BinaryFuse8, BinaryFuse8Ref, DmaSerializable, Filter, FilterRef};

/// The `identity_filter.kind` value this module produces.
pub const KIND: &str = "binary-fuse-8";

/// Length, in bytes, of the fixed-size header this module prepends to the
/// xorf descriptor: one little-endian `u64` recording how many keys the
/// filter was built from (`n_keys`, so `identity_filter.n_keys` can be read
/// back out of the blob itself rather than only from its own column).
const HEADER_LEN: usize = 8;

/// Length, in bytes, of the xorf `BinaryFuse8` descriptor: an 8-byte seed
/// plus three `u32` layout fields. Small, fixed, and — unlike the
/// fingerprints — parsed into owned fields on load rather than referenced.
const DESCRIPTOR_LEN: usize = <BinaryFuse8 as DmaSerializable>::DESCRIPTOR_LEN;

/// Deterministically map an identity string to the `u64` key a binary fuse
/// filter is built over.
///
/// BLAKE3 rather than `std::hash::Hash` / `SipHash`: the standard library's
/// hasher is seeded per-process by default (`RandomState`), which is exactly
/// the non-determinism this module exists to avoid, and BLAKE3 is already a
/// project dependency (`crate::similarity`). Truncating to the first 8 bytes
/// of a cryptographic hash gives a uniform 64-bit key regardless of the
/// identity string's own structure (a UUID's hyphens, a hex pattern's fixed
/// alphabet), which is what the filter's construction assumes.
pub fn identity_key(identity: &str) -> u64 {
    let digest = blake3::hash(identity.as_bytes());
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(buf)
}

/// An error building a gate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GateError {
    /// A gate over zero keys is a meaningless "reject everything" answer that
    /// looks exactly like an empty library rather than a bug in the caller.
    #[error("cannot build an identity gate over zero identities")]
    Empty,
    /// `xorf`'s own construction failure, most commonly a `u64` key collision
    /// after hashing two distinct identity strings to the same value —
    /// astronomically unlikely at any corpus size this project will reach,
    /// but xorf checks it in debug builds regardless of key source.
    #[error("binary fuse construction failed: {0}")]
    Construction(&'static str),
    /// The byte blob is shorter than the fixed header, so it cannot be a
    /// filter this module wrote.
    #[error("identity gate blob is truncated: {0} bytes, need at least {1}")]
    Truncated(usize, usize),
}

/// Probe counters for one gate's lifetime of use.
///
/// The gate's entire value proposition is "a negative is definitive", so the
/// number that matters operationally is how many probes it definitively
/// answered before any index lookup ran. Kept as a plain counter rather than
/// atomics: a gate is consulted from one matching pass at a time (per
/// `(scheme, architecture)`), not shared across threads.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct GateStats {
    /// Every call to a `*_counted` probe.
    pub probes: u64,
    /// Probes the gate answered `false` — a lookup it made unnecessary.
    pub negatives: u64,
}

impl GateStats {
    /// Record one probe's outcome.
    pub fn record(&mut self, present: bool) {
        self.probes += 1;
        if !present {
            self.negatives += 1;
        }
    }

    /// Fraction of probes the gate rejected outright, in `[0.0, 1.0]`.
    /// `0.0` on zero probes rather than `NaN` — "no data" and "no rejections
    /// observed" should not need different callers.
    pub fn negative_rate(&self) -> f64 {
        if self.probes == 0 {
            0.0
        } else {
            self.negatives as f64 / self.probes as f64
        }
    }
}

/// An owned BinaryFuse8 gate over a set of identity strings.
///
/// Built once from every identity in one `(scheme, architecture)` — for a
/// library, every `siglib_function.identity` row; for a corpus survey, every
/// computed function identity. Query with [`Self::contains`] or
/// [`Self::contains_counted`]; serialize with [`Self::to_bytes`] for the
/// `identity_filter.filter` BLOB.
pub struct IdentityGate {
    filter: BinaryFuse8,
    n_keys: usize,
}

impl IdentityGate {
    /// Build a gate from a set of identity strings.
    ///
    /// Duplicate identity strings are removed before construction: xorf's
    /// binary fuse filters fail to build over duplicate *keys*, and two equal
    /// identity strings hash to the same key by construction. This is a
    /// `Vec`-and-sort dedupe rather than a `HashSet`, so the result — and
    /// therefore [`Self::to_bytes`] — does not depend on the iteration order
    /// `identities` arrives in.
    pub fn build<I, S>(identities: I) -> Result<Self, GateError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut keys: Vec<u64> = identities
            .into_iter()
            .map(|s| identity_key(s.as_ref()))
            .collect();
        keys.sort_unstable();
        keys.dedup();
        if keys.is_empty() {
            return Err(GateError::Empty);
        }
        let n_keys = keys.len();
        let filter = BinaryFuse8::try_from(&keys).map_err(GateError::Construction)?;
        Ok(Self { filter, n_keys })
    }

    /// Is `identity` possibly a member? `false` is definitive; `true` means
    /// "go do the real lookup".
    pub fn contains(&self, identity: &str) -> bool {
        self.filter.contains(&identity_key(identity))
    }

    /// [`Self::contains`], recording the outcome in `stats`.
    pub fn contains_counted(&self, identity: &str, stats: &mut GateStats) -> bool {
        let present = self.contains(identity);
        stats.record(present);
        present
    }

    /// How many distinct identities this gate was built from.
    pub fn n_keys(&self) -> usize {
        self.n_keys
    }

    /// Measured bits per key: `8 * fingerprint_bytes / n_keys`. BinaryFuse8's
    /// published figure is ≈9 bits/key; this is what *this* gate actually
    /// used, which is what a docs page should quote rather than the paper's
    /// number.
    pub fn bits_per_key(&self) -> f64 {
        (self.filter.len() as f64) * 8.0 / (self.n_keys as f64)
    }

    /// Serialize to a self-describing byte blob: an 8-byte key count, the
    /// xorf descriptor, then the fingerprint bytes. This is exactly the value
    /// `identity_filter.filter` stores; [`IdentityGateRef::from_bytes`] reads
    /// it back with the fingerprints borrowed rather than copied.
    pub fn to_bytes(&self) -> Vec<u8> {
        let fingerprints = self.filter.dma_fingerprints();
        let mut out = Vec::with_capacity(HEADER_LEN + DESCRIPTOR_LEN + fingerprints.len());
        out.extend_from_slice(&(self.n_keys as u64).to_le_bytes());
        let descriptor_start = out.len();
        out.resize(descriptor_start + DESCRIPTOR_LEN, 0);
        self.filter
            .dma_copy_descriptor_to(&mut out[descriptor_start..]);
        out.extend_from_slice(fingerprints);
        out
    }
}

/// A zero-copy view of a serialized [`IdentityGate`].
///
/// Borrows its fingerprint bytes from whatever buffer `bytes` came from (a
/// `BLOB` column read into a `Vec<u8>`, an `mmap`); nothing beyond the small
/// fixed descriptor is copied or reparsed.
pub struct IdentityGateRef<'a> {
    filter: BinaryFuse8Ref<'a>,
    n_keys: usize,
}

impl<'a> IdentityGateRef<'a> {
    /// Parse [`IdentityGate::to_bytes`]'s format without copying the
    /// fingerprint bytes.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, GateError> {
        let min_len = HEADER_LEN + DESCRIPTOR_LEN;
        if bytes.len() < min_len {
            return Err(GateError::Truncated(bytes.len(), min_len));
        }
        let mut n_keys_buf = [0u8; HEADER_LEN];
        n_keys_buf.copy_from_slice(&bytes[..HEADER_LEN]);
        let n_keys = u64::from_le_bytes(n_keys_buf) as usize;
        let descriptor = &bytes[HEADER_LEN..HEADER_LEN + DESCRIPTOR_LEN];
        let fingerprints = &bytes[HEADER_LEN + DESCRIPTOR_LEN..];
        let filter = BinaryFuse8Ref::from_dma(descriptor, fingerprints);
        Ok(Self { filter, n_keys })
    }

    /// Is `identity` possibly a member? `false` is definitive.
    pub fn contains(&self, identity: &str) -> bool {
        self.filter.contains(&identity_key(identity))
    }

    /// [`Self::contains`], recording the outcome in `stats`.
    pub fn contains_counted(&self, identity: &str, stats: &mut GateStats) -> bool {
        let present = self.contains(identity);
        stats.record(present);
        present
    }

    /// The key count recorded at build time (from the blob header, not
    /// recomputed).
    pub fn n_keys(&self) -> usize {
        self.n_keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random `u64`s via `splitmix64`, so this module's
    /// tests need no `rand` dependency and are reproducible without a seed
    /// column anywhere. Same generator xorf itself uses internally.
    fn splitmix64_stream(mut seed: u64) -> impl FnMut() -> u64 {
        move || {
            seed = seed.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
    }

    fn synthetic_identities(n: usize, seed: u64) -> Vec<String> {
        let mut next = splitmix64_stream(seed);
        (0..n).map(|_| format!("{:032x}", next())).collect()
    }

    #[test]
    fn a_gate_over_no_identities_is_refused() {
        let empty: Vec<String> = Vec::new();
        assert!(matches!(IdentityGate::build(empty), Err(GateError::Empty)));
    }

    #[test]
    fn every_inserted_key_is_a_member_no_false_negatives() {
        // >= 1e5 keys, per the deliverable: measure at real scale, not a
        // handful that would hide a construction bug.
        let identities = synthetic_identities(150_000, 1);
        let gate = IdentityGate::build(&identities).unwrap();
        for id in &identities {
            assert!(gate.contains(id), "false negative on {id}");
        }
    }

    /// The measured false-positive rate and bits/key, printed so a docs page
    /// can quote the actual run rather than the paper's number.
    #[test]
    fn measured_bits_per_key_and_false_positive_rate() {
        let identities = synthetic_identities(150_000, 2);
        let gate = IdentityGate::build(&identities).unwrap();

        let bpk = gate.bits_per_key();
        // xorf's own published ceiling is ~9.1 bits/key; leave meaningful
        // headroom above it so this is a real ratchet, not a hair-trigger.
        assert!(bpk < 10.5, "bits/key too high: {bpk}");

        // Disjoint query set: a different seed than the inserted set, so
        // collisions with `synthetic_identities(150_000, 2)` are the false
        // positives being measured, not a resampling of true members.
        let queries = synthetic_identities(150_000, 3);
        let false_positives = queries.iter().filter(|q| gate.contains(q)).count();
        let fpr = false_positives as f64 / queries.len() as f64;
        // BinaryFuse8's published ceiling is <0.4%; assert well above it.
        assert!(fpr < 0.02, "false positive rate too high: {fpr}");

        let n_keys = gate.n_keys();
        eprintln!("identity_gate: n_keys={n_keys} bits_per_key={bpk:.3} fpr={fpr:.5}");
    }

    #[test]
    fn two_builds_over_the_same_keys_are_byte_identical() {
        // The determinism trap this module exists to avoid: with
        // `uniform-random` off, unused fingerprint slots are zero-filled
        // rather than drawn from a thread-local RNG, so rebuilding from the
        // same key set — even reordered — must produce identical bytes.
        let mut identities = synthetic_identities(120_000, 4);
        let a = IdentityGate::build(&identities).unwrap().to_bytes();
        identities.reverse();
        let b = IdentityGate::build(&identities).unwrap().to_bytes();
        assert_eq!(
            a, b,
            "two builds over the same key set produced different bytes"
        );
    }

    #[test]
    fn duplicate_identities_are_deduplicated_before_construction() {
        let mut identities = synthetic_identities(1_000, 5);
        let unique_len = identities.len();
        identities.extend(identities.clone());
        let gate = IdentityGate::build(&identities).unwrap();
        assert_eq!(gate.n_keys(), unique_len);
    }

    #[test]
    fn a_zero_copy_view_round_trips() {
        let identities = synthetic_identities(10_000, 6);
        let gate = IdentityGate::build(&identities).unwrap();
        let bytes = gate.to_bytes();
        let view = IdentityGateRef::from_bytes(&bytes).unwrap();
        assert_eq!(view.n_keys(), gate.n_keys());
        for id in &identities {
            assert!(view.contains(id));
        }
        // The view must agree with the owned filter on rejections too, not
        // merely on the same set of hits by coincidence.
        let unrelated = synthetic_identities(1_000, 7);
        for id in &unrelated {
            assert_eq!(gate.contains(id), view.contains(id));
        }
    }

    #[test]
    fn a_truncated_blob_is_rejected_rather_than_panicking() {
        let identities = synthetic_identities(1_000, 8);
        let gate = IdentityGate::build(&identities).unwrap();
        let bytes = gate.to_bytes();
        // Shorter than the fixed header + descriptor (28 bytes): there is no
        // fingerprint length this module can validate on its own (xorf does
        // not record one), so the contract this module can actually keep is
        // "the fixed prefix must be present", and that is what is tested.
        let truncated = &bytes[..HEADER_LEN + DESCRIPTOR_LEN - 1];
        assert!(matches!(
            IdentityGateRef::from_bytes(truncated),
            Err(GateError::Truncated(_, _))
        ));
    }

    #[test]
    fn gate_stats_count_probes_and_negatives() {
        let identities = synthetic_identities(100, 9);
        let gate = IdentityGate::build(&identities).unwrap();
        let mut stats = GateStats::default();
        for id in &identities {
            gate.contains_counted(id, &mut stats);
        }
        assert_eq!(stats.probes, 100);
        assert_eq!(stats.negatives, 0);
        assert_eq!(stats.negative_rate(), 0.0);

        // A key that was never inserted: an fp-rate's worth of `true`s is
        // possible but vanishingly unlikely on one probe over a 100-key
        // gate, so this should be a clean negative.
        let miss = "definitely-not-in-the-set";
        gate.contains_counted(miss, &mut stats);
        assert_eq!(stats.probes, 101);
        assert_eq!(stats.negatives, 1);
    }

    #[test]
    fn identity_key_is_deterministic_across_calls() {
        assert_eq!(
            identity_key("warp-guid-example"),
            identity_key("warp-guid-example")
        );
        assert_ne!(identity_key("a"), identity_key("b"));
    }
}
