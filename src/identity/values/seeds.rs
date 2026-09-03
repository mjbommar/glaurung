//! The fixed initial states, and the constants the address filters key on.
//!
//! # Why the initial state is fixed and documented rather than random
//!
//! An identity that depends on a random draw is not an identity. Every scalar
//! below is a constant in this file; nothing here reads a clock, a PID, a
//! `RandomState` or an environment variable, and two runs of the same function
//! on the same bytes therefore produce the same multiset. vSim's trial array is
//! "randomly generated" once and then fixed for the life of the tool; ours is
//! written down.
//!
//! # Where the numbers come from
//!
//! [`FRESH_SCALARS`] is vSim's own published trial array
//! (`A = [57, 44, 13, 81, 52]`, NDSS 2026 section III-D). Keeping it buys two
//! things: the values are small enough that arithmetic on them stays small
//! (so a product does not wander into an address range and get filtered), and
//! a reader who has the paper open can follow the worked example straight
//! through.

/// The trial values an uninitialised read produces, one per seed.
///
/// vSim's array verbatim. [`crate::identity::values::ValueSettings::seeds`]
/// takes a prefix of it.
pub const FRESH_SCALARS: [u64; 5] = [57, 44, 13, 81, 52];

/// The concrete stack pointer every run starts from.
///
/// Concretising the stack and base pointers before an under-constrained run is
/// the standard practice vSim cites: it removes the need to reason about stack
/// layout symbolically, and it is what makes rule F3 (a value near the stack
/// pointer is a local's address) computable at all. The value is deliberately
/// far above anything an image maps and far above anything arithmetic on
/// [`FRESH_SCALARS`] can reach.
pub const STACK_BASE: u64 = 0x7fff_0000_0000;

/// How far from [`STACK_BASE`] a value is still considered a stack address.
///
/// vSim calls this the "configurable stack size threshold" and suggests 1 GiB
/// for 64-bit binaries, sized for a real process whose stack pointer it did
/// not choose. We choose the stack pointer, so the window can be the largest
/// frame anything plausible allocates rather than the largest stack anything
/// plausible has: 1 MiB either side.
pub const STACK_EPSILON: u64 = 1 << 20;

/// Below this, a value is never treated as an image address by rules F1/F2.
///
/// **This is a deliberate deviation from vSim, and it matters.** vSim's HC1
/// and HC2 filter any value that falls inside a mapped data or executable
/// section. Its corpus is non-PIE executables based at `0x400000`, so the rule
/// never touches a small integer. Half of ours are x86-64 *shared objects*
/// whose entire image maps below `0x10000`, and there the unguarded rule
/// deletes `0`, `1`, `-1`, every structure size and every loop bound -- which
/// is precisely the population vSim's ablation says carries the most signal.
/// The floor is the conventional low-address guard (`vm.mmap_min_addr` ships
/// at 65536 on Linux): nothing a loader will map a real object over, and above
/// every constant a compiler emits as an immediate in practice.
///
/// The cost is stated rather than hidden: on a shared object whose image lies
/// entirely below the floor, F1 and F2 contribute nothing and the filter is
/// carried by F3 (stack) and F4 (used as an address). On a based executable
/// all four fire.
pub const ADDRESS_FLOOR: u64 = 0x1_0000;

/// The x86-64 general-purpose registers seeded before a run.
///
/// `rsp` and `rbp` are absent on purpose: they are set to [`STACK_BASE`], not
/// to a trial value. `rip` is not a register the LLIR reads.
pub const SEEDED_X86_64_REGISTERS: [&str; 14] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
];

/// SplitMix64. The mixing step for every derived constant in this module.
///
/// A named, self-contained finalizer rather than `DefaultHasher`, because
/// `DefaultHasher`'s output is explicitly not guaranteed stable across Rust
/// releases and a fingerprint that changes when the toolchain changes is not a
/// fingerprint.
pub fn mix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

/// A stable 64-bit hash of a byte string, built from [`mix64`].
pub fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut accumulator = 0xCBF2_9CE4_8422_2325u64;
    for byte in bytes {
        accumulator = mix64(accumulator ^ u64::from(*byte));
    }
    accumulator
}

/// The value an uninitialised read produces under `seed`.
///
/// With `role` empty (the uniform policy, the default) every fresh read in one
/// run yields the same scalar. With a role name (the `role_seeds` policy) the
/// scalar is perturbed by the role, staying inside a small window so the
/// "arithmetic stays small" property survives.
pub fn fresh_value(seed: u8, role: Option<&str>) -> u64 {
    let base = FRESH_SCALARS[usize::from(seed) % FRESH_SCALARS.len()];
    match role {
        None => base,
        Some(role) => {
            // A small, deterministic offset: still far below ADDRESS_FLOOR, so
            // a role-keyed scalar cannot be mistaken for an image address.
            base + 1 + (hash_bytes(role.as_bytes()) % 512)
        }
    }
}

/// The value written into the return register for a call the interpreter does
/// not execute into.
///
/// Derived from the callee's identity so that two builds calling `memcpy` see
/// the same number and two builds calling different externals do not. Placed
/// in a high, unmapped band: far from any image, far from [`STACK_BASE`], and
/// unreachable by arithmetic on [`FRESH_SCALARS`], so it survives every filter
/// unless the program actually dereferences it -- which is exactly vSim's
/// treatment of a `malloc` return (added to the address set, then filtered).
pub fn callee_sentinel(seed: u8, callee: &str) -> u64 {
    const BAND: u64 = 0x00C0_DE00_0000_0000;
    let mixed = mix64(hash_bytes(callee.as_bytes()) ^ mix64(u64::from(seed)));
    BAND | (mixed & 0x0000_00FF_FFFF_FFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_trial_array_is_the_published_one() {
        assert_eq!(FRESH_SCALARS, [57, 44, 13, 81, 52]);
    }

    #[test]
    fn seed_scalars_stay_below_the_address_floor_under_both_policies() {
        for seed in 0..5u8 {
            assert!(fresh_value(seed, None) < ADDRESS_FLOOR);
            for role in SEEDED_X86_64_REGISTERS {
                assert!(fresh_value(seed, Some(role)) < ADDRESS_FLOOR);
            }
        }
    }

    #[test]
    fn role_seeds_separate_the_registers() {
        let mut seen = std::collections::BTreeSet::new();
        for role in SEEDED_X86_64_REGISTERS {
            seen.insert(fresh_value(0, Some(role)));
        }
        // Not a guarantee of injectivity -- 512 slots and 14 registers -- but a
        // collapse to one value would silently undo the whole policy.
        assert!(seen.len() >= 12, "role seeding collapsed to {seen:?}");
    }

    #[test]
    fn callee_sentinels_are_stable_high_and_callee_specific() {
        let a = callee_sentinel(0, "memcpy");
        assert_eq!(a, callee_sentinel(0, "memcpy"));
        assert_ne!(a, callee_sentinel(0, "strlen"));
        assert_ne!(a, callee_sentinel(1, "memcpy"));
        assert!(a > ADDRESS_FLOOR);
        assert!(a.abs_diff(STACK_BASE) > STACK_EPSILON);
    }

    #[test]
    fn the_mixer_is_pinned_not_borrowed_from_the_standard_library() {
        // Pinned digits: if these move, every stored fingerprint moves with
        // them and the major version has to move too.
        assert_eq!(mix64(0), 0xE220_A839_7B1D_CDAF);
        assert_eq!(hash_bytes(b"memcpy"), hash_bytes(b"memcpy"));
        assert_ne!(hash_bytes(b"memcpy"), hash_bytes(b"memcmp"));
    }
}
