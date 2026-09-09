//! Portable instruction-decoding primitives for Glaurung.
//!
//! This crate deliberately has no allocator, operating-system, C, or Python
//! dependency. ISA decoders live here; the main Glaurung crate adapts their
//! compact results into its richer analysis model.

#![no_std]
#![forbid(unsafe_code)]

pub mod aarch64;
pub mod aarch64_sysregs;

/// Sign-extend `width` low bits of `value` and apply a power-of-two scale.
pub const fn sign_extend_scaled(value: u64, width: u32, scale: u32) -> i64 {
    debug_assert!(width > 0 && width <= 64);
    debug_assert!(scale < 64 && width + scale <= 64);
    let shift = 64 - width;
    (((value << shift) as i64) >> shift) << scale
}

#[cfg(test)]
mod tests {
    use super::sign_extend_scaled;

    #[test]
    fn signed_scaled_boundaries() {
        assert_eq!(sign_extend_scaled(0x1, 26, 2), 4);
        assert_eq!(sign_extend_scaled(0x3ff_ffff, 26, 2), -4);
        assert_eq!(sign_extend_scaled(0x200_0000, 26, 2), -134_217_728);
        assert_eq!(sign_extend_scaled(0x1fff, 14, 2), 32_764);
        assert_eq!(sign_extend_scaled(0x2000, 14, 2), -32_768);
    }
}
