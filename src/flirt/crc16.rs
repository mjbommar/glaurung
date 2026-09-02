//! The CRC16 that IDA's FLIRT uses, and only that one.
//!
//! FLIRT stores, next to each 32-byte pattern, a CRC over the bytes that
//! follow it up to the first variant byte. That second field is what stops a
//! pattern from being a 32-byte prefix match: two functions can share a
//! prologue and still differ two instructions later, and the CRC catches it
//! without storing (or redistributing) the library's bytes.
//!
//! The algorithm is not a standard CRC-16 preset. It is a reflected CCITT
//! (polynomial `0x8408`) with `0xFFFF` seeding, a final complement, and a
//! **byte swap** of the result, and the empty input is defined to be `0`
//! rather than the seed. Ported from Hex-Rays' `flair/crc16.cpp`; the same
//! reading is in `lancelot-flirt` 0.10.0 `src/lib.rs::crc16`. Every one of
//! those four details changes the value, so an "equivalent" CRC-16 from a
//! crate would silently fail to match any real signature.

/// Reflected CCITT polynomial, as `flair/crc16.cpp` spells it.
const POLY: u32 = 0x8408;

/// FLIRT's CRC16 over `buf`.
///
/// Returns `0` for empty input, which is FLIRT's own convention for "this
/// signature has no CRC" and is why [`super::FlirtSignature`] carries the
/// covered length separately rather than inferring it from a zero CRC.
pub fn crc16(buf: &[u8]) -> u16 {
    if buf.is_empty() {
        return 0;
    }
    let mut crc: u32 = 0xFFFF;
    for &byte in buf {
        let mut b = u32::from(byte);
        for _ in 0..8 {
            if ((crc ^ b) & 1) != 0 {
                crc = (crc >> 1) ^ POLY;
            } else {
                crc >>= 1;
            }
            b >>= 1;
        }
    }
    crc = !crc;
    let low = (crc & 0xFF) as u16;
    let high = ((crc >> 8) & 0xFF) as u16;
    (low << 8) | high
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The empty case is a convention, not an arithmetic result, and it is
    /// load-bearing: `crc_len == 0` means "no CRC recorded".
    #[test]
    fn the_empty_input_is_zero_by_convention() {
        assert_eq!(crc16(&[]), 0);
    }

    /// A real published FLIRT vector, not one of ours.
    ///
    /// `lancelot-flirt` 0.10.0's README carries a `.pat` signature for
    /// `__EH_prolog3_catch_align` -- `... 20 6562 0067 :0000 ...`, i.e. CRC
    /// length `0x20` and CRC `6562` -- together with the 103 bytes of
    /// `utcutil.dll` (SHA-256 `760789...61ac2`) that it matches. Hashing bytes
    /// `[32, 32+0x20)` of that buffer must give `0x6562`. Only IDA's exact
    /// variant does; a stock CRC-16/CCITT does not, which is the whole reason
    /// this file exists rather than a dependency.
    #[test]
    fn reproduces_a_published_flirt_signature_crc() {
        #[rustfmt::skip]
        const UTCUTIL_EH_PROLOG3_CATCH_ALIGN: [u8; 103] = [
            0x51, 0x8b, 0x4c, 0x24, 0x0c, 0x89, 0x5c, 0x24,
            0x0c, 0x8d, 0x5c, 0x24, 0x0c, 0x50, 0x8d, 0x44,
            0x24, 0x08, 0xf7, 0xd9, 0x23, 0xc1, 0x8d, 0x60,
            0xf8, 0x8b, 0x43, 0xf0, 0x89, 0x04, 0x24, 0x8b,
            0x43, 0xf8, 0x50, 0x8b, 0x43, 0xfc, 0x8b, 0x4b,
            0xf4, 0x89, 0x6c, 0x24, 0x0c, 0x8d, 0x6c, 0x24,
            0x0c, 0xc7, 0x44, 0x24, 0x08, 0xff, 0xff, 0xff,
            0xff, 0x51, 0x53, 0x2b, 0xe0, 0x56, 0x57, 0xa1,
            0x70, 0x14, 0x01, 0x10, 0x33, 0xc5, 0x50, 0x89,
            0x65, 0xf0, 0x8b, 0x43, 0x04, 0x89, 0x45, 0x04,
            0xff, 0x75, 0xf4, 0x64, 0xa1, 0x00, 0x00, 0x00,
            0x00, 0x89, 0x45, 0xf4, 0x8d, 0x45, 0xf4, 0x64,
            0xa3, 0x00, 0x00, 0x00, 0x00, 0xf2, 0xc3,
        ];
        assert_eq!(
            crc16(&UTCUTIL_EH_PROLOG3_CATCH_ALIGN[32..32 + 0x20]),
            0x6562
        );
    }

    /// One flipped bit anywhere in the covered range must move the CRC --
    /// otherwise the field is decoration.
    #[test]
    fn a_single_flipped_bit_changes_the_value() {
        let a = [0x55u8, 0x48, 0x89, 0xe5, 0x5d, 0xc3];
        let mut b = a;
        b[3] ^= 0x01;
        assert_ne!(crc16(&a), crc16(&b));
    }

    /// Length is part of the input: a truncated tail is a different CRC.
    #[test]
    fn a_shorter_range_is_a_different_value() {
        let a = [0x55u8, 0x48, 0x89, 0xe5];
        assert_ne!(crc16(&a), crc16(&a[..3]));
    }
}
