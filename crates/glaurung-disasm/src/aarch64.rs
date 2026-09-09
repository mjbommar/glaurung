//! AArch64 encoding primitives.

/// Expand the AArch64 logical-immediate fields into their register-width mask.
///
/// This implements ARM's `DecodeBitMasks` rule directly. Returning `None`
/// distinguishes reserved encodings, including a 64-bit element in a 32-bit
/// instruction and an all-ones element.
pub const fn decode_logical_immediate_mask(
    n: u8,
    immr: u8,
    imms: u8,
    register_bits: u8,
) -> Option<u64> {
    if !matches!(register_bits, 32 | 64) || n > 1 || immr > 63 || imms > 63 {
        return None;
    }
    if register_bits == 32 && n != 0 {
        return None;
    }
    let length_source = ((n as u32) << 6) | (!(imms as u32) & 0x3f);
    if length_source == 0 {
        return None;
    }
    let length = 31 - length_source.leading_zeros();
    if length < 1 {
        return None;
    }
    let element_bits = 1_u32 << length;
    if element_bits > register_bits as u32 {
        return None;
    }
    let levels = element_bits - 1;
    let set_bits = imms as u32 & levels;
    if set_bits == levels {
        return None;
    }
    let rotation = immr as u32 & levels;
    let element_mask = if element_bits == 64 {
        u64::MAX
    } else {
        (1_u64 << element_bits) - 1
    };
    let ones = (1_u64 << (set_bits + 1)) - 1;
    let element = if rotation == 0 {
        ones
    } else {
        ((ones >> rotation) | (ones << (element_bits - rotation))) & element_mask
    };
    let mut result = 0_u64;
    let mut offset = 0;
    while offset < register_bits as u32 {
        result |= element << offset;
        offset += element_bits;
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::decode_logical_immediate_mask;

    #[test]
    fn expands_representative_element_sizes_and_rotations() {
        assert_eq!(
            decode_logical_immediate_mask(0, 16, 15, 32),
            Some(0xffff_0000)
        );
        assert_eq!(
            decode_logical_immediate_mask(0, 1, 32, 32),
            Some(0x8000_8000)
        );
        assert_eq!(
            decode_logical_immediate_mask(0, 3, 10, 64),
            Some(0xe000_00ff_e000_00ff)
        );
        assert_eq!(
            decode_logical_immediate_mask(1, 1, 12, 64),
            Some(0x8000_0000_0000_0fff)
        );
    }

    #[test]
    fn rejects_reserved_encodings() {
        assert_eq!(decode_logical_immediate_mask(1, 0, 0, 32), None);
        assert_eq!(decode_logical_immediate_mask(1, 0, 63, 64), None);
        assert_eq!(decode_logical_immediate_mask(2, 0, 0, 64), None);
        assert_eq!(decode_logical_immediate_mask(0, 64, 0, 64), None);
    }

    #[test]
    fn every_valid_result_is_nonzero_and_not_all_ones() {
        for register_bits in [32, 64] {
            for n in 0..=1 {
                for immr in 0..=63 {
                    for imms in 0..=63 {
                        if let Some(mask) =
                            decode_logical_immediate_mask(n, immr, imms, register_bits)
                        {
                            let width_mask = if register_bits == 64 {
                                u64::MAX
                            } else {
                                u64::from(u32::MAX)
                            };
                            assert_ne!(mask, 0);
                            assert_ne!(mask, width_mask);
                            assert_eq!(mask & !width_mask, 0);
                        }
                    }
                }
            }
        }
    }
}
