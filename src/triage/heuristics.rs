//! Heuristics for binary classification when headers are inconclusive.

use crate::core::binary::{Arch, Endianness};
use crate::core::triage::{DetectedString, StringsSummary};

/// Endianness detection based on byte patterns and simple statistics.
pub mod endianness {
    use super::*;

    /// Guess endianness by scanning 32-bit words and scoring common patterns.
    /// Returns (endianness, confidence [0.0, 1.0]).
    pub fn guess(data: &[u8]) -> (Endianness, f32) {
        if data.len() < 256 {
            return (Endianness::Little, 0.5);
        }

        let mut le_score: u32 = 0;
        let mut be_score: u32 = 0;

        for chunk in data.chunks_exact(4).take(16384) {
            // Zero-byte alignment heuristic
            if chunk[0] == 0 && chunk[1] == 0 {
                be_score = be_score.saturating_add(1);
            }
            if chunk[2] == 0 && chunk[3] == 0 {
                le_score = le_score.saturating_add(1);
            }

            // Small integer heuristic (< 256)
            let le_val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let be_val = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            if (1..=255).contains(&le_val) {
                le_score = le_score.saturating_add(2);
            }
            if (1..=255).contains(&be_val) {
                be_score = be_score.saturating_add(2);
            }
        }

        let total = (le_score + be_score) as f32;
        if total == 0.0 {
            (Endianness::Little, 0.5)
        } else if le_score >= be_score {
            (
                Endianness::Little,
                (le_score as f32 / total).clamp(0.0, 1.0),
            )
        } else {
            (Endianness::Big, (be_score as f32 / total).clamp(0.0, 1.0))
        }
    }
}

/// Architecture inference based on opcode and byte-frequency patterns.
pub mod architecture {
    use super::*;
    use std::collections::HashMap;

    // Simplified indicative opcode bytes
    const X86_PROFILE: &[u8] = &[0x90, 0x55, 0x89, 0x48, 0xE8, 0xC3, 0xFF];
    const ARM64_PROFILE: &[u8] = &[0xE0, 0x03, 0x1F, 0xAA, 0xD5, 0x03, 0x20]; // AArch64 patterns
    const ARM_PROFILE: &[u8] = &[0xE5, 0x9F, 0xB0, 0xE3, 0xA0, 0xEA]; // LDR/STR/B/BL common prefixes
    const MIPS_PROFILE: &[u8] = &[0x00, 0x02, 0x03, 0x23, 0x2B]; // SPECIAL, J, JAL, LW, SW
    const RISCV_PROFILE: &[u8] = &[0x13, 0x33, 0x63, 0x6F, 0x67]; // ADDI, ADD, BRANCH, JAL, JALR

    /// Infer likely architectures and confidence scores.
    pub fn infer(data: &[u8]) -> Vec<(Arch, f32)> {
        let mut histogram = [0u32; 256];
        for &b in data.iter().take(65_536) {
            histogram[b as usize] = histogram[b as usize].saturating_add(1);
        }

        let total: u32 = histogram.iter().sum();
        if total == 0 {
            return vec![(Arch::Unknown, 0.0)];
        }

        let mut scores: HashMap<Arch, f32> = HashMap::new();
        scores.insert(Arch::X86_64, score_profile(&histogram, X86_PROFILE));
        scores.insert(Arch::X86, score_profile(&histogram, X86_PROFILE));
        scores.insert(Arch::AArch64, score_profile(&histogram, ARM64_PROFILE));
        scores.insert(Arch::ARM, score_profile(&histogram, ARM_PROFILE));
        scores.insert(Arch::MIPS, score_profile(&histogram, MIPS_PROFILE));
        scores.insert(Arch::RISCV64, score_profile(&histogram, RISCV_PROFILE));

        let mut v: Vec<(Arch, f32)> = scores.into_iter().collect();
        v.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        v.truncate(3);
        if v.is_empty() {
            vec![(Arch::Unknown, 0.0)]
        } else {
            v
        }
    }

    fn score_profile(hist: &[u32; 256], profile: &[u8]) -> f32 {
        let total: u32 = hist.iter().sum();
        if total == 0 {
            return 0.0;
        }
        let mut score = 0.0f32;
        for &op in profile {
            let freq = hist[op as usize] as f32 / total as f32;
            score += freq;
        }
        (score / profile.len() as f32).clamp(0.0, 1.0)
    }
}

/// String extraction and summarization.
pub mod strings {
    use super::*;

    const MIN_ASCII_LEN: usize = 4;
    const MAX_SCAN: usize = 1_048_576; // 1 MiB cap
    const MAX_SAMPLES: usize = 10;

    pub fn extract(data: &[u8]) -> StringsSummary {
        let scan = &data[..data.len().min(MAX_SCAN)];

        // ASCII strings
        let mut ascii_samples: Vec<String> = Vec::new();
        let mut ascii_count: u32 = 0;
        let mut cur: Vec<u8> = Vec::new();
        for &b in scan.iter() {
            if (b.is_ascii_graphic() || b == b'\t' || b == b' ') && b != b'\x7f' {
                cur.push(b);
            } else {
                if cur.len() >= MIN_ASCII_LEN {
                    ascii_count = ascii_count.saturating_add(1);
                    if ascii_samples.len() < MAX_SAMPLES {
                        if let Ok(s) = String::from_utf8(cur.clone()) {
                            ascii_samples.push(s);
                        }
                    }
                }
                cur.clear();
            }
        }
        if cur.len() >= MIN_ASCII_LEN {
            ascii_count = ascii_count.saturating_add(1);
            if ascii_samples.len() < MAX_SAMPLES {
                if let Ok(s) = String::from_utf8(cur.clone()) {
                    ascii_samples.push(s);
                }
            }
        }

        // UTF-16LE/BE naive extraction: look for printable halfwords
        let (mut utf16le_count, mut utf16be_count) = (0u32, 0u32);
        let mut run_len_le = 0usize;
        for chunk in scan.chunks_exact(2) {
            let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
            if ch == 0 {
                // reset on NUL
                if run_len_le >= MIN_ASCII_LEN {
                    utf16le_count = utf16le_count.saturating_add(1);
                }
                run_len_le = 0;
                continue;
            }
            let c = char::from_u32(ch as u32).unwrap_or('\u{FFFD}');
            if c.is_ascii_graphic() || c == ' ' {
                run_len_le += 1;
            } else {
                if run_len_le >= MIN_ASCII_LEN {
                    utf16le_count = utf16le_count.saturating_add(1);
                }
                run_len_le = 0;
            }
        }
        if run_len_le >= MIN_ASCII_LEN {
            utf16le_count = utf16le_count.saturating_add(1);
        }

        let mut run_len_be = 0usize;
        for chunk in scan.chunks_exact(2) {
            let ch = u16::from_be_bytes([chunk[0], chunk[1]]);
            if ch == 0 {
                if run_len_be >= MIN_ASCII_LEN {
                    utf16be_count = utf16be_count.saturating_add(1);
                }
                run_len_be = 0;
                continue;
            }
            let c = char::from_u32(ch as u32).unwrap_or('\u{FFFD}');
            if c.is_ascii_graphic() || c == ' ' {
                run_len_be += 1;
            } else {
                if run_len_be >= MIN_ASCII_LEN {
                    utf16be_count = utf16be_count.saturating_add(1);
                }
                run_len_be = 0;
            }
        }
        if run_len_be >= MIN_ASCII_LEN {
            utf16be_count = utf16be_count.saturating_add(1);
        }

        let strings = if ascii_samples.is_empty() {
            None
        } else {
            let v: Vec<DetectedString> = ascii_samples
                .into_iter()
                .take(MAX_SAMPLES)
                .map(|text| DetectedString::new(text, "ascii".to_string(), None, None, None, None))
                .collect();
            Some(v)
        };
        StringsSummary::new(
            ascii_count,
            utf16le_count,
            utf16be_count,
            strings,
            None,
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::binary::{Arch, Endianness};

    #[test]
    fn test_endianness_guess_le_be() {
        // Little-endian pattern 1,0,0,0 repeated
        let le_chunk = [1u8, 0, 0, 0];
        let mut le_data = Vec::new();
        for _ in 0..512 {
            le_data.extend_from_slice(&le_chunk);
        }
        let (e, conf) = endianness::guess(&le_data);
        assert_eq!(e, Endianness::Little);
        assert!(conf > 0.6);

        // Big-endian pattern 0,0,0,1 repeated
        let be_chunk = [0u8, 0, 0, 1];
        let mut be_data = Vec::new();
        for _ in 0..512 {
            be_data.extend_from_slice(&be_chunk);
        }
        let (e2, conf2) = endianness::guess(&be_data);
        assert_eq!(e2, Endianness::Big);
        assert!(conf2 > 0.6);
    }

    #[test]
    fn test_architecture_infer_profiles() {
        // x86-like stream (NOP flood)
        let x86_data = vec![0x90; 4096];
        let results = architecture::infer(&x86_data);
        assert!(!results.is_empty());
        let top = results[0].0;
        assert!(top == Arch::X86 || top == Arch::X86_64);

        // AArch64-like stream
        let mut a64_data = Vec::new();
        let a64_ops = [0xE0u8, 0x03, 0x1F, 0xAA, 0xD5, 0x03, 0x20];
        for _ in 0..1024 {
            a64_data.extend_from_slice(&a64_ops);
        }
        let results2 = architecture::infer(&a64_data);
        assert!(!results2.is_empty());
        assert_eq!(results2[0].0, Arch::AArch64);
    }
}
