//! Recursive discovery of nested artifacts with budget control.

use crate::core::triage::{Budgets, ContainerChild};
use serde::{Deserialize, Serialize};
use crate::triage::containers::detect_containers;

/// Recursion engine for discovering nested payloads with depth accounting.
pub struct RecursionEngine {
    pub max_depth: usize,
}

impl Default for RecursionEngine {
    fn default() -> Self {
        Self { max_depth: 1 }
    }
}

impl RecursionEngine {
    pub fn new(max_depth: usize) -> Self {
        Self { max_depth }
    }

    /// Detect FAT Mach-O and yield child slices for each arch.
    fn detect_fat_macho(&self, data: &[u8]) -> Vec<ContainerChild> {
        if data.len() < 8 {
            return Vec::new();
        }
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let swapped_magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        // FAT magic values (32/64, swapped variants)
        let is_fat_be = magic == 0xCAFEBABE || magic == 0xCAFEBABF;
        let is_fat_le = swapped_magic == 0xCAFEBABE || swapped_magic == 0xCAFEBABF;
        let mut out = Vec::new();
        if !is_fat_be && !is_fat_le {
            return out;
        }
        // Use big-endian by default (standard FAT), fall back to little-endian swapped
        let be = is_fat_be;
        let nfat = if be {
            u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize
        } else {
            u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize
        };
        // Header sizes: 32-bit: 20 bytes per arch; 64-bit: 24 bytes per arch (we accept either)
        let header32_size = 20usize;
        let header64_size = 24usize;
        let after_header = 8usize;
        // Try 64 then 32 (tolerant parsing); bound by data length
        for entry_size in [header64_size, header32_size] {
            if after_header + nfat.saturating_mul(entry_size) > data.len() {
                continue;
            }
            for i in 0..nfat {
                let base = after_header + i * entry_size;
                if base + entry_size > data.len() {
                    break;
                }
                // fields: offset (u32/u64), size (u32/u64) at positions:
                // For 32-bit: offset @8, size @12
                // For 64-bit: offset @8 (u64), size @16 (u64)
                if entry_size == header32_size {
                    let off = if be {
                        u32::from_be_bytes([
                            data[base + 8],
                            data[base + 9],
                            data[base + 10],
                            data[base + 11],
                        ])
                    } else {
                        u32::from_le_bytes([
                            data[base + 8],
                            data[base + 9],
                            data[base + 10],
                            data[base + 11],
                        ])
                    } as u64;
                    let sz = if be {
                        u32::from_be_bytes([
                            data[base + 12],
                            data[base + 13],
                            data[base + 14],
                            data[base + 15],
                        ])
                    } else {
                        u32::from_le_bytes([
                            data[base + 12],
                            data[base + 13],
                            data[base + 14],
                            data[base + 15],
                        ])
                    } as u64;
                    if off == 0 || sz == 0 {
                        continue;
                    }
                    if (off as usize) < data.len()
                        && (off as usize).saturating_add(sz as usize) <= data.len()
                    {
                        out.push(ContainerChild::new("macho-thin".into(), off, sz));
                    }
                } else {
                    // 64-bit
                    if base + 24 > data.len() {
                        continue;
                    }
                    let off = if be {
                        u64::from_be_bytes([
                            data[base + 8],
                            data[base + 9],
                            data[base + 10],
                            data[base + 11],
                            data[base + 12],
                            data[base + 13],
                            data[base + 14],
                            data[base + 15],
                        ])
                    } else {
                        u64::from_le_bytes([
                            data[base + 8],
                            data[base + 9],
                            data[base + 10],
                            data[base + 11],
                            data[base + 12],
                            data[base + 13],
                            data[base + 14],
                            data[base + 15],
                        ])
                    };
                    let sz = if be {
                        u64::from_be_bytes([
                            data[base + 16],
                            data[base + 17],
                            data[base + 18],
                            data[base + 19],
                            data[base + 20],
                            data[base + 21],
                            data[base + 22],
                            data[base + 23],
                        ])
                    } else {
                        u64::from_le_bytes([
                            data[base + 16],
                            data[base + 17],
                            data[base + 18],
                            data[base + 19],
                            data[base + 20],
                            data[base + 21],
                            data[base + 22],
                            data[base + 23],
                        ])
                    };
                    if off == 0 || sz == 0 {
                        continue;
                    }
                    if (off as usize) < data.len()
                        && (off as usize).saturating_add(sz as usize) <= data.len()
                    {
                        out.push(ContainerChild::new("macho-thin".into(), off, sz));
                    }
                }
            }
            if !out.is_empty() {
                break;
            }
        }
        out
    }

    /// Detect embedded container signatures at non-zero offsets (simple overlay heuristic).
    fn detect_embedded_containers(&self, data: &[u8]) -> Vec<ContainerChild> {
        let mut out = Vec::new();
        // ZIP local header signature anywhere
        let sig_zip = b"PK\x03\x04";
        let mut start = 1usize; // skip offset 0 (handled by detect_containers)
        while let Some(pos) = memchr::memmem::find(&data[start..], sig_zip) {
            let off = start + pos;
            if off > 0 {
                out.push(ContainerChild::new(
                    "zip".into(),
                    off as u64,
                    (data.len() - off) as u64,
                ));
                break; // first hit is enough for triage
            }
            start = off + 4;
        }
        // GZIP signature 1F 8B at non-zero offset
        let sig_gz = [0x1F, 0x8B];
        if let Some(i) = data.windows(2).position(|w| w == sig_gz) {
            if i > 0 {
                out.push(ContainerChild::new(
                    "gzip".into(),
                    i as u64,
                    (data.len() - i) as u64,
                ));
            }
        }
        // XZ signature FD 37 7A 58 5A 00
        let sig_xz = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
        if let Some(i) = data.windows(sig_xz.len()).position(|w| w == sig_xz) {
            if i > 0 {
                out.push(ContainerChild::new(
                    "xz".into(),
                    i as u64,
                    (data.len() - i) as u64,
                ));
            }
        }
        // BZIP2 signature "BZh"
        let sig_bz = b"BZh";
        if let Some(i) = memchr::memmem::find(&data[1..], sig_bz) {
            let off = 1 + i;
            out.push(ContainerChild::new(
                "bzip2".into(),
                off as u64,
                (data.len() - off) as u64,
            ));
        }
        // ZSTD signature 28 B5 2F FD
        let sig_zstd = [0x28, 0xB5, 0x2F, 0xFD];
        if let Some(i) = data.windows(sig_zstd.len()).position(|w| w == sig_zstd) {
            if i > 0 {
                out.push(ContainerChild::new(
                    "zstd".into(),
                    i as u64,
                    (data.len() - i) as u64,
                ));
            }
        }
        // TAR: look for "ustar" at offset +257 within a 512-byte header block
        if let Some(pos) = memchr::memmem::find(&data[1..], b"ustar") {
            let abs = pos + 1;
            if abs >= 257 {
                let hdr_start = abs - 257;
                if hdr_start % 512 == 0 {
                    out.push(ContainerChild::new(
                        "tar".into(),
                        hdr_start as u64,
                        (data.len() - hdr_start) as u64,
                    ));
                }
            }
        }
        out
    }

    /// Discover immediate children; enforce max_depth.
    pub fn discover_children(
        &self,
        data: &[u8],
        budgets: &mut Budgets,
        depth: usize,
    ) -> Vec<ContainerChild> {
        if depth >= self.max_depth {
            return Vec::new();
        }
        // Account depth usage
        budgets.recursion_depth = budgets.recursion_depth.saturating_add(1);
        let mut children = Vec::new();
        // Top-level container magic
        children.extend(detect_containers(data));
        // Fat Mach-O slicing
        children.extend(self.detect_fat_macho(data));
        // Embedded container (overlay) heuristics
        children.extend(self.detect_embedded_containers(data));
        // Deterministic ordering: by offset, then type_name, then label (if present)
        children.sort_by(|a, b| {
            a.offset
                .cmp(&b.offset)
                .then(a.type_name.cmp(&b.type_name))
        });
        children
    }
}

/// Rollup summary for recursion/children stats
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub struct RecursionSummary {
    /// Total immediate children discovered (bounded)
    pub total_children: u32,
    /// Maximum recursion depth observed during discovery
    pub max_depth: u32,
    /// True if any packer/compression indicator was present
    pub dangerous_child_present: bool,
}

#[cfg(test)]
mod tests_rollup {
    use super::*;

    #[test]
    fn sort_children_is_deterministic() {
        let mut b = Budgets::new(0, 0, 0);
        let eng = RecursionEngine::new(1);
        let mut data = vec![0u8; 1200];
        // Embed two signatures out of order
        data[700..704].copy_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]); // zstd at 700
        data[100..106].copy_from_slice(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]); // xz at 100
        let kids = eng.discover_children(&data, &mut b, 0);
        assert!(kids.len() >= 2);
        assert!(kids[0].offset <= kids[1].offset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_macho_fat_two_slices() {
        // Build a minimal FAT header (big-endian), 2 entries, 32-bit arch entries
        let mut data = vec![0u8; 8 + 2 * 20 + 200];
        // magic CAFEBABE
        data[0..4].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
        data[4..8].copy_from_slice(&(2u32).to_be_bytes());
        // entry 0: offset 100, size 50
        let base0 = 8;
        data[base0 + 8..base0 + 12].copy_from_slice(&(100u32).to_be_bytes());
        data[base0 + 12..base0 + 16].copy_from_slice(&(50u32).to_be_bytes());
        // entry 1: offset 150, size 30
        let base1 = 8 + 20;
        data[base1 + 8..base1 + 12].copy_from_slice(&(150u32).to_be_bytes());
        data[base1 + 12..base1 + 16].copy_from_slice(&(30u32).to_be_bytes());

        let eng = RecursionEngine::new(2);
        let mut b = Budgets::new(data.len() as u64, 0, 0);
        let kids = eng.discover_children(&data, &mut b, 0);
        assert!(kids
            .iter()
            .any(|c| c.type_name == "macho-thin" && c.offset == 100 && c.size == 50));
        assert!(kids
            .iter()
            .any(|c| c.type_name == "macho-thin" && c.offset == 150 && c.size == 30));
    }

    #[test]
    fn detect_embedded_xz_bz_zstd_tar() {
        // Build a buffer with multiple embedded signatures
        let mut data = vec![0u8; 4096];
        // XZ at 100
        let off_xz = 100usize;
        data[off_xz..off_xz + 6].copy_from_slice(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]);
        // BZIP2 at 300
        let off_bz = 300usize;
        data[off_bz..off_bz + 3].copy_from_slice(b"BZh");
        // ZSTD at 700
        let off_zs = 700usize;
        data[off_zs..off_zs + 4].copy_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]);
        // TAR header at 1024 (aligned); write "ustar" at +257
        let off_tar = 1024usize;
        data[off_tar + 257..off_tar + 262].copy_from_slice(b"ustar");

        let eng = RecursionEngine::new(1);
        let mut b = Budgets::new(data.len() as u64, 0, 0);
        let kids = eng.discover_children(&data, &mut b, 0);
        assert!(kids
            .iter()
            .any(|c| c.type_name == "xz" && c.offset == off_xz as u64));
        assert!(kids
            .iter()
            .any(|c| c.type_name == "bzip2" && c.offset == off_bz as u64));
        assert!(kids
            .iter()
            .any(|c| c.type_name == "zstd" && c.offset == off_zs as u64));
        assert!(kids
            .iter()
            .any(|c| c.type_name == "tar" && c.offset == off_tar as u64));
    }
}
