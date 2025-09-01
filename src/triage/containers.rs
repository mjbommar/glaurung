//! Container and archive format detection.
//!
//! Fast magic checks for zip, tar, 7z, ar, cpio, gzip, xz, bzip2, zstd, lz4
//! with bounded metadata extraction.
use crate::core::triage::{ContainerChild, ContainerMetadata};

fn parse_zip_metadata(data: &[u8]) -> Option<ContainerMetadata> {
    // Search for End of Central Directory (EOCD) signature 0x06054b50 near the end
    const EOCD_SIG: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
    let tail_len = data.len().min(66_000);
    let tail = &data[data.len() - tail_len..];
    // Scan backwards for the signature
    for i in (0..=tail_len.saturating_sub(22)).rev() {
        if tail[i..i + 4] == EOCD_SIG {
            // EOCD structure at i
            if i + 22 > tail.len() {
                break;
            }
            // fields: skip 4 sig + 2 disk + 2 cd_start_disk
            let total_entries = u16::from_le_bytes([tail[i + 10], tail[i + 11]]) as u32;
            let cd_size = u32::from_le_bytes([tail[i + 12], tail[i + 13], tail[i + 14], tail[i + 15]]) as u64;
            return Some(ContainerMetadata {
                file_count: Some(total_entries as u32),
                total_uncompressed_size: None,
                total_compressed_size: Some(cd_size),
            });
        }
    }
    None
}

fn parse_gzip_metadata(data: &[u8]) -> Option<ContainerMetadata> {
    if data.len() < 18 {
        return None;
    }
    // ISIZE: last 4 bytes (mod 2^32) is uncompressed size for non-streamed gzip
    let n = data.len();
    let isize = u32::from_le_bytes([data[n - 4], data[n - 3], data[n - 2], data[n - 1]]) as u64;
    Some(ContainerMetadata {
        file_count: Some(1),
        total_uncompressed_size: Some(isize),
        total_compressed_size: Some(data.len() as u64),
    })
}

fn parse_tar_metadata(data: &[u8]) -> Option<ContainerMetadata> {
    // Parse ustar headers (512-byte blocks), count entries and sum sizes bounded by available data
    const BLOCK: usize = 512;
    if data.len() < 262 || &data[257..262] != b"ustar" {
        return None;
    }
    let mut off = 0usize;
    let mut count: u32 = 0;
    let mut total: u64 = 0;
    // Iterate over headers until two zero blocks or out of data; cap iterations
    let mut zero_blocks = 0;
    let max_iter = data.len() / BLOCK;
    for _ in 0..max_iter {
        if off + BLOCK > data.len() {
            break;
        }
        let hdr = &data[off..off + BLOCK];
        if hdr.iter().all(|&b| b == 0) {
            zero_blocks += 1;
            if zero_blocks >= 2 {
                break;
            }
            off += BLOCK;
            continue;
        }
        zero_blocks = 0;
        // size field: offset 124, length 12, octal ASCII
        let size_field = &hdr[124..136];
        let size_trim = size_field
            .iter()
            .take_while(|&&c| c != 0)
            .cloned()
            .collect::<Vec<u8>>();
        let size_str = String::from_utf8_lossy(&size_trim);
        let size = u64::from_str_radix(size_str.trim(), 8).unwrap_or(0);
        // typeflag at 156: '0' or '\0' indicates a regular file
        let typeflag = hdr[156];
        if typeflag == b'0' || typeflag == 0 {
            count = count.saturating_add(1);
            total = total.saturating_add(size);
        }
        // Advance by header + file content rounded up to 512-byte boundary
        let file_blocks = ((size + (BLOCK as u64 - 1)) / BLOCK as u64) as usize;
        off = off.saturating_add(BLOCK + file_blocks * BLOCK);
        if off >= data.len() {
            break;
        }
    }
    Some(ContainerMetadata {
        file_count: Some(count),
        total_uncompressed_size: Some(total),
        total_compressed_size: Some(data.len() as u64),
    })
}

pub fn detect_containers(data: &[u8]) -> Vec<ContainerChild> {
    let mut containers = Vec::new();

    // ZIP/JAR
    if data.len() >= 4 && &data[..4] == b"PK\x03\x04" {
        let mut c = ContainerChild::new("zip".to_string(), 0, data.len() as u64);
        c.metadata = parse_zip_metadata(data);
        containers.push(c);
    }

    // GZIP
    if data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B {
        let mut c = ContainerChild::new("gzip".to_string(), 0, data.len() as u64);
        c.metadata = parse_gzip_metadata(data);
        containers.push(c);
    }

    // TAR: "ustar" at offset 257
    if data.len() > 262 && data[257..262] == *b"ustar" {
        let mut c = ContainerChild::new("tar".into(), 0, data.len() as u64);
        c.metadata = parse_tar_metadata(data);
        containers.push(c);
    }

    // 7z
    if data.len() >= 6 && data[..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        containers.push(ContainerChild::new("7z".into(), 0, data.len() as u64));
    }

    // AR (Unix archive)
    if data.len() >= 8 && &data[..8] == b"!<arch>\n" {
        containers.push(ContainerChild::new("ar".into(), 0, data.len() as u64));
    }

    // XZ
    if data.len() >= 6 && data[..6] == [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] {
        containers.push(ContainerChild::new("xz".into(), 0, data.len() as u64));
    }

    // BZIP2
    if data.len() >= 3 && &data[..3] == b"BZh" {
        containers.push(ContainerChild::new("bzip2".into(), 0, data.len() as u64));
    }

    // ZSTD (0x28 B5 2F FD)
    if data.len() >= 4 && data[..4] == [0x28, 0xB5, 0x2F, 0xFD] {
        containers.push(ContainerChild::new("zstd".into(), 0, data.len() as u64));
    }

    // LZ4 (magic: 04 22 4D 18)
    if data.len() >= 4 && data[..4] == [0x04, 0x22, 0x4D, 0x18] {
        containers.push(ContainerChild::new("lz4".into(), 0, data.len() as u64));
    }

    // CPIO (new ASCII formats 070701 or 070702)
    if data.len() >= 6 && (data[..6] == *b"070701" || data[..6] == *b"070702") {
        containers.push(ContainerChild::new("cpio".into(), 0, data.len() as u64));
    }

    // RAR4/RAR5
    if data.len() >= 7 && data[..7] == [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00] {
        containers.push(ContainerChild::new("rar".into(), 0, data.len() as u64));
    }
    if data.len() >= 8 && data[..8] == [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00] {
        containers.push(ContainerChild::new("rar5".into(), 0, data.len() as u64));
    }

    containers
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detect_zip_and_gzip_and_tar_real_files() {
        let zip = "samples/containers/zip/hello-cpp-g++-O0.zip";
        if let Ok(d) = fs::read(zip) {
            let v = detect_containers(&d);
            assert!(v.iter().any(|c| c.type_name == "zip"));
            if let Some(z) = v.into_iter().find(|c| c.type_name == "zip") {
                // Metadata may be present if EOCD found
                if let Some(meta) = z.metadata {
                    assert!(meta.file_count.unwrap_or(0) >= 1);
                }
            }
        }
        let gz = "samples/containers/gzip/hello-cpp-g++-O0.gz";
        if let Ok(d) = fs::read(gz) {
            let v = detect_containers(&d);
            assert!(v.iter().any(|c| c.type_name == "gzip"));
            if let Some(g) = v.into_iter().find(|c| c.type_name == "gzip") {
                if let Some(meta) = g.metadata {
                    // ISIZE may be 0 for concatenated streams, but field exists
                    assert!(meta.total_uncompressed_size.is_some());
                }
            }
        }
        let tar = "samples/containers/tar/hello-cpp-g++-O0.tar";
        if let Ok(d) = fs::read(tar) {
            let v = detect_containers(&d);
            assert!(v.iter().any(|c| c.type_name == "tar"));
            if let Some(t) = v.into_iter().find(|c| c.type_name == "tar") {
                if let Some(meta) = t.metadata {
                    assert!(meta.file_count.unwrap_or(0) >= 1);
                }
            }
        }
    }
}
