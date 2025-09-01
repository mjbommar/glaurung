//! Container and archive format detection.
//!
//! Fast magic checks for zip, tar, 7z, ar, cpio, gzip, xz, bzip2, zstd, lz4
//! with bounded metadata extraction.
use crate::core::triage::ContainerChild;

pub fn detect_containers(data: &[u8]) -> Vec<ContainerChild> {
    let mut containers = Vec::new();

    // ZIP/JAR
    if data.len() >= 4 && &data[..4] == b"PK\x03\x04" {
        containers.push(ContainerChild::new("zip".to_string(), 0, data.len() as u64));
    }

    // GZIP
    if data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B {
        containers.push(ContainerChild::new(
            "gzip".to_string(),
            0,
            data.len() as u64,
        ));
    }

    // TAR: "ustar" at offset 257
    if data.len() > 262 && data[257..262] == *b"ustar" {
        containers.push(ContainerChild::new("tar".into(), 0, data.len() as u64));
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
        }
        let gz = "samples/containers/gzip/hello-cpp-g++-O0.gz";
        if let Ok(d) = fs::read(gz) {
            let v = detect_containers(&d);
            assert!(v.iter().any(|c| c.type_name == "gzip"));
        }
        let tar = "samples/containers/tar/hello-cpp-g++-O0.tar";
        if let Ok(d) = fs::read(tar) {
            let v = detect_containers(&d);
            assert!(v.iter().any(|c| c.type_name == "tar"));
        }
    }
}
