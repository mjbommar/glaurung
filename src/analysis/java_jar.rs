//! Lightweight JAR/ZIP central-directory indexer.
//!
//! This intentionally avoids extraction and decompression. It reads the ZIP
//! central directory to recover bounded archive metadata that Java tools need
//! before deeper class parsing or source recovery.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaJarEntry {
    pub entry_name: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub compression_method: u16,
    pub crc32: u32,
    pub local_header_offset: u64,
    pub is_dir: bool,
    pub is_class: bool,
    pub is_resource: bool,
    pub is_nested_archive: bool,
    pub is_multi_release_class: bool,
    pub multi_release_version: Option<u16>,
    pub is_signature_file: bool,
    pub is_maven_metadata: bool,
    pub is_service_descriptor: bool,
    pub is_module_info: bool,
    pub is_zip_slip: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaJarIndex {
    pub entry_count: usize,
    pub entries: Vec<JavaJarEntry>,
    pub total_compressed_size: u64,
    pub total_uncompressed_size: u64,
    pub directory_count: usize,
    pub class_count: usize,
    pub resource_count: usize,
    pub nested_archive_count: usize,
    pub multi_release_class_count: usize,
    pub multi_release_versions: Vec<u16>,
    pub signature_file_count: usize,
    pub signed: bool,
    pub maven_metadata_count: usize,
    pub service_descriptor_count: usize,
    pub module_info_present: bool,
    pub zip_slip_entry_count: usize,
    pub truncated: bool,
    pub zip64_locator_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JavaJarError {
    NotZip,
    Truncated(&'static str),
    BadCentralDirectory,
    UnsupportedZip64,
}

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const CENTRAL_FILE_HEADER_SIGNATURE: u32 = 0x0201_4b50;
const EOCD_MIN_LEN: usize = 22;
const EOCD_MAX_COMMENT_LEN: usize = 65_535;

pub fn index_jar(data: &[u8], max_entries: usize) -> Result<JavaJarIndex, JavaJarError> {
    let eocd_offset = find_eocd(data).ok_or(JavaJarError::NotZip)?;
    let zip64_locator_present = has_zip64_locator(data, eocd_offset);
    let total_entries = read_u16(data, eocd_offset + 10, "EOCD total entries")? as usize;
    let cd_size = read_u32(data, eocd_offset + 12, "EOCD central directory size")?;
    let cd_offset = read_u32(data, eocd_offset + 16, "EOCD central directory offset")?;
    if total_entries == 0xffff || cd_size == 0xffff_ffff || cd_offset == 0xffff_ffff {
        return Err(JavaJarError::UnsupportedZip64);
    }

    let cd_start = cd_offset as usize;
    let cd_end = cd_start
        .checked_add(cd_size as usize)
        .ok_or(JavaJarError::Truncated("central directory"))?;
    if cd_end > data.len() || cd_start > cd_end {
        return Err(JavaJarError::Truncated("central directory"));
    }

    let mut p = cd_start;
    let mut entries = Vec::new();
    let mut entry_count = 0usize;
    let mut total_compressed_size = 0u64;
    let mut total_uncompressed_size = 0u64;
    let mut directory_count = 0usize;
    let mut class_count = 0usize;
    let mut resource_count = 0usize;
    let mut nested_archive_count = 0usize;
    let mut multi_release_class_count = 0usize;
    let mut multi_release_versions: Vec<u16> = Vec::new();
    let mut signature_file_count = 0usize;
    let mut maven_metadata_count = 0usize;
    let mut service_descriptor_count = 0usize;
    let mut module_info_present = false;
    let mut zip_slip_entry_count = 0usize;

    while p < cd_end {
        if p + 46 > cd_end {
            return Err(JavaJarError::Truncated("central file header"));
        }
        if read_u32(data, p, "central file header signature")? != CENTRAL_FILE_HEADER_SIGNATURE {
            return Err(JavaJarError::BadCentralDirectory);
        }
        let compression_method = read_u16(data, p + 10, "compression method")?;
        let crc32 = read_u32(data, p + 16, "crc32")?;
        let compressed_size = read_u32(data, p + 20, "compressed size")? as u64;
        let uncompressed_size = read_u32(data, p + 24, "uncompressed size")? as u64;
        let name_len = read_u16(data, p + 28, "file name length")? as usize;
        let extra_len = read_u16(data, p + 30, "extra field length")? as usize;
        let comment_len = read_u16(data, p + 32, "file comment length")? as usize;
        let local_header_offset = read_u32(data, p + 42, "local header offset")? as u64;
        let name_start = p + 46;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(JavaJarError::Truncated("entry name"))?;
        if name_end > cd_end {
            return Err(JavaJarError::Truncated("entry name"));
        }
        let entry_name = String::from_utf8_lossy(&data[name_start..name_end]).into_owned();

        let entry = classify_entry(
            entry_name,
            compressed_size,
            uncompressed_size,
            compression_method,
            crc32,
            local_header_offset,
        );
        entry_count += 1;
        total_compressed_size = total_compressed_size.saturating_add(compressed_size);
        total_uncompressed_size = total_uncompressed_size.saturating_add(uncompressed_size);
        if entry.is_dir {
            directory_count += 1;
        }
        if entry.is_class {
            class_count += 1;
        } else if !entry.is_dir {
            resource_count += 1;
        }
        if entry.is_nested_archive {
            nested_archive_count += 1;
        }
        if entry.is_multi_release_class {
            multi_release_class_count += 1;
            if let Some(version) = entry.multi_release_version {
                if !multi_release_versions.contains(&version) {
                    multi_release_versions.push(version);
                }
            }
        }
        if entry.is_signature_file {
            signature_file_count += 1;
        }
        if entry.is_maven_metadata {
            maven_metadata_count += 1;
        }
        if entry.is_service_descriptor {
            service_descriptor_count += 1;
        }
        if entry.is_module_info {
            module_info_present = true;
        }
        if entry.is_zip_slip {
            zip_slip_entry_count += 1;
        }
        if entries.len() < max_entries {
            entries.push(entry);
        }

        p = name_end
            .checked_add(extra_len)
            .and_then(|v| v.checked_add(comment_len))
            .ok_or(JavaJarError::Truncated("central file header variable data"))?;
    }

    multi_release_versions.sort_unstable();
    Ok(JavaJarIndex {
        entry_count,
        entries,
        total_compressed_size,
        total_uncompressed_size,
        directory_count,
        class_count,
        resource_count,
        nested_archive_count,
        multi_release_class_count,
        multi_release_versions,
        signature_file_count,
        signed: signature_file_count > 0,
        maven_metadata_count,
        service_descriptor_count,
        module_info_present,
        zip_slip_entry_count,
        truncated: entry_count > max_entries,
        zip64_locator_present,
    })
}

fn classify_entry(
    entry_name: String,
    compressed_size: u64,
    uncompressed_size: u64,
    compression_method: u16,
    crc32: u32,
    local_header_offset: u64,
) -> JavaJarEntry {
    let normalized = entry_name.replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();
    let is_dir = normalized.ends_with('/');
    let is_class = !is_dir && lower.ends_with(".class");
    let is_nested_archive = !is_dir && (lower.ends_with(".jar") || lower.ends_with(".zip"));
    let (is_multi_release_class, multi_release_version) = multi_release_version(&normalized);
    let is_signature_file = is_signature_file(&normalized);
    let is_maven_metadata = lower.starts_with("meta-inf/maven/")
        && (lower.ends_with("/pom.properties") || lower.ends_with("/pom.xml"));
    let is_service_descriptor = !is_dir
        && lower.starts_with("meta-inf/services/")
        && lower.len() > "meta-inf/services/".len();
    let is_module_info =
        !is_dir && (lower == "module-info.class" || lower.ends_with("/module-info.class"));
    let is_zip_slip = is_zip_slip_name(&normalized);
    JavaJarEntry {
        entry_name,
        compressed_size,
        uncompressed_size,
        compression_method,
        crc32,
        local_header_offset,
        is_dir,
        is_class,
        is_resource: !is_dir && !is_class,
        is_nested_archive,
        is_multi_release_class,
        multi_release_version,
        is_signature_file,
        is_maven_metadata,
        is_service_descriptor,
        is_module_info,
        is_zip_slip,
    }
}

fn multi_release_version(name: &str) -> (bool, Option<u16>) {
    let rest = match name.strip_prefix("META-INF/versions/") {
        Some(rest) => rest,
        None => return (false, None),
    };
    let Some((version_text, remainder)) = rest.split_once('/') else {
        return (false, None);
    };
    if !remainder.ends_with(".class") {
        return (false, None);
    }
    match version_text.parse::<u16>() {
        Ok(version) => (true, Some(version)),
        Err(_) => (true, None),
    }
}

fn is_signature_file(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if !upper.starts_with("META-INF/") {
        return false;
    }
    let Some(file_name) = upper.strip_prefix("META-INF/") else {
        return false;
    };
    !file_name.contains('/')
        && (file_name.ends_with(".SF")
            || file_name.ends_with(".RSA")
            || file_name.ends_with(".DSA")
            || file_name.ends_with(".EC"))
}

fn is_zip_slip_name(name: &str) -> bool {
    if name.starts_with('/') || name.starts_with('\\') {
        return true;
    }
    if name.len() >= 2 && name.as_bytes()[1] == b':' {
        return true;
    }
    name.split('/').any(|part| part == "..")
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < EOCD_MIN_LEN {
        return None;
    }
    let min = data
        .len()
        .saturating_sub(EOCD_MIN_LEN + EOCD_MAX_COMMENT_LEN);
    let max = data.len() - EOCD_MIN_LEN;
    (min..=max).rev().find(|&pos| {
        read_u32(data, pos, "EOCD signature")
            .map(|sig| sig == EOCD_SIGNATURE)
            .unwrap_or(false)
    })
}

fn has_zip64_locator(data: &[u8], eocd_offset: usize) -> bool {
    if eocd_offset < 20 {
        return false;
    }
    read_u32(data, eocd_offset - 20, "ZIP64 locator")
        .map(|sig| sig == ZIP64_LOCATOR_SIGNATURE)
        .unwrap_or(false)
}

fn read_u16(data: &[u8], pos: usize, label: &'static str) -> Result<u16, JavaJarError> {
    if pos + 2 > data.len() {
        return Err(JavaJarError::Truncated(label));
    }
    Ok(u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()))
}

fn read_u32(data: &[u8], pos: usize, label: &'static str) -> Result<u32, JavaJarError> {
    if pos + 4 > data.len() {
        return Err(JavaJarError::Truncated(label));
    }
    Ok(u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn indexes_helloworld_jar_central_directory() {
        let path = Path::new("samples/binaries/platforms/linux/amd64/export/java/HelloWorld.jar");
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let index = index_jar(&data, 128).expect("jar index");
        assert!(index.entry_count >= 2);
        assert_eq!(index.class_count, 1);
        assert!(index.resource_count >= 1);
        assert!(!index.truncated);
        assert!(index
            .entries
            .iter()
            .any(|entry| entry.entry_name == "HelloWorld.class" && entry.is_class));
    }

    #[test]
    fn returns_none_for_non_zip_magic() {
        let err = index_jar(b"not a zip", 128).expect_err("should reject non-zip");
        assert_eq!(err, JavaJarError::NotZip);
    }
}
