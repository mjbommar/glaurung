//! Fail-closed import of capsule metadata and separately stored page payloads.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, Metadata, OpenOptions};
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::capsule::{CapsuleLimits, PageContent, ProcessCapsule};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedBundle {
    pub capsule: ProcessCapsule,
    pub payloads: BTreeMap<String, Vec<u8>>,
}

/// Import one public capsule manifest and its exact sensitive payload set.
///
/// Payload files are named `<payload-id>.bin`. IDs are treated as identifiers,
/// never paths. The directory must contain exactly the referenced set.
pub fn import_capsule_bundle(
    metadata_path: &Path,
    payload_directory: &Path,
    limits: CapsuleLimits,
) -> Result<ImportedBundle, String> {
    let metadata = read_regular_file(
        metadata_path,
        limits.max_manifest_bytes as u64,
        "capsule metadata",
    )?;
    let capsule = ProcessCapsule::from_json(&metadata, limits)?;
    validate_directory(payload_directory, "capsule payload directory")?;

    let references = payload_references(&capsule)?;
    let expected_names: BTreeSet<String> =
        references.keys().map(|id| format!("{id}.bin")).collect();
    let actual_names = directory_names(payload_directory)?;
    if actual_names != expected_names {
        let missing: Vec<_> = expected_names.difference(&actual_names).cloned().collect();
        let extra: Vec<_> = actual_names.difference(&expected_names).cloned().collect();
        return Err(format!(
            "capsule payload set disagrees with metadata: missing={missing:?}, extra={extra:?}"
        ));
    }

    let mut payloads = BTreeMap::new();
    for (id, reference) in references {
        let path = payload_directory.join(format!("{id}.bin"));
        let bytes = read_regular_file(&path, reference.byte_len, "capsule payload")?;
        if bytes.len() as u64 != reference.byte_len {
            return Err(format!(
                "capsule payload {id} length {} disagrees with {}",
                bytes.len(),
                reference.byte_len
            ));
        }
        let actual_hash = hex::encode(Sha256::digest(&bytes));
        if actual_hash != reference.sha256 {
            return Err(format!(
                "capsule payload {id} SHA-256 disagrees with metadata"
            ));
        }
        payloads.insert(id, bytes);
    }
    Ok(ImportedBundle { capsule, payloads })
}

#[derive(Debug, Clone)]
struct ExpectedPayload {
    byte_len: u64,
    sha256: String,
}

fn payload_references(
    capsule: &ProcessCapsule,
) -> Result<BTreeMap<String, ExpectedPayload>, String> {
    let mut references = BTreeMap::new();
    for page in &capsule.pages {
        let PageContent::Captured { payload } = &page.content else {
            continue;
        };
        validate_payload_id(&payload.id)?;
        if references
            .insert(
                payload.id.clone(),
                ExpectedPayload {
                    byte_len: payload.byte_len,
                    sha256: payload.sha256.clone(),
                },
            )
            .is_some()
        {
            return Err(format!("duplicate capsule payload id: {}", payload.id));
        }
    }
    for snapshot in &capsule.object_snapshots {
        let PageContent::Captured { payload } = &snapshot.content else {
            continue;
        };
        validate_payload_id(&payload.id)?;
        if references
            .insert(
                payload.id.clone(),
                ExpectedPayload {
                    byte_len: payload.byte_len,
                    sha256: payload.sha256.clone(),
                },
            )
            .is_some()
        {
            return Err(format!("duplicate capsule payload id: {}", payload.id));
        }
    }
    for output in &capsule.outputs {
        let payload = &output.payload;
        validate_payload_id(&payload.id)?;
        if references
            .insert(
                payload.id.clone(),
                ExpectedPayload {
                    byte_len: payload.byte_len,
                    sha256: payload.sha256.clone(),
                },
            )
            .is_some()
        {
            return Err(format!("duplicate capsule payload id: {}", payload.id));
        }
    }
    Ok(references)
}

fn validate_payload_id(id: &str) -> Result<(), String> {
    if id.is_empty()
        || id == "."
        || id == ".."
        || id.len() > 255
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(format!("unsafe capsule payload id: {id:?}"));
    }
    Ok(())
}

fn validate_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{label} is not a non-symlink directory"));
    }
    Ok(())
}

fn directory_names(path: &Path) -> Result<BTreeSet<String>, String> {
    fs::read_dir(path)
        .map_err(|error| format!("read capsule payload directory: {error}"))?
        .map(|entry| {
            let entry = entry.map_err(|error| format!("read capsule payload entry: {error}"))?;
            entry
                .file_name()
                .into_string()
                .map_err(|_| "capsule payload directory contains a non-UTF-8 filename".to_string())
        })
        .collect()
}

fn read_regular_file(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(format!("{label} is not a non-symlink regular file"));
    }
    if before.len() > max_bytes {
        return Err(format!(
            "{label} bytes {} exceed limit {max_bytes}",
            before.len()
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    set_no_follow(&mut options);
    let mut file = options
        .open(path)
        .map_err(|error| format!("open {label} {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("inspect opened {label}: {error}"))?;
    if !same_file(&before, &opened) || !opened.is_file() {
        return Err(format!("{label} changed during secure open"));
    }
    let capacity = usize::try_from(opened.len().min(max_bytes))
        .map_err(|_| format!("{label} length does not fit memory address space"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {label}: {error}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "{label} grew beyond limit {max_bytes} while reading"
        ));
    }
    let after = file
        .metadata()
        .map_err(|error| format!("reinspect opened {label}: {error}"))?;
    if !same_file(&opened, &after) || after.len() != bytes.len() as u64 {
        return Err(format!("{label} changed while reading"));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn set_no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
}

#[cfg(windows)]
fn set_no_follow(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn set_no_follow(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len()
        && left.file_type().is_file() == right.file_type().is_file()
        && left.modified().ok() == right.modified().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_ids_are_identifiers_not_paths() {
        for invalid in ["", ".", "..", "../page", "page/one", "page.one", "a\\b"] {
            assert!(
                validate_payload_id(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        for valid in ["page-1", "PAGE_2", "core-load-000001"] {
            validate_payload_id(valid).expect("valid payload identifier");
        }
    }

    #[test]
    fn symlink_file_is_rejected_before_read() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let target = temporary.path().join("target");
        fs::write(&target, b"secret").expect("write target");
        let link = temporary.path().join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, &link).expect("create symlink");
        #[cfg(any(unix, windows))]
        assert!(read_regular_file(&link, 100, "fixture").is_err());
    }
}
