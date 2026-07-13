//! SELinux binary policy (`policydb`) parsing.
//!
//! Android ships a compiled binary policy (`/sys/fs/selinux/policy`,
//! `precompiled_sepolicy`) that encodes every `allow` rule. It is the load-
//! bearing severity gate for Android findings: *"can `untrusted_app` actually
//! reach this resource?"* is answered by the policy's domain→type access
//! vectors, not by any Linux uid.
//!
//! This module parses the `policydb` container. **Currently implemented:** the
//! header (magic, version, MLS flag, symbol/ocontext table counts) and format
//! detection. The symbol tables (types/classes/perms) and the access-vector
//! table (`avtab`) that back a `domain→resource` reachability query are the next
//! slice — deliberately staged so the reachability oracle lands correct rather
//! than rushed, since it gates every severity claim.
//!
//! Layout reference: kernel `security/selinux/ss/policydb.c` (`policydb_read`)
//! and libsepol `policydb.c`.

use std::fmt;

/// `policydb` parsing errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// Magic bytes were not `POLICYDB_MAGIC`.
    BadMagic,
    /// The `"SE Linux"` identifier string was missing or wrong.
    BadIdentifier,
    /// Policy version outside the supported range.
    UnsupportedVersion(u32),
    /// A field ran past the end of the buffer.
    Truncated { offset: usize, needed: usize },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => write!(f, "not a SELinux binary policy (bad magic)"),
            Self::BadIdentifier => write!(f, "missing 'SE Linux' policydb identifier"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported policydb version {}", v),
            Self::Truncated { offset, needed } => {
                write!(f, "truncated at {:#x}, needed {} bytes", offset, needed)
            }
        }
    }
}

impl std::error::Error for PolicyError {}

pub type Result<T> = std::result::Result<T, PolicyError>;

/// `POLICYDB_MAGIC` — the little-endian u32 that opens a kernel binary policy.
pub const POLICYDB_MAGIC: u32 = 0xf97c_ff8c;
/// The identifier string that follows the magic/length.
pub const POLICYDB_STRING: &[u8] = b"SE Linux";
/// Oldest / newest `policydb` versions this parser accepts. Android 12–15 use
/// 30–33; upstream is at 35.
pub const POLICYDB_VERSION_MIN: u32 = 15;
pub const POLICYDB_VERSION_MAX: u32 = 35;

/// `config` bit set when the policy is MLS-enabled (all Android policies are).
pub const POLICYDB_CONFIG_MLS: u32 = 1;

/// Parsed `policydb` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyHeader {
    /// Policy database version (e.g. 30, 33).
    pub version: u32,
    /// Whether Multi-Level Security is enabled.
    pub mls: bool,
    /// Number of symbol tables (`SYM_NUM`, 8 for a kernel policy).
    pub sym_num: u32,
    /// Number of object-context table kinds (`OCON_NUM`, version-dependent).
    pub ocon_num: u32,
    /// Byte offset just past the header (where the policy-capability ebitmap and
    /// symbol tables begin) — the entry point for the next parsing slice.
    pub body_offset: usize,
}

fn u32le(data: &[u8], off: usize) -> Result<u32> {
    let b = data.get(off..off + 4).ok_or(PolicyError::Truncated {
        offset: off,
        needed: 4,
    })?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// True if `data` begins with a SELinux binary policy magic + identifier.
pub fn is_sepolicy(data: &[u8]) -> bool {
    if u32le(data, 0) != Ok(POLICYDB_MAGIC) {
        return false;
    }
    match u32le(data, 4) {
        Ok(len) if len as usize == POLICYDB_STRING.len() => {
            data.get(8..8 + POLICYDB_STRING.len()) == Some(POLICYDB_STRING)
        }
        _ => false,
    }
}

/// Parse the `policydb` header.
pub fn parse_header(data: &[u8]) -> Result<PolicyHeader> {
    if u32le(data, 0)? != POLICYDB_MAGIC {
        return Err(PolicyError::BadMagic);
    }
    let slen = u32le(data, 4)? as usize;
    if data.get(8..8 + slen) != Some(POLICYDB_STRING) {
        return Err(PolicyError::BadIdentifier);
    }
    let mut off = 8 + slen;

    let version = u32le(data, off)?;
    off += 4;
    if !(POLICYDB_VERSION_MIN..=POLICYDB_VERSION_MAX).contains(&version) {
        return Err(PolicyError::UnsupportedVersion(version));
    }
    let config = u32le(data, off)?;
    off += 4;
    let sym_num = u32le(data, off)?;
    off += 4;
    let ocon_num = u32le(data, off)?;
    off += 4;

    Ok(PolicyHeader {
        version,
        mls: config & POLICYDB_CONFIG_MLS != 0,
        sym_num,
        ocon_num,
        body_offset: off,
    })
}

#[cfg(test)]
mod tests;
