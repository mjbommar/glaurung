//! Common, precompiled regex patterns for string and symbol scanning.
//!
//! Patterns are intentionally conservative to avoid catastrophic backtracking
//! and false positives. Prefer token validation (e.g., std::net::IpAddr::from_str)
//! after regex candidate extraction where appropriate.

use once_cell::sync::Lazy;
use regex::Regex;

// URLs and emails
pub static RE_URL: Lazy<Regex> = Lazy::new(|| {
    // http/https URLs; simple and robust
    Regex::new(r#"(?i)\bhttps?://[^\s'"<>]+"#).expect("valid URL regex")
});
pub static RE_EMAIL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b"#).expect("valid email regex")
});

// Hostnames and domains (RFC 1123-ish; labels 1-63, alnum + hyphen, no leading/trailing hyphen)
pub static RE_HOST_LABEL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?"#).expect("valid host label")
});
pub static RE_HOSTNAME: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?))+\b"#)
        .expect("valid hostname regex")
});

// IPv4 candidates (validate with std::net::Ipv4Addr after match)
pub static RE_IPV4_CANDIDATE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\b(?:\d{1,3}\.){3}\d{1,3}\b"#).expect("valid ipv4 candidate regex"));

// IPv6 candidates: supports compressed forms; prefer validation post-match
pub static RE_IPV6_CANDIDATE: Lazy<Regex> = Lazy::new(|| {
    // Bracketed or bare IPv6 with 2+ colons, hex segments
    Regex::new(r#"\b(?:\[[0-9A-Fa-f:%\.]+\]|[0-9A-Fa-f:%\.]*:[0-9A-Fa-f:%\.]+)\b"#)
        .expect("valid ipv6 candidate regex")
});

// Windows and UNC paths
pub static RE_PATH_WINDOWS: Lazy<Regex> = Lazy::new(|| {
    // Broad and fast: drive letter + backslash + non-whitespace
    Regex::new(r#"(?i)[A-Z]:\\[^\s]+"#).expect("valid windows path regex")
});
pub static RE_PATH_UNC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\\\\[A-Za-z0-9._$\-]+\\[^\s<>:"|?*]+"#).expect("valid UNC path regex")
});

// POSIX paths (greedy but bounded by whitespace)
pub static RE_PATH_POSIX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"/(?:[^\s\x00]+)"#).expect("valid posix path regex"));

// Windows Registry keys
pub static RE_REGISTRY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\r\n\t]+"#)
        .expect("valid registry regex")
});

// Java-ish internal paths, e.g., a/b/C.class or META-INF/MANIFEST.MF
pub static RE_JAVA_PATH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(?:[a-z0-9_\-\.]+/)+[a-z0-9$_.\-]+(?:\.class)?\b"#)
        .expect("valid java path regex")
});

// C/C++ identifiers and common mangled name patterns (approximate)
pub static RE_C_IDENTIFIER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\b[_A-Za-z][_A-Za-z0-9]*\b"#).expect("valid c identifier regex"));
pub static RE_ITA_MANGLED: Lazy<Regex> = Lazy::new(|| {
    // Itanium (GCC/Clang) ABI: _Z...
    Regex::new(r#"\b_Z[a-zA-Z0-9_][a-zA-Z0-9_]*\b"#).expect("valid itanium mangled regex")
});
pub static RE_MSVC_MANGLED: Lazy<Regex> = Lazy::new(|| {
    // MSVC: ?name@@... or ??0... (avoid word boundaries due to '?')
    Regex::new(r#"\?\??[A-Za-z0-9_@\$\?]+@@[A-Za-z0-9_@\$\?]+"#).expect("valid msvc mangled regex")
});
