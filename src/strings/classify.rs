//! IOC classification with reduced false positives through semantic validation.

use super::normalize::normalize_defanged;
use super::patterns;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

// Comprehensive TLD list for better validation
static VALID_TLDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        // Generic TLDs
        "com",
        "org",
        "net",
        "edu",
        "gov",
        "mil",
        "int",
        // Country Code TLDs (most common)
        "uk",
        "us",
        "ca",
        "au",
        "de",
        "fr",
        "it",
        "es",
        "nl",
        "se",
        "no",
        "fi",
        "dk",
        "be",
        "ch",
        "at",
        "pl",
        "ru",
        "cn",
        "jp",
        "kr",
        "in",
        "br",
        "mx",
        "ar",
        "za",
        "eg",
        "ng",
        "ke",
        "nz",
        "ie",
        "pt",
        "gr",
        "tr",
        "ae",
        "sa",
        // New Generic TLDs (common ones)
        "io",
        "ai",
        "app",
        "dev",
        "tech",
        "cloud",
        "online",
        "store",
        "site",
        "xyz",
        "info",
        "biz",
        "name",
        "pro",
        "academy",
        "agency",
        "blog",
        "digital",
        "email",
        "group",
        "live",
        "media",
        "network",
        "news",
        "shop",
        "social",
        "solutions",
        "support",
        "systems",
        "technology",
        "today",
        "tools",
        "travel",
        "tv",
        "video",
        "web",
        "website",
        "work",
        "world",
        "zone",
        "me",
        "co",
        "cc",
        "to",
        "gg",
        "one",
        "ltd",
        "company",
        "global",
        // Regional/Language
        "asia",
        "africa",
        "berlin",
        "london",
        "nyc",
        "paris",
        "tokyo",
        "eu",
        // Often abused but still valid TLDs
        "tk",
        "ml",
        "ga",
        "cf",
        "ws",
        "pw",
        "click",
        "download",
        "link",
        "top",
    ]
    .into_iter()
    .collect()
});

// Common false positive patterns
static FALSE_POSITIVE_DOMAINS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        // Version-like patterns
        "1.0",
        "2.0",
        "3.0",
        "1.1",
        "1.2",
        // Common programming patterns
        "system.io",
        "system.net",
        "java.io",
        "java.net",
        // File extensions that look like domains
        "manifest.mf",
        "package.json",
        "index.html",
        "main.class",
        "config.properties",
    ]
    .into_iter()
    .collect()
});

/// Validate if an IPv4 address is likely a real network indicator
fn is_valid_network_ipv4(ip: &Ipv4Addr) -> bool {
    // Reject loopback and unspecified addresses
    if ip.is_loopback() || ip.is_unspecified() {
        return false;
    }

    let octets = ip.octets();

    // Reject version-like patterns (x.0.0.y, x.y.0.0, etc.)
    if ((octets[1] == 0 && octets[2] == 0)
        || (octets[2] == 0 && octets[3] == 0)
        || (octets[3] == 0 && octets[0] < 10))
        && octets[0] < 10
    {
        return false;
    }

    // Reject sequential patterns (1.2.3.4, 2.3.4.5, etc.)
    if octets
        .windows(2)
        .all(|w| w[1] == w[0] + 1 || w[1] == w[0].wrapping_add(1))
    {
        return false;
    }

    // Reject mathematical constants
    if (octets[0] == 3 && octets[1] == 14) || // Pi
       (octets[0] == 2 && octets[1] == 71) || // e
       (octets[0] == 1 && octets[1] == 41) || // sqrt(2)
       (octets[0] == 3 && octets[1] == 1 && octets[2] == 4)
    {
        // More pi
        return false;
    }

    // Accept only public routable addresses
    !ip.is_private() && !ip.is_link_local() && !ip.is_broadcast() && !ip.is_documentation()
}

/// Validate if an IPv6 address is likely real
fn is_valid_network_ipv6(ip: &Ipv6Addr) -> bool {
    !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast()
}

/// Validate domain with improved heuristics
fn is_valid_domain(domain: &str) -> bool {
    // Quick reject common false positives
    if FALSE_POSITIVE_DOMAINS.contains(domain) {
        return false;
    }

    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 || parts.len() > 6 {
        return false;
    }

    // Check TLD
    let tld = parts.last().unwrap();

    // Check for common file extensions first (broader list)
    let file_exts = [
        // Programming
        "class",
        "java",
        "py",
        "rs",
        "cpp",
        "h",
        "c",
        "go",
        "js",
        "ts",
        "jsx",
        "tsx",
        "rb",
        "php",
        "cs",
        "swift",
        "kt",
        "scala",
        "clj",
        "ex",
        "erl",
        "hs",
        // Web/Markup
        "html",
        "htm",
        "xml",
        "css",
        "scss",
        "sass",
        "less",
        "svg",
        "vue",
        // Config/Data
        "json",
        "yaml",
        "yml",
        "toml",
        "ini",
        "cfg",
        "conf",
        "properties",
        "env",
        // Documents
        "txt",
        "md",
        "rst",
        "pdf",
        "doc",
        "docx",
        "rtf",
        // Archives/Binaries
        "zip",
        "tar",
        "gz",
        "bz2",
        "xz",
        "rar",
        "7z",
        "jar",
        "war",
        "exe",
        "dll",
        "so",
        "dylib",
        "o",
        "a",
        "lib",
        "pdb",
        "msi",
        "deb",
        "rpm",
        "dmg",
        "pkg",
        // Media
        "jpg",
        "jpeg",
        "png",
        "gif",
        "bmp",
        "ico",
        "svg",
        "webp",
        "mp3",
        "mp4",
        "avi",
        "mkv",
        "mov",
        "wav",
        "flac",
        // Build/Project
        "mf",
        "gradle",
        "sbt",
        "lock",
        "sum",
    ];

    if file_exts.contains(tld) {
        return false;
    }

    // Only check against valid TLDs if not a file extension
    if !VALID_TLDS.contains(tld) {
        return false;
    }

    // Require at least one alphabetic character in second-level domain
    let sld = parts[parts.len() - 2];
    if !sld.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }

    // Reject if all numeric (except TLD)
    if parts[..parts.len() - 1]
        .iter()
        .all(|p| p.chars().all(|c| c.is_ascii_digit()))
    {
        return false;
    }

    true
}

/// Count valid IPv4 addresses with semantic validation
fn count_ipv4_tokens(text: &str, max: usize) -> usize {
    let mut n = 0usize;
    let mut seen = HashSet::new();

    for raw in text.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        if n >= max {
            break;
        }

        let tok = raw.trim_matches(|c: char| c.is_ascii_punctuation() && c != '.' && c != ':');
        let host = tok.split(':').next().unwrap_or("");

        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            // Deduplicate and validate
            if seen.insert(ip) && is_valid_network_ipv4(&ip) {
                n += 1;
            }
        }
    }
    n
}

/// Count valid IPv6 addresses with validation
fn count_ipv6_tokens(text: &str, max: usize) -> usize {
    let mut n = 0usize;
    let mut seen = HashSet::new();

    for raw in text.split(|c: char| c.is_whitespace()) {
        if n >= max {
            break;
        }

        let tok = raw
            .trim_matches(|c: char| c.is_ascii_punctuation() && c != ':' && c != '[' && c != ']');
        let tok = tok.trim_matches(['[', ']']);
        let host = tok.split('%').next().unwrap_or(tok);

        // Must contain at least 2 colons for IPv6
        if host.matches(':').count() >= 2 {
            if let Ok(ip) = host.parse::<Ipv6Addr>() {
                if seen.insert(ip) && is_valid_network_ipv6(&ip) {
                    n += 1;
                }
            }
        }
    }
    n
}

/// Count valid domains with improved validation
fn count_domains(text: &str, max: usize) -> usize {
    let mut n = 0usize;
    let mut seen = HashSet::new();

    for raw in text.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        if n >= max {
            break;
        }

        let tok = raw.trim_matches(|c: char| c.is_ascii_punctuation() && c != '.' && c != '-');

        // Skip paths and URLs
        if tok.contains('/') || tok.contains('\\') || tok.starts_with("http") {
            continue;
        }

        let lower = tok.to_lowercase();
        if seen.insert(lower.clone()) && is_valid_domain(&lower) {
            n += 1;
        }
    }
    n
}

/// Count valid hostnames with improved filtering
fn count_hostnames(text: &str, max: usize) -> usize {
    let mut n = 0usize;
    let mut seen = HashSet::new();

    // Common file extensions to exclude
    let file_exts = [
        "class",
        "java",
        "py",
        "rs",
        "cpp",
        "h",
        "c",
        "go",
        "js",
        "ts",
        "html",
        "htm",
        "xml",
        "css",
        "json",
        "yaml",
        "yml",
        "toml",
        "ini",
        "txt",
        "md",
        "pdf",
        "properties",
        "conf",
        "cfg",
        "log",
        "csv",
        "jar",
        "war",
        "zip",
        "tar",
        "gz",
        "exe",
        "dll",
        "so",
        "mf",
    ];

    for m in patterns::RE_HOSTNAME.find_iter(text) {
        if n >= max {
            break;
        }

        let host = m.as_str().to_lowercase();

        // Skip IPv4 addresses
        if host.parse::<Ipv4Addr>().is_ok() {
            continue;
        }

        // Skip filenames (check last part for file extension)
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() >= 2 {
            let last = parts.last().unwrap();
            if file_exts.contains(last) {
                continue;
            }
        }

        // Skip version-like patterns
        if parts.len() <= 4
            && parts
                .iter()
                .all(|p| p.parse::<u32>().map(|n| n < 100).unwrap_or(false))
        {
            continue;
        }

        // Require at least one part with alphabetic characters
        if !parts
            .iter()
            .any(|p| p.chars().any(|c| c.is_ascii_alphabetic()))
        {
            continue;
        }

        // Require at least 2 parts for a hostname
        if parts.len() < 2 {
            continue;
        }

        if seen.insert(host) {
            n += 1;
        }
    }
    n
}

/// Classify a set of texts with improved precision and reduced false positives
pub fn classify_texts<'a, I: IntoIterator<Item = &'a str>>(
    iter: I,
    max_per_text: usize,
) -> HashMap<String, u32> {
    let mut counts: HashMap<String, u32> = HashMap::new();
    let mut bump = |k: &str, v: usize| {
        if v > 0 {
            *counts.entry(k.to_string()).or_insert(0) += v as u32;
        }
    };

    for text in iter {
        // Normalize defanged indicators
        let tnorm = normalize_defanged(text, 16 * 1024);
        let text = tnorm.as_ref();

        // URLs and emails (existing patterns are adequate)
        bump(
            "url",
            patterns::RE_URL.find_iter(text).take(max_per_text).count(),
        );
        bump(
            "email",
            patterns::RE_EMAIL
                .find_iter(text)
                .take(max_per_text)
                .count(),
        );

        // Network indicators with improved validation
        bump("hostname", count_hostnames(text, max_per_text));
        bump("domain", count_domains(text, max_per_text));
        bump("ipv4", count_ipv4_tokens(text, max_per_text));
        bump("ipv6", count_ipv6_tokens(text, max_per_text));

        // File paths (keep existing patterns)
        bump(
            "path_windows",
            patterns::RE_PATH_WINDOWS
                .find_iter(text)
                .take(max_per_text)
                .count(),
        );
        bump(
            "path_unc",
            patterns::RE_PATH_UNC
                .find_iter(text)
                .take(max_per_text)
                .count(),
        );
        bump(
            "path_posix",
            patterns::RE_PATH_POSIX
                .find_iter(text)
                .take(max_per_text)
                .count(),
        );
        bump(
            "registry",
            patterns::RE_REGISTRY
                .find_iter(text)
                .take(max_per_text)
                .count(),
        );
        bump(
            "java_path",
            patterns::RE_JAVA_PATH
                .find_iter(text)
                .take(max_per_text)
                .count(),
        );

        // Hash-like tokens (conservative)
        let (md5_n, sha1_n, sha256_n) = count_hashes(text, max_per_text);
        bump("md5", md5_n);
        bump("sha1", sha1_n);
        bump("sha256", sha256_n);
    }

    counts
}

// Precompiled regex for hex sequences
static RE_HEX_32: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b[a-f0-9]{32}\b").expect("hex32"));
static RE_HEX_40: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b[a-f0-9]{40}\b").expect("hex40"));
static RE_HEX_64: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b[a-f0-9]{64}\b").expect("hex64"));

fn plausible_hex_hash(s: &str) -> bool {
    // Reject trivial repeats and very low diversity
    let unique: std::collections::HashSet<char> = s.chars().collect();
    if unique.len() < 4 {
        return false;
    }
    // Reject all-zero/all-f/obvious padding
    if s.chars().all(|c| c == '0') || s.chars().all(|c| c == 'f' || c == 'F') {
        return false;
    }
    // Accept
    true
}

fn count_hashes(text: &str, max_per_text: usize) -> (usize, usize, usize) {
    let mut md5 = 0usize;
    let mut sha1 = 0usize;
    let mut sha256 = 0usize;
    for m in RE_HEX_32.find_iter(text).take(max_per_text) {
        let tok = m.as_str();
        if plausible_hex_hash(tok) {
            md5 += 1;
        }
    }
    for m in RE_HEX_40.find_iter(text).take(max_per_text) {
        let tok = m.as_str();
        if plausible_hex_hash(tok) {
            sha1 += 1;
        }
    }
    for m in RE_HEX_64.find_iter(text).take(max_per_text) {
        let tok = m.as_str();
        if plausible_hex_hash(tok) {
            sha256 += 1;
        }
    }
    (md5, sha1, sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_basic_iocs() {
        let sample = [
            "Visit https://example.com/path and http://foo.bar.",
            "Contact: user@example.org",
            "Server at 8.8.8.8, IPv6 2001:db8::1",
            r"C:\\Windows\\System32\\cmd.exe and \\server\\share\\file.txt",
            "/usr/local/bin/python3 and HKLM\\Software\\Vendor",
        ];
        let counts = classify_texts(sample.iter().cloned(), 10);
        assert!(counts.get("url").cloned().unwrap_or(0) >= 2);
        assert!(counts.get("email").cloned().unwrap_or(0) >= 1);
        assert!(counts.get("ipv4").cloned().unwrap_or(0) >= 1);
        assert!(counts.get("ipv6").cloned().unwrap_or(0) >= 1);
        assert!(counts.get("path_windows").cloned().unwrap_or(0) >= 1);
        assert!(counts.get("path_unc").cloned().unwrap_or(0) >= 1);
        assert!(counts.get("path_posix").cloned().unwrap_or(0) >= 1);
        assert!(counts.get("registry").cloned().unwrap_or(0) >= 1);
    }

    #[test]
    fn classify_handles_defanged_and_hostnames() {
        let sample = [
            "hxxps://evil[.]example(.)com/login",
            "connect to sub.domain.example.com",
        ];
        let counts = classify_texts(sample.iter().cloned(), 10);
        // defanged URL should be recognized after normalization
        assert!(counts.get("url").cloned().unwrap_or(0) >= 1);
        // hostname bucket includes FQDNs
        assert!(counts.get("hostname").cloned().unwrap_or(0) >= 1);
    }

    #[test]
    fn test_no_false_positive_versions() {
        // Version strings should not be detected as IPs
        let samples = ["1.0.0.0", "2.0.0.1", "3.1.4.159", "1.2.3.4"];
        let counts = classify_texts(samples.iter().cloned(), 10);
        assert_eq!(counts.get("ipv4").cloned().unwrap_or(0), 0);
    }

    #[test]
    fn test_valid_public_ips_detected() {
        // Real public IPs should be detected
        let samples = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "185.228.168.168"];
        let counts = classify_texts(samples.iter().cloned(), 10);
        assert_eq!(counts.get("ipv4").cloned().unwrap_or(0), 4);
    }

    #[test]
    fn test_private_ips_rejected() {
        // Private IPs should be rejected
        let samples = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"];
        let counts = classify_texts(samples.iter().cloned(), 10);
        assert_eq!(counts.get("ipv4").cloned().unwrap_or(0), 0);
    }

    #[test]
    fn test_no_false_positive_file_extensions() {
        // File names should not be detected as domains
        let samples = [
            "Main.class",
            "config.properties",
            "index.html",
            "package.json",
        ];
        let counts = classify_texts(samples.iter().cloned(), 10);
        assert_eq!(counts.get("domain").cloned().unwrap_or(0), 0);
    }

    #[test]
    fn test_valid_domains_detected() {
        // Real domains should be detected
        let samples = ["google.com", "github.io", "example.org", "malware-c2.tk"];
        let counts = classify_texts(samples.iter().cloned(), 10);
        assert!(counts.get("domain").cloned().unwrap_or(0) >= 3);
    }

    #[test]
    fn test_dos_stub_not_hostname() {
        // DOS stub message should not trigger hostname detection
        let dos_stub = "This program cannot be run in DOS mode";
        let counts = classify_texts([dos_stub].iter().cloned(), 10);
        assert_eq!(counts.get("hostname").cloned().unwrap_or(0), 0);
    }
}
