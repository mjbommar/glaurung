//! IOC classification (network addresses, URLs, domains, emails, paths).

use super::normalize::normalize_defanged;
use super::patterns;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

// Retain local aliases for backward compatibility inside this module
fn re_url() -> &'static Regex {
    &patterns::RE_URL
}
fn re_email() -> &'static Regex {
    &patterns::RE_EMAIL
}
fn re_path_win() -> &'static Regex {
    &patterns::RE_PATH_WINDOWS
}
fn re_path_unc() -> &'static Regex {
    &patterns::RE_PATH_UNC
}
fn re_path_posix() -> &'static Regex {
    &patterns::RE_PATH_POSIX
}
fn re_registry() -> &'static Regex {
    &patterns::RE_REGISTRY
}
fn re_java_path() -> &'static Regex {
    &patterns::RE_JAVA_PATH
}

static ALLOWED_TLDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "com", "org", "net", "io", "gov", "edu", "mil", "co", "uk", "de", "fr", "jp", "cn", "ru",
        "br", "au", "ca", "es", "it", "nl", "se", "no", "fi", "dk", "pl", "ch", "at", "be", "cz",
        "sk", "ua", "in", "kr", "tw", "hk", "sg", "za", "ar", "mx", "info", "biz", "xyz", "top",
        "site", "club", "online",
    ]
    .into_iter()
    .collect()
});

fn strip_punct(token: &str) -> &str {
    token.trim_matches(|c: char| {
        matches!(
            c,
            '.' | ',' | ';' | ':' | ')' | ']' | '}' | '>' | '"' | '\''
        )
    })
}

fn count_matches(re: &Regex, text: &str, max: usize) -> usize {
    re.find_iter(text).take(max).count()
}

fn count_ipv4_tokens(text: &str, max: usize) -> usize {
    let mut n = 0usize;
    for raw in text.split(|c: char| c.is_whitespace()) {
        if n >= max {
            break;
        }
        let tok = strip_punct(raw);
        // strip :port if present
        let host = tok.split(':').next().unwrap_or("");
        if let Ok(_ip) = host.parse::<Ipv4Addr>() {
            n += 1;
        }
    }
    n
}

fn count_ipv6_tokens(text: &str, max: usize) -> usize {
    let mut n = 0usize;
    for raw in text.split(|c: char| c.is_whitespace()) {
        if n >= max {
            break;
        }
        let tok = strip_punct(raw).trim_matches(['[', ']']);
        // strip %zone if present
        let host = tok.split('%').next().unwrap_or(tok);
        if host.contains(':') {
            if let Ok(_ip) = host.parse::<Ipv6Addr>() {
                n += 1;
            }
        }
    }
    n
}

fn count_domains(text: &str, max: usize) -> usize {
    let mut n = 0usize;
    for raw in text.split(|c: char| c.is_whitespace()) {
        if n >= max {
            break;
        }
        let tok = strip_punct(raw);
        if tok.contains('/') || tok.contains('\\') {
            continue; // ignore paths and jar entries
        }
        if !tok.contains('.') {
            continue;
        }
        let lower = tok.trim_matches('.').trim().to_lowercase();
        let parts: Vec<&str> = lower.split('.').collect();
        if parts.len() < 2 {
            continue;
        }
        let tld = parts.last().unwrap();
        // exclude file-ish extensions and restrict to allowed TLDs
        let excluded_exts = [
            "class",
            "java",
            "mf",
            "xml",
            "properties",
            "txt",
            "json",
            "yaml",
        ];
        if excluded_exts.contains(tld) {
            continue;
        }
        if !ALLOWED_TLDS.contains(tld) {
            continue;
        }
        // crude: require a letter in the SLD
        if !parts[parts.len() - 2]
            .chars()
            .any(|c| c.is_ascii_alphabetic())
        {
            continue;
        }
        n += 1;
    }
    n
}

fn count_hostnames(text: &str, max: usize) -> usize {
    let mut n = 0usize;
    for m in patterns::RE_HOSTNAME.find_iter(text) {
        if n >= max {
            break;
        }
        let host = m.as_str();
        // Skip plain IPv4 literals to avoid double counting
        if host.parse::<Ipv4Addr>().is_ok() {
            continue;
        }
        n += 1;
    }
    n
}

/// Classify a set of texts and return IOC counts by category.
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
        // Normalize common defanging schemes to increase recall safely
        let tnorm = normalize_defanged(text, 16 * 1024);
        let text = tnorm.as_ref();
        bump("url", count_matches(re_url(), text, max_per_text));
        bump("email", count_matches(re_email(), text, max_per_text));
        bump("hostname", count_hostnames(text, max_per_text));
        bump("domain", count_domains(text, max_per_text));
        bump(
            "path_windows",
            count_matches(re_path_win(), text, max_per_text),
        );
        bump("path_unc", count_matches(re_path_unc(), text, max_per_text));
        bump(
            "path_posix",
            count_matches(re_path_posix(), text, max_per_text),
        );
        bump("registry", count_matches(re_registry(), text, max_per_text));
        bump(
            "java_path",
            count_matches(re_java_path(), text, max_per_text),
        );
        bump("ipv4", count_ipv4_tokens(text, max_per_text));
        bump("ipv6", count_ipv6_tokens(text, max_per_text));
    }

    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_basic_iocs() {
        let sample = [
            "Visit https://example.com/path and http://foo.bar.",
            "Contact: user@example.org",
            "Server at 192.168.1.10, IPv6 2001:db8::1",
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
}
