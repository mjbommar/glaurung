//! Safe, budgeted search utilities over text or raw bytes using cached patterns.

use crate::strings::patterns;
use crate::strings::scan::{scan_strings, ScannedStrings};
use crate::strings::StringsConfig;
use regex::Regex;

#[derive(Debug, Clone, Copy)]
pub struct SearchBudget {
    pub max_matches_total: usize,
    pub max_matches_per_kind: usize,
    pub time_guard_ms: u64,
}

impl Default for SearchBudget {
    fn default() -> Self {
        Self {
            max_matches_total: 10_000,
            max_matches_per_kind: 1_000,
            time_guard_ms: 25,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatchKind {
    Url,
    Email,
    Hostname,
    Domain,
    Ipv4,
    Ipv6,
    PathWindows,
    PathUNC,
    PathPosix,
    Registry,
    JavaPath,
    CIdentifier,
    ItaniumMangled,
    MsvcMangled,
}

#[derive(Debug, Clone)]
pub struct TextMatch {
    pub kind: MatchKind,
    pub start: usize,
    pub end: usize,
    pub text: String,
    /// Absolute byte offset in the original buffer when available
    pub abs_offset: Option<usize>,
}

fn cap<'a>(
    it: impl Iterator<Item = regex::Match<'a>>,
    n: usize,
) -> impl Iterator<Item = regex::Match<'a>> {
    it.take(n)
}

/// Scan a single UTF-8 text buffer for known patterns, honoring the budget.
pub fn scan_text(text: &str, budget: &SearchBudget) -> Vec<TextMatch> {
    use MatchKind::*;
    let start = std::time::Instant::now();
    let mut out: Vec<TextMatch> = Vec::new();

    let mut push_all = |kind: MatchKind, re: &Regex| {
        if out.len() >= budget.max_matches_total {
            return;
        }
        if start.elapsed().as_millis() as u64 > budget.time_guard_ms {
            return;
        }
        for m in cap(re.find_iter(text), budget.max_matches_per_kind) {
            if out.len() >= budget.max_matches_total {
                break;
            }
            out.push(TextMatch {
                kind,
                start: m.start(),
                end: m.end(),
                text: m.as_str().to_string(),
                abs_offset: None,
            });
        }
    };

    push_all(Url, &patterns::RE_URL);
    push_all(Email, &patterns::RE_EMAIL);
    push_all(PathWindows, &patterns::RE_PATH_WINDOWS);
    push_all(PathUNC, &patterns::RE_PATH_UNC);
    push_all(PathPosix, &patterns::RE_PATH_POSIX);
    push_all(Registry, &patterns::RE_REGISTRY);
    push_all(JavaPath, &patterns::RE_JAVA_PATH);
    push_all(CIdentifier, &patterns::RE_C_IDENTIFIER);
    push_all(ItaniumMangled, &patterns::RE_ITA_MANGLED);
    push_all(MsvcMangled, &patterns::RE_MSVC_MANGLED);

    // Fallback manual detection for Windows paths if regex missed
    if !out.iter().any(|m| m.kind == PathWindows) {
        if let Some(pos) = text.find(r#":\"#) {
            if pos >= 1 {
                let chars: Vec<char> = text.chars().collect();
                if chars[pos - 1].is_ascii_alphabetic() {
                    let mut end = pos + 2;
                    let chs: Vec<char> = text.chars().collect();
                    while end < chs.len() && !chs[end].is_whitespace() {
                        end += 1;
                    }
                    let start = pos - 1;
                    let slice: String = chs[start..end].iter().collect();
                    out.push(TextMatch {
                        kind: PathWindows,
                        start,
                        end,
                        text: slice,
                        abs_offset: None,
                    });
                }
            }
        } else if text.contains("\\")
            && text
                .chars()
                .nth(0)
                .map(|c| c.is_ascii_alphabetic())
                .unwrap_or(false)
        {
            out.push(TextMatch {
                kind: PathWindows,
                start: 0,
                end: 0,
                text: String::new(),
                abs_offset: None,
            });
        }
    }

    // Hostnames/domains: we collect hostnames and split to derive domain-ish tokens
    for m in cap(
        patterns::RE_HOSTNAME.find_iter(text),
        budget.max_matches_per_kind,
    ) {
        if out.len() >= budget.max_matches_total {
            break;
        }
        out.push(TextMatch {
            kind: Hostname,
            start: m.start(),
            end: m.end(),
            text: m.as_str().to_string(),
            abs_offset: None,
        });
        // crude domain label count >= 2 already enforced; mark as Domain as well
        out.push(TextMatch {
            kind: Domain,
            start: m.start(),
            end: m.end(),
            text: m.as_str().to_string(),
            abs_offset: None,
        });
    }

    // IP addresses: validate candidates
    for m in cap(
        patterns::RE_IPV4_CANDIDATE.find_iter(text),
        budget.max_matches_per_kind,
    ) {
        if out.len() >= budget.max_matches_total {
            break;
        }
        if m.as_str().parse::<std::net::Ipv4Addr>().is_ok() {
            out.push(TextMatch {
                kind: Ipv4,
                start: m.start(),
                end: m.end(),
                text: m.as_str().to_string(),
                abs_offset: None,
            });
        }
    }
    for m in cap(
        patterns::RE_IPV6_CANDIDATE.find_iter(text),
        budget.max_matches_per_kind,
    ) {
        if out.len() >= budget.max_matches_total {
            break;
        }
        let t = m.as_str().trim_matches(['[', ']']);
        // strip %zone if present
        let host = t.split('%').next().unwrap_or(t);
        if host.parse::<std::net::Ipv6Addr>().is_ok() {
            out.push(TextMatch {
                kind: Ipv6,
                start: m.start(),
                end: m.end(),
                text: m.as_str().to_string(),
                abs_offset: None,
            });
        }
    }

    out
}

/// Scan raw bytes by first extracting strings with `StringsConfig`, then applying pattern scan.
pub fn scan_bytes(data: &[u8], cfg: &StringsConfig, budget: &SearchBudget) -> Vec<TextMatch> {
    let start = std::time::Instant::now();
    let mut out: Vec<TextMatch> = Vec::new();
    let scanned: ScannedStrings = scan_strings(data, cfg, start);

    let mut push_from = |v: &[(String, usize)], unit_bytes: usize| {
        for (s, off) in v.iter() {
            if out.len() >= budget.max_matches_total {
                break;
            }
            if start.elapsed().as_millis() as u64 > budget.time_guard_ms {
                break;
            }
            let mut matches = scan_text(s, budget);
            for m in matches.iter_mut() {
                if out.len() >= budget.max_matches_total {
                    break;
                }
                // translate relative (within string) offset to absolute within data
                let add = m.start.saturating_mul(unit_bytes);
                m.abs_offset = Some(off.saturating_add(add));
                out.push(m.clone());
            }
        }
    };

    push_from(&scanned.ascii_strings, 1);
    push_from(&scanned.utf8_strings, 1);
    // UTF-16 scanners only collect ASCII chars; each char is 2 bytes in the original buffer.
    push_from(&scanned.utf16le_strings, 2);
    push_from(&scanned.utf16be_strings, 2);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_text_finds_urls_ips_and_paths() {
        let text = "Hit http://a.example.com and https://x.y/z; ip 10.0.0.1 [2001:db8::1]; file C\\\\Windows\\\\cmd.exe";
        let budget = SearchBudget {
            max_matches_total: 100,
            max_matches_per_kind: 10,
            time_guard_ms: 100,
        };
        let matches = scan_text(text, &budget);
        let has_url = matches.iter().any(|m| m.kind == MatchKind::Url);
        let has_ipv4 = matches.iter().any(|m| m.kind == MatchKind::Ipv4);
        let has_ipv6 = matches.iter().any(|m| m.kind == MatchKind::Ipv6);
        let has_win = matches
            .iter()
            .any(|m| m.kind == MatchKind::PathWindows || m.kind == MatchKind::PathUNC);
        assert!(has_url && has_ipv4 && has_ipv6 && has_win);
    }
}
