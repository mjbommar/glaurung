//! Bounded string scanners for ASCII and UTF-16 encodings.

use super::StringsConfig;

/// Scanned strings and counts per encoding.
pub struct ScannedStrings {
    pub ascii_count: u32,
    pub utf8_count: u32,
    pub utf16le_count: u32,
    pub utf16be_count: u32,
    pub ascii_strings: Vec<(String, usize)>,
    pub utf8_strings: Vec<(String, usize)>,
    pub utf16le_strings: Vec<(String, usize)>,
    pub utf16be_strings: Vec<(String, usize)>,
}

impl ScannedStrings {
    fn new() -> Self {
        Self {
            ascii_count: 0,
            utf8_count: 0,
            utf16le_count: 0,
            utf16be_count: 0,
            ascii_strings: Vec::new(),
            utf8_strings: Vec::new(),
            utf16le_strings: Vec::new(),
            utf16be_strings: Vec::new(),
        }
    }
}

/// Scan strings within byte/time budgets and return counts and samples.
pub fn scan_strings(data: &[u8], cfg: &StringsConfig, start: std::time::Instant) -> ScannedStrings {
    let mut out = ScannedStrings::new();
    let scan = &data[..data.len().min(cfg.max_scan_bytes)];

    // ASCII scanner with offsets
    {
        let mut cur: Vec<u8> = Vec::new();
        let mut cur_offset: usize = 0;
        for (i, &b) in scan.iter().enumerate() {
            if (i & 0x0FFF) == 0 && start.elapsed().as_millis() as u64 > cfg.time_guard_ms {
                tracing::debug!("strings/ascii time budget exhausted at {} bytes", i);
                break;
            }
            if (b.is_ascii_graphic() || b == b'\t' || b == b' ') && b != 0x7f {
                if cur.is_empty() {
                    cur_offset = i;
                }
                cur.push(b);
            } else if !cur.is_empty() {
                if cur.len() >= cfg.min_length {
                    out.ascii_count = out.ascii_count.saturating_add(1);
                    if out.ascii_strings.len() < cfg.max_samples {
                        if let Ok(text) = String::from_utf8(cur.clone()) {
                            out.ascii_strings.push((text, cur_offset));
                        }
                    }
                }
                cur.clear();
            }
        }
        if cur.len() >= cfg.min_length {
            out.ascii_count = out.ascii_count.saturating_add(1);
            if out.ascii_strings.len() < cfg.max_samples {
                if let Ok(text) = String::from_utf8(cur) {
                    out.ascii_strings.push((text, cur_offset));
                }
            }
        }
    }

    // UTF-8 scanner: collect runs that contain at least one non-ASCII char
    {
        let mut i = 0usize;
        let mut run_start: Option<usize> = None;
        let mut run_has_non_ascii = false;
        let mut char_count = 0usize;
        while i < scan.len() {
            if (i & 0x0FFF) == 0 && start.elapsed().as_millis() as u64 > cfg.time_guard_ms {
                tracing::debug!("strings/utf8 time budget exhausted at {} bytes", i);
                break;
            }
            let b0 = scan[i];
            let (cp_len, is_ascii) = if b0 < 0x80 {
                (1usize, true)
            } else if (0xC2..=0xDF).contains(&b0) {
                if i + 1 >= scan.len() || (scan[i + 1] & 0xC0) != 0x80 {
                    (0, false)
                } else {
                    (2, false)
                }
            } else if b0 == 0xE0 {
                if i + 2 < scan.len()
                    && (0xA0..=0xBF).contains(&scan[i + 1])
                    && (scan[i + 2] & 0xC0) == 0x80
                {
                    (3, false)
                } else {
                    (0, false)
                }
            } else if (0xE1..=0xEC).contains(&b0) || (0xEE..=0xEF).contains(&b0) {
                if i + 2 < scan.len()
                    && (scan[i + 1] & 0xC0) == 0x80
                    && (scan[i + 2] & 0xC0) == 0x80
                {
                    (3, false)
                } else {
                    (0, false)
                }
            } else if b0 == 0xED {
                if i + 2 < scan.len()
                    && (0x80..=0x9F).contains(&scan[i + 1])
                    && (scan[i + 2] & 0xC0) == 0x80
                {
                    (3, false)
                } else {
                    (0, false)
                }
            } else if b0 == 0xF0 {
                if i + 3 < scan.len()
                    && (0x90..=0xBF).contains(&scan[i + 1])
                    && (scan[i + 2] & 0xC0) == 0x80
                    && (scan[i + 3] & 0xC0) == 0x80
                {
                    (4, false)
                } else {
                    (0, false)
                }
            } else if (0xF1..=0xF3).contains(&b0) {
                if i + 3 < scan.len()
                    && (scan[i + 1] & 0xC0) == 0x80
                    && (scan[i + 2] & 0xC0) == 0x80
                    && (scan[i + 3] & 0xC0) == 0x80
                {
                    (4, false)
                } else {
                    (0, false)
                }
            } else if b0 == 0xF4 {
                if i + 3 < scan.len()
                    && (0x80..=0x8F).contains(&scan[i + 1])
                    && (scan[i + 2] & 0xC0) == 0x80
                    && (scan[i + 3] & 0xC0) == 0x80
                {
                    (4, false)
                } else {
                    (0, false)
                }
            } else {
                (0, false)
            };

            if cp_len == 0 {
                // invalid; end run if present
                if let Some(start_idx) = run_start.take() {
                    if char_count >= cfg.min_length && run_has_non_ascii {
                        let end = i;
                        if let Ok(text) = std::str::from_utf8(&scan[start_idx..end]) {
                            out.utf8_strings.push((text.to_string(), start_idx));
                            out.utf8_count = out.utf8_count.saturating_add(1);
                        }
                    }
                }
                char_count = 0;
                run_has_non_ascii = false;
                i += 1;
                continue;
            }

            // Valid codepoint; evaluate display property by decoding the char
            if run_start.is_none() {
                run_start = Some(i);
            }
            let cp_slice = &scan[i..i + cp_len];
            if let Ok(s) = std::str::from_utf8(cp_slice) {
                if let Some(ch) = s.chars().next() {
                    let ok = !ch.is_control() || ch == '\t' || ch == ' ';
                    if ok {
                        char_count += 1;
                        if !is_ascii {
                            run_has_non_ascii = true;
                        }
                        i += cp_len;
                        continue;
                    }
                }
            }
            // Non-display; close run
            if let Some(start_idx) = run_start.take() {
                if char_count >= cfg.min_length && run_has_non_ascii {
                    let end = i;
                    if let Ok(text) = std::str::from_utf8(&scan[start_idx..end]) {
                        out.utf8_strings.push((text.to_string(), start_idx));
                        out.utf8_count = out.utf8_count.saturating_add(1);
                    }
                }
            }
            char_count = 0;
            run_has_non_ascii = false;
            i += cp_len;
        }
        if let Some(start_idx) = run_start {
            if char_count >= cfg.min_length && run_has_non_ascii {
                let end = scan.len();
                if let Ok(text) = std::str::from_utf8(&scan[start_idx..end]) {
                    out.utf8_strings.push((text.to_string(), start_idx));
                    out.utf8_count = out.utf8_count.saturating_add(1);
                }
            }
        }
        if out.utf8_strings.len() > cfg.max_samples {
            out.utf8_strings.truncate(cfg.max_samples);
        }
    }

    // UTF-16LE scanner
    {
        let mut run: Vec<u16> = Vec::new();
        let mut run_offset: usize = 0;
        for (i, chunk) in scan.chunks_exact(2).enumerate() {
            if (i & 0x07FF) == 0 && start.elapsed().as_millis() as u64 > cfg.time_guard_ms {
                tracing::debug!("strings/utf16le time budget exhausted at chunk {}", i);
                break;
            }
            let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
            if ch == 0 {
                if run.len() >= cfg.min_length {
                    if let Ok(text) = String::from_utf16(&run) {
                        out.utf16le_strings.push((text, run_offset));
                        out.utf16le_count = out.utf16le_count.saturating_add(1);
                    }
                }
                run.clear();
            } else if ch < 128 && (ch as u8).is_ascii_graphic() || ch == 32 {
                if run.is_empty() {
                    run_offset = i * 2;
                }
                run.push(ch);
            } else {
                if run.len() >= cfg.min_length {
                    if let Ok(text) = String::from_utf16(&run) {
                        out.utf16le_strings.push((text, run_offset));
                        out.utf16le_count = out.utf16le_count.saturating_add(1);
                    }
                }
                run.clear();
            }
        }
        if run.len() >= cfg.min_length {
            if let Ok(text) = String::from_utf16(&run) {
                out.utf16le_strings.push((text, run_offset));
                out.utf16le_count = out.utf16le_count.saturating_add(1);
            }
        }
        // Cap sample vectors to max_samples each to bound memory
        if out.utf16le_strings.len() > cfg.max_samples {
            out.utf16le_strings.truncate(cfg.max_samples);
        }
    }

    // UTF-16BE scanner
    {
        let mut run: Vec<u16> = Vec::new();
        let mut run_offset: usize = 0;
        for (i, chunk) in scan.chunks_exact(2).enumerate() {
            if (i & 0x07FF) == 0 && start.elapsed().as_millis() as u64 > cfg.time_guard_ms {
                tracing::debug!("strings/utf16be time budget exhausted at chunk {}", i);
                break;
            }
            let ch = u16::from_be_bytes([chunk[0], chunk[1]]);
            if ch == 0 {
                if run.len() >= cfg.min_length {
                    if let Ok(text) = String::from_utf16(&run) {
                        out.utf16be_strings.push((text, run_offset));
                        out.utf16be_count = out.utf16be_count.saturating_add(1);
                    }
                }
                run.clear();
            } else if ch < 128 && (ch as u8).is_ascii_graphic() || ch == 32 {
                if run.is_empty() {
                    run_offset = i * 2;
                }
                run.push(ch);
            } else {
                if run.len() >= cfg.min_length {
                    if let Ok(text) = String::from_utf16(&run) {
                        out.utf16be_strings.push((text, run_offset));
                        out.utf16be_count = out.utf16be_count.saturating_add(1);
                    }
                }
                run.clear();
            }
        }
        if run.len() >= cfg.min_length {
            if let Ok(text) = String::from_utf16(&run) {
                out.utf16be_strings.push((text, run_offset));
                out.utf16be_count = out.utf16be_count.saturating_add(1);
            }
        }
        if out.utf16be_strings.len() > cfg.max_samples {
            out.utf16be_strings.truncate(cfg.max_samples);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_default() -> StringsConfig {
        StringsConfig {
            min_length: 4,
            max_samples: 10,
            max_scan_bytes: 1_048_576,
            time_guard_ms: 1_000, // generous to avoid flakiness
            enable_language: false,
            max_lang_detect: 0,
            min_len_for_detect: 10,
            enable_classification: false,
            max_classify: 0,
            max_ioc_per_string: 0,
            max_ioc_samples: 0,
        }
    }

    #[test]
    fn ascii_scan_basic() {
        let data = b"Hello world!\x00Bye"; // two strings: "Hello world!" and "Bye" (min_length=4 filters second)
        let cfg = cfg_default();
        let out = scan_strings(data, &cfg, std::time::Instant::now());
        assert_eq!(out.ascii_count, 1);
        assert_eq!(out.ascii_strings.len(), 1);
        assert_eq!(out.ascii_strings[0].0, "Hello world!");
        assert_eq!(out.ascii_strings[0].1, 0);
    }

    #[test]
    fn utf16le_scan_basic() {
        // "HELLO" in UTF-16LE with NUL terminator
        let mut data = Vec::new();
        for &c in b"HELLO" {
            data.push(c);
            data.push(0);
        }
        data.extend_from_slice(&[0, 0]); // terminator
        let cfg = cfg_default();
        let out = scan_strings(&data, &cfg, std::time::Instant::now());
        assert!(out.utf16le_count >= 1);
        assert!(!out.utf16le_strings.is_empty());
        assert_eq!(out.utf16le_strings[0].0, "HELLO");
        assert_eq!(out.utf16le_strings[0].1, 0);
    }

    #[test]
    fn respects_max_scan_bytes() {
        // Create 2MiB of 'A' so that limiting to 1MiB still produces exactly one long ASCII run
        let data = vec![b'A'; 2 * 1024 * 1024];
        let cfg = StringsConfig {
            max_scan_bytes: 64 * 1024,
            ..cfg_default()
        };
        let out = scan_strings(&data, &cfg, std::time::Instant::now());
        // One run counted even if we truncated; sample present and offset 0
        assert_eq!(out.ascii_count, 1);
        assert_eq!(out.ascii_strings.len(), 1);
        assert_eq!(out.ascii_strings[0].1, 0);
        // The collected ASCII sample length should equal the scan window (bounded by max_samples and conversion)
        assert_eq!(out.ascii_strings[0].0.len(), 64 * 1024);
    }
}
