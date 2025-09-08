//! Fuzzy hashing and similarity analysis (CTPH implementation).

/// Minimal, MIT/Apache-compatible Context-Triggered Piecewise Hashing (CTPH).
/// This implementation is based on a rolling hash trigger that chunks input into
/// pieces and emits short BLAKE3-XOF substrings per piece. The final digest is a
/// string "<window>:<digest>:<block1>:<block2>:..." suitable for Jaccard-based
/// comparisons. It avoids GPL encumbrances from ssdeep/sdhash.

/// Rolling hash functions (8/16/32/64-bit) used by CTPH.
mod rolling {
    pub struct RollingHash8 {
        window_size: usize,
        window: std::collections::VecDeque<u8>,
        hash: u8,
    }
    impl RollingHash8 {
        pub fn new(window_size: usize) -> Self {
            Self {
                window_size,
                window: std::collections::VecDeque::with_capacity(window_size),
                hash: 0,
            }
        }
        pub fn update(&mut self, byte: u8) {
            if self.window.len() == self.window_size {
                let old = self.window.pop_front().unwrap();
                self.hash = self.hash.wrapping_sub(old);
            }
            self.window.push_back(byte);
            self.hash = self.hash.wrapping_add(byte).rotate_left(1);
        }
        pub fn hash(&self) -> u8 {
            self.hash
        }
    }

    pub struct RollingHash16 {
        window_size: usize,
        window: std::collections::VecDeque<u16>,
        hash: u16,
    }
    impl RollingHash16 {
        pub fn new(window_size: usize) -> Self {
            Self {
                window_size,
                window: std::collections::VecDeque::with_capacity(window_size),
                hash: 0,
            }
        }
        pub fn update(&mut self, byte: u16) {
            if self.window.len() == self.window_size {
                let old = self.window.pop_front().unwrap();
                self.hash = self.hash.wrapping_sub(old);
            }
            self.window.push_back(byte);
            self.hash = self.hash.wrapping_add(byte).rotate_left(1);
        }
        pub fn hash(&self) -> u16 {
            self.hash
        }
    }

    pub struct RollingHash32 {
        window_size: usize,
        window: std::collections::VecDeque<u32>,
        hash: u32,
    }
    impl RollingHash32 {
        pub fn new(window_size: usize) -> Self {
            Self {
                window_size,
                window: std::collections::VecDeque::with_capacity(window_size),
                hash: 0,
            }
        }
        pub fn update(&mut self, byte: u32) {
            if self.window.len() == self.window_size {
                let old = self.window.pop_front().unwrap();
                self.hash = self.hash.wrapping_sub(old);
            }
            self.window.push_back(byte);
            self.hash = self.hash.wrapping_add(byte).rotate_left(1);
        }
        pub fn hash(&self) -> u32 {
            self.hash
        }
    }

    pub struct RollingHash64 {
        window_size: usize,
        window: std::collections::VecDeque<u64>,
        hash: u64,
    }
    impl RollingHash64 {
        pub fn new(window_size: usize) -> Self {
            Self {
                window_size,
                window: std::collections::VecDeque::with_capacity(window_size),
                hash: 0,
            }
        }
        pub fn update(&mut self, byte: u64) {
            if self.window.len() == self.window_size {
                let old = self.window.pop_front().unwrap();
                self.hash = self.hash.wrapping_sub(old);
            }
            self.window.push_back(byte);
            self.hash = self.hash.wrapping_add(byte).rotate_left(1);
        }
        pub fn hash(&self) -> u64 {
            self.hash
        }
    }

    // keep types private to this module; exposed via CTPH API
}

#[derive(Clone, Copy, Debug)]
pub struct CtphConfig {
    pub window_size: usize,
    pub digest_size: usize,
    pub precision: u8, // 8,16,32,64
}
impl Default for CtphConfig {
    fn default() -> Self {
        Self {
            window_size: 8,
            digest_size: 4,
            precision: 8,
        }
    }
}

fn hash_piece(bytes: &[u8], out_len: usize) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    let mut out = vec![0u8; out_len];
    hasher.finalize_xof().fill(&mut out);
    hex::encode(out)
}

fn ctph_with8(cfg: &CtphConfig, data: &[u8]) -> String {
    use rolling::RollingHash8;
    let mut rolling = RollingHash8::new(cfg.window_size);
    let mut blocks: Vec<String> = vec![String::new()];
    let mut cur: Vec<u8> = Vec::new();
    let mut triggers = 0usize;
    for &b in data {
        rolling.update(b);
        cur.push(b);
        if (rolling.hash() % (cfg.digest_size as u8)) == (cfg.digest_size as u8 - 1)
            || cur.len() >= 64 * cfg.window_size
        {
            let piece = hash_piece(&cur, 1);
            blocks.last_mut().unwrap().push_str(&piece);
            cur.clear();
            triggers += 1;
            if triggers % cfg.digest_size == 0 {
                blocks.push(String::new());
            }
        }
    }
    if !cur.is_empty() {
        let piece = hash_piece(&cur, 1);
        blocks.last_mut().unwrap().push_str(&piece);
    }
    blocks.retain(|b| !b.is_empty());
    format!(
        "{}:{}:{}",
        cfg.window_size,
        cfg.digest_size,
        blocks.join(":")
    )
}

fn ctph_with16(cfg: &CtphConfig, data: &[u8]) -> String {
    use rolling::RollingHash16;
    let mut rolling = RollingHash16::new(cfg.window_size);
    let mut blocks: Vec<String> = vec![String::new()];
    let mut cur: Vec<u8> = Vec::new();
    let mut triggers = 0usize;
    for &b in data {
        rolling.update(b as u16);
        cur.push(b);
        if (rolling.hash() % (cfg.digest_size as u16)) == (cfg.digest_size as u16 - 1)
            || cur.len() >= 64 * cfg.window_size
        {
            let piece = hash_piece(&cur, 2);
            blocks.last_mut().unwrap().push_str(&piece);
            cur.clear();
            triggers += 1;
            if triggers % cfg.digest_size == 0 {
                blocks.push(String::new());
            }
        }
    }
    if !cur.is_empty() {
        let piece = hash_piece(&cur, 2);
        blocks.last_mut().unwrap().push_str(&piece);
    }
    blocks.retain(|b| !b.is_empty());
    format!(
        "{}:{}:{}",
        cfg.window_size,
        cfg.digest_size,
        blocks.join(":")
    )
}

fn ctph_with32(cfg: &CtphConfig, data: &[u8]) -> String {
    use rolling::RollingHash32;
    let mut rolling = RollingHash32::new(cfg.window_size);
    let mut blocks: Vec<String> = vec![String::new()];
    let mut cur: Vec<u8> = Vec::new();
    let mut triggers = 0usize;
    for &b in data {
        rolling.update(b as u32);
        cur.push(b);
        if (rolling.hash() % (cfg.digest_size as u32)) == (cfg.digest_size as u32 - 1)
            || cur.len() >= 64 * cfg.window_size
        {
            let piece = hash_piece(&cur, 4);
            blocks.last_mut().unwrap().push_str(&piece);
            cur.clear();
            triggers += 1;
            if triggers % cfg.digest_size == 0 {
                blocks.push(String::new());
            }
        }
    }
    if !cur.is_empty() {
        let piece = hash_piece(&cur, 4);
        blocks.last_mut().unwrap().push_str(&piece);
    }
    blocks.retain(|b| !b.is_empty());
    format!(
        "{}:{}:{}",
        cfg.window_size,
        cfg.digest_size,
        blocks.join(":")
    )
}

fn ctph_with64(cfg: &CtphConfig, data: &[u8]) -> String {
    use rolling::RollingHash64;
    let mut rolling = RollingHash64::new(cfg.window_size);
    let mut blocks: Vec<String> = vec![String::new()];
    let mut cur: Vec<u8> = Vec::new();
    let mut triggers = 0usize;
    for &b in data {
        rolling.update(b as u64);
        cur.push(b);
        if (rolling.hash() % (cfg.digest_size as u64)) == (cfg.digest_size as u64 - 1)
            || cur.len() >= 64 * cfg.window_size
        {
            let piece = hash_piece(&cur, 4);
            blocks.last_mut().unwrap().push_str(&piece);
            cur.clear();
            triggers += 1;
            if triggers % cfg.digest_size == 0 {
                blocks.push(String::new());
            }
        }
    }
    if !cur.is_empty() {
        let piece = hash_piece(&cur, 4);
        blocks.last_mut().unwrap().push_str(&piece);
    }
    blocks.retain(|b| !b.is_empty());
    format!(
        "{}:{}:{}",
        cfg.window_size,
        cfg.digest_size,
        blocks.join(":")
    )
}

/// Compute CTPH digest for data with the given configuration.
pub fn ctph_hash(data: &[u8], cfg: &CtphConfig) -> String {
    match cfg.precision {
        16 => ctph_with16(cfg, data),
        32 => ctph_with32(cfg, data),
        64 => ctph_with64(cfg, data),
        _ => ctph_with8(cfg, data),
    }
}

/// Compare two CTPH digests using Jaccard similarity over piece blocks.
pub fn ctph_similarity(a: &str, b: &str) -> f64 {
    let at: Vec<&str> = a.split(':').collect();
    let bt: Vec<&str> = b.split(':').collect();
    if at.len() < 3 || bt.len() < 3 {
        return 0.0;
    }
    if at[0] != bt[0] || at[1] != bt[1] {
        return 0.0;
    }
    use std::collections::HashSet;
    let as_: HashSet<&str> = at[2..].iter().copied().collect();
    let bs: HashSet<&str> = bt[2..].iter().copied().collect();
    let inter = as_.intersection(&bs).count() as f64;
    let union = (as_.len() + bs.len()).saturating_sub(inter as usize) as f64;
    if union == 0.0 {
        0.0
    } else {
        inter / union
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctph_basic_shape() {
        let cfg = CtphConfig::default();
        let h = ctph_hash(b"hello world", &cfg);
        assert!(h.starts_with("8:4:"));
        assert!(h.contains(':'));
    }

    #[test]
    fn test_ctph_similarity_is_symmetric_and_bounded() {
        let cfg = CtphConfig {
            window_size: 8,
            digest_size: 4,
            precision: 16,
        };
        let a = ctph_hash(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &cfg);
        let b = ctph_hash(b"AAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAA", &cfg);
        let s1 = ctph_similarity(&a, &b);
        let s2 = ctph_similarity(&b, &a);
        assert!((s1 - s2).abs() < 1e-6);
        assert!(s1 >= 0.0 && s1 <= 1.0);
    }
}
