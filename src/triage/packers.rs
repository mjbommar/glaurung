use crate::core::triage::PackerMatch;
use crate::triage::config::{EntropyConfig, PackerConfig};
use crate::triage::entropy::analyze_entropy;
use crate::entropy::shannon_entropy;

fn bump_match(out: &mut Vec<PackerMatch>, name: &str, base_if_absent: f32, delta: f32) {
    if let Some(m) = out.iter_mut().find(|m| m.name.eq_ignore_ascii_case(name)) {
        m.confidence = (m.confidence + delta).clamp(0.0, 1.0);
    } else if base_if_absent > 0.0 {
        out.push(PackerMatch::new(name.to_string(), base_if_absent.clamp(0.0, 1.0)));
    }
}

pub fn detect_packers(data: &[u8], cfg: &PackerConfig) -> Vec<PackerMatch> {
    let mut out = Vec::new();
    // Respect scan_limit from PackerConfig (default) to bound scanning cost
    let scan_limit = cfg.scan_limit;
    let hay = if data.len() > scan_limit { &data[..scan_limit] } else { data };

    // UPX
    let mut upx = 0.0f32;
    if memchr::memmem::find(hay, b"UPX!").is_some() {
        upx += 0.4;
    }
    if memchr::memmem::find(hay, b"UPX0").is_some() {
        upx += 0.3;
    }
    if memchr::memmem::find(hay, b"UPX1").is_some() {
        upx += 0.3;
    }
    // Version/signature hints increase confidence
    if memchr::memmem::find(hay, b"$Id: UPX ").is_some()
        || memchr::memmem::find(hay, b"UPX ").is_some()
    {
        upx += 0.2;
    }
    if upx > 0.0 {
        // Calibrate lightly using config weights without hard-coding
        let conf = (upx * cfg.upx_detection_weight.max(0.5)).min(1.0);
        out.push(PackerMatch::new("UPX".to_string(), conf));
    }

    // ASPack
    if memchr::memmem::find(hay, b"ASPack").is_some() {
        out.push(PackerMatch::new("ASPack".into(), 0.9));
    }

    // PECompact
    if memchr::memmem::find(hay, b"PECompact").is_some()
        || memchr::memmem::find(hay, b"PEC2").is_some()
    {
        out.push(PackerMatch::new("PECompact".into(), 0.85));
    }

    // Petite
    if memchr::memmem::find(hay, b"Petite").is_some() {
        out.push(PackerMatch::new("Petite".into(), 0.8));
    }

    // FSG
    if memchr::memmem::find(hay, b"FSG!").is_some() {
        out.push(PackerMatch::new("FSG".into(), 0.85));
    }

    // MPRESS
    if memchr::memmem::find(hay, b"MPRESS").is_some() {
        out.push(PackerMatch::new("MPRESS".into(), 0.85));
    }

    // Themida/WinLicense
    if memchr::memmem::find(hay, b"Themida").is_some()
        || memchr::memmem::find(hay, b"WinLicense").is_some()
    {
        out.push(PackerMatch::new("Themida/WinLicense".into(), 0.9));
    }

    // VMProtect (section names often .vmp0/.vmp1 in PE, but scan raw too)
    if memchr::memmem::find(hay, b".vmp0").is_some()
        || memchr::memmem::find(hay, b".vmp1").is_some()
    {
        out.push(PackerMatch::new("VMProtect".into(), 0.75));
    }

    // Header/entropy heuristics: low-entropy header + high-entropy body + entropy cliff
    // Use existing entropy analyzer with defaults (bounded by heuristics buffer upper layer)
    let ecfg = EntropyConfig::default();
    let ea = analyze_entropy(hay, &ecfg);
    let pi = &ea.packed_indicators;
    let mut packed_score = 0.0f32;
    if pi.has_low_entropy_header {
        packed_score += 0.25;
    }
    if pi.has_high_entropy_body {
        packed_score += 0.35;
    }
    if pi.entropy_cliff.is_some() {
        packed_score += 0.25;
    }
    // Overall high entropy nudges up a bit
    if let Some(overall) = ea.summary.overall {
        if overall > 7.3 {
            packed_score += 0.15;
        }
    } else {
        let overall = shannon_entropy(hay);
        if overall > 7.3 {
            packed_score += 0.15;
        }
    }

    if packed_score > 0.4 {
        bump_match(&mut out, "Packed", packed_score.min(0.85), 0.0);
    }

    // Section heuristics using object crate where possible (best-effort; may fail on truncated buffers)
    if let Ok(obj) = object::read::File::parse(hay) {
        use object::{Object, ObjectSection};
        // Bump specific packers based on section names
        for sec in obj.sections() {
            if let Ok(name) = sec.name() {
                let lname = name.to_ascii_lowercase();
                if lname.contains("upx") {
                    bump_match(&mut out, "UPX", 0.6, 0.2);
                }
                if lname.contains("vmp0") || lname.contains("vmp1") || lname.contains(".vmp") {
                    bump_match(&mut out, "VMProtect", 0.6, 0.2);
                }
                if lname.contains("aspack") || lname == ".adata" {
                    bump_match(&mut out, "ASPack", 0.7, 0.1);
                }
                if lname.contains("petite") {
                    bump_match(&mut out, "Petite", 0.7, 0.1);
                }
                if lname.contains("mpress") {
                    bump_match(&mut out, "MPRESS", 0.7, 0.1);
                }
            }
            // Section entropy heuristic
            if let Ok(bytes) = sec.data() {
                if bytes.len() >= 4096 {
                    let h = shannon_entropy(bytes) as f32;
                    if h > 7.3 {
                        packed_score += 0.05; // small nudge per high-entropy section
                    }
                }
            }
        }
        if packed_score > 0.5 {
            bump_match(&mut out, "Packed", (packed_score * cfg.packer_signal_weight).min(0.95), 0.0);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detect_upx_on_real_samples() {
        let candidates = [
            "samples/packed/hello-rust-release.upx9",
            "samples/packed/hello-rust-debug.upx9",
            "samples/packed/hello-go.upx9",
        ];
        for p in candidates {
            if let Ok(d) = fs::read(p) {
                let v = detect_packers(&d, &PackerConfig::default());
                assert!(v.iter().any(|m| m.name == "UPX"));
            }
        }
    }

    #[test]
    fn detect_packed_by_entropy_cliff() {
        // Construct a buffer with low-entropy header and high-entropy body
        let mut data = Vec::new();
        data.extend(std::iter::repeat(b'\x00').take(8192)); // low-entropy header
        // High-entropy body (pseudo-random)
        let mut rng: u64 = 0xdead_beef_cafe_babe;
        for _ in 0..(64 * 1024) {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            data.push((rng >> 32) as u8);
        }
        let v = detect_packers(&data, &PackerConfig::default());
        // Expect a generic packed signal based on entropy heuristics
        assert!(v.iter().any(|m| m.name.eq_ignore_ascii_case("Packed")));
        let p = v.iter().find(|m| m.name.eq_ignore_ascii_case("Packed")).unwrap();
        assert!(p.confidence >= 0.5);
    }
}
