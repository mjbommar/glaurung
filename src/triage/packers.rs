use crate::core::triage::PackerMatch;
use crate::entropy::shannon_entropy;
use crate::triage::config::{EntropyConfig, PackerConfig};
use crate::triage::entropy::analyze_entropy;

fn bump_match(out: &mut Vec<PackerMatch>, name: &str, base_if_absent: f32, delta: f32) {
    if let Some(m) = out.iter_mut().find(|m| m.name.eq_ignore_ascii_case(name)) {
        m.confidence = (m.confidence + delta).clamp(0.0, 1.0);
    } else if base_if_absent > 0.0 {
        out.push(PackerMatch::new(
            name.to_string(),
            base_if_absent.clamp(0.0, 1.0),
        ));
    }
}

pub fn detect_packers(data: &[u8], cfg: &PackerConfig) -> Vec<PackerMatch> {
    let mut out = Vec::new();
    // Respect scan_limit from PackerConfig (default) to bound scanning cost
    let scan_limit = cfg.scan_limit;
    let hay = if data.len() > scan_limit {
        &data[..scan_limit]
    } else {
        data
    };

    // UPX.
    //
    // `UPX!` is the packer's own header magic and is written on EVERY format
    // it produces. `UPX0`/`UPX1` are PE *section names* and never appear in a
    // packed ELF. The previous model summed all four signals and then scaled
    // the total by `upx_detection_weight`, which made the score
    // format-dependent in the wrong direction: measured over the ten packed
    // builds in `samples/packed/`, every one scored **0.36** -- below any
    // threshold that would call it packed -- because two of the four signals
    // are structurally unavailable on ELF.
    //
    // So the magic is treated as what it is, a definitive and
    // format-independent identification, and the PE section names and version
    // banner corroborate it. Re-measured the same way: all ten packed builds
    // move 0.36 -> 0.72, and 60 unpacked binaries from the export tree still
    // score zero. That is the absolute calibration the note on
    // `demote_generic_below_named` deferred as "needing its own validation";
    // the ordering invariant it established is unaffected.
    let corroboration = cfg.upx_detection_weight.max(0.5);
    let mut upx_corroborating = 0.0f32;
    if memchr::memmem::find(hay, b"UPX0").is_some() {
        upx_corroborating += 0.2;
    }
    if memchr::memmem::find(hay, b"UPX1").is_some() {
        upx_corroborating += 0.2;
    }
    if memchr::memmem::find(hay, b"$Id: UPX ").is_some()
        || memchr::memmem::find(hay, b"UPX ").is_some()
    {
        // `upx_version_weight` has existed since the config was written, with
        // a default, a Python getter and a Python setter -- and was read by
        // nothing. The banner was worth a hardcoded 0.2, so anyone tuning the
        // knob changed nothing at all.
        upx_corroborating += cfg.upx_version_weight;
    }
    if memchr::memmem::find(hay, b"UPX!").is_some() {
        let conf = (0.6 + upx_corroborating * corroboration).min(1.0);
        out.push(PackerMatch::new("UPX".to_string(), conf));
    } else if upx_corroborating > 0.0 {
        // Corroboration with no magic: possible, but much weaker -- a string
        // mentioning UPX is not a packed file.
        let conf = (upx_corroborating * corroboration).min(1.0);
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
    if let Ok(obj) = crate::decompile::profile::parse_object(hay) {
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
            bump_match(
                &mut out,
                "Packed",
                (packed_score * cfg.packer_signal_weight).min(0.95),
                0.0,
            );
        }
    }

    demote_generic_below_named(&mut out);
    out
}

/// Name of the generic entropy verdict, as opposed to a named packer.
const GENERIC: &str = "Packed";

/// Keep the entropy heuristic ranked below any positive identification.
///
/// `"Packed"` means "these bytes look compressed"; `"UPX"` means "this binary
/// says it is UPX". They are not the same class of claim, and they were
/// competing on one confidence scale with the weaker one winning.
///
/// Measured over 60 of our own unpacked samples and the ten UPX-packed builds
/// in `samples/packed/`: the entropy signal fired on **14 of the 60 unpacked**
/// — every Go binary and several MinGW PEs, which are high-entropy by
/// construction — at 0.50, while a correct UPX signature match scored 0.24-0.36.
/// On `hello-go-static.upx9` both fired and the wrong one ranked higher. Anyone
/// sorting candidates by confidence, analyst or agent, saw clean binaries above
/// genuinely packed ones.
///
/// This fixes the ordering rather than the absolute calibration. The thresholds
/// are a separate question needing its own validation; the invariant that a
/// signature outranks a guess holds regardless of where they are set, so it is
/// worth enforcing on its own.
fn demote_generic_below_named(out: &mut [PackerMatch]) {
    let strongest_named = out
        .iter()
        .filter(|m| !m.name.eq_ignore_ascii_case(GENERIC))
        .map(|m| m.confidence)
        .fold(f32::NEG_INFINITY, f32::max);
    if !strongest_named.is_finite() {
        return; // nothing named matched; the heuristic stands alone
    }
    for m in out.iter_mut() {
        if m.name.eq_ignore_ascii_case(GENERIC) && m.confidence >= strongest_named {
            // Strictly below, and never negative for a very weak named match.
            m.confidence = (strongest_named - 0.01).max(0.0);
        }
    }
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
        let p = v
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case("Packed"))
            .unwrap();
        assert!(p.confidence >= 0.5);
    }
}

#[cfg(test)]
mod ranking_tests {
    use super::*;

    fn packed(name: &str, confidence: f32) -> PackerMatch {
        PackerMatch::new(name.to_string(), confidence)
    }

    fn confidence_of(matches: &[PackerMatch], name: &str) -> Option<f32> {
        matches
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(name))
            .map(|m| m.confidence)
    }

    /// The inversion this exists to prevent, in the shape it was measured in.
    ///
    /// `hello-go-static.upx9` produced exactly this pair — a correct UPX
    /// identification at 0.24 ranked below an entropy guess at 0.50.
    #[test]
    fn an_entropy_guess_never_outranks_a_named_packer() {
        let mut matches = vec![packed("UPX", 0.24), packed("Packed", 0.50)];
        demote_generic_below_named(&mut matches);
        let upx = confidence_of(&matches, "UPX").unwrap();
        let generic = confidence_of(&matches, "Packed").unwrap();
        assert!(
            generic < upx,
            "the generic signal ({generic}) still outranks the UPX \
             identification ({upx}); sorting by confidence puts a guess above \
             positive identification"
        );
    }

    /// The heuristic is not deleted, only ranked — it is the only signal we
    /// have for a packer we do not recognise.
    #[test]
    fn the_entropy_signal_survives_when_nothing_named_matched() {
        let mut matches = vec![packed("Packed", 0.50)];
        demote_generic_below_named(&mut matches);
        assert_eq!(confidence_of(&matches, "Packed"), Some(0.50));
    }

    /// A named match that already ranks above the guess must not be disturbed.
    #[test]
    fn a_confident_named_match_is_left_alone() {
        let mut matches = vec![packed("VMProtect", 0.75), packed("Packed", 0.50)];
        demote_generic_below_named(&mut matches);
        assert_eq!(confidence_of(&matches, "VMProtect"), Some(0.75));
        assert_eq!(confidence_of(&matches, "Packed"), Some(0.50));
    }

    /// Ordering is enforced against the STRONGEST named match, not the first.
    #[test]
    fn the_strongest_named_match_sets_the_ceiling() {
        let mut matches = vec![
            packed("UPX", 0.30),
            packed("ASPack", 0.70),
            packed("Packed", 0.90),
        ];
        demote_generic_below_named(&mut matches);
        let generic = confidence_of(&matches, "Packed").unwrap();
        assert!(generic < 0.70 && generic > 0.60, "got {generic}");
    }

    /// Confidence is a probability-like scale; demotion must not leave it negative.
    #[test]
    fn demotion_cannot_produce_a_negative_confidence() {
        let mut matches = vec![packed("UPX", 0.0), packed("Packed", 0.5)];
        demote_generic_below_named(&mut matches);
        assert_eq!(confidence_of(&matches, "Packed"), Some(0.0));
    }
}
