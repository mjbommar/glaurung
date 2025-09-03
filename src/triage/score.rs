//! Confidence scoring and verdict ranking.

use crate::core::triage::{
    ConfidenceSignal, TriageError, TriageErrorKind, TriageVerdict, TriagedArtifact,
};
use std::collections::HashMap;

/// Scoring engine for confidence aggregation and penalty application.
pub struct ScoreEngine {
    signal_weights: HashMap<String, f32>,
    error_penalties: HashMap<TriageErrorKind, f32>,
}

impl Default for ScoreEngine {
    fn default() -> Self {
        let mut signal_weights = HashMap::new();
        signal_weights.insert("header_match".into(), 0.30);
        signal_weights.insert("parser_success".into(), 0.25);
        signal_weights.insert("sniffer_match".into(), 0.15);
        signal_weights.insert("entropy_normal".into(), 0.10);
        signal_weights.insert("strings_present".into(), 0.10);
        signal_weights.insert("architecture_match".into(), 0.10);
        signal_weights.insert("endianness_match".into(), 0.05);

        let mut error_penalties = HashMap::new();
        error_penalties.insert(TriageErrorKind::SnifferMismatch, 0.10);
        error_penalties.insert(TriageErrorKind::ParserMismatch, 0.15);
        error_penalties.insert(TriageErrorKind::BadMagic, 0.20);
        error_penalties.insert(TriageErrorKind::IncoherentFields, 0.25);

        Self {
            signal_weights,
            error_penalties,
        }
    }
}

impl ScoreEngine {
    /// Calculate confidence score from signals with weights.
    pub fn calculate_confidence(&self, signals: &[ConfidenceSignal]) -> f32 {
        let mut total_weight = 0.0f32;
        let mut weighted_sum = 0.0f32;

        for s in signals {
            let w = self.signal_weights.get(&s.name).copied().unwrap_or(0.05);
            weighted_sum += s.score * w;
            total_weight += w;
        }

        if total_weight > 0.0 {
            (weighted_sum / total_weight).clamp(0.0, 1.0)
        } else {
            0.0
        }
    }

    /// Apply error penalties to a base confidence value.
    pub fn apply_penalties(&self, base: f32, errors: &[TriageError]) -> f32 {
        let mut c = base;
        for e in errors {
            if let Some(p) = self.error_penalties.get(&e.kind) {
                c -= *p;
            }
        }
        c.clamp(0.0, 1.0)
    }

    /// Rank verdicts by confidence (descending).
    pub fn rank_verdicts(&self, mut verdicts: Vec<TriageVerdict>) -> Vec<TriageVerdict> {
        verdicts.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        verdicts
    }

    /// Produce per-verdict signals based on artifact context.
    fn signals_for_verdict(
        &self,
        artifact: &TriagedArtifact,
        verdict: &TriageVerdict,
    ) -> Vec<ConfidenceSignal> {
        let mut signals = Vec::new();

        // Treat existing verdict confidence as header match strength
        if verdict.confidence > 0.0 {
            signals.push(ConfidenceSignal::new(
                "header_match".into(),
                verdict.confidence,
                None,
            ));
        }

        if let Some(entropy) = &artifact.entropy {
            if let Some(overall) = entropy.overall {
                let score = if (3.0..=7.6).contains(&overall) {
                    1.0
                } else {
                    0.5
                };
                signals.push(ConfidenceSignal::new("entropy_normal".into(), score, None));
            }
        }

        if let Some(strings) = &artifact.strings {
            let total = strings
                .ascii_count
                .saturating_add(strings.utf8_count)
                .saturating_add(strings.utf16le_count)
                .saturating_add(strings.utf16be_count);
            if total > 10 {
                signals.push(ConfidenceSignal::new("strings_present".into(), 1.0, None));
            }
        }

        // Parser success (any parser ok)
        if let Some(ps) = &artifact.parse_status {
            if ps.iter().any(|p| p.ok) {
                signals.push(ConfidenceSignal::new("parser_success".into(), 1.0, None));
            }
        }

        // Sniffer presence as a soft positive (conflicts are penalized separately)
        if !artifact.hints.is_empty() {
            signals.push(ConfidenceSignal::new("sniffer_match".into(), 1.0, None));
        }

        // Heuristic: architecture match
        if let Some(arch_guesses) = &artifact.heuristic_arch {
            if let Some((top_arch, conf)) = arch_guesses.first() {
                let mut score = 0.0f32;
                if verdict.arch == *top_arch {
                    score = (*conf).clamp(0.0, 1.0);
                } else {
                    // family equivalence: x86 <-> x86_64
                    use crate::core::binary::Arch;
                    let fam_match = (verdict.arch == Arch::X86 && *top_arch == Arch::X86_64)
                        || (verdict.arch == Arch::X86_64 && *top_arch == Arch::X86);
                    if fam_match {
                        score = (*conf).min(0.7).clamp(0.0, 1.0);
                    }
                }
                if score > 0.0 {
                    signals.push(ConfidenceSignal::new(
                        "architecture_match".into(),
                        score,
                        None,
                    ));
                }
            }
        }

        // Heuristic: endianness match (from byte pattern guess or UTF-16 prevalence)
        if let Some((e_guess, e_conf)) = artifact.heuristic_endianness {
            if verdict.endianness == e_guess {
                signals.push(ConfidenceSignal::new(
                    "endianness_match".into(),
                    e_conf.clamp(0.0, 1.0),
                    None,
                ));
            } else {
                // Soft hint: if strings suggest opposite, do nothing; negative scoring is handled by errors
            }
        }

        signals
    }

    /// Compute penalties and explanatory signals for abnormal flag combinations.
    fn abnormal_penalties(
        &self,
        artifact: &TriagedArtifact,
        verdict: &TriageVerdict,
    ) -> (f32, Vec<ConfidenceSignal>) {
        let mut penalty = 0.0f32;
        let mut signals: Vec<ConfidenceSignal> = Vec::new();
        if let Some(sym) = &artifact.symbols {
            if let (Some(nx), Some(aslr)) = (sym.nx, sym.aslr) {
                if !nx && !aslr {
                    penalty += 0.10;
                    signals.push(ConfidenceSignal::new(
                        "abnormal_flags".into(),
                        0.0,
                        Some("NX/ASLR both disabled".into()),
                    ));
                }
            }
            if let Some(relro) = sym.relro {
                if !relro && verdict.format == crate::core::binary::Format::ELF {
                    penalty += 0.05;
                    signals.push(ConfidenceSignal::new(
                        "abnormal_flags".into(),
                        0.0,
                        Some("RELRO disabled".into()),
                    ));
                }
            }
            if let Some(pie) = sym.pie {
                if !pie && verdict.format == crate::core::binary::Format::ELF {
                    penalty += 0.05;
                    signals.push(ConfidenceSignal::new(
                        "abnormal_flags".into(),
                        0.0,
                        Some("PIE disabled".into()),
                    ));
                }
            }
        }
        (penalty.clamp(0.0, 0.25), signals)
    }

    /// Score an entire artifact and return ranked verdicts.
    pub fn score_artifact(&self, artifact: &TriagedArtifact) -> Vec<TriageVerdict> {
        let mut verdicts = artifact.verdicts.clone();
        for v in &mut verdicts {
            let signals = self.signals_for_verdict(artifact, v);
            let base = self.calculate_confidence(&signals);
            let with_errors = match &artifact.errors {
                Some(errs) => self.apply_penalties(base, errs),
                None => base,
            };
            let (abn_pen, abn_sigs) = self.abnormal_penalties(artifact, v);
            let mut all_sigs = signals;
            all_sigs.extend(abn_sigs);
            v.confidence = (with_errors - abn_pen).clamp(0.0, 1.0);
            // Store per-verdict signal breakdown for reporting
            v.signals = Some(all_sigs);
        }
        self.rank_verdicts(verdicts)
    }
}

/// Public API: Score verdicts for an artifact and return ranked list.
pub fn score(artifact: &TriagedArtifact) -> Vec<TriageVerdict> {
    let engine = ScoreEngine::default();
    engine.score_artifact(artifact)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::binary::{Arch, Endianness, Format};
    use crate::core::triage::{
        Budgets, EntropySummary, TriageHint, TriageVerdict, TriagedArtifact,
    };

    #[test]
    fn heuristics_contribute_expected_signals() {
        // A simple verdict consistent with heuristics
        let verdict =
            TriageVerdict::try_new(Format::ELF, Arch::X86_64, 64, Endianness::Little, 0.6, None)
                .unwrap();
        let artifact = TriagedArtifact::new(
            "id".into(),
            "<mem>".into(),
            128,
            None,
            vec![] as Vec<TriageHint>,
            vec![verdict],
            Some(EntropySummary::new(Some(6.5), Some(4096), None)),
            None, // entropy_analysis
            None, // strings
            None, // symbols
            None, // packers
            None, // containers
            None, // overlay
            None, // parse_status
            Some(Budgets::new(0, 0, 0)),
            None,
            Some((Endianness::Little, 0.9)),
            Some(vec![(Arch::X86_64, 0.85)]),
        );
        let ranked = score(&artifact);
        assert!(!ranked.is_empty());
        let sigs = ranked[0]
            .signals
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.name)
            .collect::<Vec<_>>();
        assert!(sigs.iter().any(|n| n == "architecture_match"));
        assert!(sigs.iter().any(|n| n == "endianness_match"));
    }
}
