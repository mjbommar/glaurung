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

        signals
    }

    /// Score an entire artifact and return ranked verdicts.
    pub fn score_artifact(&self, artifact: &TriagedArtifact) -> Vec<TriageVerdict> {
        let mut verdicts = artifact.verdicts.clone();
        for v in &mut verdicts {
            let signals = self.signals_for_verdict(artifact, v);
            let base = self.calculate_confidence(&signals);
            let with_penalties = match &artifact.errors {
                Some(errs) => self.apply_penalties(base, errs),
                None => base,
            };
            v.confidence = with_penalties;
            // Store per-verdict signal breakdown for reporting
            v.signals = Some(signals);
        }
        self.rank_verdicts(verdicts)
    }
}

/// Public API: Score verdicts for an artifact and return ranked list.
pub fn score(artifact: &TriagedArtifact) -> Vec<TriageVerdict> {
    let engine = ScoreEngine::default();
    engine.score_artifact(artifact)
}
