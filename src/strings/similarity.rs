//! String similarity helpers powered by `strsim`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimilarityAlgo {
    Jaro,
    JaroWinkler,
    NormalizedDamerauLevenshtein,
    SorensenDice, // bigram-based dice coefficient
}

/// Compute a similarity score in [0.0, 1.0] (higher is more similar).
pub fn score(algo: SimilarityAlgo, a: &str, b: &str) -> f64 {
    use SimilarityAlgo::*;
    match algo {
        Jaro => strsim::jaro(a, b),
        JaroWinkler => strsim::jaro_winkler(a, b),
        NormalizedDamerauLevenshtein => strsim::normalized_damerau_levenshtein(a, b),
        SorensenDice => strsim::sorensen_dice(a, b),
    }
}

/// Find the best match among candidates, honoring optional limits.
pub fn best_match<'a, I>(
    query: &str,
    candidates: I,
    algo: SimilarityAlgo,
    min_score: f64,
    max_candidates: usize,
    max_len: usize,
) -> Option<(&'a str, f64)>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut best: Option<(&'a str, f64)> = None;
    for (seen, cand) in candidates.into_iter().enumerate() {
        if seen >= max_candidates {
            break;
        }
        // Bound quadratic algorithms; skip too-long pairs
        if query.len().max(cand.len()) > max_len {
            continue;
        }
        let s = score(algo, query, cand);
        if s >= min_score {
            match best {
                None => best = Some((cand, s)),
                Some((_, bs)) if s > bs => best = Some((cand, s)),
                _ => {}
            }
        }
    }
    best
}

/// Return top-k matches above a threshold.
pub fn top_k<'a, I>(
    query: &str,
    candidates: I,
    algo: SimilarityAlgo,
    min_score: f64,
    k: usize,
    max_candidates: usize,
    max_len: usize,
) -> Vec<(&'a str, f64)>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut scored: Vec<(&'a str, f64)> = Vec::new();
    for (seen, cand) in candidates.into_iter().enumerate() {
        if seen >= max_candidates {
            break;
        }
        if query.len().max(cand.len()) > max_len {
            continue;
        }
        let s = score(algo, query, cand);
        if s >= min_score {
            scored.push((cand, s));
        }
    }
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    if scored.len() > k {
        scored.truncate(k);
    }
    scored
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn best_match_basic() {
        let dict = ["printf", "fprintf", "srand", "memcpy"];
        let best = best_match(
            "prinf",
            dict.iter().copied(),
            SimilarityAlgo::JaroWinkler,
            0.80,
            100,
            64,
        )
        .unwrap();
        assert_eq!(best.0, "printf");
        assert!(best.1 > 0.85);
    }
}
