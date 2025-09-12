//! Python bindings for similarity and fuzzy hashing functionality.
//!
//! This module contains all Python bindings related to CTPH (Context Triggered
//! Piecewise Hashing) and similarity analysis.

use pyo3::prelude::*;

/// Register similarity-related Python bindings.
pub fn register_similarity_bindings(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Create similarity submodule
    let similarity_mod = pyo3::types::PyModule::new(_py, "similarity")?;

    // Register CTPH functions
    similarity_mod.add_function(wrap_pyfunction!(ctph_hash_bytes_py, &similarity_mod)?)?;
    similarity_mod.add_function(wrap_pyfunction!(ctph_hash_path_py, &similarity_mod)?)?;
    similarity_mod.add_function(wrap_pyfunction!(ctph_similarity_py, &similarity_mod)?)?;
    similarity_mod.add_function(wrap_pyfunction!(
        ctph_recommended_params_py,
        &similarity_mod
    )?)?;
    similarity_mod.add_function(wrap_pyfunction!(ctph_pairwise_matrix_py, &similarity_mod)?)?;
    similarity_mod.add_function(wrap_pyfunction!(ctph_top_k_py, &similarity_mod)?)?;

    // Add similarity submodule to main module
    m.add_submodule(&similarity_mod)?;

    Ok(())
}

/// Calculate CTPH hash from binary data.
#[pyfunction]
#[pyo3(name = "ctph_hash_bytes")]
#[pyo3(signature = (data, window_size=8, digest_size=4, precision=8))]
fn ctph_hash_bytes_py(
    data: &[u8],
    window_size: usize,
    digest_size: usize,
    precision: u8,
) -> String {
    let cfg = crate::similarity::CtphConfig {
        window_size,
        digest_size,
        precision,
    };
    crate::similarity::ctph_hash(data, &cfg)
}

/// Calculate CTPH hash from file path.
#[pyfunction]
#[pyo3(name = "ctph_hash_path")]
#[pyo3(signature = (path, max_read_bytes=10_485_760, max_file_size=104_857_600, window_size=8, digest_size=4, precision=8))]
fn ctph_hash_path_py(
    path: String,
    max_read_bytes: u64,
    max_file_size: u64,
    window_size: usize,
    digest_size: usize,
    precision: u8,
) -> PyResult<String> {
    let limit = std::cmp::min(max_read_bytes, max_file_size);
    let data = crate::triage::io::IOUtils::read_file_with_limit(&path, limit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{:?}", e)))?;
    let cfg = crate::similarity::CtphConfig {
        window_size,
        digest_size,
        precision,
    };
    Ok(crate::similarity::ctph_hash(&data, &cfg))
}

/// Calculate similarity between two CTPH hashes.
#[pyfunction]
#[pyo3(name = "ctph_similarity")]
fn ctph_similarity_py(a: &str, b: &str) -> f64 {
    crate::similarity::ctph_similarity(a, b)
}

/// Get recommended CTPH parameters for a given data length.
#[pyfunction]
#[pyo3(name = "ctph_recommended_params")]
fn ctph_recommended_params_py(length: usize) -> (usize, usize, u8) {
    // Simple heuristic tuned for typical binary sizes
    if length < 16 * 1024 {
        (8, 4, 8)
    } else if length < 1 * 1024 * 1024 {
        (16, 5, 16)
    } else {
        (32, 6, 16)
    }
}

/// Calculate pairwise similarity matrix for multiple CTPH hashes.
#[pyfunction]
#[pyo3(name = "ctph_pairwise_matrix")]
#[pyo3(signature = (digests, max_pairs=250_000))]
fn ctph_pairwise_matrix_py(digests: Vec<String>, max_pairs: usize) -> Vec<(usize, usize, f64)> {
    let n = digests.len();
    let mut out = Vec::new();
    let mut count = 0usize;
    for i in 0..n {
        for j in (i + 1)..n {
            if count >= max_pairs {
                return out;
            }
            let s = crate::similarity::ctph_similarity(&digests[i], &digests[j]);
            out.push((i, j, s));
            count += 1;
        }
    }
    out
}

/// Find top-k most similar CTPH hashes from candidates.
#[pyfunction]
#[pyo3(name = "ctph_top_k")]
#[pyo3(signature = (query_digest, candidates, k=5, min_score=0.6, max_candidates=10000))]
fn ctph_top_k_py(
    query_digest: &str,
    candidates: Vec<String>,
    k: usize,
    min_score: f64,
    max_candidates: usize,
) -> Vec<(String, f64)> {
    let mut scored: Vec<(String, f64)> = Vec::new();
    for (idx, c) in candidates.into_iter().enumerate() {
        if idx >= max_candidates {
            break;
        }
        let s = crate::similarity::ctph_similarity(query_digest, &c);
        if s >= min_score {
            scored.push((c, s));
        }
    }
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored.truncate(k);
    scored
}
