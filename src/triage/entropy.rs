use crate::core::triage::{
    EntropyAnalysis, EntropyAnomaly, EntropyClass, EntropySummary, PackedIndicators,
};
use crate::entropy::{analyze_windows, shannon_entropy, WindowConfig};
use crate::triage::config::EntropyConfig;

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;

/// Computes entropy summary using the optimized entropy module.
pub fn compute_entropy(data: &[u8], cfg: &EntropyConfig) -> EntropySummary {
    // Calculate overall entropy if requested
    let overall = if cfg.overall {
        Some(shannon_entropy(data))
    } else {
        None
    };

    // Perform sliding window analysis
    let window_config = WindowConfig {
        window_size: cfg.window_size.max(1),
        step_size: cfg.step.max(1),
        max_windows: cfg.max_windows,
    };

    let window_analysis = analyze_windows(data, &window_config);

    // Extract statistics
    let (windows, window_size, mean, std_dev, min, max) = if window_analysis.is_empty() {
        (None, None, None, None, None, None)
    } else {
        (
            Some(window_analysis.entropies.clone()),
            Some(window_analysis.window_size as u32),
            window_analysis.mean(),
            window_analysis.std_dev(),
            window_analysis.min(),
            window_analysis.max(),
        )
    };

    EntropySummary {
        overall,
        window_size,
        windows,
        mean,
        std_dev,
        min,
        max,
    }
}

/// Analyzes entropy with classification and anomaly detection.
///
/// This function performs high-level analysis including:
/// - Classification into entropy categories (Text, Code, Compressed, etc.)
/// - Detection of entropy anomalies (cliffs)
/// - Packed/encrypted indicator analysis
pub fn analyze_entropy(data: &[u8], cfg: &EntropyConfig) -> EntropyAnalysis {
    // Get entropy summary
    let summary = compute_entropy(data, cfg);
    let overall = summary.overall.unwrap_or_else(|| shannon_entropy(data));

    // Classification via thresholds
    let t = &cfg.thresholds;
    let class = classify_entropy(overall, t);

    // Analyze header vs body for packed indicators
    let indicators = analyze_packed_indicators(data, cfg, &summary, t);

    // Detect anomalies (entropy cliffs)
    let anomalies = detect_entropy_anomalies(&summary, t.cliff_delta);

    EntropyAnalysis {
        summary,
        classification: class,
        packed_indicators: indicators,
        anomalies,
    }
}

/// Classifies entropy value into categories based on thresholds.
fn classify_entropy(
    entropy: f64,
    thresholds: &crate::triage::config::EntropyThresholds,
) -> EntropyClass {
    if entropy > thresholds.encrypted {
        EntropyClass::Random(entropy as f32)
    } else if entropy > thresholds.compressed {
        EntropyClass::Encrypted(entropy as f32)
    } else if entropy > thresholds.code {
        EntropyClass::Compressed(entropy as f32)
    } else if entropy > thresholds.text {
        EntropyClass::Code(entropy as f32)
    } else {
        EntropyClass::Text(entropy as f32)
    }
}

/// Analyzes header and body entropy for packed/encrypted indicators.
fn analyze_packed_indicators(
    data: &[u8],
    cfg: &EntropyConfig,
    summary: &EntropySummary,
    thresholds: &crate::triage::config::EntropyThresholds,
) -> PackedIndicators {
    let header_len = data.len().min(cfg.header_size);

    // Calculate header entropy
    let header_entropy = if header_len > 0 {
        shannon_entropy(&data[..header_len])
    } else {
        0.0
    };

    // Calculate body entropy
    let body_entropy = if data.len() > header_len {
        shannon_entropy(&data[header_len..])
    } else {
        0.0
    };

    // Check for low-entropy header with high-entropy body (common in packed files)
    let has_low_entropy_header = header_len > 0 && header_entropy < thresholds.low_header;
    let has_high_entropy_body = data.len() > header_len && body_entropy > thresholds.high_body;

    // Find first entropy cliff if any
    let entropy_cliff_idx = if let Some(windows) = &summary.windows {
        find_first_cliff(windows, thresholds.cliff_delta)
    } else {
        None
    };

    // Calculate verdict based on indicators
    let verdict = if has_low_entropy_header && has_high_entropy_body {
        0.8 // High confidence of packing
    } else if entropy_cliff_idx.is_some() {
        0.6 // Moderate confidence
    } else {
        0.0
    };

    PackedIndicators {
        has_low_entropy_header,
        has_high_entropy_body,
        entropy_cliff: entropy_cliff_idx,
        verdict,
    }
}

/// Detects entropy anomalies (sudden changes between consecutive windows).
fn detect_entropy_anomalies(summary: &EntropySummary, cliff_threshold: f64) -> Vec<EntropyAnomaly> {
    let mut anomalies = Vec::new();

    if let Some(windows) = &summary.windows {
        for i in 1..windows.len() {
            let from = windows[i - 1];
            let to = windows[i];
            let delta = (to - from).abs();

            if delta >= cliff_threshold {
                anomalies.push(EntropyAnomaly {
                    index: i,
                    from,
                    to,
                    delta,
                });
            }
        }
    }

    anomalies
}

/// Finds the index of the first entropy cliff in window data.
fn find_first_cliff(windows: &[f64], threshold: f64) -> Option<usize> {
    for i in 1..windows.len() {
        let delta = (windows[i] - windows[i - 1]).abs();
        if delta >= threshold {
            return Some(i);
        }
    }
    None
}

// Python convenience wrappers
#[cfg(feature = "python-ext")]
#[pyfunction]
#[pyo3(name = "entropy_of_bytes")]
pub fn entropy_of_bytes_py(data: Vec<u8>) -> PyResult<f64> {
    Ok(shannon_entropy(&data))
}

#[cfg(feature = "python-ext")]
#[pyfunction]
#[pyo3(name = "compute_entropy")]
#[pyo3(signature = (data, window_size=8192, step=8192, max_windows=256, overall=true, header_size=1024))]
pub fn compute_entropy_bytes_py(
    data: Vec<u8>,
    window_size: usize,
    step: usize,
    max_windows: usize,
    overall: bool,
    header_size: usize,
) -> PyResult<EntropySummary> {
    let mut cfg = EntropyConfig::default();
    cfg.window_size = window_size;
    cfg.step = step;
    cfg.max_windows = max_windows;
    cfg.overall = overall;
    cfg.header_size = header_size;
    Ok(compute_entropy(&data, &cfg))
}

#[cfg(feature = "python-ext")]
#[pyfunction]
#[pyo3(name = "analyze_entropy_bytes")]
#[pyo3(signature = (data, window_size=8192, step=8192, max_windows=256, header_size=1024))]
pub fn analyze_entropy_bytes_py(
    data: Vec<u8>,
    window_size: usize,
    step: usize,
    max_windows: usize,
    header_size: usize,
) -> PyResult<EntropyAnalysis> {
    let mut cfg = EntropyConfig::default();
    cfg.window_size = window_size;
    cfg.step = step;
    cfg.max_windows = max_windows;
    cfg.header_size = header_size;
    Ok(analyze_entropy(&data, &cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_zero_buffer_is_zero() {
        let data = vec![0u8; 4096];
        let h = shannon_entropy(&data);
        assert!(h < 1e-9);
    }

    #[test]
    fn entropy_uniform_random_is_high() {
        // Pseudo-random bytes
        let mut rng = 123456789u64;
        let data: Vec<u8> = (0..1 << 15)
            .map(|_| {
                rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
                (rng >> 24) as u8
            })
            .collect();
        let h = shannon_entropy(&data);
        assert!(h > 7.0, "entropy too low: {}", h);
        assert!(h <= 8.0 + 1e-6);
    }

    #[test]
    fn sliding_window_detects_cliff() {
        // 8 KiB low-entropy, 8 KiB high-entropy
        let mut data = Vec::with_capacity(16384);
        data.extend(vec![b'A'; 8192]);
        let mut rng = 42u64;
        for _ in 0..8192 {
            rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
            data.push((rng >> 24) as u8);
        }

        let cfg = crate::triage::config::EntropyConfig {
            window_size: 1024,
            step: 1024,
            max_windows: 256,
            ..crate::triage::config::EntropyConfig::default()
        };

        let analysis = analyze_entropy(&data, &cfg);

        // Should detect entropy cliff
        assert!(analysis.packed_indicators.entropy_cliff.is_some());
        assert!(!analysis.anomalies.is_empty());

        // Windows should be present
        assert!(analysis
            .summary
            .windows
            .as_ref()
            .map(|w| !w.is_empty())
            .unwrap_or(false));
    }

    #[test]
    fn test_classification() {
        let cfg = EntropyConfig::default();

        // Low entropy (text-like)
        let text_data = b"Hello world, this is some text content.";
        let text_analysis = analyze_entropy(text_data, &cfg);
        match text_analysis.classification {
            EntropyClass::Text(_) | EntropyClass::Code(_) => (),
            _ => panic!("Expected Text or Code classification for text data"),
        }

        // High entropy (random)
        let mut rng = 42u64;
        let random_data: Vec<u8> = (0..1024)
            .map(|_| {
                rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
                (rng >> 24) as u8
            })
            .collect();
        let random_analysis = analyze_entropy(&random_data, &cfg);
        match random_analysis.classification {
            EntropyClass::Random(_) | EntropyClass::Encrypted(_) => (),
            _ => panic!("Expected Random or Encrypted classification for random data"),
        }
    }

    #[test]
    fn test_packed_indicators() {
        // Create data that looks like a packed file:
        // Low entropy header followed by high entropy body
        let mut data = Vec::new();
        data.extend(b"MZ\x90\x00\x03\x00\x00\x00"); // Fake PE header
        data.extend(vec![0u8; 1016]); // Pad header to 1024 bytes

        // Add high entropy body
        let mut rng = 99u64;
        for _ in 0..8192 {
            rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
            data.push((rng >> 24) as u8);
        }

        let cfg = EntropyConfig::default();
        let analysis = analyze_entropy(&data, &cfg);

        // Should detect packed indicators
        assert!(analysis.packed_indicators.has_low_entropy_header);
        assert!(analysis.packed_indicators.has_high_entropy_body);
        assert!(analysis.packed_indicators.verdict > 0.5);
    }
}
