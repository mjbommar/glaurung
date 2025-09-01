use crate::core::triage::{
    EntropyAnalysis, EntropyAnomaly, EntropyClass, EntropySummary, PackedIndicators,
};
use crate::triage::config::EntropyConfig;
#[cfg(feature = "python-ext")]
use pyo3::prelude::*;

#[inline]
pub fn entropy_of_slice(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut hist = [0usize; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for c in hist.iter().copied() {
        if c == 0 {
            continue;
        }
        let p = (c as f64) / len;
        h -= p * p.log2();
    }
    h
}

pub fn compute_entropy(data: &[u8], cfg: &EntropyConfig) -> EntropySummary {
    let mut overall = None;
    if cfg.overall {
        overall = Some(entropy_of_slice(data));
    }

    let mut windows_vec: Vec<f64> = Vec::new();
    let win = cfg.window_size.max(1);
    let step = cfg.step.max(1);
    if data.len() >= win {
        // Cap number of windows by downsampling if necessary
        let total_windows = 1 + (data.len() - win) / step;
        let stride = if total_windows > cfg.max_windows {
            total_windows.div_ceil(cfg.max_windows).max(1)
        } else {
            1
        };

        // Initialize histogram for first window
        let mut hist = [0usize; 256];
        let first = &data[0..win];
        for &b in first {
            hist[b as usize] += 1;
        }
        let mut start = 0usize;
        let mut computed = 0usize;
        while start + win <= data.len() {
            if computed.is_multiple_of(stride) {
                // compute entropy from hist
                let mut h = 0.0;
                let len = win as f64;
                for &c in &hist {
                    if c == 0 {
                        continue;
                    }
                    let p = (c as f64) / len;
                    h -= p * p.log2();
                }
                windows_vec.push(h);
                if windows_vec.len() >= cfg.max_windows {
                    break;
                }
            }
            computed += 1;
            // advance by step; update histogram by removing outgoing and adding incoming
            if start + win + step > data.len() {
                break;
            }
            for i in 0..step {
                let out_b = data[start + i];
                hist[out_b as usize] = hist[out_b as usize].saturating_sub(1);
                let in_b = data[start + win + i];
                hist[in_b as usize] = hist[in_b as usize].saturating_add(1);
            }
            start += step;
        }
    }

    let (mean, std_dev, min, max) = if windows_vec.is_empty() {
        (None, None, None, None)
    } else {
        let len = windows_vec.len() as f64;
        let sum: f64 = windows_vec.iter().copied().sum();
        let mean = sum / len;
        let var_sum: f64 = windows_vec
            .iter()
            .map(|&x| {
                let d = x - mean;
                d * d
            })
            .sum();
        let std_dev = (var_sum / len).sqrt();
        let min = windows_vec.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        let max = windows_vec.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
        (Some(mean), Some(std_dev), Some(min), Some(max))
    };

    EntropySummary {
        overall,
        window_size: if windows_vec.is_empty() {
            None
        } else {
            Some(win as u32)
        },
        windows: if windows_vec.is_empty() {
            None
        } else {
            Some(windows_vec)
        },
        mean,
        std_dev,
        min,
        max,
    }
}

pub fn analyze_entropy(data: &[u8], cfg: &EntropyConfig) -> EntropyAnalysis {
    // Summary (overall + windows)
    let summary = compute_entropy(data, cfg);
    let overall = summary.overall.unwrap_or_else(|| entropy_of_slice(data));

    // Classification via thresholds
    let t = &cfg.thresholds;
    let class = if overall > t.encrypted as f64 {
        EntropyClass::Random(overall as f32)
    } else if overall > t.compressed as f64 {
        EntropyClass::Encrypted(overall as f32)
    } else if overall > t.code as f64 {
        EntropyClass::Compressed(overall as f32)
    } else if overall > t.text as f64 {
        EntropyClass::Code(overall as f32)
    } else {
        EntropyClass::Text(overall as f32)
    };

    // Packed indicators using header/body split
    let header_len = data.len().min(cfg.header_size);
    let header_entropy = if header_len > 0 {
        entropy_of_slice(&data[..header_len])
    } else {
        0.0
    };
    let body_entropy = if data.len() > header_len {
        entropy_of_slice(&data[header_len..])
    } else {
        0.0
    };
    let has_low_entropy_header = header_len > 0 && header_entropy < t.low_header as f64;
    let has_high_entropy_body = data.len() > header_len && body_entropy > t.high_body as f64;
    let mut entropy_cliff_idx = None;
    let verdict = if has_low_entropy_header && has_high_entropy_body {
        0.8
    } else {
        0.0
    };

    // Anomalies: detect cliffs between consecutive windows
    let mut anomalies: Vec<EntropyAnomaly> = Vec::new();
    if let Some(ws) = &summary.windows {
        for i in 1..ws.len() {
            let from = ws[i - 1];
            let to = ws[i];
            let delta = (to - from).abs();
            if delta >= t.cliff_delta as f64 {
                if entropy_cliff_idx.is_none() {
                    entropy_cliff_idx = Some(i);
                }
                anomalies.push(EntropyAnomaly {
                    index: i,
                    from,
                    to,
                    delta,
                });
            }
        }
    }

    let indicators = PackedIndicators {
        has_low_entropy_header,
        has_high_entropy_body,
        entropy_cliff: entropy_cliff_idx,
        verdict,
    };

    EntropyAnalysis {
        summary,
        classification: class,
        packed_indicators: indicators,
        anomalies,
    }
}

// Python convenience wrappers
#[cfg(feature = "python-ext")]
#[pyfunction]
#[pyo3(name = "entropy_of_bytes")]
pub fn entropy_of_bytes_py(data: Vec<u8>) -> PyResult<f64> {
    Ok(entropy_of_slice(&data))
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
        let h = entropy_of_slice(&data);
        assert!(h < 1e-9);
    }

    #[test]
    fn entropy_uniform_random_is_high() {
        // Pseudo-random bytes without external crates
        let mut rng = 123456789u64;
        let data: Vec<u8> = (0..1 << 15)
            .map(|_| {
                rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
                (rng >> 24) as u8
            })
            .collect();
        let h = entropy_of_slice(&data);
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
        assert!(analysis.packed_indicators.entropy_cliff.is_some());
        assert!(!analysis.anomalies.is_empty());
        // windows present
        assert!(analysis
            .summary
            .windows
            .as_ref()
            .map(|w| !w.is_empty())
            .unwrap_or(false));
    }
}
