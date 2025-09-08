//! Sliding window entropy analysis.
//!
//! Provides efficient sliding window entropy calculations for detecting
//! entropy changes across data regions.

use crate::entropy::core::{shannon_entropy, Histogram};

/// Configuration for sliding window entropy analysis.
#[derive(Debug, Clone)]
pub struct WindowConfig {
    /// Size of each window in bytes.
    pub window_size: usize,
    /// Step size between windows in bytes.
    pub step_size: usize,
    /// Maximum number of windows to compute (for memory bounds).
    pub max_windows: usize,
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            window_size: 8192,
            step_size: 8192,
            max_windows: 256,
        }
    }
}

/// Result of sliding window entropy analysis.
#[derive(Debug, Clone)]
pub struct WindowAnalysis {
    /// Entropy values for each window.
    pub entropies: Vec<f64>,
    /// Window size used for analysis.
    pub window_size: usize,
    /// Step size used for analysis.
    pub step_size: usize,
}

impl WindowAnalysis {
    /// Returns the number of windows analyzed.
    pub fn len(&self) -> usize {
        self.entropies.len()
    }

    /// Returns true if no windows were analyzed.
    pub fn is_empty(&self) -> bool {
        self.entropies.is_empty()
    }

    /// Finds the minimum entropy value.
    pub fn min(&self) -> Option<f64> {
        self.entropies.iter().copied().reduce(f64::min)
    }

    /// Finds the maximum entropy value.
    pub fn max(&self) -> Option<f64> {
        self.entropies.iter().copied().reduce(f64::max)
    }

    /// Calculates the mean entropy.
    pub fn mean(&self) -> Option<f64> {
        if self.entropies.is_empty() {
            return None;
        }
        let sum: f64 = self.entropies.iter().sum();
        Some(sum / self.entropies.len() as f64)
    }

    /// Calculates the standard deviation of entropy values.
    pub fn std_dev(&self) -> Option<f64> {
        let mean = self.mean()?;
        let variance: f64 = self
            .entropies
            .iter()
            .map(|&x| {
                let diff = x - mean;
                diff * diff
            })
            .sum::<f64>()
            / self.entropies.len() as f64;
        Some(variance.sqrt())
    }

    /// Detects entropy cliffs (sudden changes between consecutive windows).
    ///
    /// Returns indices and delta values where the entropy change exceeds the threshold.
    pub fn detect_cliffs(&self, threshold: f64) -> Vec<(usize, f64)> {
        let mut cliffs = Vec::new();
        for i in 1..self.entropies.len() {
            let delta = (self.entropies[i] - self.entropies[i - 1]).abs();
            if delta >= threshold {
                cliffs.push((i, delta));
            }
        }
        cliffs
    }
}

/// Performs sliding window entropy analysis on data.
///
/// This function uses an optimized histogram-based approach that updates
/// incrementally as the window slides, avoiding redundant recalculation.
pub fn analyze_windows(data: &[u8], config: &WindowConfig) -> WindowAnalysis {
    if data.is_empty() || config.window_size == 0 || config.step_size == 0 {
        return WindowAnalysis {
            entropies: Vec::new(),
            window_size: config.window_size,
            step_size: config.step_size,
        };
    }

    let window_size = config.window_size.min(data.len());
    let step_size = config.step_size.max(1);

    if data.len() < window_size {
        // Data smaller than window - return single entropy value
        return WindowAnalysis {
            entropies: vec![shannon_entropy(data)],
            window_size,
            step_size,
        };
    }

    // Calculate total windows and sampling stride for memory bounds
    let total_possible = 1 + (data.len() - window_size) / step_size;
    let stride = if total_possible > config.max_windows {
        total_possible.div_ceil(config.max_windows).max(1)
    } else {
        1
    };

    let mut entropies = Vec::with_capacity(config.max_windows.min(total_possible));
    let mut histogram = Histogram::from_bytes(&data[0..window_size]);
    let mut position = 0;
    let mut computed = 0;

    loop {
        // Sample based on stride
        if computed % stride == 0 {
            entropies.push(histogram.entropy());
            if entropies.len() >= config.max_windows {
                break;
            }
        }

        // Check if we can advance
        if position + window_size + step_size > data.len() {
            break;
        }

        // Slide the histogram efficiently
        let old_start = position;
        let old_end = position + step_size;
        let new_start = position + window_size;
        let new_end = position + window_size + step_size;

        histogram.slide(&data[old_start..old_end], &data[new_start..new_end]);

        position += step_size;
        computed += 1;
    }

    WindowAnalysis {
        entropies,
        window_size,
        step_size,
    }
}

/// Performs fast non-overlapping window entropy analysis.
///
/// This is faster than sliding windows but may miss transitions at boundaries.
pub fn analyze_chunks(data: &[u8], chunk_size: usize) -> Vec<f64> {
    if data.is_empty() || chunk_size == 0 {
        return Vec::new();
    }

    data.chunks(chunk_size).map(shannon_entropy).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_analysis_empty() {
        let config = WindowConfig::default();
        let analysis = analyze_windows(&[], &config);
        assert!(analysis.is_empty());
    }

    #[test]
    fn test_window_analysis_basic() {
        // Create data with low entropy followed by high entropy
        let mut data = vec![b'A'; 1024];
        data.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7].repeat(128));

        let config = WindowConfig {
            window_size: 256,
            step_size: 256,
            max_windows: 10,
        };

        let analysis = analyze_windows(&data, &config);

        // First windows should have low entropy
        assert!(analysis.entropies[0] < 0.1);

        // Last windows should have higher entropy
        let last_idx = analysis.entropies.len() - 1;
        assert!(analysis.entropies[last_idx] > 2.0);

        // Should detect entropy cliff
        let cliffs = analysis.detect_cliffs(2.0);
        assert!(!cliffs.is_empty());
    }

    #[test]
    fn test_window_statistics() {
        let data: Vec<u8> = (0..=255).collect();
        let config = WindowConfig {
            window_size: 64,
            step_size: 32,
            max_windows: 100,
        };

        let analysis = analyze_windows(&data, &config);

        assert!(analysis.min().is_some());
        assert!(analysis.max().is_some());
        assert!(analysis.mean().is_some());
        assert!(analysis.std_dev().is_some());

        // All windows should have similar high entropy
        let std_dev = analysis.std_dev().unwrap();
        assert!(std_dev < 0.5); // Low variation
    }

    #[test]
    fn test_chunks_analysis() {
        let mut data = vec![0u8; 256];
        data.extend_from_slice(&(0..=255).collect::<Vec<u8>>());

        let entropies = analyze_chunks(&data, 256);
        assert_eq!(entropies.len(), 2);
        assert!(entropies[0] < 0.1); // All zeros
        assert!(entropies[1] > 7.9); // Full range
    }

    #[test]
    fn test_max_windows_limit() {
        let data = vec![0u8; 10000];
        let config = WindowConfig {
            window_size: 100,
            step_size: 10,
            max_windows: 5, // Limit to 5 windows
        };

        let analysis = analyze_windows(&data, &config);
        assert_eq!(analysis.entropies.len(), 5);
    }
}
