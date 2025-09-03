//! High-performance entropy calculation and analysis.
//!
//! This module provides low-level entropy calculation primitives used throughout
//! the Glaurung binary analysis framework. It includes:
//!
//! - Core Shannon entropy calculations
//! - Optimized sliding window analysis
//! - Statistical utilities for entropy data
//!
//! # Performance Considerations
//!
//! The entropy calculations in this module are performance-critical and have been
//! optimized with:
//! - Histogram-based incremental updates for sliding windows
//! - Single-pass algorithms where possible
//! - Efficient memory usage with bounded window counts
//!
//! # Example
//!
//! ```ignore
//! use glaurung::entropy::{shannon_entropy, analyze_windows, WindowConfig};
//!
//! // Simple entropy calculation
//! let data = b"Hello, World!";
//! let entropy = shannon_entropy(data);
//!
//! // Sliding window analysis
//! let config = WindowConfig {
//!     window_size: 1024,
//!     step_size: 512,
//!     max_windows: 100,
//! };
//! let analysis = analyze_windows(data, &config);
//! ```

pub mod core;
pub mod stats;
pub mod window;

// Re-export main functionality
pub use self::core::{shannon_entropy, Histogram};
pub use self::stats::{Stats, calculate_median, find_outliers, detect_anomalies_zscore};
pub use self::window::{analyze_windows, analyze_chunks, WindowConfig, WindowAnalysis};

// Backwards compatibility aliases
pub use self::core::shannon_entropy as calculate;

/// Calculates entropy over a sliding window (backwards compatibility).
///
/// This function exists for backwards compatibility with existing code.
/// New code should use `analyze_windows` or `analyze_chunks` instead.
pub fn sliding_window(data: &[u8], window_size: usize, step: usize) -> Vec<f64> {
    let config = WindowConfig {
        window_size,
        step_size: step,
        max_windows: usize::MAX,
    };
    let analysis = analyze_windows(data, &config);
    analysis.entropies
}

/// Quick entropy summary for a byte slice.
///
/// Returns (overall_entropy, min_window, max_window, mean_window)
pub fn quick_summary(data: &[u8], window_size: usize) -> (f64, f64, f64, f64) {
    let overall = shannon_entropy(data);
    
    if data.len() <= window_size {
        return (overall, overall, overall, overall);
    }
    
    let config = WindowConfig {
        window_size,
        step_size: window_size,
        max_windows: 256,
    };
    let analysis = analyze_windows(data, &config);
    
    let min = analysis.min().unwrap_or(0.0);
    let max = analysis.max().unwrap_or(0.0);
    let mean = analysis.mean().unwrap_or(0.0);
    
    (overall, min, max, mean)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_quick_summary() {
        let mut data = vec![0u8; 1024];
        data.extend_from_slice(&(0..=255).cycle().take(1024).collect::<Vec<u8>>());
        
        let (overall, min, max, mean) = quick_summary(&data, 256);
        
        assert!(overall > 3.0 && overall < 5.0);  // Mixed entropy
        assert!(min < 0.1);  // Zeros have low entropy
        assert!(max > 7.0);  // Random has high entropy
        assert!(mean > min && mean < max);
    }
    
    #[test]
    fn test_backwards_compat_sliding_window() {
        let data = vec![0u8; 512];
        let entropies = sliding_window(&data, 128, 128);
        assert_eq!(entropies.len(), 4);
        for e in entropies {
            assert!(e < 0.1);
        }
    }
}