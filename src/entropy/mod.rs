//! Entropy calculation utilities.

/// Calculates the Shannon entropy of a byte slice.
///
/// The entropy value is a float between 0.0 and 8.0, where 0.0 represents
/// no randomness and 8.0 represents maximum randomness.
pub fn calculate(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count == 0 {
            continue;
        }
        let p = (count as f64) / len;
        entropy -= p * p.log2();
    }

    entropy
}

/// Calculates entropy over a sliding window.
///
/// This is useful for detecting changes in entropy, such as finding packed or
/// encrypted sections within a larger file.
///
/// # Arguments
/// * `data` - The byte slice to analyze.
/// * `window_size` - The size of each window to calculate entropy for.
/// * `step` - The number of bytes to advance the window for each calculation.
///
/// # Returns
/// A vector of f64 entropy values, one for each window.
pub fn sliding_window(data: &[u8], window_size: usize, step: usize) -> Vec<f64> {
    if data.is_empty() || window_size == 0 || step == 0 || window_size > data.len() {
        return Vec::new();
    }

    data.windows(window_size)
        .step_by(step)
        .map(calculate)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_entropy_zeros() {
        let data = vec![0; 1024];
        assert_eq!(calculate(&data), 0.0);
    }

    #[test]
    fn test_calculate_entropy_random() {
        // Pseudo-random data should have high entropy
        let data: Vec<u8> = (0..255).cycle().take(1024).collect();
        let entropy = calculate(&data);
        assert!(entropy > 7.9 && entropy <= 8.0);
    }

    #[test]
    fn test_calculate_entropy_ascii() {
        let data = b"This is some sample text for entropy calculation.";
        let entropy = calculate(data);
        assert!(entropy > 3.0 && entropy < 5.0);
    }

    #[test]
    fn test_calculate_empty_input() {
        assert_eq!(calculate(&[]), 0.0);
    }

    #[test]
    fn test_sliding_window() {
        let mut data = vec![0; 512]; // Low entropy
        data.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8].repeat(64)); // High entropy
        
        let entropies = sliding_window(&data, 128, 128);
        
        assert_eq!(entropies.len(), 8);
        // First few windows should be low entropy
        assert!(entropies[0] < 0.1);
        assert!(entropies[1] < 0.1);
        assert!(entropies[2] < 0.1);
        assert!(entropies[3] < 0.1);
        // Last few windows should be high entropy
        assert!(entropies[4] > 2.9);
        assert!(entropies[5] > 2.9);
    }

    #[test]
    fn test_sliding_window_edge_cases() {
        // Empty data
        assert!(sliding_window(&[], 128, 128).is_empty());
        // Window larger than data
        assert!(sliding_window(&[1, 2, 3], 128, 128).is_empty());
        // Zero step
        assert!(sliding_window(&[1, 2, 3], 1, 0).is_empty());
    }
}