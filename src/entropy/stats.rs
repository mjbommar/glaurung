//! Statistical utilities for entropy analysis.
//!
//! Provides common statistical functions optimized for entropy data.

use std::cmp::Ordering;

/// Statistical summary of entropy values.
#[derive(Debug, Clone, PartialEq)]
pub struct Stats {
    pub mean: f64,
    pub std_dev: f64,
    pub min: f64,
    pub max: f64,
    pub median: f64,
}

impl Stats {
    /// Computes statistical summary from entropy values.
    ///
    /// Returns None if the input is empty.
    pub fn from_values(values: &[f64]) -> Option<Self> {
        if values.is_empty() {
            return None;
        }

        let len = values.len() as f64;

        // Calculate mean
        let sum: f64 = values.iter().sum();
        let mean = sum / len;

        // Calculate variance and std_dev
        let variance: f64 = values
            .iter()
            .map(|&x| {
                let diff = x - mean;
                diff * diff
            })
            .sum::<f64>()
            / len;
        let std_dev = variance.sqrt();

        // Find min and max
        let min = values.iter().copied().reduce(f64::min).unwrap_or(0.0);
        let max = values.iter().copied().reduce(f64::max).unwrap_or(0.0);

        // Calculate median
        let median = calculate_median(values);

        Some(Stats {
            mean,
            std_dev,
            min,
            max,
            median,
        })
    }
}

/// Calculates the median of a slice of values.
///
/// Note: This function sorts the input internally.
pub fn calculate_median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut sorted: Vec<f64> = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));

    let mid = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    }
}

/// Identifies outliers using the interquartile range (IQR) method.
///
/// Returns indices of values that are outliers (1.5 * IQR beyond Q1 or Q3).
pub fn find_outliers(values: &[f64]) -> Vec<usize> {
    if values.len() < 4 {
        return Vec::new();
    }

    let mut sorted_with_idx: Vec<(f64, usize)> =
        values.iter().enumerate().map(|(i, &v)| (v, i)).collect();
    sorted_with_idx.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal));

    let n = sorted_with_idx.len();
    let q1_idx = n / 4;
    let q3_idx = 3 * n / 4;

    let q1 = sorted_with_idx[q1_idx].0;
    let q3 = sorted_with_idx[q3_idx].0;
    let iqr = q3 - q1;

    let lower_bound = q1 - 1.5 * iqr;
    let upper_bound = q3 + 1.5 * iqr;

    sorted_with_idx
        .iter()
        .filter(|(val, _)| *val < lower_bound || *val > upper_bound)
        .map(|(_, idx)| *idx)
        .collect()
}

/// Calculates the coefficient of variation (CV).
///
/// CV = standard deviation / mean
/// Useful for comparing variability between datasets with different scales.
pub fn coefficient_of_variation(mean: f64, std_dev: f64) -> f64 {
    if mean.abs() < 1e-10 {
        return 0.0;
    }
    std_dev / mean.abs()
}

/// Detects significant changes in entropy using z-score.
///
/// Returns indices where the z-score exceeds the threshold (typically 2.0 or 3.0).
pub fn detect_anomalies_zscore(values: &[f64], threshold: f64) -> Vec<usize> {
    if values.len() < 2 {
        return Vec::new();
    }

    let stats = match Stats::from_values(values) {
        Some(s) => s,
        None => return Vec::new(),
    };

    if stats.std_dev < 1e-10 {
        return Vec::new();
    }

    values
        .iter()
        .enumerate()
        .filter(|(_, &val)| {
            let z_score = (val - stats.mean).abs() / stats.std_dev;
            z_score > threshold
        })
        .map(|(idx, _)| idx)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_basic() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let stats = Stats::from_values(&values).unwrap();

        assert_eq!(stats.mean, 3.0);
        assert_eq!(stats.min, 1.0);
        assert_eq!(stats.max, 5.0);
        assert_eq!(stats.median, 3.0);
        assert!(stats.std_dev > 1.4 && stats.std_dev < 1.5);
    }

    #[test]
    fn test_stats_empty() {
        let values: Vec<f64> = vec![];
        assert!(Stats::from_values(&values).is_none());
    }

    #[test]
    fn test_median_even() {
        let values = vec![1.0, 2.0, 3.0, 4.0];
        let median = calculate_median(&values);
        assert_eq!(median, 2.5);
    }

    #[test]
    fn test_median_odd() {
        let values = vec![1.0, 3.0, 2.0, 5.0, 4.0];
        let median = calculate_median(&values);
        assert_eq!(median, 3.0);
    }

    #[test]
    fn test_find_outliers() {
        let mut values = vec![1.0, 2.0, 2.1, 2.2, 2.3, 2.4, 2.5, 3.0];
        values.push(10.0); // Outlier
        values.push(-5.0); // Outlier

        let outliers = find_outliers(&values);
        assert!(outliers.contains(&8)); // Index of 10.0
        assert!(outliers.contains(&9)); // Index of -5.0
    }

    #[test]
    fn test_coefficient_of_variation() {
        let cv1 = coefficient_of_variation(10.0, 2.0);
        assert_eq!(cv1, 0.2);

        let cv2 = coefficient_of_variation(100.0, 20.0);
        assert_eq!(cv2, 0.2);

        // Zero mean
        let cv3 = coefficient_of_variation(0.0, 1.0);
        assert_eq!(cv3, 0.0);
    }

    #[test]
    fn test_detect_anomalies_zscore() {
        let mut values = vec![5.0; 20];
        values[10] = 15.0; // Anomaly
        values[15] = -5.0; // Anomaly

        let anomalies = detect_anomalies_zscore(&values, 2.0);
        assert!(anomalies.contains(&10));
        assert!(anomalies.contains(&15));
    }
}
