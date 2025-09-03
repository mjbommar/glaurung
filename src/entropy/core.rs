//! Core entropy calculation primitives.
//!
//! This module provides low-level, high-performance entropy calculations
//! used throughout the triage and analysis pipeline.

use std::ops::Range;

/// Calculates the Shannon entropy of a byte slice.
///
/// Returns a value between 0.0 and 8.0, where:
/// - 0.0 represents no randomness (e.g., all bytes are the same)
/// - 8.0 represents maximum randomness (uniform distribution)
///
/// # Performance
/// This function is optimized for performance with:
/// - Single-pass histogram construction
/// - Efficient log2 calculation
/// - Branch-free inner loop where possible
#[inline]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    
    // Build histogram in a single pass
    let mut histogram = [0usize; 256];
    for &byte in data {
        histogram[byte as usize] += 1;
    }
    
    // Calculate entropy from histogram
    let len = data.len() as f64;
    let mut entropy = 0.0;
    
    for &count in &histogram {
        if count == 0 {
            continue;
        }
        let p = (count as f64) / len;
        entropy -= p * p.log2();
    }
    
    entropy
}

/// Histogram structure for efficient sliding window entropy calculations.
///
/// Maintains a byte frequency histogram that can be efficiently updated
/// as a window slides through data.
#[derive(Debug, Clone)]
pub struct Histogram {
    counts: [usize; 256],
    total: usize,
}

impl Histogram {
    /// Creates a new empty histogram.
    #[inline]
    pub fn new() -> Self {
        Self {
            counts: [0; 256],
            total: 0,
        }
    }
    
    /// Creates a histogram from a byte slice.
    #[inline]
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut hist = Self::new();
        for &byte in data {
            hist.add(byte);
        }
        hist
    }
    
    /// Adds a byte to the histogram.
    #[inline]
    pub fn add(&mut self, byte: u8) {
        self.counts[byte as usize] += 1;
        self.total += 1;
    }
    
    /// Removes a byte from the histogram.
    #[inline]
    pub fn remove(&mut self, byte: u8) {
        let count = &mut self.counts[byte as usize];
        *count = count.saturating_sub(1);
        self.total = self.total.saturating_sub(1);
    }
    
    /// Slides the histogram window by removing old bytes and adding new ones.
    ///
    /// This is more efficient than recreating the histogram for overlapping windows.
    #[inline]
    pub fn slide(&mut self, old_bytes: &[u8], new_bytes: &[u8]) {
        debug_assert_eq!(old_bytes.len(), new_bytes.len(), 
                        "slide requires equal length slices");
        
        for (&old, &new) in old_bytes.iter().zip(new_bytes.iter()) {
            if old != new {
                self.remove(old);
                self.add(new);
            }
        }
    }
    
    /// Calculates the entropy of the current histogram.
    #[inline]
    pub fn entropy(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        
        let total = self.total as f64;
        let mut entropy = 0.0;
        
        for &count in &self.counts {
            if count == 0 {
                continue;
            }
            let p = (count as f64) / total;
            entropy -= p * p.log2();
        }
        
        entropy
    }
    
    /// Returns the total number of bytes in the histogram.
    #[inline]
    pub fn len(&self) -> usize {
        self.total
    }
    
    /// Returns true if the histogram is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
    
    /// Resets the histogram to empty state.
    #[inline]
    pub fn clear(&mut self) {
        self.counts = [0; 256];
        self.total = 0;
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculates entropy for a specific byte range within a slice.
///
/// This is useful for analyzing specific sections like headers or footers.
#[inline]
pub fn entropy_range(data: &[u8], range: Range<usize>) -> f64 {
    let start = range.start.min(data.len());
    let end = range.end.min(data.len());
    if start >= end {
        return 0.0;
    }
    shannon_entropy(&data[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_shannon_entropy_zeros() {
        let data = vec![0u8; 1024];
        assert!(shannon_entropy(&data) < 1e-9);
    }
    
    #[test]
    fn test_shannon_entropy_uniform() {
        // Create uniform distribution
        let data: Vec<u8> = (0..=255).cycle().take(256 * 100).collect();
        let entropy = shannon_entropy(&data);
        assert!((entropy - 8.0).abs() < 0.01);
    }
    
    #[test]
    fn test_histogram_basic() {
        let mut hist = Histogram::new();
        assert_eq!(hist.len(), 0);
        assert!(hist.is_empty());
        
        hist.add(0);
        hist.add(0);
        hist.add(255);
        assert_eq!(hist.len(), 3);
        assert!(!hist.is_empty());
        
        hist.remove(0);
        assert_eq!(hist.len(), 2);
    }
    
    #[test]
    fn test_histogram_entropy() {
        // All zeros should have zero entropy
        let data = vec![0u8; 256];
        let hist = Histogram::from_bytes(&data);
        assert!(hist.entropy() < 1e-9);
        
        // Uniform distribution should have high entropy
        let data: Vec<u8> = (0..=255).collect();
        let hist = Histogram::from_bytes(&data);
        assert!((hist.entropy() - 8.0).abs() < 0.01);
    }
    
    #[test]
    fn test_histogram_slide() {
        let mut hist = Histogram::from_bytes(b"AAABBB");
        let _initial_entropy = hist.entropy();
        
        // Slide window: remove "AAA", add "CCC"
        hist.slide(b"AAA", b"CCC");
        
        // Should now be equivalent to "BBBCCC"
        let expected = Histogram::from_bytes(b"BBBCCC");
        assert_eq!(hist.counts, expected.counts);
        assert_eq!(hist.total, expected.total);
    }
    
    #[test]
    fn test_entropy_range() {
        let data = b"AAAABBBBCCCC";
        
        // First third (AAAA) - zero entropy
        let e1 = entropy_range(data, 0..4);
        assert!(e1 < 1e-9);
        
        // Middle (BBBB) - zero entropy  
        let e2 = entropy_range(data, 4..8);
        assert!(e2 < 1e-9);
        
        // Full range - should have some entropy
        let e3 = entropy_range(data, 0..12);
        assert!(e3 > 1.0);
    }
}