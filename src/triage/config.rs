//! Configuration for the triage module.
//!
//! Provides centralized configuration for all triage components with
//! sensible defaults and Python-accessible configuration.

use serde::{Deserialize, Serialize};

/// Master configuration for the triage pipeline.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TriageConfig {
    /// I/O configuration for file reading and buffering.
    pub io: IOConfig,
    /// Entropy analysis configuration.
    pub entropy: EntropyConfig,
    /// Heuristics configuration for string extraction and analysis.
    pub heuristics: HeuristicsConfig,
    /// Scoring and confidence configuration.
    pub scoring: ScoringConfig,
    /// Packer detection configuration.
    pub packers: PackerConfig,
    /// Header analysis configuration.
    pub headers: HeaderConfig,
    /// Parser configuration.
    pub parsers: ParserConfig,
}

/// I/O configuration for file reading and buffering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IOConfig {
    /// Maximum size for content sniffing (default: 4096).
    pub max_sniff_size: usize,
    /// Maximum size for header analysis (default: 65536).
    pub max_header_size: usize,
    /// Maximum size for entropy analysis (default: 1048576).
    pub max_entropy_size: usize,
    /// Maximum bytes to read from a file (default: 10485760 = 10MB).
    pub max_read_bytes: usize,
    /// Maximum file size to process (default: 104857600 = 100MB).
    pub max_file_size: u64,
    /// Sniff buffer size (default: 1048576 = 1MB).
    pub sniff_buffer_size: usize,
}

impl Default for IOConfig {
    fn default() -> Self {
        Self {
            max_sniff_size: 4096,
            max_header_size: 65536,
            max_entropy_size: 1048576,
            max_read_bytes: 10485760,   // 10MB
            max_file_size: 104857600,   // 100MB
            sniff_buffer_size: 1048576, // 1MB
        }
    }
}

/// Entropy analysis configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyConfig {
    /// Size of the sliding window in bytes (default: 8192).
    pub window_size: usize,
    /// Step between windows in bytes (default: window_size).
    pub step: usize,
    /// Maximum number of windows to compute (default: 256).
    pub max_windows: usize,
    /// Whether to compute overall entropy (default: true).
    pub overall: bool,
    /// Size of header for separate entropy analysis (default: 1024).
    pub header_size: usize,
    /// Entropy classification thresholds.
    pub thresholds: EntropyThresholds,
    /// Entropy scoring weights.
    pub weights: EntropyWeights,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            window_size: 8192,
            step: 8192,
            max_windows: 256,
            overall: true,
            header_size: 1024,
            thresholds: EntropyThresholds::default(),
            weights: EntropyWeights::default(),
        }
    }
}

/// Entropy classification thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyThresholds {
    /// Threshold for text classification (< this value).
    pub text: f32,
    /// Threshold for code classification (< this value).
    pub code: f32,
    /// Threshold for compressed classification (< this value).
    pub compressed: f32,
    /// Threshold for encrypted classification (<= this value).
    pub encrypted: f32,
    /// Entropy cliff detection threshold (delta).
    pub cliff_delta: f32,
    /// Low entropy header threshold.
    pub low_header: f32,
    /// High entropy body threshold.
    pub high_body: f32,
}

impl Default for EntropyThresholds {
    fn default() -> Self {
        Self {
            text: 3.0,
            code: 5.0,
            compressed: 7.0,
            encrypted: 7.8,
            cliff_delta: 1.0,
            low_header: 4.0,
            high_body: 7.0,
        }
    }
}

/// Entropy scoring weights.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyWeights {
    /// Weight for low entropy header + high entropy body.
    pub header_body_mismatch: f32,
    /// Weight for entropy cliff detection.
    pub cliff_detected: f32,
    /// Weight for high entropy classification.
    pub high_entropy: f32,
    /// Weight for encrypted/random classification.
    pub encrypted_random: f32,
}

impl Default for EntropyWeights {
    fn default() -> Self {
        Self {
            header_body_mismatch: 0.6,
            cliff_detected: 0.2,
            high_entropy: 0.1,
            encrypted_random: 0.2,
        }
    }
}

/// Heuristics configuration for string extraction and analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicsConfig {
    /// Minimum string length for extraction (default: 4).
    pub min_string_length: usize,
    /// Maximum number of string samples (default: 40).
    pub string_sample_limit: usize,
    /// Maximum length of each string sample (default: 120).
    pub string_sample_max_len: usize,
    /// Threshold for endianness detection (default: 0.1).
    pub endianness_threshold: f32,
    /// Weight for endianness confidence (default: 0.05).
    pub endianness_weight: f32,
}

impl Default for HeuristicsConfig {
    fn default() -> Self {
        Self {
            min_string_length: 4,
            string_sample_limit: 40,
            string_sample_max_len: 120,
            endianness_threshold: 0.1,
            endianness_weight: 0.05,
        }
    }
}

/// Scoring and confidence configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringConfig {
    /// Weight for content-based detection (infer).
    pub infer_weight: f32,
    /// Weight for extension-based detection (mime_guess).
    pub mime_weight: f32,
    /// Weight for other detection sources.
    pub other_weight: f32,
    /// Confidence for successful parser.
    pub parser_success_confidence: f32,
    /// Penalty for format inconsistency.
    pub format_consistency_penalty: f32,
    /// Penalty for architecture inconsistency.
    pub arch_consistency_penalty: f32,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            infer_weight: 0.15,
            mime_weight: 0.05,
            other_weight: 0.10,
            parser_success_confidence: 0.30,
            format_consistency_penalty: -0.10,
            arch_consistency_penalty: -0.15,
        }
    }
}

/// Packer detection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerConfig {
    /// Maximum bytes to scan for packer signatures (default: 524288 = 512KB).
    pub scan_limit: usize,
    /// Weight for UPX detection confidence.
    pub upx_detection_weight: f32,
    /// Weight for UPX version match.
    pub upx_version_weight: f32,
    /// Overall packer detection weight in scoring.
    pub packer_signal_weight: f32,
}

impl Default for PackerConfig {
    fn default() -> Self {
        Self {
            scan_limit: 524288, // 512KB
            upx_detection_weight: 0.6,
            upx_version_weight: 0.2,
            packer_signal_weight: 0.30,
        }
    }
}

/// Header analysis configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderConfig {
    /// Base confidence for header detection.
    pub base_confidence: f32,
    /// Confidence for headers with version/machine info.
    pub detailed_confidence: f32,
}

impl Default for HeaderConfig {
    fn default() -> Self {
        Self {
            base_confidence: 0.7,
            detailed_confidence: 0.8,
        }
    }
}

/// Parser configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParserConfig {
    /// Confidence for Python bytecode detection.
    pub python_bytecode_confidence: f32,
}

impl Default for ParserConfig {
    fn default() -> Self {
        Self {
            python_bytecode_confidence: 0.9,
        }
    }
}

// TODO: Add Python bindings for configuration
// This would require adding pyclass attributes and pyo3-serde dependency
