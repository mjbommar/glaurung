//! Configuration for the triage module.
//!
//! Provides centralized configuration for all triage components with
//! sensible defaults and Python-accessible configuration.

use serde::{Deserialize, Serialize};

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;

/// Master configuration for the triage pipeline.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
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
    /// Similarity (CTPH) configuration.
    pub similarity: SimilarityConfig,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl TriageConfig {
    #[new]
    pub fn new() -> Self {
        Self::default()
    }

    #[getter]
    pub fn get_io(&self) -> IOConfig {
        self.io.clone()
    }

    #[getter]
    pub fn get_entropy(&self) -> EntropyConfig {
        self.entropy.clone()
    }

    #[getter]
    pub fn get_heuristics(&self) -> HeuristicsConfig {
        self.heuristics.clone()
    }

    #[getter]
    pub fn get_scoring(&self) -> ScoringConfig {
        self.scoring.clone()
    }

    #[getter]
    pub fn get_packers(&self) -> PackerConfig {
        self.packers.clone()
    }

    #[getter]
    pub fn get_headers(&self) -> HeaderConfig {
        self.headers.clone()
    }

    #[getter]
    pub fn get_parsers(&self) -> ParserConfig {
        self.parsers.clone()
    }

    #[getter]
    pub fn get_similarity(&self) -> SimilarityConfig {
        self.similarity.clone()
    }

    #[setter]
    pub fn set_io(&mut self, config: IOConfig) {
        self.io = config;
    }

    #[setter]
    pub fn set_entropy(&mut self, config: EntropyConfig) {
        self.entropy = config;
    }

    #[setter]
    pub fn set_heuristics(&mut self, config: HeuristicsConfig) {
        self.heuristics = config;
    }

    #[setter]
    pub fn set_scoring(&mut self, config: ScoringConfig) {
        self.scoring = config;
    }

    #[setter]
    pub fn set_packers(&mut self, config: PackerConfig) {
        self.packers = config;
    }

    #[setter]
    pub fn set_headers(&mut self, config: HeaderConfig) {
        self.headers = config;
    }

    #[setter]
    pub fn set_parsers(&mut self, config: ParserConfig) {
        self.parsers = config;
    }

    #[setter]
    pub fn set_similarity(&mut self, config: SimilarityConfig) {
        self.similarity = config;
    }
}

/// Similarity (CTPH) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct SimilarityConfig {
    /// Enable CTPH computation and inclusion in TriagedArtifact.similarity
    pub enable_ctph: bool,
    /// CTPH rolling window size
    pub window_size: usize,
    /// CTPH digest size
    pub digest_size: usize,
    /// CTPH precision (8,16,32,64)
    pub precision: u8,
}

impl Default for SimilarityConfig {
    fn default() -> Self {
        Self {
            enable_ctph: true,
            window_size: 8,
            digest_size: 4,
            precision: 8,
        }
    }
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl SimilarityConfig {
    #[new]
    pub fn new() -> Self {
        Self::default()
    }

    #[getter]
    pub fn get_enable_ctph(&self) -> bool {
        self.enable_ctph
    }
    #[setter]
    pub fn set_enable_ctph(&mut self, v: bool) {
        self.enable_ctph = v;
    }

    #[getter]
    pub fn get_window_size(&self) -> usize {
        self.window_size
    }
    #[setter]
    pub fn set_window_size(&mut self, v: usize) {
        self.window_size = v;
    }

    #[getter]
    pub fn get_digest_size(&self) -> usize {
        self.digest_size
    }
    #[setter]
    pub fn set_digest_size(&mut self, v: usize) {
        self.digest_size = v;
    }

    #[getter]
    pub fn get_precision(&self) -> u8 {
        self.precision
    }
    #[setter]
    pub fn set_precision(&mut self, v: u8) {
        self.precision = v;
    }
}

/// I/O configuration for file reading and buffering.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
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

#[cfg(feature = "python-ext")]
#[pymethods]
impl IOConfig {
    #[new]
    pub fn new() -> Self {
        Self::default()
    }

    #[getter]
    pub fn get_max_sniff_size(&self) -> usize {
        self.max_sniff_size
    }

    #[getter]
    pub fn get_max_header_size(&self) -> usize {
        self.max_header_size
    }

    #[getter]
    pub fn get_max_entropy_size(&self) -> usize {
        self.max_entropy_size
    }

    #[getter]
    pub fn get_max_read_bytes(&self) -> usize {
        self.max_read_bytes
    }
    #[getter(max_read_bytes)]
    pub fn p_get_max_read_bytes(&self) -> usize {
        self.max_read_bytes
    }

    #[getter]
    pub fn get_max_file_size(&self) -> u64 {
        self.max_file_size
    }
    #[getter(max_file_size)]
    pub fn p_get_max_file_size(&self) -> u64 {
        self.max_file_size
    }

    #[getter]
    pub fn get_sniff_buffer_size(&self) -> usize {
        self.sniff_buffer_size
    }

    #[setter]
    pub fn set_max_sniff_size(&mut self, size: usize) {
        self.max_sniff_size = size;
    }

    #[setter]
    pub fn set_max_header_size(&mut self, size: usize) {
        self.max_header_size = size;
    }

    #[setter]
    pub fn set_max_entropy_size(&mut self, size: usize) {
        self.max_entropy_size = size;
    }

    #[setter]
    pub fn set_max_read_bytes(&mut self, size: usize) {
        self.max_read_bytes = size;
    }
    #[setter(max_read_bytes)]
    pub fn p_set_max_read_bytes(&mut self, size: usize) {
        self.max_read_bytes = size;
    }

    #[setter]
    pub fn set_max_file_size(&mut self, size: u64) {
        self.max_file_size = size;
    }
    #[setter(max_file_size)]
    pub fn p_set_max_file_size(&mut self, size: u64) {
        self.max_file_size = size;
    }

    #[setter]
    pub fn set_sniff_buffer_size(&mut self, size: usize) {
        self.sniff_buffer_size = size;
    }
}

/// Entropy analysis configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
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

#[cfg(feature = "python-ext")]
#[pymethods]
impl EntropyConfig {
    #[new]
    pub fn new() -> Self {
        Self::default()
    }

    #[getter]
    pub fn get_window_size(&self) -> usize {
        self.window_size
    }

    #[getter]
    pub fn get_step(&self) -> usize {
        self.step
    }

    #[getter]
    pub fn get_max_windows(&self) -> usize {
        self.max_windows
    }

    #[getter]
    pub fn get_overall(&self) -> bool {
        self.overall
    }

    #[getter]
    pub fn get_header_size(&self) -> usize {
        self.header_size
    }

    #[getter]
    pub fn get_thresholds(&self) -> EntropyThresholds {
        self.thresholds.clone()
    }

    #[getter]
    pub fn get_weights(&self) -> EntropyWeights {
        self.weights.clone()
    }

    #[setter]
    pub fn set_window_size(&mut self, size: usize) {
        self.window_size = size;
    }

    #[setter]
    pub fn set_step(&mut self, step: usize) {
        self.step = step;
    }

    #[setter]
    pub fn set_max_windows(&mut self, max: usize) {
        self.max_windows = max;
    }

    #[setter]
    pub fn set_overall(&mut self, overall: bool) {
        self.overall = overall;
    }

    #[setter]
    pub fn set_header_size(&mut self, size: usize) {
        self.header_size = size;
    }

    #[setter]
    pub fn set_thresholds(&mut self, thresholds: EntropyThresholds) {
        self.thresholds = thresholds;
    }

    #[setter]
    pub fn set_weights(&mut self, weights: EntropyWeights) {
        self.weights = weights;
    }
}

/// Entropy classification thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct EntropyThresholds {
    /// Threshold for text classification (< this value).
    pub text: f64,
    /// Threshold for code classification (< this value).
    pub code: f64,
    /// Threshold for compressed classification (< this value).
    pub compressed: f64,
    /// Threshold for encrypted classification (<= this value).
    pub encrypted: f64,
    /// Entropy cliff detection threshold (delta).
    pub cliff_delta: f64,
    /// Low entropy header threshold.
    pub low_header: f64,
    /// High entropy body threshold.
    pub high_body: f64,
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

#[cfg(feature = "python-ext")]
#[pymethods]
impl EntropyThresholds {
    #[new]
    pub fn new() -> Self {
        Self::default()
    }

    #[getter]
    pub fn get_text(&self) -> f64 {
        self.text
    }
    #[getter(text)]
    pub fn p_get_text(&self) -> f64 {
        self.text
    }

    #[getter]
    pub fn get_code(&self) -> f64 {
        self.code
    }
    #[getter(code)]
    pub fn p_get_code(&self) -> f64 {
        self.code
    }

    #[getter]
    pub fn get_compressed(&self) -> f64 {
        self.compressed
    }
    #[getter(compressed)]
    pub fn p_get_compressed(&self) -> f64 {
        self.compressed
    }

    #[getter]
    pub fn get_encrypted(&self) -> f64 {
        self.encrypted
    }
    #[getter(encrypted)]
    pub fn p_get_encrypted(&self) -> f64 {
        self.encrypted
    }

    #[getter]
    pub fn get_cliff_delta(&self) -> f64 {
        self.cliff_delta
    }
    #[getter(cliff_delta)]
    pub fn p_get_cliff_delta(&self) -> f64 {
        self.cliff_delta
    }

    #[getter]
    pub fn get_low_header(&self) -> f64 {
        self.low_header
    }
    #[getter(low_header)]
    pub fn p_get_low_header(&self) -> f64 {
        self.low_header
    }

    #[getter]
    pub fn get_high_body(&self) -> f64 {
        self.high_body
    }
    #[getter(high_body)]
    pub fn p_get_high_body(&self) -> f64 {
        self.high_body
    }

    #[setter]
    pub fn set_text(&mut self, value: f64) {
        self.text = value;
    }
    #[setter(text)]
    pub fn p_set_text(&mut self, value: f64) {
        self.text = value;
    }

    #[setter]
    pub fn set_code(&mut self, value: f64) {
        self.code = value;
    }
    #[setter(code)]
    pub fn p_set_code(&mut self, value: f64) {
        self.code = value;
    }

    #[setter]
    pub fn set_compressed(&mut self, value: f64) {
        self.compressed = value;
    }
    #[setter(compressed)]
    pub fn p_set_compressed(&mut self, value: f64) {
        self.compressed = value;
    }

    #[setter]
    pub fn set_encrypted(&mut self, value: f64) {
        self.encrypted = value;
    }
    #[setter(encrypted)]
    pub fn p_set_encrypted(&mut self, value: f64) {
        self.encrypted = value;
    }

    #[setter]
    pub fn set_cliff_delta(&mut self, value: f64) {
        self.cliff_delta = value;
    }
    #[setter(cliff_delta)]
    pub fn p_set_cliff_delta(&mut self, value: f64) {
        self.cliff_delta = value;
    }

    #[setter]
    pub fn set_low_header(&mut self, value: f64) {
        self.low_header = value;
    }
    #[setter(low_header)]
    pub fn p_set_low_header(&mut self, value: f64) {
        self.low_header = value;
    }

    #[setter]
    pub fn set_high_body(&mut self, value: f64) {
        self.high_body = value;
    }
    #[setter(high_body)]
    pub fn p_set_high_body(&mut self, value: f64) {
        self.high_body = value;
    }
}

/// Entropy scoring weights.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct EntropyWeights {
    /// Weight for low entropy header + high entropy body.
    pub header_body_mismatch: f64,
    /// Weight for entropy cliff detection.
    pub cliff_detected: f64,
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

#[cfg(feature = "python-ext")]
#[pymethods]
impl EntropyWeights {
    #[new]
    pub fn new() -> Self {
        Self::default()
    }

    #[getter]
    pub fn get_header_body_mismatch(&self) -> f64 {
        self.header_body_mismatch
    }

    #[getter]
    pub fn get_cliff_detected(&self) -> f64 {
        self.cliff_detected
    }

    #[getter]
    pub fn get_high_entropy(&self) -> f32 {
        self.high_entropy
    }
    #[getter(high_entropy)]
    pub fn p_get_high_entropy(&self) -> f32 {
        self.high_entropy
    }

    #[getter]
    pub fn get_encrypted_random(&self) -> f32 {
        self.encrypted_random
    }

    #[setter]
    pub fn set_header_body_mismatch(&mut self, value: f64) {
        self.header_body_mismatch = value;
    }

    #[setter]
    pub fn set_cliff_detected(&mut self, value: f64) {
        self.cliff_detected = value;
    }

    #[setter]
    pub fn set_high_entropy(&mut self, value: f32) {
        self.high_entropy = value;
    }
    #[setter(high_entropy)]
    pub fn p_set_high_entropy(&mut self, value: f32) {
        self.high_entropy = value;
    }

    #[setter]
    pub fn set_encrypted_random(&mut self, value: f32) {
        self.encrypted_random = value;
    }
}

/// Heuristics configuration for string extraction and analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
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

#[cfg(feature = "python-ext")]
#[pymethods]
impl HeuristicsConfig {
    #[new]
    pub fn new() -> Self {
        Self::default()
    }

    #[getter]
    pub fn get_min_string_length(&self) -> usize {
        self.min_string_length
    }

    #[getter]
    pub fn get_string_sample_limit(&self) -> usize {
        self.string_sample_limit
    }

    #[getter]
    pub fn get_string_sample_max_len(&self) -> usize {
        self.string_sample_max_len
    }

    #[getter]
    pub fn get_endianness_threshold(&self) -> f32 {
        self.endianness_threshold
    }

    #[getter]
    pub fn get_endianness_weight(&self) -> f32 {
        self.endianness_weight
    }

    #[setter]
    pub fn set_min_string_length(&mut self, length: usize) {
        self.min_string_length = length;
    }

    #[setter]
    pub fn set_string_sample_limit(&mut self, limit: usize) {
        self.string_sample_limit = limit;
    }

    #[setter]
    pub fn set_string_sample_max_len(&mut self, length: usize) {
        self.string_sample_max_len = length;
    }

    #[setter]
    pub fn set_endianness_threshold(&mut self, threshold: f32) {
        self.endianness_threshold = threshold;
    }

    #[setter]
    pub fn set_endianness_weight(&mut self, weight: f32) {
        self.endianness_weight = weight;
    }
}

/// Scoring and confidence configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct ScoringConfig {
    /// Weight for content-based detection (infer).
    pub infer_weight: f64,
    /// Weight for extension-based detection (mime_guess).
    pub mime_weight: f64,
    /// Weight for other detection sources.
    pub other_weight: f64,
    /// Confidence for successful parser.
    pub parser_success_confidence: f64,
    /// Penalty for format inconsistency.
    pub format_consistency_penalty: f64,
    /// Penalty for architecture inconsistency.
    pub arch_consistency_penalty: f64,
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

#[cfg(feature = "python-ext")]
#[pymethods]
impl ScoringConfig {
    #[new]
    pub fn new() -> Self {
        Self::default()
    }

    #[getter]
    pub fn get_infer_weight(&self) -> f64 {
        self.infer_weight
    }

    #[getter]
    pub fn get_mime_weight(&self) -> f64 {
        self.mime_weight
    }

    #[getter]
    pub fn get_other_weight(&self) -> f64 {
        self.other_weight
    }

    #[getter]
    pub fn get_parser_success_confidence(&self) -> f64 {
        self.parser_success_confidence
    }

    #[getter]
    pub fn get_format_consistency_penalty(&self) -> f64 {
        self.format_consistency_penalty
    }

    #[getter]
    pub fn get_arch_consistency_penalty(&self) -> f64 {
        self.arch_consistency_penalty
    }

    #[setter]
    pub fn set_infer_weight(&mut self, weight: f64) {
        self.infer_weight = weight;
    }

    #[setter]
    pub fn set_mime_weight(&mut self, weight: f64) {
        self.mime_weight = weight;
    }

    #[setter]
    pub fn set_other_weight(&mut self, weight: f64) {
        self.other_weight = weight;
    }

    #[setter]
    pub fn set_parser_success_confidence(&mut self, confidence: f64) {
        self.parser_success_confidence = confidence;
    }

    #[setter]
    pub fn set_format_consistency_penalty(&mut self, penalty: f64) {
        self.format_consistency_penalty = penalty;
    }

    #[setter]
    pub fn set_arch_consistency_penalty(&mut self, penalty: f64) {
        self.arch_consistency_penalty = penalty;
    }
}

/// Packer detection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
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

#[cfg(feature = "python-ext")]
#[pymethods]
impl PackerConfig {
    #[new]
    pub fn new() -> Self {
        Self::default()
    }

    #[getter]
    pub fn get_scan_limit(&self) -> usize {
        self.scan_limit
    }

    #[getter]
    pub fn get_upx_detection_weight(&self) -> f32 {
        self.upx_detection_weight
    }

    #[getter]
    pub fn get_upx_version_weight(&self) -> f32 {
        self.upx_version_weight
    }

    #[getter]
    pub fn get_packer_signal_weight(&self) -> f32 {
        self.packer_signal_weight
    }

    #[setter]
    pub fn set_scan_limit(&mut self, limit: usize) {
        self.scan_limit = limit;
    }

    #[setter]
    pub fn set_upx_detection_weight(&mut self, weight: f32) {
        self.upx_detection_weight = weight;
    }

    #[setter]
    pub fn set_upx_version_weight(&mut self, weight: f32) {
        self.upx_version_weight = weight;
    }

    #[setter]
    pub fn set_packer_signal_weight(&mut self, weight: f32) {
        self.packer_signal_weight = weight;
    }
}

/// Header analysis configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
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

#[cfg(feature = "python-ext")]
#[pymethods]
impl HeaderConfig {
    #[new]
    pub fn new() -> Self {
        Self::default()
    }

    #[getter]
    pub fn get_base_confidence(&self) -> f32 {
        self.base_confidence
    }

    #[getter]
    pub fn get_detailed_confidence(&self) -> f32 {
        self.detailed_confidence
    }

    #[setter]
    pub fn set_base_confidence(&mut self, confidence: f32) {
        self.base_confidence = confidence;
    }

    #[setter]
    pub fn set_detailed_confidence(&mut self, confidence: f32) {
        self.detailed_confidence = confidence;
    }
}

/// Parser configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
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

#[cfg(feature = "python-ext")]
#[pymethods]
impl ParserConfig {
    #[new]
    pub fn new() -> Self {
        Self::default()
    }

    #[getter]
    pub fn get_python_bytecode_confidence(&self) -> f32 {
        self.python_bytecode_confidence
    }

    #[setter]
    pub fn set_python_bytecode_confidence(&mut self, confidence: f32) {
        self.python_bytecode_confidence = confidence;
    }
}
