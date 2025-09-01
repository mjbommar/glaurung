//! Triage data types for classifying inputs and recording signals.
//!
//! These types capture sniffer hints (infer/mime_guess), header/signature
//! validation, parser results, confidence breakdown, entropy/strings summaries,
//! packer/container detections, and resource budgets. They are exposed to
//! Python via pyo3 and serialize with serde for persistence.

use crate::core::binary::{Arch, Endianness, Format};
use crate::error::GlaurungError;
#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Source of a sniffer hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass(eq, eq_int))]
pub enum SnifferSource {
    Infer,
    MimeGuess,
    Other,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl SnifferSource {
    fn __str__(&self) -> String {
        match self {
            SnifferSource::Infer => "Infer".to_string(),
            SnifferSource::MimeGuess => "MimeGuess".to_string(),
            SnifferSource::Other => "Other".to_string(),
        }
    }

    fn __repr__(&self) -> String {
        format!("SnifferSource.{}", self.__str__())
    }
}

/// A single sniffer hint derived from content or extension.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct TriageHint {
    pub source: SnifferSource,
    /// MIME type if available (e.g., from `infer`)
    pub mime: Option<String>,
    /// File extension hint if available (e.g., from `mime_guess` or path)
    pub extension: Option<String>,
    /// A coarse label/class (e.g., "zip", "pe", "image/jpeg")
    pub label: Option<String>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl TriageHint {
    #[new]
    #[pyo3(signature = (source, mime=None, extension=None, label=None))]
    pub fn new_py(
        source: SnifferSource,
        mime: Option<String>,
        extension: Option<String>,
        label: Option<String>,
    ) -> Self {
        Self {
            source,
            mime,
            extension,
            label,
        }
    }

    #[staticmethod]
    pub fn create(
        source: SnifferSource,
        mime: Option<String>,
        extension: Option<String>,
        label: Option<String>,
    ) -> Self {
        Self {
            source,
            mime,
            extension,
            label,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "TriageHint(source={:?}, mime={:?}, ext={:?}, label={:?})",
            self.source, self.mime, self.extension, self.label
        )
    }

    // Property getters
    #[getter]
    fn source(&self) -> SnifferSource {
        self.source
    }
    #[getter]
    fn mime(&self) -> Option<String> {
        self.mime.clone()
    }
    #[getter]
    fn extension(&self) -> Option<String> {
        self.extension.clone()
    }
    #[getter]
    fn label(&self) -> Option<String> {
        self.label.clone()
    }
}

/// Standardized error kinds encountered during triage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(feature = "python-ext", pyclass(eq, eq_int))]
pub enum TriageErrorKind {
    ShortRead,
    BadMagic,
    IncoherentFields,
    UnsupportedVariant,
    Truncated,
    BudgetExceeded,
    ParserMismatch,
    SnifferMismatch,
    Other,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl TriageErrorKind {
    fn __str__(&self) -> String {
        use TriageErrorKind::*;
        match self {
            ShortRead => "ShortRead",
            BadMagic => "BadMagic",
            IncoherentFields => "IncoherentFields",
            UnsupportedVariant => "UnsupportedVariant",
            Truncated => "Truncated",
            BudgetExceeded => "BudgetExceeded",
            ParserMismatch => "ParserMismatch",
            SnifferMismatch => "SnifferMismatch",
            Other => "Other",
        }
        .to_string()
    }
    fn __repr__(&self) -> String {
        format!("TriageErrorKind.{}", self.__str__())
    }
}

/// Concrete error with optional message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct TriageError {
    pub kind: TriageErrorKind,
    pub message: Option<String>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl TriageError {
    #[new]
    #[pyo3(signature = (kind, message=None))]
    pub fn new_py(kind: TriageErrorKind, message: Option<String>) -> Self {
        Self { kind, message }
    }
    #[staticmethod]
    pub fn create(kind: TriageErrorKind, message: Option<String>) -> Self {
        Self { kind, message }
    }
    fn __repr__(&self) -> String {
        format!(
            "TriageError(kind={:?}, message={:?})",
            self.kind, self.message
        )
    }
    #[getter]
    fn kind(&self) -> TriageErrorKind {
        self.kind
    }
    #[getter]
    fn message(&self) -> Option<String> {
        self.message.clone()
    }
}

/// A single confidence signal contribution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct ConfidenceSignal {
    /// Human-readable name of the signal, e.g. "header_coherence".
    pub name: String,
    /// Score contribution in [-1.0, 1.0].
    pub score: f32,
    /// Optional note or rationale.
    pub notes: Option<String>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl ConfidenceSignal {
    #[staticmethod]
    pub fn create(name: String, score: f32, notes: Option<String>) -> Self {
        Self { name, score, notes }
    }
}

/// Which structured parser produced a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass(eq, eq_int))]
pub enum ParserKind {
    Object,
    Goblin,
    PELite,
    Nom,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl ParserKind {
    fn __str__(&self) -> String {
        match self {
            ParserKind::Object => "Object",
            ParserKind::Goblin => "Goblin",
            ParserKind::PELite => "PELite",
            ParserKind::Nom => "Nom",
        }
        .to_string()
    }
    fn __repr__(&self) -> String {
        format!("ParserKind.{}", self.__str__())
    }
}

/// Result of attempting to parse with a specific parser.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct ParserResult {
    pub parser: ParserKind,
    pub ok: bool,
    pub error: Option<TriageError>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl ParserResult {
    #[new]
    pub fn new_py(parser: ParserKind, ok: bool, error: Option<TriageError>) -> Self {
        Self { parser, ok, error }
    }
}

/// Entropy summary for an input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct EntropySummary {
    /// Overall Shannon entropy if computed.
    pub overall: Option<f64>,
    /// Window size used for sliding entropy (bytes).
    pub window_size: Option<u32>,
    /// Optional sliding entropy values (order corresponds to sequential windows).
    pub windows: Option<Vec<f64>>,
    /// Optional statistics for window entropies
    pub mean: Option<f64>,
    pub std_dev: Option<f64>,
    pub min: Option<f64>,
    pub max: Option<f64>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl EntropySummary {
    #[new]
    #[pyo3(signature = (overall=None, window_size=None, windows=None))]
    pub fn new_py(
        overall: Option<f64>,
        window_size: Option<u32>,
        windows: Option<Vec<f64>>,
    ) -> Self {
        Self {
            overall,
            window_size,
            windows,
            mean: None,
            std_dev: None,
            min: None,
            max: None,
        }
    }

    #[getter]
    fn overall(&self) -> Option<f64> {
        self.overall
    }
    #[getter]
    fn window_size(&self) -> Option<u32> {
        self.window_size
    }
    #[getter]
    fn windows(&self) -> Option<Vec<f64>> {
        self.windows.clone()
    }
    #[getter]
    fn mean(&self) -> Option<f64> {
        self.mean
    }
    #[getter]
    fn std_dev(&self) -> Option<f64> {
        self.std_dev
    }
    #[getter]
    fn min(&self) -> Option<f64> {
        self.min
    }
    #[getter]
    fn max(&self) -> Option<f64> {
        self.max
    }
}

/// Entropy classification bucket with associated measured value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub enum EntropyClass {
    Text(f32),
    Code(f32),
    Compressed(f32),
    Encrypted(f32),
    Random(f32),
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl EntropyClass {
    #[getter]
    pub fn value(&self) -> f32 {
        match self {
            EntropyClass::Text(v)
            | EntropyClass::Code(v)
            | EntropyClass::Compressed(v)
            | EntropyClass::Encrypted(v)
            | EntropyClass::Random(v) => *v,
        }
    }
}

/// Sudden entropy jump info.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct EntropyAnomaly {
    pub index: usize,
    pub from: f64,
    pub to: f64,
    pub delta: f64,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl EntropyAnomaly {
    #[getter]
    fn index(&self) -> usize {
        self.index
    }

    // Rename 'from' to 'from_value' to avoid Python keyword conflict
    #[getter(from_value)]
    fn get_from(&self) -> f64 {
        self.from
    }

    // Also provide 'to_value' for consistency
    #[getter(to_value)]
    fn get_to(&self) -> f64 {
        self.to
    }

    // Keep 'to' as well for backward compatibility
    #[getter]
    fn to(&self) -> f64 {
        self.to
    }

    #[getter]
    fn delta(&self) -> f64 {
        self.delta
    }

    fn __repr__(&self) -> String {
        format!(
            "EntropyAnomaly(index={}, from_value={:.2}, to_value={:.2}, delta={:.2})",
            self.index, self.from, self.to, self.delta
        )
    }
}

/// Heuristics to detect packing/compression patterns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct PackedIndicators {
    pub has_low_entropy_header: bool,
    pub has_high_entropy_body: bool,
    pub entropy_cliff: Option<usize>,
    pub verdict: f32,
}

/// Full entropy analysis record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct EntropyAnalysis {
    pub summary: EntropySummary,
    pub classification: EntropyClass,
    pub packed_indicators: PackedIndicators,
    pub anomalies: Vec<EntropyAnomaly>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl EntropyAnalysis {
    #[getter]
    fn classification_kind(&self) -> String {
        match self.classification {
            EntropyClass::Text(_) => "Text",
            EntropyClass::Code(_) => "Code",
            EntropyClass::Compressed(_) => "Compressed",
            EntropyClass::Encrypted(_) => "Encrypted",
            EntropyClass::Random(_) => "Random",
        }
        .to_string()
    }
    #[getter]
    fn summary(&self) -> EntropySummary {
        self.summary.clone()
    }
    #[getter]
    fn packed_indicators(&self) -> PackedIndicators {
        self.packed_indicators.clone()
    }
    #[getter]
    fn anomalies(&self) -> Vec<EntropyAnomaly> {
        self.anomalies.clone()
    }
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl PackedIndicators {
    #[getter]
    fn has_low_entropy_header(&self) -> bool {
        self.has_low_entropy_header
    }
    #[getter]
    fn has_high_entropy_body(&self) -> bool {
        self.has_high_entropy_body
    }
    #[getter]
    fn verdict(&self) -> f32 {
        self.verdict
    }
    #[getter]
    fn entropy_cliff(&self) -> Option<usize> {
        self.entropy_cliff
    }
}

/// A detected string with language information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct DetectedString {
    /// The extracted string text
    pub text: String,
    /// The encoding (ascii, utf16le, utf16be)
    pub encoding: String,
    /// The detected language (ISO 639-3 code), if detected
    pub language: Option<String>,
    /// The writing script (e.g., Latin, Cyrillic, Arabic), if detected
    pub script: Option<String>,
    /// Language detection confidence score (0.0 to 1.0)
    pub confidence: Option<f64>,
    /// Offset in the binary where string was found
    pub offset: Option<u64>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl DetectedString {
    #[new]
    #[pyo3(signature = (text, encoding, language=None, script=None, confidence=None, offset=None))]
    pub fn new_py(
        text: String,
        encoding: String,
        language: Option<String>,
        script: Option<String>,
        confidence: Option<f64>,
        offset: Option<u64>,
    ) -> Self {
        Self {
            text,
            encoding,
            language,
            script,
            confidence,
            offset,
        }
    }

    #[getter]
    fn text(&self) -> &str {
        &self.text
    }

    #[getter]
    fn encoding(&self) -> &str {
        &self.encoding
    }

    #[getter]
    fn language(&self) -> Option<String> {
        self.language.clone()
    }

    #[getter]
    fn script(&self) -> Option<String> {
        self.script.clone()
    }

    #[getter]
    fn confidence(&self) -> Option<f64> {
        self.confidence
    }

    #[getter]
    fn offset(&self) -> Option<u64> {
        self.offset
    }

    fn __str__(&self) -> String {
        match (&self.language, &self.script, self.confidence) {
            (Some(lang), Some(script), Some(conf)) => {
                format!(
                    "DetectedString({:?} [{}] {} {} conf={:.2})",
                    self.text.chars().take(30).collect::<String>(),
                    self.encoding,
                    lang,
                    script,
                    conf
                )
            }
            _ => {
                format!(
                    "DetectedString({:?} [{}])",
                    self.text.chars().take(30).collect::<String>(),
                    self.encoding
                )
            }
        }
    }

    fn __repr__(&self) -> String {
        self.__str__()
    }
}

/// Strings summary at triage time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct StringsSummary {
    pub ascii_count: u32,
    pub utf16le_count: u32,
    pub utf16be_count: u32,
    /// Detected strings with language information
    pub strings: Option<Vec<DetectedString>>,
    /// Summary of detected languages and their counts
    pub language_counts: Option<std::collections::HashMap<String, u32>>,
    /// Summary of detected scripts and their counts
    pub script_counts: Option<std::collections::HashMap<String, u32>>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl StringsSummary {
    #[new]
    #[pyo3(signature = (ascii_count, utf16le_count, utf16be_count, strings=None, language_counts=None, script_counts=None))]
    pub fn new_py(
        ascii_count: u32,
        utf16le_count: u32,
        utf16be_count: u32,
        strings: Option<Vec<DetectedString>>,
        language_counts: Option<std::collections::HashMap<String, u32>>,
        script_counts: Option<std::collections::HashMap<String, u32>>,
    ) -> Self {
        Self {
            ascii_count,
            utf16le_count,
            utf16be_count,
            strings,
            language_counts,
            script_counts,
        }
    }

    #[getter]
    fn ascii_count(&self) -> u32 {
        self.ascii_count
    }

    #[getter]
    fn utf16le_count(&self) -> u32 {
        self.utf16le_count
    }

    #[getter]
    fn utf16be_count(&self) -> u32 {
        self.utf16be_count
    }

    #[getter]
    fn strings(&self) -> Option<Vec<DetectedString>> {
        self.strings.clone()
    }

    #[getter]
    fn language_counts(&self) -> Option<std::collections::HashMap<String, u32>> {
        self.language_counts.clone()
    }

    #[getter]
    fn script_counts(&self) -> Option<std::collections::HashMap<String, u32>> {
        self.script_counts.clone()
    }

    // For backward compatibility
    #[getter]
    fn samples(&self) -> Option<Vec<String>> {
        self.strings
            .as_ref()
            .map(|strings| strings.iter().take(10).map(|s| s.text.clone()).collect())
    }
}

impl fmt::Display for SnifferSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnifferSource::Infer => write!(f, "Infer"),
            SnifferSource::MimeGuess => write!(f, "MimeGuess"),
            SnifferSource::Other => write!(f, "Other"),
        }
    }
}

impl fmt::Display for TriageErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TriageErrorKind::*;
        match self {
            ShortRead => write!(f, "ShortRead"),
            BadMagic => write!(f, "BadMagic"),
            IncoherentFields => write!(f, "IncoherentFields"),
            UnsupportedVariant => write!(f, "UnsupportedVariant"),
            Truncated => write!(f, "Truncated"),
            BudgetExceeded => write!(f, "BudgetExceeded"),
            ParserMismatch => write!(f, "ParserMismatch"),
            SnifferMismatch => write!(f, "SnifferMismatch"),
            Other => write!(f, "Other"),
        }
    }
}

impl fmt::Display for ParserKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParserKind::Object => write!(f, "Object"),
            ParserKind::Goblin => write!(f, "Goblin"),
            ParserKind::PELite => write!(f, "PELite"),
            ParserKind::Nom => write!(f, "Nom"),
        }
    }
}

/// Packer detection entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct PackerMatch {
    pub name: String,
    pub confidence: f32,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl PackerMatch {
    #[new]
    pub fn new_py(name: String, confidence: f32) -> Self {
        Self { name, confidence }
    }
    #[getter]
    fn name(&self) -> String {
        self.name.clone()
    }
    #[getter]
    fn confidence(&self) -> f32 {
        self.confidence
    }
}

/// Child artifact discovered within a container or overlay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct ContainerChild {
    pub type_name: String,
    pub offset: u64,
    pub size: u64,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl ContainerChild {
    #[new]
    pub fn new_py(type_name: String, offset: u64, size: u64) -> Self {
        Self {
            type_name,
            offset,
            size,
        }
    }
    #[getter]
    fn type_name(&self) -> String {
        self.type_name.clone()
    }
}

/// Resource usage and safety budgets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct Budgets {
    pub bytes_read: u64,
    pub time_ms: u64,
    pub recursion_depth: u32,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl Budgets {
    #[new]
    pub fn new_py(bytes_read: u64, time_ms: u64, recursion_depth: u32) -> Self {
        Self {
            bytes_read,
            time_ms,
            recursion_depth,
        }
    }
}

/// A single classification hypothesis with confidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct TriageVerdict {
    pub format: Format,
    pub arch: Arch,
    pub bits: u8,
    pub endianness: Endianness,
    pub confidence: f32,
    /// Optional per-signal breakdown.
    pub signals: Option<Vec<ConfidenceSignal>>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl TriageVerdict {
    #[new]
    #[pyo3(signature = (format, arch, bits, endianness, confidence, signals=None))]
    pub fn new(
        format: Format,
        arch: Arch,
        bits: u8,
        endianness: Endianness,
        confidence: f32,
        signals: Option<Vec<ConfidenceSignal>>,
    ) -> PyResult<Self> {
        Self::try_new(format, arch, bits, endianness, confidence, signals)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    // Property getters
    #[getter]
    fn format(&self) -> Format {
        self.format
    }
    #[getter]
    fn arch(&self) -> Arch {
        self.arch
    }
    #[getter]
    fn bits(&self) -> u8 {
        self.bits
    }
    #[getter]
    fn endianness(&self) -> Endianness {
        self.endianness
    }
    #[getter]
    fn confidence(&self) -> f32 {
        self.confidence
    }
}

// Pure Rust constructors and helpers
impl TriageHint {
    pub fn new(
        source: SnifferSource,
        mime: Option<String>,
        extension: Option<String>,
        label: Option<String>,
    ) -> Self {
        Self {
            source,
            mime,
            extension,
            label,
        }
    }
}

impl TriageError {
    pub fn new(kind: TriageErrorKind, message: Option<String>) -> Self {
        Self { kind, message }
    }
}

impl ConfidenceSignal {
    pub fn new(name: String, score: f32, notes: Option<String>) -> Self {
        Self { name, score, notes }
    }
}

impl ParserResult {
    pub fn new(parser: ParserKind, ok: bool, error: Option<TriageError>) -> Self {
        Self { parser, ok, error }
    }
}

impl EntropySummary {
    pub fn new(overall: Option<f64>, window_size: Option<u32>, windows: Option<Vec<f64>>) -> Self {
        Self {
            overall,
            window_size,
            windows,
            mean: None,
            std_dev: None,
            min: None,
            max: None,
        }
    }
}

impl DetectedString {
    pub fn new(
        text: String,
        encoding: String,
        language: Option<String>,
        script: Option<String>,
        confidence: Option<f64>,
        offset: Option<u64>,
    ) -> Self {
        Self {
            text,
            encoding,
            language,
            script,
            confidence,
            offset,
        }
    }
}

impl StringsSummary {
    pub fn new(
        ascii_count: u32,
        utf16le_count: u32,
        utf16be_count: u32,
        strings: Option<Vec<DetectedString>>,
        language_counts: Option<std::collections::HashMap<String, u32>>,
        script_counts: Option<std::collections::HashMap<String, u32>>,
    ) -> Self {
        Self {
            ascii_count,
            utf16le_count,
            utf16be_count,
            strings,
            language_counts,
            script_counts,
        }
    }

    /// Create from old-style samples for backward compatibility
    pub fn from_samples(
        ascii_count: u32,
        utf16le_count: u32,
        utf16be_count: u32,
        samples: Option<Vec<String>>,
    ) -> Self {
        let strings = samples.map(|s| {
            s.into_iter()
                .map(|text| DetectedString::new(text, "ascii".to_string(), None, None, None, None))
                .collect()
        });

        Self {
            ascii_count,
            utf16le_count,
            utf16be_count,
            strings,
            language_counts: None,
            script_counts: None,
        }
    }
}

impl PackerMatch {
    pub fn new(name: String, confidence: f32) -> Self {
        Self { name, confidence }
    }
}

impl ContainerChild {
    pub fn new(type_name: String, offset: u64, size: u64) -> Self {
        Self {
            type_name,
            offset,
            size,
        }
    }
}

impl Budgets {
    pub fn new(bytes_read: u64, time_ms: u64, recursion_depth: u32) -> Self {
        Self {
            bytes_read,
            time_ms,
            recursion_depth,
        }
    }
}

impl TriageVerdict {
    /// Create a new TriageVerdict instance (pure Rust version).
    pub fn try_new(
        format: Format,
        arch: Arch,
        bits: u8,
        endianness: Endianness,
        confidence: f32,
        signals: Option<Vec<ConfidenceSignal>>,
    ) -> Result<Self, GlaurungError> {
        if bits != 32 && bits != 64 {
            return Err(GlaurungError::InvalidInput(format!(
                "bits must be 32 or 64, got {}",
                bits
            )));
        }
        Ok(Self {
            format,
            arch,
            bits,
            endianness,
            confidence,
            signals,
        })
    }

    /// Serialize to JSON string (pure Rust version).
    pub fn to_json_string(&self) -> Result<String, GlaurungError> {
        serde_json::to_string(self)
            .map_err(|e| GlaurungError::Serialization(format!("JSON serialization error: {}", e)))
    }

    /// Deserialize from JSON string (pure Rust version).
    pub fn from_json_str(json_str: &str) -> Result<Self, GlaurungError> {
        serde_json::from_str(json_str)
            .map_err(|e| GlaurungError::Serialization(format!("JSON deserialization error: {}", e)))
    }
}

impl TriagedArtifact {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        path: String,
        size_bytes: u64,
        sha256: Option<String>,
        hints: Vec<TriageHint>,
        verdicts: Vec<TriageVerdict>,
        entropy: Option<EntropySummary>,
        entropy_analysis: Option<EntropyAnalysis>,
        strings: Option<StringsSummary>,
        packers: Option<Vec<PackerMatch>>,
        containers: Option<Vec<ContainerChild>>,
        parse_status: Option<Vec<ParserResult>>,
        budgets: Option<Budgets>,
        errors: Option<Vec<TriageError>>,
    ) -> Self {
        Self {
            id,
            path,
            size_bytes,
            sha256,
            hints,
            verdicts,
            entropy,
            entropy_analysis,
            strings,
            packers,
            containers,
            parse_status,
            budgets,
            errors,
        }
    }

    pub fn to_json_string(&self) -> Result<String, GlaurungError> {
        serde_json::to_string(self)
            .map_err(|e| GlaurungError::Serialization(format!("JSON serialization error: {}", e)))
    }

    pub fn from_json_str(json_str: &str) -> Result<Self, GlaurungError> {
        serde_json::from_str(json_str)
            .map_err(|e| GlaurungError::Serialization(format!("JSON deserialization error: {}", e)))
    }
}

/// Overall triage report for an input artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct TriagedArtifact {
    /// Identity
    pub id: String,
    pub path: String,
    pub size_bytes: u64,
    pub sha256: Option<String>,

    /// Signals and hints
    pub hints: Vec<TriageHint>,
    pub verdicts: Vec<TriageVerdict>,

    /// Summaries
    pub entropy: Option<EntropySummary>,
    pub entropy_analysis: Option<EntropyAnalysis>,
    pub strings: Option<StringsSummary>,
    pub packers: Option<Vec<PackerMatch>>,
    pub containers: Option<Vec<ContainerChild>>,

    /// Parser outcomes and budgets
    pub parse_status: Option<Vec<ParserResult>>,
    pub budgets: Option<Budgets>,
    pub errors: Option<Vec<TriageError>>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl TriagedArtifact {
    #[allow(clippy::too_many_arguments)]
    #[new]
    #[pyo3(signature = (
        id,
        path,
        size_bytes,
        sha256=None,
        hints=Vec::new(),
        verdicts=Vec::new(),
        entropy=None,
        entropy_analysis=None,
        strings=None,
        packers=None,
        containers=None,
        parse_status=None,
        budgets=None,
        errors=None
    ))]
    pub fn new_py(
        id: String,
        path: String,
        size_bytes: u64,
        sha256: Option<String>,
        hints: Vec<TriageHint>,
        verdicts: Vec<TriageVerdict>,
        entropy: Option<EntropySummary>,
        entropy_analysis: Option<EntropyAnalysis>,
        strings: Option<StringsSummary>,
        packers: Option<Vec<PackerMatch>>,
        containers: Option<Vec<ContainerChild>>,
        parse_status: Option<Vec<ParserResult>>,
        budgets: Option<Budgets>,
        errors: Option<Vec<TriageError>>,
    ) -> Self {
        Self {
            id,
            path,
            size_bytes,
            sha256,
            hints,
            verdicts,
            entropy,
            entropy_analysis,
            strings,
            packers,
            containers,
            parse_status,
            budgets,
            errors,
        }
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(self).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Serialization error: {}", e))
        })
    }

    /// Deserialize from JSON string.
    #[staticmethod]
    pub fn from_json(json_str: &str) -> PyResult<Self> {
        serde_json::from_str(json_str).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Deserialization error: {}", e))
        })
    }

    // Property getters
    #[getter]
    fn id(&self) -> &str {
        &self.id
    }
    #[getter]
    fn path(&self) -> &str {
        &self.path
    }
    #[getter]
    fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
    #[getter]
    fn sha256(&self) -> Option<String> {
        self.sha256.clone()
    }
    #[getter]
    fn hints(&self) -> Vec<TriageHint> {
        self.hints.clone()
    }
    #[getter]
    fn verdicts(&self) -> Vec<TriageVerdict> {
        self.verdicts.clone()
    }
    #[getter]
    fn entropy(&self) -> Option<EntropySummary> {
        self.entropy.clone()
    }
    #[getter]
    fn entropy_analysis(&self) -> Option<EntropyAnalysis> {
        self.entropy_analysis.clone()
    }
    #[getter]
    fn strings(&self) -> Option<StringsSummary> {
        self.strings.clone()
    }
    #[getter]
    fn packers(&self) -> Option<Vec<PackerMatch>> {
        self.packers.clone()
    }
    #[getter]
    fn containers(&self) -> Option<Vec<ContainerChild>> {
        self.containers.clone()
    }
    #[getter]
    fn parse_status(&self) -> Option<Vec<ParserResult>> {
        self.parse_status.clone()
    }
    #[getter]
    fn budgets(&self) -> Option<Budgets> {
        self.budgets.clone()
    }
    #[getter]
    fn errors(&self) -> Option<Vec<TriageError>> {
        self.errors.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_json() {
        let hint = TriageHint::new(
            SnifferSource::Infer,
            Some("application/zip".into()),
            None,
            Some("zip".into()),
        );
        let verdict = TriageVerdict::try_new(
            Format::ELF,
            Arch::X86_64,
            64,
            Endianness::Little,
            0.92,
            None,
        )
        .unwrap();
        let artifact = TriagedArtifact::new(
            "id-1".into(),
            "/tmp/a".into(),
            123,
            Some("a".repeat(64)),
            vec![hint],
            vec![verdict],
            Some(EntropySummary::new(Some(7.9), Some(4096), None)),
            None,
            Some(StringsSummary::from_samples(
                3,
                0,
                0,
                Some(vec!["hello".into()]),
            )),
            None,
            None,
            Some(vec![ParserResult::new(ParserKind::Object, true, None)]),
            Some(Budgets::new(8192, 10, 0)),
            None,
        );
        let json = artifact.to_json_string().unwrap();
        let back = TriagedArtifact::from_json_str(&json).unwrap();
        assert_eq!(artifact, back);
    }

    #[test]
    fn enums_and_repr() {
        assert_eq!(format!("{}", SnifferSource::Infer), "Infer");
        assert_eq!(format!("{}", TriageErrorKind::BadMagic), "BadMagic");
        assert_eq!(format!("{}", ParserKind::Goblin), "Goblin");
        let hint = TriageHint::new(SnifferSource::MimeGuess, None, Some("exe".into()), None);
        let _s = format!("{:?}", hint);
    }

    #[test]
    fn verdict_bits_validation() {
        // Invalid bits should error
        let bad = TriageVerdict::try_new(Format::PE, Arch::X86, 16, Endianness::Little, 0.1, None);
        assert!(bad.is_err());
        // Valid bits 32/64 ok
        let ok = TriageVerdict::try_new(Format::PE, Arch::X86, 32, Endianness::Little, 0.5, None);
        assert!(ok.is_ok());
    }

    #[test]
    fn parser_result_and_budgets() {
        let err = TriageError::new(TriageErrorKind::ParserMismatch, Some("unexpected".into()));
        let pr = ParserResult::new(ParserKind::PELite, false, Some(err));
        assert!(!pr.ok);
        let b = Budgets::new(4096, 25, 1);
        assert_eq!(b.bytes_read, 4096);
    }

    #[test]
    fn summaries_and_matches() {
        let e = EntropySummary::new(Some(7.8), Some(4096), Some(vec![7.0, 7.5]));
        assert_eq!(e.window_size, Some(4096));
        let s = StringsSummary::from_samples(10, 2, 1, Some(vec!["a".into()]));
        assert_eq!(s.ascii_count, 10);
        let pm = PackerMatch::new("UPX".into(), 0.9);
        assert_eq!(pm.name, "UPX");
        let ch = ContainerChild::new("zip".into(), 0, 100);
        assert_eq!(ch.size, 100);
    }
}
