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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        }
    }
}

/// Strings summary at triage time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct StringsSummary {
    pub ascii_count: u32,
    pub utf16le_count: u32,
    pub utf16be_count: u32,
    /// Optional top-N sample strings (truncated/sanitized).
    pub samples: Option<Vec<String>>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl StringsSummary {
    #[new]
    #[pyo3(signature = (ascii_count, utf16le_count, utf16be_count, samples=None))]
    pub fn new_py(
        ascii_count: u32,
        utf16le_count: u32,
        utf16be_count: u32,
        samples: Option<Vec<String>>,
    ) -> Self {
        Self {
            ascii_count,
            utf16le_count,
            utf16be_count,
            samples,
        }
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
        }
    }
}

impl StringsSummary {
    pub fn new(
        ascii_count: u32,
        utf16le_count: u32,
        utf16be_count: u32,
        samples: Option<Vec<String>>,
    ) -> Self {
        Self {
            ascii_count,
            utf16le_count,
            utf16be_count,
            samples,
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
            Some(StringsSummary::new(3, 0, 0, Some(vec!["hello".into()]))),
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
        let s = StringsSummary::new(10, 2, 1, Some(vec!["a".into()]));
        assert_eq!(s.ascii_count, 10);
        let pm = PackerMatch::new("UPX".into(), 0.9);
        assert_eq!(pm.name, "UPX");
        let ch = ContainerChild::new("zip".into(), 0, 100);
        assert_eq!(ch.size, 100);
    }
}
