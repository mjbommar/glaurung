//! Verdict and artifact types for triage results.

use super::containers::ContainerChild;
use super::entropy::{EntropyAnalysis, EntropySummary};
use super::errors::TriageError;
use super::hints::{ConfidenceSignal, TriageHint};
use super::packers::PackerMatch;
use super::parsers::ParserResult;
use super::strings::StringsSummary;
use crate::core::binary::{Arch, Endianness, Format};
use crate::core::triage::formats::FormatSpecificTriage;
use crate::error::GlaurungError;
use crate::symbols::SymbolSummary;
#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

/// Similarity summary (fuzzy and import-based hashes)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct SimilaritySummary {
    /// PE import hash (if applicable)
    pub imphash: Option<String>,
    /// Context-Triggered Piecewise Hashing digest
    pub ctph: Option<String>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl SimilaritySummary {
    #[new]
    pub fn new(imphash: Option<String>, ctph: Option<String>) -> Self {
        Self { imphash, ctph }
    }

    #[getter]
    pub fn get_imphash(&self) -> Option<String> {
        self.imphash.clone()
    }
    #[getter]
    pub fn get_ctph(&self) -> Option<String> {
        self.ctph.clone()
    }
}

/// Resource usage and safety budgets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct Budgets {
    /// Total bytes read across triage phases
    pub bytes_read: u64,
    /// Elapsed time in milliseconds for analysis
    pub time_ms: u64,
    /// Observed recursion depth used
    pub recursion_depth: u32,
    /// Byte ceiling configured for analysis (if known)
    pub limit_bytes: Option<u64>,
    /// Time ceiling configured in milliseconds (if known)
    pub limit_time_ms: Option<u64>,
    /// Recursion depth ceiling configured (if known)
    pub max_recursion_depth: Option<u32>,
    /// Whether any read hit the byte limit ceiling
    pub hit_byte_limit: bool,
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
            limit_bytes: None,
            limit_time_ms: None,
            max_recursion_depth: None,
            hit_byte_limit: false,
        }
    }

    #[getter]
    fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    #[getter]
    fn time_ms(&self) -> u64 {
        self.time_ms
    }

    #[getter]
    fn recursion_depth(&self) -> u32 {
        self.recursion_depth
    }

    #[getter]
    fn limit_bytes(&self) -> Option<u64> {
        self.limit_bytes
    }

    #[getter]
    fn limit_time_ms(&self) -> Option<u64> {
        self.limit_time_ms
    }

    #[getter]
    fn max_recursion_depth(&self) -> Option<u32> {
        self.max_recursion_depth
    }

    #[getter]
    fn hit_byte_limit(&self) -> bool {
        self.hit_byte_limit
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

/// Overall triage report for an input artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct TriagedArtifact {
    /// Output schema version for stability tracking
    pub schema_version: String,
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
    /// Optional symbols summary for the artifact
    pub symbols: Option<SymbolSummary>,
    /// Similarity summary (imphash/ctph)
    pub similarity: Option<SimilaritySummary>,
    /// Signing summary (presence bits)
    pub signing: Option<crate::triage::signing::SigningSummary>,
    pub packers: Option<Vec<PackerMatch>>,
    /// Immediate children (container/embedded) discovered
    pub containers: Option<Vec<ContainerChild>>,
    /// Rollup stats for recursion/children
    pub recursion_summary: Option<crate::triage::recurse::RecursionSummary>,
    /// Optional overlay analysis (data appended after official end of binary)
    pub overlay: Option<crate::triage::overlay::OverlayAnalysis>,
    /// Format-specific triage information.
    pub format_specific: Option<FormatSpecificTriage>,

    /// Parser outcomes and budgets
    pub parse_status: Option<Vec<ParserResult>>,
    pub budgets: Option<Budgets>,
    pub errors: Option<Vec<TriageError>>,
    /// Heuristic guesses (for scoring)
    pub heuristic_endianness: Option<(Endianness, f32)>,
    pub heuristic_arch: Option<Vec<(Arch, f32)>>,
    /// Optional bounded disassembly preview (rendered lines)
    pub disasm_preview: Option<Vec<String>>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl TriagedArtifact {
    #[allow(clippy::too_many_arguments)]
    #[new]
    #[pyo3(signature = (
        schema_version,
        id,
        path,
        size_bytes,
        sha256=None,
        hints=Vec::new(),
        verdicts=Vec::new(),
        entropy=None,
        entropy_analysis=None,
        strings=None,
        symbols=None,
        similarity=None,
        signing=None,
        packers=None,
        containers=None,
        recursion_summary=None,
        overlay=None,
        format_specific=None,
        parse_status=None,
        budgets=None,
        errors=None,
        heuristic_endianness=None,
        heuristic_arch=None,
        disasm_preview=None
    ))]
    pub fn new_py(
        schema_version: String,
        id: String,
        path: String,
        size_bytes: u64,
        sha256: Option<String>,
        hints: Vec<TriageHint>,
        verdicts: Vec<TriageVerdict>,
        entropy: Option<EntropySummary>,
        entropy_analysis: Option<EntropyAnalysis>,
        strings: Option<StringsSummary>,
        symbols: Option<SymbolSummary>,
        similarity: Option<SimilaritySummary>,
        signing: Option<crate::triage::signing::SigningSummary>,
        packers: Option<Vec<PackerMatch>>,
        containers: Option<Vec<ContainerChild>>,
        recursion_summary: Option<crate::triage::recurse::RecursionSummary>,
        overlay: Option<crate::triage::overlay::OverlayAnalysis>,
        format_specific: Option<FormatSpecificTriage>,
        parse_status: Option<Vec<ParserResult>>,
        budgets: Option<Budgets>,
        errors: Option<Vec<TriageError>>,
        heuristic_endianness: Option<(Endianness, f32)>,
        heuristic_arch: Option<Vec<(Arch, f32)>>,
        disasm_preview: Option<Vec<String>>,
    ) -> Self {
        Self {
            schema_version,
            id,
            path,
            size_bytes,
            sha256,
            hints,
            verdicts,
            entropy,
            entropy_analysis,
            strings,
            symbols,
            similarity,
            signing,
            packers,
            containers,
            recursion_summary,
            overlay,
            format_specific,
            parse_status,
            budgets,
            errors,
            heuristic_endianness,
            heuristic_arch,
            disasm_preview,
        }
    }

    /// Compute CTPH-based similarity against another artifact, if both
    /// contain a CTPH digest. Returns None if missing.
    pub fn ctph_similarity(&self, other: &TriagedArtifact) -> Option<f64> {
        let a = self.similarity.as_ref().and_then(|s| s.ctph.as_ref())?;
        let b = other.similarity.as_ref().and_then(|s| s.ctph.as_ref())?;
        Some(crate::similarity::ctph_similarity(a, b))
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
    fn schema_version(&self) -> &str {
        &self.schema_version
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
    fn symbols(&self) -> Option<SymbolSummary> {
        self.symbols.clone()
    }
    #[getter]
    fn similarity(&self) -> Option<SimilaritySummary> {
        self.similarity.clone()
    }
    #[getter]
    fn signing(&self) -> Option<crate::triage::signing::SigningSummary> {
        self.signing.clone()
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
    fn recursion_summary(&self) -> Option<crate::triage::recurse::RecursionSummary> {
        self.recursion_summary.clone()
    }
    #[getter]
    fn overlay(&self) -> Option<crate::triage::overlay::OverlayAnalysis> {
        self.overlay.clone()
    }
    #[getter]
    fn format_specific(&self) -> Option<FormatSpecificTriage> {
        self.format_specific.clone()
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
    #[getter]
    fn heuristic_endianness(&self) -> Option<(Endianness, f32)> {
        self.heuristic_endianness
    }
    #[getter]
    fn heuristic_arch(&self) -> Option<Vec<(Arch, f32)>> {
        self.heuristic_arch.clone()
    }
}

// Pure Rust constructors and helpers
impl Budgets {
    pub fn new(bytes_read: u64, time_ms: u64, recursion_depth: u32) -> Self {
        Self {
            bytes_read,
            time_ms,
            recursion_depth,
            limit_bytes: None,
            limit_time_ms: None,
            max_recursion_depth: None,
            hit_byte_limit: false,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_pattern_basic() {
        let artifact = TriagedArtifact::builder()
            .with_id("test-id")
            .with_path("/path/to/file")
            .with_size_bytes(1024)
            .build()
            .expect("Build should succeed");

        assert_eq!(artifact.id, "test-id");
        assert_eq!(artifact.path, "/path/to/file");
        assert_eq!(artifact.size_bytes, 1024);
        assert!(artifact.sha256.is_none());
        assert!(artifact.hints.is_empty());
        assert!(artifact.verdicts.is_empty());
    }

    #[test]
    fn test_builder_pattern_with_optional_fields() {
        let artifact = TriagedArtifact::builder()
            .with_id("test-id")
            .with_path("/path/to/file")
            .with_size_bytes(1024)
            .with_sha256(Some("abc123".to_string()))
            .with_hints(vec![])
            .with_verdicts(vec![])
            .build()
            .expect("Build should succeed");

        assert_eq!(artifact.id, "test-id");
        assert_eq!(artifact.path, "/path/to/file");
        assert_eq!(artifact.size_bytes, 1024);
        assert_eq!(artifact.sha256, Some("abc123".to_string()));
        assert!(artifact.hints.is_empty());
        assert!(artifact.verdicts.is_empty());
    }

    #[test]
    fn test_builder_pattern_missing_required_fields() {
        let result = TriagedArtifact::builder()
            .with_id("test-id")
            // Missing path and size_bytes
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("path is required"));
    }

    #[test]
    fn test_builder_pattern_with_sha256_str() {
        let artifact = TriagedArtifact::builder()
            .with_id("test-id")
            .with_path("/path/to/file")
            .with_size_bytes(1024)
            .with_sha256_str("def456")
            .build()
            .expect("Build should succeed");

        assert_eq!(artifact.sha256, Some("def456".to_string()));
    }
}

/// Builder for constructing TriagedArtifact instances with a more ergonomic API.
#[derive(Debug, Default)]
pub struct TriagedArtifactBuilder {
    id: Option<String>,
    path: Option<String>,
    size_bytes: Option<u64>,
    sha256: Option<String>,
    schema_version: Option<String>,
    hints: Option<Vec<TriageHint>>,
    verdicts: Option<Vec<TriageVerdict>>,
    entropy: Option<EntropySummary>,
    entropy_analysis: Option<EntropyAnalysis>,
    strings: Option<StringsSummary>,
    symbols: Option<SymbolSummary>,
    similarity: Option<SimilaritySummary>,
    signing: Option<crate::triage::signing::SigningSummary>,
    packers: Option<Vec<PackerMatch>>,
    containers: Option<Vec<ContainerChild>>,
    recursion_summary: Option<crate::triage::recurse::RecursionSummary>,
    overlay: Option<crate::triage::overlay::OverlayAnalysis>,
    format_specific: Option<FormatSpecificTriage>,
    parse_status: Option<Vec<ParserResult>>,
    budgets: Option<Budgets>,
    errors: Option<Vec<TriageError>>,
    heuristic_endianness: Option<(Endianness, f32)>,
    heuristic_arch: Option<Vec<(Arch, f32)>>,
    disasm_preview: Option<Vec<String>>,
}

impl TriagedArtifactBuilder {
    /// Creates a new builder instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the artifact ID.
    pub fn with_id<S: Into<String>>(mut self, id: S) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Sets the file path.
    pub fn with_path<S: Into<String>>(mut self, path: S) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Sets the schema version string.
    pub fn with_schema_version<S: Into<String>>(mut self, schema_version: S) -> Self {
        self.schema_version = Some(schema_version.into());
        self
    }

    /// Sets the size in bytes.
    pub fn with_size_bytes(mut self, size_bytes: u64) -> Self {
        self.size_bytes = Some(size_bytes);
        self
    }

    /// Sets the SHA256 hash.
    pub fn with_sha256(mut self, sha256: Option<String>) -> Self {
        self.sha256 = sha256;
        self
    }

    /// Sets the SHA256 hash from a string-like type.
    pub fn with_sha256_str<S: Into<String>>(mut self, sha256: S) -> Self {
        self.sha256 = Some(sha256.into());
        self
    }

    /// Sets the triage hints.
    pub fn with_hints(mut self, hints: Vec<TriageHint>) -> Self {
        self.hints = Some(hints);
        self
    }

    /// Sets the triage verdicts.
    pub fn with_verdicts(mut self, verdicts: Vec<TriageVerdict>) -> Self {
        self.verdicts = Some(verdicts);
        self
    }

    /// Sets the entropy summary.
    pub fn with_entropy(mut self, entropy: Option<EntropySummary>) -> Self {
        self.entropy = entropy;
        self
    }

    /// Sets the entropy analysis.
    pub fn with_entropy_analysis(mut self, entropy_analysis: Option<EntropyAnalysis>) -> Self {
        self.entropy_analysis = entropy_analysis;
        self
    }

    /// Sets the strings summary.
    pub fn with_strings(mut self, strings: Option<StringsSummary>) -> Self {
        self.strings = strings;
        self
    }

    /// Sets the symbols summary.
    pub fn with_symbols(mut self, symbols: Option<SymbolSummary>) -> Self {
        self.symbols = symbols;
        self
    }

    /// Sets the similarity summary.
    pub fn with_similarity(mut self, similarity: Option<SimilaritySummary>) -> Self {
        self.similarity = similarity;
        self
    }

    /// Sets the signing summary.
    pub fn with_signing(mut self, signing: Option<crate::triage::signing::SigningSummary>) -> Self {
        self.signing = signing;
        self
    }

    /// Sets the packer matches.
    pub fn with_packers(mut self, packers: Option<Vec<PackerMatch>>) -> Self {
        self.packers = packers;
        self
    }

    /// Sets the container children.
    pub fn with_containers(mut self, containers: Option<Vec<ContainerChild>>) -> Self {
        self.containers = containers;
        self
    }

    /// Sets recursion rollup summary.
    pub fn with_recursion_summary(
        mut self,
        summary: Option<crate::triage::recurse::RecursionSummary>,
    ) -> Self {
        self.recursion_summary = summary;
        self
    }

    /// Sets the overlay analysis.
    pub fn with_overlay(
        mut self,
        overlay: Option<crate::triage::overlay::OverlayAnalysis>,
    ) -> Self {
        self.overlay = overlay;
        self
    }

    /// Sets the format-specific triage information.
    pub fn with_format_specific(mut self, format_specific: Option<FormatSpecificTriage>) -> Self {
        self.format_specific = format_specific;
        self
    }

    /// Sets the parse status results.
    pub fn with_parse_status(mut self, parse_status: Option<Vec<ParserResult>>) -> Self {
        self.parse_status = parse_status;
        self
    }

    /// Sets the budgets.
    pub fn with_budgets(mut self, budgets: Option<Budgets>) -> Self {
        self.budgets = budgets;
        self
    }

    /// Sets the triage errors.
    pub fn with_errors(mut self, errors: Option<Vec<TriageError>>) -> Self {
        self.errors = errors;
        self
    }

    /// Sets the heuristic endianness guess.
    pub fn with_heuristic_endianness(
        mut self,
        heuristic_endianness: Option<(Endianness, f32)>,
    ) -> Self {
        self.heuristic_endianness = heuristic_endianness;
        self
    }

    /// Sets the heuristic architecture guesses.
    pub fn with_heuristic_arch(mut self, heuristic_arch: Option<Vec<(Arch, f32)>>) -> Self {
        self.heuristic_arch = heuristic_arch;
        self
    }

    /// Sets the disassembly preview lines.
    pub fn with_disasm_preview(mut self, preview: Option<Vec<String>>) -> Self {
        self.disasm_preview = preview;
        self
    }

    /// Builds the TriagedArtifact. Returns an error if required fields are missing.
    pub fn build(self) -> Result<TriagedArtifact, String> {
        let id = self.id.ok_or("id is required")?;
        let path = self.path.ok_or("path is required")?;
        let size_bytes = self.size_bytes.ok_or("size_bytes is required")?;
        let schema_version = self.schema_version.unwrap_or_else(|| "1.2".into());

        Ok(TriagedArtifact {
            schema_version,
            id,
            path,
            size_bytes,
            sha256: self.sha256,
            hints: self.hints.unwrap_or_default(),
            verdicts: self.verdicts.unwrap_or_default(),
            entropy: self.entropy,
            entropy_analysis: self.entropy_analysis,
            strings: self.strings,
            symbols: self.symbols,
            similarity: self.similarity,
            signing: self.signing,
            packers: self.packers,
            containers: self.containers,
            recursion_summary: self.recursion_summary,
            overlay: self.overlay,
            format_specific: self.format_specific,
            parse_status: self.parse_status,
            budgets: self.budgets,
            errors: self.errors,
            heuristic_endianness: self.heuristic_endianness,
            heuristic_arch: self.heuristic_arch,
            disasm_preview: self.disasm_preview,
        })
    }
}

impl TriagedArtifact {
    /// Creates a new builder for constructing TriagedArtifact instances.
    pub fn builder() -> TriagedArtifactBuilder {
        TriagedArtifactBuilder::new()
    }

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
        symbols: Option<SymbolSummary>,
        packers: Option<Vec<PackerMatch>>,
        containers: Option<Vec<ContainerChild>>,
        overlay: Option<crate::triage::overlay::OverlayAnalysis>,
        format_specific: Option<FormatSpecificTriage>,
        parse_status: Option<Vec<ParserResult>>,
        budgets: Option<Budgets>,
        errors: Option<Vec<TriageError>>,
        heuristic_endianness: Option<(Endianness, f32)>,
        heuristic_arch: Option<Vec<(Arch, f32)>>,
        disasm_preview: Option<Vec<String>>,
    ) -> Self {
        // Use the builder internally for consistency
        TriagedArtifact::builder()
            .with_schema_version("1.2")
            .with_id(id)
            .with_path(path)
            .with_size_bytes(size_bytes)
            .with_sha256(sha256)
            .with_hints(hints)
            .with_verdicts(verdicts)
            .with_entropy(entropy)
            .with_entropy_analysis(entropy_analysis)
            .with_strings(strings)
            .with_symbols(symbols)
            .with_similarity(None)
            .with_packers(packers)
            .with_containers(containers)
            .with_overlay(overlay)
            .with_format_specific(format_specific)
            .with_parse_status(parse_status)
            .with_budgets(budgets)
            .with_errors(errors)
            .with_heuristic_endianness(heuristic_endianness)
            .with_heuristic_arch(heuristic_arch)
            .with_disasm_preview(disasm_preview)
            .build()
            .expect("All required fields should be provided in new()")
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
