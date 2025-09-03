//! Entropy analysis and classification types.

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

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

// Pure Rust constructors and helpers
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
