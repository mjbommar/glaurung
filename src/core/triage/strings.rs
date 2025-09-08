//! String detection and analysis types.

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A single IOC match sample
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct IocSample {
    pub kind: String,
    pub text: String,
    pub offset: Option<u64>,
}

// Python accessors for IocSample are defined later in this file

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
    pub utf8_count: u32,
    pub utf16le_count: u32,
    pub utf16be_count: u32,
    /// Detected strings with language information
    pub strings: Option<Vec<DetectedString>>,
    /// Summary of detected languages and their counts (deterministic order)
    pub language_counts: Option<BTreeMap<String, u32>>,
    /// Summary of detected scripts and their counts (deterministic order)
    pub script_counts: Option<BTreeMap<String, u32>>,
    /// IOC counts (e.g., ipv4, ipv6, url, domain, email, path_* , registry) in deterministic order
    pub ioc_counts: Option<BTreeMap<String, u32>>,
    /// Optional IOC samples with offsets
    pub ioc_samples: Option<Vec<IocSample>>,
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
        language_counts: Option<BTreeMap<String, u32>>,
        script_counts: Option<BTreeMap<String, u32>>,
    ) -> Self {
        Self {
            ascii_count,
            utf8_count: 0,
            utf16le_count,
            utf16be_count,
            strings,
            language_counts,
            script_counts,
            ioc_counts: None,
            ioc_samples: None,
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
    fn utf8_count(&self) -> u32 {
        self.utf8_count
    }

    #[getter]
    fn strings(&self) -> Option<Vec<DetectedString>> {
        self.strings.clone()
    }

    #[getter]
    fn language_counts(&self) -> Option<std::collections::HashMap<String, u32>> {
        self.language_counts
            .as_ref()
            .map(|btree| btree.iter().map(|(k, v)| (k.clone(), *v)).collect())
    }

    #[getter]
    fn script_counts(&self) -> Option<std::collections::HashMap<String, u32>> {
        self.script_counts
            .as_ref()
            .map(|btree| btree.iter().map(|(k, v)| (k.clone(), *v)).collect())
    }

    #[getter]
    fn ioc_counts(&self) -> Option<std::collections::HashMap<String, u32>> {
        self.ioc_counts
            .as_ref()
            .map(|btree| btree.iter().map(|(k, v)| (k.clone(), *v)).collect())
    }

    #[getter]
    fn ioc_samples(&self) -> Option<Vec<IocSample>> {
        self.ioc_samples.clone()
    }

    // For backward compatibility
    #[getter]
    fn samples(&self) -> Option<Vec<String>> {
        self.strings
            .as_ref()
            .map(|strings| strings.iter().take(10).map(|s| s.text.clone()).collect())
    }
}

// Pure Rust constructors and helpers
impl IocSample {
    pub fn new(kind: String, text: String, offset: Option<u64>) -> Self {
        Self { kind, text, offset }
    }
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl IocSample {
    #[getter]
    fn kind(&self) -> String {
        self.kind.clone()
    }
    #[getter]
    fn text(&self) -> String {
        self.text.clone()
    }
    #[getter]
    fn offset(&self) -> Option<u64> {
        self.offset
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
        language_counts: Option<BTreeMap<String, u32>>,
        script_counts: Option<BTreeMap<String, u32>>,
    ) -> Self {
        Self {
            ascii_count,
            utf8_count: 0,
            utf16le_count,
            utf16be_count,
            strings,
            language_counts,
            script_counts,
            ioc_counts: None,
            ioc_samples: None,
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
            utf8_count: 0,
            utf16le_count,
            utf16be_count,
            strings,
            language_counts: None,
            script_counts: None,
            ioc_counts: None,
            ioc_samples: None,
        }
    }
}
