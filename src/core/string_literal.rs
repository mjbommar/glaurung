//! StringLiteral type for extracted strings with encoding analysis.
//!
//! StringLiteral represents extracted strings from binary analysis with
//! encoding detection, classification, and reference tracking.

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::core::address::Address;

/// String encoding types for extracted strings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub enum StringEncoding {
    /// ASCII encoding
    Ascii,
    /// UTF-8 encoding
    Utf8,
    /// UTF-16 encoding
    Utf16,
    /// UTF-32 encoding
    Utf32,
    /// Unknown encoding
    Unknown,
    /// Base64 encoded data
    Base64,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl StringEncoding {
    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for StringEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StringEncoding::Ascii => write!(f, "Ascii"),
            StringEncoding::Utf8 => write!(f, "Utf8"),
            StringEncoding::Utf16 => write!(f, "Utf16"),
            StringEncoding::Utf32 => write!(f, "Utf32"),
            StringEncoding::Unknown => write!(f, "Unknown"),
            StringEncoding::Base64 => write!(f, "Base64"),
        }
    }
}

/// String classification for semantic analysis
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub enum StringClassification {
    /// URL string
    Url,
    /// File system path
    Path,
    /// Email address
    Email,
    /// Cryptographic key or similar
    Key,
    /// Other classification
    Other,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl StringClassification {
    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for StringClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StringClassification::Url => write!(f, "Url"),
            StringClassification::Path => write!(f, "Path"),
            StringClassification::Email => write!(f, "Email"),
            StringClassification::Key => write!(f, "Key"),
            StringClassification::Other => write!(f, "Other"),
        }
    }
}

/// Extracted string with encoding and reference information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct StringLiteral {
    /// Unique identifier for the string
    pub id: String,
    /// Address where the string is located
    pub address: Address,
    /// The actual string value
    pub value: String,
    /// Raw bytes of the string (optional)
    pub raw_bytes: Option<Vec<u8>>,
    /// String encoding
    pub encoding: StringEncoding,
    /// Length in bytes
    pub length_bytes: u64,
    /// Addresses that reference this string (optional)
    pub referenced_by: Option<Vec<Address>>,
    /// Language hint (optional)
    pub language_hint: Option<String>,
    /// String classification (optional)
    pub classification: Option<StringClassification>,
    /// Entropy value (optional)
    pub entropy: Option<f64>,
}

impl StringLiteral {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        address: Address,
        value: String,
        encoding: StringEncoding,
        length_bytes: u64,
        raw_bytes: Option<Vec<u8>>,
        referenced_by: Option<Vec<Address>>,
        language_hint: Option<String>,
        classification: Option<StringClassification>,
        entropy: Option<f64>,
    ) -> Self {
        Self {
            id,
            address,
            value,
            raw_bytes,
            encoding,
            length_bytes,
            referenced_by,
            language_hint,
            classification,
            entropy,
        }
    }

    pub fn len(&self) -> usize {
        self.value.len()
    }
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
    pub fn is_url(&self) -> bool {
        self.classification == Some(StringClassification::Url)
    }
    pub fn is_path(&self) -> bool {
        self.classification == Some(StringClassification::Path)
    }
    pub fn is_email(&self) -> bool {
        self.classification == Some(StringClassification::Email)
    }
    pub fn is_key(&self) -> bool {
        self.classification == Some(StringClassification::Key)
    }
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl StringLiteral {
    /// Create a new StringLiteral instance
    #[new]
    #[pyo3(signature = (
        id,
        address,
        value,
        encoding,
        length_bytes,
        raw_bytes=None,
        referenced_by=None,
        language_hint=None,
        classification=None,
        entropy=None
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn new_py(
        id: String,
        address: Address,
        value: String,
        encoding: StringEncoding,
        length_bytes: u64,
        raw_bytes: Option<Vec<u8>>,
        referenced_by: Option<Vec<Address>>,
        language_hint: Option<String>,
        classification: Option<StringClassification>,
        entropy: Option<f64>,
    ) -> Self {
        Self {
            id,
            address,
            value,
            raw_bytes,
            encoding,
            length_bytes,
            referenced_by,
            language_hint,
            classification,
            entropy,
        }
    }

    /// Get the string ID
    #[getter]
    pub fn get_id(&self) -> &str {
        &self.id
    }

    /// Set the string ID
    #[setter]
    pub fn set_id(&mut self, id: String) {
        self.id = id;
    }

    /// Get the string address
    #[getter]
    pub fn get_address(&self) -> Address {
        self.address.clone()
    }

    /// Set the string address
    #[setter]
    pub fn set_address(&mut self, address: Address) {
        self.address = address;
    }

    /// Get the string value
    #[getter]
    pub fn get_value(&self) -> &str {
        &self.value
    }

    /// Set the string value
    #[setter]
    pub fn set_value(&mut self, value: String) {
        self.value = value;
    }

    /// Get the raw bytes
    #[getter]
    pub fn get_raw_bytes(&self) -> Option<Vec<u8>> {
        self.raw_bytes.clone()
    }

    /// Set the raw bytes
    #[setter]
    pub fn set_raw_bytes(&mut self, raw_bytes: Option<Vec<u8>>) {
        self.raw_bytes = raw_bytes;
    }

    /// Get the string encoding
    #[getter]
    pub fn get_encoding(&self) -> StringEncoding {
        self.encoding
    }

    /// Set the string encoding
    #[setter]
    pub fn set_encoding(&mut self, encoding: StringEncoding) {
        self.encoding = encoding;
    }

    /// Get the length in bytes
    #[getter]
    pub fn get_length_bytes(&self) -> u64 {
        self.length_bytes
    }

    /// Set the length in bytes
    #[setter]
    pub fn set_length_bytes(&mut self, length_bytes: u64) {
        self.length_bytes = length_bytes;
    }

    /// Get the addresses that reference this string
    #[getter]
    pub fn get_referenced_by(&self) -> Option<Vec<Address>> {
        self.referenced_by.clone()
    }

    /// Set the addresses that reference this string
    #[setter]
    pub fn set_referenced_by(&mut self, referenced_by: Option<Vec<Address>>) {
        self.referenced_by = referenced_by;
    }

    /// Get the language hint
    #[getter]
    pub fn get_language_hint(&self) -> Option<String> {
        self.language_hint.clone()
    }

    /// Set the language hint
    #[setter]
    pub fn set_language_hint(&mut self, language_hint: Option<String>) {
        self.language_hint = language_hint;
    }

    /// Get the string classification
    #[getter]
    pub fn get_classification(&self) -> Option<StringClassification> {
        self.classification.clone()
    }

    /// Set the string classification
    #[setter]
    pub fn set_classification(&mut self, classification: Option<StringClassification>) {
        self.classification = classification;
    }

    /// Get the entropy value
    #[getter]
    pub fn get_entropy(&self) -> Option<f64> {
        self.entropy
    }

    /// Set the entropy value
    #[setter]
    pub fn set_entropy(&mut self, entropy: Option<f64>) {
        self.entropy = entropy;
    }

    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    /// Get a human-readable description
    pub fn description(&self) -> String {
        let classification_str = self
            .classification
            .as_ref()
            .map(|c| format!(" ({})", c))
            .unwrap_or_default();

        format!(
            "String '{}' at {}{} ({} bytes, {})",
            self.value, self.address, classification_str, self.length_bytes, self.encoding
        )
    }

    // Additional helpers are provided in the pure-Rust impl above.

    // Helper wrappers for Python
    #[pyo3(name = "len")]
    pub fn len_py(&self) -> usize {
        self.len()
    }
    #[pyo3(name = "is_empty")]
    pub fn is_empty_py(&self) -> bool {
        self.is_empty()
    }
    #[pyo3(name = "is_url")]
    pub fn is_url_py(&self) -> bool {
        self.classification == Some(StringClassification::Url)
    }
    #[pyo3(name = "is_path")]
    pub fn is_path_py(&self) -> bool {
        self.classification == Some(StringClassification::Path)
    }
    #[pyo3(name = "is_email")]
    pub fn is_email_py(&self) -> bool {
        self.classification == Some(StringClassification::Email)
    }
    #[pyo3(name = "is_key")]
    pub fn is_key_py(&self) -> bool {
        self.classification == Some(StringClassification::Key)
    }
}

impl fmt::Display for StringLiteral {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "String '{}' ({})", self.value, self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::{Address, AddressKind};

    #[test]
    fn test_string_encoding_display() {
        assert_eq!(format!("{}", StringEncoding::Ascii), "Ascii");
        assert_eq!(format!("{}", StringEncoding::Utf8), "Utf8");
        assert_eq!(format!("{}", StringEncoding::Utf16), "Utf16");
        assert_eq!(format!("{}", StringEncoding::Utf32), "Utf32");
        assert_eq!(format!("{}", StringEncoding::Unknown), "Unknown");
        assert_eq!(format!("{}", StringEncoding::Base64), "Base64");
    }

    #[test]
    fn test_string_classification_display() {
        assert_eq!(format!("{}", StringClassification::Url), "Url");
        assert_eq!(format!("{}", StringClassification::Path), "Path");
        assert_eq!(format!("{}", StringClassification::Email), "Email");
        assert_eq!(format!("{}", StringClassification::Key), "Key");
        assert_eq!(format!("{}", StringClassification::Other), "Other");
    }

    #[test]
    fn test_string_literal_creation() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();

        let string_lit = StringLiteral::new(
            "str_1".to_string(),
            address,
            "Hello World".to_string(),
            StringEncoding::Ascii,
            11,
            Some(b"Hello World".to_vec()),
            None,
            Some("en".to_string()),
            Some(StringClassification::Other),
            Some(3.5),
        );

        assert_eq!(string_lit.id, "str_1");
        assert_eq!(string_lit.value, "Hello World");
        assert_eq!(string_lit.encoding, StringEncoding::Ascii);
        assert_eq!(string_lit.length_bytes, 11);
        assert_eq!(string_lit.len(), 11);
        assert!(!string_lit.is_empty());
    }

    #[test]
    fn test_string_literal_classification_methods() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();

        let url_string = StringLiteral::new(
            "str_1".to_string(),
            address.clone(),
            "http://example.com".to_string(),
            StringEncoding::Ascii,
            18,
            None,
            None,
            None,
            Some(StringClassification::Url),
            None,
        );

        let path_string = StringLiteral::new(
            "str_2".to_string(),
            address,
            "/usr/bin/ls".to_string(),
            StringEncoding::Ascii,
            11,
            None,
            None,
            None,
            Some(StringClassification::Path),
            None,
        );

        assert!(url_string.is_url());
        assert!(!url_string.is_path());
        assert!(!url_string.is_email());
        assert!(!url_string.is_key());

        assert!(path_string.is_path());
        assert!(!path_string.is_url());
    }
}
