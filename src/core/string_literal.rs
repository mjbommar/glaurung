//! StringLiteral type for extracted strings with encoding analysis.
//!
//! StringLiteral represents extracted strings from binary analysis with
//! encoding detection, classification, and reference tracking.

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::core::address::Address;

/// String encoding types for extracted strings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[pyclass]
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
#[pyclass]
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
#[pyclass]
pub struct StringLiteral {
    /// Unique identifier for the string
    #[pyo3(get, set)]
    pub id: String,
    /// Address where the string is located
    #[pyo3(get, set)]
    pub address: Address,
    /// The actual string value
    #[pyo3(get, set)]
    pub value: String,
    /// Raw bytes of the string (optional)
    #[pyo3(get, set)]
    pub raw_bytes: Option<Vec<u8>>,
    /// String encoding
    #[pyo3(get, set)]
    pub encoding: StringEncoding,
    /// Length in bytes
    #[pyo3(get, set)]
    pub length_bytes: u64,
    /// Addresses that reference this string (optional)
    #[pyo3(get, set)]
    pub referenced_by: Option<Vec<Address>>,
    /// Language hint (optional)
    #[pyo3(get, set)]
    pub language_hint: Option<String>,
    /// String classification (optional)
    #[pyo3(get, set)]
    pub classification: Option<StringClassification>,
    /// Entropy value (optional)
    #[pyo3(get, set)]
    pub entropy: Option<f64>,
}

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

    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    /// Get the string length in characters
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Check if the string is empty
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
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

    /// Check if this appears to be a URL
    pub fn is_url(&self) -> bool {
        self.classification == Some(StringClassification::Url)
    }

    /// Check if this appears to be a file path
    pub fn is_path(&self) -> bool {
        self.classification == Some(StringClassification::Path)
    }

    /// Check if this appears to be an email
    pub fn is_email(&self) -> bool {
        self.classification == Some(StringClassification::Email)
    }

    /// Check if this appears to be a key
    pub fn is_key(&self) -> bool {
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
