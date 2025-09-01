//! Pattern type for detected signatures and anomalies.
//!
//! Pattern represents detected signatures, heuristics, and anomalies in binary analysis.
//! This includes cryptographic patterns, packer signatures, anti-debug techniques, etc.

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::core::address::Address;

/// Simple metadata value type for PyO3 compatibility
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub enum MetadataValue {
    /// String value
    String(String),
    /// Integer value
    Integer(i64),
    /// Float value
    Float(f64),
    /// Boolean value
    Boolean(bool),
    /// Array of values
    Array(Vec<MetadataValue>),
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl MetadataValue {
    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for MetadataValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetadataValue::String(s) => write!(f, "{}", s),
            MetadataValue::Integer(i) => write!(f, "{}", i),
            MetadataValue::Float(fl) => write!(f, "{}", fl),
            MetadataValue::Boolean(b) => write!(f, "{}", b),
            MetadataValue::Array(arr) => {
                write!(f, "[")?;
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", item)?;
                }
                write!(f, "]")
            }
        }
    }
}

/// Types of patterns that can be detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub enum PatternType {
    /// Byte signature pattern
    Signature,
    /// Heuristic-based detection
    Heuristic,
    /// YARA rule match
    Yara,
    /// Behavioral pattern
    Behavior,
    /// Statistical anomaly
    Statistical,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl PatternType {
    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for PatternType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatternType::Signature => write!(f, "Signature"),
            PatternType::Heuristic => write!(f, "Heuristic"),
            PatternType::Yara => write!(f, "Yara"),
            PatternType::Behavior => write!(f, "Behavior"),
            PatternType::Statistical => write!(f, "Statistical"),
        }
    }
}

/// YARA rule match information
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct YaraMatch {
    /// Offset where the match occurred
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub offset: u64,
    /// Identifier of the matching string
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub identifier: String,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl YaraMatch {
    /// Create a new YaraMatch
    #[new]
    pub fn new(offset: u64, identifier: String) -> Self {
        Self { offset, identifier }
    }

    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}@{}", self.identifier, self.offset)
    }
}

impl fmt::Display for YaraMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.identifier, self.offset)
    }
}

impl YaraMatch {
    pub fn new(offset: u64, identifier: String) -> Self { Self { offset, identifier } }
}

/// Pattern definition variants based on pattern type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub enum PatternDefinition {
    /// Byte signature with optional mask
    Signature {
        /// Hex string of bytes
        bytes: String,
        /// Optional mask for partial matching
        mask: Option<String>,
    },
    /// YARA rule matches
    Yara {
        /// YARA rule identifier
        rule_id: String,
        /// List of matches
        matches: Vec<YaraMatch>,
    },
    /// Heuristic conditions
    Heuristic {
        /// List of condition strings
        conditions: Vec<String>,
    },
    /// Behavioral pattern
    Behavior {
        /// Optional API calls
        api_calls: Option<Vec<String>>,
        /// Optional instruction sequences
        sequences: Option<Vec<String>>,
    },
    /// Statistical anomaly
    Statistical {
        /// Optional entropy value
        entropy: Option<f64>,
        /// Optional metrics
        metrics: Option<HashMap<String, MetadataValue>>,
    },
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl PatternDefinition {
    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    // Python-only methods here
}

impl PatternDefinition {
    /// Get the pattern type for this definition (pure Rust)
    pub fn pattern_type(&self) -> PatternType {
        match self {
            PatternDefinition::Signature { .. } => PatternType::Signature,
            PatternDefinition::Yara { .. } => PatternType::Yara,
            PatternDefinition::Heuristic { .. } => PatternType::Heuristic,
            PatternDefinition::Behavior { .. } => PatternType::Behavior,
            PatternDefinition::Statistical { .. } => PatternType::Statistical,
        }
    }
}

impl fmt::Display for PatternDefinition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatternDefinition::Signature { bytes, mask } => {
                if let Some(mask) = mask {
                    write!(f, "Signature: {} (mask: {})", bytes, mask)
                } else {
                    write!(f, "Signature: {}", bytes)
                }
            }
            PatternDefinition::Yara { rule_id, matches } => {
                write!(f, "YARA: {} ({} matches)", rule_id, matches.len())
            }
            PatternDefinition::Heuristic { conditions } => {
                write!(f, "Heuristic: {} conditions", conditions.len())
            }
            PatternDefinition::Behavior {
                api_calls,
                sequences,
            } => {
                let api_count = api_calls.as_ref().map(|v| v.len()).unwrap_or(0);
                let seq_count = sequences.as_ref().map(|v| v.len()).unwrap_or(0);
                write!(f, "Behavior: {} APIs, {} sequences", api_count, seq_count)
            }
            PatternDefinition::Statistical { entropy, metrics } => {
                let entropy_str = entropy
                    .map(|e| format!("{:.3}", e))
                    .unwrap_or("N/A".to_string());
                let metrics_count = metrics.as_ref().map(|m| m.len()).unwrap_or(0);
                write!(
                    f,
                    "Statistical: entropy={}, {} metrics",
                    entropy_str, metrics_count
                )
            }
        }
    }
}

/// Detected pattern or anomaly in binary analysis
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct Pattern {
    /// Unique identifier for the pattern
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub id: String,
    /// Type of pattern
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub pattern_type: PatternType,
    /// Human-readable name
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub name: String,
    /// Addresses where this pattern was found
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub addresses: Vec<Address>,
    /// Confidence score (0.0 to 1.0)
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub confidence: f64,
    /// Pattern definition (varies by type)
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub pattern_definition: PatternDefinition,
    /// Human-readable description
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub description: String,
    /// References (URLs, CVEs, etc.)
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub references: Vec<String>,
    /// Additional metadata
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub metadata: Option<HashMap<String, MetadataValue>>,
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl Pattern {
    /// Create a new Pattern instance
    #[new]
    #[pyo3(signature = (
        id,
        pattern_type,
        name,
        addresses,
        confidence,
        pattern_definition,
        description,
        references=None,
        metadata=None
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        pattern_type: PatternType,
        name: String,
        addresses: Vec<Address>,
        confidence: f64,
        pattern_definition: PatternDefinition,
        description: String,
        references: Option<Vec<String>>,
        metadata: Option<HashMap<String, MetadataValue>>,
    ) -> PyResult<Self> {
        // Validate confidence range
        if !(0.0..=1.0).contains(&confidence) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "confidence must be between 0.0 and 1.0",
            ));
        }

        // Validate pattern type matches definition
        if pattern_type != pattern_definition.pattern_type() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "pattern_type must match pattern_definition type",
            ));
        }

        Ok(Self {
            id,
            pattern_type,
            name,
            addresses,
            confidence,
            pattern_definition,
            description,
            references: references.unwrap_or_default(),
            metadata,
        })
    }

    /// String representation for display
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    /// Get the number of addresses where this pattern was found
    pub fn address_count(&self) -> usize {
        self.addresses.len()
    }

    /// Check if this is a high-confidence pattern
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.8
    }

    /// Check if this is a medium-confidence pattern
    pub fn is_medium_confidence(&self) -> bool {
        self.confidence >= 0.5 && self.confidence < 0.8
    }

    /// Check if this is a low-confidence pattern
    pub fn is_low_confidence(&self) -> bool {
        self.confidence < 0.5
    }

    /// Get confidence level as string
    pub fn confidence_level(&self) -> &'static str {
        if self.is_high_confidence() {
            "high"
        } else if self.is_medium_confidence() {
            "medium"
        } else {
            "low"
        }
    }

    /// Check if this pattern has any references
    pub fn has_references(&self) -> bool {
        !self.references.is_empty()
    }

    /// Check if this pattern has metadata
    pub fn has_metadata(&self) -> bool {
        self.metadata.is_some()
    }

    /// Get a summary of the pattern
    pub fn summary(&self) -> String {
        format!(
            "{} pattern '{}' found at {} locations (confidence: {:.2})",
            self.pattern_type,
            self.name,
            self.address_count(),
            self.confidence
        )
    }
}

impl Pattern {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        pattern_type: PatternType,
        name: String,
        addresses: Vec<Address>,
        confidence: f64,
        pattern_definition: PatternDefinition,
        description: String,
        references: Option<Vec<String>>,
        metadata: Option<HashMap<String, MetadataValue>>,
    ) -> Result<Self, String> {
        if !(0.0..=1.0).contains(&confidence) {
            return Err("confidence must be between 0.0 and 1.0".to_string());
        }
        if pattern_type != pattern_definition.pattern_type() {
            return Err("pattern_type must match pattern_definition type".to_string());
        }
        Ok(Self {
            id,
            pattern_type,
            name,
            addresses,
            confidence,
            pattern_definition,
            description,
            references: references.unwrap_or_default(),
            metadata,
        })
    }

    pub fn address_count(&self) -> usize { self.addresses.len() }
    pub fn is_high_confidence(&self) -> bool { self.confidence >= 0.8 }
    pub fn is_medium_confidence(&self) -> bool { self.confidence >= 0.5 && self.confidence < 0.8 }
    pub fn is_low_confidence(&self) -> bool { self.confidence < 0.5 }
    pub fn confidence_level(&self) -> &'static str {
        if self.is_high_confidence() { "high" } else if self.is_medium_confidence() { "medium" } else { "low" }
    }
    pub fn has_references(&self) -> bool { !self.references.is_empty() }
    pub fn has_metadata(&self) -> bool { self.metadata.is_some() }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Pattern '{}' ({}, {} addresses, confidence: {:.2})",
            self.name,
            self.pattern_type,
            self.addresses.len(),
            self.confidence
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::{Address, AddressKind};

    #[test]
    fn test_pattern_type_display() {
        assert_eq!(format!("{}", PatternType::Signature), "Signature");
        assert_eq!(format!("{}", PatternType::Heuristic), "Heuristic");
        assert_eq!(format!("{}", PatternType::Yara), "Yara");
        assert_eq!(format!("{}", PatternType::Behavior), "Behavior");
        assert_eq!(format!("{}", PatternType::Statistical), "Statistical");
    }

    #[test]
    fn test_yara_match_creation() {
        let yara_match = YaraMatch::new(0x1000, "$string1".to_string());
        assert_eq!(yara_match.offset, 0x1000);
        assert_eq!(yara_match.identifier, "$string1");
        assert_eq!(format!("{}", yara_match), "$string1@4096");
    }

    #[test]
    fn test_pattern_definition_pattern_type() {
        let sig_def = PatternDefinition::Signature {
            bytes: "DEADBEEF".to_string(),
            mask: Some("FF00FF00".to_string()),
        };
        assert_eq!(sig_def.pattern_type(), PatternType::Signature);

        let yara_def = PatternDefinition::Yara {
            rule_id: "malware_rule".to_string(),
            matches: vec![],
        };
        assert_eq!(yara_def.pattern_type(), PatternType::Yara);

        let heur_def = PatternDefinition::Heuristic {
            conditions: vec!["condition1".to_string()],
        };
        assert_eq!(heur_def.pattern_type(), PatternType::Heuristic);

        let beh_def = PatternDefinition::Behavior {
            api_calls: Some(vec!["VirtualAlloc".to_string()]),
            sequences: None,
        };
        assert_eq!(beh_def.pattern_type(), PatternType::Behavior);

        let stat_def = PatternDefinition::Statistical {
            entropy: Some(7.5),
            metrics: None,
        };
        assert_eq!(stat_def.pattern_type(), PatternType::Statistical);
    }

    #[test]
    fn test_pattern_creation_signature() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();

        let pattern_def = PatternDefinition::Signature {
            bytes: "DEADBEEF".to_string(),
            mask: None,
        };

        let pattern = Pattern::new(
            "sig_1".to_string(),
            PatternType::Signature,
            "Deadbeef Signature".to_string(),
            vec![address],
            0.9,
            pattern_def,
            "A signature for deadbeef pattern".to_string(),
            Some(vec!["https://example.com/sig1".to_string()]),
            None,
        )
        .unwrap();

        assert_eq!(pattern.id, "sig_1");
        assert_eq!(pattern.pattern_type, PatternType::Signature);
        assert_eq!(pattern.name, "Deadbeef Signature");
        assert_eq!(pattern.address_count(), 1);
        assert_eq!(pattern.confidence, 0.9);
        assert!(pattern.is_high_confidence());
        assert!(pattern.has_references());
        assert!(!pattern.has_metadata());
    }

    #[test]
    fn test_pattern_confidence_validation() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();
        let pattern_def = PatternDefinition::Signature {
            bytes: "DEADBEEF".to_string(),
            mask: None,
        };

        // Test invalid confidence (too high)
        let result = Pattern::new(
            "test".to_string(),
            PatternType::Signature,
            "Test".to_string(),
            vec![address.clone()],
            1.5,
            pattern_def.clone(),
            "Test".to_string(),
            None,
            None,
        );
        assert!(result.is_err());

        // Test invalid confidence (negative)
        let result = Pattern::new(
            "test".to_string(),
            PatternType::Signature,
            "Test".to_string(),
            vec![address],
            -0.1,
            pattern_def,
            "Test".to_string(),
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_pattern_type_mismatch() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();
        let pattern_def = PatternDefinition::Signature {
            bytes: "DEADBEEF".to_string(),
            mask: None,
        };

        // Try to create pattern with mismatched type
        let result = Pattern::new(
            "test".to_string(),
            PatternType::Heuristic, // Wrong type
            "Test".to_string(),
            vec![address],
            0.8,
            pattern_def, // Signature definition
            "Test".to_string(),
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_pattern_confidence_levels() {
        let address = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();
        let pattern_def = PatternDefinition::Heuristic {
            conditions: vec!["condition1".to_string()],
        };

        let high_conf = Pattern::new(
            "high".to_string(),
            PatternType::Heuristic,
            "High Confidence".to_string(),
            vec![address.clone()],
            0.9,
            pattern_def.clone(),
            "High confidence pattern".to_string(),
            None,
            None,
        )
        .unwrap();

        let medium_conf = Pattern::new(
            "medium".to_string(),
            PatternType::Heuristic,
            "Medium Confidence".to_string(),
            vec![address.clone()],
            0.6,
            pattern_def.clone(),
            "Medium confidence pattern".to_string(),
            None,
            None,
        )
        .unwrap();

        let low_conf = Pattern::new(
            "low".to_string(),
            PatternType::Heuristic,
            "Low Confidence".to_string(),
            vec![address],
            0.3,
            pattern_def,
            "Low confidence pattern".to_string(),
            None,
            None,
        )
        .unwrap();

        assert!(high_conf.is_high_confidence());
        assert_eq!(high_conf.confidence_level(), "high");

        assert!(medium_conf.is_medium_confidence());
        assert_eq!(medium_conf.confidence_level(), "medium");

        assert!(low_conf.is_low_confidence());
        assert_eq!(low_conf.confidence_level(), "low");
    }
}
