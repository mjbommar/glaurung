//! High-level signing presence summary for triage output.

use serde::{Deserialize, Serialize};

/// Signing presence summary (triage-level, presence only)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub struct SigningSummary {
    /// PE Authenticode certificate directory present / overlay signature heuristic
    pub pe_authenticode_present: bool,
    /// Mach-O LC_CODE_SIGNATURE present
    pub macho_code_signature_present: bool,
    /// Mach-O entitlements blob present (heuristic)
    pub macho_entitlements_present: bool,
    /// Overlay signature indicator (e.g., PKCS#7)
    pub overlay_has_signature: bool,
}
