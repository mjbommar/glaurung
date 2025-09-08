//! Format-specific triage information.

use crate::triage::rich_header::RichHeader;
#[cfg(feature = "python-ext")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

/// PE-specific triage information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass(get_all))]
pub struct PeTriageInfo {
    /// Rich Header information, if present.
    pub rich_header: Option<RichHeader>,
}

/// ELF-specific triage information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass(get_all))]
pub struct ElfTriageInfo {
    // Placeholder for ELF-specific fields
}

/// Mach-O-specific triage information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass(get_all))]
pub struct MachOTriageInfo {
    // Placeholder for Mach-O-specific fields
}

/// Struct to hold format-specific triage information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "python-ext", pyclass(get_all))]
pub struct FormatSpecificTriage {
    pub pe: Option<PeTriageInfo>,
    pub elf: Option<ElfTriageInfo>,
    pub macho: Option<MachOTriageInfo>,
}
