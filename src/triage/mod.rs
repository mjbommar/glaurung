//! Triage runtime implementation for binary analysis.
//!
//! This module provides the core triage functionality for classifying
//! and analyzing binary artifacts safely and deterministically.

pub mod api;
pub mod compiler_detection;
pub mod config;
pub mod containers;
pub mod disasm_mini;
pub mod entropy;
pub mod format_detection;
pub mod headers;
pub mod heuristics;
pub mod io;
pub mod languages;
pub mod overlay;
pub mod packers;
pub mod parsers;
pub mod recurse;
pub mod rich_header;
pub mod score;
pub mod signatures;
pub mod signing;
pub mod sniffers;

// Re-export key types from core for convenience
pub use crate::core::triage::{
    Budgets, ConfidenceSignal, ContainerChild, EntropySummary, PackerMatch, ParserKind,
    ParserResult, SnifferSource, StringsSummary, TriageError, TriageErrorKind, TriageHint,
    TriageVerdict, TriagedArtifact,
};
