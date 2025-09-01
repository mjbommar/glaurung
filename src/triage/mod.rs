//! Triage runtime implementation for binary analysis.
//!
//! This module provides the core triage functionality for classifying
//! and analyzing binary artifacts safely and deterministically.

pub mod api;
pub mod config;
pub mod containers;
pub mod entropy;
pub mod headers;
pub mod heuristics;
pub mod io;
pub mod languages;
pub mod packers;
pub mod parsers;
pub mod recurse;
pub mod score;
pub mod signatures;
pub mod sniffers;

// Re-export key types from core for convenience
pub use crate::core::triage::{
    Budgets, ConfidenceSignal, ContainerChild, EntropySummary, PackerMatch, ParserKind,
    ParserResult, SnifferSource, StringsSummary, TriageError, TriageErrorKind, TriageHint,
    TriageVerdict, TriagedArtifact,
};
