//! Core triage data types organized by submodule.

pub mod containers;
pub mod entropy;
pub mod errors;
pub mod formats;
pub mod hints;
pub mod packers;
pub mod parsers;
pub mod strings;
pub mod verdict;

// Re-exports for convenient access under crate::core::triage::*
pub use containers::{ContainerChild, ContainerMetadata};
pub use entropy::{
    EntropyAnalysis, EntropyAnomaly, EntropyClass, EntropySummary, PackedIndicators,
};
pub use errors::{TriageError, TriageErrorKind};
pub use hints::{ConfidenceSignal, SnifferSource, TriageHint};
pub use packers::PackerMatch;
pub use parsers::{ParserKind, ParserResult};
pub use strings::{DetectedString, IocSample, StringsSummary};
pub use verdict::{
    Budgets, SimilaritySummary, TriageVerdict, TriagedArtifact, TriagedArtifactBuilder,
};
