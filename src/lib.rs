/// Core data types module
pub mod core;

/// Error types and error handling
pub mod error;

/// Logging and tracing infrastructure
pub mod logging;

/// Timeout utilities for analysis operations
pub mod timeout;

/// Triage runtime implementation
pub mod triage;

/// Integration examples (test only)
#[cfg(test)]
mod example_integration;

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;

/// A Python module implemented in Rust.
#[cfg(feature = "python-ext")]
#[pymodule]
fn _native(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register core types
    m.add_class::<crate::core::address::AddressKind>()?;
    m.add_class::<crate::core::address::Address>()?;
    m.add_class::<crate::core::address_range::AddressRange>()?;
    m.add_class::<crate::core::address_space::AddressSpaceKind>()?;
    m.add_class::<crate::core::address_space::AddressSpace>()?;
    m.add_class::<crate::core::artifact::Artifact>()?;
    m.add_class::<crate::core::binary::Format>()?;
    m.add_class::<crate::core::binary::Arch>()?;
    m.add_class::<crate::core::binary::Endianness>()?;
    m.add_class::<crate::core::binary::Hashes>()?;
    m.add_class::<crate::core::binary::Binary>()?;
    m.add_class::<crate::core::id::IdKind>()?;
    m.add_class::<crate::core::id::Id>()?;
    m.add_class::<crate::core::id::IdGenerator>()?;
    m.add_class::<crate::core::section::SectionPerms>()?;
    m.add_class::<crate::core::section::Section>()?;
    m.add_class::<crate::core::segment::Perms>()?;
    m.add_class::<crate::core::segment::Segment>()?;
    m.add_class::<crate::core::string_literal::StringEncoding>()?;
    m.add_class::<crate::core::string_literal::StringClassification>()?;
    m.add_class::<crate::core::string_literal::StringLiteral>()?;
    m.add_class::<crate::core::symbol::SymbolKind>()?;
    m.add_class::<crate::core::symbol::SymbolBinding>()?;
    m.add_class::<crate::core::symbol::SymbolVisibility>()?;
    m.add_class::<crate::core::symbol::SymbolSource>()?;
    m.add_class::<crate::core::symbol::Symbol>()?;
    m.add_class::<crate::core::instruction::OperandKind>()?;
    m.add_class::<crate::core::instruction::Access>()?;
    m.add_class::<crate::core::instruction::SideEffect>()?;
    m.add_class::<crate::core::instruction::Operand>()?;
    m.add_class::<crate::core::instruction::Instruction>()?;
    m.add_class::<crate::core::register::RegisterKind>()?;
    m.add_class::<crate::core::register::Register>()?;
    m.add_class::<crate::core::disassembler::DisassemblerError>()?;
    m.add_class::<crate::core::disassembler::Architecture>()?;
    // Endianness is exported from core::binary to avoid name collisions
    m.add_class::<crate::core::disassembler::DisassemblerConfig>()?;
    m.add_class::<crate::core::basic_block::BasicBlock>()?;
    m.add_class::<crate::core::pattern::MetadataValue>()?;
    m.add_class::<crate::core::pattern::PatternType>()?;
    m.add_class::<crate::core::pattern::YaraMatch>()?;
    m.add_class::<crate::core::pattern::PatternDefinition>()?;
    m.add_class::<crate::core::pattern::Pattern>()?;
    m.add_class::<crate::core::relocation::RelocationType>()?;
    m.add_class::<crate::core::relocation::Relocation>()?;
    m.add_class::<crate::core::tool_metadata::SourceKind>()?;
    m.add_class::<crate::core::tool_metadata::ToolMetadata>()?;

    // Submodule: triage
    let triage = pyo3::types::PyModule::new(py, "triage")?;
    triage.add_class::<crate::core::triage::SnifferSource>()?;
    triage.add_class::<crate::core::triage::TriageHint>()?;
    triage.add_class::<crate::core::triage::TriageErrorKind>()?;
    triage.add_class::<crate::core::triage::TriageError>()?;
    triage.add_class::<crate::core::triage::ConfidenceSignal>()?;
    triage.add_class::<crate::core::triage::ParserKind>()?;
    triage.add_class::<crate::core::triage::ParserResult>()?;
    triage.add_class::<crate::core::triage::EntropySummary>()?;
    triage.add_class::<crate::core::triage::StringsSummary>()?;
    triage.add_class::<crate::core::triage::PackerMatch>()?;
    triage.add_class::<crate::core::triage::ContainerChild>()?;
    triage.add_class::<crate::core::triage::Budgets>()?;
    triage.add_class::<crate::core::triage::TriageVerdict>()?;
    triage.add_class::<crate::core::triage::TriagedArtifact>()?;
    m.add_submodule(&triage)?;

    // Register logging functions
    m.add_function(wrap_pyfunction!(crate::logging::init_logging, m)?)?;
    m.add_function(wrap_pyfunction!(crate::logging::log_message, m)?)?;
    m.add_class::<crate::logging::LogLevel>()?;

    Ok(())
}
