//! Python bindings for core Glaurung types.
//!
//! This module registers all the fundamental data types used throughout
//! the Glaurung library.

use pyo3::prelude::*;

/// Register core data types with the Python module.
pub fn register_core_types(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Core address types
    m.add_class::<crate::core::address::AddressKind>()?;
    m.add_class::<crate::core::address::Address>()?;
    m.add_class::<crate::core::address_range::AddressRange>()?;
    m.add_class::<crate::core::address_space::AddressSpaceKind>()?;
    m.add_class::<crate::core::address_space::AddressSpace>()?;

    // Core binary types
    m.add_class::<crate::core::artifact::Artifact>()?;
    m.add_class::<crate::core::binary::Format>()?;
    m.add_class::<crate::core::binary::Arch>()?;
    m.add_class::<crate::core::binary::Endianness>()?;
    m.add_class::<crate::core::binary::Hashes>()?;
    m.add_class::<crate::core::binary::Binary>()?;

    // Core ID types
    m.add_class::<crate::core::id::IdKind>()?;
    m.add_class::<crate::core::id::Id>()?;
    m.add_class::<crate::core::id::IdGenerator>()?;

    // Core section types
    m.add_class::<crate::core::section::SectionPerms>()?;
    m.add_class::<crate::core::section::Section>()?;
    m.add_class::<crate::core::segment::Perms>()?;
    m.add_class::<crate::core::segment::Segment>()?;

    // Core string types
    m.add_class::<crate::core::string_literal::StringEncoding>()?;
    m.add_class::<crate::core::string_literal::StringClassification>()?;
    m.add_class::<crate::core::string_literal::StringLiteral>()?;

    // Core symbol types
    m.add_class::<crate::core::symbol::SymbolKind>()?;
    m.add_class::<crate::core::symbol::SymbolBinding>()?;
    m.add_class::<crate::core::symbol::SymbolVisibility>()?;
    m.add_class::<crate::core::symbol::SymbolSource>()?;
    m.add_class::<crate::core::symbol::Symbol>()?;

    // Core instruction types
    m.add_class::<crate::core::instruction::OperandKind>()?;
    m.add_class::<crate::core::instruction::Access>()?;
    m.add_class::<crate::core::instruction::SideEffect>()?;
    m.add_class::<crate::core::instruction::Operand>()?;
    m.add_class::<crate::core::instruction::Instruction>()?;

    // Core register types
    m.add_class::<crate::core::register::RegisterKind>()?;
    m.add_class::<crate::core::register::Register>()?;

    // Core disassembler types
    m.add_class::<crate::core::disassembler::DisassemblerError>()?;
    m.add_class::<crate::core::disassembler::Architecture>()?;
    // Endianness is exported from core::binary to avoid name collisions
    m.add_class::<crate::core::disassembler::DisassemblerConfig>()?;
    m.add_class::<crate::core::basic_block::BasicBlock>()?;

    // Core pattern types
    m.add_class::<crate::core::pattern::MetadataValue>()?;
    m.add_class::<crate::core::pattern::PatternType>()?;
    m.add_class::<crate::core::pattern::YaraMatch>()?;
    m.add_class::<crate::core::pattern::PatternDefinition>()?;
    m.add_class::<crate::core::pattern::Pattern>()?;

    // Core relocation types
    m.add_class::<crate::core::relocation::RelocationType>()?;
    m.add_class::<crate::core::relocation::Relocation>()?;

    // Core tool metadata types
    m.add_class::<crate::core::tool_metadata::SourceKind>()?;
    m.add_class::<crate::core::tool_metadata::ToolMetadata>()?;

    // Core data types
    m.add_class::<crate::core::data_type::DataTypeKind>()?;
    m.add_class::<crate::core::data_type::Field>()?;
    m.add_class::<crate::core::data_type::EnumMember>()?;
    m.add_class::<crate::core::data_type::TypeData>()?;
    m.add_class::<crate::core::data_type::DataType>()?;
    m.add_class::<crate::core::variable::StorageLocation>()?;
    m.add_class::<crate::core::variable::Variable>()?;
    m.add_class::<crate::core::function::FunctionKind>()?;
    m.add_class::<crate::core::function::FunctionFlagsPy>()?;
    m.add_class::<crate::core::function::Function>()?;

    // Core reference types
    m.add_class::<crate::core::reference::UnresolvedReferenceKind>()?;
    m.add_class::<crate::core::reference::ReferenceTarget>()?;
    m.add_class::<crate::core::reference::ReferenceKind>()?;
    m.add_class::<crate::core::reference::Reference>()?;

    // Core graph types
    m.add_class::<crate::core::control_flow_graph::ControlFlowEdgeKind>()?;
    m.add_class::<crate::core::control_flow_graph::ControlFlowEdge>()?;
    m.add_class::<crate::core::control_flow_graph::ControlFlowGraph>()?;
    m.add_class::<crate::core::control_flow_graph::ControlFlowGraphStats>()?;
    m.add_class::<crate::core::call_graph::CallType>()?;
    m.add_class::<crate::core::call_graph::CallGraphEdge>()?;
    m.add_class::<crate::core::call_graph::CallGraph>()?;
    m.add_class::<crate::core::call_graph::CallGraphStats>()?;

    Ok(())
}
