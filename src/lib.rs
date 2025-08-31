use pyo3::prelude::*;

/// Core data types module
pub mod core;

/// A Python module implemented in Rust.
#[pymodule]
fn glaurung(m: &Bound<'_, PyModule>) -> PyResult<()> {
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
    m.add_class::<crate::core::pattern::MetadataValue>()?;
    m.add_class::<crate::core::pattern::PatternType>()?;
    m.add_class::<crate::core::pattern::YaraMatch>()?;
    m.add_class::<crate::core::pattern::PatternDefinition>()?;
    m.add_class::<crate::core::pattern::Pattern>()?;
    m.add_class::<crate::core::relocation::RelocationType>()?;
    m.add_class::<crate::core::relocation::Relocation>()?;
    m.add_class::<crate::core::tool_metadata::SourceKind>()?;
    m.add_class::<crate::core::tool_metadata::ToolMetadata>()?;

    Ok(())
}
