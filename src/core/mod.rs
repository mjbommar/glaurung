//! Core data types for Glaurung binary analysis.
//!
//! This module contains the fundamental types used throughout the system,
//! starting with the Address type which is the foundation for all location
//! references in binary analysis.

pub mod address;
pub mod address_range;
pub mod address_space;
pub mod artifact;
pub mod basic_block;
pub mod binary;
pub mod call_graph;
pub mod control_flow_graph;
pub mod data_type;
pub mod disassembler;
pub mod function;
pub mod id;
pub mod instruction;
pub mod pattern;
pub mod reference;
pub mod register;
pub mod relocation;
pub mod section;
pub mod segment;
pub mod string_literal;
pub mod symbol;
pub mod tool_metadata;
pub mod triage;
pub mod variable;

// Re-export key types for convenience
pub use address::{Address, AddressKind};
pub use address_range::AddressRange;
pub use address_space::{AddressSpace, AddressSpaceKind};
pub use artifact::Artifact;
pub use basic_block::BasicBlock;
pub use binary::{Binary, Format, Arch, Endianness, Hashes};
pub use call_graph::CallGraph;
pub use control_flow_graph::ControlFlowGraph;
pub use data_type::{DataType, DataTypeKind, Field, EnumMember, TypeData};
pub use function::{Function, FunctionKind, FunctionFlags};
pub use id::{Id, IdKind, IdGenerator};
pub use instruction::{Instruction, Operand, OperandKind, Access, SideEffect};
pub use pattern::{Pattern, PatternType};
pub use reference::{Reference, ReferenceKind};
pub use register::{Register, RegisterKind};
pub use relocation::{Relocation, RelocationType};
pub use section::{Section, SectionPerms};
pub use segment::{Segment, Perms};
pub use string_literal::{StringLiteral, StringEncoding, StringClassification};
pub use symbol::{Symbol, SymbolKind, SymbolBinding, SymbolVisibility, SymbolSource};
pub use tool_metadata::{ToolMetadata, SourceKind};
pub use variable::{Variable, StorageLocation};
