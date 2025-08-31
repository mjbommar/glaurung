//! ID generation utilities for Glaurung binary analysis.
//!
//! This module provides stable, deterministic ID generation for various entities
//! in the binary analysis system, supporting cross-tool mapping and deduplication.

use pyo3::prelude::*;
use sha2::{Digest, Sha256};
use std::fmt;
use uuid::Uuid;

/// ID kinds for different types of entities in the binary analysis system.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[pyclass(eq, eq_int)]
pub enum IdKind {
    /// Binary-level identifier (content-based or UUID)
    Binary,
    /// Function identifier (deterministic based on binary + address)
    Function,
    /// Basic block identifier (deterministic based on binary + address)
    BasicBlock,
    /// Symbol identifier (name-based or address-based)
    Symbol,
    /// Section identifier (name-based or index-based)
    Section,
    /// Segment identifier (name-based or index-based)
    Segment,
    /// Instruction identifier (address-based)
    Instruction,
    /// Variable identifier (context-based)
    Variable,
    /// Data type identifier (name-based or content-based)
    DataType,
    /// Generic entity identifier
    Entity,
}

impl fmt::Display for IdKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdKind::Binary => write!(f, "Binary"),
            IdKind::Function => write!(f, "Function"),
            IdKind::BasicBlock => write!(f, "BasicBlock"),
            IdKind::Symbol => write!(f, "Symbol"),
            IdKind::Section => write!(f, "Section"),
            IdKind::Segment => write!(f, "Segment"),
            IdKind::Instruction => write!(f, "Instruction"),
            IdKind::Variable => write!(f, "Variable"),
            IdKind::DataType => write!(f, "DataType"),
            IdKind::Entity => write!(f, "Entity"),
        }
    }
}

/// A stable identifier for entities in the binary analysis system.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[pyclass(eq)]
pub struct Id {
    /// The string value of the ID
    pub value: String,
    /// The kind of entity this ID represents
    pub kind: IdKind,
}

#[pymethods]
impl Id {
    /// Create a new ID with the given value and kind.
    ///
    /// Args:
    ///     value: The string value of the ID
    ///     kind: The kind of ID
    ///
    /// Returns:
    ///     Id: A new Id instance
    #[new]
    fn new(value: String, kind: IdKind) -> Self {
        Id { value, kind }
    }

    /// Get the string value of this ID.
    #[getter]
    fn value(&self) -> &str {
        &self.value
    }

    /// Get the kind of this ID.
    #[getter]
    fn kind(&self) -> IdKind {
        self.kind.clone()
    }

    /// String representation for display.
    fn __str__(&self) -> String {
        self.value.to_string()
    }

    /// Python representation.
    fn __repr__(&self) -> String {
        format!("Id('{}', IdKind.{:?})", self.value, self.kind)
    }

    /// Check if this ID is valid (non-empty).
    fn is_valid(&self) -> bool {
        !self.value.is_empty()
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[pymethods]
impl IdKind {
    /// String representation for display.
    fn __str__(&self) -> String {
        format!("{}", self)
    }

    /// Python representation.
    fn __repr__(&self) -> String {
        format!("IdKind.{}", self.__str__())
    }
}

/// ID generation utilities and strategies.
#[derive(Debug)]
#[pyclass]
pub struct IdGenerator;

#[pymethods]
impl IdGenerator {
    /// Generate a binary ID based on content hash.
    ///
    /// Args:
    ///     content: Binary content as bytes
    ///     path: Optional file path for additional entropy
    ///
    /// Returns:
    ///     Id: A content-based binary ID
    #[staticmethod]
    fn binary_from_content(content: &[u8], path: Option<String>) -> Id {
        let mut hasher = Sha256::new();
        hasher.update(content);

        if let Some(path_str) = path {
            hasher.update(b":");
            hasher.update(path_str.as_bytes());
        }

        let hash = hasher.finalize();
        let hash_hex = hex::encode(hash);
        let value = format!("bin:sha256:{}", hash_hex);

        Id {
            value,
            kind: IdKind::Binary,
        }
    }

    /// Generate a binary ID from a UUID/build-id.
    ///
    /// Args:
    ///     uuid: The UUID or build-id as a string
    ///
    /// Returns:
    ///     Id: A UUID-based binary ID
    #[staticmethod]
    fn binary_from_uuid(uuid: String) -> Id {
        let value = format!("bin:uuid:{}", uuid);
        Id {
            value,
            kind: IdKind::Binary,
        }
    }

    /// Generate a function ID (deterministic based on binary ID and address).
    ///
    /// Args:
    ///     binary_id: The binary ID
    ///     address: The function start address as a string
    ///
    /// Returns:
    ///     Id: A deterministic function ID
    #[staticmethod]
    fn function(binary_id: &str, address: &str) -> Id {
        let value = format!("func:{}:{}", binary_id, address);
        Id {
            value,
            kind: IdKind::Function,
        }
    }

    /// Generate a basic block ID (deterministic based on binary ID and address).
    ///
    /// Args:
    ///     binary_id: The binary ID
    ///     address: The block start address as a string
    ///
    /// Returns:
    ///     Id: A deterministic basic block ID
    #[staticmethod]
    fn basic_block(binary_id: &str, address: &str) -> Id {
        let value = format!("bb:{}:{}", binary_id, address);
        Id {
            value,
            kind: IdKind::BasicBlock,
        }
    }

    /// Generate a symbol ID based on name and optional address.
    ///
    /// Args:
    ///     name: The symbol name
    ///     address: Optional address as a string
    ///
    /// Returns:
    ///     Id: A symbol ID
    #[staticmethod]
    fn symbol(name: &str, address: Option<String>) -> Id {
        let value = if let Some(addr) = address {
            format!("sym:{}:{}", name, addr)
        } else {
            format!("sym:{}", name)
        };
        Id {
            value,
            kind: IdKind::Symbol,
        }
    }

    /// Generate a section ID based on name or index.
    ///
    /// Args:
    ///     name: Optional section name
    ///     index: Optional section index
    ///
    /// Returns:
    ///     Id: A section ID
    #[staticmethod]
    fn section(name: Option<String>, index: Option<u32>) -> Id {
        let value = match (name, index) {
            (Some(n), Some(i)) => format!("sect:{}:{}", n, i),
            (Some(n), None) => format!("sect:{}", n),
            (None, Some(i)) => format!("sect:idx:{}", i),
            (None, None) => "sect:unknown".to_string(),
        };
        Id {
            value,
            kind: IdKind::Section,
        }
    }

    /// Generate a segment ID based on name or index.
    ///
    /// Args:
    ///     name: Optional segment name
    ///     index: Optional segment index
    ///
    /// Returns:
    ///     Id: A segment ID
    #[staticmethod]
    fn segment(name: Option<String>, index: Option<u32>) -> Id {
        let value = match (name, index) {
            (Some(n), Some(i)) => format!("seg:{}:{}", n, i),
            (Some(n), None) => format!("seg:{}", n),
            (None, Some(i)) => format!("seg:idx:{}", i),
            (None, None) => "seg:unknown".to_string(),
        };
        Id {
            value,
            kind: IdKind::Segment,
        }
    }

    /// Generate an instruction ID based on address.
    ///
    /// Args:
    ///     address: The instruction address as a string
    ///
    /// Returns:
    ///     Id: An instruction ID
    #[staticmethod]
    fn instruction(address: &str) -> Id {
        let value = format!("insn:{}", address);
        Id {
            value,
            kind: IdKind::Instruction,
        }
    }

    /// Generate a variable ID based on context.
    ///
    /// Args:
    ///     context: Context identifier (e.g., function ID)
    ///     name: Optional variable name
    ///     offset: Optional offset within context
    ///
    /// Returns:
    ///     Id: A variable ID
    #[staticmethod]
    fn variable(context: &str, name: Option<String>, offset: Option<i64>) -> Id {
        let value = match (name, offset) {
            (Some(n), Some(o)) => format!("var:{}:{}:{}", context, n, o),
            (Some(n), None) => format!("var:{}:{}", context, n),
            (None, Some(o)) => format!("var:{}:offset:{}", context, o),
            (None, None) => format!("var:{}:unnamed", context),
        };
        Id {
            value,
            kind: IdKind::Variable,
        }
    }

    /// Generate a data type ID based on name or content.
    ///
    /// Args:
    ///     name: Optional type name
    ///     content_hash: Optional content hash for anonymous types
    ///
    /// Returns:
    ///     Id: A data type ID
    #[staticmethod]
    fn data_type(name: Option<String>, content_hash: Option<String>) -> Id {
        let value = match (name, content_hash) {
            (Some(n), Some(h)) => format!("type:{}:{}", n, h),
            (Some(n), None) => format!("type:{}", n),
            (None, Some(h)) => format!("type:anon:{}", h),
            (None, None) => "type:unknown".to_string(),
        };
        Id {
            value,
            kind: IdKind::DataType,
        }
    }

    /// Generate a generic entity ID.
    ///
    /// Args:
    ///     entity_type: The type of entity
    ///     identifier: Unique identifier within the type
    ///
    /// Returns:
    ///     Id: A generic entity ID
    #[staticmethod]
    fn entity(entity_type: &str, identifier: &str) -> Id {
        let value = format!("{}:{}", entity_type, identifier);
        Id {
            value,
            kind: IdKind::Entity,
        }
    }

    /// Generate a UUID-based ID for cases where content-based IDs aren't suitable.
    ///
    /// Args:
    ///     kind: The kind of ID to generate
    ///
    /// Returns:
    ///     Id: A UUID-based ID
    #[staticmethod]
    fn uuid(kind: IdKind) -> Id {
        let uuid = Uuid::new_v4();
        let value = format!("{}:uuid:{}", kind.to_string().to_lowercase(), uuid);
        Id { value, kind }
    }

    /// Generate a hash-based ID from arbitrary content.
    ///
    /// Args:
    ///     kind: The kind of ID
    ///     content: Content to hash
    ///
    /// Returns:
    ///     Id: A hash-based ID
    #[staticmethod]
    fn hash(kind: IdKind, content: &str) -> Id {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let hash = hasher.finalize();
        let hash_hex = hex::encode(&hash[..8]); // Use first 8 bytes for shorter IDs
        let value = format!("{}:hash:{}", kind.to_string().to_lowercase(), hash_hex);
        Id { value, kind }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_id_from_content() {
        let content = b"test binary content";
        let id = IdGenerator::binary_from_content(content, Some("test.exe".to_string()));

        assert_eq!(id.kind, IdKind::Binary);
        assert!(id.value.starts_with("bin:sha256:"));
        assert!(id.is_valid());
    }

    #[test]
    fn test_binary_id_from_uuid() {
        let uuid = "12345678-1234-1234-1234-123456789abc".to_string();
        let id = IdGenerator::binary_from_uuid(uuid);

        assert_eq!(id.kind, IdKind::Binary);
        assert_eq!(id.value, "bin:uuid:12345678-1234-1234-1234-123456789abc");
    }

    #[test]
    fn test_function_id() {
        let binary_id = "bin:sha256:abcd";
        let address = "0x401000";
        let id = IdGenerator::function(binary_id, address);

        assert_eq!(id.kind, IdKind::Function);
        assert_eq!(id.value, "func:bin:sha256:abcd:0x401000");
    }

    #[test]
    fn test_basic_block_id() {
        let binary_id = "bin:sha256:abcd";
        let address = "0x401000";
        let id = IdGenerator::basic_block(binary_id, address);

        assert_eq!(id.kind, IdKind::BasicBlock);
        assert_eq!(id.value, "bb:bin:sha256:abcd:0x401000");
    }

    #[test]
    fn test_symbol_id_with_address() {
        let id = IdGenerator::symbol("CreateFileW", Some("0x401000".to_string()));

        assert_eq!(id.kind, IdKind::Symbol);
        assert_eq!(id.value, "sym:CreateFileW:0x401000");
    }

    #[test]
    fn test_symbol_id_without_address() {
        let id = IdGenerator::symbol("kernel32.dll", None);

        assert_eq!(id.kind, IdKind::Symbol);
        assert_eq!(id.value, "sym:kernel32.dll");
    }

    #[test]
    fn test_section_id_with_name_and_index() {
        let id = IdGenerator::section(Some(".text".to_string()), Some(1));

        assert_eq!(id.kind, IdKind::Section);
        assert_eq!(id.value, "sect:.text:1");
    }

    #[test]
    fn test_section_id_with_name_only() {
        let id = IdGenerator::section(Some(".data".to_string()), None);

        assert_eq!(id.kind, IdKind::Section);
        assert_eq!(id.value, "sect:.data");
    }

    #[test]
    fn test_segment_id() {
        let id = IdGenerator::segment(Some("CODE".to_string()), Some(0));

        assert_eq!(id.kind, IdKind::Segment);
        assert_eq!(id.value, "seg:CODE:0");
    }

    #[test]
    fn test_instruction_id() {
        let id = IdGenerator::instruction("0x401000");

        assert_eq!(id.kind, IdKind::Instruction);
        assert_eq!(id.value, "insn:0x401000");
    }

    #[test]
    fn test_variable_id() {
        let id = IdGenerator::variable("func:main", Some("local_var".to_string()), Some(8));

        assert_eq!(id.kind, IdKind::Variable);
        assert_eq!(id.value, "var:func:main:local_var:8");
    }

    #[test]
    fn test_data_type_id() {
        let id = IdGenerator::data_type(Some("int32".to_string()), Some("hash123".to_string()));

        assert_eq!(id.kind, IdKind::DataType);
        assert_eq!(id.value, "type:int32:hash123");
    }

    #[test]
    fn test_entity_id() {
        let id = IdGenerator::entity("reference", "xref_123");

        assert_eq!(id.kind, IdKind::Entity);
        assert_eq!(id.value, "reference:xref_123");
    }

    #[test]
    fn test_uuid_generation() {
        let id = IdGenerator::uuid(IdKind::Binary);

        assert_eq!(id.kind, IdKind::Binary);
        assert!(id.value.starts_with("binary:uuid:"));
        assert!(id.value.len() > 20); // UUID is longer
    }

    #[test]
    fn test_hash_generation() {
        let id = IdGenerator::hash(IdKind::Function, "test content");

        assert_eq!(id.kind, IdKind::Function);
        assert!(id.value.starts_with("function:hash:"));
        assert!(id.value.contains(":")); // Should have the hash part
    }

    #[test]
    fn test_id_equality() {
        let id1 = Id::new("test".to_string(), IdKind::Binary);
        let id2 = Id::new("test".to_string(), IdKind::Binary);
        let id3 = Id::new("different".to_string(), IdKind::Binary);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_id_display() {
        let id = Id::new("test_id".to_string(), IdKind::Binary);
        assert_eq!(format!("{}", id), "test_id");
    }

    #[test]
    fn test_id_kind_display() {
        assert_eq!(format!("{}", IdKind::Binary), "Binary");
        assert_eq!(format!("{}", IdKind::Function), "Function");
        assert_eq!(format!("{}", IdKind::BasicBlock), "BasicBlock");
    }

    #[test]
    fn test_deterministic_generation() {
        // Same inputs should produce same IDs
        let id1 = IdGenerator::function("bin:123", "0x401000");
        let id2 = IdGenerator::function("bin:123", "0x401000");

        assert_eq!(id1, id2);
    }
}
