//! Data type system for representing types in binary analysis.
//!
//! This module provides a comprehensive type system that can represent
//! primitive types, complex structures, pointers, arrays, and function signatures
//! as encountered in binary analysis and decompilation.

#[cfg(feature = "pyo3")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

/// Represents the different kinds of data types in the system.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "pyo3", pyclass(eq, eq_int))]
pub enum DataTypeKind {
    /// Primitive types like int32, float64, char, etc.
    Primitive,
    /// Pointer to another type
    Pointer,
    /// Array of elements of a base type
    Array,
    /// C-style struct with named fields
    Struct,
    /// C-style union
    Union,
    /// Enumeration type
    Enum,
    /// Function signature
    Function,
    /// Type alias/typedef
    Typedef,
}

/// Represents a field in a struct or union.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "pyo3", pyclass)]
pub struct Field {
    /// Field name
    pub name: String,
    /// Type ID of the field
    pub type_id: String,
    /// Offset from the start of the struct/union in bytes
    pub offset: u64,
}

/// Represents the underlying type for an enum.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "pyo3", pyclass)]
pub struct EnumMember {
    /// Enum member name
    pub name: String,
    /// Enum member value
    pub value: i64,
}

/// Represents the data specific to each data type kind.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "pyo3", pyclass)]
pub enum TypeData {
    /// Primitive type - no additional data needed
    Primitive {},
    /// Pointer type data
    Pointer {
        /// Type ID of the pointed-to type
        base_type_id: String,
        /// Optional attributes like const/volatile
        attributes: Vec<String>,
    },
    /// Array type data
    Array {
        /// Type ID of the element type
        base_type_id: String,
        /// Number of elements in the array
        count: u64,
    },
    /// Struct type data
    Struct {
        /// Ordered list of fields
        fields: Vec<Field>,
    },
    /// Union type data
    Union {
        /// List of fields (all at offset 0)
        fields: Vec<Field>,
    },
    /// Enum type data
    Enum {
        /// Type ID of the underlying integer type
        underlying_type_id: String,
        /// Enum members with their values
        members: Vec<EnumMember>,
    },
    /// Function type data
    Function {
        /// Type ID of the return type (None for void)
        return_type_id: Option<String>,
        /// Type IDs of the parameters
        parameter_type_ids: Vec<String>,
        /// Whether the function takes variable arguments
        variadic: bool,
    },
    /// Typedef type data
    Typedef {
        /// Type ID of the aliased type
        base_type_id: String,
    },
}

/// Represents a data type in the binary analysis system.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "pyo3", pyclass)]
pub struct DataType {
    /// Unique identifier for this type
    pub id: String,
    /// Human-readable name of the type
    pub name: String,
    /// The kind of data type this represents
    pub kind: DataTypeKind,
    /// Size in bytes
    pub size: u64,
    /// Alignment requirement in bytes (optional)
    pub alignment: Option<u64>,
    /// Type-specific data
    pub type_data: TypeData,
    /// Source of this type information (optional)
    pub source: Option<String>,
}

impl DataType {
    /// Create a new primitive data type.
    pub fn new_primitive(
        id: String,
        name: String,
        size: u64,
        alignment: Option<u64>,
        source: Option<String>,
    ) -> Self {
        Self {
            id,
            name,
            kind: DataTypeKind::Primitive,
            size,
            alignment,
            type_data: TypeData::Primitive {},
            source,
        }
    }

    /// Create a new pointer data type.
    pub fn new_pointer(
        id: String,
        name: String,
        size: u64,
        alignment: Option<u64>,
        base_type_id: String,
        attributes: Vec<String>,
        source: Option<String>,
    ) -> Self {
        Self {
            id,
            name,
            kind: DataTypeKind::Pointer,
            size,
            alignment,
            type_data: TypeData::Pointer {
                base_type_id,
                attributes,
            },
            source,
        }
    }

    /// Create a new array data type.
    pub fn new_array(
        id: String,
        name: String,
        size: u64,
        alignment: Option<u64>,
        base_type_id: String,
        count: u64,
        source: Option<String>,
    ) -> Self {
        Self {
            id,
            name,
            kind: DataTypeKind::Array,
            size,
            alignment,
            type_data: TypeData::Array {
                base_type_id,
                count,
            },
            source,
        }
    }

    /// Create a new struct data type.
    pub fn new_struct(
        id: String,
        name: String,
        size: u64,
        alignment: Option<u64>,
        fields: Vec<Field>,
        source: Option<String>,
    ) -> Self {
        Self {
            id,
            name,
            kind: DataTypeKind::Struct,
            size,
            alignment,
            type_data: TypeData::Struct { fields },
            source,
        }
    }

    /// Create a new union data type.
    pub fn new_union(
        id: String,
        name: String,
        size: u64,
        alignment: Option<u64>,
        fields: Vec<Field>,
        source: Option<String>,
    ) -> Self {
        Self {
            id,
            name,
            kind: DataTypeKind::Union,
            size,
            alignment,
            type_data: TypeData::Union { fields },
            source,
        }
    }

    /// Create a new enum data type.
    pub fn new_enum(
        id: String,
        name: String,
        size: u64,
        alignment: Option<u64>,
        underlying_type_id: String,
        members: Vec<EnumMember>,
        source: Option<String>,
    ) -> Self {
        Self {
            id,
            name,
            kind: DataTypeKind::Enum,
            size,
            alignment,
            type_data: TypeData::Enum {
                underlying_type_id,
                members,
            },
            source,
        }
    }

    /// Create a new function data type.
    #[allow(clippy::too_many_arguments)]
    pub fn new_function(
        id: String,
        name: String,
        size: u64,
        alignment: Option<u64>,
        return_type_id: Option<String>,
        parameter_type_ids: Vec<String>,
        variadic: bool,
        source: Option<String>,
    ) -> Self {
        Self {
            id,
            name,
            kind: DataTypeKind::Function,
            size,
            alignment,
            type_data: TypeData::Function {
                return_type_id,
                parameter_type_ids,
                variadic,
            },
            source,
        }
    }

    /// Create a new typedef data type.
    pub fn new_typedef(
        id: String,
        name: String,
        size: u64,
        alignment: Option<u64>,
        base_type_id: String,
        source: Option<String>,
    ) -> Self {
        Self {
            id,
            name,
            kind: DataTypeKind::Typedef,
            size,
            alignment,
            type_data: TypeData::Typedef { base_type_id },
            source,
        }
    }

    /// Validate the data type for consistency.
    pub fn is_valid(&self) -> bool {
        // Check that ID is not empty
        if self.id.trim().is_empty() {
            return false;
        }

        // Check that name is not empty
        if self.name.trim().is_empty() {
            return false;
        }

        // Check size is reasonable (allow 0 for void-like types)
        if self.size > 1_000_000 {
            // 1MB max
            return false;
        }

        // Check alignment if provided
        if let Some(alignment) = self.alignment {
            if alignment == 0 || !alignment.is_power_of_two() {
                return false;
            }
        }

        // Type-specific validation
        match &self.type_data {
            TypeData::Primitive {} => {
                // Primitive types should have reasonable sizes
                matches!(self.size, 1 | 2 | 4 | 8 | 16)
            }
            TypeData::Pointer { base_type_id, .. } => !base_type_id.trim().is_empty(),
            TypeData::Array {
                base_type_id,
                count,
            } => !base_type_id.trim().is_empty() && *count > 0,
            TypeData::Struct { fields } | TypeData::Union { fields } => {
                // Check field names are unique and offsets are valid
                let mut names = std::collections::HashSet::new();
                for field in fields {
                    if field.name.trim().is_empty() || names.contains(&field.name) {
                        return false;
                    }
                    names.insert(&field.name);

                    if field.type_id.trim().is_empty() {
                        return false;
                    }

                    // For unions, all offsets should be 0
                    if matches!(self.type_data, TypeData::Union { .. }) && field.offset != 0 {
                        return false;
                    }
                }
                true
            }
            TypeData::Enum {
                underlying_type_id,
                members,
            } => {
                if underlying_type_id.trim().is_empty() {
                    return false;
                }
                // Check member names are unique
                let mut names = std::collections::HashSet::new();
                for member in members {
                    if member.name.trim().is_empty() || names.contains(&member.name) {
                        return false;
                    }
                    names.insert(&member.name);
                }
                true
            }
            TypeData::Function {
                parameter_type_ids, ..
            } => {
                // Check all parameter type IDs are non-empty
                parameter_type_ids.iter().all(|id| !id.trim().is_empty())
            }
            TypeData::Typedef { base_type_id } => !base_type_id.trim().is_empty(),
        }
    }

    /// Get the base type ID if this is a derived type.
    pub fn base_type_id(&self) -> Option<&str> {
        match &self.type_data {
            TypeData::Pointer { base_type_id, .. } => Some(base_type_id),
            TypeData::Array { base_type_id, .. } => Some(base_type_id),
            TypeData::Typedef { base_type_id } => Some(base_type_id),
            _ => None,
        }
    }

    /// Check if this type is a pointer.
    pub fn is_pointer(&self) -> bool {
        matches!(self.kind, DataTypeKind::Pointer)
    }

    /// Check if this type is an array.
    pub fn is_array(&self) -> bool {
        matches!(self.kind, DataTypeKind::Array)
    }

    /// Check if this type is a function.
    pub fn is_function(&self) -> bool {
        matches!(self.kind, DataTypeKind::Function)
    }

    /// Check if this type is a composite type (struct/union).
    pub fn is_composite(&self) -> bool {
        matches!(self.kind, DataTypeKind::Struct | DataTypeKind::Union)
    }

    /// Get the fields if this is a struct or union.
    pub fn fields(&self) -> Option<&[Field]> {
        match &self.type_data {
            TypeData::Struct { fields } | TypeData::Union { fields } => Some(fields),
            _ => None,
        }
    }

    /// Get the enum members if this is an enum.
    pub fn enum_members(&self) -> Option<&[EnumMember]> {
        match &self.type_data {
            TypeData::Enum { members, .. } => Some(members),
            _ => None,
        }
    }

    /// Get the parameter types if this is a function.
    pub fn parameter_types(&self) -> Option<&[String]> {
        match &self.type_data {
            TypeData::Function {
                parameter_type_ids, ..
            } => Some(parameter_type_ids),
            _ => None,
        }
    }

    /// Get the return type if this is a function.
    pub fn return_type(&self) -> Option<&str> {
        match &self.type_data {
            TypeData::Function { return_type_id, .. } => return_type_id.as_deref(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_type_creation() {
        let dt = DataType::new_primitive(
            "int32".to_string(),
            "int32_t".to_string(),
            4,
            Some(4),
            Some("debug".to_string()),
        );

        assert_eq!(dt.id, "int32");
        assert_eq!(dt.name, "int32_t");
        assert_eq!(dt.size, 4);
        assert_eq!(dt.alignment, Some(4));
        assert!(matches!(dt.kind, DataTypeKind::Primitive));
        assert!(dt.is_valid());
    }

    #[test]
    fn test_pointer_type_creation() {
        let dt = DataType::new_pointer(
            "ptr_int32".to_string(),
            "*int32_t".to_string(),
            8,
            Some(8),
            "int32".to_string(),
            vec![],
            None,
        );

        assert!(dt.is_pointer());
        assert_eq!(dt.base_type_id(), Some("int32"));
        assert!(dt.is_valid());
    }

    #[test]
    fn test_array_type_creation() {
        let dt = DataType::new_array(
            "arr_int32".to_string(),
            "int32_t[10]".to_string(),
            40,
            Some(4),
            "int32".to_string(),
            10,
            None,
        );

        assert!(dt.is_array());
        assert_eq!(dt.base_type_id(), Some("int32"));
        assert!(dt.is_valid());
    }

    #[test]
    fn test_struct_type_creation() {
        let fields = vec![
            Field {
                name: "x".to_string(),
                type_id: "int32".to_string(),
                offset: 0,
            },
            Field {
                name: "y".to_string(),
                type_id: "int32".to_string(),
                offset: 4,
            },
        ];

        let dt = DataType::new_struct(
            "point".to_string(),
            "struct Point".to_string(),
            8,
            Some(4),
            fields.clone(),
            None,
        );

        assert!(dt.is_composite());
        assert_eq!(dt.fields().unwrap().len(), 2);
        assert!(dt.is_valid());
    }

    #[test]
    fn test_function_type_creation() {
        let dt = DataType::new_function(
            "func_add".to_string(),
            "int32_t add(int32_t, int32_t)".to_string(),
            0,
            None,
            Some("int32".to_string()),
            vec!["int32".to_string(), "int32".to_string()],
            false,
            None,
        );

        assert!(dt.is_function());
        assert_eq!(dt.return_type(), Some("int32"));
        assert_eq!(dt.parameter_types().unwrap().len(), 2);
        assert!(dt.is_valid());
    }

    #[test]
    fn test_invalid_empty_id() {
        let dt = DataType::new_primitive("".to_string(), "test".to_string(), 4, None, None);
        assert!(!dt.is_valid());
    }

    #[test]
    fn test_invalid_empty_name() {
        let dt = DataType::new_primitive("test".to_string(), "".to_string(), 4, None, None);
        assert!(!dt.is_valid());
    }

    #[test]
    fn test_invalid_alignment() {
        let dt = DataType::new_primitive(
            "test".to_string(),
            "test".to_string(),
            4,
            Some(3), // Not a power of 2
            None,
        );
        assert!(!dt.is_valid());
    }

    #[test]
    fn test_serialization() {
        let dt = DataType::new_primitive(
            "int32".to_string(),
            "int32_t".to_string(),
            4,
            Some(4),
            Some("debug".to_string()),
        );

        let serialized = serde_json::to_string(&dt).unwrap();
        let deserialized: DataType = serde_json::from_str(&serialized).unwrap();

        assert_eq!(dt, deserialized);
    }
}

// Python bindings
#[cfg(feature = "pyo3")]
#[pymethods]
impl DataType {
    #[new]
    #[pyo3(signature = (id, name, kind, size, alignment=None, source=None))]
    fn new_py(
        id: String,
        name: String,
        kind: DataTypeKind,
        size: u64,
        alignment: Option<u64>,
        source: Option<String>,
    ) -> PyResult<Self> {
        // For Python bindings, we'll default the type_data based on kind
        let type_data = match kind {
            DataTypeKind::Primitive => TypeData::Primitive {},
            DataTypeKind::Pointer => TypeData::Pointer {
                base_type_id: String::new(),
                attributes: vec![],
            },
            DataTypeKind::Array => TypeData::Array {
                base_type_id: String::new(),
                count: 0,
            },
            DataTypeKind::Struct => TypeData::Struct { fields: vec![] },
            DataTypeKind::Union => TypeData::Union { fields: vec![] },
            DataTypeKind::Enum => TypeData::Enum {
                underlying_type_id: String::new(),
                members: vec![],
            },
            DataTypeKind::Function => TypeData::Function {
                return_type_id: None,
                parameter_type_ids: vec![],
                variadic: false,
            },
            DataTypeKind::Typedef => TypeData::Typedef {
                base_type_id: String::new(),
            },
        };

        let dt = Self {
            id,
            name,
            kind,
            size,
            alignment,
            type_data,
            source,
        };

        if !dt.is_valid() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid DataType parameters",
            ));
        }

        Ok(dt)
    }

    #[staticmethod]
    fn primitive(
        id: String,
        name: String,
        size: u64,
        alignment: Option<u64>,
        source: Option<String>,
    ) -> PyResult<Self> {
        let dt = Self::new_primitive(id, name, size, alignment, source);
        if !dt.is_valid() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid primitive type parameters",
            ));
        }
        Ok(dt)
    }

    #[staticmethod]
    fn pointer(
        id: String,
        name: String,
        size: u64,
        alignment: Option<u64>,
        base_type_id: String,
        attributes: Vec<String>,
        source: Option<String>,
    ) -> PyResult<Self> {
        let dt = Self::new_pointer(id, name, size, alignment, base_type_id, attributes, source);
        if !dt.is_valid() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid pointer type parameters",
            ));
        }
        Ok(dt)
    }

    #[staticmethod]
    fn array(
        id: String,
        name: String,
        size: u64,
        alignment: Option<u64>,
        base_type_id: String,
        count: u64,
        source: Option<String>,
    ) -> PyResult<Self> {
        let dt = Self::new_array(id, name, size, alignment, base_type_id, count, source);
        if !dt.is_valid() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid array type parameters",
            ));
        }
        Ok(dt)
    }

    #[staticmethod]
    fn struct_(
        id: String,
        name: String,
        size: u64,
        alignment: Option<u64>,
        fields: Vec<Field>,
        source: Option<String>,
    ) -> PyResult<Self> {
        let dt = Self::new_struct(id, name, size, alignment, fields, source);
        if !dt.is_valid() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid struct type parameters",
            ));
        }
        Ok(dt)
    }

    #[staticmethod]
    fn union(
        id: String,
        name: String,
        size: u64,
        alignment: Option<u64>,
        fields: Vec<Field>,
        source: Option<String>,
    ) -> PyResult<Self> {
        let dt = Self::new_union(id, name, size, alignment, fields, source);
        if !dt.is_valid() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid union type parameters",
            ));
        }
        Ok(dt)
    }

    #[staticmethod]
    fn enum_(
        id: String,
        name: String,
        size: u64,
        alignment: Option<u64>,
        underlying_type_id: String,
        members: Vec<EnumMember>,
        source: Option<String>,
    ) -> PyResult<Self> {
        let dt = Self::new_enum(
            id,
            name,
            size,
            alignment,
            underlying_type_id,
            members,
            source,
        );
        if !dt.is_valid() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid enum type parameters",
            ));
        }
        Ok(dt)
    }

    #[staticmethod]
    fn function(
        id: String,
        name: String,
        size: u64,
        alignment: Option<u64>,
        return_type_id: Option<String>,
        parameter_type_ids: Vec<String>,
        variadic: bool,
        source: Option<String>,
    ) -> PyResult<Self> {
        let dt = Self::new_function(
            id,
            name,
            size,
            alignment,
            return_type_id,
            parameter_type_ids,
            variadic,
            source,
        );
        if !dt.is_valid() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid function type parameters",
            ));
        }
        Ok(dt)
    }

    #[staticmethod]
    fn typedef(
        id: String,
        name: String,
        size: u64,
        alignment: Option<u64>,
        base_type_id: String,
        source: Option<String>,
    ) -> PyResult<Self> {
        let dt = Self::new_typedef(id, name, size, alignment, base_type_id, source);
        if !dt.is_valid() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid typedef parameters",
            ));
        }
        Ok(dt)
    }

    fn __str__(&self) -> String {
        format!(
            "DataType(id={}, name={}, kind={:?}, size={})",
            self.id, self.name, self.kind, self.size
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "DataType(id={:?}, name={:?}, kind={:?}, size={}, alignment={:?})",
            self.id, self.name, self.kind, self.size, self.alignment
        )
    }

    fn __eq__(&self, other: &Self) -> bool {
        self == other
    }

    fn __hash__(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }

    // Property getters
    #[getter]
    fn get_id(&self) -> &str {
        &self.id
    }

    #[getter]
    fn get_name(&self) -> &str {
        &self.name
    }

    #[getter]
    fn get_kind(&self) -> DataTypeKind {
        self.kind.clone()
    }

    #[getter]
    fn get_size(&self) -> u64 {
        self.size
    }

    #[getter]
    fn get_alignment(&self) -> Option<u64> {
        self.alignment
    }

    #[getter]
    fn get_source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    // Methods
    fn is_valid_py(&self) -> bool {
        self.is_valid()
    }

    fn is_pointer_py(&self) -> bool {
        self.is_pointer()
    }

    fn is_array_py(&self) -> bool {
        self.is_array()
    }

    fn is_function_py(&self) -> bool {
        self.is_function()
    }

    fn is_composite_py(&self) -> bool {
        self.is_composite()
    }

    fn base_type_id_py(&self) -> Option<&str> {
        self.base_type_id()
    }

    fn return_type_py(&self) -> Option<&str> {
        self.return_type()
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(self)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }

    #[staticmethod]
    fn from_json(json_str: &str) -> PyResult<Self> {
        serde_json::from_str(json_str)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }
}

#[cfg(feature = "pyo3")]
#[pymethods]
impl DataTypeKind {
    fn __str__(&self) -> String {
        format!("{:?}", self)
    }

    fn __repr__(&self) -> String {
        format!("DataTypeKind.{:?}", self)
    }
}

#[cfg(feature = "pyo3")]
#[pymethods]
impl Field {
    #[new]
    fn new(name: String, type_id: String, offset: u64) -> Self {
        Self {
            name,
            type_id,
            offset,
        }
    }

    fn __str__(&self) -> String {
        format!(
            "Field(name={}, type_id={}, offset={})",
            self.name, self.type_id, self.offset
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "Field(name={:?}, type_id={:?}, offset={})",
            self.name, self.type_id, self.offset
        )
    }

    #[getter]
    fn get_name(&self) -> &str {
        &self.name
    }

    #[getter]
    fn get_type_id(&self) -> &str {
        &self.type_id
    }

    #[getter]
    fn get_offset(&self) -> u64 {
        self.offset
    }
}

#[cfg(feature = "pyo3")]
#[pymethods]
impl EnumMember {
    #[new]
    fn new(name: String, value: i64) -> Self {
        Self { name, value }
    }

    fn __str__(&self) -> String {
        format!("EnumMember(name={}, value={})", self.name, self.value)
    }

    fn __repr__(&self) -> String {
        format!("EnumMember(name={:?}, value={})", self.name, self.value)
    }

    #[getter]
    fn get_name(&self) -> &str {
        &self.name
    }

    #[getter]
    fn get_value(&self) -> i64 {
        self.value
    }
}
