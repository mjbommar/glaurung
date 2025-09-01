use crate::core::address::Address;
use crate::core::address_range::AddressRange;
use crate::core::basic_block::BasicBlock;
use crate::error::GlaurungError;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[cfg(feature = "python-ext")]
use pyo3::prelude::*;

/// Kind of function in binary analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub enum FunctionKind {
    /// Normal function defined in the binary
    Normal,
    /// Imported function from external library
    Imported,
    /// Exported function available to other modules
    Exported,
    /// Thunk function that jumps to another function
    Thunk,
    /// Library function (e.g., runtime library)
    Library,
    /// Unknown function type
    Unknown,
}

impl FunctionKind {
    pub fn value(&self) -> &str {
        match self {
            FunctionKind::Normal => "normal",
            FunctionKind::Imported => "imported",
            FunctionKind::Exported => "exported",
            FunctionKind::Thunk => "thunk",
            FunctionKind::Library => "library",
            FunctionKind::Unknown => "unknown",
        }
    }
}

/// Function flags as bitflags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FunctionFlags(u32);

impl FunctionFlags {
    pub const NONE: FunctionFlags = FunctionFlags(0);
    pub const NO_RETURN: FunctionFlags = FunctionFlags(1);
    pub const HAS_SEH: FunctionFlags = FunctionFlags(2);
    pub const HAS_EH: FunctionFlags = FunctionFlags(4);
    pub const IS_VARIADIC: FunctionFlags = FunctionFlags(8);
    pub const IS_INLINE: FunctionFlags = FunctionFlags(16);
    pub const IS_NAKED: FunctionFlags = FunctionFlags(32);
    pub const IS_CONSTRUCTOR: FunctionFlags = FunctionFlags(64);
    pub const IS_DESTRUCTOR: FunctionFlags = FunctionFlags(128);
}

impl std::ops::BitOr for FunctionFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        FunctionFlags(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for FunctionFlags {
    type Output = bool;

    fn bitand(self, rhs: Self) -> Self::Output {
        (self.0 & rhs.0) != 0
    }
}

/// Represents a function in binary analysis
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct Function {
    /// Function name
    pub name: String,

    /// Entry point address
    pub entry_point: Address,

    /// Function kind
    pub kind: FunctionKind,

    /// Address range of the function
    pub range: Option<AddressRange>,

    /// Function size in bytes
    pub size: Option<u64>,

    /// Function flags
    pub flags: FunctionFlags,

    /// Module name for imported functions
    pub module: Option<String>,

    /// Ordinal for exported functions
    pub ordinal: Option<u32>,

    /// Target address for thunk functions
    pub thunk_target: Option<Address>,

    /// Calling convention
    pub calling_convention: Option<String>,

    /// Function signature
    pub signature: Option<String>,

    /// Basic blocks in the function
    pub basic_blocks: Vec<BasicBlock>,

    /// Edges between basic blocks (from_addr, to_addr)
    pub edges: Vec<(Address, Address)>,

    /// Addresses of functions that call this function
    pub callers: HashSet<Address>,

    /// Addresses of functions called by this function
    pub callees: HashSet<Address>,

    /// Stack frame size
    pub stack_frame_size: Option<u64>,

    /// Local variables size
    pub local_vars_size: Option<u64>,

    /// Saved registers size
    pub saved_regs_size: Option<u64>,

    /// Maximum call depth
    pub max_call_depth: Option<u32>,
}

impl Function {
    /// Create a new function (pure Rust constructor)
    pub fn new(
        name: String,
        entry_point: Address,
        kind: FunctionKind,
    ) -> Result<Self, GlaurungError> {
        Ok(Function {
            name,
            entry_point,
            kind,
            range: None,
            size: None,
            flags: FunctionFlags::NONE,
            module: None,
            ordinal: None,
            thunk_target: None,
            calling_convention: None,
            signature: None,
            basic_blocks: Vec::new(),
            edges: Vec::new(),
            callers: HashSet::new(),
            callees: HashSet::new(),
            stack_frame_size: None,
            local_vars_size: None,
            saved_regs_size: None,
            max_call_depth: None,
        })
    }

    /// Create a new function with all parameters
    #[allow(clippy::too_many_arguments)]
    pub fn new_full(
        name: String,
        entry_point: Address,
        kind: FunctionKind,
        range: Option<AddressRange>,
        flags: FunctionFlags,
        module: Option<String>,
        ordinal: Option<u32>,
        thunk_target: Option<Address>,
        calling_convention: Option<String>,
        signature: Option<String>,
        stack_frame_size: Option<u64>,
        local_vars_size: Option<u64>,
        saved_regs_size: Option<u64>,
        max_call_depth: Option<u32>,
    ) -> Result<Self, GlaurungError> {
        // Validate thunk functions have a target
        if kind == FunctionKind::Thunk && thunk_target.is_none() {
            return Err(GlaurungError::InvalidInput(
                "Thunk functions must have a target".to_string(),
            ));
        }

        let size = range.as_ref().map(|r| r.size);

        Ok(Function {
            name,
            entry_point,
            kind,
            range,
            size,
            flags,
            module,
            ordinal,
            thunk_target,
            calling_convention,
            signature,
            basic_blocks: Vec::new(),
            edges: Vec::new(),
            callers: HashSet::new(),
            callees: HashSet::new(),
            stack_frame_size,
            local_vars_size,
            saved_regs_size,
            max_call_depth,
        })
    }

    /// Add a basic block to the function
    pub fn add_basic_block(&mut self, block: BasicBlock) {
        self.basic_blocks.push(block);
    }

    /// Add an edge between basic blocks
    pub fn add_edge(&mut self, from: Address, to: Address) {
        self.edges.push((from, to));
    }

    /// Add a caller address
    pub fn add_caller(&mut self, caller: Address) {
        self.callers.insert(caller);
    }

    /// Add a callee address
    pub fn add_callee(&mut self, callee: Address) {
        self.callees.insert(callee);
    }

    /// Check if function has a specific flag
    pub fn has_flag(&self, flag: FunctionFlags) -> bool {
        self.flags & flag
    }

    /// Add a flag
    pub fn add_flag(&mut self, flag: FunctionFlags) {
        self.flags = FunctionFlags(self.flags.0 | flag.0);
    }

    /// Remove a flag
    pub fn remove_flag(&mut self, flag: FunctionFlags) {
        self.flags = FunctionFlags(self.flags.0 & !flag.0);
    }

    /// Calculate function size from basic blocks
    pub fn calculate_size(&self) -> u64 {
        if let Some(size) = self.size {
            return size;
        }

        if self.basic_blocks.is_empty() {
            return 0;
        }

        // Find the maximum end address
        let mut max_end = 0u64;
        let min_start = self.entry_point.value;

        for block in &self.basic_blocks {
            let block_end = block.end_address.value;
            if block_end > max_end {
                max_end = block_end;
            }
        }

        max_end - min_start
    }

    /// Calculate cyclomatic complexity
    pub fn cyclomatic_complexity(&self) -> u32 {
        // M = E - N + 2P
        // Where E = edges, N = nodes, P = connected components (usually 1)
        let edges = self.edges.len() as u32;
        let nodes = self.basic_blocks.len() as u32;

        if nodes == 0 {
            return 0;
        }

        // For a single function, P = 1
        edges.saturating_sub(nodes).saturating_add(2)
    }

    /// Serialize to JSON string
    pub fn to_json_string(&self) -> Result<String, GlaurungError> {
        serde_json::to_string(self).map_err(|e| GlaurungError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON string
    pub fn from_json_str(json_str: &str) -> Result<Self, GlaurungError> {
        serde_json::from_str(json_str).map_err(|e| GlaurungError::Serialization(e.to_string()))
    }

    /// Serialize to binary
    pub fn to_bincode(&self) -> Result<Vec<u8>, GlaurungError> {
        bincode::serialize(self).map_err(|e| GlaurungError::Serialization(e.to_string()))
    }

    /// Deserialize from binary
    pub fn from_bincode(data: &[u8]) -> Result<Self, GlaurungError> {
        bincode::deserialize(data).map_err(|e| GlaurungError::Serialization(e.to_string()))
    }
}

// PyO3 bindings
#[cfg(feature = "python-ext")]
#[pymethods]
impl Function {
    #[new]
    #[pyo3(signature = (name, entry_point, kind, range=None, flags=None, module=None, ordinal=None, thunk_target=None, calling_convention=None, signature=None, stack_frame_size=None, local_vars_size=None, saved_regs_size=None, max_call_depth=None))]
    fn new_py(
        name: String,
        entry_point: Address,
        kind: FunctionKind,
        range: Option<AddressRange>,
        flags: Option<u32>,
        module: Option<String>,
        ordinal: Option<u32>,
        thunk_target: Option<Address>,
        calling_convention: Option<String>,
        signature: Option<String>,
        stack_frame_size: Option<u64>,
        local_vars_size: Option<u64>,
        saved_regs_size: Option<u64>,
        max_call_depth: Option<u32>,
    ) -> PyResult<Self> {
        let flags = flags.map(FunctionFlags).unwrap_or(FunctionFlags::NONE);

        Self::new_full(
            name,
            entry_point,
            kind,
            range,
            flags,
            module,
            ordinal,
            thunk_target,
            calling_convention,
            signature,
            stack_frame_size,
            local_vars_size,
            saved_regs_size,
            max_call_depth,
        )
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }

    fn __repr__(&self) -> String {
        format!(
            "Function(name='{}', entry_point={:#x}, kind={:?})",
            self.name, self.entry_point.value, self.kind
        )
    }

    fn __str__(&self) -> String {
        format!("{}@{:#x}", self.name, self.entry_point.value)
    }

    // Getters
    #[getter]
    fn name(&self) -> String {
        self.name.clone()
    }

    #[setter]
    fn set_name(&mut self, value: String) {
        self.name = value;
    }

    #[getter]
    fn entry_point(&self) -> Address {
        self.entry_point.clone()
    }

    #[setter]
    fn set_entry_point(&mut self, value: Address) {
        self.entry_point = value;
    }

    #[getter]
    fn kind(&self) -> FunctionKind {
        self.kind
    }

    #[setter]
    fn set_kind(&mut self, value: FunctionKind) {
        self.kind = value;
    }

    #[getter]
    fn range(&self) -> Option<AddressRange> {
        self.range.clone()
    }

    #[setter]
    fn set_range(&mut self, value: Option<AddressRange>) {
        self.range = value.clone();
        if let Some(r) = &self.range {
            self.size = Some(r.size);
        }
    }

    #[getter]
    fn size(&self) -> Option<u64> {
        self.size
    }

    #[setter]
    fn set_size(&mut self, value: Option<u64>) {
        self.size = value;
    }

    #[getter]
    fn flags(&self) -> u32 {
        self.flags.0
    }

    #[setter]
    fn set_flags(&mut self, value: u32) {
        self.flags = FunctionFlags(value);
    }

    #[getter]
    fn module(&self) -> Option<String> {
        self.module.clone()
    }

    #[setter]
    fn set_module(&mut self, value: Option<String>) {
        self.module = value;
    }

    #[getter]
    fn ordinal(&self) -> Option<u32> {
        self.ordinal
    }

    #[setter]
    fn set_ordinal(&mut self, value: Option<u32>) {
        self.ordinal = value;
    }

    #[getter]
    fn thunk_target(&self) -> Option<Address> {
        self.thunk_target.clone()
    }

    #[setter]
    fn set_thunk_target(&mut self, value: Option<Address>) {
        self.thunk_target = value;
    }

    #[getter]
    fn calling_convention(&self) -> Option<String> {
        self.calling_convention.clone()
    }

    #[setter]
    fn set_calling_convention(&mut self, value: Option<String>) {
        self.calling_convention = value;
    }

    #[getter]
    fn signature(&self) -> Option<String> {
        self.signature.clone()
    }

    #[setter]
    fn set_signature(&mut self, value: Option<String>) {
        self.signature = value;
    }

    #[getter]
    fn stack_frame_size(&self) -> Option<u64> {
        self.stack_frame_size
    }

    #[setter]
    fn set_stack_frame_size(&mut self, value: Option<u64>) {
        self.stack_frame_size = value;
    }

    #[getter]
    fn local_vars_size(&self) -> Option<u64> {
        self.local_vars_size
    }

    #[setter]
    fn set_local_vars_size(&mut self, value: Option<u64>) {
        self.local_vars_size = value;
    }

    #[getter]
    fn saved_regs_size(&self) -> Option<u64> {
        self.saved_regs_size
    }

    #[setter]
    fn set_saved_regs_size(&mut self, value: Option<u64>) {
        self.saved_regs_size = value;
    }

    #[getter]
    fn max_call_depth(&self) -> Option<u32> {
        self.max_call_depth
    }

    #[setter]
    fn set_max_call_depth(&mut self, value: Option<u32>) {
        self.max_call_depth = value;
    }

    #[pyo3(name = "add_basic_block")]
    fn add_basic_block_py(&mut self, block: BasicBlock) {
        self.add_basic_block(block);
    }

    #[pyo3(name = "add_edge")]
    fn add_edge_py(&mut self, from: Address, to: Address) {
        self.add_edge(from, to);
    }

    #[pyo3(name = "add_caller")]
    fn add_caller_py(&mut self, caller: Address) {
        self.add_caller(caller);
    }

    #[pyo3(name = "add_callee")]
    fn add_callee_py(&mut self, callee: Address) {
        self.add_callee(callee);
    }

    #[pyo3(name = "has_flag")]
    fn has_flag_py(&self, flag: u32) -> bool {
        self.has_flag(FunctionFlags(flag))
    }

    #[pyo3(name = "add_flag")]
    fn add_flag_py(&mut self, flag: u32) {
        self.add_flag(FunctionFlags(flag));
    }

    #[pyo3(name = "remove_flag")]
    fn remove_flag_py(&mut self, flag: u32) {
        self.remove_flag(FunctionFlags(flag));
    }

    #[pyo3(name = "calculate_size")]
    fn calculate_size_py(&self) -> u64 {
        self.calculate_size()
    }

    #[pyo3(name = "cyclomatic_complexity")]
    fn cyclomatic_complexity_py(&self) -> u32 {
        self.cyclomatic_complexity()
    }

    #[getter]
    fn basic_blocks(&self) -> Vec<BasicBlock> {
        self.basic_blocks.clone()
    }

    #[getter]
    fn callers(&self) -> Vec<Address> {
        self.callers.iter().cloned().collect()
    }

    #[getter]
    fn callees(&self) -> Vec<Address> {
        self.callees.iter().cloned().collect()
    }

    #[pyo3(name = "to_json")]
    fn to_json_py(&self) -> PyResult<String> {
        self.to_json_string()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }

    #[staticmethod]
    #[pyo3(name = "from_json")]
    fn from_json_py(json_str: &str) -> PyResult<Self> {
        Self::from_json_str(json_str)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }

    #[pyo3(name = "to_binary")]
    fn to_binary_py(&self) -> PyResult<Vec<u8>> {
        self.to_bincode()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }

    #[staticmethod]
    #[pyo3(name = "from_binary")]
    fn from_binary_py(data: Vec<u8>) -> PyResult<Self> {
        Self::from_bincode(&data)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }
}

// PyO3 bindings for FunctionKind
#[cfg(feature = "python-ext")]
#[pymethods]
impl FunctionKind {
    // Make value a property that uses the existing value() method
    #[getter(value)]
    fn get_value(&self) -> String {
        // Use the existing value() method from the main impl
        self.value().to_string()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self == other
    }

    fn __hash__(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }

    fn __str__(&self) -> String {
        self.value().to_string()
    }

    fn __repr__(&self) -> String {
        format!(
            "FunctionKind.{}",
            match self {
                FunctionKind::Normal => "Normal",
                FunctionKind::Imported => "Imported",
                FunctionKind::Exported => "Exported",
                FunctionKind::Thunk => "Thunk",
                FunctionKind::Library => "Library",
                FunctionKind::Unknown => "Unknown",
            }
        )
    }
}

// PyO3 class for FunctionFlags
#[cfg(feature = "python-ext")]
#[pyclass]
#[derive(Debug, Clone, Copy)]
pub struct FunctionFlagsPy;

#[cfg(feature = "python-ext")]
#[pymethods]
impl FunctionFlagsPy {
    #[classattr]
    const NONE: u32 = 0;
    #[classattr]
    const NO_RETURN: u32 = 1;
    #[classattr]
    const HAS_SEH: u32 = 2;
    #[classattr]
    const HAS_EH: u32 = 4;
    #[classattr]
    const IS_VARIADIC: u32 = 8;
    #[classattr]
    const IS_INLINE: u32 = 16;
    #[classattr]
    const IS_NAKED: u32 = 32;
    #[classattr]
    const IS_CONSTRUCTOR: u32 = 64;
    #[classattr]
    const IS_DESTRUCTOR: u32 = 128;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::AddressKind;

    #[test]
    fn test_function_creation() {
        let entry = Address::new(AddressKind::VA, 0x401000, 32, None, None).unwrap();

        let func =
            Function::new("test_func".to_string(), entry.clone(), FunctionKind::Normal).unwrap();

        assert_eq!(func.name, "test_func");
        assert_eq!(func.entry_point, entry);
        assert_eq!(func.kind, FunctionKind::Normal);
    }

    #[test]
    fn test_thunk_validation() {
        let entry = Address::new(AddressKind::VA, 0x401000, 32, None, None).unwrap();

        // Should fail without target
        let result = Function::new_full(
            "thunk".to_string(),
            entry,
            FunctionKind::Thunk,
            None,
            FunctionFlags::NONE,
            None,
            None,
            None, // No target
            None,
            None,
            None,
            None,
            None,
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_function_flags() {
        let flags = FunctionFlags::NO_RETURN | FunctionFlags::HAS_SEH;
        assert!(flags & FunctionFlags::NO_RETURN);
        assert!(flags & FunctionFlags::HAS_SEH);
        assert!(!(flags & FunctionFlags::IS_VARIADIC));
    }

    #[test]
    fn test_json_serialization() {
        let entry = Address::new(AddressKind::VA, 0x401000, 32, None, None).unwrap();

        let func =
            Function::new("test_func".to_string(), entry.clone(), FunctionKind::Normal).unwrap();

        let json = func.to_json_string().unwrap();
        let func2 = Function::from_json_str(&json).unwrap();

        assert_eq!(func.name, func2.name);
        assert_eq!(func.entry_point, entry);
        assert_eq!(func.kind, func2.kind);
    }
}
