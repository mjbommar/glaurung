# PyO3 Separation Plan (Core vs Python Wrappers)

## Purpose
- Eliminate PyO3/GIL dependencies from core Rust logic and tests.
- Keep a single Python package built with Maturin, with `_native` module providing Python bindings over a pure-Rust core.
- Improve testability and reliability (no GIL panics in `cargo test`), and enable optional features for runtime pieces.

## Current Status (December 2024)

### ✅ Completed
- **PyO3 as optional dependency**: `pyo3` is gated behind `python-ext` feature in Cargo.toml
- **Core modules with pure methods**:
  - `artifact.rs`: Has `to_json_string()`, `from_json_str()`, `to_bincode()`, `from_bincode()`
  - `tool_metadata.rs`: Has `to_json_string()`, `from_json_str()`, `to_bincode()`, `from_bincode()`  
  - `binary.rs`: Has `to_json_string()`, `from_json_str()`
- **Tests updated**: Binary and artifact tests use pure methods

### 🔄 In Progress
- **Triage models**: Need pure constructors (`TriageVerdict::try_new()`) and JSON methods
- **Register**: Missing pure `new()` constructor
- **PyO3 attribute gating**: Many files need fixing (see patterns below)
- **Field attribute gating**: `#[pyo3(get, set)]` needs proper feature gating

### ❌ TODO
- Create `src/py/` wrapper modules
- Audit remaining core files for proper gating
- Fix PyO3 trait bound errors in `segment.rs`, `string_literal.rs`

## Critical Patterns and Guidelines

### CORRECT PyO3 Attribute Gating

#### ❌ WRONG - This doesn't work:
```rust
#[cfg_attr(feature = "python-ext", pymethods)]
impl MyStruct {
    // This will cause compilation errors!
}
```

#### ✅ CORRECT - Use this pattern:
```rust
#[cfg(feature = "python-ext")]
#[pymethods]
impl MyStruct {
    // PyO3 methods here
}
```

### Field Attribute Gating

#### ❌ WRONG - Ungated field attributes:
```rust
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct MyStruct {
    #[pyo3(get, set)]  // This will fail without python-ext!
    pub field: String,
}
```

#### ✅ CORRECT - Gate the field attributes:
```rust
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct MyStruct {
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub field: String,
}
```

### Pure Rust Methods Pattern

Every type exposed to Python should have pure Rust methods that PyO3 methods delegate to:

```rust
impl MyType {
    /// Pure Rust constructor
    pub fn new(value: String) -> Result<Self, String> {
        // validation logic
        Ok(Self { value })
    }
    
    /// Pure Rust serialization
    pub fn to_json_string(&self) -> Result<String, GlaurungError> {
        serde_json::to_string(self)
            .map_err(|e| GlaurungError::Serialization(e.to_string()))
    }
}

#[cfg(feature = "python-ext")]
#[pymethods]
impl MyType {
    #[new]
    fn new_py(value: String) -> PyResult<Self> {
        Self::new(value)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))
    }
    
    fn to_json(&self) -> PyResult<String> {
        self.to_json_string()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }
}

Build/Feature Changes
- Cargo.toml
  - Make `pyo3` optional. Add feature to gate all Python exposure.
    - `[dependencies] pyo3 = { version = "0.25", optional = true }`
    - `[features] python-ext = ["pyo3", "pyo3/extension-module"]`
  - Ensure `crate-type = ["cdylib", "rlib"]` for testing and Python builds.
  - Gate optional runtime deps by features: `triage-core`, `triage-containers`, `triage-parsers-extra`, `triage-heuristics` (already scaffolded).
- pyproject.toml
  - `[tool.maturin] features = ["pyo3/extension-module", "python-ext", ...]` and `module-name = "glaurung._native"`.

Module Registration
- `src/lib.rs`
  - Gate the PyO3 imports and `#[pymodule] fn _native(...)` under `#[cfg(feature = "python-ext")]` (already done).
  - Only register wrappers (once separated). For now it registers core types directly; after split it should register wrapper classes.
  - Also gate `wrap_pyfunction!(crate::logging::...)` calls under `python-ext` (already implied if the whole module is gated).

Error Bridging
- `src/error.rs`
  - Good: `impl From<GlaurungError> for pyo3::PyErr` is gated under `#[cfg(feature = "python-ext")]`.
  - Keep core error type pure (using `thiserror`). Use this to standardize core Results.

## Common Errors and Solutions

### Error: "cannot find attribute `pymethods` in this scope"
**Cause**: Missing feature gate or incorrect gating pattern
**Solution**: Use proper feature gating:
```rust
#[cfg(feature = "python-ext")]
#[pymethods]
impl MyStruct { /* ... */ }
```

### Error: "the trait bound `&MyType: IntoPyCallbackOutput<'_, _>` is not satisfied"
**Cause**: PyO3 needs trait implementations for types returned from getters
**Solution**: Either clone the value or implement proper PyO3 traits:
```rust
#[getter]
fn my_field(&self) -> MyType {  // Return owned value
    self.my_field.clone()
}
```

### Error: "no function or associated item `new` found"
**Cause**: Missing pure Rust constructor that PyO3 methods can delegate to
**Solution**: Add a pure constructor:
```rust
impl MyType {
    pub fn new(value: String) -> Result<Self, String> {
        // validation and construction
    }
}
```

## File-by-File Change List

### High-priority (causing GIL/PyO3 in core tests)

- src/core/artifact.rs
  - Types: `Artifact` (#[pyclass])
  - PyO3 methods and constructs to change:
    - `#[pymethods]` block includes constructor `new(...) -> PyResult<Self>` and many accessors — keep as wrappers later.
    - Serialization methods returning `PyResult` and constructing `PyErr`:
      - `to_json(&self) -> PyResult<String>`
      - `from_json(json_str: &str) -> PyResult<Self>` (staticmethod)
      - `to_binary(&self) -> PyResult<Vec<u8>>`
      - `from_binary(data: Vec<u8>) -> PyResult<Self>` (staticmethod)
      - `data_as_json(&self) -> PyResult<String>`
      - `meta_as_json(&self) -> PyResult<Option<String>>`
  - Core changes:
    - Add pure Rust equivalents (or replace existing) that return `Result<_, String>` or `Result<_, GlaurungError>`:
      - `to_json_string(&self) -> Result<String>`
      - `from_json_str(json_str: &str) -> Result<Self>`
      - `to_bincode(&self) -> Result<Vec<u8>>`
      - `from_bincode(data: &[u8]) -> Result<Self>`
      - `data_to_json_string(&self) -> Result<String>`
      - `meta_to_json_string(&self) -> Result<Option<String>>`
    - Keep validation `validate() -> Result<(), String>` as is.
  - Wrapper changes (python-ext):
    - Expose `#[pyclass] PyArtifact` holding `inner: core::artifact::Artifact` or keep name `Artifact` but move to `src/py/artifact.rs`.
    - `#[pymethods]` map to/from Python types; translate core errors to `PyErr` using `impl From<GlaurungError> for PyErr`.
  - Test changes:
    - Update `core::artifact::tests::test_serialization` to call pure Rust methods.

- src/core/tool_metadata.rs
  - Types: `SourceKind` (#[pyclass]), `ToolMetadata` (#[pyclass])
  - PyO3 in core:
    - Serialization methods returning `PyResult` and constructing `PyErr`:
      - `to_json(&self) -> PyResult<String>`
      - `from_json(json_str: &str) -> PyResult<Self>`
      - `to_binary(&self) -> PyResult<Vec<u8>>`
      - `from_binary(data: Vec<u8>) -> PyResult<Self>`
  - Core changes:
    - Add/replace with pure Rust:
      - `to_json_string(&self) -> Result<String>`
      - `from_json_str(&str) -> Result<Self>`
      - `to_bincode(&self) -> Result<Vec<u8>>`
      - `from_bincode(&[u8]) -> Result<Self>`
  - Wrapper changes: Mirror patterns as for `Artifact`.
  - Test changes: Switch tests to pure Rust methods.

- src/core/binary.rs
  - Types: `Format`, `Arch`, `Endianness` (#[pyclass]), `Hashes` (#[pyclass]), `Binary` (#[pyclass])
  - PyO3 in core:
    - JSON helpers exist only as `to_json_py()/from_json_py()` returning `PyResult`.
  - Core changes:
    - Add pure Rust:
      - `to_json_string(&self) -> Result<String>`
      - `from_json_str(&str) -> Result<Self>`
    - Prefer bincode variants if needed: `to_bincode()/from_bincode()`.
  - Wrapper changes: Python-facing methods delegate to pure Rust.
  - Test changes: Update `core::binary::tests::test_binary_serialization` to use pure methods (not `_py()` ones).

- src/core/triage.rs (triage data models)
  - Types (#[pyclass]): `SnifferSource`, `TriageHint`, `TriageErrorKind`, `TriageError`, `ConfidenceSignal`, `ParserKind`, `ParserResult`, `EntropySummary`, `StringsSummary`, `PackerMatch`, `ContainerChild`, `Budgets`, `TriageVerdict`, `TriagedArtifact`.
  - PyO3 in core:
    - `TriageVerdict::new(...) -> PyResult<Self>` (validates bits and returns PyErr)
    - `TriagedArtifact::to_json(&self) -> PyResult<String>` and `from_json(&str) -> PyResult<Self>`
  - Core changes:
    - Make all constructors pure:
      - `TriageVerdict::try_new(...) -> Result<Self, GlaurungError>` (or `String`)
    - Replace JSON with pure:
      - `TriagedArtifact::to_json_string()` / `from_json_str()`
    - Keep #[pyclass] only in wrapper module; core types become plain `struct`s and `enum`s.
  - Wrapper changes: Python constructors wrap pure `try_new` and translate errors.
  - Test changes: Adapt triage model tests to pure methods.

Other core modules (generally OK or already staged for separation)
- src/core/address.rs
  - Pattern already correct: core methods are pure; Python methods are suffixed `_py` and only wrap core.
  - Keep this pattern and (eventually) move `#[pyclass]` and `#[pymethods]` definitions to wrapper module.
- src/core/address_range.rs, src/core/address_space.rs, src/core/segment.rs, src/core/section.rs,
  src/core/pattern.rs, src/core/relocation.rs, src/core/symbol.rs, src/core/instruction.rs,
  src/core/register.rs, src/core/basic_block.rs, src/core/disassembler.rs
  - Most have `#[pyclass]` and `#[pymethods]` in the same file. Audit each:
    - Ensure any fallible logic in core returns `Result<_, _>` (many do).
    - Move `#[pyclass]`/`#[pymethods]` to wrapper module in a second pass to fully decouple.

Runtime modules (triage)
- src/triage/* (io.rs, sniffers.rs, containers.rs, headers.rs, heuristics.rs, entropy.rs, packers.rs, parsers.rs, recurse.rs, score.rs, api.rs)
  - Pure Rust (no PyO3). Keep feature gating per module:
    - `sniffers.rs` under `triage-core` (infer/mime_guess)
    - `containers.rs`, `packers.rs` under `triage-containers`
    - `parsers.rs` under `triage-parsers-extra`
    - `heuristics.rs` under `triage-heuristics`

Logging and error modules
- src/logging.rs
  - Python exposure (`LogLevel`, `init_logging`, `log_message`) correctly gated with `#[cfg(feature = "python-ext")]`.
  - No change needed beyond keeping registration under the same gate in `src/lib.rs`.
- src/error.rs
  - Already gated conversion to `PyErr`; keep core `GlaurungError` pure.

Wrapper Module (new)
- Create a Python wrapper module tree (built only with `python-ext`):
  - `src/py/mod.rs` (pub mod artifact; pub mod tool_metadata; pub mod binary; pub mod triage; etc.)
  - `src/py/artifact.rs`: `#[pyclass] pub struct Artifact { inner: core::artifact::Artifact }` with `#[pymethods]` delegating to core.
  - Similar files for `tool_metadata`, `binary`, `triage` models, and later other core types.
  - Register wrapper classes in `#[pymodule] fn _native(...)` instead of core types directly.

Tests
- Rust unit tests
  - Update tests to call pure Rust serialization/deserialization methods (no `PyResult` in core).
  - Continue to avoid relying on `samples/` unless feature-gated or ignored.
- Rust integration tests
  - Keep as-is, importing core APIs via `glaurung::triage` and other pure modules.
- Python tests (pytest)
  - Keep coverage for wrapper surface (constructors, JSON round-trips, basic behavior). Already added `python/tests/test_triage_types.py`.

Migration Steps (incremental)
1) Cargo + lib.rs
   - Make `pyo3` optional, add `python-ext` feature, gate `#[pymodule]`. Done partially; finish import gating globally.
2) Artifact/ToolMetadata/Binary
   - Add pure `to_json_string`/`from_json_str`/`to_bincode`/`from_bincode`.
   - Update Rust tests to use pure methods.
   - Leave existing `#[pymethods]` wrappers temporarily (they can call the new pure methods internally) to minimize churn.
3) Triage models
   - Replace `PyResult` constructors with `try_new` in core; convert `to_json` to pure.
   - Update tests accordingly.
4) Optional: Move `#[pyclass]` for the above into `src/py/` wrapper module; register wrappers in `src/lib.rs`.
5) Longer term: Migrate remaining core `#[pyclass]`/`#[pymethods]` into wrappers following the Address pattern.

Notes/Edge Cases
- Keep PyO3-free codepaths for `cargo test` by disabling the `python-ext` feature by default.
- Ensure any `use pyo3::...` imports are under feature guards; otherwise CI may still link PyO3 during tests.
- Keep `.pyi` stubs in sync with wrapper methods/class names; no change to Python package name or import paths required.

Appendix: Quick Grep Summary (PyO3 hotspots)
- Core files with `#[pyclass]` and/or `#[pymethods]`:
  - artifact.rs, tool_metadata.rs, binary.rs, address.rs, address_range.rs, address_space.rs, section.rs, segment.rs,
    string_literal.rs, symbol.rs, instruction.rs, pattern.rs, relocation.rs, register.rs, basic_block.rs, disassembler.rs,
    triage.rs (data models).
- Core files returning `PyResult` for serialization (must be made pure):
  - artifact.rs (to/from JSON and binary; data/meta to_json), tool_metadata.rs (to/from JSON and binary), binary.rs (to_json_py/from_json_py only), triage.rs (TriagedArtifact to/from JSON; TriageVerdict new).
- PyO3 registration in lib.rs: gated `#[pymodule]` and submodule ‘triage’, plus logging functions.

Checklist
- [ ] Make pyo3 optional in Cargo.toml; add `python-ext` feature; gate imports.
- [ ] Add pure serialization methods to Artifact/ToolMetadata/Binary and switch tests.
- [ ] Update triage model constructors/JSON to pure; update tests.
- [ ] (Optional) Create `src/py/` and move wrappers for above types; adjust `#[pymodule]` registration accordingly.
- [ ] Audit remaining core modules and plan migration to wrappers as needed.
- [ ] Verify `cargo test` passes without `python-ext` and no GIL panics.
- [ ] Verify `maturin develop` works with features enabled; run pytest suite.
