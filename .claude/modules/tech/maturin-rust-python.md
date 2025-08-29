---
id: maturin-rust-python
name: Maturin Rust-Python Integration
category: tech
priority: 75
active: true
---

# Maturin - Building Python Extensions with Rust

This document outlines how to use Maturin to build Python packages with Rust.

## Project Setup

- Create a Rust library project:
  ```bash
  cargo new --lib --edition 2021 <project-name>
  ```
- Alternative quick start:
  ```bash
  maturin new -b pyo3 <project-name>
  ```
- For mixed Rust/Python projects:
  ```bash
  maturin new --mixed --bindings pyo3 <project-name>
  ```

## Project Layout Options

### Pure Rust Layout
```
my-rust-project/
├── Cargo.toml
├── pyproject.toml
└── src/
    └── lib.rs
```

### Mixed Rust/Python Layout (Option 1)
```
my-project/
├── Cargo.toml
├── my_project/
│   ├── __init__.py
│   └── bar.py
├── pyproject.toml
└── src/lib.rs
```

### Mixed Rust/Python Layout (Option 2)
```
my-project/
├── src/my_project/
│   ├── __init__.py
│   └── bar.py
├── pyproject.toml
└── rust/
    ├── Cargo.toml
    └── src/lib.rs
```

You can customize the Python source directory in `pyproject.toml`:

```toml
[tool.maturin]
python-source = "python"
module-name = "my_module"
```

## Configuration Files

### Cargo.toml

Ensure your `Cargo.toml` has the necessary dependencies and metadata:

```toml
[package]
name = "your-package-name"
version = "0.1.0"
edition = "2021"
description = "A short description"
readme = "README.md"
license = "MIT OR Apache-2.0"  # SPDX license expression
repository = "https://github.com/yourusername/your-repo"
keywords = ["python", "extension"]
authors = ["Your Name <your.email@example.com>"]
homepage = "https://your-project-homepage.com"

[lib]
name = "your_module_name"
crate-type = ["cdylib"]

[dependencies]
pyo3 = { version = "0.19.0", features = ["extension-module"] }
```

### pyproject.toml

Configure Python packaging with metadata:

```toml
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

# Full PEP 621 metadata specification
[project]
name = "your-package-name"
version = "0.1.0"  # Or use dynamic = ["version"] to get from Cargo.toml
description = "A short description of your package"
authors = [
    {name = "Your Name", email = "your.email@example.com"}
]
readme = "README.md"
requires-python = ">=3.7"
license = {text = "MIT OR Apache-2.0"}
classifiers = [
    "Programming Language :: Rust",
    "Programming Language :: Python :: Implementation :: CPython",
    "Programming Language :: Python :: Implementation :: PyPy",
    "Programming Language :: Python :: 3.7",
    "License :: OSI Approved :: MIT License",
]
dependencies = [
    "numpy>=1.24.0",
    "pandas~=2.0.0",
]

# Create console scripts (CLI entry points)
[project.scripts]
your-command = "your_package_name:main_function"

# Define URL mapping for project
[project.urls]
Homepage = "https://github.com/yourusername/your-repo"
Documentation = "https://your-repo.readthedocs.io/"
"Bug Tracker" = "https://github.com/yourusername/your-repo/issues"

# Maturin-specific configuration
[tool.maturin]
# Python source directory (for mixed Python/Rust projects)
python-source = "python"
# Override module name if it differs from package name
module-name = "your_module_name"
# Binding type: "pyo3", "cffi", "uniffi", or "bin"
bindings = "pyo3"
# Set Rust build profile
profile = "release"
# Include specific Rust features
features = ["some-feature", "another-feature"]
# Control wheel compatibility on Linux
compatibility = "manylinux2014"
# Strip debug symbols to reduce binary size
strip = true
# Include/exclude specific files
include = ["path/to/include/**/*"]
exclude = ["path/to/exclude/**/*"]
# Pass additional arguments to rustc
rustc-args = ["--cfg=feature=\"some-feature\""]
```

## Virtual Environment Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip maturin
```

## Local Development

Maturin provides several commands to streamline local development:

### Development Installation

For quick development and testing, use `maturin develop`:

```bash
# Basic development install
maturin develop

# With UV package manager integration
maturin develop --uv

# With specific features
maturin develop --features feature1,feature2

# Install in release mode
maturin develop --release
```

### Editable Installs (PEP 660)

Maturin supports editable installs that allow Python code changes without recompilation:

```bash
# Using pip
pip install -e .

# Using maturin directly
maturin develop

# Using UV
uv pip install -e .
```

### Benefits of Development Mode

- Quick debug builds for faster iteration
- Automatic detection of Python environment
- Immediate reflection of Python code changes
- Optionally install project dependencies
- Support for multiple binding types

### Skip Installation

To build without installing (useful for debugging):

```bash
maturin develop --release --no-pip-install
```

## Binding Options

Maturin supports multiple binding types to interface Rust with Python:

### 1. PyO3 Bindings (Default)
- Supports CPython, PyPy, and GraalPy
- Automatically detected when added as a dependency
- Offers `Py_LIMITED_API`/abi3 support for cross-Python compatibility
- Good cross-compilation capabilities

### 2. CFFI Bindings
- Compatible with all Python versions, including PyPy
- Requires manual specification with `-b cffi` or in `pyproject.toml`
- Uses cbindgen to generate header files
- Exposes `ffi` and `lib` objects for Python interaction

### 3. Binary Bindings
- Packages Rust binaries as Python scripts
- Requires manual specification
- Best practice: Expose CLI functions in library instead of shipping separate binary

### 4. UniFFI Bindings
- Generates Python `ctypes` bindings
- Compatible with all Python versions, including PyPy

Specify binding type in `pyproject.toml`:
```toml
[tool.maturin]
bindings = "pyo3" # or "cffi", "uniffi", "bin"
```

## Exposing Rust to Python with PyO3

PyO3 provides several macros and types to expose Rust code to Python:

### 1. Exposing Functions

Use the `#[pyfunction]` attribute to expose Rust functions to Python:

```rust
use pyo3::prelude::*;

#[pyfunction]
fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
    Ok((a + b).to_string())
}

// In the module definition:
#[pymodule]
fn your_module_name(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    Ok(())
}
```

### 2. Exposing Classes and Structs

Use the `#[pyclass]` attribute to expose Rust structs as Python classes:

```rust
#[pyclass]
struct MyClass {
    #[pyo3(get, set)]
    value: i32,
    internal_value: String,
}

#[pymethods]
impl MyClass {
    #[new]
    fn new(value: i32) -> Self {
        MyClass {
            value,
            internal_value: String::from("hidden"),
        }
    }

    fn get_internal(&self) -> PyResult<String> {
        Ok(self.internal_value.clone())
    }

    fn set_internal(&mut self, value: String) -> PyResult<()> {
        self.internal_value = value;
        Ok(())
    }

    fn calculate(&self, multiplier: i32) -> PyResult<i32> {
        Ok(self.value * multiplier)
    }

    // Class method (no self)
    #[classmethod]
    fn create_default(_cls: &PyType) -> PyResult<Self> {
        Ok(MyClass {
            value: 42,
            internal_value: String::from("default"),
        })
    }

    // Static method (no self or cls)
    #[staticmethod]
    fn help() -> PyResult<String> {
        Ok(String::from("This is a helpful message"))
    }
}

// In the module definition:
#[pymodule]
fn your_module_name(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<MyClass>()?;
    Ok(())
}
```

### 3. Defining Python Modules

Use the `#[pymodule]` attribute to define a Python module:

```rust
#[pymodule]
fn your_module_name(py: Python, m: &PyModule) -> PyResult<()> {
    // Add functions
    m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    
    // Add classes
    m.add_class::<MyClass>()?;
    
    // Add constants
    m.add("VERSION", "1.0.0")?;
    m.add("PI", 3.14159)?;
    
    // Add submodules
    let submodule = PyModule::new(py, "submodule")?;
    submodule.add_function(wrap_pyfunction!(another_function, submodule)?)?;
    m.add_submodule(submodule)?;
    
    Ok(())
}
```

### 4. Working with Python Types

PyO3 provides wrappers for Python types:

```rust
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyTuple};

#[pyfunction]
fn process_dict(py: Python, input: &PyDict) -> PyResult<PyObject> {
    let result = PyDict::new(py);
    for (key, value) in input.iter() {
        result.set_item(key, value)?;
    }
    Ok(result.into())
}

#[pyfunction]
fn create_list(py: Python, items: Vec<i32>) -> PyResult<PyObject> {
    let list = PyList::new(py, &items);
    Ok(list.into())
}
```

### 5. Error Handling

Use `PyResult` for error handling:

```rust
use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyTypeError};

#[pyfunction]
fn divide(a: f64, b: f64) -> PyResult<f64> {
    if b == 0.0 {
        Err(PyValueError::new_err("Cannot divide by zero"))
    } else {
        Ok(a / b)
    }
}

#[pyfunction]
fn process_value(value: &PyAny) -> PyResult<i32> {
    if let Ok(int_val) = value.extract::<i32>() {
        Ok(int_val)
    } else {
        Err(PyTypeError::new_err("Expected an integer"))
    }
}
```

### 6. The Complete Module Setup

Here's a complete example showing a typical Rust module exposing functions and classes to Python:

```rust
use pyo3::prelude::*;
use pyo3::types::PyDict;

// Function with docstring
/// Adds two numbers and returns the result as a string
/// 
/// Args:
///     a: First number to add
///     b: Second number to add
/// 
/// Returns:
///     String representation of the sum
#[pyfunction]
#[pyo3(text_signature = "(a, b)")]
fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
    Ok((a + b).to_string())
}

// Simple class with docstring
/// A simple class example
/// 
/// Attributes:
///     value: An integer value
#[pyclass]
#[pyo3(text_signature = "(value=0)")]
struct Calculator {
    #[pyo3(get, set)]
    value: i32,
}

#[pymethods]
impl Calculator {
    #[new]
    #[pyo3(text_signature = "(value=0)")]
    fn new(value: Option<i32>) -> Self {
        Calculator {
            value: value.unwrap_or(0),
        }
    }

    /// Add a value to the current value
    /// 
    /// Args:
    ///     x: Value to add
    /// 
    /// Returns:
    ///     The result after addition
    #[pyo3(text_signature = "(x)")]
    fn add(&mut self, x: i32) -> PyResult<i32> {
        self.value += x;
        Ok(self.value)
    }

    /// Multiply the current value
    /// 
    /// Args:
    ///     x: Value to multiply by
    /// 
    /// Returns:
    ///     The result after multiplication
    #[pyo3(text_signature = "(x)")]
    fn multiply(&mut self, x: i32) -> PyResult<i32> {
        self.value *= x;
        Ok(self.value)
    }

    /// Reset the calculator to a specific value
    /// 
    /// Args:
    ///     value: Value to reset to (default: 0)
    #[pyo3(text_signature = "(value=0)")]
    fn reset(&mut self, value: Option<i32>) -> PyResult<()> {
        self.value = value.unwrap_or(0);
        Ok(())
    }

    /// Create a calculator with a preset value
    /// 
    /// Args:
    ///     value: The preset value
    /// 
    /// Returns:
    ///     A new Calculator instance
    #[classmethod]
    #[pyo3(text_signature = "(cls, value)")]
    fn with_value(cls: &PyType, value: i32) -> PyResult<Py<Self>> {
        Py::new(cls.py(), Self { value })
    }
}

// Define the Python module with docstring
/// A sample module demonstrating PyO3 functionality
/// 
/// This module contains various utilities for demonstration purposes.
#[pymodule]
fn your_module_name(py: Python, m: &PyModule) -> PyResult<()> {
    // Add module-level documentation
    m.add("__doc__", "A sample module demonstrating PyO3 functionality")?;
    
    // Add functions
    m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    
    // Add classes
    m.add_class::<Calculator>()?;
    
    // Add constants
    m.add("VERSION", "1.0.0")?;
    
    // Create a utility function dictionary
    let utils = PyDict::new(py);
    utils.set_item("name", "utils")?;
    utils.set_item("description", "Utility functions and constants")?;
    m.add("UTILS", utils)?;
    
    Ok(())
}
```

## Type Annotations with .pyi Files

To provide proper type hints for Python IDEs and type checkers, create `.pyi` stub files:

### Basic Structure

Create a file with the same name as your module but with a `.pyi` extension:

```python
# your_module_name.pyi
from typing import Dict, List, Optional, Tuple, Union, Any

def sum_as_string(a: int, b: int) -> str:
    """
    Adds two numbers and returns the result as a string.
    
    Args:
        a: First number to add
        b: Second number to add
    
    Returns:
        String representation of the sum
    """
    ...

class Calculator:
    """
    A simple class example.
    
    Attributes:
        value: An integer value
    """
    value: int
    
    def __init__(self, value: int = 0) -> None:
        """
        Initialize a new Calculator.
        
        Args:
            value: Initial value
        """
        ...
    
    def add(self, x: int) -> int:
        """
        Add a value to the current value.
        
        Args:
            x: Value to add
        
        Returns:
            The result after addition
        """
        ...
    
    def multiply(self, x: int) -> int:
        """
        Multiply the current value.
        
        Args:
            x: Value to multiply by
        
        Returns:
            The result after multiplication
        """
        ...
    
    def reset(self, value: int = 0) -> None:
        """
        Reset the calculator to a specific value.
        
        Args:
            value: Value to reset to (default: 0)
        """
        ...
    
    @classmethod
    def with_value(cls, value: int) -> "Calculator":
        """
        Create a calculator with a preset value.
        
        Args:
            value: The preset value
        
        Returns:
            A new Calculator instance
        """
        ...

# Module constants
VERSION: str
UTILS: Dict[str, str]
```

### Enabling Type Checking

To enable type checking, add a `py.typed` marker file to your package:

```
your_package/
├── __init__.py
├── __init__.pyi  # Type stubs
├── py.typed     # Empty marker file
└── ...
```

Then update your `pyproject.toml` to include it:

```toml
[tool.maturin]
include = ["your_package/py.typed"]
```

## Package Metadata

Maturin supports two approaches for package metadata:

### 1. Full PEP 621 Specification
Define complete metadata in `pyproject.toml` under `[project]` section as shown above.

### 2. Dynamic Metadata from Cargo.toml
When `[project]` section is minimal or absent, Maturin will extract metadata from `Cargo.toml`:

```toml
[project]
name = "your-package-name"
requires-python = ">=3.7"
dynamic = ["version", "description", "classifiers"]
```

Fields that can be extracted from Cargo.toml:
- version
- description
- license
- authors
- keywords (converted to classifiers)
- homepage

## Required Metadata Fields

At minimum, your package should include these metadata fields:

### In Cargo.toml
```toml
[package]
name = "your-package-name"  # Required
version = "0.1.0"           # Required
edition = "2021"            # Required
description = "..."         # Strongly recommended
license = "..."             # Strongly recommended
```

### In pyproject.toml
```toml
[build-system]
requires = ["maturin>=1.0,<2.0"]  # Required
build-backend = "maturin"          # Required

[project]
name = "your-package-name"        # Required
requires-python = ">=3.8"         # Strongly recommended
```

## Command Line Interface

Define console scripts in pyproject.toml to create command-line tools:

```toml
[project.scripts]
your-command = "your_package_name:main_function"
your-other-cmd = "your_package_name.cli:entry_point"
```

Implement the entry point in your Python code:

```python
# your_package_name/cli.py
def entry_point():
    """Main entry point for the command line tool."""
    print("Hello from the CLI!")
    
if __name__ == "__main__":
    entry_point()
```

## Distribution

### Building Wheels

```bash
# Basic wheel build
maturin build

# Release mode build
maturin build --release

# Build with specific features
maturin build --release --features feature1,feature2

# Build with UV integration
maturin build --uv

# Cross-compilation for different target
maturin build --target aarch64-unknown-linux-gnu

# Include source distribution
maturin build --sdist
```

### Platform Compatibility

Maturin handles platform tags for wheels automatically:

- **Linux**: Uses manylinux2014 (default) for broad compatibility
  ```bash
  # Specify compatibility level
  maturin build --compatibility manylinux2014
  
  # For Alpine Linux and musl-based systems
  maturin build --compatibility musllinux_1_1
  
  # Use platform-specific tag
  maturin build --compatibility linux
  ```

- **macOS**: Creates universal2 wheels for Intel and Apple Silicon
  ```bash
  # Specify macOS deployment target
  MACOSX_DEPLOYMENT_TARGET=10.13 maturin build
  ```

- **Windows**: Creates wheels for current architecture
  ```bash
  # Cross-compilation requires additional setup
  maturin build --target x86_64-pc-windows-msvc
  ```

### Publishing to PyPI

```bash
# Build and upload to PyPI
maturin publish

# Using UV
maturin publish --uv

# Upload to test PyPI
maturin publish --repository testpypi

# Publish with token
MATURIN_PYPI_TOKEN=pypi-TOKEN maturin publish
```

### GitHub Actions Integration

Generate CI workflows for automated builds:

```bash
maturin generate-ci github
```

## Environment Variables

Maturin can be controlled through several environment variables:

### Python Environment Variables
- `VIRTUAL_ENV`: Specify Python virtual environment path
- `CONDA_PREFIX`: Set conda environment path
- `MATURIN_PYPI_TOKEN`: PyPI token for wheel uploads
- `MATURIN_PASSWORD`: PyPI password for wheel uploads

### PyO3 Environment Variables
- `PYO3_CROSS_PYTHON_VERSION`: Specify Python version for cross compilation
- `PYO3_CROSS_LIB_DIR`: Set directory for target's Python libraries
- `PYO3_CONFIG_FILE`: Path to PyO3 configuration file

### Platform-Specific Variables
- `MACOSX_DEPLOYMENT_TARGET`: Minimum macOS version
- `SOURCE_DATE_EPOCH`: Set timestamp for wheel metadata
- `ARCHFLAGS`: Control build architecture (e.g., universal2 wheels)

### Network Variables
- `HTTP_PROXY` / `HTTPS_PROXY`: Configure network proxy
- `REQUESTS_CA_BUNDLE`: Set CA bundle for HTTPS requests

## Using with UV Package Manager

Maturin offers integration with UV, a fast Python package installer:

```bash
# Development install with UV
maturin develop --uv

# Build and install with UV
maturin build --uv

# Publishing with UV
maturin publish --uv
```

Benefits of UV integration:
- Faster dependency resolution
- Improved installation performance
- Better compatibility with modern Python packaging standards

## Target-Specific Configuration

Configure options for specific build targets:

```toml
[tool.maturin.target.x86_64-apple-darwin]
macos-deployment-target = "10.13"

[tool.maturin.target.aarch64-apple-darwin]
macos-deployment-target = "11.0"
```

## Best Practices

- **Module Organization**:
  - Keep your public API clean and focused
  - Use submodules for organizing related functionality
  - Separate implementation details from public interfaces

- **Type Safety**:
  - Provide comprehensive `.pyi` type stubs for better IDE integration
  - Use `PyResult<T>` for all functions that can fail
  - Include detailed error messages with appropriate exception types

- **Documentation**:
  - Add docstrings to all public functions, classes, and methods
  - Include examples in docstrings where appropriate
  - Use `text_signature` to show parameter lists in Python help()

- **Performance**:
  - Minimize Python/Rust transitions for performance-critical code
  - For large datasets, process them in Rust and return only results
  - Use batch processing where possible for multiple items

- **Testing**:
  - Include both Rust tests and Python tests
  - Test the Python API as your users will use it
  - Consider using pytest for Python testing

- **Compatibility**:
  - Enable `abi3` for cross-Python version wheels
  - Set appropriate `requires-python` version in `pyproject.toml`
  - Test on multiple Python versions

## Key Considerations

- Use `abi3` feature for cross-Python version compatibility
- Configure minimum Python version in `pyproject.toml`
- Wheels contain platform-specific compiled binaries
- Maturin supports multiple Python implementations (CPython, PyPy)
- Add `.pyi` stubs for better type hints
- Use data directories with `<module_name>.data` folder for non-code files
- Strip binaries for reduced wheel size with `strip = true`
- Use `--sdist` option when building to include source distribution
- For Linux distribution, ensure at least manylinux2014 compatibility
- Consider using Docker or Zig for cross-compilation
- Use GitHub Actions with `maturin generate-ci` for automated builds

## Importing the Module

After installation, import your module:

```python
import your_module_name

result = your_module_name.sum_as_string(5, 7)
print(result)  # Outputs: "12"
```

For more details, visit the [Maturin website](https://www.maturin.rs/).