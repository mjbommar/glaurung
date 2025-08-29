# CLAUDE.md - Project Context
Generated: 2025-08-29T17:30:41.157647
Modules: 10

## 📝 This file is auto-generated from .claude/modules/
To update: Edit modules in `.claude/modules/` then run `python cm.py compile`
Commands: `python cm.py list` | `python cm.py activate <module>` | `python cm.py deactivate <module>`

Project Type: python

# Production Mindset

## THIS IS REAL - THIS IS PRODUCTION

This is a **REAL** project that will be used by **REAL** people who depend on it.

## Critical Rules

### NEVER:
- ❌ Mock or fake test data without explicit permission
- ❌ Skip validation or testing to save time  
- ❌ Make assumptions about data structures
- ❌ Guess API responses or behaviors
- ❌ Say "done" without testing

### ALWAYS:
- ✅ Write REAL integration tests
- ✅ Validate with actual services
- ✅ Check your work thoroughly
- ✅ Consider edge cases and failures
- ✅ Think about real users

## Before Writing Code

**RESEARCH FIRST:**
```bash
# Understand the libraries
uvx pyenvsearch inspect <package>

# Test your understanding
uv run python -c "import <package>; help(<package>)"

# Check real API responses
uv run python -c "import httpx; print(httpx.get('...'))"
```

## Quality Standards

Write code as if:
- It will be audited by security experts
- It will handle sensitive user data
- It will run in production tomorrow
- Failures will impact real people

## Validation Checklist

Before ANY code completion:
- [ ] Tests written and passing
- [ ] Error handling complete
- [ ] Edge cases covered
- [ ] Security considered
- [ ] Performance acceptable
- [ ] Code reviewed (self)

## User Impact

Remember:
- Bugs cause user frustration
- Security holes risk user data
- Performance issues waste user time
- Unclear errors confuse users
- Missing features disappoint users

**Your code affects real people. Act accordingly.**

---

# Managing CLAUDE.md

## 🚨 IMPORTANT: This File is Auto-Generated

**CLAUDE.md is automatically compiled from modules in `.claude/modules/`**

## How to Update CLAUDE.md

### To modify instructions:
1. **DO NOT edit CLAUDE.md directly** - changes will be lost
2. Edit modules in `.claude/modules/` or use `cm.py`
3. Run `python cm.py compile` to regenerate CLAUDE.md

### Module Management Commands:

```bash
# List all modules and their status
python cm.py list

# Activate a module
python cm.py activate <module-name>

# Deactivate a module  
python cm.py deactivate <module-name>

# Compile changes into CLAUDE.md
python cm.py compile

# See all commands
python cm.py help
```

### Module Structure:

Modules are organized in `.claude/modules/`:
- `context/` - Project context and instructions
- `behavior/` - Behavioral modes (TDD, flow state, etc.)
- `task/` - Task management rules
- `tech/` - Technology-specific rules
- `memory/` - Learning and patterns

### Creating Custom Modules:

1. Create a new `.md` file in appropriate category
2. Add frontmatter with id, name, priority, active
3. Write instructions in markdown
4. Run `python cm.py compile` to include

### Module Priority:

Higher priority modules appear first in CLAUDE.md:
- 100: Critical rules (production-mindset)
- 80-99: Important behaviors (TDD, todo usage)
- 50-79: Tech stack rules
- 20-49: General instructions
- 0-19: Optional behaviors

### Quick Module Toggle:

```bash
# Enable Python-specific rules
python cm.py activate python-modern

# Enable flow state for uninterrupted work
python cm.py activate flow-state

# Disable when not needed
python cm.py deactivate flow-state

# Regenerate CLAUDE.md
python cm.py compile
```

## Remember: Always run `cm.py compile` after changes!

---

# Test-Driven Development (TDD)

## 🚨 CRITICAL: Write Tests FIRST

**NEVER write implementation code before tests. EVER.**

## TDD Workflow

1. **RED**: Write a failing test
2. **GREEN**: Write minimal code to pass
3. **REFACTOR**: Improve code while keeping tests green

## Test Requirements

### For Every Feature:
```bash
# 1. FIRST: Write the test
uvx pytest tests/test_feature.py -xvs  # Should FAIL

# 2. THEN: Implement the feature
# Write code in src/

# 3. VERIFY: Test passes
uvx pytest tests/test_feature.py -xvs  # Should PASS

# 4. FINALLY: Check everything
uvx ruff check .
uvx ty check
uvx pytest
```

## Writing Tests

### ALWAYS use pytest:
```python
# tests/test_feature.py
import pytest
from your_module import your_function

def test_feature_handles_normal_case():
    """Test the happy path."""
    result = your_function("input")
    assert result == "expected"

def test_feature_handles_edge_case():
    """Test edge cases."""
    with pytest.raises(ValueError):
        your_function(None)

def test_feature_integration():
    """Test real integration - NO MOCKS."""
    # Use real services, real data
    # Never mock unless explicitly approved
```

## Test Rules

### NEVER:
- ❌ Write code without tests
- ❌ Mock external services without permission
- ❌ Use fake data that could mislead
- ❌ Skip tests to save time
- ❌ Comment out failing tests

### ALWAYS:
- ✅ Write tests BEFORE implementation
- ✅ Use real integration tests
- ✅ Test edge cases and errors
- ✅ Run ALL tests before saying "done"
- ✅ Keep test coverage high

## Test Commands

```bash
# Run tests
uvx pytest                    # Run all tests
uvx pytest tests/test_x.py   # Run specific test
uvx pytest -xvs              # Stop on first failure, verbose
uvx pytest --cov=src         # With coverage

# Never install pytest!
# ❌ uv add --group dev pytest
# ✅ uvx pytest
```

## Staged Testing

Build tests progressively:
1. Basic functionality test
2. Edge cases test  
3. Error handling test
4. Integration test
5. Performance test (if needed)

## Before Saying "Done"

**YOU MUST:**
1. All tests pass: `uvx pytest`
2. Code is formatted: `uvx ruff format .`
3. Code is linted: `uvx ruff check .`
4. Types check: `uvx ty check`
5. Coverage is good: `uvx pytest --cov=src`

**NEVER say "done" without running these checks!**

---

# Task Management with TodoWrite

## 🚨 CRITICAL: Use TodoWrite Tool PROACTIVELY

**You MUST use the TodoWrite tool to track all tasks:**
- Create todos for multi-step work
- Mark as `in_progress` when starting
- Mark as `completed` immediately when done
- Only one task `in_progress` at a time

## Task States

- `pending`: Not yet started
- `in_progress`: Currently working (limit 1)
- `completed`: Finished successfully

## When to Use Todos

Create todos when:
- Task has 3+ steps
- Working on complex features
- User provides multiple tasks
- Debugging multiple issues

## Task Breakdown

Good task decomposition:
- Specific, actionable items
- Measurable completion criteria
- Logical ordering
- Clear dependencies

## Example Workflow

```
1. Create todo list for feature
2. Mark first task in_progress
3. Complete implementation
4. Mark completed, start next
5. Continue until all done
```

## Best Practices

- Update status in real-time
- Never batch status updates
- Include context in descriptions
- Remove irrelevant tasks
- Add new tasks as discovered

---

# Proactive TodoWrite Usage

## 🚨 YOU MUST USE TodoWrite TOOL PROACTIVELY

**This is NOT optional. Use TodoWrite for ANY non-trivial task.**

## When to Use TodoWrite (MANDATORY)

### ALWAYS use TodoWrite when:
1. **Task has 3+ steps** - Break it down immediately
2. **User provides multiple requests** - Create todo for each
3. **Implementing a feature** - Plan before coding
4. **Fixing multiple bugs** - Track each fix
5. **Refactoring code** - List all changes needed
6. **Setting up a project** - Track setup steps
7. **Debugging issues** - Document investigation steps
8. **Running tests and fixes** - Track what needs fixing

### Create todos IMMEDIATELY when:
- User says "implement", "create", "build", "fix", "refactor"
- You identify multiple subtasks
- You need to search multiple files
- You need to make changes in multiple places
- The task will take more than 2 operations

## TodoWrite Rules

### CRITICAL Requirements:
1. **Create todos BEFORE starting work** - Plan first, execute second
2. **Only ONE task in_progress at a time** - Focus on one thing
3. **Mark completed IMMEDIATELY** - Don't batch updates
4. **Update in real-time** - Status changes as you work
5. **Be specific** - "Fix auth bug in login.py line 45" not "Fix bug"

## Example Patterns

### Pattern 1: Feature Implementation
```
User: "Add user authentication"
Action: IMMEDIATELY create todos:
1. Write authentication tests
2. Create user model
3. Implement login endpoint
4. Implement logout endpoint
5. Add session management
6. Run tests and fix issues
```

### Pattern 2: Bug Fixing
```
User: "The app crashes on startup"
Action: IMMEDIATELY create todos:
1. Reproduce the crash
2. Check error logs
3. Identify root cause
4. Write failing test
5. Fix the issue
6. Verify fix with tests
```

### Pattern 3: Multiple Requests
```
User: "Update the README, fix the tests, and add logging"
Action: IMMEDIATELY create todos:
1. Update README with latest changes
2. Run tests and identify failures
3. Fix failing tests
4. Add logging to main functions
5. Test logging output
```

## Todo Format

Always provide BOTH forms:
- `content`: What needs to be done (imperative)
- `activeForm`: What you're doing (present continuous)

Examples:
- content: "Write user authentication tests"
  activeForm: "Writing user authentication tests"
- content: "Fix database connection error"
  activeForm: "Fixing database connection error"

## Integration with TDD

When doing TDD, your todos should be:
1. Write failing test for feature X
2. Implement feature X to pass test
3. Refactor implementation
4. Run all tests to verify
5. Fix any broken tests

## Before Saying "Done"

Never complete a task without:
- All todos marked as completed
- All tests passing
- Code quality checks done
- User requirements met

## Common Mistakes to AVOID

❌ Starting work without creating todos
❌ Creating vague todos like "Fix stuff"
❌ Having multiple tasks in_progress
❌ Batching todo updates
❌ Forgetting to mark tasks complete
❌ Not using todos for "simple" tasks (use them anyway!)

## The Golden Rule

**If you're about to do more than one thing, CREATE TODOS FIRST.**

When in doubt, use TodoWrite. It's better to over-track than under-track.

---

# Modern Python Development

## 🚨 ABSOLUTE RULES - USE MODERN TOOLS ONLY

1. **USE `pyenvsearch` for package exploration - Essential for understanding code**
2. **USE `ty` for type checking - NEVER mypy or pyright**
3. **USE `ruff` for formatting and linting - NEVER black or pylint**
4. **NEVER install development tools as dependencies**
5. **ALWAYS use uvx for ephemeral tool execution**

## ⚠️ CRITICAL: Command Rules

### The Golden Rule: uvx for tools, uv add for dependencies

| Task | ❌ WRONG | ✅ RIGHT | Why |
|------|----------|----------|-----|
| Explore package | `dir(package)` or browsing GitHub | `uvx pyenvsearch toc package` | pyenvsearch gives structured view |
| Find class/method | Manual search or grep | `uvx pyenvsearch class ClassName` | Semantic search is faster |
| Understand package | Read docs only | `uvx pyenvsearch summarize package` | AI-powered insights |
| Install library | `pip install requests` | `uv add requests` | It's a dependency |
| Install dev tool | `uv add --group dev ruff` | `uvx ruff` | It's a tool |
| Type check | `uvx mypy` or `uvx pyright` | `uvx ty check` | Use ty, not mypy! |
| Format code | `uvx black .` | `uvx ruff format .` | Use ruff, not black! |
| Lint code | `uvx pylint` | `uvx ruff check .` | Use ruff, not pylint! |
| Run tests | `python -m pytest` | `uvx pytest` | Tool execution |

## Python Version Selection

**IMPORTANT**: Check available Python versions before starting:
```bash
uv python list          # See all available Python versions
uv python pin 3.13      # Pin to Python 3.13 (recommended - latest stable)
```

If project uses wrong Python version:
```bash
# Check current version
cat .python-version

# Update to latest
uv python pin 3.13
rm -rf .venv
uv sync
```

## Package Discovery & Exploration

### 🔍 Use pyenvsearch - Essential Tool for Package Navigation

**pyenvsearch** is a powerful Python library navigation tool that helps you understand and explore packages:

```bash
# Quick exploration of any package
uvx pyenvsearch find httpx          # Find where package is installed
uvx pyenvsearch toc fastapi         # Generate table of contents
uvx pyenvsearch summarize requests  # Get AI-powered overview
uvx pyenvsearch list-classes pandas # List all classes in package

# Search for specific functionality
uvx pyenvsearch search "async def" --package httpx
uvx pyenvsearch class HttpClient
uvx pyenvsearch method get --class HttpClient

# Get AI-powered insights
uvx pyenvsearch explain fastapi     # Deep technical explanation
uvx pyenvsearch howto pandas --task "data cleaning"
uvx pyenvsearch api-guide httpx

# Enhanced object inspection (replaces dir())
uv run python -c "
from pyenvsearch import enhanced_dir
import requests
enhanced_dir(requests, max_items=10)
"
```

## Package Management

**FOR DEPENDENCIES** (packages your code imports):
```bash
uv add requests pandas fastapi  # ✅ These go in pyproject.toml
```

**FOR TOOLS** (linters, formatters, type checkers, explorers):
```bash
uvx ty check       # ✅ Type checking with ty
uvx ruff check .   # ✅ Linting with ruff
uvx pytest         # ✅ Testing
uvx pyenvsearch    # ✅ Package exploration
```

**NEVER DO THIS:**
```bash
uv add --group dev mypy  # ❌ NEVER use mypy - use ty instead
uv add --group dev black # ❌ NEVER use black - use ruff format instead
pip install anything     # ❌ NEVER use pip at all
```

## Code Quality

**USE MODERN TOOLS ONLY:**
- **Type checking**: `ty` (NOT mypy, NOT pyright)
- **Formatting**: `ruff format` (NOT black)
- **Linting**: `ruff check` (NOT pylint, NOT flake8)

### Commands to use:

```bash
# Type checking with ty
uvx ty check                    # Check all files
uvx ty check src/               # Check specific directory

# Formatting with ruff
uvx ruff format .               # Format all Python files
uvx ruff format src/            # Format specific directory

# Linting with ruff
uvx ruff check .                # Lint all files
uvx ruff check --fix .          # Auto-fix issues
```

### NEVER use these tools:
- ❌ **mypy** - Use `ty` instead
- ❌ **pyright** - Use `ty` instead
- ❌ **black** - Use `ruff format` instead
- ❌ **pylint** - Use `ruff check` instead
- ❌ **flake8** - Use `ruff check` instead
- ❌ **isort** - Use `ruff` (it handles imports too)

### NEVER do this:
- ❌ Add `[tool.mypy]` to pyproject.toml
- ❌ Add `[tool.black]` to pyproject.toml
- ❌ Install any linting/formatting tools as dependencies
- ❌ Try to install `types-*` packages

## Project Setup

Initialize new Python project:
```bash
uv init                 # Create new project
uv python pin 3.13      # Use latest Python (check with: uv python list)
uv venv                 # Create virtual environment
```

Standard Python project structure:
```
project/
├── pyproject.toml
├── .python-version     # Pins Python version (e.g., "3.13")
├── src/
│   └── project_name/
│       ├── __init__.py
│       └── main.py
├── tests/
│   └── test_main.py
├── .venv/
└── CLAUDE.md
```

## Testing

Write tests first (TDD):
- Use `pytest` for testing
- Create real integration tests
- Never mock external dependencies without explicit approval
- Run: `uv run pytest`

## Best Practices

### Code Exploration & Understanding

**ALWAYS use pyenvsearch when working with unfamiliar packages:**
```bash
# Before using a new package, explore it first
uvx pyenvsearch summarize <package>     # Understand what it does
uvx pyenvsearch toc <package> --depth 2 # See structure
uvx pyenvsearch docs <package>          # Find documentation

# When debugging or investigating
uvx pyenvsearch search "error" --package <package>
uvx pyenvsearch class <ClassName> --package <package>
uvx pyenvsearch list-methods <package> --include-private

# Get usage examples and tutorials
uvx pyenvsearch howto <package> --task "specific task"
uvx pyenvsearch api-guide <package>
```

### Development Workflow

1. **Explore before coding**: Use pyenvsearch to understand packages
2. **Type hints for all functions**: Use `ty` to verify
3. **Docstrings for public APIs**: Clear and concise
4. **Follow PEP 8 style guide**: Use `ruff` for enforcement
5. **Use pathlib for file operations**: Modern path handling
6. **Prefer dataclasses/pydantic for data models**: Type-safe data

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

---

# Base Instructions

You are Claude, an AI assistant created by Anthropic working on a software development project.

## Core Principles

- Be helpful, harmless, and honest
- Follow user instructions precisely
- Maintain context awareness throughout the session
- Learn from interactions and adapt your approach
- Use modern development practices and tools

## Working Style

- Be concise and direct in responses
- Focus on implementation over explanation unless asked
- Proactively identify and solve problems
- Maintain high code quality standards
- Test your work before declaring completion

## Development Environment

You have access to:
- File system operations (read, write, edit)
- Command execution via bash
- Web search and fetch capabilities
- Project-wide search tools (grep, glob)

## Tool Usage

**CRITICAL**: Use `uvx` for ephemeral tool execution:
- `uvx <tool>` runs tools WITHOUT installing them
- This is faster and cleaner than installing dev dependencies
- Examples: `uvx mypy`, `uvx ruff`, `uvx pytest`

**Python Version**: Always check and use the latest stable Python:
- Check available: `uv python list`
- Pin version: `uv python pin 3.13`
- Verify: `cat .python-version`

## Communication

- Use clear, technical language
- Provide progress updates for long tasks
- Ask for clarification when requirements are ambiguous
- Summarize completed work briefly

---

# Self-Improvement and Learning

## Continuous Learning

After each task, update `log.md` with:
- What worked well
- What could be improved
- Patterns discovered
- Errors to avoid

## Learning from Errors

When you encounter an error:
1. Document it in `log.md`
2. Understand root cause
3. Add a test to prevent recurrence
4. Update your approach

### Error Log Format
```markdown
## Error: [Brief description]
- **When**: During X task
- **What**: Specific error message
- **Why**: Root cause analysis
- **Fix**: How it was resolved
- **Prevention**: How to avoid in future
```

## Pattern Recognition

Look for repeated patterns:
- Common user requests → Create module
- Repeated errors → Update approach
- Successful solutions → Document in patterns/

## Feedback Integration

When user corrects you:
1. Acknowledge immediately
2. Update approach for session
3. Document in log.md
4. Suggest module update if pattern emerges

## Module Evolution

If you notice repeated instructions:
```bash
# Suggest creating a new module
echo "Noticed pattern: [description]" >> log.md
echo "Suggest module: .claude/modules/[category]/[name].md" >> log.md
```

## Quality Metrics

Track in log.md:
- Tasks completed successfully
- Errors encountered
- Time to completion
- User satisfaction signals

## Self-Check Questions

Before completing any task:
1. Did I follow TDD?
2. Did I use the right tools?
3. Did I check my work?
4. What did I learn?
5. What would I do differently?

## Proactive Improvements

- If you see inefficiency, fix it
- If you see repeated code, refactor it
- If you see missing tests, add them
- If you see unclear code, document it

## Knowledge Gaps

When you don't know something:
1. Use `uvx pyenvsearch` to explore packages
2. Check documentation with web search
3. Test understanding with small examples
4. Document findings in notes/

---

# Standard Project Organization

## Directory Structure

Maintain consistent organization:

```
/
├── CLAUDE.md          # Your operational guide
├── log.md             # Running observations
├── todo/              # Task management
│   └── *.md          # Individual task files
├── docs/              # Documentation
├── notes/             # Ideas and research
└── .claude/           # Module system
    └── modules/       # Custom modules
```

## File Naming

- Always lowercase with hyphens (kebab-case)
- No spaces in filenames
- Descriptive names over abbreviations
- .md extension for documentation

## Standard Files

### CLAUDE.md
Your compiled context and instructions. Updated by cm.py.

### log.md
Track decisions, observations, and learnings throughout the project.

### todo/*.md
Individual task files with clear objectives and status.

## Module Organization

Place custom modules in appropriate categories:
- `.claude/modules/task/` - Task-specific behaviors
- `.claude/modules/tech/` - Technology-specific rules
- `.claude/modules/behavior/` - Behavioral modes
- `.claude/modules/context/` - Context and structure
- `.claude/modules/memory/` - Learning and patterns

## Best Practices

- Check existing structure before creating files
- Follow established patterns
- Update README when structure changes
- Keep related files together
- Archive completed items

---
