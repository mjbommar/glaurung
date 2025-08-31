---
id: maturin-rust-python-concise
name: Maturin Rust-Python Integration (Concise)
category: tech
priority: 75
active: false
---

# Maturin - Building Python Extensions with Rust

## Project Setup
```bash
cargo new --lib --edition 2021 <project-name>
maturin new -b pyo3 <project-name>
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

### Mixed Rust/Python Layout
```
my-project/
├── Cargo.toml
├── my_project/
│   ├── __init__.py
│   └── bar.py
├── pyproject.toml
└── src/lib.rs
```

## Configuration Files

### Cargo.toml
```toml
[package]
name = "your-package-name"
version = "0.1.0"
edition = "2021"
description = "A short description"
license = "MIT OR Apache-2.0"
repository = "https://github.com/yourusername/your-repo"

[lib]
name = "your_module_name"
crate-type = ["cdylib"]

[dependencies]
pyo3 = { version = "0.19.0", features = ["extension-module"] }
```

### pyproject.toml
```toml
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[project]
name = "your-package-name"
version = "0.1.0"
description = "A short description of your package"
requires-python = ">=3.7"
dependencies = ["numpy>=1.24.0", "pandas~=2.0.0"]

[tool.maturin]
python-source = "python"
module-name = "your_module_name"
bindings = "pyo3"
profile = "release"
strip = true
```

## Virtual Environment Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip maturin
```

## Development Installation
```bash
maturin develop
maturin develop --release
maturin develop --features feature1,feature2
```

## Exposing Rust to Python with PyO3

### Functions
```rust
use pyo3::prelude::*;

#[pyfunction]
fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
    Ok((a + b).to_string())
}

#[pymodule]
fn your_module_name(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    Ok(())
}
```

### Classes
```rust
#[pyclass]
struct MyClass {
    #[pyo3(get, set)]
    value: i32,
}

#[pymethods]
impl MyClass {
    #[new]
    fn new(value: i32) -> Self {
        MyClass { value }
    }

    fn calculate(&self, multiplier: i32) -> PyResult<i32> {
        Ok(self.value * multiplier)
    }
}
```

## Building Wheels
```bash
maturin build
maturin build --release
maturin build --release --features feature1,feature2
maturin build --target aarch64-unknown-linux-gnu
```

## Publishing to PyPI
```bash
maturin publish
maturin publish --repository testpypi
MATURIN_PYPI_TOKEN=pypi-TOKEN maturin publish
```

## Key Considerations
- Use `abi3` feature for cross-Python version compatibility
- Configure minimum Python version in `pyproject.toml`
- Wheels contain platform-specific compiled binaries
- Maturin supports multiple Python implementations (CPython, PyPy)
- Add `.pyi` stubs for better type hints
- Use data directories with `<module_name>.data` folder for non-code files
- Strip binaries for reduced wheel size with `strip = true`
- For Linux distribution, ensure at least manylinux2014 compatibility
- Consider using Docker or Zig for cross-compilation
- Use GitHub Actions with `maturin generate-ci` for automated builds