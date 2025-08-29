---
id: python-modern
name: Modern Python Development
category: tech
priority: 80
active: true
triggers:
  file_patterns:
    - "*.py"
    - "pyproject.toml"
    - "requirements.txt"
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