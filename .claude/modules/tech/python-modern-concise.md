---
id: python-modern-concise
name: Modern Python Development (Concise)
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
| Explore package | `dir(package)` | `uvx pyenvsearch toc package` | pyenvsearch gives structured view |
| Find class/method | Manual search | `uvx pyenvsearch class ClassName` | Semantic search is faster |
| Install library | `pip install requests` | `uv add requests` | It's a dependency |
| Install dev tool | `uv add --group dev ruff` | `uvx ruff` | It's a tool |
| Type check | `uvx mypy` | `uvx ty check` | Use ty, not mypy! |
| Format code | `uvx black .` | `uvx ruff format .` | Use ruff, not black! |
| Lint code | `uvx pylint` | `uvx ruff check .` | Use ruff, not pylint! |
| Run tests | `python -m pytest` | `uvx pytest` | Tool execution |

## Python Version Selection
```bash
uv python list          # See all available Python versions
uv python pin 3.13      # Pin to Python 3.13 (recommended - latest stable)
```

## Package Discovery & Exploration

### 🔍 Use pyenvsearch - Essential Tool for Package Navigation
```bash
uvx pyenvsearch find httpx          # Find where package is installed
uvx pyenvsearch toc fastapi         # Generate table of contents
uvx pyenvsearch summarize requests  # Get AI-powered overview
uvx pyenvsearch list-classes pandas # List all classes in package
uvx pyenvsearch search "async def" --package httpx
uvx pyenvsearch class HttpClient
uvx pyenvsearch method get --class HttpClient
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
uvx ty check                    # Check all files
uvx ruff format .               # Format all Python files
uvx ruff check .                # Lint all files
uvx ruff check --fix .          # Auto-fix issues
```

## Project Setup
```bash
uv init                 # Create new project
uv python pin 3.13      # Use latest Python
uv venv                 # Create virtual environment
```

## Testing
- Use `pytest` for testing
- Create real integration tests
- Never mock external dependencies without explicit approval
- Run: `uv run pytest`

## Best Practices
- **Explore before coding**: Use pyenvsearch to understand packages
- **Type hints for all functions**: Use `ty` to verify
- **Docstrings for public APIs**: Clear and concise
- **Follow PEP 8 style guide**: Use `ruff` for enforcement
- **Use pathlib for file operations**: Modern path handling
- **Prefer dataclasses/pydantic for data models**: Type-safe data