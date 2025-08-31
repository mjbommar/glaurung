# AGENTS.md - Glaurung Development Guide

## 🚨 CRITICAL: Read CLAUDE.md First
This file contains essential project context. Run `python cm.py compile` to update it.

## Build Commands
- **Build Rust extension**: `maturin develop` (development) or `maturin build --release` (production)
- **Install Python deps**: `uv sync`
- **Full build**: `maturin develop && uv sync`

## Test Commands
- **All tests**: `uvx pytest python/tests/`
- **Single test**: `uvx pytest python/tests/test_address.py::TestAddressCreation::test_create_va_address -v`
- **With coverage**: `uvx pytest --cov=python/glaurung python/tests/`

## Lint & Format
- **Format Python**: `uvx ruff format python/`
- **Lint Python**: `uvx ruff check python/ --fix`
- **Type check**: `uvx ty check python/`

## TDD Workflow (MANDATORY)
1. **RED**: Write failing test first: `uvx pytest tests/test_feature.py -xvs`
2. **GREEN**: Write minimal code to pass
3. **REFACTOR**: Improve code while keeping tests green
4. **VERIFY**: Run full suite: `uvx pytest && uvx ruff check . && uvx ty check`

## Code Style Guidelines

### Python
- **Imports**: Standard library → third-party → local. Absolute imports only.
- **Types**: Type hints for ALL parameters/returns. Use `typing` module.
- **Naming**: snake_case functions/vars, PascalCase classes, UPPER_CASE constants.
- **Error handling**: Specific exceptions only, never bare `except:`.
- **Docstrings**: Google-style for all public functions.

### Rust
- **Naming**: snake_case functions/vars, PascalCase types/structs.
- **Error handling**: `Result<T, E>` with `?`, avoid `.unwrap()`.
- **Documentation**: `///` for public items, `//!` for modules.
- **Safety**: Safe Rust preferred, `unsafe` only with justification.

### General Rules
- **NEVER**: Mock data without permission, skip validation, guess APIs
- **ALWAYS**: Real integration tests, validate inputs, consider security
- **TDD**: Tests BEFORE code. Never implement without tests.
- **Security**: Never log sensitive data, validate all inputs
- **Performance**: Profile before optimizing, document critical sections

## CLAUDE.md Management

### 🚨 IMPORTANT: CLAUDE.md is Auto-Generated
**CLAUDE.md is automatically compiled from modules in `.claude/modules/`**

### How to Update CLAUDE.md
1. **DO NOT edit CLAUDE.md directly** - changes will be lost
2. Edit modules in `.claude/modules/` or use `cm.py`
3. Run `python cm.py compile` to regenerate CLAUDE.md

### Module Management Commands
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

### Module Structure
Modules are organized in `.claude/modules/`:
- `context/` - Project context and instructions
- `behavior/` - Behavioral modes (TDD, flow state, etc.)
- `task/` - Task management rules
- `tech/` - Technology-specific rules
- `memory/` - Learning and patterns

### Creating Custom Modules
1. Create a new `.md` file in appropriate category
2. Add frontmatter with id, name, priority, active
3. Write instructions in markdown
4. Run `python cm.py compile` to include

### Module Priority
Higher priority modules appear first in CLAUDE.md:
- 100: Critical rules (production-mindset)
- 80-99: Important behaviors (TDD, todo usage)
- 50-79: Tech stack rules
- 20-49: General instructions
- 0-19: Optional behaviors

## Production Mindset

### THIS IS REAL - THIS IS PRODUCTION
This is a **REAL** project that will be used by **REAL** people who depend on it.

### Critical Rules

#### NEVER:
- ❌ Mock or fake test data without explicit permission
- ❌ Skip validation or testing to save time
- ❌ Make assumptions about data structures
- ❌ Guess API responses or behaviors
- ❌ Say "done" without testing

#### ALWAYS:
- ✅ Write REAL integration tests
- ✅ Validate with actual services
- ✅ Check your work thoroughly
- ✅ Consider edge cases and failures
- ✅ Think about real users

### Validation Checklist
Before ANY code completion:
- [ ] Tests written and passing
- [ ] Error handling complete
- [ ] Edge cases covered
- [ ] Security considered
- [ ] Performance acceptable
- [ ] Code reviewed (self)

### User Impact
Remember:
- Bugs cause user frustration
- Security holes risk user data
- Performance issues waste user time
- Unclear errors confuse users
- Missing features disappoint users
**Your code affects real people. Act accordingly.**

## Before Saying "Done"
✅ All tests pass: `uvx pytest`
✅ Code formatted: `uvx ruff format .`
✅ Code linted: `uvx ruff check .`
✅ Types checked: `uvx ty check`
✅ CLAUDE.md guidelines followed
