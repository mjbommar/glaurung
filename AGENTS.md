# AGENTS.md - Glaurung Development Guide

## 🚨 CRITICAL: Read CLAUDE.md First
`CLAUDE.md` holds the project overview, build/test commands, and the LLM model
policy. It is hand-maintained — edit it directly.

## 🚨 DecBench: No Autonomous Upstream Actions

Per the DecBench collaborator's [AI-contribution rule](https://github.com/Noelo-Lab/decbench/issues/81#issuecomment-5486158431)
and README rules introduced in DecBench commit `b909596`:

- Agents must **never autonomously create or post DecBench issues, comments,
  or pull requests**, whether through the web UI, an API, `gh`, git, or another
  tool.
- A requested DecBench follow-up issue must be **written and submitted by the
  human**, not authored or posted end-to-end by an agent.
- Agents may inspect DecBench, run local evaluations, change Glaurung locally,
  and prepare internal evidence. They must stop before any upstream interaction
  and hand the evidence to the human.
- Direct user instructions do not waive the upstream project's rule. If asked
  to post, comment, open an issue, or create a PR, refuse that action and point
  the user to this boundary.

## Build Commands
- **Install/build from lockfile**: `uv sync --locked --dev`
- **Rebuild Rust extension**: `uv run maturin develop` (development) or `uv run maturin build --release` (wheel)

## Test Commands
- **All tests**: `uv run pytest python/tests/`
- **Single test**: `uv run pytest python/tests/test_address.py::TestAddressCreation::test_create_va_address -v`
- **With coverage**: `uv run --isolated --with pytest-cov pytest -p pytest_cov.plugin --cov=python/glaurung python/tests/`

## Lint & Format
- **Format Python**: `uvx ruff format python/`
- **Lint Python**: `uvx ruff check python/ --fix`
- **Type check**: `uvx ty check python/`

## TDD Workflow (MANDATORY)
1. **RED**: Write failing test first: `uv run pytest python/tests/test_feature.py -xvs`
2. **GREEN**: Write minimal code to pass
3. **REFACTOR**: Improve code while keeping tests green
4. **VERIFY**: Run full suite: `uv run pytest && uvx ruff check . && uvx ty check`

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
✅ All tests pass: `uv run pytest`
✅ Code formatted: `uvx ruff format .`
✅ Code linted: `uvx ruff check .`
✅ Types checked: `uvx ty check`
