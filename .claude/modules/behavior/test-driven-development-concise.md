---
id: test-driven-development-concise
name: Test-Driven Development (Concise)
category: behavior
priority: 95
active: true
triggers:
  keywords:
    - test
    - pytest
    - TDD
    - feature
    - implement
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

## Before Saying "Done"

**YOU MUST:**
1. All tests pass: `uvx pytest`
2. Code is formatted: `uvx ruff format .`
3. Code is linted: `uvx ruff check .`
4. Types check: `uvx ty check`
5. Coverage is good: `uvx pytest --cov=src`

**NEVER say "done" without running these checks!**