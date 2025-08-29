---
id: production-mindset
name: Production Mindset
category: context
priority: 100
active: true
---

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