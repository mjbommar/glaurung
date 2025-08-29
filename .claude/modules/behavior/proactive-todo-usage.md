---
id: proactive-todo-usage
name: Proactive Todo Usage
category: behavior
priority: 85
active: true
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