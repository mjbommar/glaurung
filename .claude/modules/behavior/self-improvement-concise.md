---
id: self-improvement-concise
name: Self-Improvement and Learning (Concise)
category: behavior
priority: 40
active: true
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