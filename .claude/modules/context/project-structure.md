---
id: project-structure
name: Standard Project Structure
category: context
priority: 30
active: true
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