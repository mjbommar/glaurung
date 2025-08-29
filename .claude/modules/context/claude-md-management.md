---
id: claude-md-management
name: CLAUDE.md Management
category: context
priority: 99
active: true
---

# Managing CLAUDE.md

## 🚨 IMPORTANT: This File is Auto-Generated

**CLAUDE.md is automatically compiled from modules in `.claude/modules/`**

## How to Update CLAUDE.md

### To modify instructions:
1. **DO NOT edit CLAUDE.md directly** - changes will be lost
2. Edit modules in `.claude/modules/` or use `cm.py`
3. Run `python cm.py compile` to regenerate CLAUDE.md

### Module Management Commands:

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

### Module Structure:

Modules are organized in `.claude/modules/`:
- `context/` - Project context and instructions
- `behavior/` - Behavioral modes (TDD, flow state, etc.)
- `task/` - Task management rules
- `tech/` - Technology-specific rules
- `memory/` - Learning and patterns

### Creating Custom Modules:

1. Create a new `.md` file in appropriate category
2. Add frontmatter with id, name, priority, active
3. Write instructions in markdown
4. Run `python cm.py compile` to include

### Module Priority:

Higher priority modules appear first in CLAUDE.md:
- 100: Critical rules (production-mindset)
- 80-99: Important behaviors (TDD, todo usage)
- 50-79: Tech stack rules
- 20-49: General instructions
- 0-19: Optional behaviors

### Quick Module Toggle:

```bash
# Enable Python-specific rules
python cm.py activate python-modern

# Enable flow state for uninterrupted work
python cm.py activate flow-state

# Disable when not needed
python cm.py deactivate flow-state

# Regenerate CLAUDE.md
python cm.py compile
```

## Remember: Always run `cm.py compile` after changes!