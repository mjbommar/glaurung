#!/usr/bin/env python3
"""
Claude Module Manager (cm) - Simplified standalone version
Can be run with just Python 3.11+ standard library for bootstrap,
then enhances itself with better tools when available.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set, Any

# Debug mode
DEBUG = os.environ.get('QUICK_CLAUDE_DEBUG', '').lower() in ('1', 'true', 'yes')

def debug(msg: str):
    """Print debug message if DEBUG is enabled"""
    if DEBUG:
        print(f"[DEBUG] {msg}", file=sys.stderr)

# Constants
MODULE_DIR = Path(".claude/modules")
CLAUDE_MD = Path("CLAUDE.md")
CONFIG_FILE = Path(".claude/config.yaml")
MODULES_REPO = "https://raw.githubusercontent.com/mjbommar/quick-claude/master/modules"

class SimpleModuleManager:
    """Minimal module manager that works with stdlib only"""
    
    def __init__(self):
        debug("SimpleModuleManager.__init__() called")
        self.modules = {}
        self.config = self.load_config()
        debug(f"Config loaded: {self.config}")
    
    def load_config(self) -> dict:
        """Load or create default config"""
        if CONFIG_FILE.exists():
            # Simple YAML parsing for bootstrap
            config = {}
            with open(CONFIG_FILE) as f:
                for line in f:
                    if ':' in line and not line.strip().startswith('#'):
                        key, val = line.split(':', 1)
                        config[key.strip()] = val.strip()
            return config
        return {
            "auto_compile": "true",
            "max_size": "5000",
            "project_type": "auto"
        }
    
    def init(self, auto_compile=True):
        """Initialize Claude module system"""
        debug("Starting init()")
        print("🚀 Initializing Claude Module System...")
        
        # Create directory structure
        dirs = [
            ".claude/modules/task",
            ".claude/modules/tech", 
            ".claude/modules/behavior",
            ".claude/modules/context",
            ".claude/modules/memory",
        ]
        
        debug(f"Creating {len(dirs)} directories")
        for dir_path in dirs:
            Path(dir_path).mkdir(parents=True, exist_ok=True)
            debug(f"Created {dir_path}")
        
        # Create default config
        if not CONFIG_FILE.exists():
            CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            CONFIG_FILE.write_text("""# Claude Module System Configuration
auto_compile: true
max_size: 5000
project_type: auto
""")
        
        # Download essential modules
        self.download_essential_modules()
        
        print("✅ Claude module system initialized!")
        
        # Auto-compile if requested
        if auto_compile:
            print("\n📦 Compiling initial CLAUDE.md...")
            self.compile()
        else:
            print("\nNext steps:")
            print("  1. Run 'python cm.py compile' to generate CLAUDE.md")
            print("  2. Run 'python cm.py list' to see available modules")
            print("  3. Add custom modules to .claude/modules/")
    
    def download_essential_modules(self):
        """Download essential modules from repository"""
        debug("Starting download_essential_modules()")
        essential_modules = [
            ("context", "base-instructions"),
            ("context", "claude-md-management"),
            ("context", "production-mindset"),
            ("context", "project-structure"),
            ("behavior", "test-driven-development"),
            ("behavior", "self-improvement"),
            ("behavior", "proactive-todo-usage"),
            ("task", "todo-management"),
            ("tech", "python-modern"),
        ]
        
        for category, module_name in essential_modules:
            module_path = MODULE_DIR / category / f"{module_name}.md"
            debug(f"Checking {module_path}")
            if not module_path.exists():
                # Try to download from repo, fallback to creating default
                try:
                    import urllib.request
                    import urllib.error
                    url = f"{MODULES_REPO}/{category}/{module_name}.md"
                    debug(f"Downloading from {url}")
                    response = urllib.request.urlopen(url, timeout=3)
                    content = response.read().decode('utf-8')
                    module_path.parent.mkdir(parents=True, exist_ok=True)
                    module_path.write_text(content)
                    print(f"  ✓ Downloaded {category}/{module_name}")
                except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
                    # Fallback to creating default module
                    debug(f"Download failed for {category}/{module_name}: {e}")
                    print(f"  ⚠ Could not download {category}/{module_name} (using default)")
                    self.create_default_module(module_path, module_name, category)
                except Exception as e:
                    debug(f"Unexpected error for {category}/{module_name}: {e}")
                    print(f"  ⚠ Error with {category}/{module_name}: {e}")
                    self.create_default_module(module_path, module_name, category)
            else:
                debug(f"Module already exists: {module_path}")
    
    def create_default_module(self, path: Path, name: str, category: str):
        """Create a default module file"""
        path.parent.mkdir(parents=True, exist_ok=True)
        
        if name == "base-instructions":
            content = """---
id: base-instructions
name: Base Instructions
category: context
priority: 50
active: true
---

# Base Instructions

You are Claude, an AI assistant created by Anthropic.

## Core Principles
- Be helpful, harmless, and honest
- Follow user instructions precisely
- Maintain context awareness
- Use modern development practices
"""
        elif name == "project-structure":
            content = """---
id: project-structure
name: Project Structure
category: context
priority: 30
active: true
---

# Project Organization

Maintain clean project structure:
- Use .claude/ for module system
- Keep CLAUDE.md updated
- Document decisions in log.md
- Track tasks in todo/
"""
        elif name == "flow-state":
            content = """---
id: flow-state
name: Flow State Mode
category: behavior
priority: 7
active: false
---

# Flow State Mode

When activated, prioritize uninterrupted progress.
Make reasonable assumptions and batch operations.
"""
        elif name == "test-driven-development":
            content = """---
id: test-driven-development
name: Test-Driven Development
category: behavior
priority: 95
active: true
---

# Test-Driven Development

## Write Tests FIRST

Always write tests before implementation:
1. Write failing test
2. Write code to pass
3. Refactor

Use `uvx pytest` for testing.
"""
        elif name == "production-mindset":
            content = """---
id: production-mindset
name: Production Mindset
category: context
priority: 100
active: true
---

# Production Mindset

This is REAL code for REAL users.
- Never mock without permission
- Always validate thoroughly
- Consider security and performance
"""
        elif name == "self-improvement":
            content = """---
id: self-improvement
name: Self-Improvement
category: behavior
priority: 40
active: true
---

# Self-Improvement

Learn from each task:
- Document in log.md
- Recognize patterns
- Improve approach
"""
        elif name == "claude-md-management":
            content = """---
id: claude-md-management
name: CLAUDE.md Management
category: context
priority: 99
active: true
---

# Managing CLAUDE.md

## This file is auto-generated!

To update CLAUDE.md:
1. Edit modules in .claude/modules/
2. Run: python cm.py compile

Commands:
- python cm.py list
- python cm.py activate <module>
- python cm.py deactivate <module>
- python cm.py compile
"""
        elif name == "todo-management":
            content = """---
id: todo-management
name: Todo Management
category: task
priority: 90
active: true
---

# Task Management with TodoWrite

## 🚨 CRITICAL: Use TodoWrite Tool PROACTIVELY

**You MUST use the TodoWrite tool to track all tasks:**
- Create todos for multi-step work
- Mark as `in_progress` when starting
- Mark as `completed` immediately when done
- Only one task `in_progress` at a time
"""
        elif name == "proactive-todo-usage":
            content = """---
id: proactive-todo-usage
name: Proactive Todo Usage
category: behavior
priority: 85
active: true
---

# Proactive TodoWrite Usage

## YOU MUST USE TodoWrite TOOL PROACTIVELY

Use TodoWrite for ANY non-trivial task.
- Task has 3+ steps
- User provides multiple requests
- Implementing a feature
- Fixing multiple bugs
"""
        elif name == "python-modern":
            content = """---
id: python-modern
name: Modern Python Development
category: tech
priority: 80
active: false
---

# Modern Python Development

## Package Management
- Use `uv add <package>` for dependencies
- Use `uvx <tool>` for development tools
- Never use pip or pip3

## Tools
- Type check: `uvx mypy <files>`
- Format: `uvx ruff format <files>`
- Lint: `uvx ruff check --fix <files>`
"""
        else:
            content = f"""---
id: {name}
name: {name.replace('-', ' ').title()}
category: {category}
priority: 5
active: false
---

# {name.replace('-', ' ').title()}

Module content here.
"""
        
        path.write_text(content)
        print(f"  ✓ Created {category}/{name}")
    
    def compile(self, modules: Optional[List[str]] = None):
        """Compile modules into CLAUDE.md"""
        print("📦 Compiling CLAUDE.md...")
        
        # Load all modules
        all_modules = []
        if MODULE_DIR.exists():
            for module_file in MODULE_DIR.rglob("*.md"):
                content = module_file.read_text()
                if content.strip():
                    # Parse frontmatter
                    metadata = self.parse_frontmatter(content)
                    if metadata.get("active", True):
                        all_modules.append({
                            "path": module_file,
                            "content": content,
                            "metadata": metadata,
                            "priority": int(metadata.get("priority", 5))
                        })
        
        # Sort by priority
        all_modules.sort(key=lambda x: x["priority"], reverse=True)
        
        # Build CLAUDE.md
        output = [
            "# CLAUDE.md - Project Context",
            f"Generated: {datetime.now().isoformat()}",
            f"Modules: {len(all_modules)}",
            "",
            "## 📝 This file is auto-generated from .claude/modules/",
            "To update: Edit modules in `.claude/modules/` then run `python cm.py compile`",
            "Commands: `python cm.py list` | `python cm.py activate <module>` | `python cm.py deactivate <module>`",
            "",
        ]
        
        # Detect project type
        project_type = self.detect_project_type()
        if project_type:
            output.append(f"Project Type: {project_type}")
            output.append("")
        
        # Add modules
        for module in all_modules:
            # Skip frontmatter when adding content
            content = module["content"]
            if content.startswith("---"):
                parts = content.split("---", 2)
                if len(parts) >= 3:
                    content = parts[2].strip()
            
            output.append(content)
            output.append("")
            output.append("---")
            output.append("")
        
        # Write file
        CLAUDE_MD.write_text("\n".join(output))
        print(f"✅ Compiled {len(all_modules)} modules into CLAUDE.md")
    
    def parse_frontmatter(self, content: str) -> dict:
        """Simple frontmatter parser"""
        metadata = {}
        if content.startswith("---"):
            lines = content.split("\n")
            for line in lines[1:]:
                if line.strip() == "---":
                    break
                if ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip()
                    val = val.strip()
                    # Handle booleans
                    if val.lower() in ("true", "yes"):
                        val = True
                    elif val.lower() in ("false", "no"):
                        val = False
                    metadata[key] = val
        return metadata
    
    def detect_project_type(self) -> Optional[str]:
        """Detect project type from files"""
        if Path("package.json").exists():
            return "node"
        elif Path("pyproject.toml").exists() or Path("requirements.txt").exists():
            return "python"
        elif Path("Cargo.toml").exists():
            return "rust"
        elif Path("go.mod").exists():
            return "go"
        return None
    
    def list_modules(self):
        """List available modules"""
        print("\n📚 Available Modules:\n")
        
        if not MODULE_DIR.exists():
            print("No modules found. Run 'python cm.py init' first.")
            return
        
        modules_by_category = {}
        for module_file in MODULE_DIR.rglob("*.md"):
            category = module_file.parent.name
            if category not in modules_by_category:
                modules_by_category[category] = []
            
            content = module_file.read_text()
            metadata = self.parse_frontmatter(content)
            modules_by_category[category].append({
                "name": module_file.stem,
                "active": metadata.get("active", False),
                "priority": metadata.get("priority", 5)
            })
        
        for category, modules in sorted(modules_by_category.items()):
            print(f"  {category.upper()}:")
            for module in sorted(modules, key=lambda x: x["name"]):
                status = "✓" if module["active"] else "○"
                print(f"    {status} {module['name']} (priority: {module['priority']})")
        
        print("\n  ✓ = active, ○ = inactive")
        print("\nTo activate: python cm.py activate <module-name>")
        print("To compile: python cm.py compile")
    
    def activate(self, module_name: str):
        """Activate a module"""
        found = False
        for module_file in MODULE_DIR.rglob(f"*{module_name}*.md"):
            content = module_file.read_text()
            # Update active status
            content = re.sub(r'^active:\s*\w+', 'active: true', content, flags=re.MULTILINE)
            module_file.write_text(content)
            print(f"✓ Activated {module_file.stem}")
            found = True
        
        if not found:
            print(f"Module '{module_name}' not found")
        else:
            print("\nRun 'python cm.py compile' to update CLAUDE.md")
    
    def deactivate(self, module_name: str):
        """Deactivate a module"""
        found = False
        for module_file in MODULE_DIR.rglob(f"*{module_name}*.md"):
            content = module_file.read_text()
            content = re.sub(r'^active:\s*\w+', 'active: false', content, flags=re.MULTILINE)
            module_file.write_text(content)
            print(f"○ Deactivated {module_file.stem}")
            found = True
        
        if not found:
            print(f"Module '{module_name}' not found")
        else:
            print("\nRun 'python cm.py compile' to update CLAUDE.md")

def main():
    """Main entry point with simple CLI"""
    debug(f"main() called with args: {sys.argv}")
    try:
        manager = SimpleModuleManager()
    except Exception as e:
        debug(f"Failed to create SimpleModuleManager: {e}")
        print(f"Error initializing module manager: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Simple argument parsing
    args = sys.argv[1:]
    debug(f"Parsed args: {args}")
    
    if not args or args[0] in ("-h", "--help", "help"):
        print("""
Claude Module Manager (cm.py) - Simplified Version

Usage:
    python cm.py init              # Initialize module system
    python cm.py compile           # Compile CLAUDE.md
    python cm.py list              # List available modules
    python cm.py activate <name>   # Activate a module
    python cm.py deactivate <name> # Deactivate a module
    python cm.py help              # Show this help

For the full-featured version with rich UI, install dependencies:
    uv add click rich pyyaml gitpython
""")
    elif args[0] == "init":
        manager.init()
    elif args[0] == "compile":
        manager.compile()
    elif args[0] == "list":
        manager.list_modules()
    elif args[0] == "activate" and len(args) > 1:
        manager.activate(args[1])
    elif args[0] == "deactivate" and len(args) > 1:
        manager.deactivate(args[1])
    else:
        print(f"Unknown command: {args[0]}")
        print("Run 'python cm.py help' for usage")

if __name__ == "__main__":
    debug("Script started")
    # Try to use the enhanced version if available
    try:
        import click
        import rich
        # If we get here, use the full version from reference
        print("Note: Full version with rich UI available. Using simple version for bootstrap.")
        print("To use full version: uv run cm.py <command>")
        main()
    except ImportError:
        debug("Using simple version (no click/rich)")
        # Use simple version
        main()
    except Exception as e:
        debug(f"Fatal error: {e}")
        print(f"Fatal error: {e}", file=sys.stderr)
        import traceback
        if DEBUG:
            traceback.print_exc()
        sys.exit(1)