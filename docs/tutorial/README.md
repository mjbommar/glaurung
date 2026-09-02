# Glaurung tutorial

> **Kind:** guide · **Status:** maintained

This track starts with a source checkout and builds toward a repeatable binary-
analysis workflow: inspect a file, create a persistent `.glaurung` project,
navigate evidence, add analyst knowledge, and export or verify the result.

Glaurung is pre-1.0. Command flags and analyzer output can change. The tutorial
therefore treats `uv run glaurung --help` as the command-line source of truth
and keeps reproducible command output in [`_fixtures/`](_fixtures/) instead of
hard-coding volatile counts in the prose.

## What to expect

- The deterministic workflow does not require an API key.
- Pseudocode is an experimental analysis result. Confirm important conclusions
  against disassembly, cross-references, and source-level provenance.
- All sample paths are repository-relative and should be run from the checkout
  root.
- Tutorial commands use `uv run` so they work without activating `.venv`.

## Learning path

### [Tier 1: Getting started](01-getting-started/)

Start here on a fresh checkout:

1. [Install and smoke-test](01-getting-started/install.md)
2. [Analyze your first binary](01-getting-started/first-binary.md)
3. [Tour the main CLI workflows](01-getting-started/cli-tour.md)
4. [Navigate and annotate in the REPL](01-getting-started/repl-tour.md)

### [Tier 2: Daily basics](02-daily-basics/)

- [Naming and types](02-daily-basics/naming-and-types.md)
- [Cross-references](02-daily-basics/cross-references.md)
- [Stack frames](02-daily-basics/stack-frames.md)
- [Strings and data](02-daily-basics/strings-and-data.md)
- [Searching](02-daily-basics/searching.md)
- [Bookmarks and journal](02-daily-basics/bookmarks-and-journal.md)
- [Undo and redo](02-daily-basics/undo-redo.md)
- [Patch and verify](02-daily-basics/patch-and-verify.md)

### [Tier 3: Format and scenario walkthroughs](03-walkthroughs/)

- [Native C with debug information](03-walkthroughs/01-hello-c-clang.md)
- [Stripped Go](03-walkthroughs/02-stripped-go-binary.md)
- [Managed .NET PE](03-walkthroughs/03-managed-dotnet-pe.md)
- [JVM classfile and JAR](03-walkthroughs/04-jvm-classfile.md)
- [Vulnerable native parser](03-walkthroughs/05-vulnerable-parser.md)
- [UPX-packed binary](03-walkthroughs/06-upx-packed-binary.md)
- [Malware-style C2 sample](03-walkthroughs/07-malware-c2-demo.md)

### [Tier 4: Focused recipes](04-recipes/)

- [Diff two binaries](04-recipes/diffing-two-binaries.md)
- [Export to IDA, Binary Ninja, or Ghidra](04-recipes/exporting-to-ida-ghidra.md)
- [Recover typed locals from libc use](04-recipes/typed-locals-from-libc.md)
- [Use the benchmark harness in CI](04-recipes/bench-harness-as-ci.md)

### [Tier 5: Optional LLM workflows](05-agent-workflows/)

- [One-shot kickoff](05-agent-workflows/one-shot-kickoff.md)
- [Chat-driven triage](05-agent-workflows/chat-driven-triage.md)
- [Evidence and citations](05-agent-workflows/evidence-and-citations.md)

These chapters require provider credentials where noted. The deterministic
analysis and project file remain the evidence backbone.

## Reference

- [CLI cheatsheet](../reference/cli.md) — the current top-level command
  inventory and safe invocation shapes
- [REPL keymap](../reference/repl-keymap.md) — interactive commands
- [`set_by` precedence](../reference/provenance.md) — where recovered and
  analyst-provided names and types came from
- [Sample corpus](../reference/sample-corpus.md) — representative shipped inputs
  and how to regenerate the full inventory

## Verify the tutorial evidence

The verifier runs encoded tutorial recipes against real shipped binaries. Its
default and `--check` modes are read-only; only `--capture` rewrites fixtures.

```bash
uv run python scripts/verify_tutorial.py --check --chapter 01-install
uv run python scripts/verify_tutorial.py --check --chapter 01-first-binary
```

Maintainers can intentionally refresh a chapter after reviewing analyzer drift:

```bash
uv run python scripts/verify_tutorial.py --capture --chapter 01-first-binary
git diff -- docs/tutorial/_fixtures/01-first-binary
```

See [`PLAN.md`](../history/tutorial-plan-2026-04.md) for the tutorial's coverage plan and
[`../development/setup.md`](../development/setup.md) for the complete build and
development setup.
