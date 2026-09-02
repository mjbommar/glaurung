# Analysis documentation

This directory separates current operator and developer guidance from research
checkpoints, implementation diaries, and historical design proposals. Start with
the CLI when analyzing an artifact; use architecture documents to understand the
implementation, not to infer that a command or backend exists.

## Current entry points

- [Disassembly](disassembly/) documents the offline `glaurung disasm` command,
  its two native backends, resource bounds, and current fail-soft behavior.
- [Decompiler architecture](decompiler/) covers the native LLIR, SSA, AST, and
  pseudocode pipeline. Dated files in that directory are evidence checkpoints,
  not evergreen command references.
- [Function identity: the CFR](function-identity-cfr.md) documents the
  canonical function representation behind `glaurung.analysis.cfr_signatures_path`
  -- the mask/keep table, the version discipline, and the measured retrieval
  numbers with their denominators.
- [Compiler and source-language detection](language-detection/) documents the
  internal Rust heuristic and explains that it is not a standalone CLI command.
- [Binary triage](../triage/) is the first deterministic pass for format,
  architecture, strings, symbols, packer signals, and containers.
- [Parsers](../parsers/) maps current owned parsers and format-specific commands.

Other user-facing analysis commands include:

```bash
uv run glaurung symbols --help
uv run glaurung disasm --help
uv run glaurung cfg --help
uv run glaurung decompile --help
```

`symbols`, `disasm`, and `cfg` are deterministic and offline. LLM-backed
commands such as `ask`, `explain`, and `name-func` have separate provider,
budget, and persistence requirements; see the [CLI documentation](../cli/).

## Historical records

The interpreted-bytecode, lifting, language-detection measurement, and symbol
enhancement documents retain earlier research and plans. Their status banners
identify them as historical. They may contain obsolete paths, illustrative
types, stale measurements, or unimplemented phases and should not be used as
operator contracts.

For any exact capability claim, prefer this order:

1. live command help;
2. public source and focused tests;
3. maintained operator guides; and
4. dated diaries or design records.
