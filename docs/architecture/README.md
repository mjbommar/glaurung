# Architecture documentation

This directory distinguishes current storage and data boundaries from dated
reviews, parity snapshots, and earlier design proposals.

## Current contracts

- [Persistent project databases](PERSISTENT_PROJECT.md) describes the SQLite
  `.glaurung` file, sessions, lifecycle, schema compatibility, and supported
  Python entry points.
- [Core data model](data-model/README.md) maps the current Rust core, triage
  artifacts, decompiler IR, Python bindings, and persistent knowledge base.
- [Analysis documentation](../analysis/README.md) covers current operator and
  implementation entry points for disassembly, decompilation, and related
  analysis.

## Historical evidence and proposals

- `2026-07-13-architecture-quality-review.md` is a dated architecture review.
- `IDA_GHIDRA_PARITY.md` is a historical capability snapshot, not a live
  support matrix.
- `data-model/proposals/`, `data-model/critique/`, and the older implementation
  plans are retained design inputs. Their illustrative types are not APIs.

For current behavior, prefer public source, command help, and focused tests over
an unchecked item or status emoji in a historical document.
