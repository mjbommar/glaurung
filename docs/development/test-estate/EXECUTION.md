# Execution log

Live status for the work in [`README.md`](README.md) and
[`../decompiler-parity-backlog.md`](../decompiler-parity-backlog.md).
Updated as waves land. `[x]` = landed and verified, `[~]` = in flight,
`[ ]` = not started.

## Wave 1 — reachability and hygiene (disjoint territory, parallel)

| item | plan ref | owner | state |
|---|---|---|---|
| Wire the 10 dead `tests/triage/` files | estate 1.2 | agent A | [~] |
| Reachability ratchet test | estate 1.1 | agent C | [~] |
| Three CWD-dead Python files | estate 1.4 | agent C | [~] |
| `-ra` for visible skips | estate 1.6 | agent C | [~] |
| Delete 63 never-parsing metadata | estate 9.1 | agent B | [~] |
| `assets/` cleanup | estate 9.3 | agent B | [~] |
| Dead scripts | estate 9.4 | agent B | [~] |
| DWARF local/static name ingestion | parity #1 | main | [~] |

## Wave 2 — parity and measurement

| item | plan ref | state |
|---|---|---|
| Condition simplification | parity #2 | [ ] |
| `tools/compare_decompilers.py` | parity #7 | [ ] |
| Page-align fixture | parity #9 | [ ] |
| Pin angr/Ghidra as dev oracles | parity #10 | [ ] |
| Wire Go fixtures | estate 7.1 | [ ] |
| CI runs the suite | estate 1.5 | [ ] |

## Wave 3 — deeper

| item | plan ref | state |
|---|---|---|
| Canary + determinism | estate 2 | [ ] |
| Fuzz crate in a gate lane | estate 3.1 | [ ] |
| Thin-module corpora | estate 5 | [ ] |
| Perf ratchet | estate 6 | [ ] |

## Ground rules for every change here

Verified before any claim of done: `cargo test --features python-ext`,
`uv run pytest python/tests/`, `uvx ruff check python/`, `uvx ty check
python/`. `TMPDIR` exported. No DecBench, no Joern. Every fixture change
refreshes the six side files.
