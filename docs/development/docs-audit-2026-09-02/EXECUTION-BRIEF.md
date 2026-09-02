# Execution brief for docs-rewrite agents

> **Kind:** plan · **Status:** proposed

Read first: `docs/development/docs-rewrite-plan.md` (the work order) and the
ledger for your area under this directory. Ledger 02 is the code ground-truth
map; use it instead of old docs when writing anything new.

Branch: `docs/rewrite-2026-09`. Repo root: `/home/mjbommar/projects/personal/glaurung`.

## Decisions taken (do not reopen)

- D1 the `.smt2` corpus stays in git under `tests/corpora/axeyum-qfbv/`.
- D2 `docs/history/` lives in the repository.
- D3 `docs/agentic-glaurung/` moves to `docs/design/agentic-source-recovery/` (Phase 2).
- D4 `rust-version = "1.88"` is pinned in `Cargo.toml`.
- D5 `development/project-structure.md` folds into `architecture/README.md`.
- D6 the 31 axeyum ADRs are split into `docs/decisions/solver-NNN-*.md`.
- D7 `guides/` and `reference/` are two directories.

## Ground rules

1. `export TMPDIR="$HOME/.cache/glaurung/tmp"` before any `uv`, `cargo`, `pytest`,
   or `maturin`. Nothing may write to `/tmp`.
2. **Do not commit.** The orchestrator commits. Do not `git stash` (shared ref
   across worktrees). `git mv` is fine when your task says to move files.
3. **Touch only the files your task lists.** Other agents are editing other
   files in the same working tree at the same time. If you must change a file
   outside your list, say so in your report instead of doing it.
4. Run only the tests that cover your change while iterating (name them). The
   orchestrator runs the standing gate after all agents in a phase land.
5. Never run DecBench, Joern, or `tools/decbench_*`. Never hand-edit
   `docs/tutorial/_fixtures/` or a generated file; regenerate with the tool.
6. Every new or rewritten live document under `docs/` opens with, on line 3:
   `> **Kind:** <guide|reference|architecture|decision|design|plan> · **Status:** <maintained|generated|proposed>`
   Files under `docs/history/` open with `> **Kind:** record · **Date:** YYYY-MM-DD`.
   No other status banners. No sentences stating a build or gate is failing.
7. A number in a live document comes with the command that produced it and
   the commit it was run at, or it is left out.
8. No dated narrative in live documents. Incidents go to
   `docs/development/traps.md` or `docs/history/`.
9. Write from code. When a claim can be checked with `rg`, check it and keep
   the command in your notes. Ledger 02 §10 lists names that appear in docs
   but not in code; do not reintroduce them.
10. Report back with: files created/modified/moved/deleted (paths), the tests
    you ran and their result, and anything you could not do.
