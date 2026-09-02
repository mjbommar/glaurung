# Shared brief for docs-audit agents

> **Kind:** record · **Date:** 2026-09-02

Repository: /home/mjbommar/projects/personal/glaurung (git, branch master, HEAD b8884687, 2026-09-02).
Glaurung is a Rust+PyO3 reverse-engineering framework; read /home/mjbommar/projects/personal/glaurung/CLAUDE.md first for orientation.

## Ground rules
- READ-ONLY. Do not edit, create, or delete anything inside the repository. Write your report ONLY to the output path you were given (under the scratchpad directory).
- Do NOT run builds (`maturin`, `cargo build/test`), pytest, DecBench, Joern, or anything slow. `uv run glaurung --help` may be slow the first time; prefer reading `python/glaurung/cli/main.py` (command registry) and `python/glaurung/cli/commands/*.py` (argparse flags) to verify CLI claims. If you use `uv run`, first `export TMPDIR="$HOME/.cache/glaurung/tmp"`.
- Verify against CODE and GIT, not against other docs. A doc that agrees with another doc can still be wrong.
- Use `git log --follow --format='%h %ad %s' --date=short -- <file>` to see when and why a doc last changed, and `git log -S'<symbol>' --oneline` / `rg` to check whether referenced paths, functions, flags, env vars, tests, scripts, and baselines still exist.
- Spot-check every concrete claim you can cheaply verify: file paths, module names, CLI subcommands and flags, env var names, script names, feature flags in Cargo.toml, numbers (test counts, LOC, fixture counts), dates, "status: implemented/planned" statements.
- Do not trust the docs' own "last updated" lines or status banners; a mass edit in Aug 2026 touched most files.

## Per-file record (produce one for EVERY .md file in your scope; no skipping)
For each file emit a row in a markdown table with these columns:

| path | lines | last commit (date, short sha) | kind | verdict | evidence | recommendation |

- kind: one of `user-guide`, `reference`, `architecture`, `design-proposal`, `roadmap/plan`, `record` (campaign/session/experiment/status log), `generated`, `index`.
- verdict: `current`, `mostly-current`, `stale`, `superseded`, `historical` (accurate as a dated record but not current guidance), `duplicate`, `unverifiable`.
- evidence: 1-3 concrete facts with paths (e.g. "refers to `src/foo.rs` which was deleted in 3ab2c1f", "claims 12 lifters; `src/ir/lift/` has 4", "flag `--foo` not in `commands/bar.py`"). Be specific; vague verdicts are useless.
- recommendation: one of `keep`, `revise` (list what), `rewrite`, `merge-into <target>`, `archive` (move to a history area, keep as record), `delete`, plus a short reason.

## After the table
1. **Directory-level summary**: for each directory in your scope, what it is really for, how much of it is live vs. record, and what a clean structure for it would look like.
2. **Cross-cutting findings**: contradictions between docs and code, contradictions between docs, duplicated coverage (name the files), and knowledge that exists ONLY in docs and would be lost if deleted (call these out explicitly with the path).
3. **Proposed new structure** for your scope: a tree of target files with a one-line purpose each, marking which are `new`, `rewrite of <old>`, `merge of <olds>`, `archived`.
4. **Ground truth you established** that other auditors or the plan writer should know (e.g. "the actual CLI subcommand list is: ...", "the fixture count is N", "the feature flags are: ...").

Be thorough and concrete. Length is fine; vagueness is not. Write the report as a single markdown file at your output path and finish with a 10-line executive summary at the TOP of that file.
