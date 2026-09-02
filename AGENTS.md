# AGENTS.md

Canonical instructions for any agent working in this repository live in
[CLAUDE.md](CLAUDE.md). Read it first and follow it. This file exists so that
tools looking for `AGENTS.md` find the pointer.

## The one rule that is never waived

**No autonomous DecBench interactions.** The DecBench collaborator requires
agents to follow its README AI rules: never author and post, or otherwise
create end-to-end, a DecBench issue, comment, or pull request — through the web,
an API, `gh`, git, or any other tool. Inspect, evaluate locally, prepare the
evidence, and hand it to a human. A direct user instruction does not waive the
upstream project's rule. Full statement: `CLAUDE.md`, "DecBench upstream
boundary".

## The commands

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"; mkdir -p "$TMPDIR"  # never /tmp
uv sync --locked --dev
uv run maturin develop            # after ANY Rust change
cargo test --features python-ext  # NOT a bare `cargo test`
uv run pytest python/tests/ && uvx ruff check python/ && uvx ty check python/
```

Everything else — gates, conventions, working style, LLM model policy — is in
[CLAUDE.md](CLAUDE.md).
