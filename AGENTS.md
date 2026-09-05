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

## You are probably not the only agent here

This checkout is worked on by several agents at once, sometimes on different
toolchains sharing one `target/`. Three consequences, all of which have already
cost time:

* **Read the full command line of every PID before killing it.** `pkill -f
  <pattern>` matches its own shell, so the target survives and the next thing
  you kill may be another agent's hour-long run. Kill by a PID you captured at
  launch.
* **Never `git checkout`, `git stash` or `git restore` a file you did not
  dirty**, and re-check `git status` immediately before committing rather than
  trusting a look from ten minutes ago. Stage explicit paths, never `-A`.
* **A test run over a tree someone else is editing is not evidence.** If the
  suite is red, check whether the failing code is even in your diff — attribute
  with `git log -S '<the exact line>'` on the *implementation*, not `git log` on
  the file holding the assertion.

Everything else — gates, conventions, working style, LLM model policy — is in
[CLAUDE.md](CLAUDE.md).
