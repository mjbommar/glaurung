# Outcomes: the seven-project portfolio, scored against the code

> **Kind:** record · **Date:** 2026-09-02

All ten files in this directory landed in one commit, `67c525bd`
(2026-08-13, "docs: add the architecture refactoring portfolio"), and none was
touched again. `git log --grep` finds no commit citing any project, and the
only inbound link the portfolio ever had was from a project-structure page.

This file scores each project against the tree as it stood on 2026-09-02, at
commit `13faa6f7`. The pattern worth recording is not "five of seven were not
executed" — it is that **four of the seven goals were met, and three of those
four were met by a different route than the plan named**, outside the plan and
without reference to it. A well-specified boundary turned out to be durable
even when the migration attached to it was not; the boundaries are restated as
live guidance in
[`../../architecture/module-boundaries.md`](../../architecture/module-boundaries.md).

## The before-measurement

`architecture-review-2026-08-13.md` in this directory took the file-concentration
snapshot the portfolio was built on, at `fb4ee6ba`. It is the only such
measurement in the repository, which makes it the only thing that can prove any
of the results below. Its column is "Lines"; the 2026-09-02 column below is
`wc -l` at `13faa6f7`, so the two are comparable and neither excludes inline
test modules.

| file | 2026-08-13 | 2026-09-02 | |
|---|---:|---:|---|
| `src/ir/ast.rs` | 19,158 | 9,710 | −49% |
| `src/ir/lift_x86.rs` | 8,556 | **9,556** | **+12%** |
| `src/ir/call_args.rs` | 7,222 | 5,699 | −21% |
| `src/analysis/cfg.rs` | 7,125 | **1,992** | **−72%** |
| `src/ir/types_recover.rs` | 6,812 | 5,539 | −19% |
| `python/glaurung/llm/tools/windows_function_pretty_lift.py` | 6,046 | 6,046 | unchanged |
| `src/ir/stack_locals.rs` | 5,915 | 4,928 | −17% |
| `src/ir/structure.rs` | 4,938 | 3,032 | −39% |
| `src/ir/value_number.rs` | 4,437 | 2,692 | −39% |
| `python/glaurung/cli/commands/windows.py` | 4,027 | 4,025 | unchanged (a formatting commit) |
| `src/python_bindings/ir.rs` | 3,875 | 2,496 | −36% |
| `src/symbolic/explore.rs` | 3,617 | 1,768 | −51% |
| `python/glaurung/llm/kb/xref_db.py` | 3,434 | **3,557** | **+4%** |

```bash
wc -l src/ir/ast.rs src/ir/lift_x86.rs src/analysis/cfg.rs \
      python/glaurung/cli/commands/windows.py python/glaurung/llm/kb/xref_db.py
```

Eight files shrank, two grew, two did not move. `xref_db.py` grew under a
project (P6) that was never started; `lift_x86.rs` grew under one (P2) that was
partly executed elsewhere in the same directory — and the review itself said
that file might legitimately stay large if its instruction-family modules share
one tested semantic contract. `windows_function_pretty_lift.py` and
`windows.py` did not move at all, and their project (P5) was not started.

## Scoreboard

| # | project | verdict | evidence |
|---|---|---|---|
| **P1** | program semantic authority | **not started as specified; goal met elsewhere** | `src/program/symbols/` and `src/program/types/` exist (`object_import.rs`, `verify.rs`, `dwarf.rs`, `import.rs`); `src/program/diagnostics.rs` does not. The declared exit evidence — "one documented precedence table" — was satisfied on 2026-08-28 on the *Python* side, in `python/glaurung/llm/kb/provenance.py`, with no reference to this plan. |
| **P2** | IR / decompiler boundaries | **partially executed, different shape** | Of the target directories (`llir/ lift/ ssa/ mir/ recovery/ hir/ render/`), only `mir/` exists — and `PreparedLlir::mir()` carries `#[allow(dead_code)]` with no production consumer. `src/ir/` instead has 17 subdirectories named after the file each was split out of. There is no `src/ir/pipeline.rs`; orchestration is `src/python_bindings/ir/pipeline.rs`. Exit criterion "no file exceeds 2,000 lines": `ast.rs` is 9,710 and `lift_x86.rs` 9,556. |
| **P3** | CFG discovery decomposition | **largely executed** | `cfg.rs` 7,125 → 1,992 with `src/analysis/cfg/` holding 19 modules. Commit `25bd03d6` ("analysis: take the packed-image entry point back out of cfg.rs") is the visible trace. The plan's module names (`model.rs`, `builder.rs`, `discovery.rs`, `indirect.rs`, `algorithms/`, `verify.rs`, `render.rs`) were not used, and `cfg.rs` was reduced rather than deleted. |
| **P4** | native / Python API boundary | **partially executed; worst-violated exit criterion** | Done: `src/python_bindings/ir/` exists, `ir.rs` 3,875 → 2,496. Not done: `src/decompile/service.rs`, `src/analysis/service.rs`, `src/python_bindings/analysis/` and `python/glaurung/api/` do not exist. Exit criterion "binding functions contain no pass sequencing" is squarely violated — the whole AST pass ordering is `src/python_bindings/ir/pipeline.rs`. |
| **P5** | Windows workflow decomposition | **not started** | `cli/commands/windows.py` and `llm/tools/windows_function_pretty_lift.py` are the same size as at review time. No `windows/{domain,extract,services,render,validate}/`, no `cli/commands/windows/` package, no `llm/tools/windows/` package. `llm/tools/` instead accumulated 113 flat `windows_*` modules. |
| **P6** | knowledge-base boundaries | **not started; one file regressed** | No `kb/schema/`, `kb/storage/`, `kb/repositories/`, `kb/domain/` or `kb/services/`; `llm/kb/` is 27 flat modules and `xref_db.py` grew 3,434 → 3,557. Its invariant "unknown future schema versions fail with a clear error" **is** satisfied (`persistent.py:210-215`); "migration tests from every shipped schema version" cannot be, because migrations are unimplemented and there has only ever been version `1`. Its invariant "manual annotations always outrank automated evidence" landed on 2026-08-28 via `provenance.py`, again outside this plan. |
| **P7** | execution / symbolic boundaries | **partially executed** | Done: `src/symbolic/explore/` and `src/symbolic/solver/` exist; `explore.rs` 3,617 → 1,768; commit `89111140` ("symbolic: split explore.rs 2,742 → 901") is the trace. Its "one instruction-effect owner" criterion holds structurally — `src/exec/interp.rs` is the single interpreter over `src/exec/domain.rs`'s `Domain`, with `Concrete` and `Symbolic` as the two impls. Not done: no `src/exec/machine/`, no `src/exec/semantics/`, no `src/symbolic/{domain,analyses,replay}/`; `src/exec/` is ten flat files. Its exit criterion "feature combinations compile and run their declared tests independently" is now enforced by `scripts/feature-build-gate.sh` (12 lanes) — delivered outside the plan. |

## What replaced it

The live mechanism is measurement in the test suite rather than a portfolio:

- `tools/fitness_report.py` + `tools/fitness_baseline.json` —
  physical product lines over `src/*.rs` with a `--check-ratchet` mode.
- `python/tests/test_fitness_report.py` — the ratchet's test.
- `python/tests/test_large_module_review.py` — every product file over 1,000
  lines carries a review entry, and an entry outliving its file fails too.
- `python/tests/test_src_dependency_boundaries.py` — which module may read
  which environment variable, keyed by file path.
- `scripts/feature-build-gate.sh` — the twelve build lanes P7 asked for.

Those are described as live guidance in
[`../../development/testing-gates.md`](../../development/testing-gates.md), and
the boundaries themselves in
[`../../architecture/module-boundaries.md`](../../architecture/module-boundaries.md).
