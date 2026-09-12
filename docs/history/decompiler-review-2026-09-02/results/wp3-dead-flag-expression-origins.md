# WP3 dead-flag expression origins

Date: 2026-09-10

## Correctness defect

`prune_overwritten_flags` used a second, narrow expression walker that did not
descend through `Expr::Origin`. Once expression provenance was attached, a
real read between two writes could therefore become invisible and the first
reaching flag definition could be deleted as allegedly overwritten-unread.
That changes the recovered program rather than merely its formatting.

Commit `299fd4e8` deletes the obsolete walker and makes overwritten-flag
pruning use the same exhaustive `collect_flag_reads_in_expr` implementation as
the other flag-liveness paths. The shared collector covers origin carriers,
numeric conversions, calls, table entries, wide arithmetic, and every current
expression variant through an exhaustive match.

## Red/green evidence

The focused contract was observed red first. Given:

```text
zf = 1
observed = Origin(Reg(zf))
zf = 0
```

the first assignment was deleted and only two statements survived. After the
repair, all three remain and the complete owning module passes:

```text
cargo test --features python-ext ir::dce::tests:: --lib
10 passed; 0 failed; 4768 filtered out
```

The refactor also removes the shipped-build dead-code warning for the former
per-flag reader.

## Exact-release evidence

A clean detached worktree at
`299fd4e8e0b035dcf7bda11d5210e597c2d0a124` was release-built with CPython
3.12.13. `tools/build_guard.py` reported the extension fresh:

```text
SHA-256 ce9f48825dcb3a2e74a739d9218fd541bac31a3dc25b9e22f119749409438612
```

Focused product checks passed:

```text
uv run --no-sync python tools/dectest.py @polarity
SCOPED: 4 lanes of 838 (0%) - no regressions in scope

uv run --no-sync pytest -q \
  python/tests/test_decompiler_emission_invariants.py::test_every_local_used_is_also_declared
8 passed
```

No broad suite, corpus sweep, DecBench run, or baseline refresh was performed.
This closes the overwritten-flag expression-origin consumer only; universal
origin survival remains open.
