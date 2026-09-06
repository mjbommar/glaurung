# WP3 deterministic instruction-origin set

> **Kind:** record · **Date:** 2026-09-06

## Outcome

Commit `7bea3314` lands the canonical value type required for compositional
instruction provenance. `OriginSet` stores instruction virtual addresses in
ascending, deduplicated order; construction order therefore cannot affect a
mapping. Union is deterministic and idempotent, and cloning a node preserves
an exact independent copy for future tail-duplication consumers.

This is the WP3 origin foundation, not end-to-end origin tracking. Statements
and expressions do not yet own an `OriginSet`; lowering, AST rewrites,
structuring, rendering, and the Python line-mapping surface still need to be
migrated. A compile-probe of a transparent statement-origin wrapper exposed 64
exhaustive statement consumers. The probe was reverted before this commit: the
next increment must migrate those consumers explicitly rather than silently
ignore provenance.

## Changes

- `src/ir/ast/origin.rs` defines canonical construction, stable iteration,
  deterministic union, in-place merge, and `FromIterator<u64>`.
- `src/ir/ast.rs` owns and publicly exports `OriginSet` from the AST module.
- `tests/test_census_baseline.json` records three new `ir` tests, moving the
  declared total from 4,733 to 4,736 and the `ir` category from 2,140 to 2,143.

## Verification

The focused tests passed:

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"
cargo test --features python-ext ir::ast::origin::tests --lib
```

They prove unordered/non-contiguous construction is canonical, union is
commutative and idempotent, and a duplicated set can be extended without
mutating its source.

The required full Rust gate passed at `7bea3314`:

```bash
cargo test --features python-ext
```

The library target reported 4,219 passed, zero failed, and five ignored. Every
integration and documentation target passed. The long CFR target reported 44
passed and ten ignored in 550.14 seconds.

The release extension rebuilt successfully with:

```bash
uv run maturin develop --release
```

The 419-pair identity-only output sweep used:

```bash
uv run python tools/stripped_differential.py --jobs 8 --json \
  > "$HOME/.cache/glaurung/tmp/wp3-origin-set-stripped.json"
```

Its result is byte-for-byte identical to the preceding WP3 map, SHA-256
`d86d3399127f93a292e895acc84375d2622065b9acf17d38228bb20973ca0c21`.
It reports the same 116 pre-existing divergences and zero infrastructure
problems. The command exits 1 only for the existing two-sided ratchet drift.

The post-commit census suite passed all six tests. The mandatory whole Python
suite then ran from the unchanged worktree:

```bash
uv run pytest python/tests/ -q
```

The first attempt was externally terminated with exit 143 at 27% and is not
evidence. The restart completed with 86 current failed node IDs. Neither the
origin tests nor `test_test_census.py` appears in the failures. The tool
transport truncated pytest's final aggregate summary, so exact passed,
expected-failure, skipped, deselected, and elapsed totals are not claimed.
Pytest's `lastfailed` cache contains 87 entries because it retains one older
`test_shadow_batch_locally_declines_an_unavailable_function` failure that is
absent from this run's terminal `FAILED` list. The broad suite remains red on
the existing fixture, baseline, generated-document, dialect, and repository
fitness debt; this is not release evidence.

The worktree also retained pre-existing unrelated dirty `csource`, `syntax`,
and source-metrics files throughout the run. No file changed while the Python
suite was executing. The exact 419-map identity and complete Rust gate are the
bounded causality evidence for this output-neutral increment.

No DecBench run or upstream interaction was performed.

## Next boundary

Introduce statement ownership of `OriginSet`, attribute lowered LLIR
instructions by their VAs, and migrate every affected statement consumer to
preserve or deliberately union provenance. Only after that carrier survives
all enabled AST passes should rendering expose structured line-to-address data
through Python.
