# WP3 array-index expression-origin rendering

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `c373207f` makes typed array-index recognition transparent to WP3
expression-origin carriers. Proven `base + index * sizeof(T)` and equivalent
shift forms still render as `base[index]` when attribution surrounds the
address sum, pointer base, redundant zero addition, scale operation, scale
constant, index, or implicit integer-extension chain.

The proof itself is unchanged: the base must have a declared pointer pointee
width equal to the access width, and the multiply or shift must encode exactly
that scale. Width mismatches still retain raw address arithmetic. Metadata is
the only newly transparent layer.

This is a bounded readability consumer migration, not universal expression
attribution or completion of WP3.

## Focused verification

The existing array-render contract was strengthened with independent origins on
every layer of its canonical address expression. Before the production change
it was observed red and expanded the desired `arg0[local_4]` into:

```c
*(int *)(((long)arg0 + (0 + (local_4 * 4))))
```

After the semantic readers were made carrier-transparent, the exact contract
passes again while its existing mismatched-access-width refusal remains in the
same test:

```text
cargo test --features python-ext --lib \
  ir::ast::tests::decbench_array_index_render_for_pointer_arg -- --exact
1 passed; 0 failed; 4,669 filtered out
```

After a release extension rebuild, the fixture canary was restricted to the
three directly relevant host families:

```text
uv run python tools/dectest.py \
  109_subscript_commutativity 110_pointer_arithmetic \
  207_scaled_index_addressing --full --allow-stale
```

The 12 binary lanes added no regression. Clang O0
`negative_offset_from_interior` appeared as one improvement, but reversing only
the owned production lines, rebuilding, and rerunning that exact function left
it passing. The improvement therefore belongs to concurrent checkout movement
and is not attributed to this commit.

The build guard reported concurrent uncommitted native-AArch64 work newer than
the extension, so `--allow-stale` was required; each A/B extension was fresh for
the owned production state. No broad Rust or Python suite, cross-architecture
corpus, DecBench, or Joern ran. No census baseline changed because the commit
strengthens an existing test rather than declaring another one.

## Next boundary

Continue the pointer-render audit with direct pointer values, field addresses,
and declared integer casts. Preserve exact pointee-type, access-width, and
representation-boundary refusals.
