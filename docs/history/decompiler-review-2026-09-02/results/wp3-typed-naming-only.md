# WP3: typed naming is the only production boundary

Date: 2026-09-12

Code commit: `a1080d7d`

## Result

Production and measured decompilation now treat naming only as a final render
projection. The public library boundary is:

- `naming::role_names_with_identities`, which computes aliases from the
  authoritative `ValueIdentities`; and
- `naming::role_named_render_view`, which applies them to a clone.

The four older mutating entry points are compiled only for their isolated
compatibility tests. Their identity-free AST live-in inference and recursive
read/write walker are likewise test-only, so shipped code cannot accidentally
move semantic passes behind a presentation rewrite.

The `decompile_pipeline` benchmark was the final non-test caller. It now runs
canary cleanup, dead-store elimination, stack rematerialization, and label
cleanup before computing the identity-aware role map, then names only its final
render view. This matches the shipped pipeline ordering instead of benchmarking
the retired mutation boundary.

## Red/green evidence

The benchmark migration was first compiled before the typed functions were
made public and failed with two `E0603` errors. That observed-red check proves
the external Criterion target could not silently fall back to a crate-private
or identity-free path.

After exposing only the typed pair and test-gating the compatibility surface:

```text
cargo test --features python-ext --lib ir::naming::tests:: -- --test-threads=1
23 passed; 0 failed

cargo check --features python-ext --bench decompile_pipeline
exit 0

cargo bench --features python-ext --bench decompile_pipeline --no-run
exit 0

uv run maturin develop
exit 0
```

No benchmark timing was run or claimed. No broad suite, corpus matrix,
DecBench, or Joern run was performed. The native build included unrelated
concurrent dirty source and is therefore a fresh-tree build check, not
exact-clean provenance.

## Next boundary

The remaining explicit identity-free AST preparation functions are broader
public compatibility APIs and are still used by diagnostic structure-v2 and
unit-test render paths. Classify those callers separately; do not conflate this
completed naming boundary with deletion of every no-sidecar transform API.
